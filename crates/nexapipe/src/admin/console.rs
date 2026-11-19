//! The browser console: the page the instance serves, and the API it answers.
//!
//! # What it is
//!
//! A page an operator opens on the machine the instance runs on, to see what
//! the instance is doing and to change the clients that may connect to it.
//!
//! # Where it lives
//!
//! On the admin listener, next to the `/v1/*` half. The listener is
//! loopback-only and has no escape hatch, so the console is only ever as
//! reachable as the management surface already was.
//!
//! # The three rules
//!
//! A request to `/api/*` is answered only when all three hold:
//!
//! 1. **The host is loopback.** The `Host` header's host part must be a
//!    loopback address or `localhost`. This is the DNS-rebinding guard: a page
//!    on a domain the attacker controls, resolving to `127.0.0.1`, arrives with
//!    that domain in the `Host` header and is refused. The listener already
//!    refuses to bind a non-loopback address, so this checks that the request
//!    was *addressed to* this listener and not merely delivered to it.
//! 2. **The token is there.** The same bearer token `/v1/*` takes. Loopback is
//!    not the operator: every process and every user on the machine can reach
//!    a loopback port, and the token is what a process that is not the
//!    operator does not have.
//! 3. **A write says it is a write.** Anything that is not a read carries
//!    `X-NexaPipe-Admin: 1`. A browser will not let a page on another origin
//!    add a custom header without asking the server first, and this server
//!    answers no such ask and sends no cross-origin allowance — so the header
//!    is a thing a cross-origin page cannot send.
//!
//! The host is checked first because it costs nothing and refuses the
//! rebinding attempt before anything else looks at the request.
//!
//! # What is not here
//!
//! The settings. The configuration has more than thirty keys and each of them
//! has a rule, and a write that re-rendered the whole configuration would take
//! a route somebody added while the server was running with it. The clients
//! are entities in the storage seam and can be written one at a time; the
//! routes are not yet, and a route written the long way round would be exactly
//! the write the seam exists to avoid.

use crate::config::ClientSecretWrite;
use crate::storage::Storage;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use nexapipe_proto::secret::SecretString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::token::{bearer_token, matches_token};
use super::{
    AdminState, Body, WWW_AUTHENTICATE, clients_json, connections_json, health_json, json,
    routes_json, status_json, text, with_header,
};

/// The header a write has to carry, and the value it has to carry.
const WRITE_HEADER: &str = "x-nexapipe-admin";
const WRITE_HEADER_VALUE: &str = "1";

/// The content security policy the console's page is served with.
///
/// The console holds the admin token in the browser's local storage, so the
/// page that holds it is worth locking down: nothing from another origin,
/// and nothing that could phone home.
const CONSOLE_CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'";

/// What the console needs to be served and to write.
pub struct Console {
    /// The directory the bundle is in.
    pub dir: PathBuf,
    /// The store the instance reads, so a change the console makes is a
    /// change the server sees on its next reload.
    pub storage: Arc<dyn Storage>,
}

/// Answers one `/api/*` request.
pub(super) async fn api_response(req: Request<Incoming>, state: Arc<AdminState>) -> Response<Body> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok());
    if !host_is_loopback(host) {
        return text(
            StatusCode::FORBIDDEN,
            "the console's API answers only a request addressed to a loopback host",
        );
    }

    let Some(token) = state.token.as_ref() else {
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "no admin token: /api/* is unavailable",
        );
    };
    let presented = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    let authorized =
        presented.is_some_and(|presented| matches_token(presented, token.expose_secret().as_str()));
    if !authorized {
        let response = text(StatusCode::UNAUTHORIZED, "unauthorized");
        return with_header(response, hyper::header::WWW_AUTHENTICATE, WWW_AUTHENTICATE);
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let is_read = method == hyper::Method::GET || method == hyper::Method::HEAD;

    if !is_read
        && req
            .headers()
            .get(WRITE_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(WRITE_HEADER_VALUE)
    {
        return text(
            StatusCode::BAD_REQUEST,
            "a write to the console's API must carry the header X-NexaPipe-Admin: 1",
        );
    }

    let Some(rest) = path.strip_prefix("/api/") else {
        return text(StatusCode::NOT_FOUND, "not found");
    };

    // The console is the only thing that writes here, and it writes through
    // the store the server reads. The store is cloned out of the state rather
    // than borrowed from it, because the state is handed to the handlers.
    let Some(console) = state.console.as_ref() else {
        return text(StatusCode::NOT_FOUND, "not found");
    };
    let storage = console.storage.clone();

    match (method.as_str(), rest) {
        ("GET", "status") => json(&status_json(&state).await),
        ("GET", "routes") => json(&routes_json(&state.routes).await),
        ("GET", "clients") => json(&clients_json(&state).await),
        ("GET", "connections") => json(&connections_json(&state.peers)),
        ("GET", "health") => json(&health_json(&state.routes).await),
        ("POST", "clients") => issue_credential(req, state, &storage).await,
        ("DELETE", other) if other.starts_with("clients/") => {
            drop_credential(
                other.trim_start_matches("clients/"),
                &query,
                state,
                &storage,
            )
            .await
        }
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Issues a credential to a client, and answers with the client table.
///
/// The secret is in the answer, once: the operator has to be able to enroll an
/// authenticator app with it, and this is the one answer that carries one.
/// Every other answer about a client carries `has_secret` and nothing else.
async fn issue_credential(
    req: Request<Incoming>,
    state: Arc<AdminState>,
    storage: &Arc<dyn Storage>,
) -> Response<Body> {
    let body = match req.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("the request body could not be read: {e}"),
            );
        }
    };
    let request: ClientWrite = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                &format!("the request body is not a client request: {e}"),
            );
        }
    };

    let client_id = request.client_id.trim().to_string();
    if client_id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "a client id is required");
    }
    if !crate::auth::is_presentable_client_id(&client_id) {
        return text(
            StatusCode::BAD_REQUEST,
            "the client id is printable ASCII of at most 64 characters and not empty",
        );
    }

    let secret = crate::auth::TotpValidator::generate_secret();
    let written = match storage
        .write_client_secret(
            &client_id,
            &SecretString::new(secret.clone()),
            request.force,
        )
        .await
    {
        Ok(written) => written,
        Err(e) => return text(StatusCode::CONFLICT, &format!("{e:#}")),
    };

    let mut answer = clients_json(&state).await;
    if let Some(object) = answer.as_object_mut() {
        object.insert(
            "issued".to_string(),
            serde_json::json!({
                "client_id": client_id,
                // Once, for the operator to enroll with. Nothing else in the
                // console ever shows it.
                "secret": secret,
                "replaced": matches!(written, ClientSecretWrite::Replaced),
            }),
        );
    }
    json(&answer)
}

/// Drops a client's credential, or one device's.
async fn drop_credential(
    client_id: &str,
    query: &str,
    state: Arc<AdminState>,
    storage: &Arc<dyn Storage>,
) -> Response<Body> {
    let client_id = client_id.trim();
    if client_id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "a client id is required");
    }
    let device = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "device")
        .map(|(_, value)| percent_decode(value))
        .filter(|value| !value.is_empty());

    let outcome = match &device {
        Some(device) => storage.remove_device(client_id, device).await,
        None => storage.remove_client(client_id).await,
    };
    if let Err(e) = outcome {
        return text(StatusCode::CONFLICT, &format!("{e:#}"));
    }

    json(&clients_json(&state).await)
}

/// What a write that issues a credential asks for.
#[derive(serde::Deserialize)]
struct ClientWrite {
    client_id: String,
    /// Replace the credential that is already there. A device enrolled with
    /// the old one stops authenticating the moment it changes, so the console
    /// asks before it does.
    #[serde(default)]
    force: bool,
}

/// Whether the host a request was addressed to is this machine.
///
/// The `Host` header is the host the request was *addressed to*, which is not
/// the same thing as where it came from: a browser talking to `127.0.0.1`
/// sends `Host: 127.0.0.1:8080`, and a browser talking to a name that
/// resolves to `127.0.0.1` sends that name.
pub(super) fn host_is_loopback(host: Option<&str>) -> bool {
    let Some(host) = host else {
        // A request without a host cannot be shown to have been addressed to
        // this listener, so it is refused rather than assumed.
        return false;
    };
    let part = host_part(host);
    if part.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(address) = part.parse::<IpAddr>() {
        return address.is_loopback();
    }
    // `.localhost` is reserved for the loopback (RFC 6761), so a name under it
    // is this machine too.
    part.to_ascii_lowercase().ends_with(".localhost")
}

/// The host part of a `Host` header, without the port and without the
/// brackets an IPv6 address carries.
fn host_part(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    match host.rsplit_once(':') {
        // A bare IPv6 address has more than one colon and no port to strip.
        Some((before, _)) if !before.contains(':') => before,
        _ => host,
    }
}

/// Decodes the percent-escapes in a query value.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Serves one file of the console's bundle.
///
/// The bundle is a directory of files, and the two shapes it has are the index
/// and the assets it names. There is no fallback to the index for an unknown
/// path: the console's router is a hash router, so every path it needs is
/// inside the fragment and the server never has to invent one.
pub(super) fn static_response(dir: Option<&Path>, path: &str) -> Response<Body> {
    let Some(dir) = dir else {
        return text(StatusCode::NOT_FOUND, "not found");
    };
    let Some(file) = file_for(dir, path) else {
        return text(StatusCode::NOT_FOUND, "not found");
    };
    let Ok(content) = std::fs::read(&file) else {
        return text(StatusCode::NOT_FOUND, "not found");
    };

    let content_type = content_type_for(&file);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", content_type)
        .header("content-security-policy", CONSOLE_CSP)
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(
            http_body_util::Full::new(Bytes::from(content))
                .map_err(|_| unreachable!())
                .boxed_unsync(),
        )
        .expect("a response with a static body is always well formed")
}

/// The file a request path names inside the console's directory.
///
/// The file has to be inside the directory after symlinks are resolved: a
/// path that walks out of it is refused rather than followed, and the check
/// is on the resolved path rather than on the text, because a symlink inside
/// the directory can point anywhere.
fn file_for(dir: &Path, path: &str) -> Option<PathBuf> {
    let relative = path.trim_start_matches('/');
    let relative = if relative.is_empty() {
        "index.html"
    } else {
        relative
    };
    if relative != "index.html" && !relative.starts_with("assets/") {
        return None;
    }
    if relative
        .split('/')
        .any(|part| part == ".." || part == "." || part.is_empty())
    {
        return None;
    }

    let canonical_dir = dir.canonicalize().ok()?;
    let canonical = dir.join(relative).canonicalize().ok()?;
    if !canonical.starts_with(&canonical_dir) {
        return None;
    }
    Some(canonical)
}

/// The content type a file is served with.
fn content_type_for(file: &Path) -> &'static str {
    match file
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loopback_host_is_this_machine() {
        for host in [
            "127.0.0.1:8080",
            "127.0.0.1",
            "localhost:8080",
            "LOCALHOST",
            "[::1]:8080",
            "app.localhost:8080",
        ] {
            assert!(host_is_loopback(Some(host)), "{host} is this machine");
        }
    }

    #[test]
    fn a_name_that_is_not_a_loopback_host_is_not() {
        for host in [
            "example.com",
            "evil.example:80",
            "192.168.1.10:8080",
            "10.0.0.1",
        ] {
            assert!(!host_is_loopback(Some(host)), "{host} is not this machine");
        }
    }

    #[test]
    fn a_request_without_a_host_cannot_be_shown_to_be_addressed_here() {
        assert!(!host_is_loopback(None));
    }

    #[test]
    fn a_query_value_is_decoded() {
        assert_eq!(percent_decode("laptop"), "laptop");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
    }
}

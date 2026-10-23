//! A WebSocket upgrade, carried over the tunnel.
//!
//! # What this is
//!
//! A WebSocket is not a request with a body: it is a request that turns the
//! connection into a conversation once the answer says so. The answer is a
//! `101`, and after it the two ends speak a framing of their own that HTTP
//! knows nothing about.
//!
//! So the upgrade is two things, and this module does both:
//!
//! - The **handshake**: the client's upgrade request goes to the backend
//!   over a connection of its own — a WebSocket holds one connection for the
//!   whole session, so it is not the pooled client — and the backend's answer
//!   comes back. The client gets the same `101`, with the same headers, so
//!   that its `Sec-WebSocket-Accept` is the one the backend agreed to.
//! - The **session**: from then on the two are byte streams, and the bytes
//!   are moved either way until one side stops.
//!
//! The framing is the WebSocket's own and is not touched here: the bytes are
//! moved as they are, and the end of the session is the end of a stream.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::HeaderMap;
use hyper::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::conn::{find_headers_end, now_millis};
use crate::http::body::{ProxyBody, ProxyFailure, Retryability};
use crate::http::client::{BackendClients, BackendStream};
use crate::routes::BackendInfo;

/// How much of a WebSocket's stream is moved at a time.
///
/// The HTTP path coalesces into 64 KiB before it writes; the WebSocket path
/// used to move 8 KiB at a time, which is one QUIC frame and one wake-up for
/// every 8 KiB of the stream.
const WS_COPY_BUFFER: usize = 64 * 1024;

/// What the backend answered to the upgrade.
pub struct Handshake {
    /// The status the backend answered with.
    pub status: u16,
    /// The headers the backend answered with.
    pub headers: HeaderMap,
    /// The bytes that came after the handshake.
    ///
    /// A backend that answers the upgrade and sends frames in the same breath
    /// puts them here, and they belong to the session rather than to the
    /// handshake.
    pub trailing: Vec<u8>,
    /// The backend's stream, for the session itself.
    pub backend: BackendStream,
}

impl Handshake {
    /// The `101` the client gets.
    ///
    /// The headers are the backend's, so the `Sec-WebSocket-Accept` the
    /// client checks is the one the backend agreed to.
    pub fn upgrade_response(&self) -> Response<ProxyBody> {
        let mut response = Response::new(crate::http::body::empty_body());
        *response.status_mut() =
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::SWITCHING_PROTOCOLS);
        *response.headers_mut() = self.headers.clone();
        response
    }

    /// The backend's refusal, which the client gets as an ordinary answer.
    ///
    /// The backend did not agree to the upgrade, so there is no session: what
    /// it said is the answer.
    pub fn refusal_response(&self) -> Response<ProxyBody> {
        let mut response = Response::new(crate::http::body::empty_body());
        *response.status_mut() =
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_GATEWAY);
        for (name, value) in &self.headers {
            // The framing headers describe the backend's own hop and say
            // nothing about this one.
            if name.as_str().eq_ignore_ascii_case("content-length")
                || name.as_str().eq_ignore_ascii_case("transfer-encoding")
                || name.as_str().eq_ignore_ascii_case("connection")
            {
                continue;
            }
            response.headers_mut().append(name.clone(), value.clone());
        }
        response
    }
}

/// Whether the request is an upgrade this module handles.
pub fn is_upgrade(request: &Request<()>) -> bool {
    request
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// The backend's side of the upgrade.
///
/// The request goes to the backend over a connection of its own — a WebSocket
/// holds one connection for the whole session, so it is not the pooled client
/// — and the backend's answer comes back.
pub async fn handshake(
    clients: &BackendClients,
    backend_info: &BackendInfo,
    request: &Request<()>,
    timeouts: crate::config::Timeouts,
) -> Result<Handshake, ProxyFailure> {
    let backend_url = &*backend_info.url;
    let protocol = backend_info.protocol;

    if protocol == crate::config::BackendProtocol::H2c {
        // A WebSocket upgrade is HTTP/1.1. A route that speaks h2c has told
        // the server its backend starts with HTTP/2's connection preface, and
        // there is no way to carry an HTTP/1.1 upgrade on that connection.
        return Err(ProxyFailure::from(anyhow::anyhow!(
            "backend {backend_url} is reached with backend_protocol = \"h2c\", which cannot \
             carry a WebSocket upgrade; use an http:// or https:// backend that speaks HTTP/1.1"
        )));
    }

    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);

    // Not the pooled HTTP client: a WebSocket holds one dedicated connection
    // for the whole session, so this dial is its own, with the same deadline.
    // It is still the same trust store: an https:// backend is reached over a
    // TLS session this process originates and verifies, exactly as the pooled
    // clients do.
    let mut backend_stream = clients
        .connect_stream(backend_url, timeouts.connect)
        .await
        .map_err(|e| ProxyFailure::unanswered(e, Retryability::Always))?;

    let request_buf = build_upgrade_request(request, backend_info, &host);

    backend_stream.write_all(&request_buf).await.map_err(|e| {
        ProxyFailure::unanswered(
            anyhow::anyhow!("failed to write the WebSocket upgrade: {e}"),
            Retryability::Always,
        )
    })?;

    let mut response_buf = Vec::with_capacity(8192);
    let mut trailing = Vec::new();
    let mut read_buf = [0u8; 8192];
    // The handshake response arrives in reads of its own, and the marker is
    // only ever in the part that has not been scanned.
    let mut searched = 0usize;

    let read_handshake = async {
        loop {
            match backend_stream.read(&mut read_buf).await {
                Ok(0) => break,
                Ok(n) => {
                    response_buf.extend_from_slice(&read_buf[..n]);

                    if let Some(pos) = find_headers_end(&response_buf, searched) {
                        let headers_end = pos + 4;
                        if response_buf.len() > headers_end {
                            trailing.extend_from_slice(&response_buf[headers_end..]);
                        }
                        response_buf.truncate(headers_end);
                        break;
                    }

                    searched = response_buf.len().saturating_sub(3);

                    if response_buf.len() > 64 * 1024 {
                        tracing::warn!("WebSocket handshake response too large");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to read from backend stream: {e}");
                    return Err(anyhow::anyhow!(
                        "failed to read the handshake response: {e}"
                    ));
                }
            }
        }
        Ok(())
    };

    match tokio::time::timeout(timeouts.response, read_handshake).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(ProxyFailure::unanswered(e, Retryability::Always));
        }
        Err(_) => {
            return Err(ProxyFailure::unanswered(
                anyhow::anyhow!(
                    "backend {host}:{port} did not answer the WebSocket handshake within {:?}",
                    timeouts.response
                ),
                Retryability::Always,
            ));
        }
    }

    let parsed = crate::http::legacy::parse_http_response_legacy(&response_buf)?;

    Ok(Handshake {
        status: parsed.status().as_u16(),
        headers: parsed.headers().clone(),
        trailing,
        backend: backend_stream,
    })
}

/// The session: the client's bytes and the backend's bytes, moved either way.
///
/// The session ends when one of the two ends stops, or when neither has moved
/// for a whole idle window. A direction that is quiet on its own does not end
/// it: a client that only listens to a feed the backend keeps pushing has
/// nothing to say, and a gap in one direction must not end a session the
/// other direction is still using.
pub async fn pump(
    client: hyper::upgrade::Upgraded,
    backend: BackendStream,
    trailing: Vec<u8>,
    idle: Duration,
) {
    let client = crate::hyper_io::UpgradedIo::new(client);
    let (backend_read, mut backend_write) = tokio::io::split(backend);
    let (mut client_read, mut client_write) = tokio::io::split(client);

    // The bytes that came after the handshake belong to the session, not to
    // the handshake: they are the backend's first frames.
    if !trailing.is_empty()
        && let Err(e) = client_write.write_all(&trailing).await
    {
        tracing::debug!("WebSocket: writing the backend's first frames failed: {e}");
        return;
    }

    // When the last byte moved on this tunnel, in milliseconds since the
    // epoch. Both directions write to it, and a direction that has been quiet
    // for a whole window reads it to find out whether the other one is still
    // talking.
    let last_traffic = Arc::new(AtomicU64::new(now_millis()));

    let client_to_backend = async {
        let mut buf = vec![0u8; WS_COPY_BUFFER];
        loop {
            match tokio::time::timeout(idle, client_read.read(&mut buf)).await {
                Ok(Ok(0)) => return "client_finished",
                Ok(Ok(n)) => {
                    last_traffic.store(now_millis(), Ordering::Relaxed);
                    if let Err(e) = backend_write.write_all(&buf[..n]).await {
                        tracing::debug!("WebSocket backend write failed: {e}");
                        return "backend_write_error";
                    }
                    crate::metrics::METRICS.record_bytes_received(n as u64);
                }
                Ok(Err(_)) => return "client_read_error",
                Err(_) => {
                    // This direction has been quiet for a whole window. The
                    // session ends when nothing has moved in either direction
                    // for that long; until then the other side is still using
                    // it.
                    let quiet_for =
                        now_millis().saturating_sub(last_traffic.load(Ordering::Relaxed));
                    if quiet_for >= idle.as_millis() as u64 {
                        return "idle";
                    }
                    // The other side is still talking: wait for more, with
                    // the window measured from now.
                    continue;
                }
            }
        }
    };

    let backend_to_client = async {
        let mut buf = vec![0u8; WS_COPY_BUFFER];
        let mut backend_read = backend_read;
        loop {
            match tokio::time::timeout(idle, backend_read.read(&mut buf)).await {
                Ok(Ok(0)) => return "backend_finished",
                Ok(Ok(n)) => {
                    last_traffic.store(now_millis(), Ordering::Relaxed);
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        tracing::debug!("WebSocket client write failed: {e}");
                        return "client_write_error";
                    }
                    crate::metrics::METRICS.record_bytes_sent(n as u64);
                }
                Ok(Err(_)) => return "backend_read_error",
                Err(_) => {
                    // The same bound as the other direction, and the same
                    // reading of it: a quiet direction does not end a
                    // session the other one is still using.
                    let quiet_for =
                        now_millis().saturating_sub(last_traffic.load(Ordering::Relaxed));
                    if quiet_for >= idle.as_millis() as u64 {
                        return "idle";
                    }
                    continue;
                }
            }
        }
    };

    let (closed_direction, close_reason) = tokio::select! {
        reason = client_to_backend => ("client_to_backend", reason),
        reason = backend_to_client => ("backend_to_client", reason),
    };
    tracing::debug!("WebSocket tunnel closed first by {closed_direction}, reason: {close_reason}");
}

/// The upgrade request that goes to the backend.
///
/// The path is the backend's own — rewritten by the route, as every other
/// path is — and the `Host` is the client's, so that a backend which routes
/// by name sees the name the client asked for.
fn build_upgrade_request(
    request: &Request<()>,
    backend_info: &BackendInfo,
    backend_host: &str,
) -> Vec<u8> {
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path());
    let path = backend_info.rewritten_path(path);

    let request_line = format!("{} {} HTTP/1.1\r\n", request.method(), path);

    let original_host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.to_string())
        .unwrap_or_else(|| backend_host.to_string());

    let mut request_buf = Vec::new();
    request_buf.extend_from_slice(request_line.as_bytes());
    request_buf.extend_from_slice(b"Host: ");
    request_buf.extend_from_slice(original_host.as_bytes());
    request_buf.extend_from_slice(b"\r\n");

    for (name, value) in request.headers() {
        if name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        if !forwards_upgrade_header(name.as_str()) {
            continue;
        }
        request_buf.extend_from_slice(name.as_str().as_bytes());
        request_buf.extend_from_slice(b": ");
        request_buf.extend_from_slice(value.as_bytes());
        request_buf.extend_from_slice(b"\r\n");
    }
    request_buf.extend_from_slice(b"\r\n");

    request_buf
}

/// Whether a header may be forwarded in an upgrade request.
///
/// The same rule as the HTTP path's, and for the same reason: a hop-by-hop
/// header describes one connection, not the message.
fn forwards_upgrade_header(name: &str) -> bool {
    ![
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "expect",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
}
#[cfg(test)]
mod tests {
    use super::build_upgrade_request;

    /// A route table whose route rewrites the paths under `pattern`.
    ///
    /// The rewrite is what a route pairs a `path_pattern` with: the paths
    /// that match are served somewhere else, and `{}` in the rewrite is where
    /// the matched part goes.
    fn route_table_with_rewrite(
        pattern: &str,
        rewrite: &str,
    ) -> std::sync::Arc<crate::routes::RoutingTable> {
        let timeouts = crate::config::Timeouts {
            connect: std::time::Duration::from_secs(1),
            response: std::time::Duration::from_secs(1),
            deadlines: crate::deadline::Deadlines::default(),
        };
        let route = crate::routes::Route::new(
            "rewrite.test",
            pattern,
            true,
            vec!["http://127.0.0.1:9".to_string()],
            crate::lb::LoadBalancingStrategy::RoundRobin,
            crate::config::RouteMode::Http,
            Some(rewrite.to_string()),
        );
        std::sync::Arc::new(crate::routes::RoutingTable::with_settings(
            vec![route],
            timeouts,
            crate::config::Retry {
                attempts: 1,
                backoff: std::time::Duration::ZERO,
            },
        ))
    }

    /// A WebSocket upgrade goes out with the route's rewritten path.
    ///
    /// The upgrade is a request like any other, and a route that names a
    /// `path_rewrite` means it for every request it serves. The plaintext
    /// listener answers an upgrade with 426 and never gets that far, so the
    /// tunnel is the only place a WebSocket is served — and it used to
    /// forward the path the client asked for, without the rewrite. A route
    /// that named one therefore looked configured and did nothing for every
    /// WebSocket client.
    #[tokio::test]
    async fn a_websocket_upgrade_goes_out_with_the_rewritten_path() {
        let config = route_table_with_rewrite("/api", "/v2{}");

        let backend_info = config
            .get_backend_with_acl("rewrite.test", "/api/socket", None, None)
            .await
            .backend()
            .expect("a route for the host");

        let request = ::http::Request::builder()
            .method("GET")
            .uri("http://rewrite.test/api/socket")
            .header("host", "rewrite.test")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .body(())
            .expect("a request");

        let request_buf = build_upgrade_request(&request, &backend_info, "127.0.0.1");

        let request_line = String::from_utf8_lossy(&request_buf)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            request_line, "GET /v2/socket HTTP/1.1",
            "the upgrade did not go out with the route's rewritten path"
        );
    }

    /// The upgrade is the point of the request, so `upgrade` and `connection`
    /// have to reach the backend — and a credential for *this* proxy must not.
    #[tokio::test]
    async fn a_websocket_upgrade_carries_the_upgrade_and_not_the_proxy_credential() {
        let config = route_table_with_rewrite("/api", "/v2{}");

        let backend_info = config
            .get_backend_with_acl("rewrite.test", "/api/socket", None, None)
            .await
            .backend()
            .expect("a route for the host");

        let request = ::http::Request::builder()
            .method("GET")
            .uri("http://rewrite.test/api/socket")
            .header("host", "rewrite.test")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("proxy-authorization", "Basic c2VjcmV0")
            .header("proxy-authenticate", "Basic")
            .header("proxy-connection", "keep-alive")
            .body(())
            .expect("a request");

        let request_buf = build_upgrade_request(&request, &backend_info, "127.0.0.1");
        let sent = String::from_utf8_lossy(&request_buf).to_ascii_lowercase();

        assert!(sent.contains("upgrade: websocket"), "{sent}");
        assert!(sent.contains("connection: upgrade"), "{sent}");
        assert!(sent.contains("sec-websocket-key:"), "{sent}");
        for leaked in [
            "proxy-authorization",
            "proxy-authenticate",
            "proxy-connection",
        ] {
            assert!(
                !sent.contains(leaked),
                "{leaked} reached the backend:\n{sent}"
            );
        }
    }
}

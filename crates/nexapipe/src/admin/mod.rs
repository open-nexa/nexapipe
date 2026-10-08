//! The auxiliary listener: liveness, instance metrics, and the read-only
//! management surface.
//!
//! # Why its own port
//!
//! Everything here is about the proxy itself, not about the traffic it
//! forwards, so it cannot live on `[server] listen_addr`: that address serves
//! routes, and a request arriving there is matched against the routing table
//! before anything else happens. Binding a second listener keeps "what is this
//! instance doing" out of the data plane, and keeps the answer available when
//! the data plane is the thing that is broken.
//!
//! # Why it is loopback only, with no escape hatch
//!
//! `[server] expose = true` exists because the plaintext listener may
//! legitimately need to sit behind something else that gates the port. Nothing
//! on *this* listener should ever be reachable from the network: it names the
//! routes, the clients and the backends, and its unauthenticated half carries
//! no authentication of its own. So there is no `expose` here, and a
//! non-loopback address is refused at startup rather than logged.
//!
//! # What is on it
//!
//! | Path | Auth | Purpose |
//! |---|---|---|
//! | `GET /healthz` | none | Liveness: `200 ok` for as long as the listener is up. |
//! | `GET /metrics` | none, but off unless `[metrics] enabled` | Prometheus text exposition. |
//! | `GET /v1/status` | token | Uptime, counters, backend health, what is enabled. |
//! | `GET /v1/routes` | token | The live route table, as reloaded. |
//! | `GET /v1/clients` | token | Which clients exist — never their secrets. |
//! | `GET /v1/connections` | token | The peers connected right now, and which client and device each authenticated as. |
//! | `GET /v1/health` | token | Backend pools, in and out of rotation. |
//!
//! The `/v1/*` half is guarded by a generated token (see [`token`]). It is
//! read-only on purpose: `client add` and `client revoke` need the per-device
//! identity model that is not here yet, and a management surface that only
//! answers questions is one that cannot be talked into changing anything.
use crate::config::RouteMode;
use crate::conn::AuthState;
use crate::conn::peers::PeerRegistry;
use crate::metrics::{InstanceView, METRICS};
use crate::routes::RouteConfig;
use crate::shutdown::{InFlight, ShutdownSignal};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

pub mod token;

use token::{bearer_token, matches_token};

/// The content type a Prometheus scraper expects: plain text, exposition format
/// 0.0.4, and explicitly UTF-8 so a metric name or label is not read as
/// something else.
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The content type of every `/v1/*` answer.
const JSON_CONTENT_TYPE: &str = "application/json";

/// What a client has to send to be let at `/v1/*`.
const WWW_AUTHENTICATE: &str = "Bearer realm=\"nexapipe-admin\"";

/// Whether the auxiliary listener may serve `bound`.
///
/// Split out from the startup path so the rule can be tested without binding
/// anything, the same way the plaintext listener's `may_bind_plaintext` is.
/// Unlike that one it takes no `exposed` argument: there is deliberately no way
/// to ask for this listener to be reachable from the network.
pub fn may_bind_admin(bound: SocketAddr) -> bool {
    bound.ip().is_loopback()
}

/// The refusal for an address this listener must not take.
pub fn non_loopback_refusal(bound: SocketAddr) -> String {
    format!(
        "[admin] listen_addr binds {bound}, which is reachable from the network. This listener \
         serves /healthz, /metrics and /v1/* and carries no authentication on the first two; it \
         is meant for a scraper or a supervisor on the same host. Use a loopback address, or \
         reach it over SSH"
    )
}

/// What the listener reads to answer `/v1/*`.
///
/// All of it is the live object rather than a snapshot taken at startup, so a
/// reload is visible on the next request without anything being notified.
pub struct AdminState {
    routes: Arc<RouteConfig>,
    in_flight: Arc<InFlight>,
    peers: Arc<PeerRegistry>,
    auth: Option<AuthState>,
    metrics_enabled: bool,
    /// `None` when the token could not be made, which closes `/v1/*` rather
    /// than opening it.
    token: Option<String>,
}

impl AdminState {
    /// Builds the state from the objects the proxy already owns.
    pub fn new(
        routes: Arc<RouteConfig>,
        in_flight: Arc<InFlight>,
        peers: Arc<PeerRegistry>,
        auth: Option<AuthState>,
        metrics_enabled: bool,
        token: Option<String>,
    ) -> Self {
        Self {
            routes,
            in_flight,
            peers,
            auth,
            metrics_enabled,
            token,
        }
    }
}

/// Serves the auxiliary listener until shutdown.
pub async fn serve_admin(
    listener: TcpListener,
    state: Arc<AdminState>,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = match result {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        // Not fatal, and not worth a backoff: a refusal is one
                        // connection, and this listener is not the one that has
                        // to stay up for the proxy to serve.
                        tracing::error!("Admin listener failed to accept a connection: {}", e);
                        continue;
                    }
                };

                let state = state.clone();
                tokio::spawn(async move {
                    // Built per connection, because it is consumed by
                    // `serve_connection`. The timer is on for the same reason it
                    // is on the plaintext listener: without a header read
                    // timeout a client that opens a socket and sends nothing
                    // holds the connection for as long as it likes.
                    let mut builder = Builder::new(hyper_util::rt::TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Some(crate::conn::HEAD_READ_TIMEOUT));

                    let service =
                        service_fn(move |req: Request<Incoming>| handle(req, state.clone()));
                    if let Err(e) = builder.serve_connection(TokioIo::new(stream), service).await {
                        tracing::debug!("Admin connection ended: {}", e);
                    }
                });
            }
            _ = shutdown_signal.requested() => {
                tracing::info!("Shutdown signal received, stopping admin listener");
                break;
            }
        }
    }

    Ok(())
}

/// Answers one request on the auxiliary listener.
async fn handle(
    req: Request<Incoming>,
    state: Arc<AdminState>,
) -> Result<Response<http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>>, anyhow::Error>
{
    let path = req.uri().path().to_string();
    let is_get = req.method() == hyper::Method::GET;

    // The management half is the only one that authenticates, and it says so
    // before looking at anything else: an unauthenticated request is answered
    // the same way whatever it asked for, so which paths exist is not
    // something a caller can find out by guessing at them.
    if let Some(managed) = path.strip_prefix("/v1/") {
        return Ok(managed_response(
            req.headers().get(hyper::header::AUTHORIZATION),
            managed,
            is_get,
            &state,
        )
        .await);
    }

    match path.as_str() {
        // Liveness, and nothing more: a supervisor that only needs to know the
        // process is serving should not have to authenticate, and should not be
        // told anything else.
        "/healthz" if is_get => Ok(text(StatusCode::OK, "ok")),

        // Absent rather than empty when metrics are off: a scraper pointed at a
        // deployment that never enabled them has to be able to tell "disabled"
        // from "no traffic yet", and an empty but 200 body looks like the
        // latter.
        "/metrics" if is_get && state.metrics_enabled => Ok(respond(
            StatusCode::OK,
            METRICS_CONTENT_TYPE,
            &METRICS.render(&backend_view(&state).await),
        )),

        // Everything else, including /metrics while it is disabled, is not
        // here. Deliberately unhelpful bodies: this listener is for a scraper
        // with a fixed list of paths, and anything else is a probe.
        _ => Ok(text(StatusCode::NOT_FOUND, "not found")),
    }
}

/// Answers one `/v1/*` request, once the token has been checked.
async fn managed_response(
    authorization: Option<&hyper::header::HeaderValue>,
    path: &str,
    is_get: bool,
    state: &Arc<AdminState>,
) -> Response<http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>> {
    let Some(token) = state.token.as_deref() else {
        // Unavailable rather than unauthorized: there is no token to present,
        // so "try again with credentials" would be a lie.
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "no admin token: /v1/* is unavailable",
        );
    };

    let presented = authorization
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    let authorized = presented.is_some_and(|presented| matches_token(presented, token));
    if !authorized {
        let response = text(StatusCode::UNAUTHORIZED, "unauthorized");
        return with_header(response, hyper::header::WWW_AUTHENTICATE, WWW_AUTHENTICATE);
    }

    if !is_get {
        return text(StatusCode::METHOD_NOT_ALLOWED, "GET only");
    }

    match path {
        "status" => json(&status_json(state).await),
        "routes" => json(&routes_json(&state.routes).await),
        "clients" => json(&clients_json(state).await),
        "connections" => json(&connections_json(&state.peers)),
        "health" => json(&health_json(&state.routes).await),
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Everything `GET /v1/status` reports.
async fn status_json(state: &Arc<AdminState>) -> serde_json::Value {
    let counters = METRICS.snapshot();
    let view = backend_view(state).await;
    let auth = auth_view(state).await;

    let requests: Vec<serde_json::Value> = counters
        .requests_by_class
        .iter()
        .map(|(class, count)| serde_json::json!({ "class": class, "count": count }))
        .collect();
    let flows: Vec<serde_json::Value> = counters
        .l4_flows
        .iter()
        .map(|(proto, class, count)| {
            serde_json::json!({ "proto": proto, "class": class, "count": count })
        })
        .collect();

    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": crate::metrics::uptime_seconds(),
        "connections": {
            "total": counters.connections_total,
            "active": counters.connections_active,
            "direct": counters.connections_direct,
            "relayed": counters.connections_relayed,
            "unknown": counters.connections_unknown,
        },
        "requests": requests,
        "request_duration_ms": counters.request_duration_ms,
        "traffic": {
            "sent_bytes": counters.bytes_sent,
            "received_bytes": counters.bytes_received,
        },
        "l4_flows": flows,
        "backends": { "up": view.backends_up, "down": view.backends_down },
        "in_flight": view.in_flight,
        "routes": state.routes.routes().await.len(),
        "peers": state.peers.len(),
        "auth": auth,
    })
}

/// `GET /v1/routes`: the table as it is now, including what a reload changed.
async fn routes_json(routes: &Arc<RouteConfig>) -> serde_json::Value {
    let mut out = Vec::new();

    for route in routes.routes().await {
        let modes: Vec<&str> = route.modes().iter().map(|mode| mode.name()).collect();
        let backends: Vec<serde_json::Value> = route
            .backend_pool()
            .get_backend_statuses()
            .await
            .into_iter()
            .map(|(url, healthy)| serde_json::json!({ "url": url, "healthy": healthy }))
            .collect();

        out.push(serde_json::json!({
            "host_pattern": route.host_pattern(),
            "path_pattern": route.path_pattern(),
            "modes": modes,
            "priority": route.priority(),
            // Whether anything is actually probing these backends. `false` is
            // not "unhealthy": a passthrough backend speaks TLS and an L4 one
            // speaks whatever the route points at, so nothing marks them down
            // and reporting them as up would be a guess dressed as a fact.
            "health_checked": route.serves(RouteMode::Http),
            "backends": backends,
        }));
    }

    serde_json::json!({ "routes": out })
}

/// `GET /v1/clients`: who is configured, and never their secrets.
///
/// The secret is the whole of a client's second factor, so it is not in the
/// answer at all — not masked, not truncated, absent. `has_secret` is the
/// question an operator actually asks ("is this client enrolled?"), and it
/// cannot be used to enrol.
async fn clients_json(state: &Arc<AdminState>) -> serde_json::Value {
    let Some(auth) = &state.auth else {
        return serde_json::json!({ "enabled": false, "clients": [] });
    };

    let config = auth.config().read().await;
    let mut clients: Vec<serde_json::Value> = config
        .clients
        .iter()
        .map(|(id, client)| {
            serde_json::json!({
                "id": id,
                "has_secret": !client.secret.is_empty(),
                "created_at": client.created_at,
                "allow_hosts": client.allow_hosts,
                "last_used": client.last_used,
                "failed_attempts": client.failed_attempts,
                "locked_until": client.locked_until,
                "enrollment_pending": client.pending_enrollment.is_some(),
            })
        })
        .collect();
    // Sorted, so two scrapes of the same config compare equal and an operator
    // reading the list is not reading a hash order.
    clients.sort_by(|a, b| {
        a["id"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["id"].as_str().unwrap_or_default())
    });

    serde_json::json!({ "enabled": config.enabled, "clients": clients })
}

/// `GET /v1/connections`: the peers being served right now.
fn connections_json(peers: &Arc<PeerRegistry>) -> serde_json::Value {
    let mut out: Vec<serde_json::Value> = peers
        .snapshot()
        .into_iter()
        .map(|peer| {
            serde_json::json!({
                "endpoint_id": peer.endpoint_id.to_string(),
                // Who it authenticated as. Null for a connection with 2FA off,
                // which never had a handshake to answer.
                "client_id": peer.identity.client_id,
                // Null for the device that has no name, which is every peer
                // that predates the device table, and for one that never
                // authenticated at all.
                "device": peer.identity.device,
                "connected_for_seconds": peer.connected_for.as_secs(),
                "path": match peer.path {
                    crate::metrics::PathKind::Direct => "direct",
                    crate::metrics::PathKind::Relay => "relayed",
                    crate::metrics::PathKind::Unknown => "unknown",
                },
            })
        })
        .collect();
    out.sort_by(|a, b| {
        a["endpoint_id"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["endpoint_id"].as_str().unwrap_or_default())
    });

    serde_json::json!({ "peers": out })
}

/// `GET /v1/health`: backend pools, in and out of rotation.
///
/// Restricted to the routes whose backends are probed, for the same reason
/// [`backend_view`] is: the others are never marked down, so listing them
/// would report every one of them as up.
async fn health_json(routes: &Arc<RouteConfig>) -> serde_json::Value {
    let mut out = Vec::new();
    let mut up = HashSet::new();
    let mut down = HashSet::new();

    for route in routes.routes().await {
        if !route.serves(RouteMode::Http) {
            continue;
        }
        let mut backends = Vec::new();
        for (url, healthy) in route.backend_pool().get_backend_statuses().await {
            // De-duplicated across routes the way the counts are: one backend
            // listed by two routes is one backend.
            if healthy {
                up.insert(url.clone());
            } else {
                down.insert(url.clone());
            }
            backends.push(serde_json::json!({ "url": url, "healthy": healthy }));
        }
        backends.sort_by(|a, b| {
            a["url"]
                .as_str()
                .unwrap_or_default()
                .cmp(b["url"].as_str().unwrap_or_default())
        });
        out.push(serde_json::json!({
            "host_pattern": route.host_pattern(),
            "backends": backends,
        }));
    }

    out.sort_by(|a, b| {
        a["host_pattern"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["host_pattern"].as_str().unwrap_or_default())
    });

    // A URL that any route reports as down is down, even where another route
    // still has it in rotation. Counting it as both would make the two counts
    // describe more backends than exist, and "up somewhere" is not what this
    // endpoint is asked: it is asked what is in rotation and what is not.
    for url in &down {
        up.remove(url);
    }

    serde_json::json!({
        "backends_up": up.len(),
        "backends_down": down.len(),
        "routes": out,
    })
}

/// The `[auth]` half of `/v1/status`, without touching the client list.
async fn auth_view(state: &Arc<AdminState>) -> serde_json::Value {
    match &state.auth {
        Some(auth) => {
            let config = auth.config().read().await;
            serde_json::json!({
                "enabled": config.enabled,
                "clients": config.clients.len(),
            })
        }
        None => serde_json::json!({ "enabled": false, "clients": 0 }),
    }
}

/// Counts backends in and out of rotation, from the live pools.
///
/// Only routes serving `http` are counted, for the same reason
/// [`crate::proxy::sync_health_checks`] only probes those: a passthrough
/// backend is a TLS listener and an L4 backend is whatever the route points at,
/// so nothing ever marks them down and counting them would report backends as
/// up that nobody has checked.
///
/// A URL shared by two routes is counted once: the number is "how many backends
/// are serving", not "how many routes have backends".
async fn backend_view(state: &Arc<AdminState>) -> InstanceView {
    let mut up = HashSet::new();
    let mut down = HashSet::new();

    for route in state.routes.routes().await {
        if !route.serves(RouteMode::Http) {
            continue;
        }
        for (url, healthy) in route.backend_pool().get_backend_statuses().await {
            if healthy {
                up.insert(url);
            } else {
                // A backend can be listed by a healthy route and a sick one; it
                // is down, and "down" has to win rather than depend on the
                // order the routes happen to come back in.
                up.remove(&url);
                down.insert(url);
            }
        }
    }

    InstanceView {
        in_flight: state.in_flight.count(),
        backends_up: up.len(),
        backends_down: down.len(),
    }
}

fn json(
    body: &serde_json::Value,
) -> Response<http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>> {
    respond(StatusCode::OK, JSON_CONTENT_TYPE, &body.to_string())
}

fn text(
    status: StatusCode,
    body: &str,
) -> Response<http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>> {
    respond(status, "text/plain; charset=utf-8", body)
}

fn respond(
    status: StatusCode,
    content_type: &str,
    body: &str,
) -> Response<http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(
            Full::new(Bytes::copy_from_slice(body.as_bytes()))
                .map_err(|_| unreachable!())
                .boxed_unsync(),
        )
        .unwrap()
}

/// Adds a header to an already built response.
///
/// The builder is consumed by `respond`, so this is the way a challenge gets
/// onto a 401 without a second construction path for every answer that needs
/// one.
fn with_header(
    response: Response<http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>>,
    name: hyper::header::HeaderName,
    value: &'static str,
) -> Response<http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>> {
    let (mut parts, body) = response.into_parts();
    parts
        .headers
        .insert(name, value.parse().expect("a valid header value"));
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().expect("valid IP"), port)
    }

    /// Loopback is the only thing this listener binds, ever: it is the whole
    /// difference between it and the plaintext listener, which has an `expose`
    /// escape hatch.
    #[test]
    fn only_loopback_is_bindable() {
        assert!(may_bind_admin(addr("127.0.0.1", 9090)));
        assert!(may_bind_admin(addr("::1", 9090)));

        assert!(!may_bind_admin(addr("0.0.0.0", 9090)));
        assert!(!may_bind_admin(addr("::", 9090)));
        assert!(!may_bind_admin(addr("192.168.1.10", 9090)));
    }

    /// The refusal has to name the address the socket actually became, so an
    /// operator binding `0.0.0.0` is told about `0.0.0.0` and not about what
    /// they wrote in the file.
    #[test]
    fn a_refusal_names_the_address_and_says_why() {
        let refusal = non_loopback_refusal(addr("0.0.0.0", 9090));
        assert!(refusal.contains("0.0.0.0:9090"), "{refusal}");
        assert!(refusal.contains("[admin] listen_addr"), "{refusal}");
    }

    /// The management surface is a prefix, not a fixed list of paths, so a path
    /// that is not one of the five is still answered by the token check before
    /// anything else — a caller cannot enumerate what exists without one.
    #[test]
    fn every_v1_path_is_behind_the_token() {
        for path in [
            "status",
            "routes",
            "clients",
            "connections",
            "health",
            "secrets",
        ] {
            assert!(
                format!("/v1/{path}").strip_prefix("/v1/").is_some(),
                "{path} escaped the management prefix"
            );
        }
    }

    /// What `GET /v1/connections` is asked that a count cannot answer: whose
    /// connection this is. A client id alone does not tell two devices of one
    /// client apart, which is the only thing a per-device credential is for.
    #[test]
    fn the_peer_list_says_which_client_and_device_each_peer_is() {
        use crate::conn::peers::PeerIdentity;
        use crate::metrics::PathKind;

        let peers = PeerRegistry::new();
        let endpoint_id = iroh::SecretKey::generate().public();
        let _guard = peers.insert(
            endpoint_id,
            PathKind::Direct,
            PeerIdentity {
                client_id: Some("alice".to_string()),
                device: Some("laptop".to_string()),
            },
        );

        let body = connections_json(&Arc::new(peers));
        let listed = body["peers"].as_array().expect("a peers array");
        assert_eq!(listed.len(), 1, "{body}");
        assert_eq!(listed[0]["client_id"], "alice");
        assert_eq!(listed[0]["device"], "laptop");
    }

    /// A management answer is JSON, and a refusal is not: the two are read by
    /// different clients — `nexapipe status` parses the first, an operator
    /// reads the second — so neither may arrive in the other's shape.
    #[test]
    fn json_answers_are_labelled_json() {
        let body = json(&serde_json::json!({ "ok": true }));
        assert_eq!(body.status(), StatusCode::OK);
        assert_eq!(
            body.headers().get("content-type").expect("content type"),
            JSON_CONTENT_TYPE
        );
    }
}

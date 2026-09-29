//! The auxiliary listener: liveness and instance metrics.
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
//! routes, the clients and the backends, and it has no authentication of its
//! own on the unauthenticated paths. So there is no `expose` here, and a
//! non-loopback address is refused at startup rather than logged.
//!
//! # What is on it
//!
//! | Path | Purpose |
//! |---|---|
//! | `GET /healthz` | Liveness: `200 ok` for as long as the listener is up. |
//! | `GET /metrics` | Prometheus text exposition, only while `[metrics] enabled` is true. |
//!
//! The management endpoints (`/v1/*`) join it in the next step, behind a token.
use crate::config::RouteMode;
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

/// The content type a Prometheus scraper expects: plain text, exposition format
/// 0.0.4, and explicitly UTF-8 so a metric name or label is not read as
/// something else.
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

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
         serves /healthz and /metrics and carries no authentication of its own; it is meant for a \
         scraper or a supervisor on the same host. Use a loopback address, or reach it over SSH"
    )
}

/// Serves the auxiliary listener until shutdown.
///
/// `routes` and `in_flight` are the live objects the exposition reads from —
/// backend health and the drain count — rather than copies of them, so a
/// reload that changes a pool is visible to the next scrape without anything
/// being notified.
pub async fn serve_admin(
    listener: TcpListener,
    routes: Arc<RouteConfig>,
    in_flight: Arc<InFlight>,
    metrics_enabled: bool,
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

                let routes = routes.clone();
                let in_flight = in_flight.clone();
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

                    let service = service_fn(move |req: Request<Incoming>| {
                        handle(req, routes.clone(), in_flight.clone(), metrics_enabled)
                    });
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
    routes: Arc<RouteConfig>,
    in_flight: Arc<InFlight>,
    metrics_enabled: bool,
) -> Result<Response<http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>>, anyhow::Error>
{
    let path = req.uri().path().to_string();
    let is_get = req.method() == hyper::Method::GET;

    match path.as_str() {
        // Liveness, and nothing more: a supervisor that only needs to know the
        // process is serving should not have to authenticate, and should not be
        // told anything else.
        "/healthz" if is_get => Ok(text(StatusCode::OK, "ok")),

        // Absent rather than empty when metrics are off: a scraper pointed at a
        // deployment that never enabled them has to be able to tell "disabled"
        // from "no traffic yet", and an empty but 200 body looks like the
        // latter.
        "/metrics" if is_get && metrics_enabled => Ok(respond(
            StatusCode::OK,
            METRICS_CONTENT_TYPE,
            &METRICS.render(&backend_view(&routes, &in_flight).await),
        )),

        // Everything else, including /metrics while it is disabled, is not
        // here. Deliberately unhelpful bodies: this listener is for a scraper
        // with a fixed list of paths, and anything else is a probe.
        _ => Ok(text(StatusCode::NOT_FOUND, "not found")),
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
async fn backend_view(routes: &Arc<RouteConfig>, in_flight: &Arc<InFlight>) -> InstanceView {
    let mut up = HashSet::new();
    let mut down = HashSet::new();

    for route in routes.routes().await {
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
        in_flight: in_flight.count(),
        backends_up: up.len(),
        backends_down: down.len(),
    }
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
}

//! The plaintext listener: the one entry point 2FA does not cover.
//!
//! It serves plain HTTP requests to a client on the same host, and it cannot
//! ask for a credential — so what it may bind is decided by the address the
//! socket actually became.

use crate::conn;
use crate::http::BackendClients;
use crate::passthrough;
use crate::routes::RoutingTable;
use crate::shutdown::{InFlight, ShutdownSignal};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::Instrument;

use super::request::proxy_handler;

pub(super) async fn start_http_server(
    listener: TcpListener,
    config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    shutdown_signal: Arc<ShutdownSignal>,
    in_flight: Arc<InFlight>,
    limiters: conn::limits::Limiters,
) -> anyhow::Result<()> {
    // Refusals since the last accepted connection. A listener that has run out
    // of file descriptors fails again the moment it is asked, so without a
    // pause this loop would spend the rest of the process writing log lines.
    let mut refused_in_a_row = 0u32;

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, addr) = match result {
                    Ok(accepted) => {
                        refused_in_a_row = 0;
                        accepted
                    }
                    Err(e) => {
                        // One accept failure used to propagate and take the
                        // listener down for good, while the iroh side carried
                        // on serving: the port went quiet with nothing in the
                        // log to say it had. A refusal is one connection, not
                        // a verdict on the listener.
                        refused_in_a_row += 1;
                        tracing::error!("Plaintext listener failed to accept a connection: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            (refused_in_a_row.min(20) as u64) * 50,
                        ))
                        .await;
                        continue;
                    }
                };
                tracing::debug!("New connection on the plaintext listener from: {}", addr);

                // One process-wide slot per connection, taken as soon as the
                // connection is accepted.
                //
                // The per-peer cap cannot apply here: a plain TCP connection has
                // no `EndpointId`, and a cap keyed on the source address would
                // be a different design — NAT puts many clients behind one
                // address, and IPv6 hands a client an address of its own.
                //
                // The refusal is a close and nothing else. A listener that is
                // over its ceiling has nobody to send a status to, and writing
                // one would be work for a connection that is about to go.
                let Some(slot) = limiters.connections.try_acquire_global() else {
                    let limiter = &limiters.connections;
                    tracing::warn!(
                        "Refusing a connection on the plaintext listener from {addr}, the server is \
                         at {} of {} concurrent connections",
                        limiter.total(),
                        limiter.max_global()
                    );
                    drop(stream);
                    continue;
                };

                let config_clone = config.clone();
                let clients_clone = clients.clone();
                let remote_addr_str = addr.to_string();
                let in_flight_clone = in_flight.clone();
                // Counted here rather than in the task's first line, for the
                // same reason as the iroh accept loop: an accepted connection
                // that is not counted yet is one a shutdown cannot see.
                let guard = in_flight_clone.enter();

                tokio::spawn(async move {
                    // The slot is held for as long as the connection is served,
                    // and given back by the guard's Drop however this task
                    // ends — the same way the in-flight count is.
                    let _slot = slot;
                    let _connection = guard;
                    // One budget for the whole exchange, taken when the
                    // connection is accepted: the wait to tell a TLS session
                    // from an HTTP request is part of the wait for the head,
                    // not time on top of it. A client that has said nothing by
                    // the end of it is closed, rather than held for the
                    // classification wait and then a fresh header budget on
                    // top of that.
                    let deadlines = config_clone.timeouts().deadlines;
                    let head_deadline = tokio::time::Instant::now() + deadlines.header;

                    // The listener speaks HTTP, but a client may also open a
                    // TLS session straight at it. One peeked byte tells the two
                    // apart — a request line can never start with 0x16 — and a
                    // TLS session goes to the passthrough path, since this
                    // process has no key material and never decrypts anything.
                    // The peek waits for whichever budget is longer — the
                    // hello's, or what is left of the head's. Until the first
                    // byte arrives the protocol is unknown, so a short
                    // `header_secs` must not close a TLS session before its
                    // `ClientHello` can say what it is.
                    if is_tls_connection(&stream, head_deadline, deadlines.tls_hello).await {
                        tracing::debug!("TLS session on the plaintext listener from: {}", remote_addr_str);
                        if let Err(e) =
                            passthrough::handle_tcp_stream(stream, Vec::new(), &config_clone).await
                        {
                            tracing::error!("TLS passthrough failed for {}: {}", remote_addr_str, e);
                        }
                        return;
                    }

                    // The timer is not on by default, and without it hyper has no
                    // header read timeout: a client that opens a socket and
                    // sends nothing holds the connection open for as long as it
                    // likes. This is the listener an operator may expose. The
                    // bound is `[timeouts] header_secs` through the routes, and
                    // what is left of it after the classification wait is what
                    // hyper gets — the two are one budget, not two.
                    let remaining = remaining_budget(head_deadline);
                    let mut http_builder = Builder::new(hyper_util::rt::TokioExecutor::new());
                    http_builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Some(remaining));

                    // One id and one span per request. `service_fn` is called
                    // once per request rather than once per connection, which
                    // is what makes the two line up; the handler fills in
                    // `method`, `uri` and `status` as it learns them.
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        let request_id = crate::log::next_request_id();
                        let span = tracing::info_span!(
                            "request",
                            id = %request_id,
                            method = tracing::field::Empty,
                            uri = tracing::field::Empty,
                            status = tracing::field::Empty,
                        );
                        proxy_handler(
                            req,
                            config_clone.clone(),
                            clients_clone.clone(),
                            remote_addr_str.clone(),
                            request_id,
                        )
                        .instrument(span)
                    });

                    let io = TokioIo::new(stream);
                    if let Err(e) = http_builder.serve_connection_with_upgrades(io, service).await {
                        tracing::error!("Failed to serve connection: {}", e);
                    }
                });
            }
            _ = shutdown_signal.requested() => {
                tracing::info!("Shutdown signal received, stopping HTTP server");
                break;
            }
        }
    }
    Ok(())
}

/// Whether the plaintext listener may serve `bound` under this configuration.
///
/// Split out from [`run_proxy`](super::server::run_proxy) so the rule can be tested without binding
/// anything: everything the decision needs is the address the socket became and
/// whether `[server] expose` asked for it.
pub(super) fn may_bind_plaintext(bound: SocketAddr, exposed: bool) -> bool {
    exposed || bound.ip().is_loopback()
}

/// The refusal for an exposed plaintext listener that 2FA cannot protect, if
/// there is one.
///
/// `expose = true` publishes every route and every passthrough backend on an
/// address where no credential is ever asked for — 2FA lives in the iroh accept
/// loop only — so enabling both is refused rather than logged: an error that
/// only turns up in a rotated log is how a firewall nobody remembers configuring
/// becomes the sole thing standing between the network and the backends.
///
/// Split out from [`run_proxy`](super::server::run_proxy) for the same reason as
/// [`may_bind_plaintext`]: the decision is three booleans' worth of input and
/// deserves its own tests. `pub(crate)` because the config watcher asks the same
/// question when a reload turns 2FA on — a reload must not be the way around a
/// check the startup path enforces.
pub(crate) fn plaintext_auth_conflict(
    bound: SocketAddr,
    exposed: bool,
    auth_enabled: bool,
) -> Option<String> {
    (exposed && auth_enabled).then(|| {
        format!(
            "[server] expose = true leaves {bound} unauthenticated even though [auth] is \
             enabled: 2FA only runs on the iroh listener, so this address would reach every \
             route and every passthrough backend without credentials. Gate the port with \
             something else, or disable [auth]"
        )
    })
}

/// What is left of a connection's budget.
///
/// The classification wait is part of the budget rather than time on top of
/// it, so this is what the HTTP server gets for the head: the whole
/// connection, less what the wait for the first byte already spent. A budget
/// that is spent is spent — the result is zero, and the connection is closed
/// rather than given a fresh deadline.
pub(super) fn remaining_budget(deadline: tokio::time::Instant) -> std::time::Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

/// True when the peer opened a TLS session rather than sending a request.
///
/// The peek waits for whichever is longer: `hello`, the budget a TLS client
/// has to start its handshake, or what remains of `deadline`, the budget this
/// connection has for a request head. Until the first byte arrives the
/// protocol is unknown, so the shorter of the two is the wrong answer — a
/// short `header_secs` must not close a TLS session before its `ClientHello`
/// classifies it, which is the same choice `conn::handle_bidi_stream` makes
/// for an iroh stream. A timeout, an EOF or an error all mean "not a TLS
/// session, as far as this listener is concerned": the connection is handed
/// to the HTTP server, which owns the read timeouts and the error responses.
pub(super) async fn is_tls_connection(
    stream: &tokio::net::TcpStream,
    deadline: tokio::time::Instant,
    hello: std::time::Duration,
) -> bool {
    let mut first = [0u8; 1];
    let until = deadline.max(tokio::time::Instant::now() + hello);
    match tokio::time::timeout_at(until, stream.peek(&mut first)).await {
        Ok(Ok(1)) => passthrough::is_tls_handshake(first[0]),
        // EOF, error, or a peer that never sends anything: hand it to the HTTP
        // server, which owns read timeouts and error responses.
        _ => false,
    }
}

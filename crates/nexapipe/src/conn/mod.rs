//! A connection, and the two halves it is made of.
//!
//! A peer opens a connection and says who it is; the server either lets it
//! through or closes it with a reason. What happens after that is the data
//! plane: the streams the connection carries, and what each of them holds.
//!
//! The two halves are two modules, because they are two different things:
//! `auth` is the handshake and the state it authenticates against, and
//! `stream` is one stream of a connection and how it is served.

use crate::auth::ClientAcl;
use crate::http::BackendClients;
use crate::l4;
use crate::metrics;
use crate::routes::RoutingTable;
use crate::shutdown::InFlightGuard;
use futures_util::StreamExt;
use iroh::endpoint::{Connection, Incoming};
use nexapipe_proto::protocol::Protocol;
use peers::{PeerGuard, PeerIdentity, PeerRegistry};
use std::sync::Arc;
use std::sync::OnceLock;
use tracing::Instrument;

pub mod allow_list;
pub mod limits;
pub mod peers;

mod auth;
mod stream;

#[cfg(test)]
mod tests;

use limits::Limiters;

// The two-factor half is a module of its own, and what it holds is still
// reached through `conn`: the state a connection authenticates against, and
// the count of the failures against it.
pub use auth::{
    AuthContext, AuthOutcome, AuthRequest, AuthState, Authenticator, ConfigAuthenticator,
    count_enrollment_failure,
};
// The writer for the state file. The configuration watcher needs it as well:
// a reload that resets a client's enrollment counters has to reach the file
// the next start reads, or the reset is lost on the next restart. It is not
// public API — only the crate's own two halves write that file.
pub(crate) use auth::persist_auth_state;

use auth::{AuthFailure, PeerRegistration, perform_authentication};

// The data plane is a module of its own, and what it holds is still reached
// through `conn`: `handle_bidi_stream` is what a connection hands each of its
// streams to, and `find_headers_end` is what the WebSocket handshake reads the
// backend's answer with.
pub(crate) use stream::find_headers_end;
pub use stream::handle_bidi_stream;

/// How long the server waits for the client to open the 2FA handshake stream.
///
/// A client that has credentials sends AUTH_START right after the QUIC
/// handshake finishes, so in principle this only has to cover one round trip.
/// In practice the deadline also has to absorb the handshake itself: on a slow
/// or relayed link the QUIC handshake plus the client's first stream can take
/// several round trips, and a client that loses this race is closed with
/// `auth_close_code::REQUIRED` — indistinguishable from a client that never had
/// a credential — so it is deliberately generous. Five seconds is still short
/// enough that a peer which completes the QUIC handshake and then sends
/// nothing — one with no 2FA configured — does not keep its connection and the
/// task serving it alive indefinitely.
const AUTH_HANDSHAKE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);

/// Streams one connection may have in flight at once.
///
/// Every accepted bi-stream spawns a task, and `accept_bi` accepts them as fast
/// as the peer opens them, so without a cap here the task count is the peer's
/// choice. `FlowLimiter` covers L4 flows only; HTTP, WebSocket and passthrough
/// streams take this one. Sized to match the L4 default so the two read as one
/// policy on how much a single connection may ask for.
const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 256;

/// Application error codes the server closes a connection with when 2FA fails.
///
/// These travel in the CONNECTION_CLOSE frame, so a client can read them from
/// its `close_reason()` and tell "you never authenticated" apart from "your code
/// was rejected" — the difference between a misconfigured client and a wrong
/// TOTP code.
///
/// The numbers themselves live in [`nexapipe_proto::auth::close_code`], which
/// the client links too. They used to be written down here and kept in step
/// with the client's copy by a comment in each, which is the whole failure
/// mode of a protocol written down twice: a code changed on one side and not
/// the other is a client that reports a mysterious connection loss instead of
/// the reason it was given one.
pub(crate) use nexapipe_proto::auth::close_code as auth_close_code;

/// The current time in milliseconds, from a fixed base.
///
/// The WebSocket tunnel has to know when the last byte moved, and it has to
/// know it from two tasks at once, so the answer has to fit in an atomic.
///
/// The base is a **monotonic** clock, and it has to be: this measures an
/// interval, and the wall clock can step. A step backwards would suspend the
/// bound — the session would never be found quiet — and a step forwards
/// would end a session that was still carrying traffic.
pub(crate) fn now_millis() -> u64 {
    static BASE: OnceLock<std::time::Instant> = OnceLock::new();
    let base = BASE.get_or_init(std::time::Instant::now);
    base.elapsed().as_millis() as u64
}
fn get_connection_type(path: &iroh::endpoint::Path<'_>) -> &'static str {
    if path.is_ip() {
        "Direct"
    } else if path.is_relay() {
        "Relay"
    } else {
        "Unknown"
    }
}

/// Which metrics bucket a path belongs to.
///
/// The same three-way distinction [`get_connection_type`] makes for the log,
/// as the type the counters are keyed by.
fn path_kind(path: &iroh::endpoint::Path<'_>) -> metrics::PathKind {
    if path.is_ip() {
        metrics::PathKind::Direct
    } else if path.is_relay() {
        metrics::PathKind::Relay
    } else {
        metrics::PathKind::Unknown
    }
}

/// Keeps one connection's place in the `connections_by_path` buckets up to
/// date, for as long as the connection lives.
///
/// The ticket is created here and handed back by its `Drop` when this task
/// ends, which is when the path stream ends, which is when the connection is
/// gone: a connection that disappears without a clean close therefore still
/// stops being counted.
async fn track_connection_path(
    conn: Connection,
    initial: metrics::PathKind,
    peer: iroh::EndpointId,
    peers: Arc<PeerRegistry>,
) {
    let mut ticket = metrics::PathTicket::new(initial);

    // Snapshots rather than individual path events: `paths_stream` yields the
    // full current state on every change, so a burst of changes cannot leave
    // the bucket one event behind the way a lagged event stream could.
    let mut stream = conn.paths_stream();
    while let Some(paths) = stream.next().await {
        if let Some(path) = paths.iter().find(|p| p.is_selected()) {
            let kind = path_kind(&path);
            ticket.set(kind);
            // The same fact, in the place that can say *which* peer it is
            // about: a count can tell you two connections are relayed, not
            // that they are these two.
            peers.set_path(&peer, kind);
        }
    }
}

pub async fn handle_connection(
    conn: Connection,
    config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    auth_state: Option<AuthState>,
    peers: Arc<PeerRegistry>,
    limiters: Limiters,
) {
    let peer_id = conn.remote_id();
    let peer = peer_id.to_string();
    tracing::info!("New connection from peer: {}", peer_id);

    // **What this connection carries**, from the handshake.
    //
    // A client that names its protocol with ALPN has said so before a byte
    // was read, so the server does not have to guess: the first byte of a
    // stream is the protocol's, and there is nothing to sniff. A client that
    // named the old ALPN is served the way it always was, by the first byte
    // of each stream.
    let alpn = conn.alpn();
    let protocol = if alpn.is_empty() {
        // No ALPN at all: the peer named none, and the old way is the safe
        // reading of that.
        Protocol::Legacy
    } else {
        match Protocol::from_alpn(alpn) {
            Some(protocol) => protocol,
            None => {
                // An ALPN this build does not know. The connection asked for
                // something that cannot be served here, and serving it as
                // something else would be guessing.
                tracing::warn!(
                    "Connection from {} speaks a protocol this server does not know; closing it",
                    peer_id
                );
                return;
            }
        }
    };
    tracing::debug!("Connection from {} speaks {}", peer_id, protocol.name());

    // One counter for the whole connection: the L4 path hands out a slot per flow and
    // answers `TooManyFlows` once it is full, so a client with many UDP flows fails the
    // one that does not fit instead of blocking inside `open_bi`.
    let limiter = Arc::new(l4::FlowLimiter::new(l4::DEFAULT_MAX_FLOWS_PER_CONNECTION));

    // A second counter covering every stream, not just L4 flows: `accept_bi`
    // below spawns a task per stream whatever the stream turns out to be, and
    // the limiter above is only consulted once the bytes say "L4".
    let stream_slots = Arc::new(tokio::sync::Semaphore::new(
        MAX_CONCURRENT_STREAMS_PER_CONNECTION,
    ));

    let paths = conn.paths();
    let selected_path = paths.iter().find(|p| p.is_selected());
    let initial_kind = match &selected_path {
        Some(path) => {
            tracing::info!("Initial connection type: {}", get_connection_type(path));
            path_kind(path)
        }
        None => {
            tracing::info!("Initial connection type: Unknown (no selected path)");
            metrics::PathKind::Unknown
        }
    };

    // Counted here, where the connection is being served, rather than in the
    // accept loop: a connection refused by the limiter never gets this far and
    // should not appear as one that was served.
    metrics::METRICS.connection_opened();
    // A connection typically starts relayed and becomes direct once hole
    // punching succeeds, so the bucket it belongs to is not decided once. The
    // task owns the ticket and hands it back when the connection ends.
    tokio::spawn(track_connection_path(
        conn.clone(),
        initial_kind,
        peer_id,
        peers.clone(),
    ));

    // ===== 2FA Authentication Handshake =====
    //
    // Resolved before the block, not inside an `if let` condition: the read
    // guard has to be gone by the time `perform_authentication` asks for the
    // write lock, and holding a read guard across that would deadlock the
    // endpoint's own RwLock.
    //
    // `enabled` is read here, once per connection, which is also where a reload
    // that turns 2FA on takes effect: the value is live, so a connection opened
    // after that reload is gated. A connection already carrying a `client_acl`
    // is not re-gated mid-flight — its authorization was decided at its own
    // handshake, the same rule that lets a deleted client finish an open
    // connection.
    let auth = match &auth_state {
        Some(auth) => {
            let enabled = auth.config().read().await.enabled;
            if enabled { Some(auth) } else { None }
        }
        None => None,
    };
    // The authenticated client's host authorization, snapshotted at the
    // handshake and carried by every stream this connection opens. `None`
    // means no 2FA ran, which is the unrestricted case anyway.
    let mut client_acl: Option<Arc<ClientAcl>> = None;
    // Who the connection turned out to be, for the peer list. Filled in only
    // when 2FA ran and passed: with it off there is no handshake, and no
    // identity to report.
    let mut identity = PeerIdentity::default();
    // What keeps the connection in the peer registry, filled in by whichever
    // path registers it: the handshake when 2FA ran, the fallback below when it
    // did not.
    let mut registered: Option<(PeerGuard, tokio::sync::watch::Receiver<bool>)> = None;

    if let Some(auth) = auth {
        let outcome = tokio::time::timeout(
            AUTH_HANDSHAKE_TIMEOUT,
            perform_authentication(
                &conn,
                auth,
                &peer,
                PeerRegistration {
                    registry: peers.clone(),
                    endpoint_id: peer_id,
                    path: initial_kind,
                },
            ),
        )
        .await;
        match outcome {
            Ok(Ok(authenticated)) => {
                tracing::info!(
                    "Client '{}' authenticated successfully from {}",
                    authenticated.client_id,
                    peer_id
                );
                identity = PeerIdentity {
                    client_id: Some(authenticated.client_id.clone()),
                    device: authenticated.device,
                };
                client_acl = Some(Arc::new(authenticated.acl));
                registered = Some((authenticated.guard, authenticated.revoked));
            }
            Ok(Err(AuthFailure::Rejected(reason))) => {
                tracing::warn!("Authentication failed for {}: {}", peer_id, reason);
                conn.close(
                    auth_close_code::REJECTED.into(),
                    b"2FA authentication failed",
                );
                return;
            }
            Ok(Err(AuthFailure::NotStarted(reason))) => {
                // The client never offered credentials, which usually means
                // it has no 2FA configured at all: the close code is what
                // tells it so, since it is not reading anything else.
                tracing::warn!(
                    "Connection from {} refused, 2FA is required: {}",
                    peer_id,
                    reason
                );
                conn.close(auth_close_code::REQUIRED.into(), b"2FA required");
                return;
            }
            Err(_) => {
                tracing::warn!(
                    "Connection from {} refused, no 2FA handshake within {}s",
                    peer_id,
                    AUTH_HANDSHAKE_TIMEOUT.as_secs()
                );
                conn.close(auth_close_code::REQUIRED.into(), b"2FA required");
                return;
            }
        }
    }
    // ===== Authentication Complete =====
    //
    // Listed from here, not from the top of the function: a peer that was
    // refused its handshake never got a connection, and `GET /v1/connections`
    // is asked "who is connected", not "who tried". The path may be corrected a
    // moment later by the tracker above, which keeps following it.
    // The registry keeps its own copy: the identity below is also what every
    // stream of this connection writes into the access log.
    //
    // Its other half is how `client revoke` reaches a connection rather than
    // only the next dial: the config watcher flips it, and the loop below stops
    // serving this peer and hangs up.
    //
    // When 2FA ran, the channel and the guard come from the handshake, which
    // registered this connection while it still held the auth lock. Only a
    // server with 2FA off reaches the fallback, and there is nothing to be
    // revoked there — no credential was checked, so no reload can drop one.
    let (mut revoked_rx, _peer) = match registered {
        Some((guard, revoked)) => (revoked, guard),
        None => {
            // **The gate may have come on since the check above.** A reload
            // that turns 2FA on closes the connections that never
            // authenticated, and this one is not in the registry yet — so it
            // has to be refused here, or it would go on serving with no
            // credential at all.
            //
            // The value is read again rather than carried from the check
            // above: that check is what decided this connection skipped the
            // handshake, and it is stale by the time the handshake would
            // have been over.
            let gated_now = match &auth_state {
                Some(auth) => auth.config().read().await.enabled,
                None => false,
            };
            if gated_now {
                tracing::warn!(
                    "Connection from {} refused, 2FA was turned on while it was connecting",
                    peer_id
                );
                conn.close(auth_close_code::REQUIRED.into(), b"2FA required");
                return;
            }
            let (revoked_tx, revoked_rx) = tokio::sync::watch::channel(false);
            (
                revoked_rx,
                peers.insert(peer_id, initial_kind, identity.clone(), revoked_tx),
            )
        }
    };

    loop {
        // Whichever happens first wins, and a revocation that arrives while a
        // stream is being accepted loses nothing: the connection is closed in
        // the next line whether the accept completed or not.
        let accepted = tokio::select! {
            accepted = conn.accept_bi() => accepted,
            // Either the value changed, or every sender is gone — which can
            // only mean this loop outlived its own registry entry, and both
            // say the same thing: stop serving this peer.
            _ = revoked_rx.changed() => {
                tracing::info!(
                    "Closing {}: its credential is no longer in [auth]",
                    peer_id
                );
                conn.close(auth_close_code::REVOKED.into(), b"credential revoked");
                return;
            }
        };

        match accepted {
            Ok((send, recv)) => {
                // Refused rather than queued: waiting for a slot would only move
                // the unbounded growth into a backlog this loop cannot see, and
                // the peer has to learn that its stream was not served.
                //
                // Two ceilings, checked together and for different reasons: the
                // per-connection one keeps one connection from asking for the
                // whole process's allowance, and the process-wide one keeps a
                // crowd of connections from doing it between them. The process
                // slot is taken first and given back if the connection's own is
                // full, because the reverse order would leave a permit held for
                // a stream that is never served.
                let global_permit = match limiters.streams.try_acquire() {
                    Some(permit) => permit,
                    None => {
                        tracing::warn!(
                            "Refusing a stream from {peer_id}, the server already has {} streams \
                             in flight",
                            limiters.streams.max_global()
                        );
                        let mut send = send;
                        let _ = send.finish();
                        continue;
                    }
                };
                let Ok(permit) = stream_slots.clone().try_acquire_owned() else {
                    drop(global_permit);
                    tracing::warn!(
                        "Connection {} already has {} streams in flight, closing this one",
                        peer_id,
                        MAX_CONCURRENT_STREAMS_PER_CONNECTION
                    );
                    let mut send = send;
                    let _ = send.finish();
                    continue;
                };
                let config_clone = config.clone();
                let clients_clone = clients.clone();
                let limiter_clone = limiter.clone();
                let peer_clone = peer.clone();
                let acl_clone = client_acl.clone();
                // Who the connection turned out to be, for the access log.
                // Cloned per stream rather than shared, because the task owns
                // everything it reads.
                let who_clone = identity.clone();
                // One id and one span per **stream**.
                //
                // A stream is not a request: the L4 tunnel and the TLS
                // session carry a flow, and the flow is what this id and this
                // span describe. The L4 path fills `method`, `uri` and
                // `status` in on `Span::current()` as it learns them.
                //
                // **The request path does not use this id.** Hyper serves
                // keep-alive requests on one stream, so one stream may carry
                // several requests, and an id minted here would be the id of
                // every one of them. The request path mints an id per request
                // instead — see `http::server::serve`, which does it in the
                // service closure hyper calls once per request.
                let stream_id = crate::log::next_request_id();
                let span = tracing::info_span!(
                    "stream",
                    id = %stream_id,
                    method = tracing::field::Empty,
                    uri = tracing::field::Empty,
                    status = tracing::field::Empty,
                );
                tokio::spawn(async move {
                    // Held for the life of the task and released by its Drop, so
                    // a slot frees however the stream ends. Both permits, for the
                    // same reason and in the same way.
                    let _permit = permit;
                    let _global_permit = global_permit;
                    if let Err(e) = handle_bidi_stream(
                        send,
                        recv,
                        config_clone,
                        clients_clone,
                        &limiter_clone,
                        &peer_clone,
                        acl_clone,
                        &stream_id,
                        who_clone,
                        protocol,
                    )
                    .instrument(span)
                    .await
                    {
                        tracing::error!("Failed to handle stream from {}: {}", peer_clone, e);
                    }
                });
            }
            Err(e) => {
                if e.to_string().contains("closed by peer") {
                    tracing::debug!("Connection {} closed by peer", peer_id);
                } else {
                    tracing::warn!("Connection {} stream accept error: {}", peer_id, e);
                }
                break;
            }
        }
    }

    tracing::info!("Connection closed for peer: {}", peer_id);
}

/// `in_flight` is the guard the accept loop took for this connection. It has to
/// travel all the way into the task that serves the connection: the drain at
/// shutdown counts these, and a guard dropped when the accept returns would
/// make it count only connections still being accepted — every established
/// one, including WebSocket sessions and L4 flows, would be invisible to it and
/// cut off the moment the process decided to stop.
pub async fn handle_incoming(
    incoming: Incoming,
    config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    auth_state: Option<AuthState>,
    limiters: Limiters,
    in_flight: InFlightGuard,
    peers: Arc<PeerRegistry>,
) {
    match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => {
                // Checked as soon as the id is known, before the 2FA handshake
                // and before the connection task exists: a peer that has already
                // spent its allowance gets a close frame and nothing else, so
                // opening connections is not a way to make the server work.
                let peer_id = conn.remote_id();
                let Some(guard) = limiters.connections.try_acquire(peer_id) else {
                    // Both ceilings refuse here and the two mean different
                    // things to whoever has to answer the alert: one peer is
                    // over its own allowance, or the process is full. Say
                    // which, or the second reads as the first.
                    let limiter = &limiters.connections;
                    let per_peer = limiter.count(&peer_id);
                    let total = limiter.total();
                    if per_peer >= limiter.max() {
                        tracing::warn!(
                            "Refusing connection from {peer_id}, it already holds {per_peer} of {}",
                            limiter.max()
                        );
                    } else {
                        tracing::warn!(
                            "Refusing connection from {peer_id}, the server is at {total} of {} \
                             concurrent connections",
                            limiter.max_global()
                        );
                    }
                    conn.close(auth_close_code::TOO_MANY.into(), b"too many connections");
                    return;
                };
                tokio::spawn(async move {
                    // Held for as long as the connection is served, and released
                    // by the guard's Drop however this task ends: the limiter
                    // one for the peer's allowance, the in-flight one so a
                    // shutdown knows this connection is still here.
                    let _guard = guard;
                    let _in_flight = in_flight;
                    handle_connection(conn, config, clients, auth_state, peers, limiters).await;
                });
            }
            Err(e) => {
                tracing::error!("Failed to complete connection: {}", e);
            }
        },
        Err(e) => {
            tracing::error!("Failed to accept incoming connection: {}", e);
        }
    }
}

//! The connection pool: the connections this client holds for a backend, and
//! the rules that decide which of them a flow may ride.
//!
//! The pool is a module of its own. What it holds is still reached through
//! `connection_pool`, and the pieces it is made of are the subjects it is
//! made of: the pool itself and its dial path, the rules that select a
//! connection, and the watcher that watches the paths.

use iroh::endpoint::Connection;
use iroh::{EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use std::sync::Arc;

use crate::ClientError;
use crate::auth::TwoFactorAuth;
use nexapipe_proto::protocol::{Protocol, offered_alpns};

mod borrow;
mod dial;
mod link_status;
mod path_watcher;
mod paths;
mod pool;
mod selection;

// The status of a link and the borrow of a connection are modules of their
// own, and what they hold is still reached through `connection_pool`.
pub use borrow::{Borrow, BorrowState, BorrowedConnection};
pub use link_status::{LinkKind, LinkStatus, encode_link_status};
pub use pool::IrohConnectionPool;

// The rules the pieces and the tests share are named here, so that they are
// still reached through `connection_pool` — where they were before the pool
// became a module of its own. The tests are the only ones that reach them
// from here; the pieces hold their own.
#[cfg(test)]
use path_watcher::may_publish;
#[cfg(test)]
use pool::drop_stale_connections;
#[cfg(test)]
use selection::{PoolRefusal, connections_for, may_pool};

/// The ALPNs this client offers the server.
///
/// **The protocol it wants first**, and the two names a server of another
/// vintage understands beside it: the generic one, which says "the first byte
/// of each stream decides", and the spelling that predates the prefix byte
/// being dropped.
///
/// The order of the *offer* does not decide anything — QUIC's negotiation
/// picks the first of the **accept side's** entries that the peer also
/// offers — so what matters is that the server's list has the per-protocol
/// names in front of the generic one, and that the client offers the one it
/// wants.
///
/// The list itself is written down once, in the crate the server links too.
pub fn alpns(protocol: Protocol) -> Vec<Vec<u8>> {
    offered_alpns(protocol)
}

/// What a dial produced: the connection and the state its flows share, or
/// the failure that stopped it.
///
/// The state travels with the connection because the waiters for a shared
/// dial each borrow it — a hundred flows on one connection are a hundred
/// borrows, and the pool has to be able to say so.
type DialOutcome = Result<(Connection, Arc<BorrowState>), ClientError>;

/// How many connections the pool keeps **per protocol**.
///
/// A connection carries one protocol — the one it was opened with — so the
/// ceiling is counted per protocol: a protocol that needs a connection of its
/// own is not refused because another protocol's connections are sitting in the
/// pool. The pool therefore holds at most this many of each protocol, and at
/// most this many times the number of protocols in all.
///
/// It used to be one ceiling for the pool as a whole, which counted the
/// connections of one protocol against another's. A connection opened for HTTP
/// cannot carry an L4 flow, so it cannot stand in for one, and the protocol
/// that needed a connection was refused while the others' connections sat
/// idle.
///
/// Ten per protocol is the same headroom one protocol had before, and the pool
/// reaches the second connection only when the first is full or has died — so
/// this is the tail of a tail, per protocol.
const MAX_CONNECTIONS_PER_PROTOCOL: usize = 10;
const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Idle connections older than this are evicted when a new connection is requested.
const CONNECTION_IDLE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);
/// Interval of the background watcher that removes closed/stale connections from the pool.
const CONNECTION_CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);
/// How often the round-trip time is re-read.
///
/// A second is quick enough for a figure that reads as "now" and slow enough
/// to be free: iroh keeps the estimate in memory and reading it is a lookup.
const RTT_POLL_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(1);
/// Budget for the connect half of a preconnect.
///
/// Deliberately shorter than [`PRECONNECT_TIMEOUT`]: the caller cancels the whole
/// preconnect at its own deadline, and a cancelled connect reports nothing — so a
/// node that hangs stayed silent, which is exactly the case that needs explaining.
/// With a smaller budget here, the timeout (or iroh's error) surfaces in the log.
const PRECONNECT_CONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(6);

/// How long a freshly established connection is watched for a 2FA refusal when
/// this client has no credentials.
///
/// Only such a client needs it: one with credentials fails the handshake itself
/// and knows at once. Without credentials the QUIC handshake succeeds and
/// nothing else happens, so the server is the only party that knows the
/// connection is unusable — it says so by closing once its own handshake
/// deadline (`AUTH_HANDSHAKE_TIMEOUT` in `crates/nexapipe/src/conn/mod.rs`)
/// passes. This wait covers that deadline plus a round trip, so it has to stay
/// above the server's constant — raising one without the other silently turns
/// "the server requires 2FA" back into "the backend looks unreachable".
const AUTH_REQUIRED_GRACE: tokio::time::Duration = tokio::time::Duration::from_secs(6);

/// Budget for one preconnect / warm-up, covering both of its halves.
///
/// This is the whole of what [`IrohConnectionPool::preconnect`] may spend, not
/// only the connect: [`AUTH_REQUIRED_GRACE`] belongs *inside* the preconnect
/// rather than after it. It used to sit outside, with the connect alone
/// budgeted at 8s, so a backend that took more than two seconds to answer was
/// cancelled in the middle of being observed and reported unreachable for
/// being slow.
///
/// It has to hold both halves. Shortening the observation is its own failure —
/// a backend that demands 2FA starts to look like one that is merely
/// unreachable, with the reason lost — which is why this is the sum and not
/// something tighter.
pub(crate) const PRECONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(12);

/// Both halves have to fit, or the observation is what gets cut.
const _: () = assert!(
    PRECONNECT_TIMEOUT.as_secs()
        >= PRECONNECT_CONNECT_TIMEOUT.as_secs() + AUTH_REQUIRED_GRACE.as_secs()
);

/// The application error code the server closes a connection with when it
/// requires 2FA the client never performed.
///
/// The number lives in [`nexapipe_proto::auth::close_code`], which the server
/// links too.
const AUTH_REQUIRED_CLOSE_CODE: u32 = nexapipe_proto::auth::close_code::REQUIRED;

/// The application error code the server closes a connection with when a
/// `[peers]` allow-list refuses this Node ID. The number lives in
/// [`nexapipe_proto::auth::close_code`], which the server links too.
///
/// Reached from a different place than the 2FA codes: the server refuses inside
/// the QUIC handshake, so `connect` itself fails rather than a later stream. The
/// preconnect has to read the close reason from that failure to turn "connection
/// lost" into a cause the operator can act on.
const PEER_NOT_ALLOWED_CLOSE_CODE: u32 = nexapipe_proto::auth::close_code::PEER_NOT_ALLOWED;

/// Whether a credential change is a change of identity.
///
/// A connection is authenticated as whoever the handshake ran for, and the
/// handshake runs once per connection — so a connection made under the old
/// credential keeps serving traffic under the old identity after the
/// credential has been replaced. The connections are closed when the identity
/// changes.
///
/// A rotated secret is the same account with a different secret, and the
/// connections still stand for it: dropping the pool for that would close
/// every connection in flight over a rotation that changes nothing about who
/// they are.
///
/// Split out of [`IrohConnectionPool::set_two_factor`] so the decision can be
/// tested without an endpoint: a connection needs one, a rule does not.
fn identity_changed(before: Option<&TwoFactorAuth>, after: Option<&TwoFactorAuth>) -> bool {
    before.map(|a| a.identity()) != after.map(|a| a.identity())
}

pub fn parse_endpoint_addr(
    server_node_id: Option<&str>,
    server_ticket: Option<&str>,
) -> Result<EndpointAddr, crate::error::ClientError> {
    if let Some(node_id_str) = server_node_id {
        let endpoint_id: EndpointId = node_id_str.parse().map_err(|e| {
            crate::error::ClientError::ParseError(format!("Failed to parse server_node_id: {}", e))
        })?;
        Ok(endpoint_id.into())
    } else if let Some(ticket_str) = server_ticket {
        if let Ok(ticket) = ticket_str.parse::<EndpointTicket>() {
            Ok(ticket.into())
        } else {
            let endpoint_id: EndpointId = ticket_str.parse().map_err(|e| {
                crate::error::ClientError::ParseError(format!(
                    "Failed to parse as ticket or node ID: {}",
                    e
                ))
            })?;
            Ok(endpoint_id.into())
        }
    } else {
        Err(crate::error::ClientError::InvalidConfig(
            "Either server_node_id or server_ticket must be provided".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests;

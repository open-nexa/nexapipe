//! The rules that select a connection for a flow, and the ceiling they keep
//! the pool under.

use nexapipe_proto::protocol::Protocol;

use super::MAX_CONNECTIONS_PER_PROTOCOL;

/// How many of the pool's connections carry `protocol`.
///
/// The count is per protocol, because a connection carries exactly one: a
/// connection opened for HTTP cannot carry an L4 flow, so the two cannot take
/// each other's place.
pub(super) fn connections_for(protocol: Protocol, held: impl Iterator<Item = Protocol>) -> usize {
    held.filter(|each| *each == protocol).count()
}

/// Whether the pool will take one more connection for `protocol`.
///
/// A protocol is refused when **its own** connections are at the ceiling, not
/// when the pool as a whole is: the connections of another protocol cannot
/// carry this one's flows, so they cannot stand in for it.
pub(super) fn may_pool(protocol: Protocol, held: impl Iterator<Item = Protocol>) -> bool {
    connections_for(protocol, held) < MAX_CONNECTIONS_PER_PROTOCOL
}

/// Why a connection could not be put in the pool.
///
/// The three are different failures and they read differently: one is a
/// connection that was gone before it could be used, one is a pool with no
/// room left in it, and one is a connection that belongs to an identity the
/// operator has replaced.
pub(super) enum PoolRefusal {
    /// The connection was already closed.
    Closed,
    /// The pool holds as many connections of this protocol as it may.
    Full,
    /// The credential was replaced while the connection was being made.
    ///
    /// The connection is authenticated as an identity that is gone, so it
    /// is closed rather than pooled — and the caller is told, because
    /// handing it out would hand out the old identity with it.
    Replaced,
}

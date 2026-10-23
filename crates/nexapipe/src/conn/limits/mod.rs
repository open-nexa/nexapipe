//! Limits on the connections the server handles at once.
//!
//! 2FA answers *who* may connect; this answers *how much*. A peer that has
//! authenticated — or one that is never asked to, because `[auth] enabled` is
//! false — can otherwise open connections until the process runs out of memory
//! and tasks, and one QUIC handshake is cheap enough to get there fast.
//!
//! There are two ceilings, and they answer different questions. The per-peer one
//! is what makes one hostile or simply broken peer unable to crowd out the rest,
//! and a peer id is the only thing about a connection the server knows before it
//! has read anything. The global one is what keeps the *process* inside a
//! budget: an [`EndpointId`](iroh::EndpointId) is a public key, so a caller
//! can generate as many peers as it likes, and per-peer limits alone make the
//! total a product of "64 times however many identities you care to invent".
//! Neither ceiling subsumes the other, which is why both are here.

// The four pieces of it: where the ceilings come from, the connections they
// bound, the streams they bound, and the bytes they bound.
mod budget;
mod config;
mod connections;
mod streams;

#[cfg(test)]
mod tests;

pub use budget::{
    ByteBudget, ByteReservation, DEFAULT_MAX_BODY_BYTES_GLOBAL, body_budget, init_body_budget,
};
pub use config::{EnvCaps, Limits, LimitsConfig};
pub use connections::{
    ConnectionLimiter, DEFAULT_MAX_CONNECTIONS_GLOBAL, DEFAULT_MAX_CONNECTIONS_PER_PEER,
    GlobalGuard, PeerGuard,
};
pub use streams::{DEFAULT_MAX_STREAMS_GLOBAL, StreamLimiter};

use std::sync::Arc;

/// The two ceilings a connection has to get past, bundled because they are one
/// decision.
///
/// Held together rather than passed as two arguments: they answer one question
/// — how much this process is doing at once — and every accept path needs both.
/// A future third ceiling then has somewhere to go that is not a ninth
/// parameter on `handle_incoming`.
#[derive(Clone)]
pub struct Limiters {
    pub connections: Arc<ConnectionLimiter>,
    pub streams: Arc<StreamLimiter>,
    /// The ceiling on request bodies these limiters were built with.
    ///
    /// Carried here rather than read from the process-wide budget when
    /// [`Self::describe`] needs it: the budget is a static the HTTP path
    /// reaches without a config, and a type that describes its own ceilings
    /// should report the ones it was given rather than whatever the static
    /// happens to hold.
    pub max_body_bytes: usize,
}

impl Limiters {
    /// The ceilings the server runs with, resolved once at startup.
    pub fn from_limits(limits: &Limits) -> Self {
        Self {
            connections: Arc::new(ConnectionLimiter::with_caps(
                limits.max_connections_per_peer,
                limits.max_connections_global,
            )),
            streams: Arc::new(StreamLimiter::new(limits.max_streams_global)),
            max_body_bytes: limits.max_body_bytes,
        }
    }

    /// A line for the startup log, so an operator can see every ceiling the
    /// process is running with in one place.
    pub fn describe(&self) -> String {
        format!(
            "{} concurrent connections per peer, {} across the process, {} streams across the \
             process, {} bytes of request bodies across the process",
            self.connections.max(),
            self.connections.max_global(),
            self.streams.max_global(),
            self.max_body_bytes
        )
    }
}

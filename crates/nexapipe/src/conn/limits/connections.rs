//! The connections one peer may hold, and the ones the process may hold.
//!
//! Two ceilings, because they answer different questions: the per-peer one
//! keeps one peer from crowding out the rest, and the global one keeps the
//! process itself inside a budget. Neither stands in for the other, and both
//! are checked under one lock so that a connection passes both at once.

use iroh::EndpointId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Concurrent connections one peer may hold, unless the config or the environment
/// overrides it.
///
/// Deliberately generous: the client pool opens a connection per in-flight
/// request, so a busy client holds several at once. This is here to stop a peer
/// from holding thousands, not to shape traffic.
pub const DEFAULT_MAX_CONNECTIONS_PER_PEER: usize = 64;

/// Concurrent connections the whole process may hold, unless the config or the
/// environment overrides it.
///
/// A multiple of [`DEFAULT_MAX_CONNECTIONS_PER_PEER`] rather than a round number:
/// it reads as "the peers you would plausibly have, each at its own cap", which
/// is the sizing this is defending. A deployment with 64 legitimate clients is
/// unaffected by the default; one with several thousand is the deployment where
/// this number should have been written down.
pub const DEFAULT_MAX_CONNECTIONS_GLOBAL: usize = 64 * 64;

/// Overrides [`DEFAULT_MAX_CONNECTIONS_PER_PEER`] at startup.
pub(super) const ENV_MAX_CONNECTIONS_PER_PEER: &str = "NEXAPIPE_MAX_CONNS_PER_PEER";

/// Overrides [`DEFAULT_MAX_CONNECTIONS_GLOBAL`] at startup.
pub(super) const ENV_MAX_CONNECTIONS_GLOBAL: &str = "NEXAPIPE_MAX_CONNS";

/// Counts the connections each peer is currently holding, and the total.
///
/// Shared by every accepted connection, and guarded by a blocking mutex on
/// purpose: the critical section is a map lookup and an increment, so it never
/// runs long enough to be worth an async lock, and it keeps the counter usable
/// from `Drop`.
///
/// The two are one lock rather than a map plus an atomic, because a connection
/// has to pass both ceilings at once and the checks must not interleave: taking
/// the global slot first and finding the peer's own map full would leak the
/// global count on the way out.
pub struct ConnectionLimiter {
    pub(super) counts: Mutex<Counts>,
    max_per_peer: usize,
    max_global: usize,
}

/// The mutable half, kept in one struct so both ceilings are updated under one
/// lock acquisition.
#[derive(Default)]
pub(super) struct Counts {
    per_peer: HashMap<EndpointId, usize>,
    total: usize,
}

impl ConnectionLimiter {
    /// A limiter with the per-peer cap only, and the global one left generous.
    ///
    /// For tests and for callers that want the historical behaviour.
    pub fn new(max_per_peer: usize) -> Self {
        Self::with_caps(max_per_peer, usize::MAX)
    }

    pub fn with_caps(max_per_peer: usize, max_global: usize) -> Self {
        Self {
            counts: Mutex::new(Counts::default()),
            max_per_peer,
            max_global,
        }
    }

    /// Takes a slot for `peer`, or returns `None` when it already holds
    /// `max_per_peer` or the process is at `max_global`.
    ///
    /// The returned guard is what holds the slot: drop it and the count goes
    /// back down, so a connection that ends any way — peer gone, auth refused,
    /// task aborted — gives its slot back without the connection handler having
    /// to remember to.
    pub fn try_acquire(self: &Arc<Self>, peer: EndpointId) -> Option<PeerGuard> {
        // The lookup and the increment happen under one lock, so a burst of
        // connections from the same peer cannot each observe the same free slot,
        // and a burst from many peers cannot collectively overshoot the global
        // ceiling.
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let current = counts.per_peer.get(&peer).copied().unwrap_or(0);
        if current >= self.max_per_peer || counts.total >= self.max_global {
            return None;
        }
        counts.per_peer.insert(peer, current + 1);
        counts.total += 1;
        Some(PeerGuard {
            limiter: self.clone(),
            peer,
        })
    }

    /// Takes a slot for a connection that has no peer identity.
    ///
    /// The plaintext listener has no `EndpointId`: a plain TCP connection is
    /// not a peer in the sense the per-peer cap is about, and a cap keyed on
    /// the source address would be a different design — NAT puts many clients
    /// behind one address, and IPv6 hands a client an address of its own.
    ///
    /// What it can have is the process-wide slot, and that is what this takes.
    /// So an exposed listener shares one ceiling with the tunnel, which is
    /// what a process-wide ceiling is for: the two are one process, and the
    /// work they are doing is one process's work.
    ///
    /// The returned guard holds it: drop it and the count goes back down, so a
    /// connection that ends any way gives its slot back without the accept
    /// loop having to remember to.
    pub fn try_acquire_global(self: &Arc<Self>) -> Option<GlobalGuard> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if counts.total >= self.max_global {
            return None;
        }
        counts.total += 1;
        Some(GlobalGuard {
            limiter: self.clone(),
        })
    }

    /// Connections `peer` is holding right now, for tests and diagnostics.
    ///
    /// A poisoned lock is recovered rather than reported as zero: the counters
    /// themselves are still sound, and answering "0" here would have a caller
    /// log a full process as empty — the one place that must not guess.
    pub fn count(&self, peer: &EndpointId) -> usize {
        let counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.per_peer.get(peer).copied().unwrap_or(0)
    }

    /// Connections the whole process is holding right now.
    ///
    /// Recovers a poisoned lock for the reason [`Self::count`] gives.
    pub fn total(&self) -> usize {
        self.counts.lock().unwrap_or_else(|e| e.into_inner()).total
    }

    pub fn max(&self) -> usize {
        self.max_per_peer
    }

    /// The process-wide ceiling, as [`usize::MAX`] when there is none.
    pub fn max_global(&self) -> usize {
        self.max_global
    }

    /// Gives back a slot that was taken without a peer.
    ///
    /// Only the process-wide count moves: there was no peer to count, so
    /// there is no per-peer entry to take down.
    fn release_global(&self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.total = counts.total.saturating_sub(1);
    }

    fn release(&self, peer: EndpointId) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.total = counts.total.saturating_sub(1);
        if let Some(n) = counts.per_peer.get_mut(&peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.per_peer.remove(&peer);
            }
        }
    }
}

/// Holds one process-wide slot until the connection it belongs to is dropped.
///
/// The peer-less counterpart of [`PeerGuard`]: the plaintext listener has no
/// peer to count, so this counts the process.
pub struct GlobalGuard {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for GlobalGuard {
    fn drop(&mut self) {
        self.limiter.release_global();
    }
}

/// Holds one peer's slot until the connection it belongs to is dropped.
pub struct PeerGuard {
    limiter: Arc<ConnectionLimiter>,
    peer: EndpointId,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.limiter.release(self.peer);
    }
}

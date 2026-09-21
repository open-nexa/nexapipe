//! Per-peer limits on the connections the server handles at once.
//!
//! 2FA answers *who* may connect; this answers *how much*. A peer that has
//! authenticated — or one that is never asked to, because `[auth] enabled` is
//! false — can otherwise open connections until the process runs out of memory
//! and tasks, and one QUIC handshake is cheap enough to get there fast.
//!
//! The cap is per [`EndpointId`], not global: it is what makes one hostile or
//! simply broken peer unable to crowd out the rest, and a peer id is the only
//! thing about a connection the server knows before it has read anything.

use iroh::EndpointId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Concurrent connections one peer may hold, unless the environment overrides it.
///
/// Deliberately generous: the client pool opens a connection per in-flight
/// request, so a busy client holds several at once. This is here to stop a peer
/// from holding thousands, not to shape traffic.
pub const DEFAULT_MAX_CONNECTIONS_PER_PEER: usize = 64;

/// Overrides [`DEFAULT_MAX_CONNECTIONS_PER_PEER`] at startup.
const ENV_MAX_CONNECTIONS_PER_PEER: &str = "NEXAPIPE_MAX_CONNS_PER_PEER";

/// Counts the connections each peer is currently holding.
///
/// Shared by every accepted connection, and guarded by a blocking mutex on
/// purpose: the critical section is a map lookup and an increment, so it never
/// runs long enough to be worth an async lock, and it keeps the counter usable
/// from `Drop`.
pub struct ConnectionLimiter {
    counts: Mutex<HashMap<EndpointId, usize>>,
    max: usize,
}

impl ConnectionLimiter {
    /// A limiter using the cap from the environment, or the default.
    pub fn from_env() -> Arc<Self> {
        Arc::new(Self::new(max_connections_per_peer()))
    }

    pub fn new(max: usize) -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
            max,
        }
    }

    /// Takes a slot for `peer`, or returns `None` when it already holds `max`.
    ///
    /// The returned guard is what holds the slot: drop it and the count goes
    /// back down, so a connection that ends any way — peer gone, auth refused,
    /// task aborted — gives its slot back without the connection handler having
    /// to remember to.
    pub fn try_acquire(self: &Arc<Self>, peer: EndpointId) -> Option<PeerGuard> {
        // The lookup and the increment happen under one lock, so a burst of
        // connections from the same peer cannot each observe the same free slot.
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let current = counts.get(&peer).copied().unwrap_or(0);
        if current >= self.max {
            return None;
        }
        counts.insert(peer, current + 1);
        Some(PeerGuard {
            limiter: self.clone(),
            peer,
        })
    }

    /// Connections `peer` is holding right now, for tests and diagnostics.
    pub fn count(&self, peer: &EndpointId) -> usize {
        self.counts
            .lock()
            .map(|counts| counts.get(peer).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    pub fn max(&self) -> usize {
        self.max
    }

    fn release(&self, peer: EndpointId) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = counts.get_mut(&peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.remove(&peer);
            }
        }
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

/// The cap to run with: [`ENV_MAX_CONNECTIONS_PER_PEER`] when it parses, else
/// [`DEFAULT_MAX_CONNECTIONS_PER_PEER`].
///
/// Read once when the limiter is built, not per connection.
pub fn max_connections_per_peer() -> usize {
    let Ok(raw) = std::env::var(ENV_MAX_CONNECTIONS_PER_PEER) else {
        return DEFAULT_MAX_CONNECTIONS_PER_PEER;
    };
    match parse_max(&raw) {
        Some(max) => max,
        None => {
            tracing::warn!(
                "{ENV_MAX_CONNECTIONS_PER_PEER}={raw} is not a positive number, using \
                 {DEFAULT_MAX_CONNECTIONS_PER_PEER}"
            );
            DEFAULT_MAX_CONNECTIONS_PER_PEER
        }
    }
}

/// A cap, or `None` when `raw` is not a positive number.
///
/// Split out from [`max_connections_per_peer`] so the parsing is testable
/// without touching the process environment.
fn parse_max(raw: &str) -> Option<usize> {
    match raw.trim().parse::<usize>() {
        // Zero would refuse every connection, which is a typo rather than a
        // setting: falling back keeps one bad env var from taking the listener
        // offline.
        Ok(0) | Err(_) => None,
        Ok(n) => Some(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer id to count against.
    ///
    /// Derived from a secret key rather than written out as bytes: an
    /// `EndpointId` is an ed25519 public key, and arbitrary bytes are not one.
    fn peer(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn a_peer_may_hold_up_to_the_cap() {
        let limiter = Arc::new(ConnectionLimiter::new(2));
        let a = peer(1);

        let first = limiter.try_acquire(a);
        let second = limiter.try_acquire(a);
        assert!(first.is_some());
        assert!(second.is_some());
        assert_eq!(limiter.count(&a), 2);

        // The cap is per peer, so another peer is unaffected.
        assert!(limiter.try_acquire(peer(2)).is_some());
        assert!(limiter.try_acquire(a).is_none());
    }

    #[test]
    fn dropping_a_guard_frees_the_slot() {
        let limiter = Arc::new(ConnectionLimiter::new(1));
        let a = peer(1);

        let guard = limiter.try_acquire(a).expect("first connection fits");
        assert!(limiter.try_acquire(a).is_none());

        drop(guard);
        assert_eq!(limiter.count(&a), 0, "a freed peer leaves no entry behind");
        assert!(limiter.try_acquire(a).is_some());
    }

    #[test]
    fn a_zero_cap_refuses_everyone() {
        let limiter = Arc::new(ConnectionLimiter::new(0));
        assert!(limiter.try_acquire(peer(1)).is_none());
        assert_eq!(limiter.count(&peer(1)), 0);
    }

    #[test]
    fn only_a_positive_number_is_a_cap() {
        assert_eq!(parse_max("8"), Some(8));
        assert_eq!(parse_max(" 16 "), Some(16));
        assert_eq!(parse_max("0"), None);
        assert_eq!(parse_max("-1"), None);
        assert_eq!(parse_max("lots"), None);
        assert_eq!(parse_max(""), None);
    }
}

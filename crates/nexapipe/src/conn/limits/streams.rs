//! The streams the process may have in flight.
//!
//! The process-wide counterpart of the per-connection cap in `conn/mod.rs`:
//! without one, every connection may open its own allowance and the total is
//! again a product of however many peers exist.

use std::sync::Arc;

/// Concurrent streams the whole process may have in flight, unless the config or the
/// environment overrides it.
///
/// A multiple of `MAX_CONCURRENT_STREAMS_PER_CONNECTION` for the same reason
/// the global connection cap is a multiple of the per-peer one: it reads as "the
/// peers you would plausibly have, each opening its own streams".
pub const DEFAULT_MAX_STREAMS_GLOBAL: usize = 64 * 256;

/// Overrides [`DEFAULT_MAX_STREAMS_GLOBAL`] at startup.
pub(super) const ENV_MAX_STREAMS_GLOBAL: &str = "NEXAPIPE_MAX_STREAMS";

/// Counts the streams in flight across every connection.
///
/// One semaphore rather than a counter of the limiter's own: a stream is held
/// for the length of a request and released by an owned permit, and the permit is
/// what makes that automatic. The per-connection cap in `conn/mod.rs` is the
/// same shape, and this is the process-wide counterpart to it — without one,
/// every connection may open its own allowance and the total is again a product
/// of however many peers exist.
#[derive(Debug)]
pub struct StreamLimiter {
    slots: Arc<tokio::sync::Semaphore>,
    max_global: usize,
}

impl StreamLimiter {
    pub fn new(max_global: usize) -> Self {
        // Clamped, not refused. `tokio::sync::Semaphore::new` panics above
        // `MAX_PERMITS`, and an operator who writes a huge number here almost
        // certainly means "unlimited" — so the ceiling becomes "as large as a
        // semaphore can be", which is what was asked for, rather than a refusal
        // that takes the listener offline. `cap_from_env` treats a bad value as
        // a warning; this is the same rule one level down, where there is no
        // sensible fallback to substitute.
        let max_global = max_global.min(tokio::sync::Semaphore::MAX_PERMITS);
        Self {
            slots: Arc::new(tokio::sync::Semaphore::new(max_global)),
            max_global,
        }
    }

    /// Takes a slot, or returns `None` when the process is at its ceiling.
    ///
    /// Refused rather than awaited: a stream that waits is a task held open, and
    /// the whole point of the ceiling is that the process does not hold tasks
    /// open.
    pub fn try_acquire(self: &Arc<Self>) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.slots.clone().try_acquire_owned().ok()
    }

    /// Slots still free, for diagnostics and tests.
    pub fn available(&self) -> usize {
        self.slots.available_permits()
    }

    pub fn max_global(&self) -> usize {
        self.max_global
    }
}

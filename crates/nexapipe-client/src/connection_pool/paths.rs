//! The paths of one connection, and what they say about whether it is alive.
//!
//! A QUIC connection is **not** closed when its path dies. QUIC keeps the
//! connection open, waiting for a path to come back — over a relay that
//! answers again, or over a network that comes back — so "was it closed"
//! is not the question a connection can answer. "Is there still a path to
//! send on" is, and that is the question this module keeps the answer to.
//!
//! The path watcher is the only thing that sees the path events, so this
//! is where the pool reads them from.

use std::sync::atomic::{AtomicBool, Ordering};

/// What the path watcher knows about the paths of one connection.
///
/// Two facts, and the difference between them is the whole of it:
///
/// - **a path has been seen**: the connection had a path at some point;
/// - **a path is open**: it has one right now.
///
/// A connection whose paths have never been seen is **not** a dead one: the
/// watcher may simply not have looked at it yet — iroh records a path once a
/// datagram has come back on it, which is a moment of its own — and a
/// connection declared dead before it has been looked at is a connection the
/// pool throws away for nothing. So the paths being gone says something only
/// once a path has been seen.
#[derive(Debug, Default)]
pub(super) struct PathHealth {
    /// Whether a path has been seen on this connection.
    seen: AtomicBool,
    /// Whether a path is open on this connection right now.
    open: AtomicBool,
}

impl PathHealth {
    /// The paths the connection has right now: `count` of them.
    ///
    /// The snapshot and the event stream are two views of the same thing,
    /// and the snapshot is what the stream is caught up with: a path that
    /// was established before the watcher subscribed is in the snapshot and
    /// not in the stream.
    pub(super) fn snapshot(&self, count: usize) {
        if count > 0 {
            self.seen.store(true, Ordering::Release);
        }
        self.open.store(count > 0, Ordering::Release);
    }

    /// A path was opened: there is somewhere to send.
    pub(super) fn opened(&self) {
        self.seen.store(true, Ordering::Release);
        self.open.store(true, Ordering::Release);
    }

    /// A path was closed, and `remaining` paths are still open.
    ///
    /// The count is the connection's own: iroh has taken the closed path
    /// out of its list by the time the event is delivered, so the list says
    /// what is left.
    pub(super) fn closed(&self, remaining: usize) {
        if remaining > 0 {
            self.seen.store(true, Ordering::Release);
        }
        self.open.store(remaining > 0, Ordering::Release);
    }

    /// Whether a path is open on this connection right now.
    ///
    /// Test-only: the pool asks whether the paths are *all* gone, and this
    /// is the other half of that answer — the one that says the record is a
    /// reading and not the "not looked at yet" one.
    #[cfg(test)]
    pub(super) fn has_open_path(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Whether every path this connection had is gone.
    ///
    /// A connection with no path left has nowhere to send: QUIC will keep
    /// it open, waiting for a path to come back, but nothing can be
    /// carried over it.
    pub(super) fn all_gone(&self) -> bool {
        self.seen.load(Ordering::Acquire) && !self.open.load(Ordering::Acquire)
    }
}

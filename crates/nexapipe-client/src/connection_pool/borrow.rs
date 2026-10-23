//! Borrowing a connection out of the pool.
//!
//! A connection is held by the pool and handed out for the length of one
//! request. The borrow is what says how long that is, and what gives the
//! connection back when the request is over.

use iroh::endpoint::Connection;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

/// What the pool and the flows on one connection share: how many flows are
/// riding it, when it was last used, and whether the server has said the
/// connection is full.
///
/// The count is shared because the pool has to be able to tell a connection
/// nobody is using from one that a flow is still riding — and closing the
/// second would take that flow down with it.
///
/// The last-use stamp is shared for the same reason: it is stamped when the
/// **last** borrow goes, which is a moment only the borrower can see. A
/// connection that has just carried a ten-minute flow is fresh for another
/// minute, and a connection that is still carrying one is not idle at all.
#[derive(Debug)]
pub struct BorrowState {
    /// How many flows are on the connection right now.
    pub(super) borrows: AtomicUsize,
    /// When the connection was last used.
    ///
    /// Not when it was dialled: a connection that is used continuously is
    /// handed out every few seconds, and the idle timeout is about how long
    /// it has been sitting unused — not how old it is. A connection in
    /// constant use is not idle, and a ten-minute-old connection that was
    /// handed out a second ago is not either.
    pub(super) last_used: StdMutex<tokio::time::Instant>,
    /// Whether the server has refused a flow on this connection because it
    /// was already carrying as many as it allows.
    ///
    /// Set when the server answers `Status::TooManyFlows`, and **not** cleared
    /// when the last flow on the connection ends: the server counts its own
    /// flows, and the flow that was refused is not one of them — so a
    /// connection the server has called full stays out of circulation, and
    /// the next flow is given a connection of its own.
    pub(super) saturated: AtomicBool,
}

impl BorrowState {
    pub(super) fn new() -> Self {
        Self {
            borrows: AtomicUsize::new(0),
            last_used: StdMutex::new(tokio::time::Instant::now()),
            saturated: AtomicBool::new(false),
        }
    }

    /// How many flows are on the connection right now.
    pub(super) fn borrow_count(&self) -> usize {
        self.borrows.load(Ordering::Acquire)
    }

    /// Whether another flow may ride this connection.
    pub(super) fn has_room(&self) -> bool {
        !self.saturated.load(Ordering::Acquire) && self.borrow_count() < MAX_FLOWS_PER_CONNECTION
    }

    /// Takes a borrow, if there is room for one.
    ///
    /// The check and the count are one atomic step, so two callers cannot
    /// both see the last seat and both take it.
    pub(super) fn try_borrow(self: &Arc<Self>) -> Option<Borrow> {
        if self.saturated.load(Ordering::Acquire) {
            return None;
        }
        let mut current = self.borrows.load(Ordering::Acquire);
        loop {
            if current >= MAX_FLOWS_PER_CONNECTION {
                return None;
            }
            match self.borrows.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // The connection is in use again, so it is not idle
                    // however long ago it was last used.
                    self.touch();
                    return Some(Borrow {
                        state: Some(self.clone()),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Gives a borrow back.
    ///
    /// The last-use stamp moves when the **last** borrow goes: a connection
    /// that has just carried a flow is fresh for another minute, and the
    /// moment it became idle is a moment only the last borrower sees.
    pub(super) fn release(&self) {
        let mut current = self.borrows.load(Ordering::Acquire);
        loop {
            if current == 0 {
                // A borrow is given back exactly once, so this cannot
                // happen — and wrapping the counter would hide the bug
                // behind a count of billions.
                debug_assert!(false, "a borrow was given back that was never taken");
                return;
            }
            match self.borrows.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if current == 1 {
                        // The last flow on this connection ended: it is idle
                        // from now on.
                        self.touch();
                    }
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Stamps the connection as used right now.
    pub(super) fn touch(&self) {
        let mut last_used = self
            .last_used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *last_used = tokio::time::Instant::now();
    }

    /// When the connection was last used.
    pub(super) fn last_used(&self) -> tokio::time::Instant {
        *self
            .last_used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether the connection has been sitting unused for at least `timeout`.
    pub(super) fn is_idle_for(&self, timeout: tokio::time::Duration) -> bool {
        is_idle_since(self.last_used(), timeout)
    }

    /// Marks the connection as carrying as many flows as the server allows.
    pub(super) fn saturate(&self) {
        self.saturated.store(true, Ordering::Release);
    }
}

/// One flow's borrow on a connection.
///
/// The borrow is given back when the guard is dropped, and `Drop` is what
/// covers every way a flow ends: EOF, an error, a cancellation. The guard is
/// the only thing that gives a borrow back, so a borrow cannot be forgotten
/// on one path and given back twice on another.
#[derive(Debug)]
pub struct Borrow {
    /// The state the borrow belongs to.
    ///
    /// `None` once the borrow has been handed on, so that a hand-over does
    /// not give it back a second time.
    state: Option<Arc<BorrowState>>,
}

impl Borrow {
    /// Marks the connection as carrying as many flows as the server allows.
    ///
    /// The server refused a flow with `TooManyFlows`, which is a statement
    /// about the connection rather than about the flow: the pool must stop
    /// handing that connection out, or the next flow is refused the same way.
    pub fn saturate(&self) {
        if let Some(state) = &self.state {
            state.saturate();
        }
    }
}

impl Drop for Borrow {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.release();
        }
    }
}

/// A connection borrowed from the pool, and the borrow that says how many
/// flows are on it.
///
/// The borrow is given back when this value is dropped, which is what makes
/// the count true: a flow that ends in any way — EOF, an error, a
/// cancellation — drops it.
///
/// The state behind the borrow is shared with the pool's own entry for the
/// connection, so the pool can tell a connection nobody is using from one
/// that a flow is still riding.
pub struct BorrowedConnection {
    /// The connection itself. A cheap clonable handle: iroh's `Connection`
    /// may be cloned to get another handle to the same connection.
    pub conn: Connection,
    /// The borrow this connection is held under.
    pub borrow: Borrow,
}

/// How many flows may ride one connection at the same time.
///
/// The server counts the L4 flows on a connection and refuses the one that
/// does not fit (`Status::TooManyFlows`), so a client that piles every flow
/// onto one connection runs into a ceiling it cannot see. The pool keeps
/// below that ceiling itself and opens another connection instead.
///
/// The server's ceiling is 256 L4 flows per connection
/// (`DEFAULT_MAX_FLOWS_PER_CONNECTION` in `crates/nexapipe/src/l4/mod.rs`).
/// This number counts **every** flow on the connection — HTTP and L4 alike —
/// so it has to stay below the server's, and it stays below it with room to
/// spare: the two counters are not the same one, and the server's lags by a
/// flow or two while a flow is ending.
pub(super) const MAX_FLOWS_PER_CONNECTION: usize = 200;

/// Whether a connection that was last used at `last_used` has been sitting
/// unused for at least `timeout`.
///
/// Free rather than a method, so that the rule can be tested without a live
/// connection: reading it off one needs an endpoint, and the rule is the part
/// that has to be right.
pub(super) fn is_idle_since(
    last_used: tokio::time::Instant,
    timeout: tokio::time::Duration,
) -> bool {
    last_used.elapsed() >= timeout
}

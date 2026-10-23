//! The bytes the process may hold at once.
//!
//! One budget covers the request bodies and the per-stream copy buffers: both
//! are bytes the process is holding, so a ceiling that counted only one of
//! them would not be the ceiling the operator asked for.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

/// Bytes of request bodies the whole process may hold at once, unless the config or the
/// environment overrides it.
///
/// A gibibyte, which is sixteen of the largest body a single request may carry.
/// Deliberately *not* "one per peer you might plausibly have": at 64 MB a piece
/// that would be gigabytes, and a budget that large does not protect the
/// machine it runs on — the process would be OOM-killed long before the ceiling
/// was reached, which is the failure this exists to prevent. Sixteen concurrent
/// maximum-size uploads is well past what a proxy fronting ordinary web traffic
/// sees, and a deployment that legitimately needs more raises it.
pub const DEFAULT_MAX_BODY_BYTES_GLOBAL: usize = 1024 * 1024 * 1024;

/// Overrides [`DEFAULT_MAX_BODY_BYTES_GLOBAL`] at startup.
pub(super) const ENV_MAX_BODY_BYTES_GLOBAL: &str = "NEXAPIPE_MAX_BODY_BYTES";

/// Counts the bytes held in request bodies across the process.
///
/// What this bounds is memory: `MAX_REQUEST_BODY` per request is defensible,
/// and the same 64 MB times every stream the process will accept at once is
/// not. This is the third ceiling for the same reason the other
/// two are there — each one bounds a resource that the per-connection and per-peer
/// numbers cannot bound on their own.
///
/// **The per-stream copy buffers are charged here too.** They are the one
/// per-stream allocation the budget did not see: every direction of every
/// copied stream holds a buffer, and a peer that opened many streams paid for
/// them in memory the operator's ceiling never knew about — so the ceiling
/// they configured was not the ceiling they got. A copy buffer is taken with
/// the same reservation a body is, and given back when its direction ends.
///
/// **Both body paths reserve here**, which took two changes to arrange. The
/// plaintext listener buffers through `read_body_limited`, which grows a
/// reservation per frame. The iroh path has two readers of its own: the one
/// with a `content-length` **streams** the body — the bytes are read as the
/// backend asks for them, so what it holds is a buffer rather than the upload —
/// and it charges the bytes as they arrive, because QUIC is a byte stream and a
/// peer decides how much body rides along with the head, so the only honest
/// number is the one that counts what has arrived. The chunked reader charges
/// the raw bytes the same way, because a chunked body declares no length and
/// there is no moment at which the total is knowable — and a peer that declares
/// a 64 MiB chunk and then trickles the data into it holds those bytes for as
/// long as it takes, so the budget has to see them.
///
/// Every reader returns its reservation to its caller rather than dropping it:
/// the bytes are still held after the read, right up to when the body goes to
/// the backend, so a reservation released at the end of the read would report a
/// figure that undercounts exactly while the memory is held.
///
/// A process-wide static rather than something threaded through every call: the
/// bodies are read deep inside the HTTP path, and the alternative is a parameter
/// on every function between the accept loop and the readers. The same trade
/// `config_write_gate` makes. A reader that needs a budget of its own takes it
/// as a parameter — that is how the chunked reader is tested without touching
/// the shared one.
#[derive(Debug)]
pub struct ByteBudget {
    held: AtomicUsize,
    /// The ceiling, in an atomic rather than a plain field so that it can be
    /// written once at startup, from the configuration, without the budget
    /// having to be built with it.
    ///
    /// See [`init_body_budget`] for why it is written rather than baked in.
    max: AtomicUsize,
}

impl ByteBudget {
    /// A budget with a ceiling.
    ///
    /// `const` so the process-wide one can be a `static` rather than a
    /// `OnceLock`: the value it holds has to be settable after it exists.
    pub const fn new(max: usize) -> Self {
        Self {
            held: AtomicUsize::new(0),
            max: AtomicUsize::new(max),
        }
    }

    /// Sets the ceiling this budget enforces.
    ///
    /// Called once at startup, before any request is served. The `held` counter
    /// is untouched by it: what is already reserved stays reserved, and the new
    /// ceiling applies to what comes after.
    pub fn set_max(&self, max: usize) {
        self.max.store(max, Ordering::Relaxed);
    }

    /// Adds `bytes` to the total, or returns the total as it was before the
    /// attempt.
    ///
    /// Checked and added in one `try_update` rather than a load, a compare and
    /// a store: two concurrent uploads must not both read a total that leaves
    /// room for one of them.
    pub fn try_reserve(&self, bytes: usize) -> Result<(), usize> {
        // Read once, outside the closure: the closure may run more than once,
        // and the ceiling it compares against should be the same one every
        // attempt sees.
        let max = self.max.load(Ordering::Relaxed);
        // Written as a `match` rather than a chain of `map`s because
        // `try_update` hands back the total from *before* the attempt on both
        // paths, and only the `Err` case carries it: that is the number the
        // caller needs in order to say how much room was left.
        match self
            .held
            .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                let next = held.saturating_add(bytes);
                (next <= max).then_some(next)
            }) {
            Ok(_) => Ok(()),
            Err(held) => Err(held),
        }
    }

    /// Gives back a reservation.
    ///
    /// Saturating, in one step: a double release cannot wrap the counter and
    /// make the budget look permanently full, and two releases that race
    /// cannot both subtract from the same total. A load followed by a separate
    /// `fetch_sub` does both — it reads a total, then subtracts from whatever
    /// the counter says by then, which is not the total it read.
    pub fn release(&self, bytes: usize) {
        let mut current = self.held.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(bytes);
            match self.held.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    /// Bytes currently reserved, for metrics and diagnostics.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    pub fn max(&self) -> usize {
        self.max.load(Ordering::Relaxed)
    }
}

/// The process-wide body budget.
///
/// A `LazyLock` rather than a `OnceLock`, because the ceiling it enforces is
/// written into it after it exists: the budget has to be reachable from the
/// body readers, which are deep inside the HTTP path and hold no config, and
/// the ceiling comes from the configuration, which is read at startup.
///
/// Behind an [`Arc`] because a reservation holds on to the budget it was taken
/// from, and a reader that is given a budget of its own — a test that must
/// not touch the shared one — has to be able to hand the same budget to it.
static BUDGET: LazyLock<Arc<ByteBudget>> =
    LazyLock::new(|| Arc::new(ByteBudget::new(DEFAULT_MAX_BODY_BYTES_GLOBAL)));

/// The process-wide body budget.
///
/// The one every request is charged against, and the one every copied stream's
/// buffers are charged against as well. A caller with a budget of its own
/// names it where the budget is taken rather than reaching for this one.
pub fn body_budget() -> &'static Arc<ByteBudget> {
    &BUDGET
}

/// Sets the ceiling the process-wide body budget enforces.
///
/// Called once at startup, from the resolved [`Limits`](crate::conn::limits::Limits), before any request
/// is served — so no upload is ever counted against a ceiling it was not
/// counted against when it started.
///
/// Writing the ceiling rather than building the budget with it is what lets
/// the value come from `config.toml` and not only from the environment: the
/// budget is a `static` that the HTTP path reaches without a config, and its
/// ceiling is a separate write.
pub fn init_body_budget(max: usize) {
    BUDGET.set_max(max);
}

/// Holds a reservation for as long as the body it was taken for is alive.
///
/// The reason the budget needs a guard rather than a bare reserve/release pair:
/// a body is read, forwarded, and then dropped by hyper somewhere inside the
/// request, and nothing at the reading site is still around to give the bytes
/// back. Tying the release to the buffer's lifetime is what makes the total
/// mean "bytes held right now" rather than "bytes ever read".
///
/// The reservation grows rather than being taken once up front, because a
/// chunked request declares no length: the only honest moment to reserve is the
/// moment the bytes actually arrive, which is also what stops a slow sender from
/// holding a reservation on something it never sends.
#[derive(Debug)]
pub struct ByteReservation {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl ByteReservation {
    /// Reserves `bytes` from the process-wide budget, or explains that the
    /// process is full.
    pub fn take(bytes: usize) -> anyhow::Result<Self> {
        Self::take_from(body_budget(), bytes)
    }

    /// Reserves `bytes` from a named budget, or explains that it is full.
    ///
    /// The process-wide one is what the request path uses. A caller with a
    /// budget of its own — a test that must not disturb the shared one, or a
    /// future path that is accounted separately — names it here.
    pub(crate) fn take_from(budget: &Arc<ByteBudget>, bytes: usize) -> anyhow::Result<Self> {
        match budget.try_reserve(bytes) {
            Ok(()) => Ok(Self {
                budget: budget.clone(),
                bytes,
            }),
            Err(held) => Err(anyhow::anyhow!(
                "the server is holding {held} of {} bytes of request bodies, so this {} byte \
                 body does not fit",
                budget.max(),
                bytes
            )),
        }
    }

    /// Reserves `bytes` from a named budget for a copy buffer.
    ///
    /// The same reservation a body gets — the budget does not care what the
    /// bytes are for, only how many of them there are — with the words the
    /// reader of the log needs: this is a buffer the process holds for one
    /// stream, not a request body.
    ///
    /// Taken when the buffer is taken and given back when it is dropped, which
    /// is when the direction that owns it ends.
    pub(crate) fn take_buffers(budget: &Arc<ByteBudget>, bytes: usize) -> anyhow::Result<Self> {
        match budget.try_reserve(bytes) {
            Ok(()) => Ok(Self {
                budget: budget.clone(),
                bytes,
            }),
            Err(held) => Err(anyhow::anyhow!(
                "the server is holding {held} of {} bytes, so this {} byte copy buffer does not fit",
                budget.max(),
                bytes
            )),
        }
    }

    /// Adds `bytes` to what this reservation already holds.
    ///
    /// Called once per body frame as it arrives. On failure nothing is added,
    /// so the caller's `Drop` still gives back exactly what was taken.
    pub fn grow(&mut self, bytes: usize) -> anyhow::Result<()> {
        let budget = &self.budget;
        match budget.try_reserve(bytes) {
            Ok(()) => {
                self.bytes += bytes;
                Ok(())
            }
            Err(held) => Err(anyhow::anyhow!(
                "the server is holding {held} of {} bytes of request bodies, so this {} byte \
                 body does not fit",
                budget.max(),
                bytes
            )),
        }
    }

    /// Gives back `bytes` that are no longer held.
    ///
    /// A body read as raw chunks holds the raw bytes until each chunk decodes,
    /// and then holds the decoded ones instead — fewer bytes, but a different
    /// set of them. This is how the difference is returned to the budget, so
    /// the total keeps meaning "bytes held right now".
    ///
    /// More than the reservation holds is not returned: the counter never
    /// goes below zero, so a caller that gives back too much leaves the
    /// budget as it was rather than making it look emptier than it is.
    pub fn shrink(&mut self, bytes: usize) {
        let released = bytes.min(self.bytes);
        self.bytes -= released;
        self.budget.release(released);
    }

    /// Bytes this reservation is holding.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// A reservation of nothing, for a request that turned out to have no body.
    ///
    /// Still a value rather than an `Option`, so the caller holds one type and
    /// cannot forget to release in one branch and not the other.
    pub fn empty() -> Self {
        Self {
            budget: body_budget().clone(),
            bytes: 0,
        }
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.budget.release(self.bytes);
        }
    }
}

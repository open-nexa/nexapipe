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
//! budget: an [`EndpointId`] is a public key, so a caller can generate as many
//! peers as it likes, and per-peer limits alone make the total a product of
//! "64 times however many identities you care to invent". Neither ceiling
//! subsumes the other, which is why both are here.

use iroh::EndpointId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Concurrent connections one peer may hold, unless the environment overrides it.
///
/// Deliberately generous: the client pool opens a connection per in-flight
/// request, so a busy client holds several at once. This is here to stop a peer
/// from holding thousands, not to shape traffic.
pub const DEFAULT_MAX_CONNECTIONS_PER_PEER: usize = 64;

/// Concurrent connections the whole process may hold, unless the environment
/// overrides it.
///
/// A multiple of [`DEFAULT_MAX_CONNECTIONS_PER_PEER`] rather than a round number:
/// it reads as "the peers you would plausibly have, each at its own cap", which
/// is the sizing this is defending. A deployment with 64 legitimate clients is
/// unaffected by the default; one with several thousand is the deployment where
/// this number should have been written down.
pub const DEFAULT_MAX_CONNECTIONS_GLOBAL: usize = 64 * 64;

/// Overrides [`DEFAULT_MAX_CONNECTIONS_PER_PEER`] at startup.
const ENV_MAX_CONNECTIONS_PER_PEER: &str = "NEXAPIPE_MAX_CONNS_PER_PEER";

/// Overrides [`DEFAULT_MAX_CONNECTIONS_GLOBAL`] at startup.
const ENV_MAX_CONNECTIONS_GLOBAL: &str = "NEXAPIPE_MAX_CONNS";

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
    counts: Mutex<Counts>,
    max_per_peer: usize,
    max_global: usize,
}

/// The mutable half, kept in one struct so both ceilings are updated under one
/// lock acquisition.
#[derive(Default)]
struct Counts {
    per_peer: HashMap<EndpointId, usize>,
    total: usize,
}

impl ConnectionLimiter {
    /// A limiter using the caps from the environment, or the defaults.
    pub fn from_env() -> Arc<Self> {
        Arc::new(Self::with_caps(
            max_connections_per_peer(),
            max_connections_global(),
        ))
    }

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
}

impl Limiters {
    /// Both from the environment, which is how the server builds them.
    pub fn from_env() -> Self {
        Self {
            connections: ConnectionLimiter::from_env(),
            streams: StreamLimiter::from_env(),
        }
    }

    /// A line for the startup log, so an operator can see every ceiling the
    /// process is running with in one place.
    pub fn describe(&self) -> String {
        format!(
            "{} concurrent connections per peer, {} across the process, {} streams across the \
             process",
            self.connections.max(),
            self.connections.max_global(),
            self.streams.max_global()
        )
    }
}

/// The cap to run with: [`ENV_MAX_CONNECTIONS_PER_PEER`] when it parses, else
/// [`DEFAULT_MAX_CONNECTIONS_PER_PEER`].
///
/// Read once when the limiter is built, not per connection.
pub fn max_connections_per_peer() -> usize {
    cap_from_env(
        ENV_MAX_CONNECTIONS_PER_PEER,
        DEFAULT_MAX_CONNECTIONS_PER_PEER,
    )
}

/// The process-wide cap: [`ENV_MAX_CONNECTIONS_GLOBAL`] when it parses, else
/// [`DEFAULT_MAX_CONNECTIONS_GLOBAL`].
pub fn max_connections_global() -> usize {
    cap_from_env(ENV_MAX_CONNECTIONS_GLOBAL, DEFAULT_MAX_CONNECTIONS_GLOBAL)
}

/// One env var to one cap, with the same "a bad value is a warning, not an
/// outage" rule for both.
fn cap_from_env(var: &str, default: usize) -> usize {
    let Ok(raw) = std::env::var(var) else {
        return default;
    };
    match parse_max(&raw) {
        Some(max) => max,
        None => {
            tracing::warn!("{var}={raw} is not a positive number, using {default}");
            default
        }
    }
}

/// Concurrent streams the whole process may have in flight, unless the
/// environment overrides it.
///
/// A multiple of [`MAX_CONCURRENT_STREAMS_PER_CONNECTION`] for the same reason
/// the global connection cap is a multiple of the per-peer one: it reads as "the
/// peers you would plausibly have, each opening its own streams".
pub const DEFAULT_MAX_STREAMS_GLOBAL: usize = 64 * 256;

/// Overrides [`DEFAULT_MAX_STREAMS_GLOBAL`] at startup.
const ENV_MAX_STREAMS_GLOBAL: &str = "NEXAPIPE_MAX_STREAMS";

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

    /// A limiter using [`ENV_MAX_STREAMS_GLOBAL`], or the default.
    pub fn from_env() -> Arc<Self> {
        Arc::new(Self::new(cap_from_env(
            ENV_MAX_STREAMS_GLOBAL,
            DEFAULT_MAX_STREAMS_GLOBAL,
        )))
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

/// Bytes of request bodies the whole process may hold at once, unless the
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
const ENV_MAX_BODY_BYTES_GLOBAL: &str = "NEXAPIPE_MAX_BODY_BYTES";

/// Counts the bytes held in buffered request bodies across the process.
///
/// Request bodies are read whole before being forwarded, so what this bounds is
/// memory: [`MAX_REQUEST_BODY`](crate::http::MAX_REQUEST_BODY) per request is
/// defensible, and the same 64 MB times every stream the process will accept at
/// once is not. This is the third ceiling for the same reason the other two are
/// there — each one bounds a resource that the per-connection and per-peer
/// numbers cannot bound on their own.
///
/// **Both body paths reserve here**, which took two changes to arrange. The
/// plaintext listener buffers through `read_body_limited`, which grows a
/// reservation per frame. The iroh path buffers through two readers of its own:
/// the one with a `content-length` takes the whole declared size before its
/// first read, because QUIC is a byte stream and a peer decides how much body
/// rides along with the head, so the declared size is the only honest number;
/// the chunked one grows per decoded frame, because a chunked body declares no
/// length and there is no moment at which the total is knowable.
///
/// Every reader returns its reservation to its caller rather than dropping it:
/// the bytes are still held after the read, right up to when the body goes to
/// the backend, so a reservation released at the end of the read would report a
/// figure that undercounts exactly while the memory is held.
///
/// A process-wide static rather than something threaded through every call: the
/// bodies are read deep inside the HTTP path, and the alternative is a parameter
/// on every function between the accept loop and the readers. The same trade
/// [`config_write_gate`](crate::conn::config_write_gate) makes.
#[derive(Debug)]
pub struct ByteBudget {
    held: AtomicUsize,
    max: usize,
}

impl ByteBudget {
    pub fn new(max: usize) -> Self {
        Self {
            held: AtomicUsize::new(0),
            max,
        }
    }

    /// Adds `bytes` to the total, or returns the total as it was before the
    /// attempt.
    ///
    /// Checked and added in one `try_update` rather than a load, a compare and
    /// a store: two concurrent uploads must not both read a total that leaves
    /// room for one of them.
    pub fn try_reserve(&self, bytes: usize) -> Result<(), usize> {
        // Written as a `match` rather than a chain of `map`s because
        // `try_update` hands back the total from *before* the attempt on both
        // paths, and only the `Err` case carries it: that is the number the
        // caller needs in order to say how much room was left.
        match self
            .held
            .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                let next = held.saturating_add(bytes);
                (next <= self.max).then_some(next)
            }) {
            Ok(_) => Ok(()),
            Err(held) => Err(held),
        }
    }

    /// Gives back a reservation. Saturating, so a double release cannot wrap the
    /// counter and make the budget look permanently full.
    pub fn release(&self, bytes: usize) {
        self.held.fetch_sub(
            bytes.min(self.held.load(Ordering::Acquire)),
            Ordering::AcqRel,
        );
    }

    /// Bytes currently reserved, for metrics and diagnostics.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    pub fn max(&self) -> usize {
        self.max
    }
}

/// The process-wide body budget, resolved from the environment on first use.
///
/// Held for the life of the process: the caps are read once at startup, like
/// every other limit here, and a budget that changed under an in-flight upload
/// would release bytes against a ceiling it was never counted against.
pub fn body_budget() -> &'static ByteBudget {
    static BUDGET: OnceLock<ByteBudget> = OnceLock::new();
    BUDGET.get_or_init(|| {
        ByteBudget::new(cap_from_env(
            ENV_MAX_BODY_BYTES_GLOBAL,
            DEFAULT_MAX_BODY_BYTES_GLOBAL,
        ))
    })
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
    budget: &'static ByteBudget,
    bytes: usize,
}

impl ByteReservation {
    /// Reserves `bytes`, or explains that the process is full.
    pub fn take(bytes: usize) -> anyhow::Result<Self> {
        let budget = body_budget();
        match budget.try_reserve(bytes) {
            Ok(()) => Ok(Self { budget, bytes }),
            Err(held) => Err(anyhow::anyhow!(
                "the server is holding {held} of {} bytes of request bodies, so this {} byte \
                 body does not fit",
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
        let budget = self.budget;
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
            budget: body_budget(),
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
    fn diagnostics_report_the_real_counts_through_a_poisoned_lock() {
        let limiter = Arc::new(ConnectionLimiter::new(4));
        let a = peer(1);

        let guards: Vec<_> = (0..3).filter_map(|_| limiter.try_acquire(a)).collect();
        assert_eq!(
            guards.len(),
            3,
            "the connections this test poisons over are held"
        );

        // Poison it the only way a Mutex gets poisoned: a panic while held.
        let poisoner = limiter.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.counts.lock().unwrap();
            panic!("a connection handler died holding the counter");
        })
        .join();

        assert_eq!(
            limiter.count(&a),
            3,
            "a poisoned lock still reports what is held"
        );
        assert_eq!(
            limiter.total(),
            3,
            "the process total is not an empty process"
        );

        // And the accounting itself is untouched by the poison.
        drop(guards);
        assert_eq!(limiter.count(&a), 0);
        assert_eq!(limiter.total(), 0);
    }

    #[test]
    fn many_peers_still_stop_at_the_global_ceiling() {
        // The peer cap alone would let this hold `per_peer * 256` connections:
        // an EndpointId is a public key, so a caller can invent as many of them
        // as it likes and each one gets its own allowance.
        let limiter = Arc::new(ConnectionLimiter::with_caps(2, 3));
        let a = peer(1);
        let b = peer(2);
        let c = peer(3);
        let d = peer(4);

        // Held, not dropped: a guard that went out of scope early would free the
        // slot the next assertion is about the absence of.
        let first = limiter.try_acquire(a).expect("first connection fits");
        let _second = limiter.try_acquire(b).expect("second connection fits");
        let _third = limiter.try_acquire(c).expect("third connection fits");
        assert_eq!(limiter.total(), 3);

        // A fourth peer with an empty allowance of its own is still refused,
        // because the process is full. This is the case per-peer limits miss.
        assert!(
            limiter.try_acquire(d).is_none(),
            "the global ceiling outranks a peer's own unused allowance"
        );
        assert_eq!(
            limiter.count(&d),
            0,
            "a refused peer leaves no entry behind"
        );

        drop(first);
        assert_eq!(limiter.total(), 2);
        assert!(
            limiter.try_acquire(d).is_some(),
            "a freed global slot is reusable"
        );
    }

    #[test]
    fn dropping_a_guard_frees_the_global_count_too() {
        let limiter = Arc::new(ConnectionLimiter::with_caps(4, 2));
        let a = peer(1);
        let b = peer(2);

        let guards: Vec<_> = (0..2).map(|_| limiter.try_acquire(a).unwrap()).collect();
        assert_eq!(limiter.total(), 2);
        assert!(limiter.try_acquire(b).is_none());

        drop(guards);
        // Not just zero: a release that only decremented the per-peer map would
        // leave the total stuck at 2 and refuse every connection from here on.
        assert_eq!(limiter.total(), 0);
        assert!(limiter.try_acquire(b).is_some());
    }

    #[test]
    fn the_per_peer_cap_still_applies_under_a_generous_global_one() {
        let limiter = Arc::new(ConnectionLimiter::with_caps(1, 1000));
        let a = peer(1);

        let first = limiter.try_acquire(a).expect("first connection fits");
        assert!(
            limiter.try_acquire(a).is_none(),
            "a peer at its own cap is refused long before the global one"
        );
        assert_eq!(limiter.total(), 1);

        drop(first);
        assert_eq!(limiter.total(), 0);
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

    #[tokio::test]
    async fn streams_stop_at_the_process_ceiling() {
        let limiter = Arc::new(StreamLimiter::new(2));

        let first = limiter.try_acquire().expect("first stream fits");
        let second = limiter.try_acquire().expect("second stream fits");
        assert_eq!(limiter.available(), 0);

        assert!(
            limiter.try_acquire().is_none(),
            "a stream past the process ceiling is refused, not queued"
        );

        drop(first);
        assert_eq!(limiter.available(), 1);
        assert!(limiter.try_acquire().is_some());
        drop(second);
    }

    #[tokio::test]
    async fn a_zero_stream_ceiling_refuses_everything() {
        let limiter = Arc::new(StreamLimiter::new(0));
        assert!(limiter.try_acquire().is_none());
        assert_eq!(limiter.available(), 0);
    }

    /// An operator who writes a huge `NEXAPIPE_MAX_STREAMS` means "unlimited",
    /// and `Semaphore::new` panics above `MAX_PERMITS` — so without a clamp the
    /// server does not start at all, which is the one outcome a value this large
    /// should never produce.
    #[tokio::test]
    async fn an_oversized_stream_ceiling_does_not_take_the_listener_down() {
        let limiter = Arc::new(StreamLimiter::new(usize::MAX));
        assert_eq!(
            limiter.max_global(),
            tokio::sync::Semaphore::MAX_PERMITS,
            "the ceiling is clamped to what a semaphore can actually hold"
        );
        assert!(
            limiter.try_acquire().is_some(),
            "a clamped ceiling still admits streams"
        );
    }

    #[test]
    fn bodies_are_bounded_across_the_process() {
        let budget = ByteBudget::new(100);

        budget.try_reserve(60).expect("the first body fits");
        assert_eq!(budget.held(), 60);

        // The per-request cap would allow this; the process-wide one does not,
        // and that is the case a single request's limit cannot catch.
        let err = budget.try_reserve(60).expect_err("the second does not fit");
        assert_eq!(err, 60, "the error reports the total that was already held");
        assert_eq!(budget.held(), 60, "a refused reservation changes nothing");

        budget.release(60);
        assert_eq!(budget.held(), 0);
        budget
            .try_reserve(100)
            .expect("the whole budget is usable again");
    }

    #[test]
    fn releasing_more_than_was_taken_cannot_wrap_the_counter() {
        // Saturating on purpose: a double release would otherwise wrap a usize
        // to near its maximum and leave the budget permanently full, which is a
        // far worse failure than a counter that drifts low.
        let budget = ByteBudget::new(100);
        budget.try_reserve(10).unwrap();
        budget.release(50);
        assert_eq!(budget.held(), 0);
        budget.try_reserve(100).expect("still usable");
    }

    #[test]
    fn a_reservation_returns_its_bytes_when_dropped() {
        // The whole reason this is a guard: nothing at the reading site is
        // around later to give the bytes back.
        {
            let _held = ByteReservation::take(10).expect("the first fits");
            assert!(body_budget().held() >= 10);
        }
        assert!(
            ByteReservation::take(1).is_ok(),
            "a released budget admits the next body"
        );
    }
}

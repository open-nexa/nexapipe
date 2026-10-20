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
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// The `[limits]` section: the ceilings the whole process runs under.
///
/// Every key is optional, and every default is the constant the server used
/// before this section existed, so a config that does not mention `[limits]`
/// behaves exactly as it did — the section is a way to *write down* a ceiling,
/// not a new one.
///
/// **Unknown keys are refused here**, for the reason they are refused under
/// `[peers]`: a misspelled limit is a limit that silently does not apply, and
/// the process then runs with a ceiling nobody wrote down. Refused at load,
/// where the error names the key, rather than ignored at runtime, where
/// nothing would say so.
///
/// **A zero is refused at startup**, in [`Limits::resolve`]: it would refuse
/// every connection, which is a typo rather than a setting.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Concurrent connections one peer may hold.
    pub max_connections_per_peer: Option<usize>,
    /// Concurrent connections the whole process may hold.
    pub max_connections_global: Option<usize>,
    /// Concurrent streams the whole process may have in flight.
    pub max_streams_global: Option<usize>,
    /// Bytes of request bodies the whole process may hold at once.
    pub max_body_bytes: Option<usize>,
}

/// What the environment says about the ceilings.
///
/// Read once at startup, like everything else here. A value that is not a
/// positive number is a warning and not an outage: the environment is set in
/// a Dockerfile or a shell profile, and a bad value there should not keep the
/// server from starting — the default is used instead and the log says so.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnvCaps {
    pub max_connections_per_peer: Option<usize>,
    pub max_connections_global: Option<usize>,
    pub max_streams_global: Option<usize>,
    pub max_body_bytes: Option<usize>,
}

impl EnvCaps {
    /// Reads the four environment variables that name these ceilings.
    pub fn from_environment() -> Self {
        Self {
            max_connections_per_peer: cap_from_env(ENV_MAX_CONNECTIONS_PER_PEER),
            max_connections_global: cap_from_env(ENV_MAX_CONNECTIONS_GLOBAL),
            max_streams_global: cap_from_env(ENV_MAX_STREAMS_GLOBAL),
            max_body_bytes: cap_from_env(ENV_MAX_BODY_BYTES_GLOBAL),
        }
    }
}

/// The ceilings the process runs with, resolved once at startup.
///
/// The file answers "was this key written?"; this answers "how much may this
/// process do at once?", which is the question every accept path and every
/// body reader actually asks. Reading either side of the config directly would
/// put an `.unwrap_or(...)` in each of them, and one of them would eventually
/// disagree with the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_connections_per_peer: usize,
    pub max_connections_global: usize,
    pub max_streams_global: usize,
    pub max_body_bytes: usize,
}

impl Limits {
    /// Resolves the ceilings from the config and the environment.
    ///
    /// **The environment wins over the config.** It is the last thing an
    /// operator sets, and in a container it is often the only thing they can
    /// set without editing a file the image does not own. A key both name is
    /// a *warning* rather than a refusal: the effective ceilings are logged at
    /// startup, so the ambiguity is visible rather than silent, and refusing to
    /// boot over a resource knob is a heavier hand than this deserves.
    ///
    /// **A zero in the config is refused at startup**, because it would refuse
    /// every connection and the file is somewhere the operator can read the
    /// error. The environment keeps the older rule of ignoring a value it
    /// cannot use, because a bad variable in a Dockerfile should not take the
    /// listener offline.
    pub fn resolve(config: &LimitsConfig, env: &EnvCaps) -> anyhow::Result<Self> {
        Ok(Self {
            max_connections_per_peer: resolve_one(
                "[limits] max_connections_per_peer",
                config.max_connections_per_peer,
                env.max_connections_per_peer,
                ENV_MAX_CONNECTIONS_PER_PEER,
                DEFAULT_MAX_CONNECTIONS_PER_PEER,
            )?,
            max_connections_global: resolve_one(
                "[limits] max_connections_global",
                config.max_connections_global,
                env.max_connections_global,
                ENV_MAX_CONNECTIONS_GLOBAL,
                DEFAULT_MAX_CONNECTIONS_GLOBAL,
            )?,
            max_streams_global: resolve_one(
                "[limits] max_streams_global",
                config.max_streams_global,
                env.max_streams_global,
                ENV_MAX_STREAMS_GLOBAL,
                DEFAULT_MAX_STREAMS_GLOBAL,
            )?,
            max_body_bytes: resolve_one(
                "[limits] max_body_bytes",
                config.max_body_bytes,
                env.max_body_bytes,
                ENV_MAX_BODY_BYTES_GLOBAL,
                DEFAULT_MAX_BODY_BYTES_GLOBAL,
            )?,
        })
    }
}

/// One ceiling, from whichever source names it.
///
/// The order is the environment, then the config, then the default — see
/// [`Limits::resolve`] for why the environment outranks the file.
fn resolve_one(
    key: &str,
    from_config: Option<usize>,
    from_env: Option<usize>,
    env_var: &str,
    default: usize,
) -> anyhow::Result<usize> {
    // A zero from the environment is ignored rather than obeyed: it would
    // refuse everything, and the environment is a source an operator cannot
    // always edit. [`EnvCaps::from_environment`] already drops such a value,
    // so this is the belt to that braces.
    let from_env = from_env.filter(|value| *value > 0);
    if let Some(value) = from_config {
        if value == 0 {
            anyhow::bail!(
                "{key} is 0: that refuses every connection rather than bounding them, which is a \
                 typo rather than a setting. The smallest useful value is 1"
            );
        }
        if let Some(env_value) = from_env {
            tracing::warn!(
                "{env_var}={env_value} and {key}={value} are both set; the environment wins and the \
                 config's value is ignored. Remove one of them to say which was meant"
            );
            return Ok(env_value);
        }
        return Ok(value);
    }
    Ok(from_env.unwrap_or(default))
}

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
    /// The ceilings the server runs with, resolved once at startup.
    pub fn from_limits(limits: &Limits) -> Self {
        Self {
            connections: Arc::new(ConnectionLimiter::with_caps(
                limits.max_connections_per_peer,
                limits.max_connections_global,
            )),
            streams: Arc::new(StreamLimiter::new(limits.max_streams_global)),
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
            body_budget().max()
        )
    }
}

/// One env var to one cap, with the same "a bad value is a warning, not an
/// outage" rule the config file follows for a number it cannot use.
///
/// `None` means the variable is absent or unusable, and the caller falls back
/// to the config or the default.
fn cap_from_env(var: &str) -> Option<usize> {
    let Ok(raw) = std::env::var(var) else {
        return None;
    };
    match parse_max(&raw) {
        Some(max) => Some(max),
        None => {
            tracing::warn!("{var}={raw} is not a positive number, ignoring it");
            None
        }
    }
}

/// Concurrent streams the whole process may have in flight, unless the config or the
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
        self.max.load(Ordering::Relaxed)
    }
}

/// The process-wide body budget.
///
/// A `static` rather than a `OnceLock`, because the ceiling it enforces is
/// written into it after it exists: the budget has to be reachable from the
/// body readers, which are deep inside the HTTP path and hold no config, and
/// the ceiling comes from the configuration, which is read at startup.
///
/// The ceiling it starts with is the default one, and
/// [`init_body_budget`] replaces it before the first request is served.
static BUDGET: ByteBudget = ByteBudget::new(DEFAULT_MAX_BODY_BYTES_GLOBAL);

/// The process-wide body budget.
pub fn body_budget() -> &'static ByteBudget {
    &BUDGET
}

/// Sets the ceiling the process-wide body budget enforces.
///
/// Called once at startup, from the resolved [`Limits`], before any request
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

    #[test]
    fn the_body_budget_ceiling_can_be_written_after_it_exists() {
        // The point of the write: the budget is a `static` the HTTP path
        // reaches without a config, and its ceiling comes from one.
        let budget = ByteBudget::new(DEFAULT_MAX_BODY_BYTES_GLOBAL);
        assert_eq!(budget.max(), DEFAULT_MAX_BODY_BYTES_GLOBAL);

        budget.set_max(100);
        assert_eq!(budget.max(), 100);

        // And the ceiling is the one that is enforced, not just the one that is
        // reported.
        budget.try_reserve(60).expect("the first body fits");
        assert!(
            budget.try_reserve(60).is_err(),
            "the ceiling that was written is the one that applies"
        );

        // What is already reserved stays reserved: the write is about the
        // ceiling, not about the bytes held under the old one.
        assert_eq!(budget.held(), 60);
    }

    #[test]
    fn an_absent_section_resolves_to_the_defaults() {
        let limits = Limits::resolve(&LimitsConfig::default(), &EnvCaps::default())
            .expect("the defaults are usable");

        assert_eq!(
            limits.max_connections_per_peer,
            DEFAULT_MAX_CONNECTIONS_PER_PEER
        );
        assert_eq!(
            limits.max_connections_global,
            DEFAULT_MAX_CONNECTIONS_GLOBAL
        );
        assert_eq!(limits.max_streams_global, DEFAULT_MAX_STREAMS_GLOBAL);
        assert_eq!(limits.max_body_bytes, DEFAULT_MAX_BODY_BYTES_GLOBAL);
    }

    #[test]
    fn the_config_names_the_ceiling() {
        let config = LimitsConfig {
            max_connections_per_peer: Some(11),
            max_connections_global: Some(22),
            max_streams_global: Some(33),
            max_body_bytes: Some(44),
        };

        let limits = Limits::resolve(&config, &EnvCaps::default()).expect("the config is usable");
        assert_eq!(limits.max_connections_per_peer, 11);
        assert_eq!(limits.max_connections_global, 22);
        assert_eq!(limits.max_streams_global, 33);
        assert_eq!(limits.max_body_bytes, 44);
    }

    #[test]
    fn the_environment_outranks_the_config() {
        let config = LimitsConfig {
            max_connections_per_peer: Some(11),
            ..LimitsConfig::default()
        };
        let env = EnvCaps {
            max_connections_per_peer: Some(7),
            ..EnvCaps::default()
        };

        let limits = Limits::resolve(&config, &env).expect("the two sources are usable");
        assert_eq!(
            limits.max_connections_per_peer, 7,
            "the environment is the last thing an operator sets, so it wins"
        );
        assert_eq!(
            limits.max_connections_global, DEFAULT_MAX_CONNECTIONS_GLOBAL,
            "a key only one of them names is unaffected by the other"
        );
    }

    #[test]
    fn a_zero_ceiling_in_the_config_is_refused() {
        let config = LimitsConfig {
            max_connections_global: Some(0),
            ..LimitsConfig::default()
        };

        let error = Limits::resolve(&config, &EnvCaps::default())
            .expect_err("a ceiling of zero refuses every connection");
        let message = format!("{error:#}");
        assert!(
            message.contains("max_connections_global"),
            "the error names the key that cannot work: {message}"
        );
    }

    #[test]
    fn every_ceiling_is_refused_when_it_is_zero() {
        // One rule for all four, so a typo is refused wherever it is written
        // rather than in one key only.
        for config in [
            LimitsConfig {
                max_connections_per_peer: Some(0),
                ..LimitsConfig::default()
            },
            LimitsConfig {
                max_connections_global: Some(0),
                ..LimitsConfig::default()
            },
            LimitsConfig {
                max_streams_global: Some(0),
                ..LimitsConfig::default()
            },
            LimitsConfig {
                max_body_bytes: Some(0),
                ..LimitsConfig::default()
            },
        ] {
            assert!(
                Limits::resolve(&config, &EnvCaps::default()).is_err(),
                "a ceiling of zero is refused whatever it bounds"
            );
        }
    }

    #[test]
    fn a_zero_ceiling_in_the_environment_is_ignored() {
        // The environment keeps the older rule: a bad value in a Dockerfile
        // should not keep the server from starting.
        let env = EnvCaps {
            max_connections_per_peer: Some(0),
            ..EnvCaps::default()
        };

        let limits =
            Limits::resolve(&LimitsConfig::default(), &env).expect("the default is usable");
        assert_eq!(
            limits.max_connections_per_peer,
            DEFAULT_MAX_CONNECTIONS_PER_PEER
        );
    }
}

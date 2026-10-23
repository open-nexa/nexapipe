use crate::config::CircuitBreaker;
use rand;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::RwLock;

use super::circuit::{CircuitState, Phase};
use super::status::BackendStatus;
use super::strategy::LoadBalancingStrategy;

/// The scheme, the host and the port of a backend address, ready to be joined
/// to a path.
///
/// Parsed **once**, when the pool is built. A backend does not move, so the
/// answer does not either, and a `Url::parse` per request is a measurable
/// share of what a request costs.
///
/// The two failures are kept as they were written, because the request path
/// says them and the operator reads them there.
pub(super) fn origin_of(url: &str) -> Result<Arc<str>, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid backend URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "backend URL missing host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    Ok(Arc::from(
        format!("{}://{host}:{port}", parsed.scheme()).as_str(),
    ))
}

/// One backend in the pool: its health, and how much work it has outstanding.
///
/// The two sit together because choosing between backends needs both, and not
/// behind one lock because they are not read the same way: health changes twice
/// an `interval` from one probe, while the load is touched on every flow. [`Self::in_flight`]
/// is atomic so that releasing it — which happens in a `Drop`, with no chance
/// to await anything — can always happen, and never waits behind a health probe.
#[derive(Debug)]
pub(super) struct BackendEntry {
    /// The address, kept beside the health status so that the circuit can
    /// name the backend it is talking about without waiting on a lock.
    ///
    /// Shared, so that handing it to a request is a reference count rather
    /// than a copy: the address used to be cloned into every request that
    /// chose this backend.
    url: Arc<str>,
    /// The scheme, the host and the port of the address, ready to be joined
    /// to a path.
    ///
    /// **Parsed once, here**, when the pool is built: a backend does not
    /// move, and a `Url::parse` per request is a measurable share of what a
    /// request costs.
    ///
    /// The error is kept rather than thrown: a backend that cannot be parsed
    /// is reported when a request is built, where the operator can read it.
    origin: Result<Arc<str>, String>,
    /// Whether the backend is healthy.
    ///
    /// An **atomic**, because choosing a backend happens on every request and
    /// it is a read: it used to take the status lock, so a route with one
    /// backend paid a lock round trip per request for a flag.
    healthy: AtomicBool,
    status: RwLock<BackendStatus>,
    pub(super) in_flight: AtomicUsize,
    /// The circuit this backend's failures are counted on.
    ///
    /// A plain mutex rather than the async lock the health status uses: the
    /// circuit is read and written on every request, and it never waits for
    /// anything.
    circuit: Mutex<CircuitState>,
    /// The settings the circuit runs with.
    ///
    /// Absent means the circuit is off — a pool built in code, rather than
    /// from a config, behaves as it always did. Set once, when the route is
    /// built.
    breaker: OnceLock<CircuitBreaker>,
}

impl BackendEntry {
    fn new(url: String) -> Self {
        let origin = origin_of(&url);
        BackendEntry {
            url: Arc::from(url.as_str()),
            origin: match origin {
                Ok(origin) => Ok(origin),
                Err(reason) => Err(reason),
            },
            healthy: AtomicBool::new(true),
            status: RwLock::new(BackendStatus::default()),
            in_flight: AtomicUsize::new(0),
            circuit: Mutex::new(CircuitState::new()),
            breaker: OnceLock::new(),
        }
    }

    /// The settings the circuit runs with, if it runs with any.
    fn breaker(&self) -> Option<&CircuitBreaker> {
        self.breaker.get()
    }

    /// Whether a request may be sent to this backend right now.
    ///
    /// An open circuit says no until its cooldown has passed. The check does
    /// not change the state: whether the request that gets through is the
    /// trial one is decided by what happens to it.
    fn circuit_allows(&self) -> bool {
        let Some(breaker) = self.breaker() else {
            return true;
        };
        if !breaker.enabled {
            return true;
        }
        let circuit = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
        match circuit.phase {
            Phase::Closed => true,
            Phase::Open => circuit
                .opened_at
                .map(|at| at.elapsed() >= breaker.reset)
                .unwrap_or(true),
        }
    }

    /// The backend answered.
    fn circuit_succeeded(&self) {
        let mut circuit = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
        circuit.phase = Phase::Closed;
        circuit.failures = 0;
        circuit.opened_at = None;
    }

    /// The backend did not answer.
    fn circuit_failed(&self) {
        let Some(breaker) = self.breaker() else {
            return;
        };
        if !breaker.enabled {
            return;
        }
        let mut circuit = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
        circuit.failures += 1;
        // A circuit that is open re-opens on the first failure: the trial
        // request that the cooldown let through failed, and the backend is
        // still down.
        if circuit.phase == Phase::Open || circuit.failures >= breaker.failure_threshold {
            circuit.phase = Phase::Open;
            circuit.opened_at = Some(std::time::Instant::now());
            tracing::warn!(
                "Backend {} failed {} time(s) in a row; it is out of rotation for {:?}",
                self.url,
                circuit.failures,
                breaker.reset
            );
        }
    }
}

/// A backend handed out for one flow.
///
/// Holding this is what makes `least_conn` true: `Drop` is where the backend's
/// load goes back down, so the caller decides when the work counts as finished
/// simply by deciding when to let go. A caller that releases early tells the
/// balancer the work is over; there is no second, mandatory step to forget.
///
/// That freedom has a failure mode — see the tie-breaking note on
/// [`BackendPool::select_backend`] for how the pick degrades rather than
/// stampedes when a lease is released too early.
pub struct BackendLease {
    entry: Arc<BackendEntry>,
}

impl BackendLease {
    /// The scheme, the host and the port of the address, ready to be joined
    /// to a path.
    ///
    /// Parsed once, when the pool was built.
    pub fn origin(&self) -> &Result<Arc<str>, String> {
        &self.entry.origin
    }

    /// The address this flow is to be forwarded to, shared.
    ///
    /// A reference to the pool's own copy, so that handing it to a request
    /// is a reference count and not a copy of the address.
    pub fn shared_url(&self) -> &Arc<str> {
        &self.entry.url
    }

    /// The address this flow is to be forwarded to.
    pub fn url(&self) -> &str {
        // The entry holds the address, so this is a borrow of it: the lease
        // used to keep a copy of its own, which was a heap allocation and a
        // lock read on every request.
        &self.entry.url
    }

    /// The backend answered.
    ///
    /// What the circuit counts: a backend that answers is a backend that is
    /// up, however slowly it answered.
    pub fn record_success(&self) {
        self.entry.circuit_succeeded();
    }

    /// The backend did not answer.
    ///
    /// What the circuit counts: a backend that refuses connections or that
    /// never sends a status line is a backend that is down, and after enough
    /// of those it stops being picked.
    pub fn record_failure(&self) {
        self.entry.circuit_failed();
    }
}

// Hand-written because the useful `Debug` for this is not its fields but what it
// is: an address, and how much work the pool thinks that address has.
impl std::fmt::Debug for BackendLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendLease")
            .field("url", &self.entry.url)
            .field("outstanding", &self.entry.in_flight.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for BackendLease {
    fn drop(&mut self) {
        self.entry.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct BackendPool {
    pub(super) backends: Vec<Arc<BackendEntry>>,
    strategy: LoadBalancingStrategy,
    /// Where the rotation is, so that two requests do not pick the same
    /// backend.
    ///
    /// **An atomic, not a lock.** The whole of the round-robin's work is one
    /// increment, and it stood under an exclusive write lock — so every
    /// request to this route queued behind every other one for the sake of a
    /// counter, and the queue was an async one. The increment is the only
    /// thing that has to be exclusive, and an atomic increment is exclusive by
    /// itself.
    ///
    /// Both rotations share it — the round-robin's own and the `least_conn`
    /// tie-break's — so a pool has one cursor rather than two.
    pub(super) round_robin_index: Arc<AtomicUsize>,
}

impl BackendPool {
    pub fn new(backends: Vec<String>, strategy: LoadBalancingStrategy) -> Self {
        let backend_statuses = backends
            .into_iter()
            .map(|url| Arc::new(BackendEntry::new(url)))
            .collect();

        BackendPool {
            backends: backend_statuses,
            strategy,
            round_robin_index: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The settings the circuit on every backend of this pool runs with.
    ///
    /// Set once, when the route is built: a pool built in code — a test, the
    /// local proxy — has no circuit at all and behaves as it always did.
    pub fn set_circuit_breaker(&self, breaker: CircuitBreaker) {
        for backend in &self.backends {
            let _ = backend.breaker.set(breaker);
        }
    }

    /// Which backend a `least_conn` pool hands out, from a snapshot of every
    /// healthy backend's outstanding count.
    ///
    /// It takes a snapshot rather than the pool because the minimum and the tie
    /// have to come from the same reading of the counters, and only one reading
    /// can guarantee that — see the caller.
    ///
    /// `cursor` is where the rotation is, and it is taken modulo the size of
    /// the tie here, where the tie is known: the tie's size decides where the
    /// rotation continues, and it is not known until the counts have been
    /// read, so the cursor cannot be reduced to it before the call.
    ///
    /// `counts` is never empty: a pool with no healthy backend either refuses
    /// or hands out its single entry before reaching here, so the tie — which
    /// always contains whoever holds the minimum, and the minimum comes from
    /// this same slice — is never empty either.
    pub(super) fn least_conn_pick(counts: &[(usize, usize)], cursor: usize) -> usize {
        debug_assert!(
            !counts.is_empty(),
            "a pool with nothing healthy answers before it reaches the balancer"
        );

        let least = counts
            .iter()
            .map(|(_, outstanding)| *outstanding)
            .min()
            .unwrap_or(0);
        let tied: Vec<usize> = counts
            .iter()
            .filter(|(_, outstanding)| *outstanding == least)
            .map(|(index, _)| *index)
            .collect();

        tied[cursor % tied.len()]
    }

    /// A backend to send this flow to, or `None` when the pool has nothing left
    /// to serve.
    ///
    /// One healthy backend is enough to get an answer, and the two unhappy cases
    /// are deliberately answered differently:
    ///
    /// - **Nothing healthy, one backend in the pool.** Handed out anyway. With
    ///   one candidate, health information buys nothing — there is no second
    ///   choice for it to inform — and refusing would take down the only path
    ///   this route has in order to report that the one path is unavailable.
    /// - **Nothing healthy, several backends.** `None`: all of them being down
    ///   *is* the answer, and dialling the first one regardless spends the whole
    ///   connect timeout writing the same `502`/refusal the caller can write now,
    ///   with nothing left to try afterwards.
    ///
    /// `None` from a **pool of one** therefore never happens, and from a pool of
    /// several it is not routeable — which is why callers must not collapse it
    /// into their own "no route" answer. See each caller in
    /// `crate::routes::RoutingTable`.
    pub async fn select_backend(&self) -> Option<BackendLease> {
        self.select_backend_excluding(&[]).await
    }

    /// A backend to send this flow to, preferring one that has not been tried
    /// yet.
    ///
    /// The exclusion list is what a retry is built on: a backend that just
    /// failed is the one most likely to fail again, so the next attempt asks
    /// somebody else — where the route has somebody else. A route with a
    /// single backend has nobody else to ask, and that backend is handed out
    /// again: there is no other answer to give, and a second attempt at the
    /// same backend is still better than none.
    pub async fn select_backend_excluding(&self, exclude: &[String]) -> Option<BackendLease> {
        // **One vector, filtered in place.** It used to be three — the healthy
        // ones, the ones whose circuit is not open, and the ones that have not
        // been tried — and each was a heap allocation on every request.
        let mut healthy_backends: Vec<usize> = Vec::new();
        for (i, b) in self.backends.iter().enumerate() {
            if b.healthy.load(Ordering::Relaxed) {
                healthy_backends.push(i);
            }
        }

        if healthy_backends.is_empty() {
            // A pool of one has nothing to choose between, so health is not
            // information here — it is a single backend that is either up, or
            // the only chance this request has.
            if self.backends.len() == 1 {
                let url = self.backends[0].url.clone();
                tracing::warn!(
                    "Backend {} is the only one behind this route and reports unhealthy; \
                     forwarding anyway, because refusing would answer for every request to it",
                    url
                );
                return Some(self.lease(0).await);
            }

            // Several, all down: the question has an answer now, and it does not
            // improve by dialling one of them.
            tracing::warn!(
                "No healthy backend among {} behind this route; refusing without dialling one",
                self.backends.len()
            );
            return None;
        }

        // The ones whose circuit is not open. A backend that keeps failing is
        // out of rotation until its cooldown passes: the route answers 503
        // rather than dialling a backend that is known to be down, which
        // spends a whole connect timeout to say the same thing.
        //
        // Filtered before the exclusion list, not after: an untried backend
        // whose circuit is open cannot be asked either, and preferring it over
        // a tried backend that is still serving would refuse a request that
        // has somewhere to go.
        let healthy_count = healthy_backends.len();
        healthy_backends.retain(|i| self.backends[*i].circuit_allows());
        if healthy_backends.len() < healthy_count {
            tracing::warn!(
                "{} of {healthy_count} healthy backend(s) behind this route are out of \
                 rotation; the circuit is open on them",
                healthy_count - healthy_backends.len(),
            );
        }
        if healthy_backends.is_empty() {
            // Every healthy backend has an open circuit. That is an answer:
            // the route is configured and nothing behind it is serving.
            return None;
        }

        // The ones that have not been tried yet, when there are any. A pool
        // whose every serving backend is on the list falls back to the whole
        // set, because the alternative is not to try at all.
        //
        // The address is the entry's own, so the comparison does not take the
        // status lock — it used to, once per backend.
        let any_untried = healthy_backends.iter().any(|i| {
            !exclude
                .iter()
                .any(|e| e.as_str() == &*self.backends[*i].url)
        });
        if any_untried {
            healthy_backends.retain(|i| {
                !exclude
                    .iter()
                    .any(|e| e.as_str() == &*self.backends[*i].url)
            });
        } else if !exclude.is_empty() {
            tracing::debug!(
                "Every serving backend behind this route has been tried; trying one of them \
                 again, because there is nobody else to ask"
            );
        }

        let idx = match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                // The counter is the whole of the state, and an atomic
                // increment is the whole of the work: two requests that arrive
                // together get two different numbers, and neither waits for
                // the other.
                let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed);
                healthy_backends[index % healthy_backends.len()]
            }
            LoadBalancingStrategy::Random => {
                let rand_idx = (rand::random::<u64>() % healthy_backends.len() as u64) as usize;
                healthy_backends[rand_idx]
            }
            LoadBalancingStrategy::LeastConn => {
                // Fewest requests outstanding wins. "Outstanding" is counted
                // from the moment a backend is chosen until the flow releases
                // its [`BackendLease`], which is wherever that flow decides the
                // work ended — response written by the HTTP paths, flow copied
                // by the tunnels and passthrough. It counts requests, not
                // sockets: an HTTP backend is reached through a pooled,
                // keep-alive client, and how many connections that pool is
                // holding open is not something this process can see.
                //
                // Ties rotate rather than taking the first index, because almost
                // every tie is "nothing is happening right now" — an idle proxy
                // is all zeroes — and taking the first index would then send
                // every request to the first healthy backend, which is the load
                // this strategy exists to spread. Rotating also means a lease
                // released too early costs a little accuracy instead of all of
                // it: worst case the balance degrades towards round-robin.
                //
                // The counts are read once, into one snapshot, and both the
                // least and the tie come out of it. Reading them twice — once
                // for the least, once for whoever is tied at it — lets a lease
                // released in between empty the tie: the only backend at the
                // least finishes, nothing is at the least any more, and a pool
                // that does have backends divides by a tie of zero.
                let counts: Vec<(usize, usize)> = healthy_backends
                    .into_iter()
                    .map(|i| (i, self.backends[i].in_flight.load(Ordering::Relaxed)))
                    .collect();

                // The tie is broken by the rotation, so that a pool of equal
                // backends does not send everything to the first one.
                //
                // The cursor is advanced by one atomic increment, the same one
                // the round-robin uses: two requests that arrive together get
                // two different cursors, and neither waits for the other.
                // That is what makes the rotation a rotation under a burst —
                // a read followed by a write is not one thing, and two
                // requests that read the same cursor pick the same backend,
                // which lands the burst on one backend while its peers sit
                // idle.
                //
                // The tie's own size decides where the rotation continues, and
                // that size is only known once the counts have been read, so
                // the modulo is applied where the cursor is used — picking
                // from the tie — and not where it is stored.
                let cursor = self.round_robin_index.fetch_add(1, Ordering::Relaxed);
                Self::least_conn_pick(&counts, cursor)
            }
        };

        let selected = self.lease(idx).await;
        let outstanding = self.backends[idx].in_flight.load(Ordering::Relaxed);
        tracing::debug!(
            "Selected backend: {} (strategy={:?}, outstanding={})",
            selected.url(),
            self.strategy,
            outstanding,
        );
        // Some, because reaching here means one was chosen; the `None`s above are
        // the cases where no choice exists at all.
        Some(selected)
    }

    /// Hands out one backend, counting it as outstanding from here until the
    /// lease is dropped.
    async fn lease(&self, idx: usize) -> BackendLease {
        // Indexed rather than looked up: every index handed here came out of
        // this same vector in the caller, and an out-of-range one panics here
        // rather than being quietly read as "no backend available".
        let entry = Arc::clone(&self.backends[idx]);
        entry.in_flight.fetch_add(1, Ordering::Relaxed);
        BackendLease { entry }
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn strategy(&self) -> LoadBalancingStrategy {
        self.strategy
    }

    pub async fn backends(&self) -> Vec<String> {
        let mut result = Vec::new();
        for b in &self.backends {
            result.push(b.url.to_string());
        }
        result
    }

    /// How many requests are outstanding against one backend right now.
    ///
    /// The number `least_conn` balances on, exposed so that what it counts
    /// can be checked rather than taken on trust: a backend that is streaming
    /// a response is busy, and one that answered and is waiting for the next
    /// request is not.
    pub async fn outstanding(&self, url: &str) -> usize {
        let mut count = 0;
        for backend in &self.backends {
            if &*backend.url == url {
                count += backend.in_flight.load(Ordering::Relaxed);
            }
        }
        count
    }

    /// How many backends are healthy right now.
    ///
    /// Reported rather than deduced from [`BackendPool::select_backend`], which
    /// still answers from a pool of one that is down — deliberately, see there —
    /// so "healthy" and "handed out" are not the same question and only this one
    /// answers the healthy half of it.
    pub async fn healthy_count(&self) -> usize {
        let mut count = 0;
        for backend in &self.backends {
            if backend.healthy.load(Ordering::Relaxed) {
                count += 1;
            }
        }
        count
    }

    pub async fn set_backend_health(&self, url: &str, healthy: bool) {
        // Every entry carrying this URL, not the first: a pool is allowed to
        // name the same backend twice, and stopping at the first left the rest
        // healthy forever — so the pool reported a backend as up while half its
        // entries were down and the balancer kept picking them.
        let mut matched = false;
        for backend in &self.backends {
            if &*backend.url != url {
                continue;
            }
            matched = true;
            // The flag first, then the bookkeeping: the flag is what the
            // request path reads, and it is read without a lock.
            backend.healthy.store(healthy, Ordering::Relaxed);
            let mut status = backend.status.write().await;
            if healthy {
                status.mark_healthy();
            } else {
                status.mark_unhealthy();
            }
            tracing::debug!(
                "Backend {} health status: {} (failures: {})",
                url,
                healthy,
                status.consecutive_failures()
            );
        }

        if !matched {
            tracing::debug!("set_backend_health: no backend named {url} in this pool");
        }
    }

    pub async fn get_backend_statuses(&self) -> Vec<(String, bool)> {
        let mut result = Vec::new();
        for b in &self.backends {
            result.push((b.url.to_string(), b.healthy.load(Ordering::Relaxed)));
        }
        result
    }

    /// How many times in a row the backend named `url` has been marked
    /// unhealthy.
    ///
    /// This counts **transitions**, not probes: the count goes up when the
    /// pool is told the backend is down, and a round that marks the same
    /// backend twice in a row counts twice — which is the mistake a test that
    /// only looks at the end state cannot see.
    ///
    /// Only the tests read this. The pool is what a health check marks, so a
    /// test that wants to know how often it was marked has to ask the pool.
    #[cfg(test)]
    pub(crate) async fn backend_failures(&self, url: &str) -> Option<usize> {
        let mut failures = None;
        for backend in &self.backends {
            if &*backend.url != url {
                continue;
            }
            let count = backend.status.read().await.consecutive_failures();
            failures = Some(failures.map_or(count, |seen: usize| seen.max(count)));
        }
        failures
    }
}

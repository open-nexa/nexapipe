use rand;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
    /// Fewest requests outstanding to this backend wins; see
    /// [`BackendPool::select_backend`] for what "outstanding" counts and what
    /// happens to the ties.
    LeastConn,
}

#[derive(Debug, Clone)]
pub struct BackendStatus {
    url: String,
    healthy: bool,
    last_check: Option<std::time::Instant>,
    consecutive_failures: usize,
}

impl BackendStatus {
    pub fn new(url: String) -> Self {
        BackendStatus {
            url,
            healthy: true,
            last_check: None,
            consecutive_failures: 0,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    pub fn mark_healthy(&mut self) {
        self.healthy = true;
        self.consecutive_failures = 0;
        self.last_check = Some(std::time::Instant::now());
    }

    pub fn mark_unhealthy(&mut self) {
        self.healthy = false;
        self.consecutive_failures += 1;
        self.last_check = Some(std::time::Instant::now());
    }

    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }
}

/// One backend in the pool: its health, and how much work it has outstanding.
///
/// The two sit together because choosing between backends needs both, and not
/// behind one lock because they are not read the same way: health changes twice
/// an `interval` from one probe, while the load is touched on every flow. [`Self::in_flight`]
/// is atomic so that releasing it — which happens in a `Drop`, with no chance
/// to await anything — can always happen, and never waits behind a health probe.
#[derive(Debug)]
struct BackendEntry {
    status: RwLock<BackendStatus>,
    in_flight: AtomicUsize,
}

impl BackendEntry {
    fn new(url: String) -> Self {
        BackendEntry {
            status: RwLock::new(BackendStatus::new(url)),
            in_flight: AtomicUsize::new(0),
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
    url: String,
}

impl BackendLease {
    /// The address this flow is to be forwarded to.
    pub fn url(&self) -> &str {
        &self.url
    }
}

// Hand-written because the useful `Debug` for this is not its fields but what it
// is: an address, and how much work the pool thinks that address has.
impl std::fmt::Debug for BackendLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendLease")
            .field("url", &self.url)
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
    backends: Vec<Arc<BackendEntry>>,
    strategy: LoadBalancingStrategy,
    round_robin_index: Arc<RwLock<usize>>,
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
            round_robin_index: Arc::new(RwLock::new(0)),
        }
    }

    /// Which backend a `least_conn` pool hands out, from a snapshot of every
    /// healthy backend's outstanding count.
    ///
    /// It takes a snapshot rather than the pool because the minimum and the tie
    /// have to come from the same reading of the counters, and only one reading
    /// can guarantee that — see the caller. Returns the chosen backend's index
    /// and how many backends tied at the least, so the caller can advance its
    /// cursor over the set it chose from.
    ///
    /// `counts` is never empty: a pool with no healthy backend either refuses
    /// or hands out its single entry before reaching here, so the tie — which
    /// always contains whoever holds the minimum, and the minimum comes from
    /// this same slice — is never empty either.
    fn least_conn_pick(counts: &[(usize, usize)], cursor: usize) -> (usize, usize) {
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

        (tied[cursor % tied.len()], tied.len())
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
    /// `crate::routes::RouteConfig`.
    pub async fn select_backend(&self) -> Option<BackendLease> {
        let mut healthy_backends = Vec::new();
        for (i, b) in self.backends.iter().enumerate() {
            if b.status.read().await.is_healthy() {
                healthy_backends.push(i);
            }
        }

        if healthy_backends.is_empty() {
            // A pool of one has nothing to choose between, so health is not
            // information here — it is a single backend that is either up, or
            // the only chance this request has.
            if self.backends.len() == 1 {
                let url = self.backends[0].status.read().await.url.clone();
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

        let idx = match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let mut index = self.round_robin_index.write().await;
                let idx = healthy_backends[*index % healthy_backends.len()];
                *index = (*index + 1) % healthy_backends.len();
                idx
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

                let mut index = self.round_robin_index.write().await;
                let (idx, tied) = Self::least_conn_pick(&counts, *index);
                *index = (*index + 1) % tied;
                idx
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
        let url = entry.status.read().await.url.clone();
        entry.in_flight.fetch_add(1, Ordering::Relaxed);
        BackendLease { entry, url }
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
            result.push(b.status.read().await.url.clone());
        }
        result
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
            if backend.status.read().await.is_healthy() {
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
            let mut status = backend.status.write().await;
            if status.url != url {
                continue;
            }
            matched = true;
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
            let status = b.status.read().await;
            result.push((status.url.clone(), status.healthy));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(backends: &[&str]) -> BackendPool {
        BackendPool::new(
            backends.iter().map(|b| b.to_string()).collect(),
            LoadBalancingStrategy::RoundRobin,
        )
    }

    /// Same pool with another strategy. Every test below is about one strategy's
    /// choice, so which one it is should be the only thing spelled at its top.
    fn pool_with(strategy: LoadBalancingStrategy, backends: &[&str]) -> BackendPool {
        BackendPool::new(backends.iter().map(|b| b.to_string()).collect(), strategy)
    }

    #[tokio::test]
    async fn every_entry_carrying_a_url_is_marked_not_just_the_first() {
        let pool = pool(&["http://a:80", "http://a:80"]);
        assert_eq!(pool.healthy_count().await, 2);

        pool.set_backend_health("http://a:80", false).await;

        assert_eq!(
            pool.get_backend_statuses().await,
            vec![
                ("http://a:80".to_string(), false),
                ("http://a:80".to_string(), false),
            ],
            "the second entry stayed healthy, so the balancer kept picking a backend the pool had already given up on"
        );
        assert_eq!(pool.healthy_count().await, 0);
    }

    /// The one backend a route has is the one it serves, health or not: there is
    /// no second candidate for that information to choose between, and refusing
    /// would answer for every request to a route rather than let any through.
    #[tokio::test]
    async fn a_pool_of_one_is_handed_out_though_it_is_unhealthy() {
        let pool = pool(&["http://only:80"]);
        pool.set_backend_health("http://only:80", false).await;
        assert_eq!(pool.healthy_count().await, 0);

        let lease = pool
            .select_backend()
            .await
            .expect("a single backend is the only path this route has");
        assert_eq!(lease.url(), "http://only:80");
    }

    /// Several backends, none healthy: the answer is known before any dialling
    /// happens, so none is attempted. This is a behaviour change — it used to
    /// hand out the first one and let the client wait out a connect timeout.
    #[tokio::test]
    async fn a_pool_with_several_unhealthy_backends_refuses_without_dialling() {
        let pool = pool(&["http://a:80", "http://b:80"]);
        pool.set_backend_health("http://a:80", false).await;
        pool.set_backend_health("http://b:80", false).await;

        assert_eq!(pool.healthy_count().await, 0);
        assert!(
            pool.select_backend().await.is_none(),
            "every backend behind this route is down, so there is nothing to dial"
        );
    }

    /// An empty pool refuses, which cannot come from a config: `build_routes`
    /// rejects a route with no backends. Reached only by a pool built in code.
    #[tokio::test]
    async fn an_empty_pool_refuses() {
        let pool = pool(&[]);
        assert!(pool.select_backend().await.is_none());
    }

    #[tokio::test]
    async fn least_conn_sends_the_next_flow_to_whichever_backend_is_freer() {
        let pool = pool_with(
            LoadBalancingStrategy::LeastConn,
            &["http://a:80", "http://b:80"],
        );

        let busy = pool
            .select_backend()
            .await
            .expect("both backends are idle and healthy");
        // Still held: this backend has one flow against the other one's none.
        assert_eq!(busy.url(), "http://a:80");

        let next = pool
            .select_backend()
            .await
            .expect("a healthy backend remains");
        assert_eq!(
            next.url(),
            "http://b:80",
            "the first backend is still serving the flow it was handed out for"
        );

        // Now the scores are level, and the tie rotates — which is why this is
        // `least_conn` and not "one backend until somebody finishes".
        drop(busy);
        assert_eq!(
            pool.select_backend().await.unwrap().url(),
            "http://a:80",
            "A is free again while B still carries its flow, so A is next"
        );
    }

    /// What keeps `least_conn` from being worse than `RoundRobin`: nearly every
    /// tie is "nothing is running right now", and picking the lowest index would
    /// then send everything to the first backend — the load this strategy exists
    /// to spread.
    #[tokio::test]
    async fn least_conn_rotates_when_nothing_is_outstanding() {
        let pool = pool_with(
            LoadBalancingStrategy::LeastConn,
            &["http://a:80", "http://b:80"],
        );

        let first = pool.select_backend().await.unwrap().url().to_string();
        let second = pool.select_backend().await.unwrap().url().to_string();

        assert_eq!(
            (first.as_str(), second.as_str()),
            ("http://a:80", "http://b:80"),
            "both are idle, so the two picks should not land on the same backend"
        );
    }

    /// A lease nobody held any more has to have been released, or every later
    /// choice is made against a count that only ever grows.
    #[tokio::test]
    async fn dropping_a_lease_releases_the_backend() {
        let pool = pool_with(
            LoadBalancingStrategy::LeastConn,
            &["http://a:80", "http://b:80"],
        );

        let first = pool.select_backend().await.unwrap();
        drop(first);

        assert_eq!(
            pool.backends
                .iter()
                .map(|b| b.in_flight.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            vec![0, 0],
            "a dropped lease is finished work"
        );
    }

    #[test]
    fn least_conn_pick_takes_the_backend_with_the_least_outstanding() {
        assert_eq!(
            BackendPool::least_conn_pick(&[(0, 3), (1, 1), (2, 7)], 0),
            (1, 1),
            "one backend carries a single flow against three and seven"
        );
    }

    /// Ties rotate, and over the tied set rather than the whole pool: the caller
    /// advances its cursor by the number the pick reports, so three idle
    /// backends are walked in turn instead of the first one taking everything.
    #[test]
    fn least_conn_pick_rotates_through_every_backend_tied_at_the_least() {
        let counts = vec![(0, 0), (1, 0), (2, 0)];

        let picked: Vec<usize> = (0..4)
            .map(|cursor| BackendPool::least_conn_pick(&counts, cursor).0)
            .collect();
        assert_eq!(
            picked,
            vec![0, 1, 2, 0],
            "three idle backends, walked in turn"
        );

        // A unique minimum leaves nothing to rotate, however far the cursor has
        // run — and it reports a tie of one, not of zero.
        assert_eq!(
            BackendPool::least_conn_pick(&[(0, 9), (1, 4), (2, 9)], 41),
            (1, 1)
        );
    }

    /// The pick reads the counters once, so the least and the tie come from the
    /// same slice and whoever holds the least is always in the tie. Reading them
    /// twice let a lease released in between empty it: the only backend at the
    /// least finished, nothing was at the least any more, and a pool that did
    /// have backends divided by zero.
    #[test]
    fn least_conn_pick_always_leaves_something_to_choose_from() {
        let samples: Vec<Vec<(usize, usize)>> = vec![
            vec![(0, 0)],
            vec![(0, 5), (1, 5)],
            vec![(0, 1), (1, 2), (2, 3)],
            vec![(0, 3), (1, 2), (2, 1)],
            vec![(0, 0), (1, 9), (2, 0)],
            vec![(0, 7), (1, 7), (2, 7), (3, 6)],
        ];

        for counts in samples {
            let least = counts
                .iter()
                .map(|(_, outstanding)| *outstanding)
                .min()
                .unwrap();
            // `usize::MAX` included: the cursor is only ever taken modulo the
            // tie, so it must not be able to overflow its way out of one.
            for cursor in [0, 1, 2, 5, usize::MAX] {
                let (index, tied) = BackendPool::least_conn_pick(&counts, cursor);

                assert!(
                    tied >= 1,
                    "a tie of {tied} would divide by zero in the caller: {counts:?}"
                );
                let (_, outstanding) = counts
                    .iter()
                    .find(|(i, _)| *i == index)
                    .expect("the pick is one of the backends it was given");
                assert_eq!(
                    *outstanding, least,
                    "a backend that is not at the least was chosen from {counts:?}"
                );
            }
        }
    }
}

use crate::ClientError;
use crate::auth::{Enrollment, IssuedCredential, TwoFactorAuth};
use crate::connection_pool::{IrohConnectionPool, LinkKind, PRECONNECT_TIMEOUT};
use crate::lb::{LoadBalancer, LoadBalancingStrategy, RandomBalancer, RoundRobinBalancer};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

#[cfg(feature = "jni")]
use crate::jni_log;

/// No-op `jni_log!` for builds without the `jni` feature.
///
/// The format arguments are still *evaluated* (borrowed) inside a dead branch,
/// so the optimiser removes the call but `unused_variables` does not fire on
/// variables that only ever appear inside a log statement.
#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if false {
            let _ = ::std::format_args!($($arg)*);
        }
    };
}

#[derive(Debug, Clone)]
pub struct PooledConnection {
    conn: Connection,
    pool_index: usize,
}

impl PooledConnection {
    pub fn new(conn: Connection, pool_index: usize) -> Self {
        Self { conn, pool_index }
    }

    pub fn into_inner(self) -> Connection {
        self.conn
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Closes the connection instead of just letting go of it.
    ///
    /// Dropping one handle does not close a connection: it closes when the
    /// last one goes, and a path watcher holds one for as long as it lives, so
    /// a caller that has decided the connection is dead has to say so or it
    /// stays open — still in the pool's address space, still counted, and
    /// still handed to whatever asks next.
    pub fn discard(self, reason: &'static [u8]) {
        self.conn.close(0u32.into(), reason);
    }

    pub fn pool_index(&self) -> usize {
        self.pool_index
    }
}

pub struct DomainPools {
    pools: Vec<Arc<IrohConnectionPool>>,
    balancer: Box<dyn LoadBalancer + Sync + Send>,
}

impl DomainPools {
    pub fn new(pools: Vec<Arc<IrohConnectionPool>>, strategy: LoadBalancingStrategy) -> Self {
        let balancer: Box<dyn LoadBalancer + Sync + Send> = match strategy {
            LoadBalancingStrategy::RoundRobin => Box::new(RoundRobinBalancer::new()),
            LoadBalancingStrategy::Random => Box::new(RandomBalancer::new()),
        };
        Self { pools, balancer }
    }

    pub async fn get_connection(&self) -> Result<PooledConnection, ClientError> {
        if self.pools.is_empty() {
            return Err(ClientError::InvalidConfig(
                "No endpoint pools configured".to_string(),
            ));
        }
        let index = self.balancer.select(self.pools.len());
        let conn = self.pools[index].get_connection().await?;
        Ok(PooledConnection::new(conn, index))
    }

    pub async fn return_connection(&self, pooled_conn: PooledConnection) {
        if self.pools.is_empty() {
            return;
        }
        let index = pooled_conn.pool_index();
        if index < self.pools.len() {
            self.pools[index]
                .return_connection(pooled_conn.into_inner())
                .await;
        }
    }

    /// The backend node IDs this domain load-balances across (the configured
    /// `server_node_id`s), one per pool.
    pub fn node_ids(&self) -> Vec<EndpointId> {
        self.pools.iter().map(|p| p.backend_id()).collect()
    }
}

pub struct EndpointGroup {
    domains: HashMap<String, Arc<DomainPools>>,
    default_pools: Option<Arc<DomainPools>>,
    /// What the background probe last found, per backend.
    ///
    /// Behind a lock of its own rather than inside the pools because it is not
    /// connection state: a request that is handed a connection never reads it,
    /// and the only writer is the probe task. `std::sync` and not `tokio`: the
    /// critical section is a few map lookups, so there is nothing to yield on,
    /// and `health_snapshot()` then works off a runtime as well as on one.
    health: Mutex<HashMap<EndpointId, NodeHealth>>,
    /// Set for good by [`Self::close_all`], and read by the probe before it
    /// dials anything.
    ///
    /// Not a shutdown signal for the *task* — the task ends when the group is
    /// dropped and its `Weak` stops upgrading — but for the work: `close_all()`
    /// drops the connections while the group itself is still alive, and a probe
    /// that then ran would dial them all again. That is the state a stopped
    /// tunnel would be left in: idle, and quietly reconnecting.
    probe_stopped: AtomicBool,
}

/// How often each backend is asked whether it still answers.
///
/// Under the pool's own idle timeout (60 s) on purpose. A pool that goes quiet
/// has its connections dropped, so the probe is also what keeps one warm to a
/// backend nobody has talked to for a minute; and it is what finds out a
/// backend died half a minute after it happened instead of at the next request,
/// which is the whole of what this buys.
const PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// How far the first probe (and every following one) may be pushed back.
///
/// Every client of one server that started at the same moment would otherwise
/// probe on the same second, which is a thundering herd for no reason — and
/// without it the probe also runs in lockstep with the pool's 5 s cleanup.
const PROBE_JITTER: Duration = Duration::from_secs(5);

/// A persistently dead backend is reported once, then every this-many probes.
///
/// A backend that has been down for an hour has failed a hundred probes. Saying
/// so a hundred times buries everything else in the log; saying it once hides
/// the fact that it is still down.
const PROBE_REMINDER_EVERY: u32 = 10;

/// What the last probe of one backend found.
#[derive(Debug, Clone)]
pub struct NodeHealth {
    /// The backend this describes.
    pub node: EndpointId,
    /// Whether it answered the last time it was asked.
    pub reachable: bool,
    /// How many probes in a row have failed. Zero since the last success.
    pub consecutive_failures: u32,
    /// When it last answered — `None` when it never has.
    pub last_ok: Option<Instant>,
    /// When it was last asked — `None` before the first probe.
    pub last_probe: Option<Instant>,
}

impl NodeHealth {
    /// How long ago it last answered, if it ever has.
    ///
    /// "It has been down for twenty minutes" is the question a UI actually asks;
    /// a timestamp makes every caller do this subtraction and get the direction
    /// wrong at least once.
    pub fn down_for(&self) -> Option<Duration> {
        self.last_ok.map(|ok| ok.elapsed())
    }
}

/// Every backend's health at one moment, for a UI that polls.
#[derive(Debug, Clone, Default)]
pub struct HealthSnapshot {
    pub nodes: Vec<NodeHealth>,
}

impl HealthSnapshot {
    /// How many backends answered their last probe.
    pub fn reachable(&self) -> usize {
        self.nodes.iter().filter(|n| n.reachable).count()
    }

    /// Whether anything at all answered. False means the tunnel has nowhere to
    /// send anything.
    pub fn any_reachable(&self) -> bool {
        self.reachable() > 0
    }

    /// The backends that did not answer, as a comma-separated list.
    pub fn unreachable_ids(&self) -> String {
        self.nodes
            .iter()
            .filter(|n| !n.reachable)
            .map(|n| n.node.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Which configured backends answered a reachability probe.
///
/// Building an `EndpointGroup` never dials anything: a well-formed but
/// nonexistent `server_node_id` passes every setup call, and only an actual
/// connection attempt reveals that nothing is there. This report is that
/// attempt, per backend, so a caller can refuse to call a start "successful"
/// when it reached no backend at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreconnectReport {
    /// Backend nodes that accepted a connection.
    pub reachable: Vec<EndpointId>,
    /// Backend nodes that refused, were unreachable, or timed out.
    pub unreachable: Vec<EndpointId>,
    /// Backend nodes that answered the QUIC handshake and then refused the
    /// connection because this client has no 2FA credentials.
    ///
    /// A client without credentials cannot fail the 2FA handshake — it never
    /// starts one — so as far as QUIC is concerned these backends are up. They
    /// are listed here as well as in `unreachable`, so the caller can say *why*
    /// a backend that answered is not going to serve anything.
    pub auth_required: Vec<EndpointId>,
}

impl PreconnectReport {
    /// How many distinct backends were probed. Zero means none was configured.
    pub fn total(&self) -> usize {
        self.reachable.len() + self.unreachable.len()
    }

    /// True when at least one configured backend answered.
    pub fn any_reachable(&self) -> bool {
        !self.reachable.is_empty()
    }

    /// True when at least one backend demanded 2FA credentials this client does
    /// not have. Such a backend answers, then refuses to serve anything.
    pub fn any_auth_required(&self) -> bool {
        !self.auth_required.is_empty()
    }

    /// The unreachable backends as a comma-separated list, for error details.
    ///
    /// Empty when everything answered.
    pub fn unreachable_ids(&self) -> String {
        self.unreachable
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl EndpointGroup {
    /// Builds a group that binds its **own** iroh endpoints, one per distinct backend.
    ///
    /// Nothing in this workspace calls it: both UIs build the endpoint themselves (so it can
    /// carry the relay mode and the QUIC tuning) and pass it to
    /// [`Self::new_with_domain_mappings_and_endpoint`]. Prefer that one — an endpoint created
    /// inside here gets iroh's defaults, which means the preset's relay map, no auth token and
    /// a 1.25 MB stream window.
    pub async fn new_with_domain_mappings(
        domain_mappings: Vec<DomainMapping>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
    ) -> Result<Self, ClientError> {
        let mut pool_by_key: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_keys: HashMap<String, Vec<String>> = HashMap::new();

        jni_log!(
            "[DEBUG:endpoint-group] Creating EndpointGroup with {} domain mappings",
            domain_mappings.len()
        );
        for (i, mapping) in domain_mappings.iter().enumerate() {
            let key = mapping.key();
            let domain_lower = mapping.domain.to_lowercase();
            jni_log!(
                "[DEBUG:endpoint-group] Mapping {}: domain='{}', key='{}'",
                i,
                domain_lower,
                key
            );

            if !pool_by_key.contains_key(&key) {
                let endpoint_addr = mapping.to_endpoint_addr()?;
                let pool = IrohConnectionPool::new(endpoint_addr).await?;
                pool_by_key.insert(key.clone(), Arc::new(pool));
                jni_log!(
                    "[DEBUG:endpoint-group] Created connection pool for key: {}",
                    key
                );
            }

            domain_to_keys
                .entry(domain_lower.clone())
                .or_default()
                .push(key.clone());
            jni_log!(
                "[DEBUG:endpoint-group] Mapping domain '{}' to backend '{}'",
                domain_lower,
                key
            );
        }

        let mut domains = HashMap::new();
        for (domain, keys) in domain_to_keys {
            jni_log!(
                "[DEBUG:endpoint-group] Domain '{}' maps to backends: {:?}",
                domain,
                keys
            );
            let pools: Vec<Arc<IrohConnectionPool>> = keys
                .into_iter()
                .filter_map(|k| pool_by_key.get(&k).cloned())
                .collect();
            if !pools.is_empty() {
                let domain_pools = Arc::new(DomainPools::new(pools, default_strategy));
                domains.insert(domain.clone(), domain_pools);
                jni_log!(
                    "[DEBUG:endpoint-group] Created DomainPools for domain '{}'",
                    domain
                );
            }
        }

        jni_log!(
            "[DEBUG:endpoint-group] Final domain map: {:?}",
            domains.keys()
        );

        let default_pools = if let Some(addr) = default_endpoint_addr {
            let pool = IrohConnectionPool::new(addr).await?;
            Some(Arc::new(DomainPools::new(
                vec![Arc::new(pool)],
                default_strategy,
            )))
        } else {
            None
        };

        Ok(Self {
            domains,
            default_pools,
            health: Mutex::new(HashMap::new()),
            probe_stopped: AtomicBool::new(false),
        })
    }

    pub async fn new_with_nodes_and_endpoint(
        nodes: Vec<NodeConfig>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
        ep: Endpoint,
    ) -> Result<Self, ClientError> {
        let domain_mappings: Vec<DomainMapping> = nodes
            .into_iter()
            .flat_map(|node| node.to_domain_mappings())
            .collect();

        Self::new_with_domain_mappings_and_endpoint(
            domain_mappings,
            default_endpoint_addr,
            default_strategy,
            ep,
        )
        .await
    }

    pub async fn new_with_domain_mappings_and_endpoint(
        domain_mappings: Vec<DomainMapping>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
        ep: Endpoint,
    ) -> Result<Self, ClientError> {
        let mut pool_by_key: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_keys: HashMap<String, Vec<String>> = HashMap::new();

        jni_log!(
            "[DEBUG:endpoint-group] Creating EndpointGroup (with endpoint) with {} domain mappings",
            domain_mappings.len()
        );
        for (i, mapping) in domain_mappings.iter().enumerate() {
            let key = mapping.key();
            let domain_lower = mapping.domain.to_lowercase();
            jni_log!(
                "[DEBUG:endpoint-group] Mapping {}: domain='{}', key='{}'",
                i,
                domain_lower,
                key
            );

            if !pool_by_key.contains_key(&key) {
                let endpoint_addr = mapping.to_endpoint_addr()?;
                let pool = IrohConnectionPool::new_with_endpoint(ep.clone(), endpoint_addr);
                pool_by_key.insert(key.clone(), Arc::new(pool));
                jni_log!(
                    "[DEBUG:endpoint-group] Created connection pool for key: {}",
                    key
                );
            }

            domain_to_keys
                .entry(domain_lower.clone())
                .or_default()
                .push(key.clone());
            jni_log!(
                "[DEBUG:endpoint-group] Mapping domain '{}' to backend '{}'",
                domain_lower,
                key
            );
        }

        let mut domains = HashMap::new();
        for (domain, keys) in domain_to_keys {
            jni_log!(
                "[DEBUG:endpoint-group] Domain '{}' maps to backends: {:?}",
                domain,
                keys
            );
            let pools: Vec<Arc<IrohConnectionPool>> = keys
                .into_iter()
                .filter_map(|k| pool_by_key.get(&k).cloned())
                .collect();
            if !pools.is_empty() {
                let domain_pools = Arc::new(DomainPools::new(pools, default_strategy));
                domains.insert(domain.clone(), domain_pools);
                jni_log!(
                    "[DEBUG:endpoint-group] Created DomainPools for domain '{}'",
                    domain
                );
            }
        }

        jni_log!(
            "[DEBUG:endpoint-group] Final domain map (with endpoint): {:?}",
            domains.keys()
        );

        let default_pools = if let Some(addr) = default_endpoint_addr {
            let pool = IrohConnectionPool::new_with_endpoint(ep, addr);
            Some(Arc::new(DomainPools::new(
                vec![Arc::new(pool)],
                default_strategy,
            )))
        } else {
            None
        };

        Ok(Self {
            domains,
            default_pools,
            health: Mutex::new(HashMap::new()),
            probe_stopped: AtomicBool::new(false),
        })
    }

    pub async fn new_with_single_pool(conn_pool: IrohConnectionPool) -> Self {
        let default_pools = Some(Arc::new(DomainPools::new(
            vec![Arc::new(conn_pool)],
            LoadBalancingStrategy::RoundRobin,
        )));
        Self {
            domains: HashMap::new(),
            default_pools,
            health: Mutex::new(HashMap::new()),
            probe_stopped: AtomicBool::new(false),
        }
    }

    /// Configure client 2FA credentials for one backend, leaving every other
    /// pool untouched.
    ///
    /// [`Self::set_two_factor`] writes the same value into every pool, which a
    /// client talking to several servers cannot use: each server has its own
    /// `[auth].clients` entry, and the one shared secret is the reason a second
    /// server either refuses the handshake or has to be given the first one's
    /// key. Credentials are keyed by the configured endpoint ID here, so a
    /// backend left out keeps none at all — and a backend with none never opens
    /// an auth stream, which is what makes a mixed setup (some servers with
    /// 2FA, some without) work.
    ///
    /// Safe to call any time before connections are established.
    pub async fn set_two_factor_for(&self, node_id: &str, auth: Option<TwoFactorAuth>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                if pool.backend_id().to_string() == node_id {
                    pool.set_two_factor(auth.clone()).await;
                }
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                if pool.backend_id().to_string() == node_id {
                    pool.set_two_factor(auth.clone()).await;
                }
            }
        }
    }

    /// Configure client 2FA credentials on every pool in this group.
    /// Safe to call any time before connections are established.
    pub async fn set_two_factor(&self, auth: Option<TwoFactorAuth>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                pool.set_two_factor(auth.clone()).await;
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                pool.set_two_factor(auth.clone()).await;
            }
        }
    }

    /// Configure a one-time enrollment token on every pool, and on one backend
    /// only — see [`Self::set_two_factor_for`] for why a group talking to
    /// several servers needs the per-backend form.
    pub async fn set_enrollment_for(&self, node_id: &str, enrollment: Option<Enrollment>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                if pool.backend_id().to_string() == node_id {
                    pool.set_enrollment(enrollment.clone()).await;
                }
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                if pool.backend_id().to_string() == node_id {
                    pool.set_enrollment(enrollment.clone()).await;
                }
            }
        }
    }

    /// Configure a one-time enrollment token on every pool in this group.
    pub async fn set_enrollment(&self, enrollment: Option<Enrollment>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                pool.set_enrollment(enrollment.clone()).await;
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                pool.set_enrollment(enrollment.clone()).await;
            }
        }
    }

    /// The credential the server issued for an enrollment token, from whichever
    /// pool has one, cleared once read.
    ///
    /// A group usually holds one backend per server and only one of them will
    /// have enrolled, so this returns the first it finds rather than a list —
    /// the caller knows which server it just enrolled against.
    pub async fn take_issued_credential(&self) -> Option<IssuedCredential> {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                if let Some(issued) = pool.take_issued_credential().await {
                    return Some(issued);
                }
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                if let Some(issued) = pool.take_issued_credential().await {
                    return Some(issued);
                }
            }
        }
        None
    }

    pub async fn get_connection(&self, domain: &str) -> Result<PooledConnection, ClientError> {
        let domain_lower = domain.to_lowercase();
        jni_log!(
            "[DEBUG:endpoint-group] Looking up connection for domain: '{}'",
            domain_lower
        );

        if let Some(pools) = self.domains.get(&domain_lower) {
            jni_log!(
                "[DEBUG:endpoint-group] Found exact match for domain: '{}'",
                domain_lower
            );
            return pools.get_connection().await;
        }

        let mut parts: Vec<&str> = domain_lower.split('.').collect();
        while parts.len() > 1 {
            parts.remove(0);
            let parent_domain = parts.join(".");
            jni_log!(
                "[DEBUG:endpoint-group] Trying parent domain: '{}'",
                parent_domain
            );
            if let Some(pools) = self.domains.get(&parent_domain) {
                jni_log!(
                    "[DEBUG:endpoint-group] Found parent domain match: '{}'",
                    parent_domain
                );
                return pools.get_connection().await;
            }
        }

        if let Some(default) = &self.default_pools {
            jni_log!(
                "[DEBUG:endpoint-group] Using default pools for domain: '{}'",
                domain_lower
            );
            return default.get_connection().await;
        }

        jni_log!(
            "[DEBUG:endpoint-group] No endpoint configured for domain: '{}'",
            domain_lower
        );
        Err(ClientError::InvalidConfig(format!(
            "No endpoint configured for domain: {}",
            domain
        )))
    }

    pub async fn return_connection(&self, domain: &str, pooled_conn: PooledConnection) {
        let domain_lower = domain.to_lowercase();

        if let Some(pools) = self.domains.get(&domain_lower) {
            pools.return_connection(pooled_conn).await;
            return;
        }

        let mut parts: Vec<&str> = domain_lower.split('.').collect();
        while parts.len() > 1 {
            parts.remove(0);
            let parent_domain = parts.join(".");
            if let Some(pools) = self.domains.get(&parent_domain) {
                pools.return_connection(pooled_conn).await;
                return;
            }
        }

        if let Some(default) = &self.default_pools {
            default.return_connection(pooled_conn).await;
        }
    }

    /// Test iroh-level connectivity to each unique backend node, in parallel.
    ///
    /// Unlike the old sequential preconnect, this:
    /// - Deduplicates pools by *backend* node ID (same backend serving several
    ///   domains is tested once) — deliberately not by the pool's local endpoint
    ///   ID, which is identical for every pool when the group shares one
    ///   caller-owned endpoint, and would collapse all backends into a single
    ///   probe
    /// - Runs all connectivity tests in parallel via `JoinSet`
    /// - Applies a short per-pool timeout (PRECONNECT_TIMEOUT = 5s)
    /// - Caps the overall phase at 10s
    ///
    /// This ensures that a single unreachable backend node does not block the
    /// entire connection flow.
    ///
    /// Returns how many nodes answered. Call [`Self::preconnect_report`] when the
    /// caller also needs to name the ones that did not.
    pub async fn preconnect_all(&self) -> usize {
        self.preconnect_report().await.reachable.len()
    }

    /// Probe every unique backend node in parallel and report which answered.
    ///
    /// This is the availability check every entry point shares. Because no setup
    /// call ever dials, a config pointing at a node that does not exist looks
    /// perfectly valid until something connects; callers therefore treat
    /// [`PreconnectReport::any_reachable`] being false as a failed start rather
    /// than reporting a connection that was never established.
    pub async fn preconnect_report(&self) -> PreconnectReport {
        // Collect unique pools by backend node ID. Multiple domains pointing to
        // the same backend share a single connection pool, so we only need to
        // test each backend once.
        let unique_pools = self.unique_pools();
        let seen_nodes: Vec<EndpointId> = unique_pools.iter().map(|(id, _)| *id).collect();

        jni_log!(
            "[preconnect] Testing connectivity to {} unique node(s) in parallel",
            unique_pools.len()
        );

        let mut report = PreconnectReport::default();
        if unique_pools.is_empty() {
            return report;
        }

        // Run connectivity tests in parallel, each capped at PRECONNECT_TIMEOUT.
        let mut join_set = tokio::task::JoinSet::new();
        for (backend_id, pool) in &unique_pools {
            let backend_id = *backend_id;
            let pool = pool.clone();
            join_set.spawn(async move {
                let answered =
                    match tokio::time::timeout(PRECONNECT_TIMEOUT, pool.preconnect()).await {
                        Ok(true) => true,
                        Ok(false) => {
                            jni_log!("[preconnect] Node unreachable (preconnect returned false)");
                            // `jni_log` only reaches logcat; the desktop and the service need
                            // this in their own log — the pool's warning says why.
                            #[cfg(feature = "tracing")]
                            tracing::warn!("preconnect: node {} is unreachable", backend_id);
                            false
                        }
                        Err(_) => {
                            jni_log!(
                                "[preconnect] Node timed out after {}s",
                                PRECONNECT_TIMEOUT.as_secs()
                            );
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                "preconnect: node {} gave no answer within {}s",
                                backend_id,
                                PRECONNECT_TIMEOUT.as_secs()
                            );
                            false
                        }
                    };
                (backend_id, answered)
            });
        }

        // Overall cap: 10s for the entire preconnect phase.
        let overall_deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
        let mut probed = 0usize;
        while let Ok(result) = tokio::time::timeout_at(overall_deadline, join_set.join_next()).await
        {
            match result {
                Some(Ok((backend_id, true))) => {
                    probed += 1;
                    report.reachable.push(backend_id);
                }
                Some(Ok((backend_id, false))) => {
                    probed += 1;
                    report.unreachable.push(backend_id);
                }
                Some(Err(_e)) => {
                    jni_log!("[preconnect] Task failed");
                }
                None => break, // JoinSet empty
            }
        }

        // A task the overall cap cut off never reported. Count it as unreachable:
        // a backend may only be called usable when it actually answered, and
        // `total()` must still equal the number of configured backends.
        if probed < seen_nodes.len() {
            let mut classified = report.reachable.clone();
            classified.extend(report.unreachable.iter().copied());
            let missing = seen_nodes
                .iter()
                .copied()
                .filter(|id| !classified.contains(id));
            report.unreachable.extend(missing);
        }

        // A backend that answered and then refused the connection leaves the
        // reason on its pool. Collect it so the caller can report "this server
        // wants 2FA" instead of an "unreachable" that hides the real cause.
        for (backend_id, pool) in &unique_pools {
            if let Some(reason) = pool.take_auth_required().await {
                jni_log!("[preconnect] Node {} requires 2FA: {}", backend_id, reason);
                report.auth_required.push(*backend_id);
            }
        }

        jni_log!(
            "[preconnect] Connectivity test done: {}/{} node(s) reachable",
            report.reachable.len(),
            seen_nodes.len()
        );
        report
    }

    /// Starts the periodic health probe.
    ///
    /// One task per group, holding only a [`Weak`] reference, so it ends when
    /// the group does — a stopped proxy is not kept alive by the thing that is
    /// watching it. Nothing else stops it; a group that outlives the probe
    /// simply stops being probed, which is the same state as before it started.
    ///
    /// Not started by the constructors: those return a bare `Self`, and the
    /// probe needs the `Arc` the caller is about to wrap it in. Every long-lived
    /// owner therefore has to call this once, right after building the group.
    pub fn start_health_probe(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            // A full interval before the first round, not the jitter alone.
            // Whoever starts the group probes it once at startup, and a round
            // that landed 0–5 s in would dial the same backends while that one
            // was still dialling them, so both would find the pool empty and
            // each would open a connection the other did not know about.
            let first = tokio::time::Instant::now()
                + PROBE_INTERVAL
                + Duration::from_millis(fastrand::u64(0..PROBE_JITTER.as_millis() as u64));
            let mut interval = tokio::time::interval_at(first, PROBE_INTERVAL);
            // A round that ran long (a backend timing out costs up to
            // PRECONNECT_TIMEOUT) must not queue up a burst of make-up rounds.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                let Some(group) = weak.upgrade() else {
                    break;
                };
                if group.probe_stopped.load(Ordering::SeqCst) {
                    break;
                }
                group.probe_round().await;
                // Dropped here, at the end of the iteration: the strong
                // reference must not survive into the sleep, or the group would
                // never be dropped and this loop never ends.
            }
        });
    }

    /// Asks every backend once, in parallel, and records what each answered.
    ///
    /// In parallel because a dead backend costs the whole probe timeout, and
    /// four of them would then take longer than the interval between rounds.
    async fn probe_round(&self) {
        if self.probe_stopped.load(Ordering::SeqCst) {
            return;
        }
        let mut probing = tokio::task::JoinSet::new();
        for (backend_id, pool) in self.unique_pools() {
            probing.spawn(async move {
                let answered =
                    match tokio::time::timeout(PRECONNECT_TIMEOUT, pool.preconnect()).await {
                        Ok(true) => true,
                        Ok(false) => false,
                        Err(_) => false,
                    };
                (backend_id, answered)
            });
        }
        while let Some(result) = probing.join_next().await {
            // Checked here as well as at the top: a round that is already
            // dialling when the group closes has to stop dialling, and letting
            // the set drop is what aborts the members still in flight.
            if self.probe_stopped.load(Ordering::SeqCst) {
                break;
            }
            if let Ok((backend_id, answered)) = result {
                self.record_probe(backend_id, answered);
            }
        }
    }

    /// Folds one probe result into the group's health, logging the changes.
    ///
    /// The probe is the only writer, and it writes from one task, so the only
    /// thing the lock protects is the snapshot a UI may be reading concurrently.
    fn record_probe(&self, backend_id: EndpointId, answered: bool) {
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = health.entry(backend_id).or_insert(NodeHealth {
            node: backend_id,
            // Not "unknown": a backend that has not been probed has not
            // answered, and the caller asking is about to be told so.
            reachable: false,
            consecutive_failures: 0,
            last_ok: None,
            last_probe: None,
        });

        let was_reachable = entry.reachable;
        entry.last_probe = Some(Instant::now());

        if answered {
            entry.consecutive_failures = 0;
            entry.last_ok = Some(Instant::now());
            entry.reachable = true;
            if !was_reachable {
                jni_log!("[health] Node {} answers again", backend_id);
                #[cfg(feature = "tracing")]
                tracing::info!("backend {} answers again", backend_id);
            }
            return;
        }

        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.reachable = false;
        // The first failure is news. So is every tenth one — a backend that has
        // been down for an hour has failed a hundred probes, and a log line per
        // probe would bury everything else.
        if was_reachable || entry.consecutive_failures % PROBE_REMINDER_EVERY == 1 {
            jni_log!(
                "[health] Node {} did not answer ({} probes in a row)",
                backend_id,
                entry.consecutive_failures
            );
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "backend {} did not answer ({} probes in a row)",
                backend_id,
                entry.consecutive_failures
            );
        }
    }

    /// Every backend's health as the last probe left it.
    ///
    /// Empty until the first probe has run, which is up to
    /// [`PROBE_INTERVAL`] plus [`PROBE_JITTER`] after [`Self::start_health_probe`].
    /// A caller that needs an answer before then wants
    /// [`Self::preconnect_report`], which probes on the spot.
    ///
    /// Sorted by node ID so a UI polling it does not see the entries change
    /// places between two polls.
    pub fn health_snapshot(&self) -> HealthSnapshot {
        let mut nodes: Vec<NodeHealth> = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect();
        nodes.sort_by_key(|n| n.node.to_string());
        HealthSnapshot { nodes }
    }

    /// How traffic is currently reaching each backend: direct, or via a relay.
    ///
    /// One entry per *distinct backend*, because that is what a link describes — two domains
    /// served by the same node share one connection pool and therefore one answer.
    ///
    /// A backend that has never connected reports [`LinkKind::Unknown`]; the caller decides
    /// whether that means "not connected yet" or "not connected at all".
    pub async fn link_kinds(&self) -> Vec<(EndpointId, LinkKind)> {
        let mut kinds = Vec::new();
        for (backend_id, pool) in self.unique_pools() {
            kinds.push((backend_id, pool.link_kind().await));
        }
        kinds
    }

    /// Closes and forgets every cached connection to every backend, keeping the endpoints.
    ///
    /// Called when the device switched networks: the tunnel itself stays up, but the
    /// connections inside it were opened on the old network and are dead while still looking
    /// open. See [`IrohConnectionPool::drop_connections`] for why they have to be closed
    /// explicitly instead of waiting for QUIC to notice.
    pub async fn drop_connections(&self) {
        let pools = self.unique_pools();
        for (backend_id, pool) in pools {
            pool.drop_connections().await;
            jni_log!(
                "[drop-connections] dropped cached connections to {}",
                backend_id
            );
        }
    }

    /// Every distinct backend in this group, with its pool.
    ///
    /// Deduplicated by *backend* node ID, not by the pool's local endpoint ID: when the group
    /// shares one caller-owned endpoint (the Android JNI shape) every pool reports the same
    /// local ID, and deduplicating on it would collapse all backends into one.
    fn unique_pools(&self) -> Vec<(EndpointId, Arc<IrohConnectionPool>)> {
        let mut seen: Vec<EndpointId> = Vec::new();
        let mut unique: Vec<(EndpointId, Arc<IrohConnectionPool>)> = Vec::new();

        for pool in self.all_pools() {
            let backend_id = pool.backend_id();
            if !seen.contains(&backend_id) {
                seen.push(backend_id);
                unique.push((backend_id, pool.clone()));
            }
        }
        unique
    }

    fn all_pools(&self) -> Vec<&Arc<IrohConnectionPool>> {
        self.domains
            .values()
            .flat_map(|dp| dp.pools.iter())
            .chain(
                self.default_pools
                    .as_ref()
                    .map(|dp| dp.pools.iter())
                    .into_iter()
                    .flatten(),
            )
            .collect()
    }

    /// The backend node IDs configured in this group (one per pool, deduplicated
    /// per domain). These are the servers traffic is dialed to, i.e. the
    /// `server_node_id`s from the client configuration.
    pub fn node_ids(&self) -> Vec<EndpointId> {
        let mut ids = Vec::new();
        for pools in self.domains.values() {
            ids.extend(pools.node_ids());
        }
        if let Some(default) = &self.default_pools {
            ids.extend(default.node_ids());
        }
        ids
    }

    pub async fn close_all(&self) {
        // Before the pools are cleared, not after: the probe reads this, and a
        // round that started before this line must not go on to dial what is
        // being closed underneath it.
        self.probe_stopped.store(true, Ordering::SeqCst);

        for pools in self.domains.values() {
            for pool in &pools.pools {
                pool.close_all().await;
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                pool.close_all().await;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainMapping {
    pub domain: String,
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
}

impl DomainMapping {
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, ClientError> {
        crate::connection_pool::parse_endpoint_addr(
            self.server_node_id.as_deref(),
            self.server_ticket.as_deref(),
        )
    }

    pub fn key(&self) -> String {
        if let Some(id) = &self.server_node_id {
            format!("node_id:{}", id)
        } else if let Some(ticket) = &self.server_ticket {
            format!("ticket:{}", ticket)
        } else {
            "unknown".to_string()
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
    pub domains: Vec<String>,
}

impl NodeConfig {
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, ClientError> {
        crate::connection_pool::parse_endpoint_addr(
            self.server_node_id.as_deref(),
            self.server_ticket.as_deref(),
        )
    }

    pub fn key(&self) -> String {
        if let Some(id) = &self.server_node_id {
            format!("node_id:{}", id)
        } else if let Some(ticket) = &self.server_ticket {
            format!("ticket:{}", ticket)
        } else {
            "unknown".to_string()
        }
    }

    pub fn to_domain_mappings(&self) -> Vec<DomainMapping> {
        self.domains
            .iter()
            .map(|domain| DomainMapping {
                domain: domain.clone(),
                server_node_id: self.server_node_id.clone(),
                server_ticket: self.server_ticket.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TotpAlgorithm;
    use iroh::endpoint::presets;

    /// A syntactically valid backend node ID that no endpoint is bound to.
    fn unused_backend_id() -> EndpointId {
        iroh::SecretKey::generate()
            .public()
            .to_string()
            .parse()
            .expect("a generated public key is a valid node ID")
    }

    fn node(backend: EndpointId, domain: &str) -> NodeConfig {
        NodeConfig {
            server_node_id: Some(backend.to_string()),
            server_ticket: None,
            domains: vec![domain.to_string()],
        }
    }

    /// Regression guard: the group must report the *configured* backend IDs.
    ///
    /// When every pool shares one caller-owned endpoint (the Android JNI shape),
    /// `IrohConnectionPool::node_id()` answers with the same local endpoint ID
    /// for all of them. Reporting that made `preconnect_all` dedupe every
    /// backend into a single probe, so only one of N nodes was ever checked and
    /// N-1 unreachable nodes went unnoticed.
    #[tokio::test]
    async fn node_ids_are_the_configured_backends_not_the_local_endpoint() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");

        let backend_a = unused_backend_id();
        let backend_b = unused_backend_id();
        assert_ne!(backend_a, backend_b);

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![
                node(backend_a, "a.example.com"),
                node(backend_b, "b.example.com"),
            ],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep.clone(),
        )
        .await
        .expect("a bogus but well-formed node ID must still build a group");

        let ids = group.node_ids();
        assert_eq!(ids.len(), 2, "both backends must be listed: {ids:?}");
        assert!(ids.contains(&backend_a), "{ids:?} is missing {backend_a}");
        assert!(ids.contains(&backend_b), "{ids:?} is missing {backend_b}");
        assert!(
            !ids.contains(&ep.id()),
            "the group reported its local endpoint ID {ids:?} instead of the backends"
        );
    }

    /// Two distinct backends behind two domains must stay two pools, so the
    /// dedup in `preconnect_all` probes each of them.
    #[tokio::test]
    async fn distinct_backends_stay_distinct_pools() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");

        let backend_a = unused_backend_id();
        let backend_b = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![
                node(backend_a, "a.example.com"),
                node(backend_b, "b.example.com"),
            ],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        // One pool per backend, and each domain load-balances over its own pool.
        for (domain, expected) in [("a.example.com", backend_a), ("b.example.com", backend_b)] {
            let pools = group
                .domains
                .get(domain)
                .expect("the domain must have a pool");
            assert_eq!(pools.pools.len(), 1, "{domain} should map to one pool");
            assert_eq!(pools.pools[0].backend_id(), expected);
        }
    }

    /// Credentials given for one backend must not reach any other.
    ///
    /// `set_two_factor` writes to every pool, so the only way a client can hold
    /// a different key per server is `set_two_factor_for`. If it ever leaks, a
    /// server that has no 2FA at all gets an auth stream it never asked for.
    #[tokio::test]
    async fn per_backend_two_factor_does_not_spill_to_other_backends() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");

        let backend_a = unused_backend_id();
        let backend_b = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![
                node(backend_a, "a.example.com"),
                node(backend_b, "b.example.com"),
            ],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        let auth = TwoFactorAuth::new("client-a", "JBSWY3DPEHPK3PXP", TotpAlgorithm::SHA1)
            .expect("a Base32 secret must decode");
        group
            .set_two_factor_for(&backend_a.to_string(), Some(auth))
            .await;

        for (domain, expected) in [("a.example.com", true), ("b.example.com", false)] {
            let pools = group
                .domains
                .get(domain)
                .expect("the domain must have a pool");
            for pool in &pools.pools {
                assert_eq!(
                    pool.has_two_factor().await,
                    expected,
                    "{domain} (backend {}) should{} have credentials",
                    pool.backend_id(),
                    if expected { "" } else { " not" }
                );
            }
        }
    }

    /// A group with no backend must not look like a reachable one: the callers
    /// treat an empty report as a failed start, so `total()` has to be 0 rather
    /// than "all of nothing answered".
    #[tokio::test]
    async fn group_without_backends_reports_nothing_probed() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let group = EndpointGroup::new_with_nodes_and_endpoint(
            Vec::new(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        let report = group.preconnect_report().await;
        assert_eq!(report.total(), 0);
        assert!(!report.any_reachable());
        assert_eq!(report.unreachable_ids(), "");
    }

    /// The report is what callers put in their error messages, so the summary
    /// must name exactly the backends that failed and nothing else.
    #[test]
    fn report_names_only_the_unreachable_backends() {
        let reached = unused_backend_id();
        let failed = unused_backend_id();

        let report = PreconnectReport {
            reachable: vec![reached],
            unreachable: vec![failed],
            auth_required: Vec::new(),
        };

        assert_eq!(report.total(), 2);
        assert!(report.any_reachable());
        assert!(!report.any_auth_required());
        assert_eq!(report.unreachable_ids(), failed.to_string());
        assert!(!report.unreachable_ids().contains(&reached.to_string()));

        let all_failed = PreconnectReport {
            reachable: Vec::new(),
            unreachable: vec![reached, failed],
            auth_required: Vec::new(),
        };
        assert!(!all_failed.any_reachable());
        assert_eq!(
            all_failed.unreachable_ids(),
            format!("{}, {}", reached, failed)
        );

        // A backend that answers the handshake and then refuses it for missing
        // 2FA is unreachable *and* named as such: the caller's error message
        // has to be able to say why.
        let needs_2fa = PreconnectReport {
            reachable: Vec::new(),
            unreachable: vec![failed],
            auth_required: vec![failed],
        };
        assert!(!needs_2fa.any_reachable());
        assert!(needs_2fa.any_auth_required());
    }

    /// A group with two backends, bound to a local endpoint. Nothing is dialled
    /// by building it, so the tests below decide what each "probe" found.
    async fn group_with(backends: &[EndpointId]) -> EndpointGroup {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        EndpointGroup::new_with_nodes_and_endpoint(
            backends
                .iter()
                .enumerate()
                .map(|(i, id)| node(*id, &format!("backend{i}.example.com")))
                .collect(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .expect("a bogus but well-formed node ID must still build a group")
    }

    /// The snapshot is empty — not "everything is up" — before the first probe:
    /// a caller reading it must not conclude the tunnel is healthy because
    /// nothing has been asked yet.
    #[tokio::test]
    async fn nothing_has_been_probed_yet_is_not_the_same_as_healthy() {
        let backend = unused_backend_id();
        let group = group_with(&[backend]).await;

        let snapshot = group.health_snapshot();
        assert!(snapshot.nodes.is_empty(), "{snapshot:?}");
        assert!(!snapshot.any_reachable(), "{snapshot:?}");
    }

    #[tokio::test]
    async fn one_down_backend_does_not_hide_the_one_that_answers() {
        let up = unused_backend_id();
        let down = unused_backend_id();
        let group = group_with(&[up, down]).await;

        group.record_probe(up, true);
        group.record_probe(down, false);

        let snapshot = group.health_snapshot();
        assert_eq!(snapshot.nodes.len(), 2, "{snapshot:?}");
        assert_eq!(snapshot.reachable(), 1, "{snapshot:?}");
        assert!(snapshot.any_reachable(), "{snapshot:?}");
        assert_eq!(snapshot.unreachable_ids(), down.to_string());

        let up = snapshot
            .nodes
            .iter()
            .find(|n| n.reachable)
            .expect("the answering backend");
        assert_eq!(up.consecutive_failures, 0);
        assert!(up.last_ok.is_some(), "it answered");
        assert!(up.down_for().is_some());

        let down = snapshot
            .nodes
            .iter()
            .find(|n| !n.reachable)
            .expect("the silent backend");
        assert_eq!(down.consecutive_failures, 1);
        assert!(down.last_ok.is_none(), "it never answered");
        assert!(down.down_for().is_none());
    }

    /// What an operator is told: "down for twenty minutes", not "down".
    #[tokio::test]
    async fn a_backend_that_comes_back_resets_its_failure_count() {
        let backend = unused_backend_id();
        let group = group_with(&[backend]).await;

        for _ in 0..3 {
            group.record_probe(backend, false);
        }
        let snapshot = group.health_snapshot();
        assert_eq!(snapshot.nodes[0].consecutive_failures, 3, "{snapshot:?}");
        assert!(!snapshot.any_reachable());

        group.record_probe(backend, true);

        let snapshot = group.health_snapshot();
        assert_eq!(snapshot.nodes[0].consecutive_failures, 0, "{snapshot:?}");
        assert!(snapshot.nodes[0].reachable);
        assert!(snapshot.nodes[0].down_for().is_some());
        assert!(snapshot.any_reachable());
    }

    /// The snapshot is what a UI polls, and entries that change places between
    /// two polls read as backends flapping.
    #[tokio::test]
    async fn the_snapshot_stays_in_one_order() {
        let first = unused_backend_id();
        let second = unused_backend_id();
        let group = group_with(&[second, first]).await;
        group.record_probe(first, true);
        group.record_probe(second, false);

        let ids: Vec<String> = group
            .health_snapshot()
            .nodes
            .iter()
            .map(|n| n.node.to_string())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "the entries are not in a stable order");
        assert_eq!(
            ids,
            group
                .health_snapshot()
                .nodes
                .iter()
                .map(|n| n.node.to_string())
                .collect::<Vec<_>>()
        );
    }
}

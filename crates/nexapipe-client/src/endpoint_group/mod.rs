//! The endpoint group: the pools that serve a name, and the backends behind them.
//!
//! A group holds one pool of connections per domain, and every pool reaches a
//! backend. Which pool serves a host is the one rule the proxy uses, and the
//! parts of that — the pools, the index that answers for a name, the probe
//! that watches the backends — are modules of their own.

use crate::ClientError;
use crate::auth::{Enrollment, IssuedCredential, TwoFactorAuth};
use crate::connection_pool::{IrohConnectionPool, PRECONNECT_TIMEOUT};
use crate::flow::{FlowId, FlowRegistry, FlowView};
use crate::lb::LoadBalancingStrategy;
use crate::traffic::{self, NodeVolume, TrafficTable};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use nexapipe_proto::normalize_pattern;
use nexapipe_proto::protocol::Protocol;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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

mod connection;
mod domain_pools;
mod health;
mod index;
mod links;
mod node;
mod probe;

// The connection the group hands out, the pools of one domain, what the
// panel says about a node, the index that answers for a name, the links to
// the backends and the node the group is configured with are modules of
// their own, and what they hold is still reached through `endpoint_group`.
pub use connection::PooledConnection;
pub use domain_pools::DomainPools;
pub use health::{HealthSnapshot, NodeHealth, PreconnectReport};
use index::wildcards_of;
pub use node::{DomainMapping, NodeConfig};

pub struct EndpointGroup {
    domains: HashMap<String, Arc<DomainPools>>,
    /// The domains that serve a name by **pattern**, keyed by the name the
    /// pattern covers: `*.example.com` is keyed by `example.com`, and the
    /// catch-all `*` by the empty string.
    ///
    /// An index rather than a scan. The lookup used to walk every configured
    /// domain and ask whether it covered the name, and for a name the
    /// configuration does not name exactly — which is every name a TUN device
    /// asks about — that walk happened on every request and every flow.
    ///
    /// A pattern covers a name when the name ends with the pattern's suffix
    /// **at a label boundary**, so the suffixes worth asking about are the
    /// name's own label-aligned ones: `a.b.example.com`, `b.example.com`,
    /// `example.com`, `com`. The walk below asks exactly those, and the
    /// longest one is the longest pattern that covers the name — the same
    /// answer the scan gave, without the scan.
    wildcards: HashMap<String, Arc<DomainPools>>,
    default_pools: Option<Arc<DomainPools>>,
    /// What the background probe last found, per backend.
    ///
    /// Behind a lock of its own rather than inside the pools because it is not
    /// connection state: a request that is handed a connection never reads it,
    /// and the only writer is the probe task. `std::sync` and not `tokio`: the
    /// critical section is a few map lookups, so there is nothing to yield on,
    /// and `health_snapshot()` then works off a runtime as well as on one.
    ///
    /// Shared rather than owned because the pools read it: which backend serves
    /// a request is decided per domain, and the domain's pools need the answer
    /// the probe wrote for that backend.
    health: Arc<Mutex<HashMap<EndpointId, NodeHealth>>>,
    /// What each backend has carried, and how many flows it carries right now.
    ///
    /// Its own table rather than fields on the pools for the same reason as the
    /// health one: this is not connection state, nothing serving a request reads
    /// it, and it has to outlive every connection. It also has to be readable
    /// from outside the request path entirely — a UI asking how much traffic is
    /// moving is not a request, and does not belong on their critical path.
    ///
    /// Shared rather than owned so a connection can carry the one entry it is
    /// meant to charge. See [`crate::traffic`].
    traffic: TrafficTable,
    /// The flows this group has open right now.
    ///
    /// Beside the traffic table rather than inside it because the two answer
    /// different questions at different depths: one counts bytes per backend,
    /// the other lists connections, and a reader wanting the list is not a
    /// reader wanting the totals. Shared so a connection can list the flows it
    /// opens. See [`crate::flow`].
    flows: Arc<FlowRegistry>,
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

/// Ceiling for a whole preconnect phase, across every pool at once.
///
/// [`PRECONNECT_TIMEOUT`] is what one pool may spend; this is what the phase
/// may. It has to stay above the former or a backend that used its full budget
/// is cut off here instead — counted unreachable for being slow, which is the
/// same confusion the per-pool budget exists to avoid. The slack is for
/// scheduling and for assembling the report, not for more dialling.
pub(crate) const PRECONNECT_PHASE_CAP: Duration =
    PRECONNECT_TIMEOUT.saturating_add(Duration::from_secs(2));

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
        Self::build(
            domain_mappings,
            default_endpoint_addr,
            default_strategy,
            None,
        )
        .await
    }

    /// Builds a group whose pools share one endpoint.
    pub async fn new_with_domain_mappings_and_endpoint(
        domain_mappings: Vec<DomainMapping>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
        ep: Endpoint,
    ) -> Result<Self, ClientError> {
        Self::build(
            domain_mappings,
            default_endpoint_addr,
            default_strategy,
            Some(ep),
        )
        .await
    }

    /// The one body both doors open onto.
    ///
    /// The two constructors used to be a copy of each other — a hundred lines
    /// apart, differing in the two lines that make a pool and in the wording of
    /// two log lines. A change to the mapping had to be made twice, and the
    /// two copies were free to drift: which is what happened to the pool, which
    /// one of them made with the caller's endpoint and the other without.
    async fn build(
        domain_mappings: Vec<DomainMapping>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
        ep: Option<Endpoint>,
    ) -> Result<Self, ClientError> {
        let mut pool_by_key: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_keys: HashMap<String, Vec<String>> = HashMap::new();

        jni_log!(
            "[DEBUG:endpoint-group] Creating EndpointGroup with {} domain mappings",
            domain_mappings.len()
        );
        for (i, mapping) in domain_mappings.iter().enumerate() {
            let key = mapping.key();
            let domain_key = normalize_pattern(&mapping.domain).into_owned();
            jni_log!(
                "[DEBUG:endpoint-group] Mapping {}: domain='{}', key='{}'",
                i,
                domain_key,
                key
            );

            if !pool_by_key.contains_key(&key) {
                let endpoint_addr = mapping.to_endpoint_addr()?;
                let pool = match &ep {
                    Some(ep) => IrohConnectionPool::new_with_endpoint(ep.clone(), endpoint_addr),
                    None => IrohConnectionPool::new(endpoint_addr).await?,
                };
                pool_by_key.insert(key.clone(), Arc::new(pool));
                jni_log!(
                    "[DEBUG:endpoint-group] Created connection pool for key: {}",
                    key
                );
            }

            domain_to_keys
                .entry(domain_key.clone())
                .or_default()
                .push(key.clone());
            jni_log!(
                "[DEBUG:endpoint-group] Mapping domain '{}' to backend '{}'",
                domain_key,
                key
            );
        }

        // Built here and shared with every pool: the health table is one fact
        // per backend, not one per domain, so it cannot live inside a pool.
        let health = Arc::new(Mutex::new(HashMap::new()));
        let traffic = traffic::table();
        let flows = traffic::flow_registry();

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
                let domain_pools = Arc::new(DomainPools::new(
                    pools,
                    default_strategy,
                    health.clone(),
                    traffic.clone(),
                    flows.clone(),
                ));
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
            let pool = match ep {
                Some(ep) => IrohConnectionPool::new_with_endpoint(ep, addr),
                None => IrohConnectionPool::new(addr).await?,
            };
            Some(Arc::new(DomainPools::new(
                vec![Arc::new(pool)],
                default_strategy,
                health.clone(),
                traffic.clone(),
                flows.clone(),
            )))
        } else {
            None
        };

        let wildcards = wildcards_of(&domains);
        Ok(Self {
            domains,
            wildcards,
            default_pools,
            health,
            traffic,
            flows,
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

    pub async fn new_with_single_pool(conn_pool: IrohConnectionPool) -> Self {
        let health = Arc::new(Mutex::new(HashMap::new()));
        let traffic = traffic::table();
        let flows = traffic::flow_registry();
        let default_pools = Some(Arc::new(DomainPools::new(
            vec![Arc::new(conn_pool)],
            LoadBalancingStrategy::RoundRobin,
            health.clone(),
            traffic.clone(),
            flows.clone(),
        )));
        Self {
            domains: HashMap::new(),
            wildcards: HashMap::new(),
            default_pools,
            health,
            traffic,
            flows,
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

    pub async fn get_connection(
        &self,
        domain: &str,
        protocol: Protocol,
    ) -> Result<PooledConnection, ClientError> {
        jni_log!(
            "[DEBUG:endpoint-group] Looking up connection for domain: '{}'",
            domain
        );

        if let Some(pools) = self.pools_for(domain) {
            jni_log!(
                "[DEBUG:endpoint-group] Found mapping for domain: '{}'",
                domain
            );
            return pools.get_connection(protocol).await;
        }

        if let Some(default) = &self.default_pools {
            jni_log!(
                "[DEBUG:endpoint-group] Using default pools for domain: '{}'",
                domain
            );
            return default.get_connection(protocol).await;
        }

        jni_log!(
            "[DEBUG:endpoint-group] No endpoint configured for domain: '{}'",
            domain
        );
        Err(ClientError::InvalidConfig(format!(
            "No endpoint configured for domain: {}",
            domain
        )))
    }

    /// What each backend has carried since this group was built, and how many
    /// flows are open to it right now.
    ///
    /// Keyed by node, and only contains nodes this group has served something
    /// through: a quiet node is absent rather than zero, which a caller showing
    /// per-node figures has to say rather than leave looking like "down".
    pub fn traffic_snapshot(&self) -> HashMap<EndpointId, NodeVolume> {
        traffic::snapshot(&self.traffic)
    }

    /// The flows this group has open right now, and how many there are in total.
    ///
    /// The count comes back alongside the list rather than being implied by it
    /// because the list is capped — a UI that says "200 of 1 431" is saying
    /// something true, and one that said "200" would be quietly lying about how
    /// busy the tunnel is.
    ///
    /// `limit` is the caller's, not the registry's: only a reader knows how many
    /// rows it can draw, and a fixed cap here would be a second opinion about
    /// somebody else's screen.
    pub fn flow_snapshot(&self, limit: usize) -> (usize, Vec<FlowView>) {
        (self.flows.len(), self.flows.view(limit))
    }

    /// Asks one flow to end.
    ///
    /// `false` when there is no open flow with that id, which covers both "no
    /// such flow" and "it ended while you were reading the list" — a UI polling
    /// every few seconds will sometimes click on a row that has already gone, and
    /// the honest answer is that nothing was asked rather than an error.
    ///
    /// Nothing is removed here. The flow lets go of its own sockets and then
    /// deregisters itself, so a list read immediately afterwards may still show
    /// it for a moment.
    pub fn close_flow(&self, id: FlowId) -> bool {
        self.flows.close(id)
    }

    /// Asks every flow reaching `node` to end, and drops the connections the
    /// pool was keeping for it.
    ///
    /// The connections as well as the flows, because they are not the same
    /// thing: a pool holds idle connections that no flow is using, and ending
    /// the flows while leaving those behind is how a backend that has gone bad
    /// keeps getting handed out. See [`IrohConnectionPool::drop_connections`].
    ///
    /// Returns how many flows were asked, which is the number a UI can show.
    ///
    /// The flows are asked first and the pool is dropped second, and the gap between the two is
    /// accepted rather than waited out: a flow that is still winding down has its connection
    /// checked out, so the drop does not reach it, and the one it hands back a moment later goes
    /// back into the pool. Waiting for every copy loop to notice it has been cancelled would mean
    /// putting a sleep in the middle of a click — and a connection that was carrying traffic a
    /// moment ago is not the stale one this is meant to clear.
    pub async fn close_node_flows(&self, node: &EndpointId) -> usize {
        let asked = self.flows.close_node(node);

        for (backend_id, pool) in self.unique_pools() {
            if &backend_id == node {
                pool.drop_connections().await;
            }
        }

        asked
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

#[cfg(test)]
mod tests;

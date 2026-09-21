use crate::proxy::dns::{DnsServerConfig, IpMapping};
use crate::proxy::local_proxy::LocalProxyWrapper;
use crate::proxy::tun_proxy::{TunProxy, TunProxyConfig, TUN_IP};
use anyhow::Result;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId, RelayMap, RelayUrl};
use nexapipe_client::auth::{TotpAlgorithm, TwoFactorAuth};
use nexapipe_client::connection_pool::parse_endpoint_addr;
use nexapipe_client::endpoint_group::{EndpointGroup, NodeConfig};
use nexapipe_client::lb::LoadBalancingStrategy;
use nexapipe_client::transport::TransportTuning;
use nexapipe_client::LinkKind;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use crate::status::EndpointLink;

/// Why a start attempt failed.
///
/// `start()` is awaited from a background task in both the app and the service, so its caller
/// never matches on the error type: it only records an [`crate::error::AppError`]. Keeping "no
/// configured backend could be reached" as its own variant is what lets that case keep a code of
/// its own instead of being flattened into `proxy.start_failed`.
#[derive(Debug)]
pub enum StartError {
    /// Nothing would have been forwarded: either no node carries a domain, or every probed
    /// backend failed to connect.
    NoReachableBackend {
        /// How many distinct backends were probed. Zero means the routing table was empty.
        total: usize,
        /// The backends that failed, comma-separated. Empty when `total` is zero.
        unreachable_ids: String,
    },
    /// Everything else: binding the iroh endpoint, the TUN device, the listen socket, ...
    Other(anyhow::Error),
    /// A backend was reached and then closed the connection because this client has no 2FA
    /// credentials while the server requires them. Unreachable in the sense that nothing will be
    /// proxied, but the cause is a missing setting here, not a server that is down.
    TwoFactorRequired {
        /// The backends that demanded credentials, comma-separated.
        unreachable_ids: String,
    },
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::NoReachableBackend { total: 0, .. } => f.write_str(
                "no backend is configured: the configured nodes carry no domains, so there is \
                 nothing to forward",
            ),
            StartError::NoReachableBackend {
                total,
                unreachable_ids,
            } => write!(
                f,
                "no backend is reachable: all {} configured node(s) failed to connect ({})",
                total, unreachable_ids
            ),
            StartError::TwoFactorRequired { unreachable_ids } => write!(
                f,
                "the server requires 2FA but this client has no credentials: {} accepted the \
                 connection and then refused it",
                unreachable_ids
            ),
            StartError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartError::NoReachableBackend { .. } | StartError::TwoFactorRequired { .. } => None,
            StartError::Other(e) => e.source(),
        }
    }
}

/// Every `?` and `anyhow` error inside `start()` lands in the catch-all variant.
impl From<anyhow::Error> for StartError {
    fn from(e: anyhow::Error) -> Self {
        StartError::Other(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyMode {
    Tun,
    LocalProxy,
}

#[derive(Debug, Clone)]
pub enum ConnectionConfig {
    Ticket(String),
    EndpointId(String),
}

#[derive(Debug, Clone)]
pub struct ProxyNodeConfig {
    pub connection: ConnectionConfig,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyLoadBalancingStrategy {
    RoundRobin,
    Random,
}

impl std::str::FromStr for ProxyLoadBalancingStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "round_robin" => Ok(Self::RoundRobin),
            "random" => Ok(Self::Random),
            _ => Err(format!("Unknown load balancing strategy: {}", s)),
        }
    }
}

impl From<ProxyLoadBalancingStrategy> for LoadBalancingStrategy {
    fn from(strategy: ProxyLoadBalancingStrategy) -> Self {
        match strategy {
            ProxyLoadBalancingStrategy::RoundRobin => LoadBalancingStrategy::RoundRobin,
            ProxyLoadBalancingStrategy::Random => LoadBalancingStrategy::Random,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyManagerConfig {
    pub nodes: Vec<ProxyNodeConfig>,
    pub local_proxy_addr: String,
    pub dns_listen_addr: String,
    pub upstream_dns: String,
    pub load_balancing: ProxyLoadBalancingStrategy,
    pub tun_name: String,
    /// Forwarding mode, chosen by the user, not probed: `true` requests TUN (and fails if the
    /// process cannot create it), `false` runs the local proxy. There is no automatic mode
    /// selection any more — an implicit probe made the mode depend on how the app happened to be
    /// launched, so the same configuration could forward traffic two different ways.
    pub use_tun: bool,
    pub relay_mode: String,
    pub relay_url: String,
    pub force_relay: bool,
    pub two_factor_enabled: bool,
    pub two_factor_client_id: String,
    pub two_factor_secret: String,
    pub two_factor_algorithm: String,
}

struct ProxyInstance {
    tun_proxy: Option<Arc<TunProxy>>,
    local_proxy: Option<Arc<LocalProxyWrapper>>,
    endpoint_group: Option<Arc<EndpointGroup>>,
}

impl ProxyInstance {
    async fn stop(self) {
        tracing::info!("Stopping proxy instance");

        // The local DNS server is owned by tun_proxy::run and cleaned up when TUN stops
        if let Some(tun_proxy) = self.tun_proxy {
            tun_proxy.stop();
        }

        if let Some(local_proxy) = self.local_proxy {
            local_proxy.stop().await;
        }

        if let Some(endpoint_group) = self.endpoint_group {
            endpoint_group.close_all().await;
        }
    }
}

pub struct ProxyManager {
    config: ProxyManagerConfig,
    ip_mapping: Arc<IpMapping>,
    mode: parking_lot::Mutex<Option<ProxyMode>>,
    instance: parking_lot::Mutex<Option<ProxyInstance>>,
}

impl ProxyManager {
    pub fn new(config: ProxyManagerConfig) -> Self {
        Self {
            config,
            ip_mapping: Arc::new(IpMapping::new()),
            mode: parking_lot::Mutex::new(None),
            instance: parking_lot::Mutex::new(None),
        }
    }

    pub fn get_mode(&self) -> Option<ProxyMode> {
        self.mode.lock().clone()
    }

    pub async fn stop(&self) {
        tracing::info!("ProxyManager stopping");
        let instance = self.instance.lock().take();
        if let Some(instance) = instance {
            instance.stop().await;
        }
        *self.mode.lock() = None;
    }

    /// Bring the proxy up, in TUN or local-proxy mode.
    ///
    /// Every failure mode is a hard failure: a proxied start that cannot reach a single backend is
    /// reported (see [`StartError::NoReachableBackend`]) rather than announced as running, because
    /// the UI shows a green light for "running" and the user would have no way to tell that their
    /// traffic goes nowhere.
    pub async fn start(&self) -> Result<(), StartError> {
        tracing::info!("Initializing proxy manager...");

        let all_domains: Vec<String> = self
            .config
            .nodes
            .iter()
            .flat_map(|node| node.domains.iter().cloned())
            .collect();

        let nodes: Vec<NodeConfig> = self
            .config
            .nodes
            .iter()
            .map(|node| match &node.connection {
                ConnectionConfig::Ticket(t) => NodeConfig {
                    server_node_id: None,
                    server_ticket: Some(t.clone()),
                    domains: node.domains.clone(),
                },
                ConnectionConfig::EndpointId(e) => NodeConfig {
                    server_node_id: Some(e.clone()),
                    server_ticket: None,
                    domains: node.domains.clone(),
                },
            })
            .collect();

        // Build iroh endpoint with relay configuration.
        //
        // The QUIC transport tuning has to be applied here too: this endpoint carries every
        // proxied stream in both modes, and without it each stream falls back to iroh's 1.25 MB
        // default receive window, which caps a single connection at roughly 50 Mbps on a 200 ms
        // path. `TransportTuning::from_env()` keeps the A/B overrides working.
        let transport_tuning = TransportTuning::from_env();
        tracing::info!("QUIC transport tuning: {}", transport_tuning.describe());
        let mut ep_builder = Endpoint::builder(presets::N0)
            .transport_config(transport_tuning.transport_config());
        match self.config.relay_mode.as_str() {
            "disabled" => {
                tracing::info!("Relay mode: disabled (direct connections only)");
                ep_builder = ep_builder.relay_mode(iroh::RelayMode::Disabled);
            }
            "default" => {
                tracing::info!("Relay mode: default (all N0 relays)");
            }
            "custom" => {
                if !self.config.relay_url.is_empty() {
                    tracing::info!("Relay mode: custom, url={}", self.config.relay_url);
                    let relay_url = RelayUrl::from_str(&self.config.relay_url)
                        .map_err(|e| anyhow::anyhow!("Invalid relay URL: {}", e))?;
                    ep_builder = ep_builder.relay_mode(
                        iroh::RelayMode::Custom(RelayMap::from_iter(vec![relay_url])),
                    );
                } else {
                    tracing::warn!("Relay mode is custom but no URL provided, using pinned default");
                }
            }
            "pinned" | _ => {
                // Default behaviour: pin the relay to aps1-1 (Asia Pacific South) so that a
                // relay switch cannot drop the WebSocket connection.
                let pinned_url = "https://aps1-1.relay.n0.iroh.link.";
                let relay_url = RelayUrl::from_str(pinned_url)
                    .expect("PINNED_RELAY_URL must be a valid relay URL");
                tracing::info!("Relay mode: pinned to {}", pinned_url);
                ep_builder = ep_builder.relay_mode(
                    iroh::RelayMode::Custom(RelayMap::from_iter(vec![relay_url])),
                );
            }
        }

        let iroh_endpoint = ep_builder.bind().await
            .map_err(|e| anyhow::anyhow!("Failed to bind iroh endpoint: {}", e))?;
        tracing::info!("Iroh endpoint bound, node_id={}", iroh_endpoint.id());
        if self.config.force_relay {
            tracing::info!("Force relay enabled: direct connections will be disabled");
        }

        let endpoint_group =
            EndpointGroup::new_with_nodes_and_endpoint(nodes.clone(), None, self.config.load_balancing.into(), iroh_endpoint)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

        // 2FA: when enabled and a secret is configured, every new connection performs the
        // authentication handshake first.
        if self.config.two_factor_enabled && !self.config.two_factor_secret.trim().is_empty() {
            let auth = TwoFactorAuth::new(
                &self.config.two_factor_client_id,
                &self.config.two_factor_secret,
                TotpAlgorithm::from_name(&self.config.two_factor_algorithm),
            )
            .map_err(|e| anyhow::anyhow!("Invalid 2FA config: {}", e))?;
            endpoint_group.set_two_factor(Some(auth)).await;
            tracing::info!(
                "2FA enabled, client_id: {}",
                self.config.two_factor_client_id
            );
        }

        let endpoint_group = Arc::new(endpoint_group);

        tracing::info!("EndpointGroup initialized with {} nodes", nodes.len());

        // Reachability gate. Nothing so far has dialed anything: building the group only binds a
        // local endpoint, so a well-formed node ID that does not exist gets this far looking
        // valid. Probing now means a start that would forward to nothing fails here, before a TUN
        // device or a listen socket exists to tear down.
        let report = endpoint_group.preconnect_report().await;
        // A backend that answered and then refused the connection for missing 2FA is counted as
        // unreachable, which on its own reads like "the server is down". Report the real cause
        // instead: the credentials belong on this side.
        if report.any_auth_required() && !report.any_reachable() {
            tracing::error!(
                "Backend(s) require 2FA, but no credentials are configured: {}",
                report.unreachable_ids()
            );
            return Err(StartError::TwoFactorRequired {
                unreachable_ids: report.unreachable_ids(),
            });
        }
        if !report.any_reachable() {
            tracing::error!(
                "No reachable backend out of {} probed node(s)",
                report.total()
            );
            return Err(StartError::NoReachableBackend {
                total: report.total(),
                unreachable_ids: report.unreachable_ids(),
            });
        }
        if report.unreachable.is_empty() {
            tracing::info!("All {} backend(s) reachable", report.total());
        } else {
            // Load balancing tolerates a partial outage, so a partial failure is only a warning.
            tracing::warn!(
                "{} of {} backend(s) unreachable, the remaining {} still serve traffic: {}",
                report.unreachable.len(),
                report.total(),
                report.reachable.len(),
                report.unreachable_ids()
            );
        }

        if self.config.use_tun {
            if !TunProxy::is_available().await {
                // Requested but not granted: fail loudly instead of forwarding traffic through a
                // local proxy the user did not ask for. Callers translate this into
                // `proxy.tun_unavailable`.
                return Err(StartError::Other(anyhow::anyhow!(
                    "TUN mode was requested but this process has no privileges to create the tunnel"
                )));
            }

            tracing::info!("TUN mode requested, starting TUN + DNS hijack mode");

            // Starting the local DNS server and switching system DNS is handled inside
            // tun_proxy::run (DNS is started after the interface is configured to avoid
            // WSAEADDRNOTAVAIL); here we only build the configuration.
            let dns_ip = self
                .config
                .dns_listen_addr
                .split(':')
                .next()
                .unwrap_or(TUN_IP)
                .to_string();
            let tun_config = TunProxyConfig {
                tunnel_name: self.config.tun_name.clone(),
                dns_ip,
                dns: DnsServerConfig {
                    listen_addr: self.config.dns_listen_addr.clone(),
                    upstream_dns: self.config.upstream_dns.clone(),
                    proxy_domains: all_domains.clone(),
                },
            };
            let tun_proxy = Arc::new(TunProxy::new(
                tun_config,
                endpoint_group.clone(),
                self.ip_mapping.clone(),
            ));

            *self.instance.lock() = Some(ProxyInstance {
                tun_proxy: Some(tun_proxy.clone()),
                local_proxy: None,
                endpoint_group: Some(endpoint_group.clone()),
            });
            *self.mode.lock() = Some(ProxyMode::Tun);

            // run() creates the device and configures interface/routes/DNS, restoring
            // everything on exit
            match tun_proxy.run().await {
                Ok(()) => {
                    tracing::info!("TUN proxy stopped successfully");
                    // Properly close endpoints before clearing instance
                    let instance = self.instance.lock().take();
                    if let Some(instance) = instance {
                        instance.stop().await;
                    }
                    *self.mode.lock() = None;
                    return Ok(());
                }
                Err(e) => {
                    // TUN was requested explicitly, so a runtime failure is reported rather than
                    // answered with a local proxy: the caller surfaces it as a startup failure
                    // (`proxy.start_failed` with this detail) and the mode goes back to stopped.
                    tracing::error!("TUN proxy failed: {}", e);
                    let instance = self.instance.lock().take();
                    if let Some(instance) = instance {
                        instance.stop().await;
                    }
                    *self.mode.lock() = None;
                    return Err(StartError::Other(anyhow::anyhow!(
                        "TUN proxy failed: {}",
                        e
                    )));
                }
            }
        }

        *self.mode.lock() = Some(ProxyMode::LocalProxy);
        tracing::info!("Starting local proxy...");

        // The proxy runs on the group built above, not on a fresh one: it is what carries the relay
        // mode, the transport tuning and the 2FA credentials, and it is what the reachability probe
        // just validated. Building a second group here used to silently drop all three.
        let local_proxy = Arc::new(
            LocalProxyWrapper::new(
                &self.config.local_proxy_addr,
                all_domains,
                endpoint_group.clone(),
            )
            .await?,
        );

        *self.instance.lock() = Some(ProxyInstance {
            tun_proxy: None,
            local_proxy: Some(local_proxy.clone()),
            endpoint_group: Some(endpoint_group.clone()),
        });

        // Spawn the local proxy run loop as a separate task. This keeps the
        // large async state machine (handle_local_connection, handle_tls_tunnel,
        // etc.) off the current task's stack, preventing stack overflow on
        // tokio worker threads (default 2 MB stack).
        let run_local_proxy = local_proxy.clone();
        tokio::spawn(async move {
            if let Err(e) = run_local_proxy.run().await {
                tracing::error!("Local proxy error: {}", e);
            }
        });

        // The local proxy is now running in a background task, so start() returns immediately;
        // shutdown is handled by ProxyManager::stop(). Do not tear down the instance here.
        Ok(())
    }

    pub async fn get_node_id(&self) -> Option<String> {
        None
    }

    /// How each configured node currently reaches its backend: direct, or through a relay.
    ///
    /// One entry per configured node, in configuration order, so the UI can pair a link with
    /// the node it belongs to. Empty when nothing is running: there is no path to report, and a
    /// stale icon for a link that no longer exists is worse than none.
    ///
    /// The answer comes from the paths iroh actually selected, never from the configured relay
    /// mode — a node permitted to use a relay may well have punched through to a direct path.
    pub async fn endpoint_links(&self) -> Vec<EndpointLink> {
        // Cloned out of the lock and dropped before the first await: a parking_lot guard must
        // not be held across a suspension point.
        let group = self
            .instance
            .lock()
            .as_ref()
            .and_then(|instance| instance.endpoint_group.clone());

        let Some(group) = group else {
            return Vec::new();
        };

        let kinds: HashMap<EndpointId, LinkKind> = group.link_kinds().await.into_iter().collect();

        self.config
            .nodes
            .iter()
            .filter_map(|node| {
                let (connection, addr) = match &node.connection {
                    ConnectionConfig::Ticket(ticket) => {
                        (ticket.clone(), parse_endpoint_addr(None, Some(ticket)))
                    }
                    ConnectionConfig::EndpointId(id) => {
                        (id.clone(), parse_endpoint_addr(Some(id), None))
                    }
                };
                // A node the group could not parse never got a pool, so there is nothing to
                // report for it; dropping it keeps the list aligned with what actually dialed.
                let addr = addr.ok()?;
                Some(EndpointLink {
                    connection,
                    endpoint_id: addr.id.to_string(),
                    link: kinds.get(&addr.id).copied().unwrap_or(LinkKind::Unknown),
                })
            })
            .collect()
    }
}

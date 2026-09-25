use crate::proxy::dns::DnsServerConfig;
use crate::proxy::local_proxy::LocalProxyWrapper;
use crate::proxy::tun_proxy::{tun_ip, TunProxy, TunProxyConfig};
use anyhow::Result;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use nexapipe_client::auth::{TotpAlgorithm, TwoFactorAuth};
use nexapipe_client::connection_pool::parse_endpoint_addr;
use nexapipe_client::endpoint_group::{EndpointGroup, NodeConfig};
use nexapipe_client::lb::LoadBalancingStrategy;
use nexapipe_client::relay::RelayModeSpec;
use nexapipe_client::transport::TransportTuning;
use nexapipe_client::LinkKind;
use std::collections::HashMap;
use std::fmt;
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
    /// 2FA credentials for *this* endpoint, not for every endpoint: each server keeps its own
    /// `[auth].clients` entry, so a single shared pair is what forced a second server to be
    /// given the first one's secret. `None` performs no handshake at all, which is also what
    /// lets one client mix servers that require 2FA with ones that do not.
    pub two_factor: Option<NodeTwoFactor>,
}

/// The 2FA credentials one node is configured with.
#[derive(Debug, Clone)]
pub struct NodeTwoFactor {
    pub client_id: String,
    pub secret: String,
    /// Lowercase algorithm name, as `TotpAlgorithm::from_name` expects it.
    pub algorithm: String,
}

/// The address a configured node resolves to.
///
/// `None` when the string is neither a valid Node ID nor a valid ticket: such a node never got a
/// pool in the group, so there is nothing to configure or report for it.
fn backend_addr(connection: &ConnectionConfig) -> Option<EndpointAddr> {
    match connection {
        ConnectionConfig::Ticket(ticket) => parse_endpoint_addr(None, Some(ticket)).ok(),
        ConnectionConfig::EndpointId(id) => parse_endpoint_addr(Some(id), None).ok(),
    }
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
    /// Bearer token for a `custom` relay that requires one. Only ever read together with
    /// `relay_url`, and never logged.
    pub relay_auth_token: String,
}

struct ProxyInstance {
    tun_proxy: Option<Arc<TunProxy>>,
    local_proxy: Option<Arc<LocalProxyWrapper>>,
    endpoint_group: Option<Arc<EndpointGroup>>,
    /// Our own iroh endpoint id: what the UI shows as "this machine", and what a server-side
    /// auth entry has to name when it keys 2FA by client id.
    local_node_id: String,
}

impl ProxyInstance {
    async fn stop(self) {
        tracing::info!("Stopping proxy instance");

        // The local DNS server and the system-DNS restore are owned by tun_proxy::run, and
        // they only happen when that task winds down — so wait for the teardown instead of
        // just flagging it. A service stop drops the whole tokio runtime right after this
        // returns; without the wait the restore never runs and the machine keeps a static
        // DNS pointing at a TUN address that no longer exists.
        if let Some(tun_proxy) = self.tun_proxy {
            tun_proxy.stop_and_wait().await;
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
    mode: parking_lot::Mutex<Option<ProxyMode>>,
    instance: parking_lot::Mutex<Option<ProxyInstance>>,
}

impl ProxyManager {
    pub fn new(config: ProxyManagerConfig) -> Self {
        Self {
            config,
            mode: parking_lot::Mutex::new(None),
            instance: parking_lot::Mutex::new(None),
        }
    }

    pub fn get_mode(&self) -> Option<ProxyMode> {
        // `ProxyMode` is `Copy`, so this is a dereference, not a clone.
        *self.mode.lock()
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
        //
        // The relay mode comes from the shared resolver in nexapipe-client, so the desktop,
        // Android and the server cannot drift apart. A mode that is set but unusable is an
        // error, never a silent substitution — an empty mode (nothing configured) is the only
        // thing that defers, to "pinned".
        let transport_tuning = TransportTuning::from_env();
        tracing::info!("QUIC transport tuning: {}", transport_tuning.describe());
        let relay = RelayModeSpec::parse(
            Some(&self.config.relay_mode),
            Some(&self.config.relay_url),
            Some(&self.config.relay_auth_token),
        )
        .map_err(StartError::Other)?
        .unwrap_or(RelayModeSpec::Pinned);
        if !relay.uses_url() && !self.config.relay_url.is_empty() {
            tracing::warn!(
                "relay_url {:?} is set but relay_mode {:?} does not use one; ignoring it",
                self.config.relay_url,
                self.config.relay_mode
            );
        }
        tracing::info!("Relay: {}", relay.describe());
        // Bind IPv4 only. On hosts where IPv6 exists but cannot carry full-size QUIC
        // datagrams (PPPoE: v6 MTU 1480, ICMPv6 "packet too big" filtered), iroh's net
        // report calls v6 usable, relay dials and path migration move traffic onto v6 —
        // where every datagram above the real MTU fails (sendmsg 10040), which reads as a
        // connection that dies a few seconds in. With no v6 socket the net report stays
        // v4-only and relay dials stop preferring v6. The TUN is IPv4-only anyway.
        let ep_builder = Endpoint::builder(presets::N0)
            .clear_ip_transports()
            .bind_addr("0.0.0.0:0")
            .map_err(|e| anyhow::anyhow!("Failed to configure the IPv4-only socket: {}", e))?
            .transport_config(transport_tuning.transport_config())
            .relay_mode(relay.relay_mode());

        let iroh_endpoint = ep_builder
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind iroh endpoint: {}", e))?;
        tracing::info!("Iroh endpoint bound, node_id={}", iroh_endpoint.id());
        // Taken before the endpoint is handed to the group, which owns it from here on.
        let local_node_id = iroh_endpoint.id().to_string();

        let endpoint_group = EndpointGroup::new_with_nodes_and_endpoint(
            nodes.clone(),
            None,
            self.config.load_balancing.into(),
            iroh_endpoint,
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

        // 2FA is per endpoint, applied after the group exists because that is when each node has
        // been resolved to the backend ID its pool is keyed by. A node with no credentials keeps
        // none, so it opens no auth stream.
        for node in &self.config.nodes {
            let two_factor = match &node.two_factor {
                Some(two_factor) => two_factor,
                None => continue,
            };
            if two_factor.secret.trim().is_empty() {
                continue;
            }

            let addr = match backend_addr(&node.connection) {
                Some(addr) => addr,
                None => {
                    tracing::warn!(
                        "2FA configured for a node that is neither a Node ID nor a ticket, ignoring it"
                    );
                    continue;
                }
            };

            // The server looks a handshake up by client_id (`clients.get(client_id)`),
            // so a secret with no id can never match any entry there: it authenticates
            // as client '' and is refused. That is a configuration mistake worth
            // saying out loud, because the client only ever sees the refusal.
            if two_factor.client_id.trim().is_empty() {
                tracing::warn!(
                    "2FA for {} has a secret but an empty client_id — this node will be rejected by any server keyed by client id",
                    addr.id
                );
            }

            let auth = TwoFactorAuth::new(
                &two_factor.client_id,
                &two_factor.secret,
                TotpAlgorithm::from_name(&two_factor.algorithm),
            )
            .map_err(|e| anyhow::anyhow!("Invalid 2FA config for {}: {}", addr.id, e))?;
            endpoint_group
                .set_two_factor_for(&addr.id.to_string(), Some(auth))
                .await;
            tracing::info!(
                "2FA enabled for {}, client_id: {}",
                addr.id,
                two_factor.client_id
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
            // No `TunProxy::is_available()` pre-flight any more. That probe is a bare `is_admin()`
            // (`net session` on Windows), and it is the wrong question: what matters is whether
            // the device can be created, which is what `run()` tries next and reports verbatim.
            // The service runs as LocalSystem, where the probe answers false even though the
            // tunnel can be created — so this check alone refused every service-mode TUN start a
            // couple of seconds in, once the endpoint bind and the reachability probe had
            // finished. Callers that want to refuse before touching anything (the desktop process,
            // which is never elevated) still do their own check.
            tracing::info!("TUN mode requested, starting TUN + DNS hijack mode");

            // Starting the local DNS server and switching system DNS is handled inside
            // tun_proxy::run (DNS is started after the interface is configured to avoid
            // WSAEADDRNOTAVAIL); here we only build the configuration.
            // The interface address is only decided when the TUN comes up (the block may have
            // moved), so the fallback is the *currently configured* one; `tun_proxy::retarget`
            // moves whatever lands here into the block actually in use.
            let fallback_ip = tun_ip();
            let dns_ip = self
                .config
                .dns_listen_addr
                .split(':')
                .next()
                .unwrap_or(&fallback_ip)
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
            let tun_proxy = Arc::new(TunProxy::new(tun_config, endpoint_group.clone()));

            *self.instance.lock() = Some(ProxyInstance {
                tun_proxy: Some(tun_proxy.clone()),
                local_proxy: None,
                endpoint_group: Some(endpoint_group.clone()),
                local_node_id: local_node_id.clone(),
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
            local_node_id: local_node_id.clone(),
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

    /// Our own endpoint id, or `None` when nothing is running.
    ///
    /// It used to be a stub that always answered `None`, which made every poll log
    /// `proxy.node_id_unavailable` — noise that looked exactly like a proxy that had died.
    pub async fn get_node_id(&self) -> Option<String> {
        // Cloned out of the lock before anything else: a parking_lot guard must not be held
        // across a suspension point.
        self.instance
            .lock()
            .as_ref()
            .map(|i| i.local_node_id.clone())
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
                let connection = match &node.connection {
                    ConnectionConfig::Ticket(ticket) => ticket.clone(),
                    ConnectionConfig::EndpointId(id) => id.clone(),
                };
                // A node the group could not parse never got a pool, so there is nothing to
                // report for it; dropping it keeps the list aligned with what actually dialed.
                let addr = backend_addr(&node.connection)?;
                Some(EndpointLink {
                    connection,
                    endpoint_id: addr.id.to_string(),
                    link: kinds.get(&addr.id).copied().unwrap_or(LinkKind::Unknown),
                })
            })
            .collect()
    }
}

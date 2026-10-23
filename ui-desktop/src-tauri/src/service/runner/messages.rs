//! What the IPC messages mean: the start, the stop and the readings the desktop polls.

use crate::error::{codes, AppError};
use crate::proxy::{
    ConnectionConfig, ProxyManager, ProxyManagerConfig, ProxyNodeConfig, StartError,
};
use crate::service::ipc::{IpcResponse, IssuedCredentialPayload, NodeInput};
use crate::status::{ActiveFlowPage, ProxyStatus, FLOW_PAGE_LIMIT};
use std::sync::Arc;

use super::{
    require_loopback, require_tun_name, require_tun_subnet, startup_error_slot, ServiceRunner,
};

impl ServiceRunner {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_start_proxy(
        nodes: Vec<NodeInput>,
        domains: Vec<String>,
        local_addr: Option<String>,
        dns_addr: Option<String>,
        upstream_dns: Option<String>,
        dns_strategy: Option<String>,
        load_balancing: Option<String>,
        tun_name: Option<String>,
        use_tun: Option<bool>,
        relay_mode: Option<String>,
        relay_url: Option<String>,
        relay_auth_token: Option<String>,
        discovery_mode: Option<String>,
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        // A new start owns the slot: whatever the previous one recorded is history, and a caller
        // that polls the status before the spawn has finished must not read a stale failure.
        *startup_error_slot().write().await = None;

        // Merge the global domains into every node — same logic as process mode (lib.rs) —
        // so that domains added through the text box in service mode are also handled
        // correctly by DNS hijacking and routing.
        let global_domains: Vec<String> = domains
            .into_iter()
            .filter(|d| !d.trim().is_empty())
            .collect();
        let parsed_nodes: Vec<ProxyNodeConfig> = nodes
            .into_iter()
            .filter(|n| !n.ticket.is_empty() || !n.endpoint_id.is_empty())
            .map(|n| {
                // Read before the connection string is moved out of `n`.
                let two_factor = n.two_factor();
                let enrollment = n.enrollment();
                let connection = if n.connection_type == "ticket" || !n.ticket.is_empty() {
                    ConnectionConfig::Ticket(n.ticket)
                } else {
                    ConnectionConfig::EndpointId(n.endpoint_id)
                };
                let mut merged: Vec<String> = n.domains;
                for g in &global_domains {
                    if !merged.iter().any(|d| d == g) {
                        merged.push(g.clone());
                    }
                }
                ProxyNodeConfig {
                    connection,
                    domains: merged,
                    two_factor,
                    enrollment,
                    // The device's own key, which belongs to the device rather
                    // than to the credential: the same key is offered by the
                    // enrollment and signs every handshake after it.
                    device_key: n.device_key.clone(),
                }
            })
            .collect();

        if parsed_nodes.is_empty() {
            return IpcResponse::Error(AppError::new(codes::PROXY_NO_NODES));
        }

        let load_balancing = load_balancing.unwrap_or_else(|| "round_robin".to_string());
        let load_balancing =
            match nexapipe_client::lb::LoadBalancingStrategy::from_name(&load_balancing) {
                Ok(lb) => lb,
                Err(e) => {
                    return IpcResponse::Error(AppError::cause(
                        codes::PROXY_INVALID_LOAD_BALANCING,
                        e,
                    ))
                }
            };

        // The service runs elevated and binds whatever it is told, so both
        // addresses are validated to the thing they are for. Anything else would
        // turn this message into "ask the elevated service to publish an
        // unauthenticated proxy", which is not a capability a caller gets.
        let local_addr = local_addr.unwrap_or_else(|| "127.0.0.1:8080".to_string());
        if let Err(e) = require_loopback(&local_addr, codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK) {
            return IpcResponse::Error(e);
        }

        let dns_addr = dns_addr.unwrap_or_else(|| "198.18.0.254:53".to_string());
        if let Err(e) = require_tun_subnet(&dns_addr) {
            return IpcResponse::Error(e);
        }

        let upstream_dns = upstream_dns.unwrap_or_else(|| "8.8.8.8:53".to_string());

        // What the machine's DNS is asked to do. Read here rather than deeper
        // down, so a spelling nobody knows is refused before anything is
        // changed: a strategy that is not known must not be read as "leave the
        // machine's DNS alone" or "replace all of it".
        let dns_strategy = match dns_strategy.as_deref() {
            Some(value) => match crate::proxy::dns_config::DnsStrategy::parse(value) {
                Ok(strategy) => strategy,
                Err(e) => {
                    return IpcResponse::Error(AppError::cause(
                        codes::PROXY_INVALID_DNS_STRATEGY,
                        e.to_string(),
                    ));
                }
            },
            None => crate::proxy::dns_config::DnsStrategy::default(),
        };

        let tun_name = tun_name.unwrap_or_else(|| "nexa-tun".to_string());

        // The interface name is checked here as well as on the desktop's side: this
        // process is the one that runs it, as LocalSystem, and it does not trust a
        // message from another process — the desktop is a peer, not a guarantee, and
        // it may be an older build that never had this check.
        if let Err(e) = require_tun_name(&tun_name) {
            return IpcResponse::Error(e);
        }

        // Explicit forwarding mode, same contract as process mode: requested TUN is honoured or
        // refused, never silently replaced by a local proxy.
        //
        // Deliberately no `TunProxy::is_available()` gate here: the probe is a bare `is_admin()`
        // (`net session`), and under LocalSystem it answers false regardless of what the process
        // can actually do, so it refused tunnels this service could create. Creating the device
        // is the check that means something, and it reports the real reason when it fails.
        let use_tun = use_tun.unwrap_or(false);

        let config = ProxyManagerConfig {
            nodes: parsed_nodes,
            local_proxy_addr: local_addr,
            dns_listen_addr: dns_addr,
            upstream_dns,
            dns_strategy,
            load_balancing,
            tun_name,
            use_tun,
            relay_mode: relay_mode.unwrap_or_else(|| "pinned".to_string()),
            relay_url: relay_url.unwrap_or_default(),
            relay_auth_token: relay_auth_token.unwrap_or_default(),
            discovery_mode: discovery_mode.unwrap_or_else(|| "n0".to_string()),
        };

        let manager = Arc::new(ProxyManager::new(config));

        {
            let mut pm = proxy_manager.write().await;
            // The previous manager is stopped before the new one takes the slot. It may own a
            // tunnel, and a tunnel that is still up under a manager that is no longer registered
            // is a tunnel nobody can stop: the status reads "stopped" while the traffic is
            // still flowing, and the stop command has nothing to stop.
            if let Some(previous) = pm.as_ref() {
                previous.stop().await;
            }
            *pm = Some(manager.clone());
        }

        let proxy_manager_clone = proxy_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.start().await {
                tracing::error!("Proxy manager failed: {}", e);
                // Same mapping as the desktop's own start path, so the same code reaches the UI
                // whichever process ran the proxy.
                let code = match &e {
                    StartError::NoReachableBackend { .. } => codes::PROXY_NO_REACHABLE_BACKEND,
                    StartError::TwoFactorRequired { .. } => codes::PROXY_TWO_FACTOR_REQUIRED,
                    StartError::Other(_) => codes::PROXY_START_FAILED,
                };
                *startup_error_slot().write().await =
                    Some(AppError::with_detail(code, e.to_string()));
                // Cleared only when the slot still holds this manager: a newer start has
                // replaced it, and clearing the slot then would unregister a manager that is
                // running. Same guard as the desktop's own path.
                let mut pm = proxy_manager_clone.write().await;
                if pm
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &manager))
                {
                    *pm = None;
                }
            }
        });

        IpcResponse::Ok
    }

    pub(super) async fn handle_stop_proxy(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        // A deliberate stop is not a failure: leaving one on file would have the caller explain
        // the next start with it.
        *startup_error_slot().write().await = None;

        let mut pm = proxy_manager.write().await;
        if let Some(manager) = pm.as_ref() {
            manager.stop().await;
        }
        // Clear the registration as well as stopping the instance. `stop()` sets the mode back
        // to `None`, and a manager that is still registered with no mode reads as "starting" —
        // after a deliberate stop nothing is starting. Same rationale as the desktop's own stop
        // path; without this, a stop followed by a UI restart left every status poll answering
        // `starting` forever.
        *pm = None;
        IpcResponse::Ok
    }

    pub(super) async fn handle_get_status(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let status = match pm.as_ref() {
            // The manager answers `None` until the tunnel is up, which is exactly the
            // "starting" state; see `ProxyStatus::starting` for why that is not `running`.
            Some(manager) => match manager.get_mode() {
                Some(mode) => ProxyStatus::running_with(mode),
                None => ProxyStatus::starting(),
            },
            None => ProxyStatus::stopped(),
        };
        IpcResponse::Status(status)
    }

    pub(super) async fn handle_get_node_id(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        if let Some(manager) = pm.as_ref() {
            match manager.get_node_id().await {
                Some(id) => IpcResponse::NodeId(id),
                None => IpcResponse::Error(AppError::new(codes::PROXY_NODE_ID_UNAVAILABLE)),
            }
        } else {
            IpcResponse::Error(AppError::new(codes::PROXY_NOT_RUNNING))
        }
    }

    /// The credential the server issued for an enrollment token, if one was spent.
    ///
    /// Not an error when nothing enrolled: the desktop asks after every start, and a start
    /// that simply had no token to spend is the common case.
    pub(super) async fn handle_get_issued_credential(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let issued = match pm.as_ref() {
            Some(manager) => manager.take_issued_credential().await,
            None => None,
        };
        IpcResponse::IssuedCredential(issued.map(|credential| IssuedCredentialPayload {
            client_id: credential.client_id,
            // On its way to the app, and out of this process: the copy handed
            // over is a plain string, and the one that stays behind is wiped
            // with the credential.
            secret: credential.secret.expose_secret().to_string(),
            algorithm: credential.algorithm,
            public_key: credential.public_key,
            device: credential.device,
        }))
    }

    /// How each configured node currently reaches its backend.
    ///
    /// An absent manager answers with an empty list rather than an error: this is polled while
    /// the proxy is up, and "nothing is running" is a state the caller renders by drawing no
    /// icon, not by showing a failure.
    pub(super) async fn handle_get_endpoint_links(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let links = match pm.as_ref() {
            Some(manager) => manager.endpoint_links().await,
            None => Vec::new(),
        };
        IpcResponse::EndpointLinks(links)
    }

    /// Whether each configured node answered its last probe.
    ///
    /// An absent manager answers with an empty list rather than an error, as the links do: this
    /// is polled while the proxy is up, and "nothing is running" is a state the caller renders
    /// by drawing no badge at all, not by showing a failure.
    pub(super) async fn handle_get_node_health(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let health = match pm.as_ref() {
            Some(manager) => manager.node_health().await,
            None => Vec::new(),
        };
        IpcResponse::NodeHealth(health)
    }

    /// What each configured node has carried, and how many flows are open to it.
    ///
    /// An absent manager answers with an empty list rather than an error, as the links and the
    /// health do: this is polled while the proxy is up, and "nothing is running" is a state the
    /// caller draws as no figure at all, not as a failure.
    pub(super) async fn handle_get_node_traffic(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let traffic = match pm.as_ref() {
            Some(manager) => manager.node_traffic().await,
            None => Vec::new(),
        };
        IpcResponse::NodeTraffic(traffic)
    }

    /// The connections the proxy has open right now.
    ///
    /// An absent manager answers with an empty page rather than an error, as every other reading
    /// here does: "nothing is running" is a state the caller draws as an empty list, not as a
    /// failure.
    pub(super) async fn handle_get_active_flows(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let page = match pm.as_ref() {
            Some(manager) => manager.active_flows(FLOW_PAGE_LIMIT).await,
            None => ActiveFlowPage::empty(),
        };
        IpcResponse::ActiveFlows(page)
    }

    /// Ends one open flow, by id.
    pub(super) async fn handle_close_flow(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
        id: u64,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let closed = pm.as_ref().is_some_and(|manager| manager.close_flow(id));
        IpcResponse::FlowClosed(closed)
    }

    /// Ends every flow reaching one configured node.
    pub(super) async fn handle_close_node_flows(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
        connection: &str,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let closed = match pm.as_ref() {
            Some(manager) => manager.close_node_flows(connection).await,
            None => None,
        };
        IpcResponse::NodeFlowsClosed(closed)
    }
}

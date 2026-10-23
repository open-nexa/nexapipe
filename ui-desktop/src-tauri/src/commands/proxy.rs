//! The proxy: starting it, stopping it, and asking it what it is doing.
//!
//! These are the commands the renderer polls while the app is open, and the
//! two that change anything: starting the proxy and stopping it again.

use crate::commands::credentials::require_unlocked;
use crate::commands::{ask_service, PROXY_MANAGER, STARTUP_ERROR};
use crate::credentials;
use crate::error::{codes, AppError};
use crate::proxy;
use crate::proxy::{
    ConnectionConfig, ProxyManager, ProxyManagerConfig, ProxyNodeConfig, StartError,
};
use crate::service;
use crate::service::ipc::{NodeInput, StartProxyRequest};
use crate::service::IpcClient;
use crate::status::{
    ActiveFlowPage, EndpointLink, NodeHealthStatus, NodeTrafficStatus, ProxyStatus, FLOW_PAGE_LIMIT,
};

use std::sync::Arc;

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_proxy(
    nodes: Vec<NodeInput>,
    domains: Vec<String>,
    local_addr: Option<String>,
    dns_addr: Option<String>,
    upstream_dns: Option<String>,
    dns_strategy: Option<String>,
    load_balancing: Option<String>,
    tun_name: Option<String>,
    use_service: Option<bool>,
    use_tun: Option<bool>,
    relay_mode: Option<String>,
    relay_url: Option<String>,
    relay_auth_token: Option<String>,
    discovery_mode: Option<String>,
) -> Result<(), AppError> {
    let use_service = use_service.unwrap_or(false);
    let use_tun = use_tun.unwrap_or(false);

    // Before anything is probed or spawned, and only when a tunnel is actually being asked for.
    // The stale-hijack cleanup resets every adapter still pointing at a TUN address, and on
    // Windows there is no "is that tunnel still alive" guard (`address_is_held` is macOS and
    // Linux only) — so a cleanup still running would reset the DNS of the tunnel this start is
    // in the middle of bringing up.
    //
    // Service mode is not exempt. The cleanup this process started is *this* process's, not the
    // service's: the service runs one of its own when it boots (`ServiceRunner::run`), which is
    // no help here, because a long-lived service does not boot again between two starts and has
    // no reason to re-clean before the second one. The tunnel whose DNS is at stake belongs to
    // the service, and this process's cleanup is perfectly capable of resetting it.
    if use_tun {
        stale_hijack_cleanup().await;
    }

    // Checked here, before anything is spawned, so the caller gets the precise code instead of a
    // generic async start failure: a manager that cannot obtain privileges must not be created
    // in TUN mode at all.
    //
    // Service mode is exempt on purpose. The tunnel is created by whoever runs the proxy, and in
    // service mode that is the service process, which is already elevated — while this process is
    // the desktop GUI and never is, so asking `TunProxy::is_available()` here (it is just an
    // `is_admin()` probe) refused a tunnel the service could perfectly well create, and reported
    // `proxy.tun_unavailable` for every TUN start. The service re-checks on its side, where the
    // answer means something.
    if use_tun && !use_service && !proxy::tun_proxy::TunProxy::is_available().await {
        // Named so the log says which of the two processes refused: the same code is raised by
        // the service runner for its own probe, and they were indistinguishable.
        return Err(AppError::with_detail(
            codes::PROXY_TUN_UNAVAILABLE,
            "the desktop process is not elevated, so it cannot create the tunnel itself",
        ));
    }

    // Anything the caller spells out is checked before the request is handed to
    // either runner. Absent means "take the default", and both defaults are
    // loopback / TUN addresses by construction — they are re-checked below in
    // case they ever stop being.
    //
    // What is at stake: `local_addr` fronts a proxy with nothing authenticating
    // in front of it, so binding it anywhere but loopback publishes an open
    // proxy to everyone who can reach the machine. That is the one thing the
    // service side refuses on purpose, and until now only the service side
    // refused it — the in-process path took the address as it came.
    if let Some(addr) = local_addr.as_deref() {
        service::runner::require_loopback(addr, codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK)?;
    }
    if let Some(addr) = dns_addr.as_deref() {
        service::runner::require_tun_subnet(addr)?;
    }
    // The interface name ends up in a PowerShell script in the service, which runs as
    // LocalSystem, so it is checked here rather than trusted: the caller gets the
    // precise error instead of a mysterious failure much later.
    if let Some(name) = tun_name.as_deref() {
        service::runner::require_tun_name(name)?;
    }

    if use_service {
        match IpcClient::start_proxy(StartProxyRequest {
            nodes: nodes.clone(),
            domains: domains.clone(),
            local_addr: local_addr.clone(),
            dns_addr: dns_addr.clone(),
            upstream_dns: upstream_dns.clone(),
            dns_strategy: dns_strategy.clone(),
            load_balancing: load_balancing.clone(),
            tun_name: tun_name.clone(),
            use_tun: Some(use_tun),
            relay_mode: relay_mode.clone(),
            relay_url: relay_url.clone(),
            relay_auth_token: relay_auth_token.clone(),
            discovery_mode: discovery_mode.clone(),
        })
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                // With TUN requested, a service failure is reported instead of falling back:
                // the fallback would start a local proxy while the user asked for a tunnel.
                //
                // This is the one command that does not go through `ask_service`, because
                // here the fallback is not allowed at all rather than merely unwanted.
                if use_tun {
                    tracing::error!("TUN requested but service start failed: {}", e);
                    return Err(e);
                }
                tracing::warn!(
                    "Failed to start proxy via service, falling back to process mode: {}",
                    e
                );
            }
        }
    }

    // Merge the global domains into every node's domains: the global list holds every domain
    // configured in the UI text area. Migration from older versions writes them into
    // node[0].domains, but domains the user adds later only exist in the global list, so we
    // de-duplicate and append them to each node. This makes sure both DNS hijacking
    // (all_domains collection) and routing (EndpointGroup) pick up newly added domains
    // (e.g. comfyui.iroh.top).
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
            // Merge: node-local domains + global domains, de-duplicated, order preserved
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
        return Err(AppError::new(codes::PROXY_NO_NODES));
    }

    let load_balancing = load_balancing.unwrap_or_else(|| "round_robin".to_string());
    let load_balancing = nexapipe_client::lb::LoadBalancingStrategy::from_name(&load_balancing)
        .map_err(|e: String| AppError::cause(codes::PROXY_INVALID_LOAD_BALANCING, e))?;

    let local_addr = local_addr.unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let dns_addr = dns_addr.unwrap_or_else(|| "198.18.0.254:53".to_string());
    let upstream_dns = upstream_dns.unwrap_or_else(|| "8.8.8.8:53".to_string());

    // What the machine's DNS is asked to do. Read here rather than deeper
    // down, so a spelling nobody knows is refused before anything is changed:
    // a strategy that is not known must not be read as "leave the machine's
    // DNS alone" or "replace all of it".
    let dns_strategy = match dns_strategy.as_deref() {
        Some(value) => proxy::dns_config::DnsStrategy::parse(value)
            .map_err(|e| AppError::cause(codes::PROXY_INVALID_DNS_STRATEGY, e.to_string()))?,
        None => proxy::dns_config::DnsStrategy::default(),
    };

    // The in-process path is the one that had no validation at all, so it
    // re-checks after the defaults have been substituted: the caller's values
    // were already refused above, and this catches a default that stops being
    // loopback or leaves the TUN block.
    service::runner::require_loopback(&local_addr, codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK)?;
    service::runner::require_tun_subnet(&dns_addr)?;

    let tun_name = tun_name.unwrap_or_else(|| "nexa-tun".to_string());
    service::runner::require_tun_name(&tun_name)?;

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
        let mut proxy_manager = PROXY_MANAGER.write().await;
        *proxy_manager = Some(manager.clone());
    }

    let startup_error_clone = STARTUP_ERROR.clone();
    let proxy_manager_clone = PROXY_MANAGER.clone();
    let manager_cleanup = manager.clone();
    tokio::spawn(async move {
        if let Err(e) = manager.start().await {
            tracing::error!("Proxy manager failed: {}", e);
            // "No backend is reachable" is a foreseeable configuration/network problem the user
            // can act on, so it keeps its own code; everything else stays the generic startup
            // failure. Either way the raw reason rides along as `detail`.
            let code = match &e {
                StartError::NoReachableBackend { .. } => codes::PROXY_NO_REACHABLE_BACKEND,
                StartError::TwoFactorRequired { .. } => codes::PROXY_TWO_FACTOR_REQUIRED,
                StartError::Other(_) => codes::PROXY_START_FAILED,
            };
            *startup_error_clone.write().await = Some(AppError::with_detail(code, e.to_string()));

            // A manager that failed to start reports `None` as its mode, which `get_proxy_status`
            // renders as "starting" — but nothing is starting: the tunnel or the listen socket was
            // never brought up, or has just gone away. Leaving it registered made the UI sit on
            // the connecting state forever after a failed start. This mirrors what the service
            // runner already does, and only clears the entry if a newer start has not replaced it.
            let mut registered = proxy_manager_clone.write().await;
            if registered
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &manager_cleanup))
            {
                *registered = None;
            }
        }
    });

    Ok(())
}

#[tauri::command]
pub(crate) async fn stop_proxy(use_service: Option<bool>) -> Result<(), AppError> {
    let use_service = use_service.unwrap_or(false);

    if ask_service(use_service, "stop proxy", IpcClient::stop_proxy())
        .await
        .is_some()
    {
        return Ok(());
    }

    // Clear the registration as well as stopping the instance. A manager that is still registered
    // reports its mode as `None`, which the UI reads as "starting"; after a stop nothing is
    // starting, and `waitForStart` in the frontend relies on that mode to tell a failed start from
    // a slow one.
    let mut proxy_manager = PROXY_MANAGER.write().await;
    if let Some(manager) = proxy_manager.as_ref() {
        manager.stop().await;
    }
    *proxy_manager = None;
    Ok(())
}

#[tauri::command]
pub(crate) async fn get_proxy_status(use_service: Option<bool>) -> Result<ProxyStatus, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(status) = ask_service(use_service, "get status", IpcClient::get_status()).await {
        return Ok(status);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        // A manager with no mode yet is starting up, not running: see `ProxyStatus::starting`.
        Some(manager) => match manager.get_mode() {
            Some(mode) => ProxyStatus::running_with(mode),
            None => ProxyStatus::starting(),
        },
        // No manager here, and the service could not be asked: the tunnel may be the service's,
        // and this process cannot say. "Stopped" would be a guess, and the guess is what starts a
        // second tunnel over a live one — so the state is reported as unknown instead.
        None if use_service => ProxyStatus::unknown(),
        None => ProxyStatus::stopped(),
    })
}

/// This endpoint's Node ID, as [`credentials::mask`] renders it.
///
/// Masked for the same reason a stored credential is: this is the string the UI
/// prints, and it is the name this machine answers to on the network. Nothing in
/// the app needs the whole of it to work — [`reveal_node_id`] is how the user
/// gets one to paste somewhere, which is a deliberate act rather than a glance.
#[tauri::command]
pub(crate) async fn get_node_id_display(use_service: Option<bool>) -> Result<String, AppError> {
    Ok(credentials::mask(&node_id(use_service).await?))
}

/// This endpoint's Node ID in full.
///
/// The one way a surface gets the whole of it, for the user to copy into a
/// server's `[peers] allow` or into a message to whoever runs one — which is
/// why the door stands in front of it.
#[tauri::command]
pub(crate) async fn reveal_node_id(use_service: Option<bool>) -> Result<String, AppError> {
    require_unlocked()?;
    node_id(use_service).await
}

/// This endpoint's Node ID, from whichever process is running the proxy.
pub(crate) async fn node_id(use_service: Option<bool>) -> Result<String, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(id) = ask_service(use_service, "get node ID", IpcClient::get_node_id()).await {
        return Ok(id);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    match proxy_manager.as_ref() {
        Some(manager) => manager
            .get_node_id()
            .await
            .ok_or_else(|| AppError::new(codes::PROXY_NODE_ID_UNAVAILABLE)),
        None => Err(AppError::new(codes::PROXY_NOT_RUNNING)),
    }
}

/// How each configured node currently reaches its backend: direct, or through a relay.
///
/// Empty when the proxy is not running. There is deliberately no error for "not running": the
/// UI polls this while the proxy is up and simply draws no icon when it gets nothing back.
#[tauri::command]
pub(crate) async fn get_endpoint_links(
    use_service: Option<bool>,
) -> Result<Vec<EndpointLink>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(links) = ask_service(
        use_service,
        "get endpoint links",
        IpcClient::get_endpoint_links(),
    )
    .await
    {
        return Ok(links);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.endpoint_links().await,
        None => Vec::new(),
    })
}

/// Whether each configured node answered its last probe, and how long it has been down.
///
/// Empty when the proxy is not running — there is nothing probing. Like the links, this is a
/// poll with no error for "not running": the UI draws no badge when it gets nothing back.
#[tauri::command]
pub(crate) async fn get_node_health(
    use_service: Option<bool>,
) -> Result<Vec<NodeHealthStatus>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(health) =
        ask_service(use_service, "get node health", IpcClient::get_node_health()).await
    {
        return Ok(health);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.node_health().await,
        None => Vec::new(),
    })
}

/// What each configured node has carried since the counters started, and how many flows are open
/// to it.
///
/// Cumulative bytes, not a rate: a rate is two readings and a division, and the UI already polls
/// this on its own interval. Empty when the proxy is not running, and keyed by `connection` like
/// the links and the health, so the UI can put all three on one row.
#[tauri::command]
pub(crate) async fn get_node_traffic(
    use_service: Option<bool>,
) -> Result<Vec<NodeTrafficStatus>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(traffic) = ask_service(
        use_service,
        "get node traffic",
        IpcClient::get_node_traffic(),
    )
    .await
    {
        return Ok(traffic);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.node_traffic().await,
        None => Vec::new(),
    })
}

/// The connections the proxy has open right now, one row each.
///
/// The per-node counters say how much each backend has carried; this says which connections
/// those are, so a reader can see what is actually open and end one of them. Empty when the
/// proxy is not running, like the polls above — no tunnel, no flows.
///
/// Capped at [`FLOW_PAGE_LIMIT`] rows, with `total` reported alongside so a UI can say how busy
/// the tunnel really is without trying to draw thousands of rows.
#[tauri::command]
pub(crate) async fn get_active_flows(
    use_service: Option<bool>,
) -> Result<ActiveFlowPage, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(page) = ask_service(
        use_service,
        "list active flows",
        IpcClient::get_active_flows(),
    )
    .await
    {
        return Ok(page);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.active_flows(FLOW_PAGE_LIMIT).await,
        None => ActiveFlowPage::empty(),
    })
}

/// Asks one open flow to end.
///
/// `false` when there is no flow open with that id, which covers both "there never was one" and
/// "it ended while the list was being read" — a page polling every few seconds will sometimes be
/// clicked on a row that has already gone, and that is not an error.
///
/// The flow is not *gone* when this returns: it wakes the copy loop holding its sockets, and
/// that loop is what lets go of them. The next poll is where the UI sees it disappear.
#[tauri::command]
pub(crate) async fn close_flow(id: u64, use_service: Option<bool>) -> Result<bool, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(closed) = ask_service(use_service, "close a flow", IpcClient::close_flow(id)).await
    {
        return Ok(closed);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.close_flow(id),
        None => false,
    })
}

/// Asks every flow reaching one configured node to end.
///
/// `connection` is the ticket or endpoint ID exactly as the node was configured — the same key
/// the links, the health and the traffic are keyed by — and `None` comes back when it names a
/// node this configuration cannot resolve to. That is deliberately not `Some(0)`: one of those
/// is a request about a node that is not configured, the other is a configured node that had
/// nothing open.
#[tauri::command]
pub(crate) async fn close_node_flows(
    connection: String,
    use_service: Option<bool>,
) -> Result<Option<usize>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(closed) = ask_service(
        use_service,
        "close a node's flows",
        IpcClient::close_node_flows(&connection),
    )
    .await
    {
        return Ok(closed);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.close_node_flows(&connection).await,
        None => None,
    })
}

/// Runs [`cleanup_stale_hijack`] once per process, off the async runtime, and resolves when it
/// has finished.
///
/// Two callers, opposite needs: [`setup`] starts it and walks away so the first paint is not
/// held up, and [`start_proxy`] waits for it so a tunnel cannot come up underneath it. Both
/// reach the same cleanup through [`STALE_HIJACK_CLEANUP`], so whichever gets there first does
/// the work and the other one waits for the result rather than starting a second run.
pub(crate) async fn stale_hijack_cleanup() {
    let _ = STALE_HIJACK_CLEANUP
        .get_or_init(|| async {
            let _ =
                tokio::task::spawn_blocking(crate::proxy::dns_config::cleanup_stale_hijack).await;
        })
        .await;
}

/// The stale-hijack cleanup, once per process: whoever needs it first runs it, everyone else
/// waits for that run.
///
/// Spawned rather than run inline because on Windows it costs 1.4-1.7 seconds: it shells out
/// to PowerShell, and `Get-NetUDPEndpoint` / `Get-DnsClientServerAddress` each load the
/// `NetTCPIP` module first. Run from `setup()` that is time the window sits there empty — the
/// window is created *before* the setup closure runs, so the user stares at a blank frame for
/// the whole of it.
///
/// Waiting for it in [`start_proxy`] is not optional. The Windows cleanup resets every adapter
/// whose DNS still points at a TUN address, and the guard that spares a live tunnel
/// (`address_is_held`) is only compiled on macOS and Linux — so a cleanup still running when a
/// start begins would reset the DNS of the tunnel that start is bringing up.
///
/// A [`tokio::sync::OnceCell`], not a `OnceLock` plus a second cell standing in for "finished".
/// `OnceLock::get_or_init` is the wrong shape for this: the closure runs in whichever caller
/// finds the cell empty, so a caller arriving while the cleanup is mid-flight would initialise
/// the cell itself and return at once — the wait would be a no-op in exactly the case it
/// exists for. This cell's `get_or_init` instead hands the work to the one caller that wins the
/// permit and parks the others until it is done, and the cleanup goes to a blocking thread
/// because it is 1.4 seconds of synchronous process output that must not sit on a runtime
/// worker.
static STALE_HIJACK_CLEANUP: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

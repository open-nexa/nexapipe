pub mod error;
mod proxy;
pub mod service;
pub mod status;

use error::{codes, AppError};
use proxy::{
    ConnectionConfig, ProxyLoadBalancingStrategy, ProxyManager, ProxyManagerConfig, ProxyNodeConfig,
    StartError,
};
use service::ipc::NodeInput;
use service::platform::ServiceState;
use service::IpcClient;
use status::{EndpointLink, ProxyStatus};
use std::sync::Arc;
use tokio::sync::RwLock;

lazy_static::lazy_static! {
    static ref PROXY_MANAGER: Arc<RwLock<Option<Arc<ProxyManager>>>> = Arc::new(RwLock::new(None));
    static ref STARTUP_ERROR: Arc<RwLock<Option<AppError>>> = Arc::new(RwLock::new(None));
}

/// Log directory: %APPDATA%/nexa/logs on Windows, the temp directory elsewhere
pub fn log_dir() -> std::path::PathBuf {
    std::env::var("APPDATA")
        .map(|d| std::path::Path::new(&d).join("nexa").join("logs"))
        .unwrap_or_else(|_| std::env::temp_dir().join("nexa"))
}

/// Initializes logging: info level by default (override with RUST_LOG), writing both to the
/// console and to a log file (%APPDATA%/nexa/logs/{prefix}.log.YYYY-MM-DD).
/// The returned guard must be kept alive for the log flushing thread to keep running.
pub fn init_tracing(prefix: &str) -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let file_appender = tracing_appender::rolling::daily(&dir, prefix);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_writer)
                .with_ansi(false),
        )
        .with(filter)
        .init();
    guard
}

/// Starts the proxy, in service mode when asked and in process mode otherwise.
///
/// The forwarding mode is explicit: `use_tun` requests TUN and fails with
/// `proxy.tun_unavailable` when the process cannot create the tunnel, everything else runs the
/// local proxy. Nothing is probed and nothing is downgraded silently — the UI gates TUN on the
/// service being installed, so a request that cannot be honoured must say so.
///
/// Returns nothing on success: the success text this used to return was English prose that the
/// frontend discarded, so the UI now renders its own localized confirmation. Failures come back
/// as an [`AppError`] whose code the frontend translates and whose detail it can log.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn start_proxy(
    nodes: Vec<NodeInput>,
    domains: Vec<String>,
    local_addr: Option<String>,
    dns_addr: Option<String>,
    upstream_dns: Option<String>,
    load_balancing: Option<String>,
    tun_name: Option<String>,
    use_service: Option<bool>,
    use_tun: Option<bool>,
    relay_mode: Option<String>,
    relay_url: Option<String>,
    force_relay: Option<bool>,
    two_factor_enabled: Option<bool>,
    two_factor_client_id: Option<String>,
    two_factor_secret: Option<String>,
    two_factor_algorithm: Option<String>,
) -> Result<(), AppError> {
    let use_service = use_service.unwrap_or(false);
    let use_tun = use_tun.unwrap_or(false);

    // Checked here, before anything is spawned, so the caller gets the precise code instead of a
    // generic async start failure: a manager that cannot obtain privileges must not be created
    // in TUN mode at all.
    if use_tun && !proxy::tun_proxy::TunProxy::is_available().await {
        return Err(AppError::new(codes::PROXY_TUN_UNAVAILABLE));
    }

    if use_service {
        match IpcClient::start_proxy(
            nodes.clone(),
            domains.clone(),
            local_addr.clone(),
            dns_addr.clone(),
            upstream_dns.clone(),
            load_balancing.clone(),
            tun_name.clone(),
            use_tun,
            relay_mode.clone(),
            relay_url.clone(),
            force_relay,
            two_factor_enabled,
            two_factor_client_id.clone(),
            two_factor_secret.clone(),
            two_factor_algorithm.clone(),
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                // With TUN requested, a service failure is reported instead of falling back:
                // the fallback would start a local proxy while the user asked for a tunnel.
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
            }
        })
        .collect();

    if parsed_nodes.is_empty() {
        return Err(AppError::new(codes::PROXY_NO_NODES));
    }

    let load_balancing = load_balancing.unwrap_or_else(|| "round_robin".to_string());
    let load_balancing: ProxyLoadBalancingStrategy = load_balancing
        .parse()
        .map_err(|e: String| AppError::cause(codes::PROXY_INVALID_LOAD_BALANCING, e))?;

    let local_addr = local_addr.unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let dns_addr = dns_addr.unwrap_or_else(|| "10.0.0.254:53".to_string());
    let upstream_dns = upstream_dns.unwrap_or_else(|| "8.8.8.8:53".to_string());

    let tun_name = tun_name.unwrap_or_else(|| "nexa-tun".to_string());

    let config = ProxyManagerConfig {
        nodes: parsed_nodes,
        local_proxy_addr: local_addr,
        dns_listen_addr: dns_addr,
        upstream_dns,
        load_balancing,
        tun_name,
        use_tun,
        relay_mode: relay_mode.unwrap_or_else(|| "pinned".to_string()),
        relay_url: relay_url.unwrap_or_default(),
        force_relay: force_relay.unwrap_or(false),
        two_factor_enabled: two_factor_enabled.unwrap_or(false),
        two_factor_client_id: two_factor_client_id.unwrap_or_default(),
        two_factor_secret: two_factor_secret.unwrap_or_default(),
        two_factor_algorithm: two_factor_algorithm.unwrap_or_else(|| "sha1".to_string()),
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
async fn stop_proxy(use_service: Option<bool>) -> Result<(), AppError> {
    let use_service = use_service.unwrap_or(false);

    if use_service {
        match IpcClient::stop_proxy().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(
                    "Failed to stop proxy via service, trying process mode: {}",
                    e
                );
            }
        }
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
async fn get_proxy_status(use_service: Option<bool>) -> Result<ProxyStatus, AppError> {
    let use_service = use_service.unwrap_or(false);

    if use_service {
        match IpcClient::get_status().await {
            Ok(status) => return Ok(status),
            Err(e) => {
                tracing::warn!(
                    "Failed to get status via service, falling back to process mode: {}",
                    e
                );
            }
        }
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        // A manager with no mode yet is starting up, not running: see `ProxyStatus::starting`.
        Some(manager) => match manager.get_mode() {
            Some(mode) => ProxyStatus::running_with(mode),
            None => ProxyStatus::starting(),
        },
        None => ProxyStatus::stopped(),
    })
}

#[tauri::command]
async fn get_node_id(use_service: Option<bool>) -> Result<String, AppError> {
    let use_service = use_service.unwrap_or(false);

    if use_service {
        match IpcClient::get_node_id().await {
            Ok(id) => return Ok(id),
            Err(e) => {
                tracing::warn!(
                    "Failed to get node ID via service, falling back to process mode: {}",
                    e
                );
            }
        }
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
async fn get_endpoint_links(use_service: Option<bool>) -> Result<Vec<EndpointLink>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if use_service {
        match IpcClient::get_endpoint_links().await {
            Ok(links) => return Ok(links),
            Err(e) => {
                tracing::warn!(
                    "Failed to get endpoint links via service, falling back to process mode: {}",
                    e
                );
            }
        }
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.endpoint_links().await,
        None => Vec::new(),
    })
}

/// Registers the system service, asking for administrator rights.
///
/// Deliberately *not* routed through the IPC channel: the service is by definition not running
/// before it is installed, so an IPC request could only ever fail with `service.unavailable` and
/// the user would never see the UAC / sudo prompt. Running it here lets
/// [`service::platform::install_service`] re-launch this binary elevated when needed.
#[tauri::command]
async fn install_service() -> Result<(), AppError> {
    run_elevated("install", service::platform::install_service).await
}

/// Removes the system service, asking for administrator rights — see [`install_service`] for why
/// this does not go through the IPC channel.
#[tauri::command]
async fn uninstall_service() -> Result<(), AppError> {
    run_elevated("uninstall", service::platform::uninstall_service).await
}

/// Runs a service-management operation that may have to wait for an elevation prompt.
///
/// The wait is not bounded by this process: a sudo password typed in a terminal gets a two-minute
/// budget inside [`service::elevate`], so the work is moved off the async runtime's thread
/// instead of blocking every other command while the user decides.
async fn run_elevated(verb: &str, operation: fn() -> Result<(), AppError>) -> Result<(), AppError> {
    let outcome = tauri::async_runtime::spawn_blocking(operation)
        .await
        .unwrap_or_else(|e| Err(AppError::cause(codes::SERVICE_FAILED, e)));

    if let Err(e) = &outcome {
        tracing::error!("service {} failed: {}", verb, e);
    }

    outcome
}

/// Whether the service is registered, stopped or running — as the service manager sees it.
///
/// Infallible: an unreadable service manager means "we cannot tell", which the UI renders like an
/// uninstalled service rather than failing the whole panel.
#[tauri::command]
async fn get_service_status() -> ServiceState {
    tauri::async_runtime::spawn_blocking(service::platform::service_state)
        .await
        .unwrap_or(ServiceState::NotInstalled)
}

/// Starts the service, asking for administrator rights when the unprivileged call is refused.
#[tauri::command]
async fn start_service() -> Result<(), AppError> {
    run_elevated("start", service::platform::start_service).await
}

/// Stops the service, asking for administrator rights when the unprivileged call is refused.
#[tauri::command]
async fn stop_service() -> Result<(), AppError> {
    run_elevated("stop", service::platform::stop_service).await
}

/// Whether a service is answering on the IPC port.
///
/// Infallible on purpose: an unreachable service is reported as "not running", which is what the
/// status indicator needs to know. The reason is logged by the IPC client on the way out.
#[tauri::command]
async fn is_service_running() -> bool {
    IpcClient::is_service_running().await
}

/// The failure `start_proxy` recorded after it had already returned, if any.
///
/// Infallible: "there is no recorded failure" and "the failure could not be read" are the same
/// answer to the caller. That is also why this deliberately does *not* clear the value — the
/// frontend polls it, and clearing it would make the message flash for one poll interval.
#[tauri::command]
async fn get_startup_error() -> Option<AppError> {
    STARTUP_ERROR.read().await.clone()
}

/// Reads the tail of the log file (the last 200 lines by default) for the frontend log page.
///
/// The lines themselves are raw log output and stay untranslated; only failures to read them are
/// reported as codes.
#[tauri::command]
async fn get_logs(limit: Option<usize>) -> Result<Vec<String>, AppError> {
    use std::io::{Read, Seek};

    let limit = limit.unwrap_or(200);
    let dir = log_dir();

    // Pick the most recently modified nexa.log file (daily rolling: nexa.log.YYYY-MM-DD)
    let newest = std::fs::read_dir(&dir)
        .map_err(|e| AppError::cause(codes::LOGS_DIR_UNREADABLE, e))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("nexa.log"))
                    .unwrap_or(false)
        })
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());

    let Some(path) = newest else {
        return Ok(vec![]);
    };

    // Only read the tail so that large files are not loaded in full
    let mut file =
        std::fs::File::open(&path).map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    const MAX_TAIL: u64 = 512 * 1024; // Read at most the trailing 512KB
    let offset = file_len.saturating_sub(MAX_TAIL);
    let mut content = String::new();
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
    }
    file.read_to_string(&mut content)
        .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;

    let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let start = lines.len().saturating_sub(limit);
    Ok(lines[start..].to_vec())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _guard = init_tracing("nexa.log");

    // Increase tokio worker thread stack size to 4 MB (default 2 MB) to
    // prevent stack overflow from deeply nested async state machines in
    // iroh / proxy code.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(4 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let handle = runtime.handle().clone();
    // Prevent the runtime from being dropped — it must live as long as the
    // process. Tauri holds the Handle and uses it for all async commands.
    std::mem::forget(runtime);
    tauri::async_runtime::set(handle);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            get_proxy_status,
            get_node_id,
            get_endpoint_links,
            install_service,
            uninstall_service,
            start_service,
            stop_service,
            get_service_status,
            is_service_running,
            get_startup_error,
            get_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

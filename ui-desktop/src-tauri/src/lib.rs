pub mod error;
mod proxy;
pub mod service;
pub mod status;

use error::{codes, AppError};
use nexapipe_client::provisioning::{EndpointInvite, EndpointTarget};
use proxy::{
    ConnectionConfig, ProxyLoadBalancingStrategy, ProxyManager, ProxyManagerConfig, ProxyNodeConfig,
    StartError,
};
use service::ipc::{IssuedCredentialPayload, NodeInput, StartProxyRequest};
use service::platform::ServiceState;
use service::IpcClient;
use status::{EndpointLink, ProxyStatus};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

lazy_static::lazy_static! {
    static ref PROXY_MANAGER: Arc<RwLock<Option<Arc<ProxyManager>>>> = Arc::new(RwLock::new(None));
    static ref STARTUP_ERROR: Arc<RwLock<Option<AppError>>> = Arc::new(RwLock::new(None));
    static ref LOG_CURSOR: Arc<RwLock<Option<LogCursor>>> = Arc::new(RwLock::new(None));
}

/// How far the log page has read into the newest log file.
///
/// `get_logs` in incremental mode returns only the bytes after this offset, which is what makes
/// "clear" stick: the lines before the offset are never offered to the frontend again, even
/// though the file itself keeps growing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LogCursor {
    path: std::path::PathBuf,
    offset: u64,
}

/// Log directory for the desktop process: `%APPDATA%\nexa\logs` on Windows and the user's
/// XDG state directory on Unix.
///
/// This is deliberately per-user and never shared with [`service_log_dir`]. A root service must
/// not create the directory first and leave the desktop user unable to write its own log there.
pub fn log_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var("APPDATA")
            .map(|d| std::path::Path::new(&d).join("nexa").join("logs"))
            .unwrap_or_else(|_| std::env::temp_dir().join("nexa").join("logs"))
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| std::path::PathBuf::from(home).join(".local").join("state"))
            })
            .unwrap_or_else(std::env::temp_dir);
        base.join("nexa").join("logs")
    }
}

/// Where the *service* writes its log.
///
/// Not [`log_dir()`]: the service runs as LocalSystem on Windows and root on Unix, while the
/// desktop process runs as the logged-in user. Keeping the two apart means a service startup
/// failure can always write its diagnostic without taking ownership of the user's log directory.
pub fn service_log_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var("PROGRAMDATA")
            .map(|d| std::path::Path::new(&d).join("nexa").join("logs"))
            .unwrap_or_else(|_| log_dir())
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/var/log/nexa-service")
    }
}

/// [`init_tracing`] pointed at a directory of the caller's choosing; see [`service_log_dir`].
///
/// Logging is allowed to degrade to stdout when the directory or file cannot be created. A
/// missing log file must never prevent either binary from starting.
pub fn init_tracing_in(dir: std::path::PathBuf, prefix: &str) -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let file_appender = match std::fs::create_dir_all(&dir) {
        Ok(()) => tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(prefix)
            .build(&dir)
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    let (file_writer, guard) = match file_appender {
        Ok(appender) => tracing_appender::non_blocking(appender),
        Err(error) => {
            eprintln!(
                "failed to initialize log file in {}: {}; continuing with stdout logging",
                dir.display(),
                error
            );
            // The stdout layer below remains active, so this writer is only a harmless sink for
            // the file layer and keeps the returned guard type uniform.
            tracing_appender::non_blocking(std::io::sink())
        }
    };

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

/// Initializes logging: info level by default (override with RUST_LOG), writing both to the
/// console and to a daily rolling file below [`log_dir()`].
/// The returned guard must be kept alive for the log flushing thread to keep running.
pub fn init_tracing(prefix: &str) -> tracing_appender::non_blocking::WorkerGuard {
    init_tracing_in(log_dir(), prefix)
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
    relay_auth_token: Option<String>,
) -> Result<(), AppError> {
    let use_service = use_service.unwrap_or(false);
    let use_tun = use_tun.unwrap_or(false);

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

    if use_service {
        match IpcClient::start_proxy(StartProxyRequest {
            nodes: nodes.clone(),
            domains: domains.clone(),
            local_addr: local_addr.clone(),
            dns_addr: dns_addr.clone(),
            upstream_dns: upstream_dns.clone(),
            load_balancing: load_balancing.clone(),
            tun_name: tun_name.clone(),
            use_tun: Some(use_tun),
            relay_mode: relay_mode.clone(),
            relay_url: relay_url.clone(),
            relay_auth_token: relay_auth_token.clone(),
        })
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
    let dns_addr = dns_addr.unwrap_or_else(|| "198.18.0.254:53".to_string());
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
        relay_auth_token: relay_auth_token.unwrap_or_default(),
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

/// A `nexapipe://` invitation read into the shape the UI needs to fill in a node.
///
/// The grammar lives in `nexapipe-client` (module `provisioning`), the same parser the server that
/// prints the code and the Android client that scans it both read; the desktop asks it instead of
/// growing a third implementation that would drift. Only what the UI has to *show* before the
/// user commits is carried across, and nothing is applied here: an invite is described, then the
/// frontend decides.
///
/// The fields cross into TypeScript, where `InvitePayload` in `src/types/index.ts` spells them
/// camelCase. Nothing in Tauri rewrites the keys of a command result — every struct has to ask
/// for the conversion itself — so without this rename the frontend reads `undefined` for every
/// multi-word field while the single-word ones arrive intact, which is how a parsed invite lost
/// its client id and kept its secret.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePayload {
    /// `endpoint` for a bare Node ID, `ticket` for an address-bearing ticket.
    pub kind: String,
    /// The Node ID, or the ticket, verbatim.
    pub target: String,
    /// Cosmetic label from the invite. Nothing routes on it.
    pub name: Option<String>,
    pub domains: Vec<String>,
    pub relay: Option<String>,
    pub totp: Option<InviteTotpPayload>,
    /// A one-time enrollment token, which is what a `v=2` invite carries instead of a
    /// secret. Mutually exclusive with `totp` — the parser refuses a code that carries
    /// both — so the UI can branch on this without deciding a precedence of its own.
    pub enrollment: Option<InviteEnrollmentPayload>,
}

/// The enrollment half of an invite: a token to spend, not a secret to keep.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteEnrollmentPayload {
    /// Which `[auth.clients]` entry the token is pending for.
    pub client_id: String,
    pub token: String,
}

/// The 2FA half of an invite, in the form the config store keeps it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteTotpPayload {
    pub client_id: String,
    pub secret: String,
    /// Lowercase algorithm name, which is what `twoFactorAlgorithm` holds.
    pub algorithm: String,
    pub issuer: String,
}

/// Reads a `nexapipe://` invite pasted into the UI.
///
/// Pure parsing: no proxy is touched and no config is written, so the UI can show what a code
/// carries before the user accepts it. A rejected code comes back as `invite.parse_failed` with
/// the parser's reason as `detail` — the reason names the offending part ("unsupported version",
/// "unknown host"), which is worth more than a generic failure but is still an English diagnostic.
///
/// Not `async`: it is a string parse with no I/O, and a synchronous command keeps it off the
/// async runtime entirely.
#[tauri::command]
fn parse_invite(uri: String) -> Result<InvitePayload, AppError> {
    let invite = EndpointInvite::from_uri(&uri)
        .map_err(|e| AppError::cause(codes::INVITE_PARSE_FAILED, e))?;

    let (kind, target) = match &invite.target {
        EndpointTarget::NodeId(id) => ("endpoint".to_string(), id.clone()),
        EndpointTarget::Ticket(ticket) => ("ticket".to_string(), ticket.clone()),
    };

    Ok(InvitePayload {
        kind,
        target,
        name: invite.name.clone(),
        domains: invite.domains.clone(),
        relay: invite.relay.clone(),
        totp: invite.totp.as_ref().map(|totp| InviteTotpPayload {
            client_id: totp.client_id.clone(),
            secret: totp.secret.clone(),
            algorithm: totp.algorithm.name().to_string(),
            issuer: totp.issuer.clone(),
        }),
        enrollment: invite
            .enrollment
            .as_ref()
            .map(|enrollment| InviteEnrollmentPayload {
                client_id: enrollment.client_id.clone(),
                token: enrollment.token.clone(),
            }),
    })
}

/// Hands back the credential a server issued for an enrollment token, and clears it.
///
/// `None` when nothing enrolled on this run — no node carried a token, or the credential
/// has already been taken. A token is spent by the first connection that uses it, so the
/// caller gets exactly one chance to read this; the frontend stores it as that node's 2FA
/// credentials, because without it a restart has nothing left to authenticate with.
#[tauri::command]
async fn take_issued_credential(
    use_service: Option<bool>,
) -> Result<Option<IssuedCredentialPayload>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if use_service {
        match IpcClient::take_issued_credential().await {
            Ok(credential) => return Ok(credential),
            Err(e) => {
                tracing::warn!(
                    "Failed to read the enrolled credential via service, falling back to process mode: {}",
                    e
                );
            }
        }
    }

    // Cloned out of the lock first: the guard must not be held across the await below.
    let manager = PROXY_MANAGER.read().await.as_ref().cloned();
    Ok(match manager {
        Some(manager) => manager
            .take_issued_credential()
            .await
            .map(|credential| IssuedCredentialPayload {
                client_id: credential.client_id,
                secret: credential.secret,
                algorithm: credential.algorithm,
            }),
        None => None,
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
    if let Some(error) = STARTUP_ERROR.read().await.clone() {
        return Some(error);
    }

    // A service-mode start fails in the other process, where this one cannot see it — and its
    // log is written under LocalSystem's profile, which nobody can read. So ask: the service
    // records the same failure with the same code, and an unreachable service or an older build
    // that does not know the question is simply "no failure on file".
    match IpcClient::get_startup_error().await {
        Ok(Some(error)) => Some(error),
        Ok(None) | Err(_) => None,
    }
}

/// The result of `get_logs`.
///
/// `fresh` marks a full tail read (the first poll, a day roll-over, or anything else that
/// invalidates the incremental cursor); the frontend must *replace* its view with `lines`.
/// `fresh: false` lines are an append-only continuation of what was delivered before.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogPage {
    lines: Vec<String>,
    fresh: bool,
}

/// Picks the most recently modified `nexa.log` file in `dir` (daily rolling: `nexa.log.YYYY-MM-DD`).
fn newest_log_file(dir: &std::path::Path) -> Result<Option<std::path::PathBuf>, AppError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(AppError::cause(codes::LOGS_DIR_UNREADABLE, error)),
    };

    Ok(entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("nexa.log"))
                    .unwrap_or(false)
        })
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok()))
}

/// Splits `content` into the lines that are guaranteed complete.
///
/// A log file is read while the writer is still appending, so the tail may end mid-line; a
/// fragment without a trailing newline is held back and the returned byte length tells the
/// caller where the complete portion ends, so the next poll re-reads it instead of losing it.
/// Returns `(lines, consumed_bytes)`.
fn complete_lines(content: &str) -> (Vec<&str>, usize) {
    match content.rfind('\n') {
        Some(pos) => (content[..pos].lines().collect(), pos + 1),
        None => (Vec::new(), 0),
    }
}

/// Reads the log file for the frontend log page.
///
/// Pass `append: true` to get only the lines written since the previous call (incremental);
/// the default is a fresh tail read. Incremental reads are what keep the page in sync with a
/// file that outgrew the tail window — a file with more than `limit` lines never changes the
/// *length* of the tail, so counting lines to detect new ones never fires. They are also what
/// makes `clear_logs` stick.
///
/// The lines themselves are raw log output and stay untranslated; only failures to read them are
/// reported as codes.
#[tauri::command]
async fn get_logs(limit: Option<usize>, append: Option<bool>) -> Result<LogPage, AppError> {
    use std::io::{Read, Seek};

    let limit = limit.unwrap_or(200);
    let append = append.unwrap_or(false);
    let dir = log_dir();

    let Some(path) = newest_log_file(&dir)? else {
        *LOG_CURSOR.write().await = None;
        return Ok(LogPage {
            lines: vec![],
            fresh: true,
        });
    };

    let mut file =
        std::fs::File::open(&path).map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut cursor = LOG_CURSOR.write().await;
    let incremental = append
        && cursor
            .as_ref()
            .is_some_and(|c| c.path == path && c.offset <= file_len);

    let (lines, fresh) = if incremental {
        // Continue exactly where the previous read stopped.
        let offset = cursor.as_ref().expect("checked above").offset;
        file.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        // A partially written last line stays in the file for the next poll.
        let (lines, consumed) = complete_lines(&content);
        *cursor = Some(LogCursor {
            path,
            offset: offset + consumed as u64,
        });
        (lines.into_iter().map(String::from).collect::<Vec<_>>(), false)
    } else {
        // Only read the tail so that large files are not loaded in full. When the window starts
        // mid-line, drop the partial first line instead of showing it as garbled output.
        const MAX_TAIL: u64 = 512 * 1024;
        let tail_offset = file_len.saturating_sub(MAX_TAIL);
        if tail_offset > 0 {
            file.seek(std::io::SeekFrom::Start(tail_offset))
                .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        }
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        if tail_offset > 0 {
            if let Some(pos) = content.find('\n') {
                content.drain(..=pos);
            } else {
                content.clear();
            }
        }
        let all: Vec<&str> = content.lines().collect();
        let start = all.len().saturating_sub(limit);
        let lines = all[start..].iter().map(|l| l.to_string()).collect();
        *cursor = Some(LogCursor {
            path,
            offset: file_len,
        });
        (lines, true)
    };

    Ok(LogPage { lines, fresh })
}

/// Marks every line currently in the newest log file as already seen.
///
/// The frontend clears its view and calls this; the next incremental poll returns only lines
/// written *after* the clear, so old entries never reappear. The file itself is deliberately not
/// truncated: the rolling writer in whichever process owns it (often the service) keeps its
/// handle open, and cutting a file out from under an appender corrupts the stream.
#[tauri::command]
async fn clear_logs() -> Result<(), AppError> {
    let newest = newest_log_file(&log_dir())?;
    *LOG_CURSOR.write().await = newest.and_then(|path| {
        std::fs::File::open(&path)
            .ok()
            .and_then(|f| f.metadata().ok())
            .map(|m| LogCursor {
                path,
                offset: m.len(),
            })
    });
    Ok(())
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
            parse_invite,
            take_issued_credential,
            install_service,
            uninstall_service,
            start_service,
            stop_service,
            get_service_status,
            is_service_running,
            get_startup_error,
            get_logs,
            clear_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexapipe_client::provisioning::{InviteEnrollment, InviteTotp};

    /// A Node ID nobody is listening on, derived from a fixed seed so the expected strings in
    /// these tests stay stable — parsing checks that the point is valid, not just that it is
    /// 64 hex characters.
    fn node_id() -> String {
        iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string()
    }

    fn endpoint_invite() -> EndpointInvite {
        EndpointInvite::new(
            EndpointTarget::NodeId(node_id()),
            &["a.example".to_string(), "b.example".to_string()],
        )
        .expect("the sample invite is well formed")
    }

    #[test]
    fn reads_a_node_id_invite() {
        let payload = parse_invite(endpoint_invite().with_name("Home").to_uri()).unwrap();

        assert_eq!(payload.kind, "endpoint");
        assert_eq!(payload.target, node_id());
        assert_eq!(payload.name.as_deref(), Some("Home"));
        assert_eq!(payload.domains, vec!["a.example", "b.example"]);
        assert_eq!(payload.relay, None);
        assert!(payload.totp.is_none());
    }

    #[test]
    fn reads_a_ticket_invite() {
        let target = EndpointTarget::Ticket(
            iroh_tickets::endpoint::EndpointTicket::new(
                node_id()
                    .parse::<iroh::EndpointId>()
                    .expect("the sample node ID is well formed")
                    .into(),
            )
            .to_string(),
        );
        let invite =
            EndpointInvite::new(target.clone(), &[]).expect("the sample invite is well formed");

        let payload = parse_invite(invite.to_uri()).unwrap();
        assert_eq!(payload.kind, "ticket");
        assert_eq!(payload.target, target.to_string());
        assert!(payload.domains.is_empty());
    }

    #[test]
    fn reads_the_2fa_half() {
        let invite = endpoint_invite().with_totp(Some(
            InviteTotp::new("client-001", "jbswy3dpehpk3pxp").expect("the secret is valid base32"),
        ));

        let payload = parse_invite(invite.to_uri()).unwrap();
        let totp = payload.totp.expect("the invite carries 2FA");
        assert_eq!(totp.client_id, "client-001");
        assert_eq!(totp.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.algorithm, "sha1");
    }

    /// The frontend reads `invite.totp.clientId`, and only the multi-word key was ever at risk:
    /// `secret` and `algorithm` have no casing to disagree about, so a missing rename did not fail
    /// a parse — it produced a node with a secret and no client id, which every server then
    /// refuses. Pin the keys the UI actually sees.
    #[test]
    fn hands_the_2fa_half_to_the_frontend_in_camel_case() {
        let invite = endpoint_invite().with_totp(Some(
            InviteTotp::new("client-001", "jbswy3dpehpk3pxp").expect("the secret is valid base32"),
        ));

        let payload = parse_invite(invite.to_uri()).unwrap();
        let json: serde_json::Value = serde_json::to_value(&payload).unwrap();
        let totp = json["totp"].as_object().expect("the 2FA block travels whole");
        assert_eq!(totp["clientId"], "client-001");
        assert!(totp.get("client_id").is_none(), "keys must reach the UI as camelCase");
    }

    /// A registration invite carries a token instead of a secret, and the UI has to be able
    /// to tell the two apart without guessing: it enrolls for one and stores credentials for
    /// the other.
    #[test]
    fn hands_a_registration_token_to_the_frontend_instead_of_a_secret() {
        let invite = endpoint_invite()
            .with_enrollment(Some(InviteEnrollment::new("client-001", "tok").unwrap()));

        let payload = parse_invite(invite.to_uri()).unwrap();
        let enrollment = payload
            .enrollment
            .clone()
            .expect("the invite carries a token");
        assert_eq!(enrollment.client_id, "client-001");
        assert_eq!(enrollment.token, "tok");
        assert!(payload.totp.is_none(), "a code cannot carry both");

        let json: serde_json::Value = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["enrollment"]["clientId"], "client-001");
    }

    #[test]
    fn reports_a_code_and_a_reason_when_the_link_is_not_an_invite() {
        let error = parse_invite("https://example.com".to_string()).unwrap_err();

        assert_eq!(error.code, codes::INVITE_PARSE_FAILED);
        assert!(error.detail.is_some(), "the parser's reason travels as detail");
    }

    #[test]
    fn complete_lines_hold_back_a_trailing_fragment() {
        let (lines, consumed) = complete_lines("one\ntwo\nthree");

        assert_eq!(lines, vec!["one", "two"]);
        assert_eq!(consumed, 8, "only the bytes up to and including the last newline");
    }

    #[test]
    fn complete_lines_accept_a_fully_terminated_buffer() {
        let (lines, consumed) = complete_lines("one\ntwo\n");

        assert_eq!(lines, vec!["one", "two"]);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn complete_lines_return_nothing_without_a_newline() {
        let (lines, consumed) = complete_lines("half a line");

        assert!(lines.is_empty());
        assert_eq!(consumed, 0);
    }
}

use crate::error::{codes, AppError};
use crate::proxy::tun_proxy::TUN_BASE_CANDIDATES;
use crate::proxy::{
    ConnectionConfig, ProxyLoadBalancingStrategy, ProxyManager, ProxyManagerConfig, ProxyNodeConfig,
    StartError,
};
use crate::service::ipc::{IpcMessage, IpcResponse, NodeInput, IPC_SOCKET_PATH, MAX_IPC_LINE};
use crate::status::ProxyStatus;
use anyhow::{Context, Result};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// The failure the last start recorded after it had already answered `Ok`.
///
/// Kept beside the manager because the two are set together: a start is dispatched on a spawned
/// task (a TUN run loop only returns when the tunnel goes down, so the service cannot wait for
/// it), and anything that fails there would otherwise be visible only in this process's log —
/// which is written under LocalSystem's profile and nobody can read. The desktop asks for it and
/// shows it, exactly like it does for a process-mode start.
fn startup_error_slot() -> &'static Arc<tokio::sync::RwLock<Option<AppError>>> {
    static SLOT: std::sync::OnceLock<Arc<tokio::sync::RwLock<Option<AppError>>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| Arc::new(tokio::sync::RwLock::new(None)))
}

pub struct ServiceRunner {
    proxy_manager: Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
}

impl Default for ServiceRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRunner {
    pub fn new() -> Self {
        Self {
            proxy_manager: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Service runner starting");

        // A hijack whose process died mid-run (killed, or a machine shutdown that reached
        // the service before its teardown finished) leaves static DNS entries that survive
        // the reboot: the machine comes back with no working name resolution — including
        // for this service itself, whose iroh endpoint cannot even publish to pkarr.
        // Clean that up before anything here needs DNS.
        crate::proxy::dns_config::cleanup_stale_hijack();

        let listener = TcpListener::bind(IPC_SOCKET_PATH)
            .await
            .context("Failed to bind IPC socket")?;

        tracing::info!("IPC server listening on: {}", IPC_SOCKET_PATH);

        // Where this process will look for the token, printed once. A service that refuses every
        // call because it cannot find one is otherwise indistinguishable from a service that is
        // not there at all: the refusal names no path, and the desktop can only report that the
        // connection closed. One line here turns that dead end into a diffable list.
        tracing::info!(
            "IPC token candidates: {:?}",
            crate::service::ipc_token::service_token_paths()
        );

        loop {
            let (mut stream, _) = listener
                .accept()
                .await
                .context("Failed to accept connection")?;
            tracing::debug!("Client connected");

            let proxy_manager = self.proxy_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(&mut stream, proxy_manager).await {
                    tracing::error!("Client handler error: {}", e);
                }
            });
        }
    }

    /// Winds the proxy down because the process itself is exiting.
    ///
    /// Not the same thing as answering [`IpcMessage::StopProxy`]: that leaves the service up and
    /// the caller free to start again, whereas here nothing is served any more, so the instance is
    /// *taken* out — the tunnel has to be torn down (the TUN adapter outlives this process) and no
    /// late status request may be answered with "running".
    pub async fn shutdown(&self) {
        let manager = self.proxy_manager.write().await.take();
        if let Some(manager) = manager {
            tracing::info!("Stopping the proxy before exiting");
            manager.stop().await;
        }
    }

    async fn handle_client(
        stream: &mut tokio::net::TcpStream,
        proxy_manager: Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> Result<()> {
        // Nothing is served before the caller authenticates: this process runs
        // elevated, and a loopback socket says nothing about who dialled it.
        let mut authenticated = false;
        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();

        loop {
            line.clear();
            match Self::read_ipc_line(&mut reader, &mut line).await {
                // Peer gone, nothing left to answer.
                Ok(0) => {
                    tracing::debug!("Client disconnected");
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    if !authenticated {
                        // Refusing to answer is the whole point; dropping the
                        // connection keeps a caller that never authenticates
                        // from holding a task open.
                        tracing::warn!("Dropping an unauthenticated IPC client: {}", e);
                        break;
                    }
                    let response = IpcResponse::Error(AppError::cause(
                        codes::SERVICE_MALFORMED_REQUEST,
                        e,
                    ));
                    Self::write_response(reader.get_mut(), &response).await?;
                    continue;
                }
            }

            let msg: IpcMessage = match serde_json::from_slice(&line) {
                Ok(msg) => msg,
                Err(e) => {
                    if !authenticated {
                        tracing::warn!("Dropping an unauthenticated IPC client: {}", e);
                        break;
                    }
                    let response = IpcResponse::Error(AppError::cause(
                        codes::SERVICE_MALFORMED_REQUEST,
                        e,
                    ));
                    Self::write_response(reader.get_mut(), &response).await?;
                    continue;
                }
            };

            if !authenticated {
                let presented = match &msg {
                    IpcMessage::Auth(token) => token.clone(),
                    other => {
                        // Obeyed nothing, answered once, connection closed.
                        tracing::warn!(
                            "Refusing an IPC client that spoke before authenticating: {:?}",
                            std::mem::discriminant(other)
                        );
                        let response = IpcResponse::Error(AppError::new(codes::SERVICE_UNAUTHORIZED));
                        Self::write_response(reader.get_mut(), &response).await?;
                        break;
                    }
                };

                // Every published token is a candidate: the service cannot tell which account
                // dialled it, so which one happens to be found first says nothing about which
                // one the caller holds.
                let known = crate::service::ipc_token::read_tokens()?;
                if crate::service::ipc_token::token_matches_any(&known, &presented) {
                    authenticated = true;
                    tracing::debug!("IPC client authenticated");
                } else if known.is_empty() {
                    // No token published yet means no desktop session has asked for the
                    // service, so there is nobody to answer.
                    tracing::warn!("Refusing an IPC call with no token on file");
                    let response = IpcResponse::Error(AppError::with_detail(
                        codes::SERVICE_IPC_TOKEN,
                        "no desktop session has published an IPC token",
                    ));
                    Self::write_response(reader.get_mut(), &response).await?;
                    break;
                } else {
                    tracing::warn!("Refusing an IPC client that presented a wrong token");
                    let response = IpcResponse::Error(AppError::new(codes::SERVICE_UNAUTHORIZED));
                    Self::write_response(reader.get_mut(), &response).await?;
                    break;
                }

                Self::write_response(reader.get_mut(), &IpcResponse::Ok).await?;
                continue;
            }

            tracing::debug!("Received IPC message: {:?}", msg);

            let response = match msg {
                IpcMessage::StartProxy(req) => {
                    Self::handle_start_proxy(
                        req.nodes,
                        req.domains,
                        req.local_addr,
                        req.dns_addr,
                        req.upstream_dns,
                        req.load_balancing,
                        req.tun_name,
                        req.use_tun,
                        req.relay_mode,
                        req.relay_url,
                        req.relay_auth_token,
                        &proxy_manager,
                    )
                    .await
                }
                IpcMessage::StopProxy => Self::handle_stop_proxy(&proxy_manager).await,
                IpcMessage::GetStatus => Self::handle_get_status(&proxy_manager).await,
                IpcMessage::GetNodeId => Self::handle_get_node_id(&proxy_manager).await,
                IpcMessage::GetEndpointLinks => {
                    Self::handle_get_endpoint_links(&proxy_manager).await
                }
                IpcMessage::GetStartupError => {
                    IpcResponse::StartupError(startup_error_slot().read().await.clone())
                }
                // Handled above, when the caller introduced itself.
                IpcMessage::Auth(_) => IpcResponse::Ok,
            };

            Self::write_response(reader.get_mut(), &response).await?;
        }

        Ok(())
    }

    /// Reads one newline-terminated IPC line into `buf`, never buffering more
    /// than [`MAX_IPC_LINE`].
    ///
    /// `read_line` cannot be used: it grows its `String` without bound, and the
    /// caller has not authenticated yet at the point it would grow. Returns the
    /// line length excluding the terminator, which is `0` at end of stream.
    async fn read_ipc_line<R>(reader: &mut R, buf: &mut Vec<u8>) -> Result<usize, IpcReadError>
    where
        R: AsyncBufRead + Unpin,
    {
        loop {
            // Owned results only: `consume` below needs the borrow released.
            let (end, complete) = {
                let available = AsyncBufReadExt::fill_buf(reader).await?;
                if available.is_empty() {
                    return Ok(buf.len());
                }
                match available.iter().position(|&b| b == b'\n') {
                    Some(at) => (at + 1, true),
                    None => (available.len(), false),
                }
            };

            // Checked before extending, so an oversized line cannot be buffered
            // even transiently.
            if end > MAX_IPC_LINE.saturating_sub(buf.len()) {
                return Err(IpcReadError::TooLong(buf.len() + end));
            }

            let bytes = AsyncBufReadExt::fill_buf(reader).await?;
            buf.extend_from_slice(&bytes[..end]);
            AsyncBufReadExt::consume(reader, end);

            if complete {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                }
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                return Ok(buf.len());
            }
        }
    }

    async fn write_response(
        stream: &mut tokio::net::TcpStream,
        response: &IpcResponse,
    ) -> Result<()> {
        // The channel is newline-delimited in both directions, so the terminator belongs to the
        // response as much as it does to a request. Without it `IpcClient::exchange` — which
        // reads a line — waits for a byte that never comes: the answer is already in its socket
        // buffer but `read_line` only returns at end of stream, and this connection stays open
        // for the next message. Every service call then hung until the connection died, which
        // the caller saw as `service.io_error` (10053) rather than an answer.
        let response_str =
            serde_json::to_string(response).context("Failed to serialize response")?;
        stream
            .write_all(response_str.as_bytes())
            .await
            .context("Failed to write response")?;
        stream
            .write_all(b"\n")
            .await
            .context("Failed to write response")?;
        stream.flush().await.context("Failed to flush response")?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_start_proxy(
        nodes: Vec<NodeInput>,
        domains: Vec<String>,
        local_addr: Option<String>,
        dns_addr: Option<String>,
        upstream_dns: Option<String>,
        load_balancing: Option<String>,
        tun_name: Option<String>,
        use_tun: Option<bool>,
        relay_mode: Option<String>,
        relay_url: Option<String>,
        relay_auth_token: Option<String>,
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
                }
            })
            .collect();

        if parsed_nodes.is_empty() {
            return IpcResponse::Error(AppError::new(codes::PROXY_NO_NODES));
        }

        let load_balancing = load_balancing.unwrap_or_else(|| "round_robin".to_string());
        let load_balancing: ProxyLoadBalancingStrategy = match load_balancing.parse() {
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

        let tun_name = tun_name.unwrap_or_else(|| "nexa-tun".to_string());

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
            load_balancing,
            tun_name,
            use_tun,
            relay_mode: relay_mode.unwrap_or_else(|| "pinned".to_string()),
            relay_url: relay_url.unwrap_or_default(),
            relay_auth_token: relay_auth_token.unwrap_or_default(),
        };

        let manager = Arc::new(ProxyManager::new(config));

        {
            let mut pm = proxy_manager.write().await;
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
                let mut pm = proxy_manager_clone.write().await;
                *pm = None;
            }
        });

        IpcResponse::Ok
    }

    async fn handle_stop_proxy(
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

    async fn handle_get_status(
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

    async fn handle_get_node_id(
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

    /// How each configured node currently reaches its backend.
    ///
    /// An absent manager answers with an empty list rather than an error: this is polled while
    /// the proxy is up, and "nothing is running" is a state the caller renders by drawing no
    /// icon, not by showing a failure.
    async fn handle_get_endpoint_links(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.read().await;
        let links = match pm.as_ref() {
            Some(manager) => manager.endpoint_links().await,
            None => Vec::new(),
        };
        IpcResponse::EndpointLinks(links)
    }
}

/// Why one line could not be read off the IPC channel.
#[derive(Debug)]
enum IpcReadError {
    /// The peer wrote more than [`MAX_IPC_LINE`] without a newline.
    TooLong(usize),
    /// The socket failed underneath us.
    Io(std::io::Error),
}

impl From<std::io::Error> for IpcReadError {
    fn from(e: std::io::Error) -> Self {
        IpcReadError::Io(e)
    }
}

impl fmt::Display for IpcReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpcReadError::TooLong(len) => write!(
                f,
                "IPC line exceeded the {MAX_IPC_LINE} byte limit after {len} bytes"
            ),
            IpcReadError::Io(e) => write!(f, "IPC read failed: {e}"),
        }
    }
}

/// Refuses `addr` unless it is loopback.
///
/// `code` names what was being validated, because "not loopback" is the same
/// fact with two different fixes depending on which address it was.
fn require_loopback(addr: &str, code: &str) -> Result<(), AppError> {
    let parsed = addr.parse::<SocketAddr>().map_err(|e| {
        AppError::cause(code, format!("{addr:?} is not a host:port address ({e})"))
    })?;
    if parsed.ip().is_loopback() {
        Ok(())
    } else {
        Err(AppError::with_detail(
            code,
            format!(
                "{parsed} is not loopback; the local proxy has nothing authenticating in front of it"
            ),
        ))
    }
}

/// Refuses `addr` unless it is inside one of the candidate TUN blocks the DNS server can
/// answer on.
///
/// The block actually in use is only decided when the TUN interface comes up
/// (`routing::configure_interface` walks [`TUN_BASE_CANDIDATES`]), which is *after* this
/// validation runs — so an address inside any candidate block is accepted, and `retarget`
/// later moves it into the block that took. See `proxy::tun_proxy` for the block policy.
fn require_tun_subnet(addr: &str) -> Result<(), AppError> {
    let parsed = addr.parse::<SocketAddr>().map_err(|e| {
        AppError::cause(
            codes::SERVICE_DNS_ADDR_OUTSIDE_TUN,
            format!("{addr:?} is not a host:port address ({e})"),
        )
    })?;

    // Every candidate is a /24, so the network part is everything but the last octet.
    let in_candidate = |ip: &Ipv4Addr| {
        TUN_BASE_CANDIDATES
            .iter()
            .any(|base| u32::from(*ip) & 0xFFFF_FF00 == u32::from(*base))
    };

    match parsed.ip() {
        IpAddr::V4(ip) if in_candidate(&ip) => Ok(()),
        other => Err(AppError::with_detail(
            codes::SERVICE_DNS_ADDR_OUTSIDE_TUN,
            format!(
                "{other} is outside every candidate TUN block ({TUN_BASE_CANDIDATES:?}), \
                 where the TUN DNS server answers"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{IpcReadError, ServiceRunner, MAX_IPC_LINE, require_loopback, require_tun_subnet};
    use crate::error::codes;

    /// A caller that has not authenticated yet must not be able to make this
    /// buffer grow, which is the whole reason the reader is capped.
    #[tokio::test]
    async fn an_oversized_ipc_line_is_refused_without_buffering_it() {
        let hostile = vec![b'x'; MAX_IPC_LINE + 100];
        let mut buf = Vec::new();

        let err = ServiceRunner::read_ipc_line(&mut hostile.as_slice(), &mut buf)
            .await
            .expect_err("a line over the limit is an error");

        assert!(matches!(err, IpcReadError::TooLong(_)), "{err}");
        assert!(
            buf.len() <= MAX_IPC_LINE,
            "the oversized line must never be buffered"
        );
    }

    /// The reply has to end the line it is written on: `IpcClient::exchange` reads a *line*, so
    /// a response sent without its terminator is one the caller never receives — it sits in the
    /// socket buffer while `read_line` waits for a byte that never comes, until the connection
    /// dies and the call is reported as `service.io_error` instead of an answer.
    #[tokio::test]
    async fn a_response_ends_the_line_the_client_is_reading() {
        use crate::service::ipc::IpcResponse;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral loopback port");
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .expect("the client connects");
        let (mut server, _) = listener.accept().await.expect("the service accepts");

        ServiceRunner::write_response(&mut server, &IpcResponse::Ok)
            .await
            .expect("the response is written");

        let mut line = String::new();
        let read = tokio::io::AsyncBufReadExt::read_line(
            &mut tokio::io::BufReader::new(client),
            &mut line,
        )
        .await
        .expect("the caller reads the reply");

        assert!(read > 0, "the reply must arrive without waiting for a close");
        assert_eq!(line.trim(), "\"Ok\"");
    }

    #[tokio::test]
    async fn one_line_is_returned_without_its_terminator() {
        let mut input: &[u8] = b"{\"GetStatus\":null}\r\n";
        let mut buf = Vec::new();

        let n = ServiceRunner::read_ipc_line(&mut input, &mut buf)
            .await
            .expect("a complete line reads cleanly");

        assert_eq!(n, buf.len());
        assert_eq!(&buf, b"{\"GetStatus\":null}");
    }

    #[tokio::test]
    async fn a_truncated_line_is_handed_back_at_end_of_stream() {
        let mut input: &[u8] = b"{\"GetStatus\":null}";
        let mut buf = Vec::new();

        let n = ServiceRunner::read_ipc_line(&mut input, &mut buf)
            .await
            .expect("end of stream is not an error");

        assert_eq!(n, buf.len());
    }

    #[test]
    fn loopback_is_the_only_allowed_local_proxy_address() {
        assert!(require_loopback("127.0.0.1:8080", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_ok());
        assert!(require_loopback("[::1]:8080", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_ok());
        assert!(require_loopback("0.0.0.0:8080", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_err());
        assert!(require_loopback("10.0.0.5:8080", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_err());
        assert!(require_loopback("not-an-addr", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_err());
    }

    #[test]
    fn the_dns_server_stays_inside_the_tun_network() {
        // The default block (198.18.0.0/24) and the legacy one (10.0.0.0/24) are both
        // candidates — a config saved against the old default keeps working.
        assert!(require_tun_subnet("198.18.0.254:53").is_ok());
        assert!(require_tun_subnet("10.0.0.254:53").is_ok());
        assert!(require_tun_subnet("10.0.0.1:53").is_ok());
        assert!(require_tun_subnet("100.100.0.254:53").is_ok());
        assert!(require_tun_subnet("8.8.8.8:53").is_err());
        assert!(require_tun_subnet("127.0.0.1:53").is_err());
        assert!(require_tun_subnet("10.0.1.1:53").is_err());
        assert!(require_tun_subnet("198.19.1.1:53").is_err());
        assert!(require_tun_subnet("[::1]:53").is_err());
    }
}

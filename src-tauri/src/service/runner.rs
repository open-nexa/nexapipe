use crate::error::{codes, AppError};
use crate::proxy::tun_proxy::{TUN_NETWORK, TunProxy};
use crate::proxy::{
    ConnectionConfig, ProxyLoadBalancingStrategy, ProxyManager, ProxyManagerConfig, ProxyNodeConfig,
};
use crate::service::ipc::{IpcMessage, IpcResponse, NodeInput, IPC_SOCKET_PATH, MAX_IPC_LINE};
use crate::status::ProxyStatus;
use anyhow::{Context, Result};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub struct ServiceRunner {
    proxy_manager: Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
}

impl ServiceRunner {
    pub fn new() -> Self {
        Self {
            proxy_manager: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Service runner starting");

        let listener = TcpListener::bind(IPC_SOCKET_PATH)
            .await
            .context("Failed to bind IPC socket")?;

        tracing::info!("IPC server listening on: {}", IPC_SOCKET_PATH);

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

                match (crate::service::ipc_token::read_token()?, presented) {
                    (Some(expected), presented)
                        if crate::service::ipc_token::token_matches(&expected, &presented) =>
                    {
                        authenticated = true;
                        tracing::debug!("IPC client authenticated");
                    }
                    (Some(_), _) => {
                        tracing::warn!("Refusing an IPC client that presented a wrong token");
                        let response = IpcResponse::Error(AppError::new(codes::SERVICE_UNAUTHORIZED));
                        Self::write_response(reader.get_mut(), &response).await?;
                        break;
                    }
                    // No token published yet means no desktop session has asked
                    // for the service, so there is nobody to answer.
                    (None, _) => {
                        tracing::warn!("Refusing an IPC call with no token on file");
                        let response = IpcResponse::Error(AppError::with_detail(
                            codes::SERVICE_IPC_TOKEN,
                            "no desktop session has published an IPC token",
                        ));
                        Self::write_response(reader.get_mut(), &response).await?;
                        break;
                    }
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
                        req.force_relay,
                        req.two_factor_enabled,
                        req.two_factor_client_id,
                        req.two_factor_secret,
                        req.two_factor_algorithm,
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
        let response_str =
            serde_json::to_string(response).context("Failed to serialize response")?;
        stream
            .write_all(response_str.as_bytes())
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
        force_relay: Option<bool>,
        two_factor_enabled: Option<bool>,
        two_factor_client_id: Option<String>,
        two_factor_secret: Option<String>,
        two_factor_algorithm: Option<String>,
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
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

        let dns_addr = dns_addr.unwrap_or_else(|| "10.0.0.254:53".to_string());
        if let Err(e) = require_tun_subnet(&dns_addr) {
            return IpcResponse::Error(e);
        }

        let upstream_dns = upstream_dns.unwrap_or_else(|| "8.8.8.8:53".to_string());

        let tun_name = tun_name.unwrap_or_else(|| "nexa-tun".to_string());

        // Explicit forwarding mode, same contract as process mode: requested TUN is honoured or
        // refused, never silently replaced by a local proxy. The service runs elevated, so this
        // only fires when the request could not be satisfied at all.
        let use_tun = use_tun.unwrap_or(false);
        if use_tun && !TunProxy::is_available().await {
            return IpcResponse::Error(AppError::new(codes::PROXY_TUN_UNAVAILABLE));
        }

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
            let mut pm = proxy_manager.write().await;
            *pm = Some(manager.clone());
        }

        let proxy_manager_clone = proxy_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.start().await {
                tracing::error!("Proxy manager failed: {}", e);
                let mut pm = proxy_manager_clone.write().await;
                *pm = None;
            }
        });

        IpcResponse::Ok
    }

    async fn handle_stop_proxy(
        proxy_manager: &Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
    ) -> IpcResponse {
        let pm = proxy_manager.write().await;
        if let Some(manager) = pm.as_ref() {
            manager.stop().await;
        }
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

/// Refuses `addr` unless it is inside the TUN network the DNS server answers on.
fn require_tun_subnet(addr: &str) -> Result<(), AppError> {
    let (network, mask) = tun_network().ok_or_else(|| {
        AppError::with_detail(
            codes::SERVICE_DNS_ADDR_OUTSIDE_TUN,
            format!("cannot interpret {TUN_NETWORK:?} as a network"),
        )
    })?;

    let parsed = addr.parse::<SocketAddr>().map_err(|e| {
        AppError::cause(
            codes::SERVICE_DNS_ADDR_OUTSIDE_TUN,
            format!("{addr:?} is not a host:port address ({e})"),
        )
    })?;

    match parsed.ip() {
        IpAddr::V4(ip) if u32::from(ip) & mask == network => Ok(()),
        other => Err(AppError::with_detail(
            codes::SERVICE_DNS_ADDR_OUTSIDE_TUN,
            format!("{other} is outside {TUN_NETWORK}, where the TUN DNS server answers"),
        )),
    }
}

/// The TUN network as `(network address, netmask)`, or `None` if
/// [`TUN_NETWORK`] is not a plain IPv4 CIDR block.
fn tun_network() -> Option<(u32, u32)> {
    let (network, bits) = TUN_NETWORK.split_once('/')?;
    let network: Ipv4Addr = network.parse().ok()?;
    let bits: u32 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    // Shifting by the full width overflows, hence the explicit zero case.
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some((u32::from(network) & mask, mask))
}

#[cfg(test)]
mod tests {
    use super::{IpcReadError, ServiceRunner, MAX_IPC_LINE, require_loopback, require_tun_subnet, tun_network};
    use crate::error::codes;
    use std::net::Ipv4Addr;

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
        assert!(require_tun_subnet("10.0.0.254:53").is_ok());
        assert!(require_tun_subnet("10.0.0.1:53").is_ok());
        assert!(require_tun_subnet("8.8.8.8:53").is_err());
        assert!(require_tun_subnet("127.0.0.1:53").is_err());
        assert!(require_tun_subnet("10.0.1.1:53").is_err());
        assert!(require_tun_subnet("[::1]:53").is_err());
    }

    #[test]
    fn the_tun_network_parses_into_a_maskable_prefix() {
        let (network, mask) = tun_network().expect("TUN_NETWORK is an IPv4 CIDR");
        assert_eq!(mask, 0xFFFF_FF00);
        assert_eq!(network, u32::from(Ipv4Addr::new(10, 0, 0, 0)));
    }
}

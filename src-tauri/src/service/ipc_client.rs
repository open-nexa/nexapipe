use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::error::{codes, AppError};
use crate::service::ipc::{IpcMessage, IpcResponse, NodeInput, StartProxyRequest, IPC_SOCKET_PATH};
use crate::status::{EndpointLink, ProxyStatus};

pub struct IpcClient;

/// The service answered with a message kind that does not match the request. This also covers
/// "the response was produced by a service build we do not understand", which is why the raw
/// response is kept as the detail.
fn unexpected(response: &IpcResponse) -> AppError {
    AppError::with_detail(
        codes::SERVICE_MALFORMED_RESPONSE,
        format!("unexpected response: {response:?}"),
    )
}

impl IpcClient {
    pub async fn send_message(msg: IpcMessage) -> Result<IpcResponse, AppError> {
        tracing::debug!("Connecting to service on: {}", IPC_SOCKET_PATH);

        let mut stream = TcpStream::connect(IPC_SOCKET_PATH)
            .await
            .map_err(|e| AppError::cause(codes::SERVICE_UNAVAILABLE, e))?;

        // The service runs elevated and will not answer anything before this.
        // The token is generated and owned by this side, so it — and only it —
        // can drive the service; see `service::ipc_token`.
        let token = crate::service::ipc_token::ensure_token()?;
        Self::exchange(&mut stream, IpcMessage::Auth(token)).await?;

        tracing::debug!("Authenticated, sending message");
        Self::exchange(&mut stream, msg).await
    }

    /// Writes one newline-delimited message and reads the answer.
    async fn exchange(stream: &mut TcpStream, msg: IpcMessage) -> Result<IpcResponse, AppError> {
        let msg_str =
            serde_json::to_string(&msg).map_err(|e| AppError::cause(codes::SERVICE_FAILED, e))?;

        stream
            .write_all(msg_str.as_bytes())
            .await
            .map_err(|e| AppError::cause(codes::SERVICE_IO_ERROR, e))?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|e| AppError::cause(codes::SERVICE_IO_ERROR, e))?;
        stream
            .flush()
            .await
            .map_err(|e| AppError::cause(codes::SERVICE_IO_ERROR, e))?;

        let mut reader = BufReader::new(stream);
        let mut buffer = String::new();
        tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut buffer)
            .await
            .map_err(|e| AppError::cause(codes::SERVICE_IO_ERROR, e))?;

        if buffer.is_empty() {
            return Err(AppError::with_detail(
                codes::SERVICE_IO_ERROR,
                "the service closed the connection without answering",
            ));
        }

        let response: IpcResponse = serde_json::from_str(&buffer)
            .map_err(|e| AppError::cause(codes::SERVICE_MALFORMED_RESPONSE, e))?;

        tracing::debug!("Received response: {:?}", response);
        Ok(response)
    }

    pub async fn start_proxy(
        nodes: Vec<NodeInput>,
        domains: Vec<String>,
        local_addr: Option<String>,
        dns_addr: Option<String>,
        upstream_dns: Option<String>,
        load_balancing: Option<String>,
        tun_name: Option<String>,
        use_tun: bool,
        relay_mode: Option<String>,
        relay_url: Option<String>,
        force_relay: Option<bool>,
        two_factor_enabled: Option<bool>,
        two_factor_client_id: Option<String>,
        two_factor_secret: Option<String>,
        two_factor_algorithm: Option<String>,
    ) -> Result<(), AppError> {
        let response = Self::send_message(IpcMessage::StartProxy(StartProxyRequest {
            nodes,
            domains,
            local_addr,
            dns_addr,
            upstream_dns,
            load_balancing,
            tun_name,
            use_tun: Some(use_tun),
            relay_mode,
            relay_url,
            force_relay,
            two_factor_enabled,
            two_factor_client_id,
            two_factor_secret,
            two_factor_algorithm,
        }))
        .await?;

        match response {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn stop_proxy() -> Result<(), AppError> {
        match Self::send_message(IpcMessage::StopProxy).await? {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn get_status() -> Result<ProxyStatus, AppError> {
        match Self::send_message(IpcMessage::GetStatus).await? {
            IpcResponse::Status(status) => Ok(status),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn get_node_id() -> Result<String, AppError> {
        match Self::send_message(IpcMessage::GetNodeId).await? {
            IpcResponse::NodeId(id) => Ok(id),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    /// How each configured node currently reaches its backend.
    ///
    /// Empty when the service has no manager, which is the same shape the process-mode answer
    /// takes — the UI matches links to nodes by `connection` and simply finds none.
    pub async fn get_endpoint_links() -> Result<Vec<EndpointLink>, AppError> {
        match Self::send_message(IpcMessage::GetEndpointLinks).await? {
            IpcResponse::EndpointLinks(links) => Ok(links),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    /// Whether a service is answering on the IPC port.
    ///
    /// Any error is reported as "not running" on purpose: this feeds a status indicator, and an
    /// unreachable service is indistinguishable from a stopped one from the caller's point of
    /// view. The reason is logged by [`Self::send_message`] on the way out.
    pub async fn is_service_running() -> bool {
        Self::get_status().await.is_ok()
    }
}

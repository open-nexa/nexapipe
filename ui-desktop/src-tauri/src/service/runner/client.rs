//! One connection: the challenge this side speaks first, the caller's answer to it and
//! the messages that follow.

use crate::error::{codes, AppError};
use crate::proxy::ProxyManager;
use crate::service::ipc::{IpcMessage, IpcResponse, IpcStream, BUILD_VERSION, MAX_IPC_LINE};
use crate::service::platform::account::AccountId;
use anyhow::{Context, Result};
use std::fmt;
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::{startup_error_slot, ServiceRunner, HANDSHAKE_TIMEOUT};

impl ServiceRunner {
    pub(super) async fn handle_client(
        stream: &mut IpcStream,
        proxy_manager: Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,
        installed_by: Option<&AccountId>,
    ) -> Result<()> {
        // Nothing is served before the caller authenticates: this process runs
        // elevated, and a loopback socket says nothing about who dialled it.
        let mut authenticated = false;
        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();

        // And this process speaks first, so a caller never hands anything to a
        // peer that has not identified itself — see `IpcResponse::Challenge`.
        let service_nonce = crate::service::ipc_token::random_nonce()?;
        Self::write_response(
            reader.get_mut(),
            &IpcResponse::Challenge {
                nonce: service_nonce.clone(),
            },
        )
        .await?;

        loop {
            line.clear();

            // Unauthenticated reads are the only ones with a deadline: a caller that connects,
            // takes the challenge and then says nothing would otherwise hold this task — and its
            // socket — for as long as it likes, which is a few dozen connections away from an
            // elevated process that answers nobody.
            let read = if authenticated {
                Self::read_ipc_line(&mut reader, &mut line).await
            } else {
                match tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    Self::read_ipc_line(&mut reader, &mut line),
                )
                .await
                {
                    Ok(read) => read,
                    Err(_) => {
                        tracing::warn!(
                            "Dropping an IPC client that did not authenticate within {:?}",
                            HANDSHAKE_TIMEOUT
                        );
                        break;
                    }
                }
            };

            match read {
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
                    let response =
                        IpcResponse::Error(AppError::cause(codes::SERVICE_MALFORMED_REQUEST, e));
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
                    let response =
                        IpcResponse::Error(AppError::cause(codes::SERVICE_MALFORMED_REQUEST, e));
                    Self::write_response(reader.get_mut(), &response).await?;
                    continue;
                }
            };

            if !authenticated {
                let (caller_nonce, presented) = match &msg {
                    IpcMessage::Auth { nonce, mac } => (nonce.clone(), mac.clone()),
                    other => {
                        // Obeyed nothing, answered once, connection closed.
                        tracing::warn!(
                            "Refusing an IPC client that spoke before authenticating: {:?}",
                            std::mem::discriminant(other)
                        );
                        let response =
                            IpcResponse::Error(AppError::new(codes::SERVICE_UNAUTHORIZED));
                        Self::write_response(reader.get_mut(), &response).await?;
                        break;
                    }
                };

                // Every published token is a candidate: the service cannot tell which account
                // dialled it by looking at the socket, so it asks the kernel instead. The
                // answer is bound to both nonces, so a recorded one is worth nothing on the
                // next connection.
                let known = crate::service::ipc_token::read_candidates()?;
                let matched = crate::service::ipc_token::token_for_auth(
                    &known,
                    &service_nonce,
                    &caller_nonce,
                    &presented,
                );

                // Who is on the other end of the socket. A loopback connection says nothing
                // about that, and this process does root things on the caller's word, so the
                // account has to be asked of the operating system rather than assumed.
                let peer = match AccountId::peer_of(reader.get_mut()) {
                    Some(account) => account,
                    None => {
                        tracing::warn!(
                            "Refusing an IPC client whose account could not be identified"
                        );
                        let response = IpcResponse::Error(AppError::with_detail(
                            codes::SERVICE_UNAUTHORIZED,
                            "the account behind this connection could not be identified",
                        ));
                        Self::write_response(reader.get_mut(), &response).await?;
                        break;
                    }
                };

                let candidate = match matched {
                    Some(candidate) => {
                        // The token was right; the account has to be right too. This service
                        // serves the account it was installed for and nobody else, because
                        // what it does on the caller's word — the TUN device, the
                        // machine-wide routes, the DNS hijack — is the machine's.
                        let allowed = crate::service::platform::account::allows(
                            installed_by,
                            &peer,
                            &candidate.owner,
                        );
                        if !allowed {
                            tracing::warn!(
                                "Refusing an IPC client that is not the account this service \
                                 serves: the caller is {peer}, its token belongs to {}, and \
                                 this service is installed for {installed_by:?}",
                                candidate.owner
                            );
                            let response = IpcResponse::Error(AppError::with_detail(
                                codes::SERVICE_UNAUTHORIZED,
                                "this service is installed for another account",
                            ));
                            Self::write_response(reader.get_mut(), &response).await?;
                            break;
                        }

                        authenticated = true;
                        tracing::debug!("IPC client authenticated");
                        candidate
                    }
                    None if known.is_empty() => {
                        // No token published yet means no desktop session has asked for the
                        // service, so there is nobody to answer.
                        tracing::warn!("Refusing an IPC call with no token on file");
                        let response = IpcResponse::Error(AppError::with_detail(
                            codes::SERVICE_IPC_TOKEN,
                            "no desktop session has published an IPC token",
                        ));
                        Self::write_response(reader.get_mut(), &response).await?;
                        break;
                    }
                    None => {
                        tracing::warn!("Refusing an IPC client that answered the challenge wrong");
                        let response =
                            IpcResponse::Error(AppError::new(codes::SERVICE_UNAUTHORIZED));
                        Self::write_response(reader.get_mut(), &response).await?;
                        break;
                    }
                };

                // The caller proved itself; now this side proves itself back, so a caller
                // that connected to something else on the port finds out.
                let proof = crate::service::ipc_token::proof_mac(
                    &candidate.token,
                    &service_nonce,
                    &caller_nonce,
                );
                Self::write_response(reader.get_mut(), &IpcResponse::AuthOk { mac: proof }).await?;
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
                        req.dns_strategy,
                        req.load_balancing,
                        req.tun_name,
                        req.use_tun,
                        req.relay_mode,
                        req.relay_url,
                        req.relay_auth_token,
                        req.discovery_mode,
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
                IpcMessage::GetNodeHealth => Self::handle_get_node_health(&proxy_manager).await,
                IpcMessage::GetNodeTraffic => Self::handle_get_node_traffic(&proxy_manager).await,
                IpcMessage::GetActiveFlows => Self::handle_get_active_flows(&proxy_manager).await,
                IpcMessage::CloseFlow { id } => Self::handle_close_flow(&proxy_manager, id).await,
                IpcMessage::CloseNodeFlows { connection } => {
                    Self::handle_close_node_flows(&proxy_manager, &connection).await
                }
                IpcMessage::GetIssuedCredential => {
                    Self::handle_get_issued_credential(&proxy_manager).await
                }
                IpcMessage::GetStartupError => {
                    IpcResponse::StartupError(startup_error_slot().read().await.clone())
                }
                IpcMessage::GetVersion => IpcResponse::Version(BUILD_VERSION.to_string()),
                // Handled above, when the caller introduced itself. A second
                // handshake on a connection that already has one is refused
                // rather than answered: there is nothing it could establish, and
                // answering it would make this side sign arbitrary nonces for
                // whoever is on the other end.
                IpcMessage::Auth { .. } => {
                    IpcResponse::Error(AppError::new(codes::SERVICE_UNAUTHORIZED))
                }
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
    pub(super) async fn read_ipc_line<R>(
        reader: &mut R,
        buf: &mut Vec<u8>,
    ) -> Result<usize, IpcReadError>
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

    pub(super) async fn write_response(
        stream: &mut IpcStream,
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
}

/// Why one line could not be read off the IPC channel.
#[derive(Debug)]
pub(super) enum IpcReadError {
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

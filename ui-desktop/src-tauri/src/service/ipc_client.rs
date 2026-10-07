use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::error::{codes, AppError};
use crate::service::ipc::{
    IpcMessage, IpcResponse, IssuedCredentialPayload, StartProxyRequest, IPC_SOCKET_PATH,
};
use crate::status::{
    ActiveFlowPage, EndpointLink, NodeHealthStatus, NodeTrafficStatus, ProxyStatus,
};

pub struct IpcClient;

/// How long the service gets to answer each step of the handshake.
///
/// A peer that says nothing at all is not this build's service but an older one:
/// that one waits for the caller to speak first, which is exactly the shape the
/// handshake replaced. Without a deadline the difference shows up as a hang
/// rather than as an error anybody can act on.
///
/// The same deadline covers the proof: a peer that opens with a challenge and
/// then stops — a squatter on the port, or a service that stalled mid-handshake —
/// would otherwise park every caller here indefinitely, including the one that
/// feeds the status indicator.
const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(5);

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

        // One reader for the whole connection. `exchange` used to build a fresh
        // `BufReader` per message, which drops whatever the previous one had
        // already buffered — harmless while every exchange was write-then-read
        // one line at a time, and a lost reply as soon as the service speaks
        // first and two answers can arrive together.
        let (read_half, mut write_half) = stream.split();
        let mut reader = BufReader::new(read_half);

        Self::handshake(&mut reader, &mut write_half, &token).await?;

        tracing::debug!("Authenticated, sending message");
        Self::write_message(&mut write_half, &msg).await?;
        Self::read_response(&mut reader).await
    }

    /// The mutual authentication exchange over an already-connected channel.
    ///
    /// Split out from [`Self::send_message`] so it can be driven against a
    /// stand-in peer: every decision it makes is visible in the messages alone,
    /// and the case that matters — a peer that cannot answer for this side's
    /// nonce — is otherwise only reachable by squatting on the real port.
    async fn handshake<R, W>(reader: &mut R, writer: &mut W, token: &str) -> Result<(), AppError>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        // The service speaks first. This side offers nothing until it has a
        // nonce to answer for, so a squatter on the port — the reason this
        // replaced a bare token — is handed nothing it could replay.
        let challenge =
            match tokio::time::timeout(CHALLENGE_TIMEOUT, Self::read_response(reader)).await {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(AppError::with_detail(
                        codes::SERVICE_PROTOCOL_MISMATCH,
                        format!(
                            "nothing on {IPC_SOCKET_PATH} opened with a challenge within \
                             {CHALLENGE_TIMEOUT:?}; the installed service is older than this app"
                        ),
                    ))
                }
            };

        let service_nonce = match challenge {
            IpcResponse::Challenge { nonce } => nonce,
            IpcResponse::Error(e) => return Err(e),
            other => return Err(unexpected(&other)),
        };

        // A nonce of this side's own, which the service has to answer back for:
        // what makes the exchange mutual rather than one-way.
        let caller_nonce = crate::service::ipc_token::random_nonce()?;
        let mac = crate::service::ipc_token::auth_mac(token, &service_nonce, &caller_nonce);
        Self::write_message(
            writer,
            &IpcMessage::Auth {
                nonce: caller_nonce.clone(),
                mac,
            },
        )
        .await?;

        // Checked rather than trusted: a peer that cannot answer for this side's
        // nonce does not hold the token, whatever it accepted above.
        let proof =
            match tokio::time::timeout(CHALLENGE_TIMEOUT, Self::read_response(reader)).await {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(AppError::with_detail(
                        codes::SERVICE_UNAUTHORIZED,
                        format!(
                            "nothing on {IPC_SOCKET_PATH} proved it holds the token within \
                             {CHALLENGE_TIMEOUT:?}"
                        ),
                    ))
                }
            };
        match proof {
            IpcResponse::AuthOk { mac } => {
                if !crate::service::ipc_token::proof_matches(
                    token,
                    &service_nonce,
                    &caller_nonce,
                    &mac,
                ) {
                    return Err(AppError::with_detail(
                        codes::SERVICE_UNAUTHORIZED,
                        "the service could not prove it holds the IPC token: something else is \
                         answering on the IPC port",
                    ));
                }
            }
            IpcResponse::Error(e) => return Err(e),
            other => return Err(unexpected(&other)),
        }

        Ok(())
    }

    /// Writes one newline-delimited message.
    async fn write_message<W>(writer: &mut W, msg: &IpcMessage) -> Result<(), AppError>
    where
        W: AsyncWrite + Unpin,
    {
        let msg_str =
            serde_json::to_string(msg).map_err(|e| AppError::cause(codes::SERVICE_FAILED, e))?;

        writer
            .write_all(msg_str.as_bytes())
            .await
            .map_err(|e| AppError::cause(codes::SERVICE_IO_ERROR, e))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| AppError::cause(codes::SERVICE_IO_ERROR, e))?;
        writer
            .flush()
            .await
            .map_err(|e| AppError::cause(codes::SERVICE_IO_ERROR, e))?;

        Ok(())
    }

    /// Reads one newline-delimited answer.
    async fn read_response<R>(reader: &mut R) -> Result<IpcResponse, AppError>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut buffer = String::new();
        AsyncBufReadExt::read_line(reader, &mut buffer)
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

    pub async fn start_proxy(request: StartProxyRequest) -> Result<(), AppError> {
        let response = Self::send_message(IpcMessage::StartProxy(Box::new(request))).await?;

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

    /// Whether each configured node answered its last probe.
    ///
    /// Empty when the service has no manager, which is the same shape the process-mode answer
    /// takes — the UI matches a reading to a node by `connection` and simply finds none.
    pub async fn get_node_health() -> Result<Vec<NodeHealthStatus>, AppError> {
        match Self::send_message(IpcMessage::GetNodeHealth).await? {
            IpcResponse::NodeHealth(health) => Ok(health),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    /// What each configured node has carried, and how many flows are open to it.
    ///
    /// Empty when the service has no manager, which is the same shape the process-mode answer
    /// takes — the UI matches a volume to a node by `connection` and simply finds none. Cumulative
    /// figures: nothing here divides by anything.
    pub async fn get_node_traffic() -> Result<Vec<NodeTrafficStatus>, AppError> {
        match Self::send_message(IpcMessage::GetNodeTraffic).await? {
            IpcResponse::NodeTraffic(traffic) => Ok(traffic),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    /// The connections the proxy has open right now.
    ///
    /// An empty page when the service has no manager, which is the same shape the process-mode
    /// answer takes — the UI draws an empty list and does not treat it as a failure.
    pub async fn get_active_flows() -> Result<ActiveFlowPage, AppError> {
        match Self::send_message(IpcMessage::GetActiveFlows).await? {
            IpcResponse::ActiveFlows(page) => Ok(page),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    /// Asks one open flow to end. `false` when the service has no such flow.
    pub async fn close_flow(id: u64) -> Result<bool, AppError> {
        match Self::send_message(IpcMessage::CloseFlow { id }).await? {
            IpcResponse::FlowClosed(closed) => Ok(closed),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    /// Asks every flow reaching one configured node to end.
    ///
    /// `None` when `connection` names a node this configuration cannot resolve to, which is a
    /// different answer from "resolved, and had nothing open".
    pub async fn close_node_flows(connection: &str) -> Result<Option<usize>, AppError> {
        match Self::send_message(IpcMessage::CloseNodeFlows {
            connection: connection.to_string(),
        })
        .await?
        {
            IpcResponse::NodeFlowsClosed(closed) => Ok(closed),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    /// The failure the service's last start recorded after it had already answered `Ok`.
    ///
    /// `None` is a legitimate answer, not an error: it means the start settled.
    /// The credential the server issued for an enrollment token, if one was spent.
    ///
    /// Read once and gone: the token cannot be spent twice, so the caller gets one chance
    /// to persist it. `None` means nothing enrolled on this run.
    pub async fn take_issued_credential() -> Result<Option<IssuedCredentialPayload>, AppError> {
        match Self::send_message(IpcMessage::GetIssuedCredential).await? {
            IpcResponse::IssuedCredential(credential) => Ok(credential),
            IpcResponse::Error(e) => Err(e),
            _ => Err(AppError::new(codes::SERVICE_UNAVAILABLE)),
        }
    }

    /// The build the installed service is.
    ///
    /// `Err` when it cannot be asked, which includes the case this exists for: a service that
    /// predates [`IpcMessage::GetVersion`] refuses the request at its own deserializer and
    /// drops the connection, so from here it looks like a service that is not answering. A
    /// caller that wants "whose build is running, if anybody knows" should read that as `None`.
    pub async fn get_version() -> Result<String, AppError> {
        match Self::send_message(IpcMessage::GetVersion).await? {
            IpcResponse::Version(version) => Ok(version),
            IpcResponse::Error(e) => Err(e),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn get_startup_error() -> Result<Option<AppError>, AppError> {
        match Self::send_message(IpcMessage::GetStartupError).await? {
            IpcResponse::StartupError(e) => Ok(e),
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

#[cfg(test)]
mod tests {
    use super::{IpcClient, IpcMessage, IpcResponse};
    use crate::error::{codes, AppError};
    use crate::service::ipc_token::{auth_mac, proof_mac};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    /// The token a test authenticates with, minted the way the real one is.
    ///
    /// A literal would do — nothing here depends on the value — but a constant
    /// sitting in the key slot is exactly what CWE-798 is about, and all these
    /// tests need is a secret both ends agree on.
    fn fresh_token() -> String {
        crate::service::ipc_token::generate_token().expect("the OS has randomness")
    }

    /// Runs the handshake against a stand-in peer.
    ///
    /// `answer` decides what the peer replies to the caller's `Auth`: its own
    /// proof, or nothing at all. Returns what the handshake concluded.
    async fn handshake_against(answer: Answer) -> Result<(), AppError> {
        let (client_end, server_end) = tokio::io::duplex(4096);
        let service_nonce = crate::service::ipc_token::random_nonce().expect("a nonce");
        let token = fresh_token();

        let peer = tokio::spawn(peer_side(
            server_end,
            service_nonce.clone(),
            token.clone(),
            answer,
        ));

        let (read_half, mut write_half) = tokio::io::split(client_end);
        let mut reader = BufReader::new(read_half);
        let result = IpcClient::handshake(&mut reader, &mut write_half, &token).await;

        peer.abort();
        result
    }

    /// What a stand-in peer replies with.
    enum Answer {
        /// The proof the token really produces.
        Proof,
        /// A proof computed under some other token — what a squatter holding
        /// nothing would have to send.
        Forged,
    }

    /// The service's half: challenge, read the answer, reply.
    async fn peer_side(
        server_end: DuplexStream,
        service_nonce: String,
        token: String,
        answer: Answer,
    ) {
        let (read_half, mut write_half) = tokio::io::split(server_end);
        let mut reader = BufReader::new(read_half);

        write_line(
            &mut write_half,
            &IpcResponse::Challenge {
                nonce: service_nonce.clone(),
            },
        )
        .await;

        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .expect("the caller answers");
        if read == 0 {
            return;
        }

        let caller_nonce = match serde_json::from_str::<IpcMessage>(&line) {
            Ok(IpcMessage::Auth { nonce, .. }) => nonce,
            other => panic!("the caller must answer with an Auth, got {other:?}"),
        };

        let mac = match answer {
            Answer::Proof => proof_mac(&token, &service_nonce, &caller_nonce),
            // A squatter holds nothing, so what it sends is a proof under some
            // other secret nobody published — one more token, not a literal.
            Answer::Forged => proof_mac(&fresh_token(), &service_nonce, &caller_nonce),
        };
        write_line(&mut write_half, &IpcResponse::AuthOk { mac }).await;
    }

    async fn write_line<W>(writer: &mut W, response: &IpcResponse)
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let line = serde_json::to_string(response).expect("the response serializes");
        writer
            .write_all(line.as_bytes())
            .await
            .expect("the line is written");
        writer
            .write_all(b"\n")
            .await
            .expect("the line is terminated");
        writer.flush().await.expect("the line is flushed");
    }

    #[tokio::test]
    async fn a_peer_that_answers_for_the_callers_nonce_is_accepted() {
        handshake_against(Answer::Proof)
            .await
            .expect("a peer holding the token proves it");
    }

    /// The case the handshake exists for: something on the port that accepted the
    /// caller's answer but cannot answer for its nonce does not hold the token,
    /// and the caller has to find out rather than keep talking to it.
    #[tokio::test]
    async fn a_peer_that_cannot_prove_it_holds_the_token_is_refused() {
        let error = handshake_against(Answer::Forged)
            .await
            .expect_err("a forged proof is refused");

        assert_eq!(error.code, codes::SERVICE_UNAUTHORIZED);
    }

    /// An older service waits for the caller to speak first, so it never opens
    /// with a challenge. That has to surface as a mismatch the UI can act on —
    /// reinstall the service — and not as a call that never returns.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_challenges_is_a_mismatch() {
        let (client_end, server_end) = tokio::io::duplex(64);

        let handshake = tokio::spawn(async move {
            let (read_half, mut write_half) = tokio::io::split(client_end);
            let mut reader = BufReader::new(read_half);
            IpcClient::handshake(&mut reader, &mut write_half, &fresh_token()).await
        });

        // Held open and silent: the connection is alive, nothing arrives on it.
        let _silent_peer = server_end;
        tokio::time::advance(Duration::from_secs(30)).await;

        let error = handshake
            .await
            .expect("the task ends")
            .expect_err("no challenge");
        assert_eq!(error.code, codes::SERVICE_PROTOCOL_MISMATCH);
    }

    /// The caller's answer is bound to the challenge: an answer recorded from one
    /// connection is not an answer on the next, so it cannot be replayed.
    #[test]
    fn an_answer_is_bound_to_the_challenge_it_was_made_for() {
        let token = fresh_token();

        assert_ne!(
            auth_mac(&token, "one-challenge", "caller"),
            auth_mac(&token, "another", "caller")
        );
    }
}

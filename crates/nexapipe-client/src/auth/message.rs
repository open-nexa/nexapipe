//! The framing of the handshake's messages.
//!
//! Both sides of a handshake write the same framing, and the size of a
//! message is bounded before it is read — a peer that announces a huge
//! message gets refused rather than believed.

use nexapipe_proto::auth::{AuthMessage, Format};
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

use crate::ClientError;

/// Writes one length-prefixed message in the form asked for.
pub(super) async fn write_message(
    send: &mut iroh::endpoint::SendStream,
    message: &AuthMessage,
    format: Format,
) -> Result<(), ClientError> {
    let bytes = message
        .to_payload(format)
        .map_err(|e| ClientError::Other(format!("Serialization error: {}", e)))?;
    let len = bytes.len() as u32;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send length: {}", e)))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send message: {}", e)))
}

/// Reads one length-prefixed message.
///
/// Generic on purpose: `tokio::io::duplex` gives a test both ends of the
/// framing in one process, so what a peer sends can be read without an iroh
/// endpoint behind it — the same reason the L4 tunnel is written this way.
pub(super) async fn read_message<R>(recv: &mut R) -> Result<(AuthMessage, Format), ClientError>
where
    R: AsyncRead + Unpin,
{
    let bytes = read_message_bytes(recv).await?;
    // The message is parsed out of the buffer, and the parsed message holds a
    // copy of its own: a `SecretString` is built from the bytes, so the copy
    // in the buffer is the redundant one — and the buffer wipes it.
    AuthMessage::from_payload(&bytes[..])
        .map_err(|e| ClientError::Other(format!("Deserialization error: {}", e)))
}

/// Reads one length-prefixed message's bytes.
///
/// **The buffer wipes itself when it goes out of scope.** A message may carry
/// a credential — the secret an `ENROLL_ISSUE` hands out is the one that
/// matters — and this buffer holds it in the clear until it is dropped. A
/// plain `Vec<u8>` would leave those bytes in the heap for the allocator to
/// hand out again, which is where a core dump, a swap file or a read of
/// `/proc/<pid>/mem` finds them: the credential outlives the handshake that
/// needed it.
pub(super) async fn read_message_bytes<R>(recv: &mut R) -> Result<Zeroizing<Vec<u8>>, ClientError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| {
        ClientError::ConnectionFailed(format!("Failed to read message length: {e}"))
    })?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    // The server caps what it will read at 64 KiB; anything longer is a peer
    // that is not speaking this protocol, not a message worth allocating for.
    if msg_len > MAX_AUTH_MESSAGE {
        return Err(ClientError::ConnectionFailed(format!(
            "auth message length {msg_len} is out of range"
        )));
    }
    let mut msg_buf = Zeroizing::new(vec![0u8; msg_len]);
    recv.read_exact(&mut msg_buf[..])
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to read message: {e}")))?;
    Ok(msg_buf)
}

/// The `type` tag of a message, for errors that name what arrived.
pub(super) fn message_name(message: &AuthMessage) -> &'static str {
    match message {
        AuthMessage::Start { .. } => "AUTH_START",
        AuthMessage::Challenge { .. } => "AUTH_CHALLENGE",
        AuthMessage::Response { .. } => "AUTH_RESPONSE",
        AuthMessage::Ok => "AUTH_OK",
        AuthMessage::Failed { .. } => "AUTH_FAILED",
        AuthMessage::EnrollStart { .. } => "ENROLL_START",
        AuthMessage::EnrollIssue { .. } => "ENROLL_ISSUE",
        AuthMessage::EnrollFailed { .. } => "ENROLL_FAILED",
    }
}

/// The largest AUTH_* message the client accepts.
///
/// Mirrors `MAX_AUTH_MESSAGE` in `crates/nexapipe/src/conn/mod.rs`: the length
/// prefix is read before anything is known about the peer, so it is not
/// trusted until it is in range.
const MAX_AUTH_MESSAGE: usize = 64 * 1024;

/// How long the client waits for the server to finish the handshake.
///
/// Comfortably longer than the server's own five-second wait for the first
/// stream: that one covers a client that never speaks, while this covers a
/// server that answers and then stalls, which nothing else on either side does.
pub(super) const AUTH_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

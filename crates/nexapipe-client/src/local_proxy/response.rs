//! The backend's answer, relayed to the client.
//!
//! The bound is a quiet window rather than a clock over the whole exchange: a
//! response that keeps arriving keeps the exchange alive however long it
//! takes, and only a gap of silence ends it.

#[cfg(feature = "jni")]
use crate::jni_log;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::STREAM_BUF_SIZE;
use super::debug_log_enabled;

/// How a relayed response ended.
#[derive(Debug)]
pub(super) enum ResponseRelay {
    /// The backend closed the stream: the response is over.
    Complete,
    /// The backend went quiet for a whole window: it is not coming back.
    Quiet,
    /// The backend's stream failed.
    Failed,
    /// The client is gone, or the write to it failed.
    ClientGone,
}

/// Relay the backend's response to the client, with the quiet window as the
/// bound.
///
/// **The bound is a gap, not a clock over the whole exchange.** Every chunk
/// that arrives gives the next read a fresh window, so a response that keeps
/// arriving keeps the exchange alive however long it takes — a large
/// download, an SSE stream, a long-poll — and only a *gap* of silence ends
/// it.
///
/// The bound that used to sit around this loop was a total one: sixty
/// seconds from the moment the request went out, whatever else was
/// happening. A response that was still arriving was cut at the minute, and
/// because the socket was dropped rather than an answer written, the client
/// was left holding a truncated body and no error to explain it.
///
/// `counted` is told how many bytes each chunk carried, so the flow's
/// counter sees the response as it is relayed.
pub(super) async fn relay_the_response<R, W>(
    backend: &mut R,
    client: &mut W,
    quiet: tokio::time::Duration,
    counted: &mut (dyn FnMut(usize) + Send),
) -> ResponseRelay
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; STREAM_BUF_SIZE];
    let mut total_bytes = 0usize;
    // The preview is only ever read when the debug log is on, so it is only
    // built then: a 1.5 KiB buffer filled for every response, for a log
    // line nobody asked for.
    let mut debug_preview = debug_log_enabled().then(|| Vec::with_capacity(1500));
    let mut response_sent = false;
    let mut outcome = ResponseRelay::Complete;
    loop {
        // **The bound is here, on the read.** The window goes to the read
        // that waits for the next chunk, and every chunk that arrives gives
        // the next read a fresh one: a response that keeps arriving never
        // runs out of time, and only a backend that has gone quiet for the
        // whole window is cut.
        let n = match tokio::time::timeout(quiet, backend.read(&mut buf)).await {
            // The backend closed its side: the response is over.
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Backend read error: {}", e);
                outcome = ResponseRelay::Failed;
                break;
            }
            Err(_) => {
                outcome = ResponseRelay::Quiet;
                break;
            }
        };
        total_bytes += n;
        if let Some(preview) = debug_preview.as_mut()
            && !response_sent
            && preview.len() < 1500
        {
            preview.extend_from_slice(&buf[..std::cmp::min(n, 1500 - preview.len())]);
        }
        if let Err(e) = client.write_all(&buf[..n]).await {
            #[cfg(feature = "tracing")]
            tracing::debug!("Backend to client write error: {}", e);
            outcome = ResponseRelay::ClientGone;
            break;
        }
        if let Err(e) = client.flush().await {
            #[cfg(feature = "tracing")]
            tracing::debug!("Backend to client flush error: {}", e);
            outcome = ResponseRelay::ClientGone;
            break;
        }
        counted(n);
        if !response_sent {
            response_sent = true;
            jni_log!("[DEBUG:local-proxy] Response sent: {} bytes", total_bytes);
            if let Some(preview) = debug_preview.as_ref()
                && !preview.is_empty()
            {
                jni_log!(
                    "[DEBUG:local-proxy] Response preview: {}",
                    String::from_utf8_lossy(preview)
                );
            }
        }
    }
    if !response_sent && total_bytes > 0 {
        jni_log!(
            "[DEBUG:local-proxy] Response sent (late): {} bytes",
            total_bytes
        );
        if let Some(preview) = debug_preview.as_ref()
            && !preview.is_empty()
        {
            jni_log!(
                "[DEBUG:local-proxy] Response preview: {}",
                String::from_utf8_lossy(preview)
            );
        }
    }
    outcome
}

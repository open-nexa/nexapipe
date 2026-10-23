//! The WebSocket path: the upgrade, and the frames as far as they are
//! looked at.
//!
//! The frames themselves are not touched: the bytes are moved as they are.
//! What is here is the preview a debug log prints, which is the only reason
//! the tunnel looks inside a frame at all, and the upgrade that turns a
//! request into a tunnel that stays open.

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::ClientError;
use crate::endpoint_group::EndpointGroup;
use crate::flow::{FlowKind, FlowMeta};

use nexapipe_proto::protocol::Protocol;

use std::sync::Arc;

use ::http::Request;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::http_head::filter_request_headers;
use super::tunnel::{TunnelTasks, open_stream_with_retry};
use super::{STREAM_BUF_SIZE, debug_log_enabled};

// Only referenced from the `debug_log_enabled()`-gated WebSocket dumps; in non-JNI builds
// that guard is a constant `false`, so the lint sees no live caller.
#[allow(dead_code)]
pub(super) fn websocket_frame_preview(data: &[u8]) -> String {
    let mut preview = String::new();
    for &b in data.iter().take(256) {
        if b.is_ascii_graphic() || b == b' ' {
            preview.push(b as char);
        } else {
            preview.push_str(&format!("\\x{:02x}", b));
        }
    }
    if data.len() > 256 {
        preview.push_str("...");
    }
    format!("{} bytes: {}", data.len(), preview)
}

/// Adds a chunk to the WebSocket debug buffer when it fits under the ceiling.
///
/// Returns `false` when the chunk would take the buffer past its ceiling, in
/// which case the buffer is left as it was and the caller drops it.
///
/// The check is **before** the append, so the buffer never grows past the
/// ceiling: a check after the append would let the last chunk take it
/// `chunk.len()` bytes over, which is how a ceiling stops being one.
pub(super) fn ws_frame_buffer_append(buffer: &mut Vec<u8>, chunk: &[u8]) -> bool {
    if buffer.len().saturating_add(chunk.len()) > WS_FRAME_BUFFER_LIMIT {
        return false;
    }
    buffer.extend_from_slice(chunk);
    true
}

pub(super) fn parse_websocket_frames(buffer: &mut Vec<u8>, frames: &mut Vec<(u8, Vec<u8>)>) {
    let mut pos = 0usize;
    while buffer.len().saturating_sub(pos) >= 2 {
        let b0 = buffer[pos];
        let b1 = buffer[pos + 1];
        let opcode = b0 & 0x0f;
        let masked = b1 & 0x80 != 0;
        let mut payload_len = (b1 & 0x7f) as u64;
        let mut header_len = 2usize;

        if payload_len == 126 {
            if buffer.len() < pos + 4 {
                break;
            }
            payload_len = u16::from_be_bytes([buffer[pos + 2], buffer[pos + 3]]) as u64;
            header_len = 4;
        } else if payload_len == 127 {
            if buffer.len() < pos + 10 {
                break;
            }
            payload_len = u64::from_be_bytes(
                buffer[pos + 2..pos + 10]
                    .try_into()
                    .expect("slice length is 8"),
            );
            header_len = 10;
        }

        if masked {
            header_len += 4;
        }

        let payload_start = pos + header_len;
        let total = match payload_start.checked_add(payload_len as usize) {
            Some(total) => total,
            None => break,
        };
        if total > buffer.len() {
            break;
        }

        let payload = if masked {
            let mask = &buffer[payload_start - 4..payload_start];
            buffer[payload_start..total]
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ mask[i % 4])
                .collect()
        } else {
            buffer[payload_start..total].to_vec()
        };

        frames.push((opcode, payload));
        pos = total;
    }

    if pos > 0 {
        buffer.drain(..pos);
    }
}

/// How much of an unfinished WebSocket frame the debug dump keeps.
///
/// The dump assembles a frame's bytes until the frame is whole, and a peer
/// that sends a frame header and then nothing would grow that without end:
/// the bytes are held for a frame that is never completed. A megabyte is far
/// more than the dump needs — it prints 256 bytes of a frame — and it is a
/// ceiling rather than a limit.
pub(super) const WS_FRAME_BUFFER_LIMIT: usize = 1024 * 1024;

/// The WebSocket upgrade, and the tunnel that carries it.
///
/// The request line is rewritten to an absolute "http://" URI, the headers
/// that must not be forwarded are dropped, and the bytes that came with the
/// head go out with the request: they are the session's first frame.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_websocket_upgrade<S>(
    stream: S,
    request: &Request<()>,
    request_buf: &[u8],
    header_end: usize,
    first_line_end: usize,
    mut temp_buf: Vec<u8>,
    host: &str,
    endpoint_group: &Arc<EndpointGroup>,
    peer: Option<String>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The method and the version come from the **parsed** request, not
    // from the bytes: the request line is rebuilt here, and a raw slice
    // of it carries whatever the client put there. A bare LF ends the
    // line for a parser that accepts one, and the rest of it lands in
    // the version token — straight into the request this proxy sends.
    let method = request.method().as_str();
    // `http::Version`'s Debug is the wire spelling — "HTTP/1.1" — and
    // the request line wants exactly that.
    let version = format!("{:?}", request.version());
    {
        let path = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        // Use http:// scheme (not ws://) — the backend handles
        // the WebSocket upgrade via the Upgrade header, not the URI
        let absolute_uri = format!("http://{}{}", host, path);
        let new_line = format!("{} {} {}\r\n", method, absolute_uri, version);

        let mut request_to_send = Vec::with_capacity(new_line.len() + header_end - first_line_end);
        request_to_send.extend_from_slice(new_line.as_bytes());
        // Copy the rest of headers (skip the original request line),
        // minus the ones that must not be forwarded. `Upgrade` and
        // `Connection` stay: the upgrade is the point of this request.
        let rest_start = first_line_end + 1; // skip the line feed
        if rest_start < header_end {
            request_to_send.extend_from_slice(&filter_request_headers(
                &request_buf[rest_start..header_end],
                true,
            ));
        }
        // **The bytes that came with the head are the session's first
        // frame**, and they go out with the request: the copy loop
        // starts at the socket, and the socket has already given these
        // up. A client that wrote the upgrade and its first frame in
        // one go lost that frame here.
        request_to_send.extend_from_slice(&request_buf[header_end..]);

        jni_log!(
            "[DEBUG:local-proxy] Rewrote WebSocket request line: {}",
            new_line.trim()
        );

        // Open iroh bi-stream and send the modified request
        let (pooled_conn, mut send, mut recv) =
            open_stream_with_retry(endpoint_group, host, Some(&request_to_send), Protocol::Http)
                .await?;

        // One tunnel is one flow, and it stays counted until the
        // handler this sits in returns — see the CONNECT branch.
        let flow = pooled_conn.enter_flow(FlowMeta {
            kind: FlowKind::WebSocket,
            target: Some(host.to_string()),
            source: peer.clone(),
        });
        flow.record_sent(request_to_send.len() as u64);
        let count_to_backend = flow.counter();
        let count_from_backend = flow.counter();

        let (mut client_read, mut client_write) = tokio::io::split(stream);
        jni_log!(
            "[DEBUG:local-proxy] WebSocket request sent to iroh: {} bytes",
            request_to_send.len()
        );

        // Bidirectional forwarding (no send.finish() — keep stream open)
        //
        // The buffer the head was read into becomes the client half's
        // buffer: a connection holds two of them — one per direction —
        // rather than three.
        let header_buf = std::mem::take(&mut temp_buf);
        let client_to_iroh = async move {
            let mut buf = header_buf;
            let mut ws_buffer = Vec::new();
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => {
                        jni_log!("[DEBUG:local-proxy] WS client EOF");
                        return "client_eof";
                    }
                    Ok(n) => {
                        // Payload, not metadata: it costs a preview to
                        // build and it is the user's traffic, so it is
                        // only worth it while debugging.
                        if debug_log_enabled() {
                            jni_log!(
                                "[DEBUG:local-proxy] WS client->iroh: {}",
                                websocket_frame_preview(&buf[..n])
                            );
                        }
                        // The buffer only feeds the dumps above, and it
                        // only empties once a whole frame is in it: a
                        // client that sends a frame header and then
                        // nothing would grow it forever, logs or no
                        // logs. So the decode is part of what is
                        // switched off with them.
                        if debug_log_enabled() {
                            if ws_frame_buffer_append(&mut ws_buffer, &buf[..n]) {
                                let mut frames = Vec::new();
                                parse_websocket_frames(&mut ws_buffer, &mut frames);
                                for (opcode, payload) in frames {
                                    if opcode == 1 || opcode == 8 {
                                        jni_log!(
                                            "[DEBUG:local-proxy] WS client frame decoded \
                                             (opcode {}): {}",
                                            opcode,
                                            String::from_utf8_lossy(&payload)
                                        );
                                    }
                                }
                            } else {
                                // The frame is never finished, so the
                                // bytes are held for a frame that will
                                // not arrive. They are dropped rather
                                // than kept: the dump is a preview of
                                // 256 bytes, and a peer that sends a
                                // header and then nothing would
                                // otherwise grow this without end.
                                ws_buffer.clear();
                                jni_log!(
                                    "[DEBUG:local-proxy] WS client frame over {} bytes \
                                     and never finished, dropping it",
                                    WS_FRAME_BUFFER_LIMIT
                                );
                            }
                        }
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            jni_log!("[DEBUG:local-proxy] WS client->backend err: {}", e);
                            return "client_write_error";
                        }
                        count_to_backend.record_sent(n as u64);
                    }
                    Err(e) => {
                        jni_log!("[DEBUG:local-proxy] WS client read error: {}", e);
                        return "client_read_error";
                    }
                }
            }
        };

        let iroh_to_client = async move {
            let mut buf = vec![0u8; STREAM_BUF_SIZE];
            let mut first = true;
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) => {
                        jni_log!("[DEBUG:local-proxy] WS iroh EOF");
                        return "iroh_eof";
                    }
                    Ok(Some(n)) => {
                        if first {
                            first = false;
                            let p = &buf[..std::cmp::min(n, 200)];
                            if debug_log_enabled() {
                                jni_log!(
                                    "[DEBUG:local-proxy] WS first response: {}",
                                    String::from_utf8_lossy(p)
                                );
                            }
                        }
                        if debug_log_enabled() {
                            jni_log!(
                                "[DEBUG:local-proxy] WS iroh->client: {}",
                                websocket_frame_preview(&buf[..n])
                            );
                        }
                        if n <= 1024 && debug_log_enabled() {
                            jni_log!(
                                "[DEBUG:local-proxy] WS iroh->client decoded: {}",
                                String::from_utf8_lossy(&buf[..n])
                            );
                        }
                        if client_write.write_all(&buf[..n]).await.is_err() {
                            return "client_write_error";
                        }
                        count_from_backend.record_received(n as u64);
                        let _ = client_write.flush().await;
                    }
                    Err(e) => {
                        jni_log!("[DEBUG:local-proxy] WS iroh read error: {}", e);
                        return "iroh_read_error";
                    }
                }
            }
        };

        let mut client_task = tokio::spawn(client_to_iroh);
        let mut backend_task = tokio::spawn(iroh_to_client);
        // See the CONNECT branch: this dies with the handler, and with
        // it both halves of the WebSocket tunnel.
        let _tasks = TunnelTasks(vec![
            client_task.abort_handle(),
            backend_task.abort_handle(),
        ]);

        let (closed_direction, close_reason) = tokio::select! {
            result = &mut client_task => {
                ("client_to_iroh", result.unwrap_or("client_task_panicked"))
            }
            result = &mut backend_task => {
                ("iroh_to_client", result.unwrap_or("backend_task_panicked"))
            }
            // Asked to end: not an error, and not one of the two
            // directions going quiet either.
            _ = flow.cancelled() => ("closed", "closed_by_request"),
        };

        if closed_direction == "client_to_iroh" {
            backend_task.abort();
        } else {
            client_task.abort();
        }
        jni_log!(
            "[DEBUG:local-proxy] WebSocket tunnel closed first by {} ({})",
            closed_direction,
            close_reason
        );

        Ok(())
    }
}

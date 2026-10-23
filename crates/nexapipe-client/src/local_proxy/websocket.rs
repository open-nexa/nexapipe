//! The WebSocket frames, as far as they are looked at.
//!
//! The frames themselves are not touched: the bytes are moved as they are.
//! What is here is the preview a debug log prints, which is the only reason
//! the tunnel looks inside a frame at all.

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

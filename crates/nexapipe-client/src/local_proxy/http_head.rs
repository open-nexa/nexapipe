//! The head of an HTTP request, and the headers that travel with it.
//!
//! The client reads the head off the socket before it knows what the request
//! is, so the reading is the careful part: a head that is too large is
//! refused, a head that never ends is given up on, and the headers that go
//! upstream are the ones that mean something for the message rather than for
//! the hop.

#[cfg(feature = "jni")]
use crate::jni_log;

use tokio::io::AsyncReadExt;

/// Where the request line ends, in the bytes of a request's header block.
///
/// The end is the first **line feed**, whether it came with a carriage return
/// or not: a bare LF ends the line for a parser that accepts one, and
/// looking for "\r\n" instead would step over the first header as well — and
/// the header it steps over is the `Host` one, which says which name the
/// request is for. The server substitutes the backend's address for a
/// request that arrives without one, and a request for a name is then served
/// by the wrong site.
///
/// Returns the offset of the line feed, so the line itself ends at
/// `offset + 1`; zero when there is no line feed at all, which is a header
/// block that never had a request line.
pub(super) fn request_line_end(request: &[u8]) -> usize {
    request.iter().position(|b| *b == b'\n').unwrap_or(0)
}

/// The headers of a request, with the values that carry credentials replaced.
///
/// Logging them whole put `Authorization` and `Cookie` into logcat on every
/// request. Names and non-sensitive values are still what makes a dump useful
/// when debugging, so only the values are dropped.
pub(super) fn redacted_headers(headers: &::http::HeaderMap) -> String {
    let mut out = String::from("{");
    for (name, value) in headers {
        let lowered = name.as_str().to_lowercase();
        if SENSITIVE_HEADER_WORDS
            .iter()
            .any(|word| lowered.contains(word))
        {
            out.push_str(&format!("{}: <redacted>, ", name));
        } else {
            out.push_str(&format!("{}: {:?}, ", name, value));
        }
    }
    out.push('}');
    out
}

/// Whether what has been read of a request is over [`MAX_REQUEST_HEADER`].
///
/// The cap is on the header, not on the request: a small header followed by a
/// body of any size is an ordinary upload, so what is measured is what precedes
/// the terminator. Until one arrives, everything read so far is header as far as
/// anyone can tell — which is the case that bounds a peer that never ends one.
pub(super) fn header_over_limit(request: &[u8], header_end: Option<usize>) -> bool {
    header_end.unwrap_or(request.len()) > MAX_REQUEST_HEADER
}

/// What reading a request head produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HeaderOutcome {
    /// The head is complete, ending at this offset into the buffer.
    Complete(usize),
    /// The connection should be closed: the caller went away, the head went past
    /// its size cap, or the deadline expired. One value rather than three
    /// because every one of them is answered the same way, and a caller that had
    /// to tell them apart would only be able to log the difference.
    Closed,
}

/// Reads a request head up to its `\r\n\r\n`, bounded by one deadline.
///
/// The deadline is a parameter rather than something read from the environment
/// here, for two reasons: the caller has already taken the instant for the first
/// byte and the rest of the head shares it, and a test can then drive this over
/// a `tokio::io::duplex` pair in milliseconds instead of waiting out the
/// production thirty seconds.
///
/// Extracted from the connection handler so the anti-slowloris property is
/// testable on its own. Under the per-read timeout this replaces, a caller
/// sending one byte before each expiry renewed the deadline on every read and
/// was never disconnected — which is precisely what the test below pins.
///
/// The buffer is the caller's, not one of its own: a request used to allocate
/// two 32 KiB buffers to read one head, and the second was thrown away as soon
/// as the head was complete.
pub(super) async fn read_http_header<S>(
    stream: &mut S,
    request_buf: &mut Vec<u8>,
    temp_buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> HeaderOutcome
where
    S: tokio::io::AsyncRead + Unpin,
{
    // Already complete in what the first read carried, e.g. a header that
    // arrived whole. Checked before any read so a request that needed none is
    // not charged a deadline it did not need.
    let mut header_end = request_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4);

    // The same cap as the loop, applied to what already arrived: a header that
    // came in one read never enters the loop and would escape the limit.
    if header_over_limit(request_buf, header_end) {
        jni_log!("[DEBUG:local-proxy] Request header over the limit, closing connection");
        return HeaderOutcome::Closed;
    }

    while header_end.is_none() {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut *temp_buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                jni_log!("[DEBUG:local-proxy] Read error: {}", e);
                return HeaderOutcome::Closed;
            }
            Err(_) => {
                jni_log!(
                    "[DEBUG:local-proxy] Request head did not arrive before its deadline, closing \
                     connection"
                );
                return HeaderOutcome::Closed;
            }
        };

        let prev_len = request_buf.len();
        request_buf.extend_from_slice(&temp_buf[..n]);

        // Search for \r\n\r\n, starting a few bytes before the new data: a
        // terminator can straddle two reads.
        let search_start = prev_len.saturating_sub(3);
        if let Some(pos) = request_buf[search_start..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
        {
            header_end = Some(search_start + pos + 4);
        }

        // A peer that keeps sending without ever ending its headers grows this
        // buffer without bound, and the deadline alone does not stop it: it is
        // sending, just not finishing.
        if header_over_limit(request_buf, header_end) {
            jni_log!("[DEBUG:local-proxy] Request header over the limit, closing connection");
            return HeaderOutcome::Closed;
        }
    }

    match header_end {
        Some(pos) => HeaderOutcome::Complete(pos),
        None => {
            jni_log!("[DEBUG:local-proxy] HTTP header end not found, closing connection");
            HeaderOutcome::Closed
        }
    }
}

/// The header block with the fields that must not be forwarded taken out.
///
/// `keep_upgrade` keeps `Upgrade` and `Connection`, which is what the
/// WebSocket request is about: the upgrade is the point of it, and a backend
/// that does not see it does not switch protocols.
///
/// The names `Connection` nominates go as well — RFC 9110 §7.6.1 makes that
/// header a list of the names that are hop-by-hop for this message — so a
/// `Connection: X-Secret` does not carry `X-Secret` on.
///
/// The two cache-validation headers go too: they make the origin answer with
/// a 304 and an empty body, which the proxy has no way to fill.
pub(super) fn filter_request_headers(block: &[u8], keep_upgrade: bool) -> Vec<u8> {
    let nominated = nominated_hop_by_hop(block);

    // The input always ends with \r\n\r\n (the HTTP header terminator,
    // up to header_end). We iterate over each header line and preserve the
    // original \r\n\r\n terminator, so the body (appended separately) starts
    // at the right position.
    let mut result = Vec::with_capacity(block.len());
    let mut start = 0;

    while let Some(pos) = block[start..].windows(2).position(|w| w == b"\r\n") {
        let line_end = start + pos;
        let line = &block[start..line_end];

        if !is_dropped_header(line, keep_upgrade, &nominated) {
            result.extend_from_slice(line);
            result.extend_from_slice(b"\r\n");
        }

        start = line_end + 2;
    }

    // Loop already preserved the \r\n\r\n terminator — don't add an extra one
    result
}

/// The header names `Connection` nominates as hop-by-hop.
///
/// RFC 9110 §7.6.1: `Connection` lists the names that are hop-by-hop for
/// this message, so a `Connection: X-Secret` means `X-Secret` must not be
/// forwarded either.
fn nominated_hop_by_hop(block: &[u8]) -> Vec<Vec<u8>> {
    let mut nominated = Vec::new();
    let mut start = 0;

    while let Some(pos) = block[start..].windows(2).position(|w| w == b"\r\n") {
        let line_end = start + pos;
        let line = &block[start..line_end];

        if let Some(value) = header_value(line, b"connection") {
            for token in value.split(|b| *b == b',') {
                let token: Vec<u8> = token
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect();
                if !token.is_empty() {
                    nominated.push(token.to_ascii_lowercase());
                }
            }
        }

        start = line_end + 2;
    }

    nominated
}

/// The name of a header line, lower-cased, or `None` when the line is not a
/// header.
///
/// A name with a space in it is not a name: the request line is the one line
/// that can carry a colon without being a header (`GET /a:b HTTP/1.1`), and it
/// is not a header at all.
fn header_name(line: &[u8]) -> Option<Vec<u8>> {
    let colon = line.iter().position(|b| *b == b':')?;
    let name = &line[..colon];
    if name.is_empty() || name.iter().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// The value of a header line, when the line is that header.
fn header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let colon = line.iter().position(|b| *b == b':')?;
    if !line[..colon].eq_ignore_ascii_case(name) {
        return None;
    }
    Some(&line[colon + 1..])
}

/// Whether a header line must not be forwarded.
fn is_dropped_header(line: &[u8], keep_upgrade: bool, nominated: &[Vec<u8>]) -> bool {
    if is_cache_validation_header(line) {
        return true;
    }

    let Some(name) = header_name(line) else {
        return false;
    };

    // The upgrade is the point of a WebSocket request, so it stays there.
    if keep_upgrade && (name == b"upgrade" || name == b"connection") {
        return false;
    }

    if HOP_BY_HOP_HEADERS.iter().any(|hop| name == hop.as_bytes()) {
        return true;
    }

    nominated.iter().any(|token| token == &name)
}

/// Whether a header line is one of the two cache-validation headers.
///
/// **The two names are checked separately**, each against its own length.
/// They are four bytes apart — `if-modified-since:` is eighteen, `if-none-match:`
/// is fourteen — so a single length guard for both would be the length of the
/// longer one, and the shorter header's smallest forms would fall through it:
/// `If-None-Match: *` is sixteen bytes and `If-None-Match: ""` is seventeen.
/// Those are exactly the requests the origin answers with a 304 and an empty
/// body, which is what this is here to prevent.
fn is_cache_validation_header(line: &[u8]) -> bool {
    starts_with_ignore_case(line, b"if-modified-since:")
        || starts_with_ignore_case(line, b"if-none-match:")
}

/// Whether `line` starts with `prefix`, ignoring ASCII case.
///
/// Without allocating: the header name is ASCII, and the comparison is
/// against a fixed prefix.
fn starts_with_ignore_case(line: &[u8], prefix: &[u8]) -> bool {
    line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// The words in a header name that mean its value is a credential.
///
/// A list of exact names is a list that has to be extended every time an
/// application invents its own header for a token — `X-Auth-Token`,
/// `X-Session-Id`, `X-Api-Key` — and a debug log that prints those in the
/// clear is the same leak the list was meant to stop. A name that carries one
/// of these words is redacted whatever else it says.
///
/// The cost is that a name which merely *contains* one of them is redacted
/// too: `Sec-WebSocket-Key` is a nonce rather than a credential, and it is
/// hidden anyway. That is the right way round for a debug dump — a value
/// that is hidden when it did not need to be costs an argument, and a value
/// that is printed when it did costs a credential.
///
/// The words are the ones that name a credential outright. A name that says
/// nothing of the sort — `X-Jwt`, `X-Otp`, `X-Csrf-Token` is caught by
/// `token` but `X-Csrf` is not — is still printed, and that is the edge of
/// the rule: a word list is a word list, and the point is that it no longer
/// has to be a list of names.
const SENSITIVE_HEADER_WORDS: [&str; 8] = [
    "auth",
    "token",
    "secret",
    "key",
    "session",
    "cookie",
    "password",
    "credential",
];

/// Largest request header the local proxy collects, before it gives up on a
/// peer that never ends one. Same order as the server's own head limit, and
/// far above any real request: what it bounds is a client that keeps the
/// connection open and dribbles bytes into it.
pub(super) const MAX_REQUEST_HEADER: usize = 64 * 1024;

/// The header names a proxy must not forward.
///
/// RFC 9110 §7.6.1: these describe one connection rather than the message, so
/// they belong to the hop the proxy is on and not to the one behind it.
/// `Proxy-Authorization` is the one that matters most here — it is a
/// credential for *this* proxy, and forwarding it hands that credential to a
/// third-party server.
///
/// `Transfer-Encoding` is deliberately **not** in the list. It is hop-by-hop,
/// and the rule says a proxy removes it — but only because the proxy is
/// expected to re-frame the body. This one does not: the client's bytes cross
/// the tunnel verbatim, so removing the header would leave a chunked body
/// with nothing saying it is chunked.
const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

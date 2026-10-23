use ::http::Request;
use std::collections::HashMap;

#[cfg(feature = "jni")]
use crate::jni_log;

/// No-op `jni_log!` for builds without the `jni` feature.
///
/// The format arguments are still *evaluated* (borrowed) inside a dead branch,
/// so the optimiser removes the call but `unused_variables` does not fire on
/// variables that only ever appear inside a log statement.
#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if false {
            let _ = ::std::format_args!($($arg)*);
        }
    };
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct HttpRequest {
    method: String,
    path: String,
    host: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: &str, path: &str, host: &str) -> Self {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            host: host.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// The host this request is for.
    ///
    /// The host is what picks the server: the domain mapping is keyed by it,
    /// so a caller that wants a different server sends a different host.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", self.method, self.path).as_bytes());
        buf.extend_from_slice(format!("Host: {}\r\n", self.host).as_bytes());

        for (name, value) in &self.headers {
            buf.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }

        if !self.body.is_empty() {
            buf.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }

        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.body);
        buf
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct HttpResponse {
    status_code: u16,
    status_text: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn parse(response: &[u8]) -> Result<Self, crate::error::ClientError> {
        // The head is split off by *bytes*, not by counting characters of a
        // lossy decode: `from_utf8_lossy` replaces every invalid byte with one
        // U+FFFD, which is three bytes where the response had one, so a head
        // carrying any non-UTF-8 byte produced an offset past the real body and
        // sliced the wrong bytes out of it. Locating the terminator in the raw
        // bytes removes the whole class — the decode below is only ever used to
        // read header text, never to measure it.
        let Some(head_len) = find_head_end(response) else {
            // No terminator: everything received is headers, so there is no body.
            return Err(crate::error::ClientError::ParseError(
                "No header terminator in response".to_string(),
            ));
        };

        let head = String::from_utf8_lossy(&response[..head_len]);
        let mut lines = head.split("\r\n");

        let status_line = lines.next().ok_or_else(|| {
            crate::error::ClientError::ParseError("Missing status line".to_string())
        })?;

        let status_parts: Vec<&str> = status_line.split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err(crate::error::ClientError::ParseError(
                "Invalid status line".to_string(),
            ));
        }

        let status_code = status_parts[1].parse::<u16>().map_err(|e| {
            crate::error::ClientError::ParseError(format!("Invalid status code: {}", e))
        })?;

        let status_text = if status_parts.len() > 2 {
            status_parts[2..].join(" ")
        } else {
            String::new()
        };

        let mut headers = HashMap::new();
        for line in lines {
            // The final split element is empty: the terminator ends the head.
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_lowercase(), value.trim().to_string());
            }
        }

        Ok(HttpResponse {
            status_code,
            status_text,
            headers,
            body: response[head_len..].to_vec(),
        })
    }
}

/// Length of the head, terminator included, or `None` when the head never ends.
///
/// Searches for `\r\n\r\n` in the raw bytes. A lone `\n\n` is deliberately not
/// accepted: this parses what the server crate itself writes, and that writes
/// CRLF.
fn find_head_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// The body of a request, and how much of it is still to come.
///
/// The head of a request says how long its body is — or says that the body
/// is chunked, which is a framing rather than a length. A request that says
/// neither has no body at all: RFC 9112 §6.3 gives a message with no framing
/// header a body of zero bytes.
///
/// The distinction is what tells a body from a second request. The bytes that
/// follow a head are the body's if the head declares one, and the head of
/// another request if it does not — and a second request is one that the
/// list of proxied domains was never consulted about.
#[derive(Debug, Clone)]
pub enum Body {
    /// No body: not one byte may follow the head.
    None,
    /// A body of a known length: this many bytes may still follow.
    Length {
        /// How many bytes of the body are still to come.
        left: u64,
    },
    /// A chunked body: the framing says where it ends.
    Chunked(Chunked),
}

impl Body {
    /// What the request declares about the bytes that may follow its head.
    ///
    /// A request that declares nothing has no body, and a request whose
    /// length cannot be read has none either: the bytes that follow such a
    /// head are not the body's, and treating them as if they were is what
    /// lets a second request through.
    pub fn declared(request: &Request<()>) -> Self {
        // A transfer encoding means the body is chunked: the framing, not a
        // number, says where it ends.
        if request.headers().contains_key("transfer-encoding") {
            return Body::Chunked(Chunked::default());
        }

        // A length says how many bytes may follow. Two lengths that disagree
        // are a request that cannot be framed, and a length that cannot be
        // read is one either.
        let mut length: Option<u64> = None;
        for value in request.headers().get_all("content-length") {
            let Ok(text) = value.to_str() else {
                return Body::None;
            };
            let Ok(number) = text.trim().parse::<u64>() else {
                return Body::None;
            };
            match length {
                Some(seen) if seen != number => return Body::None,
                _ => length = Some(number),
            }
        }

        match length {
            Some(left) => Body::Length { left },
            None => Body::None,
        }
    }

    /// How many of `bytes` are the body's; the rest are not.
    ///
    /// The bytes that are not the body's are the head of another request, or
    /// whatever else the client sent after this one.
    pub fn take(&mut self, bytes: &[u8]) -> usize {
        match self {
            Body::None => 0,
            Body::Length { left } => {
                let taken = std::cmp::min(*left, bytes.len() as u64);
                *left -= taken;
                taken as usize
            }
            Body::Chunked(chunked) => chunked.take(bytes),
        }
    }

    /// Whether the body is over: not one byte of it may follow.
    pub fn is_complete(&self) -> bool {
        match self {
            Body::None => true,
            Body::Length { left } => *left == 0,
            Body::Chunked(chunked) => chunked.is_complete(),
        }
    }
}

/// Where a chunked body is in its own framing.
///
/// The end of a chunked body is not a number: it is the framing itself — a
/// zero-size chunk and then the trailers. A client that wants to know where
/// the body ends, and therefore where the next request would begin, has to
/// read the framing.
#[derive(Debug, Clone)]
pub struct Chunked {
    state: ChunkState,
    /// The line being read: a chunk's size, or a trailer's line.
    line: Vec<u8>,
}

#[derive(Debug, Clone)]
enum ChunkState {
    /// The size of the next chunk, up to the line feed that ends it.
    Size,
    /// The chunk's own bytes.
    Data {
        /// How many bytes of the chunk are still to come.
        left: u64,
    },
    /// The line feed that ends the chunk's bytes.
    ChunkEnd,
    /// The trailers, line by line; the empty line ends them.
    Trailer,
    /// The body is over.
    Done,
}

impl Default for Chunked {
    /// A body whose framing has not been read yet: the first size line is
    /// what comes next.
    fn default() -> Self {
        Chunked {
            state: ChunkState::Size,
            line: Vec::new(),
        }
    }
}

impl Chunked {
    /// How many of `bytes` are still the body's.
    pub fn take(&mut self, bytes: &[u8]) -> usize {
        let mut taken = 0;
        for &byte in bytes {
            // The body is over: the rest is not the body's.
            if matches!(self.state, ChunkState::Done) {
                break;
            }
            taken += 1;

            let state = std::mem::replace(&mut self.state, ChunkState::Done);
            self.state = match state {
                ChunkState::Size => {
                    self.line.push(byte);
                    if byte == b'\n' {
                        match chunk_size(&self.line) {
                            // The last chunk: the trailers end the body.
                            Some(0) => {
                                self.line.clear();
                                ChunkState::Trailer
                            }
                            Some(size) => {
                                self.line.clear();
                                ChunkState::Data { left: size }
                            }
                            // A size that cannot be read is a framing that
                            // cannot be followed: the body ends here, and
                            // whatever follows is not the body's.
                            None => ChunkState::Done,
                        }
                    } else if self.line.len() > MAX_CHUNK_SIZE_LINE {
                        ChunkState::Done
                    } else {
                        ChunkState::Size
                    }
                }
                ChunkState::Data { mut left } => {
                    left -= 1;
                    if left == 0 {
                        ChunkState::ChunkEnd
                    } else {
                        ChunkState::Data { left }
                    }
                }
                ChunkState::ChunkEnd => {
                    // The line feed that ends the chunk's bytes. The
                    // carriage return before it is a byte of its own.
                    if byte == b'\n' {
                        ChunkState::Size
                    } else {
                        ChunkState::ChunkEnd
                    }
                }
                ChunkState::Trailer => {
                    self.line.push(byte);
                    if byte == b'\n' {
                        if is_empty_line(&self.line) {
                            ChunkState::Done
                        } else {
                            self.line.clear();
                            ChunkState::Trailer
                        }
                    } else if self.line.len() > MAX_TRAILER_LINE {
                        ChunkState::Done
                    } else {
                        ChunkState::Trailer
                    }
                }
                ChunkState::Done => ChunkState::Done,
            };
        }
        taken
    }

    /// Whether the body is over.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, ChunkState::Done)
    }
}

/// The size a chunk's size line says, if it says one.
///
/// The line is the size and, maybe, an extension: `1*HEXDIG [ ";" chunk-ext ]`.
fn chunk_size(line: &[u8]) -> Option<u64> {
    let line = line.strip_suffix(b"\n")?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let size = match line.iter().position(|byte| *byte == b';') {
        Some(at) => &line[..at],
        None => line,
    };
    let text = std::str::from_utf8(size).ok()?.trim();
    u64::from_str_radix(text, 16).ok()
}

/// Whether a line is the empty line that ends the trailers.
fn is_empty_line(line: &[u8]) -> bool {
    line == b"\r\n" || line == b"\n"
}

/// The longest size line a chunked body may have.
///
/// The size is a number and the extension is a string, and neither is worth
/// more than this: a longer line is a framing that cannot be followed, and
/// the body ends where the line stops fitting.
const MAX_CHUNK_SIZE_LINE: usize = 1024;

/// The longest trailer line a chunked body may have.
///
/// The same order as the header the head reader allows, and for the same
/// reason: it bounds what a peer can make the proxy hold on to.
const MAX_TRAILER_LINE: usize = 64 * 1024;

pub fn parse_http_request_legacy(buf: &[u8]) -> Result<Request<()>, crate::error::ClientError> {
    let request_str = String::from_utf8_lossy(buf);
    let mut lines = request_str.split("\r\n");

    let request_line = lines.next().ok_or_else(|| {
        crate::error::ClientError::ParseError(
            "Invalid HTTP request: missing request line".to_string(),
        )
    })?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(crate::error::ClientError::ParseError(
            "Invalid HTTP request line".to_string(),
        ));
    }

    let method = http::Method::from_bytes(parts[0].as_bytes()).map_err(|e| {
        crate::error::ClientError::ParseError(format!("Invalid HTTP method: {}", e))
    })?;
    let uri = http::Uri::try_from(parts[1])
        .map_err(|e| crate::error::ClientError::ParseError(format!("Invalid URI: {}", e)))?;

    let mut builder = Request::builder().method(method).uri(uri);

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    Ok(builder.body(())?)
}

pub fn is_websocket_request_static(req: &Request<()>) -> bool {
    let upgrade_header = req.headers().get("upgrade");
    let connection_header = req.headers().get("connection");

    jni_log!(
        "[DEBUG:http] WebSocket detection - upgrade header: {:?}",
        upgrade_header.map(|h| h.to_str().ok())
    );
    jni_log!(
        "[DEBUG:http] WebSocket detection - connection header: {:?}",
        connection_header.map(|h| h.to_str().ok())
    );

    if let Some(upgrade) = upgrade_header
        && let Ok(upgrade_str) = upgrade.to_str()
        && upgrade_str.to_lowercase() == "websocket"
    {
        jni_log!("[DEBUG:http] WebSocket detection - upgrade header is websocket");
        if let Some(connection) = connection_header
            && let Ok(connection_str) = connection.to_str()
        {
            jni_log!(
                "[DEBUG:http] WebSocket detection - connection header: {}",
                connection_str
            );
            let contains_upgrade = connection_str.to_lowercase().contains("upgrade");
            jni_log!(
                "[DEBUG:http] WebSocket detection - contains upgrade: {}",
                contains_upgrade
            );
            return contains_upgrade;
        }
    }
    jni_log!("[DEBUG:http] WebSocket detection - returning false");
    false
}

#[cfg(test)]
mod tests {
    use super::{Body, HttpResponse, parse_http_request_legacy};

    /// A request that declares no body has none, whatever its method says.
    ///
    /// RFC 9112 §6.3: a message with no framing header has a body of zero
    /// bytes. So the bytes that follow such a head are not the body's — they
    /// are the head of another request, and the list of proxied domains was
    /// never consulted about that one.
    #[test]
    fn a_request_without_a_framing_header_has_no_body() {
        let request = parse_http_request_legacy(b"POST / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        assert!(body.is_complete(), "the request declares no body");
        assert_eq!(
            body.take(b"GET /b HTTP/1.1\r\nHost: other.test\r\n\r\n"),
            0,
            "the bytes that follow a bodiless head are not the body's"
        );
    }

    /// A length of zero is no body either.
    #[test]
    fn a_length_of_zero_is_no_body() {
        let request = parse_http_request_legacy(
            b"POST / HTTP/1.1\r\nHost: example.test\r\ncontent-length: 0\r\n\r\n",
        )
        .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        assert!(body.is_complete(), "a body of zero bytes is no body");
        assert_eq!(body.take(b"GET /b HTTP/1.1\r\n"), 0);
    }

    /// A length says how many bytes may follow the head.
    #[test]
    fn a_declared_length_is_the_body() {
        let request = parse_http_request_legacy(
            b"POST / HTTP/1.1\r\nHost: example.test\r\ncontent-length: 5\r\n\r\n",
        )
        .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        assert!(!body.is_complete(), "the body has not come yet");
        assert_eq!(body.take(b"hello"), 5, "the five bytes are the body's");
        assert!(body.is_complete(), "the body is over");
        assert_eq!(
            body.take(b"GET /b HTTP/1.1\r\n"),
            0,
            "the bytes past the body are not the body's"
        );
    }

    /// A body that is shorter than it declares is still the body's: the
    /// length says how much may follow the head, not that all of it is
    /// there already.
    #[test]
    fn a_body_shorter_than_its_length_is_still_the_body() {
        let request = parse_http_request_legacy(
            b"POST / HTTP/1.1\r\nHost: example.test\r\ncontent-length: 11\r\n\r\n",
        )
        .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        assert_eq!(body.take(b"hello"), 5, "the first bytes are the body's");
        assert!(!body.is_complete(), "the body is not over yet");
        assert_eq!(body.take(b" world"), 6, "the rest of it is the body's too");
        assert!(body.is_complete(), "the body is over");
    }

    /// A length that cannot be read is not a length: the request cannot be
    /// framed, so the bytes that follow its head are not its body's.
    #[test]
    fn a_length_that_cannot_be_read_is_no_body() {
        let request = parse_http_request_legacy(
            b"POST / HTTP/1.1\r\nHost: example.test\r\ncontent-length: many\r\n\r\n",
        )
        .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        assert!(
            body.is_complete(),
            "a request that cannot be framed has no body"
        );
        assert_eq!(body.take(b"GET /b HTTP/1.1\r\n"), 0);
    }

    /// Two lengths that disagree cannot be framed either.
    #[test]
    fn two_lengths_that_disagree_are_no_body() {
        let request = parse_http_request_legacy(
            b"POST / HTTP/1.1\r\nHost: example.test\r\ncontent-length: 5\r\ncontent-length: 6\r\n\r\n",
        )
        .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        assert!(
            body.is_complete(),
            "a request that cannot be framed has no body"
        );
        assert_eq!(body.take(b"GET /b HTTP/1.1\r\n"), 0);
    }

    /// A chunked body ends where its framing says it does.
    #[test]
    fn a_chunked_body_ends_where_the_framing_says() {
        let request = parse_http_request_legacy(
            b"POST / HTTP/1.1\r\nHost: example.test\r\ntransfer-encoding: chunked\r\n\r\n",
        )
        .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        let framing = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(
            body.take(framing),
            framing.len(),
            "the framing is the body's"
        );
        assert!(body.is_complete(), "the body is over");
        assert_eq!(
            body.take(b"GET /b HTTP/1.1\r\n"),
            0,
            "the bytes past the body are not the body's"
        );
    }

    /// The framing is read as it arrives, and a framing split across two
    /// reads is still followed: the copy loop reads whatever the socket
    /// hands it, and the size line does not arrive in one piece.
    #[test]
    fn a_chunked_framing_split_across_reads_is_still_followed() {
        let request = parse_http_request_legacy(
            b"POST / HTTP/1.1\r\nHost: example.test\r\ntransfer-encoding: chunked\r\n\r\n",
        )
        .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        assert_eq!(body.take(b"5\r\nhel"), 6, "the size and part of the chunk");
        assert!(!body.is_complete(), "the chunk is not over yet");
        assert_eq!(body.take(b"lo\r\n"), 4, "the rest of the chunk");
        assert!(!body.is_complete(), "the last chunk has not come yet");
        assert_eq!(body.take(b"0\r\n\r\n"), 5, "the last chunk ends the body");
        assert!(body.is_complete(), "the body is over");
    }

    /// A chunked body may carry trailers, and they are part of it.
    #[test]
    fn a_chunked_body_with_trailers_ends_after_them() {
        let request = parse_http_request_legacy(
            b"POST / HTTP/1.1\r\nHost: example.test\r\ntransfer-encoding: chunked\r\n\r\n",
        )
        .expect("a well-formed request parses");

        let mut body = Body::declared(&request);

        let framing = b"0\r\nX-Note: here\r\n\r\n";
        assert_eq!(body.take(framing), framing.len());
        assert!(body.is_complete(), "the body is over");
        assert_eq!(body.take(b"GET /b HTTP/1.1\r\n"), 0);
    }

    /// A header value is bytes, not text, and a Latin-1 one is what a broken
    /// or binary backend actually sends.
    ///
    /// The head used to be measured off `from_utf8_lossy`, which turns each
    /// invalid byte into one U+FFFD — three bytes in UTF-8 — so every offset
    /// after it drifted by two and the body was sliced out of the middle of the
    /// headers. One such byte in a header is enough.
    #[test]
    fn a_non_utf8_byte_in_a_header_does_not_move_the_body_start() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        // 0xFF is not valid UTF-8 anywhere.
        raw.extend_from_slice(b"X-Note: caf\xe9\r\n");
        raw.extend_from_slice(b"Content-Length: 5\r\n");
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(b"hello");

        let response = HttpResponse::parse(&raw).expect("a Latin-1 header still parses");

        assert_eq!(
            response.body(),
            b"hello",
            "the body is what followed the head"
        );
        assert_eq!(
            response.headers().get("content-length").map(String::as_str),
            Some("5")
        );
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn a_plain_response_still_parses() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nX-A: 1\r\n\r\n{\"ok\":true}";

        let response = HttpResponse::parse(raw).expect("a well-formed response parses");

        assert_eq!(response.status_code(), 201);
        assert_eq!(response.status_text(), "Created");
        assert_eq!(
            response.headers().get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(response.headers().get("x-a").map(String::as_str), Some("1"));
        assert_eq!(response.body(), b"{\"ok\":true}");
    }

    /// A response with no body still ends its head with the terminator, and an
    /// empty body must not be mistaken for a missing one.
    #[test]
    fn an_empty_body_parses_as_empty() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";

        let response = HttpResponse::parse(raw).expect("a bodiless response parses");

        assert_eq!(response.status_code(), 204);
        assert!(response.body().is_empty());
    }

    /// A head that never terminates is a truncated response, not one whose body
    /// happens to be empty — reporting it as the latter would hand the caller a
    /// success it cannot act on.
    #[test]
    fn an_unterminated_head_is_an_error() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";

        assert!(HttpResponse::parse(raw).is_err());
    }

    /// The header terminator is the first one, so a body containing the same
    /// bytes must not be mistaken for the end of the head.
    #[test]
    fn a_terminator_inside_the_body_does_not_end_the_head() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
        raw.extend_from_slice(b"part1\r\n\r\npart2");

        let response = HttpResponse::parse(&raw).expect("the head ends at the first terminator");

        assert_eq!(response.body(), b"part1\r\n\r\npart2");
    }
}

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
    use super::HttpResponse;

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

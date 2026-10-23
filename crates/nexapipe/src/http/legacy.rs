//! The hand-written HTTP/1 parser.
//!
//! The **request** is hyper's now: the tunnel path runs on hyper's codec, so
//! the head is parsed by hyper and there is nothing left to parse by hand.
//!
//! The **response** is still read here, because it is the backend's answer to
//! a WebSocket upgrade — and that one is read off a connection of its own,
//! before hyper is involved at all.

use ::http::Response;

pub fn parse_http_response_legacy(response: &[u8]) -> Result<Response<Vec<u8>>, anyhow::Error> {
    // The end of the header block is looked for in the bytes, never measured
    // off a decoded string: `from_utf8_lossy` turns each invalid byte into
    // U+FFFD, which is three bytes in UTF-8, so every offset computed from the
    // decoded text drifts by two per bad byte and the body started — or ended
    // — in the wrong place. A header with a single non-UTF-8 byte was enough
    // to hand the caller a body sliced out of the middle of the headers.
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response: no end of headers"))?;
    let body_start = header_end + 4;

    // Only the head is decoded, so nothing below can produce an offset again.
    let head = String::from_utf8_lossy(&response[..header_end]);
    let mut lines = head.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response: missing status line"))?;

    let status_parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code = if status_parts.len() >= 2 {
        status_parts[1]
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid status code: {}", e))?
    } else {
        500
    };

    let mut builder = Response::builder().status(status_code);

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    let body = response[body_start..].to_vec();

    Ok(builder.body(body)?)
}

/// Whether the request names more than one host.
///
/// RFC 9110 §7.2: *"A server MUST respond with a 400 (Bad Request) status code
/// to any HTTP/1.1 request message that contains more than one Host header
/// field."*
///
/// This is not pedantry. A request with two `Host` headers is a request whose
/// destination is ambiguous, and the two halves of this proxy used to resolve
/// that ambiguity differently: the route and the access check read the **first**
/// one, and the backend was handed **both**. A client that was allowed for
/// `allowed.example.com` could therefore send that name first and a second
/// name behind it, and a backend that picks the last one would serve the
/// second name's vhost to a request that was authorised for the first.
///
/// Neither of the two listeners this server has can lean on its HTTP parser to
/// catch it: the plaintext one uses hyper, which accepts two `Host` headers
/// and passes them both on, and the tunnel one parses the head by hand. So
/// both check here, and both answer 400.
pub fn names_more_than_one_host(headers: &::http::HeaderMap) -> bool {
    headers.get_all("host").iter().count() > 1
}

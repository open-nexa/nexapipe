//! The hand-written HTTP/1 parser.
//!
//! The tunnel path cannot use hyper's own codec, because it has to have the
//! whole head before it can answer — and hyper's server consumes the head
//! as it parses it. So the request is parsed here, by hand, and a response is
//! read back the same way.

use ::http::{Request, Response};

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

/// The request as it arrived, parsed out of the bytes.
///
/// The head only, because the body is read separately and this is the only
/// place the head exists as bytes.
///
/// A request that names more than one host is refused here rather than
/// downstream: the route and the access check read the first `Host` header,
/// and the backend would be handed all of them, so the request that is
/// authorised and the request that is served would be two different requests.
/// See [`names_more_than_one_host`].
pub fn parse_http_request_legacy(buf: &[u8]) -> Result<Request<()>, anyhow::Error> {
    let request_str = String::from_utf8_lossy(buf);
    let mut lines = request_str.split("\r\n");

    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP request: missing request line"))?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("invalid HTTP request line"));
    }

    let method = http::Method::from_bytes(parts[0].as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid HTTP method: {}", e))?;
    let uri = http::Uri::try_from(parts[1]).map_err(|e| anyhow::anyhow!("invalid URI: {}", e))?;

    let mut builder = Request::builder().method(method).uri(uri);
    let mut hosts = 0usize;

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("host") {
                hosts += 1;
                if hosts > 1 {
                    return Err(anyhow::anyhow!(
                        "the request carries more than one Host header"
                    ));
                }
            }
            builder = builder.header(name, value.trim());
        }
    }

    Ok(builder.body(())?)
}

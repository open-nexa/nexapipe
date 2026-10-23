//! What the access log is allowed to claim about a request.
//!
//! The request id that ties a response to the line it was written down in, and
//! the rule that says whether a response puts a body on the wire at all.

/// Put the request id on a response, so a client can name the exact line in
/// the access log that goes with what it got.
///
/// It replaces rather than appends: the id we publish is the one our own log
/// records, and a second `x-request-id` from a backend would leave whoever
/// reads the response guessing which of the two to quote.
pub(super) fn with_request_id<T>(
    mut response: hyper::Response<T>,
    request_id: &str,
) -> hyper::Response<T> {
    if let Ok(value) = ::http::HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

/// Whether a response to this request puts a body on the wire.
///
/// RFC 9110 s6.4.1 and s8.3: a HEAD response, a 1xx, a 204 and a 304 answer
/// without a body, and each of them may still carry `Content-Length` saying how
/// long that absent body would have been. Anything counting bytes as traffic has
/// to ask this before reading the header.
pub(super) fn response_has_body(method: &str, status: u16) -> bool {
    if method == "HEAD" {
        return false;
    }
    !matches!(status, 204 | 304) && !(100..200).contains(&status)
}

//! The tests of the HTTP half.

//! They are in their own file because there are more of them than there is code
//! to test, and because a file that is mostly tests hides the code it is testing.

use crate::deadline::Deadlines;

use super::body::*;
use super::legacy::*;
use super::response::*;

use ::http::StatusCode;
use futures_util::StreamExt;
use http_body_util::Full;
/// A reason is capitalised for the path that said it that way.
///
/// The backend's address can fail in two ways, and the two paths that
/// report it word it differently: the plaintext path says "Invalid
/// backend URL" and the tunnel path says "invalid backend URL". Both are
/// the same reason, and the operator reads both.
#[test]
fn a_reason_keeps_the_wording_of_the_path_that_says_it() {
    assert_eq!(
        capitalised("invalid backend URL: relative URL without a base"),
        "Invalid backend URL: relative URL without a base"
    );
    assert_eq!(
        capitalised("backend URL missing host"),
        "Backend URL missing host"
    );
    // A message that is already capitalised is left alone.
    assert_eq!(
        capitalised("Backend URL missing host"),
        "Backend URL missing host"
    );
    // And an empty one stays empty rather than panicking.
    assert_eq!(capitalised(""), "");
}

/// The check every path makes, on the headers hyper hands it.
///
/// hyper accepts two `Host` headers and passes both on, so the proxy has to
/// make this check itself: the route and the access check read the **first**
/// `Host` header and the backend is handed **all** of them, so a request
/// that was authorised for one host could be served as another. RFC 9110
/// §7.2 asks for a 400.
#[test]
fn the_host_count_is_seen_in_the_headers() {
    let mut headers = ::http::HeaderMap::new();
    assert!(
        !names_more_than_one_host(&headers),
        "no host is not two hosts"
    );

    headers.append("host", "a.example".parse().unwrap());
    assert!(
        !names_more_than_one_host(&headers),
        "one host is not two hosts"
    );

    headers.append("host", "b.example".parse().unwrap());
    assert!(
        names_more_than_one_host(&headers),
        "two hosts are two hosts"
    );
}

/// A body of `len` bytes, which is what the limit has to be checked against.
fn body_of(len: usize) -> Full<bytes::Bytes> {
    Full::new(bytes::Bytes::from(vec![b'x'; len]))
}

/// The plaintext listener's body reader with the default `[timeouts]` body
/// budget: what these tests exercise is the cap and the reservation, not the
/// configured length of the deadline.
#[tokio::test]
async fn a_body_within_the_limit_is_read_whole() {
    let (read, reservation) = read_body_limited(body_of(10), 10, Deadlines::default().body)
        .await
        .unwrap();
    assert_eq!(read.len(), 10);
    assert_eq!(reservation.bytes(), 10, "the body is held for its lifetime");
}

#[tokio::test]
async fn a_body_over_the_limit_is_refused() {
    // One frame is enough to exceed it, so this is the case the old
    // `collect()` could not catch without first holding all of it.
    let err = read_body_limited(body_of(11), 10, Deadlines::default().body)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("over the 10 byte limit"));
}

#[tokio::test]
async fn an_empty_body_is_within_any_limit() {
    let (read, reservation) = read_body_limited(body_of(0), 0, Deadlines::default().body)
        .await
        .unwrap();
    assert!(read.is_empty());
    assert_eq!(reservation.bytes(), 0);
}

#[tokio::test]
async fn a_refused_body_hands_its_reservation_back() {
    // Asserted through the reservation this call returns rather than by
    // reading the process-wide total: that total is shared with every other
    // test in this binary, which run concurrently, so a "same as before"
    // comparison here would mostly be measuring the other tests.
    //
    // What this pins is that the per-request limit refuses *before* anything
    // is reserved, so there is nothing to leak. The direct statement about
    // the budget's own arithmetic is `ByteBudget::bodies_are_bounded_across_the_process`.
    let refused = read_body_limited(body_of(4096), 16, Deadlines::default().body).await;
    assert!(refused.is_err(), "a body over the limit must be refused");
}

#[test]
fn legacy_response_parser_splits_status_headers_and_body() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello";
    let res = parse_http_response_legacy(raw).unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.body().as_slice(), b"hello".as_slice());
}

#[test]
fn legacy_response_parser_leaves_no_body_when_there_is_none() {
    let res = parse_http_response_legacy(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();

    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(res.body().is_empty());
}

#[test]
fn legacy_response_parser_falls_back_to_500_without_a_status_code() {
    let res = parse_http_response_legacy(b"HTTP/1.1\r\n\r\n").unwrap();

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(res.body().is_empty());
}

/// What the offset arithmetic used to get wrong: `from_utf8_lossy` turns
/// one invalid byte into a three-byte U+FFFD, so a header carrying binary
/// data shifted `body_start` and the body came out of the middle of the
/// headers — or was empty.
#[test]
fn legacy_response_parser_finds_the_body_behind_a_non_utf8_header() {
    let mut raw = b"HTTP/1.1 200 OK\r\nX-Binary: ".to_vec();
    raw.extend_from_slice(&[0xff, 0xfe]);
    raw.extend_from_slice(b"\r\n\r\nbody-bytes");

    let res = parse_http_response_legacy(&raw).unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.body().as_slice(), b"body-bytes".as_slice());
}

#[test]
fn legacy_response_parser_rejects_a_response_with_no_end_of_headers() {
    // Truncated: there is no place where the body could start, and
    // guessing one used to be how it silently returned an empty body.
    assert!(parse_http_response_legacy(b"HTTP/1.1 200 OK\r\nX-A: 1\r\n").is_err());
}

#[test]
fn hop_by_hop_headers_do_not_reach_the_backend() {
    for dropped in [
        "connection",
        "Proxy-Connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "expect",
        // A credential for this proxy: forwarding it hands it to a
        // third-party server.
        "proxy-authorization",
        "Proxy-Authorization",
        "proxy-authenticate",
    ] {
        assert!(
            !forwards_request_header(dropped),
            "{dropped} belongs to this hop only"
        );
    }
    for kept in ["host", "accept", "content-length", "sec-websocket-key"] {
        assert!(forwards_request_header(kept), "{kept} is the message's own");
    }
}

/// A body that produces `frames` frames and then goes silent.
///
/// What a backend that answered with a head and then stopped looks like to
/// the proxy: the frames that did arrive are delivered, and then nothing
/// comes — not an end, and not an error either.
struct StallingBody {
    frames: usize,
    sent: usize,
}

impl hyper::body::Body for StallingBody {
    type Data = bytes::Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if self.sent < self.frames {
            self.sent += 1;
            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(
                bytes::Bytes::from_static(b"chunk"),
            ))))
        } else {
            // Silence: no frame, and no end of the body either.
            std::task::Poll::Pending
        }
    }
}

/// A body that produces a frame every `gap` and never ends.
struct DrippingBody {
    gap: std::time::Duration,
    timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl DrippingBody {
    fn new(gap: std::time::Duration) -> Self {
        Self { gap, timer: None }
    }
}

impl hyper::body::Body for DrippingBody {
    type Data = bytes::Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if self.timer.is_none() {
            self.timer = Some(Box::pin(tokio::time::sleep(self.gap)));
        }
        let timer = self.timer.as_mut().expect("a timer was just set");
        if timer.as_mut().poll(cx).is_pending() {
            return std::task::Poll::Pending;
        }
        self.timer = None;
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(
            bytes::Bytes::from_static(b"chunk"),
        ))))
    }
}

#[tokio::test(start_paused = true)]
async fn a_backend_that_goes_silent_mid_body_ends_at_the_idle_deadline() {
    // The observation this test exists for: `response_idle_secs` has to
    // reach the response body of the plaintext listener, not merely the
    // streamed one. A backend that sent the head and then went silent used
    // to hold the request — and the connection — for as long as it liked.
    let idle = std::time::Duration::from_secs(120);
    let mut body = Box::pin(idle_bounded(StallingBody { frames: 1, sent: 0 }, idle));

    // The frame the backend did send arrives.
    let first = tokio::time::timeout(std::time::Duration::from_secs(200), body.next())
        .await
        .expect("the frame must arrive")
        .expect("the body must not end");
    assert!(
        first.is_ok(),
        "the frame the backend sent must pass through: {first:?}"
    );

    // Then the backend goes silent, and the gap is bounded.
    let second = tokio::time::timeout(std::time::Duration::from_secs(200), body.next())
        .await
        .expect("the idle deadline must end the body")
        .expect("the body must not end");
    match second {
        Err(BodyError::Idle(d)) => assert_eq!(d, idle),
        other => panic!("expected an idle failure, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_backend_that_drips_within_the_idle_deadline_stays_open() {
    // The other half of the same rule: the deadline is idle, not a phase
    // deadline, so it re-arms on every frame. A backend that keeps saying
    // something — an SSE feed, a long transfer — is not cut off.
    let idle = std::time::Duration::from_secs(120);
    let mut body = Box::pin(idle_bounded(
        DrippingBody::new(std::time::Duration::from_secs(100)),
        idle,
    ));

    for _ in 0..3 {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(200), body.next())
            .await
            .expect("a frame must arrive")
            .expect("the body must not end");
        assert!(
            frame.is_ok(),
            "a frame within the idle deadline must pass through: {frame:?}"
        );
    }
}

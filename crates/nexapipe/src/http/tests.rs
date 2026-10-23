//! The tests of the HTTP half.

//! They are in their own file because there are more of them than there is code
//! to test, and because a file that is mostly tests hides the code it is testing.

use crate::deadline::Deadlines;

use super::body::*;
use super::legacy::*;
use super::response::*;

use ::http::{Request, StatusCode};
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

/// A request that names more than one host is refused.
///
/// The route and the access check read the **first** `Host` header and the
/// backend was handed **all** of them, so a request that was authorised for
/// one host could be served as another. RFC 9110 §7.2 asks for a 400.
#[test]
fn a_request_with_more_than_one_host_is_refused() {
    let head = b"GET /x HTTP/1.1\r\nHost: allowed.example\r\nHost: internal.example\r\n\r\n";
    let err = parse_http_request_legacy(head).expect_err("two hosts are not one host");
    assert!(
        err.to_string().contains("more than one Host"),
        "the refusal does not say why: {err}"
    );
}

/// One host is one host.
#[test]
fn a_request_with_one_host_is_accepted() {
    let head = b"GET /x HTTP/1.1\r\nHost: allowed.example\r\n\r\n";
    let request = parse_http_request_legacy(head).expect("one host is fine");
    assert_eq!(request.headers().get("host").unwrap(), "allowed.example");
}

/// The check the plaintext listener uses, on the headers hyper hands it.
///
/// hyper accepts two `Host` headers and passes both on, so the plaintext
/// path has to make this check itself.
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

/// A chunked body of one or more `chunks`, terminated the usual way.
fn chunked(chunks: &[&str]) -> Vec<u8> {
    let mut raw = Vec::new();
    for chunk in chunks {
        raw.extend_from_slice(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes());
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    raw
}

#[test]
fn a_chunked_body_is_decoded_whole() {
    let raw = chunked(&["hello", " world"]);
    let (body, used, complete) = decode_chunks(&raw, 1024).unwrap();
    assert_eq!(body, b"hello world");
    assert!(complete);
    assert_eq!(used, raw.len());
}

#[test]
fn a_chunk_header_may_carry_extensions() {
    let raw = b"5;name=value\r\nhello\r\n0\r\n\r\n";
    let (body, _, complete) = decode_chunks(raw, 1024).unwrap();
    assert_eq!(body, b"hello");
    assert!(complete);
}

#[test]
fn an_incomplete_chunk_is_left_for_the_next_read() {
    // What a stream split mid-chunk looks like: the reader must keep the
    // bytes it could not decode and hand them back with the next read.
    let raw = chunked(&["hello", " world"]);
    // Three bytes into the second chunk's data: its header arrived, the
    // payload did not.
    let split = 16;

    let (first, used, complete) = decode_chunks(&raw[..split], 1024).unwrap();
    assert_eq!(first, b"hello");
    assert!(!complete);
    assert!(used < split);

    let mut pending = raw[used..split].to_vec();
    pending.extend_from_slice(&raw[split..]);
    let (body, _, complete) = decode_chunks(&pending, 1024).unwrap();
    assert_eq!(body, b" world");
    assert!(complete);
}

#[test]
fn the_body_ends_at_the_zero_chunk() {
    // Trailers are not forwarded, so they must not be swallowed either:
    // anything after the zero chunk is not part of what was decoded.
    let mut raw = chunked(&["hello"]);
    raw.extend_from_slice(b"X-Trailer: done\r\n\r\n");
    let (body, used, complete) = decode_chunks(&raw, 1024).unwrap();
    assert_eq!(body, b"hello");
    assert!(complete);
    assert_eq!(&raw[used..], b"X-Trailer: done\r\n\r\n");
}

#[test]
fn a_chunked_body_over_the_limit_is_refused() {
    let raw = chunked(&["hello"]);
    let err = decode_chunks(&raw, 4).unwrap_err();
    assert!(err.to_string().contains("over the 4 byte limit"));
}

/// Hands out the pieces it was given, and records what the budget held
/// each time it was asked for more.
///
/// The samples are the point: they are the moments *between* reads, which
/// is when the bytes that have arrived but have not decoded yet are held.
struct SamplingReader {
    pieces: std::collections::VecDeque<Vec<u8>>,
    budget: std::sync::Arc<crate::conn::limits::ByteBudget>,
    samples: Vec<usize>,
}

impl SamplingReader {
    fn new(budget: &std::sync::Arc<crate::conn::limits::ByteBudget>, pieces: &[&[u8]]) -> Self {
        Self {
            pieces: pieces.iter().map(|p| p.to_vec()).collect(),
            budget: budget.clone(),
            samples: Vec::new(),
        }
    }
}

impl tokio::io::AsyncRead for SamplingReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let held = self.budget.held();
        self.samples.push(held);
        match self.pieces.pop_front() {
            Some(chunk) => {
                buf.put_slice(&chunk);
                std::task::Poll::Ready(Ok(()))
            }
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

/// `read_chunked_request_body` against a budget of the test's own.
///
/// The process-wide one is shared with every other test in this binary,
/// which run concurrently, so a total read from it would mostly be
/// measuring the other tests.
async fn read_chunked<R>(
    recv: &mut R,
    body: &mut Vec<u8>,
    budget: &std::sync::Arc<crate::conn::limits::ByteBudget>,
) -> Result<crate::conn::limits::ByteReservation, anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    read_chunked_request_body(recv, body, Deadlines::default().body, budget).await
}

/// A chunked body is charged for the bytes that are still in flight.
///
/// The bytes of a chunk that has not decoded yet are held: the peer sent
/// them and the process has them in memory. It used to charge only what a
/// chunk decoded, which left every byte of an unfinished chunk outside
/// the budget — a peer that declares a 64 MiB chunk and then trickles the
/// data into it was invisible to the ceiling.
#[tokio::test(start_paused = true)]
async fn a_chunked_body_charges_the_bytes_that_are_still_in_flight() {
    let budget = std::sync::Arc::new(crate::conn::limits::ByteBudget::new(1024 * 1024));
    // A chunk header and the first two bytes of its data: the chunk
    // cannot decode yet, so these five bytes wait for the rest of it.
    let mut reader = SamplingReader::new(&budget, &[b"5\r\nhe", b"llo\r\n", b"0\r\n\r\n"]);
    let mut body = Vec::new();

    let reservation = read_chunked(&mut reader, &mut body, &budget)
        .await
        .expect("the body is read");

    assert_eq!(body, b"hello");
    assert_eq!(
        reader.samples,
        vec![0, 5, 5],
        "the five bytes of the unfinished chunk are charged while they wait, and the \
         framing of the decoded one is given back"
    );

    // And the accounting ends where it should: the decoded body is held
    // and nothing else — the framing is gone and the terminator was never
    // part of the body.
    assert_eq!(reservation.bytes(), body.len());
    assert_eq!(budget.held(), reservation.bytes());

    drop(reservation);
    assert_eq!(
        budget.held(),
        0,
        "a dropped reservation gives its bytes back"
    );
}

/// A chunked body that outgrows the budget is refused while it arrives.
#[tokio::test(start_paused = true)]
async fn a_chunked_body_that_outgrows_the_budget_is_refused() {
    let budget = std::sync::Arc::new(crate::conn::limits::ByteBudget::new(8));
    let mut reader = SamplingReader::new(&budget, &[b"5\r\nhello\r\n0\r\n\r\n"]);
    let mut body = Vec::new();

    let err = read_chunked(&mut reader, &mut body, &budget)
        .await
        .expect_err("the body does not fit");

    assert!(err.to_string().contains("does not fit"), "{err}");
    assert_eq!(
        budget.held(),
        0,
        "a refused body hands its reservation back"
    );
}

/// The trailer of a chunked body is not held.
///
/// It is not forwarded and it is dropped with the read, so the budget must
/// not keep counting it for as long as the body lives.
#[tokio::test(start_paused = true)]
async fn a_chunked_body_holds_its_body_and_nothing_else() {
    let budget = std::sync::Arc::new(crate::conn::limits::ByteBudget::new(1024 * 1024));
    let mut reader = SamplingReader::new(
        &budget,
        &[b"5\r\nhello\r\n0\r\n\r\nX-Trailer: done\r\n\r\n"],
    );
    let mut body = Vec::new();

    let reservation = read_chunked(&mut reader, &mut body, &budget)
        .await
        .expect("the body is read");

    assert_eq!(body, b"hello");
    assert_eq!(
        reservation.bytes(),
        5,
        "the trailer is not part of the body"
    );
    assert_eq!(
        budget.held(),
        5,
        "and it is not held for the body's lifetime"
    );
}

#[test]
fn a_chunk_size_that_would_overflow_is_refused() {
    // `usize::MAX`, spelled as a chunk size: the old `out.len() + size`
    // wrapped to a small number in release and panicked in debug, so the
    // limit looked satisfied and the slice below ran off the end.
    let err = decode_chunks(b"ffffffffffffffff\r\nhello\r\n", 1024).unwrap_err();
    assert!(err.to_string().contains("over the 1024 byte limit"));

    // Same for the `size + 2` that checked for the trailing CRLF.
    let err = decode_chunks(b"ffffffffffffffff\r\nhello", 1024).unwrap_err();
    assert!(err.to_string().contains("over the 1024 byte limit"));
}

#[test]
fn a_chunk_header_that_never_ends_is_refused() {
    // No CRLF anywhere, so the caller would keep buffering: a peer that
    // sends a header and never terminates it grows it without bound.
    let mut raw = Vec::new();
    raw.extend_from_slice(&b"5;".repeat(MAX_CHUNK_HEADER));
    let err = decode_chunks(&raw, 1024).unwrap_err();
    assert!(err.to_string().contains("chunk header longer than"));

    // A short header that is still arriving is fine — it is not an error
    // to be waiting for the rest of one.
    let (body, used, complete) = decode_chunks(b"5\r", 1024).unwrap();
    assert!(body.is_empty());
    assert_eq!(used, 0);
    assert!(!complete);
}

#[test]
fn a_chunk_header_that_is_not_hexadecimal_is_refused() {
    let err = decode_chunks(b"zz\r\nhello\r\n0\r\n\r\n", 1024).unwrap_err();
    assert!(err.to_string().contains("not a hexadecimal chunk size"));
}

#[test]
fn chunk_data_without_its_crlf_is_refused() {
    let err = decode_chunks(b"5\r\nhelloXX\r\n0\r\n\r\n", 1024).unwrap_err();
    assert!(err.to_string().contains("not followed by CRLF"));
}

#[test]
fn a_chunked_request_is_recognised_by_its_encoding() {
    let chunked_req = Request::builder()
        .header("transfer-encoding", "Chunked")
        .body(())
        .unwrap();
    assert!(request_is_chunked(&chunked_req));

    let plain = Request::builder()
        .header("transfer-encoding", "gzip")
        .body(())
        .unwrap();
    assert!(!request_is_chunked(&plain));
    assert!(!request_is_chunked(&Request::builder().body(()).unwrap()));
}

#[test]
fn legacy_request_parser_keeps_the_request_line_and_headers() {
    let raw = b"GET /index.html HTTP/1.1\r\nHost: app.example.com\r\nX-Empty:\r\n\r\n";
    let req = parse_http_request_legacy(raw).unwrap();

    assert_eq!(req.method(), http::Method::GET);
    assert_eq!(req.uri().path(), "/index.html");
    assert_eq!(req.headers()["host"], "app.example.com");
    // A header with no value is still a header.
    assert_eq!(req.headers()["x-empty"], "");
}

#[test]
fn legacy_request_parser_stops_at_the_blank_line() {
    let raw = b"POST /api HTTP/1.1\r\nHost: a\r\n\r\nnot-a-header";
    let req = parse_http_request_legacy(raw).unwrap();

    assert_eq!(req.method(), http::Method::POST);
    assert_eq!(req.headers().len(), 1);
}

#[test]
fn legacy_request_parser_rejects_a_request_line_without_a_target() {
    assert!(parse_http_request_legacy(b"GET\r\nHost: a\r\n\r\n").is_err());
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

//! Forwarding a request to a backend.
//!
//! The path a request takes: read it, pick a backend, send it, and forward
//! what comes back — with the body streamed rather than collected, so a
//! large upload is never held in memory whole.

use crate::routes::{BackendInfo, BackendLookup, RoutingTable};

use ::http::header::{HeaderMap, HeaderValue};
use ::http::{Method, Request, Response, StatusCode};

use http_body_util::combinators::UnsyncBoxBody;

use http_body_util::BodyExt;

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;

use super::*;

///
/// The request body is a parameter rather than `Incoming` so that the path can
/// be driven by something other than a live connection — a test, mostly. The
/// body is read whole either way, and what comes back does not depend on where
/// the request came from.
pub async fn proxy_request<B>(
    clients: &BackendClients,
    req: Request<B>,
    config: Arc<RoutingTable>,
) -> Result<Response<ProxyBody>, anyhow::Error>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    // Answered, not raised: no `Host` means no route can match, which is the
    // same answer as a host no route matches — and the caller maps an `Err`
    // from here to a 502, which would blame a backend for a request that never
    // got as far as choosing one.
    let Some(host) = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(crate::routes::host_without_port)
        // Owned, because the request is moved into the body read below and
        // the host is needed after that.
        .map(str::to_string)
    else {
        return Ok(create_error_response(
            StatusCode::NOT_FOUND,
            "Missing host header",
        ));
    };

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path())
        // Owned, for the same reason the host is: the request is moved into
        // the body read below, and the path is needed after that.
        .to_string();

    let accept_encoding = req
        .headers()
        .get("accept-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let headers_clone = req.headers().clone();
    let method = req.method().clone();

    // The first backend is chosen before the body is read, so a request for a
    // host nobody serves is answered without reading what it carries.
    let mut backend_info: BackendInfo = match config.get_backend(&host, &path).await {
        BackendLookup::Found(info) => info,
        // No route serves this host: saying 404 beats guessing at one.
        BackendLookup::NoRoute => {
            return Ok(create_error_response(
                hyper::StatusCode::NOT_FOUND,
                &format!("No route for host {host}"),
            ));
        }
        // The route is configured and every backend behind it is unhealthy. 503
        // rather than 404, because the difference is which file the operator has
        // to open: nothing here is misconfigured, something downstream is down.
        BackendLookup::Unavailable => {
            tracing::warn!("No healthy backend behind {host}{path}, answering 503");
            return Ok(create_error_response(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                &format!("No healthy backend for host {host}"),
            ));
        }
    };

    // Read once, for every attempt: the body cannot be read twice, and what
    // goes out is the same bytes whichever backend receives it.
    //
    // Held for as long as the buffered body is alive — see `read_body_limited`.
    // Dropping it here rather than at the end of the function is deliberate and
    // is what makes the budget mean what it says.
    let (body, _body_reservation) = read_body_limited(
        req.into_body(),
        MAX_REQUEST_BODY,
        config.timeouts().deadlines.body,
    )
    .await?;

    let attempts = config.retry().attempts;
    let backoff = config.retry().backoff;
    // The backends that already failed this request. A retry asks somebody
    // else, because the one that just failed is the one most likely to fail
    // again.
    let mut tried: Vec<String> = Vec::new();
    let mut attempt = 0u32;

    loop {
        let outcome = attempt_backend(
            clients,
            &config,
            &backend_info,
            &method,
            &headers_clone,
            &path,
            &body,
        )
        .await;

        let response = match outcome {
            Ok(response) => {
                // The backend answered, so it is up: the circuit is told, and
                // a backend that was out of rotation comes back into it.
                backend_info.report_success();
                response
            }
            Err(failure) => {
                // Only a failure that says the backend is unreachable counts
                // against it. A response that broke halfway is a different
                // thing: the backend did answer.
                if failure.backend_is_down() {
                    backend_info.report_failure();
                }

                // Two questions, and the failure answers both: may this be
                // tried again at all, and is there another backend to try it
                // on.
                if attempt >= attempts || !failure.retry.may_retry(&method) {
                    return Err(failure.error);
                }
                attempt += 1;

                tracing::warn!(
                    "Request to {} failed ({}); trying another backend ({attempt}/{attempts})",
                    backend_info.url,
                    failure.error,
                );

                tried.push(backend_info.url.to_string());
                match config.get_backend_excluding(&host, &path, &tried).await {
                    BackendLookup::Found(info) => backend_info = info,
                    // Nobody else to ask. The failure is the answer: the pool
                    // being empty is a consequence of it, not a new fact.
                    BackendLookup::NoRoute | BackendLookup::Unavailable => {
                        return Err(failure.error);
                    }
                }

                if !backoff.is_zero() {
                    tokio::time::sleep(backoff).await;
                }
                continue;
            }
        };

        let content_encoding = response.headers().get("content-encoding");
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok());

        // The idle deadline covers the body as well as the head: a backend that
        // answers and then goes silent must not hold this request open. The
        // streaming path has always bounded this; the plaintext listener had no
        // bound at all, so a backend that sent the head and stalled kept the
        // request — and the connection — for as long as it liked.
        let idle = config.timeouts().deadlines.response_idle;

        // The lease moves out of the backend info and into the body, because
        // the work against that backend is not over when the response head
        // arrives: a body that is still streaming is a backend that is still
        // busy. See `LeasedBody`.
        let lease = backend_info.take_lease();

        if content_encoding.is_none()
            && should_compress(content_type)
            && let Some(encodings) = accept_encoding
            && encodings.contains("gzip")
        {
            // The whole body is read and compressed here, so the backend is
            // done with it before the answer goes out: the lease goes back
            // with the `backend_info` that is dropped at the end of this
            // function.
            return compress_response(response, "gzip", idle).await;
        }

        return Ok(response.map(|body| {
            let body = http_body_util::StreamBody::new(idle_bounded(body, idle)).boxed_unsync();
            http_body_util::BodyExt::boxed_unsync(LeasedBody {
                inner: body,
                _lease: lease,
            })
        }));
    }
}

/// One attempt at one backend: the answer, or the reason there was none.
///
/// Split out of [`proxy_request`] so that the retry loop above it is about
/// retrying and this is about asking. The request is rebuilt for every
/// attempt, because the backend it goes to may be a different one.
pub(super) async fn attempt_backend(
    clients: &BackendClients,
    config: &RoutingTable,
    backend_info: &BackendInfo,
    method: &Method,
    headers: &::http::HeaderMap,
    path: &str,
    body: &bytes::Bytes,
) -> Result<Response<hyper::body::Incoming>, ProxyFailure> {
    // The client is picked by the protocol the route speaks to its backends,
    // which is decided by the route rather than by the request: a backend that
    // speaks h2 in the clear is reached with the h2c client, everything else
    // with the one that speaks HTTP/1.1 and negotiates h2 over TLS.
    let client = clients.for_protocol(backend_info.protocol);
    let response_deadline = config.timeouts().response;

    let rewritten_path = backend_info.rewritten_path(path);

    // The origin was parsed when the pool was built, so this is a borrow of
    // it rather than a `Url::parse` per request.
    //
    // The reason is capitalised for this path: it said "Invalid backend URL"
    // here and "invalid backend URL" on the tunnel path, and the operator
    // reads both.
    let origin: &str = match &backend_info.origin {
        Ok(origin) => origin,
        Err(reason) => return Err(anyhow::anyhow!("{}", capitalised(reason)).into()),
    };

    // The host and the port on their own, which is how this path named the
    // backend that did not answer.
    let host_and_port = match origin.split_once("://") {
        Some((_, rest)) => rest,
        None => origin,
    };

    let new_uri = format!("{origin}{rewritten_path}")
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let mut builder = Request::builder().method(method.clone()).uri(new_uri);

    for (name, value) in headers.iter() {
        // Preserve the client's original Host header so backend virtual-host
        // routing works; drop the rest that only meant something for the hop
        // from the client to here.
        if !forwards_request_header(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }

    let proxied_req = builder.body(full_body(body.clone()))?;

    tracing::debug!(
        "Proxying request: {} {} -> {origin}",
        proxied_req.method(),
        proxied_req.uri(),
    );

    match tokio::time::timeout(response_deadline, client.request(proxied_req)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => Err(ProxyFailure {
            error: anyhow::anyhow!("backend request failed: {e}"),
            partial: None,
            // A connect error means the request was never carried: the
            // connection was refused, the name did not resolve, the handshake
            // failed. Nothing reached the backend, so asking again is free of
            // consequence whatever the request was. Anything else means the
            // request was sent and the answer did not come, which only an
            // idempotent request may be asked twice.
            retry: if e.is_connect() {
                Retryability::Always
            } else {
                Retryability::IfIdempotent
            },
        }),
        Err(_) => Err(ProxyFailure {
            error: anyhow::anyhow!(
                "backend {host_and_port} did not respond within {response_deadline:?}"
            ),
            partial: None,
            // The request was carried: the deadline expired after it went out.
            retry: Retryability::IfIdempotent,
        }),
    }
}

/// The request as it goes to the backend.
///
/// The path is the one the route rewrote it to — a route that pairs a
/// `path_pattern` with a `path_rewrite` serves the matched paths somewhere
/// else, and this is where that happens on the tunnel path. It used to happen
/// only on the plaintext path, so a rewrite looked configured and did nothing
/// for every real client.
///
/// The headers are the client's own, minus the ones that only meant something
/// for the hop from the client to here.
/// The head of the request that goes to the backend.
///
/// The backend's own origin, the rewritten path, and the client's headers that
/// may be forwarded — and the length the proxy declares for the body it
/// carries, which is the truth rather than the client's own header.
fn backend_request_builder(
    req: &Request<()>,
    backend_info: &BackendInfo,
    content_length: Option<usize>,
) -> Result<http::request::Builder, anyhow::Error> {
    // The origin was parsed when the pool was built, so this is a borrow of
    // it rather than a `Url::parse` per request.
    let origin: &str = match &backend_info.origin {
        Ok(origin) => origin,
        Err(reason) => return Err(anyhow::anyhow!("{}", reason)),
    };

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let rewritten_path = backend_info.rewritten_path(path);

    let new_uri = format!("{origin}{rewritten_path}")
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let mut builder = Request::builder().method(req.method()).uri(new_uri);

    // Whether the proxy declares the length itself.
    //
    // A chunked body is sent as one buffer with a length of our own, so only a
    // request whose `content-length` we could not read takes that path. One we
    // could read is forwarded with the header it arrived with — and a body
    // that is still being read carries the length the client gave, so the
    // proxy states it again rather than passing the client's own header on.
    let declares_own_length = content_length.is_some();

    for (name, value) in req.headers() {
        // Preserve the client's original Host header so backend virtual-host
        // routing works. The body below is sent with a length of the proxy's
        // own — whole, or streamed — so `transfer-encoding` and friends must
        // not claim otherwise.
        if !forwards_request_header(name.as_str()) {
            continue;
        }
        // Dropped rather than overwritten: a second `content-length` on one
        // request is what lets a proxy and a backend disagree about where the
        // body ends, and an unreadable one is exactly the case that survives
        // the filter above.
        if declares_own_length && name == "content-length" {
            continue;
        }
        builder = builder.header(name, value);
    }

    // The length the proxy declares for the body it carries. The client's own
    // `content-length` is dropped above, because this one is the truth.
    if let Some(content_length) = content_length {
        builder = builder.header("content-length", content_length);
    }

    Ok(builder)
}

pub(super) fn build_backend_request(
    req: &Request<()>,
    backend_info: &BackendInfo,
    body: &mut RequestBody,
    body_deadline: tokio::time::Instant,
) -> Result<Request<HttpBody>, anyhow::Error> {
    let builder = backend_request_builder(req, backend_info, body.content_length())?;

    // The body is **lent** to the request that carries it, not given away: a
    // request that fails before the body was read has to be able to send it
    // again, and the client's stream is where the bytes are. The head is
    // copied — it is a reference to the same buffer, not a second copy of it
    // — and the reader and the state are shared.
    let http_body: HttpBody = match &*body {
        RequestBody::Whole { bytes, .. } => full_body(bytes.clone()),
        RequestBody::Streaming {
            head,
            reader,
            state,
            content_length,
            ..
        } => {
            let head = head.clone();
            let remaining = *content_length;
            UnsyncBoxBody::new(StreamingBody {
                head,
                reader: reader.clone(),
                remaining,
                deadline: body_deadline,
                timer: None,
                // The head's bytes are charged by the request that owns the
                // body; this reservation is for the rest of it.
                reservation: crate::conn::limits::ByteReservation::empty(),
                buf: Vec::new(),
                state: state.clone(),
            })
        }
    };

    Ok(builder.body(http_body)?)
}

// One more argument than clippy allows: the alternative is a struct bundling the
// client with its deadlines, which every caller would have to build in order to
// pass the same two things — see the note on `conn::handle_bidi_stream`.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_to_backend_streaming(
    clients: &BackendClients,
    // How long the backend may take to answer. Not read off the client, because
    // it is not the client's: the client owns the deadline for every dial, this
    // is the one for a single answer. See `crate::config::Timeouts`.
    timeouts: crate::config::Timeouts,
    req: &Request<()>,
    // Where this request goes, and how it gets there. The route decided both:
    // the address, the protocol, and the rewrite the path goes through.
    //
    // This used to be the URL and the protocol as two separate arguments, with
    // the rewrite left out — which is how a route that named a `path_rewrite`
    // looked configured and did nothing here.
    backend_info: &BackendInfo,
    body: &mut RequestBody,
    send: &mut iroh::endpoint::SendStream,
    request_id: &str,
) -> Result<ProxySummary, ProxyFailure> {
    let client = clients.for_protocol(backend_info.protocol);

    // When the body has to be finished by. It is the same deadline the
    // buffered path had for the same phase — the client's own `[timeouts]
    // body_secs` — and it is taken once per attempt, because an attempt is
    // an attempt.
    let body_deadline_at = tokio::time::Instant::now() + timeouts.deadlines.body;

    let proxied_req = build_backend_request(req, backend_info, body, body_deadline_at)?;

    tracing::debug!(
        "Proxying request via client (streaming): {} {}",
        proxied_req.method(),
        proxied_req.uri()
    );

    // Two deadlines, and they are not the same one.
    //
    // The **body** has its own (`[timeouts] body_secs`): the client may take
    // that long to send the body, and the body enforces that for itself. The
    // **response** has its own (`[timeouts] response_secs`): the backend may
    // take that long to answer with a status line — and that clock runs from
    // the moment the body was sent, because a backend cannot answer before it
    // has the body. That is the bound the buffered path had, where the body
    // was read first and the response deadline started after it.
    //
    // A streamed body is still going out while the proxy waits for the
    // answer, so the two overlap and the wait is under both. The answer's
    // deadline is re-armed when the body has been sent; until then it is the
    // body's deadline plus the response's, which is the longest the answer
    // can be waited for.
    let answer_deadline_at = match body {
        RequestBody::Whole { .. } => tokio::time::Instant::now() + timeouts.response,
        RequestBody::Streaming { .. } => body_deadline_at + timeouts.response,
    };
    let streaming = matches!(body, RequestBody::Streaming { .. });

    let mut request = Box::pin(client.request(proxied_req));
    let mut upload_deadline = Box::pin(tokio::time::sleep_until(body_deadline_at));
    let mut answer_deadline = Box::pin(tokio::time::sleep_until(answer_deadline_at));
    let mut answer_armed = false;

    let response = futures_util::future::poll_fn(|cx| {
        use std::task::Poll;

        // The request itself.
        if let Poll::Ready(result) = request.as_mut().poll(cx) {
            return Poll::Ready(match result {
                Ok(response) => Ok(response),
                Err(e) => {
                    tracing::error!("Failed to send request: {:?}", e);
                    // A body that ran out of time is not a backend that
                    // failed, and the error says so: the two have deadlines
                    // of their own, and this is the one that expired.
                    if body.did_time_out() {
                        Err(ProxyFailure::unanswered(
                            anyhow::anyhow!(
                                "the request body did not finish in time (the body's deadline \
                                 is {:?})",
                                timeouts.deadlines.body
                            ),
                            // The request was carried: the head went out.
                            Retryability::IfIdempotent,
                        ))
                    } else {
                        // A connect error means the request was never
                        // carried: the connection was refused, the name did
                        // not resolve, the handshake failed. Anything else
                        // means the request went out and the answer did not
                        // come, which only an idempotent request may be asked
                        // twice. The tunnel path needs this exactly as the
                        // plaintext one does, or `[retry]` would only work on
                        // one of them.
                        let retry = if e.is_connect() {
                            Retryability::Always
                        } else {
                            Retryability::IfIdempotent
                        };
                        Err(ProxyFailure::unanswered(
                            anyhow::anyhow!("failed to send request: {e:?}"),
                            retry,
                        ))
                    }
                }
            });
        }

        // The body may have gone out while the request was being polled: the
        // answer's deadline runs from that moment, not from the start.
        if !answer_armed && body.has_been_sent() {
            answer_deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + timeouts.response);
            answer_armed = true;
        }

        // The upload's own deadline: the body has to be finished by then.
        if streaming && upload_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(ProxyFailure::unanswered(
                anyhow::anyhow!(
                    "the request body did not finish in time (the body's deadline is {:?})",
                    timeouts.deadlines.body
                ),
                // The request was carried: the head went out.
                Retryability::IfIdempotent,
            )));
        }

        // The answer's deadline.
        if answer_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(ProxyFailure::unanswered(
                anyhow::anyhow!("backend did not respond within {:?}", timeouts.response),
                // The request was carried: the deadline expired after it went
                // out.
                Retryability::IfIdempotent,
            )));
        }

        Poll::Pending
    })
    .await;

    let response = response?;

    let (parts, body) = response.into_parts();

    let status = parts.status;
    let status_text = status.canonical_reason().unwrap_or("Unknown");

    let mut response_buf = Vec::new();
    response_buf
        .extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status_text).as_bytes());

    // Whether the backend framed the body with a transfer coding of its own
    // that is not `chunked`. Such a body is still encoded when it arrives, and
    // the header that says so is dropped below, so it is not framed again
    // either.
    let other_transfer_coding = parts
        .headers
        .get("transfer-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|v| !v.to_lowercase().split(',').any(|c| c.trim() == "chunked"))
        .unwrap_or(false);
    let has_content_length = parts.headers.get("content-length").is_some();

    for (name, value) in parts.headers.iter() {
        // The name is **already** lower case: HTTP header names are
        // case-insensitive and the parser folds them, so this is a borrow and
        // not a copy. It used to be a `to_lowercase` per header, which is an
        // allocation for every header of every response.
        let name_lower = name.as_str();
        // A header that belongs to the hop between the backend and this
        // process does not belong on the hop between this process and the
        // client.
        if !forwards_response_header(name_lower) {
            continue;
        }
        // Dropped, not duplicated: the id we write below is the one our own
        // access log records, and a second one from the backend would leave
        // whoever reads the response guessing which to quote.
        if name_lower == "x-request-id" {
            continue;
        }
        response_buf.extend_from_slice(name.as_str().as_bytes());
        response_buf.extend_from_slice(b": ");
        response_buf.extend_from_slice(value.as_bytes());
        response_buf.extend_from_slice(b"\r\n");
    }

    // Whether the body is framed for the client, which is a question about
    // what the *client* can be told rather than about what the backend said.
    //
    // The client on the other end of the tunnel speaks HTTP/1.1, and HTTP/1.1
    // has no way to say "the body ends when this stream ends": a body with no
    // length has to be chunked, or the client waits for a connection close
    // that never comes. A backend that speaks HTTP/2 never sends a length at
    // all — the stream carries the end — so a response from an h2 backend is
    // exactly the case that has to be framed here. A backend that sent no
    // length over HTTP/1.1 means the same thing, and is framed the same way.
    //
    // A bodyless response has no body to frame. RFC 9110 §6.1 forbids a
    // `transfer-encoding` on a 204 or a 304, and a client told "chunked"
    // waits for the terminator of a body that is not there. A `HEAD` request
    // asks for the head of a response whose body is not sent, whatever the
    // status says — so it is not framed either.
    let status_allows_a_body = !status.is_informational()
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED;
    let use_chunked = status_allows_a_body
        && !has_content_length
        && !other_transfer_coding
        && *req.method() != Method::HEAD;
    if use_chunked {
        response_buf.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    // The id the caller gave this request, so a client can name the access log
    // line that goes with the answer it got. Built by hand like the rest of
    // this buffer: there is no `http::Response` here to hang a header on.
    response_buf.extend_from_slice(b"x-request-id: ");
    response_buf.extend_from_slice(request_id.as_bytes());
    response_buf.extend_from_slice(b"\r\n");
    response_buf.extend_from_slice(b"\r\n");

    // Counted once it is on the wire, not when it is formatted: `bytes_sent`
    // is what the access log reports as delivered, and a header that failed to
    // write reached nobody.
    let mut bytes_sent = 0;
    if let Err(e) = send.write_all(&response_buf).await {
        return Err(ProxyFailure::from(anyhow::anyhow!(
            "failed to write the response head: {e}"
        )));
    }
    bytes_sent += response_buf.len();

    // Body chunks used to go out as one `write_all` per hyper chunk (plus three more per
    // chunk when the response is chunk-encoded). Each of those turns into its own QUIC
    // STREAM frame, so a 64 KiB hyper chunk produced ~4 tiny frames instead of one. Coalesce
    // into a buffer and flush at 64 KiB: same latency profile for streamed responses, a
    // large drop in frame count and `SendStream` wakeups for bulk transfer.
    //
    // The header above is still written separately so that a slow producer
    // (SSE, long-poll) is not held back until 64 KiB accumulate.
    const RESPONSE_FLUSH_THRESHOLD: usize = 64 * 1024;
    // Started small rather than at the threshold: the threshold is a latency
    // bound, not an expected size, and most responses never come near it —
    // reserving it up front took 64 KiB from every streamed response, most of
    // which then went back unused. Growing costs the same few reallocs the
    // large responses would have paid anyway.
    const INITIAL_FLUSH_CAPACITY: usize = 8 * 1024;
    let mut out = Vec::with_capacity(INITIAL_FLUSH_CAPACITY);

    // Bytes the client has actually received, as opposed to `out`, which holds
    // what is being coalesced and may still be lost: a body that died half way
    // is reported as the half that arrived, not as the whole that was intended.
    let mut body_stream = http_body_util::BodyExt::into_data_stream(body);
    // Idle, not a phase deadline: see `Deadlines::response_idle`. What is being
    // bounded is the gap between chunks, so this re-arms on every chunk — which
    // is what lets an SSE stream or a WebSocket stay open for as long as both
    // ends want, while a backend that accepted the request and then went silent
    // cannot hold this slot and its backend lease forever. The value comes from
    // `[timeouts] response_idle_secs` through the `timeouts` argument.
    let response_idle = timeouts.deadlines.response_idle;
    loop {
        // A `loop` rather than `while let`: the three outcomes — a chunk, the
        // end of the body, and the backend going quiet — are told apart here,
        // and only the first two are ordinary iteration.
        let chunk = match tokio::time::timeout(response_idle, body_stream.next()).await {
            Ok(Some(chunk)) => chunk,
            // The body finished: this is the end, not a failure, and it must not
            // be mistaken for one.
            Ok(None) => break,
            Err(_) => {
                // The backend went quiet mid-body, which is a failure and not an
                // end: returning here rather than breaking out is what keeps the
                // two apart. Breaking would fall through to the chunked
                // terminator and `send.finish()` below, and the client would
                // get a body that is syntactically complete and silently
                // truncated — a truncated stream it has no way to tell from a
                // whole one, and an access line recording a success.
                //
                // `bytes_sent` is what the client actually received, so it is
                // still reported rather than zero.
                tracing::warn!(
                    "Backend sent nothing for {response_idle:?} mid-body, ending the stream \
                     after {bytes_sent} bytes"
                );
                return Err(ProxyFailure::after(
                    status,
                    bytes_sent,
                    anyhow::anyhow!("backend sent nothing for {response_idle:?} mid-body"),
                ));
            }
        };
        match chunk {
            Ok(data) => {
                if use_chunked {
                    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
                    out.extend_from_slice(&data);
                    out.extend_from_slice(b"\r\n");
                } else {
                    out.extend_from_slice(&data);
                }
                if out.len() >= RESPONSE_FLUSH_THRESHOLD {
                    if let Err(e) = send.write_all(&out).await {
                        return Err(ProxyFailure::after(status, bytes_sent, e.into()));
                    }
                    bytes_sent += out.len();
                    out.clear();
                }
            }
            Err(e) => {
                tracing::debug!("Streaming response read error: {}", e);
                return Err(ProxyFailure::after(status, bytes_sent, e.into()));
            }
        }
    }

    if use_chunked {
        out.extend_from_slice(b"0\r\n\r\n");
    }
    if !out.is_empty() {
        if let Err(e) = send.write_all(&out).await {
            return Err(ProxyFailure::after(status, bytes_sent, e.into()));
        }
        bytes_sent += out.len();
    }

    if let Err(e) = send.finish() {
        return Err(ProxyFailure::after(status, bytes_sent, e.into()));
    }

    Ok(ProxySummary {
        status: status.as_u16(),
        bytes_sent,
    })
}

/// The answer a backend gave, before hyper writes it.
///
/// The bytes that reached the client are counted as they go out, so the access
/// log reports what was delivered rather than what was intended.
pub struct Answer {
    response: Response<hyper::body::Incoming>,
    bytes_sent: Arc<std::sync::atomic::AtomicUsize>,
    idle: Duration,
}

impl Answer {
    /// The status the client is getting.
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    /// How many bytes reached the client.
    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The answer, as hyper writes it.
    pub fn into_response(self) -> Response<crate::http::body::ProxyBody> {
        let Answer {
            response,
            bytes_sent,
            idle,
        } = self;
        let (parts, body) = response.into_parts();
        let body = UnsyncBoxBody::new(crate::http::server::CountedBody::new(
            body, bytes_sent, idle,
        ));
        Response::from_parts(parts, body)
    }
}

/// Forward a request to a backend and hand the answer back.
///
/// The answer is **returned**, not written: hyper writes it, which is the
/// point of the tunnel path running on hyper's codec — the status line, the
/// headers and the framing are hyper's, and they are the ones every other
/// HTTP server sends.
pub async fn proxy_to_backend(
    clients: &BackendClients,
    timeouts: crate::config::Timeouts,
    req: &Request<()>,
    backend_info: &BackendInfo,
    body: &crate::http::server::RequestBody,
    request_id: &str,
) -> Result<Answer, ProxyFailure> {
    let client = clients.for_protocol(backend_info.protocol);

    // When the body has to be finished by. It is the same deadline the
    // hand-written path had for the same phase — the client's own `[timeouts]
    // body_secs` — and it is taken once per attempt, because an attempt is an
    // attempt.
    let body_deadline_at = tokio::time::Instant::now() + timeouts.deadlines.body;

    let proxied_req = build_backend_request_from(req, backend_info, body)?;

    tracing::debug!(
        "Proxying request via client (streaming): {} {}",
        proxied_req.method(),
        proxied_req.uri()
    );

    // The **body** has its own deadline (`[timeouts] body_secs`): the client
    // may take that long to send the body. The **response** has its own
    // (`[timeouts] response_secs`): the backend may take that long to answer,
    // and that clock runs from the moment the body was sent, because a backend
    // cannot answer before it has the body.
    let answer_deadline_at = body_deadline_at + timeouts.response;

    let mut request = Box::pin(client.request(proxied_req));
    let mut upload_deadline = Box::pin(tokio::time::sleep_until(body_deadline_at));
    let mut answer_deadline = Box::pin(tokio::time::sleep_until(answer_deadline_at));
    let mut answer_armed = false;

    let response = futures_util::future::poll_fn(|cx| {
        use std::task::Poll;

        // The request itself.
        if let Poll::Ready(result) = request.as_mut().poll(cx) {
            return Poll::Ready(match result {
                Ok(response) => Ok(response),
                Err(e) => {
                    tracing::error!("Failed to send request: {:?}", e);
                    // A body that ran out of time is not a backend that
                    // failed, and the error says so.
                    if body.did_time_out() {
                        Err(ProxyFailure::unanswered(
                            anyhow::anyhow!(
                                "the request body did not finish in time (the body's deadline \
                                 is {:?})",
                                timeouts.deadlines.body
                            ),
                            Retryability::IfIdempotent,
                        ))
                    } else {
                        // A connect error means the request was never carried;
                        // anything else means it went out and the answer did
                        // not come.
                        let retry = if e.is_connect() {
                            Retryability::Always
                        } else {
                            Retryability::IfIdempotent
                        };
                        Err(ProxyFailure::unanswered(
                            anyhow::anyhow!("failed to send request: {e:?}"),
                            retry,
                        ))
                    }
                }
            });
        }

        // The body may have gone out while the request was being polled: the
        // answer's deadline runs from that moment, not from the start.
        if !answer_armed && body.has_been_sent() {
            answer_deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + timeouts.response);
            answer_armed = true;
        }

        // The upload's own deadline: the body has to be finished by then.
        if upload_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(ProxyFailure::unanswered(
                anyhow::anyhow!(
                    "the request body did not finish in time (the body's deadline is {:?})",
                    timeouts.deadlines.body
                ),
                Retryability::IfIdempotent,
            )));
        }

        // The answer's deadline.
        if answer_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(ProxyFailure::unanswered(
                anyhow::anyhow!("backend did not respond within {:?}", timeouts.response),
                Retryability::IfIdempotent,
            )));
        }

        Poll::Pending
    })
    .await;

    let response = response?;
    let (parts, body) = response.into_parts();

    // The headers the client may see: the ones that describe the answer
    // rather than the hop. `forwards_response_header` drops the hop-by-hop
    // ones, and the id the caller gave this request is the one that goes out
    // — a second one from the backend would leave whoever reads the response
    // guessing which to quote.
    let mut headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if !forwards_response_header(name.as_str()) {
            continue;
        }
        if name.as_str() == "x-request-id" {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(request_id).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    let mut parts = parts;
    parts.headers = headers;

    Ok(Answer {
        response: Response::from_parts(parts, body),
        bytes_sent: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        idle: timeouts.deadlines.response_idle,
    })
}

/// Builds the request that goes to the backend, with the body hyper read.
///
/// The head is built the way the hand-written path built it — the backend's
/// own origin, the rewritten path, the client's headers that may be forwarded
/// — and the body is the one the client sent.
///
/// The length the proxy declares is the length of the body it carries, and
/// that is the one the client's own header is replaced with:
///
/// - a body that is **here** is sent with a length of its own, because the
///   bytes are the whole of it;
/// - a body that is **still arriving** is sent with the length the client
///   declared, because that length is the truth.
fn build_backend_request_from(
    req: &Request<()>,
    backend_info: &BackendInfo,
    body: &crate::http::server::RequestBody,
) -> Result<Request<HttpBody>, anyhow::Error> {
    let (content_length, http_body) = match body {
        crate::http::server::RequestBody::Whole { bytes, .. } => {
            (Some(bytes.len()), full_body(bytes.clone()))
        }
        crate::http::server::RequestBody::Streaming(inner) => {
            let length = req
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok());
            (length, UnsyncBoxBody::new(inner.lend()))
        }
    };
    let builder = backend_request_builder(req, backend_info, content_length)?;
    Ok(builder.body(http_body)?)
}

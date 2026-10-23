//! The tunnel path, served by hyper's own HTTP/1 codec.
//!
//! # What this is
//!
//! The tunnel path used to read the request head off the iroh stream by hand,
//! parse it by hand, read the body by hand, and write the answer by hand —
//! the status line, the headers, the framing, all of it assembled into a
//! buffer and pushed at the socket. Hyper does all of that, and does it the
//! way every other HTTP server does it, so the bytes on the wire are the bytes
//! a client expects from any other server.
//!
//! What is **not** hyper's is in here: which route serves a name, whether
//! this peer may use it, which backend it goes to, how a failure is retried,
//! what the access log says. Those are this project's rules, and they are the
//! same rules they were before.
//!
//! # How the two protocols get here
//!
//! A connection that named its protocol with ALPN says what it carries:
//! `nexapipe/http` is HTTP and `nexapipe/l4` is a tunnel. Nothing is sniffed
//! and nothing is read twice.
//!
//! A connection that named the old ALPN does not say, so the first byte is
//! read to find out: `0x05` is an L4 preface, `0x16` is a TLS hello, and
//! anything else is a request line. That one byte is **handed back** to hyper
//! with the rest of the stream, so hyper reads the head from the beginning
//! and nothing is lost or parsed twice.
//!
//! That is the one thing the ALPN change bought: the protocol is known
//! before a byte is read, so the codec does not have to guess.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};

use crate::auth::ClientAcl;
use crate::conn::peers::PeerIdentity;
use crate::http::client::BackendClients;
use crate::http::client::BoxError;
use crate::http::forward::Answer;
use crate::http::response::BodyError;
use crate::hyper_io::IrohIo;
use crate::routes::{BackendInfo, BackendLookup, RoutingTable};

/// The largest request head hyper will buffer.
///
/// The hand-written parser refused a head over 64 KiB, and it refused it
/// *before* forwarding anything: a head that large is not a request, and a
/// peer that sends one is not one to be given a backend.
pub const MAX_HEAD: usize = 64 * 1024;

/// What the service needs to answer a request.
///
/// Everything here is the tunnel path's own rules. The connection's peer and
/// its credentials travel with the request because the service runs once per
/// request, on a connection that may carry several.
pub struct Context {
    /// The routes, and the timeouts they carry.
    pub config: Arc<RoutingTable>,
    /// The clients the backends are reached through.
    pub clients: Arc<BackendClients>,
    /// Where the connection came from, for the access log.
    pub peer: String,
    /// Who may use which route. `None` when there is no allow list.
    pub acl: Option<Arc<ClientAcl>>,
    /// The id of this request, for the access log and the `x-request-id` header.
    pub request_id: String,
    /// Who the connection authenticated as, for the access log.
    pub who: PeerIdentity,
}

/// Serve one iroh bi-stream as HTTP.
///
/// The stream is handed to hyper whole: hyper reads the head, hands the
/// service a request, and writes the answer the service returns. Nothing is
/// read out of the stream and put back.
pub async fn serve(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    ctx: Arc<Context>,
) -> anyhow::Result<()> {
    let io = IrohIo::new(send, recv);
    let service_ctx = ctx.clone();
    let service = service_fn(move |req| handle(req, service_ctx.clone()));

    hyper::server::conn::http1::Builder::new()
        // The deadline below is measured with this.
        .timer(crate::hyper_io::TokioTimer)
        // The head has to arrive within the head budget: a peer that opens a
        // stream and sends nothing must not hold the slot forever. The same
        // bound the hand-written reader applied, and hyper applies it to the
        // head rather than to every read.
        .header_read_timeout(ctx.config.timeouts().deadlines.header)
        // A head over this is not a request.
        .max_buf_size(MAX_HEAD)
        // The client finishes its half of the stream once the request is out
        // and waits for the answer, which is what a tunnel client does and what
        // a browser does over a connection it will not reuse. Hyper reads the
        // end of the write half as the end of the connection unless it is told
        // that a half-close is a thing.
        .half_close(true)
        .serve_connection(io, service)
        .await
        .map_err(|e| anyhow::anyhow!("the connection ended in error: {e}"))
}

/// The service: one request, one answer.
async fn handle(
    req: Request<Incoming>,
    ctx: Arc<Context>,
) -> Result<Response<crate::http::body::ProxyBody>, Infallible> {
    let (parts, body) = req.into_parts();
    let request = Request::from_parts(parts.clone(), ());

    // The head's size, as far as the proxy can tell: hyper parsed the head
    // and does not hand the raw bytes over. What it parsed is what went on
    // the wire, so it is measured from that.
    crate::metrics::METRICS.record_bytes_received(head_size(&request) as u64);

    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(crate::routes::host_and_port);

    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path());

    // **The verdict comes before the body is read.** A request for a host no
    // route serves has nothing to forward to, and reading its body first is
    // work nobody asked for. Hyper has not read the body either — it is a
    // stream, and it is only read when it is polled — so the bytes are still
    // on the client's side when the answer goes out.
    let lookup: BackendLookup<BackendInfo> = match host {
        Some((h, port)) => {
            ctx.config
                .get_backend_with_acl(h, path, port, ctx.acl.as_deref())
                .await
        }
        None => BackendLookup::NoRoute,
    };

    let unavailable = matches!(lookup, BackendLookup::Unavailable);
    let status = if unavailable {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::NOT_FOUND
    };

    let Some(backend_info) = lookup.backend() else {
        tracing::warn!(
            "Refusing host={:?}: {}, answering {}",
            host,
            if unavailable {
                "no healthy backend behind a route that matches"
            } else {
                "no route matches"
            },
            status.as_u16()
        );
        crate::metrics::METRICS.record_request(status.as_u16(), 0);
        crate::log::log_access(
            &ctx.request_id,
            &ctx.peer,
            request.method().as_str(),
            request.uri().path(),
            status.as_u16(),
            0,
            0,
            Some(&ctx.who),
        );
        return Ok(refusal(status));
    };

    tracing::debug!(
        "Request: host={:?}, path={} -> backend={}",
        host,
        path,
        backend_info.url
    );

    // A WebSocket upgrade: the client wants the connection to become a
    // conversation rather than a request. It is answered before the body is
    // read — there is no body — and the session that follows is two byte
    // streams moved either way.
    if crate::http::websocket::is_upgrade(&request) {
        return Ok(upgrade(Request::from_parts(parts, body), ctx, backend_info).await);
    }

    let started = std::time::Instant::now();
    let method = request.method().clone();
    let request_target = request.uri().to_string();
    let span = tracing::Span::current();
    crate::log::record_request_on_span(&span, method.as_ref(), &request_target);

    // The body is hyper's own stream, with the accounting the hand-written
    // path had: the bytes are charged to the process-wide budget as they
    // arrive, and counted for the access log.
    let body = IncomingBody::new(body, ctx.config.timeouts().deadlines.body);

    match forward(
        &ctx,
        &request,
        &request_target,
        &method,
        host,
        path,
        backend_info,
        body,
        started,
    )
    .await
    {
        Ok(answer) => Ok(answer.into_response()),
        Err(failure) => {
            // What the client was actually told, when it was told anything: a
            // failure that broke halfway still put a status line and part of a
            // body on the wire, and the log has to say so.
            let status = failure
                .partial
                .as_ref()
                .map(|p| p.status)
                .unwrap_or(StatusCode::BAD_GATEWAY.as_u16());
            let bytes_sent = failure.partial.as_ref().map(|p| p.bytes_sent).unwrap_or(0);
            crate::metrics::METRICS.record_request(status, 0);
            crate::log::log_access(
                &ctx.request_id,
                &ctx.peer,
                method.as_str(),
                &request_target,
                status,
                started.elapsed().as_millis() as u64,
                bytes_sent,
                Some(&ctx.who),
            );
            Ok(crate::http::response::create_error_response(
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                "502 Bad Gateway",
            ))
        }
    }
}

/// A WebSocket upgrade, answered.
///
/// Hyper hands the client's side of the connection over once the `101` is
/// written, so the answer and the session are two things: the answer is what
/// the client is waiting for, and the session is what happens after it.
async fn upgrade(
    request: Request<Incoming>,
    ctx: Arc<Context>,
    backend_info: BackendInfo,
) -> Response<crate::http::body::ProxyBody> {
    let (parts, body) = request.into_parts();
    let head = Request::from_parts(parts.clone(), ());

    // Hyper hands the client's side over once the `101` is written, so this
    // has to be asked for **before** the answer goes out.
    let upgraded = hyper::upgrade::on(Request::from_parts(parts, body));

    let handshake = match crate::http::websocket::handshake(
        &ctx.clients,
        &backend_info,
        &head,
        ctx.config.timeouts(),
    )
    .await
    {
        Ok(handshake) => handshake,
        Err(failure) => {
            tracing::warn!("The WebSocket upgrade failed: {}", failure.error);
            crate::metrics::METRICS.record_request(502, 0);
            crate::log::log_access(
                &ctx.request_id,
                &ctx.peer,
                head.method().as_str(),
                &head.uri().path().to_string(),
                502,
                0,
                0,
                Some(&ctx.who),
            );
            return crate::http::response::create_error_response(
                StatusCode::BAD_GATEWAY,
                "502 Bad Gateway",
            );
        }
    };

    // The backend refused the upgrade: the client gets the backend's own
    // answer, which is an ordinary response and not a session.
    if handshake.status != 101 {
        tracing::debug!(
            "WebSocket handshake failed with backend, status: {}",
            handshake.status
        );
        crate::metrics::METRICS.record_request(handshake.status, 0);
        return handshake.refusal_response();
    }

    let response = handshake.upgrade_response();
    let backend = handshake.backend;
    let trailing = handshake.trailing;
    let idle = ctx.config.timeouts().deadlines.response_idle;

    // The session, in its own task: it outlives the answer, and the answer is
    // what the client is waiting for.
    tokio::spawn(async move {
        match upgraded.await {
            Ok(client) => crate::http::websocket::pump(client, backend, trailing, idle).await,
            Err(e) => tracing::debug!("The upgraded stream did not arrive: {e}"),
        }
    });

    crate::metrics::METRICS.record_request(101, 0);
    response
}

/// The retry loop, and the answer it produced.
#[allow(clippy::too_many_arguments)]
async fn forward(
    ctx: &Arc<Context>,
    request: &Request<()>,
    request_target: &str,
    method: &Method,
    host: Option<(&str, Option<u16>)>,
    path: &str,
    backend_info: BackendInfo,
    body: IncomingBody,
    started: std::time::Instant,
) -> Result<Answer, crate::http::body::ProxyFailure> {
    let attempts = ctx.config.retry().attempts;
    let backoff = ctx.config.retry().backoff;
    // The backends that already failed this request. A retry asks somebody
    // else, because the one that just failed is the one most likely to fail
    // again.
    let mut tried: Vec<String> = Vec::new();
    let mut attempt = 0u32;
    let mut backend = backend_info;

    loop {
        let result = crate::http::forward::proxy_to_backend(
            &ctx.clients,
            ctx.config.timeouts(),
            request,
            &backend,
            &body,
            &ctx.request_id,
        )
        .await;

        let failure = match result {
            Ok(answer) => {
                // The backend answered, so it is up: the circuit is told, and a
                // backend that was out of rotation comes back into it.
                backend.report_success();
                let elapsed_ms = started.elapsed().as_millis() as u64;
                crate::metrics::METRICS.record_request(answer.status().as_u16(), elapsed_ms);
                crate::log::log_access(
                    &ctx.request_id,
                    &ctx.peer,
                    method.as_str(),
                    request_target,
                    answer.status().as_u16(),
                    elapsed_ms,
                    answer.bytes_sent(),
                    Some(&ctx.who),
                );
                return Ok(answer);
            }
            Err(failure) => failure,
        };

        // Only a failure that says the backend is unreachable counts against
        // it. A response that broke halfway is a different thing: the backend
        // did answer.
        if failure.backend_is_down() {
            backend.report_failure();
        }

        // Two questions, and the failure answers both: may this be tried
        // again at all, and is there another backend to try it on.
        if attempt >= attempts || !failure.retry.may_retry(method) {
            return Err(failure);
        }

        // A body that has been **read** is gone: its bytes came off the
        // client's stream and there is no second copy of them, so the request
        // cannot be tried again.
        if !body.may_retry() {
            return Err(crate::http::body::ProxyFailure::from(anyhow::anyhow!(
                "the request has a body that cannot be read a second time, so it is not tried \
                 again: {}",
                failure.error
            )));
        }

        attempt += 1;

        tracing::warn!(
            "Request to {} failed ({}); trying another backend ({attempt}/{attempts})",
            backend.url,
            failure.error,
        );

        tried.push(backend.url.to_string());
        let next = match host {
            Some((h, port)) => {
                ctx.config
                    .get_backend_with_acl_excluding(h, path, port, ctx.acl.as_deref(), &tried)
                    .await
            }
            None => BackendLookup::NoRoute,
        };
        match next.backend() {
            Some(info) => backend = info,
            // Nobody else to ask. The failure is the answer: the pool being
            // empty is a consequence of it, not a new fact.
            None => return Err(failure),
        }

        if !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }
    }
}

/// A refusal, as an answer.
fn refusal(status: StatusCode) -> Response<crate::http::body::ProxyBody> {
    let message = match status {
        StatusCode::NOT_FOUND => "404 Not Found",
        StatusCode::SERVICE_UNAVAILABLE => "503 Service Unavailable",
        _ => "400 Bad Request",
    };
    crate::http::response::create_error_response(status, message)
}

/// The size of the head on the wire, as far as the proxy can tell.
///
/// Hyper parsed the head and does not hand the raw bytes over. What it
/// parsed is what went on the wire, so the head is measured from that: the
/// request line, and every header with the four bytes of framing around it.
fn head_size(request: &Request<()>) -> usize {
    let mut size =
        request.method().as_str().len() + request.uri().to_string().len() + "HTTP/1.1\r\n".len();
    for (name, value) in request.headers() {
        size += name.as_str().len() + value.as_bytes().len() + ": \r\n".len();
    }
    size + "\r\n".len()
}

/// The body of a request whose head hyper read.
///
/// Hyper's own stream: the bytes are still on the client's side, and hyper
/// reads them as the backend asks for them. What this adds is the accounting
/// the hand-written path had — the bytes are charged to the process-wide
/// budget as they arrive, and counted for the access log.
///
/// The stream is **shared** with the copy the request carries, for the same
/// reason the hand-written path shared its reader: a request that fails
/// before the body was read has to be able to send the body again, and the
/// client's bytes are the only place they are. The lock is held for the
/// length of one poll and for nothing else.
pub struct IncomingBody {
    /// Hyper's stream, shared with the copy the request carries.
    reader: Arc<std::sync::Mutex<Incoming>>,
    /// What the owner of the request needs to know about this body.
    state: Arc<crate::http::body::BodyState>,
    /// When the body has to be finished by.
    deadline: tokio::time::Instant,
}

impl IncomingBody {
    /// The body, and the deadline it is held to.
    pub fn new(inner: Incoming, body_deadline: Duration) -> Self {
        Self {
            reader: Arc::new(std::sync::Mutex::new(inner)),
            state: Arc::new(crate::http::body::BodyState::default()),
            deadline: tokio::time::Instant::now() + body_deadline,
        }
    }

    /// Whether the request may be tried again: a body that has been read is
    /// gone, and one that has not is still there.
    pub fn may_retry(&self) -> bool {
        !self.state.was_read()
    }

    /// Whether the body's deadline expired while it was being read.
    pub fn did_time_out(&self) -> bool {
        self.state.did_time_out()
    }

    /// Whether the body is over: everything the client promised has been
    /// read, or the client stopped sending.
    pub fn has_been_sent(&self) -> bool {
        self.state.has_been_sent()
    }

    /// The copy the request carries.
    ///
    /// The body is **lent** rather than given away: the request that fails
    /// before the body was read has to be able to send it again.
    pub fn lend(&self) -> LentBody {
        LentBody {
            reader: self.reader.clone(),
            state: self.state.clone(),
            deadline: self.deadline,
            timer: None,
            reservation: crate::conn::limits::ByteReservation::empty(),
        }
    }
}

/// The copy of the request body that the request carries.
///
/// It reads the shared stream, charges the bytes it reads to the process-wide
/// budget, and records that they were read — which is what the retry rule
/// asks, and what the access log's byte count is made of.
pub struct LentBody {
    /// Hyper's stream, shared with the owner of the request.
    reader: Arc<std::sync::Mutex<Incoming>>,
    /// What the owner of the request needs to know about this body.
    state: Arc<crate::http::body::BodyState>,
    /// When the body has to be finished by.
    deadline: tokio::time::Instant,
    /// The timer that ends the body when the deadline passes.
    ///
    /// The deadline is a clock reading, and a clock reading wakes nobody: a
    /// body that is only checked when it is polled is never given up on while
    /// the client is silent, which is exactly when it should be.
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// What the process budget holds for the bytes this body is reading.
    ///
    /// Grown as the bytes arrive rather than taken for the whole length up
    /// front: a client that promises a large body and sends nothing holds
    /// nothing, which is what the buffered path did as well. A promise is not
    /// a reservation.
    reservation: crate::conn::limits::ByteReservation,
}

impl hyper::body::Body for LentBody {
    type Data = bytes::Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        // The timer is armed on the first poll, so a body nobody asks for
        // holds none.
        let timer = this
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(this.deadline)));
        if timer.as_mut().poll(cx).is_ready() {
            this.state.mark_timed_out();
            return Poll::Ready(Some(Err(anyhow::anyhow!(
                "the request body did not finish in time (the body's deadline is {:?})",
                this.deadline
            )
            .into())));
        }

        let mut reader = this
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match Pin::new(&mut *reader).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.state.mark_read();
                    this.reservation.grow(data.len())?;
                    crate::metrics::METRICS.record_bytes_received(data.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(BoxError::from(e)))),
            Poll::Ready(None) => {
                this.state.mark_sent();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The backend's answer, counted as it goes out.
///
/// The count is what the access log reports, and it is taken at the write
/// rather than at the format: a body that died half way is reported as the
/// half that arrived, not as the whole that was intended.
pub struct CountedBody {
    /// The backend's own stream.
    inner: Incoming,
    /// The bytes that reached the client.
    bytes_sent: Arc<AtomicUsize>,
    /// How long the backend may be silent before the answer is cut.
    ///
    /// Idle, not a phase deadline: what is being bounded is the gap between
    /// chunks, so this re-arms on every chunk — which is what lets an SSE
    /// stream stay open for as long as both ends want, while a backend that
    /// accepted the request and then went silent cannot hold the slot and its
    /// backend lease forever.
    idle: Duration,
    /// The timer that ends the answer when the backend goes quiet.
    timer: Pin<Box<tokio::time::Sleep>>,
}

impl CountedBody {
    /// The answer, and where the count is kept.
    pub fn new(inner: Incoming, bytes_sent: Arc<AtomicUsize>, idle: Duration) -> Self {
        Self {
            inner,
            bytes_sent,
            idle,
            timer: Box::pin(tokio::time::sleep(idle)),
        }
    }
}

impl hyper::body::Body for CountedBody {
    type Data = bytes::Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        // The idle bound is a clock reading, and a clock reading wakes nobody:
        // without the timer the check below would run only when the backend
        // sends something, so a backend that goes quiet would never be given
        // up on.
        this.timer
            .as_mut()
            .reset(tokio::time::Instant::now() + this.idle);
        if this.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(BodyError::Idle(this.idle))));
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes_sent.fetch_add(data.len(), Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(BodyError::from(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

//! The bodies.
//!
//! A request body is read once and may be replayed, a response body is read
//! once and may not, and both are bounded: the ceiling is what stops a peer
//! from holding the process's memory for as long as it likes to send.

use ::http::Request;

use futures_util::{StreamExt, TryStreamExt};

use http_body_util::combinators::UnsyncBoxBody;

use http_body_util::{BodyExt, Full};

use std::pin::Pin;

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use super::*;

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::Idle(idle) => {
                write!(f, "backend sent nothing for {idle:?} mid-body")
            }
            BodyError::Hyper(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BodyError::Idle(_) => None,
            BodyError::Hyper(e) => Some(e),
        }
    }
}

impl From<hyper::Error> for BodyError {
    fn from(e: hyper::Error) -> Self {
        BodyError::Hyper(e)
    }
}

/// The body a proxied response carries.
pub type ProxyBody = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BodyError>;

/// The backend's response body, with the gap between its frames bounded.
///
/// Idle, not a phase deadline: what is bounded is the gap, so it re-arms on
/// every frame — which is what lets an SSE stream or a long transfer stay open
/// for as long as both ends want, while a backend that sent the head and then
/// went silent cannot hold this slot and its backend lease forever. The value
/// comes from `[timeouts] response_idle_secs` through the caller.
///
/// The stream is the body a client is handed, so the failure it reports is
/// the one the client sees: hyper aborts the connection rather than writing a
/// complete-looking response that is missing its tail.
pub(super) fn idle_bounded<B>(
    body: B,
    idle: std::time::Duration,
) -> impl futures_util::Stream<Item = Result<hyper::body::Frame<bytes::Bytes>, BodyError>>
where
    B: hyper::body::Body<Data = bytes::Bytes>,
    B::Error: Into<BodyError>,
{
    let frames = http_body_util::BodyExt::into_data_stream(body).map_ok(hyper::body::Frame::data);
    // `timeout` re-arms on every item, which is the idle semantics wanted
    // here. Both `StreamExt` traits have a `timeout`-shaped surface, so the
    // call is made by its full path rather than by an import.
    let timed = tokio_stream::StreamExt::timeout(frames, idle);
    timed.map(move |item| match item {
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => {
            tracing::warn!("Backend sent nothing for {idle:?} mid-body, ending the response body");
            Err(BodyError::Idle(idle))
        }
    })
}

/// The largest request body this proxy will carry.
///
/// `content-length` is whatever the client says it is, and the limit is
/// checked against that declaration before a byte of the body is read — so
/// this bounds one request whatever the client says it is sending.
///
/// What the process **holds** is a different matter. A body that declares a
/// length is streamed: the bytes are read from the client as the backend asks
/// for them, and only a buffer is held rather than the upload. A body with
/// no length — a chunked one — is read whole, because the proxy re-frames it
/// as one buffer with a length of its own, and this is what bounds that.
///
/// How many such bodies may be held at once is
/// [`ByteBudget`](crate::conn::limits::ByteBudget)'s, which is why a body is
/// only read once it has been given a reservation from it.
pub(super) const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

/// Whether a request header may be forwarded to the backend.
///
/// Two groups are dropped. Hop-by-hop headers describe one connection, not the
/// message (RFC 7230 6.1): `connection: keep-alive` is about the client's link
/// to this proxy, and forwarding it asks the backend to keep *its* link open
/// for a request that arrived over a different one. `transfer-encoding` is in
/// the same group and has to go: the body is sent with a length of the
/// proxy's own, so a leftover `chunked` would disagree with the framing on
/// the wire.
///
/// `proxy-authorization` is in the same group and is the one that matters most:
/// it is a credential for *this* proxy, and forwarding it hands that credential
/// to a third-party server. `proxy-authenticate` goes with it — it is the
/// challenge this proxy answers, and the backend has no business seeing it.
///
/// `expect: 100-continue` is dropped for a different reason. The expectation
/// is the client's, about the client's link to this proxy, and this proxy
/// does not answer it with a `100` of its own: a client that waits for one
/// before sending its body waits until the body's deadline. Forwarding the
/// header would only tell the backend to wait as well.
///
/// The WebSocket handshake does not use this: it is the one request that
/// *must* carry `upgrade` and `connection`, because switching protocols is
/// exactly what it is asking the backend for.
pub(super) fn forwards_request_header(name: &str) -> bool {
    ![
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "expect",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
}

/// A response body that keeps its backend busy until the body is done.
///
/// The lease is what the balancer counts, and a backend that is still
/// streaming a response is still busy with it. A balancer that cannot see
/// that hands the next request to a backend that is already working, which
/// is the whole failure `least_conn` exists to avoid.
///
/// Holding the lease in the body is what makes the count true: the body is
/// dropped when the client has read it — or when the connection goes away
/// instead — and the backend is free again then. The streaming path has
/// always held its lease for the whole flow; this is the same rule on the
/// path that did not.
pub(super) struct LeasedBody {
    pub(super) inner: ProxyBody,
    /// Kept, never read: dropping it is what releases the backend.
    pub(super) _lease: Option<crate::lb::BackendLease>,
}

impl hyper::body::Body for LeasedBody {
    type Data = bytes::Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }
}

/// Reads a request body whole, refusing one past `limit` or past what the
/// process can hold at once.
///
/// Returns the reservation as well as the bytes, and the caller has to keep it:
/// dropping it gives the bytes back, so the total the budget reports is what is
/// held *now* rather than what was ever read. A caller that answers the request
/// and returns is exactly the lifetime a buffered body has.
///
/// The size is not known up front — a chunked request says nothing about how
/// much is coming — so the limit has to be enforced while reading rather than
/// by checking a `content-length` header the client is free to understate.
///
/// The deadline over the read is likewise total rather than per frame, so a
/// client that trickles one byte before each expiry renews nothing.
pub(super) async fn read_body_limited<B>(
    body: B,
    limit: usize,
    body_deadline: std::time::Duration,
) -> anyhow::Result<(bytes::Bytes, crate::conn::limits::ByteReservation)>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut body = body;
    let mut bytes: Vec<u8> = Vec::new();
    // Claimed as the frames arrive rather than up front: see `ByteReservation`.
    let mut reservation = crate::conn::limits::ByteReservation::empty();
    // A deadline over the whole read, not per frame: this is the path the
    // plaintext listener takes, and it had no bound at all, so a client that
    // opened a socket and then sent a byte of body every few seconds held the
    // connection, the task and the buffer indefinitely. The iroh path has always
    // bounded this read; this is the same bound, in one place. The value comes
    // from `[timeouts] body_secs` through the caller, not from here.
    let deadline_at = tokio::time::Instant::now() + body_deadline;
    loop {
        // A `loop` rather than `while let`, so that the deadline's own expiry is
        // told apart from the end of the body.
        let frame =
            match tokio::time::timeout_at(deadline_at, http_body_util::BodyExt::frame(&mut body))
                .await
            {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "request body did not finish within {}s",
                        body_deadline.as_secs()
                    ));
                }
            };
        let frame = frame.map_err(|e| anyhow::anyhow!("failed to read the request body: {}", e))?;
        // Anything that is not a data frame — trailers — carries no body bytes.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if bytes.len() + data.len() > limit {
            return Err(anyhow::anyhow!(
                "request body is over the {limit} byte limit"
            ));
        }
        reservation.grow(data.len())?;
        bytes.extend_from_slice(&data);
    }
    Ok((bytes.into(), reservation))
}

/// What one proxied request came to.
///
/// The streaming path writes the response straight into the QUIC stream, so
/// there is no `Response` left for the caller to inspect; without this the
/// tunnel path — the one every client actually uses — could not be logged at
/// all.
#[derive(Debug, Clone, Copy)]
pub struct ProxySummary {
    pub status: u16,
    /// Response headers plus body payload, excluding chunk framing.
    ///
    /// What reached the client, counted at each successful write rather than
    /// at each byte formatted: a partially streamed response reports the part
    /// that was flushed, not the length it was going to be.
    pub bytes_sent: usize,
}

/// A proxied request that did not finish.
///
/// The streaming path writes as it goes, so by the time something fails the
/// status line — and possibly half the body — is already on the wire. Reporting
/// every failure as a 502 with zero bytes claims a response was never sent when
/// the client is holding part of one, which is the worst possible thing for an
/// access log to say about a request: it points the reader at the backend for a
/// problem that happened after the backend answered. What had arrived when it
/// broke is carried here instead, and is `None` only when nothing had.
#[derive(Debug)]
pub struct ProxyFailure {
    pub error: anyhow::Error,
    pub partial: Option<ProxySummary>,
    /// What may be done about this failure.
    pub retry: Retryability,
}

/// What may be done about a failed attempt.
///
/// The question is never "did it fail" but "may it be tried again", and the
/// answer depends on two things that are easy to confuse:
///
/// - **Did the request reach the backend?** A connection that was refused
///   never carried it, so the backend did not act on it and asking again is
///   free of consequence — whatever the request was.
/// - **Is the request safe to send twice?** A `GET` is. A `POST` that
///   charges a card is not, and the only way to know is what the method says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryability {
    /// The request was never carried to the backend. It may be tried again
    /// whatever it is.
    Always,
    /// The request was carried and no answer came. It may be tried again only
    /// if sending it twice is safe, which is what an idempotent method is.
    IfIdempotent,
    /// Nothing may be tried again: the client already has part of the answer,
    /// or the failure says nothing about the backend.
    Never,
}

// One more argument than clippy allows: the alternative is a struct bundling the
// client with its deadlines, which every caller would have to build in order to
// pass the same two things — see the note on `conn::handle_bidi_stream`.
#[allow(clippy::too_many_arguments)]
/// The body of a request, read once and ready to be sent to a backend.
///
/// Read outside the attempt, because the bytes come off the client's stream
/// and that stream has them only once: a retry that had to read them again
/// would wait for bytes that are never coming.
/// A body that is already in memory, as the client's body type.
pub fn full_body(bytes: bytes::Bytes) -> HttpBody {
    let inner =
        Full::new(bytes).map_err(|never: std::convert::Infallible| -> BoxError { match never {} });
    UnsyncBoxBody::new(inner)
}

/// A body with nothing in it.
///
/// What an answer that is not a body at all carries: a refusal, and a `101` —
/// the upgrade has no body of its own, and the bytes that follow it are the
/// session's.
pub fn empty_body() -> ProxyBody {
    let empty = http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|never: std::convert::Infallible| -> BodyError { match never {} });
    UnsyncBoxBody::new(empty)
}

/// What the proxy knows about a body that is still on the client's stream.
///
/// Shared between the body the request carries and the request that owns it:
/// the body knows when it has been read, and the owner needs to know that
/// afterwards — a body that has been read cannot be sent a second time, and
/// one that has not can.
#[derive(Debug, Default)]
pub struct BodyState {
    /// Set once a byte has come off the client's stream.
    ///
    /// The head's bytes are not counted: they are in memory, and the request
    /// still holds them, so a retry can send them again. What is gone once
    /// the stream has been read is the rest of the body, and the stream is
    /// the only place it was.
    read: std::sync::atomic::AtomicBool,
    /// Set when the body's deadline expired while it was being read.
    timed_out: std::sync::atomic::AtomicBool,
    /// Set once the body is over: everything the client promised has been
    /// read, or the client stopped sending.
    ///
    /// The answer's deadline runs from this moment, because a backend cannot
    /// answer before it has the body.
    sent: std::sync::atomic::AtomicBool,
}

impl BodyState {
    /// Records that a byte has come off the client's stream.
    pub(crate) fn mark_read(&self) {
        self.read.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records that the body's deadline expired.
    pub(crate) fn mark_timed_out(&self) {
        self.timed_out
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records that the body is over.
    pub(crate) fn mark_sent(&self) {
        self.sent.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the body has been read off the client's stream.
    pub(crate) fn was_read(&self) -> bool {
        self.read.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the body's deadline expired while it was being read.
    pub(crate) fn did_time_out(&self) -> bool {
        self.timed_out.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the body is over.
    pub(crate) fn has_been_sent(&self) -> bool {
        self.sent.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The client's stream, shared by the body that reads it and the request that
/// owns it.
///
/// The reader is shared rather than moved because a request that fails
/// *before* the body was read has to be able to send the body again — to the
/// next backend — and the client's stream is the only place those bytes are.
/// The lock is held for the length of one read and for nothing else, so it is
/// never held across an await.
#[derive(Clone)]
pub struct BodyReader {
    reader: std::sync::Arc<std::sync::Mutex<Box<dyn AsyncRead + Send + Unpin>>>,
}

impl BodyReader {
    /// The reader, shared with whoever else has to read it.
    pub(crate) fn new(reader: Box<dyn AsyncRead + Send + Unpin>) -> Self {
        Self {
            reader: Arc::new(std::sync::Mutex::new(reader)),
        }
    }

    /// Reads into `buf`, registering `cx` for the wake-up.
    fn poll_read(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut reader = self
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Pin::new(&mut *reader).poll_read(cx, buf)
    }
}

/// A request body that is still on its way from the client.
///
/// The bytes are read from the client's stream as the backend asks for them,
/// so the proxy never holds the whole body: an upload of any size costs a
/// buffer, not a copy of the upload.
pub(super) struct StreamingBody {
    /// The part of the body that arrived with the head.
    pub(super) head: bytes::Bytes,
    /// The rest of it, still on the client's stream.
    ///
    /// Shared with the request that owns the body, so that a request that
    /// failed before the body was read can send it again.
    pub(super) reader: BodyReader,
    /// How many bytes are still to come.
    pub(super) remaining: usize,
    /// When the body has to be finished by.
    pub(super) deadline: tokio::time::Instant,
    /// The timer that ends the body when the deadline passes.
    ///
    /// The deadline is a clock reading, and a clock reading wakes nobody: a
    /// body that is only checked when it is polled is never given up on
    /// while the client is silent, which is exactly when it should be. The
    /// timer is what turns the deadline into a bound.
    pub(super) timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// What the process budget holds for the bytes this body is reading.
    ///
    /// Grown as the bytes arrive rather than taken for the whole length up
    /// front: a client that promises a large body and sends nothing holds
    /// nothing, which is what the buffered path did as well. A promise is not
    /// a reservation.
    ///
    /// The head's bytes are charged by the request that owns the body, which
    /// holds them for as long as it lives; this is the rest of it. The read
    /// buffer is not charged: it is one fixed buffer per body, and the budget
    /// is about what the process holds of the *upload*.
    pub(super) reservation: crate::conn::limits::ByteReservation,
    /// The buffer the bytes are read into, reused for every chunk.
    ///
    /// One buffer for the whole body rather than one per chunk: a 64 MiB
    /// upload is four thousand chunks, and four thousand buffers that are
    /// thrown away the moment after they are filled.
    pub(super) buf: Vec<u8>,
    /// What the owner of the request needs to know about this body.
    pub(super) state: Arc<BodyState>,
}

/// How much of a body is read at a time.
///
/// A chunk is a chunk: the backend asked for the body, not for a particular
/// size of it.
pub(super) const STREAM_CHUNK: usize = 16 * 1024;

impl hyper::body::Body for StreamingBody {
    type Data = bytes::Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;

        let this = self.get_mut();

        if this.remaining == 0 {
            return Poll::Ready(None);
        }

        // The deadline is a clock reading, and a clock reading wakes nobody:
        // without a timer the check below would run only when the client
        // sends something, so a client that goes silent would never be given
        // up on. The timer is what turns the deadline into a bound, and it is
        // armed on the first poll so that a body nobody asks for holds none.
        let deadline = this.deadline;
        let timer = this
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        if timer.as_mut().poll(cx).is_ready() {
            this.state.mark_timed_out();
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the request body did not finish in time",
            )) as BoxError)));
        }

        // The part that arrived with the head goes first: it is the beginning
        // of the body, and the stream continues after it.
        if !this.head.is_empty() {
            let n = this.head.len().min(this.remaining);
            let chunk = this.head.split_to(n);
            this.remaining -= n;
            if this.remaining == 0 {
                // The body is over: the backend has all of it.
                this.state.mark_sent();
            }
            crate::metrics::METRICS.record_bytes_received(n as u64);
            return Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk))));
        }

        let want = this.remaining.min(STREAM_CHUNK);
        if this.buf.len() < want {
            this.buf.resize(want, 0);
        }

        // **Reserved before the read**, so the budget counts the bytes before
        // they are in the process. What the budget holds is what the process
        // holds, never less.
        if let Err(e) = this.reservation.grow(want) {
            return Poll::Ready(Some(Err(Box::from(e))));
        }

        let mut read_buf = ReadBuf::new(&mut this.buf[..want]);
        let n = match this.reader.poll_read(cx, &mut read_buf) {
            Poll::Pending => {
                // Nothing was read, so nothing is held — and nothing is spent:
                // the bytes are still on the client's stream.
                this.reservation.shrink(want);
                return Poll::Pending;
            }
            Poll::Ready(Ok(())) => {
                // The stream has been read: what came off it is gone, and
                // there is no second copy of it. A request that has to be
                // tried again cannot send this body a second time.
                this.state.mark_read();
                read_buf.filled().len()
            }
            Poll::Ready(Err(e)) => {
                this.reservation.shrink(want);
                // The stream is broken, so what was on it is gone as well.
                this.state.mark_read();
                return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
            }
        };

        // What did not arrive is given back: the budget counts the bytes that
        // are here, not the bytes that were asked for.
        this.reservation.shrink(want - n);

        if n == 0 {
            // The client stopped sending. The body is short, and the backend
            // will see it end.
            this.state.mark_sent();
            return Poll::Ready(None);
        }
        this.remaining -= n;
        if this.remaining == 0 {
            // The body is over: the backend has all of it.
            this.state.mark_sent();
        }
        crate::metrics::METRICS.record_bytes_received(n as u64);
        Poll::Ready(Some(Ok(hyper::body::Frame::data(
            bytes::Bytes::copy_from_slice(read_buf.filled()),
        ))))
    }
}

/// A request's body: either already here, or still on its way.
///
/// The two cases are different in kind. A body that is **whole** can be sent
/// again — a retry takes another reference to the same bytes rather than a
/// second copy of them, and the peak is what the byte budget says it is. A
/// body that is **streaming** came off the client's stream and there is no
/// second copy of it, so it can be sent exactly once.
pub enum RequestBody {
    /// The bytes are whole.
    Whole {
        /// The bytes.
        ///
        /// **Shared, not owned twice.** The body is read into a buffer, and
        /// the request that goes to the backend used to be handed a *copy* of
        /// it: the buffer stayed alive for the retry, and the copy was thrown
        /// away with the attempt. A [`Bytes`](bytes::Bytes) is the same buffer with a
        /// reference count, so the retry takes another reference to the same
        /// bytes rather than a second copy of them.
        bytes: bytes::Bytes,
        /// The length to declare to the backend, when the client declared
        /// none.
        ///
        /// A chunked request has no length of its own; the proxy reads the
        /// chunks and sends one buffer with a length of its own.
        content_length: Option<usize>,
        /// Held for as long as the body is alive, so the process budget
        /// counts what it holds now rather than what it ever read. See
        /// [`crate::conn::limits::ByteReservation`].
        reservation: crate::conn::limits::ByteReservation,
    },
    /// The bytes are still coming from the client.
    Streaming {
        /// The part of the body that arrived with the head.
        head: bytes::Bytes,
        /// The rest of it, still on the client's stream.
        ///
        /// Shared with the body the request carries, so that a request that
        /// failed before the body was read can send the body again: the
        /// bytes are still on the client's stream, and that stream is the
        /// only place they are.
        reader: BodyReader,
        /// How many bytes the whole body is.
        content_length: usize,
        /// Held for as long as the body is alive.
        ///
        /// The head's bytes are charged here, and stay charged: the request
        /// holds them for as long as it lives, and a retry sends them again.
        reservation: crate::conn::limits::ByteReservation,
        /// What the proxy knows about the body.
        state: Arc<BodyState>,
    },
}

impl RequestBody {
    /// The length to declare to the backend, when the client declared none.
    pub fn content_length(&self) -> Option<usize> {
        match self {
            RequestBody::Whole { content_length, .. } => *content_length,
            RequestBody::Streaming { content_length, .. } => Some(*content_length),
        }
    }

    /// Whether this body can be sent a second time.
    ///
    /// A body that is whole can: its bytes are here. A body that is
    /// streaming can be sent again only while it has **not been read**: the
    /// bytes are still on the client's stream, and a request that failed
    /// before the body was touched — a connection that was refused, say —
    /// has not spent them. Once the body has been read, what came off the
    /// stream is gone and there is no second copy of it.
    pub fn may_retry(&self) -> bool {
        match self {
            RequestBody::Whole { .. } => true,
            RequestBody::Streaming { state, .. } => !state.was_read(),
        }
    }

    /// Whether the body's deadline expired while it was being read.
    ///
    /// A body that ran out of time is not a backend that failed, and the
    /// failure it caused says so.
    pub(crate) fn did_time_out(&self) -> bool {
        match self {
            RequestBody::Whole { .. } => false,
            RequestBody::Streaming { state, .. } => state.did_time_out(),
        }
    }

    /// Whether the body has been sent to the backend.
    ///
    /// The answer's deadline runs from that moment: a backend cannot answer
    /// before it has the body. A body that is whole was sent before this, and
    /// its deadline runs from here.
    pub(crate) fn has_been_sent(&self) -> bool {
        match self {
            RequestBody::Whole { .. } => false,
            RequestBody::Streaming { state, .. } => state.has_been_sent(),
        }
    }
}

/// Written out rather than derived: a stream has no `Debug`, and the shape of
/// a body is worth saying — how many bytes it holds, and whether it is still
/// on the wire.
impl std::fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestBody::Whole {
                bytes,
                content_length,
                reservation,
            } => f
                .debug_struct("Whole")
                .field("bytes", &bytes.len())
                .field("content_length", content_length)
                .field("reservation", reservation)
                .finish(),
            RequestBody::Streaming {
                head,
                state,
                content_length,
                reservation,
                ..
            } => f
                .debug_struct("Streaming")
                .field("head", &head.len())
                .field("read", &state.was_read())
                .field("content_length", content_length)
                .field("reservation", reservation)
                .finish(),
        }
    }
}

/// Reads the body of a request off the client's stream.
///
/// The bytes that arrived with the head are `body_data`; the rest is read
/// here. What comes back is whole: either every byte the client promised, or
/// an error — a body that stops halfway is a request that was never sent.
pub async fn read_request_body(
    req: &Request<()>,
    recv: &mut Option<iroh::endpoint::RecvStream>,
    body_data: Vec<u8>,
    timeouts: crate::config::Timeouts,
) -> Result<RequestBody, ProxyFailure> {
    // A chunked body is sent as one buffer with a length of our own, so only a
    // request whose `content-length` we could not read takes that path. One we
    // could read is forwarded with the header it arrived with.
    let declared_length = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let chunked = declared_length.is_none() && request_is_chunked(req);

    if let Some(content_length) = declared_length {
        // Checked before the body is read, not after: `content_length` is the
        // size of the body this is about to carry.
        if content_length > MAX_REQUEST_BODY {
            return Err(ProxyFailure::from(anyhow::anyhow!(
                "request body of {content_length} bytes is over the {MAX_REQUEST_BODY} byte limit"
            )));
        }

        // **Streamed.** The bytes are still on the client's stream, and the
        // backend reads them as it sends them: the proxy never holds the whole
        // body, so an upload of any size costs a buffer rather than a copy of
        // the upload.
        //
        // The reservation is for what has **arrived**, not for what the client
        // promised. The bytes that came with the head are in memory already,
        // so they are charged now — the same rule the buffered path used — and
        // the rest is charged as it arrives. A promise is not a reservation:
        // a client that declares a large body and sends nothing holds
        // nothing, which is what the buffered path did as well.
        let mut head = body_data;
        // More than the client declared is not part of the body: the request
        // said how long it is, and what came after that is not the body.
        head.truncate(content_length);
        let reservation = crate::conn::limits::ByteReservation::take(head.len())?;
        let stream = recv.take().ok_or_else(|| {
            ProxyFailure::from(anyhow::anyhow!("the request's stream was already taken"))
        })?;
        return Ok(RequestBody::Streaming {
            head: bytes::Bytes::from(head),
            // The reader is shared rather than moved: a request that fails
            // before the body was read has to be able to send the body again,
            // and the client's stream is where the bytes are.
            reader: BodyReader::new(Box::new(stream)),
            content_length,
            reservation,
            state: Arc::new(BodyState::default()),
        });
    }

    let mut full_body = body_data;
    // Held for as long as the body is alive, which is until the request is
    // done: the buffer is handed to the backend and dropped with the request.
    // Same rule as `read_body_limited` on the plaintext path, and the reason
    // the two are worth keeping in step — one without the other leaves the
    // process budget counting a fraction of what it actually holds.
    let (reservation, content_length) = if chunked {
        // A chunked body declares no length, so without this branch the request
        // went out carrying only the bytes that happened to arrive with the
        // head — and `transfer-encoding` is not forwarded, so the backend was
        // handed a body with no framing at all and no way to know it was
        // truncated. Decode the chunks and send one buffer with a length.
        let stream = recv.as_mut().ok_or_else(|| {
            ProxyFailure::from(anyhow::anyhow!("the request's stream was already taken"))
        })?;
        let reservation = read_chunked_request_body(
            stream,
            &mut full_body,
            timeouts.deadlines.body,
            crate::conn::limits::body_budget(),
        )
        .await?;
        (reservation, Some(full_body.len()))
    } else {
        (crate::conn::limits::ByteReservation::empty(), None)
    };

    // The body is complete at this point in every branch above, and this is the
    // only place it is whole: what goes out is a reconstructed request with its
    // own framing, so its size on the way out is not what arrived.
    crate::metrics::METRICS.record_bytes_received(full_body.len() as u64);

    Ok(RequestBody::Whole {
        // The buffer is handed over rather than copied: the body is read into
        // it once, and the request that goes to the backend takes a reference
        // to the same bytes.
        bytes: bytes::Bytes::from(full_body),
        content_length,
        reservation,
    })
}

/// The longest line a chunk header may be.
///
/// A chunk size is a hex number with optional extensions, so anything past a
/// few dozen bytes is malformed; the cap keeps a stream that never sends a
/// CRLF from growing this buffer without bound.
pub(super) const MAX_CHUNK_HEADER: usize = 1024;

/// How many bytes of a chunked body `input` decodes on its own.
///
/// Returns the decoded bytes, how much of `input` was used up, and whether the
/// terminating zero chunk was seen. Bytes belonging to an incomplete chunk are
/// *not* reported as used: the caller keeps them and hands them back with
/// whatever it reads next. `limit` is how much body is still allowed.
pub(super) fn decode_chunks(
    input: &[u8],
    limit: usize,
) -> Result<(Vec<u8>, usize, bool), anyhow::Error> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut used = 0usize;

    loop {
        let Some(rel) = input[pos..].windows(2).position(|w| w == b"\r\n") else {
            // Still waiting for the line, which is normal while the header is
            // arriving — but only for so long. Without this the caller keeps
            // appending every read to its buffer, and a peer that never sends
            // a CRLF grows it without bound.
            if input.len() - pos > MAX_CHUNK_HEADER {
                return Err(anyhow::anyhow!(
                    "chunk header longer than {MAX_CHUNK_HEADER} bytes"
                ));
            }
            return Ok((out, used, false));
        };
        if rel > MAX_CHUNK_HEADER {
            return Err(anyhow::anyhow!(
                "chunk header longer than {MAX_CHUNK_HEADER} bytes"
            ));
        }

        let size = parse_chunk_size(&input[pos..pos + rel])?;
        let after_header = pos + rel + 2;

        // The zero chunk ends the body. What follows is the trailer section,
        // which is not forwarded: an empty one (the usual case) is consumed so
        // the stream is left clean, and a real one is left untouched — this
        // request owns the stream, so there is nothing after it to keep in
        // step with.
        if size == 0 {
            let done = input.len() >= after_header + 2
                && &input[after_header..after_header + 2] == b"\r\n";
            return Ok((
                out,
                if done { after_header + 2 } else { after_header },
                true,
            ));
        }

        // Neither check may add: `size` comes from the client and
        // `usize::from_str_radix` accepts values near `usize::MAX`, so
        // `out.len() + size` and `size + 2` overflow — a panic in a debug
        // build, and in release a bound that wraps and then lets the slice
        // below run off the end.
        if size > limit || out.len() > limit - size {
            return Err(anyhow::anyhow!(
                "chunked request body is over the {limit} byte limit"
            ));
        }
        // What is left after the header, so "is there a whole chunk here" is a
        // subtraction of two lengths instead of an addition that can wrap.
        let remaining = input.len() - after_header;
        if remaining < size || remaining - size < 2 {
            return Ok((out, used, false));
        }

        out.extend_from_slice(&input[after_header..after_header + size]);
        if &input[after_header + size..after_header + size + 2] != b"\r\n" {
            return Err(anyhow::anyhow!("chunk data is not followed by CRLF"));
        }

        pos = after_header + size + 2;
        used = pos;
    }
}

/// The size a chunk header declares, in bytes.
pub(super) fn parse_chunk_size(header: &[u8]) -> Result<usize, anyhow::Error> {
    let text = std::str::from_utf8(header)
        .map_err(|_| anyhow::anyhow!("chunk header is not valid UTF-8"))?;
    let digits = text.split(';').next().unwrap_or("").trim();
    if digits.is_empty() {
        return Err(anyhow::anyhow!("chunk header declares no size"));
    }
    usize::from_str_radix(digits, 16)
        .map_err(|_| anyhow::anyhow!("{digits:?} is not a hexadecimal chunk size"))
}

/// Reads a chunked request body off an iroh stream, leaving the de-chunked
/// bytes in `body`.
///
/// Whatever arrived with the head is already the start of the chunk stream, so
/// it is handed to the decoder first and only then is more read.
///
/// A chunked body declares no length, so the reservation grows as the bytes
/// arrive rather than being taken up front — there is no honest moment at which
/// this knows how much it wants. Returns the reservation, which the caller keeps
/// for the lifetime of the body.
///
/// Generic over the reader so the accounting can be tested without an endpoint;
/// callers pass an iroh receive stream. The budget is a parameter for the same
/// reason: the accounting is only observable against a budget of the test's
/// own, because the process-wide one is shared with every other test in this
/// binary.
pub(super) async fn read_chunked_request_body<R>(
    recv: &mut R,
    body: &mut Vec<u8>,
    body_deadline: std::time::Duration,
    budget: &std::sync::Arc<crate::conn::limits::ByteBudget>,
) -> Result<crate::conn::limits::ByteReservation, anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut pending = std::mem::take(body);
    let mut buf = [0u8; 8192];
    // The bytes that came with the head are the beginning of the chunk stream,
    // so they are held the same way the rest of it is: charged while they wait
    // to be decoded.
    let mut reservation = crate::conn::limits::ByteReservation::take_from(budget, pending.len())?;

    // A phase deadline, not a per-read one: a peer sending one chunk before
    // each expiry renews a per-read bound forever, and this holds a stream slot
    // for as long as it keeps doing so. The value comes from
    // `[timeouts] body_secs` through the caller.
    let deadline_at = tokio::time::Instant::now() + body_deadline;

    loop {
        let (decoded, used, complete) =
            decode_chunks(&pending, MAX_REQUEST_BODY.saturating_sub(body.len()))?;
        // The framing of the chunks that just decoded is gone: only the
        // payload is left, and it was already charged as part of the raw bytes
        // it came from. So the difference goes back to the budget, and the
        // reservation keeps meaning "the bytes held right now" — the raw
        // bytes still waiting for their chunk, plus the body decoded so far.
        reservation.shrink(used.saturating_sub(decoded.len()));
        body.extend_from_slice(&decoded);
        pending.drain(..used);
        if complete {
            // Whatever is left in `pending` is the trailer section, which is
            // not forwarded and is dropped with this function. Those bytes are
            // given back rather than counted for as long as the body lives.
            reservation.shrink(pending.len());
            return Ok(reservation);
        }

        let n = match tokio::time::timeout_at(deadline_at, recv.read(&mut buf)).await {
            Ok(result) => result
                .map_err(|e| anyhow::anyhow!("failed to read request body from iroh: {}", e))?,
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "chunked request body did not finish within {}s",
                    body_deadline.as_secs()
                ));
            }
        };
        // A read of zero is the end of the stream: the peer stopped before the
        // terminating chunk, so the body is truncated.
        if n == 0 {
            return Err(anyhow::anyhow!(
                "chunked request body ended before its terminating chunk"
            ));
        }
        // The raw bytes are held while they wait for their chunk to complete,
        // so they are charged while they are held. A peer that declares a
        // 64 MiB chunk and then trickles the data into it holds those bytes
        // for as long as it takes, and the budget has to see them: it is the
        // difference between "this process holds 64 MiB" and "this process
        // holds nothing", and the budget is about the first one.
        reservation.grow(n)?;
        pending.extend_from_slice(&buf[..n]);
    }
}

/// Whether the request body is framed as chunks.
pub(super) fn request_is_chunked(req: &Request<()>) -> bool {
    req.headers()
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_lowercase().contains("chunked"))
}

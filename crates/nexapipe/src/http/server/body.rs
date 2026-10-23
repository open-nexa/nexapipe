//! The body of a request, in the shape the backend is sent it in.
//!
//! Two shapes: the bytes are here, or they are still on the client's stream.
//! The stream is **shared** with the copy the request carries, so a request
//! that fails before the body was read can send it again.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use super::{Frame, Incoming};
use crate::http::client::BoxError;
use crate::http::reader::SharedReader;
use hyper::StatusCode;

/// The body of a request, in the shape the backend is sent it in.
///
/// Two shapes, and the difference is what the backend is told:
///
/// - **Whole**: the bytes are here, so the backend is sent them with a
///   length of its own. A body that declared no length is this one: it
///   arrives framed, and the framing was the client's — so the proxy
///   re-frames it, because a backend that only knows `content-length`
///   cannot read a chunked request. Reading it whole is also what bounds
///   it.
/// - **Streaming**: the bytes are still on the client's stream, and they are
///   read as the backend asks for them. A body that declared a length is
///   this one: the length is known, so the upload never has to be held, and
///   the backend can start on the first byte.
pub enum RequestBody<B = Incoming> {
    /// The bytes are here, and they can be sent again.
    Whole {
        bytes: bytes::Bytes,
        /// What the process budget holds for them.
        reservation: crate::conn::limits::ByteReservation,
    },
    /// Still on the client's stream.
    Streaming(IncomingBody<B>),
}

impl<B> RequestBody<B>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: Into<BoxError>,
{
    /// Whether the request may be tried again.
    ///
    /// A body that is here can be sent again; one that is still on the
    /// client's stream can, as long as it has not been read — a body that
    /// has been read is gone, and there is no second copy of it.
    pub fn may_retry(&self) -> bool {
        match self {
            RequestBody::Whole { .. } => true,
            RequestBody::Streaming(body) => body.may_retry(),
        }
    }

    /// Whether the body's deadline expired while it was being read.
    pub fn did_time_out(&self) -> bool {
        match self {
            RequestBody::Whole { .. } => false,
            RequestBody::Streaming(body) => body.did_time_out(),
        }
    }

    /// Whether the body is over: everything the client promised has been
    /// read, or the client stopped sending.
    pub fn has_been_sent(&self) -> bool {
        match self {
            RequestBody::Whole { .. } => true,
            RequestBody::Streaming(body) => body.has_been_sent(),
        }
    }
}

/// A request body that could not be read.
///
/// The client is answered and the reason is logged. The body never reached a
/// backend, so the answer is about the request — not about a backend that
/// could not be blamed for it.
pub struct BodyFailure {
    /// The status the client is answered with.
    pub status: StatusCode,
    /// The body of the answer.
    pub message: &'static str,
    /// Why it failed, for the log.
    pub reason: String,
}

/// Reads the body of a request, in the shape the backend is sent it in.
///
/// The client's own declaration decides the shape, and it is the same
/// decision the hand-written path made:
///
/// - A body that **declares a length** is streamed. The bytes are still on
///   the client's side, and the backend reads them as it asks for them, so an
///   upload of any size costs a buffer rather than a copy of the upload. The
///   length is checked against the limit **before** a byte of it is read: it
///   is the size of the body this is about to carry.
/// - A body that **declares no length** arrives framed, and the framing was
///   the client's — so the proxy re-frames it. The bytes are read whole and
///   the backend is sent them with a length of its own, because a backend
///   that only knows `content-length` cannot read a chunked request. Reading
///   it whole is also what bounds it.
pub(super) async fn read_request_body(
    headers: &::http::HeaderMap,
    body: Incoming,
    timeouts: crate::config::Timeouts,
) -> Result<RequestBody, BodyFailure> {
    let declared = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());

    match declared {
        Some(length) => {
            if length > crate::http::body::MAX_REQUEST_BODY {
                return Err(BodyFailure {
                    status: StatusCode::PAYLOAD_TOO_LARGE,
                    message: "413 Payload Too Large",
                    reason: format!(
                        "a request body of {length} bytes is over the {} byte limit",
                        crate::http::body::MAX_REQUEST_BODY
                    ),
                });
            }
            Ok(RequestBody::Streaming(IncomingBody::new(
                body,
                timeouts.deadlines.body,
            )))
        }

        None => {
            match crate::http::body::read_body_limited(
                body,
                crate::http::body::MAX_REQUEST_BODY,
                timeouts.deadlines.body,
            )
            .await
            {
                Ok((bytes, reservation)) => Ok(RequestBody::Whole { bytes, reservation }),
                Err(e) => {
                    let (status, message) = match &e {
                        crate::http::body::BodyReadError::TooLarge { .. } => {
                            (StatusCode::PAYLOAD_TOO_LARGE, "413 Payload Too Large")
                        }
                        crate::http::body::BodyReadError::TimedOut { .. } => {
                            (StatusCode::REQUEST_TIMEOUT, "408 Request Timeout")
                        }
                        crate::http::body::BodyReadError::Failed(_) => {
                            (StatusCode::BAD_REQUEST, "400 Bad Request")
                        }
                    };
                    Err(BodyFailure {
                        status,
                        message,
                        reason: e.to_string(),
                    })
                }
            }
        }
    }
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
/// client's bytes are the only place they are. The reader is shared through a
/// cell it **leaves** rather than one it is locked in, so a task that polls
/// it never waits on a lock.
pub struct IncomingBody<B = Incoming> {
    /// Hyper's stream, shared with the copy the request carries.
    reader: Arc<SharedReader<B>>,
    /// What the owner of the request needs to know about this body.
    state: Arc<crate::http::body::BodyState>,
    /// When the body has to be finished by.
    deadline: tokio::time::Instant,
    /// The budget the bytes are charged to.
    ///
    /// The process-wide one is what a request is charged against. A caller
    /// with a budget of its own — a test that must not disturb the shared one
    /// — names it here.
    budget: Arc<crate::conn::limits::ByteBudget>,
}

impl<B> IncomingBody<B>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: Into<BoxError>,
{
    /// The body, and the deadline it is held to.
    pub fn new(inner: B, body_deadline: Duration) -> Self {
        Self::with_budget(
            inner,
            body_deadline,
            crate::conn::limits::body_budget().clone(),
        )
    }

    /// The body, the deadline it is held to, and the budget it is charged
    /// against.
    pub fn with_budget(
        inner: B,
        body_deadline: Duration,
        budget: Arc<crate::conn::limits::ByteBudget>,
    ) -> Self {
        Self {
            reader: Arc::new(SharedReader::new(inner)),
            state: Arc::new(crate::http::body::BodyState::default()),
            deadline: tokio::time::Instant::now() + body_deadline,
            budget,
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
    pub fn lend(&self) -> LentBody<B> {
        LentBody {
            reader: self.reader.clone(),
            state: self.state.clone(),
            deadline: self.deadline,
            timer: None,
            reservation: crate::conn::limits::ByteReservation::take_from(&self.budget, 0)
                .expect("a reservation of nothing is always available"),
        }
    }
}

/// The copy of the request body that the request carries.
///
/// It reads the shared stream, charges the bytes it reads to the process-wide
/// budget, and records that they were read — which is what the retry rule
/// asks, and what the access log's byte count is made of.
///
/// The reader is **taken out** of the cell it is shared through and put back
/// when the poll is over, on every path: a body that ended, a body that
/// failed, a body the budget refuses and a body that is not ready yet are all
/// the same to the copy that is lent out next. A task that finds the cell
/// empty waits for the reader instead of blocking a worker thread on a lock.
pub struct LentBody<B = Incoming> {
    /// Hyper's stream, shared with the owner of the request.
    reader: Arc<SharedReader<B>>,
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

impl<B> hyper::body::Body for LentBody<B>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: Into<BoxError>,
{
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

        // The reader is **taken out** of the cell it is shared through, not
        // locked in it: a `std::sync::Mutex` taken inside a poll parks the
        // worker thread every other task on this runtime is scheduled on, and
        // the reader is held for the length of the poll.
        //
        // A task that finds the cell empty registers its waker and waits for
        // the holder to give the reader back.
        let Some(mut reader) = this.reader.take(cx) else {
            return Poll::Pending;
        };

        let polled = Pin::new(&mut reader).poll_frame(cx);
        let outcome = match polled {
            Poll::Ready(Some(Ok(frame))) => {
                let mut charged = Ok(());
                if let Some(data) = frame.data_ref() {
                    this.state.mark_read();
                    charged = this.reservation.grow(data.len());
                    if charged.is_ok() {
                        crate::metrics::METRICS.record_bytes_received(data.len() as u64);
                    }
                }
                match charged {
                    Ok(()) => Poll::Ready(Some(Ok(frame))),
                    Err(e) => Poll::Ready(Some(Err(e.into()))),
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => {
                this.state.mark_sent();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        };

        // The reader goes back whatever the poll said: the bytes are on the
        // client's stream once, and the copy that is lent out next is the one
        // that has to read them.
        this.reader.put_back(reader);

        outcome
    }
}

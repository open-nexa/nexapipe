//! What the access log says, and the body that writes it.
//!
//! The line is written when the answer's body is over, because the bytes it
//! reports are the bytes that reached the client, and they are not known
//! until then.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use super::{Frame, Incoming};
use crate::http::response::BodyError;

/// What the access log says about a request that was answered.
///
/// It travels with the answer's body, because the answer is not over until
/// the body is: the bytes that reached the client are counted as they go
/// out, and the line is written when the last of them has gone. A line
/// written when the head went out would report a body of nothing, and a
/// duration that stopped before the answer did.
pub struct AccessReport {
    /// The id of the request.
    pub request_id: String,
    /// The span the request was served under.
    ///
    /// The line is written when the answer's body is over, which is after the
    /// request's own future is gone — so the span travels with the report for
    /// the line to be logged under the request it belongs to, rather than
    /// under the stream it arrived on.
    pub span: tracing::Span,
    /// Who sent it.
    pub peer: String,
    /// The method.
    pub method: String,
    /// What was asked for.
    pub request_target: String,
    /// The status the client is being answered with.
    pub status: u16,
    /// When the request started: the duration is the whole exchange.
    pub started: std::time::Instant,
    /// Who the connection authenticated as.
    pub who: crate::conn::peers::PeerIdentity,
}

/// The backend's answer, counted as it goes out.
///
/// The count is what the access log reports, and it is taken at the write
/// rather than at the format: a body that died half way is reported as the
/// half that arrived, not as the whole that was intended.
pub struct CountedBody<B = Incoming> {
    /// The backend's own stream.
    inner: B,
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
    ///
    /// Armed on the first poll and re-armed after every frame: what it
    /// bounds is the gap between two frames, not the time since the answer
    /// was created.
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// What the access log says, once the answer is over.
    report: Option<AccessReport>,
}

impl<B> CountedBody<B> {
    /// The answer, and where the count is kept.
    pub fn new(
        inner: B,
        bytes_sent: Arc<AtomicUsize>,
        idle: Duration,
        report: Option<AccessReport>,
    ) -> Self {
        Self {
            inner,
            bytes_sent,
            idle,
            timer: None,
            report,
        }
    }
}

impl<B> Drop for CountedBody<B> {
    fn drop(&mut self) {
        // The answer is over: whatever reached the client is what the line
        // says, and a body that died half way is reported as the half that
        // arrived.
        let Some(report) = self.report.take() else {
            return;
        };
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        // Under the request's own span: the line is written here, but it is
        // about the request, and the span it is logged under is the one that
        // request was served in.
        report.span.in_scope(|| {
            crate::log::log_access(
                &report.request_id,
                &report.peer,
                &report.method,
                &report.request_target,
                report.status,
                report.started.elapsed().as_millis() as u64,
                bytes_sent,
                Some(&report.who),
            );
        });
    }
}

impl<B> hyper::body::Body for CountedBody<B>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: Into<BodyError>,
{
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
        //
        // **The bound is checked before the timer is re-armed.** A timer that
        // is reset and then polled is always in the future, so the check
        // below could never fire: the bound would be a comment, and a backend
        // that accepted the request and then went quiet would hold this slot
        // and its backend lease for as long as the peer kept the stream open.
        // The timer is re-armed when a frame arrives instead — the gap
        // between two frames is what is bounded, so a backend that keeps
        // talking is never cut off.
        let timer = this
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(this.idle)));
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(BodyError::Idle(this.idle))));
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // The backend is talking, so the next gap starts now.
                timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.idle);
                if let Some(data) = frame.data_ref() {
                    this.bytes_sent.fetch_add(data.len(), Ordering::Relaxed);
                    // The process-wide total counts what left for the client,
                    // and it counts it as it leaves.
                    crate::metrics::METRICS.record_bytes_sent(data.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

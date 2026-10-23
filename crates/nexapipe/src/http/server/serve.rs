//! The entry point: the stream handed to hyper, and the service hyper calls.
//!
//! The stream is handed over whole — hyper reads the head, hands the service a
//! request, and writes the answer the service returns — and the service is
//! called once per request rather than once per connection.

use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use tracing::Instrument;

use super::Context;
use super::MAX_HEAD;
use super::request::handle;

/// Serve one iroh bi-stream as HTTP.
///
/// The stream is handed to hyper whole: hyper reads the head, hands the
/// service a request, and writes the answer the service returns. Nothing is
/// read out of the stream and put back.
///
/// `prefix` holds the bytes that were already read off the stream — the first
/// byte of a connection that did not say what it carries. They are handed back
/// before the rest, so hyper reads the head from the beginning.
pub async fn serve(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    prefix: Vec<u8>,
    head_timeout: Duration,
    ctx: Arc<Context>,
) -> anyhow::Result<()> {
    let io =
        crate::hyper_io::IrohIo::reading_through(send, crate::hyper_io::Replay::new(prefix, recv));
    serve_io(io, head_timeout, ctx).await
}

/// The same, over any IO hyper can read and write.
///
/// Split out from [`serve`] so that the path can be driven over a plain
/// duplex pair: the rules this path follows are worth more than the iroh
/// stream they arrive on, and a test can make a stream of its own.
pub(super) async fn serve_io<IO>(
    io: IO,
    head_timeout: Duration,
    ctx: Arc<Context>,
) -> anyhow::Result<()>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service_ctx = ctx.clone();
    // **One id and one span per request.** `service_fn` is called once per
    // request rather than once per connection, which is what makes the two
    // line up: hyper serves keep-alive requests on one stream, so an id
    // minted per connection would be the id of every request on it, and a
    // client quoting that id could not be matched to one log line.
    //
    // The plaintext listener does the same, and for the same reason.
    let service = service_fn(move |req| {
        let request_id = crate::log::next_request_id();
        let span = tracing::info_span!(
            "request",
            id = %request_id,
            method = tracing::field::Empty,
            uri = tracing::field::Empty,
            status = tracing::field::Empty,
        );
        // The context of **this** request: the connection's own, with the id
        // of this request in it. Everything the handler logs — the access
        // line, the `x-request-id` header — carries that id.
        let mut request_ctx = (*service_ctx).clone();
        request_ctx.request_id = request_id;
        handle(req, Arc::new(request_ctx)).instrument(span)
    });

    hyper::server::conn::http1::Builder::new()
        // The deadline below is measured with this.
        .timer(crate::hyper_io::TokioTimer)
        // The head has to arrive within the head budget: a peer that opens a
        // stream and sends nothing must not hold the slot forever. The same
        // bound the hand-written reader applied, and hyper applies it to the
        // head rather than to every read.
        .header_read_timeout(head_timeout)
        // A head over this is not a request.
        .max_buf_size(MAX_HEAD)
        // The client finishes its half of the stream once the request is out
        // and waits for the answer, which is what a tunnel client does and what
        // a browser does over a connection it will not reuse. Hyper reads the
        // end of the write half as the end of the connection unless it is told
        // that a half-close is a thing.
        .half_close(true)
        .serve_connection(io, service)
        // **`with_upgrades`, not the plain connection.** The plain one refuses
        // to hand a connection over: an upgrade it cannot follow ends the
        // connection with "upgrade expected but low level API in use". The
        // upgradeable one gives the stream to whoever asked for it — here,
        // the task that runs the WebSocket session — and keeps the bytes that
        // were read past the head.
        .with_upgrades()
        .await
        .map_err(|e| anyhow::anyhow!("the connection ended in error: {e}"))
}

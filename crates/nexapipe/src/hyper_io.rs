//! An iroh bi-stream as hyper's IO, so the tunnel path can use hyper's own
//! HTTP/1 codec.
//!
//! The two ends of the tunnel are an iroh `SendStream` and a `RecvStream`.
//! Hyper reads and writes through **its own** IO traits — not tokio's — so
//! the streams have to be presented as one of those before hyper's codec can
//! be pointed at them.
//!
//! This is the same shape as [`DuplexIroh`], which presents the same pair as
//! a tokio duplex stream. The two are kept apart because their traits are
//! apart: tokio's `AsyncRead`/`AsyncWrite` and hyper's `Read`/`Write` say
//! the same thing in different words, and a type that implements one does not
//! implement the other.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::rt::ReadBufCursor;

/// An iroh bi-stream seen as hyper's IO.
pub struct IrohIo {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

impl IrohIo {
    /// The two halves of one bi-stream.
    pub fn new(send: iroh::endpoint::SendStream, recv: iroh::endpoint::RecvStream) -> Self {
        IrohIo { send, recv }
    }
}

impl hyper::rt::Read for IrohIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();

        // Hyper's cursor and tokio's buffer are the same idea — a region of
        // memory with a "filled" part and an "unfilled" part — and the bytes
        // tokio writes into the unfilled part are the bytes hyper reads out
        // of it. The cursor hands out its unfilled region as
        // `MaybeUninit<u8>`, which is what tokio's `ReadBuf::uninit` takes.
        //
        // SAFETY: the region belongs to the cursor, and the cursor is only
        // advanced by this function, after the read has said how many bytes
        // arrived. A `MaybeUninit<u8>` is exactly what an uninitialized
        // buffer is.
        let mut read_buf = tokio::io::ReadBuf::uninit(unsafe { buf.as_mut() });

        match tokio::io::AsyncRead::poll_read(Pin::new(&mut this.recv), cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                // The bytes tokio read are initialized, so the cursor can be
                // told they are there.
                let filled = read_buf.filled().len();
                // SAFETY: the cursor's unfilled region is the one tokio was
                // given, and `filled` is how many of those bytes tokio
                // initialized.
                unsafe { buf.advance(filled) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl hyper::rt::Write for IrohIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let out = tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf);
        out
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }

    fn is_write_vectored(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::IrohIo;
    use iroh::Endpoint;
    use iroh::endpoint::presets;
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;

    const ALPN: &[u8] = b"nexapipe";

    /// **Hyper's own HTTP/1 codec serves a request over an iroh bi-stream.**
    ///
    /// This is the whole point of the adapter: hyper reads the head itself,
    /// so nothing has to be read out of the stream and handed back, and the
    /// request arrives whole.
    #[tokio::test]
    async fn hyper_serves_a_request_over_an_iroh_stream() {
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the server binds");
        let server_addr = server.addr();
        // The endpoint and the connection both outlive the stream: a dropped
        // endpoint takes every connection on it down, and a dropped
        // `Connection` handle closes the connection — and a connection that
        // closes before the answer is on its way loses it.
        let _server = server.clone();

        let incoming = server.accept().await.expect("a connection");
        let accepting = incoming.accept().expect("the connection is accepted");
        let connection = accepting.await.expect("the handshake finishes");
        let _connection = connection.clone();

        tokio::spawn(async move {
            let (send, recv) = connection.accept_bi().await.expect("a bi-stream");

            let io = IrohIo::new(send, recv);
            let service = hyper::service::service_fn(
                |req: hyper::Request<hyper::body::Incoming>| async move {
                    Ok::<_, hyper::Error>(hyper::Response::new(http_body_util::Full::new(
                        bytes::Bytes::from_static(b"hello"),
                    )))
                },
            );
            let outcome = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the client binds");
        let connection = client
            .connect(server_addr, ALPN)
            .await
            .expect("the connection opens");
        let (mut send, mut recv) = connection.open_bi().await.expect("a bi-stream");

        send.write_all(b"GET /thing HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("the request goes out");

        let mut answer = Vec::new();
        // The trait path, not the inherent method: iroh's own `read_to_end`
        // takes a length rather than a buffer.
        tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut answer)
            .await
            .expect("the answer comes back");
        let answer = String::from_utf8_lossy(&answer).to_string();

        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("hello"), "{answer}");
    }
}

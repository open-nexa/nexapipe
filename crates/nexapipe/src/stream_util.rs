//! Byte-stream plumbing shared by the two paths that move opaque bytes.
//!
//! TLS passthrough and the L4 tunnel both end up doing the same two things: presenting
//! an iroh bi-stream as one duplex object, and copying bytes both ways until one side
//! stops. They differ only in what they do *before* that point — SNI sniffing versus
//! preface decoding — so that part stays in each module.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Read size for the copy loops. Large enough that a 1400-byte inner segment never
/// needs two syscalls, small enough to stay off the allocator's slow path.
pub const COPY_BUF_SIZE: usize = 16 * 1024;

/// An iroh bi-stream seen as one duplex stream, so it can be piped like a socket.
///
/// The iroh streams also carry inherent `poll_*` methods with their own error type,
/// which win method resolution; the trait paths below are written out in full so the
/// tokio ones are the ones called.
pub struct DuplexIroh {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

impl DuplexIroh {
    pub fn new(send: iroh::endpoint::SendStream, recv: iroh::endpoint::RecvStream) -> Self {
        DuplexIroh { send, recv }
    }
}

impl AsyncRead for DuplexIroh {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for DuplexIroh {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

/// Copies bytes in both directions until either side stops.
///
/// First EOF wins rather than waiting for both: a tunnel is finished when either end
/// is, and waiting would pin a half-open connection. Both ends are then half-closed,
/// so the peers see a clean EOF instead of a dropped connection.
///
/// The result is the one from the direction that finished first. A clean EOF on
/// either side is `Ok`, so this only reports a transport failure — which is the
/// difference between a tunnel that ended and one that broke, and the caller needs
/// it to log the right thing.
///
/// `label` only ever reaches a debug log — it exists so an operator can tell the TLS
/// path from the L4 path when both are in play.
pub async fn copy_both_ways<A, B>(client: A, backend: B, label: &str) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);

    // The halves are borrowed, not moved, because the direction that loses the race
    // is dropped mid-flight and a shutdown written inside it would never run. Shutting
    // both write halves down out here is what makes the half-close reach both peers.
    let finished = tokio::select! {
        result = copy_one_way(&mut client_read, &mut backend_write, label, "client->backend") => result,
        result = copy_one_way(&mut backend_read, &mut client_write, label, "backend->client") => result,
    };

    let _ = backend_write.shutdown().await;
    let _ = client_write.shutdown().await;

    finished
}

/// Copies until `reader` ends. Returns `Ok` on a clean EOF, and the error otherwise.
async fn copy_one_way<R, W>(
    reader: &mut R,
    writer: &mut W,
    label: &str,
    direction: &str,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUF_SIZE];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) => {
                tracing::debug!("{}: {} read failed: {}", label, direction, e);
                return Err(e);
            }
        };

        writer.write_all(&buf[..n]).await.map_err(|e| {
            tracing::debug!("{}: {} write failed: {}", label, direction, e);
            e
        })?;
        // An iroh send stream buffers, so without this the last bytes of a reply can
        // sit in the buffer until the tunnel is torn down. On a TcpStream it is a no-op.
        writer.flush().await.map_err(|e| {
            tracing::debug!("{}: {} flush failed: {}", label, direction, e);
            e
        })?;
    }
}

/// Appends one chunk to `buf`; `false` on EOF, timeout or read error.
///
/// A peer that goes quiet is not an error here: the caller decides whether the bytes
/// received so far are enough (SNI parsing) or not (a preface that must be complete).
pub async fn read_more<R>(reader: &mut R, buf: &mut Vec<u8>, timeout: Duration) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    match tokio::time::timeout(timeout, reader.read(&mut chunk)).await {
        Ok(Ok(0)) => Ok(false),
        Ok(Ok(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(false),
    }
}

/// The same, bounded by a deadline for the whole read rather than by one idle
/// gap between chunks.
///
/// A peer that sends a byte just inside the timeout restarts a per-read one
/// every time, which kept a stream slot — and the buffer behind it — alive for
/// as long as it cared to keep dribbling. Anything that waits on a peer to
/// finish saying something wants this one, not [`read_more`].
pub async fn read_more_by<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    match tokio::time::timeout_at(deadline, reader.read(&mut chunk)).await {
        Ok(Ok(0)) => Ok(false),
        Ok(Ok(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Two in-memory pipes: `copy_both_ways` gets one end of each, and the test
    /// plays the client and the backend from the other ends.
    fn pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (client_end, client_side) = duplex(1024);
        let (backend_end, backend_side) = duplex(1024);
        (client_end, backend_end, client_side, backend_side)
    }

    #[tokio::test]
    async fn copies_bytes_in_both_directions() {
        let (mut client_end, mut backend_end, client_side, backend_side) = pair();
        let copy = tokio::spawn(copy_both_ways(client_side, backend_side, "test"));

        client_end.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        backend_end.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        backend_end.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        client_end.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        drop(client_end);
        drop(backend_end);
        copy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn half_closes_the_backend_when_the_client_stops() {
        let (mut client_end, mut backend_end, client_side, backend_side) = pair();
        let copy = tokio::spawn(copy_both_ways(client_side, backend_side, "test"));

        client_end.write_all(b"hello").await.unwrap();
        drop(client_end);

        // The client's end of stream has to reach the backend as one: everything
        // it sent, then a clean EOF rather than a dropped connection.
        let mut seen = Vec::new();
        backend_end.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"hello");

        copy.await.unwrap().unwrap();
    }

    /// A stream that fails the first read and swallows everything written to it.
    ///
    /// `duplex` cannot produce this: dropping the far end is a clean EOF, and a
    /// transport failure is the case the return value has to tell apart.
    struct Broken;

    impl AsyncRead for Broken {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("broken transport")))
        }
    }

    impl AsyncWrite for Broken {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_client_that_fails_mid_flow_is_reported_as_an_error() {
        let (_backend_end, backend_side) = duplex(1024);
        let result = copy_both_ways(Broken, backend_side, "test").await;
        assert!(
            result.is_err(),
            "a broken transport is not a clean end of stream"
        );
    }

    #[tokio::test]
    async fn a_backend_that_fails_mid_flow_is_reported_as_an_error() {
        let (_client_end, client_side) = duplex(1024);
        let result = copy_both_ways(client_side, Broken, "test").await;
        assert!(
            result.is_err(),
            "a broken transport is not a clean end of stream"
        );
    }

    #[tokio::test]
    async fn half_closes_the_client_when_the_backend_stops() {
        let (mut client_end, mut backend_end, client_side, backend_side) = pair();
        let copy = tokio::spawn(copy_both_ways(client_side, backend_side, "test"));

        backend_end.write_all(b"bye").await.unwrap();
        drop(backend_end);

        let mut seen = Vec::new();
        client_end.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"bye");

        copy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn returns_when_the_far_end_disappears() {
        let (mut client_end, _backend_end, client_side, backend_side) = pair();
        let copy = tokio::spawn(copy_both_ways(client_side, backend_side, "test"));

        // The backend is gone mid-flow. What matters is that the copy comes
        // back: a tunnel that keeps a task (and its stream) alive after the far
        // end vanished would leak one per abandoned connection.
        drop(_backend_end);
        let returned = tokio::time::timeout(Duration::from_secs(5), copy).await;
        assert!(returned.is_ok(), "copy_both_ways never returned");

        let mut rest = Vec::new();
        let _ = client_end.read_to_end(&mut rest).await;
    }

    #[tokio::test]
    async fn read_more_appends_the_chunk_it_read() {
        let (mut writer, mut reader) = duplex(1024);
        writer.write_all(b"abc").await.unwrap();

        let mut buf = Vec::new();
        let more = read_more(&mut reader, &mut buf, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(more);
        assert_eq!(buf, b"abc");
    }

    #[tokio::test]
    async fn read_more_reports_eof() {
        let (writer, mut reader) = duplex(1024);
        drop(writer);

        let mut buf = Vec::new();
        let more = read_more(&mut reader, &mut buf, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!more);
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn read_more_reports_a_silent_peer_as_false() {
        let (_writer, mut reader) = duplex(1024);

        // Nothing is ever written, so this is the timeout path: a peer that goes
        // quiet is not an error, the caller decides whether what arrived so far
        // is enough.
        let mut buf = Vec::new();
        let more = read_more(&mut reader, &mut buf, Duration::from_millis(50))
            .await
            .unwrap();
        assert!(!more);
        assert!(buf.is_empty());
    }
}

//! The TCP half: the connections the device opens, and the bytes they carry.
//!
//! A connection the device opens arrives as a segment that starts a
//! handshake. The stack answers it — the handshake, the windows and the
//! retransmissions are smoltcp's work — and what is left for this module is
//! the byte stream: the bytes the peer sends have to reach the application,
//! and the bytes the application writes have to reach the peer.
//!
//! The two ends of a flow are in different tasks. The runner owns the socket
//! inside smoltcp; the application owns a [`TcpStream`]. Between them is a
//! block of state they both touch: a buffer for each direction, and the
//! waker of whoever is waiting on it.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use futures_util::Stream;
use smoltcp::storage::RingBuffer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

/// A connection the device opened.
///
/// The stream is the device's end of the connection: what the application
/// writes goes to the peer, and what the peer sends comes back.
pub struct TcpStream {
    control: Arc<SocketControl>,
    /// The application's address: where the connection comes from.
    src: SocketAddr,
    /// The address the application asked for: where the connection goes.
    dst: SocketAddr,
}

impl TcpStream {
    /// A stream for a connection that has just been opened.
    pub(super) fn new(control: Arc<SocketControl>, src: SocketAddr, dst: SocketAddr) -> Self {
        Self { control, src, dst }
    }

    /// The application's address.
    ///
    /// **The name is the opposite of what a socket of the application's own
    /// would say**, and the inversion is deliberate: the stack plays the
    /// *server* in the connection the device opened, so the address the
    /// connection comes from is the one the device's socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.src
    }

    /// The address the application asked for.
    pub fn remote_addr(&self) -> SocketAddr {
        self.dst
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.control.poll_read(cx, buf)
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // The application is gone: the runner looks at the flows that are
        // left when it wakes up, so it has to be woken to notice.
        self.control.notify.notify_one();
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.control.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The bytes are already in the flow's own buffer; the runner moves
        // them into the stack when it can.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.control.poll_shutdown(cx)
    }
}

/// The connections the device opens.
///
/// Each item is the stream, the application's address, and the address the
/// application asked for.
pub struct TcpListener {
    rx: mpsc::UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    /// A listener over the connections the runner opens.
    pub(super) fn new(rx: mpsc::UnboundedReceiver<TcpStream>) -> Self {
        Self { rx }
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(stream)) => {
                let client = stream.local_addr();
                let server = stream.remote_addr();
                Poll::Ready(Some((stream, client, server)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// What a flow's two ends share.
///
/// The runner owns the socket inside smoltcp and reaches the flow through
/// this; the application owns the [`TcpStream`] and reaches it through the
/// same block.
pub(super) struct SocketControl {
    state: Mutex<FlowState>,
    /// Wakes the runner when the application has something for it.
    notify: Arc<Notify>,
}

/// The state of one flow.
struct FlowState {
    /// What the peer sent, waiting for the application.
    recv: RingBuffer<'static, u8>,
    /// What the application wrote, waiting for the peer.
    send: RingBuffer<'static, u8>,
    /// The peer closed its side.
    recv_closed: bool,
    /// The application closed its side.
    send_closed: bool,
    /// The FIN has been handed to the stack.
    fin_sent: bool,
    /// The socket is closed.
    socket_closed: bool,
    /// Whoever is waiting for the peer's bytes.
    recv_waker: Option<Waker>,
    /// Whoever is waiting for room in the outgoing buffer.
    send_waker: Option<Waker>,
    /// Whoever is waiting for the connection to be shut down.
    close_waker: Option<Waker>,
}

impl FlowState {
    fn wake_reader(&mut self) {
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }

    fn wake_writer(&mut self) {
        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
    }

    fn wake_closer(&mut self) {
        if let Some(waker) = self.close_waker.take() {
            waker.wake();
        }
    }
}

impl SocketControl {
    /// A flow with room for a window's worth of bytes in each direction.
    pub(super) fn new(recv_capacity: usize, send_capacity: usize, notify: Arc<Notify>) -> Self {
        Self {
            state: Mutex::new(FlowState {
                recv: RingBuffer::new(vec![0u8; recv_capacity]),
                send: RingBuffer::new(vec![0u8; send_capacity]),
                recv_closed: false,
                send_closed: false,
                fin_sent: false,
                socket_closed: false,
                recv_waker: None,
                send_waker: None,
                close_waker: None,
            }),
            notify,
        }
    }

    /// The state, whatever happened to the lock.
    ///
    /// A panic while the lock was held would have left the state behind in a
    /// shape the flow can still work with, so the poison is not fatal.
    fn lock(&self) -> MutexGuard<'_, FlowState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How many bytes the application may still take.
    pub(super) fn recv_space(&self) -> usize {
        self.lock().recv.window()
    }

    /// Move what the peer sent into the application's buffer.
    ///
    /// `from` is what the socket has received; the bytes that are taken from
    /// it are the ones the socket's window gives back. Returns how many
    /// bytes moved.
    pub(super) fn copy_in(&self, from: &mut [u8], limit: usize) -> usize {
        let mut state = self.lock();
        let space = limit.min(state.recv.window());
        if space == 0 {
            return 0;
        }
        let take = space.min(from.len());
        let written = state.recv.enqueue_slice(&from[..take]);
        if written > 0 {
            state.wake_reader();
        }
        written
    }

    /// Move what the application wrote into the socket's send buffer.
    ///
    /// `into` is the room the socket has; the bytes that are put in it are
    /// the ones the socket will send. Returns how many bytes moved.
    pub(super) fn copy_out(&self, into: &mut [u8]) -> usize {
        let mut state = self.lock();
        if state.send.is_empty() {
            return 0;
        }
        let written = state.send.dequeue_slice(into);
        if written > 0 {
            state.wake_writer();
        }
        written
    }

    /// The peer closed its side.
    pub(super) fn mark_recv_closed(&self) {
        let mut state = self.lock();
        if !state.recv_closed {
            state.recv_closed = true;
            state.wake_reader();
        }
    }

    /// The FIN has been handed to the stack.
    pub(super) fn mark_fin_sent(&self) {
        let mut state = self.lock();
        state.fin_sent = true;
        state.wake_closer();
    }

    /// The socket is closed.
    pub(super) fn mark_socket_closed(&self) {
        let mut state = self.lock();
        state.socket_closed = true;
        state.recv_closed = true;
        state.wake_reader();
        // A writer that is waiting for room in the outgoing buffer has to be
        // woken: it would otherwise wait for a room that is never going to
        // come, and the flow would never end.
        state.wake_writer();
        state.wake_closer();
    }

    /// Whether the application has nothing left to send.
    pub(super) fn send_is_empty(&self) -> bool {
        self.lock().send.is_empty()
    }

    /// Whether the application asked to stop sending.
    pub(super) fn send_closed(&self) -> bool {
        self.lock().send_closed
    }

    /// Whether the FIN has been handed over.
    pub(super) fn fin_sent(&self) -> bool {
        self.lock().fin_sent
    }

    /// Take what the peer sent, if there is any.
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.lock();
        if state.recv.is_empty() {
            if state.recv_closed {
                // The peer is done: this is the end of the stream.
                return Poll::Ready(Ok(()));
            }
            state.recv_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let moved = state.recv.dequeue_slice(buf.initialize_unfilled());
        buf.advance(moved);
        drop(state);
        if moved > 0 {
            // Room was freed: the runner can move the rest of the socket's
            // bytes out of it, and the window the peer sees opens again.
            self.notify.notify_one();
        }
        Poll::Ready(Ok(()))
    }

    /// Put what the application wrote into the flow's outgoing buffer.
    fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.lock();
        if state.send_closed || state.socket_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the connection is closed",
            )));
        }
        if state.send.is_full() {
            state.send_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let written = state.send.enqueue_slice(data);
        drop(state);
        // The runner has to move the bytes into the socket.
        self.notify.notify_one();
        Poll::Ready(Ok(written))
    }

    /// The application is done sending.
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.lock();
        state.send_closed = true;
        if state.fin_sent || state.socket_closed {
            return Poll::Ready(Ok(()));
        }
        state.close_waker = Some(cx.waker().clone());
        drop(state);
        // The runner closes the socket once the bytes are out.
        self.notify.notify_one();
        Poll::Pending
    }
}

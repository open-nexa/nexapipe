//! The user-space TCP/IP stack behind the TUN proxy.
//!
//! The TUN device hands out raw IP packets and expects raw IP packets back.
//! Between them sits a stack: it has to terminate the TCP connections the
//! device opens — the handshake, the windows, the retransmissions — because
//! the tunnel that carries the traffic to the server is a byte stream, not a
//! packet pipe. The device's packets go in one side, the tunnel's bytes come
//! out of the other.
//!
//! The stack is [smoltcp], driven directly by this module. It is the only
//! third-party dependency in the TUN path, and it is the unpatched crates.io
//! release: the sequence-number underflow panic that once required a vendored
//! fork of smoltcp is fixed upstream (smoltcp PR #1079), and 0.13 is the
//! first release that carries the fix.
//!
//! # The shape of it
//!
//! ```text
//! TUN ──IP frames──► Stack (a Sink: packets into the stack)
//!                        │
//!                        ├── TCP, ICMP ──► the runner ──► the smoltcp interface
//!                        └── UDP ────────► the UDP read half
//!
//! TUN ◄──IP frames── Stack (a Stream: packets out of the stack)
//!                        ▲
//!                        └── the runner and the UDP write half
//! ```
//!
//! The runner owns the smoltcp interface and the sockets in it, and it is the
//! only task that talks to smoltcp. The application side of a flow — the
//! [`TcpStream`] — shares a small block of state with the runner: two ring
//! buffers and the wakers of whoever is waiting on them.
//!
//! [smoltcp]: https://crates.io/crates/smoltcp

mod device;
mod packet;
mod runner;
mod tcp;
#[cfg(test)]
mod tests;
mod udp;

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use smoltcp::iface::{Config as IfaceConfig, Interface};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::PollSender;

pub use runner::Runner;
pub use tcp::{TcpListener, TcpStream};
pub use udp::{ReadHalf, UdpDatagram, UdpSocket, WriteHalf};

/// How many IP frames may be waiting to go out to the device.
///
/// The queue is what absorbs a burst: the device reads a frame, the stack
/// answers it, and the answer waits here until the device's writer picks it
/// up. A full queue is back-pressure, not a loss — the stack keeps the packet
/// and sends it again.
const EGRESS_QUEUE: usize = 1024;

/// How many IP frames may be waiting to go into the stack.
const INGRESS_QUEUE: usize = 64;

/// How many UDP frames may be waiting for the UDP read half.
const UDP_QUEUE: usize = 512;

/// Why the stack could not be built, or stopped.
#[derive(Debug)]
pub enum StackError {
    /// The configuration is not one the stack can run with.
    InvalidConfig(&'static str),
    /// The other end of one of the stack's channels is gone.
    Closed,
}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StackError::InvalidConfig(what) => write!(f, "the stack cannot run with {what}"),
            StackError::Closed => write!(f, "the other end of the stack is gone"),
        }
    }
}

impl std::error::Error for StackError {}

impl From<StackError> for crate::ClientError {
    fn from(error: StackError) -> Self {
        match error {
            StackError::InvalidConfig(what) => crate::ClientError::InvalidConfig(what.to_string()),
            StackError::Closed => crate::ClientError::Other("the stack is gone".to_string()),
        }
    }
}

/// How the stack is put together.
///
/// The defaults are the ones a caller that does not care would want; the TUN
/// proxy sets the window sizes itself, because the window is what a flow
/// costs and what a flow carries.
#[derive(Clone, Debug)]
pub struct StackBuilder {
    tcp: bool,
    udp: bool,
    mtu: usize,
    tcp_recv_buffer_size: u32,
    tcp_send_buffer_size: u32,
}

impl Default for StackBuilder {
    fn default() -> Self {
        Self {
            tcp: false,
            udp: false,
            mtu: 1500,
            tcp_recv_buffer_size: 64 * 1024,
            tcp_send_buffer_size: 64 * 1024,
        }
    }
}

impl StackBuilder {
    /// A builder with nothing enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the stack terminates TCP connections.
    pub fn enable_tcp(mut self, enable: bool) -> Self {
        self.tcp = enable;
        self
    }

    /// Whether the stack carries UDP datagrams.
    pub fn enable_udp(mut self, enable: bool) -> Self {
        self.udp = enable;
        self
    }

    /// The largest IP frame the device carries, in bytes.
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// The window a TCP socket advertises, in bytes.
    ///
    /// This is also how much a flow may hold at once, so it is a memory
    /// budget as much as a throughput one.
    pub fn tcp_recv_buffer_size(mut self, size: u32) -> Self {
        self.tcp_recv_buffer_size = size;
        self
    }

    /// How much a TCP socket may have queued to send, in bytes.
    pub fn tcp_send_buffer_size(mut self, size: u32) -> Self {
        self.tcp_send_buffer_size = size;
        self
    }

    /// Build the stack.
    ///
    /// Returns the packet halves, the task that drives the stack, and the two
    /// halves of the UDP socket. The task is `None` when neither TCP nor UDP
    /// is enabled, and so are the sockets.
    pub fn build(
        self,
    ) -> Result<
        (
            Stack,
            Option<Runner>,
            Option<UdpSocket>,
            Option<TcpListener>,
        ),
        StackError,
    > {
        if self.mtu == 0 {
            return Err(StackError::InvalidConfig("an MTU of zero"));
        }

        let (egress_tx, egress_rx) = mpsc::channel(EGRESS_QUEUE);
        let (ingress_tx, ingress_rx) = mpsc::channel(INGRESS_QUEUE);
        let (udp_tx, udp_rx) = mpsc::channel(UDP_QUEUE);
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let notify = Arc::new(Notify::new());

        let stack = Stack {
            egress: egress_rx,
            ingress: PollSender::new(ingress_tx),
            udp: self.udp.then(|| PollSender::new(udp_tx)),
            pending: None,
        };

        if !self.tcp && !self.udp {
            return Ok((stack, None, None, None));
        }

        let mut device = device::FrameDevice::new(egress_tx.clone(), self.mtu);
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        // The seed decides the initial sequence numbers and the ephemeral
        // ports, so it has to differ from one run to the next.
        config.random_seed = fastrand::u64(..);

        let now = Instant::now();
        let mut iface = Interface::new(config, &mut device, now);
        // The device addresses are the virtual ones the tunnel hands out, and
        // they are not assigned to any interface the operating system knows
        // about. AnyIP says so: accept a packet for any address.
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            // The addresses themselves do not matter under AnyIP; they are
            // placeholders so that the interface has an address to answer from.
            let _ = addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0));
            let _ = addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Addr::new(0, 0, 0, 1));
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

        let runner = runner::spawn(runner::RunnerParts {
            device,
            iface,
            ingress: ingress_rx,
            accept: accept_tx,
            notify: notify.clone(),
            tcp_recv_buffer_size: self.tcp_recv_buffer_size,
            tcp_send_buffer_size: self.tcp_send_buffer_size,
            tcp_enabled: self.tcp,
        });

        let udp_socket = self.udp.then(|| UdpSocket::new(udp_rx, egress_tx.clone()));
        let tcp_listener = self.tcp.then(|| TcpListener::new(accept_rx));

        Ok((stack, Some(runner), udp_socket, tcp_listener))
    }
}

/// The packet halves: the frames going into the stack, and the frames coming
/// out of it.
///
/// The two directions are one value, split by [`futures_util::StreamExt::split`],
/// because the device reads and writes at the same time and neither side
/// should hold the other's lock.
pub struct Stack {
    /// The frames the stack produces, on their way to the device.
    egress: mpsc::Receiver<Vec<u8>>,
    /// The frames from the device, on their way into the stack.
    ingress: PollSender<Vec<u8>>,
    /// The UDP frames from the device, on their way to the UDP read half.
    ///
    /// `None` when UDP is not enabled, in which case a UDP frame is not ours
    /// to carry.
    udp: Option<PollSender<Vec<u8>>>,
    /// The frame waiting to be handed over.
    pending: Option<Pending>,
}

/// A frame on its way into the stack, and where it goes.
struct Pending {
    frame: Vec<u8>,
    /// Whether the frame is UDP, and so goes to the UDP half rather than to
    /// the runner.
    udp: bool,
}

impl Stream for Stack {
    type Item = Result<Vec<u8>, StackError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.egress.poll_recv(cx) {
            Poll::Ready(Some(frame)) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for Stack {
    type Error = StackError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        // One frame is buffered at a time. If there is one, it has to go out
        // before another can be taken — and flushing it is what registers the
        // waker for a queue that is full.
        this.flush(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let udp = this.udp.is_some() && packet::is_udp(&item);
        this.pending = Some(Pending { frame: item, udp });
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().flush(cx)
    }
}

impl Stack {
    /// Hand the buffered frame over, if there is one.
    fn flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StackError>> {
        let Some(pending) = self.pending.take() else {
            return Poll::Ready(Ok(()));
        };

        // The frame goes to the UDP half when it is UDP and the UDP half is
        // there; to the runner otherwise.
        let channel: &mut PollSender<Vec<u8>> = if pending.udp {
            match self.udp.as_mut() {
                Some(tx) => tx,
                None => return Poll::Ready(Ok(())),
            }
        } else {
            &mut self.ingress
        };

        let reserved = channel.poll_reserve(cx);
        match reserved {
            Poll::Ready(Ok(())) => {
                // The room is reserved, so the frame goes out.
                let _ = channel.send_item(pending.frame);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(StackError::Closed)),
            Poll::Pending => {
                // Put the frame back: it goes out when the queue has room.
                self.pending = Some(pending);
                Poll::Pending
            }
        }
    }
}

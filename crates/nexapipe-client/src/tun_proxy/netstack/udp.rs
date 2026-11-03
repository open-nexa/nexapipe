//! The UDP half: the datagrams the device sends and receives.
//!
//! A datagram has no connection and no stream, so the half that receives
//! them is a queue of datagrams and the half that sends them builds the
//! packets itself. The packets do not go through the TCP/IP stack: the stack
//! has no socket that could match a datagram to the right flow — it binds
//! one socket to one endpoint, and a device sends to a different address
//! every time — so the datagrams are read and written here instead.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use etherparse::PacketBuilder;
use futures_util::{Sink, Stream};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use super::packet;

/// The time-to-live the packets we build carry.
///
/// The device is one hop away, so anything sensible works; 64 is the usual
/// default.
const TTL: u8 = 64;

/// A datagram, with the two addresses it goes between.
pub struct UdpDatagram {
    /// What the datagram carries.
    pub payload: Vec<u8>,
    /// The address it comes from.
    pub src: SocketAddr,
    /// The address it goes to.
    pub dst: SocketAddr,
}

/// The socket the device's datagrams arrive on.
///
/// The datagrams are not matched to flows here: one socket carries them all,
/// and the caller sorts them out by their addresses.
pub struct UdpSocket {
    rx: mpsc::Receiver<Vec<u8>>,
    egress: PollSender<Vec<u8>>,
}

impl UdpSocket {
    /// A socket over the frames the stack has set aside.
    pub(super) fn new(rx: mpsc::Receiver<Vec<u8>>, egress: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            rx,
            egress: PollSender::new(egress),
        }
    }

    /// The two halves of the socket.
    pub fn split(self) -> (ReadHalf, WriteHalf) {
        (
            ReadHalf { rx: self.rx },
            WriteHalf {
                egress: self.egress,
            },
        )
    }
}

/// The half the device's datagrams arrive on.
pub struct ReadHalf {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl Stream for ReadHalf {
    type Item = UdpDatagram;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(frame)) => match packet::udp_datagram(&frame) {
                    Some((payload, src, dst)) => {
                        return Poll::Ready(Some(UdpDatagram { payload, src, dst }));
                    }
                    // A frame that is not a datagram is not ours; the next
                    // one may be.
                    None => continue,
                },
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// The half the datagrams go out on.
pub struct WriteHalf {
    egress: PollSender<Vec<u8>>,
}

impl Sink<UdpDatagram> for WriteHalf {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match this.egress.poll_reserve(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::other("the stack is gone"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn start_send(self: Pin<&mut Self>, item: UdpDatagram) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if item.payload.is_empty() {
            // A datagram with nothing in it is legal, and the stack drops it
            // anyway, so there is nothing to work around here.
            return Ok(());
        }
        let frame = build(&item)?;
        this.egress
            .send_item(frame)
            .map_err(|_| io::Error::other("the stack is gone"))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// The IP packet that carries a datagram.
///
/// The addresses have to be of the same family: there is no way to put an
/// IPv4 address in an IPv6 packet.
fn build(datagram: &UdpDatagram) -> Result<Vec<u8>, io::Error> {
    let builder = match (datagram.src, datagram.dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), TTL)
                .udp(src.port(), dst.port())
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), TTL)
                .udp(src.port(), dst.port())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the two addresses of a datagram are of different families",
            ));
        }
    };

    let mut frame = Vec::with_capacity(builder.size(datagram.payload.len()));
    builder
        .write(&mut frame, &datagram.payload)
        .map_err(|e| io::Error::other(format!("the datagram could not be built: {e}")))?;
    Ok(frame)
}

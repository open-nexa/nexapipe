//! Reading the headers of the frames that cross the device.
//!
//! The stack needs to know three things about a frame before it can act on
//! it: which protocol it carries, whether it opens a TCP connection, and —
//! for UDP — what the datagram inside it says. The headers are read here so
//! that the rest of the stack does not have to.

use std::net::{IpAddr, SocketAddr};

use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};

/// The protocol a frame carries, if the frame says.
pub(super) fn protocol(frame: &[u8]) -> Option<IpProtocol> {
    let (protocol, _, _, _) = split(frame)?;
    Some(protocol)
}

/// Whether the frame carries a UDP datagram.
pub(super) fn is_udp(frame: &[u8]) -> bool {
    protocol(frame) == Some(IpProtocol::Udp)
}

/// The segment that opens a TCP connection.
pub(super) struct Syn {
    /// Where the connection comes from: the application's address.
    pub src: SocketAddr,
    /// Where the connection goes: the address the application asked for.
    pub dst: SocketAddr,
}

/// The connection-opening segment in the frame, if it is one.
pub(super) fn tcp_syn(frame: &[u8]) -> Option<Syn> {
    let (protocol, src, dst, payload) = split(frame)?;
    if protocol != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(payload).ok()?;
    // A connection is opened by a SYN that is not an answer to one.
    if !tcp.syn() || tcp.ack() {
        return None;
    }
    Some(Syn {
        src: SocketAddr::new(src, tcp.src_port()),
        dst: SocketAddr::new(dst, tcp.dst_port()),
    })
}

/// The datagram in the frame: its payload, and the two addresses it goes
/// between.
pub(super) fn udp_datagram(frame: &[u8]) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
    let (protocol, src, dst, payload) = split(frame)?;
    if protocol != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(payload).ok()?;
    Some((
        udp.payload().to_vec(),
        SocketAddr::new(src, udp.src_port()),
        SocketAddr::new(dst, udp.dst_port()),
    ))
}

/// The protocol, the two addresses, and the payload of an IP frame.
fn split(frame: &[u8]) -> Option<(IpProtocol, IpAddr, IpAddr, &[u8])> {
    // The version is the first nibble, and reading it needs a byte.
    if frame.is_empty() {
        return None;
    }
    match IpVersion::of_packet(frame).ok()? {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(frame).ok()?;
            Some((
                packet.next_header(),
                IpAddr::V4(packet.src_addr()),
                IpAddr::V4(packet.dst_addr()),
                packet.payload(),
            ))
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(frame).ok()?;
            Some((
                packet.next_header(),
                IpAddr::V6(packet.src_addr()),
                IpAddr::V6(packet.dst_addr()),
                packet.payload(),
            ))
        }
    }
}

//! The stack, driven the way the device drives it.
//!
//! The tests speak to the stack the way the TUN device does: IP packets in,
//! IP packets out. A segment that opens a connection is built by hand, and
//! so are the ones that follow it, because that is the only way to put the
//! stack on the other side of a handshake without a second stack to talk to.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use smoltcp::wire::{Ipv4Packet, TcpPacket, UdpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::{Stack, StackBuilder, TcpListener, UdpDatagram, UdpSocket};

/// The address the device's socket is bound to.
const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 16);
/// The address the device is asking for.
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 17);
const CLIENT_PORT: u16 = 40_000;
const SERVER_PORT: u16 = 443;

/// How long a test waits for the stack to say something.
const PATIENCE: Duration = Duration::from_secs(5);

/// A stack with TCP and no UDP.
fn tcp_stack() -> (
    Stack,
    Option<super::Runner>,
    Option<UdpSocket>,
    Option<TcpListener>,
) {
    StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(false)
        .mtu(1280)
        .tcp_recv_buffer_size(16 * 1024)
        .tcp_send_buffer_size(16 * 1024)
        .build()
        .expect("the stack builds")
}

/// A stack with UDP and no TCP.
fn udp_stack() -> (
    Stack,
    Option<super::Runner>,
    Option<UdpSocket>,
    Option<TcpListener>,
) {
    StackBuilder::default()
        .enable_tcp(false)
        .enable_udp(true)
        .mtu(1280)
        .build()
        .expect("the stack builds")
}

/// A segment that opens a connection.
fn syn_segment() -> Vec<u8> {
    segment(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 1000, 0, 0x02, &[])
}

/// A segment that opens a connection, with a checksum that does not add up.
///
/// The stack refuses it — a segment whose checksum does not add up is not
/// one it acts on — but the runner cannot tell that from the segment alone,
/// so it opens a flow for it all the same.
fn syn_segment_with_a_broken_checksum() -> Vec<u8> {
    let mut frame = syn_segment();
    // The TCP checksum sits after the ports, the sequence number and the
    // acknowledgement number, and the IP header is twenty bytes.
    frame[20 + 16] ^= 0xff;
    frame
}

/// A segment that acknowledges the stack's answer.
fn ack_segment(seq: u32, ack: u32) -> Vec<u8> {
    segment(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        seq,
        ack,
        0x10,
        &[],
    )
}

/// A segment that carries bytes.
fn data_segment(seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    segment(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        seq,
        ack,
        0x18,
        payload,
    )
}

/// A TCP segment, with the checksums the stack checks.
///
/// The arguments are the ones a segment is made of, and a segment is made of
/// all of them: bundling them into a struct would only move the list
/// somewhere else.
#[allow(clippy::too_many_arguments)]
fn segment(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(0x50); // data offset: five words, no options
    tcp.push(flags);
    tcp.extend_from_slice(&65_535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer

    // The checksum covers a pseudo-header — the two addresses, the protocol
    // and the length of the segment — and the segment itself, payload and
    // all.
    let mut pseudo = Vec::with_capacity(12 + tcp.len() + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0); // reserved
    pseudo.push(6); // TCP
    pseudo.extend_from_slice(&((tcp.len() + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    pseudo.extend_from_slice(payload);
    let checksum = ones_complement_sum(&pseudo);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(20 + tcp.len() + payload.len());
    packet.push(0x45); // version 4, header length 5 (20 bytes)
    packet.push(0x00); // DSCP / ECN
    packet.extend_from_slice(&((20 + tcp.len() + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&0x1234u16.to_be_bytes()); // identification
    packet.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    packet.push(64); // TTL
    packet.push(6); // TCP
    packet.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let checksum = ones_complement_sum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet.extend_from_slice(&tcp);
    packet.extend_from_slice(payload);
    packet
}

/// A UDP datagram, with the checksums the stack checks.
fn datagram_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    udp.extend_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0); // reserved
    pseudo.push(17); // UDP
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let checksum = ones_complement_sum(&pseudo);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(20 + udp.len());
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    packet.extend_from_slice(&0x4000u16.to_be_bytes());
    packet.push(64);
    packet.push(17); // UDP
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let checksum = ones_complement_sum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet.extend_from_slice(&udp);
    packet
}

/// A piece of a datagram that the kernel split.
///
/// What the piece carries starts where the datagram's header would be, and
/// the header says so: the stack does not reassemble fragments, so the piece
/// must not be read as a datagram.
fn fragment_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = datagram_frame(src, dst, src_port, dst_port, payload);
    // The flags and the fragment offset: a piece that starts eight bytes into
    // the datagram.
    frame[6..8].copy_from_slice(&1u16.to_be_bytes());
    let checksum = ones_complement_sum(&frame[..20]);
    frame[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// The sequence and acknowledgement numbers of a segment.
fn seq_ack(frame: &[u8]) -> (u32, u32) {
    let ip = Ipv4Packet::new_checked(frame).expect("a packet");
    let tcp = TcpPacket::new_checked(ip.payload()).expect("a segment");
    (tcp.seq_number().0 as u32, tcp.ack_number().0 as u32)
}

/// The payload of a segment.
fn payload_of(frame: &[u8]) -> Vec<u8> {
    let ip = Ipv4Packet::new_checked(frame).expect("a packet");
    let tcp = TcpPacket::new_checked(ip.payload()).expect("a segment");
    tcp.payload().to_vec()
}

/// The payload of a datagram.
fn datagram_payload(frame: &[u8]) -> Vec<u8> {
    let ip = Ipv4Packet::new_checked(frame).expect("a packet");
    let udp = UdpPacket::new_checked(ip.payload()).expect("a datagram");
    udp.payload().to_vec()
}

/// Whether the segment ends the connection.
fn is_fin(frame: &[u8]) -> bool {
    let ip = Ipv4Packet::new_checked(frame).expect("a packet");
    let tcp = TcpPacket::new_checked(ip.payload()).expect("a segment");
    tcp.fin()
}

/// Whether the segment resets the connection.
fn is_reset(frame: &[u8]) -> bool {
    let ip = Ipv4Packet::new_checked(frame).expect("a packet");
    let tcp = TcpPacket::new_checked(ip.payload()).expect("a segment");
    tcp.rst()
}

/// The one's complement of the one's complement sum of the header's words.
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut words = bytes.chunks(2);
    for word in words.by_ref() {
        match word {
            [high, low] => sum += u32::from(u16::from_be_bytes([*high, *low])),
            [high] => sum += u32::from(u16::from_be_bytes([*high, 0])),
            _ => {}
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// A segment that opens a connection is answered with a flow.
#[tokio::test]
async fn a_segment_that_opens_a_connection_is_answered_with_a_flow() {
    let (stack, runner, _udp, listener) = tcp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with TCP has a runner").await;
    });
    let (mut sink, _stream) = stack.split();
    let mut listener = listener.expect("a stack with TCP has a listener");

    sink.send(syn_segment())
        .await
        .expect("the stack takes the segment");

    let (stream, client, server) = timeout(PATIENCE, listener.next())
        .await
        .expect("the stack opens the flow")
        .expect("the listener has a flow");

    // The addresses are the ones the segment carried: the application's
    // address is the one the connection comes from, and the address it asked
    // for is the one it goes to.
    assert_eq!(client, SocketAddr::new(CLIENT.into(), CLIENT_PORT));
    assert_eq!(server, SocketAddr::new(SERVER.into(), SERVER_PORT));
    drop(stream);
}

/// The bytes the peer sends reach the application.
#[tokio::test]
async fn the_bytes_the_peer_sends_reach_the_application() {
    let (stack, runner, _udp, listener) = tcp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with TCP has a runner").await;
    });
    let (mut sink, mut stream_out) = stack.split();
    let mut listener = listener.expect("a stack with TCP has a listener");

    sink.send(syn_segment())
        .await
        .expect("the stack takes the segment");
    let (mut flow, _client, _server) = timeout(PATIENCE, listener.next())
        .await
        .expect("the stack opens the flow")
        .expect("the listener has a flow");

    // The stack answers the handshake; its sequence number is what the peer
    // has to acknowledge.
    let answer = timeout(PATIENCE, stream_out.next())
        .await
        .expect("the stack answers the handshake")
        .expect("the stack has an answer")
        .expect("the answer is not an error");
    let (seq, ack) = seq_ack(&answer);

    sink.send(ack_segment(ack, seq + 1))
        .await
        .expect("the stack takes the ack");
    sink.send(data_segment(ack, seq + 1, b"hello"))
        .await
        .expect("the stack takes the data");

    let mut buf = [0u8; 5];
    timeout(PATIENCE, flow.read_exact(&mut buf))
        .await
        .expect("the application gets the bytes")
        .expect("the read succeeds");
    assert_eq!(&buf, b"hello");
}

/// What the application writes goes out as a segment.
#[tokio::test]
async fn what_the_application_writes_goes_out_as_a_segment() {
    let (stack, runner, _udp, listener) = tcp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with TCP has a runner").await;
    });
    let (mut sink, mut stream_out) = stack.split();
    let mut listener = listener.expect("a stack with TCP has a listener");

    sink.send(syn_segment())
        .await
        .expect("the stack takes the segment");
    let (mut flow, _client, _server) = timeout(PATIENCE, listener.next())
        .await
        .expect("the stack opens the flow")
        .expect("the listener has a flow");

    let answer = timeout(PATIENCE, stream_out.next())
        .await
        .expect("the stack answers the handshake")
        .expect("the stack has an answer")
        .expect("the answer is not an error");
    let (seq, ack) = seq_ack(&answer);
    sink.send(ack_segment(ack, seq + 1))
        .await
        .expect("the stack takes the ack");

    flow.write_all(b"world").await.expect("the write succeeds");

    // The stack may answer the handshake with an acknowledgement of its own
    // before it carries the bytes, so the frames are read until one of them
    // has a payload.
    let mut sent = Vec::new();
    while sent.is_empty() {
        let frame = timeout(PATIENCE, stream_out.next())
            .await
            .expect("the stack sends the bytes")
            .expect("the stack has a frame")
            .expect("the frame is not an error");
        sent = payload_of(&frame);
    }
    assert_eq!(sent, b"world");
}

/// A datagram reaches the UDP half, with the addresses it came from.
#[tokio::test]
async fn a_datagram_reaches_the_udp_half() {
    let (stack, runner, udp, _listener) = udp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with UDP has a runner").await;
    });
    let (mut sink, _stream) = stack.split();
    let (mut reader, _writer) = udp.expect("a stack with UDP has a socket").split();

    sink.send(datagram_frame(CLIENT, SERVER, 53_000, 53, b"query"))
        .await
        .expect("the stack takes the datagram");

    let datagram = timeout(PATIENCE, reader.next())
        .await
        .expect("the datagram arrives")
        .expect("the half has a datagram");
    assert_eq!(datagram.payload, b"query");
    assert_eq!(datagram.src, SocketAddr::new(CLIENT.into(), 53_000));
    assert_eq!(datagram.dst, SocketAddr::new(SERVER.into(), 53));
}

/// The answer to a datagram is a packet with the two addresses the other way
/// round.
#[tokio::test]
async fn the_answer_to_a_datagram_goes_back_to_the_sender() {
    let (stack, runner, udp, _listener) = udp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with UDP has a runner").await;
    });
    let (mut sink, mut stream_out) = stack.split();
    let (mut reader, mut writer) = udp.expect("a stack with UDP has a socket").split();

    sink.send(datagram_frame(CLIENT, SERVER, 53_000, 53, b"query"))
        .await
        .expect("the stack takes the datagram");
    let received = timeout(PATIENCE, reader.next())
        .await
        .expect("the datagram arrives")
        .expect("the half has a datagram");

    writer
        .send(UdpDatagram {
            payload: b"answer".to_vec(),
            src: received.dst,
            dst: received.src,
        })
        .await
        .expect("the answer goes out");

    let frame = timeout(PATIENCE, stream_out.next())
        .await
        .expect("the answer goes to the device")
        .expect("the stack has a frame")
        .expect("the frame is not an error");
    assert_eq!(datagram_payload(&frame), b"answer");
}

/// A piece of a datagram is not a datagram.
#[tokio::test]
async fn a_piece_of_a_datagram_is_not_a_datagram() {
    let (stack, runner, udp, _listener) = udp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with UDP has a runner").await;
    });
    let (mut sink, _stream) = stack.split();
    let (mut reader, _writer) = udp.expect("a stack with UDP has a socket").split();

    // The piece starts where the datagram's header would be. Reading it as
    // one would open a flow to a port that is made up.
    sink.send(fragment_frame(CLIENT, SERVER, 53_000, 53, b"query"))
        .await
        .expect("the stack takes the piece");

    assert!(
        timeout(Duration::from_millis(300), reader.next())
            .await
            .is_err(),
        "a piece of a datagram is not a datagram"
    );
}

/// A segment that is sent again opens one flow, not two.
#[tokio::test]
async fn a_segment_that_is_sent_again_opens_one_flow() {
    let (stack, runner, _udp, listener) = tcp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with TCP has a runner").await;
    });
    let (mut sink, _stream) = stack.split();
    let mut listener = listener.expect("a stack with TCP has a listener");

    // The device did not get the answer to the first segment, so it sends it
    // again.
    sink.send(syn_segment())
        .await
        .expect("the stack takes the segment");
    sink.send(syn_segment())
        .await
        .expect("the stack takes the segment");

    let (stream, _client, _server) = timeout(PATIENCE, listener.next())
        .await
        .expect("the stack opens the flow")
        .expect("the listener has a flow");

    // One flow, not two: the socket that is already there answers the
    // segment that was sent again. A second one would listen for the rest of
    // its life and hold a slot and a tunnel that nothing ever finishes.
    assert!(
        timeout(Duration::from_millis(300), listener.next())
            .await
            .is_err(),
        "the segment that was sent again does not open a second flow"
    );
    drop(stream);
}

/// A connection that is closed cleanly is not reset.
#[tokio::test]
async fn a_connection_that_is_closed_cleanly_is_not_reset() {
    let (stack, runner, _udp, listener) = tcp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with TCP has a runner").await;
    });
    let (mut sink, mut stream_out) = stack.split();
    let mut listener = listener.expect("a stack with TCP has a listener");

    sink.send(syn_segment())
        .await
        .expect("the stack takes the segment");
    let (mut flow, _client, _server) = timeout(PATIENCE, listener.next())
        .await
        .expect("the stack opens the flow")
        .expect("the listener has a flow");

    let answer = timeout(PATIENCE, stream_out.next())
        .await
        .expect("the stack answers the handshake")
        .expect("the stack has an answer")
        .expect("the answer is not an error");
    let (seq, ack) = seq_ack(&answer);
    sink.send(ack_segment(ack, seq + 1))
        .await
        .expect("the stack takes the ack");

    // The application writes its last bytes and closes its side.
    flow.write_all(b"hello").await.expect("the write succeeds");
    flow.shutdown().await.expect("the close succeeds");
    drop(flow);

    // The stack answers with the bytes and the end of the connection.
    let mut next_seq = seq + 1;
    let mut ended = false;
    while !ended {
        let frame = timeout(PATIENCE, stream_out.next())
            .await
            .expect("the stack sends the bytes")
            .expect("the stack has a frame")
            .expect("the frame is not an error");
        let (frame_seq, _frame_ack) = seq_ack(&frame);
        let payload = payload_of(&frame);
        ended = is_fin(&frame);
        next_seq = frame_seq + payload.len() as u32 + u32::from(ended);
    }

    // The runner has time to notice that the application is gone.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The peer acknowledges the end of the connection.
    sink.send(ack_segment(ack, next_seq))
        .await
        .expect("the stack takes the ack");

    // The stack must not answer with a reset. The connection was closed
    // cleanly, and a reset would tell the device to throw away what it has
    // already received.
    let mut reset = false;
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(300), stream_out.next()).await {
        if is_reset(&frame) {
            reset = true;
            break;
        }
    }
    assert!(!reset, "a connection that was closed cleanly is not reset");
}

/// A flow the stack refused is told that it is over.
#[tokio::test]
async fn a_flow_the_stack_refused_is_told_that_it_is_over() {
    let (stack, runner, _udp, listener) = tcp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with TCP has a runner").await;
    });
    let (mut sink, _stream) = stack.split();
    let mut listener = listener.expect("a stack with TCP has a listener");

    // The stack does not act on a segment whose checksum does not add up.
    sink.send(syn_segment_with_a_broken_checksum())
        .await
        .expect("the stack takes the segment");

    // The flow is announced all the same: the runner reads the segment
    // itself, and it cannot tell a broken checksum from a good one.
    let (mut flow, _client, _server) = timeout(PATIENCE, listener.next())
        .await
        .expect("the stack opens the flow")
        .expect("the listener has a flow");

    // The socket is given up on, and the application is told: it is waiting
    // for bytes that are never coming.
    let mut buf = [0u8; 1];
    let read = timeout(PATIENCE, flow.read(&mut buf))
        .await
        .expect("the application is told that the connection is over")
        .expect("the read succeeds");
    assert_eq!(read, 0, "the stream ends rather than waiting for ever");
}

/// A flow the application still holds is not given up on.
#[tokio::test]
async fn a_flow_the_application_still_holds_is_not_given_up_on() {
    let (stack, runner, _udp, listener) = tcp_stack();
    tokio::spawn(async move {
        let _ = runner.expect("a stack with TCP has a runner").await;
    });
    let (mut sink, mut stream_out) = stack.split();
    let mut listener = listener.expect("a stack with TCP has a listener");

    sink.send(syn_segment())
        .await
        .expect("the stack takes the segment");
    let (mut flow, _client, _server) = timeout(PATIENCE, listener.next())
        .await
        .expect("the stack opens the flow")
        .expect("the listener has a flow");

    let answer = timeout(PATIENCE, stream_out.next())
        .await
        .expect("the stack answers the handshake")
        .expect("the stack has an answer")
        .expect("the answer is not an error");
    let (seq, ack) = seq_ack(&answer);
    sink.send(ack_segment(ack, seq + 1))
        .await
        .expect("the stack takes the ack");

    // The application writes its last bytes and closes its side, but keeps
    // reading: a half-close is a request, not an ending.
    flow.write_all(b"hello").await.expect("the write succeeds");
    flow.shutdown().await.expect("the close succeeds");

    // Longer than a flow nobody holds is given for, and longer than the
    // stack's first retransmission: the runner only looks at its sockets when
    // something wakes it, and a retransmission is what wakes it.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The peer sends what it has, and the application still receives it.
    sink.send(data_segment(ack, seq + 6, b"more"))
        .await
        .expect("the stack takes the data");

    let mut buf = [0u8; 4];
    timeout(PATIENCE, flow.read_exact(&mut buf))
        .await
        .expect("the application gets the bytes")
        .expect("the read succeeds");
    assert_eq!(&buf, b"more");
}

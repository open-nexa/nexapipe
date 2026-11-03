//! The task that drives the stack.
//!
//! smoltcp does not run by itself: something has to hand it the frames that
//! arrived and take the frames it produced, and something has to keep its
//! sockets fed and its timers watched. That something is this task, and it
//! is the only place in the TUN proxy that talks to smoltcp.
//!
//! Two things happen in the loop. The frames that arrived are looked at —
//! and a frame that opens a connection has to be recognised *before* the
//! stack sees it, or the handshake is lost until the device retransmits it.
//! Then the stack is given the frames and its sockets are pumped: what the
//! peer sent moves into the application's buffer, what the application
//! wrote moves into the socket.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use tokio::sync::{Notify, mpsc};

use super::StackError;
use super::device::FrameDevice;
use super::packet;
use super::tcp::{SocketControl, TcpStream};

/// The task that drives the stack.
pub type Runner =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StackError>> + Send>>;

/// How long the runner waits when the stack has nothing to say.
///
/// The stack asks for no timer at all when it has no socket, so this is the
/// floor between two looks at an idle stack.
const IDLE_WAIT: Duration = Duration::from_millis(5);

/// How long a TCP socket may sit idle before it is given up on.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(7200);

/// How often a TCP socket is probed when it has nothing to send.
const TCP_KEEP_ALIVE: Duration = Duration::from_secs(28);

/// How long a handshake may take before the socket that waits for it is given
/// up on.
///
/// A socket that opens a connection listens until the stack has seen the
/// segment that opened it. A socket that is still listening that long after
/// it was opened is one the stack refused — the segment's checksum did not
/// add up — and a listening socket has no timeout of its own: it would wait
/// for ever, holding a slot and a tunnel that nothing ever finishes.
#[cfg(not(test))]
const TCP_HANDSHAKE_GRACE: Duration = Duration::from_secs(10);
/// The tests do not wait ten seconds for a handshake to be given up on.
#[cfg(test)]
const TCP_HANDSHAKE_GRACE: Duration = Duration::from_millis(300);

/// How long the end of a connection may take.
///
/// The application is gone once it has closed its side, but the bytes that
/// are still in the socket's send buffer have to go out first, and the peer
/// has to acknowledge them. A peer that never does must not hold the flow's
/// slot for ever.
#[cfg(not(test))]
const TCP_FIN_TIMEOUT: Duration = Duration::from_secs(30);
/// The tests do not wait thirty seconds for a connection to end.
#[cfg(test)]
const TCP_FIN_TIMEOUT: Duration = Duration::from_millis(300);

/// What the runner needs to run.
pub(super) struct RunnerParts {
    /// The device the stack is bound to.
    pub(super) device: FrameDevice,
    /// The stack itself.
    pub(super) iface: Interface,
    /// The frames on their way into the stack.
    pub(super) ingress: mpsc::Receiver<Vec<u8>>,
    /// Where the connections the device opens are announced.
    pub(super) accept: mpsc::UnboundedSender<TcpStream>,
    /// Wakes the runner when an application has something for it.
    pub(super) notify: Arc<Notify>,
    /// The window a TCP socket advertises.
    pub(super) tcp_recv_buffer_size: u32,
    /// How much a TCP socket may have queued to send.
    pub(super) tcp_send_buffer_size: u32,
    /// Whether the stack terminates TCP connections at all.
    pub(super) tcp_enabled: bool,
}

/// Start the task that drives the stack.
pub(super) fn spawn(parts: RunnerParts) -> Runner {
    Box::pin(run(parts))
}

async fn run(mut parts: RunnerParts) -> Result<(), StackError> {
    let mut sockets: SocketSet<'static> = SocketSet::new(vec![]);
    let mut flows: HashMap<SocketHandle, Flow> = HashMap::new();
    // The flows whose handshake is unfinished, by the addresses they connect.
    let mut handshaking: HashMap<(SocketAddr, SocketAddr), SocketHandle> = HashMap::new();

    loop {
        // Every frame that is waiting is looked at before any of them reaches
        // the stack. A connection-opening segment has to be recognised before
        // the segment itself is handed over: the socket that answers it does
        // not exist until it is.
        let mut waiting = Vec::new();
        while let Ok(frame) = parts.ingress.try_recv() {
            waiting.push(frame);
        }
        for frame in waiting {
            take_frame(
                &mut parts,
                &mut sockets,
                &mut flows,
                &mut handshaking,
                frame,
            );
        }

        // Let the stack work on what it has.
        let now = Instant::now();
        parts.iface.poll(now, &mut parts.device, &mut sockets);
        pump(&mut sockets, &mut flows, &mut handshaking, now);

        // Then wait for the next thing to happen: a frame, an application with
        // something to say, or the stack's own timer.
        let wait: std::time::Duration = parts
            .iface
            .poll_delay(now, &sockets)
            .unwrap_or(IDLE_WAIT.into())
            .into();
        if wait.is_zero() {
            // The stack has something to do right now. Give the other tasks
            // a turn before going round again, or a busy stack would keep the
            // runtime to itself.
            tokio::task::yield_now().await;
            continue;
        }

        tokio::select! {
            frame = parts.ingress.recv() => {
                match frame {
                    Some(frame) => take_frame(
                        &mut parts,
                        &mut sockets,
                        &mut flows,
                        &mut handshaking,
                        frame,
                    ),
                    // The other end of the stack is gone: there is nothing
                    // left to drive it for.
                    None => break,
                }
            }
            _ = parts.notify.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }

    Ok(())
}

/// One flow the runner drives.
struct Flow {
    /// What the application and the runner share.
    control: Arc<SocketControl>,
    /// The addresses the flow connects, while the handshake is unfinished.
    ///
    /// This is the key a segment that is sent again is matched against: the
    /// socket that is already there answers it.
    handshake: Option<(SocketAddr, SocketAddr)>,
    /// When the socket was opened.
    opened_at: Instant,
    /// When the application closed its side and the FIN went out.
    closed_at: Option<Instant>,
}

/// Take one frame from the device: open a connection if it opens one, and
/// hand the frame to the stack.
fn take_frame(
    parts: &mut RunnerParts,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, Flow>,
    handshaking: &mut HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    frame: Vec<u8>,
) {
    if parts.tcp_enabled
        && let Some(syn) = packet::tcp_syn(&frame)
    {
        open_flow(parts, sockets, flows, handshaking, syn);
    }
    parts.device.push(frame);
}

/// A socket for one flow, with the interactive defaults taken off.
///
/// The peer is the device's own kernel on the TUN fd, so an acknowledgement
/// costs a local round trip, not a network one. smoltcp otherwise holds a
/// small downlink segment behind an unacknowledged one (Nagle) and waits
/// 10 ms before acknowledging an uplink segment (delayed ACK). Neither buys
/// anything here and both add latency to small messages.
fn new_flow_socket(recv_size: usize, send_size: usize) -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; recv_size]),
        tcp::SocketBuffer::new(vec![0u8; send_size]),
    );
    socket.set_keep_alive(Some(TCP_KEEP_ALIVE.into()));
    socket.set_timeout(Some(TCP_IDLE_TIMEOUT.into()));
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);
    socket
}

/// Open a flow for a connection the device started.
///
/// The socket plays the server's part: it listens on the address the device
/// asked for, which is the address the segment that opened the connection
/// was sent to. smoltcp has no socket that listens on "any port", and a
/// device connects to a different port every time, so a socket is opened
/// for each connection as it arrives.
fn open_flow(
    parts: &mut RunnerParts,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, Flow>,
    handshaking: &mut HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    syn: packet::Syn,
) {
    // A segment that is sent again — the answer to it was lost, or the
    // device is impatient — is answered by the socket that is already
    // there. A second socket would listen for the rest of its life: the
    // stack gives a listening socket no timeout, and it would hold a slot
    // and a tunnel that nothing ever finishes.
    if handshaking.contains_key(&(syn.src, syn.dst)) {
        return;
    }

    let mut socket = new_flow_socket(
        parts.tcp_recv_buffer_size as usize,
        parts.tcp_send_buffer_size as usize,
    );
    if socket.listen(syn.dst).is_err() {
        // The address cannot be listened on, so the connection cannot be
        // answered. The device will see the handshake time out.
        return;
    }

    let control = Arc::new(SocketControl::new(
        parts.tcp_recv_buffer_size as usize,
        parts.tcp_send_buffer_size as usize,
        parts.notify.clone(),
    ));
    let handle = sockets.add(socket);
    handshaking.insert((syn.src, syn.dst), handle);
    flows.insert(
        handle,
        Flow {
            control: control.clone(),
            handshake: Some((syn.src, syn.dst)),
            opened_at: Instant::now(),
            closed_at: None,
        },
    );

    let stream = TcpStream::new(control, syn.src, syn.dst);
    if parts.accept.send(stream).is_err() {
        // Nobody is taking connections any more; the flow will be closed with
        // the socket below.
    }
}

/// Move the bytes between the sockets and the applications.
fn pump(
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, Flow>,
    handshaking: &mut HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    now: Instant,
) {
    let mut finished: Vec<SocketHandle> = Vec::new();

    for (handle, flow) in flows.iter_mut() {
        // Every socket in the set is a TCP socket: the set holds nothing else.
        let socket = sockets.get_mut::<tcp::Socket>(*handle);
        let control = &flow.control;

        // What the peer sent: into the application's buffer.
        //
        // The loop ends when nothing moves: a socket that can receive but
        // has nothing to give is a socket whose window is full, and a socket
        // that can send but has nothing to take is a socket the application
        // has not written to yet.
        while socket.can_recv() {
            let space = control.recv_space();
            if space == 0 {
                break;
            }
            let moved = socket.recv(|buf| {
                let moved = control.copy_in(buf, space);
                (moved, moved)
            });
            match moved {
                Ok(moved) if moved > 0 => {}
                _ => break,
            }
        }

        // What the application wrote: into the socket.
        while socket.can_send() {
            let moved = socket.send(|buf| {
                let moved = control.copy_out(buf);
                (moved, moved)
            });
            match moved {
                Ok(moved) if moved > 0 => {}
                _ => break,
            }
        }

        // The peer closed its side. The socket is in one of the states that
        // mean "the connection is over" once that happens; the others are the
        // ones where the peer has not finished yet.
        let peer_closed = !socket.may_recv()
            && !matches!(
                socket.state(),
                tcp::State::Listen
                    | tcp::State::SynReceived
                    | tcp::State::Established
                    | tcp::State::FinWait1
                    | tcp::State::FinWait2
            );
        if peer_closed {
            control.mark_recv_closed();
        }

        // The application is done sending. The socket is closed only once
        // the bytes are out: closing earlier would move it to FIN-WAIT-1,
        // where no more data can be sent, and the rest of it would be lost.
        if control.send_closed() && control.send_is_empty() && !control.fin_sent() {
            socket.close();
            control.mark_fin_sent();
            flow.closed_at = Some(now);
        }

        // The handshake is over once the connection is up. Until then the
        // socket answers a segment that is sent again, so the key stays:
        // a segment that arrives now opens a connection of its own.
        if !matches!(socket.state(), tcp::State::Listen | tcp::State::SynReceived)
            && let Some(key) = flow.handshake.take()
        {
            handshaking.remove(&key);
        }

        // The socket is closed on both sides.
        if socket.state() == tcp::State::Closed {
            control.mark_socket_closed();
            finished.push(*handle);
            continue;
        }

        // The stack never took the segment that opened the connection, so the
        // socket is still listening. A listening socket has no timeout: it
        // has to be given up on here, or it waits for ever.
        if socket.state() == tcp::State::Listen
            && now >= flow.opened_at + TCP_HANDSHAKE_GRACE.into()
        {
            socket.abort();
            // The application is holding the stream this flow was announced
            // with, and it is waiting for bytes that will never come: it has
            // to be told that the connection is over.
            control.mark_socket_closed();
            finished.push(*handle);
            continue;
        }

        // The application dropped the stream: nothing is waiting for this
        // flow any more, so the socket goes with it.
        //
        // A flow that was closed cleanly is not aborted: the bytes that are
        // still in the socket's send buffer have to go out, and the FIN with
        // them. Aborting would throw them away, and the peer would be told
        // that the connection was reset instead of being answered.
        if Arc::strong_count(control) == 1 && !control.fin_sent() {
            socket.abort();
            finished.push(*handle);
            continue;
        }

        // The application is gone and the FIN is on its way out, but the peer
        // has not answered it. The wait is bounded: a peer that never answers
        // must not hold the flow's slot for ever.
        //
        // Only once the application has dropped its end of the flow: an
        // application that is still attached is reading, and the reply it is
        // waiting for is worth more than the slot this flow takes.
        if let Some(closed_at) = flow.closed_at
            && now >= closed_at + TCP_FIN_TIMEOUT.into()
            && Arc::strong_count(control) == 1
        {
            socket.abort();
            finished.push(*handle);
            continue;
        }
    }

    for handle in finished {
        if let Some(flow) = flows.remove(&handle)
            && let Some(key) = flow.handshake
        {
            handshaking.remove(&key);
        }
        sockets.remove(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flow_socket_does_not_delay_small_messages() {
        let socket = new_flow_socket(4096, 4096);
        assert!(
            !socket.nagle_enabled(),
            "Nagle would hold a small segment behind an unacknowledged one"
        );
        assert!(
            socket.ack_delay().is_none(),
            "the default delayed ACK waits 10 ms before answering an uplink segment"
        );
    }
}

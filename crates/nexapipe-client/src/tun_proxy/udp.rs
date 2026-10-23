//! The UDP half of the tunnel.
//!
//! A datagram has no stream to carry it, so a flow is a queue: the datagram
//! waits in it until the tunnel has carried it, and the answer waits in it
//! until the stack has taken it. Both waits are bounded, because a peer that
//! stops answering must not be able to grow the queue for ever.

use super::*;

/// The live UDP flows: their key, and the channel feeding datagrams into them.
/// One flow's queue: the datagrams waiting to go into the tunnel, and how
/// many bytes they are.
///
/// The count of datagrams is the channel's own bound; the count of **bytes**
/// is this one, and it is the one that matters: a datagram may be 65,507
/// bytes, so a bound on the number of them is not a bound on the memory.
#[derive(Clone)]
struct UdpQueue {
    /// The datagrams waiting to go into the tunnel.
    sender: mpsc::Sender<Vec<u8>>,
    /// How many bytes are waiting.
    ///
    /// Shared with the demultiplexer, which adds to it, and with the flow,
    /// which takes from it.
    queued: Arc<AtomicUsize>,
}

impl UdpQueue {
    /// A queue with nothing in it.
    fn new(sender: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            sender,
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Reserves room for `len` bytes, and says whether there was room.
    ///
    /// The bytes are counted **before** the datagram goes in, so the queue
    /// cannot pass its bound between the check and the send. A reservation
    /// that does not fit is given back at once, so a datagram that is dropped
    /// for want of room leaves the count as it was.
    fn reserve(&self, len: usize) -> bool {
        let queued = self.queued.fetch_add(len, Ordering::Relaxed) + len;
        if queued > UDP_FLOW_QUEUE_BYTES {
            self.release(len);
            return false;
        }
        true
    }

    /// Gives `len` bytes back to the queue.
    ///
    /// Called when a datagram leaves the queue — because the flow took it, or
    /// because it never went in.
    fn release(&self, len: usize) {
        self.queued.fetch_sub(len, Ordering::Relaxed);
    }

    /// Puts a datagram into the queue, and says whether it went in.
    ///
    /// The bytes are reserved **before** the datagram goes in, so the queue
    /// cannot pass its bound between the check and the send. A datagram that
    /// does not go in gives its reservation back at once, so the budget the
    /// queue holds is the budget it has — a reservation that was never given
    /// back would shrink the queue a byte at a time until it was wedged.
    ///
    /// The three ways a datagram does not go in are told apart, because the
    /// caller says something different about each: the queue's own byte bound
    /// was reached, the channel's datagram count was reached, or the flow
    /// ended.
    fn send(&self, payload: Vec<u8>) -> Result<(), UdpSendError> {
        let len = payload.len();
        if !self.reserve(len) {
            return Err(UdpSendError::NoRoom);
        }
        match self.sender.try_send(payload) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.release(len);
                Err(UdpSendError::Full)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.release(len);
                Err(UdpSendError::Closed)
            }
        }
    }

    /// A datagram left the queue, so its bytes are no longer waiting for it.
    ///
    /// The datagram itself is passed in rather than its length, so the bytes
    /// given back are the bytes that were taken in.
    fn taken(&self, datagram: &[u8]) {
        self.release(datagram.len());
    }

    /// How many bytes are waiting.
    #[cfg(test)]
    fn queued_bytes(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }
}

/// Why a datagram did not go into a flow's queue.
#[derive(Debug, PartialEq, Eq)]
enum UdpSendError {
    /// The queue's byte budget was reached.
    NoRoom,
    /// The queue's datagram count was reached.
    Full,
    /// The flow ended before the datagram went in.
    Closed,
}

/// Which side of a UDP flow spoke.
#[derive(Debug)]
enum Activity {
    /// A datagram from the application; `None` means the flow was replaced.
    Application(Option<Vec<u8>>),
    /// Bytes from the tunnel, or why it ended.
    Tunnel(Result<Option<usize>, String>),
    /// Somebody asked for this flow to end. Neither side spoke.
    Cancelled,
    /// The proxy is stopping. Neither side spoke.
    Stopped,
}

/// Waits for the next thing a UDP flow has to react to.
///
/// Four ways out: the application sent a datagram, the tunnel sent bytes, the
/// flow was asked to end, or the proxy is stopping.
///
/// **The last one is the reason this is here.** A flow is spawned by the
/// demultiplexer, and aborting the demultiplexer does not abort the flows it
/// started — the channel that feeds them stays open, so `datagrams.recv()`
/// never returns `None` and the flow has no reason to end on its own. A flow
/// that outlives the proxy keeps a pooled connection checked out of a group
/// nobody can close, and it sits on a tunnel until the server's idle timeout
/// closes it: fifty seconds after the proxy is gone.
///
/// The futures are taken as arguments so that the choice between the four can
/// be tested without a tunnel: a test hands in ones that never resolve, and
/// one that does.
async fn next_activity<D, T, C, S, E>(datagram: D, tunnel: T, cancelled: C, stopping: S) -> Activity
where
    D: std::future::Future<Output = Option<Vec<u8>>>,
    T: std::future::Future<Output = Result<Option<usize>, E>>,
    E: std::fmt::Display,
    C: std::future::Future<Output = ()>,
    S: std::future::Future<Output = ()>,
{
    tokio::select! {
        datagram = datagram => Activity::Application(datagram),
        read = tunnel => Activity::Tunnel(read.map_err(|e| e.to_string())),
        _ = cancelled => Activity::Cancelled,
        _ = stopping => Activity::Stopped,
    }
}

/// Write every datagram the proxy has for the application back into the stack.
///
/// One task owns the smoltcp `WriteHalf`; everyone else hands datagrams to it
/// through the channel in [`TunContext::tun_out`].
pub(super) async fn run_tun_udp_writer(
    mut writer: UdpWriteHalf,
    mut queue: mpsc::Receiver<UdpMsg>,
) {
    while let Some(datagram) = queue.recv().await {
        // Note: the stack's sink drops a zero-length payload silently. A
        // zero-length UDP datagram is legal but nothing sends one, so there is
        // nothing to work around here.
        if let Err(e) = writer.send(datagram).await {
            jni_log!("[tun-proxy] TUN UDP write error: {}", e);
            break;
        }
    }
    jni_log!("[tun-proxy] UDP writer task exiting");
}

/// Split the stack's inbound UDP stream into DNS queries and proxied flows.
pub(super) async fn run_udp_demux(mut socket: UdpReadHalf, ctx: TunContext) {
    let table: FlowTable = Arc::new(Mutex::new(HashMap::new()));
    // One log line per episode of being full, not one per dropped datagram.
    let warned_full = AtomicBool::new(false);

    while !ctx.stopped.load(Ordering::Acquire) {
        let Some((payload, client_addr, dst_addr)) = socket.next().await else {
            jni_log!("[tun-proxy] UDP stream ended");
            break;
        };

        // The system resolver is pointed at the DNS address (Kotlin: addDnsServer;
        // the desktop: the TUN interface address), and the virtual /24 is the only
        // route into the TUN, so a datagram to port 53 there is a DNS query and
        // nothing else.
        if dst_addr.ip() == IpAddr::V4(ctx.dns_ip) && dst_addr.port() == DNS_PORT {
            // One permit per query in flight. A device asks for a handful of
            // names at a time, so this is far above what it uses; it is here so
            // that a device which floods the TUN with queries cannot make the
            // number of outstanding DNS round trips grow without limit.
            //
            // A query that finds no permit is dropped rather than held: holding
            // it would stall the UDP flows that share this loop, and the
            // device's resolver retries a query that gets no answer.
            let Ok(permit) = ctx.dns_permits.clone().try_acquire_owned() else {
                jni_log!("[tun-proxy] too many DNS queries in flight, dropping one");
                continue;
            };

            // Answer from the address the query went to: the application's socket
            // may be connected, and a reply from anywhere else is discarded by the
            // kernel before the application ever sees it.
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Some(response) = handle_dns_query(
                    &payload,
                    &ctx.proxy_domains,
                    &ctx.resolvers,
                    &ctx.ip_mapping,
                )
                .await
                else {
                    return;
                };
                if ctx
                    .tun_out
                    .send((response, dst_addr, client_addr))
                    .await
                    .is_err()
                {
                    jni_log!("[tun-proxy] TUN writer is gone, dropping the DNS reply");
                }
            });
            continue;
        }

        // Same split as the TCP acceptor: the destination's family says which
        // pool to look the name up in.
        let Some(domain) = (match dst_addr.ip() {
            IpAddr::V4(dst_ip) => ctx.ip_mapping.lookup_domain(&dst_ip),
            IpAddr::V6(dst_ip) => ctx.ip_mapping.lookup_domain_v6(&dst_ip),
        }) else {
            jni_log!(
                "[tun-proxy] UDP to {} has no domain mapping, dropping",
                dst_addr
            );
            continue;
        };

        let key: FlowKey = (client_addr, dst_addr);
        // A closed channel means the flow ended (idle, refused, or the server
        // closed it) — the next datagram starts a fresh one rather than being
        // written into a dead tunnel.
        let existing = lock_flows(&table)
            .get(&key)
            .filter(|queue| !queue.sender.is_closed())
            .cloned();

        let queue = match existing {
            Some(queue) => queue,
            None => {
                let (sender, receiver) = mpsc::channel::<Vec<u8>>(UDP_FLOW_QUEUE);
                let queue = UdpQueue::new(sender);
                let mut flows = lock_flows(&table);

                if flows.len() >= MAX_UDP_FLOWS {
                    // A flow that has ended is still in the table until its
                    // task gets to `release_flow`, so the count is not the
                    // number of live flows — look again before refusing.
                    flows.retain(|_, queue| !queue.sender.is_closed());
                }
                if flows.len() >= MAX_UDP_FLOWS {
                    drop(flows);
                    if !warned_full.swap(true, Ordering::Relaxed) {
                        jni_log!(
                            "[tun-proxy] {} UDP flows are open, dropping datagrams until one ends",
                            MAX_UDP_FLOWS
                        );
                    }
                    // UDP is allowed to lose datagrams, and the alternative is
                    // a tunnel per source port.
                    continue;
                }

                warned_full.store(false, Ordering::Relaxed);
                flows.insert(key, queue.clone());
                drop(flows);
                tokio::spawn(run_udp_flow(
                    ctx.clone(),
                    table.clone(),
                    key,
                    queue.clone(),
                    receiver,
                    domain,
                ));
                queue
            }
        };

        // The bytes are reserved **before** the datagram goes in, so that the
        // queue cannot pass its bound between the check and the send.
        match queue.send(payload) {
            Ok(()) => {}
            // Datagrams arriving while the tunnel is still opening are the normal
            // case for the first few, so a full queue is not worth a log line —
            // printing one per dropped datagram would be its own problem under
            // load. Losing them is what UDP promises anyway.
            Err(UdpSendError::NoRoom | UdpSendError::Full) => {}
            // The flow ended between the lookup and the send. The next datagram
            // creates a new one.
            Err(UdpSendError::Closed) => {
                jni_log!("[tun-proxy] UDP flow to {} closed", dst_addr);
            }
        }
    }
    jni_log!("[tun-proxy] UDP demux task exiting");
}

/// Takes a datagram out of a flow's queue, and gives its bytes back.
///
/// The bytes are given back **here**, where the datagram leaves the queue: the
/// queue's budget is what the flow is holding, and a datagram that is no
/// longer waiting is no longer part of it. One place does it, so that a call
/// site cannot forget — a reservation that is never given back shrinks the
/// budget a byte at a time until the flow is wedged and drops every datagram
/// it is given.
fn take_from_queue(queue: &UdpQueue, datagram: Vec<u8>) -> Vec<u8> {
    queue.taken(&datagram);
    datagram
}

/// Carry one UDP flow: datagrams in from the demultiplexer, frames out to the
/// tunnel, and the reverse.
///
/// The flow ends on silence in either direction, when the tunnel closes, or when
/// the server refuses it. A refusal is logged once and the flow is dropped: UDP
/// has nowhere to report an error to, and the application's own retry is what
/// creates the next flow.
async fn run_udp_flow(
    ctx: TunContext,
    table: FlowTable,
    key: FlowKey,
    mine: UdpQueue,
    mut datagrams: mpsc::Receiver<Vec<u8>>,
    domain: std::sync::Arc<str>,
) {
    let (client_addr, virtual_dst) = key;
    let port = virtual_dst.port();

    let (pooled, mut tunnel_send, mut tunnel_recv) =
        match l4::open_udp(&ctx.endpoint_group, &domain, port).await {
            Ok(tunnel) => tunnel,
            Err(e) => {
                jni_log!("[tun-proxy] UDP {}:{} refused: {}", domain, port, e);
                release_flow(&table, &key, &mine);
                return;
            }
        };

    jni_log!(
        "[tun-proxy] UDP flow {} -> {}:{}",
        client_addr,
        domain,
        port
    );

    // A UDP "flow" is one socket's traffic to one host: it lasts until either
    // side goes quiet, so for accounting it is one open flow for all that time
    // rather than one per datagram. That is deliberately not the same unit as
    // the TCP one, and it is the honest one — an application holding a QUIC
    // socket open has one thing in flight, not thousands.
    let flow = pooled.enter_flow(FlowMeta {
        kind: FlowKind::TunUdp,
        target: Some(format!("{domain}:{port}")),
        source: Some(client_addr.to_string()),
    });

    let mut read_buf = vec![0u8; MAX_UDP_PAYLOAD + FRAME_HEADER_LEN];
    // A bi-stream has no message boundaries, so a datagram can start in one read
    // and finish in the next. `partial` holds the bytes of the frames that have
    // not fully arrived.
    let mut partial: Vec<u8> = Vec::new();
    let mut encoded: Vec<u8> = Vec::new();

    loop {
        // Silence in *either* direction is what ends a flow, so the timer wraps
        // the whole step rather than just the tunnel read.
        let activity = match tokio::time::timeout(
            UDP_FLOW_IDLE,
            next_activity(
                datagrams.recv(),
                tunnel_recv.read(&mut read_buf),
                flow.cancelled(),
                wait_for_stop(ctx.stopped.clone()),
            ),
        )
        .await
        {
            Ok(activity) => activity,
            Err(_) => {
                jni_log!(
                    "[tun-proxy] UDP flow {} -> {}:{} idle for {}s, closing",
                    client_addr,
                    domain,
                    port,
                    UDP_FLOW_IDLE.as_secs()
                );
                break;
            }
        };

        match activity {
            // The demultiplexer dropped our sender: the flow was replaced.
            Activity::Application(None) => break,
            Activity::Application(Some(datagram)) => {
                // The datagram is out of the queue now, so its bytes are no
                // longer waiting for it.
                let datagram = take_from_queue(&mine, datagram);
                encoded.clear();
                match encode_frame(&datagram, &mut encoded) {
                    Ok(()) => {
                        // The datagram, not the frame: the two bytes that carry
                        // its length are the tunnel's own, and an application
                        // that sent `datagram.len()` bytes sent exactly those.
                        // Counted behind the write, like every other path here:
                        // a datagram the tunnel refused never left the device.
                        if tunnel_send.write_all(&encoded).await.is_err() {
                            jni_log!("[tun-proxy] UDP flow to {}:{} is gone", domain, port);
                            break;
                        }
                        flow.record_sent(datagram.len() as u64);
                    }
                    Err(e) => {
                        jni_log!(
                            "[tun-proxy] dropping a {}-byte datagram to {}:{}: {}",
                            datagram.len(),
                            domain,
                            port,
                            e
                        );
                    }
                }
            }
            // The server closed the flow.
            Activity::Tunnel(Ok(None)) => break,
            // A read that returned no bytes is not an end of stream.
            Activity::Tunnel(Ok(Some(0))) => {}
            Activity::Tunnel(Ok(Some(n))) => {
                partial.extend_from_slice(&read_buf[..n]);

                // A frame that is still arriving may ask for up to 65 535
                // bytes and take as long as it likes to send them, one byte
                // per idle window if that suits the far side. Two maximum-size
                // frames is the most this buffer can legitimately hold, so
                // anything past that is a frame that is never going to
                // complete: end the flow rather than keep buffering toward a
                // length nobody is sending.
                if partial.len() > MAX_UDP_PARTIAL {
                    jni_log!(
                        "[tun-proxy] UDP flow to {}:{} buffered {} bytes without a complete frame, ending it",
                        domain,
                        port,
                        partial.len()
                    );
                    break;
                }

                let mut consumed = 0usize;
                let mut tun_gone = false;
                let mut oversized = false;
                while let Frame::Ready {
                    payload,
                    consumed: frame_len,
                } = decode_frame(&partial[consumed..])
                {
                    // A datagram larger than a UDP payload cannot be written to
                    // the TUN: the IP header's total-length field is sixteen
                    // bits wide, and the stack builds the packet from this
                    // payload. The encoder on the other side refuses to
                    // produce one, so a frame this size is a peer that is not
                    // speaking the protocol — and the flow ends rather than
                    // the packet going out truncated.
                    if !payload_fits_datagram(payload) {
                        jni_log!(
                            "[tun-proxy] UDP frame of {} bytes from {}:{} exceeds the datagram limit, ending the flow",
                            payload.len(),
                            domain,
                            port
                        );
                        oversized = true;
                        break;
                    }
                    // The reply comes *from* the address the application sent to,
                    // because the application's socket is often connected and a
                    // datagram from any other source is discarded.
                    // The payload, not the frame: the two bytes that carried
                    // its length are the tunnel's own. Counted once the TUN
                    // writer has taken it, which is the moment it becomes the
                    // application's bytes rather than the frame's.
                    if ctx
                        .tun_out
                        .send((payload.to_vec(), virtual_dst, client_addr))
                        .await
                        .is_err()
                    {
                        tun_gone = true;
                        break;
                    }
                    flow.record_received(payload.len() as u64);
                    consumed += frame_len;
                }
                partial.drain(..consumed);
                if tun_gone {
                    jni_log!(
                        "[tun-proxy] TUN writer is gone, ending UDP flow to {}",
                        domain
                    );
                    break;
                }
                if oversized {
                    break;
                }
            }
            Activity::Tunnel(Err(e)) => {
                jni_log!("[tun-proxy] UDP flow to {}:{} ended: {}", domain, port, e);
                break;
            }
            Activity::Cancelled => {
                jni_log!(
                    "[tun-proxy] UDP flow {} -> {}:{} closed by request",
                    client_addr,
                    domain,
                    port
                );
                break;
            }
            // The proxy is going away. Without this the flow sits on its tunnel
            // until the server's idle timeout closes it, holding a pooled
            // connection the whole time.
            Activity::Stopped => {
                jni_log!(
                    "[tun-proxy] UDP flow {} -> {}:{} ended: the proxy is stopping",
                    client_addr,
                    domain,
                    port
                );
                break;
            }
        }
    }

    let _ = tunnel_send.finish();
    release_flow(&table, &key, &mine);
}

/// Drop a finished flow from the table.
///
/// Only removes the entry if it is still *ours*: a flow that ends after the
/// demultiplexer replaced it (which happens when the channel is closed) must not
/// take the live flow's channel down with it.
fn release_flow(table: &FlowTable, key: &FlowKey, mine: &UdpQueue) {
    let mut flows = lock_flows(table);
    if flows
        .get(key)
        .is_some_and(|entry| entry.sender.same_channel(&mine.sender))
    {
        flows.remove(key);
    }
}

/// A poisoned lock still holds a usable table — every critical section is a
/// handful of `HashMap` calls and nothing that can panic in between — so
/// recovering beats taking the tunnel down.
fn lock_flows(table: &FlowTable) -> MutexGuard<'_, HashMap<FlowKey, UdpQueue>> {
    table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `(the application's address, the address the application sent to)`.
///
/// The application's address is enough to separate two sockets on the same
/// address — its port distinguishes them — and the destination address
/// identifies the flow, since every domain has its own (see [`IpMapping`]).
type FlowKey = (SocketAddr, SocketAddr);

type FlowTable = Arc<Mutex<HashMap<FlowKey, UdpQueue>>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_flow_gives_the_bytes_back_when_it_takes_a_datagram() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(UDP_FLOW_QUEUE);
        let queue = UdpQueue::new(sender);

        let datagram = vec![7u8; 1400];
        assert_eq!(queue.send(datagram.clone()), Ok(()), "the datagram goes in");
        assert_eq!(
            queue.queued_bytes(),
            datagram.len(),
            "the datagram's bytes are waiting for it"
        );

        // The flow takes it out of the queue, and the bytes go back with it.
        let taken = receiver.recv().await.expect("the datagram is there");
        let datagram = take_from_queue(&queue, taken);
        assert_eq!(datagram, vec![7u8; 1400], "the datagram is the one sent");

        assert_eq!(
            queue.queued_bytes(),
            0,
            "the bytes are given back when the datagram leaves the queue"
        );
    }
}

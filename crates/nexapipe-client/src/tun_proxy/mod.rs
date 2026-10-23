//! TUN proxy: a user-space TCP/IP stack implemented in Rust with netstack-smoltcp,
//! shared by the Android client (fd-based entry, `TunProxy::new`) and the desktop
//! app (IP-packet reader/writer entry, [`TunProxy::with_io`]).
//!
//! Data flow:
//! ```text
//! APP → TUN (fd on Android / tun crate device on desktop) → Stack(Sink: IP packets in)
//!                                  ↓ smoltcp processing
//!                            ┌──────┴────────┐
//!                       TcpListener      UdpSocket
//!                            │              │
//!                            │              ├─ dst <dns_ip>:53 ─→ DNS hijack,
//!                            │              │                     answers with a
//!                            │              │                     per-domain IP
//!                            │              │
//!                            │              └─ dst <mapped IP>+ ─→ l4::open_udp(domain, port)
//!                            │                                   (one bi-stream per flow,
//!                            │                                    one datagram per frame)
//!                            ↓
//!                  reverse-lookup the destination address
//!                            │
//!                            ↓
//!                  l4::open_tcp(domain, port)
//!                            │
//!                            ↓
//!                  iroh bi-stream → server route → backend (TCP or UDP)
//!
//! Stack(Stream: IP packets out) → TUN → APP
//! ```
//!
//! # The destination address is the destination
//!
//! `.3` of the block used to be the single virtual proxy address: every connection
//! went there and the far side worked out where it was going from the payload —
//! SNI out of a TLS `ClientHello`, `Host` out of an HTTP request — and the port was
//! thrown away, so a flow to `example.com:8080` arrived looking like a flow to
//! 443. UDP cannot work that way at all: a datagram carries no host name.
//!
//! So the DNS answers handed out by this module carry one address per domain
//! (see [`IpMapping`]), and the address *is* the destination:
//!
//! ```text
//! dns.example.com   → 198.18.0.16:53    → l4::open_udp("dns.example.com", 53)
//! db.example.com    → 198.18.0.17:5432  → l4::open_tcp("db.example.com", 5432)
//! ```
//!
//! On Android, the legacy proxy address is still accepted **for TCP only**, so
//! applications that cached the address before the per-domain change keep
//! working; it goes down the old payload-sniffing path
//! (`handle_local_connection`). The desktop never handed out a fixed proxy
//! address, so it passes no legacy IP.

use crate::ClientError;
use crate::EndpointGroup;
use crate::dns::UpstreamResolvers;
use crate::dns::server::handle_dns_query;
use crate::flow::{FlowKind, FlowMeta};
use crate::l4;
use crate::local_proxy::{handle_local_connection, report_domain_patterns, warn};
use crate::virtual_ip::IpMapping;

#[cfg(feature = "jni")]
use crate::jni_log;

/// Desktop/server builds log through `tracing`; builds without either the `jni`
/// or the `tracing` feature get a no-op.
///
/// At `debug`, not `info`: these are the per-packet and per-flow lines of the
/// data path, and one of them names the domain every TCP and UDP flow is for.
/// A default-level desktop build logged every site a user visited.
///
/// The format arguments are still *evaluated* (borrowed) inside the no-op's dead
/// branch, so the optimiser removes the call but `unused_variables` does not fire
/// on variables that only ever appear inside a log statement.
#[cfg(all(not(feature = "jni"), feature = "tracing"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        ::tracing::debug!($($arg)*)
    };
}

#[cfg(all(not(feature = "jni"), not(feature = "tracing")))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if false {
            let _ = ::std::format_args!($($arg)*);
        }
    };
}

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::udp::{ReadHalf as UdpReadHalf, UdpMsg, WriteHalf as UdpWriteHalf};
use netstack_smoltcp::{
    AnyIpPktFrame, Stack, StackBuilder, TcpListener as SmolTcpListener, TcpStream as SmolTcpStream,
};
use nexapipe_proto::{
    FRAME_HEADER_LEN, Frame, MAX_UDP_PAYLOAD, decode_frame, encode_frame, payload_fits_datagram,
};
use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
// Only the Android half names an IPv6 literal: the constants it builds the TUN's
// virtual block from are matched against the Kotlin side's.
#[cfg(target_os = "android")]
use std::net::Ipv6Addr;
#[cfg(any(target_os = "android", test))]
#[cfg(target_os = "android")]
use std::os::fd::{FromRawFd, IntoRawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
#[cfg(target_os = "android")]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

mod fd;
mod tcp;
mod udp;

#[cfg(target_os = "android")]
use fd::dup_tun_fds;
#[cfg(target_os = "android")]
use fd::{TunFds, set_nonblocking};
#[cfg(target_os = "android")]
use std::os::fd::OwnedFd;
use tcp::run_tcp_acceptor;
use udp::{run_tun_udp_writer, run_udp_demux};

// Virtual IP addresses — must match the TUN config in the Kotlin-side NexaVpnService.
// They are derived from the block the tunnel claims, so the two sides cannot
// disagree about which addresses they are:
//
//   .1  = the TUN interface
//   .2  = DNS server (smoltcp UdpSocket receives DNS queries)
//   .3  = legacy proxy IP (TCP only; payload sniffing, kept for stale caches)
//   .16+ = per-domain addresses handed out by `IpMapping`
//
// See `crate::virtual_block` for the block and the rules behind it.

/// The virtual IPv6 block — must match the TUN config in the Kotlin-side
/// NexaVpnService, which assigns `::1` to the interface and routes the whole
/// /64 into the TUN.
///
/// Derived from the IPv4 block: `fd00:{b0}:{b1}:{b2}::/64`, so the two
/// families read as one block and the v6 half follows the v4 half wherever it
/// goes. A ULA (`fd00::/8`) rather than a global address: it is never routed
/// on the public internet, so a leak of one of these addresses — a DNS answer
/// that escapes the tunnel, a log line — is a dead end.
#[cfg(target_os = "android")]
fn virtual_ipv6_net() -> Ipv6Addr {
    crate::virtual_block::ipv6_block()
}
/// First address handed out of the IPv6 block: `::10`, mirroring the IPv4
/// pool's `.16` — the sixteenth address, written in hexadecimal as IPv6
/// notation has it.
#[cfg(target_os = "android")]
fn virtual_ipv6_first() -> Ipv6Addr {
    crate::virtual_block::ipv6_pool_first()
}
/// Last address handed out: `::fffe`. The top of the /64 is left alone the same
/// way `.255` is — the interface's own address is at the bottom, and a pool
/// that could hand out the block's own solicited-node or anycast addresses is
/// asking for confusion.
#[cfg(target_os = "android")]
fn virtual_ipv6_last() -> Ipv6Addr {
    crate::virtual_block::ipv6_pool_last()
}

/// The only port the DNS hijack answers on. A datagram to any other port is a flow.
const DNS_PORT: u16 = 53;

/// Inner MTU for both the TUN device (see `Builder.setMtu` in NexaVpnService.kt) and the
/// smoltcp stack. These two must agree.
///
/// Not 1500: an inner IP packet of 1500 bytes does not fit in one QUIC datagram. iroh's MTU
/// discovery tops out around a 1452-byte UDP payload, and the QUIC short header plus the
/// AEAD tag eat ~17 more bytes, leaving ~1435 for stream data. A 1500-byte inner packet
/// therefore had to be fragmented across two datagrams, roughly doubling the datagram count
/// and the number of AEAD operations per megabyte. 1400 leaves ~35 bytes of headroom and
/// keeps one inner segment == one QUIC datagram.
const TUN_MTU: usize = 1400;

/// The per-socket TCP window the TUN stack uses, in bytes.
///
/// **The window is the flow's memory.** The stack gives every socket four
/// buffers of this size — two for the protocol and two for the application
/// side of the tunnel — so a flow costs four times this whether it is
/// carrying anything or not. Measured (see the `tun_flow_memory` example): at
/// 320 KiB a flow is 1,280 KiB of address space, at 128 KiB it is 512 KiB.
///
/// **It is also the flow's throughput.** Steady single-flow speed is the
/// window divided by the round-trip time:
///
/// | round trip | 128 KiB | 320 KiB |
/// |---|---|---|
/// | 20 ms | 6.25 MB/s | 15.6 MB/s |
/// | 50 ms | 2.5 MB/s | 6.25 MB/s |
/// | 100 ms | 1.25 MB/s | 3.1 MB/s |
///
/// 128 KiB is the default because the traffic through a TUN is mostly
/// request-and-response, where a flow never reaches its window, and because
/// the memory is paid by every flow at once. A path that carries bulk data
/// wants the other number: `NEXAPIPE_TUN_TCP_WINDOW` sets it without a
/// rebuild, and [`TunStackConfig::tcp_window`] sets it for a library user.
pub const DEFAULT_TCP_WINDOW: u32 = 128 * 1024;

/// The smallest window the stack is given.
///
/// A window below this cannot carry a segment and a half, so a flow on it
/// would crawl rather than fail — which is worse than a refused value,
/// because nothing says why. A value under the floor is ignored and the
/// default is used instead.
pub const MIN_TCP_WINDOW: u32 = 16 * 1024;

/// Overrides [`DEFAULT_TCP_WINDOW`] for the TUN stack, in bytes.
///
/// The desktop can set it; Android has no useful environment and runs the
/// compiled-in default.
pub const ENV_TCP_WINDOW: &str = "NEXAPIPE_TUN_TCP_WINDOW";

/// The window the stack is built with.
///
/// The caller's own value if it has one, then the environment's, then the
/// default. A value that cannot work is ignored with a warning rather than
/// obeyed: the same rule the other environment variables follow.
fn resolve_tcp_window(requested: Option<u32>, from_env: Option<&str>) -> u32 {
    if let Some(window) = requested {
        if window < MIN_TCP_WINDOW {
            warn(&format!(
                "a TCP window of {window} bytes is below the {MIN_TCP_WINDOW} byte floor, \
                 using the default instead"
            ));
            return DEFAULT_TCP_WINDOW;
        }
        return window;
    }

    let Some(raw) = from_env else {
        return DEFAULT_TCP_WINDOW;
    };
    match raw.trim().parse::<u32>() {
        Ok(window) if window >= MIN_TCP_WINDOW => window,
        _ => {
            warn(&format!(
                "{ENV_TCP_WINDOW}={raw} is not a number of at least {MIN_TCP_WINDOW} bytes, \
                 ignoring it"
            ));
            DEFAULT_TCP_WINDOW
        }
    }
}

/// How long a UDP flow may stay silent before this side closes it.
///
/// Deliberately under the server's own 60 s UDP idle timeout: if the server closes
/// first, we keep writing into a stream that is being reset. The window is the same
/// on both sides — silence in *either* direction — so this side simply gets there
/// first.
const UDP_FLOW_IDLE: Duration = Duration::from_secs(50);

/// How often a flow looks at the stop flag while it is running.
///
/// A flow is not one of the tasks `stop()` aborts, so this is how it finds out
/// the proxy is gone — and it has to, because it is holding a pooled connection
/// until it does. Cheap either way: one timer per flow, and a second is far
/// sooner than the alternative.
const STOP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Datagrams that may be waiting for one UDP flow's tunnel to accept them.
///
/// A flow is created when its first datagram arrives and the tunnel takes a
/// moment to open (a connection may have to be dialled), so the datagrams that
/// follow in that window queue here. Beyond this depth they are dropped: UDP is
/// allowed to lose datagrams, and buffering without bound would turn a stalled
/// flow into memory growth.
const UDP_FLOW_QUEUE: usize = 256;

/// How many bytes of datagrams one flow may have waiting to go into the
/// tunnel.
///
/// **The queue is bounded by bytes, not only by datagrams.** A datagram may be
/// 65,507 bytes, so a queue of 256 of them is 16 MiB per flow — and there are
/// 32 flows, so half a gigabyte of datagrams a device may have queued at
/// once, for a queue that is meant to smooth a burst.
///
/// A megabyte is sixteen full-size datagrams, and thirty-two flows at that is
/// 32 MiB: the same order as the TCP side's per-flow budget, and a sixteenth
/// of what the datagram count alone allowed.
const UDP_FLOW_QUEUE_BYTES: usize = 1024 * 1024;

/// Datagrams on their way from the proxy to the application (DNS replies and
/// every UDP flow's inbound traffic) queue here for the single TUN writer.
const TUN_WRITE_QUEUE: usize = 1024;

/// How many UDP flows may be open at once.
///
/// One flow per (client address, destination), and each one holds a tunnel
/// open — a stream, and a pooled connection, on the server — plus a 65 KiB
/// read buffer and a queue 256 datagrams deep. Nothing bounded how many an
/// application could start: a peer that sent one datagram each from a few
/// thousand source ports, or a leak of flows whose idle timer had not run out
/// yet, was answered with as many tunnels as it cared to open.
const MAX_UDP_FLOWS: usize = 32;

/// How many TCP flows may be open at once.
///
/// One flow is one smoltcp socket, one tunnel on the server, and one
/// connection checked out of a group — and nothing bounded how many an
/// application could start: the stack's socket set grows as connections
/// arrive, and a flow whose tunnel has to be dialled opens a new connection
/// when the pool has nothing free. On Android the TUN is system-wide, so any
/// installed application reaches this.
///
/// **Sixty-four, and the number is about memory.** A flow owns four buffers of
/// the TCP window ([`DEFAULT_TCP_WINDOW`]), so at the window the stack used
/// before the client had a say in it a flow was 1.25 MiB of address space
/// before it had carried a byte: 256 of them were 320 MiB. A phone running a
/// browser, a music player and a messaging app holds a few dozen flows open
/// at a time rather than hundreds, and a flow past the cap is refused with a
/// log line — which is the answer an application that wants more has to act
/// on.
///
/// The local HTTP proxy's own ceiling is higher, and rightly so: its
/// connections cost a buffer each rather than four.
const MAX_TCP_FLOWS: usize = 64;

/// How many DNS queries may be in flight at once.
///
/// A device's resolver asks for a handful of names at a time — a page load is a
/// few, a preconnect is a few more — so this is far above what a real device
/// uses. It is here so that a device which floods the TUN with queries cannot
/// make the number of outstanding DNS round trips grow without limit.
const MAX_DNS_QUERIES: usize = 32;

/// How many bytes one UDP flow may hold of a frame that has not arrived yet.
///
/// Two maximum-size frames, which is the most the buffer can legitimately
/// reach: the tail of one frame left over from the previous read, plus one
/// read on top of it. A length prefix is a `u16`, so a frame can announce
/// 65 535 bytes and then arrive however slowly the far side likes, and
/// nothing in the read loop objects — this is the line that says how much a
/// flow may be made to wait.
const MAX_UDP_PARTIAL: usize = 2 * (MAX_UDP_PAYLOAD + FRAME_HEADER_LEN);

/// Buffer size for the byte-copying TCP paths.
const COPY_BUF_SIZE: usize = 16 * 1024;

/// TUN proxy: manages the smoltcp stack and all background pump/acceptor tasks.
///
/// Lifecycle: created by `nativeStartTunProxy` and stored in `ProxyState.tun_proxy`.
/// `nativeStopTunProxy` / `nativeDestroy` call `stop()` to terminate all tasks.
/// `Drop` also calls `stop()` as a safety net.
pub struct TunProxy {
    stopped: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

/// Everything the acceptors and the flows need, so each spawned task takes one
/// clone instead of five arguments.
#[derive(Clone)]
struct TunContext {
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
    ip_mapping: Arc<IpMapping>,
    /// The address the system resolver is pointed at: a UDP datagram to this
    /// address on port 53 is a DNS query (Android: `.2` of the block the tunnel
    /// claims, assigned to nothing so the packets traverse the TUN; the desktop:
    /// the interface's own address).
    dns_ip: Ipv4Addr,
    /// The legacy single virtual proxy address (payload sniffing for stale DNS
    /// caches) or `None` where none was ever handed out (the desktop).
    legacy_proxy_ip: Option<Ipv4Addr>,
    /// Every datagram leaving the proxy for the application, from both the DNS
    /// hijack and the L4 UDP flows.
    ///
    /// One queue and one writer task: the smoltcp `WriteHalf` is a `Sink`, not a
    /// shared writer, and a `Mutex` around it (the previous design) made every
    /// concurrent reply wait for the lock, so one slow flow delayed the DNS
    /// answers behind it.
    tun_out: mpsc::Sender<UdpMsg>,
    /// Slots left for TCP flows: one is taken per accepted connection and
    /// given back when the flow ends, however it ends.
    tcp_flow_slots: Arc<Semaphore>,
    /// The upstream resolvers the DNS queries are forwarded to, and the sockets
    /// they go through.
    ///
    /// One set for the whole proxy: a query that built a socket of its own
    /// would come from a new source port every time, which is the thing this
    /// exists to stop. See [`crate::dns`].
    resolvers: UpstreamResolvers,
    /// Permits left for DNS queries in flight.
    ///
    /// One is taken per query and given back when the answer is on its way.
    /// The device's resolver asks for a handful of names at a time and never
    /// more than this many at once; a query that finds no permit is dropped
    /// rather than held, because holding it would stall the UDP flows that
    /// share the demultiplexer with it.
    dns_permits: Arc<Semaphore>,
    stopped: Arc<AtomicBool>,
}

/// The platform-independent half of [`TunProxy::with_io`]: the network layout
/// the stack is expected to live in.
pub struct TunStackConfig {
    /// See `TunContext::dns_ip`.
    pub dns_ip: Ipv4Addr,
    /// See `TunContext::legacy_proxy_ip`.
    pub legacy_proxy_ip: Option<Ipv4Addr>,
    /// The per-domain virtual IP mapping. Must be the same instance the DNS
    /// answers are handed out from — on the desktop the local DNS server and the
    /// stack share it, so an address allocated by either is routable by both.
    pub ip_mapping: Arc<IpMapping>,
    /// The per-socket TCP window, in bytes.
    ///
    /// `None` takes the client's default — or the environment's, when it names
    /// one. See [`DEFAULT_TCP_WINDOW`] for what the number costs and what it
    /// buys.
    pub tcp_window: Option<u32>,
}

/// The stack's packet halves: IP packets in (from the TUN) and out (to the TUN).
type StackSink = futures_util::stream::SplitSink<Stack, AnyIpPktFrame>;
type StackStream = futures_util::stream::SplitStream<Stack>;

/// Build the smoltcp stack and spawn every task that is not a TUN device pump:
/// the stack runner (retransmits, timeouts), the TCP acceptor and the UDP
/// writer/demultiplexer.
///
/// Returns the stack's packet sink/stream halves for the caller's platform
/// pumps — fd-based on Android ([`TunProxy::new`]), `AsyncDevice` halves on the
/// desktop ([`TunProxy::with_io`]).
fn start_stack_services(
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Vec<String>,
    custom_dns_servers: Vec<SocketAddr>,
    net: TunStackConfig,
    stopped: Arc<AtomicBool>,
    tasks: &mut Vec<JoinHandle<()>>,
) -> Result<(StackSink, StackStream), ClientError> {
    let (stack, runner, udp_socket, tcp_listener) = {
        // The window is the client's to choose, with the environment as the
        // operator's way of choosing it. See [`DEFAULT_TCP_WINDOW`].
        let from_env = std::env::var(ENV_TCP_WINDOW).ok();
        let window = resolve_tcp_window(net.tcp_window, from_env.as_deref());
        StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .mtu(TUN_MTU)
            .tcp_recv_buffer_size(window)
            .tcp_send_buffer_size(window)
            .build()?
    };

    // What the list of names is worth saying, once, before anything asks it a
    // question. Both TUN entry points come through here.
    report_domain_patterns(&proxy_domains);

    // The Runner drives smoltcp's internal processing: retransmits, timeouts, etc.
    if let Some(runner) = runner {
        let stopped_clone = stopped.clone();
        tasks.push(tokio::spawn(async move {
            match runner.await {
                Ok(()) => jni_log!("[tun-proxy] smoltcp runner completed"),
                Err(e) => jni_log!("[tun-proxy] smoltcp runner error: {}", e),
            }
            stopped_clone.store(true, Ordering::Release);
        }));
    }

    // Split Stack → (Sink for IP packets in, Stream for IP packets out).
    let (sink, stream) = stack.split();

    let (tun_out, tun_out_rx) = mpsc::channel::<UdpMsg>(TUN_WRITE_QUEUE);

    // The upstream resolvers, and the sockets they are asked through. One set
    // for the whole proxy: a socket per query would mean a new source port for
    // every lookup, which is what a NAT has to keep a mapping for. See
    // [`crate::dns`].
    let resolvers = UpstreamResolvers::new(&custom_dns_servers, stopped.clone());

    let ctx = TunContext {
        endpoint_group,
        proxy_domains: Arc::new(proxy_domains),
        ip_mapping: net.ip_mapping,
        dns_ip: net.dns_ip,
        legacy_proxy_ip: net.legacy_proxy_ip,
        tun_out,
        tcp_flow_slots: Arc::new(Semaphore::new(MAX_TCP_FLOWS)),
        resolvers,
        dns_permits: Arc::new(Semaphore::new(MAX_DNS_QUERIES)),
        stopped: stopped.clone(),
    };

    // TCP acceptor — accept the TCP connections produced by smoltcp and route them by destination IP.
    //
    // Beware a netstack-smoltcp naming trap: TcpListener yields (stream, local_addr, remote_addr)
    // where local_addr = stream.local_addr() = src_addr = the packet's source IP = the client address,
    //      remote_addr = stream.remote_addr() = dst_addr = the packet's destination IP = the server address.
    // So local/remote semantics are the REVERSE of standard TCP! We use the third element (remote_addr) to decide the destination IP.
    if let Some(tcp_listener) = tcp_listener {
        let ctx = ctx.clone();
        tasks.push(tokio::spawn(run_tcp_acceptor(tcp_listener, ctx)));
    }

    // UDP: one writer for everything going back to the application, and one
    // demultiplexer splitting the inbound stream into DNS queries and L4 flows.
    if let Some(udp_socket) = udp_socket {
        let (udp_rx, udp_tx) = udp_socket.split();
        tasks.push(tokio::spawn(run_tun_udp_writer(udp_tx, tun_out_rx)));
        tasks.push(tokio::spawn(run_udp_demux(udp_rx, ctx)));
    }

    Ok((sink, stream))
}

/// Stops the tasks a partly built proxy already has running.
///
/// Not optional: dropping a `JoinHandle` detaches its task instead of
/// cancelling it, so without this a task started before the failure keeps
/// polling a stack and an endpoint group belonging to a proxy that was never
/// finished — and `stopped` is the only signal it listens for.
#[cfg(target_os = "android")]
fn stop_started_tasks(tasks: &[JoinHandle<()>], stopped: &AtomicBool) {
    stopped.store(true, Ordering::Release);
    for task in tasks {
        task.abort();
    }
}

/// Resolves once the proxy has been told to stop.
///
/// Polled, because there is nothing to await on a bool, and a wake-up per flow
/// is far cheaper than a connection stuck until the app gives up on it.
///
/// **Every flow needs this.** A flow is not one of the tasks `stop()` aborts:
/// it is spawned by the demultiplexer or the acceptor, and aborting the
/// demultiplexer does not abort the flows it started. A flow that outlives the
/// proxy keeps a pooled connection checked out of a group nobody can close,
/// and the only thing that gives it back is the flow itself ending.
async fn wait_for_stop(stopped: Arc<AtomicBool>) {
    while !stopped.load(Ordering::Acquire) {
        tokio::time::sleep(STOP_POLL_INTERVAL).await;
    }
}

impl TunProxy {
    /// Create and start the TUN proxy (Android).
    ///
    /// - `tun_fd`: the descriptor Kotlin's `ParcelFileDescriptor.detachFd()`
    ///   handed over. **This function owns it**: it duplicates it into a
    ///   read/write pair and closes the original, on every path including the
    ///   ones that fail. The caller must not close it again — the parameter is
    ///   an [`OwnedFd`], so it is closed when this returns.
    /// - `endpoint_group`: the `Arc<EndpointGroup>` cloned from `ProxyState`, used for iroh connections.
    /// - `proxy_domains`: the list of domains to proxy (already split from comma-separated input).
    /// - `custom_dns_servers`: the system DNS server list (read from `CUSTOM_DNS_SERVERS`).
    ///
    /// All tasks are started via `runtime.spawn()` internally — **no block_on**.
    #[cfg(target_os = "android")]
    pub fn new(
        tun_fd: OwnedFd,
        endpoint_group: Arc<EndpointGroup>,
        proxy_domains: Vec<String>,
        custom_dns_servers: Vec<SocketAddr>,
    ) -> Result<Self, ClientError> {
        // 1. dup the fd into the read/write pair. The original is closed by
        //    this call, whichever way it ends: `tun_fd` is an `OwnedFd`, and it
        //    is dropped when this scope ends.
        let (fd_read, fd_write) = match dup_tun_fds(tun_fd) {
            Ok(pair) => pair,
            Err(e) => {
                jni_log!("[tun-proxy] dup of the TUN fd failed: {}", e);
                return Err(e);
            }
        };
        let (fd_read, fd_write) = (fd_read.into_raw_fd(), fd_write.into_raw_fd());

        // From here the dups are ours to lose: the original is already closed,
        // so every remaining step that can fail would leak both for the life of
        // the process — and with them the VPN, which cannot be brought up
        // again on a device whose TUN fd is still open.
        let mut fds = TunFds {
            read: Some(unsafe { OwnedFd::from_raw_fd(fd_read) }),
            write: Some(unsafe { OwnedFd::from_raw_fd(fd_write) }),
        };

        set_nonblocking(fd_read)?;
        set_nonblocking(fd_write)?;

        jni_log!(
            "[tun-proxy] fd_read={}, fd_write={} (non-blocking)",
            fd_read,
            fd_write
        );
        jni_log!(
            "[tun-proxy] virtual blocks: {} and {}/64",
            crate::virtual_block::network(),
            virtual_ipv6_net()
        );

        let stopped = Arc::new(AtomicBool::new(false));
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        // 2. Build the stack and every service task; we get back the packet halves.
        let (stack_sink, stack_stream) = match start_stack_services(
            endpoint_group,
            proxy_domains,
            custom_dns_servers,
            TunStackConfig {
                dns_ip: crate::virtual_block::dns_ip(),
                legacy_proxy_ip: Some(crate::virtual_block::legacy_proxy_ip()),
                // IPv6 as well as IPv4: the Kotlin side routes the IPv6 half
                // of the block into the TUN, so an AAAA answer inside it comes
                // back to us the same way an A answer does.
                ip_mapping: Arc::new(
                    IpMapping::new().with_ipv6(virtual_ipv6_first(), virtual_ipv6_last()),
                ),
                // Android has no useful environment, so the window is the
                // compiled-in default.
                tcp_window: None,
            },
            stopped.clone(),
            &mut tasks,
        ) {
            Ok(halves) => halves,
            Err(e) => {
                // It can have spawned part of the stack before failing, and
                // those tasks are not reachable from anywhere else. The dups
                // are closed by `fds` dropping.
                stop_started_tasks(&tasks, &stopped);
                return Err(e);
            }
        };

        // 3. TUN → Stack pump (read fd → Stack Sink).
        {
            let file = unsafe {
                std::fs::File::from_raw_fd(fds.read.take().expect("still held").into_raw_fd())
            };
            // A failure here has to stop what `start_stack_services` already
            // spawned: dropping a `JoinHandle` detaches its task rather than
            // cancelling it, and `stopped` is the only signal those tasks hear.
            let async_fd = match AsyncFd::new(file) {
                Ok(async_fd) => async_fd,
                Err(e) => {
                    stop_started_tasks(&tasks, &stopped);
                    return Err(e.into());
                }
            };
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let async_fd = async_fd;
                let mut sink = stack_sink;
                let mut buf = vec![0u8; TUN_MTU];
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    let mut guard = match async_fd.readable().await {
                        Ok(g) => g,
                        Err(e) => {
                            jni_log!("[tun-proxy] readable() error: {}", e);
                            break;
                        }
                    };
                    // Use try_io: &File implements Read, so we can use get_ref() (the immutable guard
                    // only has get_ref()). try_io auto-clears readiness on WouldBlock, no manual clear_ready needed.
                    match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                        Ok(Ok(0)) => {
                            // EOF — the TUN fd was closed.
                            jni_log!("[tun-proxy] TUN read EOF, stopping pump-in");
                            break;
                        }
                        Ok(Ok(n)) => {
                            // n > 0 — read an IP packet; feed it into the smoltcp stack.
                            if let Err(e) = sink.send(buf[..n].to_vec()).await {
                                jni_log!("[tun-proxy] stack send error: {}", e);
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            jni_log!("[tun-proxy] TUN read error: {}", e);
                            break;
                        }
                        Err(_would_block) => {
                            // try_io already cleared readiness; wait again.
                            continue;
                        }
                    }
                }
                stopped_clone.store(true, Ordering::Release);
                jni_log!("[tun-proxy] pump-in task exiting");
            }));
        }

        // 4. Stack → TUN pump (Stack Stream → write fd).
        {
            let file = unsafe {
                std::fs::File::from_raw_fd(fds.write.take().expect("still held").into_raw_fd())
            };
            let async_fd = match AsyncFd::new(file) {
                Ok(async_fd) => async_fd,
                Err(e) => {
                    stop_started_tasks(&tasks, &stopped);
                    return Err(e.into());
                }
            };
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let async_fd = async_fd;
                let mut stream = stack_stream;
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match stream.next().await {
                        Some(Ok(pkt)) => {
                            // Write to the TUN fd, retrying on WouldBlock.
                            loop {
                                if stopped_clone.load(Ordering::Acquire) {
                                    break;
                                }
                                let mut guard = match async_fd.writable().await {
                                    Ok(g) => g,
                                    Err(e) => {
                                        jni_log!("[tun-proxy] writable() error: {}", e);
                                        break;
                                    }
                                };
                                // Use try_io: &File implements Write, so we can use get_ref().
                                // try_io auto-clears readiness on WouldBlock.
                                match guard.try_io(|inner| inner.get_ref().write_all(&pkt)) {
                                    Ok(Ok(())) => break, // write succeeded
                                    Ok(Err(e)) => {
                                        jni_log!("[tun-proxy] TUN write error: {}", e);
                                        break;
                                    }
                                    Err(_would_block) => {
                                        // try_io already cleared readiness; retry.
                                        continue;
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            jni_log!("[tun-proxy] stack stream error: {}", e);
                        }
                        None => {
                            jni_log!("[tun-proxy] stack stream ended, stopping pump-out");
                            break;
                        }
                    }
                }
                stopped_clone.store(true, Ordering::Release);
                jni_log!("[tun-proxy] pump-out task exiting");
            }));
        }

        jni_log!("[tun-proxy] Started with {} tasks", tasks.len());
        Ok(Self { stopped, tasks })
    }

    /// Create and start the TUN proxy over an IP-packet reader/writer pair.
    ///
    /// The desktop uses this with a `tun` crate `AsyncDevice`'s split halves:
    /// each `read`/`write_all` carries exactly one IP packet. The Android
    /// fd-based entry point is `TunProxy::new`.
    pub fn with_io<R, W>(
        reader: R,
        writer: W,
        endpoint_group: Arc<EndpointGroup>,
        proxy_domains: Vec<String>,
        custom_dns_servers: Vec<SocketAddr>,
        net: TunStackConfig,
    ) -> Result<Self, ClientError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let stopped = Arc::new(AtomicBool::new(false));
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        let (sink, stream) = start_stack_services(
            endpoint_group,
            proxy_domains,
            custom_dns_servers,
            net,
            stopped.clone(),
            &mut tasks,
        )?;

        // TUN → Stack pump (reader → Stack Sink). One read = one IP packet.
        {
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let mut reader = reader;
                let mut sink = sink;
                let mut buf = vec![0u8; TUN_MTU];
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match reader.read(&mut buf).await {
                        Ok(0) => {
                            // EOF — the TUN device was closed.
                            jni_log!("[tun-proxy] TUN read EOF, stopping pump-in");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = sink.send(buf[..n].to_vec()).await {
                                jni_log!("[tun-proxy] stack send error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            jni_log!("[tun-proxy] TUN read error: {}", e);
                            break;
                        }
                    }
                }
                stopped_clone.store(true, Ordering::Release);
                jni_log!("[tun-proxy] pump-in task exiting");
            }));
        }

        // Stack → TUN pump (Stack Stream → writer).
        {
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let mut writer = writer;
                let mut stream = stream;
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match stream.next().await {
                        Some(Ok(pkt)) => {
                            if let Err(e) = writer.write_all(&pkt).await {
                                jni_log!("[tun-proxy] TUN write error: {}", e);
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            jni_log!("[tun-proxy] stack stream error: {}", e);
                        }
                        None => {
                            jni_log!("[tun-proxy] stack stream ended, stopping pump-out");
                            break;
                        }
                    }
                }
                stopped_clone.store(true, Ordering::Release);
                jni_log!("[tun-proxy] pump-out task exiting");
            }));
        }

        jni_log!("[tun-proxy] Started with {} tasks", tasks.len());
        Ok(Self { stopped, tasks })
    }

    /// Stop all background tasks. Non-blocking — abort() marks the tasks for cancellation without waiting.
    /// Used by `Drop` or when we don't need to wait for the fd to close.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        for task in &self.tasks {
            task.abort();
        }
        jni_log!("[tun-proxy] Stopped (aborted {} tasks)", self.tasks.len());
    }

    /// Whether every task has wound down — the stop flag is set by `stop()` and
    /// by each task on its own exit, so a `false` here means the stack is live.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Abort all tasks and wait for them to finish (with a timeout), from async
    /// context. Consumes self; the TUN device halves held by the pumps are
    /// dropped here, releasing the device.
    pub async fn shutdown_async(mut self) {
        self.stopped.store(true, Ordering::Release);
        // Use mem::take to pull tasks out, avoiding E0509 (can't move a field out of a Drop type).
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            task.abort();
            let _ = tokio::time::timeout(Duration::from_millis(500), task).await;
        }
        jni_log!("[tun-proxy] Shutdown complete (all tasks joined)");
        // self dropped here → Drop::drop calls stop() (idempotent; tasks are already empty).
    }

    /// Abort all tasks and wait for them to finish (with a timeout), ensuring the fd is closed before returning.
    /// Consumes self. Used in `nativeStopTunProxy` / `nativeStopProxy` to ensure the TUN proxy's fd
    /// is released before endpoint_group.close_all().
    pub fn shutdown(mut self, runtime: &tokio::runtime::Runtime) {
        self.stopped.store(true, Ordering::Release);
        // Use mem::take to pull tasks out, avoiding E0509 (can't move a field out of a Drop type).
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            task.abort();
            // Wait for the task to end (drop future → drop AsyncFd → close fd).
            runtime.block_on(async {
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
            });
        }
        jni_log!("[tun-proxy] Shutdown complete (all tasks joined)");
        // self dropped here → Drop::drop calls stop() (idempotent; tasks are already empty).
    }
}

impl Drop for TunProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

// ============================================================
// TCP
// ============================================================

// ============================================================
// UDP
// ============================================================

// ============================================================
// Helper functions
// ============================================================

// ============================================================

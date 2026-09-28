//! TUN proxy: a user-space TCP/IP stack implemented in Rust with netstack-smoltcp,
//! shared by the Android client (fd-based entry, [`TunProxy::new`]) and the desktop
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
//! `10.0.1.3` used to be the single virtual proxy address: every connection went
//! there and the far side worked out where it was going from the payload — SNI
//! out of a TLS `ClientHello`, `Host` out of an HTTP request — and the port was
//! thrown away, so a flow to `example.com:8080` arrived looking like a flow to
//! 443. UDP cannot work that way at all: a datagram carries no host name.
//!
//! So the DNS answers handed out by this module carry one address per domain
//! (see [`IpMapping`]), and the address *is* the destination:
//!
//! ```text
//! dns.example.com   → 10.0.1.16:53    → l4::open_udp("dns.example.com", 53)
//! db.example.com    → 10.0.1.17:5432  → l4::open_tcp("db.example.com", 5432)
//! ```
//!
//! On Android, `10.0.1.3` is still accepted **for TCP only**, so applications
//! that cached the address before the per-domain change keep working; it goes
//! down the old payload-sniffing path ([`handle_local_connection`]). The desktop
//! never handed out a fixed proxy address, so it passes no legacy IP.

use crate::ClientError;
use crate::EndpointGroup;
use crate::l4;
use crate::local_proxy::{handle_local_connection, should_proxy_domain};
use crate::virtual_ip::IpMapping;

#[cfg(feature = "jni")]
use crate::jni_log;

/// Desktop/server builds log through `tracing`; builds without either the `jni`
/// or the `tracing` feature get a no-op.
///
/// The format arguments are still *evaluated* (borrowed) inside the no-op's dead
/// branch, so the optimiser removes the call but `unused_variables` does not fire
/// on variables that only ever appear inside a log statement.
#[cfg(all(not(feature = "jni"), feature = "tracing"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        ::tracing::info!($($arg)*)
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
use nexapipe_proto::{FRAME_HEADER_LEN, Frame, MAX_UDP_PAYLOAD, decode_frame, encode_frame};
use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(target_os = "android")]
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
#[cfg(target_os = "android")]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// Virtual IP constants — must match the TUN config in the Kotlin-side NexaVpnService.
// 10.0.1.1 = the TUN interface
// 10.0.1.2 = DNS server (smoltcp UdpSocket receives DNS queries)
// 10.0.1.3 = legacy proxy IP (TCP only; payload sniffing, kept for stale caches)
// 10.0.1.16+ = per-domain addresses handed out by `IpMapping`
/// Virtual DNS server IP — matches Kotlin-side NexaVpnService.virtualDNSIP, which
/// the system resolver is pointed at (`addDnsServer`). The query's dst_addr is this
/// IP, and it is used as-is as the src_addr in the response.
#[cfg(target_os = "android")]
const VIRTUAL_DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
/// The address every proxied domain used to resolve to. See the module docs.
#[cfg(target_os = "android")]
const VIRTUAL_PROXY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 3);
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
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a UDP flow may stay silent before this side closes it.
///
/// Deliberately under the server's own 60 s UDP idle timeout: if the server closes
/// first, we keep writing into a stream that is being reset. The window is the same
/// on both sides — silence in *either* direction — so this side simply gets there
/// first.
const UDP_FLOW_IDLE: Duration = Duration::from_secs(50);

/// How often a TCP flow looks at the stop flag while it is copying bytes.
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

/// Datagrams on their way from the proxy to the application (DNS replies and
/// every UDP flow's inbound traffic) queue here for the single TUN writer.
const TUN_WRITE_QUEUE: usize = 1024;

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
    /// address on port 53 is a DNS query (Android: 10.0.1.2, assigned to nothing
    /// so the packets traverse the TUN; the desktop: the interface's own address).
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
    stopped: Arc<AtomicBool>,
}

/// The platform-independent half of [`TunProxy::with_io`]: the network layout
/// the stack is expected to live in.
pub struct TunStackConfig {
    /// See [`TunContext::dns_ip`].
    pub dns_ip: Ipv4Addr,
    /// See [`TunContext::legacy_proxy_ip`].
    pub legacy_proxy_ip: Option<Ipv4Addr>,
    /// The per-domain virtual IP mapping. Must be the same instance the DNS
    /// answers are handed out from — on the desktop the local DNS server and the
    /// stack share it, so an address allocated by either is routable by both.
    pub ip_mapping: Arc<IpMapping>,
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
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(TUN_MTU)
        .build()?;

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
    let ctx = TunContext {
        endpoint_group,
        proxy_domains: Arc::new(proxy_domains),
        ip_mapping: net.ip_mapping,
        dns_ip: net.dns_ip,
        legacy_proxy_ip: net.legacy_proxy_ip,
        tun_out,
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
        tasks.push(tokio::spawn(run_udp_demux(
            udp_rx,
            Arc::new(custom_dns_servers),
            ctx,
        )));
    }

    Ok((sink, stream))
}

/// The two dups of the TUN fd, closed unless the pumps take them over.
///
/// Android hands the fd over and it is closed straight after being dup'ed, so
/// every step between the dups and the pumps taking ownership can fail with
/// both dups still open — leaked for the life of the process, and the VPN
/// cannot be brought up again while they are. Each half is taken out as it is
/// handed to a pump; whatever is left here when this drops is closed.
#[cfg(target_os = "android")]
struct TunFds {
    read: Option<RawFd>,
    write: Option<RawFd>,
}

#[cfg(target_os = "android")]
impl Drop for TunFds {
    fn drop(&mut self) {
        for fd in [self.read.take(), self.write.take()].into_iter().flatten() {
            unsafe { libc::close(fd) };
        }
    }
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

impl TunProxy {
    /// Create and start the TUN proxy (Android).
    ///
    /// - `tun_fd`: the raw fd returned by Kotlin's `ParcelFileDescriptor.detachFd()`.
    ///   This function `dup`s it twice (read/write) and closes the original fd.
    /// - `endpoint_group`: the `Arc<EndpointGroup>` cloned from `ProxyState`, used for iroh connections.
    /// - `proxy_domains`: the list of domains to proxy (already split from comma-separated input).
    /// - `custom_dns_servers`: the system DNS server list (read from `CUSTOM_DNS_SERVERS`).
    ///
    /// All tasks are started via `runtime.spawn()` internally — **no block_on**.
    #[cfg(target_os = "android")]
    pub fn new(
        tun_fd: RawFd,
        endpoint_group: Arc<EndpointGroup>,
        proxy_domains: Vec<String>,
        custom_dns_servers: Vec<SocketAddr>,
    ) -> Result<Self, ClientError> {
        // 1. dup the fd twice (read/write) and close the original fd.
        let fd_read = unsafe { libc::dup(tun_fd) };
        if fd_read < 0 {
            let e = std::io::Error::last_os_error();
            jni_log!("[tun-proxy] dup(read) failed: {}", e);
            return Err(e.into());
        }
        let fd_write = unsafe { libc::dup(tun_fd) };
        if fd_write < 0 {
            let e = std::io::Error::last_os_error();
            jni_log!("[tun-proxy] dup(write) failed: {}", e);
            unsafe { libc::close(fd_read) };
            return Err(e.into());
        }
        // Close the original fd — we now hold two dups.
        unsafe { libc::close(tun_fd) };

        // From here the dups are ours to lose: the original is already closed,
        // so every remaining step that can fail would leak both for the life of
        // the process — and with them the VPN, which cannot be brought up
        // again on a device whose TUN fd is still open.
        let mut fds = TunFds {
            read: Some(fd_read),
            write: Some(fd_write),
        };

        set_nonblocking(fd_read)?;
        set_nonblocking(fd_write)?;

        jni_log!(
            "[tun-proxy] fd_read={}, fd_write={} (non-blocking)",
            fd_read,
            fd_write
        );

        let stopped = Arc::new(AtomicBool::new(false));
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        // 2. Build the stack and every service task; we get back the packet halves.
        let (stack_sink, stack_stream) = match start_stack_services(
            endpoint_group,
            proxy_domains,
            custom_dns_servers,
            TunStackConfig {
                dns_ip: VIRTUAL_DNS_IP,
                legacy_proxy_ip: Some(VIRTUAL_PROXY_IP),
                ip_mapping: Arc::new(IpMapping::new()),
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
            let file = unsafe { std::fs::File::from_raw_fd(fds.read.take().expect("still held")) };
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
            let file = unsafe { std::fs::File::from_raw_fd(fds.write.take().expect("still held")) };
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
    /// fd-based entry point is [`TunProxy::new`].
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

/// Accept TCP connections from the stack and route each one by destination address.
async fn run_tcp_acceptor(mut listener: SmolTcpListener, ctx: TunContext) {
    while !ctx.stopped.load(Ordering::Acquire) {
        let Some((stream, client_addr, server_addr)) = listener.next().await else {
            jni_log!("[tun-proxy] TCP listener stream ended");
            break;
        };

        let dest_ip = server_addr.ip();
        let dest_port = server_addr.port();
        jni_log!(
            "[tun-proxy] TCP accept: dest={}:{}, client={}",
            dest_ip,
            dest_port,
            client_addr
        );

        let IpAddr::V4(dest_ip) = dest_ip else {
            jni_log!("[tun-proxy] TCP to {dest_ip} has no domain mapping, dropping");
            continue;
        };

        // Legacy address: applications that cached a DNS answer from before the
        // per-domain addresses existed still connect to 10.0.1.3, so those
        // connections keep the payload-sniffing path (SNI / Host header) instead
        // of being dropped. DNS answers only live 60 s, so this is a short tail.
        // (Android only — the desktop never handed out a fixed proxy address.)
        if ctx.legacy_proxy_ip == Some(dest_ip) {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_local_connection(
                    stream,
                    ctx.proxy_domains.clone(),
                    ctx.endpoint_group.clone(),
                )
                .await
                {
                    jni_log!("[tun-proxy] handle_local_connection error: {}", e);
                }
            });
            continue;
        }

        let Some(domain) = ctx.ip_mapping.lookup_domain(&dest_ip) else {
            jni_log!("[tun-proxy] TCP to {dest_ip}:{dest_port} has no domain mapping, dropping");
            continue;
        };

        let ctx = ctx.clone();
        tokio::spawn(serve_tcp_flow(stream, ctx, domain, dest_port));
    }
    jni_log!("[tun-proxy] TCP acceptor task exiting");
}

/// Carry one TCP flow between the application's smoltcp socket and a server route.
///
/// Nothing is sniffed: the domain came from the destination address, so a raw
/// binary protocol on any port works as well as TLS on 443.
async fn serve_tcp_flow(stream: SmolTcpStream, ctx: TunContext, domain: String, port: u16) {
    // The tunnel is opened before any payload is read, so the application sees
    // the connection go quiet rather than being told a connection exists that
    // the server has no route for.
    let (pooled, mut tunnel_send, mut tunnel_recv) =
        match l4::open_tcp(&ctx.endpoint_group, &domain, port).await {
            Ok(tunnel) => tunnel,
            Err(e) => {
                jni_log!("[tun-proxy] TCP {}:{} refused: {}", domain, port, e);
                return;
            }
        };

    jni_log!(
        "[tun-proxy] TCP flow {} -> {}:{}",
        client_addr_hint(&stream),
        domain,
        port
    );

    let (mut app_read, mut app_write) = tokio::io::split(stream);

    let app_to_tunnel = async {
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            match app_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tunnel_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    jni_log!("[tun-proxy] TCP {}:{} app read error: {}", domain, port, e);
                    break;
                }
            }
        }
        // Half-close: the application said it is done sending, and the backend
        // needs to hear that (an HTTP request without a length ends this way).
        let _ = tunnel_send.finish();
    };

    let tunnel_to_app = async {
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            match tunnel_recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if app_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    jni_log!(
                        "[tun-proxy] TCP {}:{} tunnel read error: {}",
                        domain,
                        port,
                        e
                    );
                    break;
                }
            }
        }
        // smoltcp's `poll_shutdown` returns `Pending` until the FIN has been
        // acknowledged, so this is bounded: sending the FIN is what matters, and
        // waiting forever for an application that has already gone away is not.
        let _ = tokio::time::timeout(Duration::from_secs(5), app_write.shutdown()).await;
    };

    // The third branch: this flow is not one of the tasks `stop()` knows about,
    // so nothing aborts it — and a flow that outlives the proxy keeps a pooled
    // connection checked out of a group nobody can close. Watching the flag is
    // what returns it. Polled, because there is nothing to await on a bool, and
    // a wake-up per flow is far cheaper than a connection stuck until the app
    // gives up on it.
    //
    // No idle timeout on top of that, unlike the UDP flows: a TCP connection
    // may legitimately sit quiet for minutes, and only the applications at
    // either end can say when it is finished.
    tokio::select! {
        _ = app_to_tunnel => (),
        _ = tunnel_to_app => (),
        _ = async {
            while !ctx.stopped.load(Ordering::Acquire) {
                tokio::time::sleep(STOP_POLL_INTERVAL).await;
            }
        } => (),
    }

    // Dropping both halves closes the smoltcp socket (its `Drop` sends, at most,
    // a FIN; the flow is over either way).
    ctx.endpoint_group.return_connection(&domain, pooled).await;
}

/// The application's address, for the log line. Only valid before `split`.
fn client_addr_hint(stream: &SmolTcpStream) -> String {
    // `local_addr` is the *source* address here; see the naming trap in
    // `run_tcp_acceptor`.
    stream.local_addr().to_string()
}

// ============================================================
// UDP
// ============================================================

/// `(the application's address, the address the application sent to)`.
///
/// The application's address is enough to separate two sockets on the same
/// address — its port distinguishes them — and the destination address
/// identifies the flow, since every domain has its own (see [`IpMapping`]).
type FlowKey = (SocketAddr, SocketAddr);

/// The live UDP flows: their key, and the channel feeding datagrams into them.
type FlowTable = Arc<Mutex<HashMap<FlowKey, mpsc::Sender<Vec<u8>>>>>;

/// Which side of a UDP flow spoke.
enum Activity {
    /// A datagram from the application; `None` means the flow was replaced.
    Application(Option<Vec<u8>>),
    /// Bytes from the tunnel, or why it ended.
    Tunnel(Result<Option<usize>, String>),
}

/// Write every datagram the proxy has for the application back into the stack.
///
/// One task owns the smoltcp `WriteHalf`; everyone else hands datagrams to it
/// through the channel in [`TunContext::tun_out`].
async fn run_tun_udp_writer(mut writer: UdpWriteHalf, mut queue: mpsc::Receiver<UdpMsg>) {
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
async fn run_udp_demux(
    mut socket: UdpReadHalf,
    dns_servers: Arc<Vec<SocketAddr>>,
    ctx: TunContext,
) {
    let table: FlowTable = Arc::new(Mutex::new(HashMap::new()));

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
            // Answer from the address the query went to: the application's socket
            // may be connected, and a reply from anywhere else is discarded by the
            // kernel before the application ever sees it.
            let ctx = ctx.clone();
            let dns_servers = dns_servers.clone();
            tokio::spawn(async move {
                let Some(response) =
                    handle_dns_query(&payload, &ctx.proxy_domains, &dns_servers, &ctx.ip_mapping)
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

        let IpAddr::V4(dst_ip) = dst_addr.ip() else {
            jni_log!(
                "[tun-proxy] UDP to {} has no domain mapping, dropping",
                dst_addr
            );
            continue;
        };
        let Some(domain) = ctx.ip_mapping.lookup_domain(&dst_ip) else {
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
            .filter(|sender| !sender.is_closed())
            .cloned();

        let sender = match existing {
            Some(sender) => sender,
            None => {
                let (sender, receiver) = mpsc::channel::<Vec<u8>>(UDP_FLOW_QUEUE);
                lock_flows(&table).insert(key, sender.clone());
                tokio::spawn(run_udp_flow(
                    ctx.clone(),
                    table.clone(),
                    key,
                    sender.clone(),
                    receiver,
                    domain,
                ));
                sender
            }
        };

        match sender.try_send(payload) {
            Ok(()) => {}
            // Datagrams arriving while the tunnel is still opening are the normal
            // case for the first few, so a full queue is not worth a log line —
            // printing one per dropped datagram would be its own problem under
            // load. Losing them is what UDP promises anyway.
            Err(mpsc::error::TrySendError::Full(_)) => {}
            // The flow ended between the lookup and the send. The next datagram
            // creates a new one.
            Err(mpsc::error::TrySendError::Closed(_)) => {
                jni_log!("[tun-proxy] UDP flow to {} closed", dst_addr);
            }
        }
    }
    jni_log!("[tun-proxy] UDP demux task exiting");
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
    mine: mpsc::Sender<Vec<u8>>,
    mut datagrams: mpsc::Receiver<Vec<u8>>,
    domain: String,
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

    let mut read_buf = vec![0u8; MAX_UDP_PAYLOAD + FRAME_HEADER_LEN];
    // A bi-stream has no message boundaries, so a datagram can start in one read
    // and finish in the next. `partial` holds the bytes of the frames that have
    // not fully arrived.
    let mut partial: Vec<u8> = Vec::new();
    let mut encoded: Vec<u8> = Vec::new();

    loop {
        // Silence in *either* direction is what ends a flow, so the timer wraps
        // the whole step rather than just the tunnel read.
        let activity = match tokio::time::timeout(UDP_FLOW_IDLE, async {
            tokio::select! {
                datagram = datagrams.recv() => Activity::Application(datagram),
                read = tunnel_recv.read(&mut read_buf) => {
                    Activity::Tunnel(read.map_err(|e| e.to_string()))
                }
            }
        })
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
                encoded.clear();
                match encode_frame(&datagram, &mut encoded) {
                    Ok(()) => {
                        if tunnel_send.write_all(&encoded).await.is_err() {
                            jni_log!("[tun-proxy] UDP flow to {}:{} is gone", domain, port);
                            break;
                        }
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

                let mut consumed = 0usize;
                let mut tun_gone = false;
                while let Frame::Ready {
                    payload,
                    consumed: frame_len,
                } = decode_frame(&partial[consumed..])
                {
                    // The reply comes *from* the address the application sent to,
                    // because the application's socket is often connected and a
                    // datagram from any other source is discarded.
                    if ctx
                        .tun_out
                        .send((payload.to_vec(), virtual_dst, client_addr))
                        .await
                        .is_err()
                    {
                        tun_gone = true;
                        break;
                    }
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
            }
            Activity::Tunnel(Err(e)) => {
                jni_log!("[tun-proxy] UDP flow to {}:{} ended: {}", domain, port, e);
                break;
            }
        }
    }

    let _ = tunnel_send.finish();
    ctx.endpoint_group.return_connection(&domain, pooled).await;
    release_flow(&table, &key, &mine);
}

/// Drop a finished flow from the table.
///
/// Only removes the entry if it is still *ours*: a flow that ends after the
/// demultiplexer replaced it (which happens when the channel is closed) must not
/// take the live flow's channel down with it.
fn release_flow(table: &FlowTable, key: &FlowKey, mine: &mpsc::Sender<Vec<u8>>) {
    let mut flows = lock_flows(table);
    if flows.get(key).is_some_and(|entry| entry.same_channel(mine)) {
        flows.remove(key);
    }
}

/// A poisoned lock still holds a usable table — every critical section is a
/// handful of `HashMap` calls and nothing that can panic in between — so
/// recovering beats taking the tunnel down.
fn lock_flows(table: &FlowTable) -> MutexGuard<'_, HashMap<FlowKey, mpsc::Sender<Vec<u8>>>> {
    table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ============================================================
// Helper functions
// ============================================================

/// Put the fd into non-blocking mode.
#[cfg(target_os = "android")]
fn set_nonblocking(fd: RawFd) -> Result<(), ClientError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

// ============================================================
// DNS handling — ported from the Kotlin NexaVpnService.
// ============================================================

/// Handle a DNS query and return the DNS response payload.
///
/// - Proxied domain → allocate a virtual address for it and return that as an A record.
/// - iroh infrastructure domain → forward to the real DNS (not proxied inside the TUN).
/// - Other domain → forward to the real DNS and return the response as-is.
///
/// Note: do NOT hijack the system's captive-portal validation domains (connectivitycheck.gstatic.com,
/// etc.) to a private virtual IP. Android's NetworkMonitor treats "validation domain resolves to a
/// private IP" as "no internet" (DNS returned private IP = no internet), which shows a WiFi
/// exclamation mark in the status bar. Let them use the real DNS and reach the physical network,
/// matching the behavior when the VPN is off.
///
/// Public so the desktop's loopback DNS listener (queries the OS local-delivers
/// to `[::1]:53`, which never traverse the TUN) can answer with the same
/// mapping the stack routes by.
pub async fn handle_dns_query(
    query: &[u8],
    proxy_domains: &[String],
    dns_servers: &[SocketAddr],
    ip_mapping: &IpMapping,
) -> Option<Vec<u8>> {
    let (domain, qtype) = match parse_dns_query(query) {
        Some(d) => d,
        None => return None,
    };
    if domain.is_empty() {
        return None;
    }

    let domain_lower = domain.to_lowercase();

    // iroh infrastructure domains are not proxied through the TUN — iroh's own traffic goes via addDisallowedApplication.
    let is_iroh = domain_lower.ends_with(".iroh.link") || domain_lower.ends_with(".n0.iroh.link");

    let is_proxy = !is_iroh && should_proxy_domain(&domain, proxy_domains);

    if is_proxy {
        // Only an A query gets an address. A rack of virtual IPv4 addresses
        // cannot answer an AAAA query with the truth, so non-A types get an empty
        // NOERROR and the application falls back to A — and, just as important,
        // do not consume an address for a name nothing may ever connect to.
        if qtype != 1 {
            return Some(build_empty_dns_response(query));
        }
        let virtual_ip = ip_mapping.allocate(&domain);
        // The name is deliberately left out: this runs for every name the
        // device resolves, so logging it turns logcat into a record of where
        // the user goes. What debugging needs is the decision, not the name.
        jni_log!("[tun-proxy] DNS: proxying a query -> {}", virtual_ip);
        Some(build_dns_response(query, virtual_ip, qtype))
    } else {
        // Forward to the real DNS.
        jni_log!("[tun-proxy] DNS: forwarding a query (qtype={})", qtype);
        forward_dns_query(query, dns_servers).await
    }
}

/// How many compression pointers one name may follow before the name is
/// declared unreadable. A real name needs one; more than that is a loop.
const MAX_DNS_POINTER_JUMPS: usize = 4;

/// Parse a DNS query, returning (domain, QTYPE).
/// QTYPE: 1=A, 28=AAAA. Returns None on parse failure.
fn parse_dns_query(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 12 {
        return None;
    }

    // DNS header: ID(2) + flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse the Question section's domain name (length-prefixed labels).
    let mut pos = 12;
    let mut labels: Vec<&str> = Vec::new();
    let mut jumps = 0usize;
    // Where QTYPE sits once the name is over. It follows the terminating zero
    // byte for an uncompressed name, but the two pointer bytes when the name
    // jumped: the labels those bytes point at are somewhere else entirely, so
    // reading on from there would land inside another section.
    let mut after_name: Option<usize> = None;

    while pos < payload.len() {
        let len = payload[pos] as usize;

        if len == 0 {
            pos += 1; // Skip the null terminator.
            break;
        }

        // A compression pointer (RFC 1035 4.1.4): the two top bits are set and
        // the rest, with the byte after, is an offset into the message — an
        // earlier label list that this name continues with. Reading it as a
        // length gives a nonsense label, and from there a nonsense domain: what
        // decides whether the name is proxied was silently wrong. Rare in a
        // query, legal, and some stacks do it.
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= payload.len() {
                return None;
            }
            let offset = ((len & 0x3F) << 8) | payload[pos + 1] as usize;
            if offset >= payload.len() {
                return None;
            }
            // A pointer that points at another pointer forever is a loop; stop
            // after a few hops rather than spin.
            jumps += 1;
            if jumps > MAX_DNS_POINTER_JUMPS {
                return None;
            }
            if after_name.is_none() {
                after_name = Some(pos + 2);
            }
            pos = offset;
            continue;
        }

        // The remaining two label types (0x40, 0x80) are reserved or unused;
        // a name using one cannot be read as text.
        if len & 0xC0 != 0 {
            return None;
        }

        // Prevent out-of-bounds access.
        if pos + 1 + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
        labels.push(label);
        pos += 1 + len;
    }

    let qtype_pos = after_name.unwrap_or(pos);
    let qtype = if qtype_pos + 2 <= payload.len() {
        u16::from_be_bytes([payload[qtype_pos], payload[qtype_pos + 1]])
    } else {
        0
    };

    Some((labels.join("."), qtype))
}

/// Build a DNS response resolving the domain to the given IPv4 address.
///
/// - qtype=1 (A): return an A record with 4 bytes of RDATA.
/// - qtype=28 (AAAA) or other: return an empty answer (ANCOUNT=0) so the client falls back to an A query.
fn build_dns_response(query: &[u8], ip: Ipv4Addr, qtype: u16) -> Vec<u8> {
    // Non-A query: return an empty answer (the virtual IP is IPv4, so it can't answer AAAA/MX, etc.).
    if qtype != 1 {
        return build_empty_dns_response(query);
    }

    let mut response = Vec::with_capacity(query.len() + 16);
    response.extend_from_slice(query);

    // Set flags: QR=1, Opcode=0, AA=0, TC=0, RD=1(copied), RA=1
    response[2] = 0x81;
    response[3] = 0x80;
    // ANCOUNT = 1
    response[6] = 0x00;
    response[7] = 0x01;

    // Answer section:
    // Name: compression pointer 0xC00C → points to offset 12 (the Question section's domain name)
    response.push(0xC0);
    response.push(0x0C);
    // TYPE: A = 1
    response.push(0x00);
    response.push(0x01);
    // CLASS: IN = 1
    response.push(0x00);
    response.push(0x01);
    // TTL: 60 seconds (0x0000003C)
    response.push(0x00);
    response.push(0x00);
    response.push(0x00);
    response.push(0x3C);
    // RDLENGTH: 4 (IPv4)
    response.push(0x00);
    response.push(0x04);
    // RDATA: the 4 bytes of the IP address.
    response.extend_from_slice(&ip.octets());

    response
}

/// Build an empty DNS answer: QR=1, RA=1, RCODE=0 (NoError), ANCOUNT=0.
/// Used for "query type not supported" or "no address of the matching type".
fn build_empty_dns_response(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    // ANCOUNT = 0
    response[6] = 0x00;
    response[7] = 0x00;
    response
}

/// Forward a DNS query to the real DNS server and return the response as-is.
///
/// Iterates over all configured DNS servers, **preferring IPv4**, binding the socket by address family
/// (IPv4→0.0.0.0:0, IPv6→[::]:0). Each server has its own 800ms timeout, with an overall 3s cap.
///
/// A name that was resolved recently is answered from a cache instead, for as
/// long as the answer's own records say it is good — see [`remember_answer`].
/// The transaction ID of the query asking now is written into the answer before
/// it goes out.
///
/// Fix: the system DNS list often starts with IPv6 servers (e.g. 2408:8888::8), which made binding
/// 0.0.0.0:0 then connect() fail, and the old code only tried dns_servers[0] with no fallback.
pub async fn forward_dns_query(query: &[u8], dns_servers: &[SocketAddr]) -> Option<Vec<u8>> {
    if dns_servers.is_empty() {
        jni_log!("[tun-proxy] No DNS servers configured, dropping query");
        return None;
    }

    // Every name the device looks up comes through here, and a lookup the
    // resolver has already answered does not need another round trip to a
    // server — which on a phone is a radio wake-up, not a LAN packet.
    let key = parse_dns_query(query).map(|(domain, qtype)| (domain.to_lowercase(), qtype));
    if let Some(key) = &key
        && let Some(answer) = cached_answer(key, query)
    {
        return Some(answer);
    }

    let answer = forward_dns_query_uncached(query, dns_servers).await;

    if let (Some(key), Some(answer)) = (key, &answer) {
        remember_answer(key.clone(), answer);
    }

    answer
}

async fn forward_dns_query_uncached(query: &[u8], dns_servers: &[SocketAddr]) -> Option<Vec<u8>> {
    // Prefer IPv4: try IPv4 DNS first (faster and more reliable), then IPv6.
    let mut ordered: Vec<&SocketAddr> = dns_servers.iter().collect();
    ordered.sort_by_key(|s| !s.is_ipv4() as u8); // false(=IPv4) goes first

    let per_server_timeout = Duration::from_millis(800);

    let result = tokio::time::timeout(DNS_FORWARD_TIMEOUT, async {
        for dns_server in ordered.iter() {
            // Bind by address family: IPv4 DNS → 0.0.0.0:0, IPv6 DNS → [::]:0.
            let bind_addr = if dns_server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };

            // Per-server timeout so we don't get stuck on an unreachable IPv6 DNS server.
            let server_result = tokio::time::timeout(per_server_timeout, async {
                let sock = tokio::net::UdpSocket::bind(bind_addr).await.ok()?;
                sock.connect(**dns_server).await.ok()?;
                sock.send(query).await.ok()?;
                let mut buf = vec![0u8; 4096];
                let n = sock.recv(&mut buf).await.ok()?;
                Some(buf[..n].to_vec())
            })
            .await;

            match server_result {
                Ok(Some(resp)) => return Some(resp),
                _ => continue,
            }
        }
        None
    })
    .await;

    match result {
        Ok(Some(resp)) => Some(resp),
        Ok(None) => {
            jni_log!(
                "[tun-proxy] DNS forward failed (all {} servers failed)",
                dns_servers.len()
            );
            None
        }
        Err(_) => {
            jni_log!(
                "[tun-proxy] DNS forward timed out after {}s",
                DNS_FORWARD_TIMEOUT.as_secs()
            );
            None
        }
    }
}

// ============================================================
// DNS answer cache
// ============================================================

/// How long an answer may be kept when the records disagree, or carry a TTL
/// nobody would wait for. Bounded on both sides: a `0` TTL is a record the
/// server wanted re-asked, and one that never expires would pin an address to
/// a name for as long as the process lives.
const DNS_CACHE_MIN_TTL: Duration = Duration::from_secs(1);
const DNS_CACHE_MAX_TTL: Duration = Duration::from_secs(300);

/// Answers kept before the oldest are dropped to make room. A phone resolves a
/// few dozen names; this is a few hundred, so a busy app cannot grow it.
const DNS_CACHE_MAX_ENTRIES: usize = 512;

/// A name and the record type asked for, which together are what an answer is
/// for. Lower-cased, because DNS names are case-insensitive.
type CacheKey = (String, u16);

struct CachedAnswer {
    response: Vec<u8>,
    expires_at: tokio::time::Instant,
}

static DNS_CACHE: std::sync::LazyLock<Mutex<HashMap<CacheKey, CachedAnswer>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock_cache() -> MutexGuard<'static, HashMap<CacheKey, CachedAnswer>> {
    DNS_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The answer already held for `key`, with the transaction ID of the query
/// asking now.
///
/// `None` when there is none, or when the one there has expired.
fn cached_answer(key: &CacheKey, query: &[u8]) -> Option<Vec<u8>> {
    let cache = lock_cache();
    let entry = cache.get(key)?;
    if entry.expires_at <= tokio::time::Instant::now() {
        return None;
    }

    // The answer was fetched with a different ID, and a resolver drops a reply
    // whose ID does not match the question it sent — so without this a cached
    // answer looks to the application exactly like no answer at all.
    let mut response = entry.response.clone();
    if response.len() >= 2 && query.len() >= 2 {
        response[0] = query[0];
        response[1] = query[1];
    }
    Some(response)
}

/// Stores `response` for `key`, for as long as its own records say it is good.
fn remember_answer(key: CacheKey, response: &[u8]) {
    let Some(ttl) = answer_ttl(response) else {
        // Nothing to keep: an answer with no records, or one the server
        // refused, is either a negative answer (which a resolver may want to
        // re-ask at any moment) or unreadable.
        return;
    };

    let mut cache = lock_cache();
    let now = tokio::time::Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);

    // No room and nothing expired: the whole table is dropped rather than
    // picking a victim one record at a time, which for a cache this size is
    // not worth the bookkeeping.
    if cache.len() >= DNS_CACHE_MAX_ENTRIES {
        cache.clear();
    }

    cache.insert(
        key,
        CachedAnswer {
            response: response.to_vec(),
            expires_at: now + ttl,
        },
    );
}

/// How long the records in `response` may be served from the cache: the
/// shortest TTL among the answers, since one expired record makes the answer
/// wrong. `None` when the response has no answers to read a TTL from, or is
/// an error.
fn answer_ttl(response: &[u8]) -> Option<Duration> {
    if response.len() < 12 {
        return None;
    }

    // RCODE is the low four bits of the flags: anything but 0 is a refusal or
    // a failure, which is not something to keep answering with.
    if response[3] & 0x0F != 0 {
        return None;
    }

    let answers = u16::from_be_bytes([response[6], response[7]]) as usize;
    if answers == 0 {
        return None;
    }

    // Skip the header and the question — one name plus QTYPE and QCLASS.
    let mut pos = skip_dns_name(response, 12)? + 4;

    let mut shortest: Option<u32> = None;
    for _ in 0..answers {
        pos = skip_dns_name(response, pos)?;
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
        if pos + 10 > response.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10 + rdlength;

        shortest = Some(match shortest {
            Some(seen) => seen.min(ttl),
            None => ttl,
        });
    }

    shortest.map(|ttl| {
        let bounded = (ttl as u64).clamp(DNS_CACHE_MIN_TTL.as_secs(), DNS_CACHE_MAX_TTL.as_secs());
        Duration::from_secs(bounded)
    })
}

/// The offset just past the name starting at `pos`, following a compression
/// pointer if the name ends in one.
fn skip_dns_name(payload: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *payload.get(pos)? as usize;
        match len {
            0 => return Some(pos + 1),
            // A pointer ends the name, and is two bytes long.
            0xC0.. => return Some(pos + 2),
            _ => pos += 1 + len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{answer_ttl, cached_answer, parse_dns_query, remember_answer};
    use std::time::Duration;

    /// A query packet: 12 bytes of header, then the question.
    fn query(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(name);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        packet
    }

    /// A query whose QNAME is partly compressed: `www` in the question, then a
    /// pointer to the `example.com` written further along. The pointer ends the
    /// name where it stands, so QTYPE follows its two bytes — not the labels it
    /// points at.
    fn query_with_partly_compressed_name(qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&[0x03, b'w', b'w', b'w']); // offset 12..16
        packet.extend_from_slice(&[0xC0, 24]); // pointer at 16..18 -> offset 24
        packet.extend_from_slice(&qtype.to_be_bytes()); // 18..20
        packet.extend_from_slice(&1u16.to_be_bytes()); // 20..22
        packet.extend_from_slice(&[0, 0]); // 22..24, filler
        packet.extend_from_slice(&[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        packet.extend_from_slice(&[0x03, b'c', b'o', b'm', 0x00]);
        packet
    }

    #[test]
    fn reads_an_uncompressed_name() {
        let name = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let (domain, qtype) = parse_dns_query(&query(&name, 1)).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 1);
    }

    /// The bug: read as a length, the pointer's 0xC0 became a 192-byte label
    /// (out of bounds, so `None`) or, with a smaller value, a garbage one — and
    /// the routing decision that follows the name was silently wrong.
    #[test]
    fn follows_a_compression_pointer_to_the_rest_of_the_name() {
        let (domain, qtype) = parse_dns_query(&query_with_partly_compressed_name(1)).unwrap();
        assert_eq!(domain, "www.example.com");
        assert_eq!(qtype, 1);
    }

    /// QTYPE follows the pointer, not the labels it points at: reading on from
    /// the pointed-to name's terminator would land in the tail of the packet.
    #[test]
    fn reads_the_qtype_where_the_pointer_ended() {
        let (_, qtype) = parse_dns_query(&query_with_partly_compressed_name(28)).unwrap();
        assert_eq!(qtype, 28);
    }

    #[test]
    fn refuses_a_pointer_that_loops() {
        // 0xC00C points at offset 12, which is this very pointer.
        let name = [0xC0, 0x0C];
        assert!(parse_dns_query(&query(&name, 1)).is_none());
    }

    #[test]
    fn refuses_a_pointer_outside_the_packet() {
        let name = [0x03, b'a', b'b', b'c', 0xC0, 0xF0];
        assert!(parse_dns_query(&query(&name, 1)).is_none());
    }

    /// An answer with two A records: the same header and question, then two
    /// records whose TTLs differ, so the cache has to keep the shorter one.
    fn answer(ttls: &[u32]) -> Vec<u8> {
        let name = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let mut packet = vec![0xAA, 0xBB, 0x81, 0x80, 0x00, 0x01];
        packet.extend_from_slice(&(ttls.len() as u16).to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT + ARCOUNT
        packet.extend_from_slice(&name);
        packet.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

        for ttl in ttls {
            packet.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to the question
            packet.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
            packet.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
            packet.extend_from_slice(&ttl.to_be_bytes());
            packet.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
            packet.extend_from_slice(&[10, 0, 0, 1]); // RDATA
        }
        packet
    }

    #[test]
    fn the_cache_keeps_the_shortest_ttl_in_the_answer() {
        assert_eq!(
            answer_ttl(&answer(&[300, 60])),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            answer_ttl(&answer(&[60, 300])),
            Some(Duration::from_secs(60))
        );
    }

    /// A TTL nobody would wait for, and one that never expires: both are
    /// bounded, or the cache would re-ask constantly / pin a name forever.
    #[test]
    fn ttls_outside_the_bounds_are_clamped() {
        assert_eq!(answer_ttl(&answer(&[0])), Some(Duration::from_secs(1)));
        assert_eq!(
            answer_ttl(&answer(&[u32::MAX])),
            Some(Duration::from_secs(300))
        );
    }

    /// Nothing to keep: an answer with no records, or one the server refused.
    #[test]
    fn an_answer_with_no_records_is_not_cached() {
        assert_eq!(answer_ttl(&answer(&[])), None);

        let mut refused = answer(&[60]);
        refused[3] = 0x83; // RCODE = NXDOMAIN
        assert_eq!(answer_ttl(&refused), None);
    }

    /// The answer is fetched once and served to many queries, each with its own
    /// transaction ID — a resolver drops a reply whose ID does not match the
    /// question it sent.
    #[test]
    fn a_cached_answer_is_served_with_the_asking_query_id() {
        let name = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let fetched = query(&name, 1); // ID 0x1234
        let asking = {
            let mut other = fetched.clone();
            other[0] = 0xAB;
            other[1] = 0xCD;
            other
        };

        remember_answer(("example.com".to_string(), 1), &answer(&[60]));

        let served = cached_answer(&("example.com".to_string(), 1), &asking)
            .expect("the answer was remembered with a 60s TTL");
        assert_eq!(&served[..2], &[0xAB, 0xCD]);

        // A different record type is a different question, even for one name.
        assert!(cached_answer(&("example.com".to_string(), 28), &asking).is_none());
    }
}

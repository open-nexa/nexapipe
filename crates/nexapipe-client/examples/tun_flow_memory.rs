//! What one TCP flow costs in the TUN stack.
//!
//! The stack creates a socket per flow, and the socket owns four buffers whose
//! size is the TCP window — two for the protocol and two for the application
//! side of the tunnel. This opens a number of flows through a real stack (one
//! SYN each, which is all it takes for the stack to create the socket) and
//! reports what they cost: the bytes the heap was asked for, and the peak
//! resident set.
//!
//! ```text
//! cargo run --release -p nexapipe-client --example tun_flow_memory --features tun-proxy
//! cargo run --release -p nexapipe-client --example tun_flow_memory --features tun-proxy -- 32 131072
//! ```
//!
//! The first argument is how many flows to open, the second the window in
//! bytes. Both default to the client's own numbers.
//!
//! **The heap number is the one to compare.** The resident set is a high-water
//! mark of the whole process, and the pages behind a buffer of zeroes are not
//! resident until something writes to them: an idle flow costs its buffers in
//! address space, not in pages. A flow that carries traffic pays for the pages
//! it touches.

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The address the packets come from. Anything plausible will do: the stack
/// answers for every address.
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 16);

/// The address the packets go to.
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);

/// The port the packets go to.
const SERVER_PORT: u16 = 443;

/// The MTU the TUN uses.
const TUN_MTU: usize = 1400;

/// How many flows to open when the caller does not say.
const DEFAULT_FLOWS: usize = 32;

/// The window the client uses when the caller does not say.
const DEFAULT_WINDOW: u32 = nexapipe_client::tun_proxy::DEFAULT_TCP_WINDOW;

// ============================================================
// The counting allocator
// ============================================================

/// A global allocator that keeps track of what the heap was asked for.
struct Counting;

/// The bytes the heap is holding right now.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// The most the heap was ever holding.
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Adds `size` to the live total and keeps the peak.
fn count(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            count(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // The system's own zeroed allocation, rather than a fresh block the
        // allocator then memsets: the pages the system hands out are zero
        // already, and it does not touch them. A memset would make every
        // buffer resident the moment it is allocated, and the resident set
        // would then say more about the allocator than about the traffic.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            count(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            count(new_size);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

// ============================================================
// The measurement
// ============================================================

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let flows: usize = args
        .next()
        .map(|a| a.parse().expect("the flow count is a number"))
        .unwrap_or(DEFAULT_FLOWS);
    let window: u32 = args
        .next()
        .map(|a| a.parse().expect("the window is a number"))
        .unwrap_or(DEFAULT_WINDOW);

    let (stack, runner, _udp, listener) = StackBuilder::default()
        .enable_tcp(true)
        .mtu(TUN_MTU)
        .tcp_recv_buffer_size(window)
        .tcp_send_buffer_size(window)
        .build()
        .expect("the stack builds");
    let runner = runner.expect("a stack with TCP has a runner");
    let mut listener = listener.expect("a stack with TCP has a listener");
    tokio::spawn(async move {
        let _ = runner.await;
    });
    let (mut sink, _stream) = stack.split();

    // The stack is up and idle. This is the baseline: what the stack costs
    // before it has a single flow in it.
    let baseline = LIVE.load(Ordering::Relaxed);
    let rss_before = peak_rss();

    // One SYN per flow. The stack creates the socket — and its buffers — as
    // soon as the SYN arrives; the handshake does not have to finish for the
    // memory to be spent.
    for flow in 0..flows {
        let port = 10_000 + u16::try_from(flow).expect("fewer than 60 000 flows");
        sink.send(syn_packet(port, SERVER_PORT))
            .await
            .expect("the stack takes the packet");
    }

    // The accepted streams are what keep the sockets alive: a socket that is
    // dropped takes its buffers with it, and the measurement would be of
    // nothing.
    let mut sockets = Vec::new();
    for _ in 0..flows {
        let (stream, _client, _server) = listener
            .next()
            .await
            .expect("the stack accepts the connection it was sent");
        sockets.push(stream);
    }

    let live = LIVE.load(Ordering::Relaxed);
    let peak = PEAK.load(Ordering::Relaxed);
    let rss_after = peak_rss();

    let per_flow = (live.saturating_sub(baseline)) as f64 / flows as f64;
    println!("flows:              {flows}");
    println!("window:             {window} bytes");
    println!("heap, stack alone:  {}", kib(baseline));
    println!("heap, with flows:   {}", kib(live));
    println!("per flow:           {}", kib(per_flow as usize));
    println!("heap, peak:         {}", kib(peak));
    println!("rss, before:        {}", kib(rss_before as usize));
    println!("rss, after:         {}", kib(rss_after as usize));
    println!(
        "rss, growth:        {}",
        kib(rss_after.saturating_sub(rss_before) as usize)
    );

    // The sockets are dropped here, and with them the buffers.
    drop(sockets);
}

/// A size in kibibytes, for a report a person reads.
fn kib(bytes: usize) -> String {
    format!("{:.1} KiB", bytes as f64 / 1024.0)
}

/// The peak resident set of this process, in bytes.
///
/// `getrusage` reports a high-water mark, and its unit is bytes on macOS and
/// kilobytes on Linux.
#[cfg(unix)]
fn peak_rss() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    #[cfg(target_os = "macos")]
    {
        usage.ru_maxrss as u64
    }
    #[cfg(not(target_os = "macos"))]
    {
        usage.ru_maxrss as u64 * 1024
    }
}

/// The peak resident set, where the platform does not say.
#[cfg(not(unix))]
fn peak_rss() -> u64 {
    0
}

/// A TCP SYN, as the IP packet the TUN device would carry it in.
///
/// The checksums are the real ones: a packet that is wrong in any way is a
/// packet the measurement should not depend on.
fn syn_packet(src_port: u16, dst_port: u16) -> Vec<u8> {
    let src = CLIENT_IP.octets();
    let dst = SERVER_IP.octets();

    // The TCP header: ports, sequence number, acknowledgement number, the
    // data offset and the SYN flag, the window, the checksum and the urgent
    // pointer.
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // sequence number
    tcp.extend_from_slice(&0u32.to_be_bytes()); // acknowledgement number
    tcp.push(0x50); // data offset: five words, no options
    tcp.push(0x02); // SYN
    tcp.extend_from_slice(&65_535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer

    // The checksum covers a pseudo-header: the two addresses, the protocol,
    // and the length of the segment.
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0); // reserved
    pseudo.push(6); // TCP
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    let checksum = ones_complement_sum(&pseudo);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

    // The IPv4 header around it.
    let total_len = 20 + tcp.len();
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x45); // version 4, header length 5 (20 bytes)
    packet.push(0x00); // DSCP / ECN
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&0x1234u16.to_be_bytes()); // identification
    packet.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    packet.push(64); // TTL
    packet.push(6); // TCP
    packet.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    let checksum = ones_complement_sum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet.extend_from_slice(&tcp);
    packet
}

/// The one's complement of the one's complement sum of the header's words.
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for word in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

//! What one connection costs in memory.
//!
//! The client keeps a pool of connections to each server, and a flow borrows
//! one of them, so the number of connections a client holds is a number a
//! deployment pays for — and on a phone, where the client holds one connection
//! per server for as long as the app is open, it is a number that is paid
//! **all the time** rather than once.
//!
//! This is what choosing the protocol with ALPN would change: the protocol
//! would be chosen at the handshake, so a client that speaks both HTTP and L4
//! would hold **two** connections to the same server where it holds one today.
//! The time that costs is measured by the `connection_cost` benchmark — a
//! handshake is about one round trip more than a flow — and this is the other
//! half of the same question.
//!
//! ```text
//! cargo run --release -p nexapipe-client --example connection_memory
//! ```
//!
//! ## What the number is
//!
//! **The heap the process holds while the connections are open**, and the
//! difference between holding none and holding them. The heap is counted by a
//! global allocator, so it is the bytes the process was asked for and is still
//! holding — not the resident set, which is a high-water mark of everything and
//! says more about the machine than about the connection.
//!
//! **Both ends are counted.** The far side runs in this process too, so the
//! number is what one connection costs the client *and* the server together.
//! A client's share is therefore **at most half** of it, and the server's
//! share is a real cost of its own: the server holds state per connection
//! (a path watcher task, a stream limiter, the counters) whatever the client
//! does.
//!
//! ## The number to read is the total, not the steps
//!
//! The per-connection readings are printed too, and they are **bursty**: a
//! connection's buffers are not all allocated when the connection opens, so
//! two of the readings can be zero and the next one can be three hundred
//! kilobytes. The total is the number that is stable — measured twice on the
//! same machine it came out within a kilobyte of itself — and the per-connection
//! figure is the total divided by the number of connections.
//!
//! What this does not measure is the address space the buffers reserve rather
//! than hold: the pages behind a buffer of zeroes are not resident until
//! something writes to them, so an idle connection costs its buffers in
//! address space and in pages only once it carries traffic.

use iroh::Endpoint;
use iroh::endpoint::presets;
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The ALPN the client uses. The same bytes.
const ALPN: &[u8] = b"\x05nexapipe";

/// How long the measurement waits before it reads the heap.
///
/// The handshake allocates and frees a good deal — keys, packet buffers, the
/// certificate — and the far side allocates its half when it accepts. A
/// reading taken before that has settled is a reading of the handshake, not of
/// the connection.
const SETTLE: std::time::Duration = std::time::Duration::from_millis(400);

/// How many connections to open.
///
/// Enough for the **marginal** cost of a connection to show: the first one
/// carries the one-time costs, and a client that holds two connections pays
/// the steady-state cost twice.
const CONNECTIONS: usize = 16;

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
        // would then say more about the allocator than about the connection.
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

/// The bytes the heap is holding right now.
fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Waits for the heap to settle.
async fn settle() {
    tokio::time::sleep(SETTLE).await;
}

/// Prints a number in KiB, with the bytes beside it.
fn kib(bytes: usize) -> String {
    format!("{} bytes ({:.1} KiB)", bytes, bytes as f64 / 1024.0)
}

#[tokio::main]
async fn main() {
    // The far side: it accepts connections and holds them for as long as the
    // process lives, which is what a server does with one.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    // How many connections the far side has been given. The reading is taken
    // only once this has caught up: the far side allocates its half of a
    // connection when it accepts, and a reading taken before that is a
    // reading of one end of the connection.
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let Ok(accepting) = incoming.accept() else {
                    return;
                };
                let Ok(_connection) = accepting.await else {
                    return;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                // Held for as long as the process lives: a connection that
                // closed here would not be a connection.
                std::future::pending::<()>().await;
            });
        }
    });

    // This side.
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");

    // The baseline: both endpoints are up and no connection is open.
    settle().await;
    let baseline = live();

    // One connection after another, with the heap read between them.
    //
    // **The first one is not the number.** It carries the one-time costs —
    // the crypto state, the certificate, the session keys — and the
    // connections after it are the ones that say what a connection costs
    // *permanently*. So the heap is read after every one, and the marginal
    // cost of each is what is reported.
    let mut readings: Vec<usize> = Vec::with_capacity(CONNECTIONS + 1);
    readings.push(baseline);

    let mut held = Vec::with_capacity(CONNECTIONS);
    for _ in 0..CONNECTIONS {
        let connection = client
            .connect(server_addr.clone(), ALPN)
            .await
            .expect("the connection opens");
        held.push(connection);
        settle().await;
        readings.push(live());
    }

    // The far side has accepted them all by now — or the readings below are
    // of half a connection each.
    for _ in 0..40 {
        if accepted.load(Ordering::Relaxed) >= CONNECTIONS {
            break;
        }
        settle().await;
    }
    assert!(
        accepted.load(Ordering::Relaxed) >= CONNECTIONS,
        "the far side accepted {} of {CONNECTIONS} connections: the measurement would be of \
         one end of them",
        accepted.load(Ordering::Relaxed)
    );
    settle().await;
    let settled_total = live();

    let margins: Vec<usize> = readings
        .windows(2)
        .map(|pair| pair[1].saturating_sub(pair[0]))
        .collect();

    println!("heap, endpoints up, no connection:  {}", kib(baseline));
    println!(
        "heap, {CONNECTIONS} connections:              {}",
        kib(settled_total)
    );
    println!(
        "heap, peak:                             {}",
        kib(PEAK.load(Ordering::Relaxed))
    );
    println!();
    println!("both ends, per connection:");
    for (index, margin) in margins.iter().enumerate() {
        println!("  connection {:>2}: {}", index + 1, kib(*margin));
    }
    println!();
    println!(
        "the first connection:   {}   (it carries the one-time costs)",
        kib(margins[0])
    );
    println!(
        "the last connection:    {}   (the steady state)",
        kib(*margins.last().unwrap())
    );
    println!(
        "the mean of them:       {}",
        kib(margins.iter().sum::<usize>() / margins.len())
    );
    println!();
    println!(
        "all {CONNECTIONS}, both ends:    {}   ({:.1} KiB each)",
        kib(settled_total.saturating_sub(baseline)),
        settled_total.saturating_sub(baseline) as f64 / CONNECTIONS as f64 / 1024.0
    );

    // The connections are held until here on purpose: dropping them would give
    // the bytes back, and the numbers above are about what is held.
    drop(held);
}

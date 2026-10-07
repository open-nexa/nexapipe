//! What each node has carried, and what it is carrying right now.
//!
//! # What the numbers are
//!
//! Every counter here counts **tunnel payload**: the bytes delivered to and by
//! an application, as they cross the tunnel. Nothing else counts, and three
//! things are deliberately outside that:
//!
//! - **Protocol headers are not counted.** A byte accounted here is a byte the
//!   application saw, so the same volume is comparable across HTTP, a CONNECT
//!   tunnel and a flow through the TUN interface. Counting at the network layer
//!   instead would charge every application for headers it never chose, and the
//!   two would add up to different totals for the same transfer.
//! - **Bytes that never made it are not counted.** A packet the stack discarded
//!   never became payload, and counting it would report traffic the other end
//!   did not receive.
//! - **Nothing is counted twice.** One application byte crosses this code once,
//!   whichever door it came in by. Which means the layer doing the counting is
//!   a decision, not an accident: the TUN interface pump carries IP packets that
//!   later reappear as flows inside it, so only the flows count, and whatever
//!   the tunnel hands back is counted where it is handed back.
//!
//! Direction is from this machine's point of view: `sent` is what we put into
//! the tunnel, `received` is what came back. "Upload" and "download" if you
//! prefer, and it is the only sense in which those words mean anything to a
//! peer-to-peer client.
//!
//! # Why this lives beside nothing else
//!
//! The client has no `stream_util` to sit in — that module is the server's, and
//! the client's copies are six hand-written loops in two modules that share no
//! code. A funnel does not exist to be instrumented, so what travels instead is
//! *where to record*: a connection carries the counters it belongs to, exactly
//! as it already carries the health table it belongs to, and a copy loop that
//! is handed one can say how much it moved without knowing whose it is.
//!
//! Accumulators are cumulative and never reset while the [`EndpointGroup`] that
//! owns them lives. That is a deliberate omission of convenience: a rate is two
//! readings and a division, and every consumer here already polls — the desktop
//! every few seconds, a notification every second — so keeping a per-second
//! number here would be a second clock with nothing to say that two samples do
//! not. Cumulative also survives the consumer going away: nothing is lost while
//! the UI is in the background.
//!
//! [`EndpointGroup`]: crate::endpoint_group::EndpointGroup
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use iroh::EndpointId;

/// The accumulators of one node.
///
/// Shared rather than owned: a node's counters outlive any single flow through
/// it, and the copy loops that move bytes for it run as their own tasks.
#[derive(Debug, Default)]
pub struct NodeTraffic {
    /// Bytes this machine has put into the tunnel towards this node.
    sent: AtomicU64,
    /// Bytes that have come back from it.
    received: AtomicU64,
    /// Flows open through it right now, not since ever.
    active: AtomicU64,
}

impl NodeTraffic {
    /// Nothing yet.
    ///
    /// Public for the table's own `entry` API rather than for callers to build:
    /// a node's counters belong in exactly one table, and intermediates get
    /// them from [`NodeTraffic::record_sent`]'s callers, not from a constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts `bytes` leaving this machine towards the node.
    pub fn record_sent(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Counts `bytes` arriving from the node.
    pub fn record_received(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Everything counted for the node so far, copied out.
    ///
    /// A copy rather than a view so that a reader — which may be a UI building
    /// its own picture — cannot hold the numbers still while they move: the
    /// three are read separately, and their sum is only consistent because
    /// nothing waits between the reads.
    pub fn volume(&self) -> NodeVolume {
        NodeVolume {
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
        }
    }

    fn enter(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    fn leave(&self) {
        // Saturating rather than wrapping: a `leave` without an `enter` should
        // read as zero flows, not as four billion of them. Nothing calls it
        // that way — the guard below cannot outlive its own increment — but a
        // counter that can underflow into nonsense is a counter worth distrusting.
        let _ = self
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                Some(active.saturating_sub(1))
            });
    }
}

/// One node's counters taken together, copied out of the accumulators.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeVolume {
    /// Bytes this machine has sent towards the node. Cumulative for as long as
    /// the owning group lives.
    pub sent: u64,
    /// Bytes received from it, cumulative on the same clock.
    pub received: u64,
    /// Flows open right now. The only reading here that ever goes down.
    pub active: u64,
}

/// Holds one node's counters open for as long as it lives.
///
/// A flow is counted by its lifetime and not by two calls somewhere in a copy
/// loop, because the ways outnumber the ways in: a copy loop returns on EOF,
/// on a read error, on a write error, on a flush error, and on being cancelled
/// when the proxy stops. Every one of those would have to remember to count
/// itself out, and one that forgot would leave a node looking busy forever.
/// `Drop` cannot forget.
#[derive(Debug)]
pub struct Flow {
    traffic: Arc<NodeTraffic>,
}

impl Flow {
    /// Counts one flow as open on `traffic`, until this value is dropped.
    pub fn open(traffic: Arc<NodeTraffic>) -> Self {
        traffic.enter();
        Self { traffic }
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.traffic.leave();
    }
}

/// The traffic of every node one [`EndpointGroup`] knows about.
///
/// Keyed by node rather than by domain or by connection because that is what a
/// reader wants to ask about: the desktop lists nodes, and a connection is an
/// implementation detail that comes and goes. Shared behind a `std::sync` lock
/// on the same terms as the group's health table — the critical section is a
/// couple of map operations and never waits on I/O, so there is nothing to
/// yield on and no reason the reading should need a runtime.
///
/// [`EndpointGroup`]: crate::endpoint_group::EndpointGroup
pub type TrafficTable = Arc<Mutex<HashMap<EndpointId, Arc<NodeTraffic>>>>;

/// One node's accumulators, inserting the entry if this is its first byte.
///
/// Called when a connection is handed out, not when it is used: a node that has
/// carried nothing yet still has counters to be asked about, and a reader that
/// finds no entry has no way to tell "unknown node" from "quiet one".
pub fn of(traffic: &TrafficTable, node: EndpointId) -> Arc<NodeTraffic> {
    let mut table = traffic
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    table.entry(node).or_default().clone()
}

/// One reading of every node in the table.
pub fn snapshot(traffic: &TrafficTable) -> HashMap<EndpointId, NodeVolume> {
    let table = traffic
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    table
        .iter()
        .map(|(node, traffic)| (*node, traffic.volume()))
        .collect()
}

/// An empty table, for a group that has nothing to count into.
pub fn table() -> TrafficTable {
    Arc::new(Mutex::new(HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node that has carried nothing reads as zero on all three, so "never
    /// used" and "used and now quiet" stay distinguishable.
    #[test]
    fn nothing_counted_reads_as_zero() {
        let traffic = NodeTraffic::new();
        assert_eq!(
            traffic.volume(),
            NodeVolume {
                sent: 0,
                received: 0,
                active: 0
            }
        );
    }

    /// The two directions are nobody's sum of each other: acknowledging one
    /// direction must not move the other, or a download would also be an upload.
    #[test]
    fn directions_are_counted_separately() {
        let traffic = NodeTraffic::new();
        traffic.record_sent(1200);
        traffic.record_received(34);

        assert_eq!(traffic.volume().sent, 1200);
        assert_eq!(traffic.volume().received, 34);
    }

    /// Counting is cumulative, because these are accumulators and the rate is
    /// somebody else's division.
    #[test]
    fn counting_accumulates_across_calls() {
        let traffic = NodeTraffic::new();
        for _ in 0..4 {
            traffic.record_sent(512);
        }
        assert_eq!(traffic.volume().sent, 2048);
    }

    /// Zero is not worth a lock-free add, and skipping it must not be visible
    /// as "forgot to count".
    #[test]
    fn zero_leaves_the_total_alone() {
        let traffic = NodeTraffic::new();
        traffic.record_sent(0);
        traffic.record_received(0);
        assert_eq!(traffic.volume().sent, 0);
        assert_eq!(traffic.volume().received, 0);
    }

    /// A flow is open for exactly as long as its guard lives — this is the one
    /// number here that has to come back down, and every way out of a copy loop
    /// goes through the same `Drop`.
    #[test]
    fn a_flow_open_and_closed_returns_to_zero() {
        let traffic = Arc::new(NodeTraffic::new());
        {
            let _flow = Flow::open(traffic.clone());
            let _second = Flow::open(traffic.clone());
            assert_eq!(traffic.volume().active, 2);
        }
        assert_eq!(traffic.volume().active, 0);
    }

    /// Asking twice gets the same accumulators, not a second set that could
    /// disagree — two flows on one node have to land in one total.
    #[test]
    fn one_node_has_one_set_of_counters() {
        let table = table();
        let node = iroh::SecretKey::from_bytes(&[7u8; 32]).public();

        let first = of(&table, node);
        let second = of(&table, node);

        first.record_sent(10);
        assert_eq!(second.volume().sent, 10);
        assert_eq!(snapshot(&table).len(), 1);
    }

    /// Every node in the table answers, and each one's reading is its own.
    #[test]
    fn snapshot_carries_every_node() {
        let table = table();
        let one = iroh::SecretKey::from_bytes(&[1u8; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[2u8; 32]).public();

        of(&table, one).record_received(99);
        of(&table, other).record_sent(1);

        let reading = snapshot(&table);
        assert_eq!(reading[&one].received, 99);
        assert_eq!(reading[&other].sent, 1);
    }
}

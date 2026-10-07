//! What each open flow is, and where to find the ones still open.
//!
//! # What this is for
//!
//! [`crate::traffic`] answers "how much has each node carried", and it answers it
//! with three numbers per node. What it cannot answer is what a reader asks
//! next: *which* connections are those, and what is each of them doing. A node
//! carrying 40 MiB across 12 flows says nothing about whether one of them is a
//! download that has been stuck for an hour, and "how much" has no way to become
//! "stop that one".
//!
//! So a flow gets an identity. The [`Flow`] guard in `traffic.rs` was already
//! the one place every path through the tunnel passes through — a forwarded
//! HTTP request, a CONNECT tunnel, a WebSocket, a TLS passthrough, and both TUN
//! protocols all enter through `enter_flow` and all leave through its `Drop` —
//! which makes it the only place where "this flow is open" is a fact rather than
//! something six call sites each have to remember to say. Registration rides on
//! that: a copy loop that forgot to deregister is not a bug this design can
//! have, for the same reason one that forgot to count itself out was not.
//!
//! # What is recorded, and what is not
//!
//! Recorded once, when the flow opens: which node it reaches, which door it came
//! in by, and what the client said it was talking to. Naming a target is the
//! client's business — a CONNECT line, a `Host` header, a TLS SNI, or the
//! virtual IP a TUN packet was addressed to — and every one of those is read
//! *before* the tunnel is opened, which is why a flow that never gets one
//! reports `None` rather than a guess.
//!
//! Not recorded: a rate. The per-flow counters here are cumulative, like the
//! node ones, and for the same reason (see `traffic.rs`): a rate is two readings
//! and a division, and the only reader is a UI that already polls.
//!
//! # Ending one
//!
//! [`FlowRegistry::close`] does not close anything. It wakes the copy loop,
//! which is the only thing that owns the sockets, and the flow is deregistered
//! by the same `Drop` that would have run a moment later for any other reason.
//! That is deliberate: the ways a flow can end outnumber the ways it can start,
//! and a second exit path would be a second thing to keep correct. A reader
//! asking "is it gone yet" is therefore asking about a moment, not about a
//! command having been obeyed.
//!
//! [`Flow`]: crate::traffic::Flow
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use iroh::EndpointId;
use tokio::sync::Notify;

/// Identifies one flow within one [`EndpointGroup`].
///
/// Only ever handed out by one registry and never reused inside it, so a reader
/// holding the id of a flow that has since ended cannot be handed that id again
/// and mistaken about which flow it is looking at.
///
/// [`EndpointGroup`]: crate::endpoint_group::EndpointGroup
pub type FlowId = u64;

/// Which door the bytes came in by.
///
/// Not a protocol the tunnel speaks — the tunnel carries bytes either way — but
/// the answer to "what made this flow", which is what a reader looking at a list
/// of them actually wants to know. Every variant corresponds to one place a
/// [`Flow`] is opened.
///
/// [`Flow`]: crate::traffic::Flow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    /// A request the local proxy read as HTTP and forwarded as one.
    Http,
    /// A CONNECT tunnel: the client asked for a socket to somewhere and got one.
    Connect,
    /// An HTTP request that was upgraded to a WebSocket.
    WebSocket,
    /// TLS the client started, copied through untouched to a route picked by SNI.
    TlsPassthrough,
    /// A TCP connection off the TUN interface.
    TunTcp,
    /// One socket's UDP traffic to one host, off the TUN interface.
    TunUdp,
}

impl FlowKind {
    /// The stable name of the kind, for a reader that has to print it.
    ///
    /// A name and not a label: it crosses to a UI in a language this crate does
    /// not know about, so it is the same string in every translation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Connect => "connect",
            Self::WebSocket => "websocket",
            Self::TlsPassthrough => "tls",
            Self::TunTcp => "tun_tcp",
            Self::TunUdp => "tun_udp",
        }
    }
}

/// What was known about a flow at the moment it opened.
///
/// Filled in by whoever is opening the tunnel, which is the only place that has
/// read the client's request far enough to know. Both fields are optional
/// because neither is guaranteed: a TLS passthrough whose ClientHello carried no
/// SNI is still a flow, and so is one whose origin the client socket did not
/// say.
#[derive(Debug, Clone)]
pub struct FlowMeta {
    /// Which door the bytes came in by.
    pub kind: FlowKind,
    /// Where they are going, as the client named it: `example.com:443`, or the
    /// virtual IP a TUN packet was addressed to.
    pub target: Option<String>,
    /// Where they came from: the socket that connected to the local proxy, or
    /// the client address behind the TUN interface.
    pub source: Option<String>,
}

/// One flow's identity, counters and cancel switch.
///
/// Shared rather than owned because two things hold it at once: the copy loop
/// that moves its bytes, and the registry that lists it for a reader. Kept alive
/// by the [`Flow`] guard, whose `Drop` is what removes it from the registry.
///
/// [`Flow`]: crate::traffic::Flow
#[derive(Debug)]
pub struct FlowEntry {
    id: FlowId,
    node: EndpointId,
    meta: FlowMeta,
    started: Instant,
    sent: AtomicU64,
    received: AtomicU64,
    /// Set once, by [`Self::cancel`], and never cleared: a flow is cancelled
    /// once and then it is gone, so there is nothing to put it back.
    cancelled: AtomicBool,
    notify: Notify,
}

impl FlowEntry {
    /// The id this flow was registered under.
    pub fn id(&self) -> FlowId {
        self.id
    }

    /// Counts `bytes` leaving this machine through this flow.
    pub(crate) fn record_sent(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Counts `bytes` arriving through this flow.
    pub(crate) fn record_received(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Resolves when somebody has asked for this flow to end.
    ///
    /// Waiting on it is how a copy loop learns it should stop: cancelling from
    /// the outside cannot drop the sockets — only the code holding them can —
    /// and a loop that is told is a loop that still runs its own cleanup.
    pub async fn cancelled(&self) {
        loop {
            // Interest registered before the flag is read, so a cancel landing
            // between the two is not lost: `notify_waiters` reaches only those
            // already waiting, and the flag is what catches everyone else.
            let notified = self.notify.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
        }
    }

    /// Wakes whoever is waiting on [`Self::cancelled`].
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// This flow as a reader sees it, copied out.
    ///
    /// A copy rather than a view for the same reason `traffic::NodeVolume` is
    /// one: the counters move while a reader is looking, and a reading that
    /// could change between two of its fields is a reading nobody can add up.
    pub fn view(&self) -> FlowView {
        FlowView {
            id: self.id,
            node: self.node,
            kind: self.meta.kind,
            target: self.meta.target.clone(),
            source: self.meta.source.clone(),
            open_for_secs: self.started.elapsed().as_secs(),
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
        }
    }
}

/// One open flow as a reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowView {
    /// Stable for as long as the flow is open, and never reused afterwards.
    pub id: FlowId,
    /// The backend this flow reaches.
    pub node: EndpointId,
    /// Which door the bytes came in by.
    pub kind: FlowKind,
    /// Where they are going, as the client named it. `None` when it never said.
    pub target: Option<String>,
    /// Where they came from. `None` when the socket did not say.
    pub source: Option<String>,
    /// Whole seconds since the flow opened.
    pub open_for_secs: u64,
    /// Bytes this machine has put into the tunnel through this flow. Cumulative.
    pub sent: u64,
    /// Bytes that have come back through it. Cumulative.
    pub received: u64,
}

/// The flows one [`EndpointGroup`] has open right now.
///
/// Owned by the group and shared with the connections it hands out, on the same
/// terms as its traffic table: not connection state, never read by anything
/// serving a request, and readable from off the request path entirely — a UI
/// listing connections is not a request. A `std::sync` lock because the critical
/// section is a map lookup and never waits on I/O, which is also what lets
/// [`Self::view`] be called without a runtime.
///
/// [`EndpointGroup`]: crate::endpoint_group::EndpointGroup
#[derive(Debug, Default)]
pub struct FlowRegistry {
    /// Handed out by `fetch_add`, so two flows opening at once cannot be given
    /// the same id and a reader cannot be handed a stale one.
    next: AtomicU64,
    entries: Mutex<HashMap<FlowId, Arc<FlowEntry>>>,
}

impl FlowRegistry {
    /// A registry with nothing in it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a flow as open.
    ///
    /// Called by `Flow::listed` and by nothing else: the caller gets an entry it
    /// is expected to hold until the flow ends, and deregistration is the
    /// holder's `Drop`. A registry that could be added to from anywhere would be
    /// a registry with entries nobody owns, and those are the ones that leak.
    pub(crate) fn open(&self, node: EndpointId, meta: FlowMeta) -> Arc<FlowEntry> {
        // Starting at 1 rather than 0: an id of 0 would be indistinguishable
        // from "no flow" to a caller that models the absence as a default.
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = Arc::new(FlowEntry {
            id,
            node,
            meta,
            started: Instant::now(),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        });

        self.lock().insert(id, entry.clone());
        entry
    }

    /// Deregisters a flow. Called by the guard holding it, and by nobody else.
    pub(crate) fn remove(&self, id: FlowId) {
        self.lock().remove(&id);
    }

    /// How many flows are open.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether any flow is open.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// One reading of the open flows, oldest first, at most `limit` of them.
    ///
    /// Oldest first and not newest, because that is the order they opened in and
    /// the only one that means anything to a reader: a list that reordered itself
    /// on every poll would be unreadable, and the newest is the one least likely
    /// to still be there.
    ///
    /// Capped because a list is for a person: a browser opening two hundred
    /// sockets at once is ordinary, and a UI that tried to draw all of them
    /// would be drawing a thousands-row table several times a second. `len()`
    /// still reports the real number, so a reader that says "200 of 1 431" is
    /// saying something true.
    pub fn view(&self, limit: usize) -> Vec<FlowView> {
        let mut entries: Vec<Arc<FlowEntry>> = self.lock().values().cloned().collect();
        entries.sort_by_key(|entry| entry.id);
        entries.truncate(limit);
        entries.iter().map(|entry| entry.view()).collect()
    }

    /// Asks one flow to end.
    ///
    /// `false` when there is no such flow, which covers "never existed" and
    /// "already ended" alike — from here the two are the same fact, and a caller
    /// that needs to tell them apart is a caller that kept its own list.
    ///
    /// Nothing is removed here. The flow deregisters itself when the copy loop
    /// it woke has actually let go of its sockets, so a list read a moment later
    /// may still show it, briefly, as open.
    pub fn close(&self, id: FlowId) -> bool {
        let entry = self.lock().get(&id).cloned();
        match entry {
            Some(entry) => {
                entry.cancel();
                true
            }
            None => false,
        }
    }

    /// Asks every flow reaching `node` to end. Returns how many were asked.
    ///
    /// The one a reader reaches for when the answer is "this backend", not "this
    /// connection": a node that has gone bad is not fixed one flow at a time,
    /// and the number returned is what tells a UI whether anything happened.
    pub fn close_node(&self, node: &EndpointId) -> usize {
        let entries: Vec<Arc<FlowEntry>> = self
            .lock()
            .values()
            .filter(|entry| &entry.node == node)
            .cloned()
            .collect();

        for entry in &entries {
            entry.cancel();
        }
        entries.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<FlowId, Arc<FlowEntry>>> {
        // Same reason as every other table in this crate: poisoning means a
        // holder panicked while the map was consistent, and the map is still
        // consistent.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::{Flow, NodeTraffic};

    fn node(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn meta(kind: FlowKind, target: &str) -> FlowMeta {
        FlowMeta {
            kind,
            target: Some(target.to_string()),
            source: Some("127.0.0.1:51244".to_string()),
        }
    }

    /// An open flow is one a reader can see, with the node it reaches and what
    /// the client said it was talking to — which is the whole point of the table.
    #[test]
    fn an_open_flow_appears_in_the_view() {
        let registry = Arc::new(FlowRegistry::new());
        let backend = node(1);

        let flow = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            backend,
            meta(FlowKind::Connect, "example.com:443"),
        );

        let view = registry.view(10);
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].id, flow.id().unwrap());
        assert_eq!(view[0].node, backend);
        assert_eq!(view[0].kind, FlowKind::Connect);
        assert_eq!(view[0].target.as_deref(), Some("example.com:443"));
        assert_eq!(view[0].source.as_deref(), Some("127.0.0.1:51244"));
    }

    /// A flow that has ended is one a reader can no longer see — the table is
    /// what is open *now*, and an entry that outlived its flow would be a list
    /// of connections that are not there.
    #[test]
    fn a_dropped_flow_leaves_the_view() {
        let registry = Arc::new(FlowRegistry::new());
        let backend = node(1);

        {
            let _flow = Flow::listed(
                Arc::new(NodeTraffic::new()),
                &registry,
                backend,
                meta(FlowKind::Http, "a.example"),
            );
            assert_eq!(registry.len(), 1);
        }

        assert_eq!(registry.len(), 0);
        assert!(registry.view(10).is_empty());
    }

    /// Ending a flow is what the registry asks for; it is the copy loop that
    /// ends it. Until then the flow is still open, and a reader is told the
    /// truth about that rather than being told it is gone.
    #[tokio::test]
    async fn close_wakes_the_flow_and_leaves_it_open_until_it_goes() {
        let registry = Arc::new(FlowRegistry::new());
        let backend = node(1);
        let flow = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            backend,
            meta(FlowKind::TunTcp, "b.example:80"),
        );

        // Waited on *before* the close, which is the only order that exercises
        // the wake-up: `notify_waiters` reaches those already waiting, and the
        // flag is the fallback for everybody else. A test that closed first would
        // pass with the notification removed entirely.
        let id = flow.id().unwrap();
        let closed = tokio::spawn({
            let registry = registry.clone();
            async move {
                // Long enough for the wait below to have been registered, and
                // the only ordering a closed-first test could not cover.
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                registry.close(id)
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), flow.cancelled())
            .await
            .expect("close() did not wake a flow that was already waiting");
        assert!(closed.await.expect("the closer panicked"));

        // Asked, not ended: the copy loop has not run yet, so the flow is still
        // open and still listed — a registry that removed it here would be
        // hiding a connection that is still carrying bytes.
        assert_eq!(registry.len(), 1);
        drop(flow);
        assert_eq!(registry.len(), 0);
    }

    /// A flow cancelled before anybody waited is already cancelled: the flag, not
    /// the notification, is what a late waiter reads — and `notify_waiters`
    /// reaches only those who were there at the time.
    #[tokio::test]
    async fn a_flow_closed_before_anyone_waits_is_already_cancelled() {
        let registry = Arc::new(FlowRegistry::new());
        let flow = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            node(2),
            meta(FlowKind::Http, "a.example"),
        );

        assert!(registry.close(flow.id().unwrap()));

        tokio::time::timeout(std::time::Duration::from_secs(2), flow.cancelled())
            .await
            .expect("cancelled() did not resolve for a flow closed earlier");
    }

    /// A flow nobody registered has nobody who could end it, so waiting on its
    /// cancel switch must wait forever rather than return at once — a copy loop
    /// that gained an immediate exit would close every connection the moment it
    /// opened one.
    #[tokio::test]
    async fn an_unlisted_flow_is_never_cancelled() {
        let flow = Flow::open(Arc::new(NodeTraffic::new()));

        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(50), flow.cancelled()).await;

        assert!(pending.is_err(), "an unlisted flow must never be woken");
    }

    /// Finishing one half of a copy loop finishes nothing.
    ///
    /// The guard is what ends a flow and a counter is only a counter, because a
    /// bidirectional tunnel ends one direction first by definition — and a
    /// registry that deregistered on the first half to finish would drop a
    /// connection that is still carrying bytes off the list, and count the node
    /// idle while it is not.
    #[test]
    fn a_dropped_counter_does_not_end_the_flow() {
        let registry = Arc::new(FlowRegistry::new());
        let traffic = Arc::new(NodeTraffic::new());
        let flow = Flow::listed(
            traffic.clone(),
            &registry,
            node(9),
            meta(FlowKind::Http, "a.example"),
        );

        let counter = flow.counter();
        counter.record_sent(500);
        drop(counter);

        // Still open, still listed, and its bytes are on both ledgers.
        assert_eq!(registry.len(), 1);
        assert_eq!(traffic.volume().active, 1);
        assert_eq!(traffic.volume().sent, 500);
        assert_eq!(registry.view(10)[0].sent, 500);

        drop(flow);
        assert_eq!(registry.len(), 0);
        assert_eq!(traffic.volume().active, 0);
    }

    /// Two flows through one node are two entries, and each one's bytes are its
    /// own: a list that showed one row per node would be the per-node counter
    /// under a different name.
    #[test]
    fn two_flows_are_counted_separately() {
        let registry = Arc::new(FlowRegistry::new());
        let backend = node(3);

        let one = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            backend,
            meta(FlowKind::Http, "a.example"),
        );
        let other = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            backend,
            meta(FlowKind::WebSocket, "b.example"),
        );

        one.record_sent(1200);
        other.record_received(34);

        let view = registry.view(10);
        assert_eq!(view.len(), 2);
        let first = view.iter().find(|v| v.id == one.id().unwrap()).unwrap();
        let second = view.iter().find(|v| v.id == other.id().unwrap()).unwrap();
        assert_eq!(first.sent, 1200);
        assert_eq!(first.received, 0);
        assert_eq!(second.sent, 0);
        assert_eq!(second.received, 34);
    }

    /// Ids are never reused: a reader holding the id of a flow that ended must
    /// not be handed the same id again and mistake a different connection for it.
    #[test]
    fn ids_are_not_reused() {
        let registry = Arc::new(FlowRegistry::new());
        let backend = node(4);

        let first = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            backend,
            meta(FlowKind::Http, "a.example"),
        );
        let first_id = first.id().unwrap();
        drop(first);

        let second = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            backend,
            meta(FlowKind::Http, "a.example"),
        );
        assert_ne!(second.id().unwrap(), first_id);
    }

    /// The cap is on what a reader is given, not on what is counted: a list
    /// cropped to ten of eleven still reports eleven.
    #[test]
    fn the_view_is_capped_but_the_count_is_not() {
        let registry = Arc::new(FlowRegistry::new());
        let backend = node(5);
        let traffic = Arc::new(NodeTraffic::new());

        let flows: Vec<Flow> = (0..11)
            .map(|i| {
                Flow::listed(
                    traffic.clone(),
                    &registry,
                    backend,
                    meta(FlowKind::Http, &format!("host{i}.example")),
                )
            })
            .collect();

        assert_eq!(registry.len(), 11);
        assert_eq!(registry.view(10).len(), 10);
        drop(flows);
    }

    /// "Stop everything through this backend" stops that backend's flows and
    /// leaves every other one alone — a reader asking for one node's connections
    /// to end is not asking about anybody else's.
    #[test]
    fn closing_a_node_leaves_other_nodes_flows_alone() {
        let registry = Arc::new(FlowRegistry::new());
        let backend = node(6);
        let other = node(7);

        let _theirs = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            other,
            meta(FlowKind::Http, "other.example"),
        );
        let mine = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &registry,
            backend,
            meta(FlowKind::Http, "mine.example"),
        );

        assert_eq!(registry.close_node(&backend), 1);
        assert_eq!(registry.close_node(&other), 1);
        // Both are still open: cancelling asks, it does not close.
        assert_eq!(registry.len(), 2);
        assert!(registry.close(mine.id().unwrap()));
    }

    /// A kind prints as the same name a UI is written against, so the two cannot
    /// drift apart when a variant is renamed in Rust.
    #[test]
    fn kinds_have_stable_names() {
        assert_eq!(FlowKind::Http.as_str(), "http");
        assert_eq!(FlowKind::Connect.as_str(), "connect");
        assert_eq!(FlowKind::WebSocket.as_str(), "websocket");
        assert_eq!(FlowKind::TlsPassthrough.as_str(), "tls");
        assert_eq!(FlowKind::TunTcp.as_str(), "tun_tcp");
        assert_eq!(FlowKind::TunUdp.as_str(), "tun_udp");
    }

    /// The registry is shared, not owned: a flow registered through one handle
    /// is visible through another, exactly as the traffic table is.
    #[test]
    fn the_registry_is_shared_not_copied() {
        let registry = Arc::new(FlowRegistry::new());
        let shared = registry.clone();

        let _flow = Flow::listed(
            Arc::new(NodeTraffic::new()),
            &shared,
            node(8),
            meta(FlowKind::TlsPassthrough, "c.example"),
        );

        assert_eq!(registry.len(), 1);
    }
}

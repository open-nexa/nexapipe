//! The connection the group hands out.
//!
//! A group lends a connection to whoever asks for a backend, and the
//! connection carries where its bytes are charged to and which flows it holds.

use crate::connection_pool::Borrow;
use crate::flow::{FlowMeta, FlowRegistry};
use crate::traffic::{self, Flow, NodeTraffic, TrafficTable};

use iroh::EndpointId;
use iroh::endpoint::Connection;

use std::sync::Arc;

/// A connection the group handed out, and the borrow it was handed out under.
///
/// Not `Clone`: a copy would be a second handle on the **same** borrow, and
/// the pool's count of the flows on the connection would then be wrong —
/// the connection would look busy after the flow that held it was gone.
#[derive(Debug)]
pub struct PooledConnection {
    conn: Connection,
    pool_index: usize,
    /// The backend this connection reaches, when somebody is keeping health for
    /// it.
    ///
    /// `None` for a connection nobody is keeping health for, which is a pool
    /// standing on its own rather than one inside an [`EndpointGroup`].
    ///
    /// Carried by the connection so that the caller which spent its attempts on
    /// it can name whose health those attempts were about. Asking the group
    /// afterwards would be asking again, and by then it may have handed somebody
    /// else out; naming the backend at every failure path instead would mean
    /// every one of them knowing how health is recorded.
    ///
    /// [`EndpointGroup`]: crate::endpoint_group::EndpointGroup
    node: Option<EndpointId>,
    /// Where to count what this connection carries. Also `None` for a pool
    /// standing on its own — the two are set together and absent together,
    /// because neither means anything about a node nobody is tracking.
    traffic: Option<Arc<NodeTraffic>>,
    /// Where the flows opened through this connection are listed. Set and absent
    /// together with `traffic`, for the same reason: neither means anything about
    /// a node nobody is tracking, and a flow that is counted but not listed is a
    /// list with a hole in it.
    flows: Option<Arc<FlowRegistry>>,
    /// The borrow this connection is held under.
    ///
    /// The pool owns the connection and the flows **borrow** it, so the pool
    /// cannot tell from the handle alone whether anyone is still on it — and
    /// it has to: a connection with a flow on it is not idle, and closing it
    /// would take that flow down with it.
    ///
    /// `None` for a connection that was not borrowed from a pool.
    borrow: Option<Borrow>,
}

impl PooledConnection {
    pub fn new(conn: Connection, pool_index: usize) -> Self {
        Self {
            conn,
            pool_index,
            node: None,
            traffic: None,
            flows: None,
            borrow: None,
        }
    }

    /// A connection whose volume and backend the group keeps track of.
    pub(crate) fn tracked(
        conn: Connection,
        pool_index: usize,
        node: EndpointId,
        traffic: TrafficTable,
        flows: Arc<FlowRegistry>,
        borrow: Borrow,
    ) -> Self {
        Self {
            conn,
            pool_index,
            node: Some(node),
            traffic: Some(traffic::of(&traffic, node)),
            flows: Some(flows),
            borrow: Some(borrow),
        }
    }

    /// Counts `bytes` leaving this machine towards the node this connection
    /// reaches.
    ///
    /// Nothing happens when nothing is being tracked: a pool standing on its
    /// own has no node to charge, and a copy loop should not need to know
    /// whether it is inside a group to count correctly. This is the one call a
    /// copy site makes, and it cannot be pointed at the wrong place: the
    /// connection decided where its bytes go.
    pub fn record_sent(&self, bytes: u64) {
        if let Some(traffic) = &self.traffic {
            traffic.record_sent(bytes);
        }
    }

    /// Counts `bytes` arriving back from that node.
    pub fn record_received(&self, bytes: u64) {
        if let Some(traffic) = &self.traffic {
            traffic.record_received(bytes);
        }
    }

    /// Holds one flow through this connection open until the guard is dropped.
    ///
    /// `meta` is what the caller knows about the flow and this connection does
    /// not: which door the bytes came in by, and — having read the client's
    /// request far enough to know — where they are going. It is read once here
    /// and never again, which is why it is not something the copy loop carries.
    ///
    /// The guard is why this returns a value at all: a flow ends on EOF, on any
    /// of several errors, on being cancelled because the proxy stopped, and on
    /// being asked to end, and only `Drop` covers all of them. See [`Flow`].
    ///
    /// A flow on a connection nobody is tracking is still returned, and still
    /// counts itself out on drop — the caller cannot tell, and does not have to:
    /// recording through a guard with nothing behind it already does nothing,
    /// exactly as [`Self::record_sent`] does for an untracked connection.
    pub fn enter_flow(&self, meta: FlowMeta) -> Flow {
        match (&self.traffic, &self.flows, self.node) {
            (Some(traffic), Some(flows), Some(node)) => {
                Flow::listed(traffic.clone(), flows, node, meta)
            }
            _ => Flow::open(self.traffic.clone().unwrap_or_default()),
        }
    }

    /// The node this connection reaches, when somebody is tracking it.
    pub fn node(&self) -> Option<EndpointId> {
        self.node
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Closes the connection instead of just letting go of it.
    ///
    /// Dropping one handle does not close a connection: it closes when the
    /// last one goes, and a path watcher holds one for as long as it lives, so
    /// a caller that has decided the connection is dead has to say so or it
    /// stays open — still in the pool's address space, still counted, and
    /// still handed to whatever asks next.
    ///
    /// Says nothing about the backend's health, and that is the point. Most of
    /// what reaches here is a connection the peer closed while nothing was
    /// using it — the ordinary case these retry loops exist for, and one that
    /// says nothing about whether the backend itself answers. Condemning it
    /// here would take a healthy backend out of rotation for as long as the
    /// next probe is away, and on the paths with no probe at all, permanently.
    /// The failure worth recording is the one no attempt outlived: see
    /// [`EndpointGroup::record_request_failures`].
    ///
    /// [`EndpointGroup::record_request_failures`]: crate::endpoint_group::EndpointGroup::record_request_failures
    pub fn discard(self, reason: &'static [u8]) {
        self.conn.close(0u32.into(), reason);
    }

    /// Marks the connection as carrying as many flows as the server allows.
    ///
    /// The server refused a flow with `TooManyFlows`, which says something
    /// about the connection rather than about the flow: the pool must stop
    /// handing this connection out, or the next flow is refused the same way.
    pub fn saturate(&self) {
        if let Some(borrow) = &self.borrow {
            borrow.saturate();
        }
    }

    pub fn pool_index(&self) -> usize {
        self.pool_index
    }
}

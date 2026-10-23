//! What the panel says about a node.
//!
//! A node is healthy, or it is not, or nobody has asked yet — and the report
//! of a pre-connect says what would happen if the connection were made now.

use iroh::EndpointId;

use std::time::Duration;
use std::time::Instant;

/// What the last probe of one backend found.
#[derive(Debug, Clone)]
pub struct NodeHealth {
    /// The backend this describes.
    pub node: EndpointId,
    /// Whether it answered the last time it was asked.
    pub reachable: bool,
    /// How many failures in a row it has had. Zero since the last success.
    ///
    /// Not only probes: a request that spent every attempt it had without being
    /// served counts too, and reaches this counter from the same place.
    pub consecutive_failures: u32,
    /// When it last answered — `None` when it never has.
    pub last_ok: Option<Instant>,
    /// When it was last asked — `None` before the first probe.
    pub last_probe: Option<Instant>,
}

impl NodeHealth {
    /// How long ago it last answered, if it ever has.
    ///
    /// "It has been down for twenty minutes" is the question a UI actually asks;
    /// a timestamp makes every caller do this subtraction and get the direction
    /// wrong at least once.
    pub fn down_for(&self) -> Option<Duration> {
        self.last_ok.map(|ok| ok.elapsed())
    }
}

/// Every backend's health at one moment, for a UI that polls.
#[derive(Debug, Clone, Default)]
pub struct HealthSnapshot {
    pub nodes: Vec<NodeHealth>,
}

impl HealthSnapshot {
    /// How many backends answered their last probe.
    pub fn reachable(&self) -> usize {
        self.nodes.iter().filter(|n| n.reachable).count()
    }

    /// Whether anything at all answered. False means the tunnel has nowhere to
    /// send anything.
    pub fn any_reachable(&self) -> bool {
        self.reachable() > 0
    }

    /// The backends that did not answer, as a comma-separated list.
    pub fn unreachable_ids(&self) -> String {
        self.nodes
            .iter()
            .filter(|n| !n.reachable)
            .map(|n| n.node.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Which configured backends answered a reachability probe.
///
/// Building an `EndpointGroup` never dials anything: a well-formed but
/// nonexistent `server_node_id` passes every setup call, and only an actual
/// connection attempt reveals that nothing is there. This report is that
/// attempt, per backend, so a caller can refuse to call a start "successful"
/// when it reached no backend at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreconnectReport {
    /// Backend nodes that accepted a connection.
    pub reachable: Vec<EndpointId>,
    /// Backend nodes that refused, were unreachable, or timed out.
    pub unreachable: Vec<EndpointId>,
    /// Backend nodes that answered the QUIC handshake and then refused the
    /// connection because this client has no 2FA credentials.
    ///
    /// A client without credentials cannot fail the 2FA handshake — it never
    /// starts one — so as far as QUIC is concerned these backends are up. They
    /// are listed here as well as in `unreachable`, so the caller can say *why*
    /// a backend that answered is not going to serve anything.
    pub auth_required: Vec<EndpointId>,
}

impl PreconnectReport {
    /// How many distinct backends were probed. Zero means none was configured.
    pub fn total(&self) -> usize {
        self.reachable.len() + self.unreachable.len()
    }

    /// True when at least one configured backend answered.
    pub fn any_reachable(&self) -> bool {
        !self.reachable.is_empty()
    }

    /// True when at least one backend demanded 2FA credentials this client does
    /// not have. Such a backend answers, then refuses to serve anything.
    pub fn any_auth_required(&self) -> bool {
        !self.auth_required.is_empty()
    }

    /// The unreachable backends as a comma-separated list, for error details.
    ///
    /// Empty when everything answered.
    pub fn unreachable_ids(&self) -> String {
        self.unreachable
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

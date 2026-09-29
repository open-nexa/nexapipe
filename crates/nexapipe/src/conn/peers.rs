//! Who is connected right now.
//!
//! The metrics module counts connections — how many, and over what kind of
//! path — but a count cannot answer "is *this* peer here", which is what the
//! management surface is asked. This is the other half: the set of peers being
//! served, with what is known about each.
//!
//! # Why a guard and not an explicit removal
//!
//! A connection ends in more ways than it has `return`s: the peer goes away,
//! a stream errors, the task is cancelled, authentication is refused. Each of
//! those would need its own removal call, and one missed would leave a peer
//! listed as connected forever. [`PeerGuard`] takes it out of the map on
//! `Drop` instead, the same way [`crate::shutdown::InFlightGuard`] reports a
//! connection as no longer in flight.
//!
//! # Why it is not a counter
//!
//! Two peers count as two entries even when they are the same key reconnecting:
//! a peer that drops and comes back is a new connection, and the map is keyed
//! by endpoint id because that is what an operator recognises — a Node ID they
//! can compare against their client list.
use crate::metrics::PathKind;
use iroh::EndpointId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// One peer currently being served.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's endpoint id, as it is printed everywhere else.
    pub endpoint_id: EndpointId,
    /// How long this connection has been open.
    pub connected_for: Duration,
    /// How its traffic is currently reaching us.
    pub path: PathKind,
}

/// What the registry keeps per peer.
#[derive(Debug, Clone, Copy)]
struct Peer {
    since: Instant,
    path: PathKind,
}

/// The set of peers with a connection being served right now.
///
/// Cloning shares the map rather than copying it, so it can be handed to the
/// listener and to every connection task without either outliving the other.
#[derive(Debug, Clone, Default)]
pub struct PeerRegistry {
    peers: Arc<RwLock<HashMap<EndpointId, Peer>>>,
}

impl PeerRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a peer, and returns the guard that takes it out again.
    ///
    /// Called once the connection is actually being served — after the 2FA
    /// handshake — because a peer that was refused is not connected, and
    /// listing it would make "who is connected" include peers that were turned
    /// away.
    pub fn insert(&self, endpoint_id: EndpointId, path: PathKind) -> PeerGuard {
        let mut peers = write(&self.peers);
        peers.insert(
            endpoint_id,
            Peer {
                since: Instant::now(),
                path,
            },
        );
        PeerGuard {
            registry: self.clone(),
            endpoint_id,
        }
    }

    /// Moves a peer to another path, because hole punching succeeded or the
    /// direct path was lost.
    ///
    /// A no-op for a peer that is not in the map: the task that follows path
    /// events outlives the handshake, so between a refused connection and its
    /// removal it can still be told about a path.
    pub fn set_path(&self, endpoint_id: &EndpointId, path: PathKind) {
        if let Some(peer) = write(&self.peers).get_mut(endpoint_id) {
            peer.path = path;
        }
    }

    /// Every peer, in no particular order.
    pub fn snapshot(&self) -> Vec<PeerInfo> {
        let peers = read(&self.peers);
        peers
            .iter()
            .map(|(endpoint_id, peer)| PeerInfo {
                endpoint_id: *endpoint_id,
                connected_for: peer.since.elapsed(),
                path: peer.path,
            })
            .collect()
    }

    /// How many peers are connected.
    pub fn len(&self) -> usize {
        read(&self.peers).len()
    }

    /// Whether anybody is connected.
    pub fn is_empty(&self) -> bool {
        read(&self.peers).is_empty()
    }

    fn remove(&self, endpoint_id: &EndpointId) {
        write(&self.peers).remove(endpoint_id);
    }
}

/// One peer's place in the registry, released when the connection ends.
#[derive(Debug)]
pub struct PeerGuard {
    registry: PeerRegistry,
    endpoint_id: EndpointId,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.endpoint_id);
    }
}

/// Takes the write lock, or poisons it.
///
/// Panicking on a poisoned lock rather than swallowing it: the map is only ever
/// read and written in a few lines that cannot panic in between, so a poisoned
/// lock means a bug elsewhere, and silently serving a stale peer list would
/// hide it.
fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

/// Takes the read lock, or recovers from a poisoned one. See [`read`].
fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two different endpoint ids, because two entries are what "a set" tests.
    fn ids() -> (EndpointId, EndpointId) {
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        (a, b)
    }

    /// A peer is listed from the moment it is inserted, and gone once the guard
    /// is dropped: the whole contract of the guard is that no early return can
    /// leave one behind.
    #[test]
    fn a_peer_is_listed_only_while_its_guard_lives() {
        let registry = PeerRegistry::new();
        let (a, b) = ids();

        let guard_a = registry.insert(a, PathKind::Relay);
        let _guard_b = registry.insert(b, PathKind::Direct);
        assert_eq!(registry.len(), 2);

        drop(guard_a);
        let listed = registry.snapshot();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].endpoint_id, b);
        assert_eq!(listed[0].path, PathKind::Direct);
    }

    /// The path is updated in place, because a connection that starts relayed
    /// and hole punches is still one peer.
    #[test]
    fn a_peer_stays_one_entry_when_its_path_changes() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        let _guard = registry.insert(a, PathKind::Relay);
        registry.set_path(&a, PathKind::Direct);

        let listed = registry.snapshot();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, PathKind::Direct);
    }

    /// Updating a peer that was already removed must not put it back: the path
    /// task outlives the connection it was started for.
    #[test]
    fn a_path_change_does_not_resurrect_a_removed_peer() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        drop(registry.insert(a, PathKind::Relay));
        registry.set_path(&a, PathKind::Direct);

        assert!(registry.is_empty(), "a removed peer came back");
    }
}

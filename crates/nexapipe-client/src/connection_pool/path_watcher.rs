//! The path watcher: the only thing that sees the path events, and so the
//! only thing that knows whether a connection can still carry traffic.

use iroh::endpoint::Connection;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use tokio_stream::StreamExt;

use super::link_status::measured_rtt;
use super::paths::PathHealth;
use super::pool::{CachedLinkStatus, IrohConnectionPoolInner};
use super::{LinkKind, LinkStatus, RTT_POLL_INTERVAL};

/// Whether a watcher that started in `generation` may still publish.
///
/// The pool's generation moves when the network changes, and a watcher whose
/// generation is behind describes a network that is gone: the round trip it
/// would publish is the one of a path that no longer carries anything.
pub(super) fn may_publish(current: u64, generation: u64) -> bool {
    current == generation
}

/// Watches one connection's paths and records which kind is carrying traffic.
///
/// The initial snapshot matters: right after the handshake iroh has already selected a path
/// (the relay one, usually) and only *later* promotes a direct one. Waiting for the first
/// event would leave the answer at [`LinkKind::Unknown`] for as long as the connection stays
/// on its first path — which, for a backend behind a symmetric NAT, is forever.
///
/// The watcher is also the only thing that sees the path **events**, so it is where the
/// pool's answer to "can this connection still carry traffic?" is kept: a path that is
/// gone is a path the connection cannot send on, whatever QUIC thinks of the connection
/// itself.
pub(super) fn spawn_path_watcher(
    inner: Weak<IrohConnectionPoolInner>,
    conn: Connection,
    paths: Arc<PathHealth>,
) {
    let status = LinkStatus::of(&conn);
    // The generation this connection belongs to. A watcher that outlives its
    // generation has a reading that describes a network that is gone, so it
    // stops publishing when the generation moves.
    let generation = inner
        .upgrade()
        .map(|inner| inner.epoch.load(Ordering::Acquire))
        .unwrap_or_default();
    // `try_lock`, not `lock`: this runs on the caller's task, and a lock held elsewhere must
    // not stall a connection being handed out. Losing the race only costs one stale reading.
    if let Some(inner) = inner.upgrade()
        && let Ok(mut slot) = inner.link_status.try_lock()
    {
        *slot = CachedLinkStatus {
            conn: Some(conn.clone()),
            paths: Some(paths.clone()),
            status,
        };
    }

    tokio::spawn(async move {
        let mut path_events = conn.path_events();
        // The paths the connection has right now. The subscription is made
        // first, so that a path which opens between the snapshot and the
        // next poll is still seen.
        paths.snapshot(conn.paths().len());
        // The round-trip time moves on its own: iroh re-estimates it from every
        // acknowledgement, and says nothing when it does. A path event is rare —
        // the connection may sit on one path for hours — so the latency is
        // refreshed on a tick instead, or the reading a user sees would be the
        // one the connection happened to have when it opened.
        let mut ticker = tokio::time::interval(RTT_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                event = path_events.next() => {
                    let Some(event) = event else {
                        break;
                    };
                    match event {
                        // A path opened: there is somewhere to send.
                        iroh::endpoint::PathEvent::Opened { .. } => paths.opened(),
                        // A path is gone. What is left of it is the
                        // connection's own answer: iroh has taken this path
                        // out of its list by the time the event is delivered.
                        iroh::endpoint::PathEvent::Closed { .. } => paths.closed(conn.paths().len()),
                        // The stream fell behind and dropped events. The
                        // connection's list is the truth, and the stream is
                        // caught up with it.
                        iroh::endpoint::PathEvent::Lagged { .. } => paths.snapshot(conn.paths().len()),
                        iroh::endpoint::PathEvent::Selected { id, remote_addr, .. } => {
                            let kind = if remote_addr.is_ip() {
                                LinkKind::Direct
                            } else if remote_addr.is_relay() {
                                LinkKind::Relay
                            } else {
                                LinkKind::Unknown
                            };

                            let Some(inner) = inner.upgrade() else {
                                // Pool dropped; nobody is left to tell.
                                break;
                            };
                            // The pool moved to another network: this connection is
                            // from the one that is gone, and the reading it would
                            // publish is that network's — the round trip of a path
                            // that no longer carries anything. The connection is
                            // closed on the way out: the drop closes every
                            // connection the pool still holds, and this watcher is
                            // what closes the one it does not — a connection the
                            // pool has let go of must not stay open on the network
                            // that is gone. A closed connection is not pooled again.
                            //
                            // The check is under the lock the reading is written
                            // with, and the drop moves the generation under that
                            // same lock: so the two cannot interleave, and a reading
                            // of the network that is gone cannot land after the
                            // reading was cleared.
                            let mut cached = inner.link_status.lock().await;
                            if !may_publish(inner.epoch.load(Ordering::Acquire), generation) {
                                conn.close(0u32.into(), b"network changed");
                                break;
                            }
                            *cached = CachedLinkStatus {
                                conn: Some(conn.clone()),
                                paths: Some(paths.clone()),
                                status: LinkStatus {
                                    kind,
                                    // The round trip is read off the path the event
                                    // named, not off whichever path is selected at the
                                    // moment of the read: the two halves of a reading
                                    // describe one path, and the selection can move
                                    // between the event and the read.
                                    //
                                    // An unknown kind has no path to measure, which
                                    // is how [`LinkStatus::of`] reads it too.
                                    rtt: if kind == LinkKind::Unknown {
                                        None
                                    } else {
                                        conn.rtt(id).and_then(measured_rtt)
                                    },
                                },
                            };
                        }
                        _ => {}
                    }
                }
                _ = ticker.tick() => {
                    // The paths are read again here as well: a path can go
                    // without the watcher hearing about it — the event
                    // stream can fall behind — and the connection's own
                    // list is the truth.
                    paths.snapshot(conn.paths().len());
                    let Some(inner) = inner.upgrade() else {
                        // Pool dropped; nobody is left to tell.
                        break;
                    };
                    let status = LinkStatus::of(&conn);
                    if status.kind == LinkKind::Unknown {
                        continue;
                    }
                    // The pool moved to another network: this connection is
                    // from the one that is gone, and the reading it would
                    // publish is that network's — the round trip of a path
                    // that no longer carries anything. The connection is
                    // closed on the way out: the drop closes every
                    // connection the pool still holds, and this watcher is
                    // what closes the one it does not — a connection the
                    // pool has let go of must not stay open on the network
                    // that is gone. A closed connection is not pooled again.
                    //
                    // The check is under the lock the reading is written
                    // with, and the drop moves the generation under that
                    // same lock: so the two cannot interleave, and a reading
                    // of the network that is gone cannot land after the
                    // reading was cleared.
                    let mut cached = inner.link_status.lock().await;
                    if !may_publish(inner.epoch.load(Ordering::Acquire), generation) {
                        conn.close(0u32.into(), b"network changed");
                        break;
                    }
                    *cached = CachedLinkStatus {
                        conn: Some(conn.clone()),
                        paths: Some(paths.clone()),
                        status,
                    };
                }
            }
        }
    });
}

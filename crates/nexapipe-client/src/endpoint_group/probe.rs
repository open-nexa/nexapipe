//! The probe: asking every backend whether it still answers.
//!
//! One table holds what every probe found, and the request that spent every
//! attempt it had writes into the same table, so that "down" has one meaning.

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::connection_pool::PRECONNECT_TIMEOUT;

use iroh::EndpointId;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::EndpointGroup;
use super::PRECONNECT_PHASE_CAP;
use super::domain_pools::record_outcome;
use super::health::{HealthSnapshot, NodeHealth, PreconnectReport};

/// How often each backend is asked whether it still answers.
///
/// Under the pool's own idle timeout (60 s) on purpose. A pool that goes quiet
/// has its connections dropped, so the probe is also what keeps one warm to a
/// backend nobody has talked to for a minute; and it is what finds out a
/// backend died half a minute after it happened instead of at the next request,
/// which is the whole of what this buys.
const PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// How far the first probe (and every following one) may be pushed back.
///
/// Every client of one server that started at the same moment would otherwise
/// probe on the same second, which is a thundering herd for no reason — and
/// without it the probe also runs in lockstep with the pool's 5 s cleanup.
const PROBE_JITTER: Duration = Duration::from_secs(5);

impl EndpointGroup {
    /// Test iroh-level connectivity to each unique backend node, in parallel.
    ///
    /// Unlike the old sequential preconnect, this:
    /// - Deduplicates pools by *backend* node ID (same backend serving several
    ///   domains is tested once) — deliberately not by the pool's local endpoint
    ///   ID, which is identical for every pool when the group shares one
    ///   caller-owned endpoint, and would collapse all backends into a single
    ///   probe
    /// - Runs all connectivity tests in parallel via `JoinSet`
    /// - Applies a per-pool budget of `PRECONNECT_TIMEOUT`, which covers the
    ///   connect and the wait for a 2FA refusal together
    /// - Caps the whole phase at `PRECONNECT_PHASE_CAP`
    ///
    /// This ensures that a single unreachable backend node does not block the
    /// entire connection flow.
    ///
    /// Returns how many nodes answered. Call [`Self::preconnect_report`] when the
    /// caller also needs to name the ones that did not.
    pub async fn preconnect_all(&self) -> usize {
        self.preconnect_report().await.reachable.len()
    }

    /// Probe every unique backend node in parallel and report which answered.
    ///
    /// This is the availability check every entry point shares. Because no setup
    /// call ever dials, a config pointing at a node that does not exist looks
    /// perfectly valid until something connects; callers therefore treat
    /// [`PreconnectReport::any_reachable`] being false as a failed start rather
    /// than reporting a connection that was never established.
    pub async fn preconnect_report(&self) -> PreconnectReport {
        // Collect unique pools by backend node ID. Multiple domains pointing to
        // the same backend share a single connection pool, so we only need to
        // test each backend once.
        let unique_pools = self.unique_pools();
        let seen_nodes: Vec<EndpointId> = unique_pools.iter().map(|(id, _)| *id).collect();

        jni_log!(
            "[preconnect] Testing connectivity to {} unique node(s) in parallel",
            unique_pools.len()
        );

        let mut report = PreconnectReport::default();
        if unique_pools.is_empty() {
            return report;
        }

        // Run connectivity tests in parallel, each capped at PRECONNECT_TIMEOUT.
        let mut join_set = tokio::task::JoinSet::new();
        for (backend_id, pool) in &unique_pools {
            let backend_id = *backend_id;
            let pool = pool.clone();
            join_set.spawn(async move {
                let answered =
                    match tokio::time::timeout(PRECONNECT_TIMEOUT, pool.preconnect()).await {
                        Ok(true) => true,
                        Ok(false) => {
                            jni_log!("[preconnect] Node unreachable (preconnect returned false)");
                            // `jni_log` only reaches logcat; the desktop and the service need
                            // this in their own log — the pool's warning says why.
                            #[cfg(feature = "tracing")]
                            tracing::warn!("preconnect: node {} is unreachable", backend_id);
                            false
                        }
                        Err(_) => {
                            jni_log!(
                                "[preconnect] Node timed out after {}s",
                                PRECONNECT_TIMEOUT.as_secs()
                            );
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                "preconnect: node {} gave no answer within {}s",
                                backend_id,
                                PRECONNECT_TIMEOUT.as_secs()
                            );
                            false
                        }
                    };
                (backend_id, answered)
            });
        }

        // Overall cap: the per-pool budget plus a little slack, so a pool that
        // used its whole budget is still what decided the answer.
        let overall_deadline = tokio::time::Instant::now() + PRECONNECT_PHASE_CAP;
        let mut probed = 0usize;
        while let Ok(result) = tokio::time::timeout_at(overall_deadline, join_set.join_next()).await
        {
            match result {
                Some(Ok((backend_id, true))) => {
                    probed += 1;
                    report.reachable.push(backend_id);
                }
                Some(Ok((backend_id, false))) => {
                    probed += 1;
                    report.unreachable.push(backend_id);
                }
                Some(Err(_e)) => {
                    jni_log!("[preconnect] Task failed");
                }
                None => break, // JoinSet empty
            }
        }

        // A task the overall cap cut off never reported. Count it as unreachable:
        // a backend may only be called usable when it actually answered, and
        // `total()` must still equal the number of configured backends.
        if probed < seen_nodes.len() {
            let mut classified = report.reachable.clone();
            classified.extend(report.unreachable.iter().copied());
            let missing = seen_nodes
                .iter()
                .copied()
                .filter(|id| !classified.contains(id));
            report.unreachable.extend(missing);
        }

        // A backend that answered and then refused the connection leaves the
        // reason on its pool. Collect it so the caller can report "this server
        // wants 2FA" instead of an "unreachable" that hides the real cause.
        for (backend_id, pool) in &unique_pools {
            if let Some(reason) = pool.take_auth_required().await {
                jni_log!("[preconnect] Node {} requires 2FA: {}", backend_id, reason);
                report.auth_required.push(*backend_id);
            }
        }

        // What the probe would have recorded, written now: startup has just
        // dialled every backend, so the group knows which of them answer from
        // the first request instead of from the first probe round, which is up
        // to a whole interval later. A backend that answered the handshake and
        // then asked for 2FA counts as answering — it is reachable, and what it
        // wants is a credential, which is a different thing to go and fix.
        for backend_id in report.reachable.iter().chain(report.auth_required.iter()) {
            self.record_probe(*backend_id, true);
        }
        for backend_id in report
            .unreachable
            .iter()
            .filter(|id| !report.auth_required.contains(id))
        {
            self.record_probe(*backend_id, false);
        }

        jni_log!(
            "[preconnect] Connectivity test done: {}/{} node(s) reachable",
            report.reachable.len(),
            seen_nodes.len()
        );
        report
    }

    /// Starts the periodic health probe.
    ///
    /// One task per group, holding only a [`std::sync::Weak`] reference, so it
    /// ends when the group does — a stopped proxy is not kept alive by the
    /// thing that is watching it. Nothing else stops it; a group that outlives
    /// the probe simply stops being probed, which is the same state as before
    /// it started.
    ///
    /// Not started by the constructors: those return a bare `Self`, and the
    /// probe needs the `Arc` the caller is about to wrap it in. Every long-lived
    /// owner therefore has to call this once, right after building the group.
    pub fn start_health_probe(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            // A full interval before the first round, not the jitter alone.
            // Whoever starts the group probes it once at startup, and a round
            // that landed 0–5 s in would dial the same backends while that one
            // was still dialling them, so both would find the pool empty and
            // each would open a connection the other did not know about.
            let first = tokio::time::Instant::now()
                + PROBE_INTERVAL
                + Duration::from_millis(fastrand::u64(0..PROBE_JITTER.as_millis() as u64));
            let mut interval = tokio::time::interval_at(first, PROBE_INTERVAL);
            // A round that ran long (a backend timing out costs up to
            // PRECONNECT_TIMEOUT) must not queue up a burst of make-up rounds.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                let Some(group) = weak.upgrade() else {
                    break;
                };
                if group.probe_stopped.load(Ordering::SeqCst) {
                    break;
                }
                group.probe_round().await;
                // Dropped here, at the end of the iteration: the strong
                // reference must not survive into the sleep, or the group would
                // never be dropped and this loop never ends.
            }
        });
    }

    /// Asks every backend once, in parallel, and records what each answered.
    ///
    /// In parallel because a dead backend costs the whole probe timeout, and
    /// four of them would then take longer than the interval between rounds.
    async fn probe_round(&self) {
        if self.probe_stopped.load(Ordering::SeqCst) {
            return;
        }
        let mut probing = tokio::task::JoinSet::new();
        for (backend_id, pool) in self.unique_pools() {
            probing.spawn(async move {
                let answered =
                    match tokio::time::timeout(PRECONNECT_TIMEOUT, pool.preconnect()).await {
                        Ok(true) => true,
                        Ok(false) => false,
                        Err(_) => false,
                    };
                (backend_id, answered)
            });
        }
        while let Some(result) = probing.join_next().await {
            // Checked here as well as at the top: a round that is already
            // dialling when the group closes has to stop dialling, and letting
            // the set drop is what aborts the members still in flight.
            if self.probe_stopped.load(Ordering::SeqCst) {
                break;
            }
            if let Ok((backend_id, answered)) = result {
                self.record_probe(backend_id, answered);
            }
        }
    }

    /// Folds one probe result into the group's health.
    pub(super) fn record_probe(&self, backend_id: EndpointId, answered: bool) {
        record_outcome(&self.health, backend_id, answered);
    }

    /// Says that a request spent every attempt it had on `backends` without
    /// being served by any of them.
    ///
    /// The counterpart to a probe: same table, same one meaning of "down", but
    /// the evidence is stronger, because somebody asked for real and waited.
    ///
    /// Takes the list rather than one backend so that a backend is counted once
    /// however many attempts landed on it: one request that failed is one
    /// failure, not three, and a counter someone reads has to mean one thing.
    ///
    /// Callers reach this through [`PooledConnection::node`] only once every
    /// attempt has failed — never per attempt. That boundary is what keeps an
    /// ordinary stale connection from taking its backend out of rotation: the
    /// retry loops exist precisely because the first attempt often draws a
    /// connection the peer closed while nothing was using it, and the second
    /// one usually succeeds.
    ///
    /// [`PooledConnection::node`]: crate::endpoint_group::PooledConnection::node
    pub fn record_request_failures(&self, backends: &[EndpointId]) {
        let mut counted: Vec<EndpointId> = Vec::with_capacity(backends.len());
        for backend in backends.iter().copied() {
            if counted.contains(&backend) {
                continue;
            }
            record_outcome(&self.health, backend, false);
            counted.push(backend);
        }
    }

    /// Every backend's health as the last probe left it.
    ///
    /// Empty until the first probe has run, which is up to
    /// `PROBE_INTERVAL` plus `PROBE_JITTER` after [`Self::start_health_probe`].
    /// A caller that needs an answer before then wants
    /// [`Self::preconnect_report`], which probes on the spot.
    ///
    /// Sorted by node ID so a UI polling it does not see the entries change
    /// places between two polls.
    pub fn health_snapshot(&self) -> HealthSnapshot {
        let mut nodes: Vec<NodeHealth> = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect();
        nodes.sort_by_key(|n| n.node.to_string());
        HealthSnapshot { nodes }
    }
}

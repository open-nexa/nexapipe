use crate::auth::{AuthConfig, ClientAuth};
use crate::config::ProxyConfig;
use crate::conn::AuthState;
use crate::conn::peers::PeerRegistry;
use crate::health::HealthProbes;
use crate::proxy::{BackendClients, sync_health_checks};
use crate::routes::RoutingTable;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Watches `config.toml` and applies a change to the live routing table.
///
/// Reloading used to stop at re-parsing the file: the new `ProxyConfig` was
/// stored, the log said "reloaded successfully", and the routes — built once at
/// startup — kept serving the old table. An edit to `[[routes]]` only took
/// effect after a restart, which is exactly how a freshly added route came to
/// look like it had never been added. The watcher
/// now owns what applying one takes: the `RoutingTable` to update and the HTTP
/// client any new health check needs.
///
/// The same edit usually carries an `[auth]` change the running server also
/// needs — a `--generate-invite --registration` run in another process (in
/// Docker, on the host against the mounted file) writes `pending_enrollment`
/// into the file, and without a reload the enrollment link only worked after a
/// restart. When an auth state is present, a reload swaps the clients table in
/// the same pass; see `ConfigWatcher::reload_auth`.
///
/// `enabled` now moves too, in one direction only: a reload may turn 2FA *on*
/// (for connections opened after it), and is refused when it would turn 2FA
/// *off*. See `ConfigWatcher::apply_auth_enabled`.
pub struct ConfigWatcher {
    config_path: String,
    route_config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    /// Health probes already running, and the pool each one is watching, so a
    /// reload can tell a route that was rebuilt from one that is still here.
    health_probes: Arc<Mutex<HealthProbes>>,
    /// Whether probing is on right now. Shared with every `HealthChecker`, which
    /// pauses instead of exiting: a spawned probe has no owner left to cancel it.
    health_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// The live 2FA state, when 2FA is configured. Its `RwLock` is what makes a
    /// client-table reload possible without dropping an existing connection.
    auth: Option<AuthState>,
    /// The connections being served right now, so a reload can tell one about
    /// the credential it authenticated with going away. See
    /// [`PeerRegistry::close_where`]: removing a client — or one device of it —
    /// from `[auth]` has to stop the traffic it is carrying now, not only the
    /// next dial.
    peers: Arc<PeerRegistry>,
    /// Where the plaintext listener ended up, when it is bound at all.
    ///
    /// Carried here for one check: turning 2FA on is only sound if the plaintext
    /// listener is not reachable from the network, which is the conflict
    /// `run_proxy` refuses a *start* over. A reload has to reach the same
    /// verdict, and it cannot see the bound socket from inside this task.
    ///
    /// A `OnceLock` rather than a constructor argument because the socket is
    /// bound minutes of code after the watcher is constructed and spawned; the
    /// reload that needs this value cannot run before the first 5 s poll, so the
    /// two are ordered by construction, not by luck. Empty means "bound a
    /// listener whose address nobody recorded, or none at all", which the
    /// enabling check treats as the permissive case — losing the check is not a
    /// reason to refuse an operator's edit.
    plaintext: std::sync::OnceLock<PlaintextListener>,
}

/// The plaintext listener as the reload path needs to judge it: the address it
/// actually bound and whether the operator opted into exposing it.
///
/// Copied out of `run_proxy` rather than looked up later because the socket's
/// own `local_addr` is the only thing that knows what `0.0.0.0` and a concrete
/// LAN address have in common, and the listener task owns it after startup.
#[derive(Debug, Clone, Copy)]
pub struct PlaintextListener {
    pub addr: std::net::SocketAddr,
    pub exposed: bool,
}

/// How often the watcher looks at the file.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The longest the watcher waits before trying the same file again after a
/// failed load.
///
/// A file that is wrong stays wrong, and a log line every five seconds for
/// ever is not a thing anyone wants to read. The wait starts at the poll
/// interval and doubles, so a file that was half-written is retried soon.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);

/// What the watcher remembers between ticks.
///
/// Two things: the file as it was when it was last loaded **successfully**,
/// and what to do about a load that failed.
#[derive(Debug, Clone, Copy)]
struct WatchState {
    /// The file as it was when it was last loaded.
    loaded: FileStamp,
    /// When a failed load may be tried again.
    retry_at: Instant,
    /// How long the next wait is. Doubles after every failure.
    retry_delay: Duration,
}

impl WatchState {
    fn new(loaded: FileStamp, now: Instant) -> Self {
        Self {
            loaded,
            retry_at: now,
            retry_delay: Duration::ZERO,
        }
    }

    /// Whether the file as it is now should be loaded.
    ///
    /// The stamp is compared as a whole, and **neither half has to be
    /// newer**: the time *or* the length being different is enough. A file
    /// that replaced another one — restored from a backup, checked out by
    /// `git` — can be *older* than the one it replaces, and a file written
    /// twice inside one second has the same time and a different length.
    ///
    /// A file that failed to load is tried again once the backoff says so.
    fn should_load(&self, current: FileStamp, now: Instant) -> bool {
        current != self.loaded && now >= self.retry_at
    }

    /// The file was loaded: this is the one to compare against next time.
    fn loaded(&mut self, current: FileStamp, now: Instant) {
        self.loaded = current;
        self.retry_at = now;
        self.retry_delay = Duration::ZERO;
    }

    /// The load failed: try again after a wait that grows.
    ///
    /// A file that was half-written when it was read is worth retrying soon;
    /// a file that is simply wrong is worth retrying every so often rather
    /// than on every tick, which is a log line every five seconds for ever.
    fn failed(&mut self, now: Instant) {
        self.retry_delay = (self.retry_delay * 2)
            .max(POLL_INTERVAL)
            .min(MAX_RETRY_DELAY);
        self.retry_at = now + self.retry_delay;
    }
}

/// What the file looked like the last time it was read.
///
/// The length is here as well as the time, for the two reasons the state's
/// own comment gives: a file written twice inside one second has the same
/// time and a different length, and a file that replaced another one can be
/// older.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: std::time::SystemTime,
    len: u64,
}

impl FileStamp {
    /// The stamp of a file that has not been loaded yet.
    const UNKNOWN: Self = Self {
        modified: std::time::SystemTime::UNIX_EPOCH,
        len: 0,
    };

    /// The stamp of the file as it is now.
    async fn read(path: &str) -> std::io::Result<Self> {
        let metadata = fs::metadata(path).await?;
        Ok(Self {
            modified: metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            len: metadata.len(),
        })
    }
}

impl ConfigWatcher {
    pub fn new(
        config_path: String,
        route_config: Arc<RoutingTable>,
        clients: Arc<BackendClients>,
        health_probes: Arc<Mutex<HealthProbes>>,
        health_enabled: Arc<std::sync::atomic::AtomicBool>,
        auth: Option<AuthState>,
        peers: Arc<PeerRegistry>,
    ) -> Self {
        ConfigWatcher {
            config_path,
            route_config,
            clients,
            health_probes,
            health_enabled,
            auth,
            peers,
            plaintext: std::sync::OnceLock::new(),
        }
    }

    /// Records where the plaintext listener ended up, once `run_proxy` has bound
    /// it. Ignored on a second call: there is only one listener per process.
    pub fn set_plaintext_listener(&self, listener: PlaintextListener) {
        let _ = self.plaintext.set(listener);
    }

    pub async fn start_watch(&self) {
        // The asynchronous one, like the check below: a synchronous
        // `std::fs::metadata` in an async function blocks the runtime's
        // thread, and the runtime has few of them.
        let mut state = WatchState::new(
            FileStamp::read(&self.config_path)
                .await
                // A file that is not there yet is a file that has not been
                // loaded: the first tick loads it, whatever its time says.
                .unwrap_or(FileStamp::UNKNOWN),
            Instant::now(),
        );

        loop {
            tokio::time::sleep(POLL_INTERVAL).await;

            let current = match FileStamp::read(&self.config_path).await {
                Ok(current) => current,
                Err(e) => {
                    tracing::warn!("Failed to check config file: {}", e);
                    continue;
                }
            };

            let now = Instant::now();
            if !state.should_load(current, now) {
                continue;
            }

            if self.reload_config().await {
                // Only now: a reload that failed keeps the old stamp, so the
                // file is tried again rather than ignored for ever.
                state.loaded(current, now);
            } else {
                state.failed(now);
            }
        }
    }

    /// Re-reads the file and applies what is live in it: the `[auth]` section
    /// and the routing table, each keeping the old value if the new one is
    /// unusable.
    ///
    /// A bad edit must not take the proxy down: the file is saved every time it
    /// is touched, so half-written and downright invalid configs are both normal
    /// here, and keeping the previous routes costs far less than dropping every
    /// connection. Once the file parses, the two halves are applied separately:
    /// a route table that will not build leaves the auth half applied, and an
    /// `[auth] enabled` the server refuses does not stop the clients table from
    /// being merged. A file that does not parse at all is refused whole, as the
    /// startup path refuses it.
    ///
    /// Whether the new config was applied.
    ///
    /// `false` means the file was read and could not be used, and the file is
    /// worth trying again: a half-written file is the common case, and it
    /// becomes a good file a moment later. It is also `false` when the routes
    /// were applied but the auth half was left for the next attempt: the file
    /// stamp is only advanced on `true`, which is what makes that attempt
    /// happen.
    async fn reload_config(&self) -> bool {
        tracing::info!("Detected config change, reloading...");

        // The epoch is sampled **before** the read: an enrollment that lands
        // while the file is being read is what the merge has to notice.
        let epoch = self.auth.as_ref().map(|s| s.enroll_epoch()).unwrap_or(0);

        // **One read for both halves.** The file is read once and parsed once,
        // so the routes and the 2FA clients come from the same revision of it.
        // Two reads could hand the two halves two different revisions, and a
        // change made between them would be half-applied.
        //
        // The read and the parse are synchronous, so they happen on a
        // blocking thread: the worker this runs on is not parked in `read(2)`
        // while every other task queued behind it waits for the disk.
        let config_path = self.config_path.clone();
        let loaded =
            tokio::task::spawn_blocking(move || ProxyConfig::load_with_auth(&config_path)).await;
        let (new_config, new_auth) = match loaded {
            Ok(Ok((config, auth))) => (config, auth),
            Ok(Err(e)) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return false;
            }
            Err(e) => {
                tracing::error!(
                    "Config not reloaded, keeping the current routes: the read did not run: {}",
                    e
                );
                return false;
            }
        };

        // The same warning the startup path gives. It does not need the auth
        // half to exist: a reload can bring in an inline `[iroh]` credential
        // on a file with no `[auth]` section at all, and that is a credential
        // in the open just the same.
        crate::config::warn_about_readable_credentials(
            std::path::Path::new(&self.config_path),
            &new_config,
            new_auth.as_ref(),
        );

        // Ahead of the routes, and on the same footing as them: a new
        // `[auth.clients]` entry is a change an operator makes while the server
        // runs — an invite was just generated, a device is about to connect —
        // so it must not be lost to a route table that does not parse. The two
        // are separate failure domains: either can fail and the other still
        // applies.
        //
        // The one case where the auth half is not applied is a snapshot that an
        // enrollment overtook twice. Reporting that up keeps the file stamp
        // where it was, so the watcher reads the file again instead of
        // forgetting the edit until somebody touches the file.
        let auth_applied = self.reload_auth(new_auth, epoch).await;

        let routes = match new_config.build_routes() {
            Ok(routes) => routes,
            Err(e) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return false;
            }
        };

        self.route_config.update_routes(routes).await;

        // Live, unlike the intervals a running checker was built with: those are
        // baked into spawned tasks, so only the switch travels.
        self.health_enabled.store(
            new_config.health_check.enabled,
            std::sync::atomic::Ordering::Relaxed,
        );
        sync_health_checks(
            &self.route_config,
            &self.clients,
            &self.health_probes,
            &new_config.health_check,
            &self.health_enabled,
        )
        .await;

        let routes_live = self.route_config.routes().await.len();
        if auth_applied {
            tracing::info!("Config reloaded: {routes_live} routes now live");
        } else {
            tracing::warn!(
                "Config reloaded: {routes_live} routes now live, but the 2FA half was not; the \
                 file is tried again"
            );
        }
        auth_applied
    }
    /// Applies the `[auth]` section of a freshly read config to the live 2FA
    /// state.
    ///
    /// `snapshot` is the auth half of the file as it was when the caller read
    /// it, and `epoch` the number of enrollments applied to the live config at
    /// that moment. The two go together: an enrollment that lands between the
    /// read and the lock would be undone by the merge, and the epoch is what
    /// says whether one did.
    ///
    /// Returns `false` when the snapshot was overtaken twice, or when the
    /// re-read that follows an overtake failed: either way the auth half has
    /// not been applied, and the caller has to keep the file on the retry list.
    ///
    /// The clients table is swapped unconditionally; `enabled` is applied by
    /// [`ConfigWatcher::apply_auth_enabled`], which may refuse it. The TOTP
    /// parameters stay as they were at startup: flipping the algorithm the
    /// issued secrets are keyed with — or the step and digit count their codes
    /// are computed under — mid-run would silently strand every client enrolled
    /// under the old ones, and unlike `enabled` there is no direction of that
    /// change which is ever safe. Those still need a restart; a client list edit
    /// does not.
    ///
    /// Counters live in memory and are only periodically flushed to disk by
    /// [`save_auth_state`], so for a client that survives the reload the
    /// in-memory lockout state wins over whatever the file says. Everything
    /// else — a new client from an invite, a rotated secret, a removed
    /// client — comes from the file.
    async fn reload_auth(&self, mut snapshot: Option<AuthConfig>, mut epoch: u64) -> bool {
        let Some(state) = &self.auth else {
            return true;
        };

        // Two attempts: the snapshot the caller read, and — if an enrollment
        // landed while it was being read — one more read.
        //
        // The read is **outside** the lock, which is the point of the whole
        // change: the lock is what every handshake and every lockout write
        // waits for, and holding it across a disk read makes the disk the
        // bottleneck for all of them.
        for attempt in 0..2 {
            let mut live = state.config().write().await;

            // An enrollment that landed between the read and this lock would
            // be undone by the merge, so the epoch is compared here — under
            // the lock the enrollment itself holds, so the two cannot
            // disagree about what happened.
            if state.enroll_epoch() != epoch {
                drop(live);

                if attempt == 1 {
                    tracing::warn!(
                        "2FA clients not reloaded: an enrollment landed while the config was \
                         being read, twice; the file is kept for the next attempt"
                    );
                    return false;
                }

                // Read the file again — outside the lock — and sample the
                // epoch again before it, so the same check covers this read.
                epoch = state.enroll_epoch();
                let config_path = self.config_path.clone();
                let loaded =
                    tokio::task::spawn_blocking(move || ProxyConfig::load_with_auth(&config_path))
                        .await;
                match loaded {
                    Ok(Ok((_proxy, auth))) => snapshot = auth,
                    Ok(Err(e)) => {
                        tracing::error!(
                            "2FA clients not reloaded, keeping the current ones: {}",
                            e
                        );
                        return false;
                    }
                    Err(e) => {
                        tracing::error!(
                            "2FA clients not reloaded, keeping the current ones: the read did not \
                             run: {}",
                            e
                        );
                        return false;
                    }
                }
                continue;
            }

            // The merge, under the lock, from a snapshot that is known to be
            // current.

            // What was here before the merge replaces it. Taken now rather than
            // derived afterwards because the merge overwrites each client whole:
            // a client survives losing a device, so after it there is nothing to
            // compare against and no way to notice the device is gone.
            let before: HashMap<String, Vec<String>> = live
                .clients
                .iter()
                .map(|(id, client)| (id.clone(), client.devices.keys().cloned().collect()))
                .collect();

            let Some(new_auth) = snapshot else {
                // The section is gone while 2FA is live: treat that as a bad edit,
                // not as "disable everything", the same way an unparsable route
                // table keeps the old routes. Worth saying out loud, but only when
                // something is actually being kept — a server that runs with no
                // `[auth]` at all reaches here on every reload, and a warning each
                // time would be noise about a state nobody asked to leave.
                if live.enabled || !live.clients.is_empty() {
                    tracing::warn!(
                        "Reloaded config has no [auth] section; keeping the current 2FA clients"
                    );
                }
                return true;
            };

            // `enabled` first, because it is the only value here that can refuse
            // itself. A refusal covers that value alone: the clients table below is
            // still merged, so a reload that could not move the gate does not also
            // drop the client the operator just added.
            if let Some(refusal) =
                ConfigWatcher::auth_enabled_refusal(&live, &new_auth, self.plaintext.get().copied())
            {
                tracing::error!("{refusal}");
            } else if apply_auth_enabled(&mut live, &new_auth) == Some(true) {
                tracing::warn!(
                    "[auth] enabled is now true: connections opened from here on must complete \
                 the 2FA handshake. Connections that are already authenticated keep working — \
                 they carry the authorization they were given when they connected"
                );
            }

            let (added, removed) = merge_auth_clients(&mut live, &new_auth);

            for id in &added {
                tracing::info!("2FA client '{id}' added by config reload");
            }
            for id in &removed {
                tracing::info!("2FA client '{id}' removed by config reload");
            }
            if !added.is_empty() || !removed.is_empty() {
                tracing::info!(
                    "2FA clients reloaded: {} now live ({} added, {} removed)",
                    live.clients.len(),
                    added.len(),
                    removed.len()
                );
            }

            // A client that survived losing one of its devices is not in `removed`,
            // so the devices are diffed against the snapshot from before the merge.
            let removed_devices = Self::removed_devices(&before, &live.clients);
            for (client_id, device) in &removed_devices {
                tracing::info!(
                    "2FA device '{device}' of client '{client_id}' removed by config reload"
                );
            }

            if !removed.is_empty() {
                let closed = self.peers.close_where(|identity| {
                    removed
                        .iter()
                        .any(|id| identity.client_id.as_deref() == Some(id))
                });
                if closed > 0 {
                    tracing::info!(
                        "Closed {} connection(s) authenticating as a client that is no longer in [auth]",
                        closed
                    );
                }
            }
            if !removed_devices.is_empty() {
                let closed = self.peers.close_where(|identity| {
                    removed_devices.iter().any(|(client_id, device)| {
                        identity.client_id.as_deref() == Some(client_id)
                            && identity.device.as_deref() == Some(device)
                    })
                });
                if closed > 0 {
                    tracing::info!(
                        "Closed {} connection(s) authenticating as a device that is no longer in [auth]",
                        closed
                    );
                }
            }

            return true;
        }

        // Unreachable: the second attempt either merges the snapshot or
        // returns `false`. Written out rather than `unreachable!()` because a
        // future third attempt that falls through must not claim the auth half
        // was applied.
        false
    }

    /// Which `(client, device)` pairs the merge dropped, for clients that are
    /// still there.
    ///
    /// Only clients on both sides are asked: one that disappeared takes every
    /// device under it with it, and those connections are already closed by
    /// the client-level pass — diffing it here too would count them twice.
    fn removed_devices(
        before: &HashMap<String, Vec<String>>,
        after: &HashMap<String, ClientAuth>,
    ) -> Vec<(String, String)> {
        let mut removed = Vec::new();
        for (client_id, devices) in before {
            let Some(client) = after.get(client_id) else {
                continue;
            };
            for device in devices {
                if !client.devices.contains_key(device) {
                    removed.push((client_id.clone(), device.clone()));
                }
            }
        }
        removed
    }

    /// Why this reload must not move `enabled`, when it must not.
    ///
    /// Returns the message to log and otherwise does nothing; the caller keeps
    /// the live state and applies the rest of the section. Two refusals, both
    /// about the single direction that can go wrong — turning the gate on:
    ///
    /// - **The file wants 2FA off.** Nothing requires this direction, and it
    ///   silently removes the listener's only gate on a running server. An
    ///   operator who wants it off restarts, which is also the only way to be
    ///   sure the change was meant rather than a half-saved edit.
    /// - **The plaintext listener is reachable from the network.** `run_proxy`
    ///   already refuses to *start* in this configuration, and 2FA does not run
    ///   on that listener, so enabling it mid-run would produce exactly the
    ///   state the startup check exists to prevent. A reload must not be the way
    ///   around a check the startup path enforces.
    ///
    /// A permissive mode on `config.toml` itself is no longer a reason to
    /// refuse: the file's permissions are not checked at start or on reload,
    /// and credentials belong in a sidecar file or the environment.
    ///
    /// `live.enabled == true` short-circuits all of it: once 2FA is on, the file
    /// saying `true` again changes nothing, so a reload that only edits routes
    /// cannot be blocked by either.
    fn auth_enabled_refusal(
        live: &AuthConfig,
        incoming: &AuthConfig,
        plaintext: Option<PlaintextListener>,
    ) -> Option<String> {
        if live.enabled == incoming.enabled {
            return None;
        }

        // The file says false while the process is gating: refuse the change.
        if live.enabled {
            return Some(
                "[auth] enabled = false is ignored: 2FA gates this listener and a reload cannot \
                 drop the only gate it has. Restart to disable 2FA."
                    .to_string(),
            );
        }

        // The file says true while the process is not gating: the plaintext
        // listener has to be the local one, and that gets its own message.
        if let Some(plaintext) = plaintext
            && crate::proxy::plaintext_auth_conflict(plaintext.addr, plaintext.exposed, true)
                .is_some()
        {
            return Some(format!(
                "[auth] enabled = true is ignored: the plaintext listener on {} would still reach \
                 every route without credentials, because 2FA only runs on the iroh listener. \
                 Remove [server] listen_addr or set expose = false, then restart.",
                plaintext.addr
            ));
        }

        None
    }
}

/// Moves `enabled` from the file onto the live state, and reports the transition.
///
/// Returns `Some(true)` when 2FA was just switched on, `Some(false)` when it was
/// switched off, and `None` when nothing changed — so the caller can log the one
/// transition worth a word without re-reading the state.
///
/// Deliberately only `enabled`: every other field of `[auth]` is either applied
/// by [`merge_auth_clients`] or startup-only, and the TOTP parameters are the
/// latter for the reason on [`ConfigWatcher::reload_auth`].
fn apply_auth_enabled(live: &mut AuthConfig, incoming: &AuthConfig) -> Option<bool> {
    if live.enabled == incoming.enabled {
        return None;
    }
    live.enabled = incoming.enabled;
    Some(live.enabled)
}

pub type SharedConfigWatcher = Arc<ConfigWatcher>;

/// Persists the runtime 2FA counters of `config` into the state file at `path`.
///
/// A lockout only means anything if it survives a restart, so
/// `failed_attempts`, `locked_until` and `last_used` are written back whenever
/// the connection layer changes them — and `last_used` under
/// `[auth.clients.<id>.devices.<name>]` with them, which is the stamp that says
/// whether a device is still in use.
///
/// The file they go to is the **state file**, not the configuration file, and
/// that is the whole point of this function having moved: the configuration is
/// the operator's, and a server that writes its own counters into it changes
/// a file nobody asked it to touch — and moves its modification time, which
/// the watcher watches, so a stranger mistyping a code was a configuration
/// reload. The state file is the server's, and only the server writes it.
///
/// Only the counters travel. The credentials, the host lists and the
/// enrollment tokens stay where they are, and a client or device that the
/// configuration does not have is not written: the operator may have removed
/// it while the server was running.
pub fn save_auth_state(path: &str, config: &AuthConfig) -> anyhow::Result<()> {
    // The whole read-modify-write runs under the lock, not just the write: two
    // counter writebacks that both read first would each build their document
    // from the file as it was before the other one landed, and one set of
    // counters would be lost.
    crate::config::with_config_lock(path, || {
        crate::auth::state::save(
            std::path::Path::new(path),
            &crate::auth::state::snapshot(config),
        )
    })
}

/// Folds the freshly parsed `[auth.clients]` table into the live one.
///
/// Returns the ids that were added and the ones that were removed, for the
/// reload log. A client present on both sides keeps its in-memory counters —
/// [`save_auth_state`] flushes them to the state file, but a failure recorded
/// between the last flush and this merge is newer than the file — and takes
/// everything else (`secret`, `pending_enrollment`, `allow_hosts`) from the
/// file, which is how an invite written by another process becomes spendable
/// and a rotated secret takes over without a restart. A client the file no
/// longer lists is dropped: the operator removed it, and keeping it alive in
/// memory would let a deleted credential keep authenticating until the next
/// restart.
/// The greater of two step memories, whichever they are.
///
/// The live value is by construction never older than the file's — it is
/// moved forward by every acceptance — so the greater of the two is the live
/// one. Taking the greater rather than the live one outright keeps the rule
/// right if the two ever disagree the other way, and it keeps the two
/// optionals from needing three cases at every call site.
fn newest_step(live: Option<u64>, from_file: Option<u64>) -> Option<u64> {
    match (live, from_file) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

fn merge_auth_clients(live: &mut AuthConfig, incoming: &AuthConfig) -> (Vec<String>, Vec<String>) {
    let mut added = Vec::new();
    let mut removed = Vec::new();

    let mut merged = HashMap::with_capacity(incoming.clients.len());
    for (id, incoming_client) in &incoming.clients {
        let mut client = incoming_client.clone();
        match live.clients.get(id) {
            Some(existing) => {
                // A token the file carries and memory does not — or a
                // different one — is a new invite, not more guesses at the old
                // one: the guesses and the lockout belong to the token they
                // were paid for, and this one starts with its own budget. A
                // reload that leaves the token alone keeps the live counter,
                // which is newer than the file's.
                let replaces_token = client.pending_enrollment != existing.pending_enrollment;
                client.failed_attempts = existing.failed_attempts;
                client.locked_until = existing.locked_until;
                if !replaces_token {
                    client.enrollment_failed_attempts = existing.enrollment_failed_attempts;
                    client.enrollment_locked_until = existing.enrollment_locked_until;
                }
                client.last_used = existing.last_used;
                // The step memory is preserved the same way, and for the same
                // reason: it is what refuses the second use of a code, and a
                // reload that lands between the in-memory record and the
                // state-file write would otherwise put the older value back
                // and hand the replay protection away.
                client.last_used_step = newest_step(existing.last_used_step, client.last_used_step);
                // The devices' own step memory, for the same reason: a
                // device's credential is its own, and a device that
                // authenticated in memory must not lose that by a reload.
                for (name, device) in client.devices.iter_mut() {
                    if let Some(existing_device) = existing.devices.get(name) {
                        device.last_used_step =
                            newest_step(existing_device.last_used_step, device.last_used_step);
                    }
                }
            }
            None => added.push(id.clone()),
        }
        merged.insert(id.clone(), client);
    }

    for id in live.clients.keys() {
        if !incoming.clients.contains_key(id) {
            removed.push(id.clone());
        }
    }

    live.clients = merged;
    (added, removed)
}

#[cfg(test)]
mod tests;

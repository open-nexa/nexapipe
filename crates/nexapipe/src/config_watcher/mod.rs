use crate::auth::{AuthConfig, ClientAuth};
use crate::config::ProxyConfig;
use crate::conn::AuthState;
use crate::conn::peers::PeerRegistry;
use crate::health::HealthProbes;
use crate::proxy::{HttpClient, sync_health_checks};
use crate::routes::RouteConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;

/// Watches `config.toml` and applies a change to the live routing table.
///
/// Reloading used to stop at re-parsing the file: the new `ProxyConfig` was
/// stored, the log said "reloaded successfully", and the routes — built once at
/// startup — kept serving the old table. An edit to `[[routes]]` only took
/// effect after a restart, which is exactly how a freshly added route came to
/// look like it had never been added. The watcher
/// now owns what applying one takes: the `RouteConfig` to update and the HTTP
/// client any new health check needs.
///
/// The same edit usually carries an `[auth]` change the running server also
/// needs — a `--generate-invite --registration` run in another process (in
/// Docker, on the host against the mounted file) writes `pending_enrollment`
/// into the file, and without a reload the enrollment link only worked after a
/// restart. When an auth state is present, a reload swaps the clients table in
/// the same pass; see [`ConfigWatcher::reload_auth`].
///
/// `enabled` now moves too, in one direction only: a reload may turn 2FA *on*
/// (for connections opened after it), and is refused when it would turn 2FA
/// *off*. See [`ConfigWatcher::apply_auth_enabled`].
pub struct ConfigWatcher {
    config_path: String,
    route_config: Arc<RouteConfig>,
    http_client: Arc<HttpClient>,
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

impl ConfigWatcher {
    pub fn new(
        config_path: String,
        route_config: Arc<RouteConfig>,
        http_client: Arc<HttpClient>,
        health_probes: Arc<Mutex<HealthProbes>>,
        health_enabled: Arc<std::sync::atomic::AtomicBool>,
        auth: Option<AuthState>,
        peers: Arc<PeerRegistry>,
    ) -> Self {
        ConfigWatcher {
            config_path,
            route_config,
            http_client,
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
        let mut last_modified = std::fs::metadata(&self.config_path)
            .map(|m| m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            match fs::metadata(&self.config_path).await {
                Ok(metadata) => {
                    if let Ok(modified) = metadata.modified()
                        && modified > last_modified
                    {
                        last_modified = modified;
                        self.reload_config().await;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to check config file: {}", e);
                }
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
    /// connection. The two halves fail independently: one refusing does not
    /// stop the other from being applied.
    async fn reload_config(&self) {
        tracing::info!("Detected config change, reloading...");

        let new_config = match ProxyConfig::from_file(&self.config_path) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return;
            }
        };

        // Ahead of the routes, and on the same footing as them: a new
        // `[auth.clients]` entry is a change an operator makes while the server
        // runs — an invite was just generated, a device is about to connect —
        // so it must not be lost to a route table that does not parse. The two
        // are separate failure domains: either can fail and the other still
        // applies.
        self.reload_auth().await;

        let routes = match new_config.build_routes() {
            Ok(routes) => routes,
            Err(e) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return;
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
            &self.http_client,
            &self.health_probes,
            &new_config.health_check,
            &self.health_enabled,
        )
        .await;

        tracing::info!(
            "Config reloaded: {} routes now live",
            self.route_config.routes().await.len()
        );
    }

    /// Applies the `[auth]` section of a freshly read config to the live 2FA
    /// state.
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
    async fn reload_auth(&self) {
        let Some(state) = &self.auth else {
            return;
        };

        // The lock is taken before the file is read, and held across both.
        //
        // Reading first and merging after would leave a window that an
        // enrollment fits neatly inside: it spends a token by changing the
        // live state and only then writing the change back, so a snapshot
        // taken a moment earlier still carries the spent token and the
        // pre-enrollment secret — and applying it afterwards puts both back,
        // handing out a token that was already used and undoing the secret
        // the enrollment just issued. Reading under the lock makes "read, then
        // merge" one step nothing can land in the middle of.
        let mut live = state.config().write().await;

        // What was here before the merge replaces it. Taken now rather than
        // derived afterwards because the merge overwrites each client whole:
        // a client survives losing a device, so after it there is nothing to
        // compare against and no way to notice the device is gone.
        let before: HashMap<String, Vec<String>> = live
            .clients
            .iter()
            .map(|(id, client)| (id.clone(), client.devices.keys().cloned().collect()))
            .collect();

        let new_auth = match ProxyConfig::load_with_auth(&self.config_path) {
            Ok((_, auth)) => auth,
            Err(e) => {
                tracing::error!("2FA clients not reloaded, keeping the current ones: {}", e);
                None
            }
        };
        let Some(new_auth) = new_auth else {
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
            return;
        };

        // `enabled` first, because it is the only value here that can refuse
        // itself. A refusal covers that value alone: the clients table below is
        // still merged, so a reload that could not move the gate does not also
        // drop the client the operator just added.
        if let Some(refusal) = ConfigWatcher::auth_enabled_refusal(
            &live,
            &new_auth,
            &self.config_path,
            self.plaintext.get().copied(),
        ) {
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
    /// the live state and applies the rest of the section. Three refusals, all
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
    /// - **The config file is not private.** 2FA off is how a 0644 file is
    ///   allowed to exist (a Docker bind mount arrives that way); enabling 2FA
    ///   turns every secret in it into a live credential for every account that
    ///   can read it, which `check_config_permissions` refuses at startup for
    ///   the same reason.
    ///
    /// `live.enabled == true` short-circuits all of it: once 2FA is on, the file
    /// saying `true` again changes nothing, so a reload that only edits routes
    /// cannot be blocked by any of the three.
    fn auth_enabled_refusal(
        live: &AuthConfig,
        incoming: &AuthConfig,
        config_path: &str,
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

        // The file says true while the process is not gating: three conditions
        // have to hold, and each has a message naming the way out.
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

        if let Some(refusal) = config_file_enabling_refusal(config_path) {
            return Some(format!("[auth] enabled = true is ignored: {refusal}"));
        }

        None
    }
}

/// The refusal for turning 2FA on against the config file as it is right now.
///
/// The rule itself is `config::world_readable_refusal` — the same "the secrets
/// become live credentials, so the file has to be private" test the startup path
/// applies — reused rather than restated so the two cannot drift. Only the mode
/// is read here, because that is the one input the caller cannot supply.
#[cfg(unix)]
fn config_file_enabling_refusal(path: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;

    // The file has just been read, so a failed stat is its own problem and not a
    // reason to refuse a change.
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    crate::config::world_readable_refusal(path, mode, true)
}

/// No file modes to inspect outside Unix, so there is nothing to refuse.
#[cfg(not(unix))]
fn config_file_enabling_refusal(_path: &str) -> Option<String> {
    None
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

/// Persists the runtime 2FA counters of `config` into the file at `path`.
///
/// A lockout only means anything if it survives a restart, so
/// `failed_attempts`, `locked_until` and `last_used` are written back whenever
/// the connection layer changes them — and `last_used` under
/// `[auth.clients.<id>.devices.<name>]` with them, which is the stamp that says
/// whether a device is still in use. Only those keys are touched, and only for
/// clients and devices that already have a section on disk, so a stale
/// in-memory entry cannot resurrect one the operator removed. Everything else
/// in the file, comments included, survives byte for byte, exactly like
/// [`ProxyConfig::write_client_secret`].
pub fn save_auth_state(path: &str, config: &AuthConfig) -> anyhow::Result<()> {
    // The whole read-modify-write runs under the lock, not just the write: two
    // counter writebacks that both read first would each build their document
    // from the file as it was before the other one landed, and one set of
    // counters would be lost.
    crate::config::with_config_lock(path, || save_auth_state_unlocked(path, config))
}

fn save_auth_state_unlocked(path: &str, config: &AuthConfig) -> anyhow::Result<()> {
    let content =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, auth state not written ({e})"))?;

    let clients = doc
        .as_table_mut()
        .get_mut("auth")
        .and_then(|item| item.as_table_like_mut())
        .and_then(|auth| auth.get_mut("clients"))
        .and_then(|item| item.as_table_like_mut())
        .ok_or_else(|| {
            anyhow::anyhow!("{path} has no [auth.clients] table, auth state not written")
        })?;

    for (id, client) in &config.clients {
        let Some(table) = clients
            .get_mut(id)
            .and_then(|item| item.as_table_like_mut())
        else {
            // Not on disk: the operator edited the file under us; writing a
            // section without a secret would break the next load.
            continue;
        };
        set_counter(table, "failed_attempts", client.failed_attempts as u64);
        set_counter(table, "locked_until", client.locked_until.unwrap_or(0));
        set_counter(table, "last_used", client.last_used.unwrap_or(0));

        // The same stamp per device, which is the one a per-device credential
        // is for: without it `client list` answers "never used" for every named
        // device, and "which of these can I revoke" has nothing to go on. Only
        // devices the file already carries are written — inventing a section
        // with no secret would leave a device nobody can authenticate as.
        if !client.devices.is_empty() {
            let Some(devices) = table
                .get_mut("devices")
                .and_then(|item| item.as_table_like_mut())
            else {
                continue;
            };
            for (name, device) in &client.devices {
                let Some(entry) = devices
                    .get_mut(name)
                    .and_then(|item| item.as_table_like_mut())
                else {
                    continue;
                };
                set_counter(entry, "last_used", device.last_used.unwrap_or(0));
            }
        }
    }

    crate::config::write_config_file(path, &doc.to_string())?;

    // The startup check only runs once, and this write recreates the file under
    // some editors and bind mounts — so a mode that was private when the proxy
    // started can be permissive by now. Refusing here would take a running
    // proxy down over a file it has already rewritten, so this reports only.
    crate::config::warn_world_readable_config(path);
    Ok(())
}

/// Writes `value` under `key`, or removes the key when the counter is back at
/// zero — a config file should not accumulate `failed_attempts = 0` lines for
/// every client that ever mistyped a code.
fn set_counter(table: &mut dyn toml_edit::TableLike, key: &str, value: u64) {
    if value != 0 {
        table.insert(key, toml_edit::value(value as i64));
    } else {
        table.remove(key);
    }
}

/// Folds the freshly parsed `[auth.clients]` table into the live one.
///
/// Returns the ids that were added and the ones that were removed, for the
/// reload log. A client present on both sides keeps its in-memory counters —
/// [`save_auth_state`] flushes them, but a failure recorded between the last
/// flush and this merge is newer than the file — and takes everything else
/// (`secret`, `pending_enrollment`, `allow_hosts`) from the file, which is how
/// an invite written by another process becomes spendable and a rotated secret
/// takes over without a restart. A client the file no longer lists is dropped:
/// the operator removed it, and keeping it alive in memory would let a deleted
/// credential keep authenticating until the next restart.
fn merge_auth_clients(live: &mut AuthConfig, incoming: &AuthConfig) -> (Vec<String>, Vec<String>) {
    let mut added = Vec::new();
    let mut removed = Vec::new();

    let mut merged = HashMap::with_capacity(incoming.clients.len());
    for (id, incoming_client) in &incoming.clients {
        let mut client = incoming_client.clone();
        match live.clients.get(id) {
            Some(existing) => {
                client.failed_attempts = existing.failed_attempts;
                client.locked_until = existing.locked_until;
                client.last_used = existing.last_used;
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
mod tests {
    use super::*;
    use crate::auth::{ClientAuth, DeviceAuth};
    use crate::conn::peers::PeerIdentity;

    fn client(secret: &str) -> ClientAuth {
        ClientAuth {
            secret: secret.to_string(),
            created_at: "0".to_string(),
            allow_hosts: None,
            pending_enrollment: None,
            devices: HashMap::new(),
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        }
    }

    fn device(secret: &str) -> DeviceAuth {
        DeviceAuth {
            secret: secret.to_string(),
            created_at: "0".to_string(),
            last_used: None,
        }
    }

    /// `removed_devices` is the detection half of revocation: a device struck
    /// out of the file while its client survives is the only case the
    /// client-level pass cannot see, so what it reports is what a reload then
    /// closes. Every case below is one an operator reaches by hand-editing —
    /// `nexapipe client revoke --device` writes exactly this diff.
    fn removed_devices_of(
        before: &[(&str, &[&str])],
        after: &[(&str, &[(&str, &str)])],
    ) -> Vec<(String, String)> {
        let before: HashMap<String, Vec<String>> = before
            .iter()
            .map(|(id, devices)| {
                (
                    id.to_string(),
                    devices.iter().map(|name| name.to_string()).collect(),
                )
            })
            .collect();
        let after: HashMap<String, ClientAuth> = after
            .iter()
            .map(|(id, devices)| {
                let mut client = client("SECRETSECRETSECR");
                client.devices = devices
                    .iter()
                    .map(|(name, secret)| (name.to_string(), device(secret)))
                    .collect();
                (id.to_string(), client)
            })
            .collect();
        let mut removed = ConfigWatcher::removed_devices(&before, &after);
        removed.sort();
        removed
    }

    #[test]
    fn a_device_struck_out_of_a_surviving_client_is_reported() {
        assert_eq!(
            removed_devices_of(
                &[("alice", &["laptop", "phone"])],
                &[("alice", &[("phone", "P")])]
            ),
            vec![("alice".to_string(), "laptop".to_string())]
        );
    }

    #[test]
    fn a_device_that_moved_to_another_client_is_reported_where_it_was() {
        assert_eq!(
            removed_devices_of(
                &[("alice", &["laptop"]), ("bob", &[])],
                &[("alice", &[]), ("bob", &[("laptop", "L")])]
            ),
            vec![("alice".to_string(), "laptop".to_string())]
        );
    }

    #[test]
    fn a_renamed_device_reports_the_old_name_only() {
        assert_eq!(
            removed_devices_of(
                &[("alice", &["laptop"])],
                &[("alice", &[("laptop-2", "L")])]
            ),
            vec![("alice".to_string(), "laptop".to_string())]
        );
    }

    /// A client that is gone takes every device under it with it, and those
    /// connections are already closed by the client-level pass. Counting them
    /// here too would close the same connection twice.
    #[test]
    fn a_client_that_disappeared_reports_no_devices() {
        assert!(
            removed_devices_of(
                &[("alice", &["laptop", "phone"])],
                &[("bob", &[("laptop", "L")])]
            )
            .is_empty()
        );
    }

    #[test]
    fn an_unchanged_table_reports_nothing() {
        assert!(
            removed_devices_of(
                &[("alice", &["laptop", "phone"])],
                &[("alice", &[("laptop", "L"), ("phone", "P")])]
            )
            .is_empty()
        );
    }

    /// The empty case: no devices anywhere is the pre-0.6.0 shape, and a
    /// reload of it must not invent a revocation.
    #[test]
    fn a_table_with_no_devices_reports_nothing() {
        assert!(removed_devices_of(&[("alice", &[])], &[("alice", &[])]).is_empty());
    }

    fn config_with(clients: &[(&str, ClientAuth)]) -> AuthConfig {
        let mut config = AuthConfig::default();
        for (id, client) in clients {
            config.clients.insert(id.to_string(), client.clone());
        }
        config
    }

    /// The whole point of the merge: an invite written by `--generate-invite`
    /// in another process becomes spendable on the running server without a
    /// restart, and a client deleted from the file stops authenticating.
    #[test]
    fn a_reload_picks_up_an_invited_client_and_drops_a_removed_one() {
        let mut live = config_with(&[("old", client("OLDOLDOLDOLDOLD"))]);
        let incoming = config_with(&[
            ("old", client("OLDOLDOLDOLDOLD")),
            ("new", client("NEWNEWNEWNEWNEW")),
        ]);

        let (added, removed) = merge_auth_clients(&mut live, &incoming);

        assert_eq!(added, vec!["new".to_string()]);
        assert!(removed.is_empty());
        assert_eq!(live.clients.len(), 2);
        assert_eq!(live.clients["new"].secret, "NEWNEWNEWNEWNEW");

        let (added, removed) = merge_auth_clients(&mut live, &config_with(&[]));

        assert!(added.is_empty());
        // HashMap order is per-process, so compare the removed set, not a sequence.
        let mut removed = removed;
        removed.sort();
        assert_eq!(removed, vec!["new".to_string(), "old".to_string()]);
        assert!(live.clients.is_empty());
    }

    /// A rotated secret (`--generate-2fa --force`, or a spent enrollment) takes
    /// over, but the lockout counters the server has been maintaining in
    /// memory are not reset by the reload — the file's copy may be stale.
    #[test]
    fn a_surviving_client_keeps_its_counters_and_takes_the_files_secret() {
        let mut live = config_with(&[("client-001", client("OLDSECRETVALUE"))]);
        let existing = live.clients.get_mut("client-001").unwrap();
        existing.failed_attempts = 2;
        existing.locked_until = Some(12345);

        let mut incoming_client = client("NEWSECRETVALUE");
        incoming_client.pending_enrollment = Some("token".to_string());
        let incoming = config_with(&[("client-001", incoming_client)]);

        let (added, removed) = merge_auth_clients(&mut live, &incoming);

        assert!(added.is_empty() && removed.is_empty());
        let client = &live.clients["client-001"];
        assert_eq!(client.secret, "NEWSECRETVALUE");
        assert_eq!(client.pending_enrollment.as_deref(), Some("token"));
        assert_eq!(client.failed_attempts, 2, "the file's stale counter loses");
        assert_eq!(client.locked_until, Some(12345));
    }

    /// A server started with no `[auth]` section at all can still switch 2FA on
    /// while it runs.
    ///
    /// Regression: the state used to be built only when the file already had an
    /// `[auth]` table, and `reload_auth` returns early on a missing state, so
    /// the one deployment that most needs a live switch — an operator adding
    /// the section to a running server for the first time — could only get it
    /// by restarting. `run_proxy` builds the state from the default config now,
    /// which is `enabled = false` with no clients, and this is what that buys.
    #[tokio::test]
    async fn a_state_built_without_a_section_still_reloads_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXP\"\n",
        )
        .unwrap();
        // Private, because enabling 2FA is refused against a file anyone else
        // can read — the secrets in it become live credentials.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let path = path.to_str().unwrap().to_string();

        let state = AuthState::new(AuthConfig::default(), &path);
        let watcher = ConfigWatcher::new(
            path,
            Arc::new(RouteConfig::new(Vec::new())),
            Arc::new(crate::http::create_http_client(
                crate::config::Timeouts::default().connect,
            )),
            Arc::new(Mutex::new(HealthProbes::new())),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            Some(state.clone()),
            Arc::new(PeerRegistry::new()),
        );

        assert!(!state.config().read().await.enabled);

        watcher.reload_auth().await;

        let live = state.config().read().await;
        assert!(
            live.enabled,
            "2FA has to come on for a server that started without it"
        );
        assert!(
            live.clients.contains_key("client-001"),
            "and the client the section brought with it has to be live too"
        );
    }

    /// The TOTP parameters are startup-only: the merge touches the clients
    /// table and nothing else, so a mid-run edit cannot strand clients enrolled
    /// under the old algorithm, step or digit count.
    #[test]
    fn the_merge_leaves_the_totp_parameters_alone() {
        let mut live = config_with(&[("a", client("A"))]);
        live.issuer = "Startup Issuer".to_string();
        live.max_attempts = 9;

        let mut incoming = config_with(&[("a", client("A2"))]);
        incoming.issuer = "File Issuer".to_string();
        incoming.max_attempts = 3;

        merge_auth_clients(&mut live, &incoming);

        assert_eq!(live.issuer, "Startup Issuer");
        assert_eq!(live.max_attempts, 9);
        assert_eq!(live.clients["a"].secret, "A2");
    }

    /// Turning 2FA on mid-run is the half of the old startup-only rule that had
    /// to go: without it, an operator who writes `enabled = true` gets a log
    /// line saying the config reloaded and a listener that is still ungated.
    #[test]
    fn a_reload_turns_2fa_on() {
        let mut live = config_with(&[("a", client("A"))]);
        live.enabled = false;

        let mut incoming = config_with(&[("a", client("A"))]);
        incoming.enabled = true;

        assert_eq!(apply_auth_enabled(&mut live, &incoming), Some(true));
        assert!(
            live.enabled,
            "the file's `true` is what the listener now uses"
        );
    }

    /// The transition is reported only when it happens, so the reload path can
    /// log it without re-reading the state — and so a route-only edit while 2FA
    /// is on stays quiet.
    #[test]
    fn an_unchanged_enabled_reports_no_transition() {
        let mut live = config_with(&[("a", client("A"))]);
        live.enabled = true;

        let mut incoming = config_with(&[("a", client("A"))]);
        incoming.enabled = true;

        assert_eq!(apply_auth_enabled(&mut live, &incoming), None);
        assert!(live.enabled);
    }

    /// The direction that has to be refused: `enabled = false` on a server that
    /// is gating would remove the listener's only gate, and an operator who
    /// wants that restarts.
    #[test]
    fn a_reload_may_not_turn_2fa_off() {
        let mut live = config_with(&[("a", client("A"))]);
        live.enabled = true;

        let mut incoming = config_with(&[("a", client("A"))]);
        incoming.enabled = false;

        let refusal = ConfigWatcher::auth_enabled_refusal(&live, &incoming, "", None)
            .expect("turning 2FA off must be refused");

        assert!(
            refusal.contains("[auth] enabled = false is ignored"),
            "{refusal}"
        );
        // The refusal is only a message; the caller applies nothing, so the live
        // state still gates.
        assert!(live.enabled);
    }

    /// Once 2FA is on, the file repeating `true` is not a transition, so none of
    /// the three enabling checks can block an unrelated edit — a route change
    /// during a `chmod 644` moment still reloads.
    #[test]
    fn an_already_enabled_config_is_never_refused() {
        let mut live = config_with(&[]);
        live.enabled = true;

        let mut incoming = config_with(&[]);
        incoming.enabled = true;

        assert_eq!(
            ConfigWatcher::auth_enabled_refusal(&live, &incoming, "/nonexistent", None),
            None
        );
    }

    /// Enabling 2FA against a config file other accounts can read would turn
    /// every secret in it into a live credential, which is what
    /// `check_config_permissions` refuses a start over.
    #[cfg(unix)]
    #[test]
    fn a_reload_may_not_enable_2fa_on_a_world_readable_config() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "[auth]\nenabled = true").unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let live = config_with(&[]);
        let mut incoming = config_with(&[]);
        incoming.enabled = true;

        let refusal =
            ConfigWatcher::auth_enabled_refusal(&live, &incoming, path.to_str().unwrap(), None)
                .expect("a world-readable config must not be enabled on");

        assert!(refusal.contains("chmod 600"), "{refusal}");

        // And the check is about the mode alone: private is not refused.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            ConfigWatcher::auth_enabled_refusal(&live, &incoming, path.to_str().unwrap(), None),
            None
        );
    }

    /// 2FA does not run on the plaintext listener, so enabling it while that
    /// listener is reachable from the network would produce exactly the state
    /// `run_proxy` refuses to start in. A reload must not be the way around a
    /// check the startup path enforces.
    #[test]
    fn a_reload_may_not_enable_2fa_while_plaintext_is_exposed() {
        let live = config_with(&[]);
        let mut incoming = config_with(&[]);
        incoming.enabled = true;

        let exposed = Some(PlaintextListener {
            addr: "0.0.0.0:8080".parse().unwrap(),
            exposed: true,
        });
        let refusal = ConfigWatcher::auth_enabled_refusal(&live, &incoming, "", exposed)
            .expect("an exposed plaintext listener must block the flip");
        assert!(refusal.contains("plaintext listener"), "{refusal}");

        // A loopback listener is the case the startup path allows, so it is not
        // refused here either.
        let loopback = Some(PlaintextListener {
            addr: "127.0.0.1:8080".parse().unwrap(),
            exposed: false,
        });
        assert_eq!(
            ConfigWatcher::auth_enabled_refusal(&live, &incoming, "", loopback),
            None
        );

        // And no plaintext listener at all is always fine.
        assert_eq!(
            ConfigWatcher::auth_enabled_refusal(&live, &incoming, "", None),
            None
        );
    }

    /// Whether a device is still in use is answered from the stamp the server
    /// writes back. A device whose `last_used` never reaches the file reports
    /// "never used" forever, and "which of these can I revoke without
    /// disconnecting someone" has nothing to go on — which is the whole of what
    /// a per-device credential is for.
    #[test]
    fn a_device_stamp_is_written_back_without_touching_its_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let path_str = path.to_str().expect("utf-8 path").to_string();
        std::fs::write(
            &path,
            "[auth]\n\
             [auth.clients.alice]\n\
             secret = \"ALICEALICEALICEA\"\n\
             \n\
             [auth.clients.alice.devices.laptop]\n\
             secret = \"LAPTOPLAPTOPLAPT\"\n",
        )
        .expect("write the config");

        let mut alice = client("ALICEALICEALICEA");
        alice.devices = [(
            "laptop".to_string(),
            DeviceAuth {
                secret: "LAPTOPLAPTOPLAPT".to_string(),
                created_at: "0".to_string(),
                last_used: Some(1700000000),
            },
        )]
        .into_iter()
        .collect();
        let config = config_with(&[("alice", alice)]);

        // Written the way the connection layer writes it: from a snapshot, which
        // is a copy that carries no credential.
        save_auth_state(&path_str, &config.counter_snapshot()).expect("the writeback succeeds");

        let on_disk = std::fs::read_to_string(&path).expect("read the config back");
        assert!(
            on_disk.contains("last_used = 1700000000"),
            "the device stamp did not reach the file: {on_disk}"
        );
        assert!(
            on_disk.contains("LAPTOPLAPTOPLAPT"),
            "the snapshot's blanked secret must not be written over the real one: {on_disk}"
        );
    }

    /// A minimal config file carrying one `[auth.clients]` entry.
    fn file_with(client_id: &str, secret: &str) -> String {
        format!(
            "[auth]\n\
             [auth.clients.{client_id}]\n\
             secret = \"{secret}\"\n\
             created_at = \"1723756800\"\n"
        )
    }

    /// A reload has to read the clients file *after* it owns the auth lock.
    ///
    /// An enrollment spends a token by changing the live state and then writing
    /// the change out, so a snapshot taken before the lock is held — and
    /// applied afterwards — would put the spent token back and roll the client's
    /// secret back to what it was before the enrollment.
    ///
    /// The enrollment is reproduced by holding the lock the way it does and
    /// rewriting the file while it is held: the reload then has to wait for the
    /// lock and must come away with what the file says *now*, not with what it
    /// said when the reload started.
    #[tokio::test]
    async fn a_reload_reads_the_clients_file_after_taking_the_auth_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let path_str = path.to_str().expect("utf-8 path").to_string();

        std::fs::write(&path, file_with("old", "OLDOLDOLDOLDOLDO")).expect("write the first file");
        let state = AuthState::new(
            config_with(&[("old", client("OLDOLDOLDOLDOLDO"))]),
            path_str.clone(),
        );

        let watcher = ConfigWatcher::new(
            path_str,
            Arc::new(RouteConfig::new(Vec::new())),
            Arc::new(crate::http::create_http_client(
                crate::config::Timeouts::default().connect,
            )),
            Arc::new(Mutex::new(HealthProbes::new())),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            Some(state.clone()),
            Arc::new(PeerRegistry::new()),
        );

        let enrolled = state.clone();
        let path_for_task = path.clone();
        let holder = tokio::spawn(async move {
            let _guard = enrolled.config().write().await;
            std::fs::write(&path_for_task, file_with("new", "NEWNEWNEWNEWNEWN"))
                .expect("write the second file");
            tokio::time::sleep(Duration::from_millis(150)).await;
        });

        // Long enough for the task above to have taken the lock and rewritten
        // the file, which is the only thing that makes this a race.
        tokio::time::sleep(Duration::from_millis(50)).await;
        watcher.reload_auth().await;
        holder.await.expect("the holder task ends");

        let live = state.config().read().await;
        assert!(
            live.clients.contains_key("new"),
            "the reload must merge the file as it reads once it holds the lock"
        );
        assert!(
            !live.clients.contains_key("old"),
            "a client the file no longer lists must not survive the reload"
        );
    }

    /// A device struck out of the file while its client survives has to reach
    /// the connection already serving as it, not only the next dial.
    ///
    /// This is the far end of the path `removed_devices` feeds: an operator
    /// runs `nexapipe client revoke alice --device laptop`, the reload diffs
    /// the device table, and the connection that authenticated as that device
    /// is told to stop through the channel it was registered with. The sibling
    /// device is the control — a revocation that took every device of the
    /// client with it would be a different bug, and a quieter one.
    #[tokio::test]
    async fn a_reload_closes_the_connection_authenticated_as_a_removed_device() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let path_str = path.to_str().expect("utf-8 path").to_string();

        let file = |devices: &[&str]| {
            let mut out = String::from(
                "[auth]\n\
                 [auth.clients.alice]\n\
                 secret = \"ALICEALICEALICEA\"\n\
                 created_at = \"1723756800\"\n",
            );
            for name in devices {
                out.push_str(&format!(
                    "\n[auth.clients.alice.devices.{name}]\n\
                     secret = \"DEVICEDEVICEDEVIC\"\n\
                     created_at = \"1723756800\"\n"
                ));
            }
            out
        };

        std::fs::write(&path, file(&["laptop", "phone"])).expect("write the config");

        let mut alice = client("ALICEALICEALICEA");
        alice.devices = ["laptop", "phone"]
            .into_iter()
            .map(|name| (name.to_string(), device("DEVICEDEVICEDEVIC")))
            .collect();
        let state = AuthState::new(config_with(&[("alice", alice)]), path_str.clone());

        let peers = Arc::new(PeerRegistry::new());
        let watcher = ConfigWatcher::new(
            path_str,
            Arc::new(RouteConfig::new(Vec::new())),
            Arc::new(crate::http::create_http_client(
                crate::config::Timeouts::default().connect,
            )),
            Arc::new(Mutex::new(HealthProbes::new())),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            Some(state.clone()),
            peers.clone(),
        );

        // Registered the way the handshake registers a connection: identity,
        // channel and guard in one step.
        let registered = |seed: u8, device: &str| {
            let (tx, rx) = tokio::sync::watch::channel(false);
            let guard = peers.insert(
                iroh::SecretKey::from_bytes(&[seed; 32]).public(),
                crate::metrics::PathKind::Direct,
                PeerIdentity {
                    client_id: Some("alice".to_string()),
                    device: Some(device.to_string()),
                },
                tx,
            );
            (rx, guard)
        };
        let (mut laptop_rx, _laptop) = registered(1, "laptop");
        let (mut phone_rx, _phone) = registered(2, "phone");

        std::fs::write(&path, file(&["phone"])).expect("rewrite without the laptop");
        watcher.reload_auth().await;

        assert!(
            *laptop_rx.borrow_and_update(),
            "a connection serving as a device the file no longer lists must be told to stop"
        );
        assert!(
            !*phone_rx.borrow_and_update(),
            "a device that is still in the file must not be closed along with it"
        );
    }
}

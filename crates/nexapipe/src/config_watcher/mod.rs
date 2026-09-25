use crate::auth::AuthConfig;
use crate::config::ProxyConfig;
use crate::conn::AuthState;
use crate::proxy::{HttpClient, spawn_health_checks};
use crate::routes::RouteConfig;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;

/// Watches `config.toml` and applies a change to the live routing table.
///
/// Reloading used to stop at re-parsing the file: the new `ProxyConfig` was
/// stored, the log said "reloaded successfully", and the routes — built once at
/// startup — kept serving the old table. An edit to `[[routes]]` or
/// `default_backend` only took effect after a restart, which is exactly how a
/// freshly added route came to look like it had never been added. The watcher
/// now owns what applying one takes: the `RouteConfig` to update and the HTTP
/// client any new health check needs.
///
/// The same edit usually carries an `[auth]` change the running server also
/// needs — a `--generate-invite --registration` run in another process (in
/// Docker, on the host against the mounted file) writes `pending_enrollment`
/// into the file, and without a reload the enrollment link only worked after a
/// restart. When an auth state is present, a reload swaps the clients table in
/// the same pass; see [`ConfigWatcher::reload_auth`].
pub struct ConfigWatcher {
    config_path: String,
    route_config: Arc<RouteConfig>,
    http_client: Arc<HttpClient>,
    /// Health checks already running, keyed by host + backends. A probe cannot
    /// be stopped, so a reload only starts the ones it has not started yet.
    health_seen: Arc<Mutex<HashSet<String>>>,
    /// The live 2FA state, when 2FA is configured. Its `RwLock` is what makes a
    /// client-table reload possible without dropping an existing connection.
    auth: Option<AuthState>,
}

impl ConfigWatcher {
    pub fn new(
        config_path: String,
        route_config: Arc<RouteConfig>,
        http_client: Arc<HttpClient>,
        health_seen: Arc<Mutex<HashSet<String>>>,
        auth: Option<AuthState>,
    ) -> Self {
        ConfigWatcher {
            config_path,
            route_config,
            http_client,
            health_seen,
            auth,
        }
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

    /// Re-reads the file and swaps the routing table, keeping the old one if the
    /// new file is unusable.
    ///
    /// A bad edit must not take the proxy down: the file is saved every time it
    /// is touched, so half-written and downright invalid configs are both normal
    /// here, and keeping the previous routes costs far less than dropping every
    /// connection.
    async fn reload_config(&self) {
        tracing::info!("Detected config change, reloading...");

        let new_config = match ProxyConfig::from_file(&self.config_path) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return;
            }
        };

        let routes = match new_config.build_routes() {
            Ok(routes) => routes,
            Err(e) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return;
            }
        };

        self.route_config
            .update_default_backend(new_config.default_backend.clone())
            .await;
        self.route_config.update_routes(routes).await;
        spawn_health_checks(&self.route_config, &self.http_client, &self.health_seen).await;

        tracing::info!(
            "Config reloaded: {} routes now live",
            self.route_config.routes().await.len()
        );

        // Best effort, and deliberately separate from the route parse above: a
        // malformed `[auth]` section must not block a route reload (serde
        // ignores unknown sections when building `ProxyConfig`, so it would
        // have reloaded before auth parsing existed). The file is read a
        // second time; a change between the two reads simply schedules
        // another reload through the mtime check.
        let new_auth = match ProxyConfig::load_with_auth(&self.config_path) {
            Ok((_, auth)) => auth,
            Err(e) => {
                tracing::error!("2FA clients not reloaded, keeping the current ones: {}", e);
                None
            }
        };
        self.reload_auth(new_auth).await;
    }

    /// Applies the `[auth]` section of a freshly read config to the live 2FA
    /// state.
    ///
    /// Only the clients table is swapped: `enabled` and the TOTP parameters
    /// stay as they were at startup. Gating the listener on 2FA is a decision
    /// with consequences for every warning and every connection, and flipping
    /// `enabled` — or the algorithm the issued secrets are keyed with —
    /// mid-run would silently strand clients that were enrolled under the old
    /// parameters. Those still need a restart; a client list edit does not.
    ///
    /// Counters live in memory and are only periodically flushed to disk by
    /// [`save_auth_state`], so for a client that survives the reload the
    /// in-memory lockout state wins over whatever the file says. Everything
    /// else — a new client from an invite, a rotated secret, a removed
    /// client — comes from the file.
    async fn reload_auth(&self, new_auth: Option<AuthConfig>) {
        let Some(state) = &self.auth else {
            return;
        };
        let Some(new_auth) = new_auth else {
            // The section is gone while 2FA is live: treat that as a bad edit,
            // not as "disable everything", the same way an unparsable route
            // table keeps the old routes.
            tracing::warn!(
                "Reloaded config has no [auth] section; keeping the current 2FA clients"
            );
            return;
        };

        let mut live = state.config().write().await;
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
    }
}

pub type SharedConfigWatcher = Arc<ConfigWatcher>;

/// Persists the runtime 2FA counters of `config` into the file at `path`.
///
/// A lockout only means anything if it survives a restart, so
/// `failed_attempts`, `locked_until` and `last_used` are written back whenever
/// the connection layer changes them. Only those three keys of
/// `[auth.clients.<id>]` are touched — and only for clients that already have
/// a section on disk, so a stale in-memory entry cannot resurrect a client
/// the operator removed. Everything else in the file, comments included,
/// survives byte for byte, exactly like [`ProxyConfig::write_client_secret`].
pub fn save_auth_state(path: &str, config: &AuthConfig) -> anyhow::Result<()> {
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
        .ok_or_else(|| anyhow::anyhow!("{path} has no [auth.clients] table, auth state not written"))?;

    for (id, client) in &config.clients {
        let Some(table) = clients.get_mut(id).and_then(|item| item.as_table_like_mut()) else {
            // Not on disk: the operator edited the file under us; writing a
            // section without a secret would break the next load.
            continue;
        };
        set_counter(table, "failed_attempts", client.failed_attempts as u64);
        set_counter(table, "locked_until", client.locked_until.unwrap_or(0));
        set_counter(table, "last_used", client.last_used.unwrap_or(0));
    }

    std::fs::write(path, doc.to_string())
        .map_err(|e| anyhow::anyhow!("cannot write {path}: {e}"))?;

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
    use crate::auth::ClientAuth;

    fn client(secret: &str) -> ClientAuth {
        ClientAuth {
            secret: secret.to_string(),
            created_at: "0".to_string(),
            allow_hosts: None,
            pending_enrollment: None,
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        }
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

    /// `enabled` and the TOTP parameters are startup-only: the merge touches
    /// the clients table and nothing else, so a mid-run edit cannot strand
    /// clients enrolled under the old parameters.
    #[test]
    fn the_merge_leaves_everything_but_the_clients_alone() {
        let mut live = config_with(&[("a", client("A"))]);
        live.enabled = true;
        live.issuer = "Startup Issuer".to_string();
        live.max_attempts = 9;

        let mut incoming = config_with(&[("a", client("A2"))]);
        incoming.enabled = false;
        incoming.issuer = "File Issuer".to_string();
        incoming.max_attempts = 3;

        merge_auth_clients(&mut live, &incoming);

        assert!(live.enabled);
        assert_eq!(live.issuer, "Startup Issuer");
        assert_eq!(live.max_attempts, 9);
        assert_eq!(live.clients["a"].secret, "A2");
    }
}

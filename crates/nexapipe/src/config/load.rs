//! Loading the configuration, from a file or from a store.
//!
//! The parse is the same either way, and that is the point: the schema in
//! [`schema`] is the one place a key is named, so a configuration that came
//! out of a database is validated by the same code, with the same messages,
//! as one that came out of a file.
//!
//! Two entry points, because two things are true at once:
//!
//! - the file-based one is **synchronous**, because everything that reads a
//!   file today — the CLI, the tests, the paths an operator names — reads it
//!   without a runtime;
//! - the store-based one is **asynchronous**, because a store that is not a
//!   file answers when it answers.
//!
//! They share the parse, so the two cannot drift.

use crate::auth::AuthConfig;
use crate::config::schema::ProxyConfig;
use crate::storage::Storage;
use crate::storage::file::FileStorage;
use crate::toml_zeroize::ZeroizedValue;

use nexapipe_proto::secret::SecretString;

use std::collections::HashMap;
use std::path::Path;

use super::parse_config;

impl ProxyConfig {
    /// The configuration, from the file at `path`.
    ///
    /// The 2FA half of the file is read as far as the port rules and no
    /// further: this is the read for a caller that wants the routing and the
    /// settings and not the credentials. [`Self::load_with_auth`] is the one
    /// that reads the seeds.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let storage = FileStorage::new(path);
        tracing::debug!("Loading config from: {}", path);

        let content = storage
            .config_text()?
            .ok_or_else(|| anyhow::anyhow!("Config file not found: {path}"))?;

        tracing::debug!("Config content read successfully, parsing TOML");
        let mut config: Self = parse_config(content.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {e:#}"))?;
        config.resolve_external_credentials(storage.base_dir())?;

        tracing::debug!("Config parsed successfully: {:?}", config);
        Ok(config)
    }

    /// The configuration and the 2FA half of it, from the file at `path`.
    ///
    /// Both halves come from one read of the file, so the routes and the
    /// clients are the same revision of it.
    pub fn load_with_auth(path: &str) -> anyhow::Result<(Self, Option<AuthConfig>)> {
        let storage = FileStorage::new(path);
        let content = storage
            .config_text()?
            .ok_or_else(|| anyhow::anyhow!("Config file not found: {path}"))?;

        let (config, mut auth) = Self::parse_with_auth(&content, storage.base_dir())?;

        // The counters the server counted live in their own file, beside the
        // configuration. They are moved onto the configuration the caller
        // gets, so everything downstream — the connection layer, the admin
        // view, the client list — reads one answer and does not have to know
        // which file it came from.
        //
        // A state file that cannot be read stops the load: the lockouts it
        // holds are unknown, and a server that started anyway would have just
        // reset every one of them.
        if let Some(auth_config) = auth.as_mut() {
            let state = storage.state()?;
            crate::auth::state::apply(&state, auth_config);
        }

        Ok((config, auth))
    }

    /// The configuration and the 2FA half of it, from the text of a
    /// configuration file.
    ///
    /// `base_dir` is the directory a relative `*_file` path is resolved
    /// against — the directory the configuration file is in, for a file, and
    /// nothing for a store that has no directory.
    pub(crate) fn parse_with_auth(
        content: &SecretString,
        base_dir: Option<&Path>,
    ) -> anyhow::Result<(Self, Option<AuthConfig>)> {
        // The file can hold the 2FA seeds in the clear, so the text it is read
        // into is wiped when it goes out of scope.
        let mut base: Self = parse_config(content.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {e:#}"))?;
        base.resolve_external_credentials(base_dir)?;

        // No `[auth]` section: there is nothing to read out of one, and the
        // tree that holds it does not have to be built. The top-level parse
        // already knows whether the section is there.
        if base.auth.is_none() {
            return Ok((base, None));
        }

        // Try to parse auth section separately
        // Note `toml::from_str`, not `str::parse`: `Value::from_str` reads a
        // single TOML *value*, so it rejects a whole document with "unexpected
        // content, expected nothing" and silently leaves 2FA disabled.
        let auth_config = match toml::from_str::<toml::Value>(content.expose_secret()) {
            Ok(toml_value) => {
                // The tree is a copy of the file in plain strings, the seeds
                // included, and it is dropped on every way out of here — the
                // error paths as much as the successful one. A guard wipes it
                // on the way instead of leaving it to the allocator.
                let mut toml_value = ZeroizedValue::new(toml_value);
                // Moved out of the tree rather than borrowed out of it: a
                // clone is a second copy of the seeds, and the section that is
                // moved hands its strings to the zeroizing fields the parse
                // fills.
                let auth_section = toml_value
                    .table_mut()
                    .and_then(|table| table.remove("auth"));
                if let Some(auth_section) = auth_section {
                    let auth_toml: crate::config::auth_file::AuthTomlConfig = auth_section
                        .try_into()
                        .map_err(|e| anyhow::anyhow!("Failed to parse auth config: {}", e))?;

                    let mut clients = HashMap::new();
                    if let Some(clients_toml) = auth_toml.clients {
                        for (id, client_toml) in clients_toml {
                            // An empty token compares equal to an empty
                            // ENROLL_START — see `conn::enroll_client` — so
                            // `pending_enrollment = ""` would hand a fresh
                            // secret to anybody who asks. Refused at load time
                            // rather than read as "no enrollment outstanding":
                            // the way to close an enrollment is to delete the
                            // key, and a blank one is a typo with a wide door
                            // behind it.
                            if client_toml
                                .pending_enrollment
                                .as_ref()
                                .map(|token| token.expose_secret().as_str())
                                == Some("")
                            {
                                anyhow::bail!(
                                    "[auth.clients.{id}]: pending_enrollment is empty; delete the \
                                     key instead of setting it to \"\""
                                );
                            }
                            // An allow-hosts entry is a host pattern, and a
                            // loose one authorizes more than it names: the same
                            // refusal a route's `host_pattern` gets.
                            for host in client_toml.allow_hosts.iter().flatten() {
                                if let Some(why) = crate::routes::pattern_error(host) {
                                    anyhow::bail!(
                                        "[auth.clients.{id}]: allow_hosts entry {host:?} {why}"
                                    );
                                }
                            }
                            // A port of zero is not a port a client can ask
                            // for: no flow arrives from it and no request names
                            // it, so an entry that lists it authorizes nothing
                            // and looks like it authorizes something.
                            if let Some(ports) = &client_toml.allow_ports
                                && ports.contains(&0)
                            {
                                anyhow::bail!(
                                    "[auth.clients.{id}]: allow_ports contains port 0; no client \
                                     ever asks for it, so that entry can never match"
                                );
                            }
                            // A name in this table is a credential's whole
                            // identity: it is what the device sends, what the
                            // log line for every outcome carries, and what an
                            // operator names when revoking one. An empty one
                            // is not a name — the unnamed device is what the
                            // client's own `secret` is for.
                            //
                            // The two fields that follow are one credential
                            // spelled two ways — a TOTP seed the device shares
                            // with the server, or the public half of a key pair
                            // it keeps the other half of — and a device answers
                            // with exactly one of them. Both, or neither, is a
                            // config that does not say how the device proves
                            // itself, refused here where the operator can see
                            // which entry it is.
                            let mut devices = HashMap::new();
                            for (device_id, device_toml) in client_toml.devices.unwrap_or_default()
                            {
                                if device_id.is_empty() {
                                    anyhow::bail!(
                                        "[auth.clients.{id}.devices]: a device needs a name; a \
                                         client's own `secret` is the credential of the device \
                                         that has none"
                                    );
                                }
                                if !crate::auth::is_presentable_device_id(&device_id) {
                                    anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: a device name is \
                                         printable ASCII of at most {} characters — it is written \
                                         into the log line for everything that happens to it",
                                        crate::auth::MAX_DEVICE_ID_LEN
                                    );
                                }
                                // `secret = ""` is read as no secret at all:
                                // an empty one is not a credential, and an
                                // entry left holding only that is refused
                                // below like one that has nothing.
                                let secret =
                                    device_toml.secret.filter(|s| !s.expose_secret().is_empty());
                                match (&secret, &device_toml.public_key) {
                                    (None, None) => anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: no `secret` and \
                                         no `public_key`; a device answers with one of the two, \
                                         and an empty secret is not one"
                                    ),
                                    (Some(_), Some(_)) => anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: both a `secret` \
                                         and a `public_key`; a device answers with one \
                                         credential, and two are two answers to disagree about"
                                    ),
                                    (None, Some(public_key)) => {
                                        // Checked where the key would otherwise
                                        // first be used: at a handshake, where
                                        // a bad key and a wrong one are the
                                        // same refusal.
                                        if let Err(why) = crate::auth::parse_public_key(public_key)
                                        {
                                            anyhow::bail!(
                                                "[auth.clients.{id}.devices.{device_id}]: {why}"
                                            );
                                        }
                                    }
                                    (Some(_), None) => {}
                                }
                                devices.insert(
                                    device_id,
                                    crate::auth::DeviceAuth {
                                        secret: secret.unwrap_or_default(),
                                        public_key: device_toml.public_key,
                                        created_at: device_toml.created_at.unwrap_or_else(
                                            crate::auth::config::default_created_at,
                                        ),
                                        last_used: device_toml.last_used,
                                        last_used_step: None,
                                    },
                                );
                            }
                            clients.insert(
                                id,
                                crate::auth::ClientAuth {
                                    secret: client_toml.secret,
                                    created_at: client_toml
                                        .created_at
                                        .unwrap_or_else(crate::auth::config::default_created_at),
                                    allow_hosts: client_toml.allow_hosts,
                                    allow_ports: client_toml.allow_ports,
                                    allow_ports_strict: client_toml
                                        .allow_ports_strict
                                        .unwrap_or(false),
                                    pending_enrollment: client_toml.pending_enrollment,
                                    devices,
                                    unnamed_device_allowed: client_toml
                                        .unnamed_device_allowed
                                        .unwrap_or(true),
                                    last_used: client_toml.last_used,
                                    last_used_step: None,
                                    // The step memory is not in the config
                                    // file: it is a counter, and the counters
                                    // live in the state file beside it.
                                    failed_attempts: client_toml.failed_attempts.unwrap_or(0),
                                    locked_until: client_toml.locked_until,
                                    enrollment_failed_attempts: 0,
                                    enrollment_locked_until: None,
                                },
                            );
                        }
                    }

                    // Refused rather than guessed. Both ends of the handshake
                    // read the same config, so a name nobody supports does not
                    // fail on one side and the other: the deployment just runs
                    // weaker than the operator wrote, and nothing says so.
                    let algorithm = match auth_toml.algorithm.as_deref().map(str::trim) {
                        None | Some("") | Some("sha1") | Some("SHA1") => {
                            crate::auth::TotpAlgorithm::SHA1
                        }
                        Some("sha256") | Some("SHA256") => crate::auth::TotpAlgorithm::SHA256,
                        Some("sha512") | Some("SHA512") => crate::auth::TotpAlgorithm::SHA512,
                        Some(other) => anyhow::bail!(
                            "algorithm {other:?} is not a TOTP algorithm; expected \"sha1\" \
                             (the default), \"sha256\" or \"sha512\""
                        ),
                    };

                    let time_step = auth_toml.time_step.unwrap_or(30);
                    let digits = auth_toml.digits.unwrap_or(6);
                    let window = auth_toml.window.unwrap_or(1);
                    crate::config::validate_totp_parameters(time_step, digits, window)?;

                    Some(crate::auth::AuthConfig {
                        enabled: auth_toml.enabled.unwrap_or(false),
                        issuer: auth_toml
                            .issuer
                            .unwrap_or_else(|| crate::auth::DEFAULT_ISSUER.to_string()),
                        algorithm,
                        time_step,
                        digits,
                        window,
                        clients,
                        max_attempts: auth_toml.max_attempts.unwrap_or(5),
                        lockout_duration: auth_toml.lockout_duration.unwrap_or(300),
                    })
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        Ok((base, auth_config))
    }
}

/// The configuration a store holds, and the 2FA half of it.
///
/// Both halves come from one read of the store, so the routes and the clients
/// are the same revision of it.
pub async fn load_config_with_auth(
    storage: &dyn Storage,
) -> anyhow::Result<(ProxyConfig, Option<AuthConfig>)> {
    let content = storage
        .config()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no configuration in {}", storage.describe()))?;

    let (config, mut auth) = ProxyConfig::parse_with_auth(&content, storage.base_dir())?;

    // The counters are the server's own, and they are read only when there is
    // a 2FA section to apply them to — a deployment without one has counted
    // nothing and has nothing to read.
    if let Some(auth_config) = auth.as_mut() {
        let state = storage.state().await?;
        crate::auth::state::apply(&state, auth_config);
    }

    Ok((config, auth))
}

/// The configuration a store holds.
///
/// The 2FA half is read as far as the port rules and no further: this is the
/// read for a caller that wants the routing and the settings and not the
/// credentials.
pub async fn load_config(storage: &dyn Storage) -> anyhow::Result<ProxyConfig> {
    let content = storage
        .config()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no configuration in {}", storage.describe()))?;

    let mut config: ProxyConfig = parse_config(content.expose_secret())
        .map_err(|e| anyhow::anyhow!("Failed to parse config file: {e:#}"))?;
    config.resolve_external_credentials(storage.base_dir())?;
    Ok(config)
}

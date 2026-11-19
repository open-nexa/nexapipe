//! The configuration as a store holds it, and the codecs that speak it.
//!
//! # Why a model at all
//!
//! The configuration used to be a file and nothing else, and the file was both
//! the way an operator wrote it and the way a program read it. Two stores
//! cannot both be that: a database has rows, and a row is not a file. So the
//! configuration became a **model** — one typed shape, in the middle — and the
//! things that hold it became **codecs**, one per storage:
//!
//! ```text
//! TOML text  <--toml codec-->  the model  <--sqlite codec-->  rows
//! ```
//!
//! The model is what a store keeps and what the server runs on, and the codecs
//! are the only places that know what a store looks like. The TOML codec is
//! here; the SQLite one comes with the database backend.
//!
//! # Why the model is the file's shape
//!
//! The model's types are the shapes in [`schema`] and [`super::auth_file`], so
//! a key is still named in exactly one place and a typo is still refused at the
//! parse. What the model adds is the other direction: it can be **written**,
//! not only read, which is what a store needs.
//!
//! # The credentials move, they are not copied
//!
//! The `[auth]` section holds the 2FA seeds, and the runtime holds them in
//! [`crate::auth::AuthConfig`] — its own shape, with every default filled in.
//! The model holds the file's shape of the same section, and
//! [`Config::take_auth`] **moves** the seeds from one to the other.
//!
//! Moving and not copying is the whole point. A configuration is cloned on
//! every request that needs it, and a copy that kept the seeds would be
//! another copy of every secret in the file, in the heap, for as long as the
//! process lives. So the model holds them only between the parse and the
//! split, and a configuration that has been loaded holds none.

use crate::auth::{AuthConfig, ClientAuth, DeviceAuth, TotpAlgorithm};

use nexapipe_proto::secret::SecretString;

use super::auth_file::{Auth, AuthClient, AuthDevice};
use super::schema::Config;

/// The TOTP algorithm a configuration asks for, refused rather than guessed.
///
/// Both ends of the handshake read the same configuration, so a name nobody
/// supports does not fail on one side and the other: the deployment just runs
/// weaker than the operator wrote, and nothing says so.
fn totp_algorithm(name: Option<&str>) -> anyhow::Result<TotpAlgorithm> {
    match name.map(str::trim) {
        None | Some("") | Some("sha1") | Some("SHA1") => Ok(TotpAlgorithm::SHA1),
        Some("sha256") | Some("SHA256") => Ok(TotpAlgorithm::SHA256),
        Some("sha512") | Some("SHA512") => Ok(TotpAlgorithm::SHA512),
        Some(other) => anyhow::bail!(
            "algorithm {other:?} is not a TOTP algorithm; expected \"sha1\" \
             (the default), \"sha256\" or \"sha512\""
        ),
    }
}

impl Auth {
    /// The runtime's own shape of this section.
    ///
    /// Every default the file leaves out is filled in here, and every rule
    /// that has to hold is checked here — where the operator is looking, and
    /// where the message can name the entry that is wrong.
    fn into_runtime(self) -> anyhow::Result<AuthConfig> {
        let algorithm = totp_algorithm(self.algorithm.as_deref())?;

        let time_step = self.time_step.unwrap_or(30);
        let digits = self.digits.unwrap_or(6);
        let window = self.window.unwrap_or(1);
        super::validate_totp_parameters(time_step, digits, window)?;

        let mut clients = std::collections::HashMap::new();
        for (id, client) in self.clients {
            // An empty token compares equal to an empty ENROLL_START — see
            // `conn::enroll_client` — so `pending_enrollment = ""` would hand a
            // fresh secret to anybody who asks. Refused at load time rather
            // than read as "no enrollment outstanding": the way to close an
            // enrollment is to delete the key, and a blank one is a typo with a
            // wide door behind it.
            if client
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
            // An allow-hosts entry is a host pattern, and a loose one
            // authorizes more than it names: the same refusal a route's
            // `host_pattern` gets.
            for host in client.allow_hosts.iter().flatten() {
                if let Some(why) = crate::routes::pattern_error(host) {
                    anyhow::bail!("[auth.clients.{id}]: allow_hosts entry {host:?} {why}");
                }
            }
            // A port of zero is not a port a client can ask for: no flow
            // arrives from it and no request names it, so an entry that lists
            // it authorizes nothing and looks like it authorizes something.
            if let Some(ports) = &client.allow_ports
                && ports.contains(&0)
            {
                anyhow::bail!(
                    "[auth.clients.{id}]: allow_ports contains port 0; no client \
                     ever asks for it, so that entry can never match"
                );
            }

            let mut devices = std::collections::HashMap::new();
            for (device_id, device) in client.devices {
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
                // `secret = ""` is read as no secret at all: an empty one is
                // not a credential, and an entry left holding only that is
                // refused below like one that has nothing.
                let secret = device.secret.filter(|s| !s.expose_secret().is_empty());
                match (&secret, &device.public_key) {
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
                        // Checked where the key would otherwise first be used:
                        // at a handshake, where a bad key and a wrong one are
                        // the same refusal.
                        if let Err(why) = crate::auth::parse_public_key(public_key) {
                            anyhow::bail!("[auth.clients.{id}.devices.{device_id}]: {why}");
                        }
                    }
                    (Some(_), None) => {}
                }
                devices.insert(
                    device_id,
                    DeviceAuth {
                        secret: secret.unwrap_or_default(),
                        public_key: device.public_key,
                        created_at: device
                            .created_at
                            .unwrap_or_else(crate::auth::config::default_created_at),
                        last_used: device.last_used,
                        last_used_step: None,
                        label: device.label,
                        platform: device.platform,
                        model: device.model,
                        app_version: device.app_version,
                    },
                );
            }

            clients.insert(
                id,
                ClientAuth {
                    secret: client.secret,
                    created_at: client
                        .created_at
                        .unwrap_or_else(crate::auth::config::default_created_at),
                    allow_hosts: client.allow_hosts,
                    allow_ports: client.allow_ports,
                    allow_ports_strict: client.allow_ports_strict.unwrap_or(false),
                    pending_enrollment: client.pending_enrollment,
                    pending_enrollment_expires_at: client.pending_enrollment_expires_at,
                    devices,
                    unnamed_device_allowed: client.unnamed_device_allowed.unwrap_or(true),
                    last_used: client.last_used,
                    last_used_step: None,
                    // The step memory is not in the configuration file: it is a
                    // counter, and the counters live in the state file beside
                    // it.
                    failed_attempts: client.failed_attempts.unwrap_or(0),
                    locked_until: client.locked_until,
                    enrollment_failed_attempts: 0,
                    enrollment_locked_until: None,
                },
            );
        }

        Ok(AuthConfig {
            enabled: self.enabled.unwrap_or(false),
            issuer: self
                .issuer
                .unwrap_or_else(|| crate::auth::DEFAULT_ISSUER.to_string()),
            algorithm,
            time_step,
            digits,
            window,
            clients,
            max_attempts: self.max_attempts.unwrap_or(5),
            lockout_duration: self.lockout_duration.unwrap_or(300),
        })
    }

    /// The file's shape of this section, from the runtime's own.
    ///
    /// The other direction of the same move: a store that holds the
    /// configuration as rows writes the clients back out of them, and a client
    /// is a row before it is a section.
    fn from_runtime(auth: &AuthConfig) -> Self {
        Auth {
            enabled: Some(auth.enabled),
            issuer: Some(auth.issuer.clone()),
            algorithm: Some(auth.algorithm.name().to_string()),
            time_step: Some(auth.time_step),
            digits: Some(auth.digits),
            window: Some(auth.window),
            max_attempts: Some(auth.max_attempts),
            lockout_duration: Some(auth.lockout_duration),
            clients: auth
                .clients
                .iter()
                .map(|(id, client)| {
                    (
                        id.clone(),
                        AuthClient {
                            secret: client.secret.clone(),
                            created_at: non_empty(&client.created_at),
                            allow_hosts: client.allow_hosts.clone(),
                            allow_ports: client.allow_ports.clone(),
                            allow_ports_strict: Some(client.allow_ports_strict),
                            pending_enrollment: client.pending_enrollment.clone(),
                            pending_enrollment_expires_at: client.pending_enrollment_expires_at,
                            devices: client
                                .devices
                                .iter()
                                .map(|(name, device)| {
                                    (
                                        name.clone(),
                                        AuthDevice {
                                            // A device that answers with a public
                                            // key has no secret, and an empty
                                            // one is not a credential.
                                            secret: non_empty_secret(&device.secret),
                                            public_key: device.public_key.clone(),
                                            created_at: non_empty(&device.created_at),
                                            last_used: device.last_used,
                                            label: device.label.clone(),
                                            platform: device.platform.clone(),
                                            model: device.model.clone(),
                                            app_version: device.app_version.clone(),
                                        },
                                    )
                                })
                                .collect(),
                            unnamed_device_allowed: Some(client.unnamed_device_allowed),
                            failed_attempts: Some(client.failed_attempts),
                            locked_until: client.locked_until,
                            last_used: client.last_used,
                        },
                    )
                })
                .collect(),
        }
    }
}

/// A string the file did not have, as `None` rather than as an empty one.
///
/// The file's shape says "absent" with an absent key, and a key that is
/// written as `""` is a key that was written.
fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// A secret that is there, as `Some`, and one that is not, as `None`.
fn non_empty_secret(value: &SecretString) -> Option<SecretString> {
    if value.expose_secret().is_empty() {
        None
    } else {
        Some(value.clone())
    }
}

impl Config {
    /// The configuration a file's text holds.
    ///
    /// The parse is the one the schema does, with the one error message it
    /// produces: a key this build does not know is named, and told what to do
    /// about it.
    pub fn from_toml_text(text: &str) -> anyhow::Result<Self> {
        super::parse_config(text)
    }

    /// The text of a configuration file, from this configuration.
    ///
    /// The inverse of [`Self::from_toml_text`], and the shape a store that
    /// keeps its configuration as rows hands back: the same TOML the file
    /// would have held, so every reader, every error message and every
    /// validation runs exactly once, in one place.
    pub fn to_toml_text(&self) -> anyhow::Result<String> {
        toml::to_string(self).map_err(|e| anyhow::anyhow!("the configuration does not write: {e}"))
    }

    /// Drops the `[auth]` section without reading it.
    ///
    /// For the read that wants the routing and the settings and not the
    /// credentials. The section is not validated here: a read that does not
    /// look at it has no business refusing it, and the read that does look at
    /// it is [`Self::take_auth`].
    ///
    /// Dropping it is also what keeps the seeds out of the copy the server
    /// keeps. A configuration that held them would be a second copy of every
    /// secret in the file, and this one is cloned on every request.
    pub fn drop_auth(&mut self) {
        self.auth = None;
    }

    /// Takes the `[auth]` section out of this configuration and turns it into
    /// the runtime's own shape.
    ///
    /// **The seeds move.** What is left behind is a configuration that holds
    /// no credential, and that is the copy the server keeps — the one that is
    /// cloned on every request, and that a `Debug` view of it must never show
    /// a seed in.
    ///
    /// `None` when the file has no `[auth]` section at all, which is not the
    /// same as "no credential": a file with an inline `[iroh]` key and no
    /// `[auth]` holds a credential in the open.
    pub fn take_auth(&mut self) -> anyhow::Result<Option<AuthConfig>> {
        let Some(auth) = self.auth.take() else {
            return Ok(None);
        };

        let runtime = auth.into_runtime()?;

        // Said here, at the one place every reader of the file passes
        // through. A port list held against the port a client *names* is a
        // weaker restriction than it looks — a request that names no port is
        // not checked at all — and the flag that says so is not in the name of
        // the setting.
        for client in runtime.clients_with_the_named_port_rule() {
            tracing::warn!(
                "[auth.clients.{client}] has an allow_ports list but allow_ports_strict is off: \
                 the list is checked against the port the client names, and a request that \
                 names no port is not checked at all. Set allow_ports_strict = true to check \
                 the port the request is served from"
            );
        }

        Ok(Some(runtime))
    }

    /// The configuration as a store holds it, from the one the server runs on.
    ///
    /// The other direction of [`Self::take_auth`]: the runtime's own shape of
    /// the credentials becomes the file's shape again, so a store can write
    /// out a configuration it read in.
    pub fn from_runtime(config: &Config, auth: Option<&AuthConfig>) -> Self {
        let mut model = config.clone();
        model.auth = auth.map(Auth::from_runtime);
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration that says everything a deployment can say.
    const FULL: &str = r#"
debug = true

[server]
listen_addr = "127.0.0.1:8080"

[admin]
listen_addr = "127.0.0.1:9090"

[iroh]
relay_mode = "custom"
secret_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[routes]]
host_pattern = "example.com"
backends = ["http://127.0.0.1:8081"]
path_rewrite = "/api"

[[routes]]
host_pattern = "*.example.org"
mode = "tcp"
backends = ["127.0.0.1:5432"]

[auth]
enabled = true
issuer = "nexapipe"
algorithm = "sha256"

[auth.clients.client-001]
secret = "JBSWY3DPEHPK3PXP"
allow_hosts = ["example.com"]
allow_ports = [443]
allow_ports_strict = true

[auth.clients.client-001.devices.laptop]
public_key = "5866666666666666666666666666666666666666666666666666666666666666"
created_at = "1700000000"

[log]
file = false
"#;

    /// The text of a configuration is the text it came from.
    ///
    /// Not byte for byte: the model writes out the sections it holds, so a
    /// file that left one out gets one. What has to survive is the meaning,
    /// and the way to say that is to write both out and compare the two texts.
    #[test]
    fn a_configuration_survives_its_own_text() {
        let config = Config::from_toml_text(FULL).expect("the config parses");
        let text = config.to_toml_text().expect("the config writes");
        let again = Config::from_toml_text(&text).expect("the text parses");

        assert_eq!(
            again.to_toml_text().expect("the config writes"),
            text,
            "the configuration changed on the way through its own text"
        );
    }

    /// The credentials survive the round trip.
    ///
    /// They are the reason the model exists: a store that keeps the
    /// configuration as rows has to be able to write the seeds back out, and a
    /// codec that dropped them would quietly un-enroll every client.
    #[test]
    fn the_credentials_survive_the_round_trip() {
        let config = Config::from_toml_text(FULL).expect("the config parses");
        let text = config.to_toml_text().expect("the config writes");
        let again = Config::from_toml_text(&text).expect("the text parses");

        let auth = again.auth.expect("the [auth] section is there");
        let client = &auth.clients["client-001"];
        assert_eq!(client.secret.expose_secret(), "JBSWY3DPEHPK3PXP");
        assert_eq!(
            client.allow_hosts.as_deref(),
            Some(&["example.com".to_string()][..])
        );
        assert_eq!(client.allow_ports, Some(vec![443]));
        assert_eq!(client.allow_ports_strict, Some(true));

        let device = &client.devices["laptop"];
        assert_eq!(
            device.public_key.as_deref(),
            Some("5866666666666666666666666666666666666666666666666666666666666666")
        );
        assert_eq!(device.created_at.as_deref(), Some("1700000000"));
    }

    /// The routes survive the round trip, one route to one entry.
    ///
    /// The order they were written in is kept: a route table an operator reads
    /// top to bottom is the one whose order means something.
    #[test]
    fn the_routes_survive_the_round_trip() {
        let config = Config::from_toml_text(FULL).expect("the config parses");
        let text = config.to_toml_text().expect("the config writes");
        let again = Config::from_toml_text(&text).expect("the text parses");

        let routes = again.routes.expect("the routes are there");
        assert_eq!(routes.len(), 2, "both routes are there");
        assert_eq!(routes[0].host_pattern, "example.com");
        assert_eq!(routes[0].backends, vec!["http://127.0.0.1:8081"]);
        assert_eq!(routes[0].path_rewrite.as_deref(), Some("/api"));
        assert_eq!(routes[1].host_pattern, "*.example.org");
        assert_eq!(routes[1].mode.as_deref(), Some("tcp"));
    }

    /// A configuration with no credentials writes no credentials.
    ///
    /// The `[auth]` section is absent, so the text has no section either: a
    /// store that keeps its configuration as rows must not invent a section
    /// the operator never wrote.
    #[test]
    fn a_configuration_without_credentials_writes_no_auth_section() {
        let config = Config::from_toml_text("[server]\nlisten_addr = \"127.0.0.1:8080\"\n")
            .expect("the config parses");
        let text = config.to_toml_text().expect("the config writes");

        assert!(
            !text.contains("[auth]"),
            "a section the file did not have was written: {text}"
        );
    }

    /// The runtime's shape of the credentials becomes the file's shape again.
    ///
    /// The other direction of the move the load does: what the server runs on
    /// is what a store writes back out.
    #[test]
    fn the_runtime_shape_becomes_the_file_shape_again() {
        let mut config = Config::from_toml_text(FULL).expect("the config parses");
        let runtime = config.take_auth().expect("the auth is read");
        let runtime = runtime.expect("the [auth] section is there");

        let model = Config::from_runtime(&config, Some(&runtime));
        let text = model.to_toml_text().expect("the config writes");

        assert!(
            text.contains("JBSWY3DPEHPK3PXP"),
            "the seed was left out of the written configuration: {text}"
        );
        assert!(
            text.contains("client-001"),
            "the client was left out of the written configuration: {text}"
        );
    }

    /// The seeds are not in the configuration the server keeps.
    ///
    /// They move into the runtime's shape, and the copy that is cloned on
    /// every request holds none.
    #[test]
    fn the_loaded_configuration_holds_no_seed() {
        let mut config = Config::from_toml_text(FULL).expect("the config parses");
        config.take_auth().expect("the auth is read");

        let debug = format!("{config:?}");
        assert!(
            !debug.contains("JBSWY3DPEHPK3PXP"),
            "the seed was copied into the configuration: {debug}"
        );
    }

    /// The configuration can be read from another format.
    ///
    /// The model's types are the ones a JSON document is read into as well, so
    /// a store that keeps the configuration as JSON — or as rows, and hands it
    /// over as JSON — is a store this build can read. The `[auth]` section is
    /// read through a deserializer of its own, and it used to read the section
    /// through a TOML value: an intermediate that cannot hold what JSON
    /// writes, so a configuration that arrived as JSON was refused with a
    /// message about a TOML value.
    #[test]
    fn a_configuration_can_be_read_from_json() {
        let config = Config::from_toml_text(FULL).expect("the config parses");
        let json = serde_json::to_string(&config).expect("the config writes as JSON");
        let again: Config = serde_json::from_str(&json).expect("the JSON parses");

        assert_eq!(
            again.to_toml_text().expect("the config writes"),
            config.to_toml_text().expect("the config writes"),
            "the configuration changed on the way through JSON"
        );
    }
}

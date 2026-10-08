//! Configuration structures for 2FA authentication.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// TOTP algorithm variants
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TotpAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl TotpAlgorithm {
    /// Canonical lowercase name, as used by `[auth] algorithm`, the clients and
    /// the `otpauth://` URI.
    pub fn name(&self) -> &'static str {
        match self {
            TotpAlgorithm::SHA1 => "sha1",
            TotpAlgorithm::SHA256 => "sha256",
            TotpAlgorithm::SHA512 => "sha512",
        }
    }
}

/// Main authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Whether 2FA is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Issuer label shown by authenticator apps that import the enrollment QR
    /// code produced by `nexapipe --generate-2fa`
    #[serde(default = "default_issuer")]
    pub issuer: String,
    /// TOTP algorithm to use
    #[serde(default)]
    pub algorithm: TotpAlgorithm,
    /// Time step in seconds (default: 30)
    #[serde(default = "default_time_step")]
    pub time_step: u32,
    /// Number of digits in the TOTP code
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// Tolerance window (number of time steps to accept)
    #[serde(default = "default_window")]
    pub window: u32,
    /// Client configurations
    #[serde(default)]
    pub clients: HashMap<String, ClientAuth>,
    /// Maximum authentication attempts before lockout
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Lockout duration in seconds
    #[serde(default = "default_lockout_duration")]
    pub lockout_duration: u64,
}

fn default_time_step() -> u32 {
    30
}
fn default_issuer() -> String {
    crate::auth::otpauth::DEFAULT_ISSUER.to_string()
}
fn default_digits() -> u32 {
    6
}
fn default_window() -> u32 {
    1
}
fn default_max_attempts() -> u32 {
    5
}
fn default_lockout_duration() -> u64 {
    300
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: default_issuer(),
            algorithm: TotpAlgorithm::default(),
            time_step: default_time_step(),
            digits: default_digits(),
            window: default_window(),
            clients: HashMap::new(),
            max_attempts: default_max_attempts(),
            lockout_duration: default_lockout_duration(),
        }
    }
}

/// Client authentication information
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    /// Base32-encoded secret key
    pub secret: String,
    /// When this client was created
    #[serde(default = "default_created_at")]
    pub created_at: String,
    /// Host patterns this client may reach; `None` means every route.
    ///
    /// The patterns use the same spelling as a route's `host_pattern` — an
    /// exact name or a `*.suffix` wildcard, case-insensitively — and are
    /// folded into a [`ClientAcl`] when a connection authenticates. An empty
    /// list denies every host: `allow_hosts = []` is "this client may
    /// connect and nothing else", not "no restriction".
    #[serde(default)]
    pub allow_hosts: Option<Vec<String>>,
    /// A one-time enrollment token waiting to be exchanged for a new secret.
    ///
    /// `None` means no enrollment is outstanding, so a client with no token
    /// cannot talk the server into issuing one: enrollment is only ever opened
    /// by `--generate-invite --registration`, which writes it here.
    #[serde(default)]
    pub pending_enrollment: Option<String>,
    /// Credentials issued to individual devices under this client.
    ///
    /// A device here authenticates with its own secret, and the `secret` above
    /// is the credential of the device that has no name — which is every device
    /// that existed before this table could be written, and why an empty table
    /// changes nothing about how such a client authenticates.
    ///
    /// What the table buys is the ability to drop one entry: a phone whose
    /// secret is removed here stops authenticating while the laptop next to it
    /// keeps its own, which is what rotating the one `secret` could not do.
    /// A device still falls back to the client's `secret`, so a client that
    /// wants per-device revocation has to stop handing that one out.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub devices: HashMap<String, DeviceAuth>,
    /// Last successful authentication time (Unix timestamp)
    #[serde(default)]
    pub last_used: Option<u64>,
    /// Number of failed attempts
    #[serde(default)]
    pub failed_attempts: u32,
    /// Lockout expiry time (Unix timestamp)
    #[serde(default)]
    pub locked_until: Option<u64>,
}

/// Handwritten so `secret` and `pending_enrollment` stay out of logs.
///
/// The whole config — this struct included — is logged at debug level whenever
/// it is parsed, and both fields are live credentials: the seed is half of a
/// client's second factor, and the token is the whole of it until someone
/// spends it. `Serialize` still round-trips both, which is what the config file
/// needs; only the `Debug` view is redacted.
impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("allow_hosts", &self.allow_hosts)
            .field(
                "pending_enrollment",
                &crate::config::redacted(&self.pending_enrollment),
            )
            .field("devices", &self.devices)
            .field("last_used", &self.last_used)
            .field("failed_attempts", &self.failed_attempts)
            .field("locked_until", &self.locked_until)
            .finish()
    }
}

/// One device under a client: a TOTP secret of its own.
///
/// Everything a [`ClientAuth`] is asked for, this is asked for too, and the
/// answer is the same shape — a secret issued by the server and a record of
/// when. What it does not carry is an `allow_hosts` of its own: what a client
/// may reach is one policy, answered by the client's entry, and a second place
/// to say it would only be a second place to disagree.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceAuth {
    /// Base32-encoded secret key, issued when this device enrolled.
    pub secret: String,
    /// When this device was issued its secret
    #[serde(default = "default_created_at")]
    pub created_at: String,
    /// Last successful authentication time (Unix timestamp)
    #[serde(default)]
    pub last_used: Option<u64>,
}

/// Same reason as [`ClientAuth`]'s, and the same consequence: the whole config
/// is logged when it is parsed, and a device secret is as live a credential as
/// a client's.
impl std::fmt::Debug for DeviceAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuth")
            .field("secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .finish()
    }
}

/// Shared with the loader in `crates/nexapipe/src/config.rs`, which fills in
/// the same "issued now" for a client or a device the file does not date.
pub(crate) fn default_created_at() -> String {
    unix_now().to_string()
}

impl AuthConfig {
    /// A copy carrying only the counters the config file is written back to.
    ///
    /// The whole config used to be cloned on every attempt worth counting, and
    /// a clone copies every client's secret and enrollment token with it — once
    /// per wrong code, from any peer that can name a client id. Only
    /// `failed_attempts`, `locked_until` and `last_used` are persisted, so only
    /// those travel. Extend this alongside `save_auth_state`, or a field added
    /// there is silently written as empty.
    pub fn counter_snapshot(&self) -> AuthConfig {
        AuthConfig {
            enabled: self.enabled,
            issuer: String::new(),
            algorithm: self.algorithm.clone(),
            time_step: self.time_step,
            digits: self.digits,
            window: self.window,
            clients: self
                .clients
                .iter()
                .map(|(id, client)| {
                    (
                        id.clone(),
                        ClientAuth {
                            secret: String::new(),
                            created_at: String::new(),
                            allow_hosts: None,
                            pending_enrollment: None,
                            // Empty for the same reason `secret` is: a snapshot
                            // exists so a wrong code does not copy a
                            // credential, and every device secret is one.
                            // Nothing written from a snapshot touches this
                            // table — `save_auth_state` moves three counters
                            // per client and leaves the rest of the file
                            // alone — so an empty one costs nothing.
                            devices: HashMap::new(),
                            last_used: client.last_used,
                            failed_attempts: client.failed_attempts,
                            locked_until: client.locked_until,
                        },
                    )
                })
                .collect(),
            max_attempts: self.max_attempts,
            lockout_duration: self.lockout_duration,
        }
    }
}

/// Seconds since the Unix epoch.
///
/// The fallible `SystemTime` dance is centralised here so the lockout rules
/// below read as arithmetic; a clock before 1970 is treated as 0, which only
/// means "long ago" to every comparison made with it.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl ClientAuth {
    /// Check if client is currently locked out
    pub fn is_locked_out(&self) -> bool {
        self.locked_until.is_some_and(|until| unix_now() < until)
    }

    /// Clears a lockout whose time has run out.
    ///
    /// Without this the counter stays where `record_failure` left it — at or
    /// above `max_attempts` — so the first mistake after a lockout expires locks
    /// the client out again immediately, and every lockout after the first is
    /// one attempt long.
    pub fn refresh_lockout(&mut self) {
        let now = unix_now();
        if self.locked_until.is_some_and(|until| until <= now) {
            self.locked_until = None;
            self.failed_attempts = 0;
        }
    }

    /// Record a failed authentication attempt
    pub fn record_failure(&mut self, max_attempts: u32, lockout_duration: u64) {
        self.failed_attempts += 1;
        if self.failed_attempts >= max_attempts {
            self.locked_until = Some(unix_now() + lockout_duration);
        }
    }

    /// Reset failed attempts on successful authentication
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.locked_until = None;
        self.last_used = Some(unix_now());
    }

    /// Decode the Base32 secret into bytes.
    ///
    /// The stored spelling is normalised first. An invite puts the secret
    /// through `otpauth::normalize_secret`, which tolerates lower case and `=`
    /// padding, so a secret written either of those ways in the config has to
    /// work as well — otherwise it fails to decode here and the client is stuck
    /// at "Invalid Base32 secret" with nothing saying the spelling is why.
    pub fn decode_secret(&self) -> Result<Vec<u8>, anyhow::Error> {
        let secret = crate::auth::otpauth::normalize_secret(&self.secret)
            .ok_or_else(|| anyhow::anyhow!("Invalid Base32 secret"))?;
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret)
            .ok_or_else(|| anyhow::anyhow!("Invalid Base32 secret"))
    }

    /// The host authorization for a connection authenticated as this client.
    ///
    /// Built once per connection, not consulted per stream, so a reload that
    /// removes the client — or its `allow_hosts` — does not change what a
    /// connection already holding its credentials may reach.
    pub fn acl(&self) -> ClientAcl {
        ClientAcl::from_hosts(self.allow_hosts.as_deref())
    }
}

/// A fresh one-time enrollment token: 32 random bytes, hex-encoded.
///
/// Wide enough that guessing one is not a strategy, and opaque — it is
/// compared, never parsed, so its spelling is free to change.
pub fn generate_enrollment_token() -> String {
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        *byte = rand::random();
    }
    hex::encode(bytes)
}

/// Which hosts one authenticated client may reach.
///
/// 2FA answers *who* may connect; this answers *what they may touch once they
/// have*. Without it, one client's secret is a key to every route and every
/// backend, so a single leaked enrollment is a full-backend compromise. A
/// client with no `allow_hosts` is [`ClientAcl::Unrestricted`] — the historical
/// behaviour, kept as the default so existing configs mean what they meant.
///
/// The patterns are folded and matched by the same rules a route's
/// `host_pattern` uses ([`crate::routes::host_matches`]), so an entry here
/// authorizes exactly the hosts the corresponding route entry would serve.
///
/// A denial is always reported to the client the way "no route" is — 404,
/// `Status::NoRoute`, or a hang-up — never a 403, which would confirm to a
/// compromised client that the host it asked for exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAcl {
    /// No `allow_hosts` configured: every route is fair game.
    Unrestricted,
    /// Only hosts matching one of these folded patterns.
    Restricted(Vec<String>),
}

impl ClientAcl {
    /// Folds `hosts` into an ACL. `None` is unrestricted; an empty list
    /// restricts to nothing.
    pub fn from_hosts(hosts: Option<&[String]>) -> Self {
        match hosts {
            None => ClientAcl::Unrestricted,
            Some(hosts) => ClientAcl::Restricted(
                hosts
                    .iter()
                    .map(|h| crate::routes::normalize_host(h))
                    .collect(),
            ),
        }
    }

    /// Whether `host` may be reached by a client governed by this ACL.
    pub fn allows(&self, host: &str) -> bool {
        match self {
            ClientAcl::Unrestricted => true,
            ClientAcl::Restricted(patterns) => {
                let host = crate::routes::normalize_host(host);
                patterns
                    .iter()
                    .any(|pattern| crate::routes::host_matches(pattern, &host))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> ClientAuth {
        ClientAuth {
            secret: String::new(),
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

    #[test]
    fn a_secret_decodes_the_way_an_invite_writes_it() {
        // An invite hands the secret through `normalize_secret`, which drops
        // the padding and folds the case. A config written either of those ways
        // has to decode too, or the client is stuck at "Invalid Base32 secret"
        // with nothing pointing at the spelling.
        let mut lower = client();
        lower.secret = "jbswy3dpehpk3pxp".to_string();
        let mut padded = client();
        padded.secret = "my======".to_string();
        let mut plain = client();
        plain.secret = "JBSWY3DPEHPK3PXP".to_string();

        assert_eq!(
            lower.decode_secret().unwrap(),
            plain.decode_secret().unwrap()
        );
        assert_eq!(padded.decode_secret().unwrap(), b"f");
    }

    /// `Debug` is what a log line uses, and the whole config — this struct
    /// included — is logged whenever it is parsed. Both redacted fields are
    /// live credentials: the seed is half of a second factor, and the token is
    /// the whole of one until somebody spends it.
    #[test]
    fn a_client_prints_no_credentials() {
        let mut c = client();
        c.secret = "JBSWY3DPEHPK3PXP".to_string();
        c.pending_enrollment = Some("deadbeef".to_string());

        let rendered = format!("{c:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"), "{rendered}");
        assert!(!rendered.contains("deadbeef"), "{rendered}");
    }

    #[test]
    fn a_lockout_that_ran_out_leaves_nothing_behind() {
        let mut c = client();
        c.failed_attempts = 3;
        c.locked_until = Some(unix_now() - 1);

        c.refresh_lockout();

        assert!(!c.is_locked_out());
        assert_eq!(c.locked_until, None);
        // The counter has to go with it, or the next single failure — one
        // attempt instead of `max_attempts` — locks the client out again.
        assert_eq!(c.failed_attempts, 0);
    }

    #[test]
    fn a_lockout_still_running_is_left_alone() {
        let mut c = client();
        c.failed_attempts = 3;
        c.locked_until = Some(unix_now() + 60);

        c.refresh_lockout();

        assert!(c.is_locked_out());
        assert_eq!(c.failed_attempts, 3);
    }

    #[test]
    fn refreshing_a_client_that_was_never_locked_out_changes_nothing() {
        let mut c = client();
        c.failed_attempts = 2;

        c.refresh_lockout();

        assert_eq!(c.failed_attempts, 2, "a partial counter is not a lockout");
        assert!(!c.is_locked_out());
    }

    /// A client with no `allow_hosts` keeps the historical reach: every host.
    #[test]
    fn an_absent_allow_hosts_leaves_a_client_unrestricted() {
        let acl = ClientAcl::from_hosts(None);
        assert_eq!(acl, ClientAcl::Unrestricted);
        assert!(acl.allows("anything.test"));
        assert_eq!(client().acl(), ClientAcl::Unrestricted);
    }

    /// The patterns mean what a route's `host_pattern` means: exact or
    /// `*.suffix`, case-insensitively, ignoring a fully-qualified trailing dot.
    #[test]
    fn restricted_patterns_match_the_way_routes_do() {
        let acl = ClientAcl::from_hosts(Some(&[
            "api.example.com".to_string(),
            "*.db.example.com".to_string(),
        ]));

        assert!(acl.allows("api.example.com"));
        assert!(acl.allows("API.Example.Com"), "hosts fold like route hosts");
        assert!(
            acl.allows("api.example.com."),
            "a trailing FQDN dot is not a different host"
        );
        assert!(acl.allows("pg.db.example.com"));
        assert!(
            !acl.allows("db.example.com"),
            "the wildcard needs the *. prefix, like a route"
        );
        assert!(!acl.allows("db.example.com.evil.test"));
        assert!(!acl.allows("admin.example.com"));
    }

    /// `allow_hosts = []` is "may connect, may touch nothing", not "no
    /// restriction" — otherwise a typo in the list would silently publish a
    /// client's reach to every backend.
    #[test]
    fn an_empty_allow_hosts_denies_every_host() {
        let acl = ClientAcl::from_hosts(Some(&[]));
        assert!(!acl.allows("api.example.com"));
        assert!(!acl.allows("anything.test"));
    }

    /// The patterns themselves are folded, so a config written with uppercase
    /// letters answers the lowercase request.
    #[test]
    fn patterns_are_folded_when_the_acl_is_built() {
        let acl = ClientAcl::from_hosts(Some(&["API.Example.Com.".to_string()]));
        assert!(acl.allows("api.example.com"));
    }

    /// The fallback path, and the only one that existed before: a client with
    /// no device table keeps authenticating against its own `secret`, because
    /// an unnamed device has nowhere else to look.
    #[test]
    fn a_client_without_a_device_table_has_none() {
        let parsed: ClientAuth =
            toml::from_str(r#"secret = "JBSWY3DPEHPK3PXP""#).expect("a plain client still parses");

        assert!(parsed.devices.is_empty(), "{parsed:?}");
        assert_eq!(parsed.secret, "JBSWY3DPEHPK3PXP");
    }

    /// The table is spelled the way a `[auth.clients.<id>]` entry nests it, so
    /// what this test parses is what an operator writes.
    #[test]
    fn a_device_table_parses_into_named_devices() {
        let parsed: ClientAuth = toml::from_str(
            r#"
            secret = "CLIENTSECRET"

            [devices.laptop]
            secret = "LAPTOPSECRET"

            [devices.phone]
            secret = "PHONESECRET"
            created_at = "1700000000"
            "#,
        )
        .expect("a device table parses");

        assert_eq!(parsed.devices.len(), 2);
        assert_eq!(parsed.devices["laptop"].secret, "LAPTOPSECRET");
        assert_eq!(parsed.devices["phone"].created_at, "1700000000");
        // Issued-at is filled in when the config does not say, the way a
        // client's is: a device with an empty one looks never-issued.
        assert!(
            !parsed.devices["laptop"].created_at.is_empty(),
            "{parsed:?}"
        );
    }

    /// `Debug` is what a log line uses, and the whole config is logged when it
    /// is parsed. A device secret is as live a credential as a client's — it
    /// authenticates on its own — so it is redacted for the same reason.
    #[test]
    fn a_device_secret_is_no_more_printable_than_a_clients() {
        let mut c = client();
        c.secret = "CLIENTSECRET".to_string();
        c.devices
            .insert("laptop".to_string(), device("LAPTOPSECRET"));

        let rendered = format!("{c:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("CLIENTSECRET"), "{rendered}");
        assert!(!rendered.contains("LAPTOPSECRET"), "{rendered}");
    }

    /// `counter_snapshot` exists so that counting a wrong code does not copy a
    /// credential, and the table is the place a new field gets forgotten: it
    /// is one level further from the field the comment was written about.
    #[test]
    fn a_counter_snapshot_carries_no_device_secret() {
        let mut c = client();
        c.devices
            .insert("laptop".to_string(), device("LAPTOPSECRET"));
        let config = AuthConfig {
            enabled: true,
            clients: HashMap::from([("alice".to_string(), c)]),
            ..AuthConfig::default()
        };

        let snapshot = config.counter_snapshot();

        assert!(snapshot.clients["alice"].devices.is_empty(), "{snapshot:?}");
        assert!(snapshot.clients["alice"].secret.is_empty());
    }
}

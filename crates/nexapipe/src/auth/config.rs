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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn default_created_at() -> String {
    unix_now().to_string()
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

    /// Decode the Base32 secret into bytes
    pub fn decode_secret(&self) -> Result<Vec<u8>, anyhow::Error> {
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &self.secret)
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
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        }
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
        assert!(acl.allows("api.example.com."), "a trailing FQDN dot is not a different host");
        assert!(acl.allows("pg.db.example.com"));
        assert!(!acl.allows("db.example.com"), "the wildcard needs the *. prefix, like a route");
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
}

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
        base32::decode(base32::Alphabet::RFC4648 { padding: false }, &self.secret)
            .ok_or_else(|| anyhow::anyhow!("Invalid Base32 secret"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> ClientAuth {
        ClientAuth {
            secret: String::new(),
            created_at: "0".to_string(),
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
}

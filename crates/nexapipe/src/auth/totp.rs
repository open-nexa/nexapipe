//! TOTP validation logic.

use super::config::{AuthConfig, TotpAlgorithm};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use totp_rs::{Algorithm, Builder, Secret};

/// HMAC-SHA256 keyed by the client's TOTP secret.
type HmacSha256 = Hmac<Sha256>;

/// How far an AUTH_RESPONSE timestamp may sit from the server clock, in
/// seconds. The signature already pins the response to one challenge; the
/// timestamp bounds how long even a correctly signed response stays
/// acceptable, so an intercepted one cannot be replayed next week.
const TIMESTAMP_WINDOW_SECS: i64 = 30;

/// TOTP validator for verifying client codes.
///
/// Borrows the [`AuthConfig`] it validates against: the config is shared and
/// mutated by the connection layer (lockout counters), so owning a clone here
/// would both copy the whole client map per connection and validate against a
/// snapshot nobody can correct.
pub struct TotpValidator<'a> {
    config: &'a AuthConfig,
}

impl<'a> TotpValidator<'a> {
    /// Create a new TOTP validator borrowing the given config.
    pub fn new(config: &'a AuthConfig) -> Self {
        Self { config }
    }

    /// Get the TOTP algorithm from config
    fn get_algorithm(&self) -> Algorithm {
        match self.config.algorithm {
            TotpAlgorithm::SHA1 => Algorithm::SHA1,
            TotpAlgorithm::SHA256 => Algorithm::SHA256,
            TotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }

    /// Verifies one AUTH_RESPONSE against the challenge this connection
    /// issued.
    ///
    /// Everything a response must prove is checked here, in order: the client
    /// is known and not locked out, its secret decodes, its timestamp is
    /// fresh, its signature matches HMAC-SHA256(secret, nonce || timestamp),
    /// and finally the TOTP code is current. Only the last step can return
    /// `Ok(false)`: a wrong code is a user mistake and counts toward the
    /// lockout, while every `Err` is a refusal the caller logs instead of
    /// counting.
    ///
    /// `device_id` says which credential under that client is being proven:
    /// `None` is the device that has no name and answers with the client's own
    /// `secret`, which is what every device used before a client could carry a
    /// table of them. A name selects that device's secret, and a name the
    /// table does not carry is refused rather than falling back — dropping a
    /// device from the table is how it is revoked, and a fallback would let it
    /// back in under the name it no longer has.
    ///
    /// Which device authenticated changes nothing about the lockout: the
    /// counter is the client's, so a device cannot escape it by naming itself
    /// something new, and a device nobody has ever issued cannot be used to
    /// walk the counter up.
    pub fn verify_response(
        &self,
        client_id: &str,
        device_id: Option<&str>,
        nonce: &[u8],
        timestamp: i64,
        signature: &[u8],
        code: &str,
    ) -> Result<bool, AuthError> {
        if !self.config.enabled {
            return Ok(true);
        }

        let client = self
            .config
            .clients
            .get(client_id)
            .ok_or(AuthError::ClientNotFound)?;

        if client.is_locked_out() {
            return Err(AuthError::LockedOut);
        }

        // A name that is not in the table is "no such device", not "no name" —
        // the two are told apart by `Option` on the wire, and only the second
        // one falls back. A name that is not printable ASCII is not in the
        // table either, so it lands here as well; what keeps it out of the log
        // is that this error carries no name.
        //
        // The fallback is the credential no revocation can reach: `client
        // revoke --device` strikes one entry out of `devices` and leaves the
        // shared `secret` standing, so a secret that leaked through an invite
        // link keeps working for as long as whoever has it simply omits the
        // name. `unnamed_device_allowed = false` is how an operator says this
        // client has stopped handing that secret out, and makes revoking a
        // device mean what it reads as meaning.
        let secret = match device_id {
            None if !client.unnamed_device_allowed => {
                return Err(AuthError::UnnamedDeviceNotAllowed);
            }
            None => client.decode_secret(),
            Some(name) => client
                .devices
                .get(name)
                .ok_or(AuthError::UnknownDevice)?
                .decode_secret(),
        }
        .map_err(|_| AuthError::InvalidSecret)?;

        // `timestamp` arrives from the client, so the subtraction is attacker
        // controlled: `now - i64::MIN` overflows, which panics in a debug build
        // and wraps in release. `abs_diff` cannot overflow — the distance
        // between two i64 values always fits in a u64.
        let now = current_timestamp();
        if now.abs_diff(timestamp) > TIMESTAMP_WINDOW_SECS as u64 {
            return Err(AuthError::StaleTimestamp);
        }

        let expected = hmac_signature(&secret, nonce, timestamp)?;
        if !constant_time_eq(signature, &expected) {
            return Err(AuthError::ChallengeMismatch);
        }

        // `Builder` narrows two of these: 5.x took `digits` as a `usize` and
        // `skew` as a `u8`, 6.0 takes a `u8` and a `u16`. Converting rather
        // than casting keeps a config that does not fit from being truncated
        // into a plausible one — a `digits` of 262 would otherwise read as 6
        // and issue codes nobody asked for.
        let digits = u8::try_from(self.config.digits).map_err(|_| AuthError::TotpCreationFailed)?;
        let skew = u16::try_from(self.config.window).map_err(|_| AuthError::TotpCreationFailed)?;

        let totp = Builder::new()
            .with_algorithm(self.get_algorithm())
            .with_digits(digits)
            .with_skew(skew)
            .with_step_duration(self.config.time_step as u64)
            .with_secret(secret)
            .build()
            .map_err(|_| AuthError::TotpCreationFailed)?;

        // `check_current` answers with the step it matched on — `Some` is the
        // "yes" this used to get as a `bool`, and the step itself is nothing
        // an AUTH_RESPONSE is asking about.
        Ok(totp.check_current(code).is_some())
    }

    /// Generate a new TOTP secret for a client (for setup)
    pub fn generate_secret() -> String {
        // Unpadded base32, the same spelling `decode_secret` reads back.
        Secret::generate().to_base32()
    }
}

/// The signature a client attaches to AUTH_RESPONSE:
/// HMAC-SHA256(secret, nonce || timestamp.to_le_bytes()).
///
/// Keep in sync with `TwoFactorAuth::sign_challenge` in
/// `crates/nexapipe-client/src/auth.rs`.
pub(crate) fn hmac_signature(
    secret: &[u8],
    nonce: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, AuthError> {
    // Fallible in the type only: HMAC takes a key of any length — a long one is
    // hashed, a short one is zero-padded — so this has never failed. It is
    // returned rather than `expect`ed because it runs inside a handshake, where
    // a panic would drop the connection with nothing to report.
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AuthError::InvalidSecret)?;
    mac.update(nonce);
    mac.update(&timestamp.to_le_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Length-safe constant-time comparison: an HMAC-SHA256 tag is never secret
/// in length (32 bytes), but comparing it byte-wise stops the first mismatch
/// from leaking how many leading bytes were right.
///
/// Reused for the admin token, which is compared the same way for the same
/// reason: a token guessed one byte at a time should not be told how far it
/// got.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Authentication errors
#[derive(Debug, Clone)]
pub enum AuthError {
    ClientNotFound,
    /// The response names a device this client has no credential for — either
    /// one was never issued to it, or its entry has been dropped.
    ///
    /// Deliberately carries no name: it is answered to a name the peer chose,
    /// which is not a name this process has agreed to print.
    UnknownDevice,
    InvalidSecret,
    TotpCreationFailed,
    LockedOut,
    InvalidCode,
    /// The response timestamp sits outside the acceptance window.
    StaleTimestamp,
    /// The response signature does not match the challenge that was issued.
    ChallengeMismatch,
    /// The response names no device and this client has been configured to
    /// answer only named ones, so the shared `secret` is not a credential here.
    UnnamedDeviceNotAllowed,
    ProtocolError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::ClientNotFound => write!(f, "Client not found"),
            AuthError::UnknownDevice => write!(f, "No device of that name under this client"),
            AuthError::InvalidSecret => write!(f, "Invalid secret configuration"),
            AuthError::TotpCreationFailed => write!(f, "Failed to create TOTP validator"),
            AuthError::LockedOut => {
                write!(f, "Client is locked out due to too many failed attempts")
            }
            AuthError::InvalidCode => write!(f, "Invalid TOTP code"),
            AuthError::StaleTimestamp => write!(
                f,
                "Response timestamp is more than {TIMESTAMP_WINDOW_SECS}s away from the server clock"
            ),
            AuthError::ChallengeMismatch => {
                write!(f, "Response signature does not match the challenge")
            }
            AuthError::UnnamedDeviceNotAllowed => {
                write!(f, "This client answers only to a named device")
            }
            AuthError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::ClientAuth;
    use std::collections::HashMap;

    fn config_with_one_client() -> AuthConfig {
        let client = ClientAuth {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            created_at: String::new(),
            allow_hosts: None,
            pending_enrollment: None,
            devices: HashMap::new(),
            unnamed_device_allowed: true,
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        };

        AuthConfig {
            enabled: true,
            clients: HashMap::from([("alice".to_string(), client)]),
            ..AuthConfig::default()
        }
    }

    /// A client that has issued a credential to one named device. 160-bit
    /// secrets, because `totp-rs` refuses to build a validator from anything
    /// shorter than 128 bits — and the tests below reach the TOTP check.
    fn config_with_one_device() -> AuthConfig {
        let client = ClientAuth {
            secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
            created_at: String::new(),
            allow_hosts: None,
            pending_enrollment: None,
            devices: HashMap::from([(
                "laptop".to_string(),
                crate::auth::DeviceAuth {
                    secret: "KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP".to_string(),
                    created_at: String::new(),
                    last_used: None,
                },
            )]),
            unnamed_device_allowed: true,
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        };

        AuthConfig {
            enabled: true,
            clients: HashMap::from([("alice".to_string(), client)]),
            ..AuthConfig::default()
        }
    }

    /// The nonce a test signs over, minted the way the connection layer mints
    /// its challenge (`conn::perform_authentication` draws 32 random bytes).
    ///
    /// These two tests never reach the signature check, so a literal would do
    /// — but a constant sitting in a nonce slot is exactly what CWE-798 is
    /// about, and it would be the one place in the tree where the challenge is
    /// the same twice.
    fn fresh_nonce() -> Vec<u8> {
        (0..32).map(|_| rand::random::<u8>()).collect()
    }

    #[test]
    fn a_timestamp_at_the_bottom_of_the_range_is_refused_rather_than_fatal() {
        let config = config_with_one_client();
        let validator = TotpValidator::new(&config);

        let nonce = fresh_nonce();

        // i64::MIN overflows `now - timestamp` — a panic in a debug build, a
        // wrap in release, and reachable without authenticating.
        let outcome =
            validator.verify_response("alice", None, &nonce, i64::MIN, b"signature", "000000");

        assert!(matches!(outcome, Err(AuthError::StaleTimestamp)));
    }

    #[test]
    fn a_timestamp_at_the_top_of_the_range_is_refused_rather_than_fatal() {
        let config = config_with_one_client();
        let validator = TotpValidator::new(&config);

        let nonce = fresh_nonce();
        let outcome =
            validator.verify_response("alice", None, &nonce, i64::MAX, b"signature", "000000");

        assert!(matches!(outcome, Err(AuthError::StaleTimestamp)));
    }

    /// Which secret a named device is checked against: its own, not the
    /// client's. This is the whole of what revoking a device rests on — a
    /// device whose entry is dropped must not be able to answer with the
    /// client's secret instead, and it cannot, because the name it sends is
    /// what decides which key the signature is compared with.
    #[test]
    fn a_named_device_is_checked_against_its_own_secret() {
        let config = config_with_one_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        let laptop = hmac_signature(
            &config.clients["alice"].devices["laptop"]
                .decode_secret()
                .unwrap(),
            &nonce,
            timestamp,
        )
        .unwrap();
        let clients_own = hmac_signature(
            &config.clients["alice"].decode_secret().unwrap(),
            &nonce,
            timestamp,
        )
        .unwrap();

        // Signed with the laptop's secret under the laptop's name: the
        // signature is the one expected, so the verdict is the code's.
        let outcome = validator.verify_response(
            "alice",
            Some("laptop"),
            &nonce,
            timestamp,
            &laptop,
            "000000",
        );
        assert!(matches!(outcome, Ok(false)), "{outcome:?}");

        // The same name, signed with the client's own secret: a mismatch, not
        // a fallback.
        let outcome = validator.verify_response(
            "alice",
            Some("laptop"),
            &nonce,
            timestamp,
            &clients_own,
            "000000",
        );
        assert!(
            matches!(outcome, Err(AuthError::ChallengeMismatch)),
            "{outcome:?}"
        );
    }

    /// A name the table does not carry is refused rather than falling back to
    /// the client's secret. Falling back would make a revoked device's name
    /// its way back in, and would let a peer that never enrolled answer as
    /// the device that has no name.
    #[test]
    fn a_device_name_the_client_does_not_carry_is_refused() {
        let config = config_with_one_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        // A name nothing will ever match, including one that is not printable
        // ASCII: it is not in the table either, so it is refused here without
        // ever reaching a log line that would print it.
        for name in ["phone", "laptop\r\nINFO: enrolled", ""] {
            let outcome = validator.verify_response(
                "alice",
                Some(name),
                &nonce,
                timestamp,
                b"signature",
                "000000",
            );
            assert!(
                matches!(outcome, Err(AuthError::UnknownDevice)),
                "{name:?} must not resolve, got {outcome:?}"
            );
        }
    }

    /// The fallback, and the only path that existed before: no name sent means
    /// the device that has none, and it answers with the client's own secret.
    #[test]
    fn an_unnamed_device_is_checked_against_the_clients_secret() {
        let config = config_with_one_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        let clients_own = hmac_signature(
            &config.clients["alice"].decode_secret().unwrap(),
            &nonce,
            timestamp,
        )
        .unwrap();

        let outcome =
            validator.verify_response("alice", None, &nonce, timestamp, &clients_own, "000000");
        assert!(matches!(outcome, Ok(false)), "{outcome:?}");
    }

    /// The fallback is a credential no revocation can reach: `client revoke
    /// --device` strikes one entry out of the device table and leaves the
    /// client's own `secret` standing, so a secret that leaked keeps working
    /// for anyone who simply omits the name. `unnamed_device_allowed = false`
    /// is what closes it, and it has to close it *before* the secret is
    /// decoded — being refused must not depend on the code being wrong.
    #[test]
    fn a_client_that_answers_only_to_named_devices_refuses_an_unnamed_one() {
        let mut config = config_with_one_device();
        config
            .clients
            .get_mut("alice")
            .unwrap()
            .unnamed_device_allowed = false;
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();
        let clients_own = hmac_signature(
            &config.clients["alice"].decode_secret().unwrap(),
            &nonce,
            timestamp,
        )
        .unwrap();

        let outcome =
            validator.verify_response("alice", None, &nonce, timestamp, &clients_own, "000000");
        assert!(
            matches!(outcome, Err(AuthError::UnnamedDeviceNotAllowed)),
            "{outcome:?}"
        );
    }

    /// The same client still answers a device that names itself, which is the
    /// point: the switch takes away the shared credential, not the client.
    #[test]
    fn that_client_still_answers_a_device_that_names_itself() {
        let mut config = config_with_one_device();
        config
            .clients
            .get_mut("alice")
            .unwrap()
            .unnamed_device_allowed = false;
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();
        let laptop = hmac_signature(
            &config.clients["alice"].devices["laptop"]
                .decode_secret()
                .unwrap(),
            &nonce,
            timestamp,
        )
        .unwrap();

        let outcome = validator.verify_response(
            "alice",
            Some("laptop"),
            &nonce,
            timestamp,
            &laptop,
            "000000",
        );
        assert!(matches!(outcome, Ok(false)), "{outcome:?}");
    }

    /// The default has to stay permissive, or every client that predates the
    /// device table — which is every client issued before 0.6.0 — loses its
    /// only credential on upgrade.
    #[test]
    fn an_unnamed_device_is_allowed_unless_the_config_says_otherwise() {
        let config = config_with_one_device();
        assert!(config.clients["alice"].unnamed_device_allowed);
    }
}

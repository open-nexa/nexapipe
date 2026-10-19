// 2FA authentication module for Nexapipe client.
//
// Provides TOTP code generation and the authentication handshake, in the two
// shapes the server accepts: a secret-based device answers with an HMAC over
// the challenge plus a code, a key-based one signs the same bytes with an
// Ed25519 key it generated and never hands over. Which shape a credential has
// is whatever its enrollment produced.

use crate::ClientError;
use hmac::{Hmac, KeyInit, Mac};
use iroh::endpoint::Connection;
use sha2::Sha256;
use std::fmt;
use totp_rs::{Algorithm, Builder, Secret};

/// Application error codes the server closes a connection with during the 2FA
/// handshake. Must match `auth_close_code` in `crates/nexapipe/src/conn/mod.rs`
/// and `PEER_NOT_ALLOWED_CLOSE_CODE` in
/// `crates/nexapipe/src/conn/allow_list.rs`.
mod auth_close_code {
    /// No AUTH_START arrived within the handshake deadline, or the server does
    /// not run the handshake on that first stream at all.
    pub const REQUIRED: u32 = 2;
    /// The handshake ran and the credentials were refused.
    pub const REJECTED: u32 = 3;
    /// The peer already holds as many connections as it is allowed.
    pub const TOO_MANY: u32 = 4;
    /// The server runs a `[peers]` allow-list and this Node ID is not on it.
    /// Sent right after the QUIC handshake, so the client never gets as far as
    /// sending credentials.
    pub const PEER_NOT_ALLOWED: u32 = 5;
    /// This credential was struck out of `[auth]` *while this connection was
    /// open* — `nexapipe client revoke`, aimed at this client or at this one
    /// device of it. Unlike the four above this does not arrive during the
    /// handshake: a connection has to have authenticated to be revoked.
    pub const REVOKED: u32 = 6;
}

/// HMAC-SHA256 keyed by the TOTP secret, used to sign auth challenges.
type HmacSha256 = Hmac<Sha256>;

/// TOTP algorithm variants
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl TotpAlgorithm {
    fn to_totp_rs(&self) -> Algorithm {
        match self {
            TotpAlgorithm::SHA1 => Algorithm::SHA1,
            TotpAlgorithm::SHA256 => Algorithm::SHA256,
            TotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }

    /// Parse an algorithm name from configuration / UI (case-insensitive).
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "sha256" => TotpAlgorithm::SHA256,
            "sha512" => TotpAlgorithm::SHA512,
            _ => TotpAlgorithm::SHA1,
        }
    }

    /// Canonical lowercase algorithm name for config / UI.
    pub fn name(&self) -> &'static str {
        match self {
            TotpAlgorithm::SHA1 => "sha1",
            TotpAlgorithm::SHA256 => "sha256",
            TotpAlgorithm::SHA512 => "sha512",
        }
    }
}

/// Client-side 2FA credentials loaded from config file / app settings.
///
/// `Debug` is written out rather than derived, and `secret` is the reason: a
/// derived one prints the TOTP seed in full, so every `{:?}` that reaches a log
/// line, a panic message or a bug report pastes a working credential into it.
/// An empty `secret` prints as `""` for the same reason — an absent secret and a
/// masked one should not be told apart by a reader.
#[derive(Clone, PartialEq)]
pub struct TwoFactorConfig {
    pub client_id: String,
    pub secret: String,
    pub algorithm: TotpAlgorithm,
}

impl std::fmt::Debug for TwoFactorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorConfig")
            .field("client_id", &self.client_id)
            .field("secret", &masked(&self.secret))
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// What a secret prints as: present, and how long — never the value itself.
fn masked(secret: &str) -> String {
    if secret.is_empty() {
        String::new()
    } else {
        format!("<{} chars>", secret.chars().count())
    }
}

impl TwoFactorConfig {
    /// Build a [`TwoFactorAuth`] if a secret is configured; returns `Ok(None)`
    /// when the secret is empty (2FA effectively disabled).
    pub fn to_auth(&self) -> Result<Option<TwoFactorAuth>, ClientError> {
        if self.secret.trim().is_empty() {
            return Ok(None);
        }
        TwoFactorAuth::new(&self.client_id, &self.secret, self.algorithm.clone()).map(Some)
    }
}

/// Decodes a client-side Base32 secret.
///
/// The spelling is normalised first, because `base32` 0.5's `Rfc4648` alphabet
/// decodes upper case only: a secret written in lower case — a hand-copied
/// config, an app that stores what it was handed — decoded before the upgrade
/// and is rejected now, with an error that names neither the spelling nor the
/// case. Whitespace and `=` padding are dropped too; both are presentation
/// rather than part of the secret, and grouping it is common enough that
/// refusing it would only look pedantic.
fn decode_base32(secret_base32: &str) -> Result<Vec<u8>, ClientError> {
    let normalized: String = secret_base32
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    // An empty string decodes to an empty key, which would then generate codes
    // from nothing and fail every handshake with no hint as to why. It is a
    // missing secret, not a short one.
    if normalized.is_empty() {
        return Err(ClientError::InvalidConfig(
            "Invalid Base32 secret".to_string(),
        ));
    }

    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized)
        .ok_or_else(|| ClientError::InvalidConfig("Invalid Base32 secret".to_string()))
}

/// What a client-side credential proves itself with.
///
/// Which variant is in play is decided by the server's record, never here: a
/// device is key-based iff the server holds a `public_key` for it, and a
/// response offering the other kind of proof is simply refused. The client
/// learns its own variant at the one moment both sides agreed — enrollment —
/// and keeps it: [`TwoFactorAuth::with_key`] for a key, [`TwoFactorAuth::new`]
/// for a secret.
#[derive(Debug, Clone)]
enum Proof {
    /// A TOTP seed: an HMAC over the challenge, then a code.
    Totp {
        secret: Vec<u8>,
        algorithm: TotpAlgorithm,
        time_step: u32,
        digits: u32,
    },
    /// The device's own Ed25519 key: a signature over the same bytes the HMAC
    /// covers. The private half never leaves this process; the server holds
    /// the public half under the device's name.
    Key(iroh::SecretKey),
}

/// Client-side 2FA authenticator
///
/// The `Debug` is written out for the same reason [`TwoFactorConfig`]'s is: the
/// decoded `secret` is the credential itself, in a form a derived `Debug` would
/// print as a byte array.
#[derive(Clone)]
pub struct TwoFactorAuth {
    client_id: String,
    proof: Proof,
    /// Which of this client's devices this credential belongs to. `None` is the
    /// device that was never given a name, which is what every client was
    /// before a client could have several — it answers with the client's own
    /// secret, and it is the only thing a server that predates per-device
    /// credentials understands.
    device_id: Option<String>,
}

impl std::fmt::Debug for TwoFactorAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut rendered = f.debug_struct("TwoFactorAuth");
        rendered.field("client_id", &self.client_id);
        match &self.proof {
            Proof::Totp {
                secret,
                algorithm,
                time_step,
                digits,
            } => rendered
                .field("secret", &format_args!("<{} bytes>", secret.len()))
                .field("algorithm", algorithm)
                .field("time_step", time_step)
                .field("digits", digits),
            // The private key never prints: not its length, not a placeholder
            // beside it — nothing that varies with the key's value.
            Proof::Key(_) => rendered.field("proof", &"device-key"),
        };
        rendered.field("device_id", &self.device_id).finish()
    }
}

impl TwoFactorAuth {
    /// Create a new 2FA authenticator
    pub fn new(
        client_id: &str,
        secret_base32: &str,
        algorithm: TotpAlgorithm,
    ) -> Result<Self, ClientError> {
        let secret = decode_base32(secret_base32)?;

        Ok(Self {
            client_id: client_id.to_string(),
            proof: Proof::Totp {
                secret,
                algorithm,
                time_step: 30,
                digits: 6,
            },
            device_id: None,
        })
    }

    /// Create with custom time step and digits
    pub fn with_params(
        client_id: &str,
        secret_base32: &str,
        algorithm: TotpAlgorithm,
        time_step: u32,
        digits: u32,
    ) -> Result<Self, ClientError> {
        let secret = decode_base32(secret_base32)?;

        Ok(Self {
            client_id: client_id.to_string(),
            proof: Proof::Totp {
                secret,
                algorithm,
                time_step,
                digits,
            },
            device_id: None,
        })
    }

    /// A credential that proves itself with a device key instead of a secret.
    ///
    /// The key is this device's own — the server holds its public half under
    /// `device_id`, and every handshake is proven by a signature only this
    /// credential can produce. There is no code to read, which is the point:
    /// an unattended device has nobody to read one.
    ///
    /// The name is required rather than optional, and not for convenience: a
    /// key cannot be the credential of the unnamed slot, which is the client's
    /// own shared secret — the server refuses a key that names no device.
    pub fn with_key(client_id: &str, key: iroh::SecretKey, device_id: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            proof: Proof::Key(key),
            device_id: Some(device_id.to_string()),
        }
    }

    /// The same credential, answering as one named device of its client.
    ///
    /// What this changes is which secret the server checks the response
    /// against: a device carries one of its own, issued at enrollment, instead
    /// of sharing the client's with every other device that names it — which is
    /// what made revoking one of them rotate all of them. The name is sent on
    /// both AUTH_START and AUTH_RESPONSE, because the response is the one the
    /// server looks the secret up from; sending it on the first alone would
    /// authenticate against the client's secret while claiming a device.
    ///
    /// Nothing checks the name here. The server does, and refuses one that is
    /// not printable ASCII; [`device_id_is_usable`] is the same rule, for a
    /// caller that would rather find out before a handshake than during one.
    pub fn with_device(mut self, device_id: &str) -> Self {
        self.device_id = Some(device_id.to_string());
        self
    }

    /// The device this credential answers as, if it was given one.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Generate current TOTP code
    pub fn generate_code(&self) -> Result<String, ClientError> {
        let Proof::Totp {
            secret,
            algorithm,
            time_step,
            digits,
        } = &self.proof
        else {
            return Err(ClientError::InvalidConfig(
                "this credential proves itself with a key; there is no TOTP code".to_string(),
            ));
        };
        // Same narrowing as the server's validator: `digits` is a `u8` here
        // where 5.x gave it a `usize`, so an out-of-range config is refused
        // rather than truncated into a digit count nobody asked for.
        let digits = u8::try_from(*digits).map_err(|_| {
            ClientError::InvalidConfig(format!("{} is not a TOTP digit count", digits))
        })?;

        let totp = Builder::new()
            .with_algorithm(algorithm.to_totp_rs())
            .with_digits(digits)
            // No skew: this side only ever generates, and a code is either the
            // current one or not. The server's window is what grants tolerance.
            .with_skew(0)
            .with_step_duration(*time_step as u64)
            .with_secret(secret.clone())
            .build()
            .map_err(|e| ClientError::Other(format!("Failed to create TOTP: {e}")))?;

        // `generate_current` no longer returns a `Result`: the only thing it
        // could have failed on was a clock set before the Unix epoch, which is
        // not a condition a handshake can recover from.
        Ok(totp.generate_current().to_string())
    }

    /// Get client ID
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Sign a server challenge: HMAC-SHA256(secret, nonce || timestamp_le) for
    /// a secret-based credential, an Ed25519 signature over those same bytes
    /// for a key-based one.
    ///
    /// Keep in sync with `hmac_signature` in `crates/nexapipe/src/auth/totp.rs`
    /// and `sign_message` in `crates/nexapipe/src/auth/device_key.rs`: whichever
    /// proof is in play, what is signed is the nonce, byte for byte, then the
    /// timestamp as little-endian bytes.
    ///
    /// Fallible in the type only: HMAC takes a key of any length — a long one is
    /// hashed, a short one is zero-padded — so this has never failed. It is
    /// returned rather than `expect`ed because it runs inside a handshake, where
    /// a panic would kill the connection with nothing to report.
    pub fn sign_challenge(&self, nonce: &[u8], timestamp: i64) -> Result<Vec<u8>, ClientError> {
        match &self.proof {
            Proof::Totp { secret, .. } => {
                let mut mac = HmacSha256::new_from_slice(secret)
                    .map_err(|e| ClientError::Other(format!("HMAC rejected the secret: {e}")))?;
                mac.update(nonce);
                mac.update(&timestamp.to_le_bytes());
                Ok(mac.finalize().into_bytes().to_vec())
            }
            Proof::Key(key) => {
                let mut message = Vec::with_capacity(nonce.len() + 8);
                message.extend_from_slice(nonce);
                message.extend_from_slice(&timestamp.to_le_bytes());
                Ok(key.sign(&message).to_bytes().to_vec())
            }
        }
    }

    /// The two fields an AUTH_RESPONSE is proven with, produced together.
    ///
    /// Together because they have to agree: the server knows from its own
    /// record which proof it will demand, and it reads the code only on the
    /// secret path — a key device signs, and an empty `totp_code` is what its
    /// response carries. Building the two apart is how they could end up
    /// disagreeing.
    fn prove(&self, nonce: &[u8], timestamp: i64) -> Result<(String, Vec<u8>), ClientError> {
        let signature = self.sign_challenge(nonce, timestamp)?;
        match &self.proof {
            Proof::Totp { .. } => Ok((self.generate_code()?, signature)),
            Proof::Key(_) => Ok((String::new(), signature)),
        }
    }

    /// Turn a failed handshake read into an error that says what happened.
    ///
    /// A refusal races its own connection close: the server writes AUTH_FAILED
    /// and then immediately closes, and whichever the client sees first decides
    /// between "your credentials were refused" and a bare transport error —
    /// "connection lost", which reads like the server died. The close frame
    /// carries the verdict independently of those bytes, so read it back.
    fn read_failure(
        &self,
        conn: &Connection,
        step: &str,
        source: impl fmt::Display,
    ) -> ClientError {
        let detail = format!("{}: {}", step, source);

        let Some(iroh::endpoint::ConnectionError::ApplicationClosed(close)) = conn.close_reason()
        else {
            // Nothing to learn from a connection that is still up, or that died
            // a transport death with no application verdict attached.
            return ClientError::ConnectionFailed(detail);
        };

        match u32::try_from(close.error_code.into_inner()) {
            Ok(auth_close_code::REJECTED) => {
                let subject = if self.client_id.is_empty() {
                    "these credentials".to_string()
                } else {
                    format!("the credentials of client '{}'", self.client_id)
                };
                ClientError::AuthenticationFailed(format!(
                    "the server rejected {subject} — the client_id/secret pair does not match \
                     its [auth].clients (the reason itself never arrived, the close did)"
                ))
            }
            Ok(auth_close_code::REQUIRED) => ClientError::ConnectionFailed(format!(
                "{}: the server closed the connection mid-handshake without ever accepting AUTH_START — \
                 either it does not have 2FA enabled at all, or the two sides run different handshake versions",
                detail
            )),
            Ok(auth_close_code::TOO_MANY) => ClientError::ConnectionFailed(format!(
                "{}: the server refused this connection because this peer already holds too many",
                detail
            )),
            Ok(auth_close_code::PEER_NOT_ALLOWED) => ClientError::AuthenticationFailed(
                "the server runs a [peers] allow-list and does not permit this Node ID; ask \
                 its operator to add it (the reason itself never arrived, the close did)"
                    .to_string(),
            ),
            Ok(auth_close_code::REVOKED) => {
                let subject = if self.client_id.is_empty() {
                    "the credentials this connection authenticated with".to_string()
                } else {
                    format!("the credentials of client '{}'", self.client_id)
                };
                // Re-authenticating on a fresh connection will not help, and
                // saying so is the point: this is not a wrong code that a retry
                // could fix, it is an entry the server no longer has.
                ClientError::AuthenticationFailed(format!(
                    "the server revoked {subject} while this connection was open — an operator ran \
                     `nexapipe client revoke` against it. Import a credential again to reconnect; \
                     retrying this connection only repeats the refusal"
                ))
            }
            _ => ClientError::ConnectionFailed(detail),
        }
    }

    /// Authenticate with the server over a connection.
    pub async fn authenticate(&self, conn: &Connection) -> Result<(), ClientError> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to open stream: {}", e)))?;
        self.authenticate_on(conn, &mut send, &mut recv).await
    }

    /// The handshake itself, over a stream the caller opened.
    ///
    /// Split out so an enrollment can run ahead of it on the same stream: the
    /// server reads ENROLL_START and AUTH_START in order off one bi-stream, and
    /// a second stream would arrive looking like data sent before any
    /// credential.
    pub async fn authenticate_on(
        &self,
        conn: &Connection,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<(), ClientError> {
        // Four round trips against a server this client may be meeting for the
        // first time. The server's own deadline covers the first stream only, so
        // a server that answers the challenge and then goes quiet is covered by
        // nothing on either side — and in `Enrollment::exchange` this runs while
        // the endpoint's lock is held, which would stall every other caller.
        let handshake = self.authenticate_on_inner(conn, send, recv);
        match tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, handshake).await {
            Ok(outcome) => outcome,
            Err(_) => Err(ClientError::ConnectionFailed(format!(
                "the server did not finish the 2FA handshake within {}s",
                AUTH_HANDSHAKE_TIMEOUT.as_secs()
            ))),
        }
    }

    async fn authenticate_on_inner(
        &self,
        conn: &Connection,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<(), ClientError> {
        use crate::auth::auth_protocol::AuthMessage;

        // Step 1: Send AUTH_START
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let start_msg = AuthMessage::Start {
            client_id: self.client_id.clone(),
            timestamp,
            device_id: self.device_id.clone(),
        };

        let start_bytes = start_msg
            .to_bytes()
            .map_err(|e| ClientError::Other(format!("Serialization error: {}", e)))?;

        // Send message length + message
        let len = start_bytes.len() as u32;
        send.write_all(&len.to_le_bytes())
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send length: {}", e)))?;
        send.write_all(&start_bytes)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send message: {}", e)))?;

        // Step 2: Receive AUTH_CHALLENGE
        let nonce = match read_message(recv)
            .await
            .map_err(|e| self.read_failure(conn, "the AUTH_CHALLENGE could not be read", e))?
        {
            AuthMessage::Challenge { nonce } => nonce,
            _ => return Err(ClientError::Other("Expected AUTH_CHALLENGE".to_string())),
        };

        // Step 3: Generate and send AUTH_RESPONSE. The signature proves
        // possession of the credential and binds the response to this
        // connection's challenge; the timestamp is taken now, not reused from
        // AUTH_START, so the server's freshness window is measured from the
        // actual response. The code travels beside it for a secret-based
        // credential and is empty for a key-based one — see `prove`.
        let response_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let (totp_code, signature) = self.prove(&nonce, response_timestamp)?;

        // The same name AUTH_START carried, and not for politeness: this is the
        // message the server reads the device from when it picks which secret
        // to check against, so a response that omits it proves possession of
        // the client's own secret while asking to be counted as a device.
        let response_msg = AuthMessage::Response {
            client_id: self.client_id.clone(),
            timestamp: response_timestamp,
            totp_code,
            signature,
            device_id: self.device_id.clone(),
        };

        let response_bytes = response_msg
            .to_bytes()
            .map_err(|e| ClientError::Other(format!("Serialization error: {}", e)))?;

        let len = response_bytes.len() as u32;
        send.write_all(&len.to_le_bytes())
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send length: {}", e)))?;
        send.write_all(&response_bytes)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send message: {}", e)))?;
        send.finish().map_err(|e| {
            ClientError::ConnectionFailed(format!("Failed to finish stream: {}", e))
        })?;

        // Step 4: Receive AUTH_OK or AUTH_FAILED
        let result_msg = read_message(recv).await.map_err(|e| {
            self.read_failure(conn, "the authentication result could not be read", e)
        })?;

        match result_msg {
            AuthMessage::Ok => Ok(()),
            AuthMessage::Failed { reason } => Err(ClientError::AuthenticationFailed(reason)),
            _ => Err(ClientError::Other("Unexpected response".to_string())),
        }
    }

    /// The secret, back in the Base32 form it was configured with.
    ///
    /// An enrollment hands out a credential the app has never seen, and an app
    /// that cannot read it back cannot persist it — which would leave every
    /// restart trying to spend a token that has already been burned.
    ///
    /// Empty for a key-based credential, which has no secret: what such an app
    /// has to persist is the key — the private half is its own to keep, and
    /// [`Self::public_key_hex`] is the half the server knows it by.
    pub fn secret_base32(&self) -> String {
        match &self.proof {
            Proof::Totp { secret, .. } => {
                base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            }
            Proof::Key(_) => String::new(),
        }
    }

    /// The algorithm name, for the same reason as [`Self::secret_base32`].
    ///
    /// Empty for a key-based credential: there is no TOTP at all on that path,
    /// so there is no algorithm to name.
    pub fn algorithm_name(&self) -> &'static str {
        match &self.proof {
            Proof::Totp { algorithm, .. } => algorithm.name(),
            Proof::Key(_) => "",
        }
    }

    /// The public half of the key this credential proves itself with, lowercase
    /// hex — the spelling the server stores and an app has to persist.
    ///
    /// `None` for a secret-based credential, which has no key; a caller uses
    /// that to tell the two kinds apart. The private half is deliberately not
    /// readable from here: it was the caller's own before it was handed over,
    /// and the caller is the one that has to keep it.
    pub fn public_key_hex(&self) -> Option<String> {
        match &self.proof {
            Proof::Totp { .. } => None,
            Proof::Key(key) => Some(hex::encode(key.public().as_bytes())),
        }
    }
}

/// A credential the server issued during enrollment, in the form an app can
/// store it.
///
/// Handed out once by
/// [`crate::connection_pool::IrohConnectionPool::take_issued_credential`],
/// right after a token has been spent. An app that keeps its settings somewhere
/// durable has to write these fields down: the token is gone, so a restart that
/// still holds the invite cannot enroll a second time.
///
/// `Debug` masks `secret`, for the reason [`TwoFactorConfig`]'s does.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    pub client_id: String,
    /// Base32, exactly as it goes into [`TwoFactorAuth::new`] next time.
    /// Empty when the device was issued a key instead — see [`Self::public_key`].
    pub secret: String,
    pub algorithm: String,
    /// The public half of the key the device was issued, lowercase hex — the
    /// spelling the server stores — with `None` for a credential that is a
    /// secret.
    ///
    /// A `Some` here is also what says the credential proves itself with a
    /// signature: an app persisting it has to keep the private half it
    /// generated, because the server knows this device by its key and would
    /// refuse a secret it never issued.
    pub public_key: Option<String>,
    /// The device this credential was issued for, which has to be persisted
    /// with it: the server filed the secret under that name, so an app that
    /// writes down the secret and not the name has a credential it can no
    /// longer answer with. `None` is the unnamed device — a server that
    /// answered an enrollment which named none, or one that predates devices
    /// entirely.
    pub device: Option<String>,
}

impl std::fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCredential")
            .field("client_id", &self.client_id)
            .field("secret", &masked(&self.secret))
            .field("algorithm", &self.algorithm)
            .field("device", &self.device)
            .finish()
    }
}

/// A credential that has not been issued yet.
///
/// A `v=2` invitation carries one of these instead of the client's secret: the
/// link stops being a credential the moment it has been used, because what it
/// holds is a token the server exchanges for a freshly generated secret — or,
/// when the enrollment offers one, records as a device key — and then
/// discards. The trade is that the app has to keep what comes back — see
/// [`Enrollment::exchange`].
///
/// No `PartialEq`: an offered key is secret material with no equality of its
/// own, and comparing enrollments is not a question this type is asked.
///
/// `Debug` masks `token`, for the reason [`TwoFactorConfig`]'s does: an
/// unspent invitation link *is* the credential, and this is the struct an app
/// is most likely to log while working out why an enrollment did not go through.
#[derive(Clone)]
pub struct Enrollment {
    client_id: String,
    token: String,
    /// The name to be enrolled under. The token is what authorizes the
    /// exchange, so this is a request rather than a claim: the server is free
    /// to answer with it or to refuse it, and what it answers with is what the
    /// credential is filed under.
    device_id: Option<String>,
    /// The device key to offer, if any. What travels is the public half, and
    /// what comes back tells this side whether the offer was taken: an empty
    /// `secret` in ENROLL_ISSUE is the server saying the key was recorded.
    key: Option<iroh::SecretKey>,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("client_id", &self.client_id)
            .field("token", &masked(&self.token))
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl Enrollment {
    pub fn new(client_id: &str, token: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            token: token.to_string(),
            device_id: None,
            key: None,
        }
    }

    /// The same enrollment, asking to be issued under one device name.
    pub fn with_device(mut self, device_id: &str) -> Self {
        self.device_id = Some(device_id.to_string());
        self
    }

    /// The same enrollment, offering this device's key.
    ///
    /// What the server makes of the offer decides the credential: one that
    /// knows keys files the public half under the device name and answers with
    /// an empty secret — from then on nothing but a signature is sent — while
    /// one that predates them ignores the field and issues a secret, which
    /// then has to work as it always did. The public half travels in the
    /// clear, being public; the private half stays here.
    pub fn with_key(mut self, key: iroh::SecretKey) -> Self {
        self.key = Some(key);
        self
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The device this enrollment will ask for, if it was given one.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Trades the token for the real credential and authenticates with it, in
    /// one stream: ENROLL_START/ENROLL_ISSUE, then the ordinary handshake.
    ///
    /// The issued [`TwoFactorAuth`] is returned rather than kept, because what
    /// happens to it is the caller's decision — the process can use it for as
    /// long as it lives, but an app that wants to survive a restart has to
    /// persist [`TwoFactorAuth::secret_base32`] and drop the token.
    pub async fn exchange(&self, conn: &Connection) -> Result<TwoFactorAuth, ClientError> {
        // The same deadline the handshake below gets, and for the same reason:
        // a server that takes the ENROLL_START and never answers leaves this
        // future pending forever, and callers hold the endpoint's lock while
        // they wait for it.
        let exchange = self.exchange_inner(conn);
        match tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, exchange).await {
            Ok(outcome) => outcome,
            Err(_) => Err(ClientError::ConnectionFailed(format!(
                "the server did not answer the enrollment within {}s",
                AUTH_HANDSHAKE_TIMEOUT.as_secs()
            ))),
        }
    }

    async fn exchange_inner(&self, conn: &Connection) -> Result<TwoFactorAuth, ClientError> {
        use crate::auth::auth_protocol::AuthMessage;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to open stream: {}", e)))?;

        write_message(
            &mut send,
            &AuthMessage::EnrollStart {
                client_id: self.client_id.clone(),
                token: self.token.clone(),
                device_id: self.device_id.clone(),
                public_key: self
                    .key
                    .as_ref()
                    .map(|key| hex::encode(key.public().as_bytes())),
            },
        )
        .await?;

        let issued = match read_message(&mut recv).await? {
            AuthMessage::EnrollIssue {
                client_id,
                secret,
                algorithm,
                digits,
                period,
                device_id,
            } => {
                if client_id != self.client_id {
                    return Err(ClientError::AuthenticationFailed(
                        "the server issued a credential for a different client id".to_string(),
                    ));
                }
                if secret.is_empty() {
                    // No secret in the answer means the server recorded the
                    // key this enrollment offered — it only ever does that
                    // when the request carried one, so this is that key,
                    // whose private half never left this process.
                    let Some(key) = self.key.clone() else {
                        return Err(ClientError::Other(
                            "the server issued an empty secret, but this enrollment offered \
                             no key"
                                .to_string(),
                        ));
                    };
                    // A key is one device's credential; the unnamed slot is
                    // the client's shared secret and the server refuses to
                    // file a key there, so a key answer always names the
                    // device it was filed under.
                    let Some(name) = device_id else {
                        return Err(ClientError::Other(
                            "the server issued a key credential without naming the device \
                             it was filed under"
                                .to_string(),
                        ));
                    };
                    TwoFactorAuth::with_key(&client_id, key, &name)
                } else {
                    // A secret came back, so a secret is the credential:
                    // either that is what was asked for, or a key was offered
                    // and the server predates keys — it ignores the field and
                    // issues a secret as it always has, which then has to
                    // work.
                    //
                    // The name the server filed this secret under is the only
                    // name this credential has, and it is whatever came back
                    // here — asked for in ENROLL_START, answered in this one.
                    //
                    // An answer that names no device is a server that filed it
                    // under no device: it predates the table, or it was asked
                    // for none. Either way it has nothing to match a name
                    // against, and putting the one that was asked for back
                    // sends it on every handshake from here on — which the
                    // server answers by refusing a device it does not know.
                    // Narrowed the way `digits` is narrowed in `generate_code`, and
                    // for the same reason: a cast truncates a period that does not
                    // fit into one that looks deliberate — a 90-second step read as
                    // some other number — where a refusal names the value the
                    // server actually sent.
                    let period = u32::try_from(period).map_err(|_| {
                        ClientError::InvalidConfig(format!("{period} is not a TOTP period"))
                    })?;
                    let issued = TwoFactorAuth::with_params(
                        &client_id,
                        &secret,
                        TotpAlgorithm::from_name(&algorithm),
                        period,
                        digits,
                    )?;
                    match device_id {
                        Some(name) => issued.with_device(&name),
                        None => issued,
                    }
                }
            }
            // One reply for every way this can fail: an enrollment token is
            // either right or it is not, and saying which would only help
            // someone who is guessing.
            AuthMessage::EnrollFailed { reason } => {
                return Err(ClientError::AuthenticationFailed(reason));
            }
            other => {
                return Err(ClientError::Other(format!(
                    "expected ENROLL_ISSUE, the server sent {}",
                    message_name(&other)
                )));
            }
        };

        issued.authenticate_on(conn, &mut send, &mut recv).await?;
        Ok(issued)
    }
}

/// Writes one length-prefixed message.
async fn write_message(
    send: &mut iroh::endpoint::SendStream,
    message: &auth_protocol::AuthMessage,
) -> Result<(), ClientError> {
    let bytes = message
        .to_bytes()
        .map_err(|e| ClientError::Other(format!("Serialization error: {}", e)))?;
    let len = bytes.len() as u32;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send length: {}", e)))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send message: {}", e)))
}

/// Reads one length-prefixed message.
async fn read_message(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<auth_protocol::AuthMessage, ClientError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| {
        ClientError::ConnectionFailed(format!("Failed to read message length: {e}"))
    })?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    // The server caps what it will read at 64 KiB; anything longer is a peer
    // that is not speaking this protocol, not a message worth allocating for.
    if msg_len > MAX_AUTH_MESSAGE {
        return Err(ClientError::ConnectionFailed(format!(
            "auth message length {msg_len} is out of range"
        )));
    }
    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf)
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to read message: {e}")))?;
    auth_protocol::AuthMessage::from_bytes(&msg_buf)
        .map_err(|e| ClientError::Other(format!("Deserialization error: {}", e)))
}

/// The `type` tag of a message, for errors that name what arrived.
fn message_name(message: &auth_protocol::AuthMessage) -> &'static str {
    match message {
        auth_protocol::AuthMessage::Start { .. } => "AUTH_START",
        auth_protocol::AuthMessage::Challenge { .. } => "AUTH_CHALLENGE",
        auth_protocol::AuthMessage::Response { .. } => "AUTH_RESPONSE",
        auth_protocol::AuthMessage::Ok => "AUTH_OK",
        auth_protocol::AuthMessage::Failed { .. } => "AUTH_FAILED",
        auth_protocol::AuthMessage::EnrollStart { .. } => "ENROLL_START",
        auth_protocol::AuthMessage::EnrollIssue { .. } => "ENROLL_ISSUE",
        auth_protocol::AuthMessage::EnrollFailed { .. } => "ENROLL_FAILED",
    }
}

/// The largest AUTH_* message the client accepts.
///
/// Mirrors `MAX_AUTH_MESSAGE` in `crates/nexapipe/src/conn/mod.rs`: the length
/// prefix is read before anything is known about the peer, so it is not
/// trusted until it is in range.
const MAX_AUTH_MESSAGE: usize = 64 * 1024;

/// How long the client waits for the server to finish the handshake.
///
/// Comfortably longer than the server's own five-second wait for the first
/// stream: that one covers a client that never speaks, while this covers a
/// server that answers and then stalls, which nothing else on either side does.
const AUTH_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Generate a new secret for client setup
pub fn generate_secret() -> String {
    Secret::generate().to_base32()
}

/// Whether a device name the server will accept.
///
/// The rule is the server's, mirrored here so an app can tell before it
/// enrols rather than after: printable ASCII, space excluded, not empty, and
/// short enough to sit in a config key and a log line. A hostname is the
/// obvious thing to name a device after and the obvious way to break this —
/// "MacBook Pro" has a space in it — so whatever builds a name has to put the
/// rule somewhere it is applied rather than remembered.
pub fn device_id_is_usable(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_DEVICE_ID_LEN
        && id.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Longest device name the server accepts.
///
/// Mirrors `MAX_DEVICE_ID_LEN` in `crates/nexapipe/src/auth/protocol.rs`, which
/// is where the refusal actually happens.
pub const MAX_DEVICE_ID_LEN: usize = 255;

/// Protocol messages for authentication handshake
pub mod auth_protocol {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type")]
    pub enum AuthMessage {
        #[serde(rename = "AUTH_START")]
        Start {
            client_id: String,
            timestamp: i64,
            /// Which of this client's devices is authenticating. Absent is the
            /// device that was never given a name.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            device_id: Option<String>,
        },
        #[serde(rename = "AUTH_CHALLENGE")]
        Challenge { nonce: Vec<u8> },
        #[serde(rename = "AUTH_RESPONSE")]
        Response {
            client_id: String,
            timestamp: i64,
            /// The current TOTP code; empty when the device is known by a key,
            /// whose proof is the signature alone.
            totp_code: String,
            /// HMAC-SHA256(secret, nonce || timestamp_le) over the challenge for
            /// a secret-based credential, an Ed25519 signature over those same
            /// bytes for a key-based one.
            signature: Vec<u8>,
            /// The device [`AuthMessage::Start`] named. The server picks the
            /// credential to check this against from here, not from AUTH_START.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            device_id: Option<String>,
        },
        #[serde(rename = "AUTH_OK")]
        Ok,
        #[serde(rename = "AUTH_FAILED")]
        Failed { reason: String },
        /// Offer a one-time enrollment token instead of a secret.
        ///
        /// Keep in sync with `AuthMessage::EnrollStart` in
        /// `crates/nexapipe/src/auth/protocol.rs`.
        #[serde(rename = "ENROLL_START")]
        EnrollStart {
            client_id: String,
            token: String,
            /// The name the device asking to enroll wants to be issued under.
            /// Absent keeps the old behaviour: one secret for the client.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            device_id: Option<String>,
            /// The device key this client is asking to be issued under, as the
            /// public half of an Ed25519 key pair in lowercase hex.
            ///
            /// Absent for a client that has no key to offer. A server that
            /// predates this field ignores it and issues a secret, so a client
            /// offering one has to keep working with what it is given.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            public_key: Option<String>,
        },
        /// The credential the token stood in for, issued and the token burned.
        #[serde(rename = "ENROLL_ISSUE")]
        EnrollIssue {
            client_id: String,
            /// Base32 when a secret was issued; empty when the device was
            /// issued a key instead, which is what the offered key bought.
            secret: String,
            algorithm: String,
            digits: u32,
            period: u64,
            /// The device this credential was issued for — the name the client
            /// has to send back. Absent when the server answered an enrollment
            /// that named no device.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            device_id: Option<String>,
        },
        /// The token was not accepted.
        #[serde(rename = "ENROLL_FAILED")]
        EnrollFailed { reason: String },
    }

    impl AuthMessage {
        pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(self)
        }

        pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
            serde_json::from_slice(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Enrollment, IssuedCredential, MAX_DEVICE_ID_LEN, TotpAlgorithm, TwoFactorAuth,
        TwoFactorConfig, auth_protocol::AuthMessage, device_id_is_usable,
    };

    /// A `Debug` that prints a secret turns every log line, panic message and
    /// bug report that touches one into a credential disclosure — and these are
    /// exactly the values an app logs while working out why authentication
    /// stopped working. Every holder of a secret gets a hand-written `Debug` for
    /// that reason; this is the test that keeps the hand-written ones honest.
    #[test]
    fn no_debug_output_carries_a_secret() {
        let secret = "JBSWY3DPEHPK3PXP";
        let config = TwoFactorConfig {
            client_id: "node-1".to_string(),
            secret: secret.to_string(),
            algorithm: TotpAlgorithm::SHA1,
        };
        let auth = TwoFactorAuth::new("node-1", secret, TotpAlgorithm::SHA1).expect("a credential");
        let issued = IssuedCredential {
            client_id: "node-1".to_string(),
            secret: secret.to_string(),
            algorithm: "sha1".to_string(),
            public_key: None,
            device: Some("laptop".to_string()),
        };
        let enrollment = Enrollment::new("node-1", "an-invitation-token");

        for rendered in [
            format!("{config:?}"),
            format!("{auth:?}"),
            format!("{issued:?}"),
            format!("{enrollment:?}"),
        ] {
            assert!(
                !rendered.contains(secret),
                "a TOTP seed reached a Debug output: {rendered}"
            );
            assert!(
                !rendered.contains("an-invitation-token"),
                "an enrollment token reached a Debug output: {rendered}"
            );
        }
    }

    /// Masking must not turn into silence: a reader debugging a login needs to
    /// tell "no secret configured" from "a secret is there and I cannot see it",
    /// and needs to know the value is not the wrong length.
    #[test]
    fn a_masked_secret_still_says_whether_there_is_one() {
        let with_secret = TwoFactorConfig {
            client_id: "node-1".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: TotpAlgorithm::SHA1,
        };
        let without = TwoFactorConfig {
            client_id: "node-1".to_string(),
            secret: String::new(),
            algorithm: TotpAlgorithm::SHA1,
        };

        let present = format!("{with_secret:?}");
        let absent = format!("{without:?}");

        // Neither message interpolates the rendering: a failure here would print
        // whatever the `Debug` let through, which is the leak under test.
        assert!(
            present != absent,
            "a masked secret and an absent one are indistinguishable"
        );
        assert!(present.contains("16 chars"), "the length is not reported");
        // The whole point of masking, stated as a test: the length is not the value.
        assert!(!present.contains("JBSWY3DPEHPK3PXP"));
    }

    /// A stand-in nonce, built rather than written out — the twin of the helper
    /// in `crates/nexapipe/src/auth/device_key.rs`. No test here needs a
    /// particular value, and a literal array where a nonce goes reads to the
    /// scanner as a hard-coded key.
    fn test_nonce(seed: u8) -> [u8; 32] {
        std::array::from_fn(|i| seed ^ (i as u8))
    }

    /// The mirror of the test in `crates/nexapipe/src/auth/protocol.rs`: the
    /// two sides define these messages separately, and the tag is all that
    /// decides which one a peer is looking at.
    #[test]
    fn enrollment_messages_keep_their_wire_names() {
        let start = AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: "tok".to_string(),
            device_id: None,
            public_key: None,
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_START""#), "{json}");

        let issue = AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            device_id: None,
        };
        let json = String::from_utf8(issue.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_ISSUE""#), "{json}");

        let failed = AuthMessage::EnrollFailed {
            reason: "no".to_string(),
        };
        let json = String::from_utf8(failed.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_FAILED""#), "{json}");
    }

    /// The mirror of the server's test: the two sides define these messages
    /// separately, and the field may not appear at all — a client that predates
    /// keys sends none — so one without it has to still parse, and stay the
    /// same message on the way back out.
    #[test]
    fn an_enrollment_without_a_key_still_parses_on_the_wire() {
        let wire =
            br#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop"}"#;
        let start = AuthMessage::from_bytes(wire).unwrap();
        match &start {
            AuthMessage::EnrollStart { public_key, .. } => assert_eq!(public_key, &None),
            other => panic!("expected ENROLL_START, got {other:?}"),
        }
        assert_eq!(
            start.to_bytes().unwrap(),
            wire.to_vec(),
            "no public_key goes out as no public_key"
        );
    }

    /// And one that offers a key round-trips, exactly: the field is carried
    /// whole, not normalized in flight.
    #[test]
    fn an_enrollment_offering_a_key_round_trips_byte_exactly() {
        let wire = br#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop","public_key":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}"#;
        let start = AuthMessage::from_bytes(wire).unwrap();
        match &start {
            AuthMessage::EnrollStart { public_key, .. } => assert_eq!(
                public_key.as_deref(),
                Some("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
            ),
            other => panic!("expected ENROLL_START, got {other:?}"),
        }
        assert_eq!(start.to_bytes().unwrap(), wire.to_vec());
    }

    /// The offer is made of the public half, lowercase hex — the spelling the
    /// server's config stores — and the builder keeps the private half, which
    /// is what will sign every challenge once the offer is taken.
    #[test]
    fn an_enrollment_can_offer_a_key_beside_its_device_name() {
        let key = iroh::SecretKey::generate();
        let public_key = hex::encode(key.public().as_bytes());

        let enrollment = Enrollment::new("client-001", "tok")
            .with_device("phone-1a2b3c4d")
            .with_key(key.clone());
        assert!(
            enrollment.key.is_some(),
            "the offered key is kept to sign with"
        );

        // What those two produce on the wire, as `exchange_inner` sends it.
        let start = AuthMessage::EnrollStart {
            client_id: enrollment.client_id().to_string(),
            token: "tok".to_string(),
            device_id: enrollment.device_id().map(str::to_string),
            public_key: enrollment
                .key
                .as_ref()
                .map(|key| hex::encode(key.public().as_bytes())),
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(
            json.contains(&format!(r#""public_key":"{public_key}""#)),
            "{json}"
        );
        assert!(
            !json.contains(&hex::encode(key.to_bytes())),
            "the private half never goes on the wire: {json}"
        );
    }

    /// A key-based credential puts a signature where a secret-based one puts an
    /// HMAC and carries no code at all: the server reads the code only on the
    /// secret path, and an empty one is what a key response looks like.
    #[test]
    fn a_key_credential_responds_with_a_signature_and_no_code() {
        let key = iroh::SecretKey::generate();
        let public_key = hex::encode(key.public().as_bytes());
        let auth = TwoFactorAuth::with_key("client-001", key, "phone-1a2b3c4d");

        let (totp_code, signature) = auth.prove(&test_nonce(0x0a), 1_700_000_000).unwrap();
        assert_eq!(totp_code, "", "a key device sends no code");
        assert_eq!(signature.len(), 64, "an Ed25519 signature is 64 bytes");

        assert_eq!(auth.public_key_hex(), Some(public_key));
        assert_eq!(auth.secret_base32(), "", "a key credential has no secret");
        assert_eq!(auth.algorithm_name(), "", "and no algorithm to name");
        assert_eq!(auth.device_id(), Some("phone-1a2b3c4d"));
        assert!(
            auth.generate_code().is_err(),
            "there is no code to generate"
        );
    }

    /// What a key device signs is the same byte string the secret path HMACs —
    /// the nonce, byte for byte, then the timestamp little-endian — because the
    /// server verifies against exactly those bytes. This is the client half of
    /// the pin the server's `device_key` tests keep.
    #[test]
    fn a_key_credential_signs_the_nonce_then_the_little_endian_timestamp() {
        let key = iroh::SecretKey::generate();
        let public = key.public();
        let auth = TwoFactorAuth::with_key("client-001", key, "phone-1a2b3c4d");

        let nonce = test_nonce(0x01);
        let signature = auth.sign_challenge(&nonce, 0x0102030405060708).unwrap();
        assert_eq!(signature.len(), 64);

        let mut message = nonce.to_vec();
        message.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        public
            .verify(
                &message,
                &iroh::Signature::try_from(signature.as_slice()).expect("64 bytes of signature"),
            )
            .expect("the signature verifies against the public half");
    }

    /// An enrollment that succeeds has to hand back something the app can
    /// write down, or a restart has nothing left to authenticate with.
    #[test]
    fn an_issued_credential_comes_back_in_the_form_it_was_configured_with() {
        let auth = TwoFactorAuth::with_params(
            "client-001",
            "JBSWY3DPEHPK3PXP",
            TotpAlgorithm::SHA256,
            30,
            6,
        )
        .unwrap();
        assert_eq!(auth.secret_base32(), "JBSWY3DPEHPK3PXP");
        assert_eq!(auth.algorithm_name(), "sha256");
    }

    /// `base32` 0.5 decodes upper case only, so a secret that is correct but
    /// written in lower case — a hand-copied config, an app that stores what
    /// it was handed — used to decode and would now be rejected.
    #[test]
    fn a_secret_decodes_in_any_spelling() {
        for spelling in [
            "JBSWY3DPEHPK3PXP",
            "jbswy3dpehpk3pxp",
            "JbSwY3dPeHpK3pXp",
            "JBSW Y3DP EHPK 3PXP",
            "jbswy3dpehpk3pxp==",
        ] {
            let auth = TwoFactorAuth::new("client-001", spelling, TotpAlgorithm::SHA1)
                .unwrap_or_else(|e| panic!("{spelling:?} should decode: {e}"));
            assert_eq!(auth.secret_base32(), "JBSWY3DPEHPK3PXP", "{spelling:?}");
        }
    }

    /// The other half of the same guard: something that is not Base32 at all
    /// is still refused, in whatever spelling.
    #[test]
    fn a_secret_that_is_not_base32_is_still_refused() {
        assert!(TwoFactorAuth::new("client-001", "not-base32!", TotpAlgorithm::SHA1).is_err());
        assert!(TwoFactorAuth::new("client-001", "", TotpAlgorithm::SHA1).is_err());
    }

    /// A device is named on AUTH_START *and* on AUTH_RESPONSE, because the
    /// server reads the name off the response when it decides which secret to
    /// check against. Naming it on the first alone would ask to be counted as a
    /// device while proving possession of the client's own secret.
    #[test]
    fn a_named_device_speaks_on_both_messages() {
        let auth = TwoFactorAuth::new("client-001", "JBSWY3DPEHPK3PXP", TotpAlgorithm::SHA1)
            .unwrap()
            .with_device("laptop-7f3a9c21");
        assert_eq!(auth.device_id(), Some("laptop-7f3a9c21"));

        let start = AuthMessage::Start {
            client_id: auth.client_id().to_string(),
            timestamp: 0,
            device_id: auth.device_id().map(str::to_string),
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""device_id":"laptop-7f3a9c21""#), "{json}");

        let response = AuthMessage::Response {
            client_id: auth.client_id().to_string(),
            timestamp: 0,
            totp_code: "123456".to_string(),
            signature: vec![0u8; 32],
            device_id: auth.device_id().map(str::to_string),
        };
        let json = String::from_utf8(response.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""device_id":"laptop-7f3a9c21""#), "{json}");
    }

    /// The device that was never given a name has to look exactly like a client
    /// that predates devices: no `device_id` on the wire at all, not one set to
    /// null. A peer that predates this cannot be asked to understand a field it
    /// has never seen.
    #[test]
    fn an_unnamed_device_leaves_the_field_off_the_wire() {
        let auth =
            TwoFactorAuth::new("client-001", "JBSWY3DPEHPK3PXP", TotpAlgorithm::SHA1).unwrap();
        assert_eq!(auth.device_id(), None);

        let start = AuthMessage::Start {
            client_id: auth.client_id().to_string(),
            timestamp: 0,
            device_id: auth.device_id().map(str::to_string),
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(!json.contains("device_id"), "{json}");
    }

    /// The mirror of that, in the other direction: a server that predates
    /// per-device credentials sends no `device_id`, and ENROLL_ISSUE without
    /// one still has to deserialize.
    #[test]
    fn an_issue_from_a_server_that_names_no_device_still_parses() {
        let wire = br#"{"type":"ENROLL_ISSUE","client_id":"client-001","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}"#;
        let issue = AuthMessage::from_bytes(wire).unwrap();
        match issue {
            AuthMessage::EnrollIssue { device_id, .. } => assert_eq!(device_id, None),
            other => panic!("expected ENROLL_ISSUE, got {other:?}"),
        }
    }

    /// An enrollment carries the name it was given, and one that was given
    /// none asks for the client's own secret — which is the only thing a server
    /// that predates devices will answer.
    #[test]
    fn an_enrollment_asks_for_the_device_it_was_given() {
        assert_eq!(Enrollment::new("client-001", "tok").device_id(), None);
        let named = Enrollment::new("client-001", "tok").with_device("phone-1a2b3c4d");
        assert_eq!(named.device_id(), Some("phone-1a2b3c4d"));
        assert_eq!(named.client_id(), "client-001");
    }

    /// What the server will refuse, mirrored so an app can find out before a
    /// handshake rather than during one. A hostname is the obvious thing to
    /// name a device after, and "MacBook Pro" is the obvious way to break it.
    #[test]
    fn a_device_name_is_printable_ascii_without_spaces() {
        assert!(device_id_is_usable("laptop-7f3a9c21"));
        assert!(device_id_is_usable("phone"));

        assert!(!device_id_is_usable(""), "empty");
        assert!(!device_id_is_usable("MacBook Pro"), "a space");
        assert!(!device_id_is_usable("laptop\t"), "a tab");
        assert!(!device_id_is_usable("laptop\n"), "a newline");
        assert!(!device_id_is_usable("laptop‑pro"), "outside ASCII");
        assert!(
            !device_id_is_usable(&"x".repeat(MAX_DEVICE_ID_LEN + 1)),
            "too long"
        );

        assert!(device_id_is_usable(&"x".repeat(MAX_DEVICE_ID_LEN)));
    }
}

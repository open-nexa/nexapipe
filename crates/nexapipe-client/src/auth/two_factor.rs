//! The authenticator that answers a challenge.
//!
//! What it answers with is a proof, and there are two kinds: a code made
//! from the secret, or a signature made with the device's own key. Which
//! one it holds is decided when it is built, and the server asks for the
//! matching one.

use iroh::endpoint::Connection;
use nexapipe_proto::auth::close_code as auth_close_code;
use nexapipe_proto::auth::{AuthMessage, Format, VERSION_BINARY};
use nexapipe_proto::secret::SecretBytes;
use std::fmt;
use totp_rs::Builder;

use crate::ClientError;

use super::message::{AUTH_HANDSHAKE_TIMEOUT, read_message, write_message};
use super::totp::{TotpAlgorithm, decode_base32};

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
    ///
    /// The seed is a [`SecretBytes`], so it is wiped when the credential is
    /// dropped — and its `Debug` says nothing about its value, which is what
    /// lets this enum keep a derived one.
    Totp {
        secret: SecretBytes,
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
/// The `Debug` is written out for the same reason [`TwoFactorConfig`](super::TwoFactorConfig)'s is: the
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
                .field(
                    "secret",
                    &format_args!("<{} bytes>", secret.as_slice().len()),
                )
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
    /// not printable ASCII; [`device_id_is_usable`](super::device_id_is_usable) is the same rule, for a
    /// caller that would rather find out before a handshake than during one.
    pub fn with_device(mut self, device_id: &str) -> Self {
        self.device_id = Some(device_id.to_string());
        self
    }

    /// The device this credential answers as, if it was given one.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Who this credential proves itself as: the client, and the device of it.
    ///
    /// Two credentials with the same identity are the same account with a
    /// different secret — the seed was rotated, the account was not — and a
    /// connection authenticated as that account still stands for it. Two
    /// credentials with different identities are different accounts, and a
    /// connection authenticated as the old one is not the new one's.
    pub fn identity(&self) -> (&str, Option<&str>) {
        (self.client_id.as_str(), self.device_id.as_deref())
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
            // The validator is built from a copy of the seed, and it keeps
            // that copy: `totp-rs` is built with its `zeroize` feature, so the
            // copy is wiped when the validator is dropped at the end of this
            // function rather than left in the heap.
            .with_secret(secret.expose_secret_cloned())
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
    /// What is signed is defined once, in
    /// [`nexapipe_proto::auth::challenge_message`], which the server links too:
    /// whichever proof is in play, what is signed is the nonce, byte for byte,
    /// then the timestamp as little-endian bytes.
    ///
    /// Fallible in the type only: HMAC takes a key of any length — a long one is
    /// hashed, a short one is zero-padded — so this has never failed. It is
    /// returned rather than `expect`ed because it runs inside a handshake, where
    /// a panic would kill the connection with nothing to report.
    pub fn sign_challenge(&self, nonce: &[u8], timestamp: i64) -> Result<Vec<u8>, ClientError> {
        match &self.proof {
            Proof::Totp { secret, .. } => {
                nexapipe_proto::auth::hmac_challenge(secret.as_slice(), nonce, timestamp)
                    .map_err(|e| ClientError::Other(format!("HMAC rejected the secret: {e}")))
            }
            Proof::Key(key) => {
                let message = nexapipe_proto::auth::challenge_message(nonce, timestamp);
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
    pub(super) fn prove(
        &self,
        nonce: &[u8],
        timestamp: i64,
    ) -> Result<(String, Vec<u8>), ClientError> {
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
        use nexapipe_proto::auth::AuthMessage;

        // Step 1: Send AUTH_START
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // The old form, with the version this client speaks announced inside
        // it. A server that predates the version byte drops the field it does
        // not know and answers in the old form; a server that knows it
        // answers in the version that was asked for. A version byte *in front
        // of* the JSON would break the first case, because a server that
        // predates it reads the payload as JSON and would choke on it.
        let start_msg = self.start_message(timestamp);
        write_message(send, &start_msg, Format::LegacyJson).await?;

        // Step 2: Receive AUTH_CHALLENGE
        let (challenge, format) = read_message(recv)
            .await
            .map_err(|e| self.read_failure(conn, "the AUTH_CHALLENGE could not be read", e))?;
        let nonce = match challenge {
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

        // The form the server answered in: a server that knows the binary
        // form is answered in it, and a server that does not is answered in
        // the old one — which is the only form it can read.
        write_message(send, &response_msg, format).await?;
        send.finish().map_err(|e| {
            ClientError::ConnectionFailed(format!("Failed to finish stream: {}", e))
        })?;

        // Step 4: Receive AUTH_OK or AUTH_FAILED
        let (result_msg, _) = read_message(recv).await.map_err(|e| {
            self.read_failure(conn, "the authentication result could not be read", e)
        })?;

        match result_msg {
            AuthMessage::Ok => Ok(()),
            AuthMessage::Failed { reason } => Err(ClientError::AuthenticationFailed(reason)),
            _ => Err(ClientError::Other("Unexpected response".to_string())),
        }
    }

    /// The first message of the handshake.
    ///
    /// It carries the version this client speaks, **inside** the JSON: a
    /// server that predates the version byte drops the field it does not know
    /// and answers in the old form, and a server that knows it answers in the
    /// version that was asked for. A version byte in front of the JSON would
    /// break the first case, because a server that predates it reads the
    /// payload as JSON and would choke on it.
    pub(super) fn start_message(&self, timestamp: i64) -> AuthMessage {
        AuthMessage::Start {
            client_id: self.client_id.clone(),
            timestamp,
            device_id: self.device_id.clone(),
            version: Some(VERSION_BINARY),
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
    ///
    /// The string this returns is a plain one: it is on its way to durable
    /// storage, which is outside anything this process could wipe. That is the
    /// point of the method, not an oversight — the copy that stays here is
    /// still a [`SecretBytes`], and it is wiped with the credential.
    pub fn secret_base32(&self) -> String {
        match &self.proof {
            Proof::Totp { secret, .. } => base32::encode(
                base32::Alphabet::Rfc4648 { padding: false },
                secret.as_slice(),
            ),
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

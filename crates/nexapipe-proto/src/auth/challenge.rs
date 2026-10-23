use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// The message a proof covers: the connection's nonce, then the client's
/// timestamp as little-endian bytes.
///
/// One definition, because the two proof paths have to cover the same bytes:
/// a secret-based credential HMACs this message, a key-based one signs it
/// with Ed25519, and the server checks the key path against these same bytes.
/// Whichever credential answers, what a response proves is the same thing:
/// this client saw this connection's nonce at this time.
///
/// It used to be written down three times — the server's HMAC path, the
/// server's key path and the client's — with a comment in each copy saying to
/// keep the others in step. Two of them drifting apart is a handshake that
/// succeeds with one credential and fails with the other, and nothing in the
/// failure says which.
pub fn challenge_message(nonce: &[u8], timestamp: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(nonce.len() + 8);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&timestamp.to_le_bytes());
    message
}

/// Why a challenge could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeError {
    /// What the underlying HMAC said.
    ///
    /// Carried as text rather than flattened away, because the two callers
    /// word it differently — the server reports a refused secret, the client
    /// reports one it could not use — and each of them has been saying so for
    /// as long as it has had a copy of this.
    pub message: String,
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChallengeError {}

/// HMAC-SHA256 over [`challenge_message`]: the proof a secret-based credential
/// gives.
///
/// The key path's Ed25519 half stays on either side — the key types are not
/// the same crate's — but it signs [`challenge_message`], so the two proofs
/// cover one byte string.
pub fn hmac_challenge(
    secret: &[u8],
    nonce: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, ChallengeError> {
    // Fallible in the type only: HMAC takes a key of any length — a long one
    // is hashed, a short one is zero-padded — so this has never failed. It is
    // returned rather than `expect`ed because it runs inside a handshake,
    // where a panic would drop the connection with nothing to report.
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|e| ChallengeError {
        message: e.to_string(),
    })?;
    mac.update(&challenge_message(nonce, timestamp));
    Ok(mac.finalize().into_bytes().to_vec())
}

/// The application error codes the server closes a connection with.
///
/// They travel in the QUIC CONNECTION_CLOSE frame, so the client can tell
/// "you never authenticated" apart from "your code was rejected" — the
/// difference between a misconfigured client and a wrong TOTP code.
///
/// One definition, for the reason the rest of this module is one definition:
/// a code changed on one side and not the other is a client that reports a
/// mysterious connection loss instead of the reason it was given one.
pub mod close_code {
    /// No AUTH_START arrived within the handshake deadline: the server requires
    /// 2FA the client did not perform.
    pub const REQUIRED: u32 = 2;
    /// The handshake ran, but the client is unknown or its code was rejected.
    pub const REJECTED: u32 = 3;
    /// The peer already holds as many connections as it is allowed, so this one
    /// is closed without any traffic being served on it.
    pub const TOO_MANY: u32 = 4;
    /// The server runs a `[peers]` allow-list and this Node ID is not on it.
    /// Sent right after the QUIC handshake, so the client never gets as far as
    /// sending credentials.
    pub const PEER_NOT_ALLOWED: u32 = 5;
    /// The credential this connection authenticated with is gone: `nexapipe
    /// client revoke` struck the client, or the device, out of `[auth]` while
    /// this connection was open. Unlike the four above this does not arrive
    /// during the handshake: a connection has to have authenticated to be
    /// revoked. Five belongs to the allow list above, which is why the numbers
    /// are not adjacent.
    pub const REVOKED: u32 = 6;
}

/// HMAC-SHA256, the hash the challenge is signed with.
type HmacSha256 = Hmac<Sha256>;

//! Authentication protocol for client-server handshake.
//!
//! Protocol flow:
//! 1. Client -> Server: AUTH_START { client_id, timestamp }
//! 2. Server -> Client: AUTH_CHALLENGE { nonce }
//! 3. Client -> Server: AUTH_RESPONSE { client_id, timestamp, totp_code, signature }
//! 4. Server -> Client: AUTH_OK | AUTH_FAILED { reason }
//!
//! Optional enrollment, before the flow above:
//! 0a. Client -> Server: ENROLL_START { client_id, token }
//! 0b. Server -> Client: ENROLL_ISSUE { client_id, secret, algorithm, digits, period }
//!     | ENROLL_FAILED { reason }
//!
//! Enrollment is how an invitation that is safe to hand out stays safe after it
//! has been handed out: the link carries a one-time token instead of the
//! client's long-lived secret, the server exchanges it for a freshly generated
//! secret and burns the token in the same write, so a link that was copied in
//! transit stops being a credential the moment it has been used once. The
//! exchange runs on the same stream, ahead of AUTH_START.
//!
//! The response is signed: `signature` is
//! HMAC-SHA256(secret, nonce || timestamp.to_le_bytes()) over the client's
//! Base32-decoded TOTP secret, so a response only validates against the
//! challenge that was issued for this very connection — an intercepted
//! response cannot be replayed over a new one, and the timestamp bounds how
//! long even the right response stays acceptable.

use serde::{Deserialize, Serialize};

/// Messages exchanged during authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMessage {
    /// Client initiates authentication
    #[serde(rename = "AUTH_START")]
    Start { client_id: String, timestamp: i64 },
    /// Server sends challenge nonce
    #[serde(rename = "AUTH_CHALLENGE")]
    Challenge { nonce: Vec<u8> },
    /// Client responds with TOTP code
    #[serde(rename = "AUTH_RESPONSE")]
    Response {
        client_id: String,
        timestamp: i64,
        totp_code: String,
        /// HMAC-SHA256 over `nonce || timestamp.to_le_bytes()` keyed with the
        /// client's TOTP secret, proving the response was built for this
        /// connection's challenge by someone holding the secret.
        signature: Vec<u8>,
    },
    /// Server confirms authentication success
    #[serde(rename = "AUTH_OK")]
    Ok,
    /// Server rejects authentication
    #[serde(rename = "AUTH_FAILED")]
    Failed { reason: String },
    /// Client offers a one-time enrollment token instead of a secret
    #[serde(rename = "ENROLL_START")]
    EnrollStart {
        client_id: String,
        /// The token out of a `v=2` invite; valid until it has been exchanged
        /// once.
        token: String,
    },
    /// Server issues the credential the token was standing in for
    #[serde(rename = "ENROLL_ISSUE")]
    EnrollIssue {
        client_id: String,
        /// Base32-encoded secret, generated fresh for this enrollment.
        secret: String,
        algorithm: String,
        digits: u32,
        period: u64,
    },
    /// Server refuses the token
    #[serde(rename = "ENROLL_FAILED")]
    EnrollFailed { reason: String },
}

impl AuthMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tag is what the other side switches on, so the names are part of the
    /// contract with `crates/nexapipe-client/src/auth.rs`, which spells them
    /// out again. A rename here that misses there is a handshake that dies on
    /// the first message.
    #[test]
    fn enrollment_messages_keep_their_wire_names() {
        let start = AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: "tok".to_string(),
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_START""#), "{json}");
        assert_eq!(
            AuthMessage::from_bytes(json.as_bytes()).unwrap().to_bytes().unwrap(),
            start.to_bytes().unwrap()
        );

        let issue = AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
        };
        let json = String::from_utf8(issue.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_ISSUE""#), "{json}");

        let failed = AuthMessage::EnrollFailed {
            reason: "no".to_string(),
        };
        let json = String::from_utf8(failed.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_FAILED""#), "{json}");
    }
}

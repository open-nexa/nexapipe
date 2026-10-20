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
//! secret — or records the device key a key-based device offered — and burns
//! the token in the same write, so a link that was copied in transit stops
//! being a credential the moment it has been used once. The exchange runs on
//! the same stream, ahead of AUTH_START.
//!
//! The response is proven in one of two ways, and which one depends on what
//! the server holds for the device that answered — never on anything the
//! response itself says.
//!
//! The first is a secret: `signature` is
//! HMAC-SHA256(secret, nonce || timestamp.to_le_bytes()) over the client's
//! Base32-decoded TOTP secret, and `totp_code` carries a current code. So a
//! response only validates against the challenge that was issued for this very
//! connection — an intercepted response cannot be replayed over a new one —
//! and the timestamp bounds how long even the right response stays acceptable.
//!
//! The second is a device key: the same bytes signed with the Ed25519 private
//! half of the key registered under the device, with `totp_code` empty. A
//! device that runs unattended has nobody to read a code to it, so at
//! enrollment — the one moment a human is certainly present — such a device is
//! issued a credential that proves itself without one. Both proofs cover the
//! same message, so a response says the same thing either way: this client saw
//! this connection's nonce at this time.
//!
//! A `device_id` may ride along on the messages a client sends, and on the one
//! the server answers an enrollment with. It names which of a client's devices
//! is speaking, so one device can be revoked without rotating every other one.
//! It is `None` for a device that was never given a name — every client that
//! existed before per-device credentials — and a peer that does not know the
//! field ignores it rather than failing, so a client and a server built either
//! side of the change still complete a handshake.

use nexapipe_client::secret::SecretString;
use serde::{Deserialize, Serialize};

/// Messages exchanged during authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMessage {
    /// Client initiates authentication
    #[serde(rename = "AUTH_START")]
    Start {
        client_id: String,
        timestamp: i64,
        /// Which of this client's devices is authenticating. `None` is the
        /// device that was never given one, which is the only kind that
        /// existed before a client could have several.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    /// Server sends challenge nonce
    #[serde(rename = "AUTH_CHALLENGE")]
    Challenge { nonce: Vec<u8> },
    /// Client responds with TOTP code
    #[serde(rename = "AUTH_RESPONSE")]
    Response {
        client_id: String,
        timestamp: i64,
        /// The current TOTP code. Empty when the device is known by a key:
        /// there is no code for it, and the signature is the whole proof.
        totp_code: String,
        /// Over `nonce || timestamp.to_le_bytes()`: HMAC-SHA256 keyed with the
        /// client's TOTP secret, or an Ed25519 signature by the device's key
        /// when the server holds one for it. Both prove the same thing — this
        /// client saw this connection's challenge at this time — so which one
        /// this is depends on the receiving end's credential, not on anything
        /// said here.
        signature: Vec<u8>,
        /// The same device [`AuthMessage::Start`] named. It is signed over
        /// nowhere, so it is not proof of anything on its own — what it does is
        /// say which device's credential the response is to be checked against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
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
        ///
        /// A [`SecretString`]: an unspent token is a credential, and this one is
        /// wiped when the message is dropped.
        token: SecretString,
        /// The name the device asking to enroll wants to be issued under. The
        /// server is free to answer with the same name or refuse; the token is
        /// what authorizes the exchange, not this field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        /// The device key this client is asking to be issued under, as the
        /// public half of an Ed25519 key pair in lowercase hex.
        ///
        /// Absent for a client that has no key to offer, which is every client
        /// built before keys existed; a server that predates this field ignores
        /// it and issues a secret as before, so a client offering one has to
        /// keep working with what it is given. Present, it must arrive with a
        /// device name — a key belongs to one device, and the device that names
        /// none answers with the client's shared secret, which has no key to
        /// check against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
    },
    /// Server issues the credential the token was standing in for
    #[serde(rename = "ENROLL_ISSUE")]
    EnrollIssue {
        client_id: String,
        /// Base32-encoded secret, generated fresh for this enrollment. Empty
        /// when the device was issued a key instead: the server recorded the
        /// public key the client offered, and this device will prove itself
        /// with a signature rather than a code.
        ///
        /// A [`SecretString`]: a credential that has just been issued is the
        /// most valuable thing this process holds.
        secret: SecretString,
        algorithm: String,
        digits: u32,
        period: u64,
        /// The device this credential was issued for, which is how the client
        /// learns the name it will have to send back. Absent when the server
        /// answered an enrollment that named no device — a client that predates
        /// per-device credentials reads that as "the shared one".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    /// Server refuses the token
    #[serde(rename = "ENROLL_FAILED")]
    EnrollFailed { reason: String },
}

/// Longest client id the handshake accepts.
///
/// Long enough for any name a config would carry, short enough that one cannot
/// be used to push a wall of text through the logs.
pub const MAX_CLIENT_ID_LEN: usize = 255;

/// Longest device id the handshake accepts, and the reason is the same one.
///
/// A device id is chosen by the peer that sends it — the server echoes back
/// what an enrollment asked for, and after that the device supplies it on every
/// handshake — so it reaches the audit log without having been checked against
/// anything.
pub const MAX_DEVICE_ID_LEN: usize = 255;

/// Whether an id may be printed as it stands.
///
/// The rule is one rule because both ids arrive the same way: from a peer,
/// before anything about that peer is known, and both end up in the log line
/// for every outcome.
fn is_presentable_id(id: &str, max_len: usize) -> bool {
    !id.is_empty() && id.len() <= max_len && id.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Whether a client id may be printed as it stands.
///
/// A client id arrives before anything about the peer is known, and the server
/// puts it in the log line for every outcome — a refusal, a lockout, an
/// unknown client. Printable ASCII only, which is what keeps a peer from
/// ending its id with a CRLF and writing the next line itself.
pub fn is_presentable_client_id(id: &str) -> bool {
    is_presentable_id(id, MAX_CLIENT_ID_LEN)
}

/// Whether a device id may be printed as it stands.
pub fn is_presentable_device_id(id: &str) -> bool {
    is_presentable_id(id, MAX_DEVICE_ID_LEN)
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
            token: SecretString::new("tok".to_string()),
            device_id: None,
            public_key: None,
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_START""#), "{json}");
        assert_eq!(
            AuthMessage::from_bytes(json.as_bytes())
                .unwrap()
                .to_bytes()
                .unwrap(),
            start.to_bytes().unwrap()
        );

        let issue = AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
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

    /// The credential travels as the plain string it always was.
    ///
    /// The token and the secret are `Secret`s now, and a `Secret` that
    /// serialized differently would break every peer built before it: the
    /// field names and the spelling of the value are the contract, and the
    /// wrapper changes neither.
    #[test]
    fn a_credential_travels_as_the_plain_string_it_always_was() {
        let start = AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("tok".to_string()),
            device_id: None,
            public_key: None,
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""token":"tok""#), "{json}");

        let issue = AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            device_id: None,
        };
        let json = String::from_utf8(issue.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""secret":"JBSWY3DPEHPK3PXP""#), "{json}");
    }

    /// A peer on either side of this change has to be able to talk to one on
    /// the other side, and the whole interop story is one sentence: the field
    /// is absent when it is not being used. A peer that never heard of devices
    /// sends no such key, and this one reads that as the unnamed device.
    #[test]
    fn a_message_from_a_peer_that_never_heard_of_devices_still_parses() {
        let wire = r#"{"type":"AUTH_START","client_id":"client-001","timestamp":1}"#;

        let parsed = AuthMessage::from_bytes(wire.as_bytes()).expect("an old client still parses");
        let AuthMessage::Start {
            client_id,
            timestamp,
            device_id,
        } = parsed
        else {
            panic!("expected AUTH_START, got {parsed:?}");
        };

        assert_eq!(client_id, "client-001");
        assert_eq!(timestamp, 1);
        assert_eq!(device_id, None, "no name sent is the unnamed device");

        // And it goes back out the way it came in, so the two peers agree on
        // what a handshake between them looks like.
        assert_eq!(
            String::from_utf8(
                AuthMessage::Start {
                    client_id,
                    timestamp,
                    device_id,
                }
                .to_bytes()
                .unwrap()
            )
            .unwrap(),
            wire,
        );
    }

    /// The other half of that sentence: an unset device id is left off the
    /// wire entirely rather than sent as `null`, so a peer that does know the
    /// field cannot tell this one apart from an older one — which is what
    /// keeps nobody having to negotiate a version.
    #[test]
    fn an_unnamed_device_sends_no_device_id_at_all() {
        let json = String::from_utf8(
            AuthMessage::Response {
                client_id: "client-001".to_string(),
                timestamp: 1,
                totp_code: "123456".to_string(),
                signature: vec![7],
                device_id: None,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap();

        assert!(!json.contains("device_id"), "{json}");
    }

    /// Every message that can carry one, so a variant added later and given the
    /// field by copy-paste cannot end up with it spelled differently.
    #[test]
    fn a_named_device_survives_the_round_trip() {
        let messages = [
            AuthMessage::Start {
                client_id: "client-001".to_string(),
                timestamp: 1,
                device_id: Some("laptop".to_string()),
            },
            AuthMessage::Response {
                client_id: "client-001".to_string(),
                timestamp: 1,
                totp_code: "123456".to_string(),
                signature: vec![7],
                device_id: Some("laptop".to_string()),
            },
            AuthMessage::EnrollStart {
                client_id: "client-001".to_string(),
                token: SecretString::new("tok".to_string()),
                device_id: Some("laptop".to_string()),
                public_key: None,
            },
            AuthMessage::EnrollIssue {
                client_id: "client-001".to_string(),
                secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                algorithm: "SHA1".to_string(),
                digits: 6,
                period: 30,
                device_id: Some("laptop".to_string()),
            },
        ];

        for message in &messages {
            let bytes = message.to_bytes().expect("serializable");
            let json = String::from_utf8(bytes.clone()).unwrap();
            assert!(json.contains(r#""device_id":"laptop""#), "{json}");

            let back = AuthMessage::from_bytes(&bytes).expect("parses");
            assert_eq!(
                back.to_bytes().unwrap(),
                bytes,
                "a device id must not change shape on the way through"
            );
        }
    }

    /// A device id ends up in the log line for whatever happens to it, so it is
    /// held to what a client id is held to rather than to a rule of its own.
    #[test]
    fn a_device_id_is_refused_the_way_a_client_id_is() {
        assert!(is_presentable_device_id("laptop"));
        assert!(!is_presentable_device_id(""), "empty names nobody");
        assert!(
            !is_presentable_device_id("laptop\r\nINFO: connected"),
            "a trailing CRLF would write the next log line"
        );
        assert!(!is_presentable_device_id(
            &"d".repeat(MAX_DEVICE_ID_LEN + 1)
        ));

        // The two rules really are one rule: whatever is refused for one id is
        // refused for the other.
        for id in ["", "laptop\r\nINFO: connected", &"x".repeat(256)] {
            assert_eq!(is_presentable_device_id(id), is_presentable_client_id(id));
        }
    }

    /// A key offered at enrollment is what the server records and what the
    /// device will sign with, so it has to reach the other side exactly as it
    /// was said: a field that changes shape on the way through is a device
    /// that can never authenticate.
    #[test]
    fn an_enrollment_that_offers_a_key_carries_it_whole() {
        let key = "a1".repeat(32);
        let start = AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("tok".to_string()),
            device_id: Some("phone".to_string()),
            public_key: Some(key.clone()),
        };

        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(&format!(r#""public_key":"{key}""#)), "{json}");

        let back = AuthMessage::from_bytes(json.as_bytes()).expect("parses");
        assert_eq!(back.to_bytes().unwrap(), start.to_bytes().unwrap());
    }

    /// The other half of the absence-means-old-client rule, for enrollment: a
    /// client that has no key — every client built before this field existed —
    /// sends no such key, and what it sends goes back out byte for byte.
    #[test]
    fn an_enrollment_from_a_client_with_no_key_still_parses() {
        let wire = r#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop"}"#;

        let parsed = AuthMessage::from_bytes(wire.as_bytes()).expect("an old client still parses");
        let AuthMessage::EnrollStart { public_key, .. } = parsed else {
            panic!("expected ENROLL_START");
        };
        assert_eq!(public_key, None, "no key sent is a secret-based device");

        assert_eq!(
            String::from_utf8(
                AuthMessage::EnrollStart {
                    client_id: "client-001".to_string(),
                    token: SecretString::new("tok".to_string()),
                    device_id: Some("laptop".to_string()),
                    public_key: None,
                }
                .to_bytes()
                .unwrap()
            )
            .unwrap(),
            wire,
        );
    }
}

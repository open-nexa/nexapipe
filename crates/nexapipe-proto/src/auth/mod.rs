//! The authentication handshake, as it travels between a client and the server.
//!
//! # Why this is here and not in either of them
//!
//! The handshake used to be written down twice — once in the server and once in
//! the client — and the two copies were kept in step by a comment in each
//! saying "keep in sync with the other one". That is the whole failure mode of
//! a protocol written down twice: a field added on one side and forgotten on
//! the other is a handshake that dies on its first message, and the comment
//! that was supposed to prevent it is the only thing standing between the two
//! copies.
//!
//! So there is one copy, and both sides link it. A change to the protocol is a
//! change here, and there is nowhere else for it to be forgotten.
//!
//! # The messages
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
//! The response is proven in one of two ways, and which one depends on what the
//! server holds for the device that answered — never on anything the
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
//!
//! # The two forms
//!
//! A message travels in one of two forms, and the payload's first byte says
//! which:
//!
//! | first byte | the payload |
//! |---|---|
//! | `0x00` | the JSON form, behind the version byte |
//! | `0x01` | the binary form, behind the version byte |
//! | anything else | the JSON form with no version byte — what every peer sent before the version byte existed |
//!
//! A JSON message starts with `{`, which is neither of the two version bytes,
//! so the three are told apart by one look. The version byte is a
//! **discriminator**, not a negotiation: a message says what it is, and the
//! other end reads it. Nothing is agreed on beforehand, and nothing has to be
//! remembered between messages.
//!
//! The binary form exists because the JSON form is wasteful exactly where
//! the bytes are: a nonce and a signature are arrays of decimal numbers, so
//! each byte of either costs three. One handshake — a start, a challenge, a
//! response and an answer — is 427 bytes of JSON and 124 of binary.
//!
//! The JSON form stays, and stays readable, for as long as old peers exist.
//!
//! # What the wire format does change
//!
//! Two things, and both of them are things the wire should not have carried
//! in the first place:
//!
//! - **`algorithm` is a type.** It was a free-form string, and a name nobody
//!   supports was a name the receiving side had to decide what to do with. It
//!   is one of three now, and its spelling on the wire is the one the server
//!   has always sent.
//! - **`AUTH_START` can announce a version.** The field is optional and
//!   absent by default, so a peer that predates it sends exactly what it
//!   sent before.

mod challenge;
mod codec;
mod message;

pub use challenge::{ChallengeError, challenge_message, close_code, hmac_challenge};
pub use message::AuthMessage;

use std::fmt;
use std::io;

use serde::{Deserialize, Deserializer, Serialize, de};
use zeroize::{Zeroize, Zeroizing};

/// The TOTP algorithm, as it travels.
///
/// The names are the canonical ones — `sha1`, `sha256`, `sha512` — and they
/// are read in any case, because the configuration this comes from is read
/// that way too. What is not free-form any more is the algorithm itself: it
/// was a string on the wire, and a name nobody supports was a name the
/// receiving side had to decide what to do with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// HMAC-SHA1 — the default, and what every client used before the choice
    /// existed.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl Algorithm {
    /// The canonical name, as the configuration and the wire spell it.
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
        }
    }

    /// The algorithm a name means, in any case — or `None` for a name nobody
    /// supports.
    ///
    /// `None` rather than a default: an algorithm that is quietly turned into
    /// a different one is a silent downgrade, and the client computes codes
    /// the server does not accept.
    pub fn from_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("sha1") {
            Some(Algorithm::Sha1)
        } else if name.eq_ignore_ascii_case("sha256") {
            Some(Algorithm::Sha256)
        } else if name.eq_ignore_ascii_case("sha512") {
            Some(Algorithm::Sha512)
        } else {
            None
        }
    }

    /// The byte this algorithm is in the binary form.
    pub fn to_byte(&self) -> u8 {
        match self {
            Algorithm::Sha1 => 0x01,
            Algorithm::Sha256 => 0x02,
            Algorithm::Sha512 => 0x03,
        }
    }

    /// The algorithm a byte is — or `None` for a byte that is not one.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Algorithm::Sha1),
            0x02 => Some(Algorithm::Sha256),
            0x03 => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

/// The name is read in any case, and a name nobody supports is an error
/// rather than a quiet fall back to SHA1.
impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Algorithm::from_name(&name).ok_or_else(|| {
            de::Error::custom(format!(
                "{name:?} is not a TOTP algorithm; expected \"sha1\", \"sha256\" or \"sha512\""
            ))
        })
    }
}

/// The version byte that says the payload behind it is the JSON form.
pub const VERSION_JSON: u8 = 0x00;

/// The version byte that says the payload behind it is the binary form.
pub const VERSION_BINARY: u8 = 0x01;

/// The form a message travels in.
///
/// The payload's first byte says which of these it is — and a payload that
/// does not start with a version byte is the JSON form, because that is what
/// every peer sent before the version byte existed. A JSON message always
/// starts with `{`, which is neither of the two version bytes, so the three
/// are told apart by one look.
///
/// The version byte is a **discriminator**, not a negotiation: a message says
/// what it is, and the other end reads it. Nothing is agreed on beforehand
/// and nothing has to be remembered between messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The JSON form with no version byte in front of it: what every peer
    /// sent before the version byte existed, and what a peer that predates it
    /// can read.
    LegacyJson,
    /// The JSON form behind the version byte [`VERSION_JSON`].
    ///
    /// A peer that speaks the versioned protocol but whose messages are still
    /// JSON. It keeps the JSON encoder alive inside the versioned protocol,
    /// which is what stops the two encoders drifting apart unnoticed.
    Json,
    /// The binary form behind the version byte [`VERSION_BINARY`].
    Binary,
}

impl Format {
    /// The version byte in front of a payload in this form — or `None` for
    /// the form that has none.
    pub fn version_byte(&self) -> Option<u8> {
        match self {
            Format::LegacyJson => None,
            Format::Json => Some(VERSION_JSON),
            Format::Binary => Some(VERSION_BINARY),
        }
    }

    /// The form a version number means, if this build knows it.
    pub fn from_version(version: u8) -> Option<Self> {
        match version {
            VERSION_JSON => Some(Format::Json),
            VERSION_BINARY => Some(Format::Binary),
            _ => None,
        }
    }
}

/// Why a message could not be put on the wire, or taken off it.
#[derive(Debug)]
pub enum CodecError {
    /// The JSON form: the payload is not JSON, or not a message.
    Json(serde_json::Error),
    /// The binary form: the payload is not a message this build knows.
    Binary(String),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Json(error) => write!(f, "{error}"),
            CodecError::Binary(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for CodecError {}

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

/// The room a serialized message is given up front.
///
/// A handshake message is a few hundred bytes at most, so the buffer is given
/// room for one and does not have to grow in the ordinary case. It is only an
/// optimisation: the buffer wipes the block it leaves behind when it does
/// grow, so the size of a message is not a limit on the guarantee.
const SERIALIZED_CAPACITY: usize = 4096;

/// A buffer that wipes the block it leaves behind.
///
/// A `Vec` that grows hands the old block back to the allocator without
/// wiping it, and that block held part of the credential: the allocator is
/// where a core dump, a swap file or a read of `/proc/<pid>/mem` finds it.
/// This one copies what it holds into the new block, wipes the old one, and
/// only then lets it go.
///
/// The buffer that comes out of it is a [`Zeroizing`], so the copy the caller
/// holds is wiped when it goes out of scope as well.
struct WipingBuffer {
    bytes: Vec<u8>,
}

impl WipingBuffer {
    /// A buffer with room for `capacity` bytes.
    fn with_capacity(capacity: usize) -> Self {
        WipingBuffer {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Makes room for `extra` more bytes.
    ///
    /// The old block is wiped before it goes back to the allocator, so the
    /// bytes that were in it are gone even where the block itself is not.
    fn reserve_for(&mut self, extra: usize) {
        if self.bytes.capacity() - self.bytes.len() >= extra {
            return;
        }
        let wanted = self.bytes.len() + extra;
        let mut fresh = Vec::with_capacity(wanted.next_power_of_two());
        fresh.extend_from_slice(&self.bytes);
        self.bytes.zeroize();
        self.bytes = fresh;
    }

    /// A byte at the end.
    fn push(&mut self, byte: u8) {
        self.reserve_for(1);
        self.bytes.push(byte);
    }

    /// Bytes at the end.
    fn extend_from_slice(&mut self, other: &[u8]) {
        self.reserve_for(other.len());
        self.bytes.extend_from_slice(other);
    }

    /// The bytes written, in a buffer that wipes itself.
    fn into_wiped(mut self) -> Zeroizing<Vec<u8>> {
        // The buffer is taken rather than moved out of: a type with a `Drop`
        // cannot have its fields moved out of it. The empty vector that takes
        // its place is wiped by the `Drop` below, which is a no-op on an empty
        // one.
        Zeroizing::new(std::mem::take(&mut self.bytes))
    }
}

/// The buffer wipes itself when it goes out of scope.
///
/// The writer is dropped when a serialization fails — the `?` in
/// [`AuthMessage::to_bytes`] and [`AuthMessage::to_payload`] drops the buffer
/// on the way out — and by then it may already hold the credential: a message
/// that fails halfway through has written the token before it fails on the
/// field behind it. Without this, the bytes of that credential go back to the
/// allocator unwiped, which is the very thing the buffer exists to prevent.
impl Drop for WipingBuffer {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// The JSON encoder writes into the buffer, so the buffer writes.
impl io::Write for WipingBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;

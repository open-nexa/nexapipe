//! The credentials a device holds.
//!
//! A device is a machine: it proves itself with a key rather than with a
//! code, so it has no secret to keep and no human to type one. What it has
//! instead is a place in the client's own list of devices.

use nexapipe_proto::secret::{SecretBytes, SecretString};
use serde::{Deserialize, Serialize};

use super::step::{StepVerdict, accept_step};
use super::{decode_base32_secret, default_created_at};

/// One device under a client: a credential of its own.
///
/// Everything a [`ClientAuth`](super::ClientAuth) is asked for, this is asked for too, and the
/// answer is the same shape — a credential issued by the server and a record
/// of when. What it does not carry is an `allow_hosts` of its own: what a client
/// may reach is one policy, answered by the client's entry, and a second place
/// to say it would only be a second place to disagree.
///
/// The credential is one of two kinds, and exactly one is set: `secret` is a
/// TOTP seed the device shares with the server, `public_key` is the half of a
/// key pair the device keeps the other half of. Both, or neither, is an entry
/// the loader refuses — there would be no way to say how the device proves
/// itself — so which field is set is what the handshake reads to know which
/// proof to demand.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceAuth {
    /// Base32-encoded secret key, issued when this device enrolled.
    ///
    /// Empty when the device answers with a signature instead — see
    /// [`Self::public_key`].
    ///
    /// A [`SecretString`], for the reason the client's own secret is one.
    #[serde(default)]
    pub secret: SecretString,
    /// The device's Ed25519 public key, hex, when it proves itself with a
    /// signature instead of a TOTP code.
    ///
    /// The private half never leaves the device, so unlike a secret there is
    /// nothing here that leaks if the file is read: the entry is what makes
    /// this key the one credential the device may answer with, and deleting
    /// the entry is how that is taken away.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// When this device was issued its credential
    #[serde(default = "default_created_at")]
    pub created_at: String,
    /// Last successful authentication time (Unix timestamp)
    #[serde(default)]
    pub last_used: Option<u64>,
    /// The last TOTP step this device's code was accepted on.
    ///
    /// The step, not the code: a code changes every thirty seconds, and what
    /// is worth remembering is the **step** — a code from an earlier step is
    /// still inside the acceptance window, and this is what refuses it.
    ///
    /// A device that answers with a **signature** has no code and no step:
    /// a signature covers the challenge that was issued for one connection,
    /// so there is nothing for a second use to replay.
    #[serde(default)]
    pub last_used_step: Option<u64>,
}

/// The material one device's credential is made of, on its way into the file:
/// a TOTP secret or a public key, never both.
///
/// [`DeviceAuth`] carries the same choice as two fields, kept in the XOR the
/// loader enforces. This is that constraint at the writing end, where a caller
/// that had both would be making a mistake the type does not let it make.
///
/// `Copy` because it is a pair of borrows and callers hand it on more than
/// once; no `Debug`, so a `Secret` cannot end up in a log line by formatting
/// the enum that carries it.
#[derive(Clone, Copy)]
pub enum DeviceMaterial<'a> {
    /// A Base32 TOTP seed — what an enrollment and `client add` issue.
    Secret(&'a str),
    /// A device's Ed25519 public key, hex — the half of a key pair an operator
    /// registers, the other half staying on the device.
    PublicKey(&'a str),
}

/// Same reason as [`ClientAuth`](super::ClientAuth)'s, and the same consequence: the whole config
/// is logged when it is parsed, and a device secret is as live a credential as
/// a client's. The public key is not redacted: it is public by definition, and
/// seeing it in a log is how one tells which devices are key-based.
impl std::fmt::Debug for DeviceAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuth")
            .field("secret", &"<redacted>")
            .field("public_key", &self.public_key)
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("last_used_step", &self.last_used_step)
            .finish()
    }
}

impl DeviceAuth {
    /// Decode the Base32 secret into bytes.
    ///
    /// A device secret is spelled the way a client's is, because it is issued
    /// the same way and written by the same hand — so it is normalised by the
    /// same rule, and an un-decodable one is the same misconfiguration.
    ///
    /// A key-based device has no secret, and the handshake asks it for a
    /// signature instead of calling this.
    pub fn decode_secret(&self) -> Result<SecretBytes, anyhow::Error> {
        decode_base32_secret(self.secret.as_str())
    }

    /// Whether this device's code may be used on this step, and the memory
    /// that goes with the answer.
    ///
    /// RFC 6238 §5.2's rule: a step that is not greater than the last
    /// accepted one has been used already.
    pub fn accept_step(&mut self, step: u64) -> StepVerdict {
        accept_step(&mut self.last_used_step, step)
    }
}

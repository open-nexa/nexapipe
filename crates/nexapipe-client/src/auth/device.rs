//! The key a device proves itself with.
//!
//! A device is a machine: it has no secret to keep and no human to type a
//! code, so it signs the challenge instead. The private half never leaves
//! the process, and the public half is what an enrollment offers.

use std::fmt;

use crate::ClientError;

/// A device's own Ed25519 key: the credential a device proves itself with when
/// nobody is there to read a code off a screen.
///
/// The private half is the credential and never leaves the device; the public
/// half is what the server stores, under the name of the device the key was
/// issued to. Both are lowercase hex, because that is the spelling the server's
/// config file uses and the only spelling an app has to write down — an app
/// that keeps a key across a restart has nowhere else to put it but a string.
///
/// The type exists so that both apps agree on that spelling, and so that
/// neither of them has to do Ed25519 itself: Android's cryptography API has no
/// Ed25519 below API 33, and the app supports API 26.
#[derive(Clone)]
pub struct DeviceKey {
    key: iroh::SecretKey,
}

impl DeviceKey {
    /// A fresh key pair. The private half is never handed to anybody; the
    /// public half is what an enrollment offers.
    pub fn generate() -> Self {
        Self {
            key: iroh::SecretKey::generate(),
        }
    }

    /// Reads a private half back from the spelling it was stored in.
    ///
    /// The length is what is checked, and it is checked strictly: a key is 32
    /// bytes, so a stored key is 64 hex characters, and anything else is a
    /// string that is not a key. The bytes themselves are not a point on a
    /// curve — an Ed25519 private key is arbitrary bytes, and a key that was
    /// never offered to a server simply proves nothing.
    pub fn from_hex(spelled: &str) -> Result<Self, ClientError> {
        let trimmed = spelled.trim();
        let decoded = hex::decode(trimmed).map_err(|_| {
            ClientError::InvalidConfig(
                "a device key is 64 hex characters, and this is not hex".into(),
            )
        })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            ClientError::InvalidConfig(format!(
                "a device key is 64 hex characters, and this one is {} characters",
                trimmed.len()
            ))
        })?;
        Ok(Self {
            key: iroh::SecretKey::from_bytes(&bytes),
        })
    }

    /// The private half, lowercase hex — the spelling an app persists.
    ///
    /// It is the credential, so it is written down the way a TOTP secret is:
    /// encrypted at rest, behind the operating system's own door, and never
    /// shown on a screen.
    pub fn private_hex(&self) -> String {
        hex::encode(self.key.to_bytes())
    }

    /// The public half, lowercase hex — the spelling the server stores and the
    /// one an app displays.
    pub fn public_hex(&self) -> String {
        hex::encode(self.key.public().as_bytes())
    }

    /// The key itself, for the paths that need to sign with it.
    pub fn secret_key(&self) -> &iroh::SecretKey {
        &self.key
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key's own `Debug` is redacted, so this cannot leak the private
        // half — but the public half is named, because it is not a secret and
        // it is what identifies this device to an operator.
        f.debug_struct("DeviceKey")
            .field("public_key", &self.public_hex())
            .finish()
    }
}

/// Whether a device name the server will accept.
///
/// The rule is the server's, and it now lives with the server's: printable
/// ASCII, space excluded, not empty, and short enough to sit in a config key
/// and a log line. A hostname is the obvious thing to name a device after and
/// the obvious way to break this — "MacBook Pro" has a space in it — so
/// whatever builds a name has to put the rule somewhere it is applied rather
/// than remembered.
///
/// An app can tell before it enrols rather than after, which is why it is
/// here at all: [`nexapipe_proto::auth::is_presentable_device_id`] is the same
/// rule, and this is the name it answers to on the client side.
pub fn device_id_is_usable(id: &str) -> bool {
    nexapipe_proto::auth::is_presentable_device_id(id)
}

//! The device id: what a device is called on the wire.
//!
//! A device used to be called by a name an operator gave it, which put the
//! naming where the naming does not belong: the person inviting a device does
//! not know what it will be called, and the device does know — it is the
//! machine it runs on. So the name became a label the device reports about
//! itself, and the identity became something both sides can work out on their
//! own: the fingerprint of the public half of the device's key.
//!
//! That is what this module is for. Both sides link it, so the two cannot
//! disagree about what a device is called — a disagreement here would be a
//! device that enrolls under one id and handshakes under another, and it would
//! look like a takeover.

use sha2::{Digest, Sha256};

/// The prefix every derived device id carries.
///
/// It says what the id is, and it keeps a derived id from ever being read as a
/// name an operator chose: a row keyed `d-…` was filed by the fingerprint and
/// a row keyed anything else was filed by hand.
const DEVICE_ID_PREFIX: &str = "d-";

/// How many hex characters of the fingerprint the id carries.
///
/// Sixteen hex characters are 64 bits, which is more than enough to tell a
/// handful of devices apart and short enough to read out loud, to paste into a
/// command line and to sit in a log line without being the thing everybody
/// scrolls past.
///
/// The id is not a secret and does not have to be unguessable: the credential
/// that goes with it is the private half of the key, and the id is checked
/// against the public half the server holds. A collision would mean two
/// devices sharing one id, and the server refuses a second key under an id
/// that is already there — so a collision costs the second device an
/// enrollment, and nothing else.
const FINGERPRINT_CHARS: usize = 16;

/// The id a device is known by, derived from the public half of its key.
///
/// The same key always gives the same id, on every machine and in every
/// process: the device works out its id before it connects, and the server
/// works out the same one from the key the enrollment offered.
pub fn device_id_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    let mut id = String::with_capacity(DEVICE_ID_PREFIX.len() + FINGERPRINT_CHARS);
    id.push_str(DEVICE_ID_PREFIX);
    for byte in digest.iter().take(FINGERPRINT_CHARS / 2) {
        id.push_str(&format!("{byte:02x}"));
    }
    id
}

/// Whether an id is one this build derived.
///
/// The shape, not the origin: an id that looks like a derived one is treated as
/// one wherever the two are told apart, and what it is used for — refusing a
/// second key under an id that is already there — is the right thing to do for
/// a hand-written id as well.
pub fn is_derived_device_id(id: &str) -> bool {
    let Some(fingerprint) = id.strip_prefix(DEVICE_ID_PREFIX) else {
        return false;
    };
    fingerprint.len() == FINGERPRINT_CHARS
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public key, spelled the way the handshake spells one.
    fn public_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn the_same_key_always_gives_the_same_id() {
        assert_eq!(
            device_id_from_public_key(&public_key(1)),
            device_id_from_public_key(&public_key(1))
        );
    }

    #[test]
    fn two_keys_give_two_ids() {
        assert_ne!(
            device_id_from_public_key(&public_key(1)),
            device_id_from_public_key(&public_key(2))
        );
    }

    #[test]
    fn the_id_says_what_it_is_and_is_printable() {
        let id = device_id_from_public_key(&public_key(7));

        assert!(id.starts_with(DEVICE_ID_PREFIX));
        assert!(is_derived_device_id(&id));
        // It reaches the log line for every handshake and the config file as a
        // key, so it has to be printable ASCII and short.
        assert!(id.is_ascii());
        assert!(id.len() <= crate::auth::MAX_DEVICE_ID_LEN);
    }

    #[test]
    fn a_name_is_not_a_derived_id() {
        assert!(!is_derived_device_id("laptop"));
        assert!(!is_derived_device_id(""));
        assert!(!is_derived_device_id("d-"));
        // Right shape, wrong spelling: the fingerprint is lowercase hex.
        assert!(!is_derived_device_id("d-9F2C1A4B7E0D3F58"));
        // Right prefix, wrong length.
        assert!(!is_derived_device_id("d-9f2c"));
    }
}

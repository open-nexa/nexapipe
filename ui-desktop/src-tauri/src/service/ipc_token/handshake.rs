//! The challenge the service sends, the answer the caller sends back, and the
//! comparison that tells the two apart.

use super::candidate::TokenCandidate;

/// What the caller answers a challenge with: HMAC-SHA256 over the service's
/// nonce followed by the caller's own.
///
/// Binding both nonces is what makes the answer single-use, and the caller's
/// nonce is what the service then has to answer back for — see [`proof_mac`].
pub fn auth_mac(token: &str, service_nonce: &str, caller_nonce: &str) -> String {
    mac_hex(token, service_nonce, caller_nonce)
}

/// What the service answers with, so the caller can tell it from a squatter on
/// the IPC port.
///
/// The nonces are the other way round so the two directions cannot produce the
/// same value: otherwise a caller that recorded the service's own challenge
/// answer could hand it back as proof.
pub fn proof_mac(token: &str, service_nonce: &str, caller_nonce: &str) -> String {
    mac_hex(token, caller_nonce, service_nonce)
}

/// Whether `presented` is what [`auth_mac`] produces for the caller's nonce
/// under any published token, and which candidate it was.
///
/// The candidate is returned rather than the bare token, because the service
/// has to know *whose* token answered: it computes its own proof under the
/// same one, and it refuses a caller that is not the account the token belongs
/// to.
pub fn token_for_auth<'a>(
    candidates: &'a [TokenCandidate],
    service_nonce: &str,
    caller_nonce: &str,
    presented: &str,
) -> Option<&'a TokenCandidate> {
    candidates.iter().find(|candidate| {
        constant_time_eq(
            &auth_mac(&candidate.token, service_nonce, caller_nonce),
            presented,
        )
    })
}

/// Whether `presented` is what [`proof_mac`] produces under `token`.
pub fn proof_matches(
    token: &str,
    service_nonce: &str,
    caller_nonce: &str,
    presented: &str,
) -> bool {
    constant_time_eq(&proof_mac(token, service_nonce, caller_nonce), presented)
}

/// HMAC-SHA256 of two nonces under a token, lowercase hex.
fn mac_hex(token: &str, first: &str, second: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    // HMAC accepts a key of any length, so this cannot fail.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(token.as_bytes()).expect("HMAC takes a key of any length");
    // The separator keeps two nonces from being ambiguous: both directions carry
    // the same pair, and "ab" + "c" must not hash like "a" + "bc".
    mac.update(first.as_bytes());
    mac.update(b".");
    mac.update(second.as_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Length-tolerant, otherwise constant-time comparison.
///
/// The same shape as [`token_matches`]: the length already differs, so nothing
/// is gained by hiding it, and comparing the leading bytes one by one is not
/// free information either.
fn constant_time_eq(expected: &str, presented: &str) -> bool {
    if expected.len() != presented.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.as_bytes().iter().zip(presented.as_bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

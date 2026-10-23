//! The two secrets this module hands out: the token and the handshake nonce.

use crate::error::{codes, AppError};

/// Bytes of entropy in a token.
const TOKEN_BYTES: usize = 32;

/// Bytes of entropy in a handshake nonce.
///
/// A nonce is single-use and never leaves the connection it was made for, so it
/// needs only to be unpredictable — which is the same thing a token needs, and
/// comes from the same place.
pub const NONCE_BYTES: usize = 32;

/// A fresh token, drawn from the OS CSPRNG.
///
/// `fastrand` used to be the source here. It is a fast non-cryptographic
/// generator seeded from the clock and ASLR, which is fine for a scratch
/// directory name and not for the one secret that decides who may drive an
/// elevated service: a token an attacker can predict is a token they can
/// present.
///
/// Public so a test in another module can hold a secret of the same shape
/// without writing a literal into a key slot.
pub fn generate_token() -> Result<String, AppError> {
    random_hex(TOKEN_BYTES)
}

/// A fresh handshake nonce.
///
/// The service sends one and the caller sends one; everything the handshake
/// proves is bound to the pair, so a captured answer cannot be replayed on
/// another connection.
pub fn random_nonce() -> Result<String, AppError> {
    random_hex(NONCE_BYTES)
}

/// `len` bytes from the OS CSPRNG, lowercase hex.
///
/// Hex rather than raw bytes because both a token and a nonce cross a
/// newline-delimited JSON channel, and the token file is a text file a human may
/// end up looking at.
fn random_hex(len: usize) -> Result<String, AppError> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|e| {
        AppError::cause(
            codes::SERVICE_IPC_TOKEN,
            format!("cannot read {len} random bytes from the OS: {e}"),
        )
    })?;

    let mut hex = String::with_capacity(len * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

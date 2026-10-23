use super::master_key::KEY_LEN;
use crate::error::{codes, AppError};

pub(super) fn random_bytes<const N: usize>() -> Result<[u8; N], AppError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| {
        AppError::cause(
            codes::CREDENTIALS_STORE_FAILED,
            format!("cannot read {N} random bytes from the OS: {e}"),
        )
    })?;
    Ok(bytes)
}

pub(super) fn parse_key(hex: &str) -> Option<[u8; KEY_LEN]> {
    if hex.len() != KEY_LEN * 2 {
        return None;
    }

    // Converted whole rather than copied into a zeroed buffer: a key made of
    // zeroes is what a short conversion would silently leave behind, and the
    // two are indistinguishable once the bytes are out of this function.
    let bytes = unhex(hex)?;
    <[u8; KEY_LEN]>::try_from(bytes).ok()
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(super) fn unhex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).ok())
        .collect()
}

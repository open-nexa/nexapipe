//! The 2FA side of the client.
//!
//! It is five things, and they are five files:
//!
//! - `totp` — the algorithm, the configuration, and the secret.
//! - `two_factor` — the authenticator that answers a challenge with a code.
//! - `device` — the key a device proves itself with.
//! - `enrollment` — the exchange that trades an invitation for a credential.
//! - `message` — the framing of the handshake's messages.
//!
//! This one holds what the rest of the crate calls, and the shared imports.

mod device;
mod enrollment;
mod message;
mod totp;
mod two_factor;

#[cfg(test)]
mod tests;

pub use device::{DeviceKey, device_id_is_usable};
pub use enrollment::{Enrollment, IssuedCredential};
pub use totp::{TotpAlgorithm, TwoFactorConfig, generate_secret};
pub use two_factor::TwoFactorAuth;

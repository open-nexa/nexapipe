//! 2FA authentication module for Nexapipe server.
//!
//! Provides TOTP (Time-based One-Time Password) verification for client
//! connections, and Ed25519 device keys for devices that prove themselves
//! without a human present.

pub mod config;
pub mod device_key;
pub mod otpauth;
pub mod protocol;
pub mod state;
pub mod totp;

pub use config::{
    AuthConfig, ClientAcl, ClientAuth, DeviceAuth, DeviceMaterial, TotpAlgorithm,
    generate_enrollment_token,
};
pub use device_key::{parse_public_key, public_key_hex};
pub use otpauth::{DEFAULT_ISSUER, OtpAuthUri};
pub use protocol::{
    AuthMessage, MAX_DEVICE_ID_LEN, is_presentable_client_id, is_presentable_device_id,
};
pub use totp::{AuthError, TotpValidator};

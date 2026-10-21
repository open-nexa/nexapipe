//! 2FA authentication module for Nexapipe server.
//!
//! Provides TOTP (Time-based One-Time Password) verification for client
//! connections, and Ed25519 device keys for devices that prove themselves
//! without a human present.

pub mod config;
pub mod device_key;
pub mod otpauth;
pub mod state;
pub mod totp;

pub use config::{
    AuthConfig, ClientAcl, ClientAuth, DeviceAuth, DeviceMaterial, TotpAlgorithm,
    generate_enrollment_token,
};
pub use device_key::{parse_public_key, public_key_hex};
pub use otpauth::{DEFAULT_ISSUER, OtpAuthUri};
// The handshake and the rules about the names in it live in `nexapipe-proto`,
// which the client links too: they used to be written down twice, once on
// each side, and the comment in each copy saying "keep in sync with the
// other one" was the only thing keeping them in step.
pub use nexapipe_proto::auth::{
    AuthMessage, MAX_CLIENT_ID_LEN, MAX_DEVICE_ID_LEN, is_presentable_client_id,
    is_presentable_device_id,
};
pub use totp::{AuthError, TotpValidator};

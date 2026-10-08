//! 2FA authentication module for Nexapipe server.
//!
//! Provides TOTP (Time-based One-Time Password) verification for client connections.

pub mod config;
pub mod otpauth;
pub mod protocol;
pub mod totp;

pub use config::{
    AuthConfig, ClientAcl, ClientAuth, DeviceAuth, TotpAlgorithm, generate_enrollment_token,
};
pub use otpauth::{DEFAULT_ISSUER, OtpAuthUri};
pub use protocol::{
    AuthMessage, MAX_DEVICE_ID_LEN, is_presentable_client_id, is_presentable_device_id,
};
pub use totp::{AuthError, TotpValidator};

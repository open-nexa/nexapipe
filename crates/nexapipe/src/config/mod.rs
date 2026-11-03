//! The configuration file: what it says, and what is done with it.
//!
//! The file is one thing, and it is six: the shapes it is written in, the
//! routes it is translated into, the rules it has to satisfy, the way it is
//! read, the credential half of it, and the identity the endpoint keeps.
//!
//! Where it is kept is not this module's business: that is the storage's, and
//! it lives in [`crate::storage`]. What is here is the same whichever store
//! the configuration came out of.

mod auth_file;
mod identity;
mod io;
mod load;
mod routes;
mod schema;
mod validate;

#[cfg(test)]
mod tests;

pub use auth_file::{
    AuthTomlConfig, ClientAuthToml, ClientSecretWrite, DeviceAuthToml,
    check_credential_file_permissions,
};
pub use identity::{EndpointIdentity, generate_secret_key_hex};
pub use io::{FIRST_RUN_CONFIG, should_warn_about_permissions, warn_about_readable_credentials};
pub use load::{load_config, load_config_with_auth};
pub use schema::{
    AdminConfig, BackendProtocol, BackendsConfig, CircuitBreaker, CircuitBreakerConfig,
    CredentialSource, HealthCheckConfig, IrohConfig, LocalProxyConfig, LocalProxyNode,
    LocalProxyTwoFactorConfig, LogConfig, MetricsConfig, PeersConfig, ProxyConfig, Retry,
    RetryConfig, RouteMode, RouteSpec, ServerConfig, Timeouts, TimeoutsConfig,
    get_backend_protocol,
};
pub use validate::{
    get_route_mode, get_route_modes, get_strategy, parse_route_mode, validate_backend,
};

#[cfg(test)]
pub(crate) use identity::{
    IROH_SECRET_KEY_ENV, IROH_SECRET_KEY_FILE_ENV, persistence_disabled, resolve_secret_key_source,
};
// The lost-race test reads the key file back, and it is Unix-only: the file
// mode it sets is the point of the test. The re-export follows the test, or
// the import is unused on a host that never runs it.
#[cfg(all(test, unix))]
pub(crate) use identity::write_key_file;
pub(crate) use identity::{IdentityAction, identity_action, identity_into_file};
pub(crate) use io::parse_config;
pub(crate) use schema::redacted;
pub(crate) use validate::validate_totp_parameters;

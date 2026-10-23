//! The configuration file: what it says, and what is done with it.

// The file is one thing, and it is six: the shapes it is written in, the
// routes it is translated into, the rules it has to satisfy, the file it is
// read from and written to, the credential half of it, and the identity the
// endpoint keeps.
mod auth_file;
mod identity;
mod io;
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
pub use io::{
    ensure_config_file, should_warn_about_permissions, warn_about_readable_credentials,
    with_config_lock,
};
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

pub(crate) use auth_file::sub_table;
#[cfg(test)]
pub(crate) use identity::{
    IROH_SECRET_KEY_ENV, IROH_SECRET_KEY_FILE_ENV, persistence_disabled, resolve_secret_key_source,
};
// The lost-race test reads the key file back, and it is Unix-only: the file
// mode it sets is the point of the test. The re-export follows the test, or
// the import is unused on a host that never runs it.
#[cfg(all(test, unix))]
pub(crate) use identity::write_key_file;
pub(crate) use io::{
    device_entry, parse_config, read_config_document, write_config_document, write_config_file,
};
pub(crate) use schema::redacted;
pub(crate) use validate::validate_totp_parameters;

//! The proxy: the endpoint the clients reach, and the listeners it serves.

// The pieces of it: the two things the binary starts, the health checks the
// routes need, the plaintext listener and the request handling behind it, what
// the access log is allowed to claim, and the tests.
pub mod local_proxy;

mod access;
mod health;
mod plaintext;
mod request;
mod server;

#[cfg(test)]
mod tests;

/// Shared by the startup path and the config watcher, which spawns checkers for
/// routes that appear in a reload.
pub use crate::http::BackendClients;

pub use health::sync_health_checks;
pub use server::{ProxyOptions, run_local_proxy, run_proxy};

pub(crate) use plaintext::plaintext_auth_conflict;

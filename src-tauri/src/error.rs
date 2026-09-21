//! The error contract shared by every Tauri command and by the service IPC channel.
//!
//! The UI ships in English and Simplified Chinese, so Rust must not hand the frontend prose to
//! display. Every failure is instead described by a stable code from [`codes`], which the
//! frontend resolves against `src/api/errors.ts` / the locale files (`error.<code>`), plus an
//! optional `detail` holding the raw diagnostic (an OS error, a service-manager stderr dump,
//! ...). `detail` is English by convention, is never localized, and is meant for the log and for
//! a collapsed "technical details" disclosure — never for the headline message.
//!
//! Adding a code is a two-sided change: declare it here **and** teach the frontend about it
//! (`src/api/errors.ts` message keys). A code must never be renamed silently: it is part of the
//! wire format between the UI, the service daemon, and a previously installed service binary.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable, dot-namespaced error codes.
///
/// `detail` belongs in the error payload, not in the code: `service.install_failed` with the
/// `sc` stderr as detail is one code, not one code per possible message.
pub mod codes {
    // -- proxy ------------------------------------------------------------------------------
    /// `start_proxy` was called with no node that carries a ticket or an endpoint ID.
    pub const PROXY_NO_NODES: &str = "proxy.no_nodes";
    /// The load-balancing strategy string did not match a known strategy.
    pub const PROXY_INVALID_LOAD_BALANCING: &str = "proxy.invalid_load_balancing";
    /// `ProxyManager::start` failed asynchronously, after `start_proxy` had already returned.
    pub const PROXY_START_FAILED: &str = "proxy.start_failed";
    /// No configured backend could be reached, so the proxy would have forwarded to nothing.
    ///
    /// Separate from [`PROXY_START_FAILED`] because it is actionable: the node ID may not exist,
    /// or the network/relay may be down. Every entry point applies the same rule — building a
    /// client never dials, so an unreachable backend is only detectable by probing, and a probe
    /// that reaches nothing is a failed start rather than a successful one.
    pub const PROXY_NO_REACHABLE_BACKEND: &str = "proxy.no_reachable_backend";
    /// A backend accepted the connection and then refused it because this client never performed
    /// the 2FA handshake: it has no credentials configured while the server requires them.
    ///
    /// Separate from [`PROXY_NO_REACHABLE_BACKEND`] because the backend is up — the probe reaches
    /// it and is then closed — and because the fix is on this side of the connection.
    pub const PROXY_TWO_FACTOR_REQUIRED: &str = "proxy.two_factor_required";
    /// The proxy is not running, so it has no node ID to report.
    pub const PROXY_NOT_RUNNING: &str = "proxy.not_running";
    /// The proxy is running but has not published its node ID yet.
    pub const PROXY_NODE_ID_UNAVAILABLE: &str = "proxy.node_id_unavailable";
    /// TUN mode was requested (`use_tun = true`) but the process has no privileges to create
    /// the tunnel. Requested, not probed: the backend refuses to silently downgrade to local
    /// proxy, because that would forward traffic differently from what the user asked for.
    pub const PROXY_TUN_UNAVAILABLE: &str = "proxy.tun_unavailable";

    // -- service ----------------------------------------------------------------------------
    /// No service is listening on the IPC port.
    pub const SERVICE_UNAVAILABLE: &str = "service.unavailable";
    /// The service connection broke mid-exchange.
    pub const SERVICE_IO_ERROR: &str = "service.io_error";
    /// The service answered with something unparseable, or with an unexpected message kind.
    pub const SERVICE_MALFORMED_RESPONSE: &str = "service.malformed_response";
    /// A failure reported by an older service build that sent prose instead of a code.
    pub const SERVICE_LEGACY_FAILURE: &str = "service.legacy_failure";
    /// Generic service failure, used when no more specific code applies.
    pub const SERVICE_FAILED: &str = "service.failed";
    /// Spawning the service-manager CLI (`sc` / `systemctl` / `launchctl`) failed.
    pub const SERVICE_COMMAND_FAILED: &str = "service.command_failed";
    pub const SERVICE_INSTALL_FAILED: &str = "service.install_failed";
    pub const SERVICE_UNINSTALL_FAILED: &str = "service.uninstall_failed";
    pub const SERVICE_START_FAILED: &str = "service.start_failed";
    pub const SERVICE_STOP_FAILED: &str = "service.stop_failed";
    /// Writing the unit file / plist, or reloading the service manager, failed.
    pub const SERVICE_DEFINITION_FAILED: &str = "service.definition_failed";
    /// Service management is not implemented for this platform.
    pub const SERVICE_UNSUPPORTED_PLATFORM: &str = "service.unsupported_platform";
    /// The path of the running executable could not be resolved.
    pub const SERVICE_EXE_PATH: &str = "service.exe_path";
    /// The elevation prompt was dismissed, and the child reported nothing.
    pub const SERVICE_ELEVATION_DENIED: &str = "service.elevation_denied";
    /// The elevated child never reported back (timed out, or still waiting for a password).
    pub const SERVICE_ELEVATION_INCOMPLETE: &str = "service.elevation_incomplete";
    /// No elevation mechanism is reachable on this machine (no polkit and no terminal emulator).
    pub const SERVICE_ELEVATION_UNAVAILABLE: &str = "service.elevation_unavailable";
    /// Launching the elevation helper itself failed.
    pub const SERVICE_ELEVATION_FAILED: &str = "service.elevation_failed";

    // -- IPC authentication -----------------------------------------------------------------
    /// The IPC client spoke before authenticating, or presented a token the
    /// service does not recognise.
    ///
    /// The service runs elevated, so an unauthenticated caller being refused is
    /// the whole point of the token: see `service::ipc_token`.
    pub const SERVICE_UNAUTHORIZED: &str = "service.unauthorized";
    /// Reading or writing the IPC token file failed.
    ///
    /// On the service side it usually means no desktop session has published a
    /// token yet, so there is nobody privileged callers should be answering to.
    pub const SERVICE_IPC_TOKEN: &str = "service.ipc_token";
    /// An IPC message that exceeded the channel's line limit, or that does not
    /// parse as an [`crate::service::ipc::IpcMessage`].
    pub const SERVICE_MALFORMED_REQUEST: &str = "service.malformed_request";
    /// `local_addr` outside loopback: the local proxy would answer to whoever
    /// can reach the machine, and nothing in front of it authenticates.
    pub const SERVICE_LOCAL_ADDR_NOT_LOOPBACK: &str = "service.local_addr_not_loopback";
    /// `dns_addr` outside the TUN network the built-in DNS server answers on.
    pub const SERVICE_DNS_ADDR_OUTSIDE_TUN: &str = "service.dns_addr_outside_tun";

    // -- logs -------------------------------------------------------------------------------
    /// The log directory could not be listed.
    pub const LOGS_DIR_UNREADABLE: &str = "logs.dir_unreadable";
    /// The log file could not be opened or read.
    pub const LOGS_READ_FAILED: &str = "logs.read_failed";
}

/// A failure crossing the Rust/frontend boundary.
///
/// Serializes to `{ "code": "service.install_failed", "detail": "..." }`; `detail` is omitted
/// when absent so the frontend can branch on `detail === undefined`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppError {
    /// Stable code from [`codes`]; the frontend renders `error.<code>`.
    pub code: String,
    /// Raw diagnostic. English by convention, never localized, never the headline message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AppError {
    /// An error with no diagnostic attached.
    pub fn new(code: &str) -> Self {
        Self {
            code: code.to_string(),
            detail: None,
        }
    }

    /// An error carrying a raw diagnostic. An empty diagnostic is treated as absent, so callers
    /// can pass through a possibly-empty stderr without branching.
    pub fn with_detail(code: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            code: code.to_string(),
            detail: if detail.is_empty() { None } else { Some(detail) },
        }
    }

    /// An error whose diagnostic is the `Display` output of a lower-level error. This is the
    /// common case: the code says what failed, the source error says why.
    pub fn cause(code: &str, cause: impl fmt::Display) -> Self {
        Self::with_detail(code, cause.to_string())
    }
}

impl fmt::Display for AppError {
    /// Renders `code: detail`, for logs and for the CLI paths where no frontend is present.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "{}: {}", self.code, detail),
            None => f.write_str(&self.code),
        }
    }
}

impl std::error::Error for AppError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_detail_is_dropped() {
        assert_eq!(AppError::with_detail(codes::SERVICE_FAILED, "").detail, None);
        assert_eq!(
            AppError::with_detail(codes::SERVICE_FAILED, "boom").detail,
            Some("boom".to_string())
        );
    }

    #[test]
    fn serializes_without_detail_when_absent() {
        let json = serde_json::to_string(&AppError::new(codes::PROXY_NO_NODES)).unwrap();
        assert_eq!(json, r#"{"code":"proxy.no_nodes"}"#);
    }

    #[test]
    fn round_trips_through_json() {
        let original = AppError::with_detail(codes::SERVICE_INSTALL_FAILED, "access denied");
        let json = serde_json::to_string(&original).unwrap();
        let parsed: AppError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn accepts_a_detail_less_payload_from_the_wire() {
        let parsed: AppError = serde_json::from_str(r#"{"code":"service.failed"}"#).unwrap();
        assert_eq!(parsed, AppError::new(codes::SERVICE_FAILED));
    }
}

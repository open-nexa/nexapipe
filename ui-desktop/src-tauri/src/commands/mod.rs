//! The commands the frontend calls.
//!
//! Each one is a Tauri command: the renderer invokes it by name and the
//! answer comes back as JSON. What they share is the state of this process —
//! the proxy manager, the start-up error, the log cursor — and that is what
//! this module holds.

pub(crate) mod autostart;
pub(crate) mod credentials;
pub(crate) mod invite;
pub(crate) mod logs;
pub(crate) mod proxy;
pub(crate) mod service;
pub(crate) mod tray;

use crate::error::AppError;
use crate::proxy::ProxyManager;

use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::sync::RwLock;

use logs::LogCursor;

lazy_static::lazy_static! {
    pub(crate) static ref PROXY_MANAGER: Arc<RwLock<Option<Arc<ProxyManager>>>> = Arc::new(RwLock::new(None));
    pub(crate) static ref STARTUP_ERROR: Arc<RwLock<Option<AppError>>> = Arc::new(RwLock::new(None));
    pub(crate) static ref LOG_CURSOR: Arc<RwLock<Option<LogCursor>>> = Arc::new(RwLock::new(None));
}

/// Whether the tray icon could be created.
///
/// The window's close button can only mean "keep running" if there is a tray to
/// keep running in: without one, the window is the only way back into the app,
/// and hiding it would leave a running app nobody can reach. The renderer asks
/// before it hides anything.
pub(crate) static TRAY_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Whether [`crate::commands::credentials::take_runtime_credentials`] has answered already.
///
/// What makes it a start-up read rather than a general one: it is asked by the
/// config store filling itself in before the app mounts, and refuses everything
/// after that. A read that could be repeated at any time would be the ungated
/// one this replaced, whatever it is called.
///
/// Debug builds are the exception, and only because a reload of the webview
/// runs that start-up again without restarting this process. Re-arming it in a
/// shipped build would not be a concession to that: a script in the renderer
/// can reload the page whenever it likes, so anything that re-opens the read on
/// a reload hands the script the answer this command exists to refuse.
pub(crate) static RUNTIME_CREDENTIALS_TAKEN: AtomicBool = AtomicBool::new(false);

/// The nodes [`crate::commands::invite::accept_invite`] filed credentials for in this process.
///
/// What [`crate::commands::credentials::take_invited_node_credentials`] answers from. A node is here only
/// because the user just imported an invite for it, and it leaves when those
/// credentials are handed over — so the command cannot be pointed at a node
/// whose credentials the renderer has no business holding.
pub(crate) static INVITED_NODES: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// When this process started: the origin the backend's own start-up timings are measured from.
///
/// The frontend reports a series of its own, measured from the document navigation, and the two
/// have to be read together because neither side can see the other's start. Subtracting the
/// last frontend mark from this instant's elapsed time is the only way to put a number on the
/// stretch neither clock covers — the binary loading, the runtime coming up, the webview being
/// created — which is also the stretch nobody can guess at from the outside.
///
/// A `LazyLock` rather than a plain `Instant`, because `Instant::now()` is not `const`; the
/// first read happens in [`crate::run`], so the gap it misses is the dynamic linker's and not ours.
pub(crate) static APP_START: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

/// Ask the service for something, and say whether it answered.
///
/// `Some` is the service's answer. `None` is "it could not answer": the
/// caller then does the same thing in this process, which is what the app has
/// always done — a service that is not installed, not running or not answering
/// leaves the app usable.
///
/// The reason it could not answer is logged here, so that every command that
/// goes through the service says so the same way. The rule was written out
/// once per command, and a change to it — what a fallback means, when it is
/// allowed — was a change in eleven places.
pub(super) async fn ask_service<T, S>(use_service: bool, what: &str, service: S) -> Option<T>
where
    S: std::future::Future<Output = Result<T, AppError>>,
{
    if !use_service {
        return None;
    }
    match service.await {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::warn!("Failed to {what} via service, falling back to process mode: {e}");
            None
        }
    }
}

pub(crate) use proxy::stale_hijack_cleanup;

//! The service runner: the elevated half of the desktop.
//!
//! It listens on the IPC socket, authenticates the caller that dials it and answers what the
//! desktop asks. The pieces are the accept loop, the per-connection handler, the IPC message
//! handling and the checks the two start paths share.

use crate::error::AppError;
use crate::proxy::ProxyManager;
use crate::service::platform::account::AccountId;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;

mod accept;
mod client;
mod messages;
mod validation;

#[cfg(test)]
mod tests;

pub use validation::{require_loopback, require_tun_name, require_tun_subnet};

/// The failure the last start recorded after it had already answered `Ok`.
///
/// Kept beside the manager because the two are set together: a start is dispatched on a spawned
/// task (a TUN run loop only returns when the tunnel goes down, so the service cannot wait for
/// it), and anything that fails there would otherwise be visible only in this process's log —
/// which is written under LocalSystem's profile and nobody can read. The desktop asks for it and
/// shows it, exactly like it does for a process-mode start.
/// How long a caller has to answer the challenge before it is dropped.
///
/// Only the unauthenticated part of the exchange is bounded: once a caller has proved itself it
/// may sit idle indefinitely, because the desktop keeps one connection open for the lifetime of
/// the app and an idle timeout there would break the thing this protects.
///
/// Kept longer than the client's own 5s wait for the challenge on purpose. The two are measuring
/// different things — the client waits to be spoken to, this side waits to be answered — but if
/// this one were the shorter of the pair, an honest caller that was merely slow would be dropped
/// by a service it is still waiting on, which surfaces as a broken service rather than as a
/// refusal.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn startup_error_slot() -> &'static Arc<tokio::sync::RwLock<Option<AppError>>> {
    static SLOT: std::sync::OnceLock<Arc<tokio::sync::RwLock<Option<AppError>>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| Arc::new(tokio::sync::RwLock::new(None)))
}

/// Resolves once a stop has been requested.
///
/// Never resolves early: the sender belongs to the control handler, which lives as long as
/// this process, so a closed channel means nobody can ask any more — not that anyone did.
#[cfg(windows)]
pub async fn await_stop(mut stop: tokio::sync::watch::Receiver<bool>) {
    use std::future::pending;

    loop {
        if *stop.borrow_and_update() {
            return;
        }
        match stop.changed().await {
            Ok(()) => continue,
            Err(_) => pending::<()>().await,
        }
    }
}

pub struct ServiceRunner {
    proxy_manager: Arc<tokio::sync::RwLock<Option<Arc<ProxyManager>>>>,

    /// The account this service was installed for, when it knows one.
    ///
    /// Read once, at startup: the record is written by the install and cannot
    /// change while the service runs. `None` when there is no record, and then
    /// the service serves the account that owns the token it reads — which is
    /// weaker than serving one account, and says so in the log.
    installed_by: Option<AccountId>,
}

impl Default for ServiceRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRunner {
    pub fn new() -> Self {
        let installed_by = crate::service::platform::install_owner::read_installed_by();
        match &installed_by {
            Some(account) => {
                tracing::info!("This service serves the account it was installed for: {account}")
            }
            None => tracing::warn!(
                "No installing account is on file: this service will serve any local account that \
                 owns the token it reads. Reinstall the service to bind it to one account."
            ),
        }

        Self {
            proxy_manager: Arc::new(tokio::sync::RwLock::new(None)),
            installed_by,
        }
    }

    /// Runs the IPC server until the process is asked to stop, then winds the proxy down.
    ///
    /// A service manager has exactly one way to stop a job: it sends SIGTERM. Leaving it
    /// unhandled — which is what calling [`Self::run`] on its own amounts to — lets the
    /// default disposition end the process where it stands, and the teardown that
    /// restores the system DNS never runs. On macOS that setting lives in the system
    /// configuration and survives the reboot; on Linux it is `/etc/resolv.conf`, a plain
    /// file. So every one of uninstall, stop and machine shutdown used to leave the
    /// machine resolving against a TUN address that nothing answers any more.
    ///
    /// SIGINT is handled the same way so a service started by hand — `--foreground`,
    /// and `--daemon` before it detached — also comes down cleanly.
    #[cfg(unix)]
    pub async fn run_until_signalled(&self) -> Result<()> {
        use anyhow::Context;
        use tokio::signal::unix::{signal, SignalKind};

        // Registered before `run()` is polled: a signal that arrived during start-up
        // would otherwise still end the process outright.
        let mut terminate =
            signal(SignalKind::terminate()).context("Failed to listen for SIGTERM")?;
        let mut interrupt =
            signal(SignalKind::interrupt()).context("Failed to listen for SIGINT")?;

        tokio::select! {
            result = self.run() => result,
            _ = terminate.recv() => {
                tracing::info!("SIGTERM received; stopping the proxy so the system DNS is restored");
                self.shutdown().await;
                Ok(())
            }
            _ = interrupt.recv() => {
                tracing::info!("SIGINT received; stopping the proxy so the system DNS is restored");
                self.shutdown().await;
                Ok(())
            }
        }
    }

    /// Runs the IPC server until `stop` is raised, then winds the proxy down.
    ///
    /// The Windows counterpart of [`Self::run_until_signalled`]: the control manager
    /// delivers a stop to the handler the service registered, not as a signal, so the
    /// caller owns that half and hands the receiving end in here.
    ///
    /// `on_stopping` runs the moment the stop is seen and before the teardown starts.
    /// It is the caller's chance to tell the control manager it is stopping: without
    /// that the SCM keeps showing the state last reported, `Running`, which still
    /// accepts controls and grants no wait hint — so a teardown that takes a while
    /// looks like a service that hung and gets killed from outside.
    #[cfg(windows)]
    pub async fn run_until_stop_flag(
        &self,
        stop: tokio::sync::watch::Receiver<bool>,
        on_stopping: impl FnOnce(),
    ) -> Result<()> {
        tokio::select! {
            result = self.run() => result,
            () = await_stop(stop) => {
                on_stopping();
                self.shutdown().await;
                Ok(())
            }
        }
    }

    /// Winds the proxy down because the process itself is exiting.
    ///
    /// Not the same thing as answering
    /// [`IpcMessage::StopProxy`](crate::service::ipc::IpcMessage::StopProxy): that leaves the service
    /// up and the caller free to start again, whereas here nothing is served any more, so the
    /// instance is *taken* out — the tunnel has to be torn down (the TUN adapter outlives this
    /// process) and no late status request may be answered with "running".
    pub async fn shutdown(&self) {
        // The socket the desktop looks for goes with the service: a socket file
        // nobody listens on is one the desktop spends a connection failing to
        // reach.
        crate::service::ipc::remove_socket();

        let manager = self.proxy_manager.write().await.take();
        if let Some(manager) = manager {
            tracing::info!("Stopping the proxy before exiting");
            manager.stop().await;
        }
    }
}

//! The accept loop: the socket is waited on, and every connection is handed to a task
//! of its own.

use crate::service::ipc::{IpcListener, IPC_SOCKET_PATH};
use anyhow::{Context, Result};

use super::ServiceRunner;

impl ServiceRunner {
    pub async fn run(&self) -> Result<()> {
        tracing::info!("Service runner starting");

        // A hijack whose process died mid-run (killed, or a machine shutdown that reached
        // the service before its teardown finished) leaves static DNS entries that survive
        // the reboot: the machine comes back with no working name resolution — including
        // for this service itself, whose iroh endpoint cannot even publish to pkarr.
        // Clean that up before anything here needs DNS.
        crate::proxy::dns_config::cleanup_stale_hijack();

        let listener = IpcListener::bind()
            .await
            .context("Failed to bind IPC socket")?;

        tracing::info!("IPC server listening on: {}", IPC_SOCKET_PATH);

        // Where this process will look for the token, printed once. A service that refuses every
        // call because it cannot find one is otherwise indistinguishable from a service that is
        // not there at all: the refusal names no path, and the desktop can only report that the
        // connection closed. One line here turns that dead end into a diffable list.
        tracing::info!(
            "IPC token candidates: {:?}",
            crate::service::ipc_token::service_token_paths()
        );

        // The account this service was installed for. It cannot change while the service runs,
        // so it is read once here and every connection is checked against it.
        let installed_by = self.installed_by.clone();

        loop {
            let mut stream = listener
                .accept()
                .await
                .context("Failed to accept connection")?;
            tracing::debug!("Client connected");

            let proxy_manager = self.proxy_manager.clone();
            let installed_by = installed_by.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_client(&mut stream, proxy_manager, installed_by.as_ref()).await
                {
                    tracing::error!("Client handler error: {}", e);
                }
            });
        }
    }
}

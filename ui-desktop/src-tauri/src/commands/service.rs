//! The system service, and the elevation its installation needs.
//!
//! Installing a service is an administrator's job, and the commands that do
//! it are the ones that ask for elevation: the batch file is written and
//! re-launched through the UAC prompt, and the outcome comes back through a
//! file rather than through stdout, because an elevated process cannot hand
//! its child's output back.

use crate::error::{codes, AppError};
use crate::service;
use crate::service::platform::ServiceState;
use crate::service::IpcClient;

/// Registers the system service, asking for administrator rights.
///
/// Deliberately *not* routed through the IPC channel: the service is by definition not running
/// before it is installed, so an IPC request could only ever fail with `service.unavailable` and
/// the user would never see the UAC / sudo prompt. Running it here lets
/// [`service::platform::install_service`] re-launch this binary elevated when needed.
#[tauri::command]
pub(crate) async fn install_service() -> Result<(), AppError> {
    run_elevated("install", service::platform::install_service).await
}

/// Removes the system service, asking for administrator rights — see [`install_service`] for why
/// this does not go through the IPC channel.
#[tauri::command]
pub(crate) async fn uninstall_service() -> Result<(), AppError> {
    run_elevated("uninstall", service::platform::uninstall_service).await
}

/// Runs a service-management operation that may have to wait for an elevation prompt.
///
/// The wait is not bounded by this process: a sudo password typed in a terminal gets a two-minute
/// budget inside [`service::elevate`], so the work is moved off the async runtime's thread
/// instead of blocking every other command while the user decides.
pub(crate) async fn run_elevated(
    verb: &str,
    operation: fn() -> Result<(), AppError>,
) -> Result<(), AppError> {
    let outcome = tauri::async_runtime::spawn_blocking(operation)
        .await
        .unwrap_or_else(|e| Err(AppError::cause(codes::SERVICE_FAILED, e)));

    if let Err(e) = &outcome {
        tracing::error!("service {} failed: {}", verb, e);
    }

    outcome
}

/// Whether the service is registered, stopped or running — as the service manager sees it.
///
/// Infallible: an unreadable service manager means "we cannot tell", which the UI renders like an
/// uninstalled service rather than failing the whole panel.
#[tauri::command]
pub(crate) async fn get_service_status() -> ServiceState {
    tauri::async_runtime::spawn_blocking(service::platform::service_state)
        .await
        .unwrap_or(ServiceState::NotInstalled)
}

/// The build the installed service reports, when it can say.
///
/// `None` covers "no service is answering" and "the service predates the question", which the
/// caller cannot tell apart: a build that does not know [`IpcMessage::GetVersion`] refuses it
/// and closes the connection. Both mean the same thing to the UI, which compares this against
/// the app's own version and offers to reinstall when they differ — an older service answers
/// the requests it does understand with whatever it has, which is how an upgrade that never
/// happened looked like a page with nothing in it.
#[tauri::command]
pub(crate) async fn get_service_version() -> Option<String> {
    match IpcClient::get_version().await {
        Ok(version) => Some(version),
        Err(e) => {
            tracing::debug!("Could not ask the service which build it is: {e}");
            None
        }
    }
}

/// The build the installed service is, read from the record the install wrote.
///
/// Not from the service: asking the service which build it is needs the IPC to work, and
/// the case this exists for is the one where it does not — a service left behind by an
/// upgrade keeps running while the app has been replaced, and the two no longer speak the
/// same protocol. The record is written by the install, so it answers the question even
/// then.
///
/// `None` when there is no record: a machine that never had the service installed, or one
/// whose service predates the record.
#[tauri::command]
pub(crate) async fn get_service_installed_version() -> Option<String> {
    service::platform::install_version::read_installed_version()
}

/// Starts the service, asking for administrator rights when the unprivileged call is refused.
#[tauri::command]
pub(crate) async fn start_service() -> Result<(), AppError> {
    run_elevated("start", service::platform::start_service).await
}

/// Stops the service, asking for administrator rights when the unprivileged call is refused.
#[tauri::command]
pub(crate) async fn stop_service() -> Result<(), AppError> {
    run_elevated("stop", service::platform::stop_service).await
}

/// Whether a service is answering on the IPC port.
///
/// Infallible on purpose: an unreachable service is reported as "not running", which is what the
/// status indicator needs to know. The reason is logged by the IPC client on the way out.
#[tauri::command]
pub(crate) async fn is_service_running() -> bool {
    IpcClient::is_service_running().await
}

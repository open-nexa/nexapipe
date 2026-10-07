//! Windows service entry point.
//!
//! Both the desktop binary and `nexa-service` can act as the service, depending
//! on which one was registered with `sc create`, so the dispatcher lives here
//! instead of inside a single binary.

use std::time::Duration;

use crate::service::platform;
use tokio::sync::watch;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

define_windows_service!(ffi_service_main, service_main);

/// How long the control manager is asked to wait for the shutdown before deciding this
/// service hung. Only meaningful while stopping; enforced by the SCM, not by anything
/// here.
const STOP_WAIT_HINT: Duration = Duration::from_secs(30);

/// Hands control to the service control manager. Only valid when this process
/// was started by the SCM.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    service_dispatcher::start(platform::SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<std::ffi::OsString>) {
    if let Err(e) = serve() {
        tracing::error!("Service failed: {}", e);
    }
}

/// Reports `state` to the control manager.
///
/// A stopping service accepts no further controls — another stop arriving mid-shutdown
/// would only race the teardown — and `wait_hint` tells the SCM how much time it is
/// granting.
fn set_status(handle: &ServiceStatusHandle, state: ServiceState) -> windows_service::Result<()> {
    let wait_hint = match state {
        ServiceState::StopPending => STOP_WAIT_HINT,
        _ => Duration::default(),
    };
    let controls_accepted = match state {
        ServiceState::StopPending | ServiceState::Stopped => ServiceControlAccept::empty(),
        // SHUTDOWN and PRESHUTDOWN matter for the TUN's DNS hijack: without them the
        // control manager ends this process at machine shutdown without any control
        // event at all, the teardown never runs, and the DNS entries it left behind
        // outlive the reboot.
        _ => {
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::PRESHUTDOWN
        }
    };

    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    })
}

fn serve() -> windows_service::Result<()> {
    // A stop reaches a Windows service through the control handler, which runs on a
    // thread of its own and must therefore only *flag* it: the async loop owns the
    // tunnel and decides how to come down. Acknowledging the control here without
    // anything to pick it up — which is what this used to do — left the process alive
    // with its tunnel up while `sc query` already said STOP_PENDING, so `sc stop` and
    // everything waiting behind it hung until the control manager gave up and killed
    // it from outside. Either way the teardown never ran, and the system DNS it was
    // supposed to put back stayed pointing at the TUN.
    let (stop_tx, stop_rx) = watch::channel(false);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // PRESHUTDOWN is the early warning a service that asked for it gets; the
            // teardown (TUN down + system-DNS restore) is exactly the slow work it
            // exists for, so it is handled the same way as the shutdown itself.
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                tracing::info!("Stop requested");
                let _ = stop_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(platform::SERVICE_NAME, event_handler)?;
    set_status(&status_handle, ServiceState::Running)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(async {
            let runner = crate::service::runner::ServiceRunner::new();
            // Announced before the teardown starts, so a slow tunnel shutdown reads as
            // "stopping" to the SCM — with the 30s wait hint and no further controls
            // accepted — instead of as a service that stopped answering.
            let stopping = || {
                if let Err(e) = set_status(&status_handle, ServiceState::StopPending) {
                    tracing::error!("Could not report StopPending: {}", e);
                }
            };
            if let Err(e) = runner.run_until_stop_flag(stop_rx, stopping).await {
                tracing::error!("Service runner error: {}", e);
            }
        });

    set_status(&status_handle, ServiceState::Stopped)?;

    Ok(())
}

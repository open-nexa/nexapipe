//! Windows service entry point.
//!
//! Both the desktop binary and `nexa-service` can act as the service, depending
//! on which one was registered with `sc create`, so the dispatcher lives here
//! instead of inside a single binary.

use crate::service::platform;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

define_windows_service!(ffi_service_main, service_main);

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

fn serve() -> windows_service::Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => ServiceControlHandlerResult::NoError,
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(platform::SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(async {
            let runner = crate::service::runner::ServiceRunner::new();
            if let Err(e) = runner.run().await {
                tracing::error!("Service runner error: {}", e);
            }
        });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

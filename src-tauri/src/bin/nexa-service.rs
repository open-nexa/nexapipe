use nexa_lib::service::elevate;
use nexa_lib::service::platform;
use nexa_lib::service::runner::ServiceRunner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Shares the log directory with the service process (%APPDATA%/nexa/logs); a distinct
    // prefix keeps it from clashing with the UI process
    let _guard = nexa_lib::init_tracing("nexa-service.log");

    let mut args: Vec<String> = std::env::args().collect();
    // When this process was launched by the elevation helper, the outcome has to
    // be handed back through this file instead of stdout.
    let result_file = elevate::take_result_file_arg(&mut args);

    if args.len() > 1 {
        match args[1].as_str() {
            "--install" => {
                tracing::info!("Installing service");
                let outcome = platform::install_service();
                elevate::report_result(result_file.as_deref(), &outcome);
                return Ok(());
            }
            "--uninstall" => {
                tracing::info!("Uninstalling service");
                let outcome = platform::uninstall_service();
                elevate::report_result(result_file.as_deref(), &outcome);
                return Ok(());
            }
            "--start" => {
                tracing::info!("Starting service");
                let outcome = platform::start_service();
                elevate::report_result(result_file.as_deref(), &outcome);
                return Ok(());
            }
            "--stop" => {
                tracing::info!("Stopping service");
                let outcome = platform::stop_service();
                elevate::report_result(result_file.as_deref(), &outcome);
                return Ok(());
            }
            "--status" => {
                let running = platform::is_service_running();
                println!("Service running: {}", running);
                return Ok(());
            }
            #[cfg(windows)]
            "--service" => {
                tracing::info!("Starting as Windows Service");
                start_windows_service()?;
                return Ok(());
            }
            "--daemon" => {
                tracing::info!("Starting as daemon");
                #[cfg(unix)]
                daemonize();
                run_service().await?;
                return Ok(());
            }
            _ => {}
        }
    }

    tracing::info!("Starting as console application");
    run_service().await?;

    Ok(())
}

async fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let runner = ServiceRunner::new();
    runner.run().await?;
    Ok(())
}

#[cfg(windows)]
fn start_windows_service() -> Result<(), Box<dyn std::error::Error>> {
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

    fn service_main(args: Vec<std::ffi::OsString>) {
        if let Err(e) = run_windows_service(args) {
            tracing::error!("Service failed: {}", e);
        }
    }

    fn run_windows_service(_args: Vec<std::ffi::OsString>) -> windows_service::Result<()> {
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop => ServiceControlHandlerResult::NoError,
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle =
            service_control_handler::register(platform::SERVICE_NAME, event_handler)?;

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
            .unwrap()
            .block_on(async {
                let runner = ServiceRunner::new();
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

    service_dispatcher::start(platform::SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(unix)]
fn daemonize() {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    unsafe {
        match fork() {
            -1 => panic!("Failed to fork"),
            0 => {}
            _ => std::process::exit(0),
        }
    }

    unsafe {
        if libc::setsid() == -1 {
            panic!("Failed to setsid");
        }
    }

    std::env::set_current_dir("/").unwrap();

    let null = File::open("/dev/null").unwrap();
    unsafe {
        libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO);
        libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO);
        libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO);
    }
}

#[cfg(unix)]
unsafe fn fork() -> i32 {
    libc::fork()
}

use nexa_lib::service::elevate;
use nexa_lib::service::platform;
use nexa_lib::service::runner::ServiceRunner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The service has its own root-owned log directory; a distinct prefix also keeps the two
    // rolling files apart when both binaries are run manually during development.
    let _guard = nexa_lib::init_tracing_in(nexa_lib::service_log_dir(), "nexa-service.log");

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
            "--foreground" => {
                tracing::info!("Starting as foreground service");
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
    use std::future::pending;
    use std::time::Duration;

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

    /// How long the control manager is asked to wait for the shutdown before deciding this service
    /// hung. Only meaningful while stopping; enforced by the SCM, not by anything here.
    const STOP_WAIT_HINT: Duration = Duration::from_secs(30);

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(args: Vec<std::ffi::OsString>) {
        if let Err(e) = run_windows_service(args) {
            tracing::error!("Service failed: {}", e);
        }
    }

    /// Reports `state` to the control manager.
    ///
    /// A stopping service accepts no further controls — another stop arriving mid-shutdown would
    /// only race the teardown — and `wait_hint` tells the SCM how much time it is granting.
    fn set_status(
        handle: &ServiceStatusHandle,
        state: ServiceState,
    ) -> windows_service::Result<()> {
        let wait_hint = match state {
            ServiceState::StopPending => STOP_WAIT_HINT,
            _ => Duration::default(),
        };
        let controls_accepted = match state {
            ServiceState::StopPending | ServiceState::Stopped => ServiceControlAccept::empty(),
            // SHUTDOWN/PRESHUTDOWN matter for the TUN's DNS hijack: without them the SCM
            // kills the process at machine shutdown without any control event, the teardown
            // never runs, and the static DNS entries it left behind (they survive a reboot)
            // break name resolution for the whole machine on the next boot.
            _ => ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::PRESHUTDOWN,
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

    /// Resolves once a stop has been requested.
    ///
    /// Never resolves early: the sender belongs to the control handler, which lives as long as
    /// this process, so a closed channel means nobody can ask any more — not that anyone did.
    async fn await_stop(mut stop: watch::Receiver<bool>) {
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

    fn run_windows_service(_args: Vec<std::ffi::OsString>) -> windows_service::Result<()> {
        // A stop reaches a Windows service through the control handler, which runs on a thread of
        // its own and must therefore only *flag* it: the async loop owns the tunnel and decides
        // how to come down. Acknowledging the control here without anything to pick it up was how
        // this service used to behave, and it is what made stopping take minutes: the process
        // stayed alive with its tunnel up while `sc query` already said STOP_PENDING, so `sc stop`
        // - and everything waiting behind it - hung until the control manager gave up and the
        // process was killed from outside.
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

        let status_handle =
            service_control_handler::register(platform::SERVICE_NAME, event_handler)?;
        set_status(&status_handle, ServiceState::Running)?;

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let runner = ServiceRunner::new();
                tokio::select! {
                    result = runner.run() => {
                        if let Err(e) = result {
                            tracing::error!("Service runner error: {}", e);
                        }
                    }
                    () = await_stop(stop_rx) => {
                        // Announced before the teardown starts, so a slow tunnel shutdown reads as
                        // "stopping" to the SCM instead of as a service that stopped answering.
                        if let Err(e) = set_status(&status_handle, ServiceState::StopPending) {
                            tracing::error!("Could not report StopPending: {}", e);
                        }
                        runner.shutdown().await;
                    }
                }
            });

        set_status(&status_handle, ServiceState::Stopped)?;

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

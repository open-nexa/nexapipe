//! Command line entry points shared by the desktop app and `nexa-service`.
//!
//! Installing or removing a system service requires administrative rights, so
//! the UI re-launches the *current executable* through the platform elevation
//! prompt (see [`crate::service::elevate`]). The desktop binary therefore has
//! to understand the same verbs as `nexa-service` — otherwise the elevated copy
//! would just open another window and the operation would never run.

use crate::service::elevate;
use crate::service::platform;
use crate::service::runner::ServiceRunner;

/// Consumes the service-management verbs.
///
/// Returns `true` when `args` named one of them and the process should exit
/// without starting anything else.
pub fn handle_args(args: &mut Vec<String>) -> bool {
    // The elevation helper appends `--result-file <path>` so that the outcome
    // can be handed back to the unprivileged caller. Strip it before looking at
    // the verb itself.
    let result_file = elevate::take_result_file_arg(args);

    let verb = match args.get(1).map(String::as_str) {
        Some(verb) => verb,
        None => return false,
    };

    match verb {
        "--install" => {
            elevate::report_result(result_file.as_deref(), &platform::install_service());
            true
        }
        "--uninstall" => {
            elevate::report_result(result_file.as_deref(), &platform::uninstall_service());
            true
        }
        "--start" => {
            elevate::report_result(result_file.as_deref(), &platform::start_service());
            true
        }
        "--stop" => {
            elevate::report_result(result_file.as_deref(), &platform::stop_service());
            true
        }
        "--status" => {
            println!("Service running: {}", platform::is_service_running());
            true
        }
        "--daemon" => {
            run_daemon();
            true
        }
        "--service" => run_native_service(),
        _ => false,
    }
}

/// Runs the IPC server that the UI talks to.
pub fn run_daemon() {
    let _guard = crate::init_tracing("nexa-service.log");
    tracing::info!("Starting as daemon");

    #[cfg(unix)]
    daemonize();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async {
        if let Err(e) = ServiceRunner::new().run().await {
            tracing::error!("Service runner error: {}", e);
        }
    });
}

/// Entry point used by the Windows service control manager (`--service`).
#[cfg(windows)]
fn run_native_service() -> bool {
    let _guard = crate::init_tracing("nexa-service.log");
    tracing::info!("Starting as Windows service");

    if let Err(e) = crate::service::windows_service::run() {
        tracing::error!("Service failed: {}", e);
    }

    true
}

/// `--service` is a Windows-only concept; elsewhere it is not a known verb.
#[cfg(not(windows))]
fn run_native_service() -> bool {
    false
}

#[cfg(unix)]
fn daemonize() {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    unsafe {
        match libc::fork() {
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

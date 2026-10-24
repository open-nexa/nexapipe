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

/// Flag that tells the install to leave the service stopped, as `--leave-stopped`.
///
/// For the installer: an upgrade has to leave the machine the way it found it, and a service
/// the user had stopped is not theirs to start behind their back. The registration itself is
/// the same either way — the entry, the binary under Program Files, the account it serves —
/// only the service is left down.
///
/// Windows only in its effect. The Unix install starts the service through its own service
/// manager, and the installer that asks for this is the Windows one.
pub const LEAVE_STOPPED_ARG: &str = "--leave-stopped";

/// Flag that tells the install to keep the account the service already serves, as
/// `--keep-owner`.
///
/// For the installer: an upgrade re-registers the service, and re-registering it is not how
/// the account it serves is chosen. The account the service was installed for is the one the
/// user picked, and an upgrade that quietly moved the service to whoever happened to run the
/// installer would change which account the service serves without saying so.
///
/// Windows only in its effect. The Unix half records the account in a root-owned file that
/// the installer of the upgrade never writes.
pub const KEEP_OWNER_ARG: &str = "--keep-owner";

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
            // The install says things that only a log can carry — whether the
            // service was installed for an account, or in the degraded mode
            // that serves every local account. The elevated child is the
            // desktop binary, and it installs no subscriber of its own, so a
            // `tracing::warn!` from the install would go nowhere without this.
            //
            // The guard is held to the end of the arm, so the message is
            // flushed before the process reports its outcome and exits.
            let _guard = crate::init_tracing_in(crate::service_log_dir(), "nexa-service.log");

            // Read here rather than in the elevated child: the decision changes what the
            // install does, and the install is what the elevated child runs.
            let leave_stopped = args.iter().any(|arg| arg == LEAVE_STOPPED_ARG);
            let keep_owner = args.iter().any(|arg| arg == KEEP_OWNER_ARG);
            let outcome = platform::install_service_with(leave_stopped, keep_owner);

            elevate::report_result(result_file.as_deref(), &outcome);
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
        "--restart" => {
            elevate::report_result(result_file.as_deref(), &platform::restart_service());
            true
        }
        "--status" => {
            println!("Service running: {}", platform::is_service_running());
            true
        }
        "--daemon" => {
            if let Err(error) = run_daemon() {
                eprintln!("Service failed: {error:#}");
                std::process::exit(1);
            }
            true
        }
        "--foreground" => {
            if let Err(error) = run_foreground() {
                eprintln!("Service failed: {error:#}");
                std::process::exit(1);
            }
            true
        }
        "--service" => run_native_service(),
        _ => false,
    }
}

/// Runs the IPC server in the traditional daemonized mode.
pub fn run_daemon() -> anyhow::Result<()> {
    let _guard = crate::init_tracing_in(crate::service_log_dir(), "nexa-service.log");
    tracing::info!("Starting as daemon");

    #[cfg(unix)]
    daemonize();

    run_service()
}

/// Runs the IPC server in the foreground for service managers.
///
/// systemd and launchd both need the main process to stay attached to the service; --daemon
/// exists only for manual use and must not be used from a service unit.
pub fn run_foreground() -> anyhow::Result<()> {
    let _guard = crate::init_tracing_in(crate::service_log_dir(), "nexa-service.log");
    tracing::info!("Starting as foreground service");

    run_service()
}

fn run_service() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async {
        let runner = ServiceRunner::new();

        // Unix: a service manager stops a job with SIGTERM, and handling it is the only
        // thing that lets the teardown — the system-DNS restore — run. Windows has no
        // equivalent here: a stop reaches a service through the control manager, whose
        // handler is registered by whichever entry point the SCM started, so this path
        // simply serves until that handler ends the process.
        #[cfg(unix)]
        {
            runner.run_until_signalled().await
        }
        #[cfg(not(unix))]
        {
            runner.run().await
        }
    })
}

/// Entry point used by the Windows service control manager (`--service`).
#[cfg(windows)]
fn run_native_service() -> bool {
    let _guard = crate::init_tracing_in(crate::service_log_dir(), "nexa-service.log");
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

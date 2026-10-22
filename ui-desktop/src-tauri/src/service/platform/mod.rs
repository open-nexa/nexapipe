//! Registration of the system service, per platform.
//!
//! Two very different mechanisms live behind one API:
//!
//! * **Windows** — the desktop app runs as the invoking user (`asInvoker` manifest), so the
//!   `sc.exe` calls are written into a batch file and that batch file is re-launched through the
//!   UAC prompt (`Start-Process -Verb RunAs`). Elevating `sc.exe` rather than this binary keeps
//!   the GUI out of the privileged path — nothing depends on our own argument parsing surviving
//!   the round trip — and the batch file redirects `sc.exe`'s real error text into a log we read
//!   back, so a failure is reported instead of being flattened into "access denied".
//! * **Unix** — there is no equivalent of a batch file, and the unit file / plist has to be
//!   written by *this* process, so the whole operation re-launches the current executable
//!   elevated (`service::elevate`) and reports its outcome through a result file.

pub const SERVICE_NAME: &str = "nexa-service";
pub const SERVICE_DISPLAY_NAME: &str = "Nexa Service";

use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// What the service manager says about the service — the three states the UI shows and the ones
/// that decide which of install / start / stop / uninstall is offered.
///
/// This is deliberately *not* the same question as [`crate::service::IpcClient::is_service_running`],
/// which asks whether something is answering on the IPC port. A registered service that has not
/// been started is `Stopped`, not "gone": the two questions only coincide once the daemon is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// Nothing is registered with the service manager.
    NotInstalled,
    /// Registered, but the process is not running.
    Stopped,
    /// Registered and running.
    Running,
}

/// Current state of the service, as reported by the service manager.
pub fn service_state() -> ServiceState {
    #[cfg(windows)]
    return state();

    #[cfg(target_os = "linux")]
    return state_linux();

    #[cfg(target_os = "macos")]
    return state_macos();

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    return ServiceState::NotInstalled;
}

#[cfg(not(windows))]
use crate::error::codes;
#[cfg(not(windows))]
use crate::service::elevate;

/// Registers the service and starts it.
pub fn install_service() -> Result<(), AppError> {
    #[cfg(windows)]
    return install();

    #[cfg(not(windows))]
    return install_elevated();
}

/// Removes the service.
pub fn uninstall_service() -> Result<(), AppError> {
    #[cfg(windows)]
    return uninstall();

    #[cfg(not(windows))]
    return uninstall_elevated();
}

pub fn start_service() -> Result<(), AppError> {
    #[cfg(windows)]
    return start();

    #[cfg(not(windows))]
    return start_elevated();
}

pub fn stop_service() -> Result<(), AppError> {
    #[cfg(windows)]
    return stop();

    #[cfg(not(windows))]
    return stop_elevated();
}

pub fn is_service_running() -> bool {
    #[cfg(windows)]
    return is_service_running_windows();

    #[cfg(target_os = "linux")]
    return is_service_running_linux();

    #[cfg(target_os = "macos")]
    return is_service_running_macos();

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    return false;
}

// ==========================================================================
// Windows: sc.exe, elevated through UAC when the unprivileged call is refused
// ==========================================================================

/// What `sc query` says the service is doing, with the states [`ServiceState`] flattens kept
/// apart.
///
/// The panel draws three states, so [`ServiceState`] calls everything that is not running
/// "stopped" — including `STOP_PENDING`, which is not stopped but on its way there. Replacing a
/// running service has to tell those apart: the teardown that restores the system DNS runs in
/// that window, and starting the new build behind a teardown that has not finished is what the
/// wait exists to prevent.
///
/// Kept outside the Windows-only module, and compiled under `test` too, so the reading of an
/// `sc.exe` answer is testable on a machine that has no `sc.exe`.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScState {
    /// `RUNNING` — up, and accepting what the control manager asks of it.
    Running,
    /// `STOPPED` — finished coming down, nothing left executing.
    Stopped,
    /// Any `*PENDING` — on its way from one to the other, and currently neither.
    Pending,
    /// Not registered, so there is no state to be in.
    Absent,
    /// `sc.exe` could not be asked, or answered without a state line.
    Unknown,
}

/// Reads that answer out of what `sc.exe query` prints.
///
/// `1060` only counts when `sc.exe` reported it as a failure: the same four digits appear in the
/// `PID` line of a perfectly healthy service, and reading that as "absent" would let an install
/// replace a service that is still up.
#[cfg(any(windows, test))]
fn sc_state(query_output: &str) -> ScState {
    if query_output
        .lines()
        .any(|line| line.contains("FAILED") && line.contains("1060"))
    {
        return ScState::Absent;
    }

    match query_output
        .lines()
        .find(|line| line.trim_start().starts_with("STATE"))
    {
        // Pending is checked first, because `STOP_PENDING` is neither stopped nor running.
        Some(line) if line.contains("PENDING") => ScState::Pending,
        Some(line) if line.contains("RUNNING") => ScState::Running,
        Some(line) if line.contains("STOPPED") => ScState::Stopped,
        _ => ScState::Unknown,
    }
}

// The three halves of the registration. Each one is compiled only where it
// applies — except for the two that the tests read on every platform, which
// is why the module gates say `test` as well: the launchd plist and the
// systemd activation arguments are the two things most easily lost and least
// visible when they are.
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "linux", test))]
use linux::*;
#[cfg(any(target_os = "macos", test))]
use macos::*;
#[cfg(windows)]
use windows::*;

// ==========================================================================

#[cfg(not(windows))]
fn install_elevated() -> Result<(), AppError> {
    if elevate::is_privileged() {
        let exe_path = current_exe_string()?;
        return dispatch_install(&exe_path);
    }

    elevate::run_self_elevated(&["--install"])
}

#[cfg(not(windows))]
fn uninstall_elevated() -> Result<(), AppError> {
    if elevate::is_privileged() {
        return dispatch_uninstall();
    }

    elevate::run_self_elevated(&["--uninstall"])
}

#[cfg(not(windows))]
fn start_elevated() -> Result<(), AppError> {
    if elevate::is_privileged() {
        return dispatch_start();
    }

    elevate::run_self_elevated(&["--start"])
}

#[cfg(not(windows))]
fn stop_elevated() -> Result<(), AppError> {
    if elevate::is_privileged() {
        return dispatch_stop();
    }

    elevate::run_self_elevated(&["--stop"])
}

/// Waits for the service process to go away, so that uninstalling it cannot report
/// success while the machine's DNS still points at the TUN.
///
/// The process is the only thing that can restore the system DNS, and both service
/// managers ask it to stop by signal — so deleting the definition while the teardown
/// is still running deletes the only record of a hijack that is still up. Bounded
/// rather than fatal: a definition left on disk is a service that is still installed,
/// so the delete goes ahead either way and a timeout is only logged.
#[cfg(not(windows))]
fn wait_for_service_exit(is_gone: impl Fn() -> bool) {
    use std::time::{Duration, Instant};

    // Comfortably past `TunProxy::stop_and_wait`'s twenty seconds: that is the work
    // being waited on, and a longer wait here buys nothing the teardown would finish.
    const TIMEOUT: Duration = Duration::from_secs(45);

    let deadline = Instant::now() + TIMEOUT;
    while !is_gone() {
        if Instant::now() >= deadline {
            tracing::warn!(
                "the service process is still up {}s after it was asked to stop; \
                 the system DNS restore may not have run",
                TIMEOUT.as_secs()
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Absolute path of the running executable, which is what the service manager is pointed at.
#[cfg(not(windows))]
fn current_exe_string() -> Result<String, AppError> {
    elevate::current_executable().map(|p| p.to_string_lossy().to_string())
}

#[cfg(target_os = "linux")]
fn dispatch_install(exe_path: &str) -> Result<(), AppError> {
    install_service_linux(exe_path)
}

#[cfg(target_os = "macos")]
fn dispatch_install(exe_path: &str) -> Result<(), AppError> {
    install_service_macos(exe_path)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn dispatch_install(_exe_path: &str) -> Result<(), AppError> {
    Err(AppError::new(codes::SERVICE_UNSUPPORTED_PLATFORM))
}

#[cfg(target_os = "linux")]
fn dispatch_uninstall() -> Result<(), AppError> {
    uninstall_service_linux()
}

#[cfg(target_os = "macos")]
fn dispatch_uninstall() -> Result<(), AppError> {
    uninstall_service_macos()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn dispatch_uninstall() -> Result<(), AppError> {
    Err(AppError::new(codes::SERVICE_UNSUPPORTED_PLATFORM))
}

#[cfg(target_os = "linux")]
fn dispatch_start() -> Result<(), AppError> {
    start_service_linux()
}

#[cfg(target_os = "macos")]
fn dispatch_start() -> Result<(), AppError> {
    start_service_macos()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn dispatch_start() -> Result<(), AppError> {
    Err(AppError::new(codes::SERVICE_UNSUPPORTED_PLATFORM))
}

#[cfg(target_os = "linux")]
fn dispatch_stop() -> Result<(), AppError> {
    stop_service_linux()
}

#[cfg(target_os = "macos")]
fn dispatch_stop() -> Result<(), AppError> {
    stop_service_macos()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn dispatch_stop() -> Result<(), AppError> {
    Err(AppError::new(codes::SERVICE_UNSUPPORTED_PLATFORM))
}

#[cfg(test)]
mod tests {
    use super::{
        linux_activation_args, macos_install_commands, macos_job_target, macos_plist_content,
        sc_state, ScState, SERVICE_NAME,
    };

    /// launchd's own default for `ExitTimeOut` is documented as no more than
    /// "system-defined" and is shorter than the teardown allows itself — 5s on this
    /// machine — so a job without an explicit, longer one gets SIGKILLed well before
    /// the system-DNS restore can finish.
    #[test]
    fn the_job_is_allowed_longer_than_the_teardown_takes() {
        let plist = macos_plist_content("/Applications/Nexa.app/Contents/MacOS/nexa");

        let seconds = plist
            .split("<key>ExitTimeOut</key>")
            .nth(1)
            .and_then(|rest| rest.split("<integer>").nth(1))
            .and_then(|rest| rest.split("</integer>").next())
            .and_then(|value| value.trim().parse::<u32>().ok())
            .expect("the job carries an ExitTimeOut");

        // `TunProxy::stop_and_wait` gives the teardown twenty seconds.
        assert!(
            seconds > 20,
            "an ExitTimeOut of {seconds}s leaves the teardown no room to restore the system DNS"
        );
    }

    /// An install that only overwrote the plist installed nothing: launchd keeps running the
    /// definition it read when the job was last presented to it, so the job has to come out
    /// before the new file goes in.
    #[test]
    fn installing_presents_the_job_again_rather_than_only_the_file() {
        let plist = "/Library/LaunchDaemons/com.nexa.nexa-service.plist";
        let [removal, registration] = macos_install_commands(plist);

        assert_eq!(
            removal[0], "bootout",
            "without taking the job out first, launchd never re-reads the rewritten file"
        );
        assert_eq!(removal[1], macos_job_target());

        assert_eq!(registration[0], "bootstrap");
        assert_eq!(registration[2], plist);
    }

    /// A job kept alive in the plain `<true/>` form is restarted after *every* exit —
    /// including the one the user asked for. `launchctl stop` sends SIGTERM, the teardown
    /// answers it and the process leaves with 0, and launchd brings it straight back: measured
    /// at 60ms between the two log lines. Restarts-as-failure is what was wanted.
    ///
    /// `SuccessfulExit` false is that condition — "restart the job in the inverse [of
    /// exit status zero]", per `launchd.plist(5)` — and it has to be alone in the
    /// dictionary because the conditions there are OR'd: a second one would restart the
    /// job again for a reason nobody asked for.
    #[test]
    fn the_job_survives_a_crash_without_surviving_a_stop() {
        let plist = macos_plist_content("/Applications/Nexa.app/Contents/MacOS/nexa");

        assert!(
            !plist.contains("<key>KeepAlive</key>\n    <true/>"),
            "an unconditional KeepAlive restarts the job after a deliberate stop too"
        );

        let keep_alive = plist
            .split("<key>KeepAlive</key>")
            .nth(1)
            .and_then(|rest| rest.split("</dict>").next())
            .expect("the job is kept alive by condition, not unconditionally");

        let conditions = keep_alive.matches("<key>").count();
        assert_eq!(
            conditions, 1,
            "{conditions} conditions are OR'd together; only restart-on-failure belongs here"
        );

        let successful_exit = keep_alive.contains("<key>SuccessfulExit</key>\n        <false/>");
        assert!(
            successful_exit,
            "a clean exit is what a stop produces, so it must be the one that is not restarted"
        );
    }

    /// An install that only *started* the unit installed nothing on a machine that already had
    /// one running: the process keeps the build it was launched from, so an upgrade stayed on
    /// its first-ever binary while the unit file on disk named the new one. `restart` replaces
    /// the process, and starts a unit that is not up yet.
    #[test]
    fn an_install_replaces_a_running_unit_rather_than_starting_it() {
        let [verb, unit] = linux_activation_args();

        assert_eq!(verb, "restart", "a start leaves the old build running");
        assert_eq!(unit, SERVICE_NAME);
    }

    /// `sc query` for a service that is running. The PID is 1060 on purpose — see below.
    fn query_running() -> &'static str {
        "\
SERVICE_NAME: nexa-service
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1060
"
    }

    /// `sc query` for a service that accepted a stop and is still running its teardown, which
    /// ends with restoring the system DNS.
    fn query_stop_pending() -> &'static str {
        "\
SERVICE_NAME: nexa-service
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x4e20
"
    }

    /// A service that has not finished coming down is not a stopped one.
    ///
    /// Reading `STOP_PENDING` as stopped is what made waiting for a stop return immediately, so
    /// an install went on re-pointing the binary and starting it while the previous build was
    /// still tearing down. Restoring the system DNS is the last thing that teardown does, which
    /// makes it the one that races whatever the new build does at startup.
    #[test]
    fn a_pending_stop_is_not_a_finished_one() {
        assert_eq!(sc_state(query_stop_pending()), ScState::Pending);

        assert_ne!(
            sc_state(query_stop_pending()),
            ScState::Stopped,
            "a stop that is still in progress must not read as one that finished"
        );
    }

    /// The same digits that mean "not installed" also appear where they mean nothing.
    ///
    /// A missing service is reported as `FAILED 1060` and has no `PID` line at all, while
    /// `PID : 1060` is a process id. Matching the number anywhere would make a running service
    /// read as absent, and an install that believes the service is gone does not stop it first.
    #[test]
    fn a_process_id_is_not_a_missing_service() {
        assert_eq!(sc_state(query_running()), ScState::Running);

        assert_eq!(
            sc_state("[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service.\n"),
            ScState::Absent
        );
    }

    /// The four answers a wait keys off: coming down, up, gone, and "no answer".
    #[test]
    fn every_state_the_control_manager_reports_is_read() {
        assert_eq!(
            sc_state(
                "SERVICE_NAME: nexa-service\n        STATE              : 1  STOPPED\n        WIN32_EXIT_CODE    : 0  (0x0)\n"
            ),
            ScState::Stopped
        );
        assert_eq!(
            sc_state(
                "SERVICE_NAME: nexa-service\n        STATE              : 2  START_PENDING\n                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)\n"
            ),
            ScState::Pending
        );
        assert_eq!(
            sc_state("[SC] OpenSCManager FAILED 5:\n\nAccess is denied.\n"),
            ScState::Unknown,
            "a query that never reached a service answers no state, which is not 'stopped'"
        );
    }

    /// The executable path is the only part of the job that is interpolated into XML
    /// rather than fixed, so it is the only part that can break it.
    #[test]
    fn the_executable_path_reaches_the_job_intact() {
        let path = "/Applications/Nexa.app/Contents/MacOS/nexa";
        let plist = macos_plist_content(path);

        assert!(plist.contains(&format!("<string>{path}</string>")));
        assert!(plist.contains(&format!("com.nexa.{SERVICE_NAME}")));
    }
}

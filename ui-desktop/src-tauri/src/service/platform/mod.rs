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
#[cfg(any(windows, test))]
use std::path::{Path, PathBuf};

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

// ==========================================================================
// Windows: the binary the service control manager starts
// ==========================================================================

/// The name of the service binary, in the app's own directory and in the
/// system-wide one alike.
#[cfg(any(windows, test))]
pub(crate) const SERVICE_BINARY_NAME: &str = "nexa-service.exe";

/// The directory the service binary is copied into when the service is
/// registered.
///
/// Under `C:\Program Files`, whose permissions give an ordinary user read and
/// execute and nothing else. The control manager starts the file it is
/// pointed at as SYSTEM without asking anybody, so *where* that file lives
/// decides whether the user who installed the app can replace it — and a
/// replaced service binary is a program of the user's choosing running as
/// SYSTEM.
#[cfg(any(windows, test))]
pub(crate) fn system_service_dir(program_files: &Path) -> PathBuf {
    program_files.join("Nexa").join("Service")
}

/// The system-wide copy of the service binary: the one the control manager is
/// pointed at.
#[cfg(any(windows, test))]
pub(crate) fn system_service_binary(program_files: &Path) -> PathBuf {
    system_service_dir(program_files).join(SERVICE_BINARY_NAME)
}

/// The binary the control manager is pointed at.
///
/// The system-wide copy, and never the app's own. The app installs itself per
/// user, so the directory the per-user copy lives in belongs to the user who
/// installed it — and the control manager starts what it is pointed at as
/// SYSTEM, without asking anyone. An install that cannot put the binary
/// somewhere the user cannot write has to fail rather than register a path the
/// user owns, so there is deliberately no fallback to the per-user copy: that
/// one is what the system-wide copy is made *from*.
#[cfg(any(windows, test))]
pub(crate) fn scm_service_binary(system: &Path, _per_user: &Path) -> PathBuf {
    system.to_path_buf()
}

/// The app's own copies of the service binary, in the order they are tried.
///
/// The `resources` directory the app ships the binary in first, then the
/// directory the app binary itself is in. Neither of them is what the control
/// manager runs — see [`scm_service_binary`] — they are what the system-wide
/// copy is made from.
#[cfg(any(windows, test))]
pub(crate) fn per_user_service_candidates(app_dir: &Path) -> Vec<PathBuf> {
    vec![
        app_dir.join("resources").join(SERVICE_BINARY_NAME),
        app_dir.join(SERVICE_BINARY_NAME),
    ]
}

/// The first of `candidates` that is there, or `fallback` when none of them is.
///
/// `exists` is a parameter so the rule can be read on a machine that has none
/// of those files.
#[cfg(any(windows, test))]
pub(crate) fn pick_service_binary(
    candidates: &[PathBuf],
    fallback: &Path,
    exists: impl Fn(&Path) -> bool,
) -> PathBuf {
    candidates
        .iter()
        .find(|candidate| exists(candidate))
        .cloned()
        .unwrap_or_else(|| fallback.to_path_buf())
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
        per_user_service_candidates, pick_service_binary, sc_state, scm_service_binary,
        system_service_binary, system_service_dir, ScState, SERVICE_BINARY_NAME, SERVICE_NAME,
    };
    use std::path::{Path, PathBuf};

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

    /// The directory the service binary is copied into, and the per-user copy it
    /// is copied from.
    ///
    /// The two are what the whole fix is about: the control manager has to be
    /// pointed at the first and never at the second, because the app installs
    /// itself per user and the second therefore belongs to the user who
    /// installed it.
    fn windows_service_paths() -> (PathBuf, PathBuf) {
        let program_files = Path::new("/Program Files");
        let app_dir = Path::new("/home/user/AppData/Local/Programs/nexa");

        (
            system_service_binary(program_files),
            app_dir.join(SERVICE_BINARY_NAME),
        )
    }

    /// The path the control manager is given has to be the system-wide one.
    ///
    /// The control manager starts what it is pointed at as SYSTEM, without
    /// asking anyone, so a path the user can write is a path that hands SYSTEM
    /// to whoever writes there: the user who installed the app replaces the
    /// binary and the next start of the service runs their program as SYSTEM.
    #[test]
    fn the_control_manager_is_pointed_at_the_system_wide_copy() {
        let (system, per_user) = windows_service_paths();

        let pointed_at = scm_service_binary(&system, &per_user);

        assert_eq!(
            pointed_at, system,
            "the control manager has to run the copy in Program Files"
        );
        assert_ne!(
            pointed_at, per_user,
            "the per-user copy is in a directory the user owns; the control manager \
             would run whatever they put there, as SYSTEM"
        );
    }

    /// The resolution the control manager's path goes through prefers the
    /// system-wide copy.
    ///
    /// The app's own copy is right there — it is what the system-wide one is
    /// made from — and the answer is still the one the user cannot replace.
    /// There is no "fall back to the per-user copy" case: an install that
    /// cannot put the binary somewhere the user cannot write has to fail.
    #[test]
    fn the_service_binary_resolution_prefers_the_system_wide_copy() {
        let (system, per_user) = windows_service_paths();
        let app_dir = Path::new("/home/user/AppData/Local/Programs/nexa");

        // The per-user copies are the source the system-wide one is made from.
        let candidates = per_user_service_candidates(app_dir);
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].file_name().and_then(|name| name.to_str()),
            Some(SERVICE_BINARY_NAME)
        );
        assert!(
            candidates[0]
                .parent()
                .and_then(|dir| dir.file_name())
                .and_then(|name| name.to_str())
                == Some("resources"),
            "the copy the app ships in its resources directory comes first"
        );

        // Both the system-wide copy and the app's own copy are there, and the
        // resolution still picks the system-wide one.
        let both = [system.clone(), per_user.clone()];
        let picked = pick_service_binary(&both, &app_dir.join("nexa"), |path| {
            path == system || path == per_user
        });

        assert_eq!(picked, system);
    }

    /// The system-wide copy lives under `Program Files`, in a directory of its
    /// own.
    ///
    /// `Program Files` is the one place Windows already keeps the way this fix
    /// needs: an ordinary user may read and execute what is in it, and may
    /// not write to it.
    #[test]
    fn the_system_wide_copy_lives_under_program_files() {
        let program_files = Path::new("/Program Files");

        let dir = system_service_dir(program_files);
        assert_eq!(
            dir.strip_prefix(program_files).unwrap(),
            Path::new("Nexa").join("Service"),
            "the copy is not in the app's own directory, which the user owns"
        );
        assert_eq!(
            system_service_binary(program_files)
                .file_name()
                .and_then(|name| name.to_str()),
            Some(SERVICE_BINARY_NAME)
        );
    }
}

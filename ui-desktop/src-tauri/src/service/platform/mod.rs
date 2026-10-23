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

/// Where the daemon's own copy of the service binary lives.
///
/// Root's, and not writable by anybody else, and outside the app's own directory: the
/// service runs as root, so a program a local account can replace is a program that
/// account owns — and an app that is replaced under the service manager must not take the
/// program out from under the running service.
#[cfg(target_os = "macos")]
pub const SERVICE_COPY_PATH: &str = "/Library/Application Support/Nexa/nexa-service";

/// See the macOS note above. `/usr/libexec` is the FHS's place for the support binaries a
/// system service runs, and it is root's on every distribution that has it.
#[cfg(target_os = "linux")]
pub const SERVICE_COPY_PATH: &str = "/usr/libexec/nexa-service";

/// Where the daemon's program lives: the install's own copy of the service binary.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub fn service_binary_path() -> PathBuf {
    PathBuf::from(SERVICE_COPY_PATH)
}

pub mod account;
pub mod install_owner;
pub mod install_version;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::service::platform::account::AccountId;

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
// The elevation channel is Unix's, but the argument that names the account the
// service is installed for is read on every platform: the elevated child is
// the one that reads it back, and it is the same child on all of them.
use crate::service::elevate;
#[cfg(any(windows, test))]
use std::path::Path;
#[cfg(any(windows, target_os = "macos", target_os = "linux", test))]
use std::path::PathBuf;

/// Registers the service and starts it.
pub fn install_service() -> Result<(), AppError> {
    #[cfg(windows)]
    return install(account::AccountId::current());

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
/// A service that is marked for deletion is the third thing that is neither: it is on its way
/// out, and it is kept apart for the same reason — it cannot be started, and it is not there
/// to be uninstalled again.
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
    /// Marked for deletion: registered, but on its way out of the control manager's database.
    ///
    /// Its own state, because it is neither registered-and-stopped nor gone: the record is
    /// still there, but the control manager has already been told to remove it and refuses
    /// every operation on it. A panel that reads it as "stopped" offers to start a service
    /// that cannot be started and to uninstall one that is already leaving.
    Deleting,
    /// `sc.exe` could not be asked, or answered without a state line.
    Unknown,
}

/// The Win32 error `sc.exe query` answers with when the service is not installed.
#[cfg(any(windows, test))]
const NOT_INSTALLED: &str = "1060";

/// The Win32 error `sc.exe query` answers with when the service is marked for deletion.
///
/// `DeleteService` only *marks* a service for deletion: the record stays in the control
/// manager's database until every handle to it is closed and the service is no longer
/// running. Until then a query fails with this instead of answering a state, and a service
/// that is leaving has to read as leaving — not as one that is registered and stopped.
#[cfg(any(windows, test))]
const MARKED_FOR_DELETE: &str = "1072";

/// Reads that answer out of what `sc.exe query` prints.
///
/// A failure only counts when `sc.exe` reported it as one: the same four digits appear in the
/// `PID` line of a perfectly healthy service, and reading that as "absent" would let an install
/// replace a service that is still up.
#[cfg(any(windows, test))]
fn sc_state(query_output: &str) -> ScState {
    if failure_with(query_output, NOT_INSTALLED) {
        return ScState::Absent;
    }

    // Checked before the state line, because a query that failed this way has no state line
    // at all: it is the answer of a record that is on its way out, not a state.
    if failure_with(query_output, MARKED_FOR_DELETE) {
        return ScState::Deleting;
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

/// Whether `sc.exe` answered with `code` as the failure it reported.
///
/// The code has to be on the line that carries `FAILED`: `sc.exe` puts the error there, and
/// the same digits turn up elsewhere in an answer that is not a failure at all.
#[cfg(any(windows, test))]
fn failure_with(query_output: &str, code: &str) -> bool {
    query_output
        .lines()
        .any(|line| line.contains("FAILED") && line.contains(code))
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
#[cfg(any(target_os = "linux", target_os = "macos", test))]
mod service_copy;
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
        let installing_by = installing_account();
        return dispatch_install(&exe_path, installing_by.as_ref());
    }

    // The account the service is being installed for, named on the command
    // line of the elevated child. The child cannot work it out for itself: it
    // runs as root, and so does the account that asked for the elevation as
    // far as the child is concerned.
    let mut args: Vec<String> = vec!["--install".to_string()];
    if let Some(account) = AccountId::current() {
        args.push(elevate::INSTALL_AS_ARG.to_string());
        args.push(account.to_text());
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();

    elevate::run_self_elevated(&borrowed)
}

/// The account the service is being installed for, as far as this process can
/// tell.
///
/// The elevated child is told on the command line; failing that, the elevation
/// channel says so itself — `pkexec` sets `PKEXEC_UID` and `sudo` sets
/// `SUDO_UID`, both to the user id of the account that asked for the
/// elevation, and neither can be set by anybody but the channel itself.
///
/// `None` when nothing says, and then the service is installed without an
/// account to serve: it falls back to serving the account that owns the token
/// it reads, and says so loudly.
#[cfg(not(windows))]
fn installing_account() -> Option<AccountId> {
    installing_account_from_args(std::env::args_os().skip(1)).or_else(installing_account_from_env)
}

/// The account named on the command line, if any.
///
/// Public so that the parsing can be checked on any platform, including the
/// ones whose elevation channel has no environment variable to fall back on.
pub fn installing_account_from_args<I>(args: I) -> Option<AccountId>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg.as_os_str() == std::ffi::OsStr::new(elevate::INSTALL_AS_ARG) {
            return args
                .next()
                .and_then(|value| value.to_str().and_then(AccountId::parse));
        }
    }
    None
}

/// The account the elevation channel says asked for it.
///
/// The channel is unix's, but the function is not unix's alone: the rest of
/// the elevation path is `not(windows)`, and a target that is neither unix
/// nor windows would not compile if this one were unix-only.
#[cfg(not(windows))]
fn installing_account_from_env() -> Option<AccountId> {
    for name in ["PKEXEC_UID", "SUDO_UID"] {
        let Ok(value) = std::env::var(name) else {
            continue;
        };
        if let Ok(uid) = value.trim().parse::<u32>() {
            return Some(AccountId::Unix(uid));
        }
    }
    None
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
fn dispatch_install(exe_path: &str, installing_by: Option<&AccountId>) -> Result<(), AppError> {
    install_service_linux(exe_path, installing_by)
}

#[cfg(target_os = "macos")]
fn dispatch_install(exe_path: &str, installing_by: Option<&AccountId>) -> Result<(), AppError> {
    install_service_macos(exe_path, installing_by)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn dispatch_install(_exe_path: &str, _installing_by: Option<&AccountId>) -> Result<(), AppError> {
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
        installing_account_from_args, linux_activation_args, linux_service_exec,
        linux_unit_content, macos_install_commands, macos_job_target, macos_plist_content,
        per_user_service_candidates, pick_service_binary, sc_state, scm_service_binary,
        service_binary_path, system_service_binary, system_service_dir, ScState,
        SERVICE_BINARY_NAME, SERVICE_NAME,
    };
    use crate::service::elevate;
    use crate::service::platform::account::AccountId;
    use crate::service::platform::service_copy;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    /// systemd splits the `ExecStart=` line on whitespace, so a path with a space in it
    /// arrives as two arguments and the unit fails to start — with `status=203/EXEC`,
    /// which names neither the path nor the space that caused it.
    ///
    /// The macOS plist and the Windows `binPath` both carry such a path correctly. This is
    /// the third spelling of the same thing, and it was the one that did not.
    #[test]
    fn the_systemd_unit_quotes_a_path_with_a_space_in_it() {
        let unit = linux_unit_content("/home/me/My Apps/nexa");

        let exec_start = unit
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .expect("the unit carries an ExecStart");

        assert!(
            exec_start.starts_with("\"/home/me/My Apps/nexa\""),
            "the path is not quoted: {exec_start}"
        );
    }

    /// The argument after the path has to survive the quoting too, or it becomes part of
    /// the path — and the unit then fails with `status=203/EXEC`.
    #[test]
    fn the_systemd_exec_keeps_its_argument_outside_the_quotes() {
        let exec = linux_service_exec("/home/me/My Apps/nexa");

        assert_eq!(exec, "\"/home/me/My Apps/nexa\" --foreground");
    }

    /// A path with a quote or a backslash in it has to come out of the quoting unchanged:
    /// systemd reads the line with its own word splitter, and inside double quotes a
    /// backslash escapes the character after it.
    #[test]
    fn the_quoting_escapes_what_systemd_would_otherwise_take() {
        let exec = linux_service_exec("/home/me/My \"Apps\"/nexa-service");

        assert_eq!(
            exec,
            "\"/home/me/My \\\"Apps\\\"/nexa-service\" --foreground"
        );
    }

    /// The unit runs the install's own copy of the service binary, not the app's.
    ///
    /// The unit runs as root, and the app's own binary lives where the local accounts can
    /// replace it — so a unit that pointed at it would be running, as root, a program
    /// another account owns. The copy lives in a root-owned directory instead.
    #[test]
    fn the_unit_runs_the_copied_binary() {
        let program = service_binary_path();
        let unit = linux_unit_content(&program.to_string_lossy());

        assert!(
            unit.contains(&format!(
                "ExecStart=\"{}\" --foreground",
                program.to_string_lossy()
            )),
            "the unit does not run the copy: {unit}"
        );
        assert!(
            !unit.contains("/home/") && !unit.contains("/Applications/"),
            "the unit still runs a binary out of the app's own directory: {unit}"
        );
    }

    /// The copy lives in a root-owned directory, and not in the app's own: an app that is
    /// replaced under the service manager must not take the program out from under the
    /// running service.
    #[test]
    fn the_copy_lives_in_a_system_directory() {
        let program = service_binary_path();

        assert!(
            program.starts_with("/usr/") || program.starts_with("/Library/"),
            "the copy is not in a system directory: {program:?}"
        );

        #[cfg(target_os = "macos")]
        assert_eq!(
            program,
            Path::new("/Library/Application Support/Nexa/nexa-service")
        );
        #[cfg(target_os = "linux")]
        assert_eq!(program, Path::new("/usr/libexec/nexa-service"));
    }

    /// The dedicated service binary beside the desktop executable is what gets copied; a
    /// development build has none, and the desktop binary is the source then.
    #[test]
    fn the_source_is_the_service_binary_beside_the_app() {
        let app = Path::new("/usr/bin/nexa");

        assert_eq!(
            service_copy::service_source_with(app, |_| true),
            Path::new("/usr/bin/nexa-service")
        );
        assert_eq!(service_copy::service_source_with(app, |_| false), app);
    }

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

    /// The job runs the install's own copy of the service binary, not the app's.
    ///
    /// The app's own binary sits in a directory the local accounts own, and a privileged
    /// service must not run a program they can replace: launchd refuses to spawn one,
    /// and an install refused that way leaves the machine with no service at all.
    #[test]
    fn the_job_runs_the_copied_binary() {
        let program = service_binary_path();
        let plist = macos_plist_content(&program.to_string_lossy());

        assert!(
            plist.contains(&program.to_string_lossy().to_string()),
            "the job does not run the copy: {plist}"
        );
        assert!(
            !plist.contains("/Applications/"),
            "the job still runs the app's own binary: {plist}"
        );
    }

    /// The copy lives in a system directory, and not in the app bundle: an app that is
    /// replaced under the service manager must not take the program out from under the
    /// running service.
    #[test]
    fn the_copy_lives_outside_the_app_bundle() {
        let program = service_binary_path();

        assert!(
            !program.starts_with("/Applications/") && !program.starts_with("/home/"),
            "the copy is inside the app's own directory: {program:?}"
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
            sc_state(
                "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service.\n"
            ),
            ScState::Absent
        );
    }

    /// A service that is on its way out is not a service that is registered and stopped.
    ///
    /// `DeleteService` only *marks* a service for deletion: the record stays in the control
    /// manager's database until every handle to it is closed and the service is no longer
    /// running, and a query in that window fails instead of answering a state. Reading that as
    /// "stopped" is what left the panel offering to start a service that cannot be started, and
    /// to uninstall one that was already leaving.
    #[test]
    fn a_service_marked_for_deletion_is_not_a_stopped_one() {
        assert_eq!(sc_state(query_marked_for_delete()), ScState::Deleting);

        assert_ne!(
            sc_state(query_marked_for_delete()),
            ScState::Stopped,
            "a service that is leaving must not read as one that is registered and stopped"
        );
    }

    /// The answer, spelled the way `sc.exe` spells it.
    ///
    /// The failure carries the code on the line that says `FAILED`, and the state line the
    /// other answers have is not there at all — which is why reading it as anything but a
    /// failure needed the code to be looked for in the first place.
    #[test]
    fn the_marked_for_deletion_failure_is_read_as_one() {
        assert_eq!(
            sc_state(
                "[SC] EnumQueryServicesStatus:OpenService FAILED 1072:\n\nThe specified service has been marked for deletion.\n"
            ),
            ScState::Deleting
        );
    }

    /// A code that is not a failure is not a failure.
    ///
    /// The same four digits turn up in the exit-code line of a service that stopped badly, and
    /// reading that as "marked for deletion" would take a registered service out of the
    /// picture.
    #[test]
    fn an_exit_code_is_not_a_deletion() {
        assert_eq!(
            sc_state(
                "SERVICE_NAME: nexa-service\n        STATE              : 1  STOPPED\n        WIN32_EXIT_CODE    : 1072  (0x430)\n"
            ),
            ScState::Stopped
        );
    }

    /// `sc query` for a service that has been marked for deletion and has not left the control
    /// manager's database yet.
    fn query_marked_for_delete() -> &'static str {
        "\
[SC] EnumQueryServicesStatus:OpenService FAILED 1072:

The specified service has been marked for deletion.
"
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

    /// The account the elevated copy is told about comes back off the command
    /// line.
    ///
    /// The flag is the only channel macOS has: `do shell script … with
    /// administrator privileges` carries no `PKEXEC_UID` and no `SUDO_UID`, so
    /// a silent parse failure here installs the service for nobody — and a
    /// service with no account is one that serves every local account that
    /// owns a token.
    ///
    /// The flag comes after the verb, which is what the elevated child is
    /// started with.
    #[test]
    fn the_install_as_flag_names_the_account() {
        let account = installing_account_from_args([
            OsString::from("--install"),
            OsString::from(elevate::INSTALL_AS_ARG),
            OsString::from("1000"),
        ]);

        #[cfg(unix)]
        assert_eq!(account, Some(AccountId::Unix(1000)));
        #[cfg(windows)]
        assert_eq!(account, Some(AccountId::Windows("1000".to_string())));
    }

    /// A flag with no value behind it names nobody.
    ///
    /// The value is what says which account; a flag on its own is a flag
    /// somebody typed, and the install it starts has no account to serve.
    #[test]
    fn the_install_as_flag_with_no_value_names_nobody() {
        let account = installing_account_from_args([
            OsString::from("--install"),
            OsString::from(elevate::INSTALL_AS_ARG),
        ]);

        assert_eq!(account, None);
    }

    /// An empty value names nobody either.
    ///
    /// Empty is the one value that is not an account on either platform: a
    /// Unix account is a number and a Windows account is a non-empty string.
    #[test]
    fn the_install_as_flag_with_an_empty_value_names_nobody() {
        let account = installing_account_from_args([
            OsString::from("--install"),
            OsString::from(elevate::INSTALL_AS_ARG),
            OsString::from(""),
        ]);

        assert_eq!(account, None);
    }

    /// A value that is not an account at all names nobody.
    ///
    /// This is the Unix half of the rule: a uid is a number, and a string that
    /// is not one is not an account. Every non-empty string is a spelling of a
    /// SID on Windows, so there the equivalent is the empty value above.
    #[cfg(unix)]
    #[test]
    fn the_install_as_flag_that_is_not_a_uid_names_nobody() {
        let account = installing_account_from_args([
            OsString::from("--install"),
            OsString::from(elevate::INSTALL_AS_ARG),
            OsString::from("not-a-uid"),
        ]);

        assert_eq!(account, None);
    }

    /// A command line without the flag names nobody.
    ///
    /// The install that falls back to the environment variables is the Unix
    /// one; the flag is what carries the account where there is no
    /// environment variable to carry it.
    #[test]
    fn the_install_as_flag_that_is_not_there_names_nobody() {
        let account = installing_account_from_args([
            OsString::from("--install"),
            OsString::from("--elevated"),
        ]);

        assert_eq!(account, None);
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

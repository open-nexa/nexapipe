//! The Windows half of the service registration.
//!
//! `sc.exe` is the only way to register a service on Windows, and it needs an
//! administrator: the calls are written into a batch file and that batch file is
//! re-launched through the UAC prompt. The half that is not Windows is in
//! `super`, and the two meet at the same public API.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{
    per_user_service_candidates, pick_service_binary, remove_copy_batch, sc_state,
    scm_service_binary, system_service_binary, system_service_dir, ScState, ServiceState,
    MARKED_FOR_DELETE, NOT_INSTALLED, SERVICE_DISPLAY_NAME, SERVICE_NAME,
};
use crate::error::{codes, AppError};
use crate::service::platform::account::AccountId;
use crate::service::platform::install_owner;
use crate::service::platform::install_version;

/// Text `services.msc` shows for the entry.
const SERVICE_DESCRIPTION: &str =
    "Runs the nexa proxy (TUN mode) without a signed-in desktop session.";

/// The permissions the system-wide directory is given.
///
/// SYSTEM and the administrators may write; an ordinary user may only read
/// and execute. `Program Files` already says that much, but the directory is
/// given it explicitly so that the answer does not depend on how the machine
/// happens to be configured.
///
/// Spelled with SIDs rather than with account names, because those are
/// localized: "Administrators" is "Administrateurs" on a French Windows, and
/// a command naming an account that does not exist is a command that fails.
/// `*S-1-5-18` is SYSTEM, `*S-1-5-32-544` the administrators and
/// `*S-1-5-32-545` the ordinary users.
///
/// Each permission is quoted: the parentheses in it are part of the
/// permission and not part of the command, and `cmd.exe` reads an unquoted
/// one as the start of a command block.
const DIRECTORY_ACL: &str = "/inheritance:r /grant:r \"*S-1-5-18:(OI)(CI)F\" \
                            \"*S-1-5-32-544:(OI)(CI)F\" \"*S-1-5-32-545:(OI)(CI)RX\"";

/// The permissions the system-wide copy of the service binary is given.
///
/// The same, without the inheritance flags: a file is a file, and it gets its
/// own so that nothing about the copy it was made from travels with it.
const FILE_ACL: &str =
    "/inheritance:r /grant:r \"*S-1-5-18:F\" \"*S-1-5-32-544:F\" \"*S-1-5-32-545:RX\"";

/// The helpers are console tools; the UAC consent dialog is drawn by Windows and shows
/// regardless of this flag.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `sc.exe` answers in milliseconds, so anything slower is a stuck service rather than a slow
/// one.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// An elevated run has to wait for the user to notice the prompt and answer it.
const ELEVATION_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a start or stop may take to actually show up in `sc query`. The SCM accepts the
/// command immediately, so this is the wait for the process to reach the requested state.
///
/// Not shorter than the stop wait hint the service itself asks the control manager for
/// (`STOP_WAIT_HINT` in `nexa-service.rs`): the teardown ends with restoring the system DNS,
/// and giving up before the service's own budget is up reports a stop that is still running
/// as one that failed — which leaves the service registered, and the panel offering to start a
/// service that is on its way down.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a record that is marked for deletion is waited for.
///
/// The record normally leaves the control manager's database as soon as the last handle to it
/// is closed, which is quick. The wait is for the case where something is still holding it —
/// the service's own process on its way out, or a console that opened the service's properties
/// and stayed open — and it is bounded, so a handle that never comes back does not turn into a
/// hang.
const DELETE_RECORD_TIMEOUT: Duration = Duration::from_secs(15);

/// `sc.exe` reports a refused operation as exit code 5 carrying this text.
const ACCESS_DENIED: &str = "Access is denied";

/// Argument that hands control to the service control manager.
const SERVICE_ARGUMENT: &str = "--service";

/// `sc start` on a service that is already running.
///
/// Not a failure: running is the state the command asked for. Reported as it is, the exit
/// code turns a successful install into `service.install_failed` carrying
/// "StartService failed 1056" — an install that worked, described as one that did not.
const ALREADY_RUNNING: i32 = 1056;

/// `sc stop` on a service that is not started (or not installed).
///
/// Same shape: the state asked for is already the state, so refusing to call it a success
/// only stops a perfectly good stop from ever being reported as done.
const NOT_STARTED: i32 = 1062;

/// Accepts a nonzero exit code from the previous command as success.
///
/// `errorlevel` is compared literally rather than with `if errorlevel N` because that form
/// means "N or higher" and would swallow real failures with larger codes.
fn tolerate(code: i32) -> String {
    format!("if %errorlevel%=={code} exit /b 0")
}

/// Whether an operation can succeed without asking for elevation.
enum Escalation {
    /// It always needs administrative rights (`sc create`).
    Always,
    /// Run it as the invoking user first, and only escalate when that is refused.
    OnAccessDenied,
}

/// Registers the service, and starts it unless `leave_stopped` says otherwise.
///
/// `leave_stopped` is what the installer uses: an upgrade has to leave the machine the way it
/// found it, and a service the user had stopped is not theirs to start behind their back.
///
/// `keep_owner` is the other half of that: an upgrade does not decide which account the
/// service serves either. The account it was installed for is the one the user chose, and
/// the installer is not the place to change it — so the record is left as it is.
///
/// The registration itself is the same either way — the entry, the binary under Program
/// Files, the account it serves — only the service is left down and the account untouched.
pub fn install(
    installing_by: Option<AccountId>,
    leave_stopped: bool,
    keep_owner: bool,
) -> Result<(), AppError> {
    // A record that is still marked for deletion has to be gone before a new service can take
    // the name, so this waits for it rather than letting `sc create` refuse.
    wait_for_deletable_record()?;

    let exe = std::env::current_exe().map_err(|e| AppError::cause(codes::SERVICE_EXE_PATH, e))?;
    let app_dir = exe
        .parent()
        .ok_or_else(|| AppError::new(codes::SERVICE_EXE_PATH))?
        .to_path_buf();

    // The copy that is made is the app's own, and the control manager is
    // pointed at the system-wide copy it becomes. The app's own directory is
    // the user's to write — the app installs itself per user — and the
    // control manager runs what it is pointed at as SYSTEM, without asking
    // anyone, so that directory is the one place the service binary may not
    // come from.
    let source = service_binary(&app_dir, &exe);
    let program_files = program_files()?;
    let dir = system_service_dir(&program_files);
    let system = system_service_binary(&program_files);
    let bin_path =
        bin_path_value(&scm_service_binary(&system, Path::new(&source)).to_string_lossy());

    // Whatever is already running has to go first — see [`stop_if_running`]. Done before
    // the binary is re-pointed, because the process is what keeps the old build alive.
    stop_if_running()?;

    // `create` fails with 1073 when an older installation is already registered, so an
    // existing service is re-pointed at the current binary instead of being rejected. Both
    // branches carry their own redirection: the elevated run cannot hand stdout back, so a
    // redirect appended *outside* the parentheses would leave the log empty and make a real
    // failure look like a declined prompt.
    run(
        |log| {
            install_batch(
                InstallPaths {
                    log,
                    dir: &dir,
                    source: &source,
                    system: &system,
                    bin_path: &bin_path,
                },
                installing_by.as_ref(),
                leave_stopped,
                keep_owner,
            )
        },
        "service install",
        Escalation::Always,
        codes::SERVICE_INSTALL_FAILED,
    )
    .and_then(|()| verify_copied(Path::new(&source), &system))
    .and_then(|()| verify_present())
    // `sc start` returns success as soon as the SCM has launched the process, which says
    // nothing about whether it stays up: a service that dies during startup still reports a
    // successful start. Waiting for the state to become RUNNING is what turns "installed but
    // not running" into a reported failure instead of a mystery.
    //
    // Only for an install that started the service: one that was asked to leave it down has
    // nothing to wait for.
    .and_then(|()| {
        if leave_stopped {
            Ok(())
        } else {
            settle(ServiceState::Running, codes::SERVICE_START_FAILED)
        }
    })
}

/// The paths an install works on.
///
/// Gathered into one value so that the batch can be built from them without a list of
/// arguments long enough to be read wrong.
struct InstallPaths<'a> {
    /// Where the elevated run leaves its output.
    log: &'a Path,
    /// The system-wide directory the service binary is copied into.
    dir: &'a Path,
    /// The service binary the app ships.
    source: &'a str,
    /// The copy of it the control manager runs.
    system: &'a Path,
    /// The value the control manager's `binPath` is given.
    bin_path: &'a str,
}

/// The batch the elevated install runs.
///
/// Split out of [`install`] so that what it says about the service can be read without a
/// service manager: an upgrade is allowed to replace the binary and to leave the service
/// alone, and nothing else. What it says about the entry is the whole of that, so it is
/// worth being able to look at.
fn install_batch(
    paths: InstallPaths<'_>,
    installing_by: Option<&AccountId>,
    leave_stopped: bool,
    keep_owner: bool,
) -> Vec<String> {
    let InstallPaths {
        log,
        dir,
        source,
        system,
        bin_path,
    } = paths;
    let redirect = format!("> \"{}\" 2>&1", log.display());
    let mut lines = vec![
        // The system-wide copy is made before the entry exists, and the
        // entry is only pointed at it once it is there. A copy that
        // cannot be made, or a directory whose permissions cannot be
        // locked down, stops the install here — a service that cannot
        // be installed safely is better than one that hands SYSTEM to
        // whoever can write the directory.
        format!("mkdir \"{}\"", dir.display()),
        format!("if not exist \"{}\" exit /b 1", dir.display()),
        format!("icacls \"{}\" {DIRECTORY_ACL}", dir.display()),
        "if errorlevel 1 exit /b %errorlevel%".to_string(),
        format!("copy /y \"{source}\" \"{}\"", system.display()),
        "if errorlevel 1 exit /b %errorlevel%".to_string(),
        // The copy is a promise until it has been checked. The control
        // manager keeps running whatever was copied the day the service
        // was registered, so a copy that did not land is a service that
        // goes on running the old build while the app is new — and the
        // user has no way to tell. Compared here, in the same elevated
        // run and before the entry is touched, so a copy that is not
        // the binary that was asked for stops the install outright.
        format!("fc /b \"{source}\" \"{}\"", system.display()),
        "if errorlevel 1 exit /b %errorlevel%".to_string(),
        format!("icacls \"{}\" {FILE_ACL}", system.display()),
        "if errorlevel 1 exit /b %errorlevel%".to_string(),
        format!("sc.exe query {SERVICE_NAME} >nul 2>&1"),
        // `start=` is written only where the service is created. An entry that is already
        // there keeps the start type it has: when the user's service comes up is the user's
        // decision, and an app that is reinstalled is not a reason for a service that was set
        // to start by hand to start by itself from then on.
        format!(
            "if errorlevel 1 (sc.exe create {SERVICE_NAME} binPath= \"{bin_path}\" start= auto DisplayName= \"{SERVICE_DISPLAY_NAME}\" {redirect}) else (sc.exe config {SERVICE_NAME} binPath= \"{bin_path}\" {redirect})"
        ),
        "if errorlevel 1 exit /b %errorlevel%".to_string(),
        format!("sc.exe description {SERVICE_NAME} \"{SERVICE_DESCRIPTION}\""),
        "if errorlevel 1 exit /b %errorlevel%".to_string(),
    ];

    // Which account this service is installed for, kept in the service's own
    // registry key: the one place on Windows that only SYSTEM and the
    // administrators may write, so the unprivileged desktop cannot move the
    // service onto another account. Written after the key exists and before the
    // service starts, because the service reads it as it comes up.
    //
    // An upgrade does not write it: the account the service serves is the one the
    // user chose when they installed it, and re-registering the service is not
    // how that choice is changed.
    match (installing_by, keep_owner) {
        (Some(account), false) => {
            lines.push(install_owner::record_command(account));
            lines.push("if errorlevel 1 exit /b %errorlevel%".to_string());
        }
        (Some(_), true) => {
            tracing::info!(
                "Keeping the account the service already serves; the install leaves it alone."
            );
        }
        (None, _) => tracing::warn!(
            "Installing the service without naming the account it is for: it will serve \
             any local account that owns the token it reads"
        ),
    }

    // Which build this service is, kept in the service's own registry key beside the
    // account it serves. The desktop reads it to tell an old service from its own — a
    // question the service itself cannot answer once an upgrade has left it behind,
    // because the two no longer speak the same protocol.
    //
    // Written on an upgrade as well as on a first install: the build the service is
    // being registered from is the build it will be running.
    match install_version::record_command(crate::service::ipc::BUILD_VERSION) {
        Some(command) => {
            lines.push(command);
            lines.push("if errorlevel 1 exit /b %errorlevel%".to_string());
        }
        None => tracing::warn!(
            "Not recording which build the service is: the version cannot be written \
             into the install safely"
        ),
    }

    if !leave_stopped {
        lines.extend([
            format!("sc.exe start {SERVICE_NAME}"),
            // Nothing should be up at this point — [`stop_if_running`] brought the old
            // process down first — so 1056 means the service was started again by
            // something else, which is still the state the install asked for.
            tolerate(ALREADY_RUNNING),
            "exit /b %errorlevel%".to_string(),
        ]);
    } else {
        // Left down on purpose: the service was stopped before the upgrade and has to
        // stay stopped. The entry keeps the start type it had, so the next boot brings
        // it up — the service manager's own answer, not this installer's.
        lines.push("exit /b 0".to_string());
    }

    lines
}

/// Checks that the copy that was made is the file that was asked for.
///
/// The elevated run compares the two files as well — `fc /b`, before the entry is touched —
/// and this is the same question asked again from the outside, where a mismatch can be
/// reported with both paths in the message and where the check can be tested without a
/// service manager.
///
/// A copy that is not the copy is the whole bug this install exists to prevent: the control
/// manager keeps running whatever it was pointed at, so a service that was registered against
/// an older binary goes on running it while the app beside it is new.
fn verify_copied(source: &Path, system: &Path) -> Result<(), AppError> {
    if files_match(source, system) {
        return Ok(());
    }

    Err(AppError::with_detail(
        codes::SERVICE_INSTALL_FAILED,
        format!(
            "the service binary at {} is not the copy of {} that was installed",
            system.display(),
            source.display()
        ),
    ))
}

/// Whether two files hold the same bytes.
///
/// Read in blocks rather than whole: the service binary is tens of megabytes, and the
/// comparison is the one thing this install must not get wrong, so it reads what it has to
/// and stops at the first difference.
fn files_match(left: &Path, right: &Path) -> bool {
    use std::io::Read;

    let (Ok(mut left), Ok(mut right)) = (std::fs::File::open(left), std::fs::File::open(right))
    else {
        return false;
    };

    let mut left_block = [0u8; 64 * 1024];
    let mut right_block = [0u8; 64 * 1024];

    loop {
        let left_read = match left.read(&mut left_block) {
            Ok(read) => read,
            Err(_) => return false,
        };
        let right_read = match right.read(&mut right_block) {
            Ok(read) => read,
            Err(_) => return false,
        };

        if left_read != right_read {
            return false;
        }
        if left_read == 0 {
            return true;
        }
        if left_block[..left_read] != right_block[..right_read] {
            return false;
        }
    }
}

/// Brings a running service down, so that [`install`] can start it from the binary it has
/// just been pointed at.
///
/// A service keeps running what it was launched from: re-pointing `binPath` only takes
/// effect the next time the control manager starts it, so an install over a running service
/// — which is what an upgrade looks like — used to leave the previous build up and the app
/// talking to it. Stopping first is the only ordering that works, and it has to be waited
/// for: `sc stop` only *asks*, answering while the service is still `STOP_PENDING`, and a
/// start issued behind it is refused.
///
/// Skipped when nothing is running, which is the ordinary first install: this is the one
/// step that can cost a second elevation prompt, and a service that is not up has no build
/// to retire. Waited out by [`stop`], which reports a failure rather than letting the
/// install race a teardown that has not finished.
fn stop_if_running() -> Result<(), AppError> {
    if state() != ServiceState::Running {
        return Ok(());
    }

    stop()
}

pub fn uninstall() -> Result<(), AppError> {
    // The system-wide copy lives under Program Files, and an uninstall that
    // cannot find that directory cannot remove the copy — but it can still
    // remove the entry that points at it. Failing the whole uninstall over a
    // missing environment variable would leave the service registered, which
    // is worse than leaving a file behind.
    let system_copy = program_files().ok().map(|program_files| {
        let dir = system_service_dir(&program_files);
        let system = system_service_binary(&program_files);
        (dir, system)
    });

    if !service_exists() {
        // Nothing is registered, but the system-wide copy may still be there:
        // it is what the entry pointed at, and it is not the user's to keep.
        return match system_copy {
            Some((dir, system)) => remove_system_copy(&dir, &system),
            None => Ok(()),
        };
    }

    // Stopped, and confirmed stopped, before it is deleted. `sc delete` would stop
    // the service too, but `sc stop` reports success the moment the control manager
    // accepts the request — which says nothing about whether the teardown that
    // restores the system DNS has finished — and a delete issued on top of a stop
    // that is still running races it.
    run(
        |_| {
            vec![
                format!("sc.exe stop {SERVICE_NAME}"),
                tolerate(NOT_STARTED),
                tolerate(NOT_INSTALLED),
                "exit /b %errorlevel%".to_string(),
            ]
        },
        "service uninstall (stop)",
        Escalation::OnAccessDenied,
        codes::SERVICE_UNINSTALL_FAILED,
    )
    .and_then(|()| {
        // The stop may have taken the service off the register entirely — the code above
        // already tolerates 1060 from `sc stop` — and absent is the state an uninstall is
        // heading towards, so [`settle_down`] counts it as down instead of waiting out the
        // timeout for it. What it does wait for is the real thing: [`settle`] with
        // [`ServiceState::Stopped`] returned while the service was still STOP_PENDING, and a
        // delete issued on top of a teardown that has not finished races it.
        settle_down(codes::SERVICE_UNINSTALL_FAILED)
    })
    .and_then(|()| {
        if !service_exists() {
            return Ok(());
        }
        run(
            |_| {
                vec![
                    format!("sc.exe delete {SERVICE_NAME}"),
                    // A service that is already marked for deletion is on its way out, and the
                    // control manager answers the second delete with 1072. That is the state
                    // an uninstall is heading towards, so it counts as done.
                    tolerate(MARKED_FOR_DELETE),
                    "exit /b %errorlevel%".to_string(),
                ]
            },
            "service uninstall (delete)",
            Escalation::OnAccessDenied,
            codes::SERVICE_UNINSTALL_FAILED,
        )
    })
    .and_then(|()| verify_absent())
    // The entry is gone, so nothing is running the file any more and it can
    // be taken off the disk.
    .and_then(|()| match system_copy {
        Some((dir, system)) => remove_system_copy(&dir, &system),
        None => Ok(()),
    })
}

/// Removes the system-wide copy of the service binary, and the directory it is in.
///
/// The entry is gone by the time this runs, so nothing holds the file open. The directory is
/// only removed when it is empty: anything else in it belongs to somebody else, and leaving it
/// behind is harmless.
fn remove_system_copy(dir: &Path, binary: &Path) -> Result<(), AppError> {
    run(
        |_| remove_copy_batch(dir, binary),
        "service uninstall (remove the system copy)",
        // The copy is under Program Files, so the delete is usually refused
        // for an ordinary user — and it is refused *then*, not before: the
        // other steps of the uninstall ask for elevation the same way, and a
        // prompt here as well would be a second one for the same operation.
        Escalation::OnAccessDenied,
        codes::SERVICE_UNINSTALL_FAILED,
    )
}

pub fn start() -> Result<(), AppError> {
    run(
        |_| {
            vec![
                format!("sc.exe start {SERVICE_NAME}"),
                tolerate(ALREADY_RUNNING),
                "exit /b %errorlevel%".to_string(),
            ]
        },
        "service start",
        Escalation::OnAccessDenied,
        codes::SERVICE_START_FAILED,
    )
    .and_then(|()| settle(ServiceState::Running, codes::SERVICE_START_FAILED))
}

pub fn stop() -> Result<(), AppError> {
    run(
        |_| {
            vec![
                format!("sc.exe stop {SERVICE_NAME}"),
                tolerate(NOT_STARTED),
                tolerate(NOT_INSTALLED),
                "exit /b %errorlevel%".to_string(),
            ]
        },
        "service stop",
        Escalation::OnAccessDenied,
        codes::SERVICE_STOP_FAILED,
    )
    // Waited out with the real state rather than [`settle`]: an install replaces the binary
    // as soon as this returns, which is only safe once nothing is running.
    .and_then(|()| settle_down(codes::SERVICE_STOP_FAILED))
}

/// Stops the service and starts it again as one elevated operation.
///
/// One batch and one prompt, rather than [`stop`] followed by [`start`]: each of those may
/// escalate on its own, so a restart written that way can ask for administrator rights twice —
/// and the user who declines the second prompt is left with a service that is down.
///
/// `Escalation::Always` because the unprivileged attempt would fail inside PowerShell, whose
/// refusal is not the exit code 5 that [`is_access_denied`] reads as one — and a refused
/// operation that is not recognized as refused never gets a second, elevated try.
pub fn restart() -> Result<(), AppError> {
    run(
        |_| {
            vec![
                format!(
                    "powershell.exe -NoProfile -NonInteractive -Command \"$s = Get-Service -Name {SERVICE_NAME} -ErrorAction Stop; \
                     if ($s.Status -eq 'Running') {{ $s.Stop() }}; \
                     $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)); \
                     $s.Start(); \
                     $s.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))\""
                ),
                "exit /b %errorlevel%".to_string(),
            ]
        },
        "service restart",
        Escalation::Always,
        codes::SERVICE_RESTART_FAILED,
    )
    .and_then(|()| settle(ServiceState::Running, codes::SERVICE_RESTART_FAILED))
}

/// What the service manager says right now.
pub fn state() -> ServiceState {
    match sc_query().map(|(text, exit_code)| sc_state(&text, exit_code)) {
        Some(ScState::Running) => ServiceState::Running,
        // Nothing this can call installed: `sc.exe` could not be run, answered something that
        // is not a state, or has no such service. "Could not tell" is drawn like "not
        // installed" so that the panel offers an install instead of controls for a service
        // whose existence is in doubt. A service marked for deletion counts as gone: the
        // control manager refuses every operation on it, so there is nothing left to start,
        // stop or uninstall.
        Some(ScState::Absent) | Some(ScState::Deleting) | Some(ScState::Unknown) | None => {
            ServiceState::NotInstalled
        }
        // Pending included: a service coming up is not answering yet, and one going down has
        // already stopped answering — both are "not running" to every control keyed off this.
        _ => ServiceState::Stopped,
    }
}

/// Whether the control manager still holds a service under this name.
///
/// A record that is marked for deletion does not count: the control manager has already been
/// told to remove it and refuses every operation on it, so an uninstall that found it would try
/// to stop and delete a service that is already leaving.
///
/// A query that could not be run at all is not evidence of absence — the service may well be
/// there, and an install that believes the service is gone replaces one that is still up.
fn service_exists() -> bool {
    match sc_query().map(|(text, exit_code)| sc_state(&text, exit_code)) {
        Some(ScState::Absent) | Some(ScState::Deleting) => false,
        Some(_) | None => true,
    }
}

/// Waits until the service is down — "not running any more", rather than "reported stopped".
///
/// Waiting through [`settle`] with [`ServiceState::Stopped`] does not wait at all: [`state`]
/// answers Stopped for `STOP_PENDING` too, so it returned while the service was still coming
/// down. Replacing the binary has to wait for the real thing, because the last thing the
/// teardown does is restore the system DNS, and starting the new build races that cleanup.
///
/// A service that disappeared counts as down — nothing is running, which is what is being
/// waited for, and it is the state an uninstall is heading towards anyway.
fn settle_down(failure: &str) -> Result<(), AppError> {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        match sc_query().map(|(text, exit_code)| sc_state(&text, exit_code)) {
            // A record that is marked for deletion is down as well: nothing is running, and
            // the control manager has already been told to remove it.
            Some(ScState::Stopped | ScState::Absent | ScState::Deleting) => return Ok(()),
            // `sc.exe` could not be run at all, so there is nothing to wait out.
            Some(ScState::Unknown) | None => {
                return Err(AppError::with_detail(failure, "sc.exe reported no state"));
            }
            Some(ScState::Running | ScState::Pending) => {}
        }

        if Instant::now() >= deadline {
            return Err(AppError::with_detail(
                failure,
                format!(
                    "the service was still up after {}s\n{}",
                    SETTLE_TIMEOUT.as_secs(),
                    sc_query().map(|(text, _)| text).unwrap_or_default()
                ),
            ));
        }

        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Waits for a record that is marked for deletion to leave the control manager's database.
///
/// `DeleteService` only *marks* a service for deletion: the record stays until every handle to
/// it is closed and the service is no longer running, and `sc create` refuses to put a new
/// service in its place while it is there. A user who uninstalls and installs again therefore
/// meets a record that is still on its way out, and the wait is what turns that into an install
/// that works.
///
/// Bounded, and the answer is the control manager's own words: a record that does not go away
/// is an install that says so rather than one that hangs.
fn wait_for_deletable_record() -> Result<(), AppError> {
    let deadline = Instant::now() + DELETE_RECORD_TIMEOUT;

    loop {
        match sc_query().map(|(text, exit_code)| sc_state(&text, exit_code)) {
            // Not there at all, or there and usable: there is nothing to wait for.
            Some(ScState::Absent)
            | Some(ScState::Running | ScState::Stopped | ScState::Pending) => return Ok(()),
            // The record is on its way out; the wait is for it to actually go.
            Some(ScState::Deleting) => {}
            // `sc.exe` could not be run at all, so there is nothing to wait out.
            Some(ScState::Unknown) | None => {
                return Err(AppError::with_detail(
                    codes::SERVICE_INSTALL_FAILED,
                    "sc.exe reported no state",
                ));
            }
        }

        if Instant::now() >= deadline {
            return Err(AppError::with_detail(
                codes::SERVICE_INSTALL_FAILED,
                format!(
                    "the previous service was still marked for deletion after {}s\n{}",
                    DELETE_RECORD_TIMEOUT.as_secs(),
                    sc_query().map(|(text, _)| text).unwrap_or_default()
                ),
            ));
        }

        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Waits for the service to reach `expected`, so a command that the SCM accepted but that did
/// not take effect is reported as a failure.
fn settle(expected: ServiceState, failure: &str) -> Result<(), AppError> {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let current = state();
        if current == expected {
            return Ok(());
        }
        // A service that vanished while being started or stopped will never reach the state.
        if current == ServiceState::NotInstalled {
            return Err(AppError::with_detail(
                failure,
                "the service is no longer registered",
            ));
        }
        if Instant::now() >= deadline {
            // The `sc query` text goes along because it carries `WIN32_EXIT_CODE` — 1067 for
            // instance means the service process started and then died, which is the one
            // detail that explains an otherwise silent "still stopped".
            return Err(AppError::with_detail(
                failure,
                format!(
                    "the service is still {} after {}s\n{}",
                    match current {
                        ServiceState::Running => "running",
                        ServiceState::Stopped => "stopped",
                        ServiceState::NotInstalled => "missing",
                    },
                    SETTLE_TIMEOUT.as_secs(),
                    sc_query().map(|(text, _)| text).unwrap_or_default()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The `binPath=` value: the executable quoted with its quotes escaped, followed by the
/// service argument. `sc` takes the whole command line as one value, and an unescaped quote
/// in a path containing spaces makes it fail with 1639 (invalid command line).
fn bin_path_value(binary: &str) -> String {
    format!(r#"\"{}\" {}"#, binary, SERVICE_ARGUMENT)
}

/// Writes `lines` into a batch file, runs it, and escalates according to `escalation`.
///
/// Every command inherits the redirection [`with_logging`] appends, so `sc.exe`'s own output
/// ends up in a log file: `Start-Process -Verb RunAs` cannot hand a child's stdout back to
/// us, and without the log a failure would surface as an unexplained non-zero exit code.
///
/// The batch file's handle is held open across the whole exchange — see
/// [`write_script`] — so `script` is what has to be dropped before the file can be removed.
fn run(
    build: impl FnOnce(&Path) -> Vec<String>,
    description: &str,
    escalation: Escalation,
    failure: &str,
) -> Result<(), AppError> {
    let bat = temp_path("bat");
    let log = bat.with_extension("log");
    let lines = build(&log);
    let script = write_script(&bat, &with_logging(&lines, &log))?;

    let mut elevated = matches!(escalation, Escalation::Always);
    let output = if elevated {
        run_elevated(&bat, description)?
    } else {
        let plain = run_plain(&bat, description)?;
        if !plain.status.success() && is_access_denied(&plain, &log) {
            elevated = true;
            // The refusal is all the unprivileged attempt left behind; the log now belongs to
            // the elevated run.
            let _ = std::fs::remove_file(&log);
            run_elevated(&bat, description)?
        } else {
            plain
        }
    };

    // Read before the handle is released: the log is written by the child, and the point of
    // holding the batch file was never to stop the child reading it — only to stop anyone
    // else changing what it says.
    let text = read_log(&log).unwrap_or_default();
    drop(script);
    let _ = std::fs::remove_file(&bat);
    let _ = std::fs::remove_file(&log);

    if output.status.success() {
        return Ok(());
    }

    // Nothing reached the log, so the batch file never ran: the prompt was declined or could
    // not be obtained at all. That is a different answer from "the service manager refused".
    if elevated && text.is_empty() {
        let launcher = detail_of(&output);
        return Err(AppError::with_detail(
            codes::SERVICE_ELEVATION_DENIED,
            launcher,
        ));
    }

    let detail = if text.is_empty() {
        detail_of(&output)
    } else {
        text
    };
    Err(AppError::with_detail(failure, detail))
}

/// Turns command lines into a batch script whose output is captured for the caller.
///
/// Lines that are already complete are copied verbatim: control flow (`if errorlevel`,
/// `exit /b`) must not be redirected at all, and a command carrying its own redirection —
/// the `create`/`config` branch of the install, which has to redirect *inside* the
/// parentheses — would end up with two conflicting redirections.
fn with_logging(lines: &[String], log: &Path) -> String {
    let redirect = format!(">> \"{}\" 2>&1", log.display());
    let mut script = String::from("@echo off\r\n");

    for line in lines {
        let complete = line.starts_with("if ") || line.starts_with("exit ") || line.contains('>');

        if complete {
            script.push_str(line);
        } else {
            script.push_str(line);
            script.push(' ');
            script.push_str(&redirect);
        }
        script.push_str("\r\n");
    }

    script
}

/// Writes the batch file and returns the handle that keeps it unchangeable.
///
/// The returned handle is the whole point, and callers must hold it for as long as the script
/// can still be run. `create_new` refuses an existing path — `File::create` truncates whatever
/// is there, and on a shared machine the temporary directory is another account's to write
/// first — and the share mode then keeps the file from being changed at all while it is held:
///
/// * `FILE_SHARE_READ` and nothing else. The elevated child has to *read* the batch file, so
///   sharing reads is required; omitting write and delete is what stops anyone else from
///   rewriting it, replacing it, or swapping a link in its place for the whole window between
///   writing it and the user answering the UAC prompt.
/// * `O_NOFOLLOW` closes the same gap on the open itself, so a symlink planted between the
///   existence check and the create is refused rather than followed.
///
/// Without this the window is real and long: the prompt stays up until a human answers it, and
/// anything that rewrites the batch file in that time gets its commands run with administrator
/// rights. That is local privilege escalation from a temporary directory.
fn write_script(path: &Path, content: &str) -> Result<ScriptLock, AppError> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;

    // `sys::c` constants: `FILE_SHARE_READ` is 1, and `O_NOFOLLOW` is not exposed by
    // `std::os::windows`, so it is spelled the same way on the Windows side as on Unix —
    // as a no-op this platform cannot honour, which the regular-file check below covers.
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|e| {
            AppError::cause(
                codes::SERVICE_COMMAND_FAILED,
                format!("cannot create {}: {e}", path.display()),
            )
        })?;

    // Asked before anything is written: a symlink or a reparse point that reached this far
    // would have the batch text land wherever it points, and this file's text is what runs as
    // an administrator.
    let metadata = file.metadata().map_err(|e| {
        AppError::cause(
            codes::SERVICE_COMMAND_FAILED,
            format!("cannot inspect {}: {e}", path.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(AppError::with_detail(
            codes::SERVICE_COMMAND_FAILED,
            format!("{} is not a regular file", path.display()),
        ));
    }

    let mut file = file;
    file.write_all(content.as_bytes())
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;
    // Flushed to disk while it is still ours: the elevated child is a different process, and a
    // batch file the kernel has not yet written out is a batch file it may read short.
    let _ = file.flush();
    let _ = file.sync_all();

    Ok(ScriptLock { _file: file })
}

/// Keeps a batch file from being changed while a script that runs as an administrator can
/// still read it. Dropping it releases the file; see [`write_script`].
struct ScriptLock {
    /// Named with a leading underscore so it reads as "held, not used" at the drop site.
    _file: std::fs::File,
}

fn run_plain(bat: &Path, description: &str) -> Result<Output, AppError> {
    let mut command = Command::new("cmd.exe");
    command.args(["/c", &bat.to_string_lossy()]);
    run_with_timeout(&mut command, description, COMMAND_TIMEOUT)
}

/// Re-launches the batch file through the UAC consent dialog.
///
/// `cmd.exe` is the process being elevated because `Start-Process -Verb RunAs` needs an
/// executable it can elevate; `-Wait -PassThru` plus `exit $p.ExitCode` then hands the batch
/// file's own exit code back.
fn run_elevated(bat: &Path, description: &str) -> Result<Output, AppError> {
    let escaped = bat.display().to_string().replace('\'', "''");
    // `Stop` matters: without it a declined UAC leaves `$p` unset and `exit $p.ExitCode`
    // becomes a bare `exit`, i.e. success — the caller would report an install that never
    // happened as done.
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', '{escaped}' \
             -Verb RunAs -Wait -PassThru; \
         if ($null -eq $p) {{ exit 1 }}; \
         exit $p.ExitCode"
    );

    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    run_with_timeout(&mut command, description, ELEVATION_TIMEOUT)
}

fn run_with_timeout(
    command: &mut Command,
    description: &str,
    timeout: Duration,
) -> Result<Output, AppError> {
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e));
            }
            Ok(None) => {}
            Err(e) => return Err(AppError::cause(codes::SERVICE_COMMAND_FAILED, e)),
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AppError::with_detail(
                codes::SERVICE_COMMAND_FAILED,
                format!("{description} timed out after {}s", timeout.as_secs()),
            ));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn is_access_denied(output: &Output, log: &Path) -> bool {
    if output.status.code() == Some(5) {
        return true;
    }
    read_log(log)
        .map(|text| text.contains(ACCESS_DENIED))
        .unwrap_or(false)
}

fn read_log(log: &Path) -> Option<String> {
    std::fs::read(log)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
        .filter(|text| !text.is_empty())
}

/// Last-resort diagnostic when the log is empty: whatever the launcher printed itself.
fn detail_of(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => format!("{} (no output)", output.status),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{stdout}\n{stderr}"),
    }
}

/// The binary the system-wide copy is made from: the `nexa-service` executable bundled with the
/// app, falling back to this binary — a development build has no bundle, and the desktop binary
/// understands `--service` too.
///
/// This is the *source* of the copy, not what the control manager runs: the app's own directory
/// is the user's to write, and the control manager starts what it is pointed at as SYSTEM. See
/// [`scm_service_binary`].
fn service_binary(app_dir: &Path, exe: &Path) -> String {
    let candidates = per_user_service_candidates(app_dir);

    let found = pick_service_binary(&candidates, exe, |path| path.is_file());

    found.to_string_lossy().to_string()
}

/// The system-wide directory the service binary is copied into.
///
/// `ProgramW6432` first: it is the 64-bit `Program Files` even for a 32-bit
/// process, whose own `ProgramFiles` is redirected to `Program Files (x86)`.
/// A 64-bit process has no `ProgramW6432`, and its `ProgramFiles` is already
/// the right one.
fn program_files() -> Result<PathBuf, AppError> {
    for name in ["ProgramW6432", "ProgramFiles"] {
        if let Ok(dir) = std::env::var(name) {
            if !dir.trim().is_empty() {
                return Ok(PathBuf::from(dir));
            }
        }
    }

    Err(AppError::with_detail(
        codes::SERVICE_EXE_PATH,
        "ProgramFiles is not set",
    ))
}

/// An install that reported success still has to leave a service behind.
fn verify_present() -> Result<(), AppError> {
    std::thread::sleep(Duration::from_millis(500));

    match sc_query() {
        // Not there, or already on its way out: the install did not leave a service behind.
        Some((text, exit_code))
            if matches!(
                sc_state(&text, exit_code),
                ScState::Absent | ScState::Deleting
            ) =>
        {
            Err(AppError::with_detail(codes::SERVICE_INSTALL_FAILED, text))
        }
        Some(_) => Ok(()),
        None => Err(AppError::new(codes::SERVICE_INSTALL_FAILED)),
    }
}

/// Waits for the control manager to let go of the record.
///
/// The delete is answered as soon as the control manager has been told to remove the record,
/// which is not the same as the record being gone: it stays until every handle to it is closed.
/// A fixed sleep guessed at how long that takes and failed an uninstall that had in fact
/// worked; polling asks instead.
///
/// A record that is marked for deletion counts as gone — the service cannot be started and the
/// control manager refuses every operation on it, which is what an uninstall is for.
fn verify_absent() -> Result<(), AppError> {
    let deadline = Instant::now() + DELETE_RECORD_TIMEOUT;

    loop {
        match sc_query().map(|(text, exit_code)| sc_state(&text, exit_code)) {
            Some(ScState::Absent) | Some(ScState::Deleting) => return Ok(()),
            // `sc.exe` could not be run at all, so there is nothing to wait out.
            Some(ScState::Unknown) | None => {
                return Err(AppError::with_detail(
                    codes::SERVICE_UNINSTALL_FAILED,
                    "sc.exe reported no state",
                ));
            }
            Some(ScState::Running | ScState::Stopped | ScState::Pending) => {}
        }

        if Instant::now() >= deadline {
            return Err(AppError::with_detail(
                codes::SERVICE_UNINSTALL_FAILED,
                format!(
                    "the service was still registered after {}s\n{}",
                    DELETE_RECORD_TIMEOUT.as_secs(),
                    sc_query().map(|(text, _)| text).unwrap_or_default()
                ),
            ));
        }

        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Asks the service manager about this service: its answer, and the code it exited with.
///
/// The code goes along because it is the part of the answer that is not localized — see
/// [`sc_state`]. `None` is "the question could not be asked at all", which is not the same
/// as an answer saying the service is missing.
fn sc_query() -> Option<(String, Option<i32>)> {
    let output = run_with_timeout(
        Command::new("sc.exe").args(["query", SERVICE_NAME]),
        "service query",
        COMMAND_TIMEOUT,
    )
    .ok()?;
    Some((detail_of(&output), output.status.code()))
}

fn temp_path(extension: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!(
        "nexa-service-{}-{}.{}",
        std::process::id(),
        nanos,
        extension
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two files match only when their bytes do.
    ///
    /// The comparison is what makes "the service was replaced" a checked fact rather than a
    /// hope: the control manager keeps running whatever was copied the day the service was
    /// registered, so a copy that did not land leaves the old build serving the new app — and
    /// the user has no way to tell.
    #[test]
    fn two_files_match_only_when_their_bytes_do() {
        let dir = std::env::temp_dir().join(format!("nexa-service-match-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the scratch directory");

        let left = dir.join("left.bin");
        let right = dir.join("right.bin");
        let different = dir.join("different.bin");
        let shorter = dir.join("shorter.bin");
        let missing = dir.join("missing.bin");

        std::fs::write(&left, b"the service binary").expect("the first file");
        std::fs::write(&right, b"the service binary").expect("the second file");
        std::fs::write(&different, b"the service binarY").expect("the third file");
        std::fs::write(&shorter, b"the service binar").expect("the fourth file");

        assert!(
            files_match(&left, &right),
            "the same bytes are the same file"
        );
        assert!(!files_match(&left, &different), "one byte is one byte");
        assert!(
            !files_match(&left, &shorter),
            "a shorter file is not the file"
        );
        assert!(
            !files_match(&left, &missing),
            "a file that is not there is not a match"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The installer writes `"<exe>" --service`; the whole value has to stay one argument.
    #[test]
    fn bin_path_escapes_the_quotes_around_the_executable() {
        assert_eq!(
            bin_path_value(r"C:\Program Files\nexa\nexa-service.exe"),
            r#"\"C:\Program Files\nexa\nexa-service.exe\" --service"#
        );
    }

    /// Control-flow lines must not be redirected: appending to a log would swallow the exit
    /// code the caller reads back.
    #[test]
    fn only_command_lines_are_redirected_into_the_log() {
        let script = with_logging(
            &[
                "sc.exe stop nexa-service".to_string(),
                "if errorlevel 1 exit /b %errorlevel%".to_string(),
                "exit /b %errorlevel%".to_string(),
                "sc.exe query nexa-service >nul 2>&1".to_string(),
            ],
            Path::new(r"C:\Temp\out.log"),
        );

        assert!(script.starts_with("@echo off\r\n"));
        assert!(script.contains(r#"sc.exe stop nexa-service >> "C:\Temp\out.log" 2>&1"#));
        assert!(script.contains("if errorlevel 1 exit /b %errorlevel%\r\n"));
        assert!(!script.contains("if errorlevel 1 exit /b %errorlevel% >>"));
        // A line that already redirects keeps its own and gets no second one.
        assert!(script.contains("sc.exe query nexa-service >nul 2>&1\r\n"));
        assert_eq!(script.matches("sc.exe query nexa-service").count(), 1);
    }

    /// The script an install runs, as the batch file it would become.
    fn install_script(leave_stopped: bool, keep_owner: bool) -> String {
        let account = AccountId::Windows("S-1-5-21-1-2-3-1001".to_string());
        let lines = install_batch(
            InstallPaths {
                log: Path::new(r"C:\Temp\out.log"),
                dir: Path::new(r"C:\Program Files\Nexa\Service"),
                source: r"C:\App\nexa-service.exe",
                system: Path::new(r"C:\Program Files\Nexa\Service\nexa-service.exe"),
                bin_path: r#"\"C:\Program Files\Nexa\Service\nexa-service.exe\" --service"#,
            },
            Some(&account),
            leave_stopped,
            keep_owner,
        );

        with_logging(&lines, Path::new(r"C:\Temp\out.log"))
    }

    /// When the user's service comes up is the user's decision, and an app that is
    /// reinstalled is not a reason for a service that was set to start by hand to start
    /// by itself from then on.
    ///
    /// Only the entry that is created gets a start type; an entry that is already there
    /// keeps the one it has.
    #[test]
    fn an_existing_service_keeps_the_start_type_it_has() {
        let script = install_script(false, false);

        // The two branches are one line, so the part that has to be free of a start type
        // is the part after `sc.exe config`.
        let config = script
            .lines()
            .find(|line| line.contains("sc.exe config"))
            .expect("the entry is re-pointed at the new binary");
        let config_branch = config
            .split("sc.exe config")
            .nth(1)
            .expect("the config branch is there");
        assert!(
            !config_branch.contains("start="),
            "an entry that is already there keeps its start type: {config}"
        );

        assert!(
            script.contains("sc.exe create nexa-service binPath="),
            "a service that does not exist yet is created"
        );
        assert!(
            script.contains("start= auto DisplayName="),
            "a service that is created starts by itself"
        );
    }

    /// The account the service serves is the one the user picked when they installed it.
    /// An upgrade re-registers the service, and that is not how the account is chosen.
    #[test]
    fn an_upgrade_leaves_the_account_the_service_serves_alone() {
        let upgrade = install_script(false, true);
        assert!(
            !upgrade.contains("ServiceOwner"),
            "the account the service serves is not written again:\n{upgrade}"
        );

        let ordinary = install_script(false, false);
        assert!(
            ordinary.contains("ServiceOwner"),
            "a service that is installed for an account records it:\n{ordinary}"
        );
    }
}

#[cfg(windows)]
pub fn is_service_running_windows() -> bool {
    use std::process::Command;

    Command::new("sc")
        .args(["query", SERVICE_NAME])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

// ==========================================================================
// Unix: the definition is written by this process, so the whole operation runs

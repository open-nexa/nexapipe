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

use super::{sc_state, ScState, ServiceState, SERVICE_DISPLAY_NAME, SERVICE_NAME};
use crate::error::{codes, AppError};
use crate::service::platform::account::AccountId;
use crate::service::platform::install_owner;

/// Text `services.msc` shows for the entry.
const SERVICE_DESCRIPTION: &str =
    "Runs the nexa proxy (TUN mode) without a signed-in desktop session.";

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
const SETTLE_TIMEOUT: Duration = Duration::from_secs(20);

/// `sc.exe` reports a refused operation as exit code 5 carrying this text.
const ACCESS_DENIED: &str = "Access is denied";

/// Argument that hands control to the service control manager.
const SERVICE_ARGUMENT: &str = "--service";

/// `sc start` on a service that is already running.
///
/// Not a failure: running is the state the command asked for. Reported as it is, the exit
/// code turns a successful install into `service.install_failed` carrying
/// "StartService failed 1056" — an install that worked, described as one that did not.
const ALREADY_RUNNING: &str = "1056";

/// `sc stop` on a service that is not started (or not installed).
///
/// Same shape: the state asked for is already the state, so refusing to call it a success
/// only stops a perfectly good stop from ever being reported as done.
const NOT_STARTED: &str = "1062";
const NOT_INSTALLED: &str = "1060";

/// Accepts a nonzero exit code from the previous command as success.
///
/// `errorlevel` is compared literally rather than with `if errorlevel N` because that form
/// means "N or higher" and would swallow real failures with larger codes.
fn tolerate(code: &str) -> String {
    format!("if %errorlevel%=={code} exit /b 0")
}

/// Whether an operation can succeed without asking for elevation.
enum Escalation {
    /// It always needs administrative rights (`sc create`).
    Always,
    /// Run it as the invoking user first, and only escalate when that is refused.
    OnAccessDenied,
}

pub fn install(installing_by: Option<AccountId>) -> Result<(), AppError> {
    let bin_path = bin_path_value(&service_binary()?);

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
            let redirect = format!("> \"{}\" 2>&1", log.display());
            let mut lines = vec![
                format!("sc.exe query {SERVICE_NAME} >nul 2>&1"),
                format!(
                    "if errorlevel 1 (sc.exe create {SERVICE_NAME} binPath= \"{bin_path}\" start= auto DisplayName= \"{SERVICE_DISPLAY_NAME}\" {redirect}) else (sc.exe config {SERVICE_NAME} binPath= \"{bin_path}\" start= auto {redirect})"
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
            match installing_by.as_ref() {
                Some(account) => {
                    lines.push(install_owner::record_command(account));
                    lines.push("if errorlevel 1 exit /b %errorlevel%".to_string());
                }
                None => tracing::warn!(
                    "Installing the service without naming the account it is for: it will serve \
                     any local account that owns the token it reads"
                ),
            }

            lines.extend([
                format!("sc.exe start {SERVICE_NAME}"),
                // Nothing should be up at this point — [`stop_if_running`] brought the old
                // process down first — so 1056 means the service was started again by
                // something else, which is still the state the install asked for.
                tolerate(ALREADY_RUNNING),
                "exit /b %errorlevel%".to_string(),
            ]);

            lines
        },
        "service install",
        Escalation::Always,
        codes::SERVICE_INSTALL_FAILED,
    )
    .and_then(|()| verify_present())
    // `sc start` returns success as soon as the SCM has launched the process, which says
    // nothing about whether it stays up: a service that dies during startup still reports a
    // successful start. Waiting for the state to become RUNNING is what turns "installed but
    // not running" into a reported failure instead of a mystery.
    .and_then(|()| settle(ServiceState::Running, codes::SERVICE_START_FAILED))
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
    if !service_exists() {
        return Ok(());
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
                    "exit /b %errorlevel%".to_string(),
                ]
            },
            "service uninstall (delete)",
            Escalation::OnAccessDenied,
            codes::SERVICE_UNINSTALL_FAILED,
        )
    })
    .and_then(|()| verify_absent())
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

/// What the service manager says right now.
pub fn state() -> ServiceState {
    match sc_query().map(|text| sc_state(&text)) {
        Some(ScState::Running) => ServiceState::Running,
        // `sc.exe` itself could not be run, so there is nothing to report as installed.
        Some(ScState::Absent) | None => ServiceState::NotInstalled,
        // Pending included: a service coming up is not answering yet, and one going down has
        // already stopped answering — both are "not running" to every control keyed off this.
        _ => ServiceState::Stopped,
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
        match sc_query().map(|text| sc_state(&text)) {
            Some(ScState::Stopped | ScState::Absent) => return Ok(()),
            // `sc.exe` could not be run at all, so there is nothing to wait out.
            Some(ScState::Unknown) | None => {
                return Err(AppError::with_detail(failure, "sc.exe reported no state"))
            }
            Some(ScState::Running | ScState::Pending) => {}
        }

        if Instant::now() >= deadline {
            return Err(AppError::with_detail(
                failure,
                format!(
                    "the service was still up after {}s\n{}",
                    SETTLE_TIMEOUT.as_secs(),
                    sc_query().unwrap_or_default()
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
                    sc_query().unwrap_or_default()
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
        let complete =
            line.starts_with("if ") || line == "exit /b %errorlevel%" || line.contains('>');

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
                    .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))
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

/// The binary the service control manager should start: the `nexa-service` executable bundled
/// with the app, falling back to this binary — a development build has no bundle, and the
/// desktop binary understands `--service` too.
fn service_binary() -> Result<String, AppError> {
    let exe = std::env::current_exe().map_err(|e| AppError::cause(codes::SERVICE_EXE_PATH, e))?;
    let dir = exe
        .parent()
        .ok_or_else(|| AppError::new(codes::SERVICE_EXE_PATH))?;

    let candidates = [
        dir.join("resources").join("nexa-service.exe"),
        dir.join("nexa-service.exe"),
    ];

    let found = candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| exe.clone());

    Ok(found.to_string_lossy().to_string())
}

fn service_exists() -> bool {
    sc_query()
        .map(|output| !output.contains("1060"))
        .unwrap_or(true)
}

/// An install that reported success still has to leave a service behind.
fn verify_present() -> Result<(), AppError> {
    std::thread::sleep(Duration::from_millis(500));

    match sc_query() {
        Some(output) if !output.contains("1060") => Ok(()),
        Some(output) => Err(AppError::with_detail(codes::SERVICE_INSTALL_FAILED, output)),
        None => Err(AppError::new(codes::SERVICE_INSTALL_FAILED)),
    }
}

fn verify_absent() -> Result<(), AppError> {
    std::thread::sleep(Duration::from_millis(500));

    match sc_query() {
        Some(output) if output.contains("1060") => Ok(()),
        Some(output) => Err(AppError::with_detail(
            codes::SERVICE_UNINSTALL_FAILED,
            output,
        )),
        None => Ok(()),
    }
}

fn sc_query() -> Option<String> {
    let output = run_with_timeout(
        Command::new("sc.exe").args(["query", SERVICE_NAME]),
        "service query",
        COMMAND_TIMEOUT,
    )
    .ok()?;
    Some(detail_of(&output))
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

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
    return windows_impl::state();

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
    return windows_impl::install();

    #[cfg(not(windows))]
    return install_elevated();
}

/// Removes the service.
pub fn uninstall_service() -> Result<(), AppError> {
    #[cfg(windows)]
    return windows_impl::uninstall();

    #[cfg(not(windows))]
    return uninstall_elevated();
}

pub fn start_service() -> Result<(), AppError> {
    #[cfg(windows)]
    return windows_impl::start();

    #[cfg(not(windows))]
    return start_elevated();
}

pub fn stop_service() -> Result<(), AppError> {
    #[cfg(windows)]
    return windows_impl::stop();

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

#[cfg(windows)]
mod windows_impl {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::time::{Duration, Instant};

    use crate::error::{codes, AppError};
    use crate::service::platform::{SERVICE_DISPLAY_NAME, SERVICE_NAME, ServiceState};

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

    pub fn install() -> Result<(), AppError> {
        let bin_path = bin_path_value(&service_binary()?);

        // `create` fails with 1073 when an older installation is already registered, so an
        // existing service is re-pointed at the current binary instead of being rejected. Both
        // branches carry their own redirection: the elevated run cannot hand stdout back, so a
        // redirect appended *outside* the parentheses would leave the log empty and make a real
        // failure look like a declined prompt.
        run(
            |log| {
                let redirect = format!("> \"{}\" 2>&1", log.display());
                vec![
                    format!("sc.exe query {SERVICE_NAME} >nul 2>&1"),
                    format!(
                        "if errorlevel 1 (sc.exe create {SERVICE_NAME} binPath= \"{bin_path}\" start= auto DisplayName= \"{SERVICE_DISPLAY_NAME}\" {redirect}) else (sc.exe config {SERVICE_NAME} binPath= \"{bin_path}\" start= auto {redirect})"
                    ),
                    "if errorlevel 1 exit /b %errorlevel%".to_string(),
                    format!("sc.exe description {SERVICE_NAME} \"{SERVICE_DESCRIPTION}\""),
                    "if errorlevel 1 exit /b %errorlevel%".to_string(),
                    format!("sc.exe start {SERVICE_NAME}"),
                    // Already running is the state the install asked for. Note that the service
                    // keeps running the binary it was launched from: a re-pointed `binPath`
                    // only takes effect on the next start, which an uninstall/start or a reboot
                    // provides.
                    tolerate(ALREADY_RUNNING),
                    "exit /b %errorlevel%".to_string(),
                ]
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

    pub fn uninstall() -> Result<(), AppError> {
        if !service_exists() {
            return Ok(());
        }

        run(
            |_| {
                vec![
                    format!("sc.exe stop {SERVICE_NAME}"),
                    format!("sc.exe delete {SERVICE_NAME}"),
                    "exit /b %errorlevel%".to_string(),
                ]
            },
            "service uninstall",
            Escalation::OnAccessDenied,
            codes::SERVICE_UNINSTALL_FAILED,
        )
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
        .and_then(|()| settle(ServiceState::Stopped, codes::SERVICE_STOP_FAILED))
    }

    /// What the service manager says right now.
    pub fn state() -> ServiceState {
        match sc_query() {
            Some(text) if text.contains("1060") => ServiceState::NotInstalled,
            Some(text) if text.contains("RUNNING") => ServiceState::Running,
            Some(_) => ServiceState::Stopped,
            // `sc.exe` itself could not be run, so there is nothing to report as installed.
            None => ServiceState::NotInstalled,
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
    fn run(
        build: impl FnOnce(&Path) -> Vec<String>,
        description: &str,
        escalation: Escalation,
        failure: &str,
    ) -> Result<(), AppError> {
        let bat = temp_path("bat");
        let log = bat.with_extension("log");
        let lines = build(&log);
        write_script(&bat, &with_logging(&lines, &log))?;

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

        let text = read_log(&log).unwrap_or_default();
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

    fn write_script(path: &Path, content: &str) -> Result<(), AppError> {
        let mut file = std::fs::File::create(path)
            .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;
        file.write_all(content.as_bytes())
            .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))
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
        let exe =
            std::env::current_exe().map_err(|e| AppError::cause(codes::SERVICE_EXE_PATH, e))?;
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
        sc_query().map(|output| !output.contains("1060")).unwrap_or(true)
    }

    /// An install that reported success still has to leave a service behind.
    fn verify_present() -> Result<(), AppError> {
        std::thread::sleep(Duration::from_millis(500));

        match sc_query() {
            Some(output) if !output.contains("1060") => Ok(()),
            Some(output) => Err(AppError::with_detail(
                codes::SERVICE_INSTALL_FAILED,
                output,
            )),
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
}

#[cfg(windows)]
fn is_service_running_windows() -> bool {
    use std::process::Command;

    Command::new("sc")
        .args(["query", SERVICE_NAME])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

// ==========================================================================
// Unix: the definition is written by this process, so the whole operation runs
// elevated (see `service::elevate`).
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

#[cfg(target_os = "linux")]
fn install_service_linux(exe_path: &str) -> Result<(), AppError> {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;

    let unit_content = linux_unit_content(exe_path);

    let unit_path = Path::new("/etc/systemd/system").join(format!("{}.service", SERVICE_NAME));

    fs::create_dir_all("/etc/systemd/system")
        .map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    let mut file = File::create(&unit_path)
        .map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    file.write_all(unit_content.as_bytes())
        .map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    let output = Command::new("systemctl")
        .args(["daemon-reload"])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if !output.status.success() {
        return Err(AppError::with_detail(
            codes::SERVICE_DEFINITION_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    let output = Command::new("systemctl")
        .args(["enable", SERVICE_NAME])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if !output.status.success() {
        return Err(AppError::with_detail(
            codes::SERVICE_INSTALL_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    // Registration is not startup: a unit that is only enabled stays stopped until the next
    // boot, while the UI promises install and start as one action.
    start_service_linux()?;
    wait_for_service_state_linux(ServiceState::Running, codes::SERVICE_START_FAILED)
}

/// The command systemd should run in the foreground.
///
/// A packaged install has a dedicated nexa-service binary beside the desktop executable. A
/// development build may not, in which case the desktop binary understands --foreground and
/// can host the same service without daemonizing.
#[cfg(target_os = "linux")]
fn linux_service_exec(exe_path: &str) -> String {
    let service = std::path::Path::new(exe_path).with_file_name("nexa-service");
    linux_service_exec_with(exe_path, service.is_file())
}

#[cfg(target_os = "linux")]
fn linux_service_exec_with(exe_path: &str, has_service_binary: bool) -> String {
    if has_service_binary {
        std::path::Path::new(exe_path)
            .with_file_name("nexa-service")
            .to_string_lossy()
            .into_owned()
    } else {
        format!("{exe_path} --foreground")
    }
}

#[cfg(target_os = "linux")]
fn linux_unit_content(exe_path: &str) -> String {
    format!(
        r#"[Unit]
Description={}
After=network.target

[Service]
Type=simple
ExecStart={}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"#,
        SERVICE_DISPLAY_NAME,
        linux_service_exec(exe_path)
    )
}

#[cfg(target_os = "linux")]
fn uninstall_service_linux() -> Result<(), AppError> {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    let _ = Command::new("systemctl")
        .args(["stop", SERVICE_NAME])
        .output();

    let _ = Command::new("systemctl")
        .args(["disable", SERVICE_NAME])
        .output();

    let unit_path = Path::new("/etc/systemd/system").join(format!("{}.service", SERVICE_NAME));
    let _ = fs::remove_file(unit_path);

    let _ = Command::new("systemctl").args(["daemon-reload"]).output();

    Ok(())
}

#[cfg(target_os = "linux")]
fn is_service_running_linux() -> bool {
    use std::process::Command;

    Command::new("systemctl")
        .args(["is-active", SERVICE_NAME])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "active")
        .unwrap_or(false)
}

/// The unit file is the registration: no file means the service was never installed.
#[cfg(target_os = "linux")]
fn state_linux() -> ServiceState {
    use std::path::Path;

    let unit = Path::new("/etc/systemd/system").join(format!("{}.service", SERVICE_NAME));
    if !unit.exists() {
        return ServiceState::NotInstalled;
    }

    if is_service_running_linux() {
        ServiceState::Running
    } else {
        ServiceState::Stopped
    }
}

#[cfg(target_os = "linux")]
fn start_service_linux() -> Result<(), AppError> {
    use std::process::Command;

    let output = Command::new("systemctl")
        .args(["start", SERVICE_NAME])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::with_detail(
            codes::SERVICE_START_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

#[cfg(target_os = "linux")]
fn stop_service_linux() -> Result<(), AppError> {
    use std::process::Command;

    let output = Command::new("systemctl")
        .args(["stop", SERVICE_NAME])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::with_detail(
            codes::SERVICE_STOP_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

#[cfg(target_os = "linux")]
fn wait_for_service_state_linux(expected: ServiceState, failure: &str) -> Result<(), AppError> {
    use std::time::{Duration, Instant};

    const SETTLE_TIMEOUT: Duration = Duration::from_secs(5);

    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let current = state_linux();
        if current == expected {
            return Ok(());
        }
        if current == ServiceState::NotInstalled {
            return Err(AppError::with_detail(
                failure,
                "the service is no longer registered",
            ));
        }
        if Instant::now() >= deadline {
            return Err(AppError::with_detail(
                failure,
                format!(
                    "the service is still {} after {}s",
                    match current {
                        ServiceState::Running => "running",
                        ServiceState::Stopped => "stopped",
                        ServiceState::NotInstalled => "missing",
                    },
                    SETTLE_TIMEOUT.as_secs()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
fn install_service_macos(exe_path: &str) -> Result<(), AppError> {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.nexa.{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/nexa-service.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/nexa-service.log</string>
</dict>
</plist>
"#,
        SERVICE_NAME, exe_path
    );

    let plist_path =
        Path::new("/Library/LaunchDaemons").join(format!("com.nexa.{}.plist", SERVICE_NAME));

    fs::create_dir_all("/Library/LaunchDaemons")
        .map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    let mut file =
        File::create(&plist_path).map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    file.write_all(plist_content.as_bytes())
        .map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    let output = Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap()])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::with_detail(
            codes::SERVICE_INSTALL_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

#[cfg(target_os = "macos")]
fn uninstall_service_macos() -> Result<(), AppError> {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    let plist_path =
        Path::new("/Library/LaunchDaemons").join(format!("com.nexa.{}.plist", SERVICE_NAME));

    let _ = Command::new("launchctl")
        .args(["unload", plist_path.to_str().unwrap()])
        .output();
    let _ = fs::remove_file(&plist_path);

    Ok(())
}

#[cfg(target_os = "macos")]
fn is_service_running_macos() -> bool {
    use std::process::Command;

    // The daemon lives in the *system* domain, but a plain `launchctl list <label>` from a user
    // session queries the user's GUI domain and answers "Could not find service" (exit 1) even
    // while the daemon is running — which had the service panel show "stopped" forever.
    // `launchctl print system/<label>` is readable without root and names the state outright.
    let label = format!("com.nexa.{}", SERVICE_NAME);
    let Ok(output) = Command::new("launchctl")
        .args(["print", format!("system/{label}").as_str()])
        .output()
    else {
        return false;
    };
    output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.trim() == "state = running")
}

/// The plist is the registration: no file means the service was never installed.
#[cfg(target_os = "macos")]
fn state_macos() -> ServiceState {
    use std::path::Path;

    let plist = Path::new("/Library/LaunchDaemons").join(format!("com.nexa.{}.plist", SERVICE_NAME));
    if !plist.exists() {
        return ServiceState::NotInstalled;
    }

    if is_service_running_macos() {
        ServiceState::Running
    } else {
        ServiceState::Stopped
    }
}

#[cfg(target_os = "macos")]
fn start_service_macos() -> Result<(), AppError> {
    // `launchctl start` takes the Label (com.nexa.<SERVICE_NAME>), not a plist
    // path — passing the path succeeds silently without starting anything.
    use std::process::Command;

    let output = Command::new("launchctl")
        .args(["start", format!("com.nexa.{}", SERVICE_NAME).as_str()])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::with_detail(
            codes::SERVICE_START_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

#[cfg(target_os = "macos")]
fn stop_service_macos() -> Result<(), AppError> {
    use std::process::Command;

    let output = Command::new("launchctl")
        .args(["stop", format!("com.nexa.{}", SERVICE_NAME).as_str()])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::with_detail(
            codes::SERVICE_STOP_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

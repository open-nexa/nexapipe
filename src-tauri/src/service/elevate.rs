//! Privilege elevation for the service management commands.
//!
//! Registering or removing a system service always requires administrative
//! rights, while both the desktop UI and the `nexa-service` daemon it talks to
//! normally run as an unprivileged user. Those operations therefore re-launch
//! the current executable through the platform's own elevation prompt:
//!
//! * Windows -> UAC consent dialog (`Start-Process -Verb RunAs`)
//! * macOS   -> AppleScript `do shell script ... with administrator privileges`
//! * Linux   -> polkit (`pkexec`), falling back to `sudo` inside a terminal
//!
//! None of those channels let the caller read the elevated child's stdout
//! reliably, so the child is asked (via [`RESULT_FILE_ARG`]) to drop its
//! outcome in a result file which the caller reads back. That way the UI shows
//! the real failure reason instead of a generic "access denied".
//!
//! The result file is a single line — `OK:` on success, `ERR:<json>` on failure, where `<json>` is
//! the serialized [`AppError`]. Both parses are deliberately lenient: a child built before this
//! format existed wrote plain prose after the prefix, and that prose is preserved as the `detail`
//! of a generic code rather than dropped, because the reason is the only actionable part.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{codes, AppError};

/// CLI flag telling the elevated copy of this binary where to report its
/// outcome. It is consumed by [`take_result_file_arg`] and is always passed as
/// the last two arguments: `--result-file <path>`.
pub const RESULT_FILE_ARG: &str = "--result-file";

/// Marker argument added to the command line of the elevated copy.
///
/// The child is started through a channel whose result the privilege probe cannot always
/// confirm: a filtered or hardened token leaves [`is_privileged`] answering `false` inside the
/// child, and so does a host without PowerShell. Trusting the probe alone would re-launch the
/// prompt from inside the elevated process and loop until the user stopped it. The marker is
/// part of argv — which every launcher preserves, unlike the environment — so seeing it means
/// "elevation already happened" and the operation runs inline.
pub const ELEVATED_ARG: &str = "--elevated";

const OK_PREFIX: &str = "OK";
const ERR_PREFIX: &str = "ERR";

/// Separator between the outcome prefix and its payload. A single character keeps the payload
/// free-form (JSON uses colons), because the first colon is always the delimiter.
const SEPARATOR: char = ':';

/// How long to wait for an asynchronous elevation prompt (terminal + sudo) to
/// produce its result file.
const POLL_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Exit status `pkexec` uses when the user dismissed the authentication dialog.
///
/// 127 is a different answer — "not authorized", or no agent at all — which is a policy failure
/// rather than the user saying no, so it is reported through `hint` instead.
#[cfg(target_os = "linux")]
const PKEXEC_CANCELLED: i32 = 126;

/// Terminal emulators tried on Linux when polkit is unavailable, in order.
#[cfg(target_os = "linux")]
const TERMINALS: &[&str] = &[
    "x-terminal-emulator",
    "gnome-terminal",
    "konsole",
    "xfce4-terminal",
    "mate-terminal",
    "lxterminal",
    "tilix",
    "deepin-terminal",
    "xterm",
];

/// True when the current process already runs with administrative privileges
/// (root on Unix, a member of the local Administrators group on Windows), or when it is the
/// copy this module started through an elevation prompt (see [`ELEVATED_ARG`]).
pub fn is_privileged() -> bool {
    if is_elevated_child() {
        return true;
    }

    #[cfg(windows)]
    return is_privileged_windows();

    #[cfg(unix)]
    return unsafe { libc::geteuid() } == 0;

    #[cfg(not(any(windows, unix)))]
    return false;
}

/// Whether this process was launched by [`run_self_elevated`].
fn is_elevated_child() -> bool {
    // `args_os`, matching the entry point: a non-UTF-8 argument must not panic here.
    std::env::args_os().any(|arg| arg.as_os_str() == std::ffi::OsStr::new(ELEVATED_ARG))
}

#[cfg(windows)]
fn is_privileged_windows() -> bool {
    const SCRIPT: &str = "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); \
        $principal = New-Object Security.Principal.WindowsPrincipal($identity); \
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";

    for shell in ["powershell", "pwsh"] {
        let output = Command::new(shell)
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .output();
        if let Ok(output) = output {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .eq_ignore_ascii_case("true");
            }
        }
    }

    false
}

/// Re-runs the current executable with `args` under elevated privileges and reports whether the
/// operation succeeded.
///
/// Callers are expected to check [`is_privileged`] first; the check is repeated here so that a
/// false negative cannot turn into an elevation loop, but the child then runs inline with no
/// prompt instead of going through the platform dialog.
pub fn run_self_elevated(args: &[&str]) -> Result<(), AppError> {
    let exe = std::env::current_exe().map_err(|e| AppError::cause(codes::SERVICE_EXE_PATH, e))?;
    let requested: Vec<String> = args.iter().map(|a| a.to_string()).collect();

    let result_path = result_file_path();
    let _ = std::fs::remove_file(&result_path);

    let mut elevated_args = requested;
    elevated_args.push(ELEVATED_ARG.to_string());
    elevated_args.push(RESULT_FILE_ARG.to_string());
    elevated_args.push(result_path.to_string_lossy().to_string());

    let (reported, spawn) = if is_privileged() {
        let output = Command::new(&exe)
            .args(&elevated_args)
            .output()
            .map_err(|e| AppError::cause(codes::SERVICE_ELEVATION_FAILED, e))?;
        // The child had a result file to write to, so the output is only a fallback for a child
        // old enough to print its outcome instead.
        (
            read_result_file(&result_path).or_else(|| Some(outcome_from_output(&output))),
            None,
        )
    } else {
        // A launcher that failed outright still leaves the caller with nothing to read, so the
        // failure is carried forward instead of being flattened into "no result".
        let spawn = match spawn_elevated(&exe, &elevated_args) {
            Ok(spawn) => spawn,
            Err(failure) => ElevatedSpawn {
                waited: true,
                failure: Some(failure),
                denied: false,
                hint: String::new(),
            },
        };
        let reported = if spawn.waited {
            read_result_file(&result_path)
        } else {
            wait_for_result_file(&result_path, POLL_TIMEOUT)
        };
        (reported, Some(spawn))
    };
    let _ = std::fs::remove_file(&result_path);

    if let Some(outcome) = reported {
        return outcome;
    }

    // Nothing was reported back: the prompt was declined, the elevation helper is unavailable, or
    // the child is still waiting for a password somewhere we cannot see.
    let Some(spawn) = spawn else {
        return Err(AppError::new(codes::SERVICE_FAILED));
    };
    if let Some(failure) = spawn.failure {
        return Err(failure);
    }
    // The launcher said the prompt was dismissed, so this is a refusal rather than an unknown:
    // the user saw the dialog and answered no.
    if spawn.denied {
        return Err(AppError::with_detail(
            codes::SERVICE_ELEVATION_DENIED,
            spawn.hint,
        ));
    }
    if spawn.hint.is_empty() {
        return Err(AppError::new(codes::SERVICE_ELEVATION_DENIED));
    }
    Err(AppError::with_detail(
        codes::SERVICE_ELEVATION_INCOMPLETE,
        spawn.hint,
    ))
}

/// Removes `--result-file <path>` from `args` and returns the path.
///
/// The elevated process uses this to separate launcher plumbing from the
/// operation it was actually asked to perform.
pub fn take_result_file_arg(args: &mut Vec<String>) -> Option<String> {
    let index = args.iter().position(|a| a == RESULT_FILE_ARG)?;
    args.remove(index);
    if index < args.len() {
        Some(args.remove(index))
    } else {
        None
    }
}

/// Hands `outcome` back to the process that requested the elevation.
///
/// Writes it to `result_file` when one was provided, otherwise prints it so a
/// manual invocation still sees something useful.
pub fn report_result(result_file: Option<&str>, outcome: &Result<(), AppError>) {
    let line = match outcome {
        Ok(()) => format!("{}{}", OK_PREFIX, SEPARATOR),
        Err(e) => format!("{}{}{}", ERR_PREFIX, SEPARATOR, encode_failure(e)),
    };

    match result_file {
        Some(path) => match std::fs::write(Path::new(path), line) {
            Ok(()) => {}
            Err(e) => eprintln!("Failed to write result file {}: {}", path, e),
        },
        None => match outcome {
            Ok(()) => println!("OK"),
            Err(e) => eprintln!("{}", e),
        },
    }
}

/// Serializes a failure for the result file, falling back to `Display` so a report is never lost.
fn encode_failure(error: &AppError) -> String {
    serde_json::to_string(error).unwrap_or_else(|_| error.to_string())
}

/// Decodes a failure payload written by the elevated child.
fn decode_failure(payload: &str) -> AppError {
    serde_json::from_str::<AppError>(payload)
        .unwrap_or_else(|_| AppError::with_detail(codes::SERVICE_LEGACY_FAILURE, payload))
}

fn read_result_file(path: &Path) -> Option<Result<(), AppError>> {
    let raw = std::fs::read_to_string(path).ok()?;
    let raw = raw.trim();
    let (prefix, payload) = raw.split_once(SEPARATOR)?;

    match prefix {
        OK_PREFIX => Some(Ok(())),
        ERR_PREFIX => Some(Err(decode_failure(payload))),
        _ => None,
    }
}

fn wait_for_result_file(path: &Path, timeout: Duration) -> Option<Result<(), AppError>> {
    let deadline = SystemTime::now() + timeout;
    loop {
        if let Some(outcome) = read_result_file(path) {
            return Some(outcome);
        }
        if SystemTime::now() >= deadline {
            return None;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn result_file_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "nexapipe-elevate-{}-{}.result",
        std::process::id(),
        nanos
    ))
}

/// Interprets the output of a child that reported nothing through a result file. Only used as a
/// fallback, which is why the failure is generic: the child's own code is unrecoverable here.
fn outcome_from_output(output: &Output) -> Result<(), AppError> {
    if output.status.success() {
        return Ok(());
    }

    let diagnostics = format_output(output);
    Err(if diagnostics.is_empty() {
        AppError::with_detail(
            codes::SERVICE_FAILED,
            format!("child exited with {}", output.status),
        )
    } else {
        AppError::with_detail(codes::SERVICE_FAILED, diagnostics)
    })
}

fn format_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{}\n{}", stdout, stderr),
    }
}

/// Outcome of launching the elevated child.
struct ElevatedSpawn {
    /// Whether the launcher waited for the child to exit.
    waited: bool,
    /// Why the launcher produced no result, when it failed outright.
    failure: Option<AppError>,
    /// Whether the launcher itself reported that no elevation happened — a dismissed UAC,
    /// polkit or AppleScript prompt, which is a refusal and not an unknown outcome.
    denied: bool,
    /// What the launcher is waiting for, when it could not wait itself.
    hint: String,
}

#[cfg(windows)]
fn spawn_elevated(exe: &Path, args: &[String]) -> Result<ElevatedSpawn, AppError> {
    let arg_list = args
        .iter()
        .map(|a| quote_powershell(a))
        .collect::<Vec<String>>()
        .join(",");

    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $p = Start-Process -FilePath {} -ArgumentList @({}) -Verb RunAs -Wait \
             -WindowStyle Hidden -PassThru; \
         exit $p.ExitCode",
        quote_powershell(&exe.to_string_lossy()),
        arg_list
    );

    let mut last_error = String::new();
    for shell in ["powershell", "pwsh"] {
        match Command::new(shell)
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
        {
            Ok(output) => {
                // A declined UAC consent throws inside the script and leaves PowerShell with a
                // non-zero exit code; a prompt that was accepted runs the child, which exits 0.
                let denied = !output.status.success();
                return Ok(ElevatedSpawn {
                    waited: true,
                    failure: None,
                    denied,
                    hint: format_output(&output),
                })
            }
            Err(e) => last_error = format!("Failed to start {}: {}", shell, e),
        }
    }

    Err(AppError::with_detail(
        codes::SERVICE_ELEVATION_FAILED,
        last_error,
    ))
}

#[cfg(target_os = "macos")]
fn spawn_elevated(exe: &Path, args: &[String]) -> Result<ElevatedSpawn, AppError> {
    let mut command = quote_shell(&exe.to_string_lossy());
    for arg in args {
        command.push(' ');
        command.push_str(&quote_shell(arg));
    }

    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        quote_applescript(&command)
    );

    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_ELEVATION_FAILED, e))?;

    // AppleScript reports a cancelled prompt through a non-zero exit status.
    let denied = !output.status.success();
    Ok(ElevatedSpawn {
        waited: true,
        failure: None,
        denied,
        hint: format_output(&output),
    })
}

#[cfg(target_os = "linux")]
fn spawn_elevated(exe: &Path, args: &[String]) -> Result<ElevatedSpawn, AppError> {
    let exe_str = exe.to_string_lossy().to_string();

    if let Some(pkexec) = which("pkexec") {
        let output = Command::new(pkexec)
            .arg(&exe_str)
            .args(args)
            .output()
            .map_err(|e| AppError::cause(codes::SERVICE_ELEVATION_FAILED, e))?;

        // Only a dismissed dialog is a refusal; every other non-zero status — including the
        // child's own exit code — is explained by the output it left behind.
        let denied = output.status.code() == Some(PKEXEC_CANCELLED);
        return Ok(ElevatedSpawn {
            waited: true,
            failure: None,
            denied,
            hint: format_output(&output),
        });
    }

    // No polkit: ask for the sudo password in a terminal window instead. The
    // sudo prompt itself needs a tty, and we cannot wait for it synchronously,
    // so the caller polls for the result file.
    let mut privileged_command = quote_shell(&exe_str);
    for arg in args {
        privileged_command.push(' ');
        privileged_command.push_str(&quote_shell(arg));
    }
    let script = format!(
        "sudo -- {} ; echo ; echo \"Press Enter to close this window.\" ; read _",
        privileged_command
    );

    if let Some(terminal) = TERMINALS.iter().find_map(|name| which(name)) {
        let launched = Command::new(terminal)
            .args(["-e", "sh", "-c", &script])
            .spawn();
        let hint = match launched {
            Ok(_) => "Waiting for sudo authentication in the terminal window.".to_string(),
            Err(e) => format!("Failed to launch a terminal emulator: {}", e),
        };

        // The terminal owns the prompt from here, so whether it was dismissed is unknown: the
        // caller polls for the result file and reports a timeout if nothing arrives.
        return Ok(ElevatedSpawn {
            waited: false,
            failure: None,
            denied: false,
            hint,
        });
    }

    Err(AppError::with_detail(
        codes::SERVICE_ELEVATION_UNAVAILABLE,
        format!(
            "neither polkit (pkexec) nor a terminal emulator is available; run `sudo {} --install` \
             manually",
            exe_str
        ),
    ))
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn spawn_elevated(_exe: &Path, _args: &[String]) -> Result<ElevatedSpawn, AppError> {
    Err(AppError::new(codes::SERVICE_ELEVATION_UNAVAILABLE))
}

/// Single-quote a value for use inside a PowerShell single-quoted string.
#[cfg(windows)]
fn quote_powershell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Single-quote a value for use in POSIX shells (macOS / Linux landing paths).
#[cfg(unix)]
fn quote_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Escape a value for use inside an AppleScript double-quoted string.
#[cfg(target_os = "macos")]
fn quote_applescript(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "linux")]
fn which(program: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifts_the_result_file_flag_out_of_the_command_line() {
        let mut args = vec![
            "nexa".to_string(),
            "--install".to_string(),
            ELEVATED_ARG.to_string(),
            RESULT_FILE_ARG.to_string(),
            "/tmp/nexapipe-elevate.result".to_string(),
        ];

        assert_eq!(
            take_result_file_arg(&mut args).as_deref(),
            Some("/tmp/nexapipe-elevate.result")
        );
        // The verb has to stay first: that is the position `cli::handle_args` reads.
        assert_eq!(args, vec!["nexa", "--install", ELEVATED_ARG]);
    }

    #[test]
    fn a_missing_result_file_path_is_not_an_argument() {
        let mut args = vec!["nexa".to_string(), RESULT_FILE_ARG.to_string()];

        assert_eq!(take_result_file_arg(&mut args), None);
        assert_eq!(args, vec!["nexa"]);
    }
}

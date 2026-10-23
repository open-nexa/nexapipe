//! The Linux half of the service registration: a systemd unit written by this
//! process and handed to `systemctl`.

use super::*;
#[cfg(target_os = "linux")]
use crate::service::platform::account::AccountId;

#[cfg(target_os = "linux")]
pub fn install_service_linux(
    exe_path: &str,
    installing_by: Option<&AccountId>,
) -> Result<(), AppError> {
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

    // Which account this service is installed for, written where the
    // unprivileged desktop cannot change it: the service runs as root, so it
    // serves that account and refuses every other one. Written before the
    // service starts, because the service reads it as it comes up.
    if let Some(account) = installing_by {
        install_owner::record_installed_by(account)?;
    } else {
        tracing::warn!(
            "Installing the service without naming the account it is for: it will serve any local \
             account that owns the token it reads"
        );
    }

    // Which build this service is, written beside the account record. The desktop reads it
    // to tell an old service from its own — a question the service itself cannot answer
    // once it has been left behind by an upgrade, because the two no longer speak the same
    // protocol.
    install_version::record_installed_version(crate::service::ipc::BUILD_VERSION)?;

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
    // boot, while the UI promises install and start as one action. A restart rather than a
    // start — see [`linux_activation_args`].
    restart_service_linux()?;
    wait_for_service_state_linux(ServiceState::Running, codes::SERVICE_START_FAILED)
}

/// The `systemctl` verb an install uses to bring the unit up, with the unit's name.
///
/// `restart`, not `start`: a unit that is already running keeps the process it was launched
/// from, so an install that only started it — which is every upgrade — re-reads the unit file
/// and leaves the previous build running. systemd's `restart` also starts a unit that is not
/// running, so this covers a first install as well.
///
/// Split out of [`restart_service_linux`] because the choice is the whole fix and is otherwise
/// invisible: nothing fails when it is wrong, the service simply keeps its old build.
#[cfg(any(target_os = "linux", test))]
pub fn linux_activation_args() -> [&'static str; 2] {
    ["restart", SERVICE_NAME]
}

/// The command systemd should run in the foreground.
///
/// A packaged install has a dedicated nexa-service binary beside the desktop executable. A
/// development build may not, in which case the desktop binary understands --foreground and
/// can host the same service without daemonizing.
///
/// The path is quoted, because systemd splits the line on whitespace and an install under a
/// directory with a space in it — a development build, or a home directory that has one — would
/// otherwise arrive as two arguments and leave the unit failing with `status=203/EXEC`. The
/// macOS plist (an argv array) and the Windows `binPath` (escaped quotes) both carry such a
/// path correctly; this is the third spelling of the same thing, and it was the one that did
/// not.
#[cfg(any(target_os = "linux", test))]
pub fn linux_service_exec(exe_path: &str) -> String {
    let service = std::path::Path::new(exe_path).with_file_name("nexa-service");
    linux_service_exec_with(exe_path, service.is_file())
}

#[cfg(any(target_os = "linux", test))]
pub fn linux_service_exec_with(exe_path: &str, has_service_binary: bool) -> String {
    if has_service_binary {
        systemd_quote(
            &std::path::Path::new(exe_path)
                .with_file_name("nexa-service")
                .to_string_lossy(),
        )
    } else {
        format!("{} --foreground", systemd_quote(exe_path))
    }
}

/// A path as systemd's `ExecStart=` line wants it.
///
/// systemd reads the line with its own word splitter: whitespace separates arguments, and a
/// double-quoted run is one argument with the quotes taken off. Inside double quotes a
/// backslash escapes the character after it, so a literal backslash is written twice and a
/// literal quote is written once — which is what makes a path with either of them in it
/// survive the round trip.
///
/// The alternative — a path with a space in it, unquoted — is a unit that systemd refuses to
/// start, and the refusal names neither the path nor the space that caused it.
#[cfg(any(target_os = "linux", test))]
fn systemd_quote(path: &str) -> String {
    let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(any(target_os = "linux", test))]
pub fn linux_unit_content(exe_path: &str) -> String {
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
pub fn uninstall_service_linux() -> Result<(), AppError> {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    let _ = Command::new("systemctl")
        .args(["stop", SERVICE_NAME])
        .output();

    // `systemctl stop` sends SIGTERM; the teardown that restores the system DNS is
    // what answers it. Wait for the process to be gone before the unit file — the
    // only thing that says the service was ever installed — is deleted.
    wait_for_service_exit(|| !is_service_running_linux());

    let _ = Command::new("systemctl")
        .args(["disable", SERVICE_NAME])
        .output();

    let unit_path = Path::new("/etc/systemd/system").join(format!("{}.service", SERVICE_NAME));
    let _ = fs::remove_file(unit_path);

    // The record of which account the service served goes with it: a service
    // that is no longer installed has no account to serve.
    install_owner::forget_installed_by();
    // And so does the record of which build it was: a service that is gone has
    // no build, and a version left behind would be read as the version of a
    // service that is not there.
    install_version::forget_installed_version();

    let _ = Command::new("systemctl").args(["daemon-reload"]).output();

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn is_service_running_linux() -> bool {
    use std::process::Command;

    Command::new("systemctl")
        .args(["is-active", SERVICE_NAME])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "active")
        .unwrap_or(false)
}

/// The unit file is the registration: no file means the service was never installed.
#[cfg(target_os = "linux")]
pub fn state_linux() -> ServiceState {
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
pub fn start_service_linux() -> Result<(), AppError> {
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

/// Brings the unit up, or back up — see [`linux_activation_args`] for why this is a restart
/// rather than a start.
#[cfg(target_os = "linux")]
pub fn restart_service_linux() -> Result<(), AppError> {
    use std::process::Command;

    let output = Command::new("systemctl")
        .args(linux_activation_args())
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
pub fn stop_service_linux() -> Result<(), AppError> {
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
pub fn wait_for_service_state_linux(expected: ServiceState, failure: &str) -> Result<(), AppError> {
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

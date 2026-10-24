//! The macOS half of the service registration: a launchd job written by this
//! process and handed to `launchctl`.

use super::*;
#[cfg(target_os = "macos")]
use crate::service::platform::account::AccountId;
#[cfg(target_os = "macos")]
use crate::service::platform::service_copy;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};

/// Whether the job is still registered with launchd.
///
/// Not the same question as "is it running": after a bootout the process is gone long
/// before launchd has finished removing the job, and a bootstrap issued in that window
/// is refused — the label is still being torn down.
#[cfg(target_os = "macos")]
fn is_job_registered_macos() -> bool {
    use std::process::Command;

    Command::new("launchctl")
        .args(["print", &macos_job_target()])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Waits for launchd to let go of the job.
///
/// The removal is not the same event as the exit: the process is down first, and the
/// job disappears a moment later. A bootstrap issued in between is refused — the label
/// is still being torn down — and an install refused that way leaves the machine with
/// no service at all, which is worse than the stale one it was replacing.
#[cfg(target_os = "macos")]
fn wait_for_job_release() {
    use std::time::{Duration, Instant};

    const TIMEOUT: Duration = Duration::from_secs(15);

    let deadline = Instant::now() + TIMEOUT;
    while is_job_registered_macos() {
        if Instant::now() >= deadline {
            tracing::warn!(
                "launchd still holds the job {}s after it was booted out; the install may \
                 be refused with \"Bootstrap failed\"",
                TIMEOUT.as_secs()
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Puts the daemon's own copy of the service binary in place, and returns where it is.
///
/// The copy is what the service manager runs: the app's own binary sits in a directory
/// the local accounts own, and a privileged service must not run a program they can
/// replace. See [`service_copy`].
#[cfg(target_os = "macos")]
fn install_service_binary(source: &Path) -> Result<PathBuf, AppError> {
    let destination = service_binary_path();

    // The install was started from the copy itself — which is what happens when the
    // service binary is asked to install the service. There is nothing to copy then.
    if source == destination {
        return Ok(destination);
    }

    // The directory is root's, and not writable by anybody else: it holds the program a
    // privileged service runs, so an account that can write it can replace it.
    let directory = service_binary_path()
        .parent()
        .ok_or_else(|| {
            AppError::with_detail(
                codes::SERVICE_DEFINITION_FAILED,
                format!("{} has no parent directory", destination.display()),
            )
        })?
        .to_path_buf();
    std::fs::create_dir_all(&directory).map_err(|e| {
        AppError::cause(
            codes::SERVICE_DEFINITION_FAILED,
            format!("cannot create {}: {e}", directory.display()),
        )
    })?;
    service_copy::set_mode(&directory, 0o755)?;

    service_copy::copy_verified(source, &destination)?;
    tracing::info!(
        "The service runs {} (copied from {})",
        destination.display(),
        source.display()
    );

    Ok(destination)
}

/// Removes the daemon's own copy of the service binary.
///
/// A service that is no longer installed has no binary to run, and a copy left behind
/// is one nothing will ever replace.
#[cfg(target_os = "macos")]
fn remove_service_binary() {
    let _ = std::fs::remove_file(service_binary_path());
    if let Some(directory) = service_binary_path().parent() {
        let _ = std::fs::remove_dir(directory);
    }
}

/// The launchd job definition.
///
/// `ExitTimeOut` is how long launchd lets a job spend on SIGTERM before it sends SIGKILL.
/// The default is only documented as "system-defined" and is shorter than the 20s the
/// teardown allows itself (`TunProxy::stop_and_wait`) — 5s on this machine, read back from
/// `launchctl print system/<label>`. A job without an explicit, longer one is therefore
/// killed well before the system-DNS restore can finish. 30s leaves room.
///
/// `KeepAlive` asks to survive *failure*, not every exit. The plain `<true/>` form is the
/// one that made a stop impossible: `launchctl stop` sends SIGTERM, the teardown answers
/// it, the process leaves with 0, and launchd immediately brings it back — so the panel
/// said "stopped" for about a second before its next poll. The dictionary form keeps the
/// crash protection and nothing else; per `launchd.plist(5)`, `SuccessfulExit` false means
/// the job restarts only when the exit status is *not* zero, which is also the condition
/// Linux spells `Restart=on-failure`. It is deliberately the only key here: the conditions
/// in a `KeepAlive` dictionary are OR'd, so a second one can restart the job for a reason
/// nobody asked for.
///
/// A plist already on disk keeps whatever it was installed with, so this only takes
/// effect from the next install onwards.
///
/// Kept out of the installer and compiled under `test` on every platform because those
/// keys are both easy to lose and invisible when lost: nothing fails, and a slow stop
/// simply stops restoring the machine's DNS — or a stopped job simply comes back.
#[cfg(any(target_os = "macos", test))]
pub fn macos_plist_content(exe_path: &str) -> String {
    format!(
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
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ExitTimeOut</key>
    <integer>30</integer>
    <key>StandardOutPath</key>
    <string>/var/log/nexa-service.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/nexa-service.log</string>
</dict>
</plist>
"#,
        SERVICE_NAME, exe_path
    )
}

/// How the job is addressed in the modern `launchctl` subcommands — `system/<label>`, both to
/// remove it and to ask what it is doing.
#[cfg(any(target_os = "macos", test))]
pub fn macos_job_target() -> String {
    format!("system/com.nexa.{}", SERVICE_NAME)
}

/// The `launchctl` invocations an install needs, in the order it needs them.
///
/// `bootout` coming first is the whole point. launchd reads a job definition once, when it is
/// told about the job, and neither `load` nor `kickstart` reads it again — so writing the plist
/// over a job that is already registered changes nothing at all: the daemon keeps whatever it
/// loaded last. That is how an upgrade stayed on its first-ever `KeepAlive` and never picked up
/// `ExitTimeOut`. Taking the job out first is what makes the rest of the install mean anything,
/// and it is safe to attempt unconditionally: on a machine that has nothing installed it simply
/// fails, which is exactly the state a normal install starts from.
#[cfg(any(target_os = "macos", test))]
pub fn macos_install_commands(plist_path: &str) -> [Vec<String>; 2] {
    [
        vec!["bootout".into(), macos_job_target()],
        vec!["bootstrap".into(), "system".into(), plist_path.into()],
    ]
}

#[cfg(target_os = "macos")]
pub fn install_service_macos(
    exe_path: &str,
    installing_by: Option<&AccountId>,
) -> Result<(), AppError> {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;

    // The program the daemon runs: the install's own copy of the service binary, in a
    // directory only root can write. The app's own binary is not it — that one lives
    // where the local accounts can replace it, and launchd will not run a privileged
    // service out of a directory they own.
    let source = service_copy::service_source(Path::new(exe_path));
    let program = install_service_binary(&source)?;

    let plist_path =
        Path::new("/Library/LaunchDaemons").join(format!("com.nexa.{}.plist", SERVICE_NAME));
    let plist_content = macos_plist_content(&program.to_string_lossy());

    let [bootout, bootstrap] = macos_install_commands(plist_path.to_str().unwrap_or_default());

    // Taking the job out before the file is rewritten — see `macos_install_commands`. A
    // failure just means there was nothing to remove, which is the ordinary case.
    let _ = Command::new("launchctl").args(&bootout).output();

    // `bootout` stops the job with SIGTERM, and the teardown that restores the system DNS is
    // what answers it — see `uninstall_service_macos`, which waits for the same reason.
    //
    // What is waited for is the job being *released*, not the process being gone: launchd
    // removes the job a moment after the process is down, and a bootstrap issued in that
    // window is refused ("Bootstrap failed: 5: Input/output error") because the label is
    // still being torn down. An install refused that way leaves the machine with no
    // service at all — which is what happened to the first attempt at installing over a
    // service that was still running.
    wait_for_job_release();
    wait_for_service_exit(|| !is_service_running_macos());

    fs::create_dir_all("/Library/LaunchDaemons")
        .map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    let mut file = File::create(&plist_path)
        .map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    file.write_all(plist_content.as_bytes())
        .map_err(|e| AppError::cause(codes::SERVICE_DEFINITION_FAILED, e))?;

    // Which account this service is installed for, written where the
    // unprivileged desktop cannot change it: the service runs as root, so it
    // serves that account and refuses every other one. Written before the
    // job is registered, because the service reads it as it comes up.
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

    let output = Command::new("launchctl")
        .args(&bootstrap)
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if output.status.success() {
        // The bootstrap answers as soon as the job is registered; the process is
        // spawned a moment later, and a program launchd will not run — one whose
        // signature it refuses, or one that sits in a directory the local accounts
        // own — is refused at that point: the job is registered and nothing is
        // running. An install that reported success over that is an install that
        // left the machine with no service at all.
        verify_started()?;
        Ok(())
    } else {
        Err(AppError::with_detail(
            codes::SERVICE_INSTALL_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

/// Checks that the job came up.
#[cfg(target_os = "macos")]
fn verify_started() -> Result<(), AppError> {
    use std::time::{Duration, Instant};

    const TIMEOUT: Duration = Duration::from_secs(10);

    let deadline = Instant::now() + TIMEOUT;
    while !is_service_running_macos() {
        if Instant::now() >= deadline {
            return Err(AppError::with_detail(
                codes::SERVICE_INSTALL_FAILED,
                format!(
                    "the service was registered but did not come up within {}s; \
                     the service log says why",
                    TIMEOUT.as_secs()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall_service_macos() -> Result<(), AppError> {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    let plist_path =
        Path::new("/Library/LaunchDaemons").join(format!("com.nexa.{}.plist", SERVICE_NAME));

    let _ = Command::new("launchctl")
        .args(["unload", plist_path.to_str().unwrap()])
        .output();

    // `unload` stops the job with SIGTERM, and the teardown that restores the system
    // DNS is what answers it: on macOS that setting lives in the system configuration
    // and survives the reboot, so deleting the plist while the job is still coming
    // down leaves the machine resolving against a TUN address with nothing left to
    // put it back.
    wait_for_service_exit(|| !is_service_running_macos());

    let _ = fs::remove_file(&plist_path);

    // The daemon's own copy of the service binary goes with it: a service that is no
    // longer installed has no binary to run, and a copy left behind is one nothing
    // will ever replace.
    remove_service_binary();

    // The record of which account the service served goes with it: a service
    // that is no longer installed has no account to serve.
    install_owner::forget_installed_by();
    // And so does the record of which build it was: a service that is gone has
    // no build, and a version left behind would be read as the version of a
    // service that is not there.
    install_version::forget_installed_version();

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn is_service_running_macos() -> bool {
    use std::process::Command;

    // The daemon lives in the *system* domain, but a plain `launchctl list <label>` from a user
    // session queries the user's GUI domain and answers "Could not find service" (exit 1) even
    // while the daemon is running — which had the service panel show "stopped" forever.
    // `launchctl print system/<label>` is readable without root and names the state outright.
    let Ok(output) = Command::new("launchctl")
        .args(["print", &macos_job_target()])
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
pub fn state_macos() -> ServiceState {
    use std::path::Path;

    let plist =
        Path::new("/Library/LaunchDaemons").join(format!("com.nexa.{}.plist", SERVICE_NAME));
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
pub fn start_service_macos() -> Result<(), AppError> {
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
pub fn stop_service_macos() -> Result<(), AppError> {
    use std::process::Command;

    let output = Command::new("launchctl")
        .args(["stop", format!("com.nexa.{}", SERVICE_NAME).as_str()])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if output.status.success() {
        // `launchctl stop` only asks. The process still has to come down, and the teardown
        // that restores the system DNS is what takes the time — the process is the only
        // thing that can do it, so a stop reported before it has run leaves the machine
        // resolving against a tunnel that is going away. Nothing waited here before: the
        // job was `KeepAlive: true` (see `macos_plist_content`), so the process came
        // straight back and no wait could ever have been satisfied.
        wait_for_service_exit(|| !is_service_running_macos());
        Ok(())
    } else {
        Err(AppError::with_detail(
            codes::SERVICE_STOP_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

/// Replaces the running job with a new instance.
///
/// `kickstart -k` is the verb for this: `stop` followed by `start` would race the job's own
/// `KeepAlive`, which brings the process back between the two commands.
#[cfg(target_os = "macos")]
pub fn restart_service_macos() -> Result<(), AppError> {
    use std::process::Command;

    let output = Command::new("launchctl")
        .args(["kickstart", "-k", macos_job_target().as_str()])
        .output()
        .map_err(|e| AppError::cause(codes::SERVICE_COMMAND_FAILED, e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::with_detail(
            codes::SERVICE_RESTART_FAILED,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

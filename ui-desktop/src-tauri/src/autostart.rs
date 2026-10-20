//! Whether this app starts when the machine does.
//!
//! The settings page has carried a "launch at startup" switch for as long as it
//! has had a settings page, and it called two commands that were never
//! registered: the switch read `false` and wrote nothing, so it looked like a
//! setting and behaved like a decoration.
//!
//! Each platform says this differently, and none of them is hard:
//!
//! - **Windows**: a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
//! - **macOS**: a LaunchAgent in `~/Library/LaunchAgents`.
//! - **Linux**: a `.desktop` file under `~/.config/autostart`.
//!
//! All three are per-user: starting an app at login is the user's own
//! business, and none of them needs elevation.
//!
//! # Nothing is started now
//!
//! Enabling this writes an entry and stops there. The entry is read at the next
//! login by the platform's own mechanism — the Run key, `launchd`, the
//! session's autostart scan — so switching the setting on does not launch a
//! second copy of the app in the middle of the session, which is what a
//! `launchctl bootstrap` here would do.
//!
//! The entry carries [`BACKGROUND_FLAG`], so the app that comes up at login
//! starts without a window: it lives in the tray and the tunnel is one click
//! away, rather than a window appearing over whatever the user was doing.

use std::path::PathBuf;

use crate::error::{codes, AppError};

/// The name the entry is filed under.
///
/// One word on every platform, because it is what the user reads in whatever
/// list the platform keeps — "Startup" on Windows, "Login Items" on macOS, the
/// session's autostart list on Linux.
///
/// macOS files its agent under the bundle identifier instead, which is what
/// the system's own login items are named after, so this one is unused there.
#[cfg_attr(target_os = "macos", allow(dead_code))]
const ENTRY_NAME: &str = "nexa";

/// The argument that says "start without a window".
///
/// Carried by the entry, so the app that comes up at login lives in the tray
/// instead of opening a window over whatever the user was doing.
pub const BACKGROUND_FLAG: &str = "--background";

/// Whether this app is started when the machine starts.
///
/// A failure to read is a failure, not "off": a switch that claims to be off
/// while the entry is there is the same silent lie the switch used to tell.
pub fn is_enabled() -> Result<bool, AppError> {
    platform::is_enabled()
}

/// Arranges for this app to start when the machine starts, or not.
///
/// Turning it off removes the entry. Turning it on writes one that points at
/// the running executable — which is the installed one for an installed app,
/// and a development build for a development build, so the second is what a
/// developer wants to happen.
pub fn set_enabled(enabled: bool) -> Result<(), AppError> {
    platform::set_enabled(enabled)
}

/// Whether this launch was asked for by the machine rather than by a person.
///
/// True when the entry started the app: the window stays hidden and the app
/// waits in the tray.
pub fn is_background_launch() -> bool {
    std::env::args().any(|arg| arg == BACKGROUND_FLAG)
}

/// The path of the running executable, which is what an entry has to point at.
fn current_exe() -> Result<PathBuf, AppError> {
    std::env::current_exe().map_err(|e| {
        AppError::with_detail(
            codes::AUTOSTART_EXE_PATH,
            format!("the running executable could not be resolved: {e}"),
        )
    })
}

// -- Windows ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::{current_exe, ENTRY_NAME};
    use crate::error::{codes, AppError};
    use std::process::Command;

    /// Where Windows looks for what to run at login.
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    /// `reg.exe`, which is in `System32` on every Windows that has ever run.
    ///
    /// Named by path rather than by bare name: an app launched from a service
    /// or from a shell whose `PATH` does not include `System32` would
    /// otherwise fail to find it, and the failure would be "the setting does
    /// not work" rather than "the tool was not found".
    fn reg() -> String {
        std::env::var("SystemRoot")
            .map(|root| format!(r"{root}\System32\reg.exe"))
            .unwrap_or_else(|_| "reg.exe".to_string())
    }

    pub fn is_enabled() -> Result<bool, AppError> {
        let output = Command::new(reg())
            .args(["query", RUN_KEY, "/v", ENTRY_NAME])
            .output()
            .map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_READ_FAILED,
                    format!("reg query could not be run: {e}"),
                )
            })?;

        // The exit code is the answer; the text is localized, so it is not read.
        // `reg query` exits 1 when the value is not there, which is the
        // ordinary answer before the entry has ever been written.
        Ok(output.status.success())
    }

    pub fn set_enabled(enabled: bool) -> Result<(), AppError> {
        let mut command = Command::new(reg());
        if enabled {
            let exe = current_exe()?;
            // The value is a command line, so the path is quoted: a program
            // files under `C:\Program Files` has a space in it.
            let value = format!("\"{}\" {}", exe.display(), super::BACKGROUND_FLAG);
            command.args([
                "add",
                RUN_KEY,
                "/v",
                ENTRY_NAME,
                "/t",
                "REG_SZ",
                "/d",
                value.as_str(),
                "/f",
            ]);
        } else {
            // Removing an entry that is not there is the outcome the caller
            // asked for, so it is not a failure — and `reg delete` exits
            // non-zero when the value is missing.
            if !is_enabled()? {
                return Ok(());
            }
            command.args(["delete", RUN_KEY, "/v", ENTRY_NAME, "/f"]);
        }

        let output = command.output().map_err(|e| {
            AppError::with_detail(
                codes::AUTOSTART_WRITE_FAILED,
                format!("reg could not be run: {e}"),
            )
        })?;

        if output.status.success() {
            Ok(())
        } else {
            Err(AppError::with_detail(
                codes::AUTOSTART_WRITE_FAILED,
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    }
}

// -- macOS -----------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::current_exe;
    use crate::error::{codes, AppError};
    use std::path::PathBuf;

    /// The LaunchAgent's label.
    ///
    /// The bundle identifier, so the job is named after the app rather than
    /// after this file — the same name the system's own login items use.
    const LABEL: &str = "com.nexa.ui";

    /// Where the user agent goes.
    fn plist_path() -> Result<PathBuf, AppError> {
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            AppError::with_detail(
                codes::AUTOSTART_WRITE_FAILED,
                "HOME is not set, so there is no place to put a LaunchAgent",
            )
        })?;
        Ok(home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LABEL}.plist")))
    }

    pub fn is_enabled() -> Result<bool, AppError> {
        let path = plist_path()?;
        Ok(path.exists())
    }

    pub fn set_enabled(enabled: bool) -> Result<(), AppError> {
        let path = plist_path()?;
        if !enabled {
            // Removing a file that is not there is the outcome the caller
            // asked for, so it is not a failure.
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the LaunchAgent could not be removed: {e}"),
                )),
            }
        } else {
            let exe = current_exe()?;
            let content = plist_content(&exe);
            let dir = path.parent().expect("the path has a parent");
            std::fs::create_dir_all(dir).map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the LaunchAgents directory could not be created: {e}"),
                )
            })?;
            std::fs::write(&path, content).map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the LaunchAgent could not be written: {e}"),
                )
            })?;
            // `launchd` refuses a world-writable agent, and the default mode
            // of a new file follows the umask — which on a machine with a
            // permissive umask would be 0666.
            set_private_mode(&path);
            Ok(())
        }
    }

    /// The agent itself.
    ///
    /// `RunAtLoad` is what makes the job start when the session comes up; the
    /// agent is not bootstrapped here, so nothing starts until the next
    /// login.
    fn plist_content(exe: &std::path::Path) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
            exe.display(),
            super::BACKGROUND_FLAG,
        )
    }

    /// Narrows the mode of a file to 0644, where the platform has one.
    #[cfg(unix)]
    fn set_private_mode(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }

    #[cfg(not(unix))]
    fn set_private_mode(_path: &std::path::Path) {}

    #[cfg(test)]
    mod tests {
        use super::plist_content;
        use std::path::Path;

        #[test]
        fn the_agent_carries_the_executable_and_the_background_flag() {
            // The two arguments are separate entries in the array, so a path
            // with a space in it needs no quoting here — and the flag has to be
            // one of them, or the app comes up with a window at login.
            let plist = plist_content(Path::new("/Applications/nexa.app/nexa"));
            assert!(plist.contains("<string>/Applications/nexa.app/nexa</string>"));
            assert!(plist.contains("<string>--background</string>"));
        }

        #[test]
        fn the_agent_starts_with_the_session() {
            // `RunAtLoad` is what makes the job run at login; without it the
            // entry would be a job that never starts.
            assert!(plist_content(Path::new("/Applications/nexa.app/nexa"))
                .contains("<key>RunAtLoad</key>"));
        }
    }
}

// -- Linux -----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::{current_exe, ENTRY_NAME};
    use crate::error::{codes, AppError};
    use std::path::PathBuf;

    /// Where the desktop session looks for what to start with it.
    fn desktop_path() -> Result<PathBuf, AppError> {
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            AppError::with_detail(
                codes::AUTOSTART_WRITE_FAILED,
                "HOME is not set, so there is no place to put an autostart entry",
            )
        })?;
        Ok(home
            .join(".config")
            .join("autostart")
            .join(format!("{ENTRY_NAME}.desktop")))
    }

    pub fn is_enabled() -> Result<bool, AppError> {
        let path = desktop_path()?;
        Ok(path.exists())
    }

    pub fn set_enabled(enabled: bool) -> Result<(), AppError> {
        let path = desktop_path()?;
        if !enabled {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the autostart entry could not be removed: {e}"),
                )),
            }
        } else {
            let exe = current_exe()?;
            let content = desktop_content(&exe);
            let dir = path.parent().expect("the path has a parent");
            std::fs::create_dir_all(dir).map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the autostart directory could not be created: {e}"),
                )
            })?;
            std::fs::write(&path, content).map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the autostart entry could not be written: {e}"),
                )
            })?;
            Ok(())
        }
    }

    /// The entry, in the format the desktop entry specification defines.
    ///
    /// `X-GNOME-Autostart-enabled` is what GNOME reads; the specification
    /// itself only says the file is honoured, so the other desktops need
    /// nothing more than the file.
    fn desktop_content(exe: &std::path::Path) -> String {
        format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name={ENTRY_NAME}\n\
             Exec={} {}\n\
             Terminal=false\n\
             X-GNOME-Autostart-enabled=true\n",
            quote_argument(exe),
            super::BACKGROUND_FLAG,
        )
    }

    /// The program's path, as the `Exec` line has to carry it.
    ///
    /// That line is a command line, and a space in it would end the program
    /// name early — so a path with a space in it is quoted. The specification
    /// allows either quoting or backslash escapes; quoting is used here
    /// because a path that contains a quote of its own is a path that cannot be
    /// expressed in an `Exec` line at all.
    fn quote_argument(exe: &std::path::Path) -> String {
        let exe = exe.display().to_string();
        if exe.contains(' ') {
            format!("\"{exe}\"")
        } else {
            exe
        }
    }

    #[cfg(test)]
    mod tests {
        use super::quote_argument;
        use std::path::Path;

        #[test]
        fn a_path_with_a_space_in_it_is_quoted() {
            // The `Exec` line is read as a command, so an unquoted space would
            // end the program name early and the entry would start nothing.
            assert_eq!(
                quote_argument(Path::new("/home/a b/nexa")),
                "\"/home/a b/nexa\""
            );
        }

        #[test]
        fn a_path_without_a_space_in_it_is_left_alone() {
            // Quoting is only needed where it changes the meaning; adding it
            // everywhere would make every entry look like a special case.
            assert_eq!(quote_argument(Path::new("/home/ab/nexa")), "/home/ab/nexa");
        }
    }
}

// -- anything else ---------------------------------------------------------------------

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod platform {
    use crate::error::{codes, AppError};

    pub fn is_enabled() -> Result<bool, AppError> {
        Err(AppError::new(codes::AUTOSTART_UNSUPPORTED_PLATFORM))
    }

    pub fn set_enabled(_enabled: bool) -> Result<(), AppError> {
        Err(AppError::new(codes::AUTOSTART_UNSUPPORTED_PLATFORM))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_background_flag_is_a_word_the_launcher_can_pass() {
        // It travels through a registry value, a plist array and a desktop
        // entry's `Exec` line, so it has to be a single argument with no
        // spaces in it.
        assert!(!BACKGROUND_FLAG.contains(' '));
        assert!(BACKGROUND_FLAG.starts_with("--"));
    }

    #[test]
    fn the_entry_name_is_one_word() {
        // The same name appears in a registry value, a file name and a plist
        // label; a space in it would need quoting in two of the three.
        assert!(!ENTRY_NAME.contains(' '));
    }

    /// The launch flag is read off the process's own arguments, and it has to
    /// be matched exactly: an argument that merely starts with it is somebody
    /// else's.
    #[test]
    fn the_flag_is_matched_exactly() {
        assert!(std::env::args().any(|arg| arg == BACKGROUND_FLAG) == is_background_launch());
    }
}

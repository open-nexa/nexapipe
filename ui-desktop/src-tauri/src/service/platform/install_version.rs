//! The build the installed service is.
//!
//! The service can say which build it is over the IPC channel — but only while that channel
//! works, and the case this record exists for is precisely the one where it does not: a
//! service left behind by an earlier build keeps running while the app it belongs to has
//! been replaced, and the two no longer speak the same protocol. The desktop can then ask
//! the service nothing at all, which is how "the app is new and the service is old" came to
//! look exactly like "the service is not running" — with nothing on screen to say otherwise.
//!
//! So the build is written down where the desktop can read it *without* the service: a file
//! root owns on Unix, a value in the service's own registry key on Windows. Both are written
//! by the install — the one privileged moment — and read by the panel, which can then say
//! "the installed service is older than this app" instead of showing a service that is
//! running and an app that cannot talk to it.

use super::install_owner::{self, STATE_DIR};
#[cfg(unix)]
use super::install_owner::STATE_ROOT;
#[cfg(unix)]
use crate::error::{codes, AppError};
use std::path::{Path, PathBuf};

/// The file inside the state directory that names the build the service was installed from.
///
/// Beside the record of the account the service serves, because both are written by the same
/// install and answer the same question: what was put on this machine, and for whom.
pub const VERSION_FILE: &str = "service-version";

/// The registry value the Windows install writes the same fact into.
#[cfg(windows)]
pub const VERSION_VALUE: &str = "ServiceVersion";

/// `<root>/nexapipe/service-version`.
///
/// Derived rather than spelled out, so that the naming can be checked without a root to
/// install into — and so that it cannot drift away from the record beside it.
pub fn version_file_path(root: &Path) -> PathBuf {
    root.join(STATE_DIR).join(VERSION_FILE)
}

/// Records the build the service is being installed from.
///
/// Unix only: the write happens in the privileged install itself, which is the only place a
/// file in root's own directory can be created with root's ownership. On Windows the record
/// is a value in the service's own registry key, written by the elevated batch instead —
/// see [`record_command`].
#[cfg(unix)]
pub fn record_installed_version(version: &str) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;

    let path = version_file_path(Path::new(STATE_ROOT));
    let directory = path.parent().ok_or_else(|| {
        AppError::with_detail(
            codes::SERVICE_DEFINITION_FAILED,
            format!("{} has no parent directory", path.display()),
        )
    })?;

    std::fs::create_dir_all(directory).map_err(|e| {
        AppError::cause(
            codes::SERVICE_DEFINITION_FAILED,
            format!("cannot create {}: {e}", directory.display()),
        )
    })?;
    // Root's, and not writable by anybody else: the same rule the account record follows,
    // and for the same reason — a file another account can replace is not a record.
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).map_err(|e| {
        AppError::cause(
            codes::SERVICE_DEFINITION_FAILED,
            format!("cannot set the mode of {}: {e}", directory.display()),
        )
    })?;

    // Written the way the account record is: a temporary file and a rename, so a reader
    // sees either the old version or the new one and never an empty file. The mode is 0644
    // rather than 0600 — this is not a secret, and the point of it is that the
    // unprivileged desktop can read it.
    install_owner::write_record_atomically(&path, directory, version.as_bytes())
}

/// Forgets the build the installed service is.
///
/// A service that is no longer installed has no build: the record would outlive the thing it
/// describes and be read as the version of a service that is not there.
#[cfg(unix)]
pub fn forget_installed_version() {
    let _ = std::fs::remove_file(version_file_path(Path::new(STATE_ROOT)));
}

/// The build the installed service is, when one is on file.
///
/// `None` when there is no record: a machine that never had the service installed, or one
/// whose service predates the record. Both mean the same thing to the caller — nothing to
/// compare against — and neither is a failure to report.
pub fn read_installed_version() -> Option<String> {
    #[cfg(unix)]
    return read_installed_version_unix();

    #[cfg(windows)]
    return read_installed_version_windows();

    #[cfg(not(any(unix, windows)))]
    return None;
}

/// Reads the record from the file root owns.
///
/// The file is root's and the directory is root's, so nothing but the install can have put
/// it there. A version that is not there, or an empty file, is no version at all.
#[cfg(unix)]
fn read_installed_version_unix() -> Option<String> {
    let text = std::fs::read_to_string(version_file_path(Path::new(STATE_ROOT))).ok()?;
    let version = text.trim();
    (!version.is_empty()).then(|| version.to_string())
}

/// Reads the record from the service's own registry key.
///
/// The key is the one the control manager owns, so the value in it is the one the install
/// wrote; the desktop may read `HKLM` without any rights of its own.
#[cfg(windows)]
fn read_installed_version_windows() -> Option<String> {
    install_owner::read_service_registry_value(VERSION_VALUE)
}

/// Whether a version can be written into the batch file the Windows install runs.
///
/// The value ends up in a batch file, where a quote opens a command and a `%` starts an
/// environment variable. A version that carries one is refused rather than written.
#[cfg(any(windows, test))]
pub fn version_is_writable(version: &str) -> bool {
    !version.is_empty() && !version.contains('"') && !version.contains('%')
}

/// The command the Windows install writes the version with.
///
/// Windows only: the process that asks for the install is unprivileged, so the write has to
/// happen in the elevated batch — the same place the account record is written.
///
/// `None` for a version that cannot be written into a batch file, so that the caller skips
/// the line instead of writing one that would do something else entirely.
#[cfg(windows)]
pub fn record_command(version: &str) -> Option<String> {
    use crate::service::platform::SERVICE_NAME;

    if !version_is_writable(version) {
        return None;
    }

    Some(format!(
        "reg.exe add \"{}\" /v {VERSION_VALUE} /t REG_SZ /d \"{}\" /f",
        install_owner::owner_key_full_path(SERVICE_NAME),
        version
    ))
}

#[cfg(test)]
mod tests {
    use super::{version_file_path, version_is_writable, VERSION_FILE};
    use crate::service::platform::install_owner::{STATE_DIR, STATE_ROOT};
    use std::path::Path;

    /// The record lives beside the account record, in a directory of its own under a root
    /// that belongs to root — never somewhere a local account could put a file of its own.
    #[test]
    fn the_record_lives_beside_the_account_record() {
        let path = version_file_path(Path::new(STATE_ROOT));

        assert_eq!(
            path,
            Path::new(STATE_ROOT).join(STATE_DIR).join(VERSION_FILE)
        );
        assert!(
            path.starts_with("/var/"),
            "the record must not sit in a world-writable directory: {path:?}"
        );
    }

    /// The name is derived rather than spelled out, so the two halves cannot drift apart.
    #[test]
    fn the_record_name_is_derived_from_the_directory() {
        let path = version_file_path(Path::new("/somewhere/else"));

        assert_eq!(
            path,
            Path::new("/somewhere/else")
                .join(STATE_DIR)
                .join(VERSION_FILE)
        );
    }

    /// A version goes into a batch file on Windows, where a quote opens a command and a `%`
    /// starts an environment variable. A version carrying either is refused rather than
    /// written: the install would then do something other than record the version.
    #[test]
    fn a_version_that_cannot_be_written_is_refused() {
        assert!(version_is_writable("1.0.0"));
        assert!(version_is_writable("1.0.0-rc.1"));

        assert!(!version_is_writable(""));
        assert!(!version_is_writable("1.0.0\" & del C:\\"));
        assert!(!version_is_writable("1.0.0%PATH%"));
    }
}

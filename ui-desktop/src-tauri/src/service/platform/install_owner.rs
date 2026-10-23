//! The account the service was installed for.
//!
//! The service's actions are the machine's — the TUN device, the machine-wide
//! routes, the DNS hijack — so it must serve one account and refuse the rest.
//! Which account that is has to be recorded somewhere the unprivileged desktop
//! cannot rewrite, because the desktop is the thing that would benefit from a
//! rewrite.
//!
//! The record is written by the *install*, which is the one privileged moment
//! in the desktop's life, and read by the *service* when it starts:
//!
//! * **Unix** — a file under `/var/lib`, owned by root, in a directory owned
//!   by root. The install runs as root, so the file it writes is root's; the
//!   service reads it back only if it still is.
//! * **Windows** — a value in the service's own registry key under `HKLM`,
//!   which the service control manager creates with a security descriptor
//!   that admits SYSTEM and the administrators and nobody else. There is no
//!   file here because there is no root-owned directory on Windows that a
//!   service may write into without a security descriptor of its own, and the
//!   registry key the service already has is that place.
//!
//! A service with no record does not serve everybody: it falls back to
//! requiring the peer to own the token it answered with, and says so loudly.
//! See [`crate::service::platform::account::allows`].

use std::path::{Path, PathBuf};

use crate::service::platform::account::AccountId;

/// The directory the service's own state lives in.
pub const STATE_DIR: &str = "nexapipe";

/// The file inside it that names the account the service was installed for.
pub const OWNER_FILE: &str = "service-owner";

/// The root the state directory lives under.
///
/// `/var/lib` is root-owned on both Unix platforms the desktop ships for, and
/// neither of them lets anybody else create a directory in it — which is what
/// makes the record below it something a local account cannot replace.
pub const STATE_ROOT: &str = "/var/lib";

/// `<root>/nexapipe/service-owner`.
///
/// Derived rather than spelled out, so that the naming can be checked without
/// a root to install into.
pub fn owner_file_path(root: &Path) -> PathBuf {
    root.join(STATE_DIR).join(OWNER_FILE)
}

/// The registry key the service's own configuration lives in, below `HKLM`.
pub fn owner_key_path(service_name: &str) -> String {
    format!(r"SYSTEM\CurrentControlSet\Services\{service_name}")
}

/// The same key, spelled the way `reg.exe` wants it.
pub fn owner_key_full_path(service_name: &str) -> String {
    format!(r"HKLM\{}", owner_key_path(service_name))
}

/// The name of the value the install writes into the service's own key.
pub const OWNER_VALUE: &str = "ServiceOwner";

/// The account the service was installed for, when one is on file.
///
/// `None` when there is no record, when the record cannot be read, or when
/// the record is not where it has to be to be worth reading — a file that
/// somebody else owns, or one in a directory somebody else can write into, is
/// not a record of anything.
pub fn read_installed_by() -> Option<AccountId> {
    #[cfg(unix)]
    {
        read_installed_by_unix()
    }
    #[cfg(windows)]
    {
        read_installed_by_windows()
    }
}

/// Records the account the service is being installed for.
///
/// Unix only: the write happens in the privileged install itself, which is the
/// only place the file can be created with root's ownership. On Windows the
/// record is written by the elevated batch instead — see the Windows-only
/// `record_command` — because the process that asks for the install is not the
/// privileged one.
#[cfg(unix)]
pub fn record_installed_by(account: &AccountId) -> Result<(), crate::error::AppError> {
    use crate::error::{codes, AppError};
    use std::os::unix::fs::PermissionsExt;

    let path = owner_file_path(Path::new(STATE_ROOT));
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
    // Root's, and not writable by anybody else: a directory another account
    // owns is a directory the file inside it can be replaced in.
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).map_err(|e| {
        AppError::cause(
            codes::SERVICE_DEFINITION_FAILED,
            format!("cannot set the mode of {}: {e}", directory.display()),
        )
    })?;

    write_record_atomically(&path, directory, account.to_text().as_bytes())
}

/// Writes the record, and leaves no half-written one behind.
///
/// The file used to be opened with `truncate(true)`, which empties it at the
/// open — before a single byte of the new account is written. A write that
/// then failed, or an install that was interrupted, left an **empty** record
/// on disk; an empty record reads as "no record at all", and "no record" is
/// the degraded mode the record exists to prevent: the service falls back to
/// serving every local account that owns a token.
///
/// So the record is written to a temporary file in the same directory, the
/// bytes are flushed to the disk, and the temporary file is renamed over the
/// target. The rename is atomic, so a reader sees either the old record or
/// the new one and never an empty file; the directory is flushed afterwards,
/// so the replacement survives a crash.
#[cfg(unix)]
fn write_record_atomically(
    path: &Path,
    directory: &Path,
    bytes: &[u8],
) -> Result<(), crate::error::AppError> {
    use crate::error::{codes, AppError};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // The name carries the process id, so two installs that overlap cannot
    // write over each other's temporary file.
    let temporary = directory.join(format!(".{OWNER_FILE}.{}.new", std::process::id()));

    let write = || -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o644);
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        // The bytes are on the disk before the name moves: a rename that
        // landed before the write did would publish a file full of nothing.
        file.sync_all()?;
        drop(file);
        // The mode is set on the temporary file, before the rename: a file
        // that is renamed into place keeps the mode it had, and the mode is
        // what says the record cannot be changed by anybody but root.
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    };

    if let Err(e) = write() {
        // The temporary file is not the record, and a leftover one is a file
        // nobody asked for.
        let _ = std::fs::remove_file(&temporary);
        return Err(AppError::cause(
            codes::SERVICE_DEFINITION_FAILED,
            format!("cannot write {}: {e}", path.display()),
        ));
    }

    // The directory is flushed too: the rename is what a reader sees, and
    // without the flush a crash could undo the replacement and leave the old
    // contents under the new name.
    if let Ok(handle) = std::fs::File::open(directory) {
        let _ = handle.sync_all();
    }

    Ok(())
}

/// Forgets the account the service was installed for.
///
/// Called by the uninstall: a service that is no longer installed has no
/// account to serve, and leaving the record behind would have the next
/// install's service inherit it.
#[cfg(unix)]
pub fn forget_installed_by() {
    let path = owner_file_path(Path::new(STATE_ROOT));
    let _ = std::fs::remove_file(&path);
}

/// The command the elevated install runs to write the record.
///
/// Windows only: the process that asks for the install is unprivileged, so
/// the write has to happen in the elevated batch file. The value lands in the
/// service's own registry key, which only SYSTEM and the administrators may
/// write.
#[cfg(windows)]
pub fn record_command(account: &AccountId) -> String {
    use crate::service::platform::SERVICE_NAME;

    format!(
        "reg.exe add \"{}\" /v {OWNER_VALUE} /t REG_SZ /d \"{}\" /f",
        owner_key_full_path(SERVICE_NAME),
        account.to_text()
    )
}

/// The account the service was installed for, read off the root-owned file.
#[cfg(unix)]
fn read_installed_by_unix() -> Option<AccountId> {
    let path = owner_file_path(Path::new(STATE_ROOT));
    if !is_root_owned(&path) {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    AccountId::parse(&text)
}

/// Whether a file is root's, and is in a directory root's.
///
/// Both halves matter. A file root owns but that sits in a directory another
/// account can write into can be replaced by that account, and a file in a
/// directory root owns but that another account owns is a file that account
/// wrote.
#[cfg(unix)]
fn is_root_owned(path: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return false;
    }

    let Some(directory) = path.parent() else {
        return false;
    };
    let Ok(metadata) = std::fs::metadata(directory) else {
        return false;
    };
    metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0
}

/// The account the service was installed for, read off the service's own
/// registry key.
#[cfg(windows)]
fn read_installed_by_windows() -> Option<AccountId> {
    use crate::service::platform::SERVICE_NAME;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

    let key: Vec<u16> = owner_key_path(SERVICE_NAME)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let value: Vec<u16> = OWNER_VALUE
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Safe: both names are null-terminated, and the buffer is sized by the
    // call itself.
    unsafe {
        let mut size: u32 = 0;
        let status = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        );
        if status != WIN32_ERROR(0) || size == 0 {
            return None;
        }

        let mut buffer = vec![0u16; (size as usize / 2) + 1];
        let mut read: u32 = 0;
        let status = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            Some(&mut read),
        );
        if status != WIN32_ERROR(0) {
            return None;
        }

        // The size the call reports includes the terminator.
        let units = (read as usize / 2).saturating_sub(1);
        AccountId::parse(&String::from_utf16_lossy(&buffer[..units]))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        owner_file_path, owner_key_full_path, owner_key_path, OWNER_FILE, OWNER_VALUE, STATE_DIR,
        STATE_ROOT,
    };
    use std::path::Path;

    /// The record lives in a directory of its own, under a root that belongs
    /// to root — never directly in the root, and never somewhere a local
    /// account could put a file of its own.
    #[test]
    fn the_record_lives_under_a_root_nobody_else_owns() {
        let path = owner_file_path(Path::new(STATE_ROOT));

        assert_eq!(
            path.parent().unwrap(),
            Path::new(STATE_ROOT).join(STATE_DIR)
        );
        assert_eq!(path.file_name().unwrap(), OWNER_FILE);
        assert!(
            path.starts_with("/var/"),
            "the record must not sit in a world-writable directory: {path:?}"
        );
    }

    /// The name is derived rather than spelled out, so that the two halves
    /// cannot drift apart.
    #[test]
    fn the_record_name_is_derived_from_the_directory() {
        let path = owner_file_path(Path::new("/somewhere/else"));

        assert_eq!(
            path,
            Path::new("/somewhere/else")
                .join("nexapipe")
                .join("service-owner")
        );
    }

    /// On Windows the record is a value in the service's own registry key,
    /// which the service control manager creates for SYSTEM and the
    /// administrators only.
    #[test]
    fn the_windows_record_lives_in_the_services_own_key() {
        let key = owner_key_path("nexa-service");

        assert!(key.starts_with(r"SYSTEM\CurrentControlSet\Services\"));
        assert!(key.ends_with("nexa-service"));
        assert_eq!(owner_key_full_path("nexa-service"), format!(r"HKLM\{key}"));
        assert_eq!(OWNER_VALUE, "ServiceOwner");
    }
}

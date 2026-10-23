//! The token file: how it is written, how it is read, and who may read it.

use super::path::token_path;
use super::secret::generate_token;
use crate::error::{codes, AppError};
use std::io::ErrorKind;
use std::path::Path;

/// The token this desktop session uses, generating one if there is none yet.
///
/// Called by the UI before its first IPC request. An existing file is reused so
/// two windows agree; a missing one is created unreadable to anybody else.
pub fn ensure_token() -> Result<String, AppError> {
    ensure_token_at(&token_path())
}

/// [`ensure_token`] against an explicit path.
pub fn ensure_token_at(path: &Path) -> Result<String, AppError> {
    let parent = path.parent().ok_or_else(|| {
        AppError::with_detail(
            codes::SERVICE_IPC_TOKEN,
            "token path has no parent directory",
        )
    })?;
    // The directory that holds the token must not be writable by group or
    // other, whatever the umask says: `create_dir_all` would leave it at 0777
    // minus the umask, which is 0775 under a umask of 002 — and a
    // group-writable directory is one the service refuses to read a token
    // from, so the desktop would be locked out of its own service. The mode
    // is asked for instead, and the umask can only take bits away from it.
    create_private_dir(parent).map_err(|e| {
        AppError::cause(
            codes::SERVICE_IPC_TOKEN,
            format!("cannot create {parent:?}: {e}"),
        )
    })?;

    match std::fs::read_to_string(path) {
        Ok(existing) => {
            let token = existing.trim().to_string();
            if token.is_empty() {
                return Err(AppError::with_detail(
                    codes::SERVICE_IPC_TOKEN,
                    format!("{path:?} is empty"),
                ));
            }
            reject_world_readable(path)?;
            Ok(token)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let token = generate_token()?;
            write_private(path, &token).map_err(|e| {
                AppError::cause(
                    codes::SERVICE_IPC_TOKEN,
                    format!("cannot write {path:?}: {e}"),
                )
            })?;
            Ok(token)
        }
        Err(e) => Err(AppError::cause(
            codes::SERVICE_IPC_TOKEN,
            format!("cannot read {path:?}: {e}"),
        )),
    }
}

/// Creates the directory that holds the token, private to its owner.
///
/// The umask cannot make a directory more private than it was asked to be,
/// but it can leave it less private than the service insists on — so the mode
/// is asked for rather than inherited.
#[cfg(unix)]
pub(super) fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    // The parents are made with the mode the system would give them; only the
    // directory that holds the secret is asked to be private.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        // It was already there — possibly left by an older build that made it
        // with `create_dir_all`, which leaves it at 0777 minus the umask.
        // Under a umask of 002 that is 0775, and the service then refuses the
        // token it is reading, so the account that owns the directory is
        // locked out of its own service until it runs `chmod` by hand and
        // finds the warning in the service log first.
        //
        // The directory is the account's own, so it may be tightened: the
        // mode the service insists on is asked for. A directory somebody else
        // owns is left exactly as it is — that one is the service's rule to
        // refuse, not this one's to change.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => tighten_private_dir(path),
        Err(e) => Err(e),
    }
}

/// Tightens a directory the account owns to the mode the service insists on.
///
/// Only a directory this account owns is touched, and only when it is
/// writable by group or other: a directory that is already private keeps the
/// mode it has, so a stricter one set by hand survives.
///
/// A directory that cannot be stat'ed is not touched, and the error is
/// reported: the caller asked for a directory it could not make private, and
/// saying so is better than a token written into a directory whose mode
/// nobody knows.
#[cfg(unix)]
fn tighten_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    // A symlink is not a directory, and following it would tighten whatever
    // it points at rather than the name the token is written under.
    if !metadata.is_dir() {
        return Ok(());
    }
    // Not ours: the service's rule to refuse, not this one's to change.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Ok(());
    }
    // Already private — a stricter mode than the one asked for is kept.
    if metadata.permissions().mode() & 0o022 == 0 {
        return Ok(());
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// The token's directory on Windows is the account's own, and its access is
/// the file's own ACL rather than a mode bit.
#[cfg(not(unix))]
pub(super) fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

/// The token at `path`, read without creating one — the looking half of
/// [`ensure_token_at`], which creates one when there is none.
pub fn read_token_at(path: &Path) -> Result<Option<String>, AppError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let token = contents.trim().to_string();
            if token.is_empty() {
                return Ok(None);
            }
            reject_world_readable(path)?;
            Ok(Some(token))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AppError::cause(
            codes::SERVICE_IPC_TOKEN,
            format!("cannot read {path:?}: {e}"),
        )),
    }
}

/// A token anybody could read is the same as no token at all, so it is refused
/// rather than trusted — and loudly, because the fix is to delete the file.
fn reject_world_readable(path: &Path) -> Result<(), AppError> {
    match permissions(path) {
        Some(mode) if mode & 0o077 != 0 => Err(AppError::with_detail(
            codes::SERVICE_IPC_TOKEN,
            format!(
                "{path:?} is readable by other accounts (mode {mode:o}); delete it so it is \
                 regenerated private"
            ),
        )),
        _ => Ok(()),
    }
}

/// Writes `content` to a file only the creating account can read.
fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())
    }

    #[cfg(windows)]
    {
        // A Windows file has no mode of its own: it inherits whatever its
        // directory grants, and the token directory here is under LOCALAPPDATA,
        // which is per-user but still readable by anything running as that user —
        // including the elevated service this token exists to authenticate. So
        // the file is written and then given an explicit DACL.
        //
        // `OW` (owner rights) rather than a fixed account: the token is written
        // by whichever account first runs the app, and `SYSTEM` (`SY`) and the
        // administrators group (`BA`) need to read it too — the service runs as
        // LocalSystem and reads every session's candidate. Everyone else is
        // refused. `FA` is "all rights", which for these three is the whole point.
        //
        // Not `CO` (creator owner): Windows swaps that placeholder for the
        // creator's SID only in ACEs a child *inherits*. Set directly, as here, it
        // stays `S-1-3-0`, matches no token, and leaves the user who wrote the
        // file unable to read it back.
        const SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

        std::fs::write(path, content.as_bytes())?;
        restrict_to_owner_system_and_admins(path, SDDL)
    }

    #[cfg(not(any(unix, windows)))]
    {
        std::fs::write(path, content.as_bytes())
    }
}

/// Replaces `path`'s DACL with `sddl`.
///
/// Best-effort by design: a token that cannot be given an ACL is still a token,
/// and refusing to write one at all would leave the app unable to reach its own
/// service over a permission problem the user cannot act on. What is refused is
/// the *silent* part — the caller is told, and the read path checks what it can
/// (`reject_world_readable` is a no-op here, so this log line is the only trace).
#[cfg(windows)]
fn restrict_to_owner_system_and_admins(path: &Path, sddl: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    unsafe {
        // The out-parameter is a raw pointer, not a reference: the API fills it
        // in and the descriptor is then owned by this function, not by Rust.
        let mut descriptor: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|e| {
            std::io::Error::other(format!(
                "cannot parse the token ACL ({e:?}, os error {})",
                GetLastError().0
            ))
        })?;

        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        // `SetFileSecurityW` takes the descriptor directly, so the file is never
        // opened with `WRITE_DAC` — one less thing that can fail first.
        //
        // `PROTECTED_DACL_SECURITY_INFORMATION` is what makes the SDDL's `D:P`
        // mean anything: without it the DACL set here is merged with whatever the
        // directory would have inherited, which is the state this whole function
        // exists to remove.
        let result = SetFileSecurityW(
            PCWSTR(wide.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
        .ok();

        // The descriptor is not owned by the file, and this runs on both the
        // success and the failure path.
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));

        if let Err(e) = result {
            tracing::warn!(
                "{} keeps the ACL its directory gave it: {e:?} (os error {})",
                path.display(),
                GetLastError().0
            );
        }
        Ok(())
    }
}

/// Unix permission bits of `path`, when this platform has them.
///
/// `None` on Windows, where a file inherits whatever the directory grants
/// rather than carrying a mode of its own.
fn permissions(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).ok().map(|m| m.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

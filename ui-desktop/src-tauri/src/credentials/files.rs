use std::path::Path;

use crate::error::{codes, AppError};

/// Refuses to go on reading a file another account could have read.
///
/// The store and the fallback master key are written `0600`, but writing a file
/// privately and *reading* one privately are separate decisions, and only the
/// first was ever made here: the read paths had no check at all, so a store
/// copied off a backup, restored from an archive that does not keep modes, or
/// left behind by an older build was decrypted like any other. On the platforms
/// where the master key lives in this file rather than the keychain, reading it
/// at all hands over every credential in the store — the file *is* the key.
///
/// So the check is on the read, and it refuses rather than warns: a store
/// another account can read is not a store worth decrypting, and the fix is one
/// `chmod`, which the error says.
///
/// Unix only. Windows has no mode bits, and the equivalent there is an ACL —
/// see the service token, which is where the ACL is set.
#[cfg(unix)]
pub(super) fn reject_readable_by_others(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;

    // `metadata` and not `symlink_metadata`: a symlink is followed by the read
    // that follows, so it is the file it points at whose mode decides whether
    // this passes — `lstat` would report a link's own `0777` and refuse every
    // symlinked store. Unreadable metadata is treated as a pass, because the read
    // itself is about to fail with a better message than this one would give.
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode();

    if mode & 0o077 != 0 {
        return Err(AppError::with_detail(
            codes::CREDENTIALS_STORE_FAILED,
            format!(
                "{} is readable by other accounts (mode {mode:o}); chmod 600 it, or delete it \
                 so a private one is written",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// No mode bits to check. See the Unix half.
#[cfg(not(unix))]
pub(super) fn reject_readable_by_others(_path: &Path) -> Result<(), AppError> {
    Ok(())
}

pub(super) fn write_private(path: &Path, contents: &str) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents.as_bytes())
            .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))
    }
}

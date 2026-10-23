//! Putting the service binary where the service manager may run it.
//!
//! A system daemon's program is the one file on the machine that the local accounts
//! must not be able to replace: the service runs it as root, and a program another
//! account can rewrite is a program another account owns. So the install copies the
//! binary out of where the app keeps it into a directory only root can write, checks
//! that the copy is the file it was asked to copy, and points the service manager at
//! that.
//!
//! The copy is also what makes an upgrade mean anything: the app can be replaced under
//! the service manager's feet — launchd and systemd both read a job definition once, and
//! neither notices that the file behind it changed — but the copy is rewritten by the
//! next install, so the service manager runs a binary the install put there.

use crate::error::{codes, AppError};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Whether two files hold the same bytes.
///
/// By content and not by size: a copy that was cut short is exactly the failure this
/// exists to catch, and a size alone would not catch it.
pub fn files_match(left: &Path, right: &Path) -> Result<bool, AppError> {
    Ok(digest(left)? == digest(right)?)
}

/// The SHA-256 of a file's contents.
fn digest(path: &Path) -> Result<[u8; 32], AppError> {
    use std::io::Read;

    let mut file = fs::File::open(path).map_err(|e| {
        AppError::cause(
            codes::SERVICE_IO_ERROR,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;

    // Read in chunks: the binary is tens of megabytes, and the digest is over the
    // contents rather than over the file in one piece.
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|e| {
            AppError::cause(
                codes::SERVICE_IO_ERROR,
                format!("cannot read {}: {e}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().into())
}

/// Copies a binary to where the service manager runs it from, and checks that the copy
/// is the file it was asked to copy.
///
/// The copy is made under a temporary name and renamed over the destination, so a copy
/// that fails leaves the previous binary in place rather than a half-written one — the
/// service manager may be running that previous one at this very moment.
///
/// The destination's *directory* is not touched: what that directory looks like is the
/// platform's business — a root-owned one on Unix, an ACL on Windows — and the caller
/// is the one that knows.
pub fn copy_verified(source: &Path, destination: &Path) -> Result<(), AppError> {
    let directory = destination.parent().ok_or_else(|| {
        AppError::with_detail(
            codes::SERVICE_DEFINITION_FAILED,
            format!("{} has no parent directory", destination.display()),
        )
    })?;

    fs::create_dir_all(directory).map_err(|e| {
        AppError::cause(
            codes::SERVICE_DEFINITION_FAILED,
            format!("cannot create {}: {e}", directory.display()),
        )
    })?;

    let temporary = directory.join(format!(
        ".{}.{}.new",
        file_name(destination),
        std::process::id()
    ));

    let copied = (|| -> Result<(), AppError> {
        fs::copy(source, &temporary).map_err(|e| {
            AppError::cause(
                codes::SERVICE_DEFINITION_FAILED,
                format!(
                    "cannot copy {} to {}: {e}",
                    source.display(),
                    temporary.display()
                ),
            )
        })?;
        set_mode(&temporary, 0o755)?;
        // Windows' rename does not replace an existing file, so the previous copy is
        // removed there first. On Unix the rename replaces it atomically, which is why
        // the removal is not done there: a window in which neither copy is there is a
        // window in which the service has no program to run.
        #[cfg(windows)]
        let _ = fs::remove_file(destination);
        fs::rename(&temporary, destination).map_err(|e| {
            AppError::cause(
                codes::SERVICE_DEFINITION_FAILED,
                format!("cannot install {}: {e}", destination.display()),
            )
        })?;
        Ok(())
    })();

    if copied.is_err() {
        // A leftover temporary file is a file nobody asked for.
        let _ = fs::remove_file(&temporary);
    }
    copied?;

    if !files_match(source, destination)? {
        return Err(AppError::with_detail(
            codes::SERVICE_DEFINITION_FAILED,
            format!(
                "the copy at {} is not the file at {}",
                destination.display(),
                source.display()
            ),
        ));
    }

    Ok(())
}

/// The name of a file, or a placeholder when the path has none.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "service".to_string())
}

/// Sets a path's mode, so that the file it names is what it is meant to be.
#[cfg(unix)]
pub(super) fn set_mode(path: &Path, mode: u32) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
        AppError::cause(
            codes::SERVICE_DEFINITION_FAILED,
            format!("cannot set the mode of {}: {e}", path.display()),
        )
    })
}

/// Windows has no mode bits: the copy inherits what the directory it is written into
/// decides, and that is the directory's own ACL.
#[cfg(not(unix))]
pub(super) fn set_mode(_path: &Path, _mode: u32) -> Result<(), AppError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{copy_verified, files_match};
    use std::fs;
    use std::path::{Path, PathBuf};

    /// A file in the temporary directory, named after this process and the test.
    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nexa-service-copy-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    /// Two files with the same bytes are the same file, whatever they are called.
    #[test]
    fn the_same_bytes_are_the_same_file() {
        let left = scratch("left");
        let right = scratch("right");
        fs::write(&left, b"the service binary").expect("the left file");
        fs::write(&right, b"the service binary").expect("the right file");

        assert!(files_match(&left, &right).expect("the files are readable"));
        assert!(!files_match(&left, Path::new("/nonexistent/nexa")).is_ok());

        let _ = fs::remove_file(&left);
        let _ = fs::remove_file(&right);
    }

    /// A copy that was cut short is not the file it was copied from, and that is the
    /// failure the comparison exists to catch.
    #[test]
    fn a_truncated_copy_is_not_a_match() {
        let left = scratch("whole");
        let right = scratch("cut");
        fs::write(&left, b"the service binary").expect("the whole file");
        fs::write(&right, b"the service").expect("the cut file");

        assert!(!files_match(&left, &right).expect("the files are readable"));

        let _ = fs::remove_file(&left);
        let _ = fs::remove_file(&right);
    }

    /// The copy is checked against the file it was made from, so a copy that did not
    /// land is a failure rather than a service running the wrong binary.
    #[test]
    fn a_verified_copy_is_the_file_it_was_copied_from() {
        let source = scratch("source");
        let destination = scratch("destination").with_extension("bin");
        fs::write(&source, b"the service binary").expect("the source");

        copy_verified(&source, &destination).expect("the copy lands");

        assert!(files_match(&source, &destination).expect("the files are readable"));
        assert_eq!(
            destination.metadata().expect("the copy is there").len(),
            source.metadata().expect("the source is there").len()
        );

        let _ = fs::remove_file(&source);
        let _ = fs::remove_file(&destination);
    }
}

//! The shared secret an IPC client must present before the service obeys it.
//!
//! `ServiceRunner` listens on a loopback TCP port and runs elevated — SYSTEM on
//! Windows, root under systemd/launchd — while every IPC message is either
//! harmless (`GetStatus`) or drastic (`StartProxy` with `use_tun`, which takes
//! over routing and DNS). Nothing about a loopback socket identifies its peer,
//! so a message arriving here used to be obeyed on trust: **any** process the
//! user ran could ask the elevated service to rewrite that user's routing
//! table. The token is what replaces that trust.
//!
//! # Who owns the token
//!
//! The **UI process** holds it, not the service. That direction matters:
//!
//! * The token has to live somewhere both sides can read. Writing it into the
//!   user's own directory means the ordinary filesystem permissions already say
//!   the right thing — readable by that user plus the elevated accounts that
//!   can read anything anyway — whereas a file the service created would either
//!   be unreadable to the UI or readable to every other user.
//! * It also means the file appears when somebody actually runs the desktop
//!   app, and its absence is a meaningful answer: nobody has asked for the
//!   service yet, so nothing gets obeyed.
//!
//! The service therefore only ever *reads* it, and does so per connection so a
//! regenerated token takes effect without a restart.

use crate::error::{codes, AppError};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Bytes of entropy in a token.
const TOKEN_BYTES: usize = 32;

/// Overrides [`token_path`], used by installs that keep runtime state somewhere
/// unusual. Both processes have to see the same value.
pub const TOKEN_PATH_ENV: &str = "NEXAPIPE_IPC_TOKEN_FILE";

/// Directory holding the token, relative to the base directory below.
const TOKEN_DIR: &str = "nexapipe";
/// File name of the token.
const TOKEN_FILE: &str = "ipc.token";

/// Where the token file lives.
///
/// Kept inside the user's own state on purpose (see the module docs): the UI
/// process — which runs unprivileged — writes it, and the elevated service
/// reads it. `$XDG_RUNTIME_DIR` is the preferred spelling because it is already
/// `0700` and owned by the user; the fallbacks cover platforms that do not
/// define it.
pub fn token_path() -> PathBuf {
    match std::env::var(TOKEN_PATH_ENV) {
        Ok(path) if !path.trim().is_empty() => return PathBuf::from(path),
        _ => {}
    }

    #[cfg(windows)]
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());

    #[cfg(not(windows))]
    let base = match std::env::var("XDG_RUNTIME_DIR") {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => std::env::var("HOME")
            .map(|home| PathBuf::from(home).join(".cache"))
            .unwrap_or_else(|_| std::env::temp_dir()),
    };

    base.join(TOKEN_DIR).join(TOKEN_FILE)
}

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
        AppError::with_detail(codes::SERVICE_IPC_TOKEN, "token path has no parent directory")
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
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
            let token = generate_token();
            write_private(path, &token).map_err(|e| {
                AppError::cause(codes::SERVICE_IPC_TOKEN, format!("cannot write {path:?}: {e}"))
            })?;
            Ok(token)
        }
        Err(e) => Err(AppError::cause(
            codes::SERVICE_IPC_TOKEN,
            format!("cannot read {path:?}: {e}"),
        )),
    }
}

/// The token a caller has to present, when one has been published.
///
/// `None` is not "authentication is off": it means no desktop session has
/// published a token, so there is no legitimate caller and every privileged
/// message gets refused.
///
/// Looks past [`token_path`] because the service may not resolve that path the
/// way the desktop session does — see [`service_token_paths`].
pub fn read_token() -> Result<Option<String>, AppError> {
    for candidate in service_token_paths() {
        if let Some(token) = read_token_at(&candidate)? {
            return Ok(Some(token));
        }
    }
    Ok(None)
}

/// Every place the service looks for a token, in order.
///
/// [`token_path`] is first because it is right whenever the service runs as the
/// account that installed it — a launchd/systemd user agent, or a dev build —
/// and the Windows branch below exists because on Windows it is not: the
/// service is created by `sc create` without an `obj=`, so it runs as
/// LocalSystem, whose `LOCALAPPDATA` is the system profile rather than the
/// profile the desktop app wrote into. LocalSystem can open a file inside any
/// user's profile, so each profile is a candidate; the token itself never moves
/// somewhere more widely readable just to make it findable.
fn service_token_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match std::env::var(TOKEN_PATH_ENV) {
        Ok(path) if !path.trim().is_empty() => paths.push(PathBuf::from(path)),
        _ => {}
    }
    paths.push(token_path());

    #[cfg(windows)]
    paths.extend(profile_token_paths());

    paths
}

/// `<Users>\<profile>\AppData\Local\nexapipe\ipc.token` for every profile on
/// the machine, best effort.
#[cfg(windows)]
fn profile_token_paths() -> Vec<PathBuf> {
    // `%USERPROFILE%` is `C:\Users\<name>` when the service has one at all; its
    // parent is the profiles root. Anything unexpected just yields nothing, and
    // the service then fails closed with "no token on file".
    let Ok(profile) = std::env::var("USERPROFILE") else {
        return Vec::new();
    };
    let Some(profiles_root) = Path::new(&profile).parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(profiles_root) else {
        return Vec::new();
    };

    entries
        .filter_map(Result::ok)
        .map(|entry| {
            entry
                .path()
                .join("AppData")
                .join("Local")
                .join(TOKEN_DIR)
                .join(TOKEN_FILE)
        })
        .collect()
}

/// [`read_token`] against an explicit path.
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

/// Whether `presented` is the expected token.
///
/// Length-tolerant but otherwise constant-time: nothing in the timing is worth
/// attacking when the token is 256 bits, but there is no reason to hand out the
/// leading bytes for free either.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    if expected.len() != presented.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.as_bytes().iter().zip(presented.as_bytes()) {
        diff |= a ^ b;
    }
    diff == 0
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

fn generate_token() -> String {
    let mut token = String::with_capacity(TOKEN_BYTES * 2);
    for _ in 0..TOKEN_BYTES {
        token.push_str(&format!("{:02x}", fastrand::u8(..)));
    }
    token
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

    #[cfg(not(unix))]
    {
        std::fs::write(path, content.as_bytes())
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
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_token_at, read_token_at, service_token_paths, token_matches};
    use std::path::PathBuf;

    /// Every test gets its own file, so none of them can see the others' state.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nexapipe-ipc-{}-{}", name, fastrand::u64(..)));
        dir.join("ipc.token")
    }

    #[test]
    fn a_generated_token_reads_back_identical() {
        let path = scratch("roundtrip");

        let token = ensure_token_at(&path).unwrap();
        assert_eq!(token.len(), 64, "32 bytes render as 64 hex characters");
        assert_eq!(
            read_token_at(&path).unwrap().as_deref(),
            Some(token.as_str())
        );

        // Called again, the existing token is reused rather than rotated.
        assert_eq!(ensure_token_at(&path).unwrap(), token);
    }

    #[test]
    fn a_missing_token_file_means_nobody_authenticated_yet() {
        assert_eq!(read_token_at(&scratch("absent")).unwrap(), None);
    }

    #[test]
    fn an_empty_token_file_means_nobody_authenticated_yet() {
        let path = scratch("empty");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "\n").unwrap();

        assert_eq!(read_token_at(&path).unwrap(), None);
    }

    /// Whatever the platform, the desktop session's own path is always among
    /// the candidates — otherwise the service would never find a freshly
    /// generated token on a machine where it runs as the installing account.
    #[test]
    fn the_desktop_session_path_is_a_service_candidate() {
        let path = scratch("candidates");
        let token = ensure_token_at(&path).unwrap();
        std::env::set_var(super::TOKEN_PATH_ENV, &path);

        let candidates = service_token_paths();
        assert_eq!(candidates.first().map(PathBuf::as_path), Some(path.as_path()));
        assert_eq!(
            super::read_token().unwrap().as_deref(),
            Some(token.as_str())
        );

        std::env::remove_var(super::TOKEN_PATH_ENV);
    }

    #[test]
    fn matching_only_happens_for_the_whole_token() {
        assert!(token_matches("abc123", "abc123"));
        assert!(!token_matches("abc123", "abc124"));
        assert!(!token_matches("abc123", "abc1234"));
        assert!(!token_matches("abc123", "ABC123"));
    }
}

//! Where the token file lives.

use super::{TOKEN_DIR, TOKEN_FILE};
use std::path::PathBuf;

/// Overrides [`token_path`], used by installs that keep runtime state somewhere
/// unusual. Both processes have to see the same value.
pub const TOKEN_PATH_ENV: &str = "NEXAPIPE_IPC_TOKEN_FILE";

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

/// A file in the app's per-user runtime directory, beside the token.
///
/// The single-instance guard's files live here too: the token is what the
/// elevated service reads, and the guard is what keeps a second copy of the
/// app from starting. Both are per-user state, and one directory keeps them
/// together — and keeps them apart from each other, because they are
/// different files that never touch the same bytes.
pub fn runtime_file(name: &str) -> PathBuf {
    let token = token_path();
    match token.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => PathBuf::from(name),
    }
}

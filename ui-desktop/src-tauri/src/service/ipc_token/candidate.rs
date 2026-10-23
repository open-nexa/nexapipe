//! Every token the service may find, and the account that owns each one.

use super::file::read_token_at;
use super::path::{token_path, TOKEN_PATH_ENV};
use super::{TOKEN_DIR, TOKEN_FILE};
use crate::error::AppError;
use crate::service::platform::account::{self, AccountId};
use std::path::{Path, PathBuf};

/// A token the service found, with the account that owns the file it came from.
///
/// The owner is part of the candidate rather than something looked up later,
/// because the whole question is which account a caller belongs to: a token
/// file found in another account's profile says nothing about the account that
/// presented it, and the service serves one account only.
#[derive(Debug, Clone)]
pub struct TokenCandidate {
    /// The token's value.
    pub token: String,
    /// The account that owns the file the token came from.
    pub owner: AccountId,
    /// Where it came from, for the log line that says which file answered.
    pub path: PathBuf,
}

/// Every token that has been published, in the order [`service_token_paths`] finds them.
///
/// All of them, not just the first: on Windows the service scans every profile on the machine
/// because a loopback socket says nothing about which account dialled it, so which candidate
/// happens to come first tells it nothing about which token the caller holds. A caller is
/// legitimate when it presents one of them *and* it is the account the service was installed
/// for — see [`token_for_auth`](crate::service::ipc_token::token_for_auth) and
/// [`crate::service::platform::account::allows`].
pub fn read_candidates() -> Result<Vec<TokenCandidate>, AppError> {
    let mut candidates = Vec::new();
    for candidate in service_token_paths() {
        // A root service scans every desktop session candidate. One inaccessible profile must
        // not make every other session's valid token unusable.
        match read_candidate_at(&candidate) {
            Ok(Some(token)) => candidates.push(token),
            Ok(None) => {}
            Err(e) => {
                // A token file that is readable by other accounts is refused
                // rather than trusted, and the refusal is worth saying out
                // loud: the fix is to delete the file.
                tracing::warn!("Ignoring {candidate:?}: {e}");
            }
        }
    }
    Ok(candidates)
}

/// The token at `path` together with the account that owns it, when the file is
/// one the service is willing to read a secret from.
///
/// A file that cannot be attributed to an account is not a candidate: the
/// service would have no way to tell whose token it is holding, and a token
/// nobody can be attributed to is a token anybody may present.
pub fn read_candidate_at(path: &Path) -> Result<Option<TokenCandidate>, AppError> {
    let Some(token) = read_token_at(path)? else {
        return Ok(None);
    };

    let Some(owner) = AccountId::owner_of(path) else {
        tracing::warn!(
            "Ignoring {path:?}: its owner could not be read, so it cannot be attributed to an \
             account"
        );
        return Ok(None);
    };

    if !account::token_directory_is_trusted(path, &owner) {
        tracing::warn!(
            "Ignoring {path:?}: it is not in a directory a token may be read from, so another \
             account could have put it there"
        );
        return Ok(None);
    }

    Ok(Some(TokenCandidate {
        token,
        owner,
        path: path.to_path_buf(),
    }))
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
pub fn service_token_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match std::env::var(TOKEN_PATH_ENV) {
        Ok(path) if !path.trim().is_empty() => paths.push(PathBuf::from(path)),
        _ => {}
    }
    paths.push(token_path());

    #[cfg(windows)]
    paths.extend(profile_token_paths());

    #[cfg(not(windows))]
    paths.extend(unix_service_token_paths());

    paths
}

/// User-session token locations a root service can discover on Unix.
///
/// The desktop writes into `XDG_RUNTIME_DIR/nexapipe/ipc.token` on Linux and
/// `$HOME/.cache/nexapipe/ipc.token` on macOS, while an elevated service has a *root* runtime
/// directory — and launchd hands a LaunchDaemon neither `HOME` nor `XDG_RUNTIME_DIR`, so
/// [`token_path`] degrades to `/tmp/nexapipe/ipc.token` there. Scanning the per-session roots
/// keeps both sides on the same secret without moving a private token to a shared directory.
#[cfg(not(windows))]
fn unix_service_token_paths() -> Vec<PathBuf> {
    unix_service_token_paths_from(unix_home_roots())
}

/// Directories holding one home directory per user, per platform.
///
/// The two layouts are not interchangeable, and only one of them can be the roots for a given
/// kernel: `/run/user` and `/home` are a Linux layout, while a macOS home — the only place a
/// macOS desktop session ever writes a token — lives under `/Users`. Keeping the Linux pair as
/// the sole roots is how a LaunchDaemon came to answer "no desktop session has published an IPC
/// token" while that token sat in `/Users/<name>/.cache/nexapipe/ipc.token`; the service had no
/// candidate that could ever reach it.
#[cfg(not(windows))]
pub(super) fn unix_home_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    let roots: &[&str] = &["/Users"];

    #[cfg(not(target_os = "macos"))]
    let roots: &[&str] = &["/run/user", "/home"];

    roots.iter().map(PathBuf::from).collect()
}

#[cfg(not(windows))]
pub(super) fn unix_service_token_paths_from(
    roots: impl IntoIterator<Item = PathBuf>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };

        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            paths.push(path.join(TOKEN_DIR).join(TOKEN_FILE));
            paths.push(path.join(".cache").join(TOKEN_DIR).join(TOKEN_FILE));
        }
    }

    paths
}

/// `<profiles root>\<profile>\AppData\Local\nexapipe\ipc.token` for every profile found under
/// every plausible profiles root, best effort.
#[cfg(windows)]
fn profile_token_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    for root in profile_roots() {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };

        paths.extend(entries.filter_map(Result::ok).map(|entry| {
            entry
                .path()
                .join("AppData")
                .join("Local")
                .join(TOKEN_DIR)
                .join(TOKEN_FILE)
        }));
    }

    paths
}

/// Where user profiles live.
///
/// `USERPROFILE` is tried first because it is right whenever the service runs as the account
/// that installed it — a dev build, or a launchd/systemd user agent. Under **LocalSystem** it
/// is `C:\Windows\System32\config\systemprofile`, whose parent is the *config* directory and
/// not the profiles root: scanning the parent then yields nothing at all, which is exactly how
/// the service came to answer "no desktop session has published an IPC token" while the token
/// sat in `C:\Users\<name>\AppData\Local\nexapipe\ipc.token`. `PUBLIC` (`C:\Users\Public`) and
/// `%SystemDrive%\Users` both resolve to the real root for that account, so they are tried too.
#[cfg(windows)]
fn profile_roots() -> Vec<PathBuf> {
    profile_roots_from(
        std::env::var("USERPROFILE").ok().as_deref(),
        std::env::var("PUBLIC").ok().as_deref(),
        std::env::var("SystemDrive").ok().as_deref(),
    )
}

/// [`profile_roots`] over explicit inputs, so the LocalSystem case can be tested without
/// mutating the process environment.
#[cfg(windows)]
pub(super) fn profile_roots_from(
    user_profile: Option<&str>,
    public: Option<&str>,
    system_drive: Option<&str>,
) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut add = |root: PathBuf| {
        if !roots.contains(&root) {
            roots.push(root);
        }
    };

    if let Some(parent) = user_profile.and_then(|p| Path::new(p).parent()) {
        add(parent.to_path_buf());
    }
    if let Some(parent) = public.and_then(|p| Path::new(p).parent()) {
        add(parent.to_path_buf());
    }
    if let Some(drive) = system_drive {
        add(Path::new(drive).join("Users"));
    }

    roots
}

//! The shared secret an IPC client must present before the service obeys it.
//!
//! `ServiceRunner` listens on a socket and runs elevated — SYSTEM on Windows,
//! root under systemd/launchd — while every IPC message is either harmless
//! (`GetStatus`) or drastic (`StartProxy` with `use_tun`, which takes over
//! routing and DNS). Nothing about the connection identifies its peer, so a
//! message arriving here used to be obeyed on trust: **any** process the user
//! ran could ask the elevated service to rewrite that user's routing table.
//! The token is what replaces that trust, and the account behind the
//! connection is what says whose traffic it may carry.
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
//!
//! # Who may present it
//!
//! A token on its own says who *knows* it, not who may *use* it: the service
//! finds token files in every account's profile, so a token that is found says
//! nothing about the account that presented it. Every candidate therefore
//! carries the account that owns the file it came from, and the service serves
//! the account it was installed for and nobody else — see
//! [`crate::service::platform::account::allows`].
//!
//! A candidate is only read at all when the directory holding it is one a
//! secret may be read from: a directory another account can write into is a
//! directory it can put a token of its own into, and `/tmp` — where a service
//! with neither `HOME` nor `XDG_RUNTIME_DIR` ends up — is world-writable.

use crate::error::{codes, AppError};
use crate::service::platform::account::{self, AccountId};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Bytes of entropy in a token.
const TOKEN_BYTES: usize = 32;

/// Bytes of entropy in a handshake nonce.
///
/// A nonce is single-use and never leaves the connection it was made for, so it
/// needs only to be unpredictable — which is the same thing a token needs, and
/// comes from the same place.
pub const NONCE_BYTES: usize = 32;

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
fn create_private_dir(path: &Path) -> std::io::Result<()> {
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
/// A directory that cannot be stat'ed is left alone, and the error is
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
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

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
/// for — see [`token_for_auth`] and
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
fn unix_home_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    let roots: &[&str] = &["/Users"];

    #[cfg(not(target_os = "macos"))]
    let roots: &[&str] = &["/run/user", "/home"];

    roots.iter().map(PathBuf::from).collect()
}

#[cfg(not(windows))]
fn unix_service_token_paths_from(roots: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
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
fn profile_roots_from(
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

/// A fresh token, drawn from the OS CSPRNG.
///
/// `fastrand` used to be the source here. It is a fast non-cryptographic
/// generator seeded from the clock and ASLR, which is fine for a scratch
/// directory name and not for the one secret that decides who may drive an
/// elevated service: a token an attacker can predict is a token they can
/// present.
///
/// Public so a test in another module can hold a secret of the same shape
/// without writing a literal into a key slot.
pub fn generate_token() -> Result<String, AppError> {
    random_hex(TOKEN_BYTES)
}

/// A fresh handshake nonce.
///
/// The service sends one and the caller sends one; everything the handshake
/// proves is bound to the pair, so a captured answer cannot be replayed on
/// another connection.
pub fn random_nonce() -> Result<String, AppError> {
    random_hex(NONCE_BYTES)
}

/// `len` bytes from the OS CSPRNG, lowercase hex.
///
/// Hex rather than raw bytes because both a token and a nonce cross a
/// newline-delimited JSON channel, and the token file is a text file a human may
/// end up looking at.
fn random_hex(len: usize) -> Result<String, AppError> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|e| {
        AppError::cause(
            codes::SERVICE_IPC_TOKEN,
            format!("cannot read {len} random bytes from the OS: {e}"),
        )
    })?;

    let mut hex = String::with_capacity(len * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

/// What the caller answers a challenge with: HMAC-SHA256 over the service's
/// nonce followed by the caller's own.
///
/// Binding both nonces is what makes the answer single-use, and the caller's
/// nonce is what the service then has to answer back for — see [`proof_mac`].
pub fn auth_mac(token: &str, service_nonce: &str, caller_nonce: &str) -> String {
    mac_hex(token, service_nonce, caller_nonce)
}

/// What the service answers with, so the caller can tell it from a squatter on
/// the IPC port.
///
/// The nonces are the other way round so the two directions cannot produce the
/// same value: otherwise a caller that recorded the service's own challenge
/// answer could hand it back as proof.
pub fn proof_mac(token: &str, service_nonce: &str, caller_nonce: &str) -> String {
    mac_hex(token, caller_nonce, service_nonce)
}

/// Whether `presented` is what [`auth_mac`] produces for the caller's nonce
/// under any published token, and which candidate it was.
///
/// The candidate is returned rather than the bare token, because the service
/// has to know *whose* token answered: it computes its own proof under the
/// same one, and it refuses a caller that is not the account the token belongs
/// to.
pub fn token_for_auth<'a>(
    candidates: &'a [TokenCandidate],
    service_nonce: &str,
    caller_nonce: &str,
    presented: &str,
) -> Option<&'a TokenCandidate> {
    candidates.iter().find(|candidate| {
        constant_time_eq(
            &auth_mac(&candidate.token, service_nonce, caller_nonce),
            presented,
        )
    })
}

/// Whether `presented` is what [`proof_mac`] produces under `token`.
pub fn proof_matches(
    token: &str,
    service_nonce: &str,
    caller_nonce: &str,
    presented: &str,
) -> bool {
    constant_time_eq(&proof_mac(token, service_nonce, caller_nonce), presented)
}

/// HMAC-SHA256 of two nonces under a token, lowercase hex.
fn mac_hex(token: &str, first: &str, second: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    // HMAC accepts a key of any length, so this cannot fail.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(token.as_bytes()).expect("HMAC takes a key of any length");
    // The separator keeps two nonces from being ambiguous: both directions carry
    // the same pair, and "ab" + "c" must not hash like "a" + "bc".
    mac.update(first.as_bytes());
    mac.update(b".");
    mac.update(second.as_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Length-tolerant, otherwise constant-time comparison.
///
/// The same shape as [`token_matches`]: the length already differs, so nothing
/// is gained by hiding it, and comparing the leading bytes one by one is not
/// free information either.
fn constant_time_eq(expected: &str, presented: &str) -> bool {
    if expected.len() != presented.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.as_bytes().iter().zip(presented.as_bytes()) {
        diff |= a ^ b;
    }
    diff == 0
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

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::profile_roots_from;
    use super::{
        auth_mac, ensure_token_at, generate_token, proof_mac, proof_matches, random_nonce,
        read_token_at, service_token_paths, token_for_auth, TokenCandidate,
    };
    #[cfg(not(windows))]
    use super::{unix_home_roots, unix_service_token_paths_from};
    use crate::service::platform::account::AccountId;
    use std::path::PathBuf;

    /// A token for a test to authenticate with, minted the way the real one is.
    ///
    /// A literal would do — these tests only compare MACs against each other, so
    /// the value itself is irrelevant — but a constant sitting in the key slot is
    /// exactly what CWE-798 is about, and it would be the one place in the tree
    /// where the secret that decides who may drive the service is written down.
    fn fresh_token() -> String {
        generate_token().expect("the OS has randomness")
    }

    /// Every test gets its own file, so none of them can see the others' state.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nexapipe-ipc-{}-{}", name, fastrand::u64(..)));
        dir.join("ipc.token")
    }

    /// A scratch path for a test whose token the *service* has to accept.
    ///
    /// Not the temporary directory: that one is world-writable on Linux, and a
    /// token in a world-writable directory is exactly what the service refuses
    /// to read. A test that wants the service to accept its token has to put
    /// it somewhere the service would really look — under the package
    /// directory, whose chain no other account can write into.
    fn trusted_scratch(name: &str) -> PathBuf {
        let root = std::env::current_dir()
            .expect("the package directory")
            .join("target")
            .join("nexapipe-ipc-tests");
        std::fs::create_dir_all(&root).expect("the scratch root is created");
        root.join(format!("{}-{}", name, fastrand::u64(..)))
            .join("ipc.token")
    }

    /// A candidate holding `token`, owned by the account this test runs as.
    fn candidate(token: String) -> TokenCandidate {
        TokenCandidate {
            token,
            owner: AccountId::current().expect("this process has an account"),
            path: PathBuf::from("ipc.token"),
        }
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
        let path = trusted_scratch("candidates");
        let token = ensure_token_at(&path).unwrap();
        std::env::set_var(super::TOKEN_PATH_ENV, &path);

        let candidates = service_token_paths();
        assert_eq!(
            candidates.first().map(PathBuf::as_path),
            Some(path.as_path())
        );
        assert_eq!(
            super::read_candidates()
                .unwrap()
                .first()
                .map(|candidate| candidate.token.as_str()),
            Some(token.as_str())
        );

        std::env::remove_var(super::TOKEN_PATH_ENV);
    }

    /// A token the service reads comes with the account that owns the file it
    /// was read from — that account is what the service compares against the
    /// one on the other end of the socket.
    #[test]
    fn a_candidate_carries_the_owner_of_its_file() {
        let path = trusted_scratch("owner");
        let token = ensure_token_at(&path).unwrap();

        let candidate = super::read_candidate_at(&path)
            .unwrap()
            .expect("the token is a candidate");

        assert_eq!(candidate.token, token);
        assert_eq!(candidate.owner, AccountId::current().unwrap());
        assert_eq!(candidate.path, path);
    }

    /// A directory the desktop owns and that an older build left writable by
    /// others is tightened, so that the account is not locked out of its own
    /// service.
    ///
    /// Older builds made the directory with `create_dir_all`, which leaves it
    /// at 0777 minus the umask — 0775 under the umask of 002 that a
    /// user-private-group account has. The service refuses a token in such a
    /// directory, and the only sign of that was a warning in the service log
    /// that the account had to find and act on by hand.
    #[cfg(unix)]
    #[test]
    fn a_directory_the_desktop_owns_is_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("nexapipe-open-{}", fastrand::u64(..)));
        std::fs::create_dir_all(&dir).unwrap();
        // The mode an older build left behind: writable by group and other.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();

        let path = dir.join("ipc.token");
        ensure_token_at(&path).unwrap();

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "a directory the account owns must be made private to it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A token in a directory another account can write into is not a
    /// candidate at all: the service would be reading a file that account
    /// could have put there.
    ///
    /// The directory the desktop owns is tightened, but the directory *above*
    /// it is not the desktop's to change — and one that is world-writable
    /// lets another account replace the directories below it, which would
    /// make the rule about the token's own directory a statement about a
    /// directory the attacker owns.
    #[cfg(unix)]
    #[test]
    fn a_token_in_a_world_writable_directory_is_not_a_candidate() {
        use std::os::unix::fs::PermissionsExt;

        // `/tmp` is world-writable on both platforms the desktop ships for,
        // and it is the case that matters: it is where a service with neither
        // `HOME` nor `XDG_RUNTIME_DIR` ends up.
        let root = std::path::Path::new("/tmp");
        assert!(
            std::fs::metadata(root)
                .map(|m| m.permissions().mode() & 0o002 != 0)
                .unwrap_or(false),
            "this test needs a world-writable directory to sit in"
        );

        let dir = root.join(format!("nexapipe-open-{}", fastrand::u64(..)));
        std::fs::create_dir_all(&dir).unwrap();
        // The mode the service refuses: writable by group and other.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let path = dir.join("ipc.token");
        ensure_token_at(&path).unwrap();

        assert!(
            super::read_candidate_at(&path).unwrap().is_none(),
            "a token under a world-writable directory is not a candidate"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two directions of the handshake must never produce the same value: a
    /// caller that recorded the service's proof could otherwise hand it back as
    /// its own answer, and the service would be signing its own nonce.
    #[test]
    fn the_two_directions_of_the_handshake_differ() {
        let token = fresh_token();

        assert_ne!(
            auth_mac(&token, "server", "caller"),
            proof_mac(&token, "server", "caller")
        );
    }

    /// Which token answered matters: the service has to compute its proof under
    /// the same one, and it may have several on file.
    #[test]
    fn an_answer_is_found_under_the_token_that_produced_it() {
        let first = fresh_token();
        let second = fresh_token();
        let candidates = vec![candidate(first), candidate(second.clone())];

        assert_eq!(
            token_for_auth(
                &candidates,
                "server",
                "caller",
                &auth_mac(&second, "server", "caller")
            )
            .map(|candidate| candidate.token.as_str()),
            Some(second.as_str())
        );
    }

    /// An answer made for one pair of nonces is not an answer for another. This
    /// is the whole point of the handshake: a recorded exchange is worth nothing
    /// on the next connection.
    #[test]
    fn an_answer_does_not_carry_to_another_challenge() {
        let token = fresh_token();
        let other = fresh_token();
        let candidates = vec![candidate(token.clone())];
        let answered = auth_mac(&token, "server", "caller");

        assert!(token_for_auth(&candidates, "server", "caller", &answered).is_some());
        assert!(token_for_auth(&candidates, "server", "other-caller", &answered).is_none());
        assert!(token_for_auth(&candidates, "other-server", "caller", &answered).is_none());
        assert!(token_for_auth(
            &candidates,
            "server",
            "caller",
            &auth_mac(&other, "server", "caller")
        )
        .is_none());
    }

    #[test]
    fn the_service_proof_is_checked_against_the_same_nonces() {
        let token = fresh_token();
        let other = fresh_token();

        assert!(proof_matches(
            &token,
            "server",
            "caller",
            &proof_mac(&token, "server", "caller")
        ));
        // Not under another token, and not the caller's answer handed back.
        assert!(!proof_matches(
            &token,
            "server",
            "caller",
            &proof_mac(&other, "server", "caller")
        ));
        assert!(!proof_matches(
            &token,
            "server",
            "caller",
            &auth_mac(&token, "server", "caller")
        ));
    }

    /// Two nonces from the same process differ; a repeated one would make two
    /// handshakes interchangeable.
    #[test]
    fn two_nonces_are_not_the_same() {
        let first = random_nonce().expect("the OS has randomness");
        let second = random_nonce().expect("the OS has randomness");

        assert_eq!(first.len(), super::NONCE_BYTES * 2);
        assert_ne!(first, second);
    }

    /// A scanned root is read as a directory *of home directories*, and both layouts a session
    /// may have written into are derived from each home: the `$XDG_RUNTIME_DIR` spelling and the
    /// `$HOME/.cache` fallback.
    #[cfg(not(windows))]
    #[test]
    fn every_scanned_root_yields_both_token_layouts() {
        let root = std::env::temp_dir().join(format!("nexapipe-roots-{}", fastrand::u64(..)));
        let home = root.join("alice");
        std::fs::create_dir_all(&home).unwrap();

        let candidates = unix_service_token_paths_from([root.clone()]);

        assert!(
            candidates.contains(&home.join(super::TOKEN_DIR).join(super::TOKEN_FILE)),
            "{candidates:?}"
        );
        assert!(
            candidates.contains(
                &home
                    .join(".cache")
                    .join(super::TOKEN_DIR)
                    .join(super::TOKEN_FILE)
            ),
            "{candidates:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// macOS homes live under `/Users`. Neither `/run/user` (absent) nor `/home` (the empty
    /// `auto_home` mount point) contains one, so a root service scanning only those has *no*
    /// candidate that can reach the token a desktop session published — which is exactly how a
    /// LaunchDaemon came to refuse every call while the token was sitting in
    /// `/Users/<name>/.cache/nexapipe/ipc.token`.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_scans_the_directory_its_homes_live_in() {
        assert!(
            unix_home_roots().contains(&PathBuf::from("/Users")),
            "macOS homes are under /Users: {:?}",
            unix_home_roots()
        );
    }

    /// The equivalent end-to-end check on a real account: the path this session actually wrote
    /// has to be reachable *by the directory scan alone*. Deliberately not the whole candidate
    /// list — `token_path()` happens to be right whenever `HOME` is set, which is precisely the
    /// condition a LaunchDaemon does not meet, so asserting on it would pass while the scan that
    /// has to carry the elevated service reaches nothing. Skipped where the account does not live
    /// under a scanned root, so it asserts on macOS alone.
    #[cfg(target_os = "macos")]
    #[test]
    fn this_accounts_token_file_is_a_service_candidate() {
        let Ok(home) = std::env::var("HOME") else {
            return;
        };
        let home = PathBuf::from(home);
        if home.parent() != Some(std::path::Path::new("/Users")) {
            return;
        }

        let scanned = unix_service_token_paths_from(unix_home_roots());
        let expected = home
            .join(".cache")
            .join(super::TOKEN_DIR)
            .join(super::TOKEN_FILE);

        assert!(
            scanned.contains(&expected),
            "{expected:?} must be found by the scan, which reached {scanned:?}"
        );
    }

    /// Linux keeps its own layout; the macOS fix must not have replaced it.
    #[cfg(all(not(windows), not(target_os = "macos")))]
    #[test]
    fn linux_scans_the_runtime_and_home_roots() {
        let roots = unix_home_roots();

        assert!(roots.contains(&PathBuf::from("/run/user")), "{roots:?}");
        assert!(roots.contains(&PathBuf::from("/home")), "{roots:?}");
    }

    /// A Windows service runs as LocalSystem, whose `USERPROFILE` is the *system* profile —
    /// `C:\Windows\System32\config\systemprofile`. Its parent is the config directory, not the
    /// profiles root, so trusting it alone finds no user token at all and the service answers
    /// "no desktop session has published an IPC token" while the token is sitting in
    /// `C:\Users\<name>\AppData\Local\nexapipe\ipc.token`.
    #[cfg(windows)]
    #[test]
    fn the_profiles_root_is_found_when_running_as_local_system() {
        let roots = profile_roots_from(
            Some(r"C:\Windows\System32\config\systemprofile"),
            Some(r"C:\Users\Public"),
            Some("C:"),
        );

        assert!(
            roots
                .iter()
                .any(|root| root == std::path::Path::new(r"C:\Users")),
            "the real profiles root must be a candidate: {roots:?}"
        );
        // The misleading one is still tried — it costs a directory scan and nothing else.
        assert!(roots.contains(&PathBuf::from(r"C:\Windows\System32\config")));
    }

    /// A directory an older build left group-writable is tightened to the
    /// mode the service insists on.
    ///
    /// Older builds made the directory with `create_dir_all`, which leaves it
    /// at 0777 minus the umask — 0775 under the umask of 002 that a
    /// user-private-group account has — and the service then refuses the
    /// token it finds there. The account that owns the directory is locked
    /// out of its own service until it runs `chmod` by hand, and the only
    /// sign of that is a warning in the service log.
    #[cfg(unix)]
    #[test]
    fn a_directory_an_older_build_left_group_writable_is_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let directory =
            std::env::temp_dir().join(format!("nexapipe-private-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a directory for the test");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o775))
            .expect("the directory is made group-writable");

        super::create_private_dir(&directory).expect("the directory is made private");

        let mode = std::fs::metadata(&directory)
            .expect("the directory is stat'ed")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "the directory must be private to the account that owns it"
        );

        let _ = std::fs::remove_dir(&directory);
    }

    /// A directory that is already private keeps the mode it has, so a
    /// stricter one set by hand is not undone.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_is_already_private_is_left_alone() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!(
            "nexapipe-private-dir-strict-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a directory for the test");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
            .expect("the directory is made read-only");

        super::create_private_dir(&directory).expect("the directory is left as it is");

        let mode = std::fs::metadata(&directory)
            .expect("the directory is stat'ed")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o500,
            "a stricter mode than the one asked for must survive"
        );

        // The directory was made read-only, so it is made writable again
        // before it is removed.
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is made writable again");
        let _ = std::fs::remove_dir(&directory);
    }
}

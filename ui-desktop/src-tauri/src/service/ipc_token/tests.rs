//! The tests of the module.

#[cfg(windows)]
use super::candidate::profile_roots_from;
use super::candidate::{service_token_paths, TokenCandidate};
#[cfg(not(windows))]
use super::candidate::{unix_home_roots, unix_service_token_paths_from};
use super::file::{ensure_token_at, read_token_at};
use super::handshake::{auth_mac, proof_mac, proof_matches, token_for_auth};
use super::secret::{generate_token, random_nonce};
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

    super::file::create_private_dir(&directory).expect("the directory is made private");

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

    super::file::create_private_dir(&directory).expect("the directory is left as it is");

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

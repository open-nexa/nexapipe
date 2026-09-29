//! The token that guards `GET /v1/*`.
//!
//! # Why it is generated, never configured
//!
//! There is no `[admin] token` key. A token written into `config.toml` ends up
//! in the file an operator edits, copies, and puts in a repository; a generated
//! one is created next to it, once, and stays out of the way. Keeping only the
//! generated route also means there is one story instead of two, and no
//! question about which wins.
//!
//! # Why a separate file, and not the config
//!
//! The config watcher reloads when `config.toml`'s mtime moves
//! (`config_watcher` polls it). Writing a token into the config on first start
//! would therefore make the process reload its own configuration immediately
//! after startup — a reload nobody asked for, over a value the reload does not
//! even read. A sibling file is not watched.
//!
//! # What happens when it cannot be made
//!
//! Nothing fatal. `/healthz` and `/metrics` are unauthenticated and keep
//! working; `/v1/*` answers `503` rather than serving without a token, because
//! serving without one is the thing the token exists to prevent.
use crate::auth::totp::constant_time_eq;
use crate::config::check_config_permissions;
use std::path::Path;

/// What is appended to the config path to get the token file:
/// `config.toml` is guarded by `config.toml.admin-token`.
pub const TOKEN_FILE_SUFFIX: &str = ".admin-token";

/// Bytes of randomness in a token, before hex encoding.
const TOKEN_BYTES: usize = 32;

/// Where the token for `config_path` lives.
pub fn token_file_path(config_path: &str) -> String {
    format!("{config_path}{TOKEN_FILE_SUFFIX}")
}

/// The token for this instance, creating it on first start.
///
/// `None` when it could not be read or could not be created, which leaves
/// `/v1/*` unavailable rather than open.
pub fn load_or_create(config_path: &str) -> Option<String> {
    let path = token_file_path(config_path);

    if Path::new(&path).exists() {
        return match load(&path) {
            Ok(token) => Some(token),
            Err(reason) => {
                tracing::error!(
                    "Admin token at {path} is unusable, /v1/* is served as 503: {reason}"
                );
                None
            }
        };
    }

    match create(&path) {
        Ok(token) => {
            // Said once, and only on the run that made it: after this the file
            // is the only thing that has to be read, and an operator looking
            // for the token is looking for this line.
            tracing::info!(
                "Generated an admin token at {path}; `nexapipe status` reads it from there"
            );
            Some(token)
        }
        Err(reason) => {
            tracing::error!(
                "Could not create an admin token at {path}, /v1/* is served as 503: {reason}"
            );
            None
        }
    }
}

/// The token the server already made, without making one.
///
/// For `nexapipe status`, which is a client of a running instance and not a
/// start: a token it minted itself would be one the server does not know about,
/// and every `/v1/*` request would then be refused with a token that looks
/// correct.
pub fn load_existing(config_path: &str) -> Option<String> {
    let path = token_file_path(config_path);

    if !Path::new(&path).exists() {
        return None;
    }

    match load(&path) {
        Ok(token) => Some(token),
        Err(reason) => {
            tracing::error!("Admin token at {path} is unusable: {reason}");
            None
        }
    }
}

/// Reads an existing token file.
fn load(path: &str) -> Result<String, String> {
    // A credential, so the same check that gates a start gates this: a token
    // any account can read is not a token.
    check_config_permissions(path, true).map_err(|e| e.to_string())?;

    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read it ({e})"))?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        return Err("it is empty".to_string());
    }
    Ok(token)
}

/// Generates a token and writes it where only this account can read it.
fn create(path: &str) -> Result<String, String> {
    let token = generate();
    write_private(path, &token).map_err(|e| format!("cannot write it ({e})"))?;

    // Checked after the write rather than before: the file this is about is
    // the one that now exists, and a mode the OS did not apply is a real
    // failure and not a hypothetical one.
    check_config_permissions(path, true).map_err(|e| e.to_string())?;
    Ok(token)
}

/// A fresh token: 32 bytes of randomness, hex encoded so it survives being
/// copied out of a terminal.
fn generate() -> String {
    let bytes: [u8; TOKEN_BYTES] = rand::random();
    hex::encode(bytes)
}

/// Writes `contents` to a new file only this account can read.
///
/// `create_new` rather than `create`: a token that already exists must not be
/// replaced, because whoever is using it would be locked out without being
/// told. Races are not a concern here — one process owns this config — but a
/// silent overwrite would be.
fn write_private(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = create_private(path)?;
    file.write_all(contents.as_bytes())?;
    file.flush()
}

#[cfg(unix)]
fn create_private(path: &str) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        // Set at creation rather than after: between `create` and `chmod` the
        // file exists with the default mode, and a token is worth less than a
        // second of that.
        .mode(0o600)
        .open(path)?;

    // `mode` is applied against the process umask, so ask for what was asked
    // for and confirm: a umask that swallowed the bits would otherwise leave a
    // group-readable credential looking correctly created.
    let wanted = std::fs::Permissions::from_mode(0o600);
    file.set_permissions(wanted)?;
    Ok(file)
}

/// No file modes to set outside Unix, so the file is created as it comes.
#[cfg(not(unix))]
fn create_private(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Whether `provided` is the token.
///
/// Compared in constant time, and the length is not compared separately: a
/// token is a bearer credential presented on every request, so how much of a
/// wrong guess was right is not something to hand out.
pub fn matches_token(provided: &str, expected: &str) -> bool {
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

/// The `Authorization` header value a client has to send.
pub const BEARER_PREFIX: &str = "bearer ";

/// The token a request presented, if it presented one.
///
/// Accepts only the `Bearer` scheme and is case-insensitive about the word, as
/// HTTP requires; anything else — `Basic`, no scheme, a token in some other
/// header — is treated as no credentials at all rather than as a wrong token,
/// because both are answered the same way anyway.
pub fn bearer_token(header: &str) -> Option<&str> {
    let rest = header.get(..BEARER_PREFIX.len())?;
    if !rest.eq_ignore_ascii_case(BEARER_PREFIX) {
        return None;
    }
    let token = header[BEARER_PREFIX.len()..].trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token is generated once and then read back unchanged: an instance that
    /// restarts must not lock out whoever already has the token.
    #[test]
    fn a_second_start_reads_the_token_the_first_one_made() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "[admin]\n").expect("seed the config");
        let config = config.to_string_lossy().into_owned();

        let first = load_or_create(&config).expect("the token is created");
        let second = load_or_create(&config).expect("the token is read back");
        assert_eq!(first, second);
        assert_eq!(first.len(), TOKEN_BYTES * 2, "hex encoded, {first}");
    }

    /// The token file is next to the config, not inside it: writing to the
    /// config would trip the watcher that reloads on its mtime.
    #[test]
    fn the_token_file_is_a_sibling_of_the_config() {
        let path = token_file_path("/etc/nexapipe/config.toml");
        assert_eq!(path, "/etc/nexapipe/config.toml.admin-token");
        assert!(!path.ends_with(".toml"), "{path}");
    }

    /// No token file is created until something asks for one: a deployment that
    /// never binds the listener should not find a credential on disk.
    #[test]
    fn nothing_is_written_until_a_token_is_needed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir
            .path()
            .join("config.toml")
            .to_string_lossy()
            .into_owned();
        assert!(!Path::new(&token_file_path(&config)).exists());
    }

    /// The header is the only place a token is read from, and only as a bearer
    /// token: anything else is no credentials rather than a wrong guess.
    #[test]
    fn only_a_bearer_header_is_a_token() {
        assert_eq!(bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(bearer_token("bearer abc123"), Some("abc123"));
        assert_eq!(bearer_token("BEARER abc123"), Some("abc123"));
        assert_eq!(bearer_token("bearer  abc123 "), Some("abc123"));

        assert_eq!(bearer_token("Basic abc123"), None);
        assert_eq!(bearer_token("abc123"), None);
        assert_eq!(bearer_token("bearer "), None);
        assert_eq!(bearer_token(""), None);
    }

    /// Comparison is by value, and a prefix of the token is not the token.
    #[test]
    fn a_prefix_of_the_token_is_not_the_token() {
        let token = "0123456789abcdef";
        assert!(matches_token(token, token));
        assert!(!matches_token(&token[..8], token));
        assert!(!matches_token("", token));
    }
}

//! Reading the configuration file, and saying what is wrong with it.
//!
//! The file itself — where it is, how it is locked, how a write of it lands —
//! is the business of the storage that keeps it, and lives in
//! [`crate::storage::file`]. What is left here is the part that is about the
//! configuration rather than about the file: how the text is parsed, and what
//! is said when the file holds a credential anybody can read.

use super::ProxyConfig;

/// Parses the configuration file's text, with an error that says what to do
/// about a key this build does not know.
///
/// serde already names the key, and it already says which keys the section
/// does have. What it cannot say is the one thing the operator can do about
/// it, and it is the same either way: the key is a typo, or it belongs to a
/// version of the file this build does not read. Both are fixed by removing it
/// or by fixing its spelling.
pub(crate) fn parse_config<T: serde::de::DeserializeOwned>(text: &str) -> anyhow::Result<T> {
    match toml::from_str::<T>(text) {
        Ok(value) => Ok(value),
        Err(error) => {
            let message = error.to_string();
            if error.message().contains("unknown field") {
                anyhow::bail!(
                    "{message}\n\nThis build does not know that key: remove it, or fix its spelling."
                );
            }
            Err(anyhow::anyhow!("{message}"))
        }
    }
}

/// Warns when the config file holds a credential and lets somebody other than
/// its owner read it.
///
/// **A warning, not a refusal.** The check that used to stop the server from
/// starting over a readable config was removed on purpose (ROADMAP §3.5), so
/// that a `0644` bind mount starts. Putting it back would undo that decision.
///
/// Silence is the part that is wrong: a TOTP seed in a file the whole machine
/// can read is a credential anybody can use to generate a valid code, and
/// nothing about it is visible. One line at startup and one after a reload is
/// enough to say it.
///
/// Unix only, and it says so by doing nothing elsewhere: the permission bits
/// are a Unix idea, and on Windows the file's ACL decides, which this does not
/// read.
///
/// `auth` is the `[auth]` half of the same file, and it is `None` when the file
/// has no such section — which is not the same as "no credential". A config
/// that names an inline `[iroh]` key and no `[auth]` at all is a credential in
/// the open. The files this server ships — the generated first-run template
/// and `config.toml.example` — both carry `[auth] enabled = true` now, but a
/// deployment whose file predates the section still has one, and a warning
/// that needed an `AuthConfig` to exist would be silent for exactly that file.
pub fn warn_about_readable_credentials(
    path: &std::path::Path,
    proxy: &ProxyConfig,
    auth: Option<&crate::auth::AuthConfig>,
) {
    if !should_warn_about_permissions(path, proxy, auth) {
        return;
    }
    tracing::warn!(
        "{} holds a credential and is readable by others (mode {:04o}); anyone who can read it \
         can use it — `chmod 600`, or move the secret into a 0600 file of its own",
        path.display(),
        file_mode(path),
    );
}

/// Whether the loaded config should be warned about: it holds a credential,
/// and the file it came from is readable by somebody other than its owner.
///
/// The decision on its own, so that it can be tested without a log
/// subscriber: the warning is a line of text, and what matters is the
/// question it answers.
pub fn should_warn_about_permissions(
    path: &std::path::Path,
    proxy: &ProxyConfig,
    auth: Option<&crate::auth::AuthConfig>,
) -> bool {
    // A credential the file holds in the clear: an inline `[iroh]` key or
    // token, or a 2FA seed. One that lives in a sidecar file of its own is
    // not in this file, and that file is held to the `0600` rule in the
    // config's place — see `read_credential_file`.
    let holds_a_seed = auth.is_some_and(|auth| auth.holds_inline_secrets());
    if !proxy.holds_credentials() && !holds_a_seed {
        return false;
    }
    readable_by_others(path)
}

/// The permission bits of the file, or 0 when they cannot be read.
#[cfg(unix)]
pub(crate) fn file_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .unwrap_or(0)
}

#[cfg(not(unix))]
pub(crate) fn file_mode(_path: &std::path::Path) -> u32 {
    0
}

/// Whether somebody other than the owner can read the file.
#[cfg(unix)]
pub(crate) fn readable_by_others(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.permissions().mode() & 0o077 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub(crate) fn readable_by_others(_path: &std::path::Path) -> bool {
    false
}

/// The config written when there is none: 2FA on, nothing else.
///
/// Deliberately small, and deliberately **not** a working proxy: it carries no
/// `[[routes]]`, so every host is answered 404 until one is added. A generated
/// backend address would be a guess — `127.0.0.1:3000` is only right by
/// coincidence — and a wrong one fails every request while looking configured.
/// The commented route below is the shape to uncomment.
///
/// `[auth] enabled = true` is the one setting that is not the operator's to
/// infer: a config with no `[auth.clients]` refuses every connection, which is
/// the correct state for a file nobody has written yet.
///
/// **The file's own permission is not checked, and that is deliberate.** A
/// startup check that refused to run over a world-readable config was removed
/// on purpose (ROADMAP §3.5) so that a `0644` bind mount starts — a config
/// that is a bind mount of a secret store is readable by design, and a server
/// that refused to start over it would be a server nobody could run that way.
///
/// What is left is a **warning**: when the config itself holds a credential —
/// an inline `[iroh]` key, or a 2FA seed — and the file is readable by
/// others, the server says so once, naming the path and the mode. See
/// [`warn_about_readable_credentials`].
///
/// The file still goes out through the storage's write rather than
/// `fs::write`, so that the one it writes is `0600` from the start.
///
/// No `[iroh] secret_key`: the endpoint identity is generated and written back
/// on first start (see `ensure_iroh_secret_key`), so writing one here would
/// be a second answer to the same question.
pub const FIRST_RUN_CONFIG: &str = include_str!("../../templates/first-run-config.toml");

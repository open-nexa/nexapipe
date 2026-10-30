//! The configuration the commands work on: the `[auth]` section as the server
//! reads it, and the key a client is written under.
//!
//! Everything here goes through a **store** rather than a path: the commands
//! write the same configuration the server reads, and where that configuration
//! lives is the server's business, not theirs.

use nexapipe::auth::AuthConfig;
use nexapipe::config::ProxyConfig;
use nexapipe::storage::Storage;

/// `[auth]` as the server reads it, or `None` when the configuration has no
/// `[auth]` section.
///
/// Not `load_auth_config`, which falls back to built-in defaults and prints a
/// warning: that is right for enrollment, which has to work before a config file
/// exists, and wrong here. `list` and `revoke` are about the configuration as it
/// stands, and reporting defaults for one that could not be read would describe
/// a client table that may not be the one on disk.
pub(super) async fn load_auth_or_none(storage: &dyn Storage) -> anyhow::Result<Option<AuthConfig>> {
    let (_, auth) = nexapipe::config::load_config_with_auth(storage)
        .await
        .map_err(|e| anyhow::anyhow!("{}: {e:#}", storage.describe()))?;
    Ok(auth)
}

/// Loads the proxy config and `[auth]` together.
///
/// A config that cannot be read is not fatal: with `--endpoint-id` and
/// `--invite-domains` given on the command line everything the invite needs is
/// already known, so the missing configuration only costs the 2FA lookup.
pub(super) async fn load_config_pair(
    storage: &dyn Storage,
) -> (Option<ProxyConfig>, AuthConfig, bool) {
    match nexapipe::config::load_config_with_auth(storage).await {
        Ok((proxy, Some(auth))) => (Some(proxy), auth, true),
        Ok((proxy, None)) => {
            eprintln!(
                "warning: {} has no [auth] section, the invite carries no 2FA",
                storage.describe()
            );
            (Some(proxy), AuthConfig::default(), false)
        }
        Err(e) => {
            eprintln!(
                "warning: {} could not be read ({e}), using built-in 2FA defaults",
                storage.describe()
            );
            (None, AuthConfig::default(), false)
        }
    }
}

/// Loads `[auth]` for the enrollment output.
///
/// Returns the settings together with whether they came from the configuration.
/// A missing or unreadable configuration is not fatal here: `--generate-2fa`
/// has to work before one exists, and it only needs the TOTP parameters, not
/// the routes.
pub(super) async fn load_auth_config(storage: &dyn Storage) -> (AuthConfig, bool) {
    match nexapipe::config::load_config_with_auth(storage).await {
        Ok((_, Some(auth))) => (auth, true),
        Ok((_, None)) => {
            eprintln!(
                "warning: {} has no [auth] section, using built-in 2FA defaults",
                storage.describe()
            );
            (AuthConfig::default(), false)
        }
        Err(e) => {
            eprintln!(
                "warning: {} could not be read ({e}), using built-in 2FA defaults",
                storage.describe()
            );
            (AuthConfig::default(), false)
        }
    }
}

/// Renders a TOML key the way it is written into the config file, as
/// `[auth.clients."client.001"]` requires while `client-001` stays bare. Sharing
/// one renderer with the writer keeps the section named in a message identical
/// to the one that ends up in the file.
pub(super) fn toml_key(key: &str) -> String {
    toml_edit::Key::new(key).to_string()
}

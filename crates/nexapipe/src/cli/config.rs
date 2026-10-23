//! The configuration file the commands work on: the `[auth]` section as
//! the server reads it, and the key a client is written under.

use nexapipe::auth::AuthConfig;
use nexapipe::config::ProxyConfig;

/// `[auth]` as the server reads it, or `None` when the file has no `[auth]`
/// section.
///
/// Not `load_auth_config`, which falls back to built-in defaults and prints a
/// warning: that is right for enrollment, which has to work before a config file
/// exists, and wrong here. `list` and `revoke` are about the file as it stands,
/// and reporting defaults for a file that could not be read would describe a
/// client table that may not be the one on disk.
pub(super) fn load_auth_or_none(path: &str) -> anyhow::Result<Option<AuthConfig>> {
    let (_, auth) =
        ProxyConfig::load_with_auth(path).map_err(|e| anyhow::anyhow!("{path}: {e:#}"))?;
    Ok(auth)
}

/// Loads the proxy config and `[auth]` together.
///
/// A config that cannot be read is not fatal: with `--endpoint-id` and
/// `--invite-domains` given on the command line everything the invite needs is
/// already known, so the missing file only costs the 2FA lookup.
pub(super) fn load_config_pair(path: &str) -> (Option<ProxyConfig>, AuthConfig, bool) {
    match ProxyConfig::load_with_auth(path) {
        Ok((proxy, Some(auth))) => (Some(proxy), auth, true),
        Ok((proxy, None)) => {
            eprintln!("warning: {path} has no [auth] section, the invite carries no 2FA");
            (Some(proxy), AuthConfig::default(), false)
        }
        Err(e) => {
            eprintln!("warning: {path} could not be read ({e}), using built-in 2FA defaults");
            (None, AuthConfig::default(), false)
        }
    }
}

/// Loads `[auth]` for the enrollment output.
///
/// Returns the settings together with whether they came from the file. A missing
/// or unreadable config is not fatal here: `--generate-2fa` has to work before a
/// config file exists, and it only needs the TOTP parameters, not the routes.
pub(super) fn load_auth_config(path: &str) -> (AuthConfig, bool) {
    match ProxyConfig::load_with_auth(path) {
        Ok((_, Some(auth))) => (auth, true),
        Ok((_, None)) => {
            eprintln!("warning: {path} has no [auth] section, using built-in 2FA defaults");
            (AuthConfig::default(), false)
        }
        Err(e) => {
            eprintln!("warning: {path} could not be read ({e}), using built-in 2FA defaults");
            (AuthConfig::default(), false)
        }
    }
}

/// Renders a TOML key the way it is written into the config file, as
/// `[auth.clients."client.001"]` requires while `client-001` stays bare. Sharing
/// one renderer with `write_client_secret` keeps the section named in a message
/// identical to the one that ends up in the file.
pub(super) fn toml_key(key: &str) -> String {
    toml_edit::Key::new(key).to_string()
}

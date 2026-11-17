//! Loading the configuration, from a file or from a store.
//!
//! The parse is the same either way, and that is the point: the schema in
//! [`schema`] is the one place a key is named, so a configuration that came
//! out of a database is validated by the same code, with the same messages,
//! as one that came out of a file.
//!
//! Two entry points, because two things are true at once:
//!
//! - the file-based one is **synchronous**, because everything that reads a
//!   file today — the CLI, the tests, the paths an operator names — reads it
//!   without a runtime;
//! - the store-based one is **asynchronous**, because a store that is not a
//!   file answers when it answers.
//!
//! They share the parse, so the two cannot drift.

use crate::auth::AuthConfig;
use crate::config::schema::Config;
use crate::storage::Storage;
use crate::storage::file::FileStorage;
use nexapipe_proto::secret::SecretString;

use std::path::Path;

impl Config {
    /// The configuration, from the file at `path`.
    ///
    /// The 2FA half of the file is not read at all: this is the read for a
    /// caller that wants the routing and the settings and not the
    /// credentials. [`Self::load_with_auth`] is the one that reads the seeds.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let storage = FileStorage::new(path);
        tracing::debug!("Loading config from: {}", path);

        let content = storage
            .config_text()?
            .ok_or_else(|| anyhow::anyhow!("Config file not found: {path}"))?;

        tracing::debug!("Config content read successfully, parsing TOML");
        let mut config: Self = Config::from_toml_text(content.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {e:#}"))?;
        config.resolve_external_credentials(storage.base_dir())?;
        config.drop_auth();

        tracing::debug!("Config parsed successfully: {:?}", config);
        Ok(config)
    }

    /// The configuration and the 2FA half of it, from the file at `path`.
    ///
    /// Both halves come from one read of the file, so the routes and the
    /// clients are the same revision of it.
    pub fn load_with_auth(path: &str) -> anyhow::Result<(Self, Option<AuthConfig>)> {
        let storage = FileStorage::new(path);
        let content = storage
            .config_text()?
            .ok_or_else(|| anyhow::anyhow!("Config file not found: {path}"))?;

        let (config, mut auth) = Self::parse_with_auth(&content, storage.base_dir())?;

        // The counters the server counted live in their own file, beside the
        // configuration. They are moved onto the configuration the caller
        // gets, so everything downstream — the connection layer, the admin
        // view, the client list — reads one answer and does not have to know
        // which file it came from.
        //
        // A state file that cannot be read stops the load: the lockouts it
        // holds are unknown, and a server that started anyway would have just
        // reset every one of them.
        if let Some(auth_config) = auth.as_mut() {
            let state = storage.state()?;
            crate::auth::state::apply(&state, auth_config);
        }

        Ok((config, auth))
    }

    /// The configuration and the 2FA half of it, from the text of a
    /// configuration file.
    ///
    /// `base_dir` is the directory a relative `*_file` path is resolved
    /// against — the directory the configuration file is in, for a file, and
    /// nothing for a store that has no directory.
    pub(crate) fn parse_with_auth(
        content: &SecretString,
        base_dir: Option<&Path>,
    ) -> anyhow::Result<(Self, Option<AuthConfig>)> {
        // The file can hold the 2FA seeds in the clear, so the text it is read
        // into is wiped when it goes out of scope.
        let mut base: Self = Config::from_toml_text(content.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {e:#}"))?;
        base.resolve_external_credentials(base_dir)?;

        // The seeds move from the configuration into the runtime's own shape.
        // A configuration that kept them would be a second copy of every
        // secret in the file, and this one is cloned on every request that
        // needs it.
        let auth = base.take_auth()?;

        Ok((base, auth))
    }
}

/// The configuration a store holds, and the 2FA half of it.
///
/// Both halves come from one read of the store, so the routes and the clients
/// are the same revision of it.
pub async fn load_config_with_auth(
    storage: &dyn Storage,
) -> anyhow::Result<(Config, Option<AuthConfig>)> {
    let content = storage
        .config()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no configuration in {}", storage.describe()))?;

    let (config, mut auth) = Config::parse_with_auth(&content, storage.base_dir())?;

    // The counters are the server's own, and they are read only when there is
    // a 2FA section to apply them to — a deployment without one has counted
    // nothing and has nothing to read.
    if let Some(auth_config) = auth.as_mut() {
        let state = storage.state().await?;
        crate::auth::state::apply(&state, auth_config);
    }

    Ok((config, auth))
}

/// The configuration a store holds.
///
/// The 2FA half is not read at all: this is the read for a caller that wants
/// the routing and the settings and not the credentials.
pub async fn load_config(storage: &dyn Storage) -> anyhow::Result<Config> {
    let content = storage
        .config()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no configuration in {}", storage.describe()))?;

    let mut config: Config = Config::from_toml_text(content.expose_secret())
        .map_err(|e| anyhow::anyhow!("Failed to parse config file: {e:#}"))?;
    config.resolve_external_credentials(storage.base_dir())?;
    config.drop_auth();
    Ok(config)
}

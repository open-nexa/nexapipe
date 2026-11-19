//! Choosing the store.
//!
//! The store is chosen by the command line and by the environment, and not by
//! the configuration: a document cannot say where it lives, because it is read
//! from there in the first place.
//!
//! A deployment that says nothing gets the database, and the database lives
//! beside the configuration file `--config` names — one directory an operator
//! can look at, back up and copy, rather than a path derived from a second
//! variable that would drift from the first. The file backend stays one flag
//! away, and a build that carries no database driver says so rather than
//! pretending to open one.

use crate::storage::{FileStorage, Storage, StorageKind};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nexapipe_proto::secret::SecretString;

/// The name the database is given when the operator names no URL.
///
/// It sits next to the configuration file, in the directory `--config` names:
/// `config.toml` puts its database in `nexapipe.db`, and so does
/// `/etc/nexapipe/config.toml`.
const DATABASE_FILE: &str = "nexapipe.db";

/// The file a file-store deployment keeps its configuration in.
///
/// Not the path `--config` names: that names where the store is now, and the
/// file that may have to be imported is the one an earlier version wrote,
/// which was always `config.toml` in the configuration directory.
const LEGACY_CONFIG_FILE: &str = "config.toml";

/// Opens the store an operator asked for.
///
/// `config_path` is the file backend's configuration file — the path
/// `--config` names. `url` is what a database backend needs: a connection
/// string for PostgreSQL, a file path for SQLite.
pub async fn open(
    kind: StorageKind,
    url: Option<&str>,
    config_path: &str,
) -> anyhow::Result<Arc<dyn Storage>> {
    match kind {
        StorageKind::Toml => Ok(Arc::new(FileStorage::new(config_path))),
        StorageKind::Sqlite => {
            #[cfg(feature = "storage-sqlite")]
            {
                let url = url.ok_or_else(|| {
                    anyhow::anyhow!(
                        "a sqlite store needs a path: pass --storage-url, or set \
                         NEXAPIPE_STORAGE_URL, to say where the database is"
                    )
                })?;
                Ok(Arc::new(
                    crate::storage::sqlite::SqliteStorage::open(url).await?,
                ))
            }
            #[cfg(not(feature = "storage-sqlite"))]
            {
                let _ = url;
                anyhow::bail!(
                    "this build has no sqlite store: it arrives with the `storage-sqlite` feature, \
                     and this binary was built without it"
                )
            }
        }
        StorageKind::Postgres => {
            let _ = url;
            anyhow::bail!(
                "this build has no postgres store: it arrives with the `storage-postgres` \
                 feature, and this binary was built without it"
            )
        }
    }
}

/// The database a deployment that names none keeps its configuration in.
///
/// `<directory of the configuration file>/nexapipe.db`, so the file store's
/// file, its lock, the legacy `config.toml` and the database are one anchor. A
/// configuration named without a directory — `config.toml` — lives in the
/// working directory, and so does the database.
pub fn default_database_path(config_path: &str) -> PathBuf {
    match config_directory(config_path) {
        Some(directory) => directory.join(DATABASE_FILE),
        None => PathBuf::from(DATABASE_FILE),
    }
}

/// Imports a `config.toml` beside the store, once, into a store that holds no
/// configuration.
///
/// Returns the path it imported from, or `None` when there was nothing to do:
/// the store already holds a configuration, or there is no file beside it. The
/// file is left exactly where it is — `--storage toml` still reads it, which
/// is what makes the move reversible — and the store the configuration was
/// imported into is what the instance reads from then on.
///
/// **Emptiness decides, not a marker.** After the import the store holds a
/// configuration, so the import cannot fire twice; a marker row would be a
/// second thing that can fall out of step with the contents.
///
/// **A file that cannot be read is an error, and the store is left empty.** An
/// operator told "imported" about a configuration that was silently
/// half-applied is worse off than one told which file did not parse and why.
pub async fn import_legacy_config(
    storage: &dyn Storage,
    config_path: &str,
) -> anyhow::Result<Option<PathBuf>> {
    if storage.config().await?.is_some() {
        return Ok(None);
    }

    let path = match config_directory(config_path) {
        Some(directory) => directory.join(LEGACY_CONFIG_FILE),
        None => PathBuf::from(LEGACY_CONFIG_FILE),
    };

    let text = match tokio::fs::read_to_string(&path).await {
        Ok(text) => SecretString::new(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!("cannot read {}: {e}", path.display()),
    };

    // Where an unknown key becomes the error it is: the same parse the file
    // store's readers run, so the import refuses exactly what a start on the
    // file would have refused.
    let config = crate::config::Config::from_toml_text(text.expose_secret()).map_err(|e| {
        anyhow::anyhow!(
            "{} cannot be read as a configuration: {e:#}",
            path.display()
        )
    })?;

    storage.put_config(&config).await?;
    Ok(Some(path))
}

/// The directory the configuration file is in, when it names one.
///
/// `None` for a bare `config.toml`: it lives in the working directory, and
/// `Path::parent` answers with an empty path rather than the working directory
/// — resolving that here would turn "beside the file" into "beside the
/// process", which is the same place only by accident.
fn config_directory(config_path: &str) -> Option<&Path> {
    Path::new(config_path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

/// The store an operator asked for, read from the command line and the
/// environment.
///
/// The command line wins over the environment: an operator who typed it meant
/// it, and the environment is the fallback for a deployment that cannot change
/// its command line.
///
/// A deployment that says nothing — no flag, no `NEXAPIPE_STORAGE` — gets the
/// database, with its path derived from the configuration file. An explicit
/// `--storage-url` or `NEXAPIPE_STORAGE_URL` wins over that derived path.
pub async fn choose(
    flag: Option<StorageKind>,
    url_flag: Option<String>,
    config_path: &str,
) -> anyhow::Result<Arc<dyn Storage>> {
    let kind = match flag {
        Some(kind) => kind,
        None => match std::env::var("NEXAPIPE_STORAGE") {
            Ok(value) => StorageKind::parse(&value)?,
            Err(_) => StorageKind::Sqlite,
        },
    };

    let url = match url_flag.or_else(|| std::env::var("NEXAPIPE_STORAGE_URL").ok()) {
        Some(url) => Some(url),
        // The derived path is the default only for the store that has one: a
        // file store is named by `config_path`, and a URL it was given would
        // be a second name for the same thing.
        None if kind == StorageKind::Sqlite => Some(
            default_database_path(config_path)
                .to_string_lossy()
                .into_owned(),
        ),
        None => None,
    };

    open(kind, url.as_deref(), config_path).await
}

#[cfg(test)]
mod tests {
    use super::{default_database_path, import_legacy_config};

    use crate::storage::{FileStorage, Storage};

    use std::path::PathBuf;

    /// The database sits beside the configuration file it was derived from.
    #[test]
    fn the_default_database_follows_the_configuration_directory() {
        assert_eq!(
            default_database_path("/tmp/x/config.toml"),
            PathBuf::from("/tmp/x/nexapipe.db")
        );
        // A configuration named without a directory lives in the working
        // directory, and so does its database.
        assert_eq!(
            default_database_path("config.toml"),
            PathBuf::from("nexapipe.db")
        );
    }

    /// An empty store beside a `config.toml` comes back holding that
    /// configuration, and the file is still where it was.
    ///
    /// The store's own file is deliberately **not** the legacy path, so that
    /// what the test proves is which file the import read, not that a file
    /// store read itself.
    #[tokio::test]
    async fn a_configuration_beside_an_empty_store_is_imported() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "[auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXP\"\n",
        )
        .expect("the legacy file is written");

        let store = FileStorage::new(dir.path().join("not-the-legacy-file.toml"));
        let imported = import_legacy_config(&store, &config.to_string_lossy())
            .await
            .expect("the import runs");

        assert_eq!(imported.as_deref(), Some(config.as_path()));
        assert!(config.exists(), "the file is left where it was");

        let text = store
            .config()
            .await
            .expect("the store is readable")
            .expect("the store holds a configuration");
        assert!(
            text.expose_secret().contains("JBSWY3DPEHPK3PXP"),
            "the credential came across: {}",
            text.expose_secret()
        );

        // And a second call has nothing left to do.
        let again = import_legacy_config(&store, &config.to_string_lossy())
            .await
            .expect("the second import runs");
        assert_eq!(again, None, "the import fires once");
    }

    /// A file that cannot be parsed is refused by name, and the store is left
    /// holding nothing.
    #[tokio::test]
    async fn a_file_that_does_not_parse_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "no_such_key = true\n").expect("the broken file is written");

        let store = FileStorage::new(dir.path().join("not-the-legacy-file.toml"));
        let error = import_legacy_config(&store, &config.to_string_lossy())
            .await
            .expect_err("the import refuses");

        let message = format!("{error:#}");
        assert!(
            message.contains("config.toml"),
            "the refusal names the file: {message}"
        );
        assert!(
            store
                .config()
                .await
                .expect("the store is readable")
                .is_none(),
            "the store is left holding no configuration"
        );
    }
}

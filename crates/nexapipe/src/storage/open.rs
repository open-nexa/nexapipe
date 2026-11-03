//! Choosing the store.
//!
//! The store is chosen by the command line and by the environment, and not by
//! the configuration: a document cannot say where it lives, because it is read
//! from there in the first place.
//!
//! The file backend is the one that exists today. The two database backends
//! arrive behind cargo features (`storage-sqlite`, `storage-postgres`), so a
//! build that does not carry them says so rather than pretending to open a
//! database it has no driver for.

use crate::storage::{FileStorage, Storage, StorageKind};

use std::sync::Arc;

/// Opens the store an operator asked for.
///
/// `config_path` is the file backend's configuration file — the path
/// `--config` names. `url` is what a database backend needs: a connection
/// string for PostgreSQL, a file path for SQLite.
pub fn open(
    kind: StorageKind,
    url: Option<&str>,
    config_path: &str,
) -> anyhow::Result<Arc<dyn Storage>> {
    match kind {
        StorageKind::Toml => Ok(Arc::new(FileStorage::new(config_path))),
        StorageKind::Sqlite => {
            let _ = url;
            anyhow::bail!(
                "this build has no sqlite store: it arrives with the `storage-sqlite` feature, \
                 and this binary was built without it"
            )
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

/// The store an operator asked for, read from the command line and the
/// environment.
///
/// The command line wins over the environment: an operator who typed it meant
/// it, and the environment is the fallback for a deployment that cannot change
/// its command line.
pub fn choose(
    flag: Option<StorageKind>,
    url_flag: Option<String>,
    config_path: &str,
) -> anyhow::Result<Arc<dyn Storage>> {
    let kind = match flag {
        Some(kind) => kind,
        None => match std::env::var("NEXAPIPE_STORAGE") {
            Ok(value) => StorageKind::parse(&value)?,
            Err(_) => StorageKind::Toml,
        },
    };

    let url = url_flag.or_else(|| std::env::var("NEXAPIPE_STORAGE_URL").ok());

    open(kind, url.as_deref(), config_path)
}

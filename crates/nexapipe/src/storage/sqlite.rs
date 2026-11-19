//! The SQLite store.
//!
//! # What a database changes
//!
//! Nothing about the *configuration*: it is still one document and it is still
//! handed out as the same TOML a file would have held, so every reader, every
//! error message and every validation runs exactly once, in one place. What
//! changes is where the document lives and how a write reaches it.
//!
//! # What a write means here
//!
//! Still **by entity**, never by document — and here that is easier rather
//! than harder: a client's secret is one row, a route is one row, and the
//! counters are one row each. A write that re-rendered the whole configuration
//! would take a route somebody added while the server was running with it; a
//! write that re-rendered the whole *document* would take every other row's
//! last write with it.
//!
//! # The revision
//!
//! The watcher reloads when the configuration changes, and it finds that out
//! by comparing two stamps. A file is stamped by its modification time and its
//! length; a database has neither, so it carries a counter that every write
//! bumps. [`Stamp::Database`] is that counter, and it moves in the same
//! transaction as the write it belongs to — a reload that saw the row but not
//! the revision would miss the change until the next write.
//!
//! # The schema
//!
//! Five tables, and the split between them is the split between what a
//! deployment changes often and what it changes once:
//!
//! | Table | What it holds |
//! |---|---|
//! | `meta` | The schema version, and the revision the watcher compares. |
//! | `settings` | Everything that is not a route and not a client, as one document. |
//! | `routes` | One route per row, in the order they were written. |
//! | `clients` | One client per row, with its devices. |
//! | `runtime_state` | The counters, one row per client. |
//! | `credentials` | The credentials that are not a client's: the endpoint's key, the relay token, the admin token. |
//!
//! The settings row holds the configuration as the model holds it — the same
//! types a file is parsed into — so a key is named in exactly one place and a
//! store that reads a configuration and writes it back writes the same one.

use crate::auth::state::RuntimeState;
use crate::config::{AuthClient, AuthDevice, ClientSecretWrite, Config};
use crate::storage::{DeviceCredential, DeviceInfo, Stamp, Storage, StorageKind};

use futures_util::future::BoxFuture;

use nexapipe_proto::secret::SecretString;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqliteConnection, SqlitePool};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The statements that make the store, in the order they are created.
///
/// Every one of them is idempotent, so opening a store that is already there
/// is not an error and a store written by a newer build is not destroyed by an
/// older one opening it.
const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK (id = 1), json TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS routes (ordinal INTEGER PRIMARY KEY, host_pattern TEXT NOT NULL, json TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, json TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS runtime_state (client_id TEXT PRIMARY KEY, json TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS credentials (name TEXT PRIMARY KEY, secret TEXT NOT NULL)",
];

/// The version of the schema this build writes.
///
/// A store whose version is newer than this one is refused rather than opened:
/// an older build would read the rows it does not understand as the rows it
/// does, and the configuration it came up with would be a mixture of two
/// layouts.
const SCHEMA_VERSION: &str = "1";

/// The name the admin token is kept under.
const ADMIN_TOKEN: &str = "admin_token";

/// The store that keeps the configuration in a SQLite database.
pub struct SqliteStorage {
    pool: SqlitePool,
    path: PathBuf,
}

impl SqliteStorage {
    /// Opens the store at `path`, creating it when it is not there.
    pub async fn open(path: &str) -> anyhow::Result<Self> {
        let path = PathBuf::from(path);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                anyhow::anyhow!(
                    "the directory of {} could not be created: {e}",
                    path.display()
                )
            })?;
        }

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            // The write-ahead log lets a reader run while a writer holds the
            // write lock, which is what a reload is: the server reading the
            // configuration while the admin API changes it.
            .journal_mode(SqliteJournalMode::Wal)
            // A second writer — the admin API on one side, the server on the
            // other — waits rather than failing.
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            // One connection: SQLite writes are serialized anyway, and one
            // writer is one writer rather than several waiting for each other.
            .max_connections(1)
            .connect_with(options)
            .await?;

        let storage = Self { pool, path };
        storage.prepare().await?;
        Ok(storage)
    }

    /// Creates the tables and checks the version.
    async fn prepare(&self) -> anyhow::Result<()> {
        for &statement in SCHEMA {
            sqlx::query(statement).execute(&self.pool).await?;
        }

        sqlx::query("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)")
            .bind(SCHEMA_VERSION)
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT OR IGNORE INTO meta (key, value) VALUES ('config_revision', '0')")
            .execute(&self.pool)
            .await?;

        let version: String = sqlx::query("SELECT value FROM meta WHERE key = 'schema_version'")
            .fetch_one(&self.pool)
            .await?
            .try_get("value")?;
        if version != SCHEMA_VERSION {
            anyhow::bail!(
                "{} holds schema version {version}, and this build speaks version \
                 {SCHEMA_VERSION}; the store was written by a newer build",
                self.path.display()
            );
        }

        Ok(())
    }

    /// The revision the watcher compares.
    async fn revision(&self) -> anyhow::Result<u64> {
        let value: String = sqlx::query("SELECT value FROM meta WHERE key = 'config_revision'")
            .fetch_one(&self.pool)
            .await?
            .try_get("value")?;
        Ok(value.parse().unwrap_or(0))
    }

    /// Moves the revision on, in the transaction of the write it belongs to.
    async fn bump(connection: &mut SqliteConnection) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) \
             WHERE key = 'config_revision'",
        )
        .execute(connection)
        .await?;
        Ok(())
    }

    /// The rows the configuration is made of, or `None` when the store is
    /// empty.
    async fn read_rows(&self) -> anyhow::Result<Option<Rows>> {
        let settings = sqlx::query("SELECT json FROM settings WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        let Some(settings) = settings else {
            return Ok(None);
        };
        let settings: String = settings.try_get("json")?;

        let route_rows = sqlx::query("SELECT json FROM routes ORDER BY ordinal")
            .fetch_all(&self.pool)
            .await?;
        let mut routes = Vec::with_capacity(route_rows.len());
        for row in route_rows {
            routes.push(row.try_get::<String, _>("json")?);
        }

        let client_rows = sqlx::query("SELECT id, json FROM clients ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut clients = Vec::with_capacity(client_rows.len());
        for row in client_rows {
            clients.push((
                row.try_get::<String, _>("id")?,
                row.try_get::<String, _>("json")?,
            ));
        }

        Ok(Some(Rows {
            settings,
            routes,
            clients,
        }))
    }

    /// Writes the rows the configuration is made of, and moves the revision on.
    async fn write_rows(&self, rows: &Rows) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("INSERT INTO settings (id, json) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET json = excluded.json")
            .bind(&rows.settings)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM routes").execute(&mut *tx).await?;
        for (ordinal, route) in rows.routes.iter().enumerate() {
            let host_pattern = serde_json::from_str::<serde_json::Value>(route)
                .ok()
                .and_then(|value| {
                    value
                        .get("host_pattern")
                        .and_then(|pattern| pattern.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            sqlx::query("INSERT INTO routes (ordinal, host_pattern, json) VALUES (?, ?, ?)")
                .bind(ordinal as i64)
                .bind(host_pattern)
                .bind(route)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM clients").execute(&mut *tx).await?;
        for (id, client) in &rows.clients {
            sqlx::query("INSERT INTO clients (id, json) VALUES (?, ?)")
                .bind(id)
                .bind(client)
                .execute(&mut *tx)
                .await?;
        }

        Self::bump(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The client as it is stored, if there is one.
    async fn client(&self, client_id: &str) -> anyhow::Result<Option<AuthClient>> {
        let row = sqlx::query("SELECT json FROM clients WHERE id = ?")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let json: String = row.try_get("json")?;
        Ok(Some(serde_json::from_str(&json)?))
    }

    /// Writes the client back, and moves the revision on.
    async fn put_client(&self, client_id: &str, client: &AuthClient) -> anyhow::Result<()> {
        let json = serde_json::to_string(client)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO clients (id, json) VALUES (?, ?) \
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
        )
        .bind(client_id)
        .bind(&json)
        .execute(&mut *tx)
        .await?;
        Self::bump(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The settings row, as the model holds it.
    async fn settings(&self) -> anyhow::Result<Option<Config>> {
        let row = sqlx::query("SELECT json FROM settings WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let json: String = row.try_get("json")?;
        Ok(Some(serde_json::from_str(&json)?))
    }

    /// Writes the settings row back, and moves the revision on.
    async fn put_settings(&self, config: &Config) -> anyhow::Result<()> {
        let json = serde_json::to_string(config)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO settings (id, json) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET json = excluded.json")
            .bind(&json)
            .execute(&mut *tx)
            .await?;
        Self::bump(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

/// The rows a configuration is made of.
///
/// The settings row is the configuration without its routes and without its
/// clients; the routes are one row each and the clients are one row each.
struct Rows {
    settings: String,
    routes: Vec<String>,
    clients: Vec<(String, String)>,
}

impl Rows {
    /// The rows a configuration is made of, from the configuration.
    fn of(config: &Config) -> anyhow::Result<Self> {
        let mut settings = config.clone();
        let routes = settings.routes.take().unwrap_or_default();
        let clients = settings
            .auth
            .as_mut()
            .map(|auth| std::mem::take(&mut auth.clients))
            .unwrap_or_default();

        let mut route_rows = Vec::with_capacity(routes.len());
        for route in &routes {
            route_rows.push(serde_json::to_string(route)?);
        }

        let mut client_rows = Vec::with_capacity(clients.len());
        for (id, client) in &clients {
            client_rows.push((id.clone(), serde_json::to_string(client)?));
        }

        Ok(Rows {
            settings: serde_json::to_string(&settings)?,
            routes: route_rows,
            clients: client_rows,
        })
    }

    /// The configuration the rows are.
    fn to_config(&self) -> anyhow::Result<Config> {
        let mut config: Config = serde_json::from_str(&self.settings)?;

        let mut routes = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            routes.push(serde_json::from_str(route)?);
        }
        config.routes = (!routes.is_empty()).then_some(routes);

        if let Some(auth) = config.auth.as_mut() {
            let mut clients = BTreeMap::new();
            for (id, client) in &self.clients {
                clients.insert(id.clone(), serde_json::from_str(client)?);
            }
            auth.clients = clients;
        }

        Ok(config)
    }
}

/// The credential a device is issued, as the model holds one.
fn device_of(
    credential: DeviceCredential,
    info: DeviceInfo,
    path: &Path,
) -> anyhow::Result<AuthDevice> {
    let (secret, public_key) = match credential {
        DeviceCredential::Secret(secret) => {
            let secret = secret.expose_secret();
            if secret.is_empty() {
                anyhow::bail!(
                    "{}: a device secret cannot be empty; an empty one keys this device's HMAC \
                     with nothing and leaves a configuration that cannot be loaded",
                    path.display()
                );
            }
            (Some(secret.to_string().into()), None)
        }
        DeviceCredential::PublicKey(public_key) => {
            let key = crate::auth::parse_public_key(&public_key)
                .map_err(|why| anyhow::anyhow!("{}: {why}", path.display()))?;
            (None, Some(crate::auth::public_key_hex(&key)))
        }
    };
    Ok(AuthDevice {
        secret,
        public_key,
        created_at: Some(crate::auth::config::default_created_at()),
        last_used: None,
        label: info.label,
        platform: info.platform,
        model: info.model,
        app_version: info.app_version,
    })
}

impl Storage for SqliteStorage {
    fn kind(&self) -> StorageKind {
        StorageKind::Sqlite
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }

    fn describe_state(&self) -> String {
        format!("the runtime counters in {}", self.path.display())
    }

    fn describe_token(&self) -> String {
        format!("the admin token in {}", self.path.display())
    }

    fn base_dir(&self) -> Option<&Path> {
        // A database has no file next to it, so a `secret_key_file` in it has
        // nothing to be relative to. Refusing is the honest answer; resolving
        // it against the working directory would be a guess.
        None
    }

    fn credential_file(&self) -> Option<&Path> {
        // A database has no file and therefore no mode to check: the perimeter
        // is the database's own access control.
        None
    }

    fn stamp(&self) -> BoxFuture<'_, anyhow::Result<Stamp>> {
        Box::pin(async move {
            Ok(Stamp::Database {
                revision: self.revision().await?,
            })
        })
    }

    fn config(&self) -> BoxFuture<'_, anyhow::Result<Option<SecretString>>> {
        Box::pin(async move {
            let Some(rows) = self.read_rows().await? else {
                return Ok(None);
            };
            let config = rows.to_config()?;
            let text = config.to_toml_text()?;
            Ok(Some(SecretString::new(text)))
        })
    }

    fn ensure_config(&self, template: &str) -> BoxFuture<'_, anyhow::Result<bool>> {
        // The template is copied rather than borrowed: the future it becomes
        // lives as long as the store does, and the template does not.
        let template = template.to_string();
        Box::pin(async move {
            if self.read_rows().await?.is_some() {
                return Ok(false);
            }
            let config = Config::from_toml_text(&template)?;
            self.write_rows(&Rows::of(&config)?).await?;
            Ok(true)
        })
    }

    fn put_config<'a>(&'a self, config: &'a Config) -> BoxFuture<'a, anyhow::Result<()>> {
        // Laid out before the future is pinned, so a configuration that cannot
        // be expressed as rows is refused where it was handed over. The write
        // is `write_rows`, which bumps the revision in its own transaction:
        // the watcher sees the configuration it was handed.
        let rows = Rows::of(config);
        Box::pin(async move {
            let rows = rows?;
            self.write_rows(&rows).await
        })
    }

    fn write_client_secret<'a>(
        &'a self,
        client_id: &'a str,
        secret: &'a SecretString,
        force: bool,
    ) -> BoxFuture<'a, anyhow::Result<ClientSecretWrite>> {
        Box::pin(async move {
            let existing = self.client(client_id).await?;
            let replaced = existing
                .as_ref()
                .is_some_and(|client| !client.secret.expose_secret().is_empty());
            if replaced && !force {
                anyhow::bail!(
                    "client {client_id:?} already has a secret in {}",
                    self.path.display()
                );
            }

            let mut client = existing.unwrap_or_else(|| AuthClient {
                secret: SecretString::default(),
                created_at: Some(crate::auth::config::default_created_at()),
                allow_hosts: None,
                allow_ports: None,
                allow_ports_strict: None,
                pending_enrollment: None,
                pending_enrollment_expires_at: None,
                devices: BTreeMap::new(),
                unnamed_device_allowed: None,
                failed_attempts: None,
                locked_until: None,
                last_used: None,
            });
            client.secret = secret.clone();
            self.put_client(client_id, &client).await?;

            Ok(if replaced {
                ClientSecretWrite::Replaced
            } else {
                ClientSecretWrite::Added
            })
        })
    }

    fn write_pending_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a SecretString,
        expires_at: Option<u64>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let Some(mut client) = self.client(client_id).await? else {
                anyhow::bail!(
                    "client {client_id:?} has no [auth.clients.{client_id}] secret in {}; \
                     run `nexapipe client enroll {client_id}` first",
                    self.path.display()
                );
            };
            if client.secret.expose_secret().is_empty() {
                anyhow::bail!(
                    "client {client_id:?} has no [auth.clients.{client_id}] secret in {}; \
                     run `nexapipe client enroll {client_id}` first",
                    self.path.display()
                );
            }
            client.pending_enrollment = Some(token.clone());
            // The deadline goes in beside the token and the old one goes out
            // with it: a token that was replaced is a token that is gone.
            client.pending_enrollment_expires_at = expires_at;
            self.put_client(client_id, &client).await
        })
    }

    fn complete_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        secret: &'a SecretString,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let Some(mut client) = self.client(client_id).await? else {
                anyhow::bail!(
                    "client {client_id:?} has no [auth.clients.{client_id}] section in {}",
                    self.path.display()
                );
            };
            client.secret = secret.clone();
            client.pending_enrollment = None;
            client.pending_enrollment_expires_at = None;
            self.put_client(client_id, &client).await
        })
    }

    fn complete_device_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
        credential: DeviceCredential,
        info: DeviceInfo,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let Some(mut client) = self.client(client_id).await? else {
                anyhow::bail!(
                    "client {client_id:?} has no [auth.clients.{client_id}] section in {}",
                    self.path.display()
                );
            };
            let entry = device_of(credential, info, &self.path)?;
            client.devices.insert(device.to_string(), entry);
            client.pending_enrollment = None;
            client.pending_enrollment_expires_at = None;
            self.put_client(client_id, &client).await
        })
    }

    fn write_device_credential<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
        credential: DeviceCredential,
        force: bool,
    ) -> BoxFuture<'a, anyhow::Result<ClientSecretWrite>> {
        Box::pin(async move {
            if !crate::auth::is_presentable_device_id(device) {
                anyhow::bail!(
                    "device name {device:?} is printable ASCII of at most {} characters — it is a \
                     key in {} and the subject of every log line about it",
                    crate::auth::MAX_DEVICE_ID_LEN,
                    self.path.display()
                );
            }

            let Some(mut client) = self.client(client_id).await? else {
                anyhow::bail!(
                    "client {client_id:?} has no [auth.clients.{client_id}] secret in {}; \
                     run `nexapipe client enroll {client_id}` first",
                    self.path.display()
                );
            };
            if client.secret.expose_secret().is_empty() {
                anyhow::bail!(
                    "client {client_id:?} has no [auth.clients.{client_id}] secret in {}; \
                     run `nexapipe client enroll {client_id}` first",
                    self.path.display()
                );
            }

            let replaced = client.devices.contains_key(device);
            if replaced && !force {
                anyhow::bail!(
                    "device {device:?} of client {client_id:?} already has a credential in {}",
                    self.path.display()
                );
            }

            let entry = device_of(credential, DeviceInfo::default(), &self.path)?;
            client.devices.insert(device.to_string(), entry);
            self.put_client(client_id, &client).await?;

            Ok(if replaced {
                ClientSecretWrite::Replaced
            } else {
                ClientSecretWrite::Added
            })
        })
    }

    fn remove_device<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let Some(mut client) = self.client(client_id).await? else {
                anyhow::bail!(
                    "client {client_id:?} has no [auth.clients.{client_id}] section in {}, \
                     nothing revoked",
                    self.path.display()
                );
            };
            if client.devices.remove(device).is_none() {
                anyhow::bail!(
                    "client {client_id:?} has no device {device:?} in {}; its devices are {:?}",
                    self.path.display(),
                    client.devices.keys().collect::<Vec<_>>()
                );
            }
            self.put_client(client_id, &client).await
        })
    }

    fn remove_client<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let result = sqlx::query("DELETE FROM clients WHERE id = ?")
                .bind(client_id)
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() == 0 {
                anyhow::bail!(
                    "client {client_id:?} has no [auth.clients.{client_id}] section in {}, \
                     nothing revoked",
                    self.path.display()
                );
            }
            Self::bump(&mut tx).await?;
            tx.commit().await?;
            Ok(())
        })
    }

    fn write_endpoint_key<'a>(
        &'a self,
        key: &'a SecretString,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            // The configuration has to be there: the key is written into it,
            // and a store that wrote one into nothing would answer "the
            // configuration is written" to the next reader while holding a
            // document with nothing but a key in it.
            let mut config = self.settings().await?.ok_or_else(|| {
                anyhow::anyhow!(
                    "{}: there is no configuration to write the secret_key into",
                    self.path.display()
                )
            })?;
            let iroh = config.iroh.get_or_insert_with(Default::default);
            iroh.secret_key = Some(key.clone());
            self.put_settings(&config).await
        })
    }

    fn state(&self) -> BoxFuture<'_, anyhow::Result<RuntimeState>> {
        Box::pin(async move {
            let rows = sqlx::query("SELECT client_id, json FROM runtime_state")
                .fetch_all(&self.pool)
                .await?;
            let mut clients = std::collections::HashMap::new();
            for row in rows {
                let id: String = row.try_get("client_id")?;
                let json: String = row.try_get("json")?;
                clients.insert(id, serde_json::from_str(&json)?);
            }
            Ok(RuntimeState { clients })
        })
    }

    fn put_state<'a>(&'a self, state: &'a RuntimeState) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            sqlx::query("DELETE FROM runtime_state")
                .execute(&mut *tx)
                .await?;
            for (client_id, client) in &state.clients {
                sqlx::query("INSERT INTO runtime_state (client_id, json) VALUES (?, ?)")
                    .bind(client_id)
                    .bind(serde_json::to_string(client)?)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            Ok(())
        })
    }

    fn admin_token(&self) -> BoxFuture<'_, anyhow::Result<Option<SecretString>>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT secret FROM credentials WHERE name = ?")
                .bind(ADMIN_TOKEN)
                .fetch_optional(&self.pool)
                .await?;
            let Some(row) = row else {
                return Ok(None);
            };
            let secret: String = row.try_get("secret")?;
            Ok(Some(SecretString::new(secret)))
        })
    }

    fn put_admin_token<'a>(&'a self, token: &'a SecretString) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let existing = sqlx::query("SELECT secret FROM credentials WHERE name = ?")
                .bind(ADMIN_TOKEN)
                .fetch_optional(&mut *tx)
                .await?;
            if existing.is_some() {
                anyhow::bail!(
                    "an admin token is already in {}; whoever is using it would be locked out \
                     without being told",
                    self.path.display()
                );
            }
            sqlx::query("INSERT INTO credentials (name, secret) VALUES (?, ?)")
                .bind(ADMIN_TOKEN)
                .bind(token.expose_secret().as_str())
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(())
        })
    }
}

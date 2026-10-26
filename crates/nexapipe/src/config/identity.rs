//! Who this endpoint is, and where its credentials come from.
//!
//! The secret key is the endpoint's identity, and it is written nowhere it can
//! be read by somebody else — and it may equally live in a file or in the
//! environment, which is a decision the operator makes and the server refuses
//! to guess at.

use nexapipe_proto::secret::SecretString;

use std::fs;
use std::io::Write;

use std::path::{Path, PathBuf};

use super::*;

use crate::storage::Storage;

/// What [`ProxyConfig::ensure_iroh_secret_key`] resolved the endpoint's
/// identity to.
#[derive(Clone, PartialEq, Eq)]
pub enum EndpointIdentity {
    /// `[iroh] secret_key` was already set and parses. Nothing was written.
    Configured(SecretString),
    /// No `secret_key` was configured and one was generated and written to the
    /// config file. The Node ID is stable from this restart on.
    Generated(SecretString),
    /// No `secret_key` was configured, and persisting one was either turned off
    /// by `NEXAPIPE_NO_PERSIST_IDENTITY` or not possible (a read-only mount, a
    /// config owned by another user). The server runs on the returned key, and
    /// the Node ID will be different after the next restart.
    Ephemeral(SecretString),
}

/// Handwritten, and never `derive(Debug)`, for the reason
/// [`IrohConfig`]'s is: every variant here *is* the ed25519 private key.
///
/// The derive is a loaded gun. This enum reaches a `{:?}` on the failure path
/// of a test, where CI collects the output and keeps it — and a real key
/// printed there is the endpoint's identity in a log anyone with read access to
/// the build can lift. A failure would hand over exactly the thing the caller
/// was told is private. The variant is enough to debug with: which of the three
/// paths produced this is the question a reader actually has.
impl std::fmt::Debug for EndpointIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (variant, key) = match self {
            Self::Configured(key) => ("Configured", key),
            Self::Generated(key) => ("Generated", key),
            Self::Ephemeral(key) => ("Ephemeral", key),
        };
        f.debug_struct("EndpointIdentity")
            .field("variant", &variant)
            .field("key", &redacted(&Some(key.clone())))
            .finish()
    }
}

impl EndpointIdentity {
    /// The hex key the endpoint should run on, whichever way it was arrived at.
    pub fn key(&self) -> &str {
        match self {
            Self::Configured(key) | Self::Generated(key) | Self::Ephemeral(key) => {
                key.expose_secret()
            }
        }
    }
}

/// Set to any value other than empty, `0` or `false` (for example `1`) to keep
/// `[iroh] secret_key` out of the config file.
///
/// Empty does **not** disable persistence: a compose file that lists a variable
/// without a value (`- NEXAPIPE_NO_PERSIST_IDENTITY`) is asking for the default,
/// not for the behaviour. `persistence_disabled` is where that rule lives.
///
/// The one deployment this exists for: a throwaway container or a test harness
/// that wants a clean identity on every run, and would rather not have the file
/// silently gain a private key. Everywhere else it is the wrong setting — the
/// Node ID changing on every restart is what makes clients lose track of the
/// server.
pub(crate) const NO_PERSIST_ENV: &str = "NEXAPIPE_NO_PERSIST_IDENTITY";

/// Whether the operator asked for the identity *not* to be written to disk.
///
/// Read from the environment rather than from the config on purpose: the
/// decision is about whether this process may touch that file, so it has to be
/// answerable when the file cannot be read at all, and an env var is what a
/// systemd unit or a compose file can set without editing a config the server
/// may not even have permission to write.
pub(crate) fn persist_identity_disabled() -> bool {
    persistence_disabled(std::env::var(NO_PERSIST_ENV).ok().as_deref())
}

/// The rule [`persist_identity_disabled`] applies, as a function of the value.
///
/// `unset`, empty and `0` all mean "no": a compose file that lists a variable
/// without a value (`- NEXAPIPE_NO_PERSIST_IDENTITY`) is asking for the default,
/// not for the behaviour being switched on. Everything else means yes, so an
/// operator who writes `NEXAPIPE_NO_PERSIST_IDENTITY=yes` gets what they meant.
///
/// Split out from the `env::var` call because `set_var` is `unsafe` in Rust
/// 2024 and the parsing is the part worth testing.
pub(crate) fn persistence_disabled(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(value) => {
            let value = value.trim();
            !(value.is_empty() || value == "0" || value.eq_ignore_ascii_case("false"))
        }
    }
}

impl ProxyConfig {
    /// Resolves the endpoint's identity for this run, generating and persisting
    /// one when the config has none.
    ///
    /// Refuses a `secret_key` that does not parse. The old behaviour was a
    /// warning and a throwaway key, which left the endpoint on a different
    /// Node ID after every restart while looking like a config problem rather
    /// than one — a typo is a typo, and the fix is to delete the line (which
    /// brings this function back) or paste a real `--generate-secret` output.
    ///
    /// A write that fails is *not* fatal. A config on a read-only mount, or one
    /// the server's user cannot write, is a normal deployment: refusing to
    /// start there would be strictly worse than the fresh-Node-ID behaviour
    /// this replaced. The key is generated either way, the warning says the
    /// Node ID will not survive a restart, and the server comes up.
    ///
    /// A `secret_key_file` the load found missing is generated into, rather
    /// than written around: the key belongs in the pointed-to file — writing it
    /// back into the config would undo the deployment's whole reason for the
    /// pointer. The same not-fatal rule covers it.
    ///
    /// Takes the already-parsed `config` rather than re-reading `path`: the
    /// caller is about to run on exactly that value, and a second read could
    /// disagree with it if the file changed in between.
    pub fn ensure_iroh_secret_key(
        path: &str,
        config: &ProxyConfig,
    ) -> anyhow::Result<EndpointIdentity> {
        let storage = crate::storage::file::FileStorage::new(path);
        match identity_action(config, storage.base_dir(), path)? {
            IdentityAction::Configured(key) => Ok(EndpointIdentity::Configured(key)),
            IdentityAction::Ephemeral => Ok(EndpointIdentity::Ephemeral(SecretString::new(
                generate_secret_key_hex(),
            ))),
            IdentityAction::IntoFile(full) => Ok(identity_into_file(&full)),
            IdentityAction::IntoConfig => {
                let hex = generate_secret_key_hex();
                match storage.write_endpoint_key(&SecretString::new(hex.clone())) {
                    Ok(()) => {
                        tracing::info!(
                            "Generated an endpoint identity and saved it to {path} as [iroh] \
                             secret_key; the Node ID is now stable across restarts"
                        );
                        Ok(EndpointIdentity::Generated(SecretString::new(hex)))
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Could not write an endpoint identity to {path} ({e:#}); starting on a \
                             throwaway one, so the Node ID will be different after the next restart"
                        );
                        Ok(EndpointIdentity::Ephemeral(SecretString::new(
                            generate_secret_key_hex(),
                        )))
                    }
                }
            }
        }
    }
}

/// What the startup path has to do about the endpoint's identity.
///
/// Split out of [`ProxyConfig::ensure_iroh_secret_key`] because the decision —
/// is there a key, is there a file to put one in, may anything be written at
/// all — is the same whichever store the configuration is in, and only the last
/// step differs: a key file is written through the file, a configuration
/// through the store that holds it.
pub(crate) enum IdentityAction {
    /// The configuration already holds a key, and it parses.
    Configured(SecretString),
    /// Write a fresh key into the file the configuration points at.
    IntoFile(PathBuf),
    /// Write a fresh key into the configuration.
    IntoConfig,
    /// Write nothing; run on a throwaway key.
    Ephemeral,
}

/// What the startup path has to do about the endpoint's identity.
///
/// `where_` names the configuration in the message a bad key produces, and
/// `base_dir` is the directory a relative `secret_key_file` is resolved
/// against.
pub(crate) fn identity_action(
    config: &ProxyConfig,
    base_dir: Option<&Path>,
    where_: &str,
) -> anyhow::Result<IdentityAction> {
    let configured = config
        .iroh
        .as_ref()
        .and_then(|iroh| iroh.secret_key.clone());

    if let Some(configured) = configured {
        configured
            .expose_secret()
            .parse::<iroh::SecretKey>()
            .map_err(|e| {
                anyhow::anyhow!(
                    "[iroh] secret_key in {where_} is not a valid key ({e}): the Node ID would \
                     change on every restart and every client would lose the server. Delete the \
                     line to have a working one generated, or run --generate-secret and paste its \
                     output"
                )
            })?;
        return Ok(IdentityAction::Configured(configured));
    }

    // A pointed-to key file that does not exist yet. Reached only when the
    // load resolved no key from it, which is exactly the first-start case:
    // a file that exists but is broken was refused during the load.
    if let Some(file) = config
        .iroh
        .as_ref()
        .and_then(|iroh| iroh.secret_key_file.as_deref())
    {
        let full = credential_file_path(base_dir, file);
        if persist_identity_disabled() {
            tracing::warn!(
                "{NO_PERSIST_ENV} is set: no secret key is written to {}, so the Node ID \
                 will be different after every restart",
                full.display()
            );
            return Ok(IdentityAction::Ephemeral);
        }
        return Ok(IdentityAction::IntoFile(full));
    }

    if persist_identity_disabled() {
        tracing::warn!(
            "{NO_PERSIST_ENV} is set: [iroh] secret_key is not written to {where_}, so the Node \
             ID will be different after every restart"
        );
        return Ok(IdentityAction::Ephemeral);
    }

    Ok(IdentityAction::IntoConfig)
}

/// The identity that comes from a key file: written when it can be, thrown away
/// when it cannot.
///
/// A write that fails is *not* fatal. A config on a read-only mount, or one
/// the server's user cannot write, is a normal deployment: refusing to start
/// there would be strictly worse than the fresh-Node-ID behaviour this
/// replaced. The key is generated either way, the warning says the Node ID
/// will not survive a restart, and the server comes up.
pub(crate) fn identity_into_file(full: &Path) -> EndpointIdentity {
    match write_key_file(full) {
        Ok(hex) => {
            tracing::info!(
                "Generated an endpoint identity and saved it to {}; the Node ID is now \
                 stable across restarts",
                full.display()
            );
            EndpointIdentity::Generated(SecretString::new(hex))
        }
        Err(e) => {
            tracing::warn!(
                "Could not write an endpoint identity to {} ({e:#}); starting on a \
                 throwaway one, so the Node ID will be different after the next restart",
                full.display()
            );
            EndpointIdentity::Ephemeral(SecretString::new(generate_secret_key_hex()))
        }
    }
}

/// A fresh ed25519 key as the hex `config.toml` stores it in.
///
/// Shared by `--generate-secret` and the startup path so both spell a key the
/// same way: a hex string that round-trips through `SecretKey::from_str` is the
/// only thing either of them promises.
pub fn generate_secret_key_hex() -> String {
    hex::encode(iroh::SecretKey::generate().to_bytes())
}

/// The environment variable carrying `[iroh] secret_key` directly.
///
/// For a deployment that keeps credentials out of the config file entirely. It
/// outranks a pointed-to file and the inline literal — and a config that names
/// more than one source is refused rather than ranked (see
/// `refuse_ambiguous_credential_sources`), because a silently-picked winner is
/// how an endpoint ends up on a Node ID nobody expected.
pub(crate) const IROH_SECRET_KEY_ENV: &str = "NEXAPIPE_IROH_SECRET_KEY";

/// The environment variable carrying the *path* of the file holding
/// `[iroh] secret_key`.
///
/// The file-pointing twin of [`IROH_SECRET_KEY_ENV`], for a deployment (the
/// docker compose setup is one) that keeps the key in a file of its own
/// choosing — a mounted secrets directory — rather than next to the config.
/// Unlike a relative `secret_key_file` in the config, this path is taken
/// literally (anchored on the working directory if relative), because
/// environment wiring speaks in process paths, not config-relative ones.
pub(crate) const IROH_SECRET_KEY_FILE_ENV: &str = "NEXAPIPE_IROH_SECRET_KEY_FILE";

/// The environment variable carrying `[iroh] relay_auth_token` directly.
pub(crate) const RELAY_AUTH_TOKEN_ENV: &str = "NEXAPIPE_RELAY_AUTH_TOKEN";

/// The raw value of an environment credential, when the variable is set.
///
/// Whether the value counts — a blank or whitespace-only one means "not
/// named", the same rule `NEXAPIPE_NO_PERSIST_IDENTITY` follows — is decided
/// where the sources are ranked, in [`resolve_secret_key_source`] and
/// [`resolve_relay_auth_token_source`], so the ranking is testable without
/// touching process state.
pub(crate) fn credential_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Whether any environment variable names an `[iroh]` credential.
///
/// Blank or whitespace-only values count as unset, the same rule the value
/// variables follow in the resolver. Used to decide whether a config that has
/// no `[iroh]` table at all needs one materialised in memory before the
/// external sources can be resolved.
pub(crate) fn environment_names_iroh_credential() -> bool {
    let named = |name: &str| {
        credential_env(name)
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    };
    named(IROH_SECRET_KEY_ENV) || named(IROH_SECRET_KEY_FILE_ENV) || named(RELAY_AUTH_TOKEN_ENV)
}

/// Refuses a `[iroh]` credential that more than one source names.
///
/// One credential, one answer. Any ranking would leave the deployment's
/// behaviour turning on which of the two the operator last touched — for the
/// endpoint key that is a Node ID rotating underneath every client that stored
/// it — so a config that says two things is refused instead of adjudicated.
pub(crate) fn refuse_ambiguous_credential_sources(
    what: &str,
    sources: &[Option<&str>],
) -> anyhow::Result<()> {
    let named: Vec<&str> = sources.iter().flatten().copied().collect();
    if named.len() > 1 {
        anyhow::bail!(
            "[iroh] {what} is named by {} — one credential, one source; keep exactly one of them",
            named.join(", ")
        );
    }
    Ok(())
}

/// Turns an environment-named file path into an absolute one.
///
/// A config `secret_key_file` is read against the config's directory (see
/// [`credential_file_path`]); an environment path is deployment wiring, so it
/// is taken literally and only a relative one gets anchored, on the process's
/// working directory.
pub(crate) fn absolute_env_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

/// The path a `*_file` key names, relative paths against the config file's
/// directory.
///
/// Anchoring on the config rather than the working directory is what makes a
/// sibling file (`secret_key_file = "iroh.key"`) mean the same thing no matter
/// where the server is started from — the same reading
/// `config.toml.admin-token` gets.
pub(crate) fn credential_file_path(config_dir: Option<&Path>, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    config_dir.unwrap_or(Path::new(".")).join(path)
}

/// Reads the file a `*_file` credential names.
///
/// `None` when the file does not exist — the caller decides whether that is a
/// first start (a secret key is generated into the file) or a broken config (a
/// relay token cannot be invented). An empty file is refused rather than read
/// as "no credential": the pointer was spelled, and pointing it at a blank file
/// is a typo to see, not a mode.
///
/// Held to the credential-file permission rule
/// (`check_credential_file_permissions`): this file *is* the credential now,
/// so one another account can read or write refuses the load.
pub(crate) fn read_credential_file(
    full: &Path,
    what: &str,
) -> anyhow::Result<Option<SecretString>> {
    // The file holds the credential in the clear, so the buffer it lands in is
    // wiped when it goes out of scope: wrap the read before trimming, so the
    // copy that outlives this function is the zeroizing one.
    let content = SecretString::new(match fs::read_to_string(full) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!("cannot read the {what} file {}: {e}", full.display()),
    });
    let content = content.expose_secret().trim();
    if content.is_empty() {
        anyhow::bail!(
            "{}: the {what} file holds nothing; write the credential into it and nothing else",
            full.display()
        );
    }
    check_credential_file_permissions(&full.to_string_lossy())?;
    Ok(Some(SecretString::new(content.to_string())))
}

/// Resolves `[iroh] secret_key` from its candidate sources: the environment
/// value, the environment-named file, the file `secret_key_file` names, then
/// the literal.
///
/// `env_raw` and `env_file` are passed in rather than read here so the ranking
/// is testable without touching process state; the caller hands them over from
/// [`credential_env`], with `env_file` already made absolute by
/// [`absolute_env_path`]. `Ok(None)` means nothing named a key — including a
/// pointed-to file that does not exist yet, which is the first-start case
/// [`ProxyConfig::ensure_iroh_secret_key`] generates into. The caller folds an
/// environment-named missing path onto the `secret_key_file` field so the
/// generation lands in the file the environment named, not back in the config.
pub(crate) fn resolve_secret_key_source(
    config_dir: Option<&Path>,
    env_raw: Option<String>,
    env_file: Option<&Path>,
    iroh: &IrohConfig,
) -> anyhow::Result<Option<(SecretString, CredentialSource)>> {
    // A trailing newline from `printf`, or a compose file that lists the
    // variable without a value, must neither become key bytes nor count as a
    // source: trim, and a leftover blank means the environment named nothing.
    let env = env_raw
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    refuse_ambiguous_credential_sources(
        "secret_key",
        &[
            env.map(|_| IROH_SECRET_KEY_ENV),
            env_file.map(|_| IROH_SECRET_KEY_FILE_ENV),
            iroh.secret_key_file.as_deref().map(|_| "secret_key_file"),
            iroh.secret_key.as_ref().map(|_| "secret_key"),
        ],
    )?;

    if let Some(key) = env {
        return Ok(Some((
            SecretString::new(key.to_string()),
            CredentialSource::Env,
        )));
    }
    // An environment-named file outranks the config's pointer: both are files,
    // but deployment wiring wins over what the file on disk says.
    if let Some(full) = env_file.map(Path::to_path_buf).or_else(|| {
        iroh.secret_key_file
            .as_ref()
            .map(|file| credential_file_path(config_dir, file))
    }) {
        return match read_credential_file(&full, "secret_key")? {
            Some(key) => Ok(Some((key, CredentialSource::File))),
            None => Ok(None),
        };
    }
    Ok(iroh
        .secret_key
        .clone()
        .map(|key| (key, CredentialSource::Inline)))
}

/// Resolves `[iroh] relay_auth_token` from its candidate sources, in the same
/// order [`resolve_secret_key_source`] ranks them.
///
/// Unlike a secret key, a pointed-to token file that does not exist is refused
/// rather than deferred: the server cannot invent a relay token, and a missing
/// one would otherwise surface later as a vaguer relay-configuration error.
pub(crate) fn resolve_relay_auth_token_source(
    config_dir: Option<&Path>,
    env_raw: Option<String>,
    iroh: &IrohConfig,
) -> anyhow::Result<Option<(SecretString, CredentialSource)>> {
    // The same blank-means-nothing reading the secret key gives the
    // environment.
    let env = env_raw
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    refuse_ambiguous_credential_sources(
        "relay_auth_token",
        &[
            env.map(|_| RELAY_AUTH_TOKEN_ENV),
            iroh.relay_auth_token_file
                .as_deref()
                .map(|_| "relay_auth_token_file"),
            iroh.relay_auth_token.as_ref().map(|_| "relay_auth_token"),
        ],
    )?;

    if let Some(token) = env {
        return Ok(Some((
            SecretString::new(token.to_string()),
            CredentialSource::Env,
        )));
    }
    if let Some(file) = &iroh.relay_auth_token_file {
        let full = credential_file_path(config_dir, file);
        return match read_credential_file(&full, "relay_auth_token")? {
            Some(token) => Ok(Some((token, CredentialSource::File))),
            None => anyhow::bail!(
                "[iroh] relay_auth_token_file {} does not exist; unlike a secret key, a relay \
                 token cannot be generated, so write the token into the file first",
                full.display()
            ),
        };
    }
    Ok(iroh
        .relay_auth_token
        .clone()
        .map(|token| (token, CredentialSource::Inline)))
}

impl ProxyConfig {
    /// Resolves the `[iroh]` credentials that name a source outside this file.
    ///
    /// Both parse paths come through here — `from_file` for the server and the
    /// config watcher, `load_with_auth` for the 2FA-facing commands and the
    /// auth reload — so a credential is resolved the same way however the
    /// config was read. The resolved value replaces the field, and the
    /// [`CredentialSource`] it came from is recorded next to it: what
    /// [`ProxyConfig::holds_credentials`] then asks is not "is there a key"
    /// but "is the key in *this file*", which is what the permission gate is
    /// about.
    pub(crate) fn resolve_external_credentials(
        &mut self,
        config_dir: Option<&Path>,
    ) -> anyhow::Result<()> {
        // A config with no `[iroh]` table at all still has to honour
        // credentials wired through the environment: the docker compose setup
        // points NEXAPIPE_IROH_SECRET_KEY_FILE at a secrets directory against
        // exactly such a file — the generated first-run template has no
        // `[iroh]` table. Skipping resolution here used to let the key fall
        // through to the inline write-back into config.toml, and the watcher's
        // next reload then refused it as two sources naming one key.
        // Materialise an empty table in memory only — resolution never writes
        // the config — and resolve as usual.
        if self.iroh.is_none() && environment_names_iroh_credential() {
            self.iroh = Some(IrohConfig::default());
        }

        let Some(iroh) = self.iroh.as_mut() else {
            return Ok(());
        };

        // Blank means unset, the same rule the value env vars get; made
        // absolute here because environment paths are not config-relative.
        let env_key_file = credential_env(IROH_SECRET_KEY_FILE_ENV)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(|value| absolute_env_path(Path::new(&value)));

        match resolve_secret_key_source(
            config_dir,
            credential_env(IROH_SECRET_KEY_ENV),
            env_key_file.as_deref(),
            iroh,
        )? {
            Some((key, source)) => {
                iroh.secret_key = Some(key);
                iroh.secret_key_source = source;
            }
            None => {
                // Nothing resolved. If the environment named a file that does
                // not exist yet, fold its path onto the pointer field: the
                // first-start generation in ensure_iroh_secret_key then writes
                // the key there rather than inline back into this config.
                if let Some(env_file) = env_key_file {
                    iroh.secret_key_file = Some(env_file.to_string_lossy().into_owned());
                }
            }
        }
        if let Some((token, source)) =
            resolve_relay_auth_token_source(config_dir, credential_env(RELAY_AUTH_TOKEN_ENV), iroh)?
        {
            iroh.relay_auth_token = Some(token);
            iroh.relay_auth_token_source = source;
        }
        Ok(())
    }
}

/// Writes a freshly generated key to the file `secret_key_file` names, or
/// reads back the one that is already there.
///
/// `create_new` first rather than checking then writing: the load saw no file,
/// and one appearing in between holds the credential now — replacing it would
/// rotate the identity underneath whoever read it in that window. The same
/// read-back on a lost race `config.toml.admin-token` does.
pub(crate) fn write_key_file(path: &Path) -> anyhow::Result<String> {
    let key = iroh::SecretKey::generate();
    let hex = hex::encode(key.to_bytes());
    match create_private_file(path) {
        Ok(mut file) => {
            // sync_all, not flush: for a regular file flush is nearly a no-op,
            // and a crash between write and durability could leave a truncated
            // key on disk that the next start refuses with "holds nothing".
            // A failed write removes the file too — otherwise this one failure
            // would leave an empty file behind that makes every later start
            // refuse instead of regenerating. The handle must be dropped first
            // so the remove works on Windows as well.
            if let Err(e) = file.write_all(hex.as_bytes()).and_then(|_| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(path);
                anyhow::bail!("cannot write {}: {e}", path.display());
            }
            Ok(hex)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!(
                    "{} appeared while the key was being generated, and reading it back \
                     failed: {e}",
                    path.display()
                )
            })?;
            let existing = existing.trim();
            if existing.is_empty() {
                anyhow::bail!("{} appeared and holds nothing", path.display());
            }
            // The winner of the race wrote the file, not us, so hold it to the
            // same permission rule a normal load applies: a 0644 key a sibling
            // account dropped in is refused the same way it would be on reload.
            check_credential_file_permissions(&path.to_string_lossy())?;
            Ok(existing.to_string())
        }
        Err(e) => Err(e).map_err(|e| anyhow::anyhow!("cannot create {}: {e}", path.display())),
    }
}

/// Creates a new file only this account can read.
///
/// The mode is set at creation rather than chmod'ed after: between the two the
/// file exists with the default mode, and a credential is worth less than a
/// second of that. `mode` is applied against the umask, so the bits are set
/// again and confirmed — the same care `admin::token::create_private` takes.
#[cfg(unix)]
pub(crate) fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// No file modes to set outside Unix, so the file is created as it comes.
#[cfg(not(unix))]
pub(crate) fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

impl ProxyConfig {
    /// Writes a freshly generated `secret_key` into `[iroh]` of the config file
    /// at `path`, and returns the hex key now in it.
    ///
    /// The whole point of this function is that a Node ID nobody had to write
    /// down is still stable: an operator who skipped `--generate-secret` used
    /// to get a fresh one on every restart, and every client that had stored it
    /// lost the server. Generating the key here rather than in the endpoint
    /// builder is what makes it survive, because the builder's key is never
    /// written anywhere.
    ///
    /// Only ever called when `[iroh] secret_key` is *absent*. A key that is
    /// present but does not parse is refused at startup rather than replaced
    /// here: it is a typo the operator has to see, and silently replacing it
    /// would swap the endpoint's identity underneath whatever the typo was
    /// supposed to be — including a key that was merely truncated past the
    /// end of the line.
    ///
    /// Comments, key order and every other section survive: the document is
    /// edited as TOML rather than re-serialized from a `ProxyConfig`, which
    /// would drop the operator's prose along with the config.
    pub fn write_iroh_secret_key(path: &str) -> anyhow::Result<String> {
        let hex = generate_secret_key_hex();
        crate::storage::file::FileStorage::new(path)
            .write_endpoint_key(&SecretString::new(hex.clone()))?;
        Ok(hex)
    }
}

//! The credential half of the configuration file.
//!
//! The shapes here are the ones on disk, which are not the shapes the server
//! holds: the file says when a client was enrolled and the server says what it
//! enrolled, and the two are translated into each other.
//!
//! The loaders that read these shapes are in [`super::load`], and the writes
//! that change them are the storage's — this module is the spelling of the
//! file, and the storage is what puts it on disk.

use nexapipe_proto::secret::SecretString;

use serde::Deserialize;

use std::collections::HashMap;

use crate::storage::file::FileStorage;

use super::*;

/// Authentication config in TOML format.
///
/// Unknown keys are refused here, and only here. This is the one section where
/// a typo is a security change rather than a lost setting: `enable = true`
/// instead of `enabled` left 2FA off with nothing in the log to say so, since
/// serde drops what it does not recognise and the default for `enabled` is
/// false. Every other section stays lenient, the way a config that has carried
/// a stray key for years expects.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuthTomlConfig {
    pub enabled: Option<bool>,
    pub issuer: Option<String>,
    pub algorithm: Option<String>,
    pub time_step: Option<u32>,
    pub digits: Option<u32>,
    pub window: Option<u32>,
    pub max_attempts: Option<u32>,
    pub lockout_duration: Option<u64>,
    pub clients: Option<HashMap<String, ClientAuthToml>>,
}

/// One `[auth.clients.<id>]` entry.
///
/// Unknown keys are refused for the same reason as in [`AuthTomlConfig`]: a
/// misspelled `allow_host` is not "no restriction", but that is what it
/// quietly became.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthToml {
    /// A [`SecretString`]: the seed is a credential from the moment the file
    /// is read, and the file format is unchanged by the wrapper.
    pub secret: SecretString,
    pub created_at: Option<String>,
    /// Host patterns this client may reach; `None` means every route. Folded
    /// into the client's [`crate::auth::ClientAcl`] when a connection
    /// authenticates.
    pub allow_hosts: Option<Vec<String>>,
    /// Ports this client may reach; `None` means every port.
    ///
    /// The other half of `allow_hosts`: a host is a name, a port is a service
    /// on that name, and a client that may have the name does not
    /// automatically get every service on it.
    pub allow_ports: Option<Vec<u16>>,
    /// Whether `allow_ports` is checked against the port the request is served
    /// from rather than the one the client names.
    ///
    /// Off by default: turning it on changes what an existing configuration
    /// allows, so an operator opts in.
    pub allow_ports_strict: Option<bool>,
    /// A one-time enrollment token outstanding for this client, written by
    /// `--generate-invite --registration` and cleared by whoever spends it. Not
    /// written back by `save_auth_state`: it belongs to the operator, not to
    /// the runtime.
    pub pending_enrollment: Option<SecretString>,
    /// `[auth.clients.<id>.devices.<name>]` — credentials issued to individual
    /// devices, each with a secret of its own so one can be dropped without
    /// rotating the others. Absent means this client has never issued one, and
    /// every device then shares the `secret` above.
    pub devices: Option<HashMap<String, DeviceAuthToml>>,
    /// Whether a peer that names no device may still answer with the `secret`
    /// above. Defaults to `true`, which is the only spelling a client that
    /// predates the device table can authenticate under.
    pub unnamed_device_allowed: Option<bool>,
    /// Runtime counters, read here so a lockout survives a restart.
    ///
    /// The server writes these to its own state file now, beside this one, and
    /// not here — see [`crate::auth::state`]. They are still read from this
    /// file, so a deployment that counted here before the state file existed
    /// keeps its lockouts; the state file takes over once it has an entry for
    /// this client.
    pub failed_attempts: Option<u32>,
    pub locked_until: Option<u64>,
    pub last_used: Option<u64>,
}

/// One `[auth.clients.<id>.devices.<name>]` entry.
///
/// Unknown keys are refused for the same reason as in [`ClientAuthToml`]. There
/// is no `allow_hosts` here on purpose: what a client may reach is answered by
/// the client's entry alone, and a second place to say it is a second place for
/// it to disagree.
///
/// One of `secret` and `public_key` has to be set and the other has to not be,
/// which the loader enforces where the operator can see which entry it is
/// about; both fields are `Option` so that either spelling parses far enough to
/// be told what is wrong with it.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthToml {
    pub secret: Option<SecretString>,
    /// The device's Ed25519 public key, hex: the credential of a device that
    /// signs its handshake instead of answering with a TOTP code.
    pub public_key: Option<String>,
    pub created_at: Option<String>,
    /// Read here so "when did this device last connect" survives a restart.
    ///
    /// The stamp is written to the server's state file, beside the
    /// configuration, and not here — see [`crate::auth::state`].
    pub last_used: Option<u64>,
}

/// Checks a credential sidecar file's permissions before its secret becomes
/// live.
///
/// These files hold one secret and nothing else — the endpoint key a
/// `secret_key_file` / `NEXAPIPE_IROH_SECRET_KEY_FILE` points at, a relay
/// token file, or the admin IPC token — so there is no "nothing live in it
/// yet" half-way case, as the old config-file gate had: a file another
/// account can read or write is refused outright. `config.toml` itself is deliberately no
/// longer checked: operator-edited bind mounts are commonly 0644, and the
/// credentials now belong in a sidecar like this one or in the environment.
/// A file that cannot be stat'ed is not this function's problem: the caller
/// has already read it to get here.
#[cfg(unix)]
pub fn check_credential_file_permissions(path: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{path} is readable or writable by other accounts (mode {mode:o}) and holds a \
             credential; run `chmod 600 {path}`"
        );
    }
    Ok(())
}

/// No file modes to inspect outside Unix, so there is nothing to refuse.
#[cfg(not(unix))]
pub fn check_credential_file_permissions(_path: &str) -> anyhow::Result<()> {
    Ok(())
}

impl ProxyConfig {
    /// Writes `secret` under `[auth.clients.<client_id>]` of the config file at
    /// `path`, creating `[auth]` and `[auth.clients]` when they are missing.
    ///
    /// The document is edited as TOML instead of being re-serialized from a
    /// `ProxyConfig`, so comments, key order and the layout of every other
    /// section survive — which is the whole point, this edits the file a human
    /// wrote. `force` is what allows an existing secret to be replaced: a device
    /// that already imported the old one stops authenticating the instant it
    /// changes, so callers keep the existing secret unless told otherwise.
    ///
    /// `[auth] enabled` is deliberately left alone: flipping it on would turn
    /// 2FA on for every client, not just the one being enrolled.
    pub fn write_client_secret(
        path: &str,
        client_id: &str,
        secret: &str,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        FileStorage::new(path).write_client_secret(
            client_id,
            &SecretString::new(secret.to_string()),
            force,
        )
    }

    /// Records a one-time enrollment token for `client_id`.
    ///
    /// Any token already outstanding is replaced, which is how an invitation
    /// that never arrived gets revoked: generate another one and the old link
    /// stops working. The client's secret is left alone — enrollment does not
    /// touch it until a token is actually spent.
    ///
    /// The client has to exist: a `[auth.clients.<id>]` section with a token and
    /// no secret would fail to load.
    pub fn write_pending_enrollment(
        path: &str,
        client_id: &str,
        token: &str,
    ) -> anyhow::Result<()> {
        FileStorage::new(path)
            .write_pending_enrollment(client_id, &SecretString::new(token.to_string()))
    }

    /// Spends the token: writes the issued `secret` and drops
    /// `pending_enrollment`, so the same link cannot enroll twice.
    ///
    /// Both keys are written in one pass on purpose. A secret on disk with the
    /// token still beside it would leave the window open for a second device to
    /// trade the same link for the same credential.
    pub fn complete_enrollment(path: &str, client_id: &str, secret: &str) -> anyhow::Result<()> {
        FileStorage::new(path)
            .complete_enrollment(client_id, &SecretString::new(secret.to_string()))
    }

    /// Spends the token for one named device: writes that device's own
    /// credential into `[auth.clients.<id>.devices.<name>]` and drops
    /// `pending_enrollment`, leaving the client's `secret` as it was.
    ///
    /// The material is whichever the enrollment turned on: a secret the server
    /// generated, or the public key the device offered in ENROLL_START.
    ///
    /// The client's secret is deliberately untouched. It is the credential of
    /// the device that has no name — every device that enrolled before this
    /// table existed — so rotating it is what re-enrolls all of them at once,
    /// and an enrollment that names a device is the one case where that is
    /// known not to be what was asked for. [`Self::complete_enrollment`] is
    /// still the answer for an enrollment that names none, and still rotates it.
    ///
    /// Both keys move in one pass, for the reason given there: a secret on disk
    /// with the token still beside it would leave the window open for a second
    /// device to trade the same link for the same credential.
    ///
    /// The entry lands where [`Self::write_device_credential`] puts one: both
    /// writers go through the same device table, so a device that spent a token
    /// and one an operator wrote by hand are the same shape on disk.
    pub fn complete_device_enrollment(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
    ) -> anyhow::Result<()> {
        FileStorage::new(path).complete_device_enrollment(
            client_id,
            device,
            crate::storage::DeviceCredential::from(material),
        )
    }

    /// Writes one device's credential — a TOTP secret or a public key — under
    /// `[auth.clients.<client_id>.devices.<device>]`, which is what gives one
    /// device of a client a credential of its own.
    ///
    /// The client's own `secret` is deliberately left alone: it is the
    /// credential of the device that names none, so rotating it re-enrolls
    /// every unnamed device at once, and issuing one device a credential of its
    /// own is exactly the case where that is known not to be what was asked
    /// for.
    ///
    /// `force` is what allows an existing device to be issued another one, for
    /// the reason [`Self::write_client_secret`] needs it: a device already
    /// using the old credential stops authenticating the moment it changes.
    /// Replacing one kind with the other has to go through `force` the same
    /// way — a device that answered with a code and now answers with a
    /// signature is as enrolled-out as one whose secret changed.
    ///
    /// What it writes is the entry [`Self::complete_device_enrollment`] writes
    /// when a device spends a token — one shape on disk, reached the same way.
    /// The two differ only in what has to be true first: an enrollment has a
    /// token to spend, and this has an operator, who has to say `--force`
    /// before an existing credential is replaced.
    ///
    /// The client has to be there first — a device table under a client with no
    /// secret of its own is a config that will not load.
    pub fn write_device_credential(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        FileStorage::new(path).write_device_credential(
            client_id,
            device,
            crate::storage::DeviceCredential::from(material),
            force,
        )
    }

    /// Drops one device's credential: `[auth.clients.<client_id>.devices.<device>]`.
    ///
    /// Revoking is a delete and not a rotation, because a deleted entry is the
    /// one thing the handshake reads as "this device has no credential" — the
    /// same answer a device that never enrolled gets, so what happened cannot be
    /// told apart from outside. The client's own `secret` is left alone: it
    /// belongs to the device that names none, and a client with one is not
    /// revoked by dropping a device that named itself.
    pub fn remove_device(path: &str, client_id: &str, device: &str) -> anyhow::Result<()> {
        FileStorage::new(path).remove_device(client_id, device)
    }

    /// Drops a client and every device under it: all of
    /// `[auth.clients.<client_id>]`.
    pub fn remove_client(path: &str, client_id: &str) -> anyhow::Result<()> {
        FileStorage::new(path).remove_client(client_id)
    }
}

/// What [`ProxyConfig::write_client_secret`] did to the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSecretWrite {
    /// A `[auth.clients.<id>]` section was added, creating `[auth]` if needed.
    Added,
    /// The client already had a secret, and it was replaced.
    Replaced,
}

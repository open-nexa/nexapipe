//! The runtime 2FA state, kept beside the configuration instead of inside it.
//!
//! The configuration file is the operator's: they wrote it, they read it, they
//! keep it in version control, and a comment in it is a comment they wrote.
//! The counters a running server keeps — how many times a client mistyped a
//! code, until when it is locked out, when it was last seen — are none of
//! that. They are what the server learned while it was running, and they have
//! to survive a restart for a lockout to mean anything.
//!
//! Writing them into the configuration file made one file carry two things
//! that disagree about who owns it, and it had a cost beyond tidiness: the
//! file's modification time moved every time a client mistyped a code, and the
//! configuration watcher watches exactly that. A lockout was therefore a
//! configuration reload — the routes rebuilt and the health checks restarted,
//! because a stranger typed a code wrong.
//!
//! So the counters live in their own file, `state.toml`, beside the
//! configuration. The shape is the same on purpose: an operator who opens
//! `state.toml` next to `config.toml` sees the same client and device names
//! in both, and a mistake in one is a mistake in the other. The contents are
//! not the same: only the counters, and nothing an operator wrote.
//!
//! What is in the configuration file stays there. The three keys
//! (`failed_attempts`, `locked_until`, `last_used`) are still read from it, so
//! a deployment that was counting in the configuration file before this
//! existed keeps its lockouts; they are simply no longer written there, and
//! the state file is what decides once it has an entry for that client.

use super::config::AuthConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The file the runtime state lives in, beside the configuration file.
///
/// Derived from the configuration's own path rather than from a directory of
/// its own, so the two travel together: a configuration in
/// `/etc/nexapipe/config.toml` puts its state in `/etc/nexapipe/state.toml`,
/// and the two cannot end up in different places by accident. A configuration
/// with no directory of its own — `config.toml` in the working directory —
/// gets `state.toml` beside it.
pub fn path_for(config_path: &str) -> PathBuf {
    let path = Path::new(config_path);
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent.join("state.toml"),
        None => PathBuf::from("state.toml"),
    }
}

/// The runtime state of every client the server has counted.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeState {
    /// The counters, per client.
    #[serde(default)]
    pub clients: HashMap<String, ClientState>,
}

/// What the server knows about one client's authentication.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientState {
    /// How many times in a row the client got it wrong.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub failed_attempts: u32,
    /// When the lockout runs out, as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<u64>,
    /// How many times in a row a guess at the pending enrollment token was
    /// wrong.
    ///
    /// The enrollment's own counter, kept apart from `failed_attempts` for the
    /// reason [`crate::auth::ClientAuth::enrollment_failed_attempts`] gives: a
    /// client id is not a secret, so a stranger who knows one must not be able
    /// to lock the client's own devices out of authenticating.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub enrollment_failed_attempts: u32,
    /// When the enrollment lockout runs out, as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_locked_until: Option<u64>,
    /// When the client last authenticated, as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<u64>,
    /// The per-device stamps.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub devices: HashMap<String, DeviceState>,
}

/// What the server knows about one device of a client.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceState {
    /// When the device last authenticated, as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<u64>,
}

/// A zero counter is not written: a state file that accumulated
/// `failed_attempts = 0` lines for every client that ever existed would say
/// less than one that says nothing.
fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// The file on disk, in the shape it is written.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StateFile {
    /// The same section the configuration file uses, so the two read alike.
    #[serde(default)]
    auth: StateSection,
}

/// The `[auth]` section of the state file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StateSection {
    /// The per-client counters.
    #[serde(default)]
    clients: HashMap<String, ClientState>,
}

/// Reads the runtime state.
///
/// A file that is not there is an empty state, not an error: this is the
/// first start of a deployment that has never counted anything, and it is the
/// normal state of a deployment whose state file was removed by an operator
/// who wanted the lockouts gone.
///
/// A file that is there and cannot be read **is** an error, and the server
/// refuses to start on it. A state file that cannot be parsed is a state
/// whose lockouts are unknown, and a server that starts anyway is a server
/// that has just reset every lockout it had — which is exactly what an
/// attacker who can damage one file wants. The message says which file and
/// what to do about it, because an operator who cannot start their proxy
/// needs a way forward rather than a refusal.
pub fn load(path: &Path) -> anyhow::Result<RuntimeState> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RuntimeState::default()),
        Err(e) => {
            anyhow::bail!("cannot read the 2FA state {}: {e}", path.display());
        }
    };

    let file: StateFile = toml::from_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "the 2FA state {} cannot be read ({e}); fix it or remove it to start without the \
             lockouts it holds",
            path.display()
        )
    })?;

    Ok(RuntimeState {
        clients: file.auth.clients,
    })
}

/// Writes the runtime state.
///
/// The write is a temporary file and a rename, like the configuration's, so a
/// process killed in the middle of it leaves the old state rather than a
/// half-written one — a half-written state file would not parse, and the
/// server refuses to start on one.
///
/// The mode is `0600`, like the configuration's: the file says which clients
/// are locked out and when they were last seen, which is not a secret but is
/// not the business of every local account either.
pub fn save(path: &Path, state: &RuntimeState) -> anyhow::Result<()> {
    let file = StateFile {
        auth: StateSection {
            clients: state.clients.clone(),
        },
    };
    let contents = toml::to_string_pretty(&file)
        .map_err(|e| anyhow::anyhow!("cannot render the 2FA state: {e}"))?;

    crate::config::write_config_file(&path.to_string_lossy(), &contents)
}

/// The counters of every client and device in `config`.
///
/// This is what gets written: the credentials, the host lists and the
/// enrollment tokens stay where they are, and only the counters travel.
///
/// A client the server has never counted is left out. The snapshot carries
/// every client the configuration knows about, and writing all of them would
/// fill the state file with empty tables for clients that never mistyped a
/// code. A device is left out on the same grounds — a stamp is the only thing
/// a device has.
pub fn snapshot(config: &AuthConfig) -> RuntimeState {
    let mut clients = HashMap::with_capacity(config.clients.len());
    for (id, client) in &config.clients {
        let mut devices = HashMap::with_capacity(client.devices.len());
        for (name, device) in &client.devices {
            if device.last_used.is_none() {
                continue;
            }
            devices.insert(
                name.clone(),
                DeviceState {
                    last_used: device.last_used,
                },
            );
        }

        let state = ClientState {
            failed_attempts: client.failed_attempts,
            locked_until: client.locked_until,
            enrollment_failed_attempts: client.enrollment_failed_attempts,
            enrollment_locked_until: client.enrollment_locked_until,
            last_used: client.last_used,
            devices,
        };
        if is_empty(&state) {
            continue;
        }
        clients.insert(id.clone(), state);
    }
    RuntimeState { clients }
}

/// Whether a client has nothing worth writing down.
fn is_empty(state: &ClientState) -> bool {
    state.failed_attempts == 0
        && state.locked_until.is_none()
        && state.enrollment_failed_attempts == 0
        && state.enrollment_locked_until.is_none()
        && state.last_used.is_none()
        && state.devices.is_empty()
}

/// Moves the counters in `state` onto `config`.
///
/// A client the state file has no entry for keeps the counters it was loaded
/// with. That is the migration: a deployment that counted in the
/// configuration file before the state file existed still holds its lockouts,
/// and the first time the server counts that client again the state file
/// gains an entry for it and takes over.
///
/// A client the state file has but the configuration does not is ignored: the
/// operator removed it, and a counter nobody can authenticate against is
/// nothing to keep.
pub fn apply(state: &RuntimeState, config: &mut AuthConfig) {
    for (id, client) in &mut config.clients {
        let Some(client_state) = state.clients.get(id) else {
            continue;
        };
        client.failed_attempts = client_state.failed_attempts;
        client.locked_until = client_state.locked_until;
        client.enrollment_failed_attempts = client_state.enrollment_failed_attempts;
        client.enrollment_locked_until = client_state.enrollment_locked_until;
        client.last_used = client_state.last_used;

        for (name, device) in &mut client.devices {
            if let Some(device_state) = client_state.devices.get(name) {
                device.last_used = device_state.last_used;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::ClientAuth;

    fn client(
        failed_attempts: u32,
        locked_until: Option<u64>,
        last_used: Option<u64>,
    ) -> ClientAuth {
        ClientAuth {
            secret: nexapipe_proto::secret::SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            created_at: "0".to_string(),
            allow_hosts: None,
            allow_ports: None,
            allow_ports_strict: false,
            pending_enrollment: None,
            devices: HashMap::new(),
            unnamed_device_allowed: true,
            last_used,
            failed_attempts,
            locked_until,
            enrollment_failed_attempts: 0,
            enrollment_locked_until: None,
        }
    }

    #[test]
    fn a_state_that_is_not_there_is_an_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let state = load(&path).expect("a file that is not there is not an error");
        assert!(state.clients.is_empty());
    }

    #[test]
    fn a_state_that_cannot_be_read_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        std::fs::write(&path, "this is not TOML at all: \"\n").unwrap();
        let error = load(&path).expect_err("a broken state file refuses the start");
        assert!(
            error.to_string().contains("state.toml"),
            "the message names the file: {error}"
        );
    }

    #[test]
    fn the_counters_survive_a_write_and_a_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config.clients.insert(
            "alice".to_string(),
            client(2, Some(1700000000), Some(1699999999)),
        );

        save(&path, &snapshot(&config)).expect("the write succeeds");
        let state = load(&path).expect("the read succeeds");

        let alice = &state.clients["alice"];
        assert_eq!(alice.failed_attempts, 2);
        assert_eq!(alice.locked_until, Some(1700000000));
        assert_eq!(alice.last_used, Some(1699999999));
    }

    #[test]
    fn a_zero_counter_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(0, None, None));

        save(&path, &snapshot(&config)).expect("the write succeeds");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("failed_attempts"),
            "a zero counter says nothing: {on_disk}"
        );
        assert!(!on_disk.contains("locked_until"), "{on_disk}");
        assert!(!on_disk.contains("last_used"), "{on_disk}");
    }

    #[test]
    fn the_state_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(1, None, None));

        save(&path, &snapshot(&config)).expect("the write succeeds");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the state file is private: {mode:o}");
        }
    }

    #[test]
    fn the_state_file_sits_beside_the_configuration() {
        assert_eq!(
            path_for("/etc/nexapipe/config.toml"),
            PathBuf::from("/etc/nexapipe/state.toml")
        );
        assert_eq!(path_for("config.toml"), PathBuf::from("state.toml"));
    }

    #[test]
    fn a_client_the_state_does_not_know_keeps_its_loaded_counters() {
        // The migration: a deployment that counted in the configuration file
        // keeps its lockout until the state file has an entry for it.
        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(3, Some(1700000000), None));

        apply(&RuntimeState::default(), &mut config);

        let alice = &config.clients["alice"];
        assert_eq!(alice.failed_attempts, 3);
        assert_eq!(alice.locked_until, Some(1700000000));
    }

    #[test]
    fn the_state_wins_over_the_loaded_counters() {
        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(3, Some(1700000000), None));

        let mut state = RuntimeState::default();
        state.clients.insert(
            "alice".to_string(),
            ClientState {
                failed_attempts: 0,
                locked_until: None,
                enrollment_failed_attempts: 0,
                enrollment_locked_until: None,
                last_used: Some(1699999999),
                devices: HashMap::new(),
            },
        );

        apply(&state, &mut config);

        let alice = &config.clients["alice"];
        assert_eq!(alice.failed_attempts, 0);
        assert_eq!(alice.locked_until, None);
        assert_eq!(alice.last_used, Some(1699999999));
    }

    #[test]
    fn a_client_the_configuration_does_not_have_is_ignored() {
        let mut config = AuthConfig::default();
        let mut state = RuntimeState::default();
        state.clients.insert(
            "gone".to_string(),
            ClientState {
                failed_attempts: 9,
                locked_until: None,
                enrollment_failed_attempts: 0,
                enrollment_locked_until: None,
                last_used: None,
                devices: HashMap::new(),
            },
        );

        apply(&state, &mut config);

        assert!(
            config.clients.is_empty(),
            "a client the operator removed stays removed: {:?}",
            config.clients
        );
    }
}

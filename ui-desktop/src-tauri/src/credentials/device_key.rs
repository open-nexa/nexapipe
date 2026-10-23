//! The device key: one for the machine, as there is one name for it.
//!
//! A key belongs to the *machine*, not to the node that happens to enroll
//! with it. The server files a credential under a device name, and that name is
//! the machine's (`ensureDeviceIdFor` in the frontend keeps one for the life of
//! the install), while the node is a server: it is named by the Node ID of the
//! backend, and that changes when the backend is rebuilt.
//!
//! So a key filed per node is a key that changes with the server, and a
//! machine that answers a rebuilt server with a different key is a different
//! device to it — the server sees the same name with another public half and
//! refuses the enrollment as a takeover, for a reason that names nothing on
//! this side.
//!
//! Two entries, then: the key a node enrolled with, and the key the machine
//! answers with. The first is what the server holds under the machine's name;
//! the second is what every node without a key of its own offers. They are the
//! same key in the ordinary case, and the machine's is never replaced once it
//! exists — the servers holding it are the ones that would stop recognising
//! this machine.

use super::store::Store;
use super::types::{secret_key, CredentialKind, MACHINE_SCOPE};

use crate::error::AppError;

/// The key this machine's own device key is filed under.
///
/// Not a node id, so an entry filed under it cannot be mistaken for one of a
/// node's own.
fn machine_key() -> String {
    format!("{}:{}", CredentialKind::DeviceKey.as_str(), MACHINE_SCOPE)
}

/// The key a node has of its own: the one it enrolled with, and the one the
/// server holds under this machine's name.
pub(super) fn node_device_key(store: &Store, node_id: &str) -> Result<Option<String>, AppError> {
    store.get(&secret_key(CredentialKind::DeviceKey, node_id))
}

/// The key this machine proves itself with.
///
/// The machine's own key when it has one. A machine that has none yet adopts
/// the key of a node that has one: that is the key the server holds under this
/// machine's name, and adopting it is what keeps the two the same — so the
/// node this machine enrolls with next offers a key the server already knows,
/// instead of a new one no server has ever seen.
pub(super) fn machine_device_key(store: &Store) -> Result<Option<String>, AppError> {
    if let Some(machine) = store.get(&machine_key())? {
        return Ok(Some(machine));
    }

    let Some(adopted) = first_node_key(store)? else {
        return Ok(None);
    };
    store.put(&machine_key(), &adopted)?;
    Ok(Some(adopted))
}

/// The key a node proves itself with: its own when it has one, and the
/// machine's when it does not.
pub(super) fn effective_device_key(
    store: &Store,
    node_id: &str,
) -> Result<Option<String>, AppError> {
    match node_device_key(store, node_id)? {
        Some(own) => Ok(Some(own)),
        None => machine_device_key(store),
    }
}

/// Keeps a key as the node's own, and as the machine's when the machine has
/// none.
///
/// The node's own entry is what the server holds under this machine's name,
/// and it is never replaced: a node that enrolled with a key is answered with
/// that key, whatever the machine does afterwards.
pub(super) fn file_device_key(
    store: &Store,
    node_id: &str,
    private_key_hex: &str,
) -> Result<(), AppError> {
    store.put(
        &secret_key(CredentialKind::DeviceKey, node_id),
        private_key_hex,
    )?;

    if store.get(&machine_key())?.is_none() {
        store.put(&machine_key(), private_key_hex)?;
    }

    Ok(())
}

/// The key of the first node that has one.
///
/// A scan rather than an index: the keys are filed under the node they belong
/// to and there is no index to keep. The machine's own entry is skipped — it
/// is not a node's — and the keys come back sorted, so the same install
/// always adopts the same one.
fn first_node_key(store: &Store) -> Result<Option<String>, AppError> {
    let prefix = format!("{}:", CredentialKind::DeviceKey.as_str());
    let machine = machine_key();

    for key in store.keys()? {
        if key == machine || !key.starts_with(&prefix) {
            continue;
        }
        if let Some(value) = store.get(&key)? {
            if !value.is_empty() {
                return Ok(Some(value));
            }
        }
    }

    Ok(None)
}

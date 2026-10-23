//! The credentials, and the lock that keeps them out of reach.
//!
//! A credential is a secret the desktop holds for a node. It is kept behind a
//! lock — the gate — and it is read out of the store only when the renderer
//! asks for it and the lock is open.

use crate::commands::{INVITED_NODES, RUNTIME_CREDENTIALS_TAKEN};
use crate::credentials;
use crate::error::{codes, AppError};
use crate::gate;

use nexapipe_client::auth::DeviceKey;

use serde::Serialize;

use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// Turns what the frontend names into one of the keys [`credentials`] knows.
///
/// The frontend sends a kind and, for per-node credentials, a node id: letting it
/// spell the whole key would let it write entries nothing can ever read back, and
/// would make the two sides agree by convention rather than by construction.
pub(crate) fn credential_kind(kind: &str, node_id: Option<String>) -> Result<String, AppError> {
    let kind = match kind {
        "totp" => credentials::CredentialKind::TotpSecret,
        "enrollment" => credentials::CredentialKind::EnrollmentToken,
        "devicekey" => credentials::CredentialKind::DeviceKey,
        "relay" => credentials::CredentialKind::RelayToken,
        "ticket" => credentials::CredentialKind::Ticket,
        "endpoint" => credentials::CredentialKind::EndpointId,
        other => {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("{other:?} is not a credential kind"),
            ))
        }
    };

    // A per-node credential with no node named belongs to no node.
    let node_id = node_id.unwrap_or_default();
    if node_id.trim().is_empty() && !matches!(kind, credentials::CredentialKind::RelayToken) {
        return Err(AppError::with_detail(
            codes::CREDENTIALS_STORE_FAILED,
            format!("a {} credential needs a node id", kind.as_str()),
        ));
    }

    Ok(credentials::secret_key(kind, &node_id))
}

/// One node's credentials, in full.
///
/// Not a display shape: this is what the config store fills itself in with at
/// start-up, because `start_proxy` still takes a connection string and a TOTP
/// secret as arguments. Nothing renders it — a surface asks
/// [`credential_display`], or [`reveal_credential`] once the door is open.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeCredentials {
    totp: Option<String>,
    enrollment: Option<String>,
    /// The private half of the key this node answers with, when it has one.
    ///
    /// Its own when it enrolled with one, and the machine's otherwise — a key
    /// belongs to the machine, as the name the server files it under does. A
    /// credential like the secret beside it, and it crosses this boundary for
    /// the same reason: the proxy needs it to sign, and in the service mode the
    /// service is a separate process with no store of its own.
    device_key: Option<String>,
    /// The public half of the key *this node* enrolled with, as 64 hex
    /// characters.
    ///
    /// Derived from the node's own private half rather than stored beside it,
    /// so the two can never disagree about which key this is. Not a secret —
    /// the server holds the same one — and it is what the app shows to name
    /// the key an operator has on file.
    ///
    /// Absent for a node that never enrolled with a key: the machine's key is
    /// offered to a server, not issued to this node, and naming it here would
    /// present a node as holding a credential it was never given.
    #[serde(default)]
    public_key: Option<String>,
    ticket: Option<String>,
    endpoint: Option<String>,
}

/// Everything the app runs on: the relay bearer and one entry per node.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeCredentials {
    relay: Option<String>,
    nodes: HashMap<String, NodeCredentials>,
}

/// Reads one node's credentials out of the store.
pub(crate) fn node_credentials(node_id: &str) -> Result<NodeCredentials, AppError> {
    // The key the node answers with: its own when it enrolled with one, and
    // the machine's when it did not. A key belongs to the machine rather than
    // to the node — the server files a credential under the machine's name,
    // and that name outlives every server the machine comes back to — so a
    // node without a key of its own offers the machine's rather than a new
    // one, which the server would refuse as a takeover.
    let device_key = credentials::effective_device_key(node_id)?;
    // The public half of the key *this node* enrolled with, derived rather
    // than stored: a value that could disagree with the private half beside
    // it would name the wrong key to an operator. The node's own key and not
    // the effective one, because a node that never enrolled with a key has
    // none to name — the machine's key is offered to a server, not issued to
    // this node.
    let public_key = credentials::node_device_key(node_id)?
        .as_deref()
        .and_then(|spelled| DeviceKey::from_hex(spelled).ok())
        .map(|key| key.public_hex());
    Ok(NodeCredentials {
        totp: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::TotpSecret,
            node_id,
        ))?,
        enrollment: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::EnrollmentToken,
            node_id,
        ))?,
        device_key,
        public_key,
        ticket: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::Ticket,
            node_id,
        ))?,
        endpoint: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::EndpointId,
            node_id,
        ))?,
    })
}

/// Every credential the app runs on, read once at start-up.
///
/// The store used to be readable one value at a time, at any time, through
/// `get_credential`. [`reveal_credential`] is gated, but a general read beside
/// it is a gate with an open door next to it: anything that could reach this
/// process could ask for a TOTP secret without the operating system ever being
/// consulted. This is asked once, by the config store filling itself in before
/// the app mounts, and refuses everything after that.
///
/// The node ids are an argument rather than something discovered here, so it
/// answers for the configuration the caller already has and for nothing else.
/// A read that failed is not spent: a store that handed nothing over has given
/// nothing away.
#[tauri::command]
pub(crate) async fn take_runtime_credentials(
    node_ids: Vec<String>,
) -> Result<RuntimeCredentials, AppError> {
    // See `RUNTIME_CREDENTIALS_TAKEN`: a debug build answers again, because a
    // reload of the webview is a new renderer in the same process and would
    // otherwise be locked out of the store for the rest of the run.
    if RUNTIME_CREDENTIALS_TAKEN.load(Ordering::SeqCst) && !cfg!(debug_assertions) {
        return Err(AppError::with_detail(
            codes::CREDENTIALS_STORE_FAILED,
            "the credentials were already read at start-up",
        ));
    }

    // Timed because this is the one call the first paint waits on: it is where the master key
    // is loaded — the keychain read, on the one launch that still asks — and where the store
    // file is read and every entry in it decrypted.
    let started = std::time::Instant::now();

    let mut nodes = HashMap::with_capacity(node_ids.len());
    for node_id in &node_ids {
        let node_id = node_id.trim();
        if node_id.is_empty() {
            continue;
        }
        nodes.insert(node_id.to_string(), node_credentials(node_id)?);
    }

    let bundle = RuntimeCredentials {
        relay: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::RelayToken,
            "",
        ))?,
        nodes,
    };

    tracing::info!(
        "[startup] credentials read took {}ms for {} node(s)",
        started.elapsed().as_millis(),
        bundle.nodes.len()
    );

    RUNTIME_CREDENTIALS_TAKEN.store(true, Ordering::SeqCst);
    Ok(bundle)
}

/// One node's credentials, for the node an invite has just filed them under.
///
/// `applyInvite` needs the connection string back after [`accept_invite`]
/// filed it: the node in the configuration has to agree with the store, or the
/// next save reads the empty string as a deletion and drops what was just
/// imported. Narrower than a read by node id — it answers for the nodes this
/// process imported an invite for, once each, and for no others.
#[tauri::command]
pub(crate) async fn take_invited_node_credentials(
    node_id: String,
) -> Result<NodeCredentials, AppError> {
    let node_id = node_id.trim();

    let accepted = INVITED_NODES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(node_id);
    if !accepted {
        return Err(AppError::with_detail(
            codes::CREDENTIALS_STORE_FAILED,
            "no invite was accepted for this node",
        ));
    }

    let credentials = node_credentials(node_id)?;

    // Taken off on the way out rather than on the way in: a read that failed
    // has handed nothing over, so the caller may still ask again.
    INVITED_NODES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(node_id);

    Ok(credentials)
}

/// One credential as a surface may show it: [`credentials::mask`] applied where
/// the value is, so the renderer is handed a projection and never the thing.
#[tauri::command]
pub(crate) async fn credential_display(
    kind: String,
    node_id: Option<String>,
) -> Result<Option<String>, AppError> {
    let key = credential_kind(&kind, node_id)?;
    Ok(credentials::get(&key)?.map(|value| credentials::mask(&value)))
}

/// One credential in full, for the user to copy.
///
/// The only path from the store to a surface, and the one the door stands in
/// front of: everything else the UI can ask for is either a mask or a shape.
#[tauri::command]
pub(crate) async fn reveal_credential(
    kind: String,
    node_id: Option<String>,
) -> Result<Option<String>, AppError> {
    require_unlocked()?;
    let key = credential_kind(&kind, node_id)?;
    credentials::get(&key)
}

/// Refuses a reveal while the door is shut.
///
/// The check the rest of `gate` exists to make possible. It reads the window and
/// nothing else: whether the machine can still ask is re-read when the UI asks
/// for the status, which is what it does when the app comes back into view, and
/// a window that is open is at most two minutes old.
pub(super) fn require_unlocked() -> Result<(), AppError> {
    if gate::is_unlocked() {
        Ok(())
    } else {
        Err(AppError::new(codes::CREDENTIALS_LOCKED))
    }
}

/// The credential door, as a surface sees it: whether it is open, how long it
/// has left, and whether this machine can be asked at all.
#[tauri::command]
pub(crate) async fn gate_status() -> Result<gate::Status, AppError> {
    on_blocking_task(gate::status).await
}

/// Asks the operating system to confirm the user, and opens the door if it does.
///
/// `reason` is what the prompt says it is for, already in the user's language:
/// the caller knows which credential is about to be shown and the door does not.
/// `password` is what [`gate_status`] asked the UI to collect, and is `None` on
/// the platforms that bring their own prompt.
#[tauri::command]
pub(crate) async fn unlock_credentials(
    reason: String,
    password: Option<String>,
) -> Result<gate::Status, AppError> {
    // Zeroed on drop, so the one platform that needs a password does not leave
    // one behind in the heap of a task that has moved on.
    let password = password.map(zeroize::Zeroizing::new);

    let outcome =
        on_blocking_task(move || gate::confirm(&reason, password.as_ref().map(|p| p.as_str())))
            .await?;

    match outcome {
        gate::Outcome::Unlocked => on_blocking_task(gate::status).await,
        // Asked, and the answer was no. Not worth telling the user twice: they
        // just said it.
        gate::Outcome::Refused => Err(AppError::new(codes::CREDENTIALS_LOCKED)),
        gate::Outcome::Unavailable => Err(AppError::new(codes::CREDENTIALS_GATE_UNAVAILABLE)),
        gate::Outcome::Failed(detail) => Err(AppError::with_detail(
            codes::CREDENTIALS_GATE_FAILED,
            detail,
        )),
    }
}

/// Shuts the door again, without waiting for the window to lapse.
#[tauri::command]
pub(crate) async fn lock_credentials() -> Result<gate::Status, AppError> {
    on_blocking_task(|| {
        gate::lock();
        gate::status()
    })
    .await
}

/// Runs one of the door's blocking calls off the async runtime.
///
/// Every platform prompt is a modal that lasts as long as the user takes to
/// answer it, and even `capability` is a syscall or two; neither belongs on a
/// worker that is also answering IPC for the proxy.
pub(crate) async fn on_blocking_task<T>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AppError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|error| AppError::with_detail(codes::CREDENTIALS_GATE_FAILED, error.to_string()))
}

/// Writes one credential.
#[tauri::command]
pub(crate) async fn put_credential(
    kind: String,
    value: String,
    node_id: Option<String>,
) -> Result<(), AppError> {
    let key = credential_kind(&kind, node_id)?;
    credentials::put(&key, &value)
}

/// Forgets one credential: what "this server has no 2FA" and "the token has been
/// spent" look like on this side.
#[tauri::command]
pub(crate) async fn delete_credential(
    kind: String,
    node_id: Option<String>,
) -> Result<(), AppError> {
    let key = credential_kind(&kind, node_id)?;
    credentials::remove(&key)
}

/// Forgets every credential, for a reset that also forgets the nodes they belong to.
#[tauri::command]
pub(crate) async fn clear_credentials() -> Result<(), AppError> {
    for key in credentials::keys()? {
        credentials::remove(&key)?;
    }
    Ok(())
}

/// Where the master key ended up: `"keychain"`, or `"file"` when no keychain would
/// take it and the weaker fallback is in use. Reported so the UI can say so
/// rather than let the two look alike.
#[tauri::command]
pub(crate) async fn credential_store_status() -> Result<String, AppError> {
    Ok(credentials::status()?.as_str().to_string())
}

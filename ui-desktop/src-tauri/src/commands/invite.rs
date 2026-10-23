//! An invite, and the credential it carries.
//!
//! An invite is a link with a node in it. Importing one registers the node
//! and, when it carries an enrollment, hands out the credential that node is
//! to use — once, to the renderer, and never again.

use crate::commands::{ask_service, INVITED_NODES, PROXY_MANAGER};
use crate::credentials;
use crate::error::{codes, AppError};
use crate::service::ipc::IssuedCredentialPayload;
use crate::service::IpcClient;

use nexapipe_client::auth::DeviceKey;
use nexapipe_client::provisioning::{EndpointInvite, EndpointTarget};

use serde::Serialize;

/// A `nexapipe://` invitation read into the shape the UI needs to *show* before the
/// user commits.
///
/// The grammar lives in `nexapipe-client` (module `provisioning`), the same parser the server that
/// prints the code and the Android client that scans it both read; the desktop asks it instead of
/// growing a third implementation that would drift.
///
/// Nothing here is applied, and — the difference from what this used to return —
/// nothing secret crosses either: the connection string is masked by
/// [`credentials::mask`], and a TOTP secret or enrollment token a code carries is
/// not handed to the renderer at all. Showing an invite needs neither, and
/// `accept_invite` is what files them once the user says yes.
///
/// The fields cross into TypeScript, where `InvitePayload` in `src/types/index.ts` spells them
/// camelCase. Nothing in Tauri rewrites the keys of a command result — every struct has to ask
/// for the conversion itself — so without this rename the frontend reads `undefined` for every
/// multi-word field while the single-word ones arrive intact, which is how a parsed invite lost
/// its client id and kept its secret.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePayload {
    /// `endpoint` for a bare Node ID, `ticket` for an address-bearing ticket.
    pub kind: String,
    /// The Node ID, or the ticket, as [`credentials::mask`] renders it.
    ///
    /// Masked because the preview is a surface: this is the string the dialog
    /// prints, and a ticket is the whole of what someone needs to connect.
    pub target_masked: String,
    /// Cosmetic label from the invite. Nothing routes on it.
    pub name: Option<String>,
    pub domains: Vec<String>,
    pub relay: Option<String>,
    pub totp: Option<InviteTotpPayload>,
    /// A one-time enrollment token, which is what a `v=2` invite carries instead of a
    /// secret. Mutually exclusive with `totp` — the parser refuses a code that carries
    /// both — so the UI can branch on this without deciding a precedence of its own.
    pub enrollment: Option<InviteEnrollmentPayload>,
}

/// The enrollment half of an invite: a token to spend, not a secret to keep.
///
/// What crosses is *that* there is one and who it is for. The token itself is
/// filed by `accept_invite` and never reaches the renderer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteEnrollmentPayload {
    /// Which `[auth.clients]` entry the token is pending for.
    pub client_id: String,
}

/// The 2FA half of an invite, in the form the config store keeps it.
///
/// The secret is not in here: an invite is shown to be recognised, not to be
/// read, and the secret is the one part of a code that is still a credential
/// after the connection it authorises is set up.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteTotpPayload {
    pub client_id: String,
    /// Lowercase algorithm name, which is what `twoFactorAlgorithm` holds.
    pub algorithm: String,
    pub issuer: String,
}

/// What `accept_invite` answers: which node an invite belongs to, and
/// everything about it that is not a credential.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteAccepted {
    /// The node the invite's credentials were filed under. An existing node's id
    /// when one already held this connection string, so importing the same
    /// invite twice tops a node up instead of adding a second one pointing at
    /// the same backend.
    pub node_id: String,
    /// `ticket` or `endpoint_id`, which is what `connectionType` calls them.
    pub connection_type: String,
    /// Whether `node_id` named a node that was already here.
    pub existing: bool,
    /// Cosmetic label from the invite. Nothing routes on it.
    pub name: Option<String>,
    pub domains: Vec<String>,
    pub relay: Option<String>,
    pub totp: Option<InviteTotpPayload>,
    pub enrollment: Option<InviteEnrollmentPayload>,
    /// The public half of the device key this node will enroll with, as 64 hex
    /// characters.
    ///
    /// `None` for an invite that hands out a secret rather than a token, and
    /// for one whose key could not be stored. The private half never crosses
    /// this boundary: it is filed in the store and read from there when a
    /// connection needs it.
    pub public_key: Option<String>,
}

/// Reads a `nexapipe://` invite pasted into the UI.
///
/// Pure parsing: no proxy is touched and no config is written, so the UI can show what a code
/// carries before the user accepts it. A rejected code comes back as `invite.parse_failed` with
/// the parser's reason as `detail` — the reason names the offending part ("unsupported version",
/// "unknown host"), which is worth more than a generic failure but is still an English diagnostic.
///
/// Not `async`: it is a string parse with no I/O, and a synchronous command keeps it off the
/// async runtime entirely.
#[tauri::command]
pub(crate) fn parse_invite(uri: String) -> Result<InvitePayload, AppError> {
    let invite = EndpointInvite::from_uri(&uri)
        .map_err(|e| AppError::cause(codes::INVITE_PARSE_FAILED, e))?;

    let (kind, target) = match &invite.target {
        EndpointTarget::NodeId(id) => ("endpoint".to_string(), id.clone()),
        EndpointTarget::Ticket(ticket) => ("ticket".to_string(), ticket.clone()),
    };

    Ok(InvitePayload {
        kind,
        target_masked: credentials::mask(&target),
        name: invite.name.clone(),
        domains: invite.domains.clone(),
        relay: invite.relay.clone(),
        totp: invite.totp.as_ref().map(|totp| InviteTotpPayload {
            client_id: totp.client_id.clone(),
            algorithm: totp.algorithm.name().to_string(),
            issuer: totp.issuer.clone(),
        }),
        enrollment: invite
            .enrollment
            .as_ref()
            .map(|enrollment| InviteEnrollmentPayload {
                client_id: enrollment.client_id.clone(),
            }),
    })
}

/// Files what an invite carries into the encrypted store and says which node it
/// belongs to.
///
/// This exists because [`parse_invite`] stopped handing secrets to the renderer:
/// something has to put the connection string, the TOTP secret and the enrollment
/// token where they live, and the renderer is the one place they should not pass
/// through on the way. The answer is everything else about the code — no
/// credential in it, so the caller can build the node without ever holding one.
///
/// Which node it is gets decided here, by looking for one that already holds this
/// connection string: the renderer cannot do that comparison any more, because it
/// no longer has the string to compare with. Node ids are the keys the store
/// files credentials under, so "which node" is a question about the store.
#[tauri::command]
pub(crate) fn accept_invite(uri: String) -> Result<InviteAccepted, AppError> {
    let invite = EndpointInvite::from_uri(&uri)
        .map_err(|e| AppError::cause(codes::INVITE_PARSE_FAILED, e))?;

    let (connection_type, target, kind) = match &invite.target {
        EndpointTarget::NodeId(id) => (
            "endpoint_id",
            id.clone(),
            credentials::CredentialKind::EndpointId,
        ),
        EndpointTarget::Ticket(ticket) => (
            "ticket",
            ticket.clone(),
            credentials::CredentialKind::Ticket,
        ),
    };

    let existing = node_holding(kind, &target)?;
    let node_id = existing.clone().unwrap_or_else(new_node_id);

    // The connection string first: everything below is filed under a node that
    // is identified by having it, so a failure here must leave nothing behind.
    credentials::put(&credentials::secret_key(kind, &node_id), &target)?;

    if let Some(totp) = &invite.totp {
        credentials::put(
            &credentials::secret_key(credentials::CredentialKind::TotpSecret, &node_id),
            totp.secret.expose_secret(),
        )?;
    }
    if let Some(enrollment) = &invite.enrollment {
        credentials::put(
            &credentials::secret_key(credentials::CredentialKind::EnrollmentToken, &node_id),
            enrollment.token.expose_secret(),
        )?;
    }

    // A registration invite is the one moment a device key can be offered: the
    // token in it is the human moment, and the key is what this machine proves
    // itself with from then on. Minted here so it is on file before the token
    // is spent — a token cannot be spent twice, and a node whose key was lost
    // afterwards cannot enroll again from the same code.
    //
    // The key is the machine's, not this node's: the server files a credential
    // under the machine's name, and that name does not change when the server
    // does — a server that is rebuilt or copied keeps the row, while the
    // endpoint id it answers to changes. A node that answers a rebuilt server
    // with a different key is a different device to it, and is refused as a
    // takeover.
    //
    // So the key a node already enrolled with comes first — that is the one
    // the server holds under this machine's name, and offering another would
    // be a different device as far as the server is concerned — and the
    // machine's own key comes next, so that every server this machine comes
    // back to is answered with the same key. Only a machine that has none yet
    // mints one, and it mints one for the machine.
    //
    // The private half is filed in the store and never crosses to the
    // renderer; only the public half does, because it is not a secret and it
    // is what names this key to an operator.
    let public_key = match &invite.enrollment {
        Some(_) => {
            let private = match credentials::node_device_key(&node_id)? {
                Some(own) => {
                    // Kept as the node's own, and adopted as the machine's
                    // when the machine has none: the server holds this key
                    // under this machine's name.
                    credentials::file_device_key(&node_id, &own)?;
                    own
                }
                None => {
                    let private = match credentials::machine_device_key()? {
                        Some(machine) => machine,
                        None => DeviceKey::generate().private_hex(),
                    };
                    credentials::file_device_key(&node_id, &private)?;
                    private
                }
            };
            let key = DeviceKey::from_hex(&private)
                .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))?;
            Some(key.public_hex())
        }
        None => None,
    };

    // What `take_invited_node_credentials` answers from: the connection string
    // this node is identified by was filed by an invite the user just imported,
    // so the configuration is allowed to read it back — once.
    INVITED_NODES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(node_id.clone());

    Ok(InviteAccepted {
        node_id,
        connection_type: connection_type.to_string(),
        existing: existing.is_some(),
        name: invite.name.clone(),
        domains: invite.domains.clone(),
        relay: invite.relay.clone(),
        totp: invite.totp.as_ref().map(|totp| InviteTotpPayload {
            client_id: totp.client_id.clone(),
            algorithm: totp.algorithm.name().to_string(),
            issuer: totp.issuer.clone(),
        }),
        enrollment: invite
            .enrollment
            .as_ref()
            .map(|enrollment| InviteEnrollmentPayload {
                client_id: enrollment.client_id.clone(),
            }),
        public_key,
    })
}

/// The node whose stored connection string is `target`, if there is one.
///
/// A scan rather than an index because there is no index to keep: a node is
/// identified by its connection string and there are a handful of them. Every
/// entry is read here, and every read is a decrypt, which is the point — the
/// comparison happens where the values are plaintext anyway.
pub(crate) fn node_holding(
    kind: credentials::CredentialKind,
    target: &str,
) -> Result<Option<String>, AppError> {
    let prefix = format!("{}:", kind.as_str());

    for key in credentials::keys()? {
        if !key.starts_with(&prefix) {
            continue;
        }
        if credentials::get(&key)?.as_deref() == Some(target) {
            return Ok(Some(key[prefix.len()..].to_string()));
        }
    }

    Ok(None)
}

/// An id for a node no stored connection string belongs to yet.
///
/// Only has to be unique among the store's keys, and unguessable is not part of
/// the job: it names a node in a file the user already owns.
pub(crate) fn new_node_id() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Not a credential and not a nonce, so a coarse fallback is fine: the
        // clock plus whatever the address happened to be still distinguishes
        // two nodes created in the same session.
        return format!("node-{:?}", std::time::SystemTime::now());
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("node-{hex}")
}

/// Hands back the credential a server issued for an enrollment token, and clears it.
///
/// `None` when nothing enrolled on this run — no node carried a token, or the credential
/// has already been taken. A token is spent by the first connection that uses it, so the
/// caller gets exactly one chance to read this; the frontend stores it as that node's 2FA
/// credentials, because without it a restart has nothing left to authenticate with.
#[tauri::command]
pub(crate) async fn take_issued_credential(
    use_service: Option<bool>,
) -> Result<Option<IssuedCredentialPayload>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(credential) = ask_service(
        use_service,
        "read the enrolled credential",
        IpcClient::take_issued_credential(),
    )
    .await
    {
        return Ok(credential);
    }

    // Cloned out of the lock first: the guard must not be held across the await below.
    let manager = PROXY_MANAGER.read().await.as_ref().cloned();
    Ok(match manager {
        Some(manager) => {
            manager
                .take_issued_credential()
                .await
                .map(|credential| IssuedCredentialPayload {
                    client_id: credential.client_id,
                    // The credential is on its way to the keychain, which is
                    // outside this process: the copy handed over is a plain
                    // string, and the one that stays behind is wiped with the
                    // credential.
                    secret: credential.secret.expose_secret().to_string(),
                    algorithm: credential.algorithm,
                    public_key: credential.public_key,
                    device: credential.device,
                })
        }
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use nexapipe_client::provisioning::{InviteEnrollment, InviteTotp};

    /// A Node ID nobody is listening on, derived from a fixed seed so the expected strings in
    /// these tests stay stable — parsing checks that the point is valid, not just that it is
    /// 64 hex characters.
    fn node_id() -> String {
        iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string()
    }

    fn endpoint_invite() -> EndpointInvite {
        EndpointInvite::new(
            EndpointTarget::NodeId(node_id()),
            &["a.example".to_string(), "b.example".to_string()],
        )
        .expect("the sample invite is well formed")
    }

    #[test]
    fn reads_a_node_id_invite() {
        let payload = parse_invite(endpoint_invite().with_name("Home").to_uri()).unwrap();

        assert_eq!(payload.kind, "endpoint");
        // Recognisable, and not the thing: the preview is a surface.
        assert_eq!(payload.target_masked, credentials::mask(&node_id()));
        assert_ne!(payload.target_masked, node_id());
        assert_eq!(payload.name.as_deref(), Some("Home"));
        assert_eq!(payload.domains, vec!["a.example", "b.example"]);
        assert_eq!(payload.relay, None);
        assert!(payload.totp.is_none());
    }

    #[test]
    fn reads_a_ticket_invite() {
        let target = EndpointTarget::Ticket(
            iroh_tickets::endpoint::EndpointTicket::new(
                node_id()
                    .parse::<iroh::EndpointId>()
                    .expect("the sample node ID is well formed")
                    .into(),
            )
            .to_string(),
        );
        let invite =
            EndpointInvite::new(target.clone(), &[]).expect("the sample invite is well formed");

        let payload = parse_invite(invite.to_uri()).unwrap();
        assert_eq!(payload.kind, "ticket");
        assert_eq!(
            payload.target_masked,
            credentials::mask(&target.to_string())
        );
        assert!(
            !payload
                .target_masked
                .contains(&target.to_string()[8..target.to_string().len() - 8]),
            "the middle of the ticket must not reach the renderer"
        );
        assert!(payload.domains.is_empty());
    }

    #[test]
    fn reads_the_2fa_half() {
        let invite = endpoint_invite().with_totp(Some(
            InviteTotp::new("client-001", "jbswy3dpehpk3pxp").expect("the secret is valid base32"),
        ));

        let payload = parse_invite(invite.to_uri()).unwrap();
        assert!(payload.totp.is_some(), "the invite carries 2FA");

        // What is *not* here is the point: a secret the renderer cannot show is
        // one it cannot leak, and `accept_invite` files it without asking.
        let json: serde_json::Value = serde_json::to_value(&payload).unwrap();
        let totp = json["totp"]
            .as_object()
            .expect("the 2FA block travels whole");
        assert_eq!(totp["clientId"], "client-001");
        assert_eq!(totp["algorithm"], "sha1");
        assert!(
            totp.get("secret").is_none(),
            "a parsed invite must not carry its secret: {totp:?}"
        );
    }

    /// The frontend reads `invite.totp.clientId`, and only the multi-word key was ever at risk:
    /// `secret` and `algorithm` have no casing to disagree about, so a missing rename did not fail
    /// a parse — it produced a node with a secret and no client id, which every server then
    /// refuses. Pin the keys the UI actually sees.
    #[test]
    fn hands_the_2fa_half_to_the_frontend_in_camel_case() {
        let invite = endpoint_invite().with_totp(Some(
            InviteTotp::new("client-001", "jbswy3dpehpk3pxp").expect("the secret is valid base32"),
        ));

        let payload = parse_invite(invite.to_uri()).unwrap();
        let json: serde_json::Value = serde_json::to_value(&payload).unwrap();
        let totp = json["totp"]
            .as_object()
            .expect("the 2FA block travels whole");
        assert_eq!(totp["clientId"], "client-001");
        assert!(
            totp.get("client_id").is_none(),
            "keys must reach the UI as camelCase"
        );
    }

    /// A registration invite carries a token instead of a secret, and the UI has to be able
    /// to tell the two apart without guessing: it enrolls for one and stores credentials for
    /// the other.
    #[test]
    fn hands_a_registration_token_to_the_frontend_instead_of_a_secret() {
        let invite = endpoint_invite()
            .with_enrollment(Some(InviteEnrollment::new("client-001", "tok").unwrap()));

        let payload = parse_invite(invite.to_uri()).unwrap();
        let enrollment = payload
            .enrollment
            .clone()
            .expect("the invite carries a token");
        assert_eq!(enrollment.client_id, "client-001");
        assert!(payload.totp.is_none(), "a code cannot carry both");

        let json: serde_json::Value = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["enrollment"]["clientId"], "client-001");
        assert!(
            json["enrollment"].get("token").is_none(),
            "a parsed invite must not carry the token it is showing a summary of"
        );
    }

    #[test]
    fn reports_a_code_and_a_reason_when_the_link_is_not_an_invite() {
        let error = parse_invite("https://example.com".to_string()).unwrap_err();

        assert_eq!(error.code, codes::INVITE_PARSE_FAILED);
        assert!(
            error.detail.is_some(),
            "the parser's reason travels as detail"
        );
    }
}

use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    proxy::{NodeEnrollment, NodeTwoFactor},
    status::{EndpointLink, ProxyStatus},
};

pub const IPC_SOCKET_PATH: &str = "127.0.0.1:12345";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeInput {
    pub connection_type: String,
    pub ticket: String,
    pub endpoint_id: String,
    pub domains: Vec<String>,
    /// 2FA credentials for this endpoint alone. Every field is optional so a caller that has
    /// nothing to say about 2FA — and an older UI talking to a newer service — still round-trips.
    #[serde(default)]
    pub two_factor_client_id: Option<String>,
    #[serde(default)]
    pub two_factor_secret: Option<String>,
    #[serde(default)]
    pub two_factor_algorithm: Option<String>,
    /// A one-time enrollment token instead of a secret: the service spends it on the first
    /// connection and answers with the credential the server issued. Optional for the same
    /// reason the 2FA fields are — an older UI has nothing to say about enrollment.
    #[serde(default)]
    pub enrollment_client_id: Option<String>,
    #[serde(default)]
    pub enrollment_token: Option<String>,
}

impl NodeInput {
    /// The 2FA credentials this node carries, if it carries any.
    ///
    /// Credentials live on the node because each server keeps its own `[auth].clients` entry: one
    /// shared pair is what made a second server either refuse the handshake or be given the first
    /// one's secret. A node with no secret performs no handshake, which is also how one client
    /// mixes servers that require 2FA with ones that do not.
    /// The enrollment token this node carries, if any.
    ///
    /// A token with no client id is useless: the server looks the pending enrollment up by
    /// that id, so it would be refused — but it is still handed over, because the refusal
    /// then names the real cause instead of looking like a network failure.
    pub fn enrollment(&self) -> Option<NodeEnrollment> {
        let token = self.enrollment_token.as_deref().unwrap_or_default().trim();
        if token.is_empty() {
            return None;
        }
        Some(NodeEnrollment {
            client_id: self.enrollment_client_id.clone().unwrap_or_default(),
            token: token.to_string(),
        })
    }
    pub fn two_factor(&self) -> Option<NodeTwoFactor> {
        let secret = self.two_factor_secret.as_deref().unwrap_or_default().trim();
        if secret.is_empty() {
            return None;
        }
        Some(NodeTwoFactor {
            client_id: self.two_factor_client_id.clone().unwrap_or_default(),
            secret: secret.to_string(),
            algorithm: self
                .two_factor_algorithm
                .clone()
                .unwrap_or_else(|| "sha1".to_string()),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartProxyRequest {
    pub nodes: Vec<NodeInput>,
    pub domains: Vec<String>,
    pub local_addr: Option<String>,
    pub dns_addr: Option<String>,
    pub upstream_dns: Option<String>,
    pub load_balancing: Option<String>,
    pub tun_name: Option<String>,
    /// Requested forwarding mode. Optional so an older client (or an older service binary, which
    /// simply ignores it) keeps working: absent means "local proxy", which is what the previous
    /// probe-based behaviour produced for an unprivileged caller anyway.
    #[serde(default)]
    pub use_tun: Option<bool>,
    pub relay_mode: Option<String>,
    pub relay_url: Option<String>,
    /// Bearer token for a custom relay that requires one.
    #[serde(default)]
    pub relay_auth_token: Option<String>,
}

/// Largest line [`IPC_SOCKET_PATH`] accepts.
///
/// The channel is newline-delimited JSON, but `read_line` would let a caller
/// grow one line without bound before ever having to authenticate — so the
/// reader is capped instead. Serialized token + message-rich StartProxy requests
/// are a few kilobytes; this leaves an order of magnitude of headroom.
pub const MAX_IPC_LINE: usize = 64 * 1024;

/// The credential a server issued for an enrollment token, as it crosses a boundary.
///
/// Separate from `nexapipe_client::auth::IssuedCredential` because that one is not
/// serializable, and because the IPC channel — like the Tauri command surface, which
/// reuses this type — speaks camelCase to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCredentialPayload {
    pub client_id: String,
    pub secret: String,
    /// Lowercase algorithm name, which is what `twoFactorAlgorithm` holds.
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcMessage {
    /// First message on every connection: hands over the token written by the
    /// desktop session (see [`crate::service::ipc_token`]).
    ///
    /// Everything else is refused until this succeeds, because the service runs
    /// elevated and a loopback socket says nothing about who dialled it.
    Auth(String),
    /// Boxed: `StartProxyRequest` is ~250 bytes while every other variant is a
    /// `String` or a `Vec`, so the enum would otherwise be sized after its rarest
    /// variant and every message would pay for it.
    StartProxy(Box<StartProxyRequest>),
    StopProxy,
    GetStatus,
    GetNodeId,
    /// How each configured node currently reaches its backend (direct / relay).
    GetEndpointLinks,
    /// The credential the server issued for an enrollment token, if one was spent.
    ///
    /// Read once and gone: a token can only be spent once, so this is the service's only
    /// chance to hand what it bought to the caller that owns the configuration.
    GetIssuedCredential,
    /// The failure the last [`IpcMessage::StartProxy`] recorded after it had already answered
    /// `Ok`, if any.
    ///
    /// The proxy starts on a spawned task and the service cannot wait for it — a TUN run loop
    /// only returns when the tunnel goes down — so a start that fails a second later would
    /// otherwise leave the caller with nothing but "it stopped again".
    GetStartupError,
}

/// What the service sends back.
///
/// `Ok` carries no payload. The success prose the service used to return (`"Proxy started"`,
/// `"Service installed"`) was discarded by every caller — the UI renders its own localized
/// message — so keeping it only created the illusion of a translatable string that crossed a
/// process boundary with no locale attached.
///
/// Failures cross as [`AppError`], so the IPC channel speaks the same error vocabulary as the
/// Tauri command surface.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok,
    Error(AppError),
    Status(ProxyStatus),
    NodeId(String),
    EndpointLinks(Vec<EndpointLink>),
    /// `None` means the last start settled without a failure.
    StartupError(Option<AppError>),
    /// `None` means nothing has enrolled, or the credential was already taken.
    IssuedCredential(Option<IssuedCredentialPayload>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> NodeInput {
        NodeInput {
            connection_type: "endpoint_id".to_string(),
            ticket: String::new(),
            endpoint_id: "node".to_string(),
            domains: Vec::new(),
            two_factor_client_id: None,
            two_factor_secret: None,
            two_factor_algorithm: None,
            enrollment_client_id: None,
            enrollment_token: None,
        }
    }

    /// An endpoint with no secret performs no handshake, which is what makes a mixed setup —
    /// some servers with 2FA, some without — expressible at all.
    #[test]
    fn a_node_without_a_secret_carries_no_credentials() {
        let mut node = node();
        node.two_factor_client_id = Some("client-001".to_string());
        assert!(node.two_factor().is_none());
    }

    #[test]
    fn a_node_with_a_secret_defaults_the_algorithm() {
        let mut node = node();
        node.two_factor_client_id = Some("client-001".to_string());
        // Padded the way a value pasted out of a config file arrives.
        node.two_factor_secret = Some(" jbswy3dpehpk3pxp ".to_string());

        let two_factor = node.two_factor().expect("the node carries a secret");
        assert_eq!(two_factor.client_id, "client-001");
        assert_eq!(two_factor.secret, "jbswy3dpehpk3pxp");
        assert_eq!(two_factor.algorithm, "sha1");
    }

    /// Two nodes in one request carry two different keys; nothing here flattens them.
    #[test]
    fn two_nodes_keep_their_own_credentials() {
        let mut first = node();
        first.two_factor_client_id = Some("client-001".to_string());
        first.two_factor_secret = Some("jbswy3dpehpk3pxp".to_string());
        first.two_factor_algorithm = Some("sha256".to_string());

        let mut second = node();
        second.two_factor_client_id = Some("client-002".to_string());
        second.two_factor_secret = Some("mfrggzdfmztwq2lk".to_string());

        let first = first.two_factor().expect("the first node has credentials");
        let second = second.two_factor().expect("the second node has credentials");
        assert_ne!(first.secret, second.secret);
        assert_eq!(first.algorithm, "sha256");
        assert_eq!(second.algorithm, "sha1");
    }
}

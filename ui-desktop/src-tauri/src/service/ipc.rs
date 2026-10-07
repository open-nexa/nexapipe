use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    proxy::{NodeEnrollment, NodeTwoFactor},
    status::{ActiveFlowPage, EndpointLink, NodeHealthStatus, NodeTrafficStatus, ProxyStatus},
};

pub const IPC_SOCKET_PATH: &str = "127.0.0.1:12345";

/// What a credential looks like in a `Debug` output.
///
/// These structs are logged whole when the service runs at debug level, and a
/// node carries the TOTP secret or the enrollment token it hands to the server.
/// The debug output is the only place that would print them, so it is written
/// by hand rather than derived.
const REDACTED: &str = "<redacted>";

/// `Some(REDACTED)` when the field carries a value: whether there is a
/// credential matters when debugging, what it is does not.
fn present(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

impl std::fmt::Debug for NodeInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeInput")
            .field("connection_type", &self.connection_type)
            .field("ticket", &self.ticket)
            .field("endpoint_id", &self.endpoint_id)
            .field("domains", &self.domains)
            .field("two_factor_client_id", &self.two_factor_client_id)
            .field("two_factor_secret", &present(&self.two_factor_secret))
            .field("two_factor_algorithm", &self.two_factor_algorithm)
            .field("enrollment_client_id", &self.enrollment_client_id)
            .field("enrollment_token", &present(&self.enrollment_token))
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

impl std::fmt::Debug for StartProxyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartProxyRequest")
            .field("nodes", &self.nodes)
            .field("domains", &self.domains)
            .field("local_addr", &self.local_addr)
            .field("dns_addr", &self.dns_addr)
            .field("upstream_dns", &self.upstream_dns)
            .field("load_balancing", &self.load_balancing)
            .field("tun_name", &self.tun_name)
            .field("use_tun", &self.use_tun)
            .field("relay_mode", &self.relay_mode)
            .field("relay_url", &self.relay_url)
            .field("relay_auth_token", &present(&self.relay_auth_token))
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCredentialPayload {
    pub client_id: String,
    pub secret: String,
    /// Lowercase algorithm name, which is what `twoFactorAlgorithm` holds.
    pub algorithm: String,
}

// Hand-written rather than derived, for the same reason as `NodeInput`'s: this
// is what carries a freshly issued TOTP secret back to the UI, and the whole
// response is logged at debug level on the way through the client.
impl std::fmt::Debug for IssuedCredentialPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCredentialPayload")
            .field("client_id", &self.client_id)
            .field("secret", &REDACTED)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcMessage {
    /// The caller's answer to [`IpcResponse::Challenge`]: proof it holds the token
    /// written by the desktop session (see [`crate::service::ipc_token`]) without
    /// ever sending the token itself.
    ///
    /// Everything else is refused until this succeeds, because the service runs
    /// elevated and a loopback socket says nothing about who dialled it.
    ///
    /// `nonce` is the caller's own, chosen by the caller: the service has to
    /// answer for it too, so a caller can tell the real service from anything
    /// else sitting on the port.
    Auth {
        nonce: String,
        mac: String,
    },
    /// Boxed: `StartProxyRequest` is ~250 bytes while every other variant is a
    /// `String` or a `Vec`, so the enum would otherwise be sized after its rarest
    /// variant and every message would pay for it.
    StartProxy(Box<StartProxyRequest>),
    StopProxy,
    GetStatus,
    GetNodeId,
    /// How each configured node currently reaches its backend (direct / relay).
    GetEndpointLinks,
    /// Whether each configured node answered its last probe, and for how long it has been down.
    GetNodeHealth,
    /// What each configured node has carried, and how many flows are open to it.
    GetNodeTraffic,
    /// The connections the proxy has open right now.
    GetActiveFlows,
    /// Asks one open flow to end.
    CloseFlow {
        id: u64,
    },
    /// Asks every flow reaching one configured node to end.
    CloseNodeFlows {
        /// The ticket or endpoint ID exactly as the node was configured.
        connection: String,
    },
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
    /// Which build is answering, so a caller can tell an older service from its own.
    ///
    /// Nothing else can say it: a build that does not know a request refuses it and drops the
    /// connection, which the caller cannot tell apart from a service that is not running — so
    /// the app goes on asking a service that predates it, and every question it does not
    /// understand comes back as an empty answer rather than as a reason to reinstall.
    GetVersion,
}

/// The version this build reports over the channel — see [`IpcMessage::GetVersion`].
///
/// Both sides are built from the same package, so on a machine where the app and the service
/// are in step the answer is the caller's own version.
pub const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    /// The first thing the service says on every connection, before the caller
    /// has offered anything: nonce the caller's [`IpcMessage::Auth`] answers for.
    ///
    /// The service speaks first on purpose. Used to be the caller that did, and
    /// on a fixed port that meant handing a bearer credential to whatever was
    /// listening — a squatter on `IPC_SOCKET_PATH` collected it and drove the
    /// real service with it. Nothing is offered here until the peer has proved
    /// itself, and the caller proves itself to nobody until it has heard this.
    Challenge {
        nonce: String,
    },
    /// Proof that the service holds the token, so the caller can tell it from a
    /// squatter: HMAC over the caller's nonce. Checked by the caller, which
    /// otherwise has no way to know who answered.
    AuthOk {
        mac: String,
    },
    Error(AppError),
    Status(ProxyStatus),
    NodeId(String),
    EndpointLinks(Vec<EndpointLink>),
    NodeHealth(Vec<NodeHealthStatus>),
    NodeTraffic(Vec<NodeTrafficStatus>),
    ActiveFlows(ActiveFlowPage),
    /// Whether a flow with that id was open and asked to end.
    FlowClosed(bool),
    /// How many flows reaching that node were asked to end. `None` when the connection names a
    /// node the configuration cannot resolve to.
    NodeFlowsClosed(Option<usize>),
    /// `None` means the last start settled without a failure.
    StartupError(Option<AppError>),
    /// `None` means nothing has enrolled, or the credential was already taken.
    IssuedCredential(Option<IssuedCredentialPayload>),
    /// The build the service is — see [`IpcMessage::GetVersion`].
    Version(String),
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

    /// The name on the wire is the name a *deployed* service answers to. Renaming the variant
    /// breaks nothing in this build, where both ends are compiled together — it breaks every
    /// app talking to a service that predates the rename, which is precisely the drift
    /// [`IpcMessage::GetVersion`] exists to detect.
    #[test]
    fn the_version_exchange_keeps_its_wire_names() {
        let request = serde_json::to_string(&IpcMessage::GetVersion).expect("it serializes");
        assert_eq!(request, "\"GetVersion\"");

        let response = serde_json::to_string(&IpcResponse::Version("0.5.0".to_string()))
            .expect("it serializes");
        assert_eq!(response, r#"{"Version":"0.5.0"}"#);
    }

    /// The app compares the service's answer against the version the frontend reads out of
    /// `tauri.conf.json`, which is a different file from the manifest this constant comes
    /// from. A bump that updated one and not the other would declare every installed service
    /// out of date.
    #[test]
    fn the_reported_version_is_the_one_the_frontend_reads() {
        let conf = include_str!("../../tauri.conf.json");

        assert!(
            conf.contains(&format!("\"version\": \"{BUILD_VERSION}\"")),
            "tauri.conf.json and Cargo.toml disagree; the service would look out of date on \
             every machine"
        );
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

use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    status::{EndpointLink, ProxyStatus},
};

pub const IPC_SOCKET_PATH: &str = "127.0.0.1:12345";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeInput {
    pub connection_type: String,
    pub ticket: String,
    pub endpoint_id: String,
    pub domains: Vec<String>,
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
    pub force_relay: Option<bool>,
    pub two_factor_enabled: Option<bool>,
    pub two_factor_client_id: Option<String>,
    pub two_factor_secret: Option<String>,
    pub two_factor_algorithm: Option<String>,
}

/// Largest line [`IPC_SOCKET_PATH`] accepts.
///
/// The channel is newline-delimited JSON, but `read_line` would let a caller
/// grow one line without bound before ever having to authenticate — so the
/// reader is capped instead. Serialized token + message-rich StartProxy requests
/// are a few kilobytes; this leaves an order of magnitude of headroom.
pub const MAX_IPC_LINE: usize = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcMessage {
    /// First message on every connection: hands over the token written by the
    /// desktop session (see [`crate::service::ipc_token`]).
    ///
    /// Everything else is refused until this succeeds, because the service runs
    /// elevated and a loopback socket says nothing about who dialled it.
    Auth(String),
    StartProxy(StartProxyRequest),
    StopProxy,
    GetStatus,
    GetNodeId,
    /// How each configured node currently reaches its backend (direct / relay).
    GetEndpointLinks,
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
}

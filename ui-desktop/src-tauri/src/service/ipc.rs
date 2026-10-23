use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    proxy::{NodeEnrollment, NodeTwoFactor},
    status::{ActiveFlowPage, EndpointLink, NodeHealthStatus, NodeTrafficStatus, ProxyStatus},
};

/// Where the service listens, and where the desktop connects.
///
/// The two platforms answer the same question differently, and the question is
/// the one this whole channel exists for: **who is on the other end of this
/// connection?**
///
/// * **Unix** — a Unix-domain socket. The kernel attributes a connection on
///   one to the process that made it and says so: `SO_PEERCRED` on Linux,
///   `getpeereid` on macOS. A loopback TCP port cannot answer it at all — the
///   kernel has no way to say who dialled — so a service on one could only
///   trust every caller, which is the hole this channel was built to close.
/// * **Windows** — a loopback TCP port. Windows has no socket credential of
///   its own, so the peer is found in the connection table instead; see
///   [`crate::service::platform::account::AccountId::peer_of`].
///
/// The Unix socket lives in a directory root owns, so that no local account
/// can put a socket of its own where the service is to listen. The socket file
/// itself is open to every account — `connect()` on a Unix-domain socket asks
/// for write permission on it — because the account *behind* a connection is
/// what the service checks, and the kernel is what tells it.
#[cfg(unix)]
pub const IPC_SOCKET_PATH: &str = "/var/run/nexapipe/ipc.sock";

/// See the Unix note above: Windows has no socket credential, so the peer is
/// found in the connection table and the port is a loopback one.
#[cfg(windows)]
pub const IPC_SOCKET_PATH: &str = "127.0.0.1:12345";

/// The stream the IPC runs over.
///
/// One name for the channel, so that everything above it — the handshake, the
/// messages, the responses — is written once rather than once per platform.
#[cfg(unix)]
pub type IpcStream = tokio::net::UnixStream;

/// See [`IpcStream`].
#[cfg(windows)]
pub type IpcStream = tokio::net::TcpStream;

/// The listener the service accepts IPC connections on.
///
/// One name for the two platforms' listeners, so that the accept loop above
/// them is written once.
pub enum IpcListener {
    /// A Unix-domain socket — see [`IPC_SOCKET_PATH`].
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    /// A loopback TCP port.
    #[cfg(windows)]
    Tcp(tokio::net::TcpListener),
}

impl IpcListener {
    /// Binds the listener.
    ///
    /// On Unix this also creates the directory the socket lives in and clears
    /// a socket file a service that is no longer running left behind.
    pub async fn bind() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            bind_unix().await
        }
        #[cfg(windows)]
        {
            Ok(IpcListener::Tcp(
                tokio::net::TcpListener::bind(IPC_SOCKET_PATH).await?,
            ))
        }
    }

    /// Accepts the next connection.
    pub async fn accept(&self) -> std::io::Result<IpcStream> {
        match self {
            #[cfg(unix)]
            IpcListener::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                Ok(stream)
            }
            #[cfg(windows)]
            IpcListener::Tcp(listener) => {
                let (stream, _) = listener.accept().await?;
                Ok(stream)
            }
        }
    }
}

/// Binds the Unix-domain socket the service listens on.
///
/// The directory is created here, by the service, because the service is the
/// privileged process: it is the only one that may put a socket where the
/// desktop will look for it. It is root's, and not writable by anybody else,
/// so no local account can put a socket of its own in place of the service's.
///
/// A socket file that is already there is one a service that is no longer
/// running left behind — the file outlives the process wherever the directory
/// is not a memory-backed one — and it is removed, because a bind over it
/// would fail forever. A socket that *answers* is a service that is still
/// running, and that is not this one's to take over.
#[cfg(unix)]
async fn bind_unix() -> std::io::Result<IpcListener> {
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt;

    let path = std::path::Path::new(IPC_SOCKET_PATH);
    let directory = path.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "the IPC socket path has no parent directory",
        )
    })?;

    std::fs::create_dir_all(directory)?;
    // Root's, and not writable by anybody else: a directory another account
    // owns is a directory the socket in it can be replaced in.
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))?;

    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            if tokio::net::UnixStream::connect(path).await.is_ok() {
                return Err(std::io::Error::new(
                    ErrorKind::AddrInUse,
                    "another instance of the service is already serving this socket",
                ));
            }
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    // Every local account may connect: `connect()` on a Unix-domain socket
    // asks for write permission on the socket file, and the account behind a
    // connection is what the service checks — with the kernel's own answer to
    // who that is, not with the socket's mode.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;

    Ok(IpcListener::Unix(listener))
}

/// Connects to the service.
pub async fn connect() -> std::io::Result<IpcStream> {
    #[cfg(unix)]
    {
        tokio::net::UnixStream::connect(IPC_SOCKET_PATH).await
    }
    #[cfg(windows)]
    {
        tokio::net::TcpStream::connect(IPC_SOCKET_PATH).await
    }
}

/// Removes the socket the service listens on.
///
/// The file outlives the process wherever the directory is not a memory-backed
/// one, and a socket file nobody listens on is one the desktop spends a
/// connection failing to reach. The next start clears it as well; this is so
/// that a service that stops leaves nothing behind.
#[cfg(unix)]
pub fn remove_socket() {
    let _ = std::fs::remove_file(std::path::Path::new(IPC_SOCKET_PATH));
}

/// See [`remove_socket`]: Windows listens on a port, and a port leaves nothing
/// behind.
#[cfg(windows)]
pub fn remove_socket() {}

/// A connected pair on the transport the IPC runs over.
///
/// For the tests. The service and the desktop speak over a Unix-domain socket
/// on Unix and a loopback TCP port on Windows, and the two are not
/// interchangeable: only the socket the kernel can name is one whose peer can
/// be identified at all. The tests drive the real transport, so a change to it
/// is exercised here rather than in production.
#[cfg(test)]
pub(crate) async fn connected_pair() -> (IpcStream, IpcStream) {
    #[cfg(unix)]
    {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let path = std::env::temp_dir().join(format!(
            "nexapipe-ipc-test-{}-{}.sock",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        let listener = tokio::net::UnixListener::bind(&path).expect("a socket for the test");
        let client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("the client connects");
        let (server, _) = listener.accept().await.expect("the service accepts");
        let _ = std::fs::remove_file(&path);
        (client, server)
    }
    #[cfg(windows)]
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral loopback port");
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .expect("the client connects");
        let (server, _) = listener.accept().await.expect("the service accepts");
        (client, server)
    }
}

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
            .field("two_factor_device", &self.two_factor_device)
            .field("enrollment_client_id", &self.enrollment_client_id)
            .field("enrollment_token", &present(&self.enrollment_token))
            .field("enrollment_device", &self.enrollment_device)
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
    /// The device this secret belongs to, when the node names one. Absent is the
    /// unnamed device, which answers with the client's own secret — so an older
    /// UI that knows nothing about devices keeps working untouched.
    #[serde(default)]
    pub two_factor_device: Option<String>,
    /// This machine's own Ed25519 key for this endpoint, as 64 hex characters.
    ///
    /// A property of the *device* rather than of the credential: the same key
    /// is offered by the enrollment that spends the token and signs every
    /// handshake after it, so it exists before there is a credential to sign
    /// with. Optional for the same reason the other fields are — an older UI
    /// knows nothing about keys.
    #[serde(default)]
    pub device_key: Option<String>,
    /// A one-time enrollment token instead of a secret: the service spends it on the first
    /// connection and answers with the credential the server issued. Optional for the same
    /// reason the 2FA fields are — an older UI has nothing to say about enrollment.
    #[serde(default)]
    pub enrollment_client_id: Option<String>,
    #[serde(default)]
    pub enrollment_token: Option<String>,
    /// The name to be enrolled under, when the machine has one. Absent enrolls as
    /// the unnamed device, which is what a server that predates per-device
    /// credentials issues.
    #[serde(default)]
    pub enrollment_device: Option<String>,
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
            device: self.enrollment_device.clone(),
        })
    }
    pub fn two_factor(&self) -> Option<NodeTwoFactor> {
        let secret = self.two_factor_secret.as_deref().unwrap_or_default().trim();
        // A credential is a secret or a key, and which one it is comes from
        // what is there rather than from a flag: a key node stores no seed at
        // all, so an empty secret is not a missing credential.
        if secret.is_empty() && self.device_key.is_none() {
            return None;
        }
        Some(NodeTwoFactor {
            client_id: self.two_factor_client_id.clone().unwrap_or_default(),
            secret: secret.to_string(),
            algorithm: self
                .two_factor_algorithm
                .clone()
                .unwrap_or_else(|| "sha1".to_string()),
            device: self.two_factor_device.clone(),
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
            .field("dns_strategy", &self.dns_strategy)
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
    /// What the machine's DNS is asked to do: `scoped` (only the configured
    /// domains go through the tunnel), `global` (every query does) or `none`
    /// (the machine's DNS is not touched). Absent means `scoped`.
    ///
    /// Optional for the same reason `use_tun` is: an older service binary
    /// ignores it, and an older client that does not send it gets the default.
    #[serde(default)]
    pub dns_strategy: Option<String>,
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
    /// Whether this endpoint may use n0's address lookup. Absent means "n0",
    /// which is what the endpoint did before the setting existed.
    #[serde(default)]
    pub discovery_mode: Option<String>,
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
    /// The public half of the device key this credential was issued as, as 64
    /// hex characters.
    ///
    /// `None` for a credential that is a secret, and that is how the two kinds
    /// are told apart: a key credential has an empty secret and an empty
    /// algorithm, and this is the only thing that says which key it is.
    #[serde(default)]
    pub public_key: Option<String>,
    /// The device the server filed this credential under, which has to be kept
    /// with it: the server looks a credential up by that name.
    #[serde(default)]
    pub device: Option<String>,
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
            .field("public_key", &self.public_key)
            .field("device", &self.device)
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
            two_factor_device: None,
            device_key: None,
            enrollment_client_id: None,
            enrollment_token: None,
            enrollment_device: None,
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

    /// A key node stores no seed at all, so an empty secret is not a missing credential:
    /// the key is what this node proves itself with.
    #[test]
    fn a_node_with_a_key_carries_credentials_without_a_secret() {
        let mut node = node();
        node.two_factor_client_id = Some("client-001".to_string());
        node.two_factor_device = Some("laptop".to_string());
        node.device_key = Some("ab".repeat(32));

        let two_factor = node.two_factor().expect("the node carries a key");
        assert_eq!(two_factor.client_id, "client-001");
        assert_eq!(two_factor.secret, "", "a key node stores no seed");
        assert_eq!(two_factor.device.as_deref(), Some("laptop"));
        assert_eq!(node.device_key.as_deref(), Some("ab".repeat(32).as_str()));
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
        let second = second
            .two_factor()
            .expect("the second node has credentials");
        assert_ne!(first.secret, second.secret);
        assert_eq!(first.algorithm, "sha256");
        assert_eq!(second.algorithm, "sha1");
    }
}

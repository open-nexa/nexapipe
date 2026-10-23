//! The clients the backends are reached through.
//!
//! A route's backend may be plain HTTP, HTTP/2 in the clear, or TLS — and the
//! choice is the route's, not the request's — so the clients are made per
//! protocol and kept together.

use crate::config::BackendProtocol;

use std::pin::Pin;

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What a body that cannot be read says.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body the backend client is sent.
///
/// A **box**, so that a request can carry a body that is already in memory
/// and one that is still being read: the tunnel path streams the body
/// straight off the client's stream, and the plaintext path has hyper's own.
pub type HttpBody = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BoxError>;

/// Client used to reach backends.
///
/// Speaks HTTP/1.1 to every backend and HTTP/2 to the ones that offer it: an
/// `https://` backend negotiates h2 through ALPN, and a cleartext one is
/// spoken to over HTTP/1.1 unless its route asks for h2c.
///
/// One client serves both schemes. The connector reads the scheme off the
/// request URI, and the pool keeps one set of connections per scheme and
/// authority — so an `http://` and an `https://` backend on the same host are
/// two sets, and neither is handed a connection the other opened.
///
/// TLS here is a client-side thing: this process never holds a certificate and
/// never terminates a session. It *originates* one towards a backend the route
/// names as `https://`, and checks the certificate it gets back.
pub type HttpClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    HttpBody,
>;

/// Builds the client the proxy reaches backends through.
///
/// The connect deadline comes from `[timeouts] connect_secs` and lives inside the
/// connector, so it applies to every dial this client makes — including the ones
/// made after the response head arrives, for a pooled connection that was closed
/// meanwhile. It is a builder setting, not something a caller passes per request,
/// because that is the only place the transport enforces it.
///
/// `ca_file` names a PEM file of extra CA certificates to trust when verifying
/// an `https://` backend. It is the machine's own roots *plus* that file: a
/// backend signed by an internal authority needs the internal authority, and
/// everything else keeps working.
pub fn create_http_client(
    connect_timeout: std::time::Duration,
    ca_file: Option<&std::path::Path>,
) -> anyhow::Result<HttpClient> {
    Ok(create_http_client_with_tls(
        tls_client_config(ca_file)?,
        connect_timeout,
    ))
}

/// The HTTP/1.1 client around a TLS configuration that is already built.
///
/// Split out so [`BackendClients`] can build the trust store once and hand a
/// clone to each client, rather than reading the machine's roots (and the
/// operator's CA file) twice for the same process.
pub(super) fn create_http_client_with_tls(
    tls: rustls::ClientConfig,
    connect_timeout: std::time::Duration,
) -> HttpClient {
    let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(std::time::Duration::from_secs(30)));
    http_connector.set_connect_timeout(Some(connect_timeout));
    // The connector is handed the URI of the backend, `https://` included, and
    // it is the one that decides to put TLS on top of the socket. A connector
    // that insists on `http://` would refuse the address before the TLS layer
    // ever saw it.
    http_connector.enforce_http(false);

    // The connector is what decides between plaintext and TLS, and it decides
    // by the scheme of the URI it is handed — so the same client reaches an
    // `http://` backend and an `https://` one.
    //
    // `enable_all_versions` is also what puts the protocols on the table: the
    // ALPN list the handshake offers is `h2` first and `http/1.1` second, so a
    // backend that speaks h2 gets it and a backend that does not falls back to
    // HTTP/1.1 without anybody having to say which it is.
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);

    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Some(std::time::Duration::from_secs(120)))
        .http1_title_case_headers(true)
        .http1_ignore_invalid_headers_in_responses(true)
        // The HTTP/2 settings are the same idea as the HTTP/1 ones above: a
        // pooled connection is kept while it answers and dropped when it stops
        // answering. Without them an h2 connection to a backend that went away
        // stays in the pool until something else notices.
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .http2_keep_alive_timeout(std::time::Duration::from_secs(10))
        // The pool's own idle reaper needs a clock as well. The `timer` above
        // is the h2 half's — HTTP/2 carries its own timeouts, and without one
        // the client panics the first time it negotiates h2. The pool is
        // separate: without a timer of its own, an idle connection to a
        // backend that stopped answering is only reaped when something else
        // notices, and the `pool_idle_timeout` above is enforced lazily, at
        // the next checkout.
        .pool_timer(hyper_util::rt::TokioTimer::new())
        // The h2 half needs a clock of its own: an HTTP/2 connection
        // carries its own timeouts — a ping that has to be answered, a
        // stream that has to be reset — and without a timer the client
        // panics the first time it negotiates h2 with a backend.
        .timer(hyper_util::rt::TokioTimer::new())
        .build(connector)
}

/// The clients the proxy reaches backends through.
///
/// Two of them, because the protocol to the backend is a property of the route
/// and not of the process: a backend that speaks HTTP/2 in the clear is reached
/// with a client that starts speaking h2, and everything else is reached with
/// the client that speaks HTTP/1.1 and negotiates h2 over TLS when a backend
/// offers it.
///
/// The two are separate objects rather than one client that decides per
/// request, because the protocol is decided when the connection is made and
/// not when the request is sent: a pooled connection is a connection to one
/// backend in one protocol, and a client that mixed the two would hand an h1
/// connection to a backend that only speaks h2.
#[derive(Clone)]
pub struct BackendClients {
    /// HTTP/1.1, and HTTP/2 where a backend negotiates it over TLS.
    http: Arc<HttpClient>,
    /// HTTP/2 in the clear, with prior knowledge.
    h2c: Arc<HttpClient>,
    /// TLS for a connection that is not the pooled client's: a WebSocket holds
    /// one connection for the whole session, and its handshake is HTTP/1.1.
    /// The ALPN list this carries is `http/1.1` alone.
    tls: Arc<rustls::ClientConfig>,
}

impl BackendClients {
    /// Builds both clients, with the same connect deadline and the same trust
    /// store.
    pub fn new(
        connect_timeout: std::time::Duration,
        ca_file: Option<&std::path::Path>,
    ) -> anyhow::Result<Self> {
        let tls = tls_client_config(ca_file)?;
        let mut websocket_tls = tls.clone();
        // A WebSocket upgrade is HTTP/1.1. Offering h2 here would let a
        // backend agree to a protocol this path cannot speak, so the raw
        // connection asks for the one version it can carry.
        websocket_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(BackendClients {
            http: Arc::new(create_http_client_with_tls(tls.clone(), connect_timeout)),
            h2c: Arc::new(create_h2c_client_with_tls(tls, connect_timeout)),
            tls: Arc::new(websocket_tls),
        })
    }

    /// The client that speaks this protocol.
    pub fn for_protocol(&self, protocol: BackendProtocol) -> &HttpClient {
        match protocol {
            BackendProtocol::Http1 => &self.http,
            BackendProtocol::H2c => &self.h2c,
        }
    }

    /// Opens one connection to a backend, for a WebSocket session.
    ///
    /// This is not the pooled client: a WebSocket holds its connection for the
    /// whole conversation, so it needs the socket itself rather than a request
    /// the pool may reuse. An `https://` backend is still reached over a TLS
    /// session this process originates and verifies, with the same trust store
    /// as the pooled clients; a cleartext one is handed back as it is.
    pub(crate) async fn connect_stream(
        &self,
        backend_url: &str,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<BackendStream> {
        let url = url::Url::parse(backend_url)
            .map_err(|e| anyhow::anyhow!("invalid backend URL: {e}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(80);
        let scheme = url.scheme().to_string();

        let connect = async {
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|e| anyhow::anyhow!("failed to connect to backend: {e}"))?;
            // A WebSocket carries its own message framing; Nagle would only add
            // latency to every frame.
            let _ = tcp.set_nodelay(true);

            match scheme.as_str() {
                "http" => Ok(BackendStream::Plain(tcp)),
                "https" => {
                    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                        .map_err(|e| {
                            anyhow::anyhow!("cannot verify the backend certificate for {host}: {e}")
                        })?;
                    let connector = tokio_rustls::TlsConnector::from(self.tls.clone());
                    let tls = connector
                        .connect(server_name, tcp)
                        .await
                        .map_err(|e| anyhow::anyhow!("TLS handshake with backend failed: {e}"))?;
                    Ok(BackendStream::Tls(Box::new(tls)))
                }
                other => anyhow::bail!(
                    "backend {backend_url} uses {other}://, which cannot carry a WebSocket"
                ),
            }
        };

        tokio::time::timeout(connect_timeout, connect)
            .await
            .map_err(|_| anyhow::anyhow!("timed out connecting to backend {host}:{port}"))?
    }
}

/// A dedicated backend connection, for a flow that owns it for its lifetime.
///
/// Plain or TLS, so the WebSocket path does not have to know which one it got
/// after the dial: it writes the upgrade request and pipes the session either
/// way.
pub(crate) enum BackendStream {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for BackendStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            BackendStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BackendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            BackendStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            BackendStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            BackendStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            BackendStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Builds the client that speaks HTTP/2 in the clear, with prior knowledge.
///
/// The other name for this is h2c, and the "prior knowledge" is the whole
/// point: a cleartext connection has no handshake to negotiate a protocol in,
/// so the client has to know that the backend speaks h2 and start speaking it.
/// A backend that does not answer h2 gets a connection reset, which is a
/// failure the route's own configuration is responsible for avoiding.
pub fn create_h2c_client(
    connect_timeout: std::time::Duration,
    ca_file: Option<&std::path::Path>,
) -> anyhow::Result<HttpClient> {
    Ok(create_h2c_client_with_tls(
        tls_client_config(ca_file)?,
        connect_timeout,
    ))
}

/// The h2c client around a TLS configuration that is already built.
pub(super) fn create_h2c_client_with_tls(
    tls: rustls::ClientConfig,
    connect_timeout: std::time::Duration,
) -> HttpClient {
    let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(std::time::Duration::from_secs(30)));
    http_connector.set_connect_timeout(Some(connect_timeout));
    // As in `create_http_client`: the connector is handed the URI and does not
    // get to refuse the scheme.
    http_connector.enforce_http(false);

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);

    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        // The one setting that makes this client h2: every connection it
        // opens is an h2 connection, whatever the peer says or does not say.
        .http2_only(true)
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Some(std::time::Duration::from_secs(120)))
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .http2_keep_alive_timeout(std::time::Duration::from_secs(10))
        // The pool's own idle reaper needs a clock as well. The `timer` above
        // is the h2 half's — HTTP/2 carries its own timeouts, and without one
        // the client panics the first time it negotiates h2. The pool is
        // separate: without a timer of its own, an idle connection to a
        // backend that stopped answering is only reaped when something else
        // notices, and the `pool_idle_timeout` above is enforced lazily, at
        // the next checkout.
        .pool_timer(hyper_util::rt::TokioTimer::new())
        // The clock the h2 half needs, for the same reason the other client
        // has one: an h2 connection times things on its own.
        .timer(hyper_util::rt::TokioTimer::new())
        .build(connector)
}

/// The TLS configuration a backend handshake is made with.
///
/// The certificate is verified against the machine's own trust store, and there
/// is no way to turn that off: a proxy that connects to a backend without
/// checking who it is talking to is a proxy that can be redirected by whoever
/// answers the name. A backend whose certificate this process cannot verify is
/// a backend this proxy does not reach.
///
/// The provider is named rather than left to the process-wide default, so the
/// client does not depend on the order things happen to be installed in — the
/// iroh handshake installs a provider of its own, and the two must not race.
pub(super) fn tls_client_config(
    ca_file: Option<&std::path::Path>,
) -> anyhow::Result<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_root_certificates(root_store(ca_file)?)
        .with_no_client_auth())
}

/// The certificates a backend's certificate is checked against.
///
/// The machine's own roots rather than a list this project ships: a
/// certificate the browser on the same machine trusts is a certificate this
/// proxy trusts, and a bundled list goes stale without anybody noticing.
///
/// A host with no roots of its own — a minimal container image without
/// `ca-certificates`, say — falls back to Mozilla's bundled ones, because a
/// proxy that cannot verify anything is a proxy that cannot reach an
/// `https://` backend at all. The fallback is a weaker guarantee and says so
/// in the log, rather than turning every handshake into a message about a
/// missing issuer.
pub(super) fn root_store(
    ca_file: Option<&std::path::Path>,
) -> anyhow::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();

    // The platform loader reports what it could not read alongside what it
    // read, rather than failing as a whole: one unreadable store on a machine
    // with several is still a store.
    let native = rustls_native_certs::load_native_certs();
    if !native.certs.is_empty() {
        let mut rejected = 0usize;
        for cert in native.certs {
            if roots.add(cert).is_err() {
                rejected += 1;
            }
        }
        tracing::info!(
            "Loaded {} CA certificates from the system trust store ({rejected} rejected)",
            roots.len()
        );
    } else {
        tracing::warn!(
            "The system trust store holds no usable certificates ({} errors); falling back to \
             Mozilla's bundled roots for backend TLS",
            native.errors.len()
        );
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    // The file the operator named is read here rather than at the first
    // handshake: a CA file that cannot be read is a config that cannot work,
    // and the operator should read about it at startup rather than in the log
    // of a request that failed to verify.
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("cannot read the CA file {}: {e}", path.display()))?;
        let mut reader = std::io::BufReader::new(pem.as_slice());
        let certs = rustls_pemfile::certs(&mut reader)
            .map_err(|e| anyhow::anyhow!("cannot parse the CA file {}: {e}", path.display()))?;
        if certs.is_empty() {
            anyhow::bail!(
                "the CA file {} holds no certificates; it should hold one or more PEM-encoded \
                 certificates",
                path.display()
            );
        }
        let mut rejected = 0usize;
        for cert in certs {
            if roots
                .add(rustls::pki_types::CertificateDer::from(cert))
                .is_err()
            {
                rejected += 1;
            }
        }
        tracing::info!(
            "Loaded the CA file {} ({} certificates, {rejected} rejected)",
            path.display(),
            roots.len()
        );
    }

    Ok(roots)
}

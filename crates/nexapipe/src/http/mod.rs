use crate::routes::{BackendInfo, BackendLookup, RouteConfig};
use ::http::{Request, Response, StatusCode};
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_util::{StreamExt, TryStreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use std::io::Write;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

/// Client used to reach backends.
///
/// Plaintext HTTP only: TLS is terminated by the backend (Caddy &co), so this
/// process never speaks TLS to anything but the iroh endpoint. An `https://`
/// backend is rejected when the config is loaded rather than silently attempted.
pub type HttpClient = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    Full<bytes::Bytes>,
>;

/// Builds the client the proxy reaches backends through.
///
/// The connect deadline comes from `[timeouts] connect_secs` and lives inside the
/// connector, so it applies to every dial this client makes — including the ones
/// made after the response head arrives, for a pooled connection that was closed
/// meanwhile. It is a builder setting, not something a caller passes per request,
/// because that is the only place the transport enforces it.
pub fn create_http_client(connect_timeout: std::time::Duration) -> HttpClient {
    let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(std::time::Duration::from_secs(30)));
    http_connector.set_connect_timeout(Some(connect_timeout));

    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Some(std::time::Duration::from_secs(120)))
        .http1_title_case_headers(true)
        .http1_ignore_invalid_headers_in_responses(true)
        .build(http_connector)
}

const MAX_COMPRESS_SIZE: usize = 1024 * 1024;

/// The largest request body this proxy will read into memory.
///
/// `content-length` is whatever the client says it is, and the request is
/// buffered whole before it is forwarded, so taking the declaration at face
/// value lets a client choose how much this process allocates — one stream at a
/// time, and a peer can open many. Well past any ordinary upload; a deployment
/// that needs to push larger bodies should stream them instead of raising this.
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

/// Whether a request header may be forwarded to the backend.
///
/// Two groups are dropped. Hop-by-hop headers describe one connection, not the
/// message (RFC 7230 6.1): `connection: keep-alive` is about the client's link
/// to this proxy, and forwarding it asks the backend to keep *its* link open
/// for a request that arrived over a different one. `transfer-encoding` is in
/// the same group and has to go: the body has already been read whole and is
/// sent as a single buffer, so a leftover `chunked` would disagree with the
/// framing on the wire.
///
/// `expect: 100-continue` is dropped for a different reason. The proxy reads
/// the body before it ever asks the backend anything, so the client's
/// expectation was answered by this process — and a backend told to expect
/// more would wait for bytes that are already here.
///
/// The WebSocket handshake does not use this: it is the one request that
/// *must* carry `upgrade` and `connection`, because switching protocols is
/// exactly what it is asking the backend for.
fn forwards_request_header(name: &str) -> bool {
    ![
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "expect",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
}

pub async fn proxy_request(
    client: &HttpClient,
    req: Request<Incoming>,
    config: Arc<RouteConfig>,
) -> Result<
    Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>>,
    anyhow::Error,
> {
    // Answered, not raised: no `Host` means no route can match, which is the
    // same answer as a host no route matches — and the caller maps an `Err`
    // from here to a 502, which would blame a backend for a request that never
    // got as far as choosing one.
    let Some(host) = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(crate::routes::host_without_port)
    else {
        return Ok(create_error_response(
            StatusCode::NOT_FOUND,
            "Missing host header",
        ));
    };

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let accept_encoding = req
        .headers()
        .get("accept-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let headers_clone = req.headers().clone();
    let method = req.method().clone();

    let backend_info: BackendInfo = match config.get_backend(host, path).await {
        BackendLookup::Found(info) => info,
        // No route serves this host: saying 404 beats guessing at one.
        BackendLookup::NoRoute => {
            return Ok(create_error_response(
                hyper::StatusCode::NOT_FOUND,
                &format!("No route for host {host}"),
            ));
        }
        // The route is configured and every backend behind it is unhealthy. 503
        // rather than 404, because the difference is which file the operator has
        // to open: nothing here is misconfigured, something downstream is down.
        BackendLookup::Unavailable => {
            tracing::warn!("No healthy backend behind {host}{path}, answering 503");
            return Ok(create_error_response(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                &format!("No healthy backend for host {host}"),
            ));
        }
    };

    // `backend_info` carries the lease (see `BackendInfo::_lease`), so the
    // backend is counted as busy until this function returns — which is until
    // the response head is in hand, and exactly what the deadline below bounds.
    // A response whose body *then* streams is not counted for the whole stream,
    // so `least_conn` sees a long-running transfer as finished; that skews a
    // balance decision at worst, and it is the one path the lease cannot follow
    // without owning the response body.
    let response_deadline = config.timeouts().response;

    let rewritten_path = if let Some(rewrite_pattern) = &backend_info.path_rewrite {
        if backend_info.path_is_prefix && path.starts_with(&backend_info.path_pattern) {
            let suffix = &path[backend_info.path_pattern.len()..];
            rewrite_pattern.replace("{}", suffix)
        } else if !backend_info.path_is_prefix && path == backend_info.path_pattern {
            rewrite_pattern.replace("{}", "")
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    };

    let backend_url = url::Url::parse(&backend_info.url)
        .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

    let backend_scheme = backend_url.scheme();
    let backend_host = backend_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Backend URL missing host"))?;
    let backend_port = backend_url.port_or_known_default().unwrap_or(80);

    let new_uri = format!(
        "{}://{}:{}{}",
        backend_scheme, backend_host, backend_port, rewritten_path
    )
    .parse::<http::Uri>()
    .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let body = read_body_limited(req.into_body(), MAX_REQUEST_BODY).await?;

    let mut builder = Request::builder().method(method).uri(new_uri);

    for (name, value) in headers_clone.iter() {
        // Preserve the client's original Host header so backend virtual-host
        // routing works; drop the rest that only meant something for the hop
        // from the client to here.
        if !forwards_request_header(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }

    let proxied_req = builder.body(Full::new(body))?;

    tracing::debug!(
        "Proxying request: {} {} -> {}://{}:{}",
        proxied_req.method(),
        proxied_req.uri(),
        backend_scheme,
        backend_host,
        backend_port
    );

    let response = match tokio::time::timeout(response_deadline, client.request(proxied_req)).await
    {
        Ok(result) => result.map_err(|e| anyhow::anyhow!("backend request failed: {}", e))?,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "backend {}:{} did not respond within {:?}",
                backend_host,
                backend_port,
                response_deadline
            ));
        }
    };

    let content_encoding = response.headers().get("content-encoding");
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok());

    if content_encoding.is_none()
        && should_compress(content_type)
        && let Some(encodings) = accept_encoding
        && encodings.contains("gzip")
    {
        return compress_response(response, "gzip").await;
    }

    Ok(response.map(http_body_util::BodyExt::boxed_unsync))
}

/// Reads a request body into memory, refusing one larger than `limit`.
///
/// The size is not known up front — a chunked request says nothing about how
/// much is coming — so the limit has to be enforced while reading rather than
/// by checking a `content-length` header the client is free to understate.
async fn read_body_limited<B>(body: B, limit: usize) -> anyhow::Result<bytes::Bytes>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut body = body;
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(frame) = http_body_util::BodyExt::frame(&mut body).await {
        let frame = frame.map_err(|e| anyhow::anyhow!("failed to read the request body: {}", e))?;
        // Anything that is not a data frame — trailers — carries no body bytes.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if bytes.len() + data.len() > limit {
            return Err(anyhow::anyhow!(
                "request body is over the {limit} byte limit"
            ));
        }
        bytes.extend_from_slice(&data);
    }
    Ok(bytes.into())
}

fn should_compress(content_type: Option<&str>) -> bool {
    if let Some(ct) = content_type {
        ct.starts_with("text/")
            || ct.contains("application/json")
            || ct.contains("application/javascript")
            || ct.contains("application/xml")
            || ct.contains("application/xhtml")
    } else {
        false
    }
}

async fn compress_response(
    response: Response<hyper::body::Incoming>,
    encoding: &str,
) -> anyhow::Result<Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>>>
{
    let (parts, body) = response.into_parts();
    let mut body = body;
    let mut bytes: Vec<u8> = Vec::new();

    // Read only as far as the limit, so the decision to compress is made with
    // the size known rather than after the whole body has been collected. How
    // large a response is cannot be asked up front: a chunked one declares no
    // length at all, and a backend is free to send past the one it declared.
    while let Some(frame) = http_body_util::BodyExt::frame(&mut body).await {
        let frame =
            frame.map_err(|e| anyhow::anyhow!("failed to read the response body: {}", e))?;
        // Anything that is not a data frame — trailers — carries no body bytes.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        bytes.extend_from_slice(&data);
        if bytes.len() > MAX_COMPRESS_SIZE {
            tracing::debug!(
                "Response past {} bytes, forwarding the rest uncompressed",
                MAX_COMPRESS_SIZE
            );
            // What has been read still goes out, ahead of the body handed on:
            // dropping it would truncate the response. From here the rest is
            // streamed rather than held, so a large response costs one frame.
            let read = futures_util::stream::once(futures_util::future::ready(
                Ok::<_, hyper::Error>(hyper::body::Frame::data(bytes::Bytes::from(bytes))),
            ));
            let rest =
                http_body_util::BodyExt::into_data_stream(body).map_ok(hyper::body::Frame::data);
            return Ok(Response::from_parts(
                parts,
                http_body_util::StreamBody::new(read.chain(rest)).boxed_unsync(),
            ));
        }
    }

    // Compressing up to `MAX_COMPRESS_SIZE` bytes is straight CPU work, and it
    // used to run on whichever worker happened to be serving this request: a
    // tokio worker stalls every task scheduled behind it, so one compressible
    // response became a delay on unrelated ones. `spawn_blocking` hands it to a
    // thread built for it and leaves the worker free.
    let compressed_bytes = tokio::task::spawn_blocking(move || {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bytes)?;
        encoder.finish()
    })
    .await
    .map_err(|e| anyhow::anyhow!("the gzip encoder did not run: {e}"))??;

    let mut new_parts = parts;
    new_parts.headers.remove("content-encoding");
    new_parts.headers.remove("content-length");
    new_parts.headers.insert(
        "content-encoding",
        encoding
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid content-encoding {:?}: {}", encoding, e))?,
    );

    Ok(Response::from_parts(
        new_parts,
        http_body_util::BodyExt::boxed_unsync(
            Full::new(compressed_bytes.into()).map_err(|_| unreachable!()),
        ),
    ))
}

pub fn create_error_response(
    status: StatusCode,
    message: &str,
) -> Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(http_body_util::BodyExt::boxed_unsync(
            Full::new(message.as_bytes().to_vec().into()).map_err(|_| unreachable!()),
        ))
        .unwrap()
}

pub fn is_websocket_request(req: &Request<Incoming>) -> bool {
    if let Some(upgrade) = req.headers().get("upgrade")
        && let Ok(upgrade_str) = upgrade.to_str()
        && upgrade_str.to_lowercase() == "websocket"
        && let Some(connection) = req.headers().get("connection")
        && let Ok(connection_str) = connection.to_str()
    {
        return connection_str.to_lowercase().contains("upgrade");
    }
    false
}

pub fn is_websocket_request_static(req: &Request<()>) -> bool {
    if let Some(upgrade) = req.headers().get("upgrade")
        && let Ok(upgrade_str) = upgrade.to_str()
        && upgrade_str.to_lowercase() == "websocket"
        && let Some(connection) = req.headers().get("connection")
        && let Ok(connection_str) = connection.to_str()
    {
        return connection_str.to_lowercase().contains("upgrade");
    }
    false
}

/// What one proxied request came to.
///
/// The streaming path writes the response straight into the QUIC stream, so
/// there is no `Response` left for the caller to inspect; without this the
/// tunnel path — the one every client actually uses — could not be logged at
/// all.
#[derive(Debug, Clone, Copy)]
pub struct ProxySummary {
    pub status: u16,
    /// Response headers plus body payload, excluding chunk framing.
    ///
    /// What reached the client, counted at each successful write rather than
    /// at each byte formatted: a partially streamed response reports the part
    /// that was flushed, not the length it was going to be.
    pub bytes_sent: usize,
}

/// A proxied request that did not finish.
///
/// The streaming path writes as it goes, so by the time something fails the
/// status line — and possibly half the body — is already on the wire. Reporting
/// every failure as a 502 with zero bytes claims a response was never sent when
/// the client is holding part of one, which is the worst possible thing for an
/// access log to say about a request: it points the reader at the backend for a
/// problem that happened after the backend answered. What had arrived when it
/// broke is carried here instead, and is `None` only when nothing had.
#[derive(Debug)]
pub struct ProxyFailure {
    pub error: anyhow::Error,
    pub partial: Option<ProxySummary>,
}

impl From<anyhow::Error> for ProxyFailure {
    fn from(error: anyhow::Error) -> Self {
        ProxyFailure {
            error,
            partial: None,
        }
    }
}

impl From<::http::Error> for ProxyFailure {
    fn from(error: ::http::Error) -> Self {
        ProxyFailure::from(anyhow::anyhow!("{error}"))
    }
}

impl ProxyFailure {
    /// A failure that happened `written` bytes into a `status` response.
    ///
    /// Used on the paths where the count is of bytes the client actually
    /// received: a buffer that was filled but never flushed has not arrived, so
    /// it is not in here.
    fn after(status: StatusCode, written: usize, error: anyhow::Error) -> Self {
        ProxyFailure {
            error,
            partial: Some(ProxySummary {
                status: status.as_u16(),
                bytes_sent: written,
            }),
        }
    }
}

// One more argument than clippy allows: the alternative is a struct bundling the
// client with its deadlines, which every caller would have to build in order to
// pass the same two things — see the note on `conn::handle_bidi_stream`.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_to_backend_streaming(
    client: &HttpClient,
    // How long the backend may take to answer. Not read off the client, because
    // it is not the client's: the client owns the deadline for every dial, this
    // is the one for a single answer. See `crate::config::Timeouts`.
    timeouts: crate::config::Timeouts,
    req: &Request<()>,
    backend_url: &str,
    body_data: Vec<u8>,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    request_id: &str,
) -> Result<ProxySummary, ProxyFailure> {
    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let new_uri = format!("{}://{}:{}{}", url.scheme(), host, port, path)
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let mut builder = Request::builder().method(req.method()).uri(new_uri);

    // A chunked body is sent as one buffer with a length of our own, so only a
    // request whose `content-length` we could not read takes that path. One we
    // could read is forwarded with the header it arrived with.
    let declared_length = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let chunked = declared_length.is_none() && request_is_chunked(req);

    for (name, value) in req.headers() {
        // Preserve the client's original Host header so backend virtual-host
        // routing works. The body below is read whole and sent as one buffer,
        // so `transfer-encoding` and friends must not claim otherwise.
        if !forwards_request_header(name.as_str()) {
            continue;
        }
        // Dropped rather than overwritten: a second `content-length` on one
        // request is what lets a proxy and a backend disagree about where the
        // body ends, and an unreadable one is exactly the case that survives
        // the filter above.
        if chunked && name == "content-length" {
            continue;
        }
        builder = builder.header(name, value);
    }

    let mut full_body = body_data;
    if let Some(content_length) = declared_length {
        // Checked before the body is read, not after: `content_length` is the
        // size of the buffer this is about to fill.
        if content_length > MAX_REQUEST_BODY {
            return Err(ProxyFailure::from(anyhow::anyhow!(
                "request body of {content_length} bytes is over the {MAX_REQUEST_BODY} byte limit"
            )));
        }
        read_remaining_request_body(recv, &mut full_body, content_length).await?;
    } else if chunked {
        // A chunked body declares no length, so without this branch the request
        // went out carrying only the bytes that happened to arrive with the
        // head — and `transfer-encoding` is not forwarded, so the backend was
        // handed a body with no framing at all and no way to know it was
        // truncated. Decode the chunks and send one buffer with a length.
        read_chunked_request_body(recv, &mut full_body).await?;
        builder = builder.header("content-length", full_body.len());
    }

    let proxied_req = builder.body(Full::new(full_body.into()))?;

    tracing::debug!(
        "Proxying request via client (streaming): {} {}",
        proxied_req.method(),
        proxied_req.uri()
    );

    // The same deadline `proxy_request` uses — one number for one thing. Without
    // it a backend that accepts the connection and then never sends a head keeps
    // this task, and the stream slot it holds, alive forever.
    let response_deadline = timeouts.response;
    let response = match tokio::time::timeout(response_deadline, client.request(proxied_req)).await
    {
        Ok(result) => result.map_err(|e| {
            tracing::error!("Failed to send request: {:?}", e);
            anyhow::anyhow!("failed to send request: {:?}", e)
        })?,
        Err(_) => {
            return Err(ProxyFailure::from(anyhow::anyhow!(
                "backend did not respond within {:?}",
                response_deadline
            )));
        }
    };

    let (parts, body) = response.into_parts();

    let status = parts.status;
    let status_text = status.canonical_reason().unwrap_or("Unknown");

    let mut response_buf = Vec::new();
    response_buf
        .extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status_text).as_bytes());

    let original_was_chunked = parts
        .headers
        .get("transfer-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|v| v.to_lowercase().contains("chunked"))
        .unwrap_or(false);
    let has_content_length = parts.headers.get("content-length").is_some();

    for (name, value) in parts.headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if name_lower == "transfer-encoding" {
            continue;
        }
        // Dropped, not duplicated: the id we write below is the one our own
        // access log records, and a second one from the backend would leave
        // whoever reads the response guessing which to quote.
        if name_lower == "x-request-id" {
            continue;
        }
        response_buf.extend_from_slice(name.as_str().as_bytes());
        response_buf.extend_from_slice(b": ");
        response_buf.extend_from_slice(value.as_bytes());
        response_buf.extend_from_slice(b"\r\n");
    }

    let use_chunked = !has_content_length && original_was_chunked;
    if use_chunked {
        response_buf.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    // The id the caller gave this request, so a client can name the access log
    // line that goes with the answer it got. Built by hand like the rest of
    // this buffer: there is no `http::Response` here to hang a header on.
    response_buf.extend_from_slice(b"x-request-id: ");
    response_buf.extend_from_slice(request_id.as_bytes());
    response_buf.extend_from_slice(b"\r\n");
    response_buf.extend_from_slice(b"\r\n");

    // Counted once it is on the wire, not when it is formatted: `bytes_sent`
    // is what the access log reports as delivered, and a header that failed to
    // write reached nobody.
    let mut bytes_sent = 0;
    if let Err(e) = send.write_all(&response_buf).await {
        return Err(ProxyFailure::from(anyhow::anyhow!(
            "failed to write the response head: {e}"
        )));
    }
    bytes_sent += response_buf.len();

    // Body chunks used to go out as one `write_all` per hyper chunk (plus three more per
    // chunk when the response is chunk-encoded). Each of those turns into its own QUIC
    // STREAM frame, so a 64 KiB hyper chunk produced ~4 tiny frames instead of one. Coalesce
    // into a buffer and flush at 64 KiB: same latency profile for streamed responses, a
    // large drop in frame count and `SendStream` wakeups for bulk transfer.
    //
    // The header above is still written separately so that a slow producer
    // (SSE, long-poll) is not held back until 64 KiB accumulate.
    const RESPONSE_FLUSH_THRESHOLD: usize = 64 * 1024;
    // Started small rather than at the threshold: the threshold is a latency
    // bound, not an expected size, and most responses never come near it —
    // reserving it up front took 64 KiB from every streamed response, most of
    // which then went back unused. Growing costs the same few reallocs the
    // large responses would have paid anyway.
    const INITIAL_FLUSH_CAPACITY: usize = 8 * 1024;
    let mut out = Vec::with_capacity(INITIAL_FLUSH_CAPACITY);

    // Bytes the client has actually received, as opposed to `out`, which holds
    // what is being coalesced and may still be lost: a body that died half way
    // is reported as the half that arrived, not as the whole that was intended.
    let mut body_stream = http_body_util::BodyExt::into_data_stream(body);
    while let Some(chunk) = body_stream.next().await {
        match chunk {
            Ok(data) => {
                if use_chunked {
                    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
                    out.extend_from_slice(&data);
                    out.extend_from_slice(b"\r\n");
                } else {
                    out.extend_from_slice(&data);
                }
                if out.len() >= RESPONSE_FLUSH_THRESHOLD {
                    if let Err(e) = send.write_all(&out).await {
                        return Err(ProxyFailure::after(status, bytes_sent, e.into()));
                    }
                    bytes_sent += out.len();
                    out.clear();
                }
            }
            Err(e) => {
                tracing::debug!("Streaming response read error: {}", e);
                return Err(ProxyFailure::after(status, bytes_sent, e.into()));
            }
        }
    }

    if use_chunked {
        out.extend_from_slice(b"0\r\n\r\n");
    }
    if !out.is_empty() {
        if let Err(e) = send.write_all(&out).await {
            return Err(ProxyFailure::after(status, bytes_sent, e.into()));
        }
        bytes_sent += out.len();
    }

    if let Err(e) = send.finish() {
        return Err(ProxyFailure::after(status, bytes_sent, e.into()));
    }

    Ok(ProxySummary {
        status: status.as_u16(),
        bytes_sent,
    })
}

/// The longest line a chunk header may be.
///
/// A chunk size is a hex number with optional extensions, so anything past a
/// few dozen bytes is malformed; the cap keeps a stream that never sends a
/// CRLF from growing this buffer without bound.
const MAX_CHUNK_HEADER: usize = 1024;

/// How long the body may go without the peer sending anything.
///
/// An idle timeout, not a total one: it is rearmed on every read, so a large
/// upload that trickles for minutes is fine while a stream that opens the
/// request and then stops — holding a connection slot on the way — is not.
const REQUEST_BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many bytes of a chunked body `input` decodes on its own.
///
/// Returns the decoded bytes, how much of `input` was used up, and whether the
/// terminating zero chunk was seen. Bytes belonging to an incomplete chunk are
/// *not* reported as used: the caller keeps them and hands them back with
/// whatever it reads next. `limit` is how much body is still allowed.
fn decode_chunks(input: &[u8], limit: usize) -> Result<(Vec<u8>, usize, bool), anyhow::Error> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut used = 0usize;

    loop {
        let Some(rel) = input[pos..].windows(2).position(|w| w == b"\r\n") else {
            // Still waiting for the line, which is normal while the header is
            // arriving — but only for so long. Without this the caller keeps
            // appending every read to its buffer, and a peer that never sends
            // a CRLF grows it without bound.
            if input.len() - pos > MAX_CHUNK_HEADER {
                return Err(anyhow::anyhow!(
                    "chunk header longer than {MAX_CHUNK_HEADER} bytes"
                ));
            }
            return Ok((out, used, false));
        };
        if rel > MAX_CHUNK_HEADER {
            return Err(anyhow::anyhow!(
                "chunk header longer than {MAX_CHUNK_HEADER} bytes"
            ));
        }

        let size = parse_chunk_size(&input[pos..pos + rel])?;
        let after_header = pos + rel + 2;

        // The zero chunk ends the body. What follows is the trailer section,
        // which is not forwarded: an empty one (the usual case) is consumed so
        // the stream is left clean, and a real one is left untouched — this
        // request owns the stream, so there is nothing after it to keep in
        // step with.
        if size == 0 {
            let done = input.len() >= after_header + 2
                && &input[after_header..after_header + 2] == b"\r\n";
            return Ok((
                out,
                if done { after_header + 2 } else { after_header },
                true,
            ));
        }

        // Neither check may add: `size` comes from the client and
        // `usize::from_str_radix` accepts values near `usize::MAX`, so
        // `out.len() + size` and `size + 2` overflow — a panic in a debug
        // build, and in release a bound that wraps and then lets the slice
        // below run off the end.
        if size > limit || out.len() > limit - size {
            return Err(anyhow::anyhow!(
                "chunked request body is over the {limit} byte limit"
            ));
        }
        // What is left after the header, so "is there a whole chunk here" is a
        // subtraction of two lengths instead of an addition that can wrap.
        let remaining = input.len() - after_header;
        if remaining < size || remaining - size < 2 {
            return Ok((out, used, false));
        }

        out.extend_from_slice(&input[after_header..after_header + size]);
        if &input[after_header + size..after_header + size + 2] != b"\r\n" {
            return Err(anyhow::anyhow!("chunk data is not followed by CRLF"));
        }

        pos = after_header + size + 2;
        used = pos;
    }
}

/// The size a chunk header declares, in bytes.
fn parse_chunk_size(header: &[u8]) -> Result<usize, anyhow::Error> {
    let text = std::str::from_utf8(header)
        .map_err(|_| anyhow::anyhow!("chunk header is not valid UTF-8"))?;
    let digits = text.split(';').next().unwrap_or("").trim();
    if digits.is_empty() {
        return Err(anyhow::anyhow!("chunk header declares no size"));
    }
    usize::from_str_radix(digits, 16)
        .map_err(|_| anyhow::anyhow!("{digits:?} is not a hexadecimal chunk size"))
}

/// Reads a chunked request body off an iroh stream, leaving the de-chunked
/// bytes in `body`.
///
/// Whatever arrived with the head is already the start of the chunk stream, so
/// it is handed to the decoder first and only then is more read.
async fn read_chunked_request_body(
    recv: &mut iroh::endpoint::RecvStream,
    body: &mut Vec<u8>,
) -> Result<(), anyhow::Error> {
    let mut pending = std::mem::take(body);
    let mut buf = [0u8; 8192];

    loop {
        let (decoded, used, complete) =
            decode_chunks(&pending, MAX_REQUEST_BODY.saturating_sub(body.len()))?;
        body.extend_from_slice(&decoded);
        pending.drain(..used);
        if complete {
            return Ok(());
        }

        let read = match tokio::time::timeout(REQUEST_BODY_READ_TIMEOUT, recv.read(&mut buf)).await
        {
            Ok(result) => result
                .map_err(|e| anyhow::anyhow!("failed to read request body from iroh: {}", e))?,
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "chunked request body went {}s without sending anything",
                    REQUEST_BODY_READ_TIMEOUT.as_secs()
                ));
            }
        };
        let n = read.filter(|n| *n > 0).ok_or_else(|| {
            anyhow::anyhow!("chunked request body ended before its terminating chunk")
        })?;
        pending.extend_from_slice(&buf[..n]);
    }
}

/// Whether the request body is framed as chunks.
fn request_is_chunked(req: &Request<()>) -> bool {
    req.headers()
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_lowercase().contains("chunked"))
}

/// Generic over the reader so the idle cap below can be tested without an
/// endpoint; callers pass an iroh receive stream.
async fn read_remaining_request_body<R>(
    recv: &mut R,
    body: &mut Vec<u8>,
    content_length: usize,
) -> Result<(), anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut remaining = content_length.saturating_sub(body.len());
    let mut buf = [0u8; 8192];

    while remaining > 0 {
        // Idle-capped per read, like the chunked path: a peer that declares a
        // large `content-length` and then drips it a byte at a time otherwise
        // holds the buffer, and the stream slot, for as long as it likes.
        let read = match tokio::time::timeout(REQUEST_BODY_READ_TIMEOUT, recv.read(&mut buf)).await
        {
            Ok(result) => result
                .map_err(|e| anyhow::anyhow!("failed to read request body from iroh: {}", e))?,
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "request body went {}s without sending anything: {} of {} bytes arrived",
                    REQUEST_BODY_READ_TIMEOUT.as_secs(),
                    body.len(),
                    content_length
                ));
            }
        };
        // Zero is the reader's end of stream, which is an iroh `None` on the
        // concrete receive stream: the peer gave up before the declared length.
        if read == 0 {
            return Err(anyhow::anyhow!(
                "request body ended before content-length: expected {} bytes, got {}",
                content_length,
                body.len()
            ));
        }

        let take = read.min(remaining);
        body.extend_from_slice(&buf[..take]);
        remaining -= take;
    }

    tracing::debug!(
        "Read request body from iroh: {} bytes (content-length {})",
        body.len(),
        content_length
    );
    Ok(())
}

pub fn parse_http_response_legacy(response: &[u8]) -> Result<Response<Vec<u8>>, anyhow::Error> {
    // The end of the header block is looked for in the bytes, never measured
    // off a decoded string: `from_utf8_lossy` turns each invalid byte into
    // U+FFFD, which is three bytes in UTF-8, so every offset computed from the
    // decoded text drifts by two per bad byte and the body started — or ended
    // — in the wrong place. A header with a single non-UTF-8 byte was enough
    // to hand the caller a body sliced out of the middle of the headers.
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response: no end of headers"))?;
    let body_start = header_end + 4;

    // Only the head is decoded, so nothing below can produce an offset again.
    let head = String::from_utf8_lossy(&response[..header_end]);
    let mut lines = head.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response: missing status line"))?;

    let status_parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code = if status_parts.len() >= 2 {
        status_parts[1]
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid status code: {}", e))?
    } else {
        500
    };

    let mut builder = Response::builder().status(status_code);

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    let body = response[body_start..].to_vec();

    Ok(builder.body(body)?)
}

pub fn parse_http_request_legacy(buf: &[u8]) -> Result<Request<()>, anyhow::Error> {
    let request_str = String::from_utf8_lossy(buf);
    let mut lines = request_str.split("\r\n");

    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP request: missing request line"))?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("invalid HTTP request line"));
    }

    let method = http::Method::from_bytes(parts[0].as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid HTTP method: {}", e))?;
    let uri = http::Uri::try_from(parts[1]).map_err(|e| anyhow::anyhow!("invalid URI: {}", e))?;

    let mut builder = Request::builder().method(method).uri(uri);

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    Ok(builder.body(())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body of `len` bytes, which is what the limit has to be checked against.
    fn body_of(len: usize) -> Full<bytes::Bytes> {
        Full::new(bytes::Bytes::from(vec![b'x'; len]))
    }

    #[tokio::test]
    async fn a_body_within_the_limit_is_read_whole() {
        let read = read_body_limited(body_of(10), 10).await.unwrap();
        assert_eq!(read.len(), 10);
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused() {
        // One frame is enough to exceed it, so this is the case the old
        // `collect()` could not catch without first holding all of it.
        let err = read_body_limited(body_of(11), 10).await.unwrap_err();
        assert!(err.to_string().contains("over the 10 byte limit"));
    }

    #[tokio::test]
    async fn an_empty_body_is_within_any_limit() {
        let read = read_body_limited(body_of(0), 0).await.unwrap();
        assert!(read.is_empty());
    }

    /// A chunked body of one or more `chunks`, terminated the usual way.
    fn chunked(chunks: &[&str]) -> Vec<u8> {
        let mut raw = Vec::new();
        for chunk in chunks {
            raw.extend_from_slice(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes());
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        raw
    }

    #[test]
    fn a_chunked_body_is_decoded_whole() {
        let raw = chunked(&["hello", " world"]);
        let (body, used, complete) = decode_chunks(&raw, 1024).unwrap();
        assert_eq!(body, b"hello world");
        assert!(complete);
        assert_eq!(used, raw.len());
    }

    #[test]
    fn a_chunk_header_may_carry_extensions() {
        let raw = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        let (body, _, complete) = decode_chunks(raw, 1024).unwrap();
        assert_eq!(body, b"hello");
        assert!(complete);
    }

    #[test]
    fn an_incomplete_chunk_is_left_for_the_next_read() {
        // What a stream split mid-chunk looks like: the reader must keep the
        // bytes it could not decode and hand them back with the next read.
        let raw = chunked(&["hello", " world"]);
        // Three bytes into the second chunk's data: its header arrived, the
        // payload did not.
        let split = 16;

        let (first, used, complete) = decode_chunks(&raw[..split], 1024).unwrap();
        assert_eq!(first, b"hello");
        assert!(!complete);
        assert!(used < split);

        let mut pending = raw[used..split].to_vec();
        pending.extend_from_slice(&raw[split..]);
        let (body, _, complete) = decode_chunks(&pending, 1024).unwrap();
        assert_eq!(body, b" world");
        assert!(complete);
    }

    #[test]
    fn the_body_ends_at_the_zero_chunk() {
        // Trailers are not forwarded, so they must not be swallowed either:
        // anything after the zero chunk is not part of what was decoded.
        let mut raw = chunked(&["hello"]);
        raw.extend_from_slice(b"X-Trailer: done\r\n\r\n");
        let (body, used, complete) = decode_chunks(&raw, 1024).unwrap();
        assert_eq!(body, b"hello");
        assert!(complete);
        assert_eq!(&raw[used..], b"X-Trailer: done\r\n\r\n");
    }

    #[test]
    fn a_chunked_body_over_the_limit_is_refused() {
        let raw = chunked(&["hello"]);
        let err = decode_chunks(&raw, 4).unwrap_err();
        assert!(err.to_string().contains("over the 4 byte limit"));
    }

    #[test]
    fn a_chunk_size_that_would_overflow_is_refused() {
        // `usize::MAX`, spelled as a chunk size: the old `out.len() + size`
        // wrapped to a small number in release and panicked in debug, so the
        // limit looked satisfied and the slice below ran off the end.
        let err = decode_chunks(b"ffffffffffffffff\r\nhello\r\n", 1024).unwrap_err();
        assert!(err.to_string().contains("over the 1024 byte limit"));

        // Same for the `size + 2` that checked for the trailing CRLF.
        let err = decode_chunks(b"ffffffffffffffff\r\nhello", 1024).unwrap_err();
        assert!(err.to_string().contains("over the 1024 byte limit"));
    }

    #[test]
    fn a_chunk_header_that_never_ends_is_refused() {
        // No CRLF anywhere, so the caller would keep buffering: a peer that
        // sends a header and never terminates it grows it without bound.
        let mut raw = Vec::new();
        raw.extend_from_slice(&b"5;".repeat(MAX_CHUNK_HEADER));
        let err = decode_chunks(&raw, 1024).unwrap_err();
        assert!(err.to_string().contains("chunk header longer than"));

        // A short header that is still arriving is fine — it is not an error
        // to be waiting for the rest of one.
        let (body, used, complete) = decode_chunks(b"5\r", 1024).unwrap();
        assert!(body.is_empty());
        assert_eq!(used, 0);
        assert!(!complete);
    }

    #[test]
    fn a_chunk_header_that_is_not_hexadecimal_is_refused() {
        let err = decode_chunks(b"zz\r\nhello\r\n0\r\n\r\n", 1024).unwrap_err();
        assert!(err.to_string().contains("not a hexadecimal chunk size"));
    }

    #[test]
    fn chunk_data_without_its_crlf_is_refused() {
        let err = decode_chunks(b"5\r\nhelloXX\r\n0\r\n\r\n", 1024).unwrap_err();
        assert!(err.to_string().contains("not followed by CRLF"));
    }

    #[test]
    fn a_chunked_request_is_recognised_by_its_encoding() {
        let chunked_req = Request::builder()
            .header("transfer-encoding", "Chunked")
            .body(())
            .unwrap();
        assert!(request_is_chunked(&chunked_req));

        let plain = Request::builder()
            .header("transfer-encoding", "gzip")
            .body(())
            .unwrap();
        assert!(!request_is_chunked(&plain));
        assert!(!request_is_chunked(&Request::builder().body(()).unwrap()));
    }

    #[test]
    fn legacy_request_parser_keeps_the_request_line_and_headers() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: app.example.com\r\nX-Empty:\r\n\r\n";
        let req = parse_http_request_legacy(raw).unwrap();

        assert_eq!(req.method(), http::Method::GET);
        assert_eq!(req.uri().path(), "/index.html");
        assert_eq!(req.headers()["host"], "app.example.com");
        // A header with no value is still a header.
        assert_eq!(req.headers()["x-empty"], "");
    }

    #[test]
    fn legacy_request_parser_stops_at_the_blank_line() {
        let raw = b"POST /api HTTP/1.1\r\nHost: a\r\n\r\nnot-a-header";
        let req = parse_http_request_legacy(raw).unwrap();

        assert_eq!(req.method(), http::Method::POST);
        assert_eq!(req.headers().len(), 1);
    }

    #[test]
    fn legacy_request_parser_rejects_a_request_line_without_a_target() {
        assert!(parse_http_request_legacy(b"GET\r\nHost: a\r\n\r\n").is_err());
    }

    #[test]
    fn legacy_response_parser_splits_status_headers_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello";
        let res = parse_http_response_legacy(raw).unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["content-type"], "text/plain");
        assert_eq!(res.body().as_slice(), b"hello".as_slice());
    }

    #[test]
    fn legacy_response_parser_leaves_no_body_when_there_is_none() {
        let res = parse_http_response_legacy(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();

        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(res.body().is_empty());
    }

    #[test]
    fn legacy_response_parser_falls_back_to_500_without_a_status_code() {
        let res = parse_http_response_legacy(b"HTTP/1.1\r\n\r\n").unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(res.body().is_empty());
    }

    /// What the offset arithmetic used to get wrong: `from_utf8_lossy` turns
    /// one invalid byte into a three-byte U+FFFD, so a header carrying binary
    /// data shifted `body_start` and the body came out of the middle of the
    /// headers — or was empty.
    #[test]
    fn legacy_response_parser_finds_the_body_behind_a_non_utf8_header() {
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Binary: ".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(b"\r\n\r\nbody-bytes");

        let res = parse_http_response_legacy(&raw).unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.body().as_slice(), b"body-bytes".as_slice());
    }

    #[test]
    fn legacy_response_parser_rejects_a_response_with_no_end_of_headers() {
        // Truncated: there is no place where the body could start, and
        // guessing one used to be how it silently returned an empty body.
        assert!(parse_http_response_legacy(b"HTTP/1.1 200 OK\r\nX-A: 1\r\n").is_err());
    }

    #[test]
    fn hop_by_hop_headers_do_not_reach_the_backend() {
        for dropped in [
            "connection",
            "Proxy-Connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "expect",
        ] {
            assert!(
                !forwards_request_header(dropped),
                "{dropped} belongs to this hop only"
            );
        }
        for kept in ["host", "accept", "content-length", "sec-websocket-key"] {
            assert!(forwards_request_header(kept), "{kept} is the message's own");
        }
    }

    /// Hands over `chunks` one read at a time and then either ends the stream
    /// or stalls forever — the two shapes a peer that declared a
    /// `content-length` can take once the head has been sent.
    struct ScriptedReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
        ends: bool,
    }

    impl ScriptedReader {
        fn pieces(pieces: &[&[u8]], ends: bool) -> Self {
            Self {
                chunks: pieces.iter().map(|p| p.to_vec()).collect(),
                ends,
            }
        }
    }

    impl tokio::io::AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.chunks.pop_front() {
                Some(chunk) => {
                    buf.put_slice(&chunk);
                    std::task::Poll::Ready(Ok(()))
                }
                // Nothing left and the peer gave up: end of stream, which is
                // what reports the body as shorter than it claimed to be.
                None if self.ends => std::task::Poll::Ready(Ok(())),
                // Still connected, still silent.
                None => std::task::Poll::Pending,
            }
        }
    }

    /// The clock is paused, so the 30s cap is reached without the test waiting
    /// for it: what is being checked is that there is a cap at all.
    #[tokio::test(start_paused = true)]
    async fn a_declared_body_that_stops_arriving_is_given_up_on() {
        let mut reader = ScriptedReader::pieces(&[b"a-few-bytes"], false);
        let mut body = Vec::new();

        let err = read_remaining_request_body(&mut reader, &mut body, 64)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("without sending anything"),
            "{err}"
        );
        assert_eq!(body, b"a-few-bytes");
    }

    #[tokio::test(start_paused = true)]
    async fn a_declared_body_that_keeps_arriving_is_read_whole() {
        let mut reader = ScriptedReader::pieces(&[b"abc", b"de"], true);
        // Two bytes came in with the head, so five are still owed.
        let mut body = b"xx".to_vec();

        read_remaining_request_body(&mut reader, &mut body, 7)
            .await
            .unwrap();

        assert_eq!(body, b"xxabcde");
    }

    #[tokio::test(start_paused = true)]
    async fn a_declared_body_that_ends_early_is_an_error() {
        let mut reader = ScriptedReader::pieces(&[b"abc"], true);
        let mut body = Vec::new();

        let err = read_remaining_request_body(&mut reader, &mut body, 16)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("ended before content-length"),
            "{err}"
        );
    }
}

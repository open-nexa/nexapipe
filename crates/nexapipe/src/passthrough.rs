//! Raw byte forwarding for connections the proxy must not parse.
//!
//! TLS is terminated by the backend (Caddy &co), so a `ClientHello` reaching
//! the proxy is not a request this process can act on: the SNI inside it names
//! the route, and the bytes are copied to that route's backend untouched. The
//! proxy holds no key material and never inspects the encrypted traffic.
//!
//! Both entry points feed this module. The iroh path sees the `ClientHello`
//! written by the client's tunnel (`nexapipe-client::local_proxy::
//! handle_tls_tunnel`); the plaintext listener sees one from any local client.
//! Either way the first byte is `0x16`, which is what the dispatchers key on —
//! an HTTP request can never start with it.

use crate::auth::ClientAcl;
use crate::routes::RouteConfig;
use crate::stream_util::{DuplexIroh, copy_both_ways, read_more};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt};

/// TLS record content type: handshake (a `ClientHello` starts with this).
pub const TLS_HANDSHAKE: u8 = 0x16;

/// Handshake message type: `ClientHello`.
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Extension type: `server_name` (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;

/// SNI name type: `host_name`.
const NAME_TYPE_HOST: u8 = 0x00;

/// A `ClientHello` is a few hundred bytes; anything this large is not one, and
/// the cap keeps a hostile peer from making the proxy buffer without bound.
const MAX_HANDSHAKE_LEN: usize = 16 * 1024;

/// How long to wait for the rest of the `ClientHello` before giving up on it.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a backend connection may take to establish.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// True when `first_byte` starts a TLS handshake record.
pub fn is_tls_handshake(first_byte: u8) -> bool {
    first_byte == TLS_HANDSHAKE
}

/// Serve a TLS connection that arrived over an iroh bi-stream.
///
/// `initial` holds the bytes already read from `recv` (at least the first).
/// `acl` is the authenticated client's host authorization, if any.
pub async fn handle_iroh_stream(
    send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    initial: Vec<u8>,
    config: &RouteConfig,
    acl: Option<&ClientAcl>,
) -> anyhow::Result<()> {
    let handshake = read_tls_record(&mut recv, initial, HANDSHAKE_TIMEOUT).await?;
    let Some((host, port)) = resolve_backend(config, &handshake, acl).await else {
        return Ok(());
    };

    let mut backend = connect(&host, port).await?;
    backend.write_all(&handshake).await?;

    let client = DuplexIroh::new(send, recv);
    copy_both_ways(client, backend, "TLS passthrough").await?;
    Ok(())
}

/// Serve a TLS connection that arrived on a plain TCP listener.
///
/// `initial` holds the bytes the dispatcher already peeked, if any. The
/// plaintext listener has no authenticated client behind it, so no ACL
/// applies — see the module docs of `crate::proxy` for why that listener is
/// loopback-only unless explicitly exposed.
pub async fn handle_tcp_stream(
    mut client: tokio::net::TcpStream,
    initial: Vec<u8>,
    config: &RouteConfig,
) -> anyhow::Result<()> {
    let handshake = read_tls_record(&mut client, initial, HANDSHAKE_TIMEOUT).await?;
    let Some((host, port)) = resolve_backend(config, &handshake, None).await else {
        return Ok(());
    };

    let mut backend = connect(&host, port).await?;
    backend.write_all(&handshake).await?;

    copy_both_ways(client, backend, "TLS passthrough").await?;
    Ok(())
}

async fn connect(host: &str, port: u16) -> anyhow::Result<tokio::net::TcpStream> {
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out connecting to backend {}:{}", host, port))?
    .map_err(|e| anyhow::anyhow!("failed to connect to backend {}:{}: {}", host, port, e))?;

    // The tunnel carries TLS records; Nagle would only add latency here.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Reads until the first TLS record is complete.
///
/// SNI lives inside the `ClientHello`, which a client may spread over several
/// segments, and the proxy cannot pick a backend before it has the whole
/// record. A peer that goes quiet is not an error: whatever arrived is returned
/// and the SNI parse decides what happens next.
async fn read_tls_record<R>(
    reader: &mut R,
    mut buf: Vec<u8>,
    timeout: Duration,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(record_end) = first_record_end(&buf) else {
            if buf.len() > MAX_HANDSHAKE_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS ClientHello header not received",
                ));
            }
            if !read_more(reader, &mut buf, timeout).await? {
                return Ok(buf);
            }
            continue;
        };

        if buf.len() >= record_end {
            return Ok(buf);
        }
        if record_end > MAX_HANDSHAKE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS record larger than a ClientHello can be",
            ));
        }
        if !read_more(reader, &mut buf, timeout).await? {
            return Ok(buf);
        }
    }
}

/// End offset of the first TLS record, once its 5-byte header is available.
fn first_record_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    Some(5 + (((buf[3] as usize) << 8) | (buf[4] as usize)))
}

/// Maps a `ClientHello` to the backend that should terminate it.
///
/// `None` means "nothing to do": no SNI, no passthrough route for it, an SNI
/// the client's allowlist does not name, or an address that cannot be parsed.
/// Every case is logged, and every case hangs up the same way — a client
/// cannot tell "not configured" from "not allowed", so it cannot probe which
/// names exist behind the proxy.
async fn resolve_backend(
    config: &RouteConfig,
    handshake: &[u8],
    acl: Option<&ClientAcl>,
) -> Option<(String, u16)> {
    let Some(sni) = extract_sni(handshake) else {
        tracing::debug!("TLS passthrough: no SNI in ClientHello, closing");
        return None;
    };

    if let Some(acl) = acl
        && !acl.allows(&sni)
    {
        tracing::warn!(
            "TLS passthrough: SNI '{}' is not allowed for this client, closing",
            sni
        );
        return None;
    }

    let Some(backend) = config.get_passthrough_backend(&sni).await else {
        tracing::warn!(
            "TLS passthrough: no `mode = \"passthrough\"` route for SNI '{}', closing",
            sni
        );
        return None;
    };

    let Some((host, port)) = parse_backend_addr(&backend) else {
        tracing::error!(
            "TLS passthrough: cannot parse backend address '{}' for SNI '{}'",
            backend,
            sni
        );
        return None;
    };

    tracing::debug!("TLS passthrough: SNI '{}' -> {}:{}", sni, host, port);
    Some((host, port))
}

/// Accepts `host:port` or a full URL (`https://caddy:443`).
///
/// The scheme carries no meaning here — passthrough copies bytes and never
/// speaks TLS itself — so it is accepted and ignored, which keeps the backend
/// list in the same shape as the HTTP routes.
///
/// Public because the config check uses it too: the route is dialled with this
/// function, so validating with anything else is how a backend passes at
/// startup and fails on the first connection.
pub fn parse_backend_addr(backend: &str) -> Option<(String, u16)> {
    let backend = backend.trim();
    if backend.is_empty() {
        return None;
    }

    if backend.contains("://") {
        let url = url::Url::parse(backend).ok()?;
        let host = url.host_str()?.to_string();
        let port = url.port_or_known_default()?;
        return Some((strip_ipv6_brackets(&host).to_string(), port));
    }

    // A bracketed IPv6 literal: the colons inside the address come before the
    // one that separates the port, so the brackets have to go first.
    if let Some(rest) = backend.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            // An unclosed bracket is not a host name anyone can resolve.
            return None;
        };
        if host.is_empty() {
            return None;
        }
        return match tail.strip_prefix(':') {
            Some(port) => port.parse().ok().map(|p| (host.to_string(), p)),
            // No port: the TLS port, the same default a bare host gets.
            None => Some((host.to_string(), 443)),
        };
    }

    match backend.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => port.parse().ok().map(|p| (host.to_string(), p)),
        // A bare host means the TLS port, which is the only thing a
        // passthrough route ever points at.
        _ => Some((backend.to_string(), 443)),
    }
}

/// Drops the brackets around an IPv6 literal.
///
/// Both forms a config can use keep them — `Url::host_str()` hands back
/// `[::1]`, and so does splitting `[::1]:443` on the colon — and leaving them
/// on makes the resolver look for a host actually called `[::1]`, which no
/// backend ever is. The L4 path already did this.
fn strip_ipv6_brackets(host: &str) -> &str {
    host.trim_matches(['[', ']'])
}

/// The longest name a `host_name` may carry.
///
/// 253 is the DNS limit for a presentation-format name; a longer one cannot
/// have been meant as a host, and nothing here needs to reason about it.
const MAX_HOST_NAME_LEN: usize = 253;

/// Whether `name` is a host name this proxy is willing to act on.
///
/// Printable ASCII, and nothing else. RFC 6066 sends `host_name` as ASCII, so
/// an internationalised name arrives as its A-label and a name with non-ASCII
/// bytes in it is malformed rather than an IDN in need of normalising — which
/// also means there is no case where two different spellings of the same name
/// could reach a route as two different hosts.
///
/// Control characters are the point of the check: a host name is written to
/// the log on every path through [`resolve_backend`], and `\r\n` in it lets a
/// client append lines of its own to the server's log.
fn is_presentable_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST_NAME_LEN
        && name.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Extract the SNI host name from a TLS `ClientHello`.
///
/// Layout (RFC 8446 / RFC 6066), all lengths big-endian:
///
/// ```text
/// record:   type(1) version(2) length(2)
/// handshake: type(1) length(3)
///   client_version(2) random(32)
///   session_id:   length(1) + data
///   cipher_suites: length(2) + data
///   compression:  length(1) + data
///   extensions:   length(2) + data
///     extension: type(2) length(2) data
///       server_name: list_length(2) name_type(1) name_length(2) host_name
/// ```
///
/// Returns `None` for anything that does not fit that shape, including a
/// `ClientHello` that carries no `server_name` extension.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    let mut record = Cursor::new(data);
    if record.u8()? != TLS_HANDSHAKE {
        return None;
    }
    record.skip(2)?; // legacy record version
    let record_len = record.u16()? as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    // Handshake header. Its own length is redundant with the record length, so
    // only the type is checked.
    if record.u8()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    record.skip(3)?;

    record.skip(2)?; // client_version
    record.skip(32)?; // random

    let session_id_len = record.u8()? as usize;
    record.skip(session_id_len)?;

    let cipher_suites_len = record.u16()? as usize;
    record.skip(cipher_suites_len)?;

    let compression_len = record.u8()? as usize;
    record.skip(compression_len)?;

    let extensions_len = record.u16()? as usize;
    let mut extensions = Cursor::new(record.take(extensions_len)?);

    while extensions.remaining() >= 4 {
        let ext_type = extensions.u16()?;
        let ext_len = extensions.u16()? as usize;
        let ext_data = extensions.take(ext_len)?;

        if ext_type == EXT_SERVER_NAME {
            let mut list = Cursor::new(ext_data);
            list.skip(2)?; // server_name_list length

            // Every entry, not the first one: RFC 6066 allows a list, and a
            // client that puts an entry of another type first still has its
            // host name behind it. Stopping at a type this proxy does not
            // read turned such a hello into "no SNI".
            while list.remaining() >= 3 {
                let name_type = list.u8()?;
                let name_len = list.u16()? as usize;
                let name = list.take(name_len)?;

                if name_type != NAME_TYPE_HOST {
                    continue;
                }

                let name = String::from_utf8(name.to_vec()).ok()?;
                // Nothing downstream — the allow list, the route match, the
                // log lines — can say anything useful about a name that is not
                // a name, and a log line is the one place it could do real
                // damage: a `\r\n` in here appends whatever the client likes
                // to the server's log. Refusing is what "no SNI" already
                // means, so it costs a client nothing but a hang-up — and no
                // later entry is taken as a second guess.
                return is_presentable_host_name(&name).then_some(name);
            }
        }
    }

    None
}

/// Bounds-checked reader over a byte slice; every getter yields `None` on
/// overrun so the parser is a single chain of `?` with no index arithmetic.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let value = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        let high = self.u8()? as u16;
        let low = self.u8()? as u16;
        Some((high << 8) | low)
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(|_| ())
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but well-formed `ClientHello` carrying `sni`.
    fn client_hello_with_sni(sni: &str, include_extension: bool) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();

        let mut ext_body = Vec::new();
        if include_extension {
            ext_body.extend_from_slice(&0u16.to_be_bytes()); // ext type: server_name
            let entry_len = 1 + 2 + sni_bytes.len();
            ext_body.extend_from_slice(&((2 + entry_len) as u16).to_be_bytes()); // ext length
            ext_body.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list length
            ext_body.push(NAME_TYPE_HOST);
            ext_body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
            ext_body.extend_from_slice(sni_bytes);
        }

        client_hello_with_extension_body(&ext_body)
    }

    /// Wraps a ready-made extensions block into a full `ClientHello`, for the
    /// cases the single-SNI helper cannot spell (several entries, another
    /// entry type).
    fn client_hello_with_extension_body(ext_body: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(1); // compression_methods length
        body.push(0); // null compression
        body.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        body.extend_from_slice(ext_body);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte length
        handshake.extend_from_slice(&body);

        let mut record = vec![TLS_HANDSHAKE, 0x01, 0x00];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let hello = client_hello_with_sni("fn.iroh.iakl.top", true);
        assert_eq!(extract_sni(&hello).as_deref(), Some("fn.iroh.iakl.top"));
    }

    /// The list RFC 6066 allows: an entry of a type this proxy does not read
    /// comes first, and the host name behind it used to be invisible.
    #[test]
    fn reads_the_host_name_behind_another_kind_of_entry() {
        let mut entry = Vec::new();
        // Type 1 is not host_name; the bytes are opaque here.
        entry.push(1);
        entry.extend_from_slice(&3u16.to_be_bytes());
        entry.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        entry.push(NAME_TYPE_HOST);
        entry.extend_from_slice(&("fn.iroh.iakl.top".len() as u16).to_be_bytes());
        entry.extend_from_slice(b"fn.iroh.iakl.top");

        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&0u16.to_be_bytes()); // ext type: server_name
        ext_body.extend_from_slice(&((2 + entry.len()) as u16).to_be_bytes());
        ext_body.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(&entry);

        let hello = client_hello_with_extension_body(&ext_body);
        assert_eq!(extract_sni(&hello).as_deref(), Some("fn.iroh.iakl.top"));
    }

    #[test]
    fn returns_none_without_server_name_extension() {
        let hello = client_hello_with_sni("fn.iroh.iakl.top", false);
        assert_eq!(extract_sni(&hello), None);
    }

    #[test]
    fn returns_none_for_truncated_handshake() {
        let hello = client_hello_with_sni("fn.iroh.iakl.top", true);
        // The parser must refuse a partial record rather than read past it: the
        // caller guarantees the full record, this is the second line of defence.
        for cut in 1..hello.len().min(40) {
            assert_eq!(extract_sni(&hello[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn returns_none_for_non_handshake_records() {
        assert_eq!(extract_sni(&[]), None);
        assert_eq!(extract_sni(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), None);
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    /// Every path through `resolve_backend` writes the SNI to the log, so a
    /// name carrying a newline would let a client append lines of its own to
    /// it. It is dropped here instead of escaped on the way out: a name that
    /// is not a name has no route to reach either.
    #[test]
    fn refuses_a_host_name_that_could_forge_a_log_line() {
        for name in [
            "app.test\r\n2FA: client 'x' enrolled",
            "app.test\n",
            "app\ttest",
            "app test",
            "app.test\u{7f}",
        ] {
            let hello = client_hello_with_sni(name, true);
            assert_eq!(extract_sni(&hello), None, "{name:?}");
        }
    }

    /// `host_name` is ASCII on the wire (RFC 6066), so an internationalised
    /// name arrives as its A-label. Raw UTF-8 is malformed, and accepting it
    /// would leave one host reachable under two spellings.
    #[test]
    fn refuses_a_host_name_that_is_not_ascii() {
        let hello = client_hello_with_sni("caf\u{00e9}.test", true);
        assert_eq!(extract_sni(&hello), None);
    }

    #[test]
    fn refuses_a_host_name_past_the_dns_limit() {
        let long = "a".repeat(MAX_HOST_NAME_LEN + 1);
        let hello = client_hello_with_sni(&long, true);
        assert_eq!(extract_sni(&hello), None);

        let at_limit = "a".repeat(MAX_HOST_NAME_LEN);
        assert_eq!(
            extract_sni(&client_hello_with_sni(&at_limit, true)).as_deref(),
            Some(at_limit.as_str())
        );
    }

    #[test]
    fn parses_backend_addresses() {
        assert_eq!(
            parse_backend_addr("caddy:443"),
            Some(("caddy".to_string(), 443))
        );
        assert_eq!(
            parse_backend_addr("https://caddy:8443"),
            Some(("caddy".to_string(), 8443))
        );
        assert_eq!(
            parse_backend_addr("http://host.docker.internal"),
            Some(("host.docker.internal".to_string(), 80))
        );
        assert_eq!(
            parse_backend_addr("caddy"),
            Some(("caddy".to_string(), 443))
        );
        assert_eq!(parse_backend_addr(""), None);
        assert_eq!(parse_backend_addr("caddy:notaport"), None);
    }

    /// A restricted client gets nothing for an SNI its allowlist never named —
    /// the same `None` an unconfigured SNI gets, so the refusal cannot be
    /// told apart from "no route" and used as a probe. An on-list SNI reaches
    /// its backend as usual.
    #[tokio::test]
    async fn an_sni_off_the_clients_allowlist_resolves_to_nothing() {
        use crate::auth::ClientAcl;
        use crate::config::RouteMode;
        use crate::lb::LoadBalancingStrategy;
        use crate::routes::{Route, RouteConfig};

        let config = RouteConfig::new(vec![Route::new(
            "fn.iroh.iakl.top",
            "/",
            true,
            vec!["caddy:443".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Passthrough,
            None,
        )]);

        // Off-list: refused, even though a passthrough route exists.
        let acl = ClientAcl::from_hosts(Some(&["other.iakl.top".to_string()]));
        let hello = client_hello_with_sni("fn.iroh.iakl.top", true);
        assert!(resolve_backend(&config, &hello, Some(&acl)).await.is_none());

        // On-list: reaches the route's backend.
        let acl = ClientAcl::from_hosts(Some(&["*.iroh.iakl.top".to_string()]));
        assert_eq!(
            resolve_backend(&config, &hello, Some(&acl)).await,
            Some(("caddy".to_string(), 443))
        );

        // No ACL (no 2FA behind the connection): the historical behaviour.
        assert_eq!(
            resolve_backend(&config, &hello, None).await,
            Some(("caddy".to_string(), 443))
        );
    }

    #[test]
    fn detects_tls_handshake_prefix() {
        assert!(is_tls_handshake(0x16));
        assert!(!is_tls_handshake(b'G'));
        assert!(!is_tls_handshake(0x17));
    }

    #[test]
    fn an_ipv6_backend_loses_its_brackets() {
        // With the brackets left on, the resolver is asked for a host called
        // "[::1]" and every connection to this backend fails.
        assert_eq!(
            parse_backend_addr("[::1]:443"),
            Some(("::1".to_string(), 443))
        );
        assert_eq!(
            parse_backend_addr("https://[::1]:8443"),
            Some(("::1".to_string(), 8443))
        );
        assert_eq!(parse_backend_addr("[::1]"), Some(("::1".to_string(), 443)));
    }

    #[test]
    fn a_backend_with_no_address_is_refused() {
        assert_eq!(parse_backend_addr(""), None);
        assert_eq!(parse_backend_addr("   "), None);
    }
}

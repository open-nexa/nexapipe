//! The TLS `ClientHello`, and the name inside it.
//!
//! # Why this is here and not in either of them
//!
//! The name a `ClientHello` carries is the server's route key on the passthrough
//! path, and the client's route key on the path where the client picks the
//! route itself. Both sides have to read the same bytes and come to the same
//! answer, and they used to have a parser each: one that walked the whole
//! `server_name` list and refused a name with control characters in it, and one
//! that read the first entry and took whatever it found.
//!
//! The two could disagree about the same `ClientHello` — and the disagreement
//! is not visible in either of them, because each looks right on its own. One
//! copy, and both sides link it.
//!
//! The reader reads the **record** and nothing past it. The record's own
//! length says where the `ClientHello` ends, and the two ends do not have the
//! same buffer around those bytes, so an answer that depended on what
//! followed the record would be an answer they could disagree about.

/// TLS record content type: handshake (a `ClientHello` starts with this).
pub const TLS_HANDSHAKE: u8 = 0x16;

/// Handshake message type: `ClientHello`.
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Extension type: `server_name` (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;

/// SNI name type: `host_name`.
pub const NAME_TYPE_HOST: u8 = 0x00;

/// The longest name a `host_name` may carry.
///
/// 253 is the DNS limit for a presentation-format name; a longer one cannot
/// have been meant as a host, and nothing here needs to reason about it.
pub const MAX_HOST_NAME_LEN: usize = 253;

/// True when `first_byte` starts a TLS handshake record.
pub fn is_tls_handshake(first_byte: u8) -> bool {
    first_byte == TLS_HANDSHAKE
}

/// Whether `name` is a host name this proxy is willing to act on.
///
/// Printable ASCII, and nothing else. RFC 6066 sends `host_name` as ASCII, so
/// an internationalised name arrives as its A-label and a name with non-ASCII
/// bytes in it is malformed rather than an IDN in need of normalising — which
/// also means there is no case where two different spellings of the same name
/// could reach a route as two different hosts.
///
/// Control characters are the point of the check: a host name is written to
/// the log on every path that names it, and `\r\n` in it lets a client append
/// lines of its own to the log.
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
///
/// Only the record is read: the bytes after it are not part of the
/// `ClientHello`, and the answer must not depend on them.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    let mut header = Cursor::new(data);
    if header.u8()? != TLS_HANDSHAKE {
        return None;
    }
    header.skip(2)?; // legacy record version
    let record_len = header.u16()? as usize;
    let record_end = 5 + record_len;
    if data.len() < record_end {
        return None;
    }

    // **The record's own bytes, and nothing past them.**
    //
    // The record's length says where the `ClientHello` ends, and the answer
    // has to be about the `ClientHello` alone. Reading past the record makes
    // the answer depend on what else was in the buffer — and the two ends of
    // the tunnel do not have the same buffer: the client has whatever its
    // read pulled in, the server has what arrived on the tunnel, and the
    // tunnel path's sniffer has the record and nothing else. A hello whose
    // record understates the message inside it would then read as one name
    // on one end and another on the other.
    let mut record = Cursor::new(&data[..record_end]);
    record.skip(5)?; // the header that was just read

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
                // to the log. Refusing is what "no SNI" already means, so it
                // costs a client nothing but a hang-up — and no later entry is
                // taken as a second guess.
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

    /// Wraps a ready-made extensions block into a full `ClientHello`.
    fn hello_with_extensions(ext_body: &[u8]) -> Vec<u8> {
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

    /// A `ClientHello` carrying one name.
    fn hello(name: &str) -> Vec<u8> {
        let bytes = name.as_bytes();
        let entry_len = 1 + 2 + bytes.len();
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes()); // ext type: server_name
        ext.extend_from_slice(&((2 + entry_len) as u16).to_be_bytes()); // ext length
        ext.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list length
        ext.push(NAME_TYPE_HOST);
        ext.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(bytes);
        hello_with_extensions(&ext)
    }

    #[test]
    fn the_name_is_read_out_of_the_hello() {
        assert_eq!(
            extract_sni(&hello("example.com")).as_deref(),
            Some("example.com")
        );
    }

    /// The difference the two parsers used to have: a name that is not a name
    /// is refused, rather than being read and written to the log.
    #[test]
    fn a_name_with_a_control_character_is_refused() {
        assert_eq!(extract_sni(&hello("evil\r\nInjected: yes")), None);
    }

    /// The other difference: the `server_name` list may hold an entry of
    /// another type first, and the host name is still behind it.
    #[test]
    fn the_host_name_is_found_behind_another_entry_type() {
        // Two entries: one of a type this proxy does not read, and the host
        // name behind it. The list length covers the entries themselves.
        let entries = 6 + 9;
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&((2 + entries) as u16).to_be_bytes()); // ext length
        ext.extend_from_slice(&(entries as u16).to_be_bytes()); // list length
        ext.push(0x01); // a name type this proxy does not read
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.extend_from_slice(b"abc");
        ext.push(NAME_TYPE_HOST);
        ext.extend_from_slice(&6u16.to_be_bytes()); // "a.test" is six bytes
        ext.extend_from_slice(b"a.test");
        assert_eq!(
            extract_sni(&hello_with_extensions(&ext)).as_deref(),
            Some("a.test")
        );
    }

    #[test]
    fn a_name_that_is_too_long_is_refused() {
        let long = "a".repeat(MAX_HOST_NAME_LEN + 1);
        assert_eq!(extract_sni(&hello(&long)), None);
        let at_limit = "a".repeat(MAX_HOST_NAME_LEN);
        assert_eq!(
            extract_sni(&hello(&at_limit)).as_deref(),
            Some(at_limit.as_str())
        );
    }

    #[test]
    fn something_that_is_not_a_hello_is_refused() {
        assert_eq!(extract_sni(&[]), None);
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    /// **The record's own length is the boundary of the answer.**
    ///
    /// The bytes after the record are not part of the `ClientHello`. A peer
    /// that puts a name there — a record whose own length understates the
    /// message inside it is enough — must not have that name read as the route
    /// key.
    ///
    /// This is not a corner case for its own sake: the two ends of the tunnel
    /// hand this reader **different amounts of the same bytes** — the client
    /// has whatever its read pulled in, the server has what arrived on the
    /// tunnel — and an answer that depended on what followed the record would
    /// be an answer the two ends could disagree about, which is the whole
    /// failure the shared reader was written to remove.
    #[test]
    fn a_name_past_the_record_is_not_read() {
        let mut hello = hello("example.com");
        // The record claims to be ten bytes long, which is far short of the
        // message inside it — so the name that follows is not the name of
        // this `ClientHello`.
        hello[3] = 0x00;
        hello[4] = 0x0a;
        assert_eq!(
            extract_sni(&hello),
            None,
            "the name was read from past the end of the record"
        );
    }

    /// The same hello, read out of a buffer that carries more than the record,
    /// gives the same answer — because the answer is about the record.
    #[test]
    fn what_follows_the_record_does_not_change_the_answer() {
        let hello = hello("example.com");
        let mut with_more = hello.clone();
        // A second record, the way a client that has sent its `ClientHello`
        // and moved on would have it.
        with_more.extend_from_slice(b"\x16\x03\x03\x00\x02\xff\xff");
        assert_eq!(extract_sni(&hello), extract_sni(&with_more));
    }
}

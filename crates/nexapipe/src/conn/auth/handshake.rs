//! The handshake: what a client says, and what it proves.

use crate::auth::{AuthMessage, ClientAcl, is_presentable_client_id, is_presentable_device_id};

use nexapipe_proto::auth::Format;
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

use iroh::endpoint::Connection;

use super::authenticator::{AuthContext, AuthRequest};
use super::enrollment::{AuthFailure, AuthenticatedPeer, PeerRegistration, enroll_client};
use super::state::AuthState;

/// How long the server holds a connection open after refusing it, so the
/// AUTH_FAILED it just wrote can reach the client.
///
/// `Rejected` closes the connection the moment this returns, and that close
/// races the bytes carrying the verdict: when the close wins, the client sees
/// "connection lost" instead of "Invalid TOTP code", and cannot tell a wrong
/// client_id from a server that went away. Waiting for the peer — which closes
/// the connection itself once it has read the refusal — removes that guesswork.
///
/// It is deliberately small: this wait happens inside
/// [`AUTH_HANDSHAKE_TIMEOUT`], which still has to cover the three earlier round
/// trips on a slow link.
const AUTH_RESULT_GRACE: tokio::time::Duration = tokio::time::Duration::from_millis(500);

/// The largest AUTH_* message the server accepts.
///
/// The length prefix is the first four bytes of whatever stream arrives first,
/// so it is attacker- and bug-controlled: a client that opens a data stream
/// instead of the auth stream would otherwise make the server allocate up to
/// 4 GiB before reading anything.
const MAX_AUTH_MESSAGE: usize = 64 * 1024;

/// Writes one length-prefixed AUTH_* message.
pub(super) async fn write_auth_message(
    send: &mut iroh::endpoint::SendStream,
    message: &AuthMessage,
    format: Format,
) -> Result<(), String> {
    let bytes = message
        .to_payload(format)
        .map_err(|e| format!("failed to serialize {}: {}", message_kind(message), e))?;
    let len = bytes.len() as u32;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| format!("failed to send {}: {}", message_kind(message), e))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| format!("failed to send {}: {}", message_kind(message), e))
}

/// The form the answer to a message is in.
///
/// The client that asked is answered in the form it asked in — and, when it
/// announced a version, in that version. Nothing is negotiated and nothing is
/// remembered: the message says what it is, and the answer says the same.
///
/// A version this build does not know is answered in the form the client
/// asked in, which is a form the client can read by definition.
fn reply_format(message: &AuthMessage, asked_in: Format) -> Format {
    message
        .announced_version()
        .and_then(Format::from_version)
        .unwrap_or(asked_in)
}

/// The wire name of a message, for errors that name what was being sent.
fn message_kind(message: &AuthMessage) -> &'static str {
    match message {
        AuthMessage::Start { .. } => "AUTH_START",
        AuthMessage::Challenge { .. } => "AUTH_CHALLENGE",
        AuthMessage::Response { .. } => "AUTH_RESPONSE",
        AuthMessage::Ok => "AUTH_OK",
        AuthMessage::Failed { .. } => "AUTH_FAILED",
        AuthMessage::EnrollStart { .. } => "ENROLL_START",
        AuthMessage::EnrollIssue { .. } => "ENROLL_ISSUE",
        AuthMessage::EnrollFailed { .. } => "ENROLL_FAILED",
    }
}

/// Perform 2FA authentication handshake with a client.
///
/// Protocol:
/// 1. Receive AUTH_START from client
/// 2. Send AUTH_CHALLENGE with nonce
/// 3. Receive AUTH_RESPONSE with TOTP code and an HMAC over the nonce
/// 4. Validate and send AUTH_OK or AUTH_FAILED
///
/// Returns the client id together with its host authorization
/// ([`ClientAcl`]), snapshotted under the same lock that verified the
/// credentials — a reload landing between the two could otherwise turn a
/// client whose entry was just removed into an unrestricted one.
///
/// `registration` is spent the same way: a connection that passes is put in
/// the peer registry before the lock is released, so that the reload which
/// closes revoked credentials and this handshake cannot be interleaved. See
/// [`PeerRegistration`] for the window that moving it out would open.
///
/// The caller bounds this with a deadline, so every read in here has to be
/// cancel-safe: [`read_auth_message`] loops over `RecvStream::read` instead of
/// using `read_exact`.
pub(in crate::conn) async fn perform_authentication(
    conn: &Connection,
    auth: &AuthState,
    peer: &str,
    registration: PeerRegistration,
) -> Result<AuthenticatedPeer, AuthFailure> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| AuthFailure::NotStarted(format!("failed to open auth stream: {}", e)))?;

    // Step 1: Receive AUTH_START. A client that is not doing 2FA opens its
    // first data stream here instead, which does not parse as AUTH_START — that
    // is a refusal, not a parse error worth distinguishing in the log.
    let start_bytes = read_auth_message(&mut recv)
        .await
        .map_err(AuthFailure::NotStarted)?;

    // The payload's first byte says which form it is in, and the answers go
    // back in the form the client asked in.
    let (start_msg, start_format) = AuthMessage::from_payload(&start_bytes[..]).map_err(|_| {
        AuthFailure::NotStarted("the first stream is not an AUTH_START".to_string())
    })?;
    let mut format = reply_format(&start_msg, start_format);

    // Checked before the id is used for anything, because the first thing it is
    // used for is being printed: the log line for a refusal, a lockout or an
    // unknown client all carry it, and a peer that names itself with a trailing
    // CRLF writes the rest of that line itself. This is before any secret has
    // been checked, so it is reachable by anyone who can open a stream.
    if let AuthMessage::Start { client_id, .. } | AuthMessage::EnrollStart { client_id, .. } =
        &start_msg
        && !is_presentable_client_id(client_id)
    {
        return Err(AuthFailure::Rejected(
            "client id is not printable ASCII".to_string(),
        ));
    }

    // The same test on the name a device asks to be enrolled under, and refused
    // rather than read as "no name": it becomes a key in the config and the
    // subject of the log line for everything that happens to it, so a name that
    // cannot be printed is one nobody can revoke by hand either. Not counted
    // against the client — a malformed request is not a guess at the token.
    if let AuthMessage::EnrollStart {
        device_id: Some(device_id),
        ..
    } = &start_msg
        && !is_presentable_device_id(device_id)
    {
        return Err(AuthFailure::Rejected(
            "device id is not printable ASCII".to_string(),
        ));
    }

    // Enrollment, when the client asked for it: the token is exchanged for a
    // freshly generated secret ahead of the ordinary handshake, on the same
    // stream — the two messages are read in order here, so a client that
    // enrolled cannot have its AUTH_START mistaken for a data stream.
    let client_id = match start_msg {
        AuthMessage::Start { client_id, .. } => client_id,
        AuthMessage::EnrollStart {
            client_id,
            token,
            device_id,
            public_key,
        } => {
            enroll_client(
                auth,
                &client_id,
                token.expose_secret(),
                device_id.as_deref(),
                public_key.as_deref(),
                format,
                &mut send,
            )
            .await?;

            let start_after_enroll = read_auth_message(&mut recv)
                .await
                .map_err(AuthFailure::NotStarted)?;
            let (start_after_enroll_msg, asked_in) =
                AuthMessage::from_payload(&start_after_enroll[..]).map_err(|_| {
                    AuthFailure::NotStarted("expected AUTH_START after ENROLL_START".to_string())
                })?;
            // The client may announce its version here, so this message is
            // what settles the form of the answers.
            let answer_format = reply_format(&start_after_enroll_msg, asked_in);
            match start_after_enroll_msg {
                AuthMessage::Start { client_id: id, .. } if id == client_id => {
                    format = answer_format;
                    client_id
                }
                AuthMessage::Start { client_id: id, .. } => {
                    return Err(AuthFailure::Rejected(format!(
                        "AUTH_START names client '{id}' but the enrollment was for '{client_id}'"
                    )));
                }
                _ => {
                    return Err(AuthFailure::NotStarted(
                        "expected AUTH_START after ENROLL_START".to_string(),
                    ));
                }
            }
        }
        _ => {
            return Err(AuthFailure::NotStarted(
                "expected AUTH_START message".to_string(),
            ));
        }
    };

    // Step 2: Send AUTH_CHALLENGE
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let challenge_msg = AuthMessage::Challenge {
        nonce: nonce.clone(),
    };

    write_auth_message(&mut send, &challenge_msg, format)
        .await
        .map_err(AuthFailure::NotStarted)?;

    // Step 3: Receive AUTH_RESPONSE
    let response_bytes = read_auth_message(&mut recv)
        .await
        .map_err(AuthFailure::NotStarted)?;

    let (response_msg, response_format) = AuthMessage::from_payload(&response_bytes[..])
        .map_err(|_| AuthFailure::NotStarted("expected AUTH_RESPONSE message".to_string()))?;

    let (resp_client_id, resp_device_id, resp_timestamp, signature, totp_code) = match response_msg
    {
        AuthMessage::Response {
            client_id,
            device_id,
            timestamp,
            totp_code,
            signature,
        } => (client_id, device_id, timestamp, signature, totp_code),
        _ => {
            return Err(AuthFailure::NotStarted(
                "expected AUTH_RESPONSE message".to_string(),
            ));
        }
    };

    if resp_client_id != client_id {
        return Err(AuthFailure::Rejected(
            "client ID mismatch in AUTH_RESPONSE".to_string(),
        ));
    }

    // Checked before the name is used for anything, for the reason a client id
    // is: it ends up in the log line for the outcome, and a peer that names
    // itself with a trailing CRLF writes the rest of that line itself. `None`
    // is not a failure to name one — it is the unnamed device, which is what a
    // client with no device table has always been.
    if let Some(name) = resp_device_id.as_deref()
        && !is_presentable_device_id(name)
    {
        return Err(AuthFailure::Rejected(
            "device id is not printable ASCII".to_string(),
        ));
    }

    // Step 4: Verify the response and account for the result.
    //
    // The signature binds the response to this connection's challenge and the
    // timestamp keeps it fresh; only then does the TOTP code decide.
    //
    // The whole attempt belongs to the authenticator — the verification, the
    // counters it moves and the peer registration — because those three have
    // to happen in one critical section, and splitting them reopens races this
    // code spent a long time closing. See `authenticator` for the contract.
    let request = AuthRequest {
        client_id: &client_id,
        device_id: resp_device_id.as_deref(),
        nonce: &nonce,
        timestamp: resp_timestamp,
        signature: &signature,
        code: &totp_code,
    };
    let context = AuthContext {
        state: auth,
        peer,
        register: &|identity| registration.register(identity),
    };
    let outcome = auth.authenticator().authenticate(request, context).await;

    // The reason the attempt was refused goes to the log, inside the
    // authenticator that refused it: that is where the knowledge of *why* is.
    // What the client is told is one fixed string for every refusal, so that
    // the reply is not an oracle.
    let (is_valid, verified_acl, registered) = match outcome {
        Ok(outcome) => (true, outcome.acl, outcome.registered),
        Err(_) => (false, ClientAcl::unrestricted(), None),
    };

    // One fixed string for every refusal, logged apart but sent identically: see
    // the note above the match.
    let fail_reason = "Invalid TOTP code";
    let result_msg = if is_valid {
        AuthMessage::Ok
    } else {
        AuthMessage::Failed {
            reason: fail_reason.to_string(),
        }
    };

    write_auth_message(&mut send, &result_msg, response_format)
        .await
        .map_err(AuthFailure::NotStarted)?;
    send.finish()
        .map_err(|e| AuthFailure::NotStarted(format!("failed to finish auth stream: {}", e)))?;

    // Let a refused client read its verdict before the caller pulls the
    // connection out from under it. A client that has read AUTH_FAILED closes
    // the connection itself, which ends this wait immediately; one that has
    // vanished simply costs the grace period. Whatever the peer sends is
    // discarded — it has already been refused, nothing further is read for
    // meaning.
    if !is_valid {
        let mut buf = [0u8; 256];
        let drain = async {
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) | Ok(None) => break,
                    Ok(Some(_)) => continue,
                    Err(_) => break,
                }
            }
        };
        let _ = tokio::time::timeout(AUTH_RESULT_GRACE, drain).await;
    }

    match registered {
        Some((guard, revoked)) => Ok(AuthenticatedPeer {
            client_id,
            device: resp_device_id,
            acl: verified_acl,
            guard,
            revoked,
        }),
        None => Err(AuthFailure::Rejected(format!(
            "authentication failed for client '{client_id}': {fail_reason}"
        ))),
    }
}

/// Reads one length-prefixed AUTH_* message from the handshake stream.
///
/// The length prefix is whatever the peer sent first, so it is only trusted
/// after the range check: a data stream offered to a 2FA server starts with
/// bytes that would otherwise ask for a gigabyte-sized buffer.
///
/// Generic on purpose: `tokio::io::duplex` gives a test both ends of the
/// framing in one process, so what a peer sends can be read without an iroh
/// endpoint behind it — the same reason the L4 tunnel is written this way.
async fn read_auth_message<R>(recv: &mut R) -> Result<Zeroizing<Vec<u8>>, String>
where
    R: AsyncRead + Unpin,
{
    let len_buf = read_bytes(recv, 4).await?;
    let msg_len = u32::from_le_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;

    if msg_len == 0 || msg_len > MAX_AUTH_MESSAGE {
        return Err(format!("auth message length {} is out of range", msg_len));
    }

    read_bytes(recv, msg_len).await
}

/// Reads exactly `len` bytes, one cancel-safe `read` at a time.
///
/// `read` is cancel-safe and `read_exact` is not, and the handshake runs
/// under a deadline that may drop this future mid-message.
///
/// **The buffer wipes itself when it goes out of scope.** Two of the messages
/// this reads carry a credential — the enrollment token, and the signature
/// that answers a challenge — and the bytes of them are in the buffer until
/// it is dropped. A plain `Vec<u8>` would leave those bytes in the heap for
/// the allocator to hand out again, which is where a core dump, a swap file
/// or a read of `/proc/<pid>/mem` finds them: the credential outlives the
/// handshake that needed it.
///
/// Every message read here is wiped, not only the ones that carry a
/// credential: the buffer is the same buffer either way, and a rule that says
/// "wipe this one, not that one" is a rule somebody has to remember.
async fn read_bytes<R>(recv: &mut R, len: usize) -> Result<Zeroizing<Vec<u8>>, String>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Zeroizing::new(vec![0u8; len]);
    let mut filled = 0usize;
    while filled < len {
        match recv.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(format!("failed to read auth message: {}", e)),
        }
    }
    if filled < len {
        return Err(format!(
            "client closed the auth stream after {} of {} bytes",
            filled, len
        ));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexapipe_proto::secret::SecretString;
    use tokio::io::AsyncWriteExt;

    /// The heap, watched.
    ///
    /// The defect this fixes is a credential that survives in the heap after
    /// the message that carried it is gone, and the only way to *show* that it
    /// does not survive is to look at the memory after it is freed. The
    /// allocator is where that memory comes back from, so the allocator is
    /// where the proof is: a block on its way out that still holds the
    /// credential is a block the credential survived in.
    mod heap {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::sync::atomic::{AtomicBool, Ordering};

        /// The bytes the probe is watching for.
        ///
        /// A string no other test uses, so a block that holds it is one this
        /// test made.
        pub const NEEDLE: &str = "nexapipe-heap-probe-4b8e2a";

        /// Whether the probe is watching.
        static WATCHING: AtomicBool = AtomicBool::new(false);

        /// Whether the needle was seen in a block on its way out.
        static FOUND: AtomicBool = AtomicBool::new(false);

        /// The allocator that watches.
        struct Probe;

        unsafe impl GlobalAlloc for Probe {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                unsafe { System.alloc(layout) }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                scan(ptr, layout.size());
                unsafe { System.dealloc(ptr, layout) }
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                unsafe { System.alloc_zeroed(layout) }
            }

            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                scan(ptr, layout.size());
                unsafe { System.realloc(ptr, layout, new_size) }
            }
        }

        #[global_allocator]
        static PROBE: Probe = Probe;

        /// Looks for the needle in a block that is about to be freed.
        fn scan(ptr: *mut u8, len: usize) {
            if !WATCHING.load(Ordering::Relaxed) || len < NEEDLE.len() {
                return;
            }
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
            if bytes
                .windows(NEEDLE.len())
                .any(|window| window == NEEDLE.as_bytes())
            {
                FOUND.store(true, Ordering::SeqCst);
            }
        }

        /// Runs `body` with the heap watched, and says whether the needle was
        /// left behind in it.
        pub fn left_behind<R>(body: impl FnOnce() -> R) -> bool {
            WATCHING.store(true, Ordering::SeqCst);
            FOUND.store(false, Ordering::SeqCst);
            body();
            WATCHING.store(false, Ordering::SeqCst);
            FOUND.load(Ordering::SeqCst)
        }
    }

    /// The enrollment token a client offers does not survive in the heap.
    ///
    /// The token is the credential an enrollment is made with: it stands for
    /// the secret the client is about to be issued, and it is spent the
    /// moment it is exchanged. It arrives in a buffer, and the buffer used to
    /// be a plain `Vec<u8>`: the bytes of the token were in it until it was
    /// dropped, and dropping it left them in the heap for the allocator to
    /// hand out again. A core dump, a swap file or a read of
    /// `/proc/<pid>/mem` finds them there long after the handshake that
    /// needed them.
    ///
    /// This is the proof that they do not survive: the heap is watched while
    /// the buffer the message was read into is dropped, and a block on its
    /// way out that still holds the token fails the test.
    ///
    /// The token travels over a `tokio::io::duplex` pipe rather than a real
    /// connection on purpose: a QUIC connection would carry the token through
    /// the transport's own buffers, and those would be found by the probe for
    /// reasons that have nothing to do with this code.
    #[tokio::test]
    async fn a_received_credential_does_not_survive_in_the_heap() {
        let needle = heap::NEEDLE;
        let start = AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new(needle.to_string()),
            device_id: None,
            public_key: None,
        };
        let payload = start
            .to_payload(Format::Binary)
            .expect("the message serializes");

        // The client writes the message, and the server reads it.
        let (mut peer, mut reader) = tokio::io::duplex(4096);
        peer.write_all(&(payload.len() as u32).to_le_bytes())
            .await
            .expect("the length is written");
        peer.write_all(&payload)
            .await
            .expect("the message is written");

        let bytes = read_auth_message(&mut reader)
            .await
            .expect("the message is read");

        // The parsed message holds a copy of its own: the token is a
        // `SecretString` built out of the bytes, so the copy in the buffer is
        // the redundant one — which is the one that has to be wiped.
        let (parsed, _) = AuthMessage::from_payload(&bytes[..]).expect("the message parses");
        match &parsed {
            AuthMessage::EnrollStart { token, .. } => assert_eq!(
                token.expose_secret(),
                needle,
                "the parsed message holds the credential"
            ),
            other => panic!("expected ENROLL_START, got {other:?}"),
        }

        // The buffer the credential was read into goes out of scope with the
        // heap watched.
        assert!(
            !heap::left_behind(|| drop(bytes)),
            "the credential survived in the heap"
        );

        // And the probe is not vacuous: a buffer that is *not* wiped leaves the
        // credential behind, and the probe sees it.
        assert!(
            heap::left_behind(|| {
                let mut plain = vec![0u8; needle.len()];
                plain.copy_from_slice(needle.as_bytes());
                std::hint::black_box(&plain);
                drop(plain);
            }),
            "the probe does not see a credential that was not wiped"
        );

        // The copies that are meant to outlive the watched window: the parsed
        // message, and the pipe that carried the bytes.
        drop(parsed);
        drop(peer);
        drop(reader);
    }
}

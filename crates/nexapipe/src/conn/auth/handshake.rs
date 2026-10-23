//! The handshake: what a client says, and what it proves.

use crate::auth::{
    AuthError, AuthMessage, ClientAcl, StepVerdict, TotpValidator, Verified,
    is_presentable_client_id, is_presentable_device_id,
};
use crate::conn::peers::PeerIdentity;

use nexapipe_proto::auth::Format;

use iroh::endpoint::Connection;

use super::enrollment::{AuthFailure, AuthenticatedPeer, PeerRegistration, enroll_client};
use super::state::{AuthState, persist_auth_state};

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
    let (start_msg, start_format) = AuthMessage::from_payload(&start_bytes).map_err(|_| {
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
            let (start_after_enroll_msg, asked_in) = AuthMessage::from_payload(&start_after_enroll)
                .map_err(|_| {
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

    let (response_msg, response_format) = AuthMessage::from_payload(&response_bytes)
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

    // Step 4: Verify the response and account for the result under one write
    // lock. The signature binds the response to this connection's challenge and
    // the timestamp keeps it fresh; only then does the TOTP code decide.
    //
    // Verify and record have to share the lock. Split across a read and a write
    // lock, two connections from the same client could both read "not locked
    // out" before either had recorded anything, and the counters would under-
    // count. The lock is held across an HMAC and a TOTP check, both of which
    // are microseconds, so serialising handshakes costs nothing a client can
    // notice.
    let mut cfg = auth.config().write().await;

    // Drop a lockout that has run out before deciding anything, so an expired
    // one does not read as live and its stale counter does not push the client
    // straight back over the threshold.
    if let Some(client) = cfg.clients.get_mut(&client_id) {
        client.refresh_lockout();
    }

    let outcome = TotpValidator::new(&cfg).verify_response(
        &client_id,
        resp_device_id.as_deref(),
        &nonce,
        resp_timestamp,
        &signature,
        &totp_code,
    );

    // Only a wrong TOTP code counts toward the lockout: a skewed clock or a
    // mismatched signature is a refusal, not a failed attempt, and counting
    // those would let whoever replays a captured response lock its rightful
    // owner out.
    //
    // Every branch below ends up sending one AUTH_FAILED whose reason is a
    // single fixed string. A distinct message for "locked out" or "no such
    // client" would make the reason an oracle: anyone could walk a client's
    // counter up to the lockout and, from the change in the reply, learn that
    // the id they guessed exists. The real reason goes to the log instead.
    let mut verified_acl = ClientAcl::unrestricted();
    // Whether the counters changed and the state file has to be written. The
    // write itself happens after the lock is released.
    let mut state_dirty = false;
    let is_valid = match outcome {
        Ok(Verified::Accepted { step }) => {
            // **The step check**, under the same lock that verified the code.
            //
            // A code is inside the acceptance window for the whole of its
            // step, so "this code is current" and "this code has already been
            // used" are different questions, and only the step tells them
            // apart. RFC 6238 §5.2 asks the verifier to refuse the second
            // use of a step it has already accepted.
            //
            // The check and the record are one operation: a caller that
            // checked and then recorded could let two connections through
            // between the two, and the whole point is that the second one does
            // not get in.
            let step_verdict = match step {
                Some(step) => cfg.accept_step(&client_id, resp_device_id.as_deref(), step),
                // No code, so no step: a key device's signature covers the
                // challenge issued for this connection, and there is nothing
                // for a second use to replay.
                None => StepVerdict::Accepted { moved: false },
            };
            let (step_moved, step_refused) = match step_verdict {
                StepVerdict::Refused => (false, true),
                StepVerdict::Accepted { moved } => (moved, false),
            };
            if step_refused {
                // **Not counted.** A code that has already been used is not a
                // guess at the credential, and counting it would let whoever
                // holds one code lock the device's owner out — over a
                // credential the owner did nothing wrong.
                tracing::warn!(
                    "2FA: client '{}' from {} sent a code that has already been used; refused \
                     without counting it as an attempt",
                    client_id,
                    peer
                );
                false
            } else {
                // Which device this was, if it named one, recorded under the same
                // lock that verified it. This is the stamp `client list` reads to
                // say whether a device is still in use: without it every named
                // device reports "never used" forever, and the one question the
                // device table exists to answer — which of these can be revoked
                // without disconnecting a live one — has nothing to go on.
                let device_stamp_moved = match resp_device_id.as_deref() {
                    Some(name) => cfg
                        .clients
                        .get_mut(&client_id)
                        .is_some_and(|client| client.record_device_success(name)),
                    None => false,
                };
                // Clear the counters only when there is something to clear, so a
                // healthy client does not turn every connection into a disk write.
                // A named device that moved its stamp is worth one: `unix_now` is
                // whole seconds, so a device reconnecting inside the same second
                // is not.
                // The step's memory is worth a write too: it is the thing that
                // refuses the second use of a code, and a server that forgot it
                // over a restart would accept one.
                let dirty = step_moved
                    || device_stamp_moved
                    || cfg
                        .clients
                        .get(&client_id)
                        .is_some_and(|c| c.failed_attempts != 0 || c.locked_until.is_some());
                if dirty {
                    if let Some(client) = cfg.clients.get_mut(&client_id) {
                        client.record_success();
                    }
                    // The write happens after the lock is released; see
                    // `persist_auth_state`.
                    state_dirty = true;
                }
                // Snapshot the host authorization while the same lock that verified
                // the credentials still holds: the entry cannot vanish between the
                // two reads, and a connection keeps the ACL it authenticated with
                // even if a reload changes it right after.
                if let Some(client) = cfg.clients.get(&client_id) {
                    verified_acl = client.acl();
                }
                true
            }
        }
        Ok(Verified::WrongCode) => {
            let max_attempts = cfg.max_attempts;
            let lockout_duration = cfg.lockout_duration;
            if let Some(client) = cfg.clients.get_mut(&client_id) {
                client.record_failure(max_attempts, lockout_duration);
            }
            // The write happens after the lock is released; see
            // `persist_auth_state`.
            state_dirty = true;
            false
        }
        Err(e) => {
            match &e {
                AuthError::ClientNotFound => {
                    tracing::warn!("2FA: unknown client '{}' from {}", client_id, peer);
                }
                AuthError::UnknownDevice => {
                    // Printable ASCII, because the name was checked before it
                    // was used for anything — and it is the one thing about
                    // this refusal an operator can act on.
                    tracing::warn!(
                        "2FA: client '{}' from {} names device {:?}, which has no credential: \
                         either it never enrolled or its entry was dropped",
                        client_id,
                        peer,
                        resp_device_id.as_deref()
                    );
                }
                AuthError::InvalidSecret | AuthError::TotpCreationFailed => {
                    tracing::error!(
                        "2FA: client '{}' cannot be validated, the server's auth config is broken: {}",
                        client_id,
                        e
                    );
                }
                AuthError::LockedOut => {
                    tracing::warn!("2FA: client '{}' from {} is locked out", client_id, peer);
                }
                AuthError::WrongSignature => {
                    // Not counted, and worth saying why: a key cannot be
                    // guessed, so there is nothing for the counter to protect
                    // on this path — counting it would only let a peer that
                    // knows the client id and the device name deny the
                    // device's owner service.
                    tracing::warn!(
                        "2FA: response from {} for '{}' carries a signature that does not match \
                         the challenge",
                        peer,
                        client_id
                    );
                }
                AuthError::MalformedSignature => {
                    // Not counted, and worth saying why: the peer sent noise
                    // rather than a wrong credential, so this is not an
                    // attempt at the device.
                    tracing::warn!(
                        "2FA: response from {} for '{}' carries a signature that is not a \
                         signature",
                        peer,
                        client_id
                    );
                }
                AuthError::UnnamedDeviceNotAllowed => {
                    // The one refusal that is a configuration the operator can
                    // change, so it is the one that says which knob.
                    tracing::warn!(
                        "2FA: client '{}' from {} names no device, and this client answers only \
                         to named ones: set unnamed_device_allowed = true under \
                         [auth.clients.{}] to let it use the client's own secret",
                        client_id,
                        peer,
                        client_id
                    );
                }
                _ => {
                    tracing::warn!(
                        "2FA: response from {} for '{}' rejected: {}",
                        peer,
                        client_id,
                        e
                    );
                }
            }
            false
        }
    };
    // Registered here, while the write lock is still held, for the reason given
    // on `PeerRegistration`: a reload takes this same lock and closes the
    // connections whose credential it just dropped, so the entry has to be in
    // the registry before the lock is released or that pass misses it. Nothing
    // is registered on a refusal — a peer that was turned away was never
    // connected, and listing it would answer "who is connected" with peers
    // that were not.
    let registered = is_valid.then(|| {
        registration.register(PeerIdentity {
            client_id: Some(client_id.clone()),
            device: resp_device_id.clone(),
        })
    });

    drop(cfg);

    // The state file is written with the auth lock released. The counters it
    // carries are read at write time, so they are the ones as of now.
    if state_dirty && let Err(e) = persist_auth_state(auth).await {
        tracing::warn!(
            "2FA: failed to persist the auth counters for '{}' to {}: {}",
            client_id,
            auth.state_path(),
            e
        );
    }

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
async fn read_auth_message(recv: &mut iroh::endpoint::RecvStream) -> Result<Vec<u8>, String> {
    let len_buf = read_bytes(recv, 4).await?;
    let msg_len = u32::from_le_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;

    if msg_len == 0 || msg_len > MAX_AUTH_MESSAGE {
        return Err(format!("auth message length {} is out of range", msg_len));
    }

    read_bytes(recv, msg_len).await
}

/// Reads exactly `len` bytes, one cancel-safe `read` at a time.
///
/// `RecvStream::read` is cancel-safe and `read_exact` is not, and the handshake
/// runs under a deadline that may drop this future mid-message.
async fn read_bytes(recv: &mut iroh::endpoint::RecvStream, len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        match recv.read(&mut buf[filled..]).await {
            Ok(Some(0)) => break,
            Ok(Some(n)) => filled += n,
            Ok(None) => break,
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

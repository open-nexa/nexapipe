//! The enrollment: a client that asks for a credential, and what it gets.

use crate::auth::{AuthConfig, AuthMessage, ClientAcl, DeviceAuth};
use crate::conn::peers::{PeerGuard, PeerIdentity, PeerRegistry};
use crate::metrics;

use nexapipe_proto::auth::Format;
use nexapipe_proto::secret::SecretString;

use std::sync::Arc;

use super::constant_time_eq;
use super::handshake::write_auth_message;
use super::state::{AuthState, persist_auth_state, storage_write};

/// Why a 2FA handshake did not produce an authenticated client.
///
/// The difference is what the server closes the connection with, and the client
/// can read it back: [`AuthFailure::NotStarted`] means the client does not know
/// 2FA is required — it never opened the auth stream, so the close is the only
/// way it can ever find out — while [`AuthFailure::Rejected`] means it did
/// authenticate and the credentials were refused.
pub(in crate::conn) enum AuthFailure {
    /// No AUTH_START arrived, or the handshake could not be carried out at all.
    NotStarted(String),
    /// The handshake ran and the credentials were refused.
    Rejected(String),
}

/// What one `ENROLL_START` is worth.
///
/// Split out of [`enroll_client`] so the rule can be tested without a
/// connection: acceptance is a question about the config and nothing else, and
/// it is the question the whole invitation scheme rests on.
#[derive(Debug, PartialEq)]
pub(in crate::conn) enum EnrollmentVerdict {
    /// The token matches, so the secret may be rotated.
    Accept,
    /// Refused. `counted` says whether this should move the client's lockout
    /// counter along.
    Refuse { counted: bool },
}

impl EnrollmentVerdict {
    pub(in crate::conn) fn counted(&self) -> bool {
        matches!(self, EnrollmentVerdict::Refuse { counted: true })
    }
}

/// Decides one enrollment attempt against `cfg`.
///
/// A guess at a token that is actually outstanding is the only thing counted.
/// It is an attempt to spend a credential — the thing a token has to withstand
/// to be worth handing out — and it is what makes the link unguessable rather
/// than merely unshared. Everything else is a guess at nothing: no such client,
/// or one with no token pending. Counting those would let anyone who knows a
/// client id lock that client out of its own authentication by sending it
/// enrollment requests, which is a denial of service handed to a stranger.
///
/// A lockout outranks the token: the client is refused before the comparison
/// runs, so a locked-out client cannot extend its own lockout by retrying, and
/// a wrong code cannot be traded for extra attempts by going through
/// enrollment.
///
/// **What a counted refusal moves is the enrollment's own counter.** A client
/// id is not a secret — it is in the invite link and in whatever the operator
/// pasted into a ticket — so anybody who knows one can send enrollment
/// attempts at a client that is waiting to enroll. Counting those against the
/// client's authentication counter meant the devices that had already enrolled
/// were locked out over a credential they were never sent. The token keeps its
/// ceiling, and the ceiling is paid for by the token.
///
/// A name that is already in the table is refused too. An enrollment token
/// proves the invite reached *someone*, not which device it reached — the name
/// is chosen by the client at enrollment time — so accepting any name turned a
/// copied link into a takeover: enrolling as the name of a device that is
/// already there replaces its credential, which locks the real device out while
/// every log line and the peer list go on showing the real device's name.
/// Rotating one device's credential is the operator's move and has its own
/// `--force`; an enrollment is for a device that is not there yet.
///
/// **With one exception: the device that still holds the key the table already
/// records.** That is the same device coming back for a credential it lost —
/// the answer it was given was never written down — and not somebody taking
/// the name over. The key is not proof of possession: the public half is
/// public, and anybody who has seen a device's key can name it. What makes it
/// safe is what the enrollment does with it. It records the same key under the
/// same name, so the device holding the private half keeps working and the one
/// that does not gains nothing; and a key enrollment writes the device row and
/// nothing else, so the client's own shared secret is not rotated and no other
/// device of it is locked out. A different key, or no key at all, is refused as
/// before.
pub(in crate::conn) fn enrollment_verdict(
    cfg: &AuthConfig,
    client_id: &str,
    token: &str,
    device: Option<&str>,
    public_key: Option<&str>,
) -> EnrollmentVerdict {
    let Some(client) = cfg.clients.get(client_id) else {
        return EnrollmentVerdict::Refuse { counted: false };
    };
    if client.is_locked_out() {
        return EnrollmentVerdict::Refuse { counted: false };
    }
    // The enrollment slot's own lockout, checked the same way. The window
    // belongs to the token: a guess at the token closes the slot for a while,
    // and it does not close the client's authentication — the devices that
    // already hold a credential are not what a stranger is guessing at.
    if client.is_enrollment_locked_out() {
        return EnrollmentVerdict::Refuse { counted: false };
    }
    // An empty token is refused on both sides before the comparison runs.
    // `constant_time_eq` answers true for two empty slices, so a config holding
    // `pending_enrollment = ""` — what an operator naturally writes to "clear"
    // the key — would accept any stranger's empty ENROLL_START and hand them a
    // freshly generated secret, locking out every device already using this
    // client id. The loader refuses that spelling too; this is the runtime half
    // of the same rule, so a reload path that skips validation cannot revive it.
    let Some(expected) = client
        .pending_enrollment
        .as_ref()
        .map(|expected| expected.expose_secret())
        .filter(|expected| !expected.is_empty())
    else {
        return EnrollmentVerdict::Refuse { counted: false };
    };

    if !constant_time_eq(expected.as_bytes(), token.as_bytes()) {
        return EnrollmentVerdict::Refuse { counted: true };
    }
    // Not counted: this is the right token in the wrong hands, not a guess at
    // one. Whoever is holding it is about to be told the same thing every other
    // refusal says.
    if let Some(name) = device
        && let Some(entry) = client.devices.get(name)
        && !holds_the_key_on_file(entry, public_key)
    {
        return EnrollmentVerdict::Refuse { counted: false };
    }
    EnrollmentVerdict::Accept
}

/// Whether the credential this enrollment offers is the one the device's row
/// already holds.
///
/// The comparison is on the canonical spelling — lowercase hex — because that
/// is what the table stores, and a key that arrives in another spelling is the
/// same key.
///
/// A row that holds a secret rather than a key never matches: a device that
/// proves itself with a code is not the device that offered a key, and a
/// keyless enrollment is not a device coming back.
fn holds_the_key_on_file(entry: &DeviceAuth, offered: Option<&str>) -> bool {
    let Some(offered) = offered else {
        return false;
    };
    let Some(stored) = entry.public_key.as_deref() else {
        return false;
    };
    let Ok(offered) = crate::auth::parse_public_key(offered) else {
        return false;
    };
    let offered = crate::auth::public_key_hex(&offered);
    constant_time_eq(stored.as_bytes(), offered.as_bytes())
}

/// What a successful handshake established.
///
/// Carried as both halves because a client id on its own cannot tell two
/// devices of the same client apart, and telling them apart is the only thing
/// a per-device credential is for: what the peer list, the access log and the
/// revocation that closes one device's connections all need to know is whose
/// connection this is, not merely whose client's.
pub(in crate::conn) struct AuthenticatedPeer {
    pub(in crate::conn) client_id: String,
    /// The device name the peer sent. `None` is the device that has none,
    /// which answered with the client's own secret.
    pub(in crate::conn) device: Option<String>,
    pub(in crate::conn) acl: ClientAcl,
    /// Keeps the registry entry alive; dropped when the connection ends, which
    /// is what takes it out of `GET /v1/connections`.
    pub(in crate::conn) guard: PeerGuard,
    /// Flipped by a reload that dropped the credential this connection
    /// authenticated with. Owned here rather than created by the caller
    /// because of when it has to be created — see [`PeerRegistration`].
    pub(in crate::conn) revoked: tokio::sync::watch::Receiver<bool>,
}

/// What a connection needs to put itself in the peer registry, handed to
/// [`perform_authentication`] so that the registration happens *inside* the
/// auth write lock.
///
/// Registering after the lock is dropped leaves a window that a reload fits
/// in. The reload takes the same lock and calls `close_where` over the
/// registry; a connection that is between "verified" and "registered" is not
/// in the registry yet, so it is not found, and it goes on to insert itself
/// with a fresh watch channel that nothing will ever flip. No later reload
/// reaches it either: `removed` and `removed_devices` are recomputed from the
/// diff each time and are never replayed, so a credential revoked in that
/// window keeps serving until the client hangs up on its own.
///
/// Doing both under the lock makes "verified" and "registered" one step that a
/// reload cannot land inside: either the reload's pass runs first and the
/// connection is closed before it is ever served, or the entry is already
/// there and has its channel flipped.
pub(in crate::conn) struct PeerRegistration {
    pub(in crate::conn) registry: Arc<PeerRegistry>,
    pub(in crate::conn) endpoint_id: iroh::EndpointId,
    pub(in crate::conn) path: metrics::PathKind,
}

impl PeerRegistration {
    /// Puts the connection in the registry and hands back what keeps it there
    /// and what tells it to stop.
    pub(super) fn register(
        &self,
        identity: PeerIdentity,
    ) -> (PeerGuard, tokio::sync::watch::Receiver<bool>) {
        let (revoked_tx, revoked_rx) = tokio::sync::watch::channel(false);
        let guard = self
            .registry
            .insert(self.endpoint_id, self.path, identity, revoked_tx);
        (guard, revoked_rx)
    }
}

/// Where an enrollment puts the credential it issues, and what undoing it has
/// to put back.
///
/// This is what makes an enrollment invite worth handing out: the link carries
/// a token, and the first client to present it gets a credential the link never
/// contained while the token is dropped in the same write. A link copied in
/// transit is therefore a credential only until it is used once, instead of
/// until somebody remembers to rotate it.
///
/// Two slots, because a client's own `secret` and its device table are not the
/// same credential and an enrollment names which of the two it is asking about:
/// a device that sends a name wants an entry of its own, and a device that
/// sends none is one that predates the table, for whom the client's `secret` is
/// the only credential there is.
pub(in crate::conn) enum EnrollmentSlot {
    /// A named device. The client's `secret` is left alone, so the other
    /// devices keep theirs — which is the whole point of the table.
    Device {
        name: String,
        /// The entry this enrollment replaced, if the device was enrolled
        /// before.
        ///
        /// `None` on the enrollment path, where a name that is already in the
        /// table is refused rather than overwritten — see
        /// [`enrollment_verdict`]. Rotating a device that exists is the
        /// operator's move, `client add --device <name> --force`. What this
        /// carries is what a failed write has to put back.
        previous: Option<DeviceAuth>,
    },
    /// The device that has no name: the client's own `secret`, which is also
    /// what every peer that predates the device table answers with.
    Shared {
        /// The secret this enrollment rotated away.
        previous: SecretString,
    },
}

/// The credential an enrollment is recording, owned: the write that persists
/// it is detached, so it cannot borrow anything from the handshake.
///
/// Three shapes, not two, because there are three places a credential can go: a
/// named device takes either a secret or a key, and the unnamed slot — the
/// client's own `secret`, which every device that names none answers with — is
/// a secret or nothing. That last fact is why a key offered without a device
/// name is refused as unrecordable rather than silently ignored.
#[derive(Clone)]
pub(in crate::conn) enum IssuedCredential {
    /// A named device with a secret of its own.
    DeviceSecret { name: String, secret: SecretString },
    /// A named device with a key: it signs each challenge, and `secret` is
    /// empty on the wire because there is no code for it to send.
    ///
    /// The key is the *public* half, so it is a plain string: there is nothing
    /// secret about it.
    DeviceKey { name: String, key: String },
    /// The client's own `secret`, rotated.
    SharedSecret(SecretString),
}

/// Writes the issued credential into the slot this enrollment named, in memory.
///
/// The caller persists it and, if that fails, hands what this returns to
/// [`undo_enrolled_secret`]: a credential that is live in memory but missing
/// from disk is one that silently reverts at the next restart, putting the old
/// one back in service.
pub(in crate::conn) fn issue_enrolled_secret(
    cfg: &mut AuthConfig,
    client_id: &str,
    issued: &IssuedCredential,
) -> EnrollmentSlot {
    let Some(client) = cfg.clients.get_mut(client_id) else {
        // Accepted tokens only exist on a client that is in the table, so this
        // is unreachable; a shared slot with nothing to restore keeps the
        // caller's rollback simple rather than making it handle a third case.
        return EnrollmentSlot::Shared {
            previous: SecretString::default(),
        };
    };

    let slot = match issued {
        IssuedCredential::DeviceSecret { name, secret } => EnrollmentSlot::Device {
            previous: client.devices.insert(
                name.clone(),
                DeviceAuth {
                    secret: secret.clone(),
                    public_key: None,
                    created_at: crate::auth::config::default_created_at(),
                    last_used: None,
                    last_used_step: None,
                },
            ),
            name: name.clone(),
        },
        IssuedCredential::DeviceKey { name, key } => EnrollmentSlot::Device {
            previous: client.devices.insert(
                name.clone(),
                DeviceAuth {
                    secret: SecretString::default(),
                    public_key: Some(key.clone()),
                    created_at: crate::auth::config::default_created_at(),
                    last_used: None,
                    last_used_step: None,
                },
            ),
            name: name.clone(),
        },
        IssuedCredential::SharedSecret(secret) => EnrollmentSlot::Shared {
            previous: std::mem::replace(&mut client.secret, secret.clone()),
        },
    };
    client.pending_enrollment = None;
    slot
}

/// Puts back what [`issue_enrolled_secret`] replaced, and the token with it.
///
/// The token goes back because the write that would have spent it failed: the
/// link is still the only credential the client has for this enrollment, and
/// dropping it would leave a client that cannot enroll at all.
pub(in crate::conn) fn undo_enrolled_secret(
    cfg: &mut AuthConfig,
    client_id: &str,
    slot: EnrollmentSlot,
    token: &str,
) {
    let Some(client) = cfg.clients.get_mut(client_id) else {
        return;
    };

    match slot {
        EnrollmentSlot::Device { name, previous } => match previous {
            Some(previous) => {
                client.devices.insert(name, previous);
            }
            None => {
                client.devices.remove(&name);
            }
        },
        EnrollmentSlot::Shared { previous } => client.secret = previous,
    }
    client.pending_enrollment = Some(SecretString::new(token.to_string()));
}

/// The counted refusal: what a wrong guess at a token moves.
///
/// **The enrollment's own counter, and not the client's.** A client id is not
/// a secret — it is in the invite link, in `nexapipe client list` and in
/// whatever the operator pasted into a ticket — so anybody who knows one can
/// send enrollment attempts at a client that is waiting to enroll. Counting
/// those against the client's authentication counter meant a stranger could
/// lock out the devices that had already enrolled, over a credential those
/// devices were never sent. The token keeps its ceiling; the ceiling is paid
/// for by the token.
///
/// Public because it is the rule, and a rule that only one caller can reach
/// is a rule nobody can state: the state file's round trip is checked against
/// this function, so the two cannot drift apart.
pub fn count_enrollment_failure(
    cfg: &mut AuthConfig,
    client_id: &str,
    max_attempts: u32,
    lockout_duration: u64,
) {
    if let Some(client) = cfg.clients.get_mut(client_id) {
        client.record_enrollment_failure(max_attempts, lockout_duration);
    }
}

/// What an operator has to do about a device that is already enrolled.
///
/// The command that unblocks the enrollment is the one that **removes** the
/// device's row. The refusal is about the name being taken, and
/// `client add --device --force` replaces the credential filed under that
/// name without giving the name back — so the next enrollment is refused the
/// same way. Naming `--force` first, which is what this hint used to do, sent
/// the operator down the one path that does not work.
///
/// The revoke is the operator's own move either way: a device that is already
/// enrolled keeps its credential until somebody says otherwise.
pub(in crate::conn) fn device_taken_hint(client_id: &str, device: &str) -> String {
    format!(
        "2FA: enrollment for '{client_id}' refused, device '{device}' already has a credential; \
         `nexapipe client revoke {client_id} --device {device}` removes it so that device can \
         enroll again — `nexapipe client add {client_id} --device {device} --force` replaces \
         the credential filed under that name but leaves the name taken, so the enrollment is \
         refused the same way"
    )
}

/// Issues a credential against an enrollment token: a freshly generated secret,
/// or the device key the client offered.
///
/// The secret is rotated rather than handed out as-is, so enrolling is also how
/// a client recovers from a secret that leaked — at the cost of every device
/// already using that client id, which has to scan again.
///
/// `device` is the name the client asked to be issued under. A name means the
/// credential goes into the device table and no other device's is touched;
/// no name is the case above, and the only one that existed before the table.
///
/// `public_key` is the key a device offered to be known by, for a device that
/// will answer with a signature instead of a code. It is only ever recorded for
/// a named device: the entry it goes into is the device's, and the unnamed slot
/// — the client's own shared `secret` — is a string with no key in it.
pub(super) async fn enroll_client(
    auth: &AuthState,
    client_id: &str,
    token: &str,
    device: Option<&str>,
    public_key: Option<&str>,
    format: Format,
    send: &mut iroh::endpoint::SendStream,
) -> Result<(), AuthFailure> {
    // One reply for every way this can fail, for the same reason AUTH_FAILED
    // has one: whether the token was unknown, already spent or never issued is
    // not information a stranger is owed.
    const REFUSED: &str = "the enrollment token was not accepted";

    let mut cfg = auth.config().write().await;

    // Drop a lockout that has run out before deciding anything, so an expired
    // one does not read as live and its stale counter does not push the client
    // straight back over the threshold.
    if let Some(client) = cfg.clients.get_mut(client_id) {
        client.refresh_lockout();
        client.refresh_enrollment_lockout();
    }

    let verdict = enrollment_verdict(&cfg, client_id, token, device, public_key);
    if !matches!(verdict, EnrollmentVerdict::Accept) {
        // The refusal sent on the wire is one string for every reason, so the
        // only place this one is legible is the log — and it is the one an
        // operator can act on, because it names the command that rotates the
        // device properly.
        if let Some(name) = device
            && cfg
                .clients
                .get(client_id)
                .is_some_and(|client| client.devices.contains_key(name))
        {
            tracing::warn!("{}", device_taken_hint(client_id, name));
        }
        // Whether the counters have moved and the state file has to be
        // written. The write itself happens after the lock is released.
        let mut state_dirty = false;
        if verdict.counted() {
            let (max_attempts, lockout_duration) = (cfg.max_attempts, cfg.lockout_duration);
            count_enrollment_failure(&mut cfg, client_id, max_attempts, lockout_duration);
            // The counters have moved; the file that carries them is written
            // below, with the lock released.
            state_dirty = true;
        }
        drop(cfg);

        // The state file is written with the auth lock released, the same way
        // the handshake writes it: a write lock held across a disk write
        // stalls every connection that is authenticating, not only this one.
        // The path is reachable by anyone who knows a client id, so the stall
        // is one a stranger can ask for.
        if state_dirty && let Err(e) = persist_auth_state(auth).await {
            tracing::warn!(
                "2FA: failed to persist the enrollment lockout for '{}' to {}: {}",
                client_id,
                auth.storage().describe_state(),
                e
            );
        }

        write_auth_message(
            send,
            &AuthMessage::EnrollFailed {
                reason: REFUSED.to_string(),
            },
            format,
        )
        .await
        .map_err(AuthFailure::NotStarted)?;
        return Err(AuthFailure::Rejected(format!(
            "enrollment refused for client '{client_id}': {REFUSED}"
        )));
    }

    // Read off the config before the client is borrowed again: the credential
    // issued here has to be generated with what the server will verify against.
    let (algorithm, digits, period) = (
        nexapipe_proto::auth::Algorithm::from(&cfg.algorithm),
        cfg.digits,
        cfg.time_step as u64,
    );

    // What this enrollment records. A key is not generated here — the client
    // holds the private half already, and the server only ever learns the
    // public one — so a key enrollment mints no secret at all.
    //
    // Both ways a request can be unrecordable are settled here, after the
    // verdict so a wrong token is still the thing that gets counted, and before
    // anything is issued so a request that cannot be recorded does not spend
    // the token it came with. Neither is a guess at anything, so the counter
    // does not move, and the reason is spelled out on the wire: unlike the
    // token refusals, one fixed string for every reason, which is about what
    // this server knows and does not say.
    let issued = match public_key {
        None => {
            // Minted as a `Secret`: the credential that is about to be issued
            // is the most valuable thing this process holds, and it is wiped
            // when the enrollment is over.
            let secret = SecretString::new(crate::auth::TotpValidator::generate_secret());
            match device {
                Some(name) => IssuedCredential::DeviceSecret {
                    name: name.to_string(),
                    secret,
                },
                None => IssuedCredential::SharedSecret(secret),
            }
        }
        Some(offered) => {
            let Some(name) = device else {
                return Err(refuse_unrecordable_enrollment(
                    send,
                    client_id,
                    "a public key has to be issued to a named device; the unnamed credential is \
                     the client's own shared secret",
                    format,
                )
                .await);
            };
            let key = match crate::auth::parse_public_key(offered) {
                // Stored in the canonical spelling — lowercase hex — whatever
                // case it arrived in, so the config reads the way every writer
                // of this file writes keys.
                Ok(key) => crate::auth::public_key_hex(&key),
                Err(why) => {
                    let reason = why.to_string();
                    return Err(
                        refuse_unrecordable_enrollment(send, client_id, &reason, format).await,
                    );
                }
            };
            IssuedCredential::DeviceKey {
                name: name.to_string(),
                key,
            }
        }
    };
    let slot = issue_enrolled_secret(&mut cfg, client_id, &issued);

    // Persisted before anything is promised to the client: a credential that is
    // live in memory but missing from disk is one that silently reverts on the
    // next restart, which would put the old one back in service.
    //
    // This write stays **under** the lock, unlike the state file's write
    // below. It carries the enrollment itself, and the epoch bump that follows
    // it is the interlock that stops a reload from merging a pre-enrollment
    // snapshot back over the top of it — see the note there.
    let storage = auth.storage().clone();
    let enrolled_client = client_id.to_string();
    let persisted = issued.clone();
    let write = async move {
        match &persisted {
            IssuedCredential::DeviceSecret { name, secret } => {
                storage
                    .complete_device_enrollment(
                        &enrolled_client,
                        name,
                        crate::storage::DeviceCredential::Secret(secret.clone()),
                    )
                    .await
            }
            IssuedCredential::DeviceKey { name, key } => {
                storage
                    .complete_device_enrollment(
                        &enrolled_client,
                        name,
                        crate::storage::DeviceCredential::PublicKey(key.clone()),
                    )
                    .await
            }
            IssuedCredential::SharedSecret(secret) => {
                storage.complete_enrollment(&enrolled_client, secret).await
            }
        }
    };
    if let Err(e) = storage_write("the enrollment".to_string(), write).await {
        // Roll the in-memory client back, or this process would keep accepting
        // a secret that no longer exists anywhere else.
        undo_enrolled_secret(&mut cfg, client_id, slot, token);
        drop(cfg);
        let reason = format!("enrollment could not be saved: {e}");
        write_auth_message(
            send,
            &AuthMessage::EnrollFailed {
                reason: reason.clone(),
            },
            format,
        )
        .await
        .map_err(AuthFailure::NotStarted)?;
        return Err(AuthFailure::Rejected(reason));
    }

    // The file carries the enrollment now, so this is the moment the watcher
    // has to be able to see it. Still under the lock the enrollment holds: a
    // reload samples the epoch before it reads the file and compares it here,
    // and a bump placed any earlier — before the write — could be sampled by a
    // reload that then read the pre-enrollment file and merged it back over
    // the top of this enrollment.
    auth.bump_enroll_epoch();

    // Presenting the token is proof the invite reached the right hands, so a
    // counter left over from failed guesses is cleared: a client that just
    // enrolled should not be one wrong code away from a lockout it did not
    // earn. The token's own counter is cleared with it — the token has been
    // spent, and the next invite replaces it rather than inheriting the
    // guesses made at this one. Only written when there is something to
    // clear, as above.
    let dirty = cfg.clients.get(client_id).is_some_and(|c| {
        c.failed_attempts != 0
            || c.locked_until.is_some()
            || c.enrollment_failed_attempts != 0
            || c.enrollment_locked_until.is_some()
    });
    if dirty && let Some(client) = cfg.clients.get_mut(client_id) {
        client.record_success();
        client.record_enrollment_success();
    }
    drop(cfg);

    // The state file is written with the auth lock released, the same way the
    // handshake writes it. The counters it carries are read at write time, so
    // they are the ones as of now.
    //
    // The **configuration** file's write is the one that stays under the lock,
    // and it has to: it carries the enrollment itself, and the epoch bump above
    // is the interlock that stops a reload from merging a pre-enrollment
    // snapshot back over the top of it. Moving that write out of the lock
    // would reopen the race the epoch exists to prevent.
    if dirty && let Err(e) = persist_auth_state(auth).await {
        tracing::warn!(
            "2FA: failed to persist the cleared counter for '{}' to {}: {}",
            client_id,
            auth.storage().describe_state(),
            e
        );
    }

    match &issued {
        IssuedCredential::DeviceKey { name, .. } => tracing::info!(
            "2FA: client '{client_id}' enrolled device '{name}' with a public key; it proves \
             itself by signing each challenge, with no TOTP code"
        ),
        IssuedCredential::DeviceSecret { name, .. } => tracing::info!(
            "2FA: client '{client_id}' enrolled device '{name}'; its own secret was left \
             alone, so the other devices keep theirs"
        ),
        IssuedCredential::SharedSecret(_) => tracing::info!(
            "2FA: client '{client_id}' enrolled; its secret was rotated, so every device \
             holding the old one has to scan again"
        ),
    }

    let (secret, device_id) = match &issued {
        IssuedCredential::DeviceSecret { name, secret } => (secret.clone(), Some(name.clone())),
        // An empty secret is how the client is told its key was recorded:
        // there is no seed for it to keep, and from here on every response it
        // sends is a signature.
        IssuedCredential::DeviceKey { name, .. } => (SecretString::default(), Some(name.clone())),
        IssuedCredential::SharedSecret(secret) => (secret.clone(), None),
    };

    write_auth_message(
        send,
        &AuthMessage::EnrollIssue {
            client_id: client_id.to_string(),
            secret,
            algorithm,
            digits,
            period,
            // The name this credential was issued under, which is the name the
            // client has to send back to be checked against it. None when the
            // device named none: it answered with the client's own secret, and
            // a client that predates the table reads that as "the shared one".
            device_id,
        },
        format,
    )
    .await
    .map_err(AuthFailure::NotStarted)
}

/// Ends an enrollment that cannot be recorded, telling the client why.
///
/// The reason goes on the wire, unlike the token refusals', because it is about
/// the request the client itself just sent and not about any state this server
/// holds — repeating it back tells a peer nothing it did not already know.
pub(super) async fn refuse_unrecordable_enrollment(
    send: &mut iroh::endpoint::SendStream,
    client_id: &str,
    reason: &str,
    format: Format,
) -> AuthFailure {
    if let Err(e) = write_auth_message(
        send,
        &AuthMessage::EnrollFailed {
            reason: reason.to_string(),
        },
        format,
    )
    .await
    {
        return AuthFailure::NotStarted(e);
    }
    AuthFailure::Rejected(format!(
        "enrollment refused for client '{client_id}': {reason}"
    ))
}

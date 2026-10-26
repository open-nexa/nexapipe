//! The seam where a credential is checked.
//!
//! # Why this is a trait
//!
//! Which credentials exist is the core's business: a shared secret, a TOTP
//! seed, an Ed25519 key. What checks them is a decision, and the decision is
//! made by whatever holds the credential store. This module is that decision
//! written down as a trait, so that a deployment can put another kind of
//! credential store behind it — an identity provider, a directory, a database
//! of its own — without the protocol around it changing.
//!
//! The trait lives here, in the open source, and so does the implementation
//! that reads `config.toml`. A build that wants a different one provides its
//! own implementation and nothing else changes: the handshake, the wire
//! format, the counters and the authorization snapshot all stay where they
//! are.
//!
//! # What an implementation owns
//!
//! The whole attempt: the verification, the counters it moves, and the peer
//! registration. That is the contract, and it is not a convenience. Three
//! things have to happen in one critical section, and splitting them reopens
//! races this code spent a long time closing:
//!
//! - the verification and the counter it moves, so that two connections from
//!   the same client cannot both read "not locked out" before either has
//!   recorded anything;
//! - the counter and the peer registration, so that a reload which drops the
//!   credential cannot pass between the two and leave a connection registered
//!   under a credential that is gone;
//! - the authorization snapshot and the verification, so that a client whose
//!   entry was removed a moment ago is not left holding an unrestricted one.
//!
//! An implementation that has to reach outside the process — an identity
//! provider on the other side of a network — does that reach **before** it
//! takes the lock, and takes the lock only to record what it found. The
//! contract says the counters are moved under one lock; it does not say the
//! lock is held for the whole attempt.
//!
//! # What an implementation may not do
//!
//! The counters are the core's, and they are the core's to move: the
//! configuration behind [`AuthState`] is where the lockout accounting and the
//! step memory live, and an implementation is expected to use it rather than
//! to keep its own. A lockout that an implementation could switch off would
//! not be a lockout, and the property would hold only for the builds that
//! happen to use the built-in one.

use crate::auth::{AuthError, ClientAcl, StepVerdict, TotpValidator, Verified};

use futures_util::future::BoxFuture;

use super::state::{AuthState, persist_auth_state};
use crate::conn::peers::{PeerGuard, PeerIdentity};

/// What a client says when it authenticates.
///
/// The six facts a credential is made of. They are the wire's own fields, so an
/// implementation that speaks to something other than this protocol still
/// answers the same question: is this credential good, and what may it reach.
pub struct AuthRequest<'a> {
    /// The client the connection claims to be.
    pub client_id: &'a str,
    /// The device it names, `None` for the device that has none.
    pub device_id: Option<&'a str>,
    /// The challenge this connection was issued.
    pub nonce: &'a [u8],
    /// When the client says it answered.
    pub timestamp: i64,
    /// The signature over the challenge, for a device that holds a key.
    pub signature: &'a [u8],
    /// The code, for a device that holds a seed.
    pub code: &'a str,
}

/// What an authenticator answers with.
#[derive(Debug)]
pub struct AuthOutcome {
    /// The authorization the connection runs under.
    ///
    /// Snapshotted while the credential was being verified, so that what is
    /// checked afterwards is the state the authentication saw and not the state
    /// the configuration may have become since.
    pub acl: ClientAcl,
    /// The peer registration, when the attempt succeeded.
    ///
    /// `None` for a refusal: a peer that was turned away was never connected,
    /// and listing it would answer "who is connected" with peers that were
    /// not.
    pub registered: Option<(PeerGuard, tokio::sync::watch::Receiver<bool>)>,
}

/// The core's side of an authentication attempt.
///
/// What an implementation is given besides the credential: the state it moves
/// its counters in, the peer it is authenticating, and the way it registers
/// that peer.
pub struct AuthContext<'a> {
    /// The live state: the configuration, the counters in it, and where they
    /// are persisted.
    pub state: &'a AuthState,
    /// The peer being authenticated, for the log lines.
    pub peer: &'a str,
    /// Puts the connection in the peer registry and hands back what keeps it
    /// there and what tells it to stop.
    ///
    /// An implementation must call this **before it releases the lock it holds
    /// for the counters**. A reload takes that same lock and closes the
    /// connections whose credential it just dropped, so a peer registered after
    /// the lock is released can miss that pass and stay connected under a
    /// credential that is gone.
    pub register:
        &'a (dyn Fn(PeerIdentity) -> (PeerGuard, tokio::sync::watch::Receiver<bool>) + Send + Sync),
}

/// Checks a credential, and accounts for the attempt.
///
/// The seam a deployment that keeps its credentials somewhere else plugs into.
/// The implementation owns the whole attempt — see this module's own notes for
/// what that means and why.
pub trait Authenticator: Send + Sync + 'static {
    /// Verifies one attempt, moves the counters it should move, and registers
    /// the peer when the attempt succeeds.
    ///
    /// Called **without the auth lock held**: an implementation may have to
    /// reach an identity provider, and a lock held across that reach stalls
    /// every other connection that is authenticating.
    fn authenticate<'a>(
        &'a self,
        req: AuthRequest<'a>,
        ctx: AuthContext<'a>,
    ) -> BoxFuture<'a, Result<AuthOutcome, AuthError>>;
}

/// The authenticator that reads the credentials in `config.toml`.
///
/// This is what a deployment gets when it asks for nothing else, and it is the
/// one the wire format was written against: a shared secret, a TOTP seed or an
/// Ed25519 key, checked against the client table in the configuration.
///
/// The logic is the one that used to live in the handshake, moved here
/// unchanged: the same lock, the same order, the same refusals, the same
/// counters. What changed is where it is called from.
pub struct ConfigAuthenticator;

impl Authenticator for ConfigAuthenticator {
    fn authenticate<'a>(
        &'a self,
        req: AuthRequest<'a>,
        ctx: AuthContext<'a>,
    ) -> BoxFuture<'a, Result<AuthOutcome, AuthError>> {
        Box::pin(async move {
            let client_id = req.client_id;
            let resp_device_id = req.device_id;

            // Step 4: Verify the response and account for the result under one
            // write lock. The signature binds the response to this connection's
            // challenge and the timestamp keeps it fresh; only then does the
            // TOTP code decide.
            //
            // Verify and record have to share the lock. Split across a read and
            // a write lock, two connections from the same client could both read
            // "not locked out" before either had recorded anything, and the
            // counters would under-count. The lock is held across an HMAC and a
            // TOTP check, both of which are microseconds, so serialising
            // handshakes costs nothing a client can notice.
            let mut cfg = ctx.state.config().write().await;

            // Drop a lockout that has run out before deciding anything, so an
            // expired one does not read as live and its stale counter does not
            // push the client straight back over the threshold.
            if let Some(client) = cfg.clients.get_mut(client_id) {
                client.refresh_lockout();
            }

            let outcome = TotpValidator::new(&cfg).verify_response(
                client_id,
                resp_device_id,
                req.nonce,
                req.timestamp,
                req.signature,
                req.code,
            );

            // Only a wrong TOTP code counts toward the lockout: a skewed clock or
            // a mismatched signature is a refusal, not a failed attempt, and
            // counting those would let whoever replays a captured response lock
            // its rightful owner out.
            //
            // Every branch below ends up sending one AUTH_FAILED whose reason is
            // a single fixed string. A distinct message for "locked out" or "no
            // such client" would make the reason an oracle: anyone could walk a
            // client's counter up to the lockout and, from the change in the
            // reply, learn that the id they guessed exists. The real reason goes
            // to the log instead.
            let mut verified_acl = ClientAcl::unrestricted();
            // Whether the counters changed and the state file has to be written.
            // The write itself happens after the lock is released.
            let mut state_dirty = false;
            // The reason this attempt was refused, when it was. `None` is the
            // attempt that succeeded.
            let mut refusal: Option<AuthError> = None;
            match outcome {
                Ok(Verified::Accepted { step }) => {
                    // **The step check**, under the same lock that verified the
                    // code.
                    //
                    // A code is inside the acceptance window for the whole of
                    // its step, so "this code is current" and "this code has
                    // already been used" are different questions, and only the
                    // step tells them apart. RFC 6238 §5.2 asks the verifier to
                    // refuse the second use of a step it has already accepted.
                    //
                    // The check and the record are one operation: a caller that
                    // checked and then recorded could let two connections
                    // through between the two, and the whole point is that the
                    // second one does not get in.
                    let step_verdict = match step {
                        Some(step) => cfg.accept_step(client_id, resp_device_id, step),
                        // No code, so no step: a key device's signature covers the
                        // challenge issued for this connection, and there is
                        // nothing for a second use to replay.
                        None => StepVerdict::Accepted { moved: false },
                    };
                    let (step_moved, step_refused) = match step_verdict {
                        StepVerdict::Refused => (false, true),
                        StepVerdict::Accepted { moved } => (moved, false),
                    };
                    if step_refused {
                        // **Not counted.** A code that has already been used is
                        // not a guess at the credential, and counting it would
                        // let whoever holds one code lock the device's owner out —
                        // over a credential the owner did nothing wrong.
                        tracing::warn!(
                            "2FA: client '{}' from {} sent a code that has already been used; \
                             refused without counting it as an attempt",
                            client_id,
                            ctx.peer
                        );
                        refusal = Some(AuthError::InvalidCode);
                    } else {
                        // Which device this was, if it named one, recorded under
                        // the same lock that verified it. This is the stamp
                        // `client list` reads to say whether a device is still in
                        // use: without it every named device reports "never
                        // used" forever, and the one question the device table
                        // exists to answer — which of these can be revoked
                        // without disconnecting a live one — has nothing to go
                        // on.
                        let device_stamp_moved = match resp_device_id {
                            Some(name) => cfg
                                .clients
                                .get_mut(client_id)
                                .is_some_and(|client| client.record_device_success(name)),
                            None => false,
                        };
                        // Clear the counters only when there is something to
                        // clear, so a healthy client does not turn every
                        // connection into a disk write. A named device that moved
                        // its stamp is worth one: `unix_now` is whole seconds,
                        // so a device reconnecting inside the same second is not.
                        // The step's memory is worth a write too: it is the thing
                        // that refuses the second use of a code, and a server
                        // that forgot it over a restart would accept one.
                        let dirty = step_moved
                            || device_stamp_moved
                            || cfg.clients.get(client_id).is_some_and(|c| {
                                c.failed_attempts != 0 || c.locked_until.is_some()
                            });
                        if dirty {
                            if let Some(client) = cfg.clients.get_mut(client_id) {
                                client.record_success();
                            }
                            // The write happens after the lock is released; see
                            // `persist_auth_state`.
                            state_dirty = true;
                        }
                        // Snapshot the host authorization while the same lock
                        // that verified the credentials still holds: the entry
                        // cannot vanish between the two reads, and a connection
                        // keeps the ACL it authenticated with even if a reload
                        // changes it right after.
                        if let Some(client) = cfg.clients.get(client_id) {
                            verified_acl = client.acl();
                        }
                    }
                }
                Ok(Verified::WrongCode) => {
                    let max_attempts = cfg.max_attempts;
                    let lockout_duration = cfg.lockout_duration;
                    if let Some(client) = cfg.clients.get_mut(client_id) {
                        client.record_failure(max_attempts, lockout_duration);
                    }
                    // The write happens after the lock is released; see
                    // `persist_auth_state`.
                    state_dirty = true;
                    refusal = Some(AuthError::InvalidCode);
                }
                Err(e) => {
                    match &e {
                        AuthError::ClientNotFound => {
                            tracing::warn!("2FA: unknown client '{}' from {}", client_id, ctx.peer);
                        }
                        AuthError::UnknownDevice => {
                            // Printable ASCII, because the name was checked
                            // before it was used for anything — and it is the
                            // one thing about this refusal an operator can act
                            // on.
                            tracing::warn!(
                                "2FA: client '{}' from {} names device {:?}, which has no \
                                 credential: either it never enrolled or its entry was dropped",
                                client_id,
                                ctx.peer,
                                resp_device_id
                            );
                        }
                        AuthError::InvalidSecret | AuthError::TotpCreationFailed => {
                            tracing::error!(
                                "2FA: client '{}' cannot be validated, the server's auth config is \
                                 broken: {}",
                                client_id,
                                e
                            );
                        }
                        AuthError::LockedOut => {
                            tracing::warn!(
                                "2FA: client '{}' from {} is locked out",
                                client_id,
                                ctx.peer
                            );
                        }
                        AuthError::WrongSignature => {
                            // Not counted, and worth saying why: a key cannot be
                            // guessed, so there is nothing for the counter to
                            // protect on this path — counting it would only let a
                            // peer that knows the client id and the device name
                            // deny the device's owner service.
                            tracing::warn!(
                                "2FA: response from {} for '{}' carries a signature that does not \
                                 match the challenge",
                                ctx.peer,
                                client_id
                            );
                        }
                        AuthError::MalformedSignature => {
                            // Not counted, and worth saying why: the peer sent
                            // noise rather than a wrong credential, so this is
                            // not an attempt at the device.
                            tracing::warn!(
                                "2FA: response from {} for '{}' carries a signature that is not a \
                                 signature",
                                ctx.peer,
                                client_id
                            );
                        }
                        AuthError::UnnamedDeviceNotAllowed => {
                            // The one refusal that is a configuration the
                            // operator can change, so it is the one that says
                            // which knob.
                            tracing::warn!(
                                "2FA: client '{}' from {} names no device, and this client answers \
                                 only to named ones: set unnamed_device_allowed = true under \
                                 [auth.clients.{}] to let it use the client's own secret",
                                client_id,
                                ctx.peer,
                                client_id
                            );
                        }
                        _ => {
                            tracing::warn!(
                                "2FA: response from {} for '{}' rejected: {}",
                                ctx.peer,
                                client_id,
                                e
                            );
                        }
                    }
                    refusal = Some(e);
                }
            }

            // Registered here, while the write lock is still held, for the reason
            // given on `PeerRegistration`: a reload takes this same lock and
            // closes the connections whose credential it just dropped, so the
            // entry has to be in the registry before the lock is released or that
            // pass misses it. Nothing is registered on a refusal — a peer that
            // was turned away was never connected, and listing it would answer
            // "who is connected" with peers that were not.
            let registered = if refusal.is_none() {
                Some((ctx.register)(PeerIdentity {
                    client_id: Some(client_id.to_string()),
                    device: resp_device_id.map(str::to_string),
                }))
            } else {
                None
            };

            drop(cfg);

            // The state file is written with the auth lock released. The counters
            // it carries are read at write time, so they are the ones as of now.
            if state_dirty && let Err(e) = persist_auth_state(ctx.state).await {
                tracing::warn!(
                    "2FA: failed to persist the auth counters for '{}' to {}: {}",
                    client_id,
                    ctx.state.storage().describe(),
                    e
                );
            }

            match refusal {
                Some(e) => Err(e),
                None => Ok(AuthOutcome {
                    acl: verified_acl,
                    registered,
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthConfig, ClientAuth};
    use crate::conn::peers::PeerRegistry;
    use nexapipe_client::auth::{TotpAlgorithm, TwoFactorAuth};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A 160-bit Base32 secret, the length `--generate-2fa` hands out.
    const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// The nonce the server issues, minted the way it mints one.
    fn fresh_nonce() -> Vec<u8> {
        (0..32).map(|_| rand::random::<u8>()).collect()
    }

    /// A configuration with one client that may reach one host.
    fn auth_config() -> AuthConfig {
        let mut config = AuthConfig {
            enabled: true,
            max_attempts: 3,
            lockout_duration: 60,
            ..AuthConfig::default()
        };
        config.clients.insert(
            "client-001".to_string(),
            ClientAuth {
                secret: nexapipe_proto::secret::SecretString::new(SECRET.to_string()),
                created_at: "0".to_string(),
                allow_hosts: Some(vec!["app.example.com".to_string()]),
                allow_ports: None,
                allow_ports_strict: false,
                pending_enrollment: None,
                devices: HashMap::new(),
                unnamed_device_allowed: true,
                last_used: None,
                last_used_step: None,
                failed_attempts: 0,
                locked_until: None,
                enrollment_failed_attempts: 0,
                enrollment_locked_until: None,
            },
        );
        config
    }

    /// A state whose counters are persisted beside the configuration, in a
    /// directory that goes away with the test.
    ///
    /// The path matters: a state whose counters are written lands in a file,
    /// and a test that wrote one into the working directory would leave it
    /// there.
    fn state(config: AuthConfig) -> (tempfile::TempDir, AuthState) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir
            .path()
            .join("config.toml")
            .to_string_lossy()
            .into_owned();
        let state = AuthState::new(
            config,
            std::sync::Arc::new(crate::storage::file::FileStorage::new(path)),
        );
        (dir, state)
    }

    /// A registration a test can register its peer in.
    ///
    /// The registry is a real one: the guard it hands back is what keeps the
    /// peer listed, and a test that made one up would not be testing the
    /// registration the handshake does.
    fn registration() -> super::super::enrollment::PeerRegistration {
        super::super::enrollment::PeerRegistration {
            registry: Arc::new(PeerRegistry::new()),
            endpoint_id: iroh::SecretKey::from_bytes(&[7u8; 32]).public(),
            path: crate::metrics::PathKind::Direct,
        }
    }

    /// The built-in authenticator agrees with the validator it replaced.
    ///
    /// The two used to be one function: the validator checked the credential
    /// and the handshake counted the attempt. The authenticator owns both now,
    /// and this is the test that says the split did not change a verdict.
    #[tokio::test]
    async fn the_built_in_authenticator_agrees_with_the_validator() {
        let config = auth_config();
        let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();
        let nonce = fresh_nonce();
        let timestamp = now();
        let signature = client.sign_challenge(&nonce, timestamp).unwrap();
        let code = client.generate_code().unwrap();

        // The validator on its own: the answer the handshake used to get.
        let validated = TotpValidator::new(&config).verify_response(
            "client-001",
            None,
            &nonce,
            timestamp,
            &signature,
            &code,
        );
        assert!(
            matches!(validated, Ok(Verified::Accepted { .. })),
            "the validator refused a correct response: {validated:?}"
        );

        // The authenticator, on the same inputs.
        let (_dir, state) = state(config);
        let registration = registration();
        let register = move |identity: PeerIdentity| registration.register(identity);
        let outcome = ConfigAuthenticator
            .authenticate(
                AuthRequest {
                    client_id: "client-001",
                    device_id: None,
                    nonce: &nonce,
                    timestamp,
                    signature: &signature,
                    code: &code,
                },
                AuthContext {
                    state: &state,
                    peer: "peer",
                    register: &register,
                },
            )
            .await;
        assert!(
            outcome.is_ok(),
            "the authenticator refused what the validator accepted: {:?}",
            outcome.err()
        );
    }

    /// The authorization the connection runs under is the one the client that
    /// authenticated carries.
    ///
    /// It is snapshotted while the credential is verified, so that what is
    /// checked afterwards is the state the authentication saw.
    #[tokio::test]
    async fn the_acl_comes_from_the_client_that_authenticated() {
        let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();
        let nonce = fresh_nonce();
        let timestamp = now();
        let signature = client.sign_challenge(&nonce, timestamp).unwrap();
        let code = client.generate_code().unwrap();

        let (_dir, state) = state(auth_config());
        let registration = registration();
        let register = move |identity: PeerIdentity| registration.register(identity);
        let outcome = ConfigAuthenticator
            .authenticate(
                AuthRequest {
                    client_id: "client-001",
                    device_id: None,
                    nonce: &nonce,
                    timestamp,
                    signature: &signature,
                    code: &code,
                },
                AuthContext {
                    state: &state,
                    peer: "peer",
                    register: &register,
                },
            )
            .await
            .expect("the response to verify");

        assert!(outcome.acl.allows("app.example.com"));
        assert!(!outcome.acl.allows("other.example.com"));
        // The peer was registered, so that a reload can reach it.
        assert!(outcome.registered.is_some());
    }

    /// A wrong code is counted, and enough of them lock the client out.
    ///
    /// The counting is the core's, and it stays the core's: an authenticator
    /// that kept its own counters would be a build whose lockout was a
    /// different rule from everybody else's.
    #[tokio::test]
    async fn a_wrong_code_is_counted_and_locks_the_client_out() {
        let (_dir, state) = state(auth_config());
        let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

        for attempt in 0..3 {
            let nonce = fresh_nonce();
            let timestamp = now();
            let signature = client.sign_challenge(&nonce, timestamp).unwrap();
            let registration = registration();
            let register = move |identity: PeerIdentity| registration.register(identity);
            let outcome = ConfigAuthenticator
                .authenticate(
                    AuthRequest {
                        client_id: "client-001",
                        device_id: None,
                        nonce: &nonce,
                        timestamp,
                        signature: &signature,
                        code: "000000",
                    },
                    AuthContext {
                        state: &state,
                        peer: "peer",
                        register: &register,
                    },
                )
                .await;
            assert!(
                matches!(outcome, Err(AuthError::InvalidCode)),
                "attempt {attempt} was not refused as a wrong code: {outcome:?}"
            );
        }

        // The fourth attempt carries a correct code, and is still refused: the
        // client is locked out.
        let nonce = fresh_nonce();
        let timestamp = now();
        let signature = client.sign_challenge(&nonce, timestamp).unwrap();
        let code = client.generate_code().unwrap();
        let registration = registration();
        let register = move |identity: PeerIdentity| registration.register(identity);
        let outcome = ConfigAuthenticator
            .authenticate(
                AuthRequest {
                    client_id: "client-001",
                    device_id: None,
                    nonce: &nonce,
                    timestamp,
                    signature: &signature,
                    code: &code,
                },
                AuthContext {
                    state: &state,
                    peer: "peer",
                    register: &register,
                },
            )
            .await;
        assert!(
            matches!(outcome, Err(AuthError::LockedOut)),
            "a locked out client was let in: {outcome:?}"
        );
    }

    /// An authenticator that is not the built-in one.
    struct AlwaysRefuses;

    impl Authenticator for AlwaysRefuses {
        fn authenticate<'a>(
            &'a self,
            _req: AuthRequest<'a>,
            _ctx: AuthContext<'a>,
        ) -> BoxFuture<'a, Result<AuthOutcome, AuthError>> {
            Box::pin(async { Err(AuthError::ClientNotFound) })
        }
    }

    /// The state hands out the authenticator it was given.
    ///
    /// A deployment that keeps its credentials somewhere else plugs its own
    /// implementation in here, and this is the seam it plugs into: the answer
    /// the state hands out is the one the handshake asks.
    #[tokio::test]
    async fn the_state_hands_out_the_authenticator_it_was_given() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir
            .path()
            .join("config.toml")
            .to_string_lossy()
            .into_owned();
        let state = AuthState::with_authenticator(
            auth_config(),
            std::sync::Arc::new(crate::storage::file::FileStorage::new(path)),
            Arc::new(AlwaysRefuses),
        );

        let registration = registration();
        let register = move |identity: PeerIdentity| registration.register(identity);
        let outcome = state
            .authenticator()
            .authenticate(
                AuthRequest {
                    client_id: "client-001",
                    device_id: None,
                    nonce: &[],
                    timestamp: now(),
                    signature: &[],
                    code: "",
                },
                AuthContext {
                    state: &state,
                    peer: "peer",
                    register: &register,
                },
            )
            .await;
        assert!(
            matches!(outcome, Err(AuthError::ClientNotFound)),
            "the built-in authenticator answered instead of the one that was given: {outcome:?}"
        );
    }
}

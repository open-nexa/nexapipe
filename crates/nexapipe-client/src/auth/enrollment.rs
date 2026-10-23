//! The exchange that trades an invitation for a credential.
//!
//! The token in the invitation authorizes the exchange, so it is a request
//! rather than a claim: the server is free to answer with it or to refuse
//! it, and what it answers with is what the credential is filed under.

use iroh::endpoint::Connection;
use nexapipe_proto::auth::Format;
use nexapipe_proto::secret::SecretString;

use crate::ClientError;

use super::message::{AUTH_HANDSHAKE_TIMEOUT, message_name, read_message, write_message};
use super::totp::{TotpAlgorithm, masked};
use super::two_factor::TwoFactorAuth;

/// A credential the server issued during enrollment, in the form an app can
/// store it.
///
/// Handed out once by
/// [`crate::connection_pool::IrohConnectionPool::take_issued_credential`],
/// right after a token has been spent. An app that keeps its settings somewhere
/// durable has to write these fields down: the token is gone, so a restart that
/// still holds the invite cannot enroll a second time.
///
/// `Debug` masks `secret`, for the reason [`TwoFactorConfig`](super::TwoFactorConfig)'s does.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    pub client_id: String,
    /// Base32, exactly as it goes into [`TwoFactorAuth::new`] next time.
    /// Empty when the device was issued a key instead — see [`Self::public_key`].
    ///
    /// A [`SecretString`]: the credential is wiped when this is dropped, and
    /// the value is read through [`nexapipe_proto::secret::Secret::expose_secret`]
    /// where it has to be.
    pub secret: SecretString,
    pub algorithm: String,
    /// The public half of the key the device was issued, lowercase hex — the
    /// spelling the server stores — with `None` for a credential that is a
    /// secret.
    ///
    /// A `Some` here is also what says the credential proves itself with a
    /// signature: an app persisting it has to keep the private half it
    /// generated, because the server knows this device by its key and would
    /// refuse a secret it never issued.
    pub public_key: Option<String>,
    /// The device this credential was issued for, which has to be persisted
    /// with it: the server filed the secret under that name, so an app that
    /// writes down the secret and not the name has a credential it can no
    /// longer answer with. `None` is the unnamed device — a server that
    /// answered an enrollment which named none, or one that predates devices
    /// entirely.
    pub device: Option<String>,
}

impl std::fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCredential")
            .field("client_id", &self.client_id)
            .field("secret", &masked(self.secret.as_str()))
            .field("algorithm", &self.algorithm)
            .field("device", &self.device)
            .finish()
    }
}

/// A credential that has not been issued yet.
///
/// A `v=2` invitation carries one of these instead of the client's secret: the
/// link stops being a credential the moment it has been used, because what it
/// holds is a token the server exchanges for a freshly generated secret — or,
/// when the enrollment offers one, records as a device key — and then
/// discards. The trade is that the app has to keep what comes back — see
/// [`Enrollment::exchange`].
///
/// No `PartialEq`: an offered key is secret material with no equality of its
/// own, and comparing enrollments is not a question this type is asked.
///
/// `Debug` masks `token`, for the reason [`TwoFactorConfig`](super::TwoFactorConfig)'s does: an
/// unspent invitation link *is* the credential, and this is the struct an app
/// is most likely to log while working out why an enrollment did not go through.
#[derive(Clone)]
pub struct Enrollment {
    client_id: String,
    /// The one-time token an invitation carried.
    ///
    /// A [`SecretString`]: an unspent invitation link *is* the credential, so
    /// the token is wiped when the enrollment is dropped — which is what
    /// happens the moment it has been spent.
    token: SecretString,
    /// The name to be enrolled under. The token is what authorizes the
    /// exchange, so this is a request rather than a claim: the server is free
    /// to answer with it or to refuse it, and what it answers with is what the
    /// credential is filed under.
    device_id: Option<String>,
    /// The device key to offer, if any. What travels is the public half, and
    /// what comes back tells this side whether the offer was taken: an empty
    /// `secret` in ENROLL_ISSUE is the server saying the key was recorded.
    ///
    /// The private half is wiped when the enrollment is dropped, the way the
    /// rest of the credentials here are: `iroh::SecretKey` is built on
    /// ed25519-dalek, whose signing key zeroes itself on the way out.
    pub(super) key: Option<iroh::SecretKey>,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("client_id", &self.client_id)
            .field("token", &masked(self.token.as_str()))
            .field("device_id", &self.device_id)
            .finish()
    }
}

/// What a client says when the server refuses an enrollment.
///
/// The server sends one string for every way it can refuse — whether the token
/// was unknown, already spent or the device was already enrolled is not
/// information a stranger is owed — so the refusal on its own says nothing
/// about what to do next. What the client does know is which client id and
/// which device name it offered, and those are what an operator needs: the
/// server's log names the device, and this names it on the client's side too,
/// so the two can be put together without guessing.
///
/// The device name is what makes the refusal actionable, because it is what a
/// device that is already enrolled on the server has to be freed under — and
/// the most common reason for a refusal is exactly that: the answer the
/// server gave was never written down, so the device asked again and the name
/// it asked under was taken.
pub(crate) fn refused_enrollment_message(
    reason: &str,
    client_id: &str,
    device: Option<&str>,
) -> String {
    match device {
        Some(device) => format!(
            "{reason} (client '{client_id}', device '{device}'; if that device is already \
             enrolled on the server, an operator can free it with `nexapipe client revoke \
             {client_id} --device {device}`)"
        ),
        None => format!("{reason} (client '{client_id}')"),
    }
}

impl Enrollment {
    pub fn new(client_id: &str, token: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            token: SecretString::new(token.to_string()),
            device_id: None,
            key: None,
        }
    }

    /// The same enrollment, asking to be issued under one device name.
    pub fn with_device(mut self, device_id: &str) -> Self {
        self.device_id = Some(device_id.to_string());
        self
    }

    /// The same enrollment, offering this device's key.
    ///
    /// What the server makes of the offer decides the credential: one that
    /// knows keys files the public half under the device name and answers with
    /// an empty secret — from then on nothing but a signature is sent — while
    /// one that predates them ignores the field and issues a secret, which
    /// then has to work as it always did. The public half travels in the
    /// clear, being public; the private half stays here.
    pub fn with_key(mut self, key: iroh::SecretKey) -> Self {
        self.key = Some(key);
        self
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The device this enrollment will ask for, if it was given one.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Trades the token for the real credential and authenticates with it, in
    /// one stream: ENROLL_START/ENROLL_ISSUE, then the ordinary handshake.
    ///
    /// The issued [`TwoFactorAuth`] is returned rather than kept, because what
    /// happens to it is the caller's decision — the process can use it for as
    /// long as it lives, but an app that wants to survive a restart has to
    /// persist [`TwoFactorAuth::secret_base32`] and drop the token.
    pub async fn exchange(&self, conn: &Connection) -> Result<TwoFactorAuth, ClientError> {
        // The same deadline the handshake below gets, and for the same reason:
        // a server that takes the ENROLL_START and never answers leaves this
        // future pending forever, and callers hold the endpoint's lock while
        // they wait for it.
        let exchange = self.exchange_inner(conn);
        match tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, exchange).await {
            Ok(outcome) => outcome,
            Err(_) => Err(ClientError::ConnectionFailed(format!(
                "the server did not answer the enrollment within {}s",
                AUTH_HANDSHAKE_TIMEOUT.as_secs()
            ))),
        }
    }

    async fn exchange_inner(&self, conn: &Connection) -> Result<TwoFactorAuth, ClientError> {
        use nexapipe_proto::auth::AuthMessage;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to open stream: {}", e)))?;

        // The old form: this is the first message of the exchange, and the
        // server reading it may be one that predates the version byte. The
        // version is announced in the AUTH_START that follows, on the same
        // stream.
        write_message(
            &mut send,
            &AuthMessage::EnrollStart {
                client_id: self.client_id.clone(),
                // Onto the wire, and out of this process: the copy that
                // travels is a plain string on the other side, because the
                // receiver has to compare it — but the one here is still a
                // `Secret`, and is wiped with the message.
                token: self.token.clone(),
                device_id: self.device_id.clone(),
                public_key: self
                    .key
                    .as_ref()
                    .map(|key| hex::encode(key.public().as_bytes())),
            },
            Format::LegacyJson,
        )
        .await?;

        let (issued_message, _) = read_message(&mut recv).await?;
        let issued = match issued_message {
            AuthMessage::EnrollIssue {
                client_id,
                secret,
                algorithm,
                digits,
                period,
                device_id,
            } => {
                if client_id != self.client_id {
                    return Err(ClientError::AuthenticationFailed(
                        "the server issued a credential for a different client id".to_string(),
                    ));
                }
                if secret.as_str().is_empty() {
                    // No secret in the answer means the server recorded the
                    // key this enrollment offered — it only ever does that
                    // when the request carried one, so this is that key,
                    // whose private half never left this process.
                    let Some(key) = self.key.clone() else {
                        return Err(ClientError::Other(
                            "the server issued an empty secret, but this enrollment offered \
                             no key"
                                .to_string(),
                        ));
                    };
                    // A key is one device's credential; the unnamed slot is
                    // the client's shared secret and the server refuses to
                    // file a key there, so a key answer always names the
                    // device it was filed under.
                    let Some(name) = device_id else {
                        return Err(ClientError::Other(
                            "the server issued a key credential without naming the device \
                             it was filed under"
                                .to_string(),
                        ));
                    };
                    TwoFactorAuth::with_key(&client_id, key, &name)
                } else {
                    // A secret came back, so a secret is the credential:
                    // either that is what was asked for, or a key was offered
                    // and the server predates keys — it ignores the field and
                    // issues a secret as it always has, which then has to
                    // work.
                    //
                    // The name the server filed this secret under is the only
                    // name this credential has, and it is whatever came back
                    // here — asked for in ENROLL_START, answered in this one.
                    //
                    // An answer that names no device is a server that filed it
                    // under no device: it predates the table, or it was asked
                    // for none. Either way it has nothing to match a name
                    // against, and putting the one that was asked for back
                    // sends it on every handshake from here on — which the
                    // server answers by refusing a device it does not know.
                    // Narrowed the way `digits` is narrowed in `generate_code`, and
                    // for the same reason: a cast truncates a period that does not
                    // fit into one that looks deliberate — a 90-second step read as
                    // some other number — where a refusal names the value the
                    // server actually sent.
                    let period = u32::try_from(period).map_err(|_| {
                        ClientError::InvalidConfig(format!("{period} is not a TOTP period"))
                    })?;
                    // The algorithm is a closed type on the wire now: a name
                    // nobody supports is refused where the message is read,
                    // rather than quietly turned into a different algorithm
                    // here — which would compute codes the server does not
                    // accept, and every attempt would fail with "wrong code".
                    let algorithm = TotpAlgorithm::from(algorithm);
                    let issued = TwoFactorAuth::with_params(
                        &client_id,
                        secret.as_str(),
                        algorithm,
                        period,
                        digits,
                    )?;
                    match device_id {
                        Some(name) => issued.with_device(&name),
                        None => issued,
                    }
                }
            }
            // One reply for every way this can fail: an enrollment token is
            // either right or it is not, and saying which would only help
            // someone who is guessing.
            AuthMessage::EnrollFailed { reason } => {
                return Err(ClientError::AuthenticationFailed(
                    refused_enrollment_message(&reason, self.client_id(), self.device_id()),
                ));
            }
            other => {
                return Err(ClientError::Other(format!(
                    "expected ENROLL_ISSUE, the server sent {}",
                    message_name(&other)
                )));
            }
        };

        issued.authenticate_on(conn, &mut send, &mut recv).await?;
        Ok(issued)
    }
}

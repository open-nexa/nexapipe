//! The credentials an invite can carry.
//!
//! Either the second factor itself — a TOTP seed — or a one-time enrollment
//! token standing in for it. Both are credentials, and neither is ever
//! printed in the clear.

use std::fmt;

use anyhow::{Result, bail};
use nexapipe_proto::secret::SecretString;

use crate::auth::TotpAlgorithm;

use super::totp::normalize_secret;
use super::uri::QueryParams;

// The whole module, so that the doc links below — which point at the invite
// that carries these credentials — resolve.
use super::*;

/// What a [`fmt::Debug`] prints instead of a credential.
///
/// Nothing in this module is meant to be logged, but a parse error or a UI
/// binding that formats an invite with `{:?}` should not turn into a copy of
/// the second factor in a log file. [`EndpointInvite::to_uri`] still writes
/// secrets in the clear: that URI *is* the invite, and a redacted one would
/// scan to nothing.
const REDACTED: &str = "***";

/// The 2FA half of an invite: everything [`OtpAuth`](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
/// style codes carry, in the flat form described above.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteTotp {
    pub issuer: String,
    pub client_id: String,
    /// Upper-case Base32 without padding.
    ///
    /// A [`SecretString`]: an invite that carries a secret carries a working
    /// credential, and this one is wiped when the invite is dropped.
    pub secret: SecretString,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u32,
}

impl fmt::Debug for InviteTotp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteTotp")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("secret", &REDACTED)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

impl InviteTotp {
    /// Credentials with the parameters this library defaults to.
    pub fn new(client_id: &str, secret: &str) -> Result<Self> {
        Self::with_params(
            DEFAULT_ISSUER,
            client_id,
            secret,
            TotpAlgorithm::SHA1,
            6,
            30,
        )
    }

    /// Credentials with every parameter spelled out.
    pub fn with_params(
        issuer: &str,
        client_id: &str,
        secret: &str,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u32,
    ) -> Result<Self> {
        let issuer = issuer.trim();
        if issuer.is_empty() {
            bail!("the 2FA issuer is empty");
        }
        let client_id = client_id.trim();
        if client_id.is_empty() {
            bail!("the 2FA client id is empty");
        }
        let secret = normalize_secret(secret)?;
        if !(6..=8).contains(&digits) {
            bail!("{digits} digits per code is not supported (expected 6 to 8)");
        }
        if period == 0 {
            bail!("the 2FA period cannot be 0 seconds");
        }

        Ok(Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            secret,
            algorithm,
            digits,
            period,
        })
    }

    /// Parameters that cannot be honored once the code has been imported.
    ///
    /// [`crate::auth::TwoFactorAuth`] is built with a six-digit code over a
    /// 30 second step, so anything else in the invite is silently discarded by
    /// the generated codes; importing is the moment to say so.
    pub fn client_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.digits != 6 {
            warnings.push(format!(
                "{} digits per code is ignored: the client always generates 6-digit codes",
                self.digits
            ));
        }
        if self.period != 30 {
            warnings.push(format!(
                "a {} second step is ignored: the client always uses a 30 second step",
                self.period
            ));
        }
        warnings
    }

    /// Flat parameters, in the order [`EndpointInvite::to_uri`] writes them.
    pub(super) fn to_params(&self) -> Vec<(&'static str, String)> {
        vec![
            ("client", self.client_id.clone()),
            ("issuer", self.issuer.clone()),
            ("secret", self.secret.expose_secret_cloned()),
            ("algorithm", self.algorithm.name().to_ascii_uppercase()),
            ("digits", self.digits.to_string()),
            ("period", self.period.to_string()),
        ]
    }
}

/// A one-time enrollment token, in place of [`InviteTotp`].
///
/// What travels in the link is not the credential: the holder exchanges it for
/// one on first connect ([`crate::auth::Enrollment::exchange`]), and the server
/// burns it in the same breath. A copied link therefore stops being a
/// credential the first time it is used, instead of staying one until somebody
/// rotates the secret by hand.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteEnrollment {
    pub client_id: String,
    /// Opaque to the client: generated by the server, compared by the server.
    ///
    /// A [`SecretString`]: the link that carries this token is the credential
    /// until it is spent, and the token is wiped when the invite is dropped.
    pub token: SecretString,
    /// When the invitation stops being worth anything, as a Unix timestamp.
    ///
    /// The server decides; this is only what the link says, so a client that
    /// scanned an old invitation can say so before it connects. A token
    /// without a deadline is the older arrangement.
    pub expires_at: Option<u64>,
}

impl fmt::Debug for InviteEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteEnrollment")
            .field("client_id", &self.client_id)
            .field("token", &REDACTED)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl InviteEnrollment {
    pub fn new(client_id: &str, token: &str) -> Result<Self> {
        let client_id = client_id.trim();
        if client_id.is_empty() {
            bail!("the enrollment client id is empty");
        }
        let token = token.trim();
        if token.is_empty() {
            bail!("the enrollment token is empty");
        }
        Ok(Self {
            client_id: client_id.to_string(),
            token: SecretString::new(token.to_string()),
            expires_at: None,
        })
    }

    /// The deadline printed into the link. The server keeps its own copy, so
    /// this is a hint for whoever scanned it rather than the thing that
    /// decides whether the token still works.
    pub fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Whether this invitation has run out at `now`, both in Unix seconds.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|at| now >= at)
    }

    /// Parameters, in the order [`EndpointInvite::to_uri`] writes them.
    pub(super) fn to_params(&self) -> Vec<(&'static str, String)> {
        let mut params = vec![
            ("client", self.client_id.clone()),
            ("enroll", self.token.expose_secret_cloned()),
        ];
        if let Some(expires_at) = self.expires_at {
            params.push(("exp", expires_at.to_string()));
        }
        params
    }
}

/// The enrollment block of the invite, if any.
///
/// `enroll` is only meaningful in a v=2 code: an app that understands v=1
/// ignores unknown parameters, so a token smuggled into a v=1 code would be
/// dropped silently and the scan would import a credential-less endpoint.
pub(super) fn enrollment_from_params(
    params: &QueryParams,
    version: u32,
) -> Result<Option<InviteEnrollment>> {
    let Some(token) = params.first("enroll") else {
        return Ok(None);
    };
    if version < ENROLLMENT_INVITE_VERSION {
        bail!("the invite carries an enrollment token but is version {version}");
    }
    // Both spellings, not just `secret`: `otpauth` is the parameter an app
    // that copied an otpauth:// URI into the link would carry, and it is a
    // secret by another name. Letting it through yields an invite holding a
    // credential *and* a token for one that is about to be issued, which is
    // two answers to "what does this client authenticate with".
    if params.first("secret").is_some() || params.first("otpauth").is_some() {
        bail!("the invite carries both an enrollment token and a 2FA secret");
    }
    let Some(client_id) = params.first("client") else {
        bail!("the invite carries an enrollment token but no client id");
    };
    let mut enrollment = InviteEnrollment::new(client_id, token)?;
    if let Some(expires_at) = params.first("exp") {
        enrollment.expires_at = Some(expires_at.parse().map_err(|_| {
            anyhow::anyhow!("the invite carries an unreadable expiration time {expires_at:?}")
        })?);
    }
    Ok(Some(enrollment))
}

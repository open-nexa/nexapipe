//! The invite itself: what the link carries, and how it is read back.
//!
//! The target is either a bare Node ID or a ticket, and everything else is
//! the optional luggage: a name, the domains to route, a relay hint, and the
//! credential.

use std::fmt;

use anyhow::{Result, bail};
use iroh::EndpointId;
use iroh_tickets::endpoint::EndpointTicket;

use super::credential::{InviteEnrollment, InviteTotp, enrollment_from_params};
use super::totp::totp_from_params;
use super::uri::{comma_list, normalize_domains, parse_query, percent_decode, percent_encode};
use super::{
    ENROLLMENT_INVITE_VERSION, INVITE_SCHEME, INVITE_VERSION, MAX_URI_LEN, NODE_ID_HOST,
    TICKET_HOST,
};

/// Whether a relay hint names a relay this client could reach.
///
/// The hint is only a hint — the URL is applied later, and a hint that names
/// nothing usable is dropped rather than obeyed. But "usable" is a question
/// with an answer, and the answer is not "the URL parser accepted it":
///
/// - the scheme has to be one the relay code can dial — `https` and `http`,
///   because a self-hosted relay over plain HTTP is a supported deployment,
///   and `wss` and `ws` for the same reason;
/// - it has to name a host;
/// - it must not name an n0-operated relay, for the reason
///   [`crate::relay::RelayModeSpec`] refuses one.
pub(super) fn is_usable_relay_hint(relay: &str) -> bool {
    let Ok(url) = relay.parse::<iroh::RelayUrl>() else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        return false;
    }
    if url.host_str().is_none_or(str::is_empty) {
        return false;
    }
    !crate::relay::is_n0_relay(&url)
}

/// Where [`EndpointInvite::target`] points: either a stable Node ID, which needs
/// discovery to become an address, or a ticket that already carries addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointTarget {
    /// 64 hex characters identifying the endpoint.
    NodeId(String),
    /// A full endpoint ticket, validated on parse but kept verbatim so decision
    /// logic elsewhere (relay mode, address pinning) can inspect it as text.
    Ticket(String),
}

impl EndpointTarget {
    /// The node ID of a [`Self::NodeId`] target; tickets are opaque here.
    pub fn node_id(&self) -> Option<EndpointId> {
        match self {
            Self::NodeId(id) => id.parse().ok(),
            Self::Ticket(_) => None,
        }
    }

    /// The host component this target is written as.
    pub fn host(&self) -> &'static str {
        match self {
            Self::NodeId(_) => NODE_ID_HOST,
            Self::Ticket(_) => TICKET_HOST,
        }
    }

    /// Builds a Node ID target, rejecting anything iroh would not accept.
    pub fn node_id_target(id: &str) -> Result<Self> {
        let trimmed = id.trim();
        trimmed
            .parse::<EndpointId>()
            .map_err(|e| anyhow::anyhow!("{trimmed:?} is not a Node ID ({e})"))?;
        Ok(Self::NodeId(trimmed.to_string()))
    }

    /// Builds a ticket target, rejecting strings that are not tickets.
    pub fn ticket_target(ticket: &str) -> Result<Self> {
        let trimmed = ticket.trim();
        trimmed
            .parse::<EndpointTicket>()
            .map_err(|e| anyhow::anyhow!("not a valid endpoint ticket ({e})"))?;
        Ok(Self::Ticket(trimmed.to_string()))
    }

    /// The value as it appears after the `/` of the link.
    fn as_str(&self) -> &str {
        match self {
            Self::NodeId(id) => id,
            Self::Ticket(ticket) => ticket,
        }
    }
}

impl fmt::Display for EndpointTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A complete endpoint invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInvite {
    pub target: EndpointTarget,
    pub name: Option<String>,
    pub domains: Vec<String>,
    pub relay: Option<String>,
    pub totp: Option<InviteTotp>,
    /// Set instead of [`Self::totp`] by an invite that hands out an enrollment
    /// token; the two are mutually exclusive by construction.
    pub enrollment: Option<InviteEnrollment>,
}

impl EndpointInvite {
    /// An invite for `target` routing `domains`, with nothing optional set.
    pub fn new(target: EndpointTarget, domains: &[String]) -> Result<Self> {
        Ok(Self {
            target,
            name: None,
            domains: normalize_domains(domains)?,
            relay: None,
            totp: None,
            enrollment: None,
        })
    }

    /// Labels the endpoint. Empty names are dropped rather than erroring.
    pub fn with_name(mut self, name: &str) -> Self {
        let name = name.trim();
        self.name = (!name.is_empty()).then(|| name.to_string());
        self
    }

    /// Adds a relay hint. A hint that names no usable relay is ignored, not
    /// trusted.
    pub fn with_relay(mut self, relay: Option<&str>) -> Self {
        match relay.map(str::trim) {
            Some(relay) if !relay.is_empty() && is_usable_relay_hint(relay) => {
                self.relay = Some(relay.to_string());
            }
            _ => self.relay = None,
        }
        self
    }

    /// Attaches 2FA credentials.
    ///
    /// Clears any enrollment: an invite hands out either the secret or a token
    /// standing in for it, never both.
    pub fn with_totp(mut self, totp: Option<InviteTotp>) -> Self {
        if totp.is_some() {
            self.enrollment = None;
        }
        self.totp = totp;
        self
    }

    /// Attaches a one-time enrollment token instead of the credentials.
    ///
    /// Clears any [`InviteTotp`] for the same reason [`Self::with_totp`] clears
    /// the enrollment.
    pub fn with_enrollment(mut self, enrollment: Option<InviteEnrollment>) -> Self {
        if enrollment.is_some() {
            self.totp = None;
        }
        self.enrollment = enrollment;
        self
    }

    /// Renders the canonical link. Optional fields that are unset or empty are
    /// left out, so two invites with the same shape always compare equal.
    pub fn to_uri(&self) -> String {
        // v=2 says "this code carries an enrollment token", and v=1 says it
        // does not, so an app that only knows v=1 refuses a v=2 code instead of
        // reading it as an endpoint share with the credentials missing.
        let version = if self.enrollment.is_some() {
            ENROLLMENT_INVITE_VERSION
        } else {
            INVITE_VERSION
        };
        let mut params: Vec<(&str, String)> = vec![("v", version.to_string())];

        if let Some(name) = &self.name {
            params.push(("name", name.clone()));
        }
        if !self.domains.is_empty() {
            params.push(("domains", self.domains.join(",")));
        }
        if let Some(relay) = &self.relay {
            params.push(("relay", relay.clone()));
        }
        if let Some(totp) = &self.totp {
            params.extend(totp.to_params());
        }
        if let Some(enrollment) = &self.enrollment {
            params.extend(enrollment.to_params());
        }

        let query = params
            .iter()
            .map(|(key, value)| format!("{key}={}", percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&");

        format!(
            "{scheme}://{host}/{value}?{query}",
            scheme = INVITE_SCHEME,
            host = self.target.host(),
            value = percent_encode(self.target.as_str()),
        )
    }

    /// Reads back a link produced by [`Self::to_uri`].
    pub fn from_uri(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        // A code past the hard limit is not a code anybody will read, and
        // parsing it is work an attacker gets for free.
        if raw.len() > MAX_URI_LEN {
            anyhow::bail!(
                "the invite code is {} bytes, past the {MAX_URI_LEN} byte limit",
                raw.len()
            );
        }
        let prefix = format!("{INVITE_SCHEME}://");
        if !raw
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(&prefix))
        {
            bail!("not a {INVITE_SCHEME}:// invite code");
        }
        let body = &raw[prefix.len()..];

        // A trailing fragment is not part of the code; some QR encoders add one
        // when the payload is pasted into a browser-like URL.
        let body = body.split('#').next().unwrap_or(body);
        let (path, query) = match body.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (body, None),
        };

        // One empty segment is tolerated: a link typed into a browser-like
        // field often comes back as `.../<node-id>/?v=1`.
        let (host, value) = path.split_once('/').unwrap_or((path, ""));
        let target = match_percent_host(host, &percent_decode(value.trim_end_matches('/'))?)?;

        let params = query.map(parse_query).transpose()?.unwrap_or_default();
        // A version is not decoration: v=2 codes carry a token where v=1 codes
        // carry a secret, so accepting an unknown version is how a newer code
        // comes to be read as an older one with its credentials missing.
        let version = match params.first("v") {
            Some(version) => {
                let version: u32 = version
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invite version {version:?} is not a number"))?;
                if version != INVITE_VERSION && version != ENROLLMENT_INVITE_VERSION {
                    bail!(
                        "unsupported invite version {version} (this build understands \
                         {INVITE_VERSION} and {ENROLLMENT_INVITE_VERSION})"
                    );
                }
                version
            }
            None => INVITE_VERSION,
        };

        let domains = params
            .first("domains")
            .map(comma_list)
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            target,
            name: params.first("name").map(|name| name.trim().to_string()),
            domains: normalize_domains(&domains)?,
            relay: match params.first("relay").map(str::trim) {
                Some(relay) if !relay.is_empty() => {
                    if !is_usable_relay_hint(relay) {
                        anyhow::bail!(
                            "the relay hint {relay:?} is invalid: it does not name a relay this \
                             client can reach"
                        );
                    }
                    Some(relay.to_string())
                }
                _ => None,
            },
            totp: totp_from_params(&params)?,
            enrollment: enrollment_from_params(&params, version)?,
        })
    }

    /// Whether this invite hands out a token instead of a secret.
    pub fn is_enrollment(&self) -> bool {
        self.enrollment.is_some()
    }

    /// Warnings worth showing right after an import.
    pub fn client_warnings(&self) -> Vec<String> {
        self.totp
            .as_ref()
            .map(|totp| totp.client_warnings())
            .unwrap_or_default()
    }
}

/// Builds a target out of the host component and the decoded path.
fn match_percent_host(host: &str, value: &str) -> Result<EndpointTarget> {
    let host = host.trim();
    if host.eq_ignore_ascii_case(NODE_ID_HOST) {
        EndpointTarget::node_id_target(value)
    } else if host.eq_ignore_ascii_case(TICKET_HOST) {
        EndpointTarget::ticket_target(value)
    } else {
        bail!("unknown invite kind {host:?} (expected {NODE_ID_HOST:?} or {TICKET_HOST:?})");
    }
}

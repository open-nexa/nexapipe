//! The device invitation: one expiring link, no device name from the operator.
//!
//! A device is known by the fingerprint of its key, so there is nothing for an
//! operator to name when they invite one. What the operator hands out is a
//! one-time token with a deadline; the device says what it is when it connects.

use crate::Cli;

use nexapipe::storage::Storage;
use nexapipe_client::provisioning::{EndpointTarget, InviteEnrollment, RECOMMENDED_URI_LIMIT};
use nexapipe_proto::secret::SecretString;

use super::client::stamp;
use super::config::toml_key;
use super::invite::{build_invite_base, create_client_for_invite};
use super::qr::render_qr;

/// The invitation's default lifetime, and the longest one accepted.
pub(super) const DEFAULT_TTL_SECS: u64 = 15 * 60;
const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Prints a temporary, one-time invitation for a device to enroll under
/// `client_id`.
///
/// The token is written before the link is printed: a link whose token the
/// server does not know would be refused on first connect. Generating another
/// invitation replaces the outstanding one, which is how a link that went
/// astray is revoked.
pub(crate) async fn invite_device(
    cli: &Cli,
    storage: &dyn Storage,
    client_id: &str,
    ttl: Option<&str>,
    domains: &[String],
    relay: Option<&str>,
    create_client: bool,
) -> anyhow::Result<()> {
    let client_id = client_id.trim();
    if !nexapipe::auth::is_presentable_client_id(client_id) {
        anyhow::bail!(
            "client id {client_id:?} is printable ASCII of at most {} characters and not empty — \
             it is the key under [auth.clients] and the subject of every log line about it",
            nexapipe::auth::MAX_CLIENT_ID_LEN
        );
    }
    let ttl_secs = match ttl {
        Some(value) => parse_ttl(value)?,
        None => DEFAULT_TTL_SECS,
    };

    // The endpoint checks are the same as for any other invitation that
    // carries a credential: a token sent to another endpoint is a leak.
    let base = build_invite_base(cli, storage, true, domains, relay).await?;
    let mut invite = base.invite;
    let auth_config = base.auth_config;

    if !auth_config.clients.contains_key(client_id) {
        if !create_client {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{}] section in {}; add the client \
                 first with `nexapipe client add {client_id}`, or pass --create-client",
                toml_key(client_id),
                storage.describe()
            );
        }
        create_client_for_invite(storage, client_id, &auth_config).await?;
    }

    let now = now_secs();
    let expires_at = now
        .checked_add(ttl_secs)
        .ok_or_else(|| anyhow::anyhow!("the invitation deadline overflows the Unix clock"))?;
    let token = nexapipe::auth::generate_enrollment_token();
    storage
        .write_pending_enrollment(
            client_id,
            &SecretString::new(token.clone()),
            Some(expires_at),
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "could not record the enrollment token in {} ({e}); without it the link would \
                 be refused on first connect",
                storage.describe()
            )
        })?;

    invite = invite.with_enrollment(Some(
        InviteEnrollment::new(client_id, &token)?.with_expiry(expires_at),
    ));
    let link = invite.to_uri();

    println!();
    println!("Device invitation");
    println!("  Client      {client_id}");
    println!(
        "  Expires     {} ({} from now)",
        stamp(Some(expires_at as i64)),
        ttl.map(str::to_string).unwrap_or_else(|| "15m".to_string())
    );
    println!("  Endpoint    {}", invite.target);
    if !invite.domains.is_empty() {
        println!(
            "  Domains     {} ({})",
            invite.domains.join(", "),
            base.domains_source
        );
    }
    if let Some(relay) = &invite.relay {
        println!("  Relay       {relay}");
    }
    if !base.config_loaded {
        println!(
            "              ({} was not read, built-in defaults used)",
            storage.describe()
        );
    }
    println!();
    println!("The first device to scan this trades the token for a credential of its own.");
    println!("No device name is needed: the device reports its key and its details when it");
    println!("connects, and the server files it under the fingerprint of that key.");
    println!("Generating another invitation revokes this one. After the deadline it is worth");
    println!("nothing, and the server refuses it without counting it as a guessed token.");
    println!();

    if !auth_config.enabled {
        eprintln!(
            "warning: [auth] enabled is false in {}, so the server never runs the 2FA handshake \
             and this invitation can never be exchanged",
            storage.describe()
        );
    }
    if matches!(invite.target, EndpointTarget::NodeId(_))
        && base
            .proxy_config
            .as_ref()
            .and_then(|config| config.iroh.as_ref())
            .and_then(|iroh| iroh.discovery.as_deref())
            .is_some_and(|value| value.trim() == "none")
    {
        eprintln!(
            "warning: [iroh] discovery = \"none\" is set, so a Node ID invite cannot be resolved; \
             pass --invite-ticket <TICKET> to put the addresses in the link"
        );
    }
    if invite.domains.is_empty() {
        eprintln!("warning: the invite carries no domains, pass --domains to route traffic");
    }
    if link.len() > RECOMMENDED_URI_LIMIT {
        eprintln!(
            "warning: the invite is {} characters long; that needs a dense QR code, keep the \
             domain list short",
            link.len()
        );
    }

    println!("Invite URI, to paste into the app:");
    println!("  {link}");
    println!();
    render_qr(
        &link,
        cli,
        "Scan this with the NexaPipe app (add endpoint -> scan):",
    )?;
    println!("Scanning imports the endpoint and a one-time invitation. The device enrolls on");
    println!("its first connection; this link stops working once it has been used.");
    Ok(())
}

/// Seconds since the Unix epoch, shared with the server's deadline rules.
pub(super) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// A duration as the operator writes it: a positive number with an `s`, `m`,
/// `h` or `d` suffix, or a bare number of seconds.
fn parse_ttl(value: &str) -> anyhow::Result<u64> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("the invite lifetime is empty; write it as 15m, 2h or 30m");
    }
    let (number, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1u64),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 60 * 60),
        Some(b'd') => (&value[..value.len() - 1], 24 * 60 * 60),
        _ => (value, 1u64),
    };
    let amount: u64 = number.parse().map_err(|_| {
        anyhow::anyhow!("the invite lifetime {value:?} is not a number followed by s, m, h or d")
    })?;
    let secs = amount
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("the invite lifetime {value:?} is too long"))?;
    if secs == 0 || secs > MAX_TTL_SECS {
        anyhow::bail!(
            "the invite lifetime must be between 1s and {}d; {value:?} is out of range",
            MAX_TTL_SECS / (24 * 60 * 60)
        );
    }
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_lifetime_keeps_its_unit() {
        assert_eq!(parse_ttl("30s").unwrap(), 30);
        assert_eq!(parse_ttl("15m").unwrap(), 900);
        assert_eq!(parse_ttl("2h").unwrap(), 7200);
        assert_eq!(parse_ttl("1d").unwrap(), 86_400);
        assert_eq!(parse_ttl("45").unwrap(), 45);
        assert_eq!(parse_ttl(" 10m ").unwrap(), 600);
    }

    #[test]
    fn a_lifetime_has_to_be_positive_and_finite() {
        for bad in [
            "",
            "0",
            "0m",
            "-1m",
            "abc",
            "1w",
            "31d",
            "999999999999999999999d",
        ] {
            assert!(parse_ttl(bad).is_err(), "{bad:?} should be refused");
        }
    }
}

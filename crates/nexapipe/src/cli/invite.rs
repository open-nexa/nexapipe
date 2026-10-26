//! The endpoint invite: one scannable `nexapipe://` link carrying the
//! endpoint, its domains and, when asked for, the credentials to reach it.

use crate::Cli;

use iroh::SecretKey;
use nexapipe::auth::AuthConfig;
use nexapipe::config::ProxyConfig;
use nexapipe::storage::Storage;
use nexapipe_client::relay::RelayModeSpec;
use nexapipe_proto::secret::SecretString;

use super::config::{load_config_pair, toml_key};
use super::qr::render_qr;

/// Prints everything a client needs to reach this endpoint in one scannable
/// `nexapipe://` invite: the endpoint identity, the domains it serves and, when
/// `--client` names one, the 2FA credentials to authenticate with.
///
/// The identity comes from `[iroh] secret_key` when it is set, which is the same
/// key the server starts with, so the printed code stays valid across restarts;
/// without it the endpoint ID would change on every start and the code would be
/// worthless, so the flag is required instead of silently printing a throwaway.
pub(crate) async fn print_endpoint_invite(cli: &Cli, storage: &dyn Storage) -> anyhow::Result<()> {
    use nexapipe_client::auth::TotpAlgorithm;
    use nexapipe_client::provisioning::{
        EndpointInvite, EndpointTarget, InviteEnrollment, InviteTotp, RECOMMENDED_URI_LIMIT,
    };

    let (proxy_config, auth_config, config_loaded) = load_config_pair(storage).await;

    let target = match &cli.endpoint_id {
        Some(id) => EndpointTarget::node_id_target(id)?,
        None => {
            let secret_key = proxy_config
                .as_ref()
                .and_then(|config| config.iroh.as_ref())
                .and_then(|iroh| {
                    iroh.secret_key
                        .as_ref()
                        .map(|key| key.expose_secret().as_str())
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no endpoint identity in {}: set [iroh] secret_key \
                         (see `nexapipe --generate-secret`) or pass --endpoint-id",
                        storage.describe()
                    )
                })?;
            let public: iroh::PublicKey = secret_key
                .parse::<SecretKey>()
                .map_err(|e| {
                    anyhow::anyhow!(
                        "[iroh] secret_key in {} is invalid ({e})",
                        storage.describe()
                    )
                })?
                .public();
            EndpointTarget::node_id_target(&public.to_string())?
        }
    };

    let (domains, domains_source) = invite_domains(&cli.invite_domains, proxy_config.as_ref());
    // Only a relay this endpoint is actually pinned to is worth advertising: with `default`
    // the home relay is chosen at runtime and can move, and with `disabled` there is none.
    // Read off the resolved spec rather than the raw strings, so a `"custom"` that is really
    // unusable (no URL, n0-operated URL) does not end up in the invite.
    let relay = cli.invite_relay.clone().or_else(|| {
        let iroh = proxy_config
            .as_ref()
            .and_then(|config| config.iroh.as_ref())?;
        let spec = RelayModeSpec::parse(
            iroh.relay_mode.as_deref(),
            iroh.relay_url.as_deref(),
            iroh.relay_auth_token
                .as_ref()
                .map(|token| token.expose_secret().as_str()),
        )
        .ok()
        .flatten()?;
        match spec {
            RelayModeSpec::Custom { .. } => iroh.relay_url.clone(),
            _ => None,
        }
    });

    let mut invite = EndpointInvite::new(target, &domains)?
        .with_relay(relay.as_deref())
        .with_name(cli.invite_name.as_deref().unwrap_or_default());

    let mut two_factor_enabled = false;
    // Kept past the block below: the banner has to name the client whose
    // credential it is handing out.
    let mut enrolled_client: Option<String> = None;
    // Whether the one-time form was the default for a client this run created
    // rather than something `--registration` asked for.
    let mut enrollment_is_default = false;
    // Whether this run created the client at all. Kept past the block below
    // because the output has to say why the one-time form was not used.
    let mut client_created = false;
    // `--generate-invite` without a value is a valid request for an endpoint
    // share with no 2FA in it, so an empty client id skips the lookup instead
    // of looking up a client literally named "".
    if let Some(client_id) = cli
        .generate_invite
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        // The secret this invite will carry: the one already in the config, or
        // one created on the spot by `--create-client`. Held as a `String`
        // rather than borrowed from `auth_config` because the creation branch
        // below has no client to borrow from yet.
        //
        // `created` says which of the two it was, and that is what decides the
        // form of the invite: a secret minted a moment ago is in nobody's
        // hands.
        let (secret, created) = match auth_config.clients.get(client_id) {
            Some(client) => (client.secret.clone(), false),
            None if cli.create_client => (
                SecretString::new(
                    create_client_for_invite(storage, client_id, &auth_config).await?,
                ),
                true,
            ),
            None => {
                let known = if auth_config.clients.is_empty() {
                    " (no client is configured yet)".to_string()
                } else {
                    let mut names: Vec<&str> =
                        auth_config.clients.keys().map(String::as_str).collect();
                    names.sort_unstable();
                    format!(" (configured: {})", names.join(", "))
                };
                anyhow::bail!(
                    "client \"{}\" has no [auth.clients.{}] section in {}{}; \
                     pass --create-client to make one now, or run --generate-2fa {} first",
                    client_id,
                    toml_key(client_id),
                    storage.describe(),
                    known,
                    client_id
                )
            }
        };
        client_created = created;

        // Which form the invite takes: the one-time enrollment token, or the
        // secret itself.
        //
        // `--registration` asks for the token, and so does a client this run
        // creates. That client's secret was minted a moment ago and no device
        // is enrolled with it, so trading the token for a fresh one on first
        // connect costs nothing — and it leaves the link a credential only
        // until it is used, which is the whole difference between the two
        // forms.
        //
        // A client that exists already keeps the secret its devices are
        // enrolled with: the token would replace that secret, and every device
        // sharing it would have to scan again. That link is a password, and
        // the output says so, loudly.
        //
        // The token is only worth anything while the server runs the 2FA
        // handshake, so with 2FA off the secret form stands — the server would
        // not ask for a credential at all, and the token could never be
        // exchanged. The warning below says that too.
        let one_time = cli.registration || (created && auth_config.enabled);

        if one_time {
            // An enrollment invite has to be written down before it is printed:
            // the token is only worth anything if the server knows to accept it,
            // and generating a second one is how a link that went astray is
            // revoked — the old token is replaced, not added to.
            let token = nexapipe::auth::generate_enrollment_token();
            storage
                .write_pending_enrollment(client_id, &SecretString::new(token.clone()))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "could not record the enrollment token in {} ({e}); without it the \
                     invite would be refused on first connect",
                        storage.describe()
                    )
                })?;
            let enrollment = InviteEnrollment::new(client_id, &token)?;
            enrolled_client = Some(client_id.to_string());
            // Whether the token was asked for or is the default for a client
            // this run created: the output says which, because the two differ
            // in what the link does to the secret it carries.
            enrollment_is_default = created && !cli.registration;
            invite = invite.with_enrollment(Some(enrollment));
        } else {
            let issuer = if auth_config.issuer.is_empty() {
                nexapipe::auth::DEFAULT_ISSUER
            } else {
                auth_config.issuer.as_str()
            };
            let totp = InviteTotp::with_params(
                issuer,
                client_id,
                secret.expose_secret(),
                TotpAlgorithm::from_name(auth_config.algorithm.name()),
                auth_config.digits,
                auth_config.time_step,
            )?;
            two_factor_enabled = true;
            enrolled_client = Some(client_id.to_string());
            invite = invite.with_totp(Some(totp));
        }
    } else if cli.registration {
        anyhow::bail!(
            "--registration needs a CLIENT_ID: --generate-invite <CLIENT_ID> --registration"
        );
    }

    let link = invite.to_uri();

    println!();
    println!("Endpoint invitation");
    println!("  Endpoint    {}", invite.target);
    println!(
        "              {}",
        match invite.target {
            EndpointTarget::NodeId(_) => "Node ID, the app resolves the addresses itself",
            EndpointTarget::Ticket(_) => "ticket, the addresses travel with the code",
        }
    );
    if !invite.domains.is_empty() {
        println!("  Domains     {}", invite.domains.join(", "));
        println!("              ({domains_source})");
    }
    if let Some(relay) = &invite.relay {
        println!("  Relay       {relay}");
    }
    if let Some(name) = &invite.name {
        println!("  Label       {name}");
    }
    if let Some(totp) = &invite.totp {
        println!(
            "  2FA         client \"{}\", {}, {} digits, {} second step",
            totp.client_id,
            totp.algorithm.name().to_ascii_uppercase(),
            totp.digits,
            totp.period
        );
    }
    if !config_loaded {
        println!(
            "              ({} was not read, built-in defaults used)",
            storage.describe()
        );
    }
    println!();

    for warning in invite.client_warnings() {
        eprintln!("warning: {warning}");
    }
    // Both invite shapes, not just the one carrying a secret: with
    // `enabled = false` the server never runs the handshake, so an enrollment
    // token cannot be exchanged either — and that failure is silent, because
    // nothing ever asks the app for a code.
    if !auth_config.enabled && invite.enrollment.is_some() {
        eprintln!(
            "warning: [auth] enabled is false in {}, so the server never runs the 2FA \
             handshake and the enrollment token in this invite can never be exchanged",
            storage.describe()
        );
    } else if two_factor_enabled && !auth_config.enabled {
        eprintln!(
            "warning: [auth] enabled is false in {}, so the server will not ask for \
             these credentials even though the invite configures the app to send them",
            storage.describe()
        );
    }
    if invite.domains.is_empty() {
        eprintln!("warning: the invite carries no domains, pass --invite-domains to route traffic");
    }
    if link.len() > RECOMMENDED_URI_LIMIT {
        eprintln!(
            "warning: the invite is {} characters long; that needs a dense QR code, \
             keep the domain list short",
            link.len()
        );
    }

    // Printed between the summary and the URI, because the usual fate of a link
    // is a chat window: by the time it is pasted, "this is a password" has to
    // already have been said, and the one-line note at the end of the output is
    // easy to scroll past when all the reader wants is the code.
    if let Some(client) = &enrolled_client
        && two_factor_enabled
    {
        println!("*******************************************************************");
        println!("* THIS LINK IS A CREDENTIAL, NOT JUST AN ADDRESS.");
        println!("*");
        println!("* It carries the TOTP secret in the clear, so anyone who scans or");
        println!("* copies it can authenticate as \"{client}\" until that secret is");
        println!("* rotated. Hand it to one device over one channel, then let it go.");
        println!("*");
        println!("* The one-time form: nexapipe --generate-invite {client} --registration");
        println!("* puts an enrollment token in the link instead, and the link stops");
        println!("* being a credential the moment the first device scans it.");
        println!("*");
        println!("* To revoke it: nexapipe --generate-2fa {client} --force");
        println!("* That rotates the secret, and every device enrolled with the old");
        println!("* one has to scan again — there is no per-device revocation.");
        println!("*******************************************************************");
        println!();
        // Said on stderr as well, because the usual way to keep an invite is to
        // redirect stdout into a file — and a warning that goes into that file
        // is a warning nobody reads before the link is shared.
        eprintln!(
            "warning: this invite carries the long-lived TOTP secret of client \"{client}\"; \
             `nexapipe --generate-invite {client} --registration` prints a one-time enrollment \
             token instead, and that link stops being a credential once it has been used"
        );
        // The one-time form was available and was not used, so the reason is
        // here rather than left to be guessed at.
        if client_created && !auth_config.enabled {
            eprintln!(
                "warning: the one-time enrollment form was not used for this client because \
                 [auth] enabled is false in {}, so the server never runs the 2FA handshake and \
                 an enrollment token could never be exchanged",
                storage.describe()
            );
        }
    }
    if let Some(enrollment) = &invite.enrollment {
        println!("-------------------------------------------------------------------");
        println!(" THIS LINK CARRIES AN ENROLLMENT TOKEN, NOT THE SECRET.");
        println!();
        println!(" The first device to scan it trades the token for a freshly");
        println!(
            " generated secret for client \"{}\", and the token is spent: a",
            enrollment.client_id
        );
        println!(" copy of this link stops being a credential the moment it is used.");
        println!(" Enrolling replaces the credential the device that scans it");
        println!(" will use: one that names a device gets a secret of its own,");
        println!(" and one that does not gets this client's shared secret —");
        println!(" which every device already using it has to scan again for.");
        println!();
        if enrollment_is_default {
            println!(" This client did not exist before this run, so the token is what");
            println!(" the link carries: the secret it minted was in nobody's hands, and");
            println!(" nothing is lost by the first device trading the token for a");
            println!(" fresh one of its own.");
            println!();
        }
        println!(" A link you did not deliver is revoked by generating another one");
        println!(" -- this command again -- which replaces the outstanding token.");
        println!("-------------------------------------------------------------------");
        println!();
    }

    println!("Invite URI, to paste into the app:");
    println!("  {link}");
    println!();

    render_qr(
        &link,
        cli,
        "Scan this with the NexaPipe app (add endpoint -> scan):",
    )?;

    if invite.is_enrollment() {
        println!("Scanning imports the endpoint, the domains and a one-time enrollment");
        println!("token; the first connect turns it into the real credential.");
    } else if two_factor_enabled {
        println!("Scanning imports the endpoint, the domains and the 2FA credentials in one");
        println!("step.");
    } else {
        println!("Scanning imports the endpoint and its domains. Pass a client id to");
        println!("--generate-invite to put that client's 2FA credentials in the code too");
        println!("(add --create-client when that client does not exist yet).");
    }

    Ok(())
}

/// Generates a TOTP secret for a client that does not exist yet, writes it into
/// the config, and returns it so the invite being built can carry it.
///
/// This is what `--create-client` does, and it only ever runs for a client that
/// is missing **entirely**: a section that exists but holds no secret is a
/// broken file, not an invitation to fill in the blank, and the caller's lookup
/// handles that case by refusing.
///
/// Unlike [`save_generated_secret`](super::enrollment::save_generated_secret) a failure here is fatal. That one prints a
/// secret the operator can paste by hand because `--generate-2fa` has nothing
/// riding on the file; an invite with `--create-client` is a promise that the
/// server will recognise the client, so a secret that never reached the disk
/// would produce a link that is refused on first connect.
async fn create_client_for_invite(
    storage: &dyn Storage,
    client_id: &str,
    auth_config: &AuthConfig,
) -> anyhow::Result<String> {
    let secret = nexapipe::auth::TotpValidator::generate_secret();
    storage
        .write_client_secret(client_id, &SecretString::new(secret.clone()), false)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "could not create client \"{client_id}\" in {} ({e}); without the section there \
                 is nothing for the invite to authenticate against",
                storage.describe()
            )
        })?;

    println!(
        "Created [auth.clients.{}] in {} with a newly generated secret.",
        toml_key(client_id),
        storage.describe()
    );
    // Same warning `--generate-2fa` prints: the secret on disk is worthless
    // until the server is allowed to ask for it.
    if !auth_config.enabled {
        eprintln!(
            "warning: [auth] enabled is not true in {}, so the server will not ask for this \
             secret; add enabled = true under [auth]",
            storage.describe()
        );
    }
    println!("The 2FA settings are read once at startup, so restart the server before the");
    println!("client above can connect.");
    println!();

    Ok(secret)
}

/// Where the domain list comes from, so the printed invite says so.
pub(super) fn invite_domains(
    explicit: &[String],
    config: Option<&ProxyConfig>,
) -> (Vec<String>, String) {
    if !explicit.is_empty() {
        return (explicit.to_vec(), "from --invite-domains".to_string());
    }

    if let Some(local_proxy) = config.and_then(|config| config.local_proxy.as_ref())
        && !local_proxy.proxy_domains.is_empty()
    {
        return (
            local_proxy.proxy_domains.clone(),
            "from [local_proxy] proxy_domains".to_string(),
        );
    }

    let routed: Vec<String> = config
        .and_then(|config| config.routes.as_ref())
        .map(|routes| {
            routes
                .iter()
                .map(|route| route.host_pattern.trim().to_string())
                .filter(|host| !host.is_empty() && host != "*")
                .collect()
        })
        .unwrap_or_default();

    if !routed.is_empty() {
        (routed, "from the [[routes]] host patterns".to_string())
    } else {
        (Vec::new(), "none configured".to_string())
    }
}

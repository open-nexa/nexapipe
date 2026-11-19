//! The command line: the eight things this binary can be asked to do, and the
//! flags that asked for the same things before they were commands.
//!
//! Every spelling — the command, or the flag it replaced — is folded into the
//! flat fields `Cli` has always carried before anything is dispatched, so there
//! is one implementation per behaviour rather than one per spelling. The fold is
//! also where the old flags are reported: one line on stderr, naming the command
//! to reach for instead.
//!
//! The internal request keeps the older names — `cli.generate_invite` for the
//! `invite` command, `cli.generate_2fa` for `client enroll` — because the
//! credential modules read those fields and were not rewritten for this. When
//! they are next rewritten for another reason, the request can be renamed with
//! them.

use clap::Subcommand;

use crate::Cli;

/// The command groups, as clap parses them.
#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Start the server — what `nexapipe` does with nothing on it
    Serve {
        /// Run in client local proxy mode instead of serving
        #[arg(long)]
        local_proxy: bool,
    },

    /// Ask the instance at [admin] listen_addr what it is doing
    Status {
        /// Print the whole answer as one JSON document instead of the grouped
        /// reading, for anything that has to parse it
        #[arg(long)]
        json: bool,
    },

    /// List, add, revoke and enroll the 2FA clients in [auth.clients]
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },

    /// Invite a device to enroll under a client without naming it
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },

    /// Print a scannable nexapipe:// invite for this endpoint
    Invite {
        /// The client whose 2FA credential goes in the invite; without one the
        /// invite carries the endpoint and its domains only
        #[arg(value_name = "CLIENT_ID")]
        client_id: Option<String>,

        /// Create the client when it does not exist yet, generating and
        /// writing its TOTP secret in the same run
        #[arg(long)]
        create_client: bool,

        /// Domains to put in the invite (default: [local_proxy] proxy_domains,
        /// else the route hosts)
        #[arg(long = "domains", value_delimiter = ',', value_name = "DOMAINS")]
        domains: Vec<String>,

        /// Human readable label stored alongside the endpoint in the invite
        #[arg(long = "name", value_name = "NAME")]
        name: Option<String>,

        /// Relay URL to put in the invite (default: [iroh] relay_url)
        #[arg(long = "relay", value_name = "URL")]
        relay: Option<String>,
    },

    /// Draw a QR code carrying the text given
    Qr {
        /// The text the code carries: a link, a ticket, anything
        #[arg(value_name = "TEXT")]
        text: String,
    },

    /// Print a new secret key for the endpoint's identity, and write nothing
    Secret,

    /// Report the configuration the store holds, and where that store is
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

/// What the `client` command can be asked for.
#[derive(Subcommand, Debug)]
pub(crate) enum ClientAction {
    /// List the clients in [auth.clients], and the devices of each
    List {
        /// Print one JSON document instead of the reading below, for anything
        /// that has to parse it
        #[arg(long)]
        json: bool,
    },

    /// Issue a credential to a client, or to one device of it
    Add {
        /// The client id: the key under [auth.clients]
        #[arg(value_name = "CLIENT_ID")]
        client_id: String,

        /// Replaced by `nexapipe device invite`: a device is identified by its
        /// key fingerprint, not by a name the operator picks
        #[arg(long, value_name = "NAME")]
        device: Option<String>,

        /// Issue a key credential instead of a secret: the public half of an
        /// Ed25519 key pair, 64 hex characters. The device is filed under the
        /// fingerprint of this key; no --device is needed or allowed.
        #[arg(long, value_name = "HEX")]
        public_key: Option<String>,

        /// Replace the credential that is already there, enrolling out whatever
        /// is using it now
        #[arg(long)]
        force: bool,
    },

    /// Drop a client's credentials, or one device's
    Revoke {
        /// The client id: the key under [auth.clients]
        #[arg(value_name = "CLIENT_ID")]
        client_id: String,

        /// Drop only this device's credential, keeping the client and every
        /// other device of it
        #[arg(long, value_name = "NAME")]
        device: Option<String>,
    },

    /// Issue a new 2FA secret for a client, and print its QR code
    Enroll {
        /// The client the secret is issued to: the key under [auth.clients]
        #[arg(value_name = "CLIENT_ID")]
        client_id: String,

        /// Issue a new secret even when the client already has one, replacing
        /// it — every device enrolled with the old one has to scan again
        #[arg(long)]
        force: bool,
    },

    /// Print the QR code of the secret a client already has, writing nothing
    Qr {
        /// The client whose secret the code carries
        #[arg(value_name = "CLIENT_ID")]
        client_id: String,
    },
}

/// The device invitation: the one-time link a device enrolls with.
#[derive(Subcommand, Debug)]
pub(crate) enum DeviceAction {
    /// Print a one-time invitation link that expires after a short while
    Invite {
        /// The client the device will enroll under
        #[arg(long, value_name = "CLIENT_ID")]
        client: String,

        /// How long the invitation is good for: 15m by default, e.g. 30m, 2h
        #[arg(long, value_name = "DURATION")]
        ttl: Option<String>,

        /// Domains to put in the invite (default: [local_proxy] proxy_domains,
        /// else the route hosts)
        #[arg(long = "domains", value_delimiter = ',', value_name = "DOMAINS")]
        domains: Vec<String>,

        /// Relay URL to put in the invite (default: the configured pinned relay)
        #[arg(long = "relay", value_name = "URL")]
        relay: Option<String>,

        /// Create the client when it does not exist yet
        #[arg(long)]
        create_client: bool,
    },
}

/// What the `config` command can be asked for.
#[derive(Subcommand, Debug)]
pub(crate) enum ConfigAction {
    /// Print the configuration the store holds, in the format it is written in
    Show,

    /// Print the store that holds the configuration
    Path,
}

/// The request the command line adds up to, after the fold.
///
/// The data the implementations read stays on `Cli`: `Enroll` and `ShowQr`
/// carry no client id because `cli.generate_2fa` and `cli.show_2fa` do, and
/// `Invite` carries nothing because the invite's options are `cli.invite_*`.
/// That is the point of the fold — both spellings reach one implementation,
/// reading one set of fields.
#[derive(Debug, PartialEq)]
pub(crate) enum Request {
    /// Nothing to do before the server runs.
    Serve,
    Status {
        json: bool,
    },
    Clients(Clients),
    Device(DeviceInvite),
    /// `client enroll`, and the flag that used to be it.
    Enroll,
    /// `client qr`, and the flag that used to be it.
    ShowQr,
    /// `invite`, and the flag that used to be it.
    Invite,
    Secret,
    Qr(String),
    ConfigShow,
    ConfigPath,
}

/// The `client` operations that are dispatched as they are asked for.
#[derive(Debug, PartialEq)]
pub(crate) enum Clients {
    List {
        json: bool,
    },
    Add {
        client_id: String,
        device: Option<String>,
        public_key: Option<String>,
        force: bool,
    },
    Revoke {
        client_id: String,
        device: Option<String>,
    },
}

/// The device invitation's arguments.
#[derive(Debug, PartialEq)]
pub(crate) struct DeviceInvite {
    pub client_id: String,
    pub ttl: Option<String>,
    pub domains: Vec<String>,
    pub relay: Option<String>,
    pub create_client: bool,
}

/// Folds the parsed command line into one request.
///
/// Called once, before any store is opened and before anything runs, because
/// the refusals and the deprecation notices have to come first: an operator who
/// typed two requests has to be told so instead of having one of them silently
/// picked.
pub(crate) fn fold(cli: &mut Cli) -> anyhow::Result<Request> {
    // A spelling retired before this change stays retired. `--registration`
    // and `client add --device` already refuse and point at the device
    // invitation; spending the deprecation budget twice would give an operator
    // two different notices for the same thing.
    if cli.registration {
        anyhow::bail!(
            "--registration has been replaced by `nexapipe device invite --client <CLIENT_ID>`, \
             which issues a one-time token with a deadline"
        );
    }

    let command = cli.command.take();
    check_clashes(cli, command.as_ref())?;

    // Every old flag that is used says what replaced it, before anything runs.
    report_deprecated(cli);

    let request = match command {
        Some(Commands::Serve { local_proxy }) => {
            cli.local_proxy |= local_proxy;
            Request::Serve
        }
        Some(Commands::Status { json }) => Request::Status { json },
        Some(Commands::Client { action }) => match action {
            ClientAction::List { json } => Request::Clients(Clients::List { json }),
            ClientAction::Add {
                client_id,
                device,
                public_key,
                force,
            } => Request::Clients(Clients::Add {
                client_id,
                device,
                public_key,
                force,
            }),
            ClientAction::Revoke { client_id, device } => {
                Request::Clients(Clients::Revoke { client_id, device })
            }
            // Both fold into the fields the flags set, so the enrollment below
            // is the one implementation of both spellings.
            ClientAction::Enroll { client_id, force } => {
                cli.generate_2fa = Some(client_id);
                cli.force |= force;
                Request::Enroll
            }
            ClientAction::Qr { client_id } => {
                cli.show_2fa = Some(client_id);
                Request::ShowQr
            }
        },
        Some(Commands::Device { action }) => match action {
            DeviceAction::Invite {
                client,
                ttl,
                domains,
                relay,
                create_client,
            } => Request::Device(DeviceInvite {
                client_id: client,
                ttl,
                domains,
                relay,
                create_client,
            }),
        },
        Some(Commands::Invite {
            client_id,
            create_client,
            domains,
            name,
            relay,
        }) => {
            // An invite without a client id carries no credential, which is
            // what the flag's empty-value spelling asks for.
            cli.generate_invite = Some(client_id.unwrap_or_default());
            cli.create_client = create_client;
            cli.invite_domains = domains;
            cli.invite_name = name;
            cli.invite_relay = relay;
            Request::Invite
        }
        Some(Commands::Qr { text }) => Request::Qr(text),
        Some(Commands::Secret) => {
            cli.generate_secret = true;
            Request::Secret
        }
        Some(Commands::Config { action }) => match action {
            ConfigAction::Show => Request::ConfigShow,
            ConfigAction::Path => Request::ConfigPath,
        },
        // No command: the flags are the request, folded into the same one. Only
        // the action flags pick it; a modifier on its own changes nothing.
        None => {
            if cli.generate_secret {
                Request::Secret
            } else if cli.generate_2fa.is_some() {
                Request::Enroll
            } else if cli.show_2fa.is_some() {
                Request::ShowQr
            } else if cli.generate_invite.is_some() {
                Request::Invite
            } else {
                Request::Serve
            }
        }
    };

    // A ticket is only worth carrying when there is a link to carry it in.
    // `--invite-ticket` is global so `device invite` can put one in its link,
    // and on its own it would otherwise be dropped on a plain proxy start.
    if cli.invite_ticket.is_some() && !matches!(request, Request::Invite | Request::Device(_)) {
        anyhow::bail!(
            "--invite-ticket is used with `nexapipe invite` or `nexapipe device invite --client \
             <CLIENT_ID>`, which put it in the link"
        );
    }

    Ok(request)
}

/// Refuses a run that asks for two things.
///
/// Two spellings of one request are refused rather than resolved: picking one
/// silently would leave the operator reading output that does not match what
/// they typed. A command and an action flag that has nothing to do with it are
/// refused for the same reason.
fn check_clashes(cli: &Cli, command: Option<&Commands>) -> anyhow::Result<()> {
    let Some(command) = command else {
        return Ok(());
    };

    fn twice(flag: &str, with: &str) -> anyhow::Error {
        anyhow::anyhow!("asked for twice — with {flag} and with `{with}`; use one of them")
    }

    match command {
        Commands::Secret if cli.generate_secret => {
            return Err(twice("--generate-secret", "nexapipe secret"));
        }
        Commands::Client {
            action: ClientAction::Enroll { .. },
        } if cli.generate_2fa.is_some() => {
            return Err(twice(
                "--generate-2fa",
                "nexapipe client enroll <CLIENT_ID>",
            ));
        }
        // The top-level `--force` only ever modified `--generate-2fa`; with the
        // command named, the command carries its own.
        Commands::Client {
            action: ClientAction::Enroll { .. },
        } if cli.force => {
            return Err(twice(
                "--force",
                "nexapipe client enroll <CLIENT_ID> --force",
            ));
        }
        Commands::Client {
            action: ClientAction::Qr { .. },
        } if cli.show_2fa.is_some() => {
            return Err(twice("--show-2fa", "nexapipe client qr <CLIENT_ID>"));
        }
        Commands::Invite { .. } => {
            if cli.generate_invite.is_some() {
                return Err(twice("--generate-invite", "nexapipe invite [CLIENT_ID]"));
            }
            if cli.create_client {
                return Err(twice("--create-client", "nexapipe invite --create-client"));
            }
            if !cli.invite_domains.is_empty() {
                return Err(twice("--invite-domains", "nexapipe invite --domains"));
            }
            if cli.invite_name.is_some() {
                return Err(twice("--invite-name", "nexapipe invite --name"));
            }
            if cli.invite_relay.is_some() {
                return Err(twice("--invite-relay", "nexapipe invite --relay"));
            }
        }
        _ => {}
    }

    // An action flag and a command that is not the one that replaced it: two
    // requests in one run, and neither of them can be carried out.
    let different = |flag: &str| -> anyhow::Error {
        anyhow::anyhow!(
            "{flag} and `{}` are two different requests; run them separately",
            name(command)
        )
    };
    if cli.generate_secret && !matches!(command, Commands::Secret) {
        return Err(different("--generate-secret"));
    }
    if cli.generate_2fa.is_some()
        && !matches!(
            command,
            Commands::Client {
                action: ClientAction::Enroll { .. }
            }
        )
    {
        return Err(different("--generate-2fa"));
    }
    if cli.show_2fa.is_some()
        && !matches!(
            command,
            Commands::Client {
                action: ClientAction::Qr { .. }
            }
        )
    {
        return Err(different("--show-2fa"));
    }
    if cli.generate_invite.is_some() && !matches!(command, Commands::Invite { .. }) {
        return Err(different("--generate-invite"));
    }

    Ok(())
}

/// One line on stderr per old flag that is used, naming the command to copy.
///
/// stderr rather than stdout: the output of these commands is data — a secret,
/// a link, a QR code — and anything that reads it must not have a notice mixed
/// into it.
fn report_deprecated(cli: &Cli) {
    fn deprecated(flag: &str, command: &str) {
        eprintln!("warning: {flag} is deprecated; use \"{command}\" instead");
    }

    if cli.local_proxy {
        deprecated("--local-proxy", "nexapipe serve --local-proxy");
    }
    if cli.generate_secret {
        deprecated("--generate-secret", "nexapipe secret");
    }
    if cli.generate_2fa.is_some() {
        deprecated("--generate-2fa", "nexapipe client enroll <CLIENT_ID>");
    }
    if cli.show_2fa.is_some() {
        deprecated("--show-2fa", "nexapipe client qr <CLIENT_ID>");
    }
    if cli.generate_invite.is_some() {
        deprecated("--generate-invite", "nexapipe invite [CLIENT_ID]");
    }
    if cli.create_client {
        deprecated("--create-client", "nexapipe invite --create-client");
    }
    if !cli.invite_domains.is_empty() {
        deprecated("--invite-domains", "nexapipe invite --domains");
    }
    if cli.invite_name.is_some() {
        deprecated("--invite-name", "nexapipe invite --name");
    }
    if cli.invite_relay.is_some() {
        deprecated("--invite-relay", "nexapipe invite --relay");
    }
    if cli.force {
        deprecated("--force", "nexapipe client enroll <CLIENT_ID> --force");
    }
}

/// The command as the operator typed it, for a message that names it.
fn name(command: &Commands) -> &'static str {
    match command {
        Commands::Serve { .. } => "nexapipe serve",
        Commands::Status { .. } => "nexapipe status",
        Commands::Client { action } => match action {
            ClientAction::List { .. } => "nexapipe client list",
            ClientAction::Add { .. } => "nexapipe client add",
            ClientAction::Revoke { .. } => "nexapipe client revoke",
            ClientAction::Enroll { .. } => "nexapipe client enroll",
            ClientAction::Qr { .. } => "nexapipe client qr",
        },
        Commands::Device { .. } => "nexapipe device invite",
        Commands::Invite { .. } => "nexapipe invite",
        Commands::Qr { .. } => "nexapipe qr",
        Commands::Secret => "nexapipe secret",
        Commands::Config { action } => match action {
            ConfigAction::Show => "nexapipe config show",
            ConfigAction::Path => "nexapipe config path",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// The fields the fold writes, gathered so two spellings can be compared
    /// without comparing the whole of `Cli`.
    #[derive(Debug, Default, PartialEq)]
    struct Folded {
        request: Option<Request>,
        client: Option<String>,
        force: bool,
        create_client: bool,
        domains: Vec<String>,
        name: Option<String>,
        relay: Option<String>,
        ticket: Option<String>,
        local_proxy: bool,
        config_text: bool,
        config_path: bool,
    }

    fn folded(argv: &[&str]) -> Folded {
        let mut args = vec!["nexapipe"];
        args.extend_from_slice(argv);
        let mut cli = Cli::try_parse_from(&args).expect("the arguments parse");
        let request = fold(&mut cli).expect("the arguments fold");
        Folded {
            client: cli
                .generate_invite
                .clone()
                .or_else(|| cli.generate_2fa.clone())
                .or_else(|| cli.show_2fa.clone()),
            force: cli.force,
            create_client: cli.create_client,
            domains: cli.invite_domains.clone(),
            name: cli.invite_name.clone(),
            relay: cli.invite_relay.clone(),
            ticket: cli.invite_ticket.clone(),
            local_proxy: cli.local_proxy,
            config_text: matches!(request, Request::ConfigShow),
            config_path: matches!(request, Request::ConfigPath),
            request: Some(request),
        }
    }

    fn refused(argv: &[&str]) -> String {
        let mut args = vec!["nexapipe"];
        args.extend_from_slice(argv);
        let mut cli = Cli::try_parse_from(&args).expect("the arguments parse");
        format!(
            "{:#}",
            fold(&mut cli).expect_err("the arguments are refused")
        )
    }

    /// One test per old flag: the flag and the command that replaced it have to
    /// reach the same request and the same fields.
    #[test]
    fn every_old_flag_folds_into_the_command_that_replaced_it() {
        for (flag, command) in [
            (vec!["--generate-secret"], vec!["secret"]),
            (
                vec!["--generate-2fa", "phone"],
                vec!["client", "enroll", "phone"],
            ),
            (
                vec!["--generate-2fa", "phone", "--force"],
                vec!["client", "enroll", "phone", "--force"],
            ),
            (vec!["--show-2fa", "phone"], vec!["client", "qr", "phone"]),
            (vec!["--generate-invite", "phone"], vec!["invite", "phone"]),
            (vec!["--generate-invite"], vec!["invite"]),
            (
                vec![
                    "--generate-invite",
                    "phone",
                    "--create-client",
                    "--invite-domains",
                    "a.example,b.example",
                    "--invite-name",
                    "phone",
                    "--invite-relay",
                    "https://relay.example",
                ],
                vec![
                    "invite",
                    "phone",
                    "--create-client",
                    "--domains",
                    "a.example,b.example",
                    "--name",
                    "phone",
                    "--relay",
                    "https://relay.example",
                ],
            ),
            (vec!["--local-proxy"], vec!["serve", "--local-proxy"]),
        ] {
            assert_eq!(
                folded(&flag),
                folded(&command),
                "{flag:?} has to reach what {command:?} reaches"
            );
        }
    }

    /// A modifier on its own changes nothing: it is reported, and the server
    /// still starts — printing an invite for `--invite-domains a,b` would be a
    /// different command than the one the operator typed.
    #[test]
    fn a_modifier_on_its_own_starts_the_server() {
        let folded = folded(&["--invite-domains", "a.example"]);
        assert_eq!(folded.request, Some(Request::Serve));
        assert_eq!(folded.domains, vec!["a.example".to_string()]);
    }

    /// Asking twice is refused, and the refusal names both ways of asking.
    #[test]
    fn a_flag_and_its_command_are_refused_together() {
        for (argv, named) in [
            (
                vec!["--generate-invite", "phone", "invite", "phone"],
                "--generate-invite",
            ),
            (
                vec!["--generate-2fa", "phone", "client", "enroll", "phone"],
                "--generate-2fa",
            ),
            (
                vec!["--show-2fa", "phone", "client", "qr", "phone"],
                "--show-2fa",
            ),
            (vec!["--generate-secret", "secret"], "--generate-secret"),
            (
                vec![
                    "--invite-domains",
                    "a.example",
                    "invite",
                    "--domains",
                    "b.example",
                ],
                "--invite-domains",
            ),
        ] {
            let message = refused(&argv);
            assert!(message.contains(named), "{argv:?}: {message}");
            assert!(message.contains("nexapipe"), "{argv:?}: {message}");
        }
    }

    /// An action flag and an unrelated command are two requests in one run.
    #[test]
    fn an_action_flag_and_an_unrelated_command_are_refused() {
        let message = refused(&["--generate-2fa", "phone", "client", "list"]);
        assert!(message.contains("--generate-2fa"), "{message}");
        assert!(message.contains("nexapipe client list"), "{message}");
    }

    /// The retired spelling stays retired and points at the command.
    #[test]
    fn the_retired_registration_flag_points_at_the_device_invitation() {
        let message = refused(&["--generate-invite", "phone", "--registration"]);
        assert!(message.contains("device invite"), "{message}");
    }

    /// The commands that have no flag behind them.
    #[test]
    fn the_new_commands_are_requests_of_their_own() {
        assert_eq!(
            folded(&["qr", "nexapipe://endpoint"]).request,
            Some(Request::Qr("nexapipe://endpoint".to_string()))
        );
        assert!(folded(&["config", "show"]).config_text);
        assert!(folded(&["config", "path"]).config_path);
        assert_eq!(
            folded(&["status", "--json"]).request,
            Some(Request::Status { json: true })
        );
        assert_eq!(
            folded(&["client", "list"]).request,
            Some(Request::Clients(Clients::List { json: false }))
        );
    }

    /// The ticket is what `invite` and `device invite` carry, and a stray one
    /// is refused rather than dropped.
    #[test]
    fn a_ticket_needs_a_link_to_go_in() {
        assert_eq!(
            folded(&["invite", "phone", "--ticket", "ticket-value"]).ticket,
            Some("ticket-value".to_string())
        );
        let message = refused(&["--invite-ticket", "ticket-value"]);
        assert!(message.contains("--invite-ticket"), "{message}");
        assert!(message.contains("device invite"), "{message}");
    }
}

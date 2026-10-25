use clap::{Parser, Subcommand, ValueEnum};
use nexapipe::config::{
    AdminConfig, EndpointIdentity, IrohConfig, LocalProxyConfig, ProxyConfig, ServerConfig,
};
use nexapipe::proxy::{ProxyOptions, run_local_proxy, run_proxy};
use nexapipe::routes::RoutingTable;
use nexapipe::shutdown::{ShutdownSignal, wait_for_shutdown_signal};
use nexapipe_proto::secret::SecretString;
use std::sync::Arc;

// The credential half of the command line: the 2FA enrollment, the invite, and
// the `client` subcommand. It is a second product in the same binary, and it
// was a second product in the same file.
mod cli;

/// The default config path the binary uses when `--config` is not given.
///
/// Two paths land at the same file: `./config.toml` is what local dev has
/// always used, `./config/config.toml` is what `docker-compose.yaml`'s
/// bind-mount target resolves to inside the container. Rather than pick
/// one and break the other, this function lets the environment decide —
/// the docker-compose sets `NEXAPIPE_CONFIG_DIR=/app/config`, and the
/// binary prepends that to `config.toml`. Local dev that does not set the
/// variable gets the original behaviour.
fn compute_default_config() -> String {
    match std::env::var("NEXAPIPE_CONFIG_DIR") {
        Ok(dir) if !dir.trim().is_empty() => {
            // Trim a trailing slash so the join reads as `<dir>/config.toml`,
            // not `<dir>//config.toml`. A trailing slash is the most common
            // case (compose file style: `- /app/config/`) but other shapes
            // (`- /app/config`, `- /app/config///`) should all land at the
            // same path.
            let trimmed = dir.trim().trim_end_matches('/');
            format!("{trimmed}/config.toml")
        }
        _ => "config.toml".to_string(),
    }
}

/// How the 2FA enrollment QR code is drawn.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum QrFormat {
    /// Half blocks with explicit colors, readable on any terminal theme
    Unicode,
    /// Half blocks without escape sequences, for terminals without colors
    Plain,
    /// Plain ASCII, for logs and text files
    Ascii,
    /// SVG markup, for files and browsers
    Svg,
    /// No QR code, print the otpauth:// URI only
    None,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // `global` so it can be written before or after a subcommand: `status`
    // needs the config for the listener address, and `nexapipe --config X
    // status` is the spelling an operator who already uses the flag will try
    // first.
    //
    // The default is computed: `NEXAPIPE_CONFIG_DIR` shifts it to that
    // directory's `config.toml` when set, otherwise it stays at `./config.toml`.
    // The docker setup sets `NEXAPIPE_CONFIG_DIR=/app/config` (matching the
    // bind-mount target), so the container picks up `/app/config/config.toml`
    // by default and a local dev that omits `--config` keeps the old behaviour.
    // `--config` always wins, so an operator can still point the binary at any
    // path they like.
    #[arg(short, long, default_value_t = compute_default_config(), global = true)]
    config: String,

    #[arg(long, help = "Run in client local proxy mode")]
    local_proxy: bool,

    #[arg(long, help = "Generate a new secret key for stable endpoint identity")]
    generate_secret: bool,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        help = "Generate a new 2FA secret for a client and print a scannable QR code"
    )]
    generate_2fa: Option<String>,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        help = "Print the QR code of a client already configured in [auth.clients]"
    )]
    show_2fa: Option<String>,

    #[arg(
        long,
        help = "With --generate-2fa: issue a new secret even when the client already has \
                one in [auth.clients], and replace it in the config"
    )]
    force: bool,

    #[arg(
        long,
        value_name = "NAME",
        global = true,
        help = "Issuer label shown by the authenticator app (default: [auth] issuer)"
    )]
    issuer: Option<String>,

    #[arg(
        long,
        value_enum,
        default_value_t = QrFormat::Unicode,
        global = true,
        help = "How to draw the QR code"
    )]
    qr_format: QrFormat,

    #[arg(long, global = true, help = "Draw the QR code light on dark")]
    qr_invert: bool,

    #[arg(
        long,
        value_name = "PATH",
        global = true,
        help = "Also write the QR code to a file (.svg, anything else is ASCII)"
    )]
    qr_out: Option<String>,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        num_args = 0..=1,
        default_missing_value = "",
        help = "Print a scannable nexapipe:// invite for this endpoint; \
                with a CLIENT_ID the matching [auth.clients] 2FA secret goes in too, \
                without one the invite only carries the endpoint and its domains"
    )]
    generate_invite: Option<String>,

    #[arg(
        long,
        requires = "generate_invite",
        help = "With --generate-invite CLIENT_ID: put a one-time enrollment token in the \
                invite instead of the client's TOTP secret. The first device to scan it \
                trades the token for a freshly generated secret, and the link stops being \
                a credential — the secret in it is never one"
    )]
    registration: bool,

    #[arg(
        long,
        requires = "generate_invite",
        help = "With --generate-invite CLIENT_ID: create the client when it does not exist \
                yet, generating and writing its TOTP secret in the same run. Only a client \
                that is missing entirely is created; an existing one is used as it is"
    )]
    create_client: bool,

    #[arg(
        long = "invite-domains",
        value_delimiter = ',',
        value_name = "DOMAINS",
        help = "Domains to put in the invite (default: [local_proxy] proxy_domains, else the route hosts)"
    )]
    invite_domains: Vec<String>,

    #[arg(
        long = "invite-name",
        value_name = "NAME",
        help = "Human readable label stored alongside the endpoint in the invite"
    )]
    invite_name: Option<String>,

    #[arg(
        long = "invite-relay",
        value_name = "URL",
        help = "Relay URL to put in the invite (default: [iroh] relay_url)"
    )]
    invite_relay: Option<String>,

    #[arg(
        long = "endpoint-id",
        value_name = "NODE_ID",
        help = "Endpoint ID to advertise (default: derived from [iroh] secret_key)"
    )]
    endpoint_id: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// The two things this binary does besides run: ask a running instance how it
/// is, and — with the flags above — write credentials into a config.
///
/// A subcommand rather than another flag because it is a different kind of
/// thing: the flags are all "do this to the config and exit", while `status`
/// talks to a process that is already running.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Ask the instance at [admin] listen_addr what it is doing
    Status {
        /// Print the whole answer as one JSON document instead of the grouped
        /// reading, for anything that has to parse it
        #[arg(long)]
        json: bool,
    },

    /// List, add and revoke the 2FA clients in [auth.clients]
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },
}

/// The write half of the management surface.
///
/// Subcommands rather than `POST /v1/clients`: the admin token is one opaque
/// value with no scope and no rotation, and giving it something to change is
/// how a read-only surface becomes the way into the credential store. A
/// subcommand writes the same file the server watches instead, and needs no
/// token — but it does need to be able to write that file, which is the access
/// an operator adding a client already has.
#[derive(Subcommand, Debug)]
enum ClientAction {
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

        /// Give this device a secret of its own, leaving the client's alone
        #[arg(long, value_name = "NAME")]
        device: Option<String>,

        /// Issue this device a key instead of a secret: the public half of an
        /// Ed25519 key pair, 64 hex characters. The device proves itself by
        /// signing each challenge — no code for anyone to read — which is what
        /// a device that runs unattended needs; the private half never leaves
        /// the device.
        #[arg(long, value_name = "HEX", requires = "device")]
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
}

#[tokio::main]
async fn main() {
    // Install ring as the default CryptoProvider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring as default CryptoProvider");

    let cli = Cli::parse();

    // `status` is handled before anything that loads the config for a *start*:
    // it is the only command that runs against another process, and it has to
    // work while that process holds the config. It reads the same file, read
    // only, for the address and the token.
    if let Some(Commands::Status { json }) = &cli.command {
        if let Err(e) = nexapipe::status::status(&cli.config, *json).await {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // Handle --generate-secret flag
    if cli.generate_secret {
        // Printing a key is not the same thing as giving the endpoint one: this
        // writes nothing, and a copy-paste is still the operator's job. The
        // startup path generates and persists a key on its own
        // (`ProxyConfig::ensure_iroh_secret_key`); this stays for generating one
        // to move between hosts, or to seed a config before its first run.
        let secret_key_hex = nexapipe::config::generate_secret_key_hex();
        println!("Generated secret key for stable endpoint identity:");
        println!("{}", secret_key_hex);
        println!();
        println!("Add this to your config.toml under [iroh] section:");
        println!("secret_key = \"{}\"", secret_key_hex);
        println!();
        println!("To keep the key out of config.toml instead (so the file holds no");
        println!("credential and can stay world-readable), point [iroh] secret_key_file");
        println!("at a file holding just the key, or set NEXAPIPE_IROH_SECRET_KEY.");
        println!();
        println!("Or skip this entirely: nexapipe writes [iroh] secret_key on first start");
        println!("when the key is missing.");
        return;
    }

    // Handle --generate-2fa / --show-2fa
    if cli.generate_2fa.is_some() || cli.show_2fa.is_some() {
        if let Err(e) = cli::print_2fa_enrollment(&cli) {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // Handle --generate-invite
    if cli.generate_invite.is_some() {
        if let Err(e) = cli::print_endpoint_invite(&cli) {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // `client` reads and writes the config file, which is the other half of the
    // management surface. It is handled here rather than after the config load
    // below because it does not start a proxy: a `revoke` has to work while one
    // is running, and it takes the same lock the server does.
    if let Some(Commands::Client { action }) = &cli.command {
        let outcome = match action {
            ClientAction::List { json } => cli::list_clients(&cli, *json),
            ClientAction::Add {
                client_id,
                device,
                public_key,
                force,
            } => cli::add_client(
                &cli,
                client_id,
                device.as_deref(),
                public_key.as_deref(),
                *force,
            ),
            ClientAction::Revoke { client_id, device } => {
                cli::revoke_client(&cli, client_id, device.as_deref())
            }
        };
        if let Err(e) = outcome {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // A first start with no config file gets a minimal one written for it,
    // rather than a refusal to start with nothing to act on. Server mode only:
    // `--local-proxy` reads the same path as a *client* config, and the file
    // written here describes a server, so handing it to the client half would
    // be worse than the error it replaces.
    //
    // The "did we just write it?" flag is captured here and the advisory is
    // emitted after `log::init` below — server-mode startup routes advisory
    // output through the log channel rather than raw stdout, and the tracing
    // subscriber is not installed yet at this point.
    let config_just_generated = if !cli.local_proxy {
        match nexapipe::config::ensure_config_file(&cli.config) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                eprintln!("Failed to create {}: {:#}", cli.config, e);
                std::process::exit(1);
            }
        }
    } else {
        false
    };

    let proxy_config = match ProxyConfig::from_file(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    let debug_enabled = proxy_config.debug.unwrap_or(false);

    // Console output plus the rotating log files configured in `[log]`.
    nexapipe::log::init(proxy_config.log.as_ref(), debug_enabled);

    // Last chance to notice configuration that TLS termination left behind.
    proxy_config.warn_removed_tls_keys();

    // The endpoint's identity, generated and written back to `config.toml` if it
    // has none. Before `log::init` would mean a warning nobody sees; after the
    // credential warning would mean writing a credential into a file that
    // warning is about to name. Here it sits in both gaps' place: logged, and
    // before anything reads the file's mode.
    //
    // Local-proxy mode is skipped: it is the client half, and the endpoint it
    // dials is somebody else's identity.
    let identity = if cli.local_proxy {
        None
    } else {
        match ProxyConfig::ensure_iroh_secret_key(&cli.config, &proxy_config) {
            Ok(identity) => Some(identity),
            Err(e) => {
                tracing::error!("{}", e);
                std::process::exit(1);
            }
        }
    };

    if debug_enabled {
        tracing::info!("Debug mode enabled");
    }

    if config_just_generated {
        // Server-mode advisories go through the log channel, not raw stdout:
        // a banner is reserved for output that carries data the operator needs
        // to act on (Node ID / ticket / invite / QR). This is just "what I
        // did and what you should do next", which is what the log is for.
        tracing::info!(
            "No config at {} — wrote a minimal one: [auth] enabled = true with 0 \
             clients enrolled (nothing can connect), no [[routes]] entry (every \
             host is answered 404). Enroll the first client with: \
             nexapipe --generate-invite client-001 --create-client --config {}",
            cli.config,
            cli.config,
        );
    }

    let shutdown_signal = Arc::new(ShutdownSignal::new());
    let shutdown_signal_clone = shutdown_signal.clone();

    tokio::spawn(async move {
        wait_for_shutdown_signal(shutdown_signal_clone).await;
    });
    tracing::info!("Shutdown signal handler registered");

    if cli.local_proxy {
        run_local_proxy_mode(&proxy_config, &shutdown_signal).await;
    } else {
        run_server_mode(
            &proxy_config,
            &cli.config,
            identity.as_ref(),
            &shutdown_signal,
        )
        .await;
    }

    // The server mode has already drained its connections by the time it
    // returns, so there is nothing left to wait for here.
    tracing::info!("Proxy shutdown complete");
}

async fn run_server_mode(
    proxy_config: &ProxyConfig,
    config_path: &str,
    identity: Option<&EndpointIdentity>,
    shutdown_signal: &Arc<ShutdownSignal>,
) {
    let server_config: Option<ServerConfig> = proxy_config.server.clone();
    let mut iroh_config: Option<IrohConfig> = proxy_config.iroh.clone();
    let admin_config: Option<AdminConfig> = proxy_config.admin.clone();
    let metrics_config = proxy_config.metrics;

    // The resolved identity overrides whatever `[iroh] secret_key` the config
    // holds, because it is that key or the one written in its place.
    //
    // On the *endpoint's* copy only. `proxy_config` stays as it was loaded,
    // because `holds_credentials()` is asked about the file on disk further
    // down and an ephemeral identity was never written there — folding it in
    // would warn about a key that is not in the file, which is the one case an
    // ephemeral identity exists for.
    if let Some(identity) = identity {
        iroh_config.get_or_insert_with(Default::default).secret_key =
            Some(SecretString::new(identity.key().to_string()));
    }

    // Same builder the config watcher calls on a reload: a route that works
    // after a restart must work without one too. A bad config is fatal here,
    // where nothing is serving yet — on a reload it only keeps the old routes.
    let routes = match proxy_config.build_routes() {
        Ok(routes) => routes,
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };

    // The `[timeouts]` values ride along here rather than being read where they
    // are used: they were validated above, and being handed to the table is what
    // keeps every handler agreeing on one value for "too long to wait".
    let route_config = Arc::new(RoutingTable::with_settings(
        routes,
        proxy_config.timeouts(),
        proxy_config.retry(),
    ));

    tracing::info!("Starting proxy with domain-based and path-based routing");

    // Load 2FA auth config
    let auth_config = match ProxyConfig::load_with_auth(config_path) {
        Ok((_, auth_cfg)) => {
            if let Some(ref cfg) = auth_cfg {
                if cfg.enabled {
                    tracing::info!(
                        "2FA authentication enabled with {} clients",
                        cfg.clients.len()
                    );
                } else {
                    tracing::warn!("[auth] is configured but disabled, connections are not gated");
                }
            }
            auth_cfg
        }
        // Fatal, unlike the same error on a reload: by now the file has been
        // read and the routes have been built, so the only thing left that can
        // fail is `[auth]` itself — a misspelled key, an unknown one, an empty
        // enrollment token. Degrading to "no 2FA" was the bug this whole
        // section exists to close: `enable = true` used to be exactly as
        // silent as a typo, and the only difference was one line of log.
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };

    // The config file's own permission is not a gate (ROADMAP §3.5), but a
    // credential in a file anybody can read is worth saying out loud once.
    //
    // Called whether or not the file has an `[auth]` section: the `[iroh]`
    // half is a credential on its own, and `config.toml.example` — like the
    // generated first-run template — has no `[auth]` at all.
    nexapipe::config::warn_about_readable_credentials(
        std::path::Path::new(config_path),
        proxy_config,
        auth_config.as_ref(),
    );

    // The `[peers]` allow-list. A malformed entry is fatal rather than dropped:
    // a list whose whole purpose is to refuse strangers must not silently come
    // out shorter than it was written.
    let peer_allow_list = match proxy_config
        .peers
        .as_ref()
        .map(nexapipe::config::PeersConfig::parse_allow_list)
        .transpose()
    {
        Ok(list) => list
            .flatten()
            .map(|allowed| nexapipe::conn::allow_list::PeerAllowList::new(Some(allowed))),
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = run_proxy(
        route_config,
        config_path,
        shutdown_signal.clone(),
        ProxyOptions {
            server: server_config,
            iroh: iroh_config,
            auth: auth_config,
            peers: peer_allow_list,
            health_check: proxy_config.health_check.clone(),
            admin: admin_config,
            metrics: metrics_config,
            backends: proxy_config.backends.clone(),
            limits: proxy_config.limits,
            // The credentials in the configuration file are what this build
            // checks. A build that keeps its credentials somewhere else hands
            // its own authenticator in here instead.
            authenticator: None,
        },
    )
    .await
    {
        // The alternate form prints the whole chain, so the cause reaches the
        // log and not only the outermost context — an operator who wrote
        // `discovery = "off"` has to see which value was wrong, not just that
        // something about the iroh configuration was.
        tracing::error!("Proxy failed: {e:#}");
        std::process::exit(1);
    }
}

async fn run_local_proxy_mode(proxy_config: &ProxyConfig, shutdown_signal: &Arc<ShutdownSignal>) {
    let local_proxy_config: Option<LocalProxyConfig> = proxy_config.local_proxy.clone();

    let config = match local_proxy_config {
        Some(cfg) => cfg,
        None => {
            tracing::error!("Local proxy config not found");
            std::process::exit(1);
        }
    };

    if !config.enabled {
        tracing::error!("Local proxy is not enabled in config");
        std::process::exit(1);
    }

    tracing::info!("Starting local proxy mode");

    if let Err(e) = run_local_proxy(config, shutdown_signal.clone()).await {
        tracing::error!("Local proxy failed: {}", e);
        std::process::exit(1);
    }
}

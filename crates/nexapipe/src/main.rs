use clap::{Parser, ValueEnum};
use nexapipe::config::{
    AdminConfig, Config, EndpointIdentity, IrohConfig, LocalProxyConfig, ServerConfig,
};
use nexapipe::proxy::{Proxy, ProxyOptions, run_local_proxy};
use nexapipe::routes::RoutingTable;
use nexapipe::shutdown::{ShutdownSignal, wait_for_shutdown_signal};
use nexapipe::storage::{Storage, StorageKind};
use nexapipe_proto::secret::SecretString;
use std::sync::Arc;

use cli::Commands;

// The command line: the command groups an operator asks for, and the credential
// work behind them — the 2FA enrollment, the invites, the `client` subcommand
// and the configuration read back out. It is a second product in the same
// binary, and it was a second product in the same file.
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

/// Which store the configuration is kept in.
///
/// The choice is the command line's, and the environment's when the command
/// line does not make it: a deployment that cannot change how the binary is
/// started — a compose file, a systemd unit — says it in the environment
/// instead.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum StorageChoice {
    /// A TOML file: the configuration, the counters and the token beside each
    /// other.
    Toml,
    /// A SQLite database.
    Sqlite,
    /// A PostgreSQL database.
    Postgres,
}

impl From<StorageChoice> for StorageKind {
    fn from(choice: StorageChoice) -> Self {
        match choice {
            StorageChoice::Toml => StorageKind::Toml,
            StorageChoice::Sqlite => StorageKind::Sqlite,
            StorageChoice::Postgres => StorageKind::Postgres,
        }
    }
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

    /// Where the configuration is kept: a TOML file, a SQLite database or a
    /// PostgreSQL one.
    ///
    /// The default is the file, and it is the default for the same reason it
    /// always was: a deployment that says nothing about where its
    /// configuration lives is a deployment with a `config.toml` next to it.
    #[arg(long, value_enum, global = true)]
    storage: Option<StorageChoice>,

    /// The database the configuration is kept in: a connection string for
    /// PostgreSQL, a file path for SQLite.
    ///
    /// `NEXAPIPE_STORAGE_URL` says the same thing when the command line
    /// cannot.
    #[arg(long, value_name = "URL", global = true)]
    storage_url: Option<String>,

    // The legacy spelling. `--local-proxy` is an option of `nexapipe serve`
    // now, and the fold reports this one as replaced by that command.
    #[arg(long, hide = true, help = "Run in client local proxy mode")]
    local_proxy: bool,

    #[arg(
        long,
        hide = true,
        help = "Generate a new secret key for stable endpoint identity"
    )]
    generate_secret: bool,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        hide = true,
        help = "Generate a new 2FA secret for a client and print a scannable QR code"
    )]
    generate_2fa: Option<String>,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        hide = true,
        help = "Print the QR code of a client already configured in [auth.clients]"
    )]
    show_2fa: Option<String>,

    #[arg(
        long,
        hide = true,
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

    // The three drawing options stay global: an operator who already writes
    // `nexapipe --qr-out f.svg invite phone` has to keep working, and a
    // per-command copy would break exactly that spelling. They are named for
    // what they do rather than for what draws them, and the older spellings
    // remain as aliases.
    #[arg(
        long = "format",
        alias = "qr-format",
        value_name = "FORMAT",
        value_enum,
        default_value_t = QrFormat::Unicode,
        global = true,
        help = "How to draw the QR code (formerly --qr-format)"
    )]
    qr_format: QrFormat,

    #[arg(
        long = "invert",
        alias = "qr-invert",
        global = true,
        help = "Draw the QR code light on dark (formerly --qr-invert)"
    )]
    qr_invert: bool,

    #[arg(
        long = "out",
        alias = "qr-out",
        value_name = "PATH",
        global = true,
        help = "Also write the QR code to a file, .svg or ASCII (formerly --qr-out)"
    )]
    qr_out: Option<String>,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        num_args = 0..=1,
        default_missing_value = "",
        hide = true,
        help = "Print a scannable nexapipe:// invite for this endpoint; \
                with a CLIENT_ID the matching [auth.clients] 2FA secret goes in too, \
                without one the invite only carries the endpoint and its domains"
    )]
    generate_invite: Option<String>,

    #[arg(
        long,
        hide = true,
        requires = "generate_invite",
        help = "Replaced by `nexapipe device invite --client CLIENT_ID`, which issues a \
                one-time token with a deadline"
    )]
    registration: bool,

    #[arg(
        long,
        hide = true,
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
        hide = true,
        help = "Domains to put in the invite (default: [local_proxy] proxy_domains, else the route hosts)"
    )]
    invite_domains: Vec<String>,

    #[arg(
        long = "invite-name",
        value_name = "NAME",
        hide = true,
        help = "Human readable label stored alongside the endpoint in the invite"
    )]
    invite_name: Option<String>,

    #[arg(
        long = "invite-relay",
        value_name = "URL",
        hide = true,
        help = "Relay URL to put in the invite (default: [iroh] relay_url)"
    )]
    invite_relay: Option<String>,

    #[arg(
        long = "endpoint-id",
        value_name = "NODE_ID",
        global = true,
        help = "Endpoint ID to advertise (default: derived from [iroh] secret_key)"
    )]
    endpoint_id: Option<String>,

    #[arg(
        long = "invite-ticket",
        alias = "ticket",
        value_name = "TICKET",
        global = true,
        conflicts_with = "endpoint_id",
        help = "Put a full endpoint ticket (Node ID + addresses) in the invite instead of a \
                Node ID. Works with `nexapipe invite` and with `device invite`. Use it with \
                [iroh] discovery = \"none\", where a Node ID alone cannot be resolved"
    )]
    invite_ticket: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[tokio::main]
async fn main() {
    // Install ring as the default CryptoProvider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring as default CryptoProvider");

    let mut cli = Cli::parse();

    // One request per run, whatever spelling asked for it: the command, or the
    // flag that has been replaced by it. The fold refuses two requests in one
    // run and reports every old flag on stderr, both before a store is opened
    // and before anything runs.
    let request = match cli::fold(&mut cli) {
        Ok(request) => request,
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
    };

    // Everything but the server start is a command that returns: it reads or
    // writes the configuration and exits. Starting the proxy is what a run with
    // no command — or with `serve` — does, and what follows below.
    if request != cli::Request::Serve {
        if let Err(e) = run_command(request, &cli).await {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // Where the configuration is kept. A file today; a database tomorrow, and
    // the difference is one line here rather than a path threaded through the
    // whole server.
    let storage: Arc<dyn Storage> = match store_for(&cli).await {
        Ok(storage) => storage,
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
    };

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
        match storage
            .ensure_config(nexapipe::config::FIRST_RUN_CONFIG)
            .await
        {
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

    let proxy_config = match nexapipe::config::load_config(storage.as_ref()).await {
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
        match nexapipe::storage::ensure_endpoint_identity(storage.as_ref(), &proxy_config).await {
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
             nexapipe invite client-001 --create-client --config {}",
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
        run_server_mode(&proxy_config, storage, identity.as_ref(), &shutdown_signal).await;
    }

    // The server mode has already drained its connections by the time it
    // returns, so there is nothing left to wait for here.
    tracing::info!("Proxy shutdown complete");
}

/// The store the operator asked for.
///
/// Opened per command rather than once in `main`, because a command that never
/// touches the configuration — asking for a key to paste, say — should not open
/// a database to do it. The store is opened asynchronously: a database store
/// answers when the database answers, and a file store answers at once.
async fn store_for(cli: &Cli) -> anyhow::Result<Arc<dyn Storage>> {
    nexapipe::storage::choose(
        cli.storage.map(Into::into),
        cli.storage_url.clone(),
        &cli.config,
    )
    .await
}

/// Runs the command the operator asked for.
///
/// `Request::Serve` never reaches here; it is the server start below. Every
/// other request opens the store it needs and returns, so `nexapipe` never
/// starts a proxy for a command that was meant to exit.
async fn run_command(request: cli::Request, cli: &Cli) -> anyhow::Result<()> {
    match request {
        cli::Request::Serve => Ok(()),

        // `status` is the only command that runs against another process: it
        // has to work while that process holds the configuration, so it reads
        // the store read-only for the address and the token.
        cli::Request::Status { json } => {
            let store = store_for(cli).await?;
            nexapipe::status::status(store.as_ref(), json).await
        }

        cli::Request::Secret => {
            print_secret_key();
            Ok(())
        }

        // `client enroll` and `client qr`, and the two flags that used to be
        // them: `fold` put the client into `cli.generate_2fa` or
        // `cli.show_2fa`, so there is one implementation here as well.
        cli::Request::Enroll | cli::Request::ShowQr => {
            let store = store_for(cli).await?;
            cli::print_2fa_enrollment(cli, store.as_ref()).await
        }

        cli::Request::Invite => {
            let store = store_for(cli).await?;
            cli::print_endpoint_invite(cli, store.as_ref()).await
        }

        cli::Request::Device(invite) => {
            let store = store_for(cli).await?;
            cli::invite_device(
                cli,
                store.as_ref(),
                &invite.client_id,
                invite.ttl.as_deref(),
                &invite.domains,
                invite.relay.as_deref(),
                invite.create_client,
            )
            .await
        }

        // `client` reads and writes the configuration rather than serving it: a
        // `revoke` has to work while a server is running, and it takes the same
        // lock the server does.
        cli::Request::Clients(clients) => {
            let store = store_for(cli).await?;
            match clients {
                cli::Clients::List { json } => cli::list_clients(store.as_ref(), json).await,
                cli::Clients::Add {
                    client_id,
                    device,
                    public_key,
                    force,
                } => {
                    cli::add_client(
                        cli,
                        store.as_ref(),
                        &client_id,
                        device.as_deref(),
                        public_key.as_deref(),
                        force,
                    )
                    .await
                }
                cli::Clients::Revoke { client_id, device } => {
                    cli::revoke_client(store.as_ref(), &client_id, device.as_deref()).await
                }
            }
        }

        cli::Request::Qr(text) => cli::print_qr(&text, cli),

        cli::Request::ConfigShow => {
            let store = store_for(cli).await?;
            cli::print_config(store.as_ref()).await
        }

        cli::Request::ConfigPath => {
            let store = store_for(cli).await?;
            cli::print_config_path(store.as_ref());
            Ok(())
        }
    }
}

/// Prints a key the operator can paste, and writes nothing.
///
/// Printing a key is not the same thing as giving the endpoint one: this writes
/// nothing, and a copy-paste is still the operator's job. The startup path
/// generates and persists a key on its own (`Config::ensure_iroh_secret_key`);
/// this stays for generating one to move between hosts, or to seed a
/// configuration before its first run.
fn print_secret_key() {
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
}

async fn run_server_mode(
    proxy_config: &Config,
    storage: Arc<dyn Storage>,
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
    let auth_config = match nexapipe::config::load_config_with_auth(storage.as_ref()).await {
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
    if let Some(path) = storage.credential_file() {
        nexapipe::config::warn_about_readable_credentials(path, proxy_config, auth_config.as_ref());
    }

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

    // The proxy, assembled: the store it keeps its configuration in, the
    // routing table it serves, and the rest of the configuration.
    let proxy = match Proxy::builder()
        .routes(route_config)
        .storage(storage)
        .options(ProxyOptions {
            server: server_config,
            iroh: iroh_config,
            auth: auth_config,
            peers: peer_allow_list,
            health_check: proxy_config.health_check.clone(),
            admin: admin_config,
            metrics: metrics_config,
            backends: proxy_config.backends.clone(),
            limits: proxy_config.limits,
            // The credentials in the configuration are what this build checks.
            // A build that keeps its credentials somewhere else hands its own
            // authenticator in here instead.
            authenticator: None,
        })
        .shutdown_signal(shutdown_signal.clone())
        .build()
    {
        Ok(proxy) => proxy,
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = proxy.run().await {
        // The alternate form prints the whole chain, so the cause reaches the
        // log and not only the outermost context — an operator who wrote
        // `discovery = "off"` has to see which value was wrong, not just that
        // something about the iroh configuration was.
        tracing::error!("Proxy failed: {e:#}");
        std::process::exit(1);
    }
}

async fn run_local_proxy_mode(proxy_config: &Config, shutdown_signal: &Arc<ShutdownSignal>) {
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

    if let Err(e) =
        run_local_proxy(config, proxy_config.iroh.clone(), shutdown_signal.clone()).await
    {
        tracing::error!("Local proxy failed: {}", e);
        std::process::exit(1);
    }
}

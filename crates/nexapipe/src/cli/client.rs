//! The `client` subcommand: the clients in the config, the credentials
//! they carry, and the devices under them.

use crate::Cli;

use nexapipe::config::{ClientSecretWrite, ProxyConfig};

use super::config::{load_auth_config, load_auth_or_none, toml_key};
use super::qr::render_qr;

/// A unix timestamp as it reads where the operator is, or `-`.
///
/// Zero is not 1970 here: the counter writeback writes `last_used = 0` for a
/// client that has never authenticated, and `0` as `created_at` is the value an
/// entry carries when the file was written by hand. Both mean "never"/"unknown",
/// and a wall of 1970 dates would say the opposite.
///
/// (The state file no longer writes a zero counter at all — it leaves the key
/// out — but a `created_at` of `0` is still what a hand-written entry
/// carries.)
pub(super) fn stamp(seconds: Option<i64>) -> String {
    let Some(seconds) = seconds.filter(|at| *at > 0) else {
        return "-".to_string();
    };
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|at| {
            at.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "-".to_string())
}

/// `created_at` is carried as a string, and one written by hand may be anything.
pub(super) fn seconds_of(value: &str) -> Option<i64> {
    value.trim().parse().ok()
}

/// Prints the clients in `[auth.clients]`, and under each the devices that have
/// a credential of their own.
///
/// No secret is printed, in either form. This is the command that gets run to
/// see what is configured, and a terminal's scrollback, a paste into a ticket
/// and a screenshot are all places a secret printed once ends up living;
/// `--show-2fa` draws the code for one client for the one time it is needed.
pub(crate) fn list_clients(cli: &Cli, json: bool) -> anyhow::Result<()> {
    let Some(auth) = load_auth_or_none(&cli.config)? else {
        if json {
            println!("[]");
        } else {
            println!("{} has no [auth] section, so no clients", cli.config);
        }
        return Ok(());
    };

    let mut ids: Vec<&String> = auth.clients.keys().collect();
    ids.sort();

    if json {
        let clients: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| {
                let client = &auth.clients[*id];
                let mut devices: Vec<serde_json::Value> = client
                    .devices
                    .iter()
                    .map(|(name, device)| {
                        serde_json::json!({
                            "name": name,
                            "created_at": seconds_of(&device.created_at),
                            "last_used": device.last_used,
                            "key": device.public_key.is_some(),
                        })
                    })
                    .collect();
                devices.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
                serde_json::json!({
                    "id": id,
                    "has_secret": !client.secret.expose_secret().is_empty(),
                    "created_at": seconds_of(&client.created_at),
                    "last_used": client.last_used,
                    "allow_hosts": client.allow_hosts,
                    "allow_ports": client.allow_ports,
                    // Which of the two port rules the list above is held
                    // against. The flag is not in the name of the setting, and
                    // the two rules refuse different requests: without this,
                    // the list looks like the same restriction either way.
                    "allow_ports_strict": client.allow_ports_strict,
                    "invite_outstanding": client.pending_enrollment.is_some(),
                    "failed_attempts": client.failed_attempts,
                    "locked_out": client.is_locked_out(),
                    "devices": devices,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&clients)?);
        return Ok(());
    }

    println!(
        "{} {} in {} ([auth] enabled = {})",
        ids.len(),
        if ids.len() == 1 { "client" } else { "clients" },
        cli.config,
        auth.enabled
    );
    if ids.is_empty() {
        return Ok(());
    }
    println!();

    for id in &ids {
        let client = &auth.clients[*id];
        println!("  {id}");
        println!(
            "    secret      {}",
            if client.secret.expose_secret().is_empty() {
                "missing"
            } else {
                "set"
            }
        );
        println!("    created     {}", stamp(seconds_of(&client.created_at)));
        println!(
            "    last used   {}",
            stamp(client.last_used.map(|at| at as i64))
        );
        // Printed whenever the key is there, empty list included: an empty
        // list is the strictest setting there is, and a line that only shows
        // up for a non-empty list hides it exactly where it matters.
        if let Some(hosts) = &client.allow_hosts {
            let hosts = if hosts.is_empty() {
                "none, every host is denied".to_string()
            } else {
                hosts.join(", ")
            };
            println!("    allow hosts {hosts}");
        }
        // Printed whenever the key is there, empty list included: an empty
        // list is the strictest setting there is, and a line that only shows
        // up for a non-empty list hides it exactly where it matters.
        if let Some(ports) = &client.allow_ports {
            let ports = if ports.is_empty() {
                "none, every port is denied".to_string()
            } else {
                ports
                    .iter()
                    .map(|port| port.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!("    allow ports {ports}");
            // Which of the two port rules that list is held against. The flag
            // is not in the name of the setting and the two rules refuse
            // different requests, so the list alone says nothing about how
            // narrow it is: this line is what says it.
            println!(
                "    port rule   {}",
                if client.allow_ports_strict {
                    "allow_ports_strict = true, so the list is checked against the port the \
                     request is served from"
                } else {
                    "allow_ports_strict = false, so the list is checked against the port the \
                     client names, and a request that names no port is not checked at all"
                }
            );
        }
        if client.pending_enrollment.is_some() {
            println!("    invite      outstanding");
        }
        if client.failed_attempts > 0 {
            println!(
                "    attempts    {} failed since the last success",
                client.failed_attempts
            );
        }
        if client.is_locked_out() {
            println!(
                "    lockout     until {}",
                stamp(client.locked_until.map(|at| at as i64))
            );
        }

        let mut devices: Vec<_> = client.devices.iter().collect();
        devices.sort_by(|a, b| a.0.cmp(b.0));
        if devices.is_empty() {
            println!("    devices     none");
        } else {
            println!("    devices     {}", devices.len());
            let width = devices
                .iter()
                .map(|(name, _)| name.len())
                .max()
                .unwrap_or(0)
                .max(8);
            for (name, device) in devices {
                let mut line = format!("created {}", stamp(seconds_of(&device.created_at)));
                if let Some(used) = device.last_used {
                    line.push_str(&format!(", last used {}", stamp(Some(used as i64))));
                }
                if device.public_key.is_some() {
                    line.push_str(", key");
                }
                println!("      {name:width$}  {line}");
            }
        }
    }

    // Said once, at the bottom, because it is a property of the configuration
    // and not of one client: a port list that is held against the port a
    // client names is a weaker restriction than it looks. The lines above say
    // which rule each client is on; this says what the weaker one does not
    // check.
    if ids.iter().any(|id| {
        let client = &auth.clients[*id];
        client.allow_ports.is_some() && !client.allow_ports_strict
    }) {
        println!();
        println!("At least one client above has a port list that is checked against the port the");
        println!("client names rather than the port the request is served from, so a request that");
        println!("names no port is not checked at all. Set allow_ports_strict = true on that");
        println!("client to check the backend's own port: it refuses more, and it is the rule an");
        println!("allow-list of ports is written for.");
    }

    println!();
    println!(
        "No secret is printed here: `nexapipe --show-2fa <CLIENT_ID>` draws the code for one."
    );
    Ok(())
}

/// Issues a credential and writes it into the config, for a client or for one
/// device of it.
///
/// The two differ in what they rotate, and that is the whole reason the device
/// table exists: `client add <id>` rewrites the client's own `secret`, which is
/// the credential of the device that names none — every device that enrolled
/// before the table existed — while `client add <id> --device <name>` writes a
/// credential of its own under that device and leaves the client's alone, so the
/// other devices keep working.
///
/// `--device <name> --public-key <hex>` is the third case: the device is issued
/// a key instead of a secret, so the ordinary path — generate a secret, draw it
/// as a QR code — is skipped whole. Nothing is generated, because the private
/// half is already on the device; what is written is the public half the
/// operator pasted.
pub(crate) fn add_client(
    cli: &Cli,
    client_id: &str,
    device: Option<&str>,
    public_key: Option<&str>,
    force: bool,
) -> anyhow::Result<()> {
    use nexapipe::auth::OtpAuthUri;
    use nexapipe::auth::otpauth::DEFAULT_ISSUER;

    let client_id = client_id.trim();
    // Both ids are checked before anything is written, for the reason the
    // handshake checks them: either one becomes a key in this file, is sent by a
    // device, and is the subject of every log line about it. An id the server
    // would refuse on the wire is no use in the config either.
    if !nexapipe::auth::is_presentable_client_id(client_id) {
        anyhow::bail!(
            "client id {client_id:?} is printable ASCII of at most {} characters and not empty — \
             it is the key under [auth.clients], the name a device sends in its handshake, and \
             the subject of every log line about it",
            nexapipe::auth::MAX_CLIENT_ID_LEN
        );
    }
    if let Some(device) = device
        && !nexapipe::auth::is_presentable_device_id(device)
    {
        anyhow::bail!(
            "device name {device:?} is printable ASCII of at most {} characters and not empty — \
             it is a key under [auth.clients.{}.devices] and the subject of every log line about \
             it",
            nexapipe::auth::MAX_DEVICE_ID_LEN,
            toml_key(client_id)
        );
    }

    let (auth_config, config_loaded) = load_auth_config(&cli.config);

    // A device cannot be the first thing a client gets: a device table under a
    // client with no secret of its own is a config that will not load, and
    // saying so here beats writing a file that cannot be read back.
    let client = auth_config.clients.get(client_id);
    if device.is_some() && client.is_none() {
        anyhow::bail!(
            "client \"{client_id}\" has no [auth.clients.{}] secret in {}; add the client first \
             with `nexapipe client add {client_id}`",
            toml_key(client_id),
            cli.config
        );
    }
    let already = match device {
        Some(name) => client.is_some_and(|client| client.devices.contains_key(name)),
        None => client.is_some(),
    };
    if already && !force {
        match device {
            Some(name) => anyhow::bail!(
                "device \"{name}\" of client \"{client_id}\" already has a credential in {}; \
                 pass --force to issue it another one, which enrolls the device using the \
                 current one out",
                cli.config
            ),
            None => anyhow::bail!(
                "client \"{client_id}\" already has a secret in {}; pass --force to rotate it, \
                 which enrolls out every device using it",
                cli.config
            ),
        }
    }

    // The key path ends here: there is no secret to draw and nothing to scan,
    // because the private half is already where it belongs. What the QR code
    // normally does — getting the credential onto the device — has been done
    // by whoever generated the pair; all that is missing is the public half
    // recorded on this side.
    if let Some(offered) = public_key {
        // `requires = "device"` on the flag already refuses this spelling;
        // the check stays because this function is where the invariant lives,
        // and a key belongs to one named device — the unnamed slot is the
        // client's shared secret, which has no key to be half of.
        let Some(name) = device else {
            anyhow::bail!("--public-key needs --device: a key is issued to one named device");
        };
        let key = nexapipe::auth::parse_public_key(offered)
            .map_err(|why| anyhow::anyhow!("--public-key: {why}"))?;
        let key = nexapipe::auth::public_key_hex(&key);

        println!();
        println!("Key for device \"{name}\" of client \"{client_id}\"");
        println!("  Public key {key}");
        println!();
        println!(
            "The device proves itself by signing each challenge with the private half of this \
             key: no code for anyone to read and nothing to scan, which is what lets it run \
             unattended. The private half stays on the device; this command never sees it."
        );
        println!();

        return write_issued_credential(
            cli,
            client_id,
            Some(name),
            nexapipe::auth::DeviceMaterial::PublicKey(&key),
            auth_config.enabled,
            force,
        );
    }

    let issuer = match &cli.issuer {
        Some(issuer) => issuer.trim().to_string(),
        None => auth_config.issuer.clone(),
    };
    let issuer = if issuer.is_empty() {
        DEFAULT_ISSUER.to_string()
    } else {
        issuer
    };

    let secret = nexapipe::auth::TotpValidator::generate_secret();
    // The label is the client id even for a device: that is what the app takes
    // from the URI and sends as the client id, so a label carrying the device
    // name would authenticate as a client nobody configured. The device names
    // itself in the handshake, where the server can tell the two apart.
    let uri = OtpAuthUri::from_auth_config(&issuer, client_id, &secret, &auth_config)?;
    let link = uri.to_uri();

    println!();
    match device {
        Some(name) => println!(
            "Credential for device \"{name}\" of client \"{}\"",
            uri.client_id
        ),
        None => println!("Credential for client \"{}\"", uri.client_id),
    }
    // The secret belongs on this terminal, for the same reason as in the
    // `--generate-2fa` path above: the operator asked for this credential and
    // the next step is typing it into an authenticator app.
    // codeql[rust/cleartext-logging]
    // Rust does not honour inline suppressions yet (github/codeql#21637); see
    // the `--generate-2fa` path above for the full explanation.
    println!("  Secret     {}", uri.secret.expose_secret());
    println!("  Algorithm  {}", uri.algorithm);
    println!(
        "  Code       {} digits, {} second step",
        uri.digits, uri.period
    );
    println!("  Issuer     {}", uri.issuer);
    if !config_loaded {
        println!("             (built-in 2FA defaults)");
    }
    println!();

    for warning in uri.client_warnings() {
        eprintln!("warning: {warning}");
    }

    println!("otpauth:// URI, for manual entry:");
    println!("  {link}");
    println!();

    render_qr(
        &link,
        cli,
        "Scan this with the NexaPipe app (2FA settings -> scan QR code):",
    )?;
    println!();

    write_issued_credential(
        cli,
        client_id,
        device,
        nexapipe::auth::DeviceMaterial::Secret(uri.secret.expose_secret()),
        auth_config.enabled,
        force,
    )
}

/// Puts the credential that was just printed into the config, so the server
/// ends up holding the same thing the device carries: the secret the QR code
/// spelled out, or the public half the operator pasted.
///
/// `force` is passed through rather than assumed: whether the credential is
/// already there is decided under the config lock by the writer, which is the
/// only place that can answer it without racing a second writer.
fn write_issued_credential(
    cli: &Cli,
    client_id: &str,
    device: Option<&str>,
    material: nexapipe::auth::DeviceMaterial<'_>,
    auth_enabled: bool,
    force: bool,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    // Spelled the way the file is written: a device goes under the client's
    // `devices` table as an inline entry rather than as a section of its own,
    // because that table may be one an operator wrote inline.
    let (section, entry, noun, outcome) = match (device, material) {
        (None, nexapipe::auth::DeviceMaterial::Secret(secret)) => {
            let section = format!("[auth.clients.{}]", toml_key(client_id));
            (
                section.clone(),
                format!("secret = \"{secret}\""),
                "secret",
                ProxyConfig::write_client_secret(&cli.config, client_id, secret, force),
            )
        }
        (Some(name), nexapipe::auth::DeviceMaterial::Secret(secret)) => (
            format!("[auth.clients.{}.devices]", toml_key(client_id)),
            format!("{} = {{ secret = \"{secret}\" }}", toml_key(name)),
            "secret",
            ProxyConfig::write_device_credential(&cli.config, client_id, name, material, force),
        ),
        (Some(name), nexapipe::auth::DeviceMaterial::PublicKey(key)) => (
            format!("[auth.clients.{}.devices]", toml_key(client_id)),
            format!("{} = {{ public_key = \"{key}\" }}", toml_key(name)),
            "public key",
            ProxyConfig::write_device_credential(&cli.config, client_id, name, material, force),
        ),
        // A key is one device's, and the unnamed slot — the client's own
        // `secret` — is a string a key cannot live in. The CLI refuses this
        // spelling twice before it gets here; the arm keeps the writer from
        // being the one place that would write such a key nowhere.
        (None, nexapipe::auth::DeviceMaterial::PublicKey(_)) => {
            anyhow::bail!("a public key is issued to a named device; pass --device with it")
        }
    };
    let what = match device {
        None => section.clone(),
        Some(name) => format!("\"{name}\" under {section}"),
    };

    let written = match outcome {
        Ok(ClientSecretWrite::Added) => {
            println!("Wrote the {noun} to {} as {}.", cli.config, what);
            false
        }
        Ok(ClientSecretWrite::Replaced) => {
            println!("Replaced the {noun} of {} in {}.", what, cli.config);
            true
        }
        // Fatal rather than a warning. The credential is on screen either way,
        // so nothing is lost by stopping — but a command that exits 0 after
        // writing nothing lets `client add acme && deploy` go ahead with no
        // credential on disk, and the next thing that fails is a handshake
        // somewhere else, pointing at the client rather than at this write.
        // The snippet goes with the error for the reason it used to be printed
        // on its own: the operator can still put it in the file by hand.
        Err(e) => {
            return Err(e).context(format!(
                "the {noun} was not written to {}; add it by hand:\n\
                 {section}\n\
                 {entry}",
                cli.config
            ));
        }
    };
    println!();

    if !auth_enabled {
        eprintln!(
            "warning: [auth] enabled is not true in {}, so the server will not ask for this \
             credential; add enabled = true under [auth]",
            cli.config
        );
    }
    println!(
        "The config is watched, so a running server picks this up without a restart. \
         What changed is the file, not the server: nothing is revoked by issuing a credential."
    );
    match (device, written) {
        (Some(_), _) => println!(
            "Only this device's credential changed. The client's own secret is untouched, so \
             every other device of it keeps working."
        ),
        (None, true) => println!(
            "The client's own secret is the credential of the device that names none, so every \
             device using it has to scan again."
        ),
        (None, false) => println!(
            "Nothing was using it yet: scan the code above on the device that should carry \
             this client."
        ),
    }
    Ok(())
}

/// Drops a client, or one device of it, from `[auth.clients]`.
///
/// A revoke deletes rather than rewriting, because a missing entry is what the
/// handshake reads as "this device has no credential" — the same answer a device
/// that never enrolled gets, so what happened to it cannot be told from outside.
///
/// The `[auth]` section is read best-effort and only for the counts the message
/// prints: the removal itself edits the TOML directly and needs no typed auth,
/// so a config that no longer parses — an `allow_hosts` that is not a list, say
/// — must still be revocable. Refusing it would leave the one operator remedy
/// for a bad hand edit behind the very edit that broke it.
pub(crate) fn revoke_client(
    cli: &Cli,
    client_id: &str,
    device: Option<&str>,
) -> anyhow::Result<()> {
    let client_id = client_id.trim();
    // The checks `add` makes, for the same reason it makes them: either id
    // arrives on a command line and becomes a key in this file, and an id
    // carrying a newline or an ANSI escape splits the terminal output it is
    // printed into. A revoke is also the one command here that cannot be
    // undone by running it again, so refusing a mistyped id before anything is
    // read is cheaper than reading it first.
    if !nexapipe::auth::is_presentable_client_id(client_id) {
        anyhow::bail!(
            "client id {client_id:?} is printable ASCII of at most {} characters and not empty — \
             it is the key under [auth.clients], the name a device sends in its handshake, and \
             the subject of every log line about it",
            nexapipe::auth::MAX_CLIENT_ID_LEN
        );
    }
    if let Some(device) = device
        && !nexapipe::auth::is_presentable_device_id(device)
    {
        anyhow::bail!(
            "device name {device:?} is printable ASCII of at most {} characters and not empty — \
             it is a key under [auth.clients.{}.devices] and the subject of every log line about \
             it",
            nexapipe::auth::MAX_DEVICE_ID_LEN,
            toml_key(client_id)
        );
    }
    // Counts are for the message only; a config that fails to load must still be revocable.
    let auth = load_auth_or_none(&cli.config).ok().flatten();
    let client = auth.as_ref().and_then(|auth| auth.clients.get(client_id));

    match device {
        Some(name) => {
            let others = client.map(|client| client.devices.len()).unwrap_or(0);
            ProxyConfig::remove_device(&cli.config, client_id, name)?;
            println!(
                "Removed [auth.clients.{}.devices.{}] from {}.",
                toml_key(client_id),
                toml_key(name),
                cli.config
            );
            match others {
                // The shared secret is the credential of the peer that names no
                // device, so whether it still authenticates anyone is exactly
                // what `unnamed_device_allowed` decides.
                0 | 1 => match client {
                    Some(client) if !client.unnamed_device_allowed => println!(
                        "The client's own secret is untouched, but unnamed_device_allowed = false \
                         refuses a peer that names no device, so that secret authenticates no one."
                    ),
                    // `None` means the config could not be loaded: the counts
                    // above are best-effort in that case, so the advice stays
                    // the conservative one.
                    _ => {
                        println!(
                            "The client's own secret is untouched: that is the credential of the \
                             device that names none, so one can still authenticate as this client."
                        );
                        println!(
                            "Set unnamed_device_allowed = false under [auth.clients.{}] to take \
                             that credential away as well.",
                            toml_key(client_id)
                        );
                    }
                },
                2 => println!("1 other device of it keeps its credential."),
                left => println!("{} other devices of it keep their credentials.", left - 1),
            }
        }
        None => {
            let devices = client.map(|client| client.devices.len()).unwrap_or(0);
            ProxyConfig::remove_client(&cli.config, client_id)?;
            println!(
                "Removed [auth.clients.{}] from {}.",
                toml_key(client_id),
                cli.config
            );
            match devices {
                0 => {}
                1 => println!(
                    "Its 1 device credential went with it — a device entry under a client that \
                     is gone is one nobody can revoke, because there is no client left to list \
                     it under."
                ),
                many => println!(
                    "Its {many} device credentials went with it — a device entry under a client \
                     that is gone is one nobody can revoke, because there is no client left to \
                     list it under."
                ),
            }
        }
    }

    println!();
    println!("The config is watched, so a running server stops accepting it on the next reload —");
    println!("and closes the connections already authenticated as it, rather than leaving them");
    println!("to finish what they were doing.");
    Ok(())
}

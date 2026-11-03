//! The 2FA enrollment: the credentials, the `otpauth://` URI and the QR
//! code that carries it.

use crate::Cli;

use nexapipe::config::ClientSecretWrite;
use nexapipe::storage::Storage;
use nexapipe_proto::secret::SecretString;

use super::config::{load_auth_config, toml_key};
use super::qr::render_qr;

/// Prints everything needed to enroll a client in 2FA: the credentials, the
/// standard `otpauth://` URI and a QR code carrying that URI, which the NexaPipe
/// app and any third party authenticator app can import.
pub(crate) async fn print_2fa_enrollment(cli: &Cli, storage: &dyn Storage) -> anyhow::Result<()> {
    use nexapipe::auth::OtpAuthUri;
    use nexapipe::auth::otpauth::DEFAULT_ISSUER;

    let (auth_config, config_loaded) = load_auth_config(storage).await;

    // The QR code has to carry the secret the server will accept, so a client
    // that is already configured keeps the one it has: running --generate-2fa
    // twice must not hand out a second secret and silently lock the app out.
    let (client_id, secret, generated) = if let Some(client_id) = &cli.generate_2fa {
        let client_id = client_id.trim().to_string();
        match auth_config.clients.get(&client_id) {
            Some(client) if !cli.force => (client_id, client.secret.clone(), false),
            _ => (
                client_id,
                SecretString::new(nexapipe::auth::TotpValidator::generate_secret()),
                true,
            ),
        }
    } else if let Some(client_id) = &cli.show_2fa {
        let client_id = client_id.trim().to_string();
        let client = auth_config.clients.get(&client_id).ok_or_else(|| {
            anyhow::anyhow!(
                "client \"{}\" has no [auth.clients.{}] section in {}",
                client_id,
                toml_key(&client_id),
                storage.describe()
            )
        })?;
        (client_id, client.secret.clone(), false)
    } else {
        anyhow::bail!("no client given");
    };

    // `--issuer` wins, then the configured one, then the built-in default.
    let issuer = match &cli.issuer {
        Some(issuer) => issuer.trim().to_string(),
        None => auth_config.issuer.clone(),
    };
    let issuer = if issuer.is_empty() {
        DEFAULT_ISSUER.to_string()
    } else {
        issuer
    };

    let uri =
        OtpAuthUri::from_auth_config(&issuer, &client_id, secret.expose_secret(), &auth_config)?;
    let link = uri.to_uri();

    println!();
    println!("2FA enrollment for client \"{}\"", uri.client_id);
    // The secret belongs on this terminal: the command exists to hand the
    // operator a credential, and the two lines after it are the `otpauth://`
    // URI and the QR code, which carry the same secret by design. Nothing else
    // prints it, and this is the one place it is meant to be seen.
    // codeql[rust/cleartext-logging]
    // CodeQL does not honour inline suppressions in Rust yet (github/codeql#21637),
    // so this marker records the intent and starts suppressing on its own once
    // that support lands. Until then the alert is dismissed by hand.
    println!(
        "  Secret     {}{}",
        uri.secret.expose_secret(),
        if generated {
            "   (newly generated)"
        } else if cli.generate_2fa.is_some() {
            // Kept from the config: see the branch above.
            "   (already in the config)"
        } else {
            ""
        }
    );
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

    // These are settings the app cannot honor, so they are worth shouting about.
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

    if generated {
        save_generated_secret(
            cli,
            storage,
            &client_id,
            uri.secret.expose_secret(),
            auth_config.enabled,
        )
        .await;
    } else if cli.generate_2fa.is_some() {
        println!(
            "Client \"{}\" already has a secret in {}, so that is the one above:",
            uri.client_id,
            storage.describe()
        );
        println!("issuing a new one would enroll the app with credentials the server");
        println!("rejects. Pass --force to rotate it instead — the secret in the config");
        println!("is then replaced, and every device enrolled with the old one has to");
        println!("scan again.");
    } else {
        println!(
            "This secret already comes from {}, so the server needs no change.",
            storage.describe()
        );
        println!("Scanning the code above imports it into another app or device.");
    }

    Ok(())
}

/// Puts a freshly generated secret into the config file, so the server ends up
/// holding the same credentials the QR code carries and nothing has to be copied
/// by hand.
///
/// Failing is not fatal: the secret is on screen either way, the file may not
/// exist yet or may not be writable, and the snippet can still be typed in.
pub(super) async fn save_generated_secret(
    cli: &Cli,
    storage: &dyn Storage,
    client_id: &str,
    secret: &str,
    auth_enabled: bool,
) {
    let outcome = storage
        .write_client_secret(client_id, &SecretString::new(secret.to_string()), cli.force)
        .await;
    let written = match outcome {
        Ok(ClientSecretWrite::Added) => {
            println!(
                "Wrote the secret to {} as [auth.clients.{}].",
                storage.describe(),
                toml_key(client_id)
            );
            true
        }
        Ok(ClientSecretWrite::Replaced) => {
            println!(
                "Replaced the secret of [auth.clients.{}] in {}: every device enrolled",
                toml_key(client_id),
                storage.describe()
            );
            println!("with the old one has to scan again.");
            true
        }
        Err(e) => {
            // Not fatal, but loud: without the file the server never sees it.
            eprintln!("warning: {e:#}, so add it by hand:");
            println!("[auth.clients.{}]", toml_key(client_id));
            println!("secret = \"{}\"", secret);
            false
        }
    };
    println!();

    // Only worth saying when there is a file to edit: a config that could not be
    // written has no `[auth]` to enable either.
    if written && !auth_enabled {
        eprintln!(
            "warning: [auth] enabled is not true in {}, so the server will not ask for this \
             secret; add enabled = true under [auth]",
            storage.describe()
        );
    }
    println!("The 2FA settings are read once at startup, so restart the server to pick");
    println!("up the new client. Scanning the code above only imports the credentials");
    println!("into the app; it does not change anything on the server.");
}

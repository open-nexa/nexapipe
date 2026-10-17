//! Device keys, end to end: a device whose credential is an Ed25519 key
//! instead of a TOTP secret.
//!
//! Same harness as `two_factor_lockout.rs`: `perform_authentication` needs a
//! live QUIC connection, so these drive the two halves it is made of — the
//! client's `TwoFactorAuth`, which signs with a key here instead of HMACing
//! with a secret, and the server's `TotpValidator` — against each other, plus
//! the counter writeback that has to leave a key device's entry intact.

use nexapipe::auth::{AuthConfig, AuthError, ClientAuth, DeviceAuth, TotpValidator};
use nexapipe::config::ProxyConfig;
use nexapipe::config_watcher::save_auth_state;
use nexapipe_client::auth::{TotpAlgorithm, TwoFactorAuth};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// A 160-bit Base32 secret — the client's own. In this file it is always the
/// credential a key device must *not* be answerable with.
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The nonce the tests sign over, minted the way the connection layer mints
/// its challenge (`conn::perform_authentication` draws 32 random bytes).
fn fresh_nonce() -> Vec<u8> {
    (0..32).map(|_| rand::random::<u8>()).collect()
}

/// One client whose single device proves itself with a key, in the shape
/// `nexapipe client add <id> --device phone --public-key <hex>` writes: a
/// `public_key` and no secret.
fn auth_config_with_key_device() -> (AuthConfig, iroh::SecretKey) {
    let key = iroh::SecretKey::generate();
    let mut config = AuthConfig {
        enabled: true,
        max_attempts: 3,
        lockout_duration: 60,
        ..AuthConfig::default()
    };
    config.clients.insert(
        "client-001".to_string(),
        ClientAuth {
            secret: SECRET.to_string(),
            created_at: "0".to_string(),
            allow_hosts: None,
            pending_enrollment: None,
            devices: HashMap::from([(
                "phone".to_string(),
                DeviceAuth {
                    secret: String::new(),
                    public_key: Some(nexapipe::auth::public_key_hex(&key.public())),
                    created_at: "0".to_string(),
                    last_used: None,
                },
            )]),
            unnamed_device_allowed: true,
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        },
    );
    (config, key)
}

/// `perform_authentication`'s counting rule, mirrored: only a wrong credential
/// (`Ok(false)`) is recorded toward the lockout. Every `Err` — a stale
/// timestamp, a config the server cannot use — is a refusal and moves nothing.
fn count(config: &mut AuthConfig, outcome: &Result<bool, AuthError>) {
    if matches!(outcome, Ok(false)) {
        let max_attempts = config.max_attempts;
        let lockout_duration = config.lockout_duration;
        config
            .clients
            .get_mut("client-001")
            .unwrap()
            .record_failure(max_attempts, lockout_duration);
    }
}

/// The whole point of the key path: a device whose credential is a key signs
/// the challenge — the same bytes the secret path HMACs — and the server
/// verifies it against the public half it holds. No code travels at all.
#[test]
fn a_key_device_proves_itself_with_a_signature() {
    let (config, key) = auth_config_with_key_device();
    let client = TwoFactorAuth::with_key("client-001", key, "phone");

    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = client
        .sign_challenge(&nonce, timestamp)
        .expect("signing cannot fail");

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        Some("phone"),
        &nonce,
        timestamp,
        &signature,
        "",
    );
    assert!(
        matches!(outcome, Ok(true)),
        "a correctly signed response from a key device must verify, got {outcome:?}"
    );
}

/// A signature from a key the server does not hold is a wrong credential:
/// `Ok(false)`, the one outcome that is counted — for a key device it is also
/// the *only* wrong-credential signal there is, since there is no code to be
/// the wrong one. After `max_attempts` the client is locked, and even the
/// genuine device is refused until the lockout clears.
#[test]
fn a_wrong_signature_is_refused_and_counted() {
    let (mut config, key) = auth_config_with_key_device();
    let genuine = TwoFactorAuth::with_key("client-001", key, "phone");
    let impostor = TwoFactorAuth::with_key("client-001", iroh::SecretKey::generate(), "phone");

    for _ in 0..3 {
        let nonce = fresh_nonce();
        let timestamp = now();
        let signature = impostor.sign_challenge(&nonce, timestamp).unwrap();
        let outcome = TotpValidator::new(&config).verify_response(
            "client-001",
            Some("phone"),
            &nonce,
            timestamp,
            &signature,
            "",
        );
        assert!(
            matches!(outcome, Ok(false)),
            "a foreign key is a wrong credential, not an error, got {outcome:?}"
        );
        count(&mut config, &outcome);
    }

    assert!(
        config.clients["client-001"].is_locked_out(),
        "three wrong signatures must lock the client out"
    );

    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = genuine.sign_challenge(&nonce, timestamp).unwrap();
    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        Some("phone"),
        &nonce,
        timestamp,
        &signature,
        "",
    );
    assert!(
        matches!(outcome, Err(AuthError::LockedOut)),
        "the counter is the client's, so the real device waits too, got {outcome:?}"
    );
}

/// A stale timestamp is refused and counted for nothing, even with a
/// perfectly good signature: a peer that cannot sign anything current must not
/// be able to burn the client's attempts.
#[test]
fn a_stale_timestamp_is_refused_without_counting() {
    let (mut config, key) = auth_config_with_key_device();
    let client = TwoFactorAuth::with_key("client-001", key, "phone");

    for _ in 0..10 {
        let nonce = fresh_nonce();
        let stale = now() - 120;
        let signature = client.sign_challenge(&nonce, stale).unwrap();
        let outcome = TotpValidator::new(&config).verify_response(
            "client-001",
            Some("phone"),
            &nonce,
            stale,
            &signature,
            "",
        );
        assert!(
            matches!(outcome, Err(AuthError::StaleTimestamp)),
            "a stale response is a refusal, got {outcome:?}"
        );
        count(&mut config, &outcome);
    }

    assert_eq!(
        config.clients["client-001"].failed_attempts, 0,
        "refusals are not failures"
    );
    assert!(!config.clients["client-001"].is_locked_out());
}

/// A device known by a key has exactly one way in: a signature. The client's
/// own secret — a perfect HMAC and a perfectly good code — is a wrong
/// credential for it, never a fallback. A server that fell back would leave
/// the device reachable with a shared secret after its key was meant to be
/// the only credential it has.
#[test]
fn a_key_device_is_not_reachable_with_the_clients_secret() {
    let (config, _key) = auth_config_with_key_device();
    let secret_client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = secret_client.sign_challenge(&nonce, timestamp).unwrap();
    let code = secret_client.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        Some("phone"),
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Ok(false)),
        "the client's secret is not the device's credential, got {outcome:?}"
    );

    // The same secret, naming no device, still opens the unnamed slot — the
    // key table does not take the client's own credential out of service.
    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        None,
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Ok(true)),
        "the unnamed device still answers with the client's secret, got {outcome:?}"
    );
}

/// A device entry with neither credential — which the loader refuses from a
/// file, but which can exist in memory — is a config the server cannot use:
/// `Err`, not a wrong credential, and so it is never counted. A `public_key`
/// that is not a key reads the same way, refused where it would first be
/// used rather than at any handshake.
#[test]
fn a_device_config_the_server_cannot_use_is_a_refusal() {
    let (mut config, _key) = auth_config_with_key_device();
    {
        let client = config.clients.get_mut("client-001").unwrap();
        client.devices.insert(
            "broken".to_string(),
            DeviceAuth {
                secret: String::new(),
                public_key: None,
                created_at: "0".to_string(),
                last_used: None,
            },
        );
        client.devices.insert(
            "garbled".to_string(),
            DeviceAuth {
                secret: String::new(),
                public_key: Some("not a key".to_string()),
                created_at: "0".to_string(),
                last_used: None,
            },
        );
    }

    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();
    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = client.sign_challenge(&nonce, timestamp).unwrap();
    let code = client.generate_code().unwrap();

    for device in ["broken", "garbled"] {
        let outcome = TotpValidator::new(&config).verify_response(
            "client-001",
            Some(device),
            &nonce,
            timestamp,
            &signature,
            &code,
        );
        assert!(
            matches!(outcome, Err(AuthError::InvalidSecret)),
            "a device with no usable credential is a server-side fault, got {outcome:?}"
        );
    }
}

/// The counter writeback into a config whose device is key-based: the
/// `public_key` survives, the `last_used` stamp is written, and nothing else
/// appears — an entry that grew a second credential would be one the next
/// load refuses.
#[test]
fn keeps_a_key_device_when_it_writes_counters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap();
    let key = nexapipe::auth::public_key_hex(&iroh::SecretKey::generate().public());
    std::fs::write(
        &path,
        format!(
            "# operator comment that must survive\n\
             [auth]\n\
             enabled = true\n\
             [auth.clients.client-001]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n\
             created_at = \"1723756800\"\n\
             [auth.clients.client-001.devices.phone]\n\
             public_key = \"{key}\"\n\
             created_at = \"1723756801\"\n"
        ),
    )
    .unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path_str).unwrap();
    let mut auth = auth.expect("the config declares [auth]");
    let phone = &auth.clients["client-001"].devices["phone"];
    assert_eq!(phone.public_key.as_deref(), Some(key.as_str()));
    assert!(phone.secret.is_empty(), "a key device has no secret");

    auth.clients
        .get_mut("client-001")
        .unwrap()
        .record_device_success("phone");
    save_auth_state(path_str, &auth).unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("# operator comment that must survive"),
        "comments are not the server's to rewrite"
    );
    assert!(
        on_disk.contains(&format!("public_key = \"{key}\"")),
        "the key survives the writeback: {on_disk}"
    );
    assert!(
        on_disk.contains("last_used = "),
        "the stamp that says the device is in use was written: {on_disk}"
    );

    let (_, reloaded) = ProxyConfig::load_with_auth(path_str).unwrap();
    let reloaded = reloaded.unwrap();
    let phone = &reloaded.clients["client-001"].devices["phone"];
    assert_eq!(phone.public_key.as_deref(), Some(key.as_str()));
    assert!(phone.secret.is_empty());
}

//! The 2FA lockout and challenge-binding behaviour, end to end.
//!
//! `perform_authentication` needs a live QUIC connection, so these tests drive
//! the two halves it is made of — the client's `TwoFactorAuth` (signing and
//! code generation) and the server's `TotpValidator` (verification) — against
//! each other, plus the `save_auth_state` round trip that makes a lockout
//! survive a restart.

use nexapipe::auth::{AuthConfig, AuthError, ClientAuth, DeviceAuth, TotpValidator};
use nexapipe::config::ProxyConfig;
use nexapipe::config_watcher::save_auth_state;
use nexapipe_client::auth::{TotpAlgorithm, TwoFactorAuth};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// A 160-bit Base32 secret, the length `--generate-2fa` hands out. The
/// example configs carry an 80-bit one for brevity, but `totp-rs` refuses to
/// build a validator from anything shorter than 128 bits.
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// Two more of the same length, for the devices under that client. Distinct
/// from `SECRET` on purpose: a device that could authenticate with the
/// client's secret would not be a separate credential.
const LAPTOP_SECRET: &str = "KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP";
const PHONE_SECRET: &str = "MFRGGZDFMZTWQ2LKNNWG23TPKRSXG5BA";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The nonce the tests sign over, minted the way the connection layer mints
/// its challenge (`conn::perform_authentication` draws 32 random bytes).
///
/// A test could just as well sign over a fixed literal, but a constant sitting
/// in a nonce slot is exactly what CWE-798 is about — and it would be the one
/// place in the tree where the challenge is the same twice.
fn fresh_nonce() -> Vec<u8> {
    (0..32).map(|_| rand::random::<u8>()).collect()
}

fn auth_config_with_client(max_attempts: u32, lockout_duration: u64) -> AuthConfig {
    let mut config = AuthConfig {
        enabled: true,
        max_attempts,
        lockout_duration,
        ..AuthConfig::default()
    };
    config.clients.insert(
        "client-001".to_string(),
        ClientAuth {
            secret: SECRET.to_string(),
            created_at: "0".to_string(),
            allow_hosts: None,
            pending_enrollment: None,
            devices: HashMap::new(),
            unnamed_device_allowed: true,
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        },
    );
    config
}

/// One client with two devices under it — the shape per-device revocation
/// exists for. The client keeps its own `secret`, which is the credential of
/// the device that has no name.
fn auth_config_with_devices(max_attempts: u32, lockout_duration: u64) -> AuthConfig {
    let mut config = AuthConfig {
        enabled: true,
        max_attempts,
        lockout_duration,
        ..AuthConfig::default()
    };
    config.clients.insert(
        "client-001".to_string(),
        ClientAuth {
            secret: SECRET.to_string(),
            created_at: "0".to_string(),
            allow_hosts: None,
            pending_enrollment: None,
            devices: HashMap::from([
                (
                    "laptop".to_string(),
                    DeviceAuth {
                        secret: LAPTOP_SECRET.to_string(),
                        created_at: "0".to_string(),
                        last_used: None,
                    },
                ),
                (
                    "phone".to_string(),
                    DeviceAuth {
                        secret: PHONE_SECRET.to_string(),
                        created_at: "0".to_string(),
                        last_used: None,
                    },
                ),
            ]),
            unnamed_device_allowed: true,
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        },
    );
    config
}

/// A response the client signed over the nonce the server issued verifies.
///
/// This is the cross-crate contract of the signed AUTH_RESPONSE: both halves
/// have to agree on HMAC-SHA256(secret, nonce || timestamp_le) without sharing
/// code, so the signature is computed by the client crate and checked by the
/// server crate.
#[test]
fn accepts_a_signed_current_response() {
    let config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = client
        .sign_challenge(&nonce, timestamp)
        .expect("HMAC takes a key of any length");
    let code = client.generate_code().unwrap();

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
        "a correctly signed current response must verify, got {:?}",
        outcome
    );
}

/// A response signed over a different nonce is refused — this is what stops a
/// captured AUTH_RESPONSE being replayed at another connection, which gets a
/// fresh nonce every time.
#[test]
fn rejects_a_response_signed_over_a_different_nonce() {
    let config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let timestamp = now();
    let signed_over = fresh_nonce();
    let signature = client
        .sign_challenge(&signed_over, timestamp)
        .expect("HMAC takes a key of any length");
    let code = client.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        None,
        &fresh_nonce(),
        timestamp,
        &signature,
        &code,
    );
    assert!(matches!(outcome, Err(AuthError::ChallengeMismatch)));
}

/// A timestamp outside the ±30s window is refused even when correctly signed,
/// so a signed response cannot be replayed next week.
#[test]
fn rejects_a_stale_timestamp() {
    let config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let stale = now() - 120;
    let nonce = fresh_nonce();
    let signature = client
        .sign_challenge(&nonce, stale)
        .expect("HMAC takes a key of any length");
    let code = client.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        None,
        &nonce,
        stale,
        &signature,
        &code,
    );
    assert!(matches!(outcome, Err(AuthError::StaleTimestamp)));
}

/// A correctly signed response with a wrong code is `Ok(false)`, not an `Err`:
/// it is the only outcome the connection layer counts toward the lockout,
/// while refusals (bad signature, stale timestamp, …) never do.
#[test]
fn reports_a_wrong_code_as_a_counted_failure() {
    let config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = client
        .sign_challenge(&nonce, timestamp)
        .expect("HMAC takes a key of any length");

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        None,
        &nonce,
        timestamp,
        &signature,
        "000000",
    );
    assert!(matches!(outcome, Ok(false)));
}

/// The lockout itself: `max_attempts` counted failures lock the client, and a
/// locked client is refused — even with a correct signature and code — until
/// `record_success` clears the counters. The failure loop mirrors what
/// `perform_authentication` runs per rejected code.
#[test]
fn locks_out_after_max_attempts() {
    let mut config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = client
        .sign_challenge(&nonce, timestamp)
        .expect("HMAC takes a key of any length");
    let code = client.generate_code().unwrap();

    for _ in 0..3 {
        let outcome = TotpValidator::new(&config).verify_response(
            "client-001",
            None,
            &nonce,
            timestamp,
            &signature,
            "000000",
        );
        assert!(matches!(outcome, Ok(false)));
        config
            .clients
            .get_mut("client-001")
            .unwrap()
            .record_failure(config.max_attempts, config.lockout_duration);
    }

    assert!(
        config.clients.get("client-001").unwrap().is_locked_out(),
        "three counted failures must lock the client"
    );

    let locked = TotpValidator::new(&config).verify_response(
        "client-001",
        None,
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(locked, Err(AuthError::LockedOut)),
        "a locked client is refused even with a perfect response"
    );

    config
        .clients
        .get_mut("client-001")
        .unwrap()
        .record_success();
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
        "record_success must clear the lockout"
    );
}

/// Counters persist through `save_auth_state` and come back on the next load,
/// without touching anything a human wrote into the file.
#[test]
fn persists_lockout_counters_across_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap();
    std::fs::write(
        &path,
        "# operator comment that must survive\n\
         [auth]\n\
         enabled = true\n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         created_at = \"1723756800\"\n\
         [auth.clients.client-002]\n\
         secret = \"KBSWY3DPEHPK3PXQ\"\n\
         created_at = \"1723756800\"\n",
    )
    .unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path_str).unwrap();
    let mut auth = auth.expect("the config declares [auth]");

    let entry = auth.clients.get_mut("client-001").unwrap();
    entry.record_failure(3, 60);
    entry.record_failure(3, 60);
    entry.last_used = Some(1700000000);
    save_auth_state(path_str, &auth).unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("# operator comment that must survive"),
        "comments are not the server's to rewrite"
    );
    assert!(on_disk.contains("failed_attempts = 2"));
    assert!(on_disk.contains("last_used = 1700000000"));
    assert!(
        on_disk.contains("KBSWY3DPEHPK3PXQ"),
        "the untouched client stays as written"
    );

    let (_, reloaded) = ProxyConfig::load_with_auth(path_str).unwrap();
    let reloaded = reloaded.unwrap();
    let entry = reloaded.clients.get("client-001").unwrap();
    assert_eq!(entry.failed_attempts, 2);
    assert_eq!(entry.last_used, Some(1700000000));

    // A success zeroes the counters, and zeroed counters leave no keys behind.
    let mut auth = reloaded;
    auth.clients.get_mut("client-001").unwrap().record_success();
    save_auth_state(path_str, &auth).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(!on_disk.contains("failed_attempts"));
    assert!(!on_disk.contains("locked_until"));

    let (_, reloaded) = ProxyConfig::load_with_auth(path_str).unwrap();
    let reloaded = reloaded.unwrap();
    let entry = reloaded.clients.get("client-001").unwrap();
    assert_eq!(entry.failed_attempts, 0);
    assert!(entry.locked_until.is_none());
}

/// A client that exists only in memory is not written to disk: the operator
/// may have removed it from the file while the server was running, and a
/// section without its secret would break the next load.
#[test]
fn does_not_resurrect_a_client_removed_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap();
    std::fs::write(
        &path,
        "[auth]\n\
         enabled = true\n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    )
    .unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path_str).unwrap();
    let mut auth = auth.unwrap();
    auth.clients.insert(
        "client-002".to_string(),
        ClientAuth {
            secret: "KBSWY3DPEHPK3PXQ".to_string(),
            created_at: "0".to_string(),
            allow_hosts: None,
            pending_enrollment: None,
            devices: HashMap::new(),
            unnamed_device_allowed: true,
            last_used: Some(1),
            failed_attempts: 1,
            locked_until: None,
        },
    );

    save_auth_state(path_str, &auth).unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        !on_disk.contains("client-002"),
        "a client removed from the file must not come back"
    );
}

/// A device authenticates with its own secret, not the client's: signed with
/// the laptop's it verifies as the laptop, and the same signature offered
/// under another device's name does not.
#[test]
fn a_device_authenticates_with_its_own_secret() {
    let config = auth_config_with_devices(3, 60);
    let laptop = TwoFactorAuth::new("client-001", LAPTOP_SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = laptop.sign_challenge(&nonce, timestamp).unwrap();
    let code = laptop.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        Some("laptop"),
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Ok(true)),
        "the laptop's own response must verify, got {outcome:?}"
    );

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        Some("phone"),
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Err(AuthError::ChallengeMismatch)),
        "the laptop's signature is not the phone's credential, got {outcome:?}"
    );
}

/// The promise of the whole feature: dropping a device's entry stops that
/// device, and the one next to it keeps working — which is what rotating the
/// one shared `secret` could not do.
#[test]
fn revoking_one_device_leaves_the_other_authenticating() {
    let mut config = auth_config_with_devices(3, 60);
    config
        .clients
        .get_mut("client-001")
        .unwrap()
        .devices
        .remove("phone");

    let phone = TwoFactorAuth::new("client-001", PHONE_SECRET, TotpAlgorithm::SHA1).unwrap();
    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = phone.sign_challenge(&nonce, timestamp).unwrap();
    let code = phone.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        Some("phone"),
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Err(AuthError::UnknownDevice)),
        "a revoked device is refused even with a perfect response, got {outcome:?}"
    );

    let laptop = TwoFactorAuth::new("client-001", LAPTOP_SECRET, TotpAlgorithm::SHA1).unwrap();
    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = laptop.sign_challenge(&nonce, timestamp).unwrap();
    let code = laptop.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        Some("laptop"),
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Ok(true)),
        "the laptop is untouched by the phone's revocation, got {outcome:?}"
    );
}

/// The fallback: a device table does not take the client's own `secret` out of
/// service, because that is the credential of the device that has no name —
/// every device that existed before tables could be written.
#[test]
fn an_unnamed_device_still_answers_with_the_clients_secret() {
    let config = auth_config_with_devices(3, 60);
    let unnamed = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = unnamed.sign_challenge(&nonce, timestamp).unwrap();
    let code = unnamed.generate_code().unwrap();

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
        "no name sent is the unnamed device, got {outcome:?}"
    );
}

/// The lockout is the client's, not the device's: a device that burns the
/// counter takes its siblings down with it. The alternative — one counter per
/// device, keyed by a name the peer chooses — would let a peer escape by
/// naming a device nobody has heard of.
#[test]
fn a_device_shares_its_clients_lockout_counter() {
    let mut config = auth_config_with_devices(3, 60);
    let laptop = TwoFactorAuth::new("client-001", LAPTOP_SECRET, TotpAlgorithm::SHA1).unwrap();

    for _ in 0..3 {
        let nonce = fresh_nonce();
        let timestamp = now();
        let signature = laptop.sign_challenge(&nonce, timestamp).unwrap();
        let outcome = TotpValidator::new(&config).verify_response(
            "client-001",
            Some("laptop"),
            &nonce,
            timestamp,
            &signature,
            "000000",
        );
        assert!(matches!(outcome, Ok(false)), "{outcome:?}");
        config
            .clients
            .get_mut("client-001")
            .unwrap()
            .record_failure(config.max_attempts, config.lockout_duration);
    }

    assert!(
        config.clients["client-001"].is_locked_out(),
        "three wrong codes from one device lock the client out"
    );

    // Naming a device that has never been issued does not unlock anything.
    let phone = TwoFactorAuth::new("client-001", PHONE_SECRET, TotpAlgorithm::SHA1).unwrap();
    let nonce = fresh_nonce();
    let timestamp = now();
    let signature = phone.sign_challenge(&nonce, timestamp).unwrap();
    let code = phone.generate_code().unwrap();
    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        Some("phone"),
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Err(AuthError::LockedOut)),
        "the lockout is the client's, so another device hits it too: {outcome:?}"
    );

    // And so does the device that has no name.
    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        None,
        &nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(matches!(outcome, Err(AuthError::LockedOut)), "{outcome:?}");
}

/// `save_auth_state` rewrites the file on every counted failure — which is
/// also the file the device table lives in. A write that dropped the table
/// would revoke every device the first time somebody mistyped a code, and it
/// would do it on disk only, where the running server still has them.
#[test]
fn keeps_the_device_table_when_it_writes_counters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap();
    std::fs::write(
        &path,
        "# operator comment that must survive\n\
         [auth]\n\
         enabled = true\n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         created_at = \"1723756800\"\n\
         [auth.clients.client-001.devices.laptop]\n\
         secret = \"KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP\"\n\
         created_at = \"1723756801\"\n\
         [auth.clients.client-001.devices.phone]\n\
         secret = \"MFRGGZDFMZTWQ2LKNNWG23TPKRSXG5BA\"\n",
    )
    .unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path_str).unwrap();
    let mut auth = auth.expect("the config declares [auth]");
    assert_eq!(
        auth.clients["client-001"].devices.len(),
        2,
        "the fixture carries two devices"
    );

    auth.clients
        .get_mut("client-001")
        .unwrap()
        .record_failure(3, 60);
    save_auth_state(path_str, &auth).unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("failed_attempts = 1"),
        "the counter was written: {on_disk}"
    );
    assert!(
        on_disk.contains("KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP"),
        "the laptop's secret survives a counter write: {on_disk}"
    );
    assert!(
        on_disk.contains("MFRGGZDFMZTWQ2LKNNWG23TPKRSXG5BA"),
        "so does the phone's: {on_disk}"
    );
    assert!(
        on_disk.contains("created_at = \"1723756801\""),
        "a device's own keys are not the server's to rewrite: {on_disk}"
    );

    let (_, reloaded) = ProxyConfig::load_with_auth(path_str).unwrap();
    let reloaded = reloaded.unwrap();
    let client = &reloaded.clients["client-001"];
    assert_eq!(client.devices.len(), 2, "{client:?}");
    assert_eq!(
        client.devices["laptop"].secret,
        "KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP"
    );
    assert_eq!(
        client.devices["phone"].secret,
        "MFRGGZDFMZTWQ2LKNNWG23TPKRSXG5BA"
    );
    assert_eq!(client.failed_attempts, 1);
}

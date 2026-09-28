//! The 2FA settings of the shipped example config, end to end.
//!
//! These tests are about the config *loading* path, which is easy to break in a
//! way the compiler accepts: when the `[auth]` table cannot be read, the server
//! used to get `None` and quietly run with 2FA disabled, which is the worst
//! possible outcome for a security feature. It refuses to start now, and the
//! last test here pins that.

use nexapipe::auth::OtpAuthUri;
use nexapipe::config::ProxyConfig;

const EXAMPLE_CONFIG: &str = "../../config.toml.2fa.example";

/// `[auth]` reaches [`nexapipe::auth::AuthConfig`] with all of its clients.
///
/// Regression: the table used to be read with `str::parse::<toml::Value>()`,
/// which parses a single TOML value rather than a document and therefore always
/// failed, leaving the server without any 2FA configuration.
#[test]
fn loads_the_auth_section_of_the_example_config() {
    let (_, auth) =
        ProxyConfig::load_with_auth(EXAMPLE_CONFIG).expect("the example config has to parse");

    let auth = auth.expect("the example config declares an [auth] section");
    assert!(auth.enabled, "the example config enables 2FA");
    assert_eq!(auth.issuer, "NexaPipe");
    assert_eq!(auth.time_step, 30);
    assert_eq!(auth.digits, 6);

    let client = auth
        .clients
        .get("client-001")
        .expect("client-001 is configured");
    assert_eq!(client.secret, "JBSWY3DPEHPK3PXP");
    assert_eq!(
        auth.clients.get("client-002").map(|c| c.secret.as_str()),
        Some("KBSWY3DPEHPK3PXQ")
    );
}

/// A config without any `[auth]` table loads as "no 2FA", not as an error.
#[test]
fn accepts_a_config_without_auth() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "").unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path.to_str().unwrap()).unwrap();
    assert!(auth.is_none());
}

/// An `[auth]` table with a broken field is reported instead of being dropped,
/// so a typo cannot silently disable 2FA.
#[test]
fn reports_a_broken_auth_section() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\n\
         enabled = \"not a boolean\"\n",
    )
    .unwrap();

    let error = ProxyConfig::load_with_auth(path.to_str().unwrap()).unwrap_err();
    assert!(
        error.to_string().contains("auth config"),
        "unexpected error: {error:#}"
    );
}

/// The same broken table stops the server instead of turning 2FA off.
///
/// Regression: the startup path logged the error and carried on with no 2FA at
/// all, so `enable = true` and a broken section were the same deployment — one
/// silently unauthenticated, the other only one line of log louder.
#[test]
fn a_broken_auth_section_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[[routes]]\n\
         host_pattern = \"*\"\n\
         mode = \"http\"\n\
         backends = [\"http://127.0.0.1:18080\"]\n\
         \n\
         [auth]\n\
         enabled = \"not a boolean\"\n",
    )
    .unwrap();

    let output = duct::cmd(
        env!("CARGO_BIN_EXE_nexapipe"),
        ["--config", path.to_str().unwrap()],
    )
    .stdin_null()
    .stdout_capture()
    .stderr_capture()
    .unchecked()
    .run()
    .expect("run nexapipe");

    // Both streams: the CLI prints through tracing, which decides on its own
    // which one a refusal lands on.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "a server with a broken [auth] must not start:\n{text}"
    );
    assert!(
        text.contains("auth config"),
        "the refusal names the section that broke:\n{text}"
    );
}

/// The clients of the example config enroll through the canonical URI.
#[test]
fn builds_the_enrollment_uri_from_the_loaded_settings() {
    let (_, auth) = ProxyConfig::load_with_auth(EXAMPLE_CONFIG).unwrap();
    let auth = auth.unwrap();
    let client = auth.clients.get("client-001").unwrap();

    let uri = OtpAuthUri::from_auth_config(&auth.issuer, "client-001", &client.secret, &auth)
        .expect("the example credentials are valid");

    assert_eq!(
        uri.to_uri(),
        "otpauth://totp/NexaPipe:client-001\
         ?secret=JBSWY3DPEHPK3PXP&issuer=NexaPipe&algorithm=SHA1&digits=6&period=30"
    );
    assert!(uri.client_warnings().is_empty());
}

//! The `[peers]` allow-list, end to end through the config file.
//!
//! The unit tests in `config.rs` cover the parse; this covers the same question
//! from outside the crate, where a change to `PeersConfig`'s field names or to
//! `ProxyConfig`'s own shape would show up. The failure this guards against is
//! the quiet one: a section that stops parsing into the right set means the
//! listener is less restricted than the operator wrote, and nothing says so.

use nexapipe::config::ProxyConfig;

/// A Node ID to write into `allow`, derived rather than invented so it is a real
/// ed25519 public key.
fn node_id(seed: u8) -> String {
    iroh::SecretKey::from_bytes(&[seed; 32])
        .public()
        .to_string()
}

fn write_config(dir: &std::path::Path, peers_block: &str) -> String {
    let path = dir.join("config.toml");
    std::fs::write(&path, peers_block).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn a_config_without_peers_leaves_the_listener_unrestricted() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "");

    let config = ProxyConfig::from_file(&path).expect("a config with no [peers] still parses");
    assert!(config.peers.is_none());
}

#[test]
fn an_empty_peers_section_leaves_the_listener_unrestricted() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "[peers]\n");

    let config = ProxyConfig::from_file(&path).expect("an empty [peers] section parses");
    let allow = config
        .peers
        .as_ref()
        .expect("[peers] is present")
        .parse_allow_list()
        .expect("a section with no `allow` key is not an error");

    assert!(allow.is_none(), "no `allow` key means every peer passes");
}

#[test]
fn a_peers_allow_list_round_trips_through_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let source = format!("[peers]\nallow = [{:?}, {:?}]\n", node_id(7), node_id(9));
    let path = write_config(dir.path(), &source);

    let config = ProxyConfig::from_file(&path).expect("the config parses");
    let allow = config
        .peers
        .as_ref()
        .expect("[peers] is present")
        .parse_allow_list()
        .expect("both entries are valid Node IDs")
        .expect("the list is configured");

    assert_eq!(allow.len(), 2);
    assert!(allow.contains(&node_id(7).parse::<iroh::EndpointId>().unwrap()));
    assert!(allow.contains(&node_id(9).parse::<iroh::EndpointId>().unwrap()));
}

/// The one mistake that must not be silent: a list meant to refuse strangers
/// coming out with fewer entries than were written, or with none at all.
#[test]
fn a_broken_entry_and_an_empty_list_are_both_errors() {
    let dir = tempfile::tempdir().unwrap();

    let broken = write_config(
        dir.path(),
        &format!("[peers]\nallow = [{:?}, \"oops\"]\n", node_id(1)),
    );
    let err = ProxyConfig::from_file(&broken)
        .unwrap()
        .peers
        .unwrap()
        .parse_allow_list()
        .expect_err("a malformed entry must not be dropped");
    assert!(err.to_string().contains("oops"), "{err}");

    let empty = write_config(dir.path(), "[peers]\nallow = []\n");
    let err = ProxyConfig::from_file(&empty)
        .unwrap()
        .peers
        .unwrap()
        .parse_allow_list()
        .expect_err("an empty list must not be guessed at");
    assert!(err.to_string().contains("refuses every peer"), "{err}");
}

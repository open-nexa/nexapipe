//! The tests of the command line.

use nexapipe::config::ProxyConfig;

use super::client::{seconds_of, stamp};
use super::config::toml_key;
use super::invite::invite_domains;

/// A config written the way an operator writes one, read the way the
/// server reads it: the tests go through the real parser rather than
/// around it, so a key that stops being readable shows up here.
fn config(toml: &str) -> ProxyConfig {
    toml::from_str(toml).expect("the config in the test is readable")
}

/// A timestamp is carried as a string, and one written by hand may be
/// anything: what the operator sees is `-` rather than a wrong date.
#[test]
fn a_timestamp_that_is_not_one_reads_as_absent() {
    assert_eq!(seconds_of("1700000000"), Some(1_700_000_000));
    assert_eq!(seconds_of("  1700000000  "), Some(1_700_000_000));
    assert_eq!(seconds_of("yesterday"), None);
    assert_eq!(seconds_of(""), None);
}

/// The other half of the same pair: absent is `-`, not a date.
#[test]
fn an_absent_timestamp_is_drawn_as_a_dash() {
    assert_eq!(stamp(None), "-");
    // A timestamp that is out of range for the calendar is absent too.
    assert_eq!(stamp(Some(i64::MAX)), "-");
    assert_ne!(stamp(Some(1_700_000_000)), "-");
}

/// The section name in a message has to be the section name in the file.
/// A TOML key with a dot in it is quoted; one with a dash is bare.
#[test]
fn a_toml_key_is_rendered_the_way_the_file_writes_it() {
    assert_eq!(toml_key("client-001"), "client-001");
    assert_eq!(toml_key("client.001"), "\"client.001\"");
}

/// Where an invite's domains come from, in order: what was asked for,
/// then the client's own list, then the routes the server serves.
#[test]
fn the_domains_of_an_invite_come_from_the_first_source_that_has_any() {
    let explicit = vec!["asked-for.example".to_string()];
    let with_local = config(
        r#"
        [local_proxy]
        enabled = true
        listen_addr = "127.0.0.1:8080"
        proxy_domains = ["from-local.example"]

        [[routes]]
        host_pattern = "from-routes.example"
        backends = []
        "#,
    );
    let with_routes = config(
        r#"
        [[routes]]
        host_pattern = "from-routes.example"
        backends = []
        "#,
    );

    let (domains, source) = invite_domains(&explicit, Some(&with_local));
    assert_eq!(domains, explicit);
    assert_eq!(source, "from --invite-domains");

    let (domains, source) = invite_domains(&[], Some(&with_local));
    assert_eq!(domains, vec!["from-local.example".to_string()]);
    assert_eq!(source, "from [local_proxy] proxy_domains");

    let (domains, source) = invite_domains(&[], Some(&with_routes));
    assert_eq!(domains, vec!["from-routes.example".to_string()]);
    assert_eq!(source, "from the [[routes]] host patterns");
}

/// The catch-all is not a domain: an invite that carried it would name
/// every host in the world, and it would be refused by the client that
/// read it.
#[test]
fn the_catch_all_is_not_a_domain_of_its_own() {
    let catch_all = config(
        r#"
        [[routes]]
        host_pattern = "*"
        backends = []
        "#,
    );
    let (domains, source) = invite_domains(&[], Some(&catch_all));
    assert!(domains.is_empty(), "{domains:?}");
    assert_eq!(source, "none configured");
}

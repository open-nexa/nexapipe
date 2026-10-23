//! The tests of the proxy.

use super::access::response_has_body;
use super::plaintext::{
    is_tls_connection, may_bind_plaintext, plaintext_auth_conflict, remaining_budget,
};
use std::net::SocketAddr;

#[tokio::test(start_paused = true)]
async fn the_header_budget_is_what_is_left_of_the_connection_budget() {
    // The observation this test exists for: the wait to tell a TLS
    // session from an HTTP request is part of the wait for the head, not
    // time on top of it. hyper gets what is left of the one budget, so a
    // client that says nothing is closed after `header_secs` in total
    // rather than after the classification wait and then a fresh header
    // deadline on top of that.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    assert_eq!(
        remaining_budget(deadline),
        std::time::Duration::from_secs(30)
    );

    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    assert_eq!(
        remaining_budget(deadline),
        std::time::Duration::from_secs(20)
    );

    // A budget that is spent is spent: the connection is closed rather
    // than given a fresh deadline.
    tokio::time::advance(std::time::Duration::from_secs(30)).await;
    assert_eq!(remaining_budget(deadline), std::time::Duration::ZERO);
}

/// The first byte decides which protocol a stream carries, so the plaintext
/// listener must take the longer of `header_secs` and `tls_hello_secs` for
/// it, exactly as the iroh path does. With the shorter of the two, a short
/// `header_secs` closed a TLS session before its `ClientHello` could
/// classify it — on a configuration the README says is safe.
#[tokio::test]
async fn a_short_head_budget_still_lets_a_tls_client_classify() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Later than the head's budget, earlier than the hello's: the old
        // `min` gave up at the head's deadline and called this a request.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &[0x16])
            .await
            .unwrap();
    });

    let (server, _) = listener.accept().await.unwrap();
    let head_deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
    let is_tls = is_tls_connection(&server, head_deadline, std::time::Duration::from_secs(2)).await;
    client.await.unwrap();

    assert!(
        is_tls,
        "a TLS client slower than header_secs but within tls_hello_secs must still classify"
    );
}

fn addr(ip: &str, port: u16) -> SocketAddr {
    let ip: std::net::IpAddr = ip.parse().expect("valid IP");
    SocketAddr::new(ip, port)
}

/// Loopback is the only thing the plaintext listener serves without being
/// asked to: anything else publishes routes nobody has to authenticate to.
#[test]
fn loopback_binds_without_being_exposed() {
    assert!(may_bind_plaintext(addr("127.0.0.1", 8080), false));
    assert!(may_bind_plaintext(addr("::1", 8080), false));
}

#[test]
fn a_network_address_needs_expose() {
    assert!(!may_bind_plaintext(addr("0.0.0.0", 8080), false));
    assert!(!may_bind_plaintext(addr("::", 8080), false));
    assert!(!may_bind_plaintext(addr("192.168.1.10", 8080), false));
    assert!(may_bind_plaintext(addr("0.0.0.0", 8080), true));
    assert!(may_bind_plaintext(addr("192.168.1.10", 8080), true));
}

/// An exposed listener alongside enabled 2FA is a configuration that only
/// *looks* guarded: the iroh path asks for credentials, this one never does.
/// It has to be refused, not served with a log entry nobody reads.
#[test]
fn an_exposed_listener_conflicts_with_enabled_2fa() {
    let bound = addr("0.0.0.0", 8080);
    let refusal = plaintext_auth_conflict(bound, true, true).expect("the combination is refused");
    assert!(
        refusal.contains("expose = true"),
        "the refusal has to name the setting: {refusal}"
    );
}

#[test]
fn no_conflict_when_2fa_is_off_or_the_listener_is_not_exposed() {
    let bound = addr("0.0.0.0", 8080);
    // No 2FA at all: the iroh listener is unauthenticated too, so the
    // plaintext one adds no new exposure beyond what startup already
    // warns about.
    assert_eq!(plaintext_auth_conflict(bound, true, false), None);
    // 2FA on, but the listener is loopback-only.
    assert_eq!(
        plaintext_auth_conflict(addr("127.0.0.1", 8080), false, true),
        None
    );
}

/// The case where the metric must not follow the log line. A `HEAD` says how
/// long the `GET` answer would have been and then sends none of it, so
/// counting the header would report a download that never happened — and a
/// monitoring client scraping this would bill someone for it.
#[test]
fn head_has_no_body_whatever_content_length_says() {
    assert!(!response_has_body("HEAD", 200));
    assert!(!response_has_body("HEAD", 404));
    // Its content-length describes the GET, which nobody asked for.
    assert!(!response_has_body("HEAD", 204));
}

/// The statuses that answer without a payload, and keep `Content-Length`
/// from the representation they stand in for.
#[test]
fn no_content_and_not_modified_are_answered_without_a_body() {
    assert!(!response_has_body("GET", 204));
    assert!(!response_has_body("GET", 304));
    // Informational: there is nothing else these could be carrying yet.
    assert!(!response_has_body("GET", 100));
    assert!(!response_has_body("GET", 103));
}

/// The ordinary case, which is everything else on every other method.
#[test]
fn everything_else_delivers_what_content_length_says() {
    assert!(response_has_body("GET", 200));
    assert!(response_has_body("GET", 404));
    assert!(response_has_body("POST", 201));
    // Not HEAD, and not one of the bodyless statuses.
    assert!(response_has_body("OPTIONS", 200));
}

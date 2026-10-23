use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::config::CircuitBreaker;

use super::pool::origin_of;
use super::*;

fn pool(backends: &[&str]) -> BackendPool {
    BackendPool::new(
        backends.iter().map(|b| b.to_string()).collect(),
        LoadBalancingStrategy::RoundRobin,
    )
}

/// The origin of a backend address: the scheme, the host and the port.
///
/// These are the cases the request path depends on, and each of them
/// breaks in a way that only shows up at runtime: an IPv6 literal that
/// loses its brackets makes the URI invalid, and a host that loses its
/// port makes every request to that backend go to the wrong place.
#[test]
fn the_origin_keeps_the_scheme_the_host_and_the_port() {
    assert_eq!(&*origin_of("http://host:8080").unwrap(), "http://host:8080");
    assert_eq!(
        &*origin_of("https://host:8443").unwrap(),
        "https://host:8443"
    );
}

/// A backend address with no port is on the port its scheme says.
///
/// `http://host` is port 80, and `https://host` is port 443 — the same
/// rule `port_or_known_default()` applies, which is the rule the old
/// expression applied too.
#[test]
fn the_origin_fills_in_the_port_of_the_scheme() {
    assert_eq!(&*origin_of("http://host").unwrap(), "http://host:80");
    assert_eq!(&*origin_of("https://host").unwrap(), "https://host:443");
}

/// An IPv6 literal keeps its brackets.
///
/// `http://[::1]:8080` is the address of a backend on the loopback, and
/// the origin has to keep the brackets: `http::Uri` reads
/// `http://::1:8080` as a host with a port and a path, and the request
/// never reaches the backend.
#[test]
fn the_origin_keeps_the_brackets_of_an_ipv6_literal() {
    assert_eq!(
        &*origin_of("http://[::1]:8080").unwrap(),
        "http://[::1]:8080"
    );
    assert_eq!(
        &*origin_of("http://[2001:db8::1]:80").unwrap(),
        "http://[2001:db8::1]:80"
    );
}

/// An address that does not parse is refused, and the reason says why.
#[test]
fn the_origin_refuses_an_address_that_does_not_parse() {
    let reason = origin_of("not a url").expect_err("the address does not parse");
    assert!(
        reason.starts_with("invalid backend URL:"),
        "the reason names the parse: {reason}"
    );
}

/// An address that names no host is refused, and the reason says why.
///
/// A scheme that is not one of the special ones parses without a host,
/// so this is the address that reaches the second failure.
#[test]
fn the_origin_refuses_an_address_that_names_no_host() {
    let reason = origin_of("custom://").expect_err("the address names no host");
    assert_eq!(reason, "backend URL missing host");
}

/// An address of a special scheme with no host does not parse at all.
///
/// `http://` is refused by the parser, not by the host check, and the
/// reason says so.
#[test]
fn the_origin_refuses_an_address_that_does_not_parse_at_all() {
    let reason = origin_of("http://").expect_err("the address does not parse");
    assert!(
        reason.starts_with("invalid backend URL:"),
        "the reason names the parse: {reason}"
    );
}

/// Same pool with another strategy. Every test below is about one strategy's
/// choice, so which one it is should be the only thing spelled at its top.
fn pool_with(strategy: LoadBalancingStrategy, backends: &[&str]) -> BackendPool {
    BackendPool::new(backends.iter().map(|b| b.to_string()).collect(), strategy)
}

#[tokio::test]
async fn every_entry_carrying_a_url_is_marked_not_just_the_first() {
    let pool = pool(&["http://a:80", "http://a:80"]);
    assert_eq!(pool.healthy_count().await, 2);

    pool.set_backend_health("http://a:80", false).await;

    assert_eq!(
        pool.get_backend_statuses().await,
        vec![
            ("http://a:80".to_string(), false),
            ("http://a:80".to_string(), false),
        ],
        "the second entry stayed healthy, so the balancer kept picking a backend the pool had already given up on"
    );
    assert_eq!(pool.healthy_count().await, 0);
}

/// The one backend a route has is the one it serves, health or not: there is
/// no second candidate for that information to choose between, and refusing
/// would answer for every request to a route rather than let any through.
#[tokio::test]
async fn a_pool_of_one_is_handed_out_though_it_is_unhealthy() {
    let pool = pool(&["http://only:80"]);
    pool.set_backend_health("http://only:80", false).await;
    assert_eq!(pool.healthy_count().await, 0);

    let lease = pool
        .select_backend()
        .await
        .expect("a single backend is the only path this route has");
    assert_eq!(lease.url(), "http://only:80");
}

/// Several backends, none healthy: the answer is known before any dialling
/// happens, so none is attempted. This is a behaviour change — it used to
/// hand out the first one and let the client wait out a connect timeout.
#[tokio::test]
async fn a_pool_with_several_unhealthy_backends_refuses_without_dialling() {
    let pool = pool(&["http://a:80", "http://b:80"]);
    pool.set_backend_health("http://a:80", false).await;
    pool.set_backend_health("http://b:80", false).await;

    assert_eq!(pool.healthy_count().await, 0);
    assert!(
        pool.select_backend().await.is_none(),
        "every backend behind this route is down, so there is nothing to dial"
    );
}

/// An empty pool refuses, which cannot come from a config: `build_routes`
/// rejects a route with no backends. Reached only by a pool built in code.
#[tokio::test]
async fn an_empty_pool_refuses() {
    let pool = pool(&[]);
    assert!(pool.select_backend().await.is_none());
}

#[tokio::test]
async fn least_conn_sends_the_next_flow_to_whichever_backend_is_freer() {
    let pool = pool_with(
        LoadBalancingStrategy::LeastConn,
        &["http://a:80", "http://b:80"],
    );

    let busy = pool
        .select_backend()
        .await
        .expect("both backends are idle and healthy");
    // Still held: this backend has one flow against the other one's none.
    assert_eq!(busy.url(), "http://a:80");

    let next = pool
        .select_backend()
        .await
        .expect("a healthy backend remains");
    assert_eq!(
        next.url(),
        "http://b:80",
        "the first backend is still serving the flow it was handed out for"
    );

    // Now the scores are level, and the tie rotates — which is why this is
    // `least_conn` and not "one backend until somebody finishes".
    drop(busy);
    assert_eq!(
        pool.select_backend().await.unwrap().url(),
        "http://a:80",
        "A is free again while B still carries its flow, so A is next"
    );
}

/// What keeps `least_conn` from being worse than `RoundRobin`: nearly every
/// tie is "nothing is running right now", and picking the lowest index would
/// then send everything to the first backend — the load this strategy exists
/// to spread.
#[tokio::test]
async fn least_conn_rotates_when_nothing_is_outstanding() {
    let pool = pool_with(
        LoadBalancingStrategy::LeastConn,
        &["http://a:80", "http://b:80"],
    );

    let first = pool.select_backend().await.unwrap().url().to_string();
    let second = pool.select_backend().await.unwrap().url().to_string();

    assert_eq!(
        (first.as_str(), second.as_str()),
        ("http://a:80", "http://b:80"),
        "both are idle, so the two picks should not land on the same backend"
    );
}

/// A circuit that opens on the second failure and stays open for a minute.
fn breaker(threshold: usize) -> CircuitBreaker {
    CircuitBreaker {
        enabled: true,
        failure_threshold: threshold,
        reset: std::time::Duration::from_secs(60),
    }
}

/// A backend that keeps failing is out of rotation.
///
/// The point of a circuit: the route stops dialling a backend that is
/// known to be down, and answers instead of spending a connect timeout to
/// find out what it already knows.
#[tokio::test]
async fn a_backend_that_keeps_failing_leaves_the_rotation() {
    let pool = pool(&["http://a:80"]);
    pool.set_circuit_breaker(breaker(2));

    let lease = pool.select_backend().await.expect("a backend");
    lease.record_failure();
    let lease = pool.select_backend().await.expect("a backend");
    lease.record_failure();

    assert!(
        pool.select_backend().await.is_none(),
        "the backend has failed twice in a row, so the circuit is open and it is not picked"
    );
}

/// A retry prefers a backend it has not tried, but a backend whose circuit
/// is open is not a choice at all. When the only untried backend is out,
/// the retry goes back to one that is still serving instead of refusing.
#[tokio::test]
async fn a_retry_does_not_let_an_open_circuit_hide_a_serving_backend() {
    let pool = pool(&["http://a:80", "http://b:80"]);
    pool.set_circuit_breaker(breaker(1));

    let first = pool.select_backend().await.expect("a backend");
    assert_eq!(first.url(), "http://a:80");
    let tried = first.url().to_string();
    drop(first);

    let second = pool.select_backend().await.expect("a backend");
    assert_eq!(second.url(), "http://b:80");
    second.record_failure();
    drop(second);

    let next = pool
        .select_backend_excluding(&[tried])
        .await
        .expect("A is still serving, so the retry has somewhere to go");
    assert_eq!(
        next.url(),
        "http://a:80",
        "the untried backend's open circuit must not hide the tried one that still serves"
    );
}

/// One failure is not enough: a backend that blipped once is still a
/// backend.
#[tokio::test]
async fn one_failure_does_not_take_a_backend_out() {
    let pool = pool(&["http://a:80"]);
    pool.set_circuit_breaker(breaker(2));

    let lease = pool.select_backend().await.expect("a backend");
    lease.record_failure();

    assert!(
        pool.select_backend().await.is_some(),
        "one failure is a blip, not a verdict"
    );
}

/// A backend that answers is a backend that is up, and the circuit says
/// so.
#[tokio::test]
async fn a_backend_that_answers_closes_the_circuit() {
    let pool = pool(&["http://a:80"]);
    pool.set_circuit_breaker(breaker(2));

    let lease = pool.select_backend().await.expect("a backend");
    lease.record_failure();
    let lease = pool.select_backend().await.expect("a backend");
    lease.record_success();

    // The failure count went back to zero, so the next failure is the
    // first one again and the backend stays in rotation.
    let lease = pool.select_backend().await.expect("a backend");
    lease.record_failure();
    assert!(
        pool.select_backend().await.is_some(),
        "the success reset the count, so one failure does not open the circuit"
    );
}

/// An open circuit lets a request through again once the cooldown has
/// passed: the backend is given a chance to come back.
#[tokio::test]
async fn an_open_circuit_lets_a_request_through_after_the_cooldown() {
    let pool = pool(&["http://a:80"]);
    pool.set_circuit_breaker(CircuitBreaker {
        enabled: true,
        failure_threshold: 1,
        reset: std::time::Duration::from_millis(1),
    });

    let lease = pool.select_backend().await.expect("a backend");
    lease.record_failure();
    assert!(pool.select_backend().await.is_none(), "the circuit is open");

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    assert!(
        pool.select_backend().await.is_some(),
        "the cooldown has passed, so the backend is given another chance"
    );
}

/// A pool with no circuit behaves as it always did.
#[tokio::test]
async fn a_pool_without_a_circuit_keeps_every_backend() {
    let pool = pool(&["http://a:80"]);

    let lease = pool.select_backend().await.expect("a backend");
    lease.record_failure();
    lease.record_failure();
    lease.record_failure();

    assert!(
        pool.select_backend().await.is_some(),
        "a pool built in code has no circuit, so the backend stays in rotation"
    );
}

/// A lease nobody held any more has to have been released, or every later
/// choice is made against a count that only ever grows.
#[tokio::test]
async fn dropping_a_lease_releases_the_backend() {
    let pool = pool_with(
        LoadBalancingStrategy::LeastConn,
        &["http://a:80", "http://b:80"],
    );

    let first = pool.select_backend().await.unwrap();
    drop(first);

    assert_eq!(
        pool.backends
            .iter()
            .map(|b| b.in_flight.load(Ordering::Relaxed))
            .collect::<Vec<_>>(),
        vec![0, 0],
        "a dropped lease is finished work"
    );
}

#[test]
fn least_conn_pick_takes_the_backend_with_the_least_outstanding() {
    assert_eq!(
        BackendPool::least_conn_pick(&[(0, 3), (1, 1), (2, 7)], 0),
        1,
        "one backend carries a single flow against three and seven"
    );
}

/// Ties rotate, and over the tied set rather than the whole pool: the pick
/// takes the cursor modulo the tie, so three idle backends are walked in
/// turn instead of the first one taking everything.
#[test]
fn least_conn_pick_rotates_through_every_backend_tied_at_the_least() {
    let counts = vec![(0, 0), (1, 0), (2, 0)];

    let picked: Vec<usize> = (0..4)
        .map(|cursor| BackendPool::least_conn_pick(&counts, cursor))
        .collect();
    assert_eq!(
        picked,
        vec![0, 1, 2, 0],
        "three idle backends, walked in turn"
    );

    // A unique minimum leaves nothing to rotate, however far the cursor has
    // run — and it is still a backend to choose from, not nothing at all.
    assert_eq!(
        BackendPool::least_conn_pick(&[(0, 9), (1, 4), (2, 9)], 41),
        1
    );
}

/// The pick reads the counters once, so the least and the tie come from the
/// same slice and whoever holds the least is always in the tie. Reading them
/// twice let a lease released in between empty it: the only backend at the
/// least finished, nothing was at the least any more, and a pool that did
/// have backends divided by zero.
#[test]
fn least_conn_pick_always_leaves_something_to_choose_from() {
    let samples: Vec<Vec<(usize, usize)>> = vec![
        vec![(0, 0)],
        vec![(0, 5), (1, 5)],
        vec![(0, 1), (1, 2), (2, 3)],
        vec![(0, 3), (1, 2), (2, 1)],
        vec![(0, 0), (1, 9), (2, 0)],
        vec![(0, 7), (1, 7), (2, 7), (3, 6)],
    ];

    for counts in samples {
        let least = counts
            .iter()
            .map(|(_, outstanding)| *outstanding)
            .min()
            .unwrap();
        // `usize::MAX` included: the cursor is only ever taken modulo the
        // tie, so it must not be able to overflow its way out of one.
        for cursor in [0, 1, 2, 5, usize::MAX] {
            let index = BackendPool::least_conn_pick(&counts, cursor);

            let (_, outstanding) = counts
                .iter()
                .find(|(i, _)| *i == index)
                .expect("the pick is one of the backends it was given");
            assert_eq!(
                *outstanding, least,
                "a backend that is not at the least was chosen from {counts:?}"
            );
        }
    }
}

/// The tie-break cursor is advanced atomically, so a burst of requests that
/// arrive together spreads over the pool instead of landing on one backend.
///
/// The cursor used to be read and written in two steps, and the two steps
/// were not one: two requests that arrived together read the same cursor,
/// picked the same backend, and wrote the same value back. The rotation
/// stood still while the burst went on, and one backend took the burst
/// while the others sat idle — the spread this strategy exists to provide.
///
/// The cursor is now advanced by an atomic increment, so every request is
/// handed a cursor of its own. That is what the counter says afterwards:
/// one step per request, whatever order they arrived in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tie_break_cursor_advances_once_per_request_under_a_burst() {
    const REQUESTS: usize = 64;

    let pool = Arc::new(pool_with(
        LoadBalancingStrategy::LeastConn,
        &["http://a:80", "http://b:80", "http://c:80", "http://d:80"],
    ));
    let barrier = Arc::new(tokio::sync::Barrier::new(REQUESTS));

    let mut requests = Vec::with_capacity(REQUESTS);
    for _ in 0..REQUESTS {
        let pool = Arc::clone(&pool);
        let barrier = Arc::clone(&barrier);
        requests.push(tokio::spawn(async move {
            // They start together, so the requests really do arrive at the
            // same time rather than one after the other.
            barrier.wait().await;
            let lease = pool
                .select_backend()
                .await
                .expect("the pool has a healthy backend");
            let url = lease.url().to_string();
            drop(lease);
            url
        }));
    }

    let mut picked: Vec<String> = Vec::with_capacity(REQUESTS);
    for request in requests {
        picked.push(request.await.expect("the request finished"));
    }

    let spread: std::collections::HashSet<&str> = picked.iter().map(|url| url.as_str()).collect();
    assert!(
        spread.len() > 1,
        "a burst of {REQUESTS} requests all landed on one backend: {picked:?}"
    );

    assert_eq!(
        pool.round_robin_index.load(Ordering::Relaxed),
        REQUESTS,
        "every request advanced the cursor by exactly one step"
    );
}

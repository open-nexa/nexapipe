//! The tests of the limits.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.

use super::Limiters;
use super::budget::{ByteBudget, ByteReservation, DEFAULT_MAX_BODY_BYTES_GLOBAL, body_budget};
use super::config::{EnvCaps, Limits, LimitsConfig, parse_max};
use super::connections::{
    ConnectionLimiter, DEFAULT_MAX_CONNECTIONS_GLOBAL, DEFAULT_MAX_CONNECTIONS_PER_PEER,
    ENV_MAX_CONNECTIONS_PER_PEER,
};
use super::streams::{DEFAULT_MAX_STREAMS_GLOBAL, StreamLimiter};
use iroh::EndpointId;
use std::sync::Arc;

/// A peer id to count against.
///
/// Derived from a secret key rather than written out as bytes: an
/// `EndpointId` is an ed25519 public key, and arbitrary bytes are not one.
fn peer(seed: u8) -> EndpointId {
    iroh::SecretKey::from_bytes(&[seed; 32]).public()
}

#[test]
fn a_peer_may_hold_up_to_the_cap() {
    let limiter = Arc::new(ConnectionLimiter::new(2));
    let a = peer(1);

    let first = limiter.try_acquire(a);
    let second = limiter.try_acquire(a);
    assert!(first.is_some());
    assert!(second.is_some());
    assert_eq!(limiter.count(&a), 2);

    // The cap is per peer, so another peer is unaffected.
    assert!(limiter.try_acquire(peer(2)).is_some());
    assert!(limiter.try_acquire(a).is_none());
}

/// A connection with no peer takes a process-wide slot, and gives it back.
///
/// The plaintext listener has no peer to count, so the slot it takes is
/// the process's — and it is the same count the tunnel's connections take.
#[test]
fn a_peer_less_connection_takes_a_process_wide_slot() {
    let limiter = Arc::new(ConnectionLimiter::with_caps(10, 2));

    let first = limiter.try_acquire_global().expect("the first slot");
    let second = limiter.try_acquire_global().expect("the second slot");
    assert_eq!(limiter.total(), 2);
    assert!(
        limiter.try_acquire_global().is_none(),
        "the third is refused: the process is at its ceiling"
    );

    drop(first);
    assert_eq!(limiter.total(), 1, "the slot came back");
    let third = limiter.try_acquire_global().expect("the freed slot");
    assert_eq!(limiter.total(), 2);

    drop(second);
    drop(third);
    assert_eq!(limiter.total(), 0, "every slot came back");
}

/// The two counts are one count.
///
/// A listener that is exposed and a tunnel are one process, and the work
/// they are doing is one process's work: a ceiling that each of them had
/// a copy of would be twice the ceiling the operator asked for.
#[test]
fn a_peer_less_connection_shares_the_count_with_a_peer() {
    let limiter = Arc::new(ConnectionLimiter::with_caps(10, 2));
    let a = peer(1);

    let _global = limiter.try_acquire_global().expect("the listener's slot");
    let _peer = limiter.try_acquire(a).expect("the tunnel's slot");
    assert_eq!(limiter.total(), 2);

    // And the ceiling is the ceiling for both.
    assert!(
        limiter.try_acquire(a).is_none(),
        "the process is full, whoever asks"
    );
    assert!(
        limiter.try_acquire_global().is_none(),
        "the process is full, whoever asks"
    );
}

/// The per-peer cap does not apply to a connection with no peer, and the
/// global one does not apply to a peer on its own: the two ceilings mean
/// different things and neither stands in for the other.
#[test]
fn the_two_ceilings_are_independent() {
    let limiter = Arc::new(ConnectionLimiter::with_caps(1, 10));
    let a = peer(1);

    let held = limiter.try_acquire(a).expect("the peer's slot");
    assert!(
        limiter.try_acquire(a).is_none(),
        "the peer is at its own ceiling"
    );
    let global = limiter.try_acquire_global().expect("the process's slot");
    assert_eq!(
        limiter.total(),
        2,
        "the process is nowhere near its own ceiling"
    );

    drop(held);
    drop(global);
}

#[test]
fn dropping_a_guard_frees_the_slot() {
    let limiter = Arc::new(ConnectionLimiter::new(1));
    let a = peer(1);

    let guard = limiter.try_acquire(a).expect("first connection fits");
    assert!(limiter.try_acquire(a).is_none());

    drop(guard);
    assert_eq!(limiter.count(&a), 0, "a freed peer leaves no entry behind");
    assert!(limiter.try_acquire(a).is_some());
}

#[test]
fn a_zero_cap_refuses_everyone() {
    let limiter = Arc::new(ConnectionLimiter::new(0));
    assert!(limiter.try_acquire(peer(1)).is_none());
    assert_eq!(limiter.count(&peer(1)), 0);
}

#[test]
fn diagnostics_report_the_real_counts_through_a_poisoned_lock() {
    let limiter = Arc::new(ConnectionLimiter::new(4));
    let a = peer(1);

    let guards: Vec<_> = (0..3).filter_map(|_| limiter.try_acquire(a)).collect();
    assert_eq!(
        guards.len(),
        3,
        "the connections this test poisons over are held"
    );

    // Poison it the only way a Mutex gets poisoned: a panic while held.
    let poisoner = limiter.clone();
    let _ = std::thread::spawn(move || {
        let _held = poisoner.counts.lock().unwrap();
        panic!("a connection handler died holding the counter");
    })
    .join();

    assert_eq!(
        limiter.count(&a),
        3,
        "a poisoned lock still reports what is held"
    );
    assert_eq!(
        limiter.total(),
        3,
        "the process total is not an empty process"
    );

    // And the accounting itself is untouched by the poison.
    drop(guards);
    assert_eq!(limiter.count(&a), 0);
    assert_eq!(limiter.total(), 0);
}

#[test]
fn many_peers_still_stop_at_the_global_ceiling() {
    // The peer cap alone would let this hold `per_peer * 256` connections:
    // an EndpointId is a public key, so a caller can invent as many of them
    // as it likes and each one gets its own allowance.
    let limiter = Arc::new(ConnectionLimiter::with_caps(2, 3));
    let a = peer(1);
    let b = peer(2);
    let c = peer(3);
    let d = peer(4);

    // Held, not dropped: a guard that went out of scope early would free the
    // slot the next assertion is about the absence of.
    let first = limiter.try_acquire(a).expect("first connection fits");
    let _second = limiter.try_acquire(b).expect("second connection fits");
    let _third = limiter.try_acquire(c).expect("third connection fits");
    assert_eq!(limiter.total(), 3);

    // A fourth peer with an empty allowance of its own is still refused,
    // because the process is full. This is the case per-peer limits miss.
    assert!(
        limiter.try_acquire(d).is_none(),
        "the global ceiling outranks a peer's own unused allowance"
    );
    assert_eq!(
        limiter.count(&d),
        0,
        "a refused peer leaves no entry behind"
    );

    drop(first);
    assert_eq!(limiter.total(), 2);
    assert!(
        limiter.try_acquire(d).is_some(),
        "a freed global slot is reusable"
    );
}

#[test]
fn dropping_a_guard_frees_the_global_count_too() {
    let limiter = Arc::new(ConnectionLimiter::with_caps(4, 2));
    let a = peer(1);
    let b = peer(2);

    let guards: Vec<_> = (0..2).map(|_| limiter.try_acquire(a).unwrap()).collect();
    assert_eq!(limiter.total(), 2);
    assert!(limiter.try_acquire(b).is_none());

    drop(guards);
    // Not just zero: a release that only decremented the per-peer map would
    // leave the total stuck at 2 and refuse every connection from here on.
    assert_eq!(limiter.total(), 0);
    assert!(limiter.try_acquire(b).is_some());
}

#[test]
fn the_per_peer_cap_still_applies_under_a_generous_global_one() {
    let limiter = Arc::new(ConnectionLimiter::with_caps(1, 1000));
    let a = peer(1);

    let first = limiter.try_acquire(a).expect("first connection fits");
    assert!(
        limiter.try_acquire(a).is_none(),
        "a peer at its own cap is refused long before the global one"
    );
    assert_eq!(limiter.total(), 1);

    drop(first);
    assert_eq!(limiter.total(), 0);
}

#[test]
fn only_a_positive_number_is_a_cap() {
    assert_eq!(parse_max("8"), Some(8));
    assert_eq!(parse_max(" 16 "), Some(16));
    assert_eq!(parse_max("0"), None);
    assert_eq!(parse_max("-1"), None);
    assert_eq!(parse_max("lots"), None);
    assert_eq!(parse_max(""), None);
}

#[tokio::test]
async fn streams_stop_at_the_process_ceiling() {
    let limiter = Arc::new(StreamLimiter::new(2));

    let first = limiter.try_acquire().expect("first stream fits");
    let second = limiter.try_acquire().expect("second stream fits");
    assert_eq!(limiter.available(), 0);

    assert!(
        limiter.try_acquire().is_none(),
        "a stream past the process ceiling is refused, not queued"
    );

    drop(first);
    assert_eq!(limiter.available(), 1);
    assert!(limiter.try_acquire().is_some());
    drop(second);
}

#[tokio::test]
async fn a_zero_stream_ceiling_refuses_everything() {
    let limiter = Arc::new(StreamLimiter::new(0));
    assert!(limiter.try_acquire().is_none());
    assert_eq!(limiter.available(), 0);
}

/// An operator who writes a huge `NEXAPIPE_MAX_STREAMS` means "unlimited",
/// and `Semaphore::new` panics above `MAX_PERMITS` — so without a clamp the
/// server does not start at all, which is the one outcome a value this large
/// should never produce.
#[tokio::test]
async fn an_oversized_stream_ceiling_does_not_take_the_listener_down() {
    let limiter = Arc::new(StreamLimiter::new(usize::MAX));
    assert_eq!(
        limiter.max_global(),
        tokio::sync::Semaphore::MAX_PERMITS,
        "the ceiling is clamped to what a semaphore can actually hold"
    );
    assert!(
        limiter.try_acquire().is_some(),
        "a clamped ceiling still admits streams"
    );
}

#[test]
fn bodies_are_bounded_across_the_process() {
    let budget = ByteBudget::new(100);

    budget.try_reserve(60).expect("the first body fits");
    assert_eq!(budget.held(), 60);

    // The per-request cap would allow this; the process-wide one does not,
    // and that is the case a single request's limit cannot catch.
    let err = budget.try_reserve(60).expect_err("the second does not fit");
    assert_eq!(err, 60, "the error reports the total that was already held");
    assert_eq!(budget.held(), 60, "a refused reservation changes nothing");

    budget.release(60);
    assert_eq!(budget.held(), 0);
    budget
        .try_reserve(100)
        .expect("the whole budget is usable again");
}

#[test]
fn releasing_more_than_was_taken_cannot_wrap_the_counter() {
    // Saturating on purpose: a double release would otherwise wrap a usize
    // to near its maximum and leave the budget permanently full, which is a
    // far worse failure than a counter that drifts low.
    let budget = ByteBudget::new(100);
    budget.try_reserve(10).unwrap();
    budget.release(50);
    assert_eq!(budget.held(), 0);
    budget.try_reserve(100).expect("still usable");
}

#[test]
fn a_reservation_returns_its_bytes_when_dropped() {
    // The whole reason this is a guard: nothing at the reading site is
    // around later to give the bytes back.
    {
        let _held = ByteReservation::take(10).expect("the first fits");
        assert!(body_budget().held() >= 10);
    }
    assert!(
        ByteReservation::take(1).is_ok(),
        "a released budget admits the next body"
    );
}

/// A copy buffer is charged to the budget like a body is, and given back
/// when it is dropped.
///
/// The copy buffers are the one per-stream allocation the budget did not
/// see, so they are taken with the same reservation a body is taken with.
#[test]
fn a_copy_buffer_is_charged_to_the_budget() {
    let budget = Arc::new(ByteBudget::new(1000));

    {
        let _held =
            ByteReservation::take_buffers(&budget, 100).expect("the buffer fits the budget");
        assert_eq!(budget.held(), 100);
    }
    assert_eq!(
        budget.held(),
        0,
        "the bytes come back with the reservation that held them"
    );

    // And a buffer that does not fit is refused, with the words that say
    // what did not fit: this is a buffer, not a request body.
    budget.try_reserve(950).expect("the budget fills up");
    let refused = ByteReservation::take_buffers(&budget, 100).expect_err("the buffer does not fit");
    assert!(
        refused.to_string().contains("copy buffer"),
        "the error says what did not fit: {refused}"
    );
    assert_eq!(budget.held(), 950, "a refused buffer charges nothing");
}

#[test]
fn a_reservation_gives_back_the_bytes_it_no_longer_holds() {
    let budget = Arc::new(ByteBudget::new(1000));

    let mut reservation =
        ByteReservation::take_from(&budget, 100).expect("the body fits the budget");
    assert_eq!(budget.held(), 100);

    reservation.grow(50).expect("the body grows");
    assert_eq!(budget.held(), 150);
    assert_eq!(reservation.bytes(), 150);

    // The framing of a decoded chunk is gone: the bytes it used are given
    // back, and what the reservation holds is what is still in memory.
    reservation.shrink(30);
    assert_eq!(budget.held(), 120);
    assert_eq!(reservation.bytes(), 120);

    // More than it holds is not given back: the counter never goes below
    // zero, so a caller that gives back too much leaves the budget as it
    // was rather than making it look emptier than it is.
    reservation.shrink(1000);
    assert_eq!(budget.held(), 0);
    assert_eq!(reservation.bytes(), 0);

    drop(reservation);
    assert_eq!(
        budget.held(),
        0,
        "a reservation that holds nothing gives nothing back"
    );
}

#[test]
fn concurrent_releases_never_take_the_counter_below_zero() {
    // A release that reads the total and subtracts from it in a second
    // step subtracts from whatever the counter says by then, which is not
    // the total it read: two releases that race can both take the same
    // bytes, and the counter wraps around to near its maximum. A budget
    // that reads as permanently full refuses every body from then on, so
    // this is worth a test that races it on purpose.
    //
    // The shape is what makes the race reachable: the counter holds one
    // chunk, and every thread gives that same chunk back at the same
    // time. A release that subtracts what it read takes the chunk twice,
    // and the counter goes below zero — which is where the wrap is.
    const THREADS: usize = 8;
    const ROUNDS: usize = 1_000;
    const CHUNK: usize = 64;

    let budget = Arc::new(ByteBudget::new(usize::MAX));
    let barrier = Arc::new(std::sync::Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|thread| {
            let budget = budget.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                for _ in 0..ROUNDS {
                    // The counter is one chunk: one thread takes it, and
                    // then every thread gives it back at the same time.
                    if thread == 0 {
                        budget.try_reserve(CHUNK).expect("the budget has room");
                    }
                    barrier.wait();
                    budget.release(CHUNK);
                    barrier.wait();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("no release panicked");
    }

    assert_eq!(
        budget.held(),
        0,
        "every released byte is gone, and none of them went past zero"
    );
}

#[test]
fn the_body_budget_ceiling_can_be_written_after_it_exists() {
    // The point of the write: the budget is a `static` the HTTP path
    // reaches without a config, and its ceiling comes from one.
    let budget = ByteBudget::new(DEFAULT_MAX_BODY_BYTES_GLOBAL);
    assert_eq!(budget.max(), DEFAULT_MAX_BODY_BYTES_GLOBAL);

    budget.set_max(100);
    assert_eq!(budget.max(), 100);

    // And the ceiling is the one that is enforced, not just the one that is
    // reported.
    budget.try_reserve(60).expect("the first body fits");
    assert!(
        budget.try_reserve(60).is_err(),
        "the ceiling that was written is the one that applies"
    );

    // What is already reserved stays reserved: the write is about the
    // ceiling, not about the bytes held under the old one.
    assert_eq!(budget.held(), 60);
}

#[test]
fn an_absent_section_resolves_to_the_defaults() {
    let limits = Limits::resolve(&LimitsConfig::default(), &EnvCaps::default())
        .expect("the defaults are usable");

    assert_eq!(
        limits.max_connections_per_peer,
        DEFAULT_MAX_CONNECTIONS_PER_PEER
    );
    assert_eq!(
        limits.max_connections_global,
        DEFAULT_MAX_CONNECTIONS_GLOBAL
    );
    assert_eq!(limits.max_streams_global, DEFAULT_MAX_STREAMS_GLOBAL);
    assert_eq!(limits.max_body_bytes, DEFAULT_MAX_BODY_BYTES_GLOBAL);
}

#[test]
fn the_config_names_the_ceiling() {
    let config = LimitsConfig {
        max_connections_per_peer: Some(11),
        max_connections_global: Some(22),
        max_streams_global: Some(33),
        max_body_bytes: Some(44),
    };

    let limits = Limits::resolve(&config, &EnvCaps::default()).expect("the config is usable");
    assert_eq!(limits.max_connections_per_peer, 11);
    assert_eq!(limits.max_connections_global, 22);
    assert_eq!(limits.max_streams_global, 33);
    assert_eq!(limits.max_body_bytes, 44);
}

#[test]
fn the_environment_outranks_the_config() {
    let config = LimitsConfig {
        max_connections_per_peer: Some(11),
        ..LimitsConfig::default()
    };
    let env = EnvCaps {
        max_connections_per_peer: Some(7),
        ..EnvCaps::default()
    };

    let limits = Limits::resolve(&config, &env).expect("the two sources are usable");
    assert_eq!(
        limits.max_connections_per_peer, 7,
        "the environment is the last thing an operator sets, so it wins"
    );
    assert_eq!(
        limits.max_connections_global, DEFAULT_MAX_CONNECTIONS_GLOBAL,
        "a key only one of them names is unaffected by the other"
    );
}

#[test]
fn a_zero_ceiling_in_the_config_is_refused() {
    let config = LimitsConfig {
        max_connections_global: Some(0),
        ..LimitsConfig::default()
    };

    let error = Limits::resolve(&config, &EnvCaps::default())
        .expect_err("a ceiling of zero refuses every connection");
    let message = format!("{error:#}");
    assert!(
        message.contains("max_connections_global"),
        "the error names the key that cannot work: {message}"
    );
}

#[test]
fn every_ceiling_is_refused_when_it_is_zero() {
    // One rule for all four, so a typo is refused wherever it is written
    // rather than in one key only.
    for config in [
        LimitsConfig {
            max_connections_per_peer: Some(0),
            ..LimitsConfig::default()
        },
        LimitsConfig {
            max_connections_global: Some(0),
            ..LimitsConfig::default()
        },
        LimitsConfig {
            max_streams_global: Some(0),
            ..LimitsConfig::default()
        },
        LimitsConfig {
            max_body_bytes: Some(0),
            ..LimitsConfig::default()
        },
    ] {
        assert!(
            Limits::resolve(&config, &EnvCaps::default()).is_err(),
            "a ceiling of zero is refused whatever it bounds"
        );
    }
}

#[test]
fn a_zero_ceiling_in_the_environment_is_ignored() {
    // The environment keeps the older rule: a bad value in a Dockerfile
    // should not keep the server from starting.
    let env = EnvCaps {
        max_connections_per_peer: Some(0),
        ..EnvCaps::default()
    };

    let limits = Limits::resolve(&LimitsConfig::default(), &env).expect("the default is usable");
    assert_eq!(
        limits.max_connections_per_peer,
        DEFAULT_MAX_CONNECTIONS_PER_PEER
    );
}

#[test]
fn a_zero_in_the_config_is_refused_even_when_the_environment_names_the_key() {
    // The rule is "the environment overrides a value that works, not one
    // that does not". A zero in the file is a typo whether or not a
    // variable happens to name the same key - and a typo hidden behind an
    // environment variable is a typo that waits for the day the variable
    // goes away.
    let config = LimitsConfig {
        max_connections_per_peer: Some(0),
        ..LimitsConfig::default()
    };
    let env = EnvCaps {
        max_connections_per_peer: Some(64),
        ..EnvCaps::default()
    };

    let error = Limits::resolve(&config, &env)
        .expect_err("a ceiling of zero is refused whatever else names the key");
    let message = format!("{error:#}");
    assert!(
        message.contains("max_connections_per_peer"),
        "the error names the key that cannot work: {message}"
    );
    assert!(
        message.contains(ENV_MAX_CONNECTIONS_PER_PEER),
        "the error says that the environment does not save it: {message}"
    );
}

#[test]
fn the_limiters_describe_the_ceilings_they_were_built_with() {
    // The body budget is a process-wide static, and the limiters must not
    // read it behind the caller's back: a type that describes its own
    // ceilings reports the ones it was given.
    let limits = Limits {
        max_connections_per_peer: 11,
        max_connections_global: 22,
        max_streams_global: 33,
        max_body_bytes: 44,
    };

    let described = Limiters::from_limits(&limits).describe();
    assert!(
        described.contains("11 concurrent connections per peer"),
        "{described}"
    );
    assert!(described.contains("22 across the process"), "{described}");
    assert!(
        described.contains("33 streams across the process"),
        "{described}"
    );
    assert!(
        described.contains("44 bytes of request bodies across the process"),
        "{described}"
    );
}

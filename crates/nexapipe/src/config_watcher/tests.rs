//! The tests of the configuration watcher.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.
use super::*;
/// A file written twice inside one second has the same time and a
/// different length — and it is a different file.
#[test]
fn a_file_written_twice_inside_one_second_is_a_change() {
    let time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let state = WatchState::new(
        FileStamp {
            modified: time,
            len: 10,
        },
        Instant::now(),
    );
    let now = Instant::now();

    assert!(
        !state.should_load(
            FileStamp {
                modified: time,
                len: 10
            },
            now
        ),
        "the same file is not a change"
    );
    assert!(
        state.should_load(
            FileStamp {
                modified: time,
                len: 11
            },
            now
        ),
        "a different length is a change, time or not"
    );
}

/// A file that replaced another one — restored from a backup, checked out
/// by `git` — can be *older* than the one it replaces.
#[test]
fn an_older_file_is_still_a_change() {
    let older = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(50);
    let newer = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let state = WatchState::new(
        FileStamp {
            modified: newer,
            len: 10,
        },
        Instant::now(),
    );

    assert!(
        state.should_load(
            FileStamp {
                modified: older,
                len: 10
            },
            Instant::now()
        ),
        "an older file is a different file"
    );
}

/// A file that failed to load is tried again.
///
/// The old behaviour advanced the stamp before the reload ran, so a file
/// that was read too early — half-written — was never tried again, and the
/// server kept the routes it had for ever.
#[test]
fn a_failed_load_is_tried_again() {
    let time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let mut state = WatchState::new(
        FileStamp {
            modified: time,
            len: 10,
        },
        Instant::now(),
    );
    let now = Instant::now();
    let half_written = FileStamp {
        modified: time,
        len: 11,
    };

    assert!(
        state.should_load(half_written, now),
        "the change is noticed"
    );
    state.failed(now);

    assert!(
        !state.should_load(half_written, now),
        "not straight away: the backoff"
    );
    assert!(
        state.should_load(half_written, now + POLL_INTERVAL),
        "and again once the backoff is over"
    );
}

/// The wait grows after every failure, and it stops growing.
///
/// A file that is wrong stays wrong, and a log line every five seconds for
/// ever is not a thing anyone wants to read.
#[test]
fn the_retry_backoff_grows_and_is_capped() {
    let time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let mut state = WatchState::new(
        FileStamp {
            modified: time,
            len: 10,
        },
        Instant::now(),
    );
    let now = Instant::now();

    state.failed(now);
    assert_eq!(
        state.retry_delay, POLL_INTERVAL,
        "the first wait is one tick"
    );

    state.failed(now + POLL_INTERVAL);
    assert_eq!(
        state.retry_delay,
        POLL_INTERVAL * 2,
        "the second wait is twice as long"
    );

    for _ in 0..20 {
        state.failed(now);
    }
    assert_eq!(
        state.retry_delay, MAX_RETRY_DELAY,
        "the wait stops growing at the cap"
    );
}

/// A load that worked is remembered, so the same file is not loaded again.
#[test]
fn a_loaded_file_is_not_loaded_again() {
    let time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let stamp = FileStamp {
        modified: time,
        len: 10,
    };
    let mut state = WatchState::new(FileStamp::UNKNOWN, Instant::now());
    let now = Instant::now();

    assert!(
        state.should_load(stamp, now),
        "a file that was never loaded is loaded"
    );
    state.loaded(stamp, now);

    assert!(
        !state.should_load(stamp, now),
        "and not again until it changes"
    );
}

use crate::auth::{ClientAuth, DeviceAuth};
use crate::conn::peers::PeerIdentity;
use nexapipe_proto::secret::SecretString;

fn client(secret: &str) -> ClientAuth {
    ClientAuth {
        secret: SecretString::new(secret.to_string()),
        created_at: "0".to_string(),
        allow_hosts: None,
        allow_ports: None,
        allow_ports_strict: false,
        pending_enrollment: None,
        devices: HashMap::new(),
        unnamed_device_allowed: true,
        last_used: None,
        last_used_step: None,
        failed_attempts: 0,
        locked_until: None,
        enrollment_failed_attempts: 0,
        enrollment_locked_until: None,
    }
}

fn device(secret: &str) -> DeviceAuth {
    DeviceAuth {
        secret: SecretString::new(secret.to_string()),
        public_key: None,
        created_at: "0".to_string(),
        last_used: None,
        last_used_step: None,
    }
}

/// A reload does not take the step memory away.
///
/// The step memory is what refuses the second use of a code, so a reload
/// that put an older value back would hand the replay protection away
/// without saying so. The live value is moved forward by every
/// acceptance, and the file is written after the lock is released — so a
/// reload that lands in that window reads a file that is one step behind
/// memory, and the merge has to keep the newer of the two.
#[test]
fn a_reload_keeps_the_step_memory() {
    let mut live = config_with(&[("phone", client("s"))]);
    let incoming = config_with(&[("phone", client("s"))]);

    // The live server has accepted a code at step 100 and written it
    // down; the file it is reading still says nothing, because the write
    // has not happened yet.
    live.clients.get_mut("phone").unwrap().last_used_step = Some(100);

    merge_auth_clients(&mut live, &incoming);

    assert_eq!(
        live.clients.get("phone").unwrap().last_used_step,
        Some(100),
        "the step memory survives a reload that read a file without it"
    );
}

/// A device's own step memory survives a reload too.
///
/// A device's credential is its own, and a device that authenticated with
/// a code must not lose that by a reload any more than the client it
/// belongs to does.
#[test]
fn a_reload_keeps_a_device_s_step_memory() {
    let mut live_client = client("s");
    let mut live_device = device("d");
    live_device.last_used_step = Some(100);
    live_client
        .devices
        .insert("laptop".to_string(), live_device);

    let mut incoming_client = client("s");
    let incoming_device = device("d");
    incoming_client
        .devices
        .insert("laptop".to_string(), incoming_device);

    let mut live = config_with(&[("phone", live_client)]);
    let incoming = config_with(&[("phone", incoming_client)]);

    merge_auth_clients(&mut live, &incoming);

    assert_eq!(
        live.clients
            .get("phone")
            .and_then(|c| c.devices.get("laptop"))
            .and_then(|d| d.last_used_step),
        Some(100),
        "the device's step memory survives a reload that read a file without it"
    );
}

/// `removed_devices` is the detection half of revocation: a device struck
/// out of the file while its client survives is the only case the
/// client-level pass cannot see, so what it reports is what a reload then
/// closes. Every case below is one an operator reaches by hand-editing —
/// `nexapipe client revoke --device` writes exactly this diff.
fn removed_devices_of(
    before: &[(&str, &[&str])],
    after: &[(&str, &[(&str, &str)])],
) -> Vec<(String, String)> {
    let before: HashMap<String, Vec<String>> = before
        .iter()
        .map(|(id, devices)| {
            (
                id.to_string(),
                devices.iter().map(|name| name.to_string()).collect(),
            )
        })
        .collect();
    let after: HashMap<String, ClientAuth> = after
        .iter()
        .map(|(id, devices)| {
            let mut client = client("SECRETSECRETSECR");
            client.devices = devices
                .iter()
                .map(|(name, secret)| (name.to_string(), device(secret)))
                .collect();
            (id.to_string(), client)
        })
        .collect();
    let mut removed = ConfigWatcher::removed_devices(&before, &after);
    removed.sort();
    removed
}

#[test]
fn a_device_struck_out_of_a_surviving_client_is_reported() {
    assert_eq!(
        removed_devices_of(
            &[("alice", &["laptop", "phone"])],
            &[("alice", &[("phone", "P")])]
        ),
        vec![("alice".to_string(), "laptop".to_string())]
    );
}

#[test]
fn a_device_that_moved_to_another_client_is_reported_where_it_was() {
    assert_eq!(
        removed_devices_of(
            &[("alice", &["laptop"]), ("bob", &[])],
            &[("alice", &[]), ("bob", &[("laptop", "L")])]
        ),
        vec![("alice".to_string(), "laptop".to_string())]
    );
}

#[test]
fn a_renamed_device_reports_the_old_name_only() {
    assert_eq!(
        removed_devices_of(
            &[("alice", &["laptop"])],
            &[("alice", &[("laptop-2", "L")])]
        ),
        vec![("alice".to_string(), "laptop".to_string())]
    );
}

/// A client that is gone takes every device under it with it, and those
/// connections are already closed by the client-level pass. Counting them
/// here too would close the same connection twice.
#[test]
fn a_client_that_disappeared_reports_no_devices() {
    assert!(
        removed_devices_of(
            &[("alice", &["laptop", "phone"])],
            &[("bob", &[("laptop", "L")])]
        )
        .is_empty()
    );
}

#[test]
fn an_unchanged_table_reports_nothing() {
    assert!(
        removed_devices_of(
            &[("alice", &["laptop", "phone"])],
            &[("alice", &[("laptop", "L"), ("phone", "P")])]
        )
        .is_empty()
    );
}

/// The empty case: no devices anywhere is the pre-0.6.0 shape, and a
/// reload of it must not invent a revocation.
#[test]
fn a_table_with_no_devices_reports_nothing() {
    assert!(removed_devices_of(&[("alice", &[])], &[("alice", &[])]).is_empty());
}

fn config_with(clients: &[(&str, ClientAuth)]) -> AuthConfig {
    let mut config = AuthConfig::default();
    for (id, client) in clients {
        config.clients.insert(id.to_string(), client.clone());
    }
    config
}

/// A watcher over a config file, with the 2FA state it guards.
fn watcher_for(state: AuthState, path: &str) -> ConfigWatcher {
    ConfigWatcher::new(
        path.to_string(),
        Arc::new(RoutingTable::new(Vec::new())),
        Arc::new(
            crate::http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                .expect("the default trust store is always usable"),
        ),
        Arc::new(Mutex::new(HealthProbes::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        Some(state),
        Arc::new(PeerRegistry::new()),
    )
}

/// A snapshot the caller read is merged as it is, and the file is not read
/// again.
///
/// The read is outside the lock now — that is the point of the change — and
/// the file is not read under it at all, so the lock is not held across a
/// disk read while every handshake and every lockout write waits for it.
///
/// The file names one client and the snapshot names another, so a read
/// would show: the file's client would end up live instead of the
/// snapshot's.
#[tokio::test]
async fn a_snapshot_is_merged_without_reading_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILE\"\n",
    )
    .unwrap();
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = watcher_for(state.clone(), &path);

    watcher
        .reload_auth(
            Some(config_with(&[(
                "from-the-snapshot",
                client("FROMTHESNAPSHOT"),
            )])),
            state.enroll_epoch(),
        )
        .await;

    let live = state.config().read().await;
    assert!(
        live.clients.contains_key("from-the-snapshot"),
        "the snapshot was merged"
    );
    assert!(
        !live.clients.contains_key("from-the-file"),
        "the file was read, and its client is live instead of the snapshot's"
    );
}

/// A snapshot that an enrollment made stale is not merged.
///
/// The enrollment spends a token by changing the live state and only then
/// writing the change back, so a snapshot taken a moment earlier still
/// carries the spent token and the pre-enrollment secret. Merging it would
/// hand out a token that was already used and undo the secret the
/// enrollment just issued.
///
/// So the epoch is sampled before the read and compared under the lock, and
/// a snapshot that has been overtaken is read again.
#[tokio::test]
async fn a_snapshot_an_enrollment_made_stale_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    // The file names one client and the snapshot names another.
    std::fs::write(
        &path,
        "[auth]\nenabled = true\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILE\"\n",
    )
    .unwrap();
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = watcher_for(state.clone(), &path);

    // An enrollment lands after the snapshot was taken: the epoch moves.
    state.bump_enroll_epoch();

    assert!(
        watcher
            .reload_auth(
                Some(config_with(&[(
                    "from-the-snapshot",
                    client("FROMTHESNAPSHOT"),
                )])),
                // The epoch as it was when the snapshot was taken.
                state.enroll_epoch() - 1,
            )
            .await,
        "the snapshot the second read produced was merged"
    );

    let live = state.config().read().await;
    assert!(
        !live.clients.contains_key("from-the-snapshot"),
        "the stale snapshot was merged over the top of the enrollment"
    );
    assert!(
        live.clients.contains_key("from-the-file"),
        "the file was read again, and the client it names is live"
    );
}

/// A re-read that fails is reported as not applied.
///
/// The first read already happened when the overtake is noticed, and the
/// file can be gone or half-written by the time the second one runs. An
/// auth half that was never merged must not be recorded as loaded, or the
/// edit waits until somebody touches the file again.
#[tokio::test]
async fn a_reload_whose_second_read_fails_is_tried_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILE\"\n",
    )
    .unwrap();
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = watcher_for(state.clone(), &path);

    // The snapshot is stale, so the reload reads again — and there is
    // nothing left to read.
    state.bump_enroll_epoch();
    std::fs::remove_file(&path).unwrap();

    assert!(
        !watcher
            .reload_auth(
                Some(config_with(&[(
                    "from-the-snapshot",
                    client("FROMTHESNAPSHOT"),
                )])),
                state.enroll_epoch() - 1,
            )
            .await,
        "an auth half that was not merged is not reported as applied"
    );
}

/// The two halves of the file come from one read.
///
/// Two reads could hand the routes one revision of the file and the 2FA
/// clients another, and a change made between them would be half-applied.
#[tokio::test]
async fn a_reload_applies_both_halves_of_one_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[[routes]]\nhost_pattern = \"app.test\"\nbackends = [\"http://127.0.0.1:1\"]\n\n\
         [auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXP\"\n",
    )
    .unwrap();
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = watcher_for(state.clone(), &path);

    watcher.reload_config().await;

    let live = state.config().read().await;
    assert!(
        live.clients.contains_key("client-001"),
        "the auth half of the file was applied"
    );
    assert!(
        watcher
            .route_config
            .routes()
            .await
            .iter()
            .any(|r| r.host_pattern() == "app.test"),
        "the routes half of the same read was applied"
    );
}

/// The whole point of the merge: an invite written by `--generate-invite`
/// in another process becomes spendable on the running server without a
/// restart, and a client deleted from the file stops authenticating.
#[test]
fn a_reload_picks_up_an_invited_client_and_drops_a_removed_one() {
    let mut live = config_with(&[("old", client("OLDOLDOLDOLDOLD"))]);
    let incoming = config_with(&[
        ("old", client("OLDOLDOLDOLDOLD")),
        ("new", client("NEWNEWNEWNEWNEW")),
    ]);

    let (added, removed) = merge_auth_clients(&mut live, &incoming);

    assert_eq!(added, vec!["new".to_string()]);
    assert!(removed.is_empty());
    assert_eq!(live.clients.len(), 2);
    assert_eq!(live.clients["new"].secret.as_str(), "NEWNEWNEWNEWNEW");

    let (added, removed) = merge_auth_clients(&mut live, &config_with(&[]));

    assert!(added.is_empty());
    // HashMap order is per-process, so compare the removed set, not a sequence.
    let mut removed = removed;
    removed.sort();
    assert_eq!(removed, vec!["new".to_string(), "old".to_string()]);
    assert!(live.clients.is_empty());
}

/// A rotated secret (`--generate-2fa --force`, or a spent enrollment) takes
/// over, but the lockout counters the server has been maintaining in
/// memory are not reset by the reload — the file's copy may be stale.
#[test]
fn a_surviving_client_keeps_its_counters_and_takes_the_files_secret() {
    let mut live = config_with(&[("client-001", client("OLDSECRETVALUE"))]);
    let existing = live.clients.get_mut("client-001").unwrap();
    existing.failed_attempts = 2;
    existing.locked_until = Some(12345);
    existing.pending_enrollment = Some(SecretString::new("token".to_string()));
    existing.enrollment_failed_attempts = 2;
    existing.enrollment_locked_until = Some(54321);

    let mut incoming_client = client("NEWSECRETVALUE");
    incoming_client.pending_enrollment = Some(SecretString::new("token".to_string()));
    let incoming = config_with(&[("client-001", incoming_client)]);

    let (added, removed) = merge_auth_clients(&mut live, &incoming);

    assert!(added.is_empty() && removed.is_empty());
    let client = &live.clients["client-001"];
    assert_eq!(client.secret.as_str(), "NEWSECRETVALUE");
    assert_eq!(
        client
            .pending_enrollment
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("token")
    );
    assert_eq!(client.failed_attempts, 2, "the file's stale counter loses");
    assert_eq!(client.locked_until, Some(12345));
    assert_eq!(
        client.enrollment_failed_attempts, 2,
        "the enrollment's counter is live state too"
    );
    assert_eq!(client.enrollment_locked_until, Some(54321));
}

/// A token the file replaces in memory is a new invite: the guesses at the
/// old token are not guesses at this one, so the new one starts with its
/// own budget rather than one lockout away from closed.
#[test]
fn a_new_invite_starts_with_its_own_budget() {
    let mut live = config_with(&[("client-001", client("SECRETVALUE"))]);
    let existing = live.clients.get_mut("client-001").unwrap();
    existing.pending_enrollment = Some(SecretString::new("old-token".to_string()));
    existing.enrollment_failed_attempts = 2;
    existing.enrollment_locked_until = Some(54321);

    let mut incoming_client = client("SECRETVALUE");
    incoming_client.pending_enrollment = Some(SecretString::new("new-token".to_string()));
    let incoming = config_with(&[("client-001", incoming_client)]);

    let (added, removed) = merge_auth_clients(&mut live, &incoming);

    assert!(added.is_empty() && removed.is_empty());
    let client = &live.clients["client-001"];
    assert_eq!(
        client
            .pending_enrollment
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("new-token")
    );
    assert_eq!(
        client.enrollment_failed_attempts, 0,
        "the guesses went with the token they were made at"
    );
    assert_eq!(client.enrollment_locked_until, None);
}

/// A server started with no `[auth]` section at all can still switch 2FA on
/// while it runs.
///
/// Regression: the state used to be built only when the file already had an
/// `[auth]` table, and `reload_auth` returns early on a missing state, so
/// the one deployment that most needs a live switch — an operator adding
/// the section to a running server for the first time — could only get it
/// by restarting. `run_proxy` builds the state from the default config now,
/// which is `enabled = false` with no clients, and this is what that buys.
#[tokio::test]
async fn a_state_built_without_a_section_still_reloads_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXP\"\n",
    )
    .unwrap();
    // Private, because enabling 2FA is refused against a file anyone else
    // can read — the secrets in it become live credentials.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = ConfigWatcher::new(
        path,
        Arc::new(RoutingTable::new(Vec::new())),
        Arc::new(
            crate::http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                .expect("the default trust store is always usable"),
        ),
        Arc::new(Mutex::new(HealthProbes::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        Some(state.clone()),
        Arc::new(PeerRegistry::new()),
    );

    assert!(!state.config().read().await.enabled);

    watcher.reload_config().await;

    let live = state.config().read().await;
    assert!(
        live.enabled,
        "2FA has to come on for a server that started without it"
    );
    assert!(
        live.clients.contains_key("client-001"),
        "and the client the section brought with it has to be live too"
    );
}

/// The TOTP parameters are startup-only: the merge touches the clients
/// table and nothing else, so a mid-run edit cannot strand clients enrolled
/// under the old algorithm, step or digit count.
#[test]
fn the_merge_leaves_the_totp_parameters_alone() {
    let mut live = config_with(&[("a", client("A"))]);
    live.issuer = "Startup Issuer".to_string();
    live.max_attempts = 9;

    let mut incoming = config_with(&[("a", client("A2"))]);
    incoming.issuer = "File Issuer".to_string();
    incoming.max_attempts = 3;

    merge_auth_clients(&mut live, &incoming);

    assert_eq!(live.issuer, "Startup Issuer");
    assert_eq!(live.max_attempts, 9);
    assert_eq!(live.clients["a"].secret.as_str(), "A2");
}

/// Turning 2FA on mid-run is the half of the old startup-only rule that had
/// to go: without it, an operator who writes `enabled = true` gets a log
/// line saying the config reloaded and a listener that is still ungated.
#[test]
fn a_reload_turns_2fa_on() {
    let mut live = config_with(&[("a", client("A"))]);
    live.enabled = false;

    let mut incoming = config_with(&[("a", client("A"))]);
    incoming.enabled = true;

    assert_eq!(apply_auth_enabled(&mut live, &incoming), Some(true));
    assert!(
        live.enabled,
        "the file's `true` is what the listener now uses"
    );
}

/// The transition is reported only when it happens, so the reload path can
/// log it without re-reading the state — and so a route-only edit while 2FA
/// is on stays quiet.
#[test]
fn an_unchanged_enabled_reports_no_transition() {
    let mut live = config_with(&[("a", client("A"))]);
    live.enabled = true;

    let mut incoming = config_with(&[("a", client("A"))]);
    incoming.enabled = true;

    assert_eq!(apply_auth_enabled(&mut live, &incoming), None);
    assert!(live.enabled);
}

/// The direction that has to be refused: `enabled = false` on a server that
/// is gating would remove the listener's only gate, and an operator who
/// wants that restarts.
#[test]
fn a_reload_may_not_turn_2fa_off() {
    let mut live = config_with(&[("a", client("A"))]);
    live.enabled = true;

    let mut incoming = config_with(&[("a", client("A"))]);
    incoming.enabled = false;

    let refusal = ConfigWatcher::auth_enabled_refusal(&live, &incoming, None)
        .expect("turning 2FA off must be refused");

    assert!(
        refusal.contains("[auth] enabled = false is ignored"),
        "{refusal}"
    );
    // The refusal is only a message; the caller applies nothing, so the live
    // state still gates.
    assert!(live.enabled);
}

/// Once 2FA is on, the file repeating `true` is not a transition, so none of
/// the three enabling checks can block an unrelated edit — a route change
/// during a `chmod 644` moment still reloads.
#[test]
fn an_already_enabled_config_is_never_refused() {
    let mut live = config_with(&[]);
    live.enabled = true;

    let mut incoming = config_with(&[]);
    incoming.enabled = true;

    assert_eq!(
        ConfigWatcher::auth_enabled_refusal(&live, &incoming, None),
        None
    );
}

/// 2FA does not run on the plaintext listener, so enabling it while that
/// listener is reachable from the network would produce exactly the state
/// `run_proxy` refuses to start in. A reload must not be the way around a
/// check the startup path enforces.
#[test]
fn a_reload_may_not_enable_2fa_while_plaintext_is_exposed() {
    let live = config_with(&[]);
    let mut incoming = config_with(&[]);
    incoming.enabled = true;

    let exposed = Some(PlaintextListener {
        addr: "0.0.0.0:8080".parse().unwrap(),
        exposed: true,
    });
    let refusal = ConfigWatcher::auth_enabled_refusal(&live, &incoming, exposed)
        .expect("an exposed plaintext listener must block the flip");
    assert!(refusal.contains("plaintext listener"), "{refusal}");

    // A loopback listener is the case the startup path allows, so it is not
    // refused here either.
    let loopback = Some(PlaintextListener {
        addr: "127.0.0.1:8080".parse().unwrap(),
        exposed: false,
    });
    assert_eq!(
        ConfigWatcher::auth_enabled_refusal(&live, &incoming, loopback),
        None
    );

    // And no plaintext listener at all is always fine.
    assert_eq!(
        ConfigWatcher::auth_enabled_refusal(&live, &incoming, None),
        None
    );
}

/// Whether a device is still in use is answered from the stamp the server
/// writes back. A device whose `last_used` never reaches the file reports
/// "never used" forever, and "which of these can I revoke without
/// disconnecting someone" has nothing to go on — which is the whole of what
/// a per-device credential is for.
///
/// The stamp goes to the **state file**, and the configuration file is left
/// exactly as it was: the counters are the server's, the configuration is
/// the operator's, and a server that wrote its own counters into the
/// operator's file moved its modification time every time somebody
/// mistyped a code — which the watcher watches.
#[test]
fn a_device_stamp_is_written_back_without_touching_its_secret() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let state_path = dir.path().join("state.toml");
    let state_path_str = state_path.to_str().expect("utf-8 path").to_string();
    std::fs::write(
        &path,
        "[auth]\n\
         [auth.clients.alice]\n\
         secret = \"ALICEALICEALICEA\"\n\
         \n\
         [auth.clients.alice.devices.laptop]\n\
         secret = \"LAPTOPLAPTOPLAPT\"\n",
    )
    .expect("write the config");

    let mut alice = client("ALICEALICEALICEA");
    alice.devices = [(
        "laptop".to_string(),
        DeviceAuth {
            secret: SecretString::new("LAPTOPLAPTOPLAPT".to_string()),
            public_key: None,
            created_at: "0".to_string(),
            last_used: Some(1700000000),
            last_used_step: None,
        },
    )]
    .into_iter()
    .collect();
    let config = config_with(&[("alice", alice)]);

    // Written the way the connection layer writes it: from a snapshot, which
    // is a copy that carries no credential.
    save_auth_state(&state_path_str, &config.counter_snapshot()).expect("the writeback succeeds");

    let on_disk = std::fs::read_to_string(&state_path).expect("read the state back");
    assert!(
        on_disk.contains("last_used = 1700000000"),
        "the device stamp did not reach the file: {on_disk}"
    );
    assert!(
        !on_disk.contains("LAPTOPLAPTOPLAPT"),
        "the snapshot's blanked secret must not be written: {on_disk}"
    );

    let config_on_disk = std::fs::read_to_string(&path).expect("read the config back");
    assert_eq!(
        config_on_disk,
        "[auth]\n\
         [auth.clients.alice]\n\
         secret = \"ALICEALICEALICEA\"\n\
         \n\
         [auth.clients.alice.devices.laptop]\n\
         secret = \"LAPTOPLAPTOPLAPT\"\n",
        "the configuration is the operator's file and is not the server's to rewrite"
    );
}

/// A minimal config file carrying one `[auth.clients]` entry.
fn file_with(client_id: &str, secret: &str) -> String {
    format!(
        "[auth]\n\
         [auth.clients.{client_id}]\n\
         secret = \"{secret}\"\n\
         created_at = \"1723756800\"\n"
    )
}

/// A reload that finds an enrollment has overtaken its snapshot reads the
/// file again.
///
/// An enrollment spends a token by changing the live state and then writing
/// the change out, so a snapshot taken before the enrollment — and applied
/// afterwards — would put the spent token back and roll the client's secret
/// back to what it was before the enrollment.
///
/// The read is outside the lock now, so the lock alone cannot order the
/// two. The epoch does: it is sampled before the read and compared under
/// the lock the enrollment itself holds.
///
/// The enrollment is reproduced by holding the lock the way it does,
/// rewriting the file and moving the epoch while it is held: the reload
/// then has to wait for the lock, notice that its snapshot was overtaken,
/// and come away with what the file says *now*.
#[tokio::test]
async fn a_reload_that_finds_an_enrollment_has_overtaken_it_reads_again() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    std::fs::write(&path, file_with("old", "OLDOLDOLDOLDOLDO")).expect("write the first file");
    let state = AuthState::new(
        config_with(&[("old", client("OLDOLDOLDOLDOLDO"))]),
        path_str.clone(),
    );

    let watcher = ConfigWatcher::new(
        path_str,
        Arc::new(RoutingTable::new(Vec::new())),
        Arc::new(
            crate::http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                .expect("the default trust store is always usable"),
        ),
        Arc::new(Mutex::new(HealthProbes::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        Some(state.clone()),
        Arc::new(PeerRegistry::new()),
    );

    let enrolled = state.clone();
    let path_for_task = path.clone();
    // The epoch as it was before the enrollment: the snapshot the reload
    // is about to take belongs to the revision before it.
    let epoch_before = state.enroll_epoch();

    let holder = tokio::spawn(async move {
        let _guard = enrolled.config().write().await;
        // The order `enroll_client` uses: the file is written first, and
        // the epoch moves after it, under the same lock. A bump before the
        // write would let the reload sample the new epoch and still read
        // the old file.
        std::fs::write(&path_for_task, file_with("new", "NEWNEWNEWNEWNEWN"))
            .expect("write the second file");
        enrolled.bump_enroll_epoch();
        tokio::time::sleep(Duration::from_millis(150)).await;
    });

    // Long enough for the task above to have taken the lock and rewritten
    // the file, which is the only thing that makes this a race.
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The snapshot the reload starts with says "old" — the file as it was
    // before the enrollment.
    watcher
        .reload_auth(
            Some(config_with(&[("old", client("OLDOLDOLDOLDOLDO"))])),
            epoch_before,
        )
        .await;
    holder.await.expect("the holder task ends");

    let live = state.config().read().await;
    assert!(
        live.clients.contains_key("new"),
        "the reload must merge the file as it reads once it holds the lock"
    );
    assert!(
        !live.clients.contains_key("old"),
        "a client the file no longer lists must not survive the reload"
    );
}

/// A device struck out of the file while its client survives has to reach
/// the connection already serving as it, not only the next dial.
///
/// This is the far end of the path `removed_devices` feeds: an operator
/// runs `nexapipe client revoke alice --device laptop`, the reload diffs
/// the device table, and the connection that authenticated as that device
/// is told to stop through the channel it was registered with. The sibling
/// device is the control — a revocation that took every device of the
/// client with it would be a different bug, and a quieter one.
#[tokio::test]
async fn a_reload_closes_the_connection_authenticated_as_a_removed_device() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    let file = |devices: &[&str]| {
        let mut out = String::from(
            "[auth]\n\
             [auth.clients.alice]\n\
             secret = \"ALICEALICEALICEA\"\n\
             created_at = \"1723756800\"\n",
        );
        for name in devices {
            out.push_str(&format!(
                "\n[auth.clients.alice.devices.{name}]\n\
                 secret = \"DEVICEDEVICEDEVIC\"\n\
                 created_at = \"1723756800\"\n"
            ));
        }
        out
    };

    std::fs::write(&path, file(&["laptop", "phone"])).expect("write the config");

    let mut alice = client("ALICEALICEALICEA");
    alice.devices = ["laptop", "phone"]
        .into_iter()
        .map(|name| (name.to_string(), device("DEVICEDEVICEDEVIC")))
        .collect();
    let state = AuthState::new(config_with(&[("alice", alice)]), path_str.clone());

    let peers = Arc::new(PeerRegistry::new());
    let watcher = ConfigWatcher::new(
        path_str,
        Arc::new(RoutingTable::new(Vec::new())),
        Arc::new(
            crate::http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                .expect("the default trust store is always usable"),
        ),
        Arc::new(Mutex::new(HealthProbes::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        Some(state.clone()),
        peers.clone(),
    );

    // Registered the way the handshake registers a connection: identity,
    // channel and guard in one step.
    let registered = |seed: u8, device: &str| {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let guard = peers.insert(
            iroh::SecretKey::from_bytes(&[seed; 32]).public(),
            crate::metrics::PathKind::Direct,
            PeerIdentity {
                client_id: Some("alice".to_string()),
                device: Some(device.to_string()),
            },
            tx,
        );
        (rx, guard)
    };
    let (mut laptop_rx, _laptop) = registered(1, "laptop");
    let (mut phone_rx, _phone) = registered(2, "phone");

    std::fs::write(&path, file(&["phone"])).expect("rewrite without the laptop");
    watcher.reload_config().await;

    assert!(
        *laptop_rx.borrow_and_update(),
        "a connection serving as a device the file no longer lists must be told to stop"
    );
    assert!(
        !*phone_rx.borrow_and_update(),
        "a device that is still in the file must not be closed along with it"
    );
}

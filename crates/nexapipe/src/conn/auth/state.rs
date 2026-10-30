//! The state a connection authenticates against, and where it is kept.
//!
//! Two files are involved: the configuration, which is the operator's and holds
//! the credentials, and the state file beside it, which holds the counters the
//! server counted.

use crate::auth::AuthConfig;
use crate::config_watcher::save_auth_state_to;
use crate::storage::Storage;

use super::authenticator::{Authenticator, ConfigAuthenticator};

use std::sync::Arc;
use std::sync::OnceLock;

/// The live 2FA state a connection authenticates against.
///
/// The config is shared: every connection reads it to validate, and the ones
/// that fail write their lockout counters back into it. Two files are
/// involved: the configuration, which is the operator's and holds the
/// credentials, and the state file beside it, which holds the counters the
/// server counted. The path is the configuration's — the enrollment flow
/// writes a token into it — and the state path is derived from it.
#[derive(Clone)]
pub struct AuthState {
    config: Arc<tokio::sync::RwLock<AuthConfig>>,
    /// Where the configuration and the counters are kept.
    ///
    /// A store rather than a path: the enrollment writes a credential into it,
    /// the counters are written back into it, and a store that is not a file
    /// has no paths to name.
    storage: Arc<dyn Storage>,
    /// How many enrollments have been applied to the live config.
    ///
    /// The configuration watcher reads the file **before** it takes the lock
    /// that guards the live config, and an enrollment that lands in between
    /// would be undone by the merge: it spends a token by changing the live
    /// state and only then writing the change back, so a snapshot taken a
    /// moment earlier still carries the spent token and the pre-enrollment
    /// secret.
    ///
    /// This counter is the witness. It is sampled before the read and compared
    /// under the lock, and the two cannot disagree about what happened — which
    /// holds only because the counter moves **after** the enrollment's write
    /// has landed, still under the lock. A counter bumped at the start of an
    /// enrollment could be sampled by a reload that then read the file before
    /// the write, and the stale snapshot would look current.
    enroll_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// How a credential is checked.
    ///
    /// The built-in one reads the credentials in the configuration. A
    /// deployment that keeps its credentials somewhere else hands its own
    /// implementation to [`AuthState::with_authenticator`] instead.
    ///
    /// It lives here rather than being passed down the connection path because
    /// it is a property of the deployment, not of a connection: every
    /// connection authenticates the same way, and a build that changed its mind
    /// halfway through would be a build in which two connections disagree about
    /// who is allowed in.
    authenticator: Arc<dyn Authenticator>,
}

impl AuthState {
    /// Wraps a freshly loaded config together with the store it came from.
    ///
    /// The credentials in the configuration are what this checks.
    pub fn new(config: AuthConfig, storage: Arc<dyn Storage>) -> Self {
        Self::with_authenticator(config, storage, Arc::new(ConfigAuthenticator))
    }

    /// Wraps a freshly loaded config, and the authenticator that checks the
    /// credentials against it.
    ///
    /// The built-in authenticator reads the configuration's own client table.
    /// Another one is for a deployment that keeps its credentials elsewhere —
    /// an identity provider, a directory — and it is given the same
    /// configuration to move its counters in, so that the lockout accounting
    /// and the step memory stay where every other build keeps them.
    pub fn with_authenticator(
        config: AuthConfig,
        storage: Arc<dyn Storage>,
        authenticator: Arc<dyn Authenticator>,
    ) -> Self {
        Self {
            config: Arc::new(tokio::sync::RwLock::new(config)),
            storage,
            enroll_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            authenticator,
        }
    }

    /// The authenticator every connection on this instance is checked by.
    pub fn authenticator(&self) -> &Arc<dyn Authenticator> {
        &self.authenticator
    }

    /// How many enrollments have been applied to the live config so far.
    ///
    /// Sampled before a read of the file and compared under the lock, to see
    /// whether an enrollment landed while the file was being read.
    pub fn enroll_epoch(&self) -> u64 {
        self.enroll_epoch.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Records that an enrollment has been applied to the live config.
    ///
    /// Called under the same lock the enrollment itself holds, and only after
    /// the enrollment's write to the config file has landed: the watcher
    /// samples this before it reads that file, so a bump that came first would
    /// let the read see the file as it was before the enrollment and still
    /// look current.
    pub fn bump_enroll_epoch(&self) {
        self.enroll_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// The shared config to validate against.
    pub fn config(&self) -> &Arc<tokio::sync::RwLock<AuthConfig>> {
        &self.config
    }

    /// The store the configuration and the counters are kept in.
    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
}

/// Persists the runtime counters to the state file, without the auth lock.
///
/// The counters are read **at write time** and the file is written with the
/// auth lock released: a write lock held across a disk write stalls every
/// connection that is authenticating, not only the one whose counters are
/// being written.
///
/// The gate orders the writes, so the file always carries the count as of the
/// write that reached it last. Because the counters are read here rather than
/// by the caller, a handshake that counted a failure in between is counted
/// too — the file can lag the in-memory count by the moment between a read
/// and the write, and the in-memory count is the one that decides.
///
/// The lock order is the auth lock and **then** the gate, which is the order
/// the writers that hold the auth lock take them in: [`blocking_config_write`]
/// is called from under the auth write lock, and takes the gate inside it. A
/// writer that took them the other way round would deadlock against one of
/// those — this task holding the gate and waiting for the read lock, that one
/// holding the write lock and waiting for the gate, and neither ever letting
/// go. The read guard is dropped before the disk write, so the lock is held
/// for the snapshot and not for the write.
pub(crate) async fn persist_auth_state(auth: &AuthState) -> anyhow::Result<()> {
    let storage = auth.storage().clone();
    let config = auth.config().clone();
    let (done, wait) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let cfg = config.read().await;
        let gate = config_write_gate().lock().await;
        let snapshot = cfg.counter_snapshot();
        // The snapshot is what the write needs; the lock it was taken under is
        // not, and a writer should not wait for the disk on top of the gate.
        drop(cfg);
        let result = save_auth_state_to(storage.as_ref(), &snapshot).await;
        drop(gate);
        let _ = done.send(result);
    });

    let result = wait
        .await
        .map_err(|_| anyhow::anyhow!("the auth state write was abandoned"))?;
    result.map_err(|e| anyhow::anyhow!("the auth state write did not run: {e}"))
}

/// Runs a write against the config file without occupying a worker.
///
/// These writes happen while the auth write lock is held, and that is not
/// incidental: the lock is what keeps two connections from persisting
/// overlapping views of the lockout counters, so the IO cannot be moved out
/// from under it. What can be moved is the *thread* it blocks. `std::fs` plus a
/// TOML parse is a syscall and some CPU on whichever thread calls it, and on a
/// tokio worker that stalls every task scheduled behind it — one handshake's
/// write becomes a delay on all of them, and a slow or contended mount turns
/// into handshakes timing out for a reason that has nothing to do with the
/// network. `spawn_blocking` hands it to a thread built for it and leaves the
/// worker free.
///
/// The lock is still held across the await, so this does not change who can
/// write when — only who waits for the disk.
///
/// Detached, and gated by [`config_write_gate`] rather than by the auth lock
/// alone: the caller is bounded by a deadline, and a deadline that fires while
/// a write is on the disk drops not only the result but the lock the write was
/// running under — while the write itself keeps going, because a blocking task
/// cannot be un-spawned. Two writes to one file then overlap and one of them
/// is lost. The gate is taken *inside* the detached task, so it is held for as
/// long as the write takes and not for as long as the caller is patient.
pub(in crate::conn) async fn storage_write<T, F>(what: String, write: F) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let (done, wait) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let _gate = config_write_gate().lock().await;
        let result = write.await;
        // A caller that timed out is not an error worth reporting: the write
        // it asked for has happened, which is what the gate is for.
        let _ = done.send(result);
    });

    let result = wait
        .await
        .map_err(|_| anyhow::anyhow!("the write to {what} was abandoned"))?;
    result.map_err(|e| anyhow::anyhow!("the write to {what} did not run: {e}"))
}

/// Serialises writes to the config file and to the state file beside it,
/// independently of the caller.
///
/// A `static` because it has to outlive the task that asked for the write: the
/// auth lock is released when a handshake is cancelled, and this is what keeps
/// that cancellation from letting the next write start on top of a running
/// one. The two files have a lock each of their own; this gate is what keeps
/// the two kinds of write from running at the same time, which is no slower
/// than the writes themselves and one thing less to reason about.
pub(super) fn config_write_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

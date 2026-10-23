pub mod autostart;
pub mod commands;
pub mod credentials;
pub mod error;
pub mod gate;
mod proxy;
pub mod quit;
pub mod service;
pub mod status;
pub mod tray;
#[cfg(windows)]
mod win;

use commands::{stale_hijack_cleanup, APP_START, PROXY_MANAGER, TRAY_AVAILABLE};

use std::sync::atomic::Ordering;

use tauri::Manager;

/// One instance of the app at a time.
///
/// The app starts itself when the machine does — see [`crate::autostart`] — so a
/// second launch is a normal event rather than a mistake: the login entry fires
/// while a session the user already has open is still running. Nothing used to
/// stop that second process, and it was not harmless:
///
/// * In service mode the second instance's `StartProxy` makes the elevated
///   service stop the first instance's manager and start a new one, so the
///   tunnel is silently replaced under the first window.
/// * In process mode the second instance cannot bind the local proxy port, and
///   the failure is reported to a user who never asked for a second instance.
/// * Quitting one of them leaves the other running and still reporting
///   "connected".
///
/// So a second launch does not start a second app. It asks the instance that is
/// already running to bring its window forward and then leaves.
///
/// # What is guarded, and what is not
///
/// The desktop UI, and only the desktop UI. The elevated service is a separate
/// binary (`nexa-service`) that never builds a Tauri app, and the service verbs
/// the desktop binary itself understands (`--install`, `--start`, …) are
/// consumed in `main` before the app is built — so the elevated copy of the
/// desktop binary never reaches this code either.
///
/// # How the lock is held, and released
///
/// The lock is the operating system's own: `flock(2)` on Unix and `LockFileEx`
/// on Windows, taken through [`std::fs::File::try_lock`]. The kernel releases
/// it when the process dies, so a crash cannot leave a lock behind that would
/// stop the app from ever starting again — which is what a lock file whose
/// mere existence is the lock would do.
///
/// The lock file holds nothing, and the address the running instance answers on
/// is published in a second file beside it: on Windows the lock covers the
/// whole file, and a locked range cannot be read by another process.
pub mod single_instance {
    use std::fs::TryLockError;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

    use crate::service::ipc_token::runtime_file;

    /// The file this process locks, beside the token.
    const LOCK_FILE: &str = "instance.lock";

    /// The file this process publishes the address it answers on, beside the
    /// token.
    const ADDRESS_FILE: &str = "instance.addr";

    /// What a second launch asks for: bring the window forward.
    const SHOW_REQUEST: &[u8] = b"show\n";

    /// What a second launch asks for when the machine started it: nothing
    /// visible — only the proof that the app is running.
    const QUIET_REQUEST: &[u8] = b"quiet\n";

    /// How long a second launch waits for the running instance to publish the
    /// address it answers on.
    ///
    /// The window between "the lock is taken" and "the address is published"
    /// is the window in which two launches happen at once — a login that races
    /// a manual start — and it is short, but it is not zero.
    const ADDRESS_WAIT: Duration = Duration::from_secs(5);

    /// How often a second launch looks again while it waits.
    const ADDRESS_POLL: Duration = Duration::from_millis(50);

    /// How long a second launch waits for the running instance to answer.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    /// The lock this process holds for as long as it is the app.
    ///
    /// A static rather than a local: the lock has to be held until the process
    /// ends, and it cannot be handed back.
    static INSTANCE_LOCK: Mutex<Option<InstanceLock>> = Mutex::new(None);

    /// The requests a second launch has made, waiting to be answered.
    ///
    /// `None` in a process that did not claim the app.
    static ACTIVATION_REQUESTS: Mutex<Option<UnboundedReceiver<()>>> = Mutex::new(None);

    /// What a launch does about the app that may already be running.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Launch {
        /// This process is the app: it holds the lock and owns the window.
        RunTheApp,
        /// Another instance is running. It has been asked to bring its window
        /// forward, and this process leaves without starting anything.
        AskTheRunningInstanceToShowItsWindow,
        /// Another instance is running and the machine started this launch, so
        /// the running instance is left where the user put it: the
        /// start-at-login entry exists to keep the app in the tray, not to
        /// interrupt a session that is already open.
        LeaveTheRunningInstanceAlone,
    }

    impl Launch {
        /// Whether this process is the app and should go on to build the
        /// window.
        pub fn runs_the_app(self) -> bool {
            matches!(self, Launch::RunTheApp)
        }
    }

    /// What a launch does, given whether the app is already running and whether
    /// the machine started this launch.
    ///
    /// Both are arguments rather than facts the function looks up, so the rule
    /// can be stated — and checked — on its own: a second launch never starts a
    /// second app.
    pub fn launch_action(another_instance_running: bool, machine_started: bool) -> Launch {
        match (another_instance_running, machine_started) {
            (false, _) => Launch::RunTheApp,
            (true, true) => Launch::LeaveTheRunningInstanceAlone,
            (true, false) => Launch::AskTheRunningInstanceToShowItsWindow,
        }
    }

    /// The exclusive lock that says this process is the app.
    ///
    /// The file holds nothing: the operating system's lock on it is the whole
    /// of it. The file's *existence* is not the lock either, because a file
    /// left behind by a crash would then be indistinguishable from a running
    /// instance, and the app would never start again.
    pub struct InstanceLock {
        file: std::fs::File,
    }

    impl InstanceLock {
        /// Takes the lock, or reports that another instance holds it.
        ///
        /// `Ok(None)` means another instance has it. `Err` means the lock could
        /// not be taken for a reason that has nothing to do with another
        /// instance — a directory that cannot be written, a filesystem that
        /// does not lock — and the caller decides what to do about that.
        pub fn acquire(path: &Path) -> std::io::Result<Option<Self>> {
            let file = std::fs::OpenOptions::new()
                .create(true)
                // The lock file is a lock, not a document: whatever it already
                // holds is nobody's data, and truncating a file another process
                // may be about to lock buys nothing.
                .truncate(false)
                // Write access and not append: on Windows a file opened only
                // for append cannot be locked at all.
                .write(true)
                .read(true)
                .open(path)?;

            match file.try_lock() {
                Ok(()) => Ok(Some(Self { file })),
                Err(TryLockError::WouldBlock) => Ok(None),
                Err(TryLockError::Error(e)) => Err(e),
            }
        }
    }

    impl Drop for InstanceLock {
        fn drop(&mut self) {
            // Released on close regardless; unlocking explicitly keeps the
            // pairing visible, and the error has nowhere to go from a `Drop`.
            let _ = self.file.unlock();
        }
    }

    /// Takes the app for this process, or hands the launch over to the
    /// instance that already has it.
    ///
    /// Called before the window is built: a launch that finds the app already
    /// running must not build a second window, a second tray icon, and a
    /// second proxy over the first one.
    pub fn claim() -> Launch {
        let machine_started = crate::autostart::is_background_launch();

        let action = match take_the_lock() {
            // The lock is ours: this process is the app.
            Ok(true) => Launch::RunTheApp,
            // Another instance holds it. This launch must not start a second
            // app whatever happens next.
            Ok(false) => {
                let action = launch_action(true, machine_started);
                let _ = deliver_the_request(action);
                action
            }
            Err(e) => {
                tracing::warn!("the single-instance lock could not be taken: {e}");
                // The lock may be held after all — on Windows a locked range is
                // reported as an error the platform does not always spell
                // "would block" — so ask before starting a second copy.
                let action = launch_action(true, machine_started);
                if deliver_the_request(action) {
                    action
                } else {
                    // Nobody answered: the lock is unusable rather than held,
                    // and an app that will not start is worse than a second
                    // copy of it.
                    Launch::RunTheApp
                }
            }
        };

        if action.runs_the_app() {
            start_answering_activation_requests();
        }

        action
    }

    /// Takes the lock, and keeps it for as long as the process lives.
    ///
    /// `Ok(true)` — this process is the app.
    /// `Ok(false)` — another instance holds the lock.
    /// `Err` — the lock could not be taken for a reason that says nothing about
    /// another instance.
    fn take_the_lock() -> std::io::Result<bool> {
        let path = runtime_file(LOCK_FILE);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let Some(lock) = InstanceLock::acquire(&path)? else {
            return Ok(false);
        };

        // The lock has to be held for as long as the process lives, so it
        // cannot be a local: it goes here and is never taken out.
        *INSTANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner()) = Some(lock);
        Ok(true)
    }

    /// Delivers the request a second launch makes to the instance that is
    /// already running.
    ///
    /// `true` when the request was delivered.
    fn deliver_the_request(action: Launch) -> bool {
        let request = match action {
            Launch::AskTheRunningInstanceToShowItsWindow => SHOW_REQUEST,
            _ => QUIET_REQUEST,
        };

        let Some(address) = wait_for_the_address() else {
            tracing::warn!(
                "another instance of the app is running, but it did not say where to reach it"
            );
            return false;
        };

        let mut stream = match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!("the running instance could not be reached: {e}");
                return false;
            }
        };

        match stream.write_all(request) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("the running instance could not be reached: {e}");
                false
            }
        }
    }

    /// The address the running instance published, once it has published one.
    fn wait_for_the_address() -> Option<SocketAddr> {
        let path = runtime_file(ADDRESS_FILE);
        let deadline = Instant::now() + ADDRESS_WAIT;
        loop {
            if let Some(address) = published_address(&path) {
                return Some(address);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(ADDRESS_POLL);
        }
    }

    /// The address the running instance published, read without waiting.
    fn published_address(path: &Path) -> Option<SocketAddr> {
        let text = std::fs::read_to_string(path).ok()?;
        text.trim().parse().ok()
    }

    /// Publishes the address the running instance answers on.
    fn publish_address(path: &Path, address: SocketAddr) -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        file.write_all(address.to_string().as_bytes())
    }

    /// Starts answering the launches that ask the running instance to come
    /// forward.
    ///
    /// The address is published before the app is built, so a launch that
    /// arrives in the middle of the start-up finds it: the request waits on a
    /// channel until the window exists.
    fn start_answering_activation_requests() {
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(e) => {
                tracing::warn!("the app cannot answer a second launch: {e}");
                return;
            }
        };

        let address = match listener.local_addr() {
            Ok(address) => address,
            Err(e) => {
                tracing::warn!("the address the app answers on could not be read: {e}");
                return;
            }
        };

        if let Err(e) = publish_address(&runtime_file(ADDRESS_FILE), address) {
            tracing::warn!("the address the app answers on could not be published: {e}");
            return;
        }

        let (requests, receiver) = unbounded_channel();
        *ACTIVATION_REQUESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(receiver);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::warn!("the app stopped answering second launches: {e}");
                        break;
                    }
                };

                // The request is a line, and the answer is silence: the
                // running instance has nothing to say back.
                let mut request = Vec::new();
                let _ = stream.read_to_end(&mut request);
                if request.starts_with(SHOW_REQUEST) {
                    let _ = requests.send(());
                }
            }
        });
    }

    /// Brings the window forward whenever a second launch asks for it.
    ///
    /// Called once the app exists: the request can arrive before the window
    /// does, so it waits on a channel rather than on the window.
    pub fn answer_activation_requests(app: tauri::AppHandle) {
        let receiver = ACTIVATION_REQUESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(mut requests) = receiver else {
            return;
        };

        tauri::async_runtime::spawn(async move {
            while requests.recv().await.is_some() {
                let handle = app.clone();
                if let Err(e) = app.run_on_main_thread(move || crate::tray::show_window(&handle)) {
                    tracing::warn!("the window could not be brought forward: {e}");
                }
            }
        });
    }

    #[cfg(test)]
    mod tests {
        use super::{
            launch_action, publish_address, published_address, InstanceLock, Launch, ADDRESS_FILE,
            LOCK_FILE,
        };
        use std::net::SocketAddr;
        use std::path::PathBuf;

        /// A directory of this test's own, removed when the test ends.
        struct Scratch(PathBuf);

        impl Scratch {
            fn new(name: &str) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "nexa-single-instance-{name}-{}",
                    std::process::id()
                ));
                let _ = std::fs::remove_dir_all(&path);
                std::fs::create_dir_all(&path).expect("the scratch directory can be created");
                Self(path)
            }

            fn file(&self, name: &str) -> PathBuf {
                self.0.join(name)
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn a_second_instance_is_refused() {
            let scratch = Scratch::new("refused");
            let path = scratch.file(LOCK_FILE);

            let first = InstanceLock::acquire(&path).expect("the lock can be tried");
            assert!(first.is_some(), "the first instance takes the lock");

            let second = InstanceLock::acquire(&path).expect("the lock can be tried");
            assert!(
                second.is_none(),
                "the second instance is refused while the first holds the lock"
            );
        }

        #[test]
        fn the_lock_is_released_when_the_guard_is_dropped() {
            let scratch = Scratch::new("released");
            let path = scratch.file(LOCK_FILE);

            {
                let first = InstanceLock::acquire(&path).expect("the lock can be tried");
                assert!(first.is_some(), "the first instance takes the lock");
                // The guard goes out of scope here, and the lock with it.
            }

            let later = InstanceLock::acquire(&path).expect("the lock can be tried");
            assert!(
                later.is_some(),
                "a later start is not blocked by a lock that was given up"
            );
        }

        #[test]
        fn a_second_launch_never_starts_a_second_app() {
            assert_eq!(launch_action(false, false), Launch::RunTheApp);
            assert_eq!(launch_action(false, true), Launch::RunTheApp);
            assert_eq!(
                launch_action(true, false),
                Launch::AskTheRunningInstanceToShowItsWindow
            );
            assert_eq!(
                launch_action(true, true),
                Launch::LeaveTheRunningInstanceAlone
            );
        }

        #[test]
        fn the_running_instance_publishes_where_to_reach_it() {
            let scratch = Scratch::new("address");
            let path = scratch.file(ADDRESS_FILE);

            assert!(
                published_address(&path).is_none(),
                "nothing is published before the app starts"
            );

            let address: SocketAddr = "127.0.0.1:4242".parse().expect("it is an address");
            publish_address(&path, address).expect("the address is published");

            assert_eq!(
                published_address(&path),
                Some(address),
                "the address the app answers on is published"
            );
        }
    }
}

/// Log directory for the desktop process: `%APPDATA%\nexa\logs` on Windows and the user's
/// XDG state directory on Unix.
///
/// This is deliberately per-user and never shared with [`service_log_dir`]. A root service must
/// not create the directory first and leave the desktop user unable to write its own log there.
pub fn log_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var("APPDATA")
            .map(|d| std::path::Path::new(&d).join("nexa").join("logs"))
            .unwrap_or_else(|_| std::env::temp_dir().join("nexa").join("logs"))
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| std::path::PathBuf::from(home).join(".local").join("state"))
            })
            .unwrap_or_else(std::env::temp_dir);
        base.join("nexa").join("logs")
    }
}

/// Where the *service* writes its log.
///
/// Not [`log_dir()`]: the service runs as LocalSystem on Windows and root on Unix, while the
/// desktop process runs as the logged-in user. Keeping the two apart means a service startup
/// failure can always write its diagnostic without taking ownership of the user's log directory.
pub fn service_log_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var("PROGRAMDATA")
            .map(|d| std::path::Path::new(&d).join("nexa").join("logs"))
            .unwrap_or_else(|_| log_dir())
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/var/log/nexa-service")
    }
}

/// [`init_tracing`] pointed at a directory of the caller's choosing; see [`service_log_dir`].
///
/// Logging is allowed to degrade to stdout when the directory or file cannot be created. A
/// missing log file must never prevent either binary from starting.
pub fn init_tracing_in(
    dir: std::path::PathBuf,
    prefix: &str,
) -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let file_appender = match std::fs::create_dir_all(&dir) {
        Ok(()) => tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(prefix)
            .build(&dir)
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    let (file_writer, guard) = match file_appender {
        Ok(appender) => tracing_appender::non_blocking(appender),
        Err(error) => {
            eprintln!(
                "failed to initialize log file in {}: {}; continuing with stdout logging",
                dir.display(),
                error
            );
            // The stdout layer below remains active, so this writer is only a harmless sink for
            // the file layer and keeps the returned guard type uniform.
            tracing_appender::non_blocking(std::io::sink())
        }
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_writer)
                .with_ansi(false),
        )
        .with(filter)
        .init();
    guard
}

/// Initializes logging: info level by default (override with RUST_LOG), writing both to the
/// console and to a daily rolling file below [`log_dir()`].
/// The returned guard must be kept alive for the log flushing thread to keep running.
pub fn init_tracing(prefix: &str) -> tracing_appender::non_blocking::WorkerGuard {
    init_tracing_in(log_dir(), prefix)
}

/// How long the window stays hidden waiting for the frontend to paint, before it is shown
/// anyway.
///
/// The frontend normally shows the window itself one frame after it mounts, which is the
/// right moment: the first paint is on screen and nothing empty was ever displayed. This is
/// the deadline for the case where that never happens — a bundle that failed to load, a
/// renderer that threw before mount — because a window that never appears is
/// indistinguishable from an application that did not start.
///
/// Generous on purpose. A cold WebView2 on a slow machine, or a first run that also has to
/// unpack and JIT the bundle, can take a while, and showing a window with nothing in it is a
/// lesser failure than never showing one. Nothing waits on this: it runs alongside the
/// frontend's own `show()` and whichever arrives first wins, the second being a no-op.
const FIRST_PAINT_FALLBACK: std::time::Duration = std::time::Duration::from_secs(10);

/// Stops a tunnel this process is still running, so that quitting the app hands the
/// machine's DNS back.
///
/// Quitting reaches neither [`stop_proxy`] nor the teardown inside `TunProxy::run`,
/// so a hijack that was up when the window closed stayed up — and stayed pointing
/// the machine at a TUN address that was about to stop existing. Only the in-process
/// tunnel is stopped: one the launchd/systemd service owns belongs to that daemon,
/// which outlives the window on purpose.
async fn stop_tunnel_on_exit() {
    // Taken rather than borrowed, so a second pass — `ExitRequested` is followed by
    // `Exit` — finds nothing and does not run the teardown twice.
    let manager = PROXY_MANAGER.write().await.take();
    let Some(manager) = manager else {
        return;
    };
    tracing::info!("stopping the tunnel on exit so the system DNS is restored");
    manager.stop().await;
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Read before anything else this process does, so the elapsed times below are measured
    // from as close to the real start as a `LazyLock` can get.
    std::sync::LazyLock::force(&APP_START);

    let _guard = init_tracing("nexa.log");
    // Logged after the subscriber exists rather than before it: a line emitted before
    // `init_tracing` has nowhere to go.
    tracing::info!("[startup] process start");

    // One instance of the app at a time. The app starts itself when the machine
    // does, so a second launch is a normal event rather than a mistake — and
    // starting a second process was not harmless: in service mode the second
    // instance's `StartProxy` makes the elevated service replace the first
    // instance's tunnel. The claim is made before the window is built, so a
    // launch that finds the app already running leaves without building one.
    let launch = single_instance::claim();
    if !launch.runs_the_app() {
        tracing::info!(
            "[startup] another instance of the app is already running; this launch leaves"
        );
        return;
    }

    // Increase tokio worker thread stack size to 4 MB (default 2 MB) to
    // prevent stack overflow from deeply nested async state machines in
    // iroh / proxy code.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(4 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let handle = runtime.handle().clone();
    // Prevent the runtime from being dropped — it must live as long as the
    // process. Tauri holds the Handle and uses it for all async commands.
    std::mem::forget(runtime);
    // Kept: the exit hook below has to run the teardown on this very runtime, and
    // the one Tauri is handed is a clone of it.
    let shutdown = handle.clone();
    tauri::async_runtime::set(handle);

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            // The window exists by the time this runs and is still hidden, so this is the
            // moment the process stops being "starting up" and starts being "loading the
            // frontend": everything after it is the webview's, and everything before it was
            // ours — the binary, the runtime, the window.
            tracing::info!(
                "[startup] setup reached, window created: +{}ms",
                APP_START.elapsed().as_millis()
            );

            // Same reason the service runner does it: a hijack whose process died
            // before its teardown left the machine's DNS pointing at a TUN address
            // that no longer exists, and nothing else will ever undo that. Doing it
            // here as well matters because the tunnel is not always the service's —
            // the desktop can run one itself when it was launched elevated — and a
            // LaunchDaemon is not what that process becomes. Best effort: an
            // unprivileged desktop cannot change system DNS and the service, which
            // runs as root, cleans up on its own start.
            //
            // On a task, because this is not something the first paint should wait
            // for: the window already exists by the time this closure runs, and on
            // Windows the PowerShell it shells out to costs over a second. A start
            // waits for it explicitly — see `stale_hijack_cleanup`.
            tauri::async_runtime::spawn(stale_hijack_cleanup());

            // A second launch asks the instance that is already running to
            // bring its window forward. The request can arrive before this
            // window exists, so it waits on a channel rather than on the
            // window.
            single_instance::answer_activation_requests(app.handle().clone());

            // The tray icon: the app's second home, and the one it starts in
            // when the machine starts it. Built before the window is shown so
            // that a launch with no window still has a way back into the app.
            //
            // Best effort: a desktop with no tray — a bare session, a
            // container — must still be able to run the app, and what is lost
            // there is an icon rather than the application.
            match tray::build(app.handle()) {
                Ok(()) => TRAY_AVAILABLE.store(true, Ordering::Relaxed),
                Err(e) => tracing::warn!("the tray icon could not be created: {e}"),
            }

            // The window is created hidden (`visible: false`) and shown by the frontend
            // once it has something to paint, so a slow start shows no window rather
            // than an empty one. This is the backstop for the case where the frontend
            // never gets there — a bundle that failed to load, a renderer that threw
            // before mount: a window that never appears is indistinguishable from an app
            // that did not start, so it is shown anyway once the wait has clearly run
            // long enough to be a failure rather than a slow machine.
            //
            // Not for a launch the machine asked for: that one comes up in the
            // tray on purpose, and a window appearing over whatever the user
            // was doing at login is exactly what it was meant to avoid.
            //
            // Unless there is no tray to come up in. The tray is built on a
            // best-effort basis and can fail — a bare session, a container, a
            // Linux host without a StatusNotifier — and an app with no window
            // and no tray icon is an app nobody can reach again.
            //
            // Best effort on every platform, and deliberately not fatal: a build with no
            // window to show must still start.
            if !autostart::is_background_launch() || !TRAY_AVAILABLE.load(Ordering::Relaxed) {
                if let Some(window) = app.get_webview_window("main") {
                    let handle = window.clone();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(FIRST_PAINT_FALLBACK).await;
                        if let Err(e) = handle.show() {
                            tracing::warn!("the fallback could not show the window: {e}");
                        }
                    });
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::proxy::start_proxy,
            commands::proxy::stop_proxy,
            commands::proxy::get_proxy_status,
            commands::proxy::get_node_id_display,
            commands::proxy::reveal_node_id,
            commands::proxy::get_endpoint_links,
            commands::proxy::get_node_health,
            commands::proxy::get_node_traffic,
            commands::proxy::get_active_flows,
            commands::proxy::close_flow,
            commands::proxy::close_node_flows,
            commands::invite::parse_invite,
            commands::invite::accept_invite,
            commands::invite::take_issued_credential,
            commands::service::install_service,
            commands::service::uninstall_service,
            commands::service::start_service,
            commands::service::stop_service,
            commands::service::get_service_status,
            commands::service::get_service_version,
            commands::service::is_service_running,
            commands::logs::get_startup_error,
            commands::logs::get_logs,
            commands::logs::clear_logs,
            commands::credentials::take_runtime_credentials,
            commands::credentials::take_invited_node_credentials,
            commands::credentials::credential_display,
            commands::credentials::reveal_credential,
            commands::credentials::gate_status,
            commands::credentials::unlock_credentials,
            commands::credentials::lock_credentials,
            commands::credentials::put_credential,
            commands::credentials::delete_credential,
            commands::credentials::clear_credentials,
            commands::credentials::credential_store_status,
            commands::logs::log_startup_timing,
            commands::autostart::is_auto_start_enabled,
            commands::autostart::set_auto_start,
            commands::autostart::is_background_launch,
            commands::tray::is_tray_available,
            commands::tray::set_tray_labels,
            commands::tray::set_tray_status,
            quit::finish_quit,
            quit::quit_guard_ready,
        ]);

    // macOS only: the predefined Quit item terminates the process before any event carrying a
    // `prevent_exit()` exists, so nothing about it can be intercepted — see the module doc in
    // `quit`. Ours asks instead and leaves the deciding to the renderer, which is the same answer
    // closing the window gets. If asking itself fails the process still has to go, or Cmd+Q would
    // quietly stop working.
    #[cfg(target_os = "macos")]
    let builder = builder.menu(quit::menu_bar).on_menu_event(|app, event| {
        if event.id() != quit::QUIT_ITEM_ID {
            return;
        }
        tracing::info!("Quit chosen from the menu; waiting for the answer");
        quit::ask(app);
    });

    let app = builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    // Closing the window, Cmd+Q, or an `app.exit()` all end the process without
    // going anywhere near the proxy's teardown, which is what put the system DNS
    // back — so the machine kept the address the hijack gave it until the next
    // start cleaned up after it. Both events are handled because which of them a
    // platform emits last is not this code's to choose: one is the last window's
    // destruction, the other the event loop being torn down, and a quit reaches
    // either one or both depending on how it was asked for.
    //
    // Blocking here is what makes it work — the restore runs on the runtime these
    // commands use — and it is bounded: `stop_and_wait` gives the teardown twenty
    // seconds. Stale-hijack cleanup at start-up is still the backstop, because
    // nothing reaches either event when the process is killed or the power goes.
    app.run(move |_app_handle, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            shutdown.block_on(stop_tunnel_on_exit());
        }
    });
}

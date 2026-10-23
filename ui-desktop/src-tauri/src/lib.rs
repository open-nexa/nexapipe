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

//! The tray icon, as the renderer sees it.
//!
//! The tray is the app's way back in when the window is hidden, so what the
//! renderer needs to know about it is a command: whether it exists, what its
//! menu says, and what the state on it is.

use crate::commands::TRAY_AVAILABLE;
use crate::tray;

use std::sync::atomic::Ordering;

use tauri::AppHandle;

/// Whether the tray icon could be created.
///
/// The renderer needs this before it lets a closed window hide instead of
/// closing: a window that hides with no tray to bring it back is an app that
/// cannot be reached again.
#[tauri::command]
pub(crate) async fn is_tray_available() -> bool {
    TRAY_AVAILABLE.load(Ordering::Relaxed)
}

/// Rewrites the tray menu in the user's language.
///
/// The translations live in the renderer, which is the only side that knows
/// which language is in use, so the words are handed over rather than looked
/// up here.
///
/// Infallible on purpose: the labels are a nicety, and a tray whose menu is in
/// the wrong language is still a working tray. The failure is logged, because
/// it is worth knowing about.
#[tauri::command]
pub(crate) async fn set_tray_labels(app: AppHandle, show_label: String, quit_label: String) {
    if let Err(e) = tray::set_labels(&app, &show_label, &quit_label) {
        tracing::warn!("the tray menu could not be relabelled: {e}");
    }
}

/// Writes the connection state onto the tray icon.
///
/// The words come from the renderer, which is the only side that knows the status
/// and the language it should be said in.
///
/// Refused rather than trimmed when the text is not one short line: the text goes
/// straight to a native tooltip and a native title, and a caller that could put
/// a newline or a control character there would be writing into another
/// process's window.
///
/// Infallible on purpose, like [`set_tray_labels`]: the state on the tray is
/// information, and a tray that cannot be written to is still a working tray.
#[tauri::command]
pub(crate) async fn set_tray_status(app: AppHandle, status: String) {
    if !tray::is_writable_status(&status) {
        tracing::warn!("the tray status was refused: it is not a single short line");
        return;
    }
    if let Err(e) = tray::set_status(&app, &status) {
        tracing::warn!("the tray status could not be written: {e}");
    }
}

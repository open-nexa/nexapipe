//! The start-up entry, as the renderer sees it.
//!
//! The entry is the machine's own way of starting this app, and the renderer
//! asks about it and writes it. Whether this launch was one of those is asked
//! too: a launch the machine asked for keeps the window hidden.

use crate::autostart;
use crate::error::AppError;

/// Whether this app is started when the machine starts.
///
/// See [`autostart`]. A read that fails is a failure rather than "off": a
/// switch that claims to be off while the entry is there is the same silent
/// lie it used to tell.
#[tauri::command]
pub(crate) async fn is_auto_start_enabled() -> Result<bool, AppError> {
    autostart::is_enabled()
}

/// Arranges for this app to start when the machine starts, or not.
///
/// Writes the entry and stops there. The platform's own login mechanism is
/// what starts the app next time, so switching this on does not launch a
/// second copy of the app in the middle of the session.
#[tauri::command]
pub(crate) async fn set_auto_start(enabled: bool) -> Result<(), AppError> {
    autostart::set_enabled(enabled)
}

/// Whether this launch was asked for by the machine rather than by a person.
///
/// True when the start-up entry started the app: the window stays hidden and
/// the app waits in the tray.
#[tauri::command]
pub(crate) async fn is_background_launch() -> bool {
    autostart::is_background_launch()
}

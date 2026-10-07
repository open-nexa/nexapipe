//! The application's own Quit item, so that quitting asks first.
//!
//! The item [`tauri::menu::Menu::default`] puts in the menu bar is a predefined one, and on macOS
//! activating it calls `NSApp terminate:` — which tears the process down on the spot, without
//! ever producing a [`tauri::RunEvent::ExitRequested`], the only exit event carrying a
//! `prevent_exit()`. So nothing about it can be intercepted: whichever proxy this process was
//! carrying dies with it, and no question is asked.
//!
//! Replacing that item with one of ours turns Cmd+Q into an ordinary menu event, which this
//! module answers by asking the renderer — see [`QUIT_REQUESTED_EVENT`]. The renderer puts the
//! same question the window's close button asks and calls [`finish_quit`] when the answer is
//! "quit". The window itself needs no such replacement: Tauri holds a window open as soon as the
//! renderer listens for its close request, so that path already asks.

use tauri::AppHandle;

// macOS only: `tauri::menu` is a desktop crate, and it is macOS whose Quit item needs replacing.
// Everything else in this module is built on every platform.
#[cfg(target_os = "macos")]
use tauri::menu::{AboutMetadata, Menu, MenuBuilder, MenuItemBuilder, SubmenuBuilder};
#[cfg(target_os = "macos")]
use tauri::Wry;

/// Id of the item that stands in for the predefined Quit.
pub const QUIT_ITEM_ID: &str = "quit";

/// Emitted when that item is activated, for the renderer to answer.
pub const QUIT_REQUESTED_EVENT: &str = "nexa://quit-requested";

/// The menu bar, with Quit wired to us instead of to `NSApp`.
///
/// Every other submenu is what Tauri's own default builds: replacing one item means rebuilding
/// the bar, so the items a mac is expected to have are listed here rather than left out by
/// accident. Help is dropped on purpose — the default one carries nothing on this platform.
#[cfg(target_os = "macos")]
pub fn menu_bar(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let pkg = app.package_info();
    let about = AboutMetadata {
        name: Some(pkg.name.clone()),
        version: Some(pkg.version.to_string()),
        copyright: app.config().bundle.copyright.clone(),
        authors: app.config().bundle.publisher.clone().map(|p| vec![p]),
        ..Default::default()
    };

    let quit = MenuItemBuilder::with_id(QUIT_ITEM_ID, format!("Quit {}", pkg.name))
        .accelerator("CmdOrCtrl+Q")
        .build(app)?;

    let app_submenu = SubmenuBuilder::new(app, pkg.name.clone())
        .about(Some(about))
        .separator()
        .services()
        .separator()
        .hide()
        .hide_others()
        .show_all()
        .separator()
        .item(&quit)
        .build()?;

    let file_submenu = SubmenuBuilder::new(app, "File").close_window().build()?;

    let edit_submenu = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    let view_submenu = SubmenuBuilder::new(app, "View").fullscreen().build()?;

    let window_submenu = SubmenuBuilder::new(app, "Window")
        .minimize()
        .maximize()
        .separator()
        .close_window()
        .build()?;

    MenuBuilder::new(app)
        .item(&app_submenu)
        .item(&file_submenu)
        .item(&edit_submenu)
        .item(&view_submenu)
        .item(&window_submenu)
        .build()
}

/// Ends the process once the question has been answered.
///
/// Called by the renderer rather than from the menu handler, because stopping the proxy first is
/// the renderer's to do: the proxy store owns `stop_proxy` and the toast that reports its result.
/// [`AppHandle::exit`] still walks `ExitRequested` and then `Exit`, so the tunnel teardown in the
/// run loop runs here exactly as it does when the last window is destroyed.
#[tauri::command]
pub async fn finish_quit(app: AppHandle) {
    // Handed to the runtime rather than awaited here: `exit` closes the IPC channel this
    // command's reply is written to, and awaiting it from a future inside that channel leaves the
    // renderer holding an invoke that can never be answered.
    tauri::async_runtime::spawn(async move { app.exit(0) });
}

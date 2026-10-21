//! The tray icon: where the app lives when it has no window.
//!
//! The desktop app was a window that was either there or not — closing it ended
//! the process, and a tunnel running inside this process died with it. A proxy
//! that has to be started by hand every time the machine wakes is not a proxy
//! that is "always on", and that is the whole point of the setting this app
//! ships with.
//!
//! So the app grows a second home. The tray icon is where it goes when the
//! window is closed, and the window is one click away from there.
//!
//! # What the tray does
//!
//! - **A click** brings the window back. The icon is the app's front door.
//! - **Open** does the same, for the people who would rather use the menu.
//! - **Quit** asks the same question the window's close button asks, and goes
//!   through the same door — see [`crate::quit`]. There is one way out of this
//!   app, and it is the one that stops the tunnel first.
//!
//! # What the tray does not do
//!
//! It does not start or stop the tunnel. The tray is a way to reach the window,
//! and the window is where the tunnel is controlled. A tray menu with a
//! "connect" item would be a second control surface for the same state, and
//! two of those drift apart.
//!
//! # Labels
//!
//! The menu is written in the user's language, which the renderer knows and
//! this side does not: the labels arrive through [`set_labels`] once the locale
//! has been resolved. Until then they are English, which is the same fallback
//! the rest of the app uses for a string it has not been given yet.

use tauri::image::Image;
use tauri::menu::{Menu, MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};

/// The id the tray icon is filed under.
///
/// Tauri files trays by id, so this is what `tray_by_id` looks the icon up
/// with when the labels have to be rewritten.
pub const TRAY_ID: &str = "nexa-tray";

/// The menu item that brings the window back.
const SHOW_ITEM_ID: &str = "nexa-tray-show";

/// The menu item that quits.
const QUIT_ITEM_ID: &str = "nexa-tray-quit";

/// The icon, compiled in.
///
/// `include_bytes!` rather than a path: the installed app's icons live inside a
/// bundle whose layout is not the source tree's, and a tray icon that cannot be
/// found is a tray icon that is not there. It is also the transparent swirl
/// rather than the app icon, which has an opaque background and would show as
/// a filled square in a menu bar.
const ICON: &[u8] = include_bytes!("../icons/Square44x44Logo.png");

/// The tooltip shown when the pointer rests on the icon.
///
/// The product's name, which is not a word that gets translated.
const TOOLTIP: &str = "Nexa";

/// Puts the tray icon in place.
///
/// Best effort on purpose: a machine whose desktop has no tray (a bare
/// session, a container) must still be able to run the app, and the only
/// thing lost there is the icon. Failing the whole start-up over it would be a
/// worse trade than a missing affordance.
pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let menu = build_menu(app, "Open", "Quit")?;
    let icon = Image::from_bytes(ICON)?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip(TOOLTIP)
        .menu(&menu)
        // The menu opens on a right-click, which is the platform's own
        // convention; a left-click is the app's front door.
        //
        // Linux is the exception: the icon there is an appindicator, and that
        // backend delivers no click event at all and ignores the
        // menu-on-left-click setting. So the menu is the way back into the app
        // on Linux, and the click below is what the other platforms get.
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            SHOW_ITEM_ID => show_window(app),
            QUIT_ITEM_ID => ask_to_quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

/// Rewrites the menu in the user's language.
///
/// Called by the renderer once it has resolved the locale, which is the only
/// place the translations live. A tray that never gets this call keeps the
/// English labels it was built with, which is a fallback rather than a
/// failure.
pub fn set_labels(app: &AppHandle, show_label: &str, quit_label: &str) -> tauri::Result<()> {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return Ok(());
    };
    let menu = build_menu(app, show_label, quit_label)?;
    tray.set_menu(Some(menu))?;
    Ok(())
}

/// The menu itself.
///
/// Rebuilt rather than patched: a menu's items are what it is, and swapping one
/// for another is a rebuild in every platform's implementation anyway.
fn build_menu(app: &AppHandle, show_label: &str, quit_label: &str) -> tauri::Result<Menu<Wry>> {
    let show = MenuItemBuilder::with_id(SHOW_ITEM_ID, show_label).build(app)?;
    let quit = MenuItemBuilder::with_id(QUIT_ITEM_ID, quit_label).build(app)?;
    MenuBuilder::new(app).item(&show).item(&quit).build()
}

/// Brings the window back.
///
/// Focused as well as shown: a window that appears behind whatever the user
/// was looking at is a window they will not notice.
pub(crate) fn show_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        tracing::warn!("the tray was asked to show the window, and there is none");
        return;
    };
    if let Err(e) = window.show() {
        tracing::warn!("the tray could not show the window: {e}");
        return;
    }
    if let Err(e) = window.unminimize() {
        tracing::warn!("the tray could not unminimize the window: {e}");
    }
    if let Err(e) = window.set_focus() {
        tracing::warn!("the tray could not focus the window: {e}");
    }
}

/// Asks whether the app may quit.
///
/// The question itself belongs to the renderer, which is where the tunnel's
/// state is known — see [`crate::quit`]. This side only carries the question
/// over, exactly as the macOS menu item does.
fn ask_to_quit(app: &AppHandle) {
    crate::quit::ask(app);
}

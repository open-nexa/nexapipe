// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Installing or removing the service re-launches *this* binary through the platform
    // elevation prompt (UAC / polkit / sudo), so the service-management verbs have to be consumed
    // before Tauri would open a window — otherwise the elevated copy just shows the UI and the
    // operation never runs. See `service::cli`.
    // `args_os` rather than `args`: the latter panics on a non-UTF-8 argument, and a launcher we
    // do not control decides what lands here.
    let mut args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if nexa_lib::service::cli::handle_args(&mut args) {
        return;
    }

    nexa_lib::run()
}

pub mod cli;
pub mod elevate;
pub mod ipc;
pub mod ipc_client;
pub mod ipc_token;
pub mod platform;
pub mod runner;

#[cfg(windows)]
pub mod windows_service;

pub use ipc_client::IpcClient;
pub use platform::is_service_running;

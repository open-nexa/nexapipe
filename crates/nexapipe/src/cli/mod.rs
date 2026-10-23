//! The credential half of the command line.
//!
//! Three things live here: the 2FA enrollment (`--generate-2fa`,
//! `--show-2fa`), the invite (`--generate-invite`), and the `client`
//! subcommand (`list`, `add`, `revoke`). All three read and write the same
//! config file the server reads, and all three take the same lock the server
//! takes — a `revoke` has to work while a server is running.
//!
//! They were in `main.rs`, next to the server's own startup, and they are a
//! separate thing: they never start a proxy, they never load the routing
//! table, and they have their own failure to report.

// The module is three commands and five pieces: the 2FA enrollment, the
// `client` subcommand, the endpoint invite, the QR code two of them print,
// and the config file all of them work on.
mod client;
mod config;
mod enrollment;
mod invite;
mod qr;

#[cfg(test)]
mod tests;

pub(crate) use client::{add_client, list_clients, revoke_client};
pub(crate) use enrollment::print_2fa_enrollment;
pub(crate) use invite::print_endpoint_invite;

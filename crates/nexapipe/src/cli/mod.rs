//! The command line: the groups an operator asks for, and the credentials
//! behind them.
//!
//! The commands live in [`commands`], which folds every spelling — the
//! command, or the flag it replaced — into the flat fields the implementations
//! read. What lives here is the work: the 2FA enrollment (`client enroll`,
//! `client qr`), the endpoint invite (`invite`), the device invitation
//! (`device invite`), the `client` subcommand, the QR code four of them draw,
//! and the configuration all of them work on.
//!
//! They never start a proxy, they never load the routing table, and they have
//! their own failure to report.

mod client;
mod commands;
mod config;
mod device;
mod enrollment;
mod invite;
mod qr;

#[cfg(test)]
mod tests;

pub(crate) use client::{add_client, list_clients, revoke_client};
pub(crate) use commands::{Clients, Commands, Request, fold};
pub(crate) use config::{print_config, print_config_path};
pub(crate) use device::invite_device;
pub(crate) use enrollment::print_2fa_enrollment;
pub(crate) use invite::print_endpoint_invite;
pub(crate) use qr::print_qr;

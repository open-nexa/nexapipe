//! Console children of this GUI process.
//!
//! A console-subsystem program started by a process that has no console gets a
//! new one, and Windows paints its window a frame later. This app is a GUI
//! process, so every `reg`, `sc`, `powershell`, `netsh`, `ipconfig` or `net` it
//! runs flashes a black window on screen — even though their output is read
//! through pipes and none of them is meant to be seen.
//!
//! `CREATE_NO_WINDOW` asks for the console without the window. Every console
//! tool this GUI runs for itself goes through [`hidden`]; a bare `Command::new`
//! in one of those paths is the bug this module exists to prevent.

use std::ffi::OsStr;
use std::os::windows::process::CommandExt;
use std::process::Command;

/// The child still gets a console — its standard handles need one — but the
/// window is never shown.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A `Command` for `program` that starts without a console window.
pub(crate) fn hidden(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

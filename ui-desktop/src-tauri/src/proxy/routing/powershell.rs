//! The PowerShell calls the Windows half makes: the scripts it runs and the environment
//! they read their inputs from.

// ==========================================================================
// Windows PowerShell
//
// The interface name and the address are handed to PowerShell through the
// environment and read back as `$env:<NAME>`. They used to be written into the
// script inside single quotes, which made a quote in the name the end of the
// string: everything after it was PowerShell source, and this runs in the
// service, as LocalSystem.
//
// The environment is the channel that keeps the value out of the script.
// `powershell.exe -Command "<script>" <value>` does not pass `<value>` as an
// argument: the documented behaviour is that "all arguments following it are
// interpreted as part of the command to execute", so a value handed over that
// way is source again — and `$args` would not hold it either. `-File` does pass
// its arguments literally, but it needs a script file on disk.
//
// The module is not gated on Windows alone so that the shape of the call can be
// asserted on any host: the scripts and the environment they read are the part
// that has to hold.
// ==========================================================================

/// The variable the scripts read the interface name from.
pub(super) const INTERFACE_VAR: &str = "NEXA_TUN_INTERFACE";
/// The variable the scripts read the TUN's IPv6 address from.
pub(super) const ADDRESS_VAR: &str = "NEXA_TUN_ADDRESS";

/// A PowerShell call: the script to run, and the environment it reads its
/// inputs from.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Call {
    /// The script. It never holds the interface name or the address.
    pub script: String,
    /// The variables the script reads its inputs from.
    pub env: Vec<(&'static str, String)>,
}

impl Call {
    /// A call that runs `script` with the interface name and the address in
    /// its environment.
    pub(super) fn new(script: String, interface: &str, addr: &str) -> Self {
        Self {
            script,
            env: vec![
                (INTERFACE_VAR, interface.to_string()),
                (ADDRESS_VAR, addr.to_string()),
            ],
        }
    }
}

/// Whether the interface already holds the address.
pub(super) fn has_ipv6_script() -> String {
    format!(
        "(Get-NetIPAddress -InterfaceAlias $env:{INTERFACE_VAR} -AddressFamily IPv6 \
             -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq $env:{ADDRESS_VAR} }} \
             | Measure-Object).Count -gt 0"
    )
}

/// Assigns the address to the interface.
pub(super) fn set_ipv6_script() -> String {
    use crate::proxy::tun_proxy::TUN_V6_PREFIX_LEN;

    format!(
        "New-NetIPAddress -InterfaceAlias $env:{INTERFACE_VAR} -IPAddress $env:{ADDRESS_VAR} \
             -PrefixLength {TUN_V6_PREFIX_LEN} -ErrorAction Stop"
    )
}

/// Removes the address from the interface.
pub(super) fn remove_ipv6_script() -> String {
    format!(
        "Get-NetIPAddress -InterfaceAlias $env:{INTERFACE_VAR} -AddressFamily IPv6 \
             -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq $env:{ADDRESS_VAR} }} | \
             Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue"
    )
}

/// Runs the call, with the interface name and the address in the child's
/// environment.
#[cfg(windows)]
pub(super) fn run(call: &Call) -> std::io::Result<std::process::Output> {
    let mut command = crate::win::hidden("powershell");
    for (name, value) in &call.env {
        command.env(name, value);
    }
    command.args(["-NoProfile", "-NonInteractive", "-Command", &call.script]);
    command.output()
}

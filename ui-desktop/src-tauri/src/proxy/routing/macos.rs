//! The macOS half of the TUN interface and route management: `ifconfig` and `route` for the
//! address and the route, and the parsers of what the machine says about them.

//! The parsers of what `ifconfig` and `netstat` say are compiled under `test` on every
//! platform, because the macOS code cannot be built or run on the machine the tests run on,
//! and a parser for the output this code relies on is not something to ship unexercised.

#[allow(unused_imports)]
use super::*;

/// `ifconfig <if> inet6 <addr> prefixlen 64` plus the /64 route — an utun
/// interface gets no connected route for an address it was only just given.
#[cfg(target_os = "macos")]
pub(super) fn configure_ipv6_macos(interface: &str) -> bool {
    use crate::proxy::tun_proxy::{tun_v6_ip, TUN_V6_BASE, TUN_V6_PREFIX_LEN};

    let prefix = TUN_V6_PREFIX_LEN.to_string();
    let out = Command::new("ifconfig")
        .args([
            interface,
            "inet6",
            &tun_v6_ip().to_string(),
            "prefixlen",
            &prefix,
        ])
        .output();
    match out {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::warn!(
                "ifconfig could not set {} on {}: {}",
                tun_v6_ip(),
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Err(e) => {
            tracing::warn!("could not run ifconfig for {}: {}", interface, e);
            return false;
        }
    }

    // "File exists" is the route already being there, which is what we asked
    // for — every command here is meant to be idempotent.
    let out = Command::new("route")
        .args([
            "-n",
            "add",
            "-inet6",
            "-net",
            &TUN_V6_BASE.to_string(),
            "-prefixlen",
            &prefix,
            "-interface",
            interface,
        ])
        .output();
    match out {
        Ok(out)
            if out.status.success()
                || String::from_utf8_lossy(&out.stderr).contains("File exists") =>
        {
            true
        }
        Ok(out) => {
            tracing::warn!(
                "route could not add {} via {}: {}",
                TUN_V6_BASE,
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("could not run route for {}: {}", interface, e);
            false
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn remove_ipv6_macos(interface: &str) -> Result<()> {
    use crate::proxy::tun_proxy::{tun_v6_ip, TUN_V6_BASE, TUN_V6_PREFIX_LEN};

    let prefix = TUN_V6_PREFIX_LEN.to_string();
    let _ = Command::new("route")
        .args([
            "-n",
            "delete",
            "-inet6",
            "-net",
            &TUN_V6_BASE.to_string(),
            "-prefixlen",
            &prefix,
            "-interface",
            interface,
        ])
        .output();
    // `delete` (without `alias`) removes the address configured above; the
    // interface and its IPv4 half are untouched.
    let _ = Command::new("ifconfig")
        .args([interface, "inet6", &tun_v6_ip().to_string(), "delete"])
        .output();
    Ok(())
}

/// IPv4 addresses held by interfaces other than `skip`.
///
/// An enumeration failure yields an empty list — the bindability probe still guards the basic
/// "can this address exist here" question; this check only adds the "is it already spoken for"
/// one on top.
#[cfg(target_os = "macos")]
pub(super) fn foreign_interface_addresses(skip: &str) -> Vec<Ipv4Addr> {
    match Command::new("ifconfig").arg("-a").output() {
        Ok(output) => parse_ifconfig_addresses(&String::from_utf8_lossy(&output.stdout), skip),
        Err(_) => Vec::new(),
    }
}

/// `ifconfig -a` address lines: an unindented line names the interface, a tab-indented
/// `inet <addr> ...` line under it carries one of its addresses (`inet6` lines are excluded by
/// the trailing space in the prefix).
#[cfg(target_os = "macos")]
pub(super) fn parse_ifconfig_addresses(text: &str, skip: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut current = "";
    for line in text.lines() {
        if line.starts_with('\t') || line.starts_with(' ') {
            if let Some(addr) = line
                .trim_start()
                .strip_prefix("inet ")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|a| a.parse().ok())
            {
                if current != skip {
                    out.push(addr);
                }
            }
        } else if let Some(name) = line.split(':').next() {
            current = name.trim();
        }
    }
    out
}

/// IPv4 route prefixes installed on interfaces other than `skip`, as `(network, prefix_len)`.
///
/// An enumeration failure yields an empty list, which leaves the address check as the only
/// guard — the same trade-off [`foreign_interface_addresses`] makes.
#[cfg(target_os = "macos")]
pub(super) fn foreign_route_prefixes(skip: &str) -> Vec<(Ipv4Addr, u8)> {
    match Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
        Ok(output) => parse_netstat_routes(&String::from_utf8_lossy(&output.stdout), skip),
        Err(_) => Vec::new(),
    }
}

/// `netstat -rn -f inet` route lines: `Destination Gateway Flags Netif [Expire]`.
///
/// The destination is printed shortened — `10/24`, `198.18.0`, `169.254` — with the prefix
/// length implied by how many bytes are written when no `/len` follows. Two kinds of line are
/// dropped: anything flagged `L`, which is an ARP cache entry rather than a route, and the
/// default route — spelled `default`, which parses as nothing at all, but also `0/0` on a table
/// that prints it numerically, which parses into a route covering every block there is.
#[cfg(any(target_os = "macos", test))]
pub(super) fn parse_netstat_routes(text: &str, skip: &str) -> Vec<(Ipv4Addr, u8)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Destination, Gateway, Flags, Netif — the header row falls out here, its
        // destination column being the word "Destination".
        let (Some(dest), Some(netif)) = (tokens.first().copied(), tokens.get(3).copied()) else {
            continue;
        };
        if netif == skip {
            continue;
        }
        if tokens.get(2).is_some_and(|flags| flags.contains('L')) {
            continue;
        }
        if let Some(prefix) = parse_shortened_prefix(dest).filter(|(_, len)| *len > 0) {
            out.push(prefix);
        }
    }
    out
}

/// `10/24`, `198.18.0`, `169.254`, `127`, `224.0.0/4` — the destination column of `netstat -rn`,
/// where the prefix length is explicit after a slash and otherwise the number of bytes written:
/// one byte is a /8, two a /16, three a /24, four a host route.
#[cfg(any(target_os = "macos", test))]
fn parse_shortened_prefix(field: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, explicit_len) = match field.split_once('/') {
        Some((addr, len)) => (addr, Some(len.parse::<u8>().ok()?)),
        None => (field, None),
    };
    let mut octets = [0u8; 4];
    let mut written = 0u8;
    for (i, part) in addr.split('.').enumerate() {
        if i > 3 {
            return None;
        }
        octets[i] = part.parse().ok()?;
        written += 1;
    }
    if written == 0 {
        return None;
    }
    let len = explicit_len.unwrap_or(written * 8);
    (len <= 32).then_some((Ipv4Addr::from(octets), len))
}

#[cfg(target_os = "macos")]
pub(super) fn assign_interface_address(interface: &str, ip: &Ipv4Addr) -> Result<()> {
    // ifconfig utunX inet <ip> <netmask> — running it again replaces the existing address
    // (idempotent). utun interfaces are point-to-point by nature; the explicit /24 route in
    // `add_routes` is what makes the whole block reachable, so this only has to make the
    // address exist and be bindable.
    let output = Command::new("ifconfig")
        .args([interface, "inet", &ip.to_string(), TUN_NETMASK])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ifconfig: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ifconfig inet failed: {}", stderr.trim());
    }

    let output = Command::new("ifconfig")
        .args([interface, "up"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ifconfig up: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ifconfig up failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn remove_interface_address(interface: &str, ip: &Ipv4Addr) {
    let _ = Command::new("ifconfig")
        .args([interface, "inet", &ip.to_string(), "remove"])
        .output();
}

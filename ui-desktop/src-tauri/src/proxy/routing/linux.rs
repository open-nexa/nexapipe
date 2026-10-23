//! The Linux half of the TUN interface and route management: `ip` for the address and the
//! route, and the parsers of what `ip` says.

//! The parsers of what `ip` says are compiled under `test` on every platform, because the
//! Linux code cannot be built or run on the machine the tests run on, and a parser for the
//! output this code relies on is not something to ship unexercised.

#[allow(unused_imports)]
use super::*;

/// `ip -6 addr replace` + `ip -6 route replace`; the kernel adds the connected
/// route itself, and the explicit replace covers the cases where it does not.
#[cfg(target_os = "linux")]
pub(super) fn configure_ipv6_linux(interface: &str) -> bool {
    use crate::proxy::tun_proxy::{tun_v6_ip, tun_v6_network, TUN_V6_PREFIX_LEN};

    let addr = format!("{}/{}", tun_v6_ip(), TUN_V6_PREFIX_LEN);
    let out = Command::new("ip")
        .args(["-6", "addr", "replace", &addr, "dev", interface])
        .output();
    match out {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::warn!(
                "ip could not set {} on {}: {}",
                addr,
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Err(e) => {
            tracing::warn!("could not run ip for {}: {}", interface, e);
            return false;
        }
    }

    let network = tun_v6_network();
    let out = Command::new("ip")
        .args(["-6", "route", "replace", &network, "dev", interface])
        .output();
    match out {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::warn!(
                "ip could not route {} via {}: {}",
                network,
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("could not run ip route for {}: {}", interface, e);
            false
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn remove_ipv6_linux(interface: &str) -> Result<()> {
    use crate::proxy::tun_proxy::{tun_v6_ip, TUN_V6_PREFIX_LEN};

    let _ = Command::new("ip")
        .args([
            "-6",
            "addr",
            "del",
            &format!("{}/{}", tun_v6_ip(), TUN_V6_PREFIX_LEN),
            "dev",
            interface,
        ])
        .output();
    Ok(())
}

/// IPv4 addresses held by interfaces other than `skip`. See the macOS twin for the rationale.
#[cfg(target_os = "linux")]
pub(super) fn foreign_interface_addresses(skip: &str) -> Vec<Ipv4Addr> {
    match Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
    {
        Ok(output) => parse_ip_addr_addresses(&String::from_utf8_lossy(&output.stdout), skip),
        Err(_) => Vec::new(),
    }
}

/// `ip -o -4 addr show` lines: `<idx>: <ifname>[@<peer>] inet <addr>/<prefix> ...`.
///
/// Two shapes have to be accepted. Modern iproute2 with `-o` puts the interface name and the
/// address on one line; older builds keep the trailing colon after the name, and plain
/// `ip addr show` splits them into an unindented `<idx>: <ifname>: <flags>` header plus indented
/// `inet ...` lines below it. Parsing only the first shape silently returned an empty list on
/// the other two, which made the candidate-block conflict check a no-op.
#[cfg(target_os = "linux")]
pub(super) fn parse_ip_addr_addresses(text: &str, skip: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    // Interface the indented lines below belong to (multi-line output only).
    let mut current: Option<&str> = None;
    for line in text.lines() {
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if !indented {
            current = interface_field_name(tokens.get(1).copied());
        }
        // `inet` matched exactly, so `inet6` lines never land here.
        let Some(pos) = tokens.iter().position(|t| *t == "inet") else {
            continue;
        };
        let Some(addr) = tokens
            .get(pos + 1)
            .and_then(|a| a.split('/').next())
            .and_then(|a| a.parse().ok())
        else {
            continue;
        };
        let owner = if indented {
            current
        } else {
            interface_field_name(tokens.get(1).copied())
        };
        if owner != Some(skip) {
            out.push(addr);
        }
    }
    out
}

/// `<ifname>[@<peer>][:]` — the peer suffix and the colon some iproute2 versions print.
#[cfg(target_os = "linux")]
fn interface_field_name(token: Option<&str>) -> Option<&str> {
    token.map(|n| n.split('@').next().unwrap_or(n).trim_end_matches(':'))
}

/// IPv4 route prefixes installed on interfaces other than `skip`. See the macOS twin.
///
/// `table all` and not the default main table: a route in any other table claims its prefix
/// just as loudly while a lookup reaches it through an `ip rule`, which is how a tunnel that
/// wants to sit in front of the default route installs itself. What that adds — the host and
/// broadcast addresses of the local table — is dropped by the parser, not by luck.
#[cfg(target_os = "linux")]
pub(super) fn foreign_route_prefixes(skip: &str) -> Vec<(Ipv4Addr, u8)> {
    match Command::new("ip")
        .args(["-4", "route", "show", "table", "all"])
        .output()
    {
        Ok(output) => parse_ip_route_prefixes(&String::from_utf8_lossy(&output.stdout), skip),
        Err(_) => Vec::new(),
    }
}

/// The route types `ip` prints ahead of the destination — the ones that stand for a prefix
/// rather than for an address of this host. Each of them keeps the packets its prefix names,
/// which is what makes it a claim on a block.
#[cfg(any(target_os = "linux", test))]
const IP_ROUTE_TYPES: [&str; 5] = ["blackhole", "unreachable", "prohibit", "throw", "nat"];

/// `ip -4 route show` lines: `[<type>] <prefix> [via <gw>] dev <ifname> ...`.
///
/// The default route is dropped for the same reason as on macOS: every host has one, and
/// counting it would disqualify every block. It is spelled `default` here, or `0.0.0.0/0` on a
/// table that prints it numerically; the first parses as nothing, the second is filtered by its
/// prefix length. A route with no `dev` — a blackhole, for instance — belongs to nobody, which
/// still leaves the prefix spoken for, so its type is read past rather than read as the
/// destination.
#[cfg(any(target_os = "linux", test))]
pub(super) fn parse_ip_route_prefixes(text: &str, skip: &str) -> Vec<(Ipv4Addr, u8)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.windows(2).any(|pair| pair == ["dev", skip]) {
            continue;
        }
        // `ip` prints the type of a route that has one ahead of its prefix, and
        // those are exactly the routes with no interface to exclude: a blackhole
        // swallows the block it names as surely as a device does.
        let dest = match tokens.split_first() {
            Some((first, rest)) if IP_ROUTE_TYPES.contains(first) => match rest.first().copied() {
                Some(next) => next,
                None => continue,
            },
            Some((first, _)) => *first,
            None => continue,
        };
        let prefix = match dest.split_once('/') {
            Some((addr, len)) => len
                .parse::<u8>()
                .ok()
                .zip(addr.parse().ok())
                .map(|(len, addr)| (addr, len)),
            None => dest.parse::<Ipv4Addr>().ok().map(|addr| (addr, 32)),
        };
        if let Some(prefix) = prefix.filter(|(_, len)| *len > 0 && *len <= 32) {
            out.push(prefix);
        }
    }
    out
}

#[cfg(target_os = "linux")]
pub(super) fn assign_interface_address(interface: &str, ip: &Ipv4Addr) -> Result<()> {
    // `ip addr replace` is idempotent — setting the same address twice does not fail
    let cidr = format!("{ip}/24");
    let output = Command::new("ip")
        .args(["addr", "replace", &cidr, "dev", interface])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ip addr: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip addr replace failed: {}", stderr.trim());
    }

    let output = Command::new("ip")
        .args(["link", "set", "dev", interface, "up"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ip link: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip link set up failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn remove_interface_address(interface: &str, ip: &Ipv4Addr) {
    let cidr = format!("{ip}/24");
    let _ = Command::new("ip")
        .args(["addr", "del", &cidr, "dev", interface])
        .output();
}

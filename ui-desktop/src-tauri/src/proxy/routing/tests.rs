use std::net::Ipv4Addr;

/// The conflict the candidate-block check exists for: a fake-IP VPN (Clash/mihomo) holds
/// 198.18.0.1/30 on its utun while our default candidate block is 198.18.0.0/24.
#[cfg(target_os = "macos")]
#[test]
fn a_foreign_address_inside_a_candidate_block_is_collected() {
    let text = "\
lo0: flags=8049<LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.0.0.83 netmask 0xffffff00 broadcast 10.0.0.255
\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4
utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000
\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
\tinet6 fe80::c62:9049:5746:8c61%utun8 prefixlen 64 scopeid 0x17
nexa-tun: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet 198.18.0.254 netmask 0xffffff00
";
    let foreign = super::parse_ifconfig_addresses(text, "nexa-tun");
    assert!(foreign.contains(&"198.18.0.1".parse().unwrap()));
    assert!(foreign.contains(&"10.0.0.83".parse().unwrap()));
    // Our own interface is excluded, and inet6 lines are not addresses here.
    assert!(!foreign.contains(&"198.18.0.254".parse().unwrap()));
}

#[cfg(target_os = "linux")]
#[test]
fn a_foreign_address_inside_a_candidate_block_is_collected() {
    // `ip -o -4 addr show`: the interface and its address share one line, and the record is
    // continued with a trailing backslash.
    let oneline = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: enp3s0    inet 10.0.0.83/24 brd 10.0.0.255 scope global enp3s0\\       valid_lft forever preferred_lft forever
9: tun0    inet 198.18.0.1/30 scope global tun0\\       valid_lft forever preferred_lft forever
10: nexa-tun    inet 198.18.0.254/24 scope global nexa-tun\\       valid_lft forever preferred_lft forever
";
    // Plain `ip addr show`, plus the trailing colon older iproute2 keeps even under `-o`:
    // an unindented header names the interface, indented lines carry the addresses.
    let multiline = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
inet 127.0.0.1/8 scope host lo
2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
inet 10.0.0.83/24 brd 10.0.0.255 scope global enp3s0
9: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 9000
inet 198.18.0.1/30 scope global tun0
10: nexa-tun: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1400
inet 198.18.0.254/24 scope global nexa-tun
";
    for text in [oneline, multiline] {
        let foreign = super::parse_ip_addr_addresses(text, "nexa-tun");
        assert!(
            foreign.contains(&"198.18.0.1".parse().unwrap()),
            "the conflicting foreign address was not collected: {foreign:?}"
        );
        assert!(
            foreign.contains(&"10.0.0.83".parse().unwrap()),
            "an unrelated LAN address was not collected: {foreign:?}"
        );
        assert!(
            !foreign.contains(&"198.18.0.254".parse().unwrap()),
            "our own interface must be excluded: {foreign:?}"
        );
    }
}

/// The hole the route check closes: a fake-IP tool holds 198.18.0.1/30 on its own utun and
/// routes 198.18/16 at it, so no interface holds an address in the /24 we would take.
#[test]
fn a_foreign_route_covering_a_candidate_block_is_collected_macos() {
    // `netstat -rn -f inet` as it actually prints: shortened destinations, ARP entries
    // flagged `L`, and our own interface's route sitting among them.
    let text = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.0.0.1           UGScg                 en0
0/0                10.0.0.1           UGSc                  en0
10/24              link#12            UCS                   en0      !
10.0.0.99          8c:d0:b2:19:a8:b2  UHLWI                 en0   1157
127                127.0.0.1          UCS                   lo0
169.254            link#12            UCS                   en0      !
198.18/16          utun8              USc                 utun8
198.18.0           utun8              USc               nexa-tun
224.0.0/4          link#12            UmCS                  en0      !
";
    let routes = super::parse_netstat_routes(text, "nexa-tun");
    assert!(
        routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 16)),
        "the fake-IP route was not collected: {routes:?}"
    );
    // The prefix length is read off the bytes written when no `/len` follows.
    assert!(
        routes.contains(&(Ipv4Addr::new(169, 254, 0, 0), 16)),
        "a shortened destination lost its implied prefix: {routes:?}"
    );
    assert!(routes.contains(&(Ipv4Addr::new(10, 0, 0, 0), 24)));
    // Our own interface is skipped, the ARP entry is a neighbour rather than a destination,
    // and the default route is not a claim on any block.
    assert!(
        !routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 24)),
        "our own route must be excluded: {routes:?}"
    );
    assert!(
        !routes.contains(&(Ipv4Addr::new(10, 0, 0, 99), 32)),
        "an ARP entry is not a route: {routes:?}"
    );
    assert!(
        !routes.iter().any(|(_, len)| *len == 0),
        "the default route must not be collected: {routes:?}"
    );
}

/// Linux twin of the above: `ip -4 route show` names the prefix in full and the interface
/// after `dev`.
#[test]
fn a_foreign_route_covering_a_candidate_block_is_collected_linux() {
    let text = "\
default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.83 metric 100
0.0.0.0/0 via 10.0.0.1 dev eth0 proto dhcp
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.83 metric 100
10.0.0.99 dev eth0 scope link
198.18.0.0/16 dev tun0 proto kernel scope link src 198.18.0.1
198.18.0.0/24 dev nexa-tun proto kernel scope link src 198.18.0.254
";
    let routes = super::parse_ip_route_prefixes(text, "nexa-tun");
    assert!(
        routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 16)),
        "the fake-IP route was not collected: {routes:?}"
    );
    assert!(routes.contains(&(Ipv4Addr::new(10, 0, 0, 0), 24)));
    // A bare address is a host route, not a /24.
    assert!(
        routes.contains(&(Ipv4Addr::new(10, 0, 0, 99), 32)),
        "a host route lost its /32: {routes:?}"
    );
    assert!(
        !routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 24)),
        "our own route must be excluded: {routes:?}"
    );
    assert!(
        !routes.iter().any(|(_, len)| *len == 0),
        "the default route must not be collected: {routes:?}"
    );
}

/// The two ways a route used to hide: one installed in a table other than
/// main, reached through an `ip rule`, and one whose type `ip` prints ahead
/// of its prefix. Both claim the block they name — a blackhole more loudly
/// than most — and neither carries a `dev` to be excluded by.
#[test]
fn a_route_from_another_table_or_of_another_type_still_claims() {
    let text = "\
default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.83 metric 100
blackhole 100.100.0.0/24
unreachable 198.18.0.0/16
172.26.0.0/16 dev wg0 table 51820 proto static scope link
local 10.0.0.83 dev eth0 table local proto kernel scope host src 10.0.0.83
broadcast 10.0.0.255 dev eth0 table local proto kernel scope link src 10.0.0.83
198.18.0.0/24 dev nexa-tun proto kernel scope link src 198.18.0.254
";
    let routes = super::parse_ip_route_prefixes(text, "nexa-tun");
    assert!(
        routes.contains(&(Ipv4Addr::new(100, 100, 0, 0), 24)),
        "a blackhole route was not collected: {routes:?}"
    );
    assert!(
        routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 16)),
        "an unreachable route was not collected: {routes:?}"
    );
    assert!(
        routes.contains(&(Ipv4Addr::new(172, 26, 0, 0), 16)),
        "a route from another table was not collected: {routes:?}"
    );
    assert!(
        !routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 24)),
        "our own route must be excluded: {routes:?}"
    );
    // What `table all` adds and this does not want: the host and broadcast
    // addresses of the local table, which name no block.
    assert!(
        !routes.contains(&(Ipv4Addr::new(10, 0, 0, 83), 32)),
        "a local address is not a route: {routes:?}"
    );
    assert!(
        !routes.contains(&(Ipv4Addr::new(10, 0, 0, 255), 32)),
        "a broadcast address is not a route: {routes:?}"
    );
}

/// A /16 somebody else routes swallows the whole candidate /24.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_route_wider_than_the_block_claims_it() {
    let routes = [(Ipv4Addr::new(198, 18, 0, 0), 16)];
    assert_eq!(
        super::route_claiming_block(&routes, Ipv4Addr::new(198, 18, 0, 0)),
        Some((Ipv4Addr::new(198, 18, 0, 0), 16))
    );
    assert_eq!(
        super::route_claiming_block(&routes, Ipv4Addr::new(100, 100, 0, 0)),
        None
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_host_route_inside_the_block_claims_it_too() {
    let routes = [(Ipv4Addr::new(100, 100, 0, 7), 32)];
    assert_eq!(
        super::route_claiming_block(&routes, Ipv4Addr::new(100, 100, 0, 0)),
        Some((Ipv4Addr::new(100, 100, 0, 7), 32))
    );
}

/// `0.0.0.0/1` + `128.0.0.0/1` is how a VPN takes every destination without overwriting the
/// default route. Our /24 is more specific than either, so no block is unusable for it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn taking_every_destination_is_not_a_claim_on_any_block() {
    let routes = [
        (Ipv4Addr::new(0, 0, 0, 0), 1),
        (Ipv4Addr::new(128, 0, 0, 0), 1),
    ];
    for base in super::TUN_BASE_CANDIDATES {
        assert_eq!(
            super::route_claiming_block(&routes, base),
            None,
            "{base}/24 was claimed by a route that owns every destination"
        );
    }
}

/// The interface name used to be written into a PowerShell script inside single
/// quotes, in the service, which runs as LocalSystem: a quote in the name ended the
/// string and everything after it was PowerShell source. The name now travels in the
/// environment instead, so it is data — and no name can change what the script says.
#[test]
fn the_interface_name_is_data_and_never_source() {
    use super::powershell;

    // Everything a PowerShell string could be talked into: the closing quote, a
    // subexpression, a statement separator, an escape character and a newline.
    let hostile = "ne'; Write-Output $(whoami); `n #\r\nne";

    for script in [
        powershell::has_ipv6_script(),
        powershell::set_ipv6_script(),
        powershell::remove_ipv6_script(),
    ] {
        let call = powershell::Call::new(script, hostile, "fd00:198:18::fe");

        // The script reads its inputs from the environment…
        assert!(
            call.script
                .contains(&format!("$env:{}", powershell::INTERFACE_VAR)),
            "the script does not read the interface name: {}",
            call.script
        );
        assert!(
            call.script
                .contains(&format!("$env:{}", powershell::ADDRESS_VAR)),
            "the script does not read the address: {}",
            call.script
        );

        // …and holds neither of them.
        assert!(
            !call.script.contains(hostile) && !call.script.contains("whoami"),
            "the script carries the name: {}",
            call.script
        );
        assert!(
            !call.script.contains("fd00:198:18::fe"),
            "the script carries the address: {}",
            call.script
        );

        // The name travels beside the script, unchanged: what PowerShell reads is
        // the name itself, not a spelling of it.
        assert_eq!(
            call.env
                .iter()
                .find(|(name, _)| *name == powershell::INTERFACE_VAR)
                .map(|(_, value)| value.as_str()),
            Some(hostile)
        );
    }
}

/// The scripts have no quoted string left for a value to be spliced into: the
/// interface name and the address are read from the environment, and nothing else
/// is interpolated. A script with a literal in it is a script a name could break
/// out of.
#[test]
fn no_script_has_a_quoted_string_left_to_break_out_of() {
    use super::powershell;

    for script in [
        powershell::has_ipv6_script(),
        powershell::set_ipv6_script(),
        powershell::remove_ipv6_script(),
    ] {
        assert!(
            !script.contains('\''),
            "the script still quotes something: {script}"
        );
    }
}

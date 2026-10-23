//! The tests of the DNS configuration.
//!
//! They are in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it
//! is testing.

use super::{undo_failed_hijack, DnsHijack, DnsHijackFailure, DnsStrategy};

// The cleanup's decision, and the pieces it is built from. Compiled under
// `test` on every platform: the machine that has to answer the liveness
// question is not the one the tests run on.
#[cfg(any(windows, test))]
use super::{stale_adapter_indexes, AdapterDns, LOCALHOST_V6};

/// The three spellings there are, and nothing else.
///
/// A strategy that is not known must not be read as one of them: the
/// setting says what happens to the machine's name resolution, and "leave
/// it alone" and "replace all of it" are two very different machines.
#[test]
fn a_dns_strategy_is_read_from_its_spelling() {
    assert_eq!(DnsStrategy::parse("scoped").unwrap(), DnsStrategy::Scoped);
    assert_eq!(DnsStrategy::parse("global").unwrap(), DnsStrategy::Global);
    assert_eq!(DnsStrategy::parse("none").unwrap(), DnsStrategy::None);
    // Case and surrounding space are the reader's business, not the user's.
    assert_eq!(
        DnsStrategy::parse("  Scoped ").unwrap(),
        DnsStrategy::Scoped
    );
}

/// A spelling nobody knows is refused, and the message says what there is.
#[test]
fn an_unknown_dns_strategy_is_refused() {
    let error = DnsStrategy::parse("everything").expect_err("a typo is refused");
    let message = error.to_string();
    assert!(message.contains("everything"), "{message}");
    assert!(message.contains("scoped"), "{message}");
    assert!(message.contains("global"), "{message}");
    assert!(message.contains("none"), "{message}");
}

/// The default is the strategy that leaves the machine's own names alone.
#[test]
fn the_default_dns_strategy_is_scoped() {
    assert_eq!(DnsStrategy::default(), DnsStrategy::Scoped);
}

/// Each strategy spells itself back the way it is written.
#[test]
fn a_dns_strategy_spells_itself_back() {
    assert_eq!(DnsStrategy::Scoped.name(), "scoped");
    assert_eq!(DnsStrategy::Global.name(), "global");
    assert_eq!(DnsStrategy::None.name(), "none");
}

/// "None" means the machine's DNS was not touched, and there is nothing to
/// undo — which is what the restore path has to know.
///
/// Exercised on every platform, because the point of the strategy is that
/// it does not reach the platform at all: no scoped rules, no global
/// hijack, nothing to restore.
#[test]
fn the_none_strategy_installs_nothing() {
    let hijack = super::set_system_dns(
        "does-not-matter",
        "198.18.0.254",
        &["example.com".to_string()],
        DnsStrategy::None,
    )
    .expect("the none strategy cannot fail");
    assert_eq!(hijack, DnsHijack::None);
}

/// An empty domain list is not a failure: there is nothing to scope, so
/// nothing is installed and the machine's DNS stays where it was.
///
/// The scoped strategy is the default, and a proxy with no domain
/// configured is a proxy that resolves nothing — the tunnel still runs.
/// What it must not do is fail the run: the scoped attempt has nothing to
/// install, and a run that says "it could not be installed" is a run that
/// refuses a tunnel over a domain list that was empty to begin with.
#[test]
fn the_scoped_strategy_with_no_domains_installs_nothing() {
    let hijack = super::set_system_dns("does-not-matter", "198.18.0.254", &[], DnsStrategy::Scoped)
        .expect("an empty domain list is not a failure");
    assert_eq!(hijack, DnsHijack::None);
}

#[cfg(target_os = "macos")]
use super::{backup_is_spent, parse_getdnsservers, parse_network_services, NO_DNS_SERVERS};

// Compiled under `test` on every platform, like the resolv.conf readers: it
// is a pure parser for a command this machine cannot otherwise exercise, and
// the whole point of it is the case this machine cannot produce.
#[cfg(any(target_os = "macos", test))]
use super::parse_scutil_dns;

// The resolv.conf and resolvectl readers are pure, so they are compiled under
// `test` on every platform: the Linux code cannot be built or run here, and a
// parser for a file this code rewrites is not something to ship unexercised.
#[cfg(any(target_os = "linux", test))]
use super::{
    parse_resolvectl_competing_routes, parse_resolvectl_dns, parse_resolvectl_domains,
    resolv_conf_names_a_tun_address, resolv_conf_nameservers, resolv_conf_without_nameservers,
    routes_every_domain, DEFAULT_ROUTE_DOMAIN,
};

// The NRPT reader is pure, and the machine that has to read it back is not
// the one the tests run on: a rule that is in the table but does not name
// our resolver is the difference between a scoped hijack and a global one.
#[cfg(any(windows, test))]
use super::{
    nrpt_add_script, nrpt_effective_script, nrpt_namespaces, nrpt_namespaces_for,
    nrpt_remove_script, parse_nrpt_rules,
};

// The Windows cleanup reads the machine in two steps — what is on it, and
// what is still in use — and decides in the shared code. Both halves are
// pure, so they are compiled under `test` on every platform.
#[cfg(any(windows, test))]
use super::{
    cleanup_apply_script, cleanup_collect_script, parse_cleanup_state, stale_nrpt_rules,
    CleanupRule,
};

#[cfg(any(target_os = "macos", target_os = "linux", test))]
use super::restore::hijack_is_in_effect;
// Same for the per-domain resolver file: what this code writes has to be
// what it reads back, or a restore would leave its own files behind.
#[cfg(any(target_os = "macos", test))]
use super::{
    count_resolvers_in_effect, is_our_resolver_file, is_tun_dns_address, remove_resolver_files,
    resolver_file_contents, resolver_nameserver, scoped_install_is_complete, scoped_install_tally,
    write_resolver_files, RESOLVER_MARKER,
};
#[cfg(any(target_os = "macos", test))]
use crate::proxy::tun_proxy::TUN_BASE_CANDIDATES;
#[cfg(any(target_os = "macos", test))]
use std::net::Ipv4Addr;
#[cfg(any(target_os = "macos", test))]
use std::path::PathBuf;

/// A scratch directory for the resolver-file tests: the real one is
/// `/etc/resolver`, which a test may neither need nor be allowed to touch.
#[cfg(any(target_os = "macos", test))]
fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nexapipe-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory under the temp directory");
    dir
}

/// The legend `-listallnetworkservices` prints ahead of its list is not a service.
/// Handing it to `-setdnsservers` anyway is where every startup's worth of
/// "networksetup failed for An asterisk (*) ..." warnings came from.
#[cfg(target_os = "macos")]
#[test]
fn the_disabled_legend_is_not_a_network_service() {
    let output = "An asterisk (*) denotes that a network service is disabled.\n\
                      Thunderbolt Bridge\n\
                      *iPhone USB\n\
                      Wi-Fi\n";

    assert_eq!(
        parse_network_services(output),
        vec!["Thunderbolt Bridge".to_string(), "Wi-Fi".to_string()]
    );
}

/// `-getdnsservers` answers three ways and they mean three different things: a
/// list of servers, "none configured" — which is DHCP, and a real answer — and
/// a command that was refused. The last two must not be confused, because one
/// says "clear it" and the other says "do not touch it".
#[cfg(target_os = "macos")]
#[test]
fn getdnsservers_output_reads_as_a_list_or_as_dhcp_or_as_unknown() {
    assert_eq!(
        parse_getdnsservers("198.18.0.254\n"),
        Some(vec!["198.18.0.254".to_string()])
    );
    assert_eq!(
        parse_getdnsservers("8.8.8.8\n1.1.1.1\n"),
        Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()])
    );
    assert_eq!(
        parse_getdnsservers(&format!("{NO_DNS_SERVERS} Wi-Fi.\n")),
        Some(Vec::new())
    );
    assert_eq!(
        parse_getdnsservers("** Error: The parameters were not valid.\n"),
        None
    );
    assert_eq!(parse_getdnsservers("garbage\n"), None);
}

/// `scutil --dns` is read for one reason: on a machine that takes whatever
/// DHCP hands out, it is the only thing that names the router's DNS. A
/// resolver block the command prints without a nameserver — the mDNS one
/// always is — contributes nothing rather than poisoning the list.
#[cfg(any(target_os = "macos", test))]
#[test]
fn scutil_dns_reads_the_resolvers_in_effect_and_skips_the_ones_naming_none() {
    let output = "\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  if_index : 15 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  order    : 300000
";
    assert_eq!(
        parse_scutil_dns(output),
        vec!["192.168.1.1".to_string(), "8.8.8.8".to_string()]
    );
}

/// A resolver that answers for one name is not an upstream.
///
/// `scutil` prints a block for every `/etc/resolver/<domain>` on the
/// machine — what a VPN client, Docker or dnsmasq leaves there — and each
/// one carries a `domain :` line. Asking one of those a public name is not
/// a slow answer but a wrong one: a live resolver answers NXDOMAIN and the
/// chain takes the first reply it gets, and a dead one costs 1.5s.
#[cfg(any(target_os = "macos", test))]
#[test]
fn scutil_dns_leaves_out_the_resolvers_that_answer_for_one_domain() {
    let output = "\
DNS configuration

resolver #1
  nameserver[0] : 192.168.1.1

resolver #2
  domain   : corp.example
  nameserver[0] : 10.8.0.1
  flags    : Scoped

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
";
    assert_eq!(
        parse_scutil_dns(output),
        vec!["192.168.1.1".to_string()],
        "only the resolver that answers every name is an upstream"
    );
}

/// A block is only decidable once its last line has been read, so a
/// `domain :` at the end of one still drops the nameserver at its start.
#[cfg(any(target_os = "macos", test))]
#[test]
fn scutil_dns_drops_a_block_whose_domain_line_comes_last() {
    let output = "\
resolver #1
  nameserver[0] : 10.8.0.1
  domain   : corp.example

resolver #2
  nameserver[0] : 192.168.1.1
";
    assert_eq!(parse_scutil_dns(output), vec!["192.168.1.1".to_string()]);
}

/// The "for scoped queries" section repeats the global one, and so does
/// every interface that was given the same servers: the chain tries one
/// address at a time and pays 1.5s for each that does not answer, so the
/// repeats have to collapse rather than fill both slots with one resolver.
#[cfg(any(target_os = "macos", test))]
#[test]
fn scutil_dns_names_each_resolver_once_across_the_sections_that_repeat_it() {
    let output = "\
DNS configuration

resolver #1
  nameserver[0] : 192.168.1.1

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
";
    assert_eq!(parse_scutil_dns(output), vec!["192.168.1.1".to_string()]);
}

/// A nameserver line is only ever taken as an address: an IPv6 one carries
/// colons of its own, so the split has to be on the first colon — the one
/// after the index — and not on any of the ones inside the address.
#[cfg(any(target_os = "macos", test))]
#[test]
fn scutil_dns_reads_an_ipv6_nameserver_whole() {
    assert_eq!(
        parse_scutil_dns("resolver #1\n  nameserver[0] : 2001:db8::1\n"),
        vec!["2001:db8::1".to_string()]
    );
}

/// Output this code has never seen — a refused command, or a shape that
/// changed — is not a resolver. Guessing an address and forwarding a
/// machine's queries to it is worse than having no answer.
#[cfg(any(target_os = "macos", test))]
#[test]
fn scutil_dns_output_naming_no_address_reads_as_no_resolvers() {
    assert!(parse_scutil_dns("").is_empty());
    assert!(parse_scutil_dns("** Error: command not recognized.\n").is_empty());
    assert!(parse_scutil_dns("  nameserver[0] : not-an-address\n").is_empty());
}

/// One rule per line, `<namespaces>|<servers>`, which is what the two NRPT
/// scripts print. PowerShell ends these lines with CRLF, and a rule can name
/// more than one server — the read-back has to survive both before it is
/// trusted to say whether the hijack is in place.
#[cfg(any(windows, test))]
#[test]
fn nrpt_rules_read_back_as_the_namespaces_they_route_and_who_they_ask() {
    let rules = parse_nrpt_rules("example.com|10.7.0.254\r\n.foo.io|10.7.0.254,192.168.1.1\r\n");
    assert_eq!(
        nrpt_namespaces_for(&rules, "10.7.0.254"),
        vec!["example.com".to_string(), ".foo.io".to_string()]
    );
}

/// A rule that names another resolver is not one of ours, and neither is an
/// exemption rule, which carries no server at all. `110.7.0.254` is the
/// address the exact match is worth writing: it contains this one, and it is
/// somebody else's resolver.
#[cfg(any(windows, test))]
#[test]
fn an_nrpt_rule_naming_another_resolver_is_not_ours() {
    let rules = parse_nrpt_rules("example.com|110.7.0.254\r\n.corp.example.com|\r\nnas|10.7.0.254");
    assert_eq!(
        nrpt_namespaces_for(&rules, "10.7.0.254"),
        vec!["nas".to_string()]
    );
}

/// A machine with no NRPT rules prints nothing at all, which has to read as
/// "no rules" rather than as one rule covering no namespace.
#[cfg(any(windows, test))]
#[test]
fn an_empty_nrpt_dump_reads_as_no_rules() {
    assert!(parse_nrpt_rules("").is_empty());
    assert!(parse_nrpt_rules("\r\n").is_empty());
    assert!(nrpt_namespaces_for(&parse_nrpt_rules(""), "10.7.0.254").is_empty());
}

/// The two commands a Windows machine will run and this one cannot. Pinned
/// because a broken escape — a `{{` that survives into the script — reaches
/// that machine as a PowerShell syntax error, and there is no other way to
/// see it coming from here.
#[cfg(any(windows, test))]
#[test]
fn nrpt_scripts_are_pinned() {
    assert_eq!(
            nrpt_add_script(&nrpt_namespaces(&["example.com".to_string()]), "10.7.0.254"),
            "$namespaces = @('example.com','.example.com');\
             foreach ($namespace in $namespaces) {\
             try { Add-DnsClientNrptRule -Namespace $namespace -NameServers '10.7.0.254' -Comment 'nexapipe' -ErrorAction Stop } \
             catch { Write-Warning ('add ' + $namespace + ': ' + $_.Exception.Message) }\
             };\
             Clear-DnsClientCache;\
             Get-DnsClientNrptRule | ForEach-Object { ($_.Namespace -join ',') + '|' + ($_.NameServers -join ',') }"
        );
    assert_eq!(
            nrpt_remove_script("10.7.0.254"),
            "$ours = @(Get-DnsClientNrptRule | Where-Object { ($_.NameServers -contains '10.7.0.254') -or ($_.Comment -eq 'nexapipe') });\
             foreach ($rule in $ours) {\
             try { Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop; Write-Output ('removed ' + ($rule.Namespace -join ',')) } \
             catch { Write-Warning ('remove ' + $rule.Name + ': ' + $_.Exception.Message) }\
             };\
             Clear-DnsClientCache;\
             Get-DnsClientNrptRule | ForEach-Object { ($_.Namespace -join ',') + '|' + ($_.NameServers -join ',') }"
        );
}

/// The policy the client applies is read back in the shape the rule parser
/// already understands: a rule can be in the table and not in force, and the
/// two dumps have to be read by the same code or the comparison is between
/// different things.
#[cfg(any(windows, test))]
#[test]
fn the_effective_nrpt_policy_is_read_back_as_namespaces_and_servers() {
    assert_eq!(
        nrpt_effective_script(),
        "Get-DnsClientNrptPolicy -Effective | ForEach-Object { ($_.Namespace -join ',') + '|' \
             + ($_.NameServers -join ',') }"
    );

    let rules = parse_nrpt_rules("example.com,.example.com|10.7.0.254\n.corp|10.8.0.1\n");
    assert_eq!(
        nrpt_namespaces_for(&rules, "10.7.0.254"),
        vec!["example.com".to_string(), ".example.com".to_string()]
    );
    assert!(
        nrpt_namespaces_for(&rules, "10.7.0.253").is_empty(),
        "a policy that names another server routes nothing of ours"
    );
}

/// The apex and everything under it, as two rules. One namespace alone is
/// the half a scoped hijack fails on: `.example.com` is a suffix rule, which
/// the name `example.com` does not end in.
#[cfg(any(windows, test))]
#[test]
fn nrpt_namespaces_cover_a_domain_and_everything_under_it() {
    assert_eq!(
        nrpt_namespaces(&["example.com".to_string()]),
        vec!["example.com".to_string(), ".example.com".to_string()]
    );
    assert!(nrpt_namespaces(&[]).is_empty());
}

/// Only the host address the hijack actually uses counts as ours. Widening this
/// to the candidate /24 around it would wipe the DNS of every machine whose LAN
/// sits in 10.0.0.0/24 — one of the candidate blocks — and whose router hands
/// out 10.0.0.1.
#[cfg(target_os = "macos")]
#[test]
fn only_the_hijack_host_address_counts_as_ours() {
    assert!(is_tun_dns_address("198.18.0.254"));
    assert!(is_tun_dns_address("198.19.0.254"));
    assert!(is_tun_dns_address("10.0.0.254"));

    assert!(
        !is_tun_dns_address("198.18.0.1"),
        "a virtual IP is not a DNS server"
    );
    assert!(
        !is_tun_dns_address("10.0.0.1"),
        "a LAN router's DNS is not ours to reset"
    );
    assert!(!is_tun_dns_address("8.8.8.8"));
    assert!(!is_tun_dns_address("not-an-address"));
}

/// The recorded backup has to survive a round trip through the file it is kept
/// in, and an empty list has to stay distinguishable from a missing one: the
/// first means "clear it on restore", the second means "we never knew".
#[cfg(target_os = "macos")]
#[test]
fn a_recorded_backup_round_trips_through_json() {
    let mut backup = std::collections::BTreeMap::new();
    backup.insert("Wi-Fi".to_string(), Vec::<String>::new());
    backup.insert(
        "Thunderbolt Bridge".to_string(),
        vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
    );

    let json = serde_json::to_string(&backup).expect("a map of strings serialises");
    let read: std::collections::BTreeMap<String, Vec<String>> =
        serde_json::from_str(&json).expect("and parses back");

    assert_eq!(read, backup);
    assert_eq!(read["Wi-Fi"], Vec::<String>::new());
}

/// A resolv.conf is more than its nameservers: `search` and `options` are part of
/// what the machine was told to do, and dropping the address this code put there
/// must not take them — or a real resolver listed next to it — with it.
#[cfg(any(target_os = "linux", test))]
#[test]
fn dropping_our_nameserver_keeps_the_rest_of_the_file() {
    let contents = "# written by hand\n\
                        search example.internal\n\
                        nameserver 198.18.0.254\n\
                        nameserver 8.8.8.8\n\
                        options edns0\n";

    assert_eq!(
        resolv_conf_nameservers(contents),
        vec!["198.18.0.254".to_string(), "8.8.8.8".to_string()]
    );
    assert_eq!(
        resolv_conf_without_nameservers(contents, &["198.18.0.254".to_string()]),
        "# written by hand\nsearch example.internal\nnameserver 8.8.8.8\noptions edns0\n"
    );
}

/// The backup is only ever taken from a resolv.conf the machine still owns. A
/// file that already names one of the hijack's addresses is one this code wrote
/// and failed to put back: copying it over the backup would destroy the only
/// record of the machine's own resolver, and the next restore would then put the
/// hijack back and call it a recovery.
#[cfg(any(target_os = "linux", test))]
#[test]
fn a_hijacked_resolv_conf_is_not_a_backup_source() {
    assert!(resolv_conf_names_a_tun_address(
        "search example.internal\nnameserver 198.18.0.254\n"
    ));
    assert!(resolv_conf_names_a_tun_address(
        "nameserver 8.8.8.8\nnameserver 198.18.0.254\n"
    ));

    assert!(
        !resolv_conf_names_a_tun_address("nameserver 8.8.8.8\noptions edns0\n"),
        "the machine's own resolver is exactly what the backup exists to keep"
    );
    assert!(!resolv_conf_names_a_tun_address("# no nameserver at all\n"));
    assert!(
        !resolv_conf_names_a_tun_address("nameserver 10.0.0.1\n"),
        "a LAN router's DNS is not a hijack"
    );
}

/// The recorded DNS is spent only when a cleanup pass reset something *and* left
/// nothing behind. A service whose reset failed still carries the hijack address
/// and will be attempted again, and its original servers are written nowhere else
/// — deleting the file would leave the next pass able only to hand it to DHCP.
#[cfg(target_os = "macos")]
#[test]
fn the_backup_outlives_a_partial_cleanup() {
    let reset = ["Wi-Fi".to_string()];
    let failed = ["Thunderbolt Bridge".to_string()];

    assert!(
        backup_is_spent(&reset, &[]),
        "every service that was attempted came back"
    );
    assert!(
        !backup_is_spent(&reset, &failed),
        "a service that could not be reset still needs its recorded DNS"
    );
    assert!(
        !backup_is_spent(&[], &[]),
        "nothing was reset, so nothing was spent"
    );
}

/// `resolvectl dns` answers with a `Link …` prefix when asked about one link and
/// with a bare list when asked about all of them. Only the addresses matter, and
/// no part of that prefix reads as one — including the link index.
#[cfg(any(target_os = "linux", test))]
#[test]
fn resolvectl_dns_reads_as_addresses_in_either_shape() {
    assert_eq!(
        parse_resolvectl_dns("Link 2 (eth0): 198.18.0.254\n"),
        vec!["198.18.0.254".to_string()]
    );
    assert_eq!(
        parse_resolvectl_dns("Link 3 (wlan0): 8.8.8.8 1.1.1.1\n"),
        vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
    );
    assert_eq!(
        parse_resolvectl_dns("198.18.0.254\n"),
        vec!["198.18.0.254".to_string()]
    );
    assert_eq!(
        parse_resolvectl_dns("Link 2 (eth0):\n"),
        Vec::<String>::new()
    );
}

/// The Linux twin of `a_partial_install_is_not_a_scoped_one`: a link given
/// two domains and routing one of them has not routed them.
#[cfg(any(target_os = "linux", test))]
#[test]
fn a_link_routing_one_domain_has_not_routed_them_all() {
    let domains = vec!["example.com".to_string(), "foo.io".to_string()];
    let routed = vec!["example.com".to_string(), "foo.io".to_string()];
    assert!(routes_every_domain(&routed, &domains));
    assert!(!routes_every_domain(&["example.com".to_string()], &domains));
    assert!(!routes_every_domain(&[], &domains));
    assert!(routes_every_domain(&[], &[]));
}

/// `~` is what makes a domain routing-only: resolved sends it to that link's
/// DNS server without putting it in any search list.
#[cfg(any(target_os = "linux", test))]
#[test]
fn the_routing_domains_a_link_was_given() {
    assert_eq!(
        parse_resolvectl_domains("Link 5 (nexa0): ~example.com ~foo.io\n"),
        vec!["example.com".to_string(), "foo.io".to_string()]
    );
    // A link given none looks like the line above with nothing after it.
    assert_eq!(
        parse_resolvectl_domains("Link 5 (nexa0):\n"),
        Vec::<String>::new()
    );
}

/// The exclusive-route read-back compares what `resolvectl domain` printed
/// against [`DEFAULT_ROUTE_DOMAIN`], so the two have to agree on the shape:
/// the `~` that makes it routing-only is not part of what the parser keeps.
/// A parser that starts keeping it would turn a working hijack into one that
/// silently falls back to rewriting /etc/resolv.conf.
#[cfg(any(target_os = "linux", test))]
#[test]
fn the_default_route_domain_reads_back_as_the_root() {
    assert_eq!(
        parse_resolvectl_domains("Link 5 (nexa-tun): ~.\n"),
        vec![DEFAULT_ROUTE_DOMAIN.to_string()]
    );
    // The token it is written as, and the one it is read back as.
    assert_eq!(DEFAULT_ROUTE_DOMAIN, ".");
    assert_eq!(format!("~{DEFAULT_ROUTE_DOMAIN}"), "~.");
}

/// Routing every query to this link and being the only resolver asked are
/// two claims, and only one of them follows from `~.`: resolved keeps the
/// longest matching suffix, so a `~corp.example` on another link keeps
/// answering those names with the addresses the tunnel exists to replace.
/// Calling the hijack exclusive while that is true is how a name walks out
/// through the proxy's front door without anybody seeing it leave.
#[cfg(any(target_os = "linux", test))]
#[test]
fn a_more_specific_route_elsewhere_keeps_its_own_resolver() {
    let output = "\
Global:
Link 2 (eth0): corp.example
Link 5 (nexa0): ~.
Link 7 (wg0): ~corp.example ~corp.internal
";
    assert_eq!(
        parse_resolvectl_competing_routes(output, "nexa0"),
        vec![(
            "Link 7 (wg0)".to_string(),
            vec!["corp.example".to_string(), "corp.internal".to_string()]
        )]
    );

    // The route this hijack installs is never a competing one.
    assert!(parse_resolvectl_competing_routes(output, "wg0")
        .iter()
        .all(|(source, _)| source != "Link 7 (wg0)"));

    // A search domain is not a route: it decides how a bare name is
    // completed, not who is asked, so eth0 above counts for nothing.
    assert_eq!(
        parse_resolvectl_competing_routes("Link 2 (eth0): corp.example\n", "nexa0"),
        Vec::new()
    );

    // The global list routes too, and belongs to no link.
    assert_eq!(
        parse_resolvectl_competing_routes("Global: ~corp.example\nLink 5 (nexa0): ~.\n", "nexa0"),
        vec![("Global".to_string(), vec!["corp.example".to_string()])]
    );

    // Addressed by index rather than by name.
    assert_eq!(
        parse_resolvectl_competing_routes("Link 5 (nexa0): ~.\n", "5"),
        Vec::new()
    );

    // Nothing routes anywhere else, so the hijack really is the only one.
    assert_eq!(
        parse_resolvectl_competing_routes("Link 5 (nexa0): ~.\n", "nexa0"),
        Vec::new()
    );
}

/// What the scoped hijack writes has to be what its restore reads: a file
/// this code cannot recognise as its own is one it would leave behind.
#[cfg(any(target_os = "macos", test))]
#[test]
fn a_resolver_file_is_read_back_as_our_own() {
    let contents = resolver_file_contents("198.18.0.254");
    assert_eq!(
        resolver_nameserver(&contents).as_deref(),
        Some("198.18.0.254")
    );
    assert!(is_our_resolver_file(&contents));

    // The marker is the whole test: without it the same file is a stranger.
    assert!(contents.starts_with(RESOLVER_MARKER));
    assert!(!is_our_resolver_file("nameserver 198.18.0.254\n"));
    assert!(!is_our_resolver_file(""));
}

/// A file that names no resolver is not ours, and neither is one whose
/// `nameserver` belongs to somebody else — the second one matters more: it
/// is recognised, and for that reason left exactly as it is.
#[cfg(any(target_os = "macos", test))]
#[test]
fn only_a_file_naming_a_resolver_is_claimed() {
    assert_eq!(resolver_nameserver(""), None);
    assert_eq!(
        resolver_nameserver("# a comment\nsearch example.com\n"),
        None
    );
    assert_eq!(
        resolver_nameserver("nameserver 172.17.0.1\n").as_deref(),
        Some("172.17.0.1")
    );
}

#[cfg(any(target_os = "macos", test))]
#[test]
fn every_domain_gets_a_file_naming_our_resolver() {
    let dir = scratch_dir("resolver-write");
    let (written, left_alone) = write_resolver_files(
        &dir,
        "198.18.0.254",
        &["example.com".to_string(), "foo.io".to_string()],
    );
    assert_eq!(written.len(), 2);
    assert!(left_alone.is_empty());
    assert_eq!(count_resolvers_in_effect(&written, "198.18.0.254"), 2);

    // The read-back is what the install checks, so it has to tell the two
    // apart: a file naming somebody else's address is not in effect.
    assert_eq!(count_resolvers_in_effect(&written, "1.1.1.1"), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The whole point of the per-domain hijack over the global one: whatever
/// another resolver already owns stays exactly as it is, and survives the
/// teardown too.
#[cfg(any(target_os = "macos", test))]
#[test]
fn a_resolver_somebody_else_owns_is_left_alone() {
    let dir = scratch_dir("resolver-theirs");
    let theirs = dir.join("example.com");
    std::fs::write(&theirs, "nameserver 172.17.0.1\n").unwrap();

    let (written, left_alone) =
        write_resolver_files(&dir, "198.18.0.254", &["example.com".to_string()]);
    assert!(written.is_empty());
    assert_eq!(left_alone.len(), 1);
    assert_eq!(
        std::fs::read_to_string(&theirs).unwrap(),
        "nameserver 172.17.0.1\n"
    );

    assert!(remove_resolver_files(&dir, is_our_resolver_file).is_empty());
    assert!(theirs.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A scoped install that reached only some of the domains is not a scoped
/// install: the rest would keep resolving outside the proxy while the caller
/// is told they do not.
#[cfg(any(target_os = "macos", test))]
#[test]
fn a_partial_install_is_not_a_scoped_one() {
    assert!(scoped_install_is_complete(2, 2));
    // Nothing asked for, nothing missing.
    assert!(scoped_install_is_complete(0, 0));
    assert!(!scoped_install_is_complete(2, 3));
    // Two domains asked for and no file written — every write failed. Nothing
    // to score against is not the same as everything having taken effect.
    assert!(!scoped_install_is_complete(0, 2));
}

/// Scored against what the install set out to write, so a write that failed
/// counts as a domain that did not take rather than disappearing from the
/// score. Too long to be a filename is how a write fails here.
#[cfg(any(target_os = "macos", test))]
#[test]
fn an_install_is_scored_against_the_domains_it_meant_to_write() {
    let dir = scratch_dir("resolver-tally");
    let too_long = format!("{}.com", "a".repeat(300));

    let install = scoped_install_tally(&dir, "198.18.0.254", &[too_long]);
    assert!(install.written.is_empty());
    assert_eq!(install.in_effect, 0);
    assert_eq!(install.meant_to_write, 1);
    assert!(!scoped_install_is_complete(
        install.in_effect,
        install.meant_to_write
    ));

    let ok = scoped_install_tally(
        &dir,
        "198.18.0.254",
        &["example.com".to_string(), "foo.io".to_string()],
    );
    assert_eq!(ok.meant_to_write, 2);
    assert_eq!(ok.in_effect, 2);
    assert!(scoped_install_is_complete(ok.in_effect, ok.meant_to_write));

    // A domain another resolver owns is subtracted rather than counted as a
    // refusal: reaching for the global hijack would not win that domain back
    // — the file outranks it — and would take the rest of the machine's DNS
    // with it.
    std::fs::write(dir.join("corp.example"), "nameserver 172.17.0.1\n").unwrap();
    let mixed = scoped_install_tally(
        &dir,
        "198.18.0.254",
        &["example.com".to_string(), "corp.example".to_string()],
    );
    assert_eq!(mixed.owned_by_someone_else.len(), 1);
    assert_eq!(mixed.meant_to_write, 1);
    assert_eq!(mixed.in_effect, 1);
    assert!(scoped_install_is_complete(
        mixed.in_effect,
        mixed.meant_to_write
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Why the global restore asks before it writes. An attempt that never
/// reached the machine has nothing to undo, and undoing is not free: every
/// service gets written, from a backup an earlier run may have left behind.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
#[test]
fn undoing_a_hijack_depends_on_what_is_in_effect() {
    let none: [Vec<String>; 0] = [];
    assert!(!hijack_is_in_effect(&none, "198.18.0.254"));

    let some = [
        vec!["192.168.1.1".to_string()],
        vec!["198.18.0.254".to_string()],
    ];
    assert!(hijack_is_in_effect(&some, "198.18.0.254"));

    // `10.0.0.254` is one of the candidate blocks and a router address. It is
    // not this run's hijack, and treating it as one is what the restore would
    // have to rewrite — see the startup cleanup for the other blocks.
    assert!(!hijack_is_in_effect(
        &[vec!["10.0.0.254".to_string()]],
        "198.18.0.254"
    ));
}

/// Why ownership cannot be read off the address: `10.0.0.254` is the last of
/// the candidate blocks and it is also a router address, so a split-DNS rule
/// for an internal zone can name it without having anything to do with this
/// proxy. Such a file is neither rewritten nor removed, and this directory is
/// not the only place it can be at risk — the startup cleanup looks here too.
#[cfg(any(target_os = "macos", test))]
#[test]
fn an_unmarked_file_naming_a_hijack_address_is_left_alone() {
    let dir = scratch_dir("resolver-unmarked");
    let theirs = dir.join("corp.example");
    std::fs::write(&theirs, "nameserver 10.0.0.254\n").unwrap();
    assert!(is_tun_dns_address("10.0.0.254"));

    let (written, left_alone) =
        write_resolver_files(&dir, "198.18.0.254", &["corp.example".to_string()]);
    assert!(written.is_empty());
    assert_eq!(left_alone.len(), 1);
    assert_eq!(
        std::fs::read_to_string(&theirs).unwrap(),
        "nameserver 10.0.0.254\n"
    );

    // Both shapes of removal: the restore's, and the stale cleanup's, which
    // would otherwise match this address and find no interface holding it.
    assert!(remove_resolver_files(&dir, is_our_resolver_file).is_empty());
    assert!(remove_resolver_files(&dir, |contents| {
        is_our_resolver_file(contents)
            && resolver_nameserver(contents).is_some_and(|server| server == "10.0.0.254")
    })
    .is_empty());
    assert!(theirs.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Our own leftovers are not somebody else's: a run that used another block
/// — or died before its restore — leaves a file naming an address no tunnel
/// holds, and that one is rewritten and removed.
#[cfg(any(target_os = "macos", test))]
#[test]
fn a_resolver_left_by_an_earlier_run_is_taken_back() {
    let dir = scratch_dir("resolver-ours");
    let stale = dir.join("example.com");
    let other_block = Ipv4Addr::from(u32::from(TUN_BASE_CANDIDATES[1]) | 0x0000_00FE).to_string();
    // Marked, because the run that left it wrote it: the marker is the only
    // thing that still says so once the address belongs to no live tunnel.
    std::fs::write(&stale, resolver_file_contents(&other_block)).unwrap();
    assert!(is_tun_dns_address(&other_block));

    let (written, left_alone) =
        write_resolver_files(&dir, "198.18.0.254", &["example.com".to_string()]);
    assert_eq!(written.len(), 1);
    assert!(left_alone.is_empty());

    assert!(remove_resolver_files(&dir, is_our_resolver_file).is_empty());
    assert!(!stale.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A hijack that failed after it had already changed the machine is taken
/// back — with the hijack that was installed, because that is the only
/// thing that knows where to take it back from.
///
/// The failure is what carries it. The global paths change the machine
/// before they read it back, so "it failed" does not mean "nothing
/// happened", and a caller that had nothing but the error had nothing to
/// undo: the machine kept a static DNS pointing at a TUN address that
/// never comes up.
#[test]
fn a_hijack_that_failed_after_it_changed_the_machine_is_undone() {
    let failure = DnsHijackFailure {
        hijack: DnsHijack::Global,
        error: anyhow::anyhow!("the read-back did not show the TUN address"),
    };

    let mut undone: Option<DnsHijack> = None;
    undo_failed_hijack(&failure, |hijack| {
        undone = Some(hijack);
        Ok(())
    })
    .expect("undoing a hijack that was installed cannot fail here");

    assert_eq!(
        undone,
        Some(DnsHijack::Global),
        "the restore has to be called with the hijack that was installed"
    );
}

/// A scoped hijack that failed is taken back the same way: the rules or
/// the resolver files it wrote are still there, and only the scoped
/// restore knows how to remove them.
#[test]
fn a_scoped_hijack_that_failed_is_undone_as_a_scoped_one() {
    let failure = DnsHijackFailure {
        hijack: DnsHijack::Scoped,
        error: anyhow::anyhow!("the rules could not be removed"),
    };

    let mut undone: Option<DnsHijack> = None;
    undo_failed_hijack(&failure, |hijack| {
        undone = Some(hijack);
        Ok(())
    })
    .expect("undoing a hijack that was installed cannot fail here");

    assert_eq!(undone, Some(DnsHijack::Scoped));
}

/// A hijack that failed before it changed anything is not undone: there is
/// nothing to take back, and the restore is not free — it rewrites the
/// machine's DNS configuration.
#[test]
fn a_hijack_that_failed_before_it_changed_anything_is_not_undone() {
    let failure = DnsHijackFailure {
        hijack: DnsHijack::None,
        error: anyhow::anyhow!("the configured domains cannot each be named"),
    };

    let mut called = false;
    undo_failed_hijack(&failure, |_hijack| {
        called = true;
        Ok(())
    })
    .expect("there is nothing to undo, so nothing can fail");

    assert!(
        !called,
        "nothing was installed, so there is nothing to take back"
    );
}

/// The liveness guard the Windows cleanup was missing: an adapter whose
/// TUN address a tunnel still holds is not a leftover, and resetting it
/// would leave the tunnel up and the machine's DNS somewhere else — the
/// proxied domains would resolve at their real addresses and the traffic
/// would leave in the clear.
#[test]
fn an_adapter_whose_tun_address_is_still_in_use_is_not_reset() {
    let adapters = vec![AdapterDns {
        index: 7,
        servers: vec!["198.18.0.254".to_string()],
    }];
    let in_use = |address: &str| address == "198.18.0.254";

    assert!(
        stale_adapter_indexes(&adapters, in_use).is_empty(),
        "a live tunnel's DNS is not a stale hijack"
    );
}

/// The other half: an address nothing holds is a leftover, and the
/// adapter carrying it is reset.
#[test]
fn an_adapter_whose_tun_address_is_not_in_use_is_reset() {
    let adapters = vec![AdapterDns {
        index: 7,
        servers: vec!["198.18.0.254".to_string()],
    }];
    let in_use = |_: &str| false;

    assert_eq!(stale_adapter_indexes(&adapters, in_use), vec![7]);
}

/// Only the addresses of a hijack are ever reset: an adapter carrying the
/// machine's own DNS is not ours to touch, and the IPv6 marker is a
/// leftover only while nothing holds `[::1]:53`.
#[test]
fn only_the_addresses_of_a_hijack_are_ever_reset() {
    let adapters = vec![
        AdapterDns {
            index: 7,
            servers: vec!["192.168.1.1".to_string(), "8.8.8.8".to_string()],
        },
        AdapterDns {
            index: 8,
            servers: vec![LOCALHOST_V6.to_string()],
        },
    ];

    // Nothing is in use: the first adapter is not ours at all, the second
    // one carries the IPv6 marker of a hijack that is gone.
    let in_use = |_: &str| false;
    assert_eq!(stale_adapter_indexes(&adapters, in_use), vec![8]);

    // With the local resolver still listening on [::1]:53, the marker
    // belongs to a live tunnel and the adapter is left alone.
    let in_use = |address: &str| address == LOCALHOST_V6;
    assert!(stale_adapter_indexes(&adapters, in_use).is_empty());
}

/// What the Windows cleanup reads off the machine: the adapters and their
/// DNS servers, the rules, and the addresses a tunnel still holds.
///
/// The same adapter is reported once per address family, and the decision
/// is about the adapter rather than the family — so the two rows have to
/// end up as one.
#[cfg(any(windows, test))]
#[test]
fn the_cleanup_dump_reads_as_the_adapters_the_rules_and_what_is_still_in_use() {
    let dump = "\
adapter|12|198.18.0.254\n\
adapter|12|::1\n\
adapter|15|192.168.1.1\n\
nrpt|{rule}|example.com,.example.com|198.18.0.254\n\
live|198.18.0.254\n";
    let state = parse_cleanup_state(dump);

    assert_eq!(state.adapters.len(), 2);
    assert_eq!(state.adapters[0].index, 12);
    assert_eq!(
        state.adapters[0].servers,
        vec!["198.18.0.254".to_string(), "::1".to_string()]
    );
    assert_eq!(state.adapters[1].index, 15);
    assert_eq!(state.rules.len(), 1);
    assert_eq!(state.rules[0].name, "{rule}");
    assert_eq!(
        state.rules[0].namespaces,
        vec!["example.com".to_string(), ".example.com".to_string()]
    );
    assert_eq!(state.rules[0].servers, vec!["198.18.0.254".to_string()]);
    assert_eq!(state.in_use, vec!["198.18.0.254".to_string()]);
}

/// The guard, from what the machine says to what is done with it: an
/// adapter whose TUN address a tunnel still holds is left alone, and one
/// whose address nothing holds is reset.
#[cfg(any(windows, test))]
#[test]
fn the_cleanup_leaves_the_adapters_of_a_live_tunnel_alone() {
    let live = parse_cleanup_state(
        "adapter|12|198.18.0.254\nadapter|15|198.18.0.254\nlive|198.18.0.254\n",
    );
    let held = |address: &str| live.in_use.iter().any(|live| live == address);
    assert!(
        stale_adapter_indexes(&live.adapters, held).is_empty(),
        "a tunnel that is up keeps its DNS"
    );

    // The same machine without the listener: both adapters are leftovers.
    let stale = parse_cleanup_state("adapter|12|198.18.0.254\nadapter|15|198.18.0.254\n");
    let nothing_held = |_: &str| false;
    assert_eq!(
        stale_adapter_indexes(&stale.adapters, nothing_held),
        vec![12, 15]
    );
}

/// A rule that routes to an address a live tunnel holds is not stale:
/// removing it would take a live tunnel's names out of the proxy.
#[cfg(any(windows, test))]
#[test]
fn an_nrpt_rule_of_a_live_tunnel_is_not_removed() {
    let rules = vec![
        CleanupRule {
            name: "live".to_string(),
            namespaces: vec!["example.com".to_string()],
            servers: vec!["198.18.0.254".to_string()],
        },
        CleanupRule {
            name: "stale".to_string(),
            namespaces: vec!["foo.io".to_string()],
            servers: vec!["198.19.0.254".to_string()],
        },
    ];

    let in_use = |address: &str| address == "198.18.0.254";
    let stale = stale_nrpt_rules(&rules, in_use);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].name, "stale");
}

/// The two scripts the Windows cleanup runs: one that reports what is on
/// the machine, one that carries the decision out.
///
/// Pinned, because a broken escape reaches that machine as a PowerShell
/// syntax error, and there is no other way to see it coming from here.
/// The liveness question is in the first one: the tunnel's DNS server, on
/// the TUN address and on the IPv6 loopback.
#[cfg(any(windows, test))]
#[test]
fn the_cleanup_scripts_are_pinned() {
    let collect = cleanup_collect_script();
    // The liveness question: the socket that holds the address — the
    // tunnel's DNS server, on the TUN address and on the IPv6 loopback.
    assert!(collect.contains("Get-NetUDPEndpoint -LocalAddress $a -LocalPort 53"));
    assert!(collect.contains("$watched = @('198.18.0.254'"));
    assert!(collect.contains(",'::1');"));
    assert!(collect.contains("'adapter|' + $_.InterfaceIndex"));
    assert!(collect.contains("'nrpt|' + $_.Name"));

    let apply = cleanup_apply_script(&[12], &["{rule}".to_string()]);
    assert!(apply.contains("$reset = @(12)"));
    assert!(apply.contains("Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses"));
    assert!(apply.contains("$rules = @('{rule}')"));
    assert!(apply.contains("Remove-DnsClientNrptRule -Name $r"));
}

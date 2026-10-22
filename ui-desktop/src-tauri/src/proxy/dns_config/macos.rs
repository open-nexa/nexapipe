//! The macOS half of the system DNS configuration: a resolver file per domain
//! for the scoped strategy, and `networksetup` for the global one.

//! The per-domain files are compiled under `test` on every platform, because
//! what this code writes has to be what it reads back, or a restore would leave
//! its own files behind.

#[cfg(not(windows))]
use std::process::Command;

// The shared half of the configuration. The pure parsers of this platform are
// compiled under `test` on every platform, and on some of those the shared
// half is not what they use — so the glob is unused there, which is not a
// mistake worth a warning.
#[allow(unused_imports)]
use super::*;

/// Resets network services whose DNS still points at a TUN address no interface holds.
///
/// The macOS counterpart of [`cleanup_stale_hijack_windows`], and the reason this platform
/// needed one: `networksetup` writes a static DNS into the system configuration, where it
/// survives both the process that set it and a reboot, so a run that never reached its
/// restore leaves the machine resolving against a TUN address that no longer exists — "the
/// internet is broken", with nothing left to undo it.
///
/// A service is stale when its DNS is one of the hijack's own addresses *and* that address
/// is no longer bindable: while the tunnel is up the answer is the one we asked for, and
/// resetting it would break a proxy that is running.
#[cfg(target_os = "macos")]
pub(super) fn cleanup_stale_hijack_macos() {
    // Both places a hijack lives: the network services, and the per-domain
    // resolvers a scoped one wrote. A run that never reached its restore may
    // have left either.
    remove_stale_resolver_files();

    let services = match network_services() {
        Ok(services) => services,
        Err(e) => {
            tracing::warn!(
                "stale DNS hijack cleanup could not list the network services: {}",
                e
            );
            return;
        }
    };

    let recorded = read_dns_backup();
    let mut reset = Vec::new();
    let mut failed = Vec::new();

    for service in &services {
        let Some(servers) = dns_servers_for(service) else {
            continue;
        };
        let stale: Vec<&str> = servers
            .iter()
            .filter(|server| is_tun_dns_address(server))
            .map(String::as_str)
            .collect();
        if stale.is_empty() {
            continue;
        }
        if stale.iter().any(|address| address_is_held(address)) {
            tracing::info!(
                "{} points at {}, which an interface still holds — not a stale hijack",
                service,
                stale.join(", ")
            );
            continue;
        }

        let target = match recorded.get(service).filter(|servers| !servers.is_empty()) {
            Some(servers) => servers.clone(),
            None => vec![EMPTY.to_string()],
        };
        match set_dns_servers(service, &target) {
            Ok(()) => {
                tracing::warn!(
                    "stale DNS hijack on {}: reset {} to {:?}",
                    service,
                    stale.join(", "),
                    target
                );
                reset.push(service.clone());
            }
            // Expected when this process is not elevated: the desktop cannot change
            // system DNS by itself, and the service runs as root and will clean up on
            // its own start. Recorded all the same, because this service still needs
            // its original servers and the backup is the only record of them.
            Err(e) => {
                tracing::warn!("could not reset the stale DNS of {}: {}", service, e);
                failed.push(service.clone());
            }
        }
    }

    if reset.is_empty() {
        tracing::info!("stale DNS hijack cleanup: nothing to reset");
        return;
    }

    tracing::warn!(
        "stale DNS hijack cleanup: reset {} network service(s): {}",
        reset.len(),
        reset.join(", ")
    );

    if backup_is_spent(&reset, &failed) {
        // A later hijack has to record its own starting point.
        let _ = std::fs::remove_file(DNS_BACKUP_PATH);
    } else {
        tracing::warn!(
            "kept {}: {} could not be reset, and its original DNS is recorded nowhere else",
            DNS_BACKUP_PATH,
            failed.join(", ")
        );
    }
}

/// Whether the recorded DNS can be retired after a cleanup pass.
///
/// Only when something was actually reset *and* nothing failed. A service that
/// could not be reset still carries the hijack address, so it will be attempted
/// again — and its original servers are in no other place. Clearing the file
/// here would leave the next pass able only to hand it to DHCP.
#[cfg(target_os = "macos")]
pub(super) fn backup_is_spent(reset: &[String], failed: &[String]) -> bool {
    !reset.is_empty() && failed.is_empty()
}

/// Where mDNSResponder looks for a resolver that owns a domain: one file per
/// domain, holding a `nameserver` line. It picks the longest matching suffix, so
/// a file named `example.com` answers every name under it — which is the same
/// DOMAIN-SUFFIX rule the proxy already matches on, spelled the way the OS reads
/// it.
///
/// Preferred over `networksetup` because it leaves the machine's DNS alone: the
/// only queries that move are the ones for the proxied domains, so an internal
/// zone, a split-horizon name, or another tunnel's resolver keeps answering as
/// it did before the tunnel came up.
#[cfg(target_os = "macos")]
pub(super) const RESOLVER_DIR: &str = "/etc/resolver";

/// The line that marks a resolver file as one this code wrote.
///
/// Ownership cannot be read off the `nameserver` line. The addresses a hijack
/// hands out end in `.254`, and `10.0.0.254` — the last candidate block — is
/// also a router address, which a hand-written split-DNS rule points at just
/// as plausibly. A file naming one and carrying no marker is somebody else's,
/// and is neither overwritten nor removed: nothing here keeps a copy of what
/// it would destroy.
///
/// A comment is safe here: the parser configd reads these files with skips
/// lines starting with `;` or `#`.
#[cfg(any(target_os = "macos", test))]
pub(super) const RESOLVER_MARKER: &str = "# managed by nexapipe";

/// Whether `contents` carry [`RESOLVER_MARKER`] — the only test this code
/// trusts before it overwrites or removes a resolver file.
#[cfg(any(target_os = "macos", test))]
pub(super) fn is_our_resolver_file(contents: &str) -> bool {
    contents.lines().any(|line| line.trim() == RESOLVER_MARKER)
}

/// The contents of a `/etc/resolver/<domain>` file.
#[cfg(any(target_os = "macos", test))]
pub(super) fn resolver_file_contents(dns_ip: &str) -> String {
    format!("{RESOLVER_MARKER}\nnameserver {dns_ip}\n")
}

/// The address a `/etc/resolver` file hands its domain to.
///
/// `None` when the file names none. Whether the file is one this code wrote is
/// a separate question, answered by [`is_our_resolver_file`].
#[cfg(any(target_os = "macos", test))]
pub(super) fn resolver_nameserver(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        (parts.next()? == "nameserver").then(|| parts.next().map(str::to_string))?
    })
}

/// Points the configured domains at the TUN resolver, one file per domain.
///
/// `Ok(false)` means "not installed", which is a call to fall back to the global
/// hijack rather than a failure: whatever was written up to that point is taken
/// back first, so the two cannot be in place at once.
#[cfg(target_os = "macos")]
pub(super) fn set_scoped_dns_macos(dns_ip: &str, proxy_domains: &[String]) -> Result<bool> {
    let Some(domains) = crate::proxy::dns::scoped_domains(proxy_domains) else {
        tracing::info!(
            "the configured domains cannot each be given a resolver of their own; \
             every query goes to the TUN instead"
        );
        return Ok(false);
    };

    if let Err(e) = std::fs::create_dir_all(RESOLVER_DIR) {
        tracing::warn!(
            "could not create {}: {} — every query goes to the TUN instead",
            RESOLVER_DIR,
            e
        );
        return Ok(false);
    }

    let install = scoped_install_tally(Path::new(RESOLVER_DIR), dns_ip, &domains);

    // Zero to write is not an install. Every configured domain already has a
    // resolver owned by somebody else, and this run leaves those alone by
    // choice, so nothing was taken over: reporting success would leave the UI
    // saying "running" while every domain the proxy exists for resolves at its
    // real address and leaves in the clear. Falling back is the honest answer —
    // it is also the same answer a failed install gives.
    if install.meant_to_write == 0 {
        tracing::warn!(
            "none of the {} configured domain(s) could be given a resolver of their own — \
             another resolver already owns all of them; every query goes to the TUN instead",
            domains.len()
        );
        return Ok(false);
    }

    if !scoped_install_is_complete(install.in_effect, install.meant_to_write) {
        for path in &install.written {
            if count_resolvers_in_effect(std::slice::from_ref(path), dns_ip) == 0 {
                tracing::warn!(
                    "{} does not name {} after the write",
                    path.display(),
                    dns_ip
                );
            }
        }
        for path in &install.written {
            let _ = std::fs::remove_file(path);
        }
        tracing::warn!(
            "{} of {} resolver(s) under {} took effect — every query goes to the TUN instead",
            install.in_effect,
            install.meant_to_write,
            RESOLVER_DIR
        );
        return Ok(false);
    }

    tracing::info!(
        "{} of {} configured domain(s) resolve through {} via {}",
        install.in_effect,
        domains.len(),
        dns_ip,
        RESOLVER_DIR
    );
    if !install.owned_by_someone_else.is_empty() {
        tracing::warn!(
            "left resolving where they were, because another resolver already owns them: {}",
            install.owned_by_someone_else.join(", ")
        );
    }
    Ok(true)
}

/// What a scoped install has to be judged on.
///
/// Read back rather than trusted from the writes: a hijack that silently did not
/// happen looks exactly like a proxy that resolves nothing.
///
/// `meant_to_write` is deliberately not `written.len()`. A write that failed
/// leaves no file behind, so asking "did every file I wrote take" answers yes
/// when every single write failed — and reports a scoped hijack that is not
/// there. A domain whose resolver somebody else already owns is subtracted: that
/// file is left alone by choice, and failing the install over it would only send
/// the machine to the global hijack, which does not win the domain back.
#[cfg(any(target_os = "macos", test))]
pub(super) struct ScopedInstall {
    pub(super) written: Vec<PathBuf>,
    pub(super) owned_by_someone_else: Vec<String>,
    pub(super) in_effect: usize,
    pub(super) meant_to_write: usize,
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn scoped_install_tally(dir: &Path, dns_ip: &str, domains: &[String]) -> ScopedInstall {
    let (written, owned_by_someone_else) = write_resolver_files(dir, dns_ip, domains);
    let in_effect = count_resolvers_in_effect(&written, dns_ip);
    let meant_to_write = domains.len() - owned_by_someone_else.len();
    ScopedInstall {
        written,
        owned_by_someone_else,
        in_effect,
        meant_to_write,
    }
}

/// Writes one resolver file per domain under `dir`, and returns the paths
/// written together with the domains that were left alone.
///
/// A file already there that is not marked as ours is somebody else's: a
/// container runtime, another tunnel, a hand-written split-DNS rule.
/// Overwriting it would break whatever it is there for, so the domain keeps
/// resolving where it resolves — and the file keeps the address it named,
/// including one of the addresses a hijack of ours uses. A marked file is a
/// leftover of ours, from this run or an earlier one, and is rewritten.
#[cfg(any(target_os = "macos", test))]
pub(super) fn write_resolver_files(
    dir: &Path,
    dns_ip: &str,
    domains: &[String],
) -> (Vec<PathBuf>, Vec<String>) {
    let mut written = Vec::new();
    let mut left_alone = Vec::new();
    for domain in domains {
        let path = dir.join(domain);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if !is_our_resolver_file(&contents) {
                left_alone.push(format!("{} ({:?})", domain, resolver_nameserver(&contents)));
                continue;
            }
        }
        match std::fs::write(&path, resolver_file_contents(dns_ip)) {
            Ok(()) => written.push(path),
            Err(e) => tracing::warn!("could not write {}: {}", path.display(), e),
        }
    }
    (written, left_alone)
}

/// Reads the files written above back and returns how many of them really name
/// `dns_ip`.
#[cfg(any(target_os = "macos", test))]
pub(super) fn count_resolvers_in_effect(written: &[PathBuf], dns_ip: &str) -> usize {
    written
        .iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|contents| resolver_nameserver(&contents))
                .as_deref()
                == Some(dns_ip)
        })
        .count()
}

/// Whether a scoped install covers every domain it was asked to cover.
///
/// All of them or none of them: a domain whose file did not take would go on
/// resolving outside the proxy while the caller is told the hijack is scoped,
/// which is the one thing falling back to the global hijack is for.
///
/// `meant` is what the install set out to write, so a write that never landed
/// counts against it instead of quietly shrinking the target to what survived.
#[cfg(any(target_os = "macos", test))]
pub(super) fn scoped_install_is_complete(in_effect: usize, meant: usize) -> bool {
    in_effect == meant
}

/// Takes back the per-domain resolvers a scoped hijack installed.
///
/// Every file carrying [`RESOLVER_MARKER`] is ours whichever address it names,
/// including the one a run that used another block left behind. Files without
/// it are not touched, whatever they name.
#[cfg(target_os = "macos")]
pub(super) fn restore_scoped_dns_macos() -> Result<()> {
    let left = remove_resolver_files(Path::new(RESOLVER_DIR), is_our_resolver_file);
    if left.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{} resolver(s) under {} still point at the TUN after the restore: {}",
        left.len(),
        RESOLVER_DIR,
        left.join(", ")
    )
}

/// Removes every file under `dir` whose contents `is_ours` accepts, and
/// returns the ones that could not be removed.
///
/// `is_ours` is handed the whole file rather than its `nameserver` line because
/// what decides ownership here is the marker, not the address — see
/// [`RESOLVER_MARKER`]. Files it rejects are left untouched: a directory the
/// machine shares with other resolvers is not one this code gets to clean out.
#[cfg(any(target_os = "macos", test))]
pub(super) fn remove_resolver_files(dir: &Path, is_ours: impl Fn(&str) -> bool) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut removed = 0;
    let mut left = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !is_ours(&contents) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!("could not remove {}: {}", path.display(), e);
                left.push(path.display().to_string());
            }
        }
    }
    if removed > 0 {
        tracing::info!("removed {} resolver(s) under {}", removed, dir.display());
    }
    left
}

/// Removes the per-domain resolvers a run that never reached its restore left
/// behind.
///
/// The same test as the network-service half of this cleanup separates a stale
/// hijack from a live one: a marked file pointing at an address no interface
/// holds belongs to a tunnel that is gone, and until it is removed every query
/// for that domain goes nowhere. An unmarked one is not ours however stale its
/// address looks — a router's own `10.0.0.254` is the case that matters.
#[cfg(target_os = "macos")]
pub(super) fn remove_stale_resolver_files() {
    let left = remove_resolver_files(Path::new(RESOLVER_DIR), |contents| {
        is_our_resolver_file(contents)
            && resolver_nameserver(contents).is_some_and(|server| !address_is_held(&server))
    });
    if !left.is_empty() {
        tracing::warn!(
            "{} stale resolver(s) under {} could not be removed: {}",
            left.len(),
            RESOLVER_DIR,
            left.join(", ")
        );
    }
}

/// What `networksetup -getdnsservers` prints for a service with no static DNS,
/// i.e. one that takes whatever DHCP hands out. The line names the service, so
/// the match is on the fixed prefix rather than on the whole sentence.
#[cfg(target_os = "macos")]
pub(super) const NO_DNS_SERVERS: &str = "There aren't any DNS Servers set on";

/// The legend `-listallnetworkservices` prints ahead of the services it lists.
#[cfg(target_os = "macos")]
pub(super) const DISABLED_LEGEND: &str = "denotes that a network service is disabled";

/// The argument that clears a service's DNS servers, handing it back to DHCP.
#[cfg(target_os = "macos")]
pub(super) const EMPTY: &str = "Empty";

/// Where the pre-hijack DNS configuration is kept.
///
/// Under `/Library` because both processes that move system DNS are elevated: the
/// launchd service runs as root, and the desktop only reaches TUN mode when it was
/// launched with administrator rights. A per-user path would be readable by the
/// desktop and writable by nobody who needs to write it.
#[cfg(target_os = "macos")]
pub(super) const DNS_BACKUP_PATH: &str = "/Library/Application Support/nexapipe/dns-backup.json";

#[cfg(target_os = "macos")]
pub(super) fn set_system_dns_macos(dns_ip: &str) -> Result<()> {
    let services = network_services()?;
    if services.is_empty() {
        tracing::warn!("No network services found via networksetup");
        return Ok(());
    }

    // Recorded before the first service is touched. A process that is killed or
    // crashes between here and the teardown never runs the restore, and the next
    // start needs this file to put back whatever the machine was using — a
    // hand-picked DNS server is not something DHCP hands out again.
    save_dns_backup(&services);

    for service in &services {
        match set_dns_servers(service, &[dns_ip.to_string()]) {
            Ok(()) => tracing::info!("Set DNS for {}: {}", service, dns_ip),
            Err(e) => tracing::warn!("Could not set DNS for {}: {}", service, e),
        }
    }

    // Read back rather than trusting the exit code: `networksetup` has been seen
    // exiting 0 for a change it did not make, and a hijack that silently did not
    // happen looks exactly like a proxy that cannot resolve anything.
    let mut hijacked = 0;
    for service in &services {
        match dns_servers_for(service) {
            Some(servers) if servers.iter().any(|server| server == dns_ip) => hijacked += 1,
            Some(servers) => tracing::warn!(
                "{} does not point at {} after the switch (it has {:?})",
                service,
                dns_ip,
                servers
            ),
            None => tracing::warn!("could not read back the DNS of {}", service),
        }
    }
    if hijacked == 0 {
        anyhow::bail!(
            "no network service points at {} — DNS hijack is NOT in effect",
            dns_ip
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn restore_system_dns_macos(dns_ip: &str) -> Result<()> {
    // Not `unwrap_or_default()`: an empty list looks exactly like a machine
    // with no network services, and every check below is satisfied by nothing
    // — no service is left behind because none was looked at, and the backup
    // is not removed because there was nothing to remove it for. That is a
    // restore that restored nothing and reported success, leaving this
    // address as the machine's DNS.
    let services = network_services()?;
    let recorded = read_dns_backup();
    let mut restored = 0;

    for service in &services {
        // An empty recorded list means "no static DNS before the hijack", and so
        // does having nothing on file — clearing hands the service back to DHCP,
        // which is still better than leaving a TUN address behind.
        let target = match recorded.get(service).filter(|servers| !servers.is_empty()) {
            Some(servers) => servers.clone(),
            None => vec![EMPTY.to_string()],
        };
        match set_dns_servers(service, &target) {
            Ok(()) => {
                tracing::info!("Restored DNS for {}: {:?}", service, target);
                restored += 1;
            }
            Err(e) => tracing::warn!("Could not restore DNS for {}: {}", service, e),
        }
    }

    // The hijack's whole point is that no service mentions its address any more.
    // One that still does is the machine left without name resolution after a
    // disconnect, so it is reported instead of being assumed away.
    let left_behind: Vec<String> = services
        .iter()
        .filter(|service| {
            dns_servers_for(service).is_some_and(|servers| {
                servers
                    .iter()
                    // `dns_ip` is the address this run hijacked, which is the one
                    // that has to be gone; the candidate addresses catch a hijack
                    // left behind by a run that used another block.
                    .any(|server| *server == dns_ip || is_tun_dns_address(server))
            })
        })
        .cloned()
        .collect();
    if !left_behind.is_empty() {
        anyhow::bail!(
            "system DNS still points at a TUN address on {} service(s) after the restore: {}",
            left_behind.len(),
            left_behind.join(", ")
        );
    }
    // Nothing was restored on a machine that has services to restore. The
    // check above reads the addresses back, and a `networksetup` that refuses
    // to answer reads as "no TUN address here" — so this is the only place a
    // restore that silently did nothing says so.
    if restored == 0 && !services.is_empty() {
        anyhow::bail!(
            "system DNS could not be restored on any of {} network service(s)",
            services.len()
        );
    }

    // Spent: a later hijack has to record its own starting point, and leaving a
    // file from a restore that only partly worked would have the next one restore
    // the wrong thing.
    if restored == services.len() && !services.is_empty() {
        let _ = std::fs::remove_file(DNS_BACKUP_PATH);
    }
    Ok(())
}

/// The DNS servers `networksetup -getdnsservers` reports for `service`.
///
/// `None` when the answer is not one this code understands — a command that was
/// refused, or output in a shape it has never seen — so that "could not read"
/// cannot be mistaken for "no DNS servers", which is a real and different answer.
#[cfg(target_os = "macos")]
pub(super) fn dns_servers_for(service: &str) -> Option<Vec<String>> {
    let output = Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_getdnsservers(&String::from_utf8_lossy(&output.stdout))
}

/// Parses `-getdnsservers` output into the servers it names.
///
/// An empty `Some` is the "no static DNS" answer, i.e. DHCP. Anything that is
/// neither that nor a plain list of addresses yields `None`: writing a guess back
/// over a machine's DNS is worse than leaving it alone.
#[cfg(target_os = "macos")]
pub(super) fn parse_getdnsservers(output: &str) -> Option<Vec<String>> {
    let mut servers = Vec::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        // networksetup reports a refused command as `** Error: ...`.
        if line.starts_with("**") {
            return None;
        }
        if line.starts_with(NO_DNS_SERVERS) {
            return Some(Vec::new());
        }
        if line.parse::<IpAddr>().is_err() {
            return None;
        }
        servers.push(line.to_string());
    }
    Some(servers)
}

/// The `nameserver[n]` lines of `scutil --dns`, in the order they are printed.
///
/// `scutil` is the only thing on macOS that names the resolvers a machine is
/// *actually* resolving against. On a machine that takes whatever DHCP hands
/// out — every machine nobody configured by hand — those addresses exist
/// nowhere else: `networksetup -getdnsservers` answers "what is statically
/// configured" and prints [`NO_DNS_SERVERS`] instead. Reading nothing there is
/// what quietly turns the fallback chain into `8.8.8.8` and the public
/// resolvers, which for an internal zone or a split-horizon name is not a slow
/// answer but a wrong one.
///
/// The grammar is small but not empty: the output is a run of `resolver #N`
/// blocks and only some of them are general. A block carrying a `domain :` line
/// is a scoped resolver — one `/etc/resolver/<domain>` gave the machine, which
/// is what a VPN client, Docker or dnsmasq writes — and it answers for that
/// name alone, so its address is not an upstream: asked a public name, a dead
/// one costs the chain 1.5s and a live one answers NXDOMAIN, which
/// `forward_to_upstream` takes as the reply. mDNS blocks are the same shape and
/// name no server. The rest are deduplicated in order, because the "for scoped
/// queries" section repeats the global one.
#[cfg(any(target_os = "macos", test))]
pub(super) fn parse_scutil_dns(output: &str) -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    let mut block: Vec<&str> = Vec::new();
    let mut scoped = false;

    for line in output.lines() {
        let line = line.trim();
        // A new block: decide the one before it, whose nameservers are all in.
        if line.starts_with("resolver #") {
            take_resolver_block(&mut block, scoped, &mut servers);
            scoped = false;
            continue;
        }
        // `search domain[0]` is not this: it names the suffixes a *general*
        // resolver appends, and every global block carries one.
        if line.starts_with("domain") && line.contains(':') {
            scoped = true;
            continue;
        }
        let Some(address) = line
            .strip_prefix("nameserver[")
            .and_then(|rest| rest.split_once(':'))
            .map(|(_, address)| address.trim())
        else {
            continue;
        };
        if address.parse::<IpAddr>().is_err() {
            continue;
        }
        block.push(address);
    }
    take_resolver_block(&mut block, scoped, &mut servers);
    servers
}

/// Adds one `resolver #N` block's nameservers to `servers`, unless the block was
/// scoped to a domain of its own.
///
/// Kept out of the loop for the one thing that makes it more than a push: a
/// block is only decidable once its last line has been read, so the nameservers
/// are held until the next block starts and dropped whole if a `domain :` turns
/// up anywhere in it.
#[cfg(any(target_os = "macos", test))]
pub(super) fn take_resolver_block(block: &mut Vec<&str>, scoped: bool, servers: &mut Vec<String>) {
    if scoped {
        block.clear();
        return;
    }
    for address in block.drain(..) {
        if !servers.iter().any(|server| server == address) {
            servers.push(address.to_string());
        }
    }
}

/// The resolvers `scutil --dns` reports, or nothing when it cannot be run.
///
/// An empty answer is a fine one: it leaves the chain to the configured
/// upstream and the fallbacks, which is where it stood before this source
/// existed.
#[cfg(target_os = "macos")]
pub(super) fn effective_dns_servers_macos() -> Vec<String> {
    match Command::new("scutil").arg("--dns").output() {
        Ok(output) if output.status.success() => {
            parse_scutil_dns(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(_) => Vec::new(),
        Err(e) => {
            tracing::debug!("scutil --dns could not be run: {e}");
            Vec::new()
        }
    }
}

/// The DNS servers every network service is using, deduplicated in the order
/// the services are listed, followed by the ones `scutil --dns` says are in
/// effect.
///
/// A service with no static DNS contributes nothing from `networksetup`: it
/// takes whatever DHCP hands out, which is not an address that command will
/// print. [`parse_scutil_dns`] is what supplies it, and it is the common case.
#[cfg(target_os = "macos")]
pub(super) fn current_dns_servers_macos() -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    for service in network_services().unwrap_or_default() {
        for server in dns_servers_for(&service).unwrap_or_default() {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    for server in effective_dns_servers_macos() {
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    servers
}

/// Sets the DNS servers of one network service; `["empty"]` clears them, which
/// is how a service is handed back to DHCP.
#[cfg(target_os = "macos")]
pub(super) fn set_dns_servers(service: &str, servers: &[String]) -> Result<()> {
    let output = Command::new("networksetup")
        .arg("-setdnsservers")
        .arg(service)
        .args(servers)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run networksetup: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "networksetup -setdnsservers {} {}: {}",
            service,
            servers.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// The pre-hijack DNS servers recorded in [`DNS_BACKUP_PATH`], per service.
#[cfg(target_os = "macos")]
pub(super) fn read_dns_backup() -> BTreeMap<String, Vec<String>> {
    let Ok(contents) = std::fs::read_to_string(DNS_BACKUP_PATH) else {
        return BTreeMap::new();
    };
    serde_json::from_str(&contents).unwrap_or_default()
}

/// Records what `services` are using now, so a later restore can put it back.
///
/// A service that already points at a TUN address cannot say what it had before —
/// that is precisely the state this file exists to survive — so its recorded
/// answer is kept rather than overwritten with the hijack's own address.
#[cfg(target_os = "macos")]
pub(super) fn save_dns_backup(services: &[String]) {
    let recorded = read_dns_backup();
    let mut backup = BTreeMap::new();

    for service in services {
        let clean = dns_servers_for(service)
            .filter(|servers| !servers.iter().any(|server| is_tun_dns_address(server)));
        // Unreadable, or still hijacked from a previous run: whatever is on file
        // is a better answer than anything visible right now.
        let value = match clean {
            Some(servers) => Some(servers),
            None => recorded.get(service).cloned(),
        };
        if let Some(servers) = value {
            backup.insert(service.clone(), servers);
        }
    }

    if backup.is_empty() {
        return;
    }

    let Ok(json) = serde_json::to_string_pretty(&backup) else {
        return;
    };
    if let Some(parent) = Path::new(DNS_BACKUP_PATH).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!("could not create {}: {}", parent.display(), e);
            return;
        }
    }
    if let Err(e) = std::fs::write(DNS_BACKUP_PATH, json) {
        tracing::warn!(
            "could not record the pre-hijack DNS in {}: {}",
            DNS_BACKUP_PATH,
            e
        );
    }
}

#[cfg(target_os = "macos")]
pub(super) fn network_services() -> Result<Vec<String>> {
    let output = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| {
            anyhow::anyhow!("Failed to run networksetup -listallnetworkservices: {}", e)
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_network_services(&stdout))
}

/// The service names in `-listallnetworkservices` output.
///
/// The command prints a legend before the list ("An asterisk (*) denotes that a
/// network service is disabled.") and disables an entry by prefixing its *name*
/// with `*`. Filtering on a leading `*` alone therefore kept the legend and handed
/// it to `-setdnsservers` as a service name, which is where every startup's worth
/// of "networksetup failed for An asterisk (*) ..." warnings came from.
#[cfg(target_os = "macos")]
pub(super) fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('*'))
        .filter(|line| !line.contains(DISABLED_LEGEND))
        .map(str::to_string)
        .collect()
}

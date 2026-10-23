//! The addresses and the names a caller does not get to choose for itself.

use crate::error::{codes, AppError};
use crate::proxy::tun_proxy::TUN_BASE_CANDIDATES;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Refuses `addr` unless it is loopback.
///
/// `code` names what was being validated, because "not loopback" is the same
/// fact with two different fixes depending on which address it was.
///
/// Shared by both start paths: `start_proxy` calls it before the request is
/// handed to either runner, and the service repeats it on its own side because
/// a service binary built before that call existed may still be installed.
pub fn require_loopback(addr: &str, code: &str) -> Result<(), AppError> {
    let parsed = addr
        .parse::<SocketAddr>()
        .map_err(|e| AppError::cause(code, format!("{addr:?} is not a host:port address ({e})")))?;
    if parsed.ip().is_loopback() {
        Ok(())
    } else {
        Err(AppError::with_detail(
            code,
            format!(
                "{parsed} is not loopback; the local proxy has nothing authenticating in front of it"
            ),
        ))
    }
}

/// Refuses `addr` unless it is inside one of the candidate TUN blocks the DNS server can
/// answer on.
///
/// The block actually in use is only decided when the TUN interface comes up
/// (`routing::configure_interface` walks [`TUN_BASE_CANDIDATES`]), which is *after* this
/// validation runs — so an address inside any candidate block is accepted, and `retarget`
/// later moves it into the block that took. See `proxy::tun_proxy` for the block policy.
///
/// Shared by both start paths, like [`require_loopback`].
pub fn require_tun_subnet(addr: &str) -> Result<(), AppError> {
    let parsed = addr.parse::<SocketAddr>().map_err(|e| {
        AppError::cause(
            codes::SERVICE_DNS_ADDR_OUTSIDE_TUN,
            format!("{addr:?} is not a host:port address ({e})"),
        )
    })?;

    // Every candidate is a /24, so the network part is everything but the last octet.
    let in_candidate = |ip: &Ipv4Addr| {
        TUN_BASE_CANDIDATES
            .iter()
            .any(|base| u32::from(*ip) & 0xFFFF_FF00 == u32::from(*base))
    };

    match parsed.ip() {
        IpAddr::V4(ip) if in_candidate(&ip) => Ok(()),
        other => Err(AppError::with_detail(
            codes::SERVICE_DNS_ADDR_OUTSIDE_TUN,
            format!(
                "{other} is outside every candidate TUN block ({TUN_BASE_CANDIDATES:?}), \
                 where the TUN DNS server answers"
            ),
        )),
    }
}

/// The longest a TUN interface name may be.
///
/// One rule for every platform, so the desktop and the service cannot disagree
/// about a name: they are the same machine, and a rule that differed between
/// them would let a name through on one side and be refused on the other. 64 is
/// a comfortable length for a Windows adapter alias. Linux's own limit
/// (`IFNAMSIZ`, 16 with the terminator, so 15 usable) still applies there, and
/// the kernel reports its own clear error when a name is too long for it — which
/// is a better answer than a rule that would refuse a name Windows accepts.
const MAX_TUN_NAME_LEN: usize = 64;

/// Refuses `name` unless it is a name an interface can carry.
///
/// The name used to be written into a PowerShell script inside single quotes, in
/// the service, which runs as LocalSystem: a quote in it ended the string, and
/// what followed was PowerShell source. The rule here is deliberately narrow —
/// letters, digits, `-`, `_` and `.`, and short — because the name is an
/// identifier, not a text anybody has a reason to put punctuation in.
///
/// Shared by both start paths, like [`require_loopback`]: the desktop checks it
/// so the caller gets the precise error, and the service checks it again because
/// it is a separate process, on its own version, and it does not trust the
/// desktop's answer.
pub fn require_tun_name(name: &str) -> Result<(), AppError> {
    let len = name.chars().count();

    if len == 0 {
        return Err(tun_name_refused("it is empty", len));
    }
    if len > MAX_TUN_NAME_LEN {
        return Err(tun_name_refused(
            &format!("it is {len} characters long, more than the {MAX_TUN_NAME_LEN} allowed"),
            len,
        ));
    }
    if let Some((at, _)) = name.char_indices().find(|(_, c)| !is_tun_name_char(*c)) {
        return Err(tun_name_refused(
            &format!(
                "character {} is not a letter, a digit, '-', '_' or '.'",
                at + 1
            ),
            len,
        ));
    }
    // A leading dash is read as an option by the tools the name is handed to
    // (`ip route … dev <name>`, `netsh … name=<name>`).
    if name.starts_with('-') {
        return Err(tun_name_refused(
            "it starts with '-', which a tool could read as an option",
            len,
        ));
    }
    // "." and ".." are path names, not interface names.
    if name.chars().all(|c| c == '.') {
        return Err(tun_name_refused("it consists of dots only", len));
    }

    Ok(())
}

/// The characters a TUN interface name may be made of.
fn is_tun_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

/// The error a refused interface name produces.
///
/// The value is not in the message, only its shape: the name is caller-supplied
/// text, and a message that quotes it quotes whatever the caller put there.
/// There is no credential in a name today, and the rule is worth keeping that
/// way.
fn tun_name_refused(reason: &str, len: usize) -> AppError {
    AppError::with_detail(
        codes::PROXY_START_FAILED,
        format!(
            "the TUN interface name is refused: {reason}. A name must be 1 to {MAX_TUN_NAME_LEN} \
             characters long, made only of ASCII letters, digits, '-', '_' and '.', must not start \
             with '-', and must not consist of dots only; the name given is {len} characters long"
        ),
    )
}

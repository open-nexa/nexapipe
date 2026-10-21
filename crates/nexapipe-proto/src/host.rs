//! One host-pattern rule, shared by every side that has to agree on a name.
//!
//! # Why this crate holds it
//!
//! Three places answer "is this host one of mine?", and they used to answer it
//! three different ways:
//!
//! - the **server**, matching a request or an L4 preface against a route's
//!   `host_pattern` and against a client's `allow_hosts`;
//! - the **client library**, deciding whether a `CONNECT` target is one it
//!   proxies and whether a DNS query is for a name that belongs in the tunnel;
//! - the **desktop app**, which has a second DNS server of its own and
//!   therefore a second copy of the same question.
//!
//! They drifted, and the drift was not cosmetic. The server's rule is strict —
//! `*.example.com` is the subdomains and not the apex — while the client's was
//! loose: a bare `example.com` meant the apex *and* every subdomain, and a
//! wildcard without a dot was a bare `ends_with`, so `*example.com` also
//! matched `notexample.com`. A name the client decided to tunnel could then
//! be a name the server had no route for: the tunnel carried it, the server
//! answered `NoRoute`, and the failure looked like the tunnel was broken
//! rather than like the two halves spelled the pattern differently.
//!
//! The desktop made it worse by accident: on Windows the query is
//! local-delivered to the app's own DNS server, and on macOS and Linux it
//! traverses the TUN and reaches the library's. The same config, the same
//! name, two different answers, decided by the platform.
//!
//! So the rule lives here, in the crate both sides already link, and there is
//! exactly one of it.
//!
//! # The rule
//!
//! ```text
//! example.com      that name, exactly
//! *.example.com    its subdomains, and not the apex
//! *                every name
//! ```
//!
//! The dot in the wildcard is load-bearing. Without it a wildcard is a bare
//! `ends_with`, so `*example.com` would also match `notexample.com` — a host
//! that merely ends in the same letters and belongs to somebody else
//! entirely. A pattern that cannot be matched with is refused where it is
//! configured, by [`pattern_error`], rather than quietly matching more than it
//! says.
//!
//! # What the OS-level DNS scope does with this
//!
//! The per-domain DNS hijack has to hand a *set* of names to the operating
//! system, and the operating system's own mechanisms are coarser than this
//! rule: a resolver file for `example.com` covers the apex and its
//! subdomains whatever the pattern was. That coarseness is fine, because it
//! only decides **which resolver gets the query** — the question of whether a
//! particular name is one to hand a virtual address for is answered per
//! query, with the rule below, and a name outside it is forwarded to the real
//! resolver and resolves for real.

use std::borrow::Cow;

/// Compares host names the way DNS does: case-insensitively, without a
/// trailing dot.
///
/// A `Host` header may arrive in any case (`API.example.com`) and may carry a
/// fully-qualified trailing dot (`api.example.com.`) — both name the same host
/// the pattern was written for. Matching them raw would let such a request
/// slip past its route and reach a different service entirely. Both the
/// pattern and every input go through here, so a config written with
/// uppercase letters keeps working too.
///
/// **The result borrows when it can.** A name that is already folded — and
/// that is nearly every name a request carries — is handed back as it came
/// in, and the only copy this makes is the one a name with a capital letter
/// needs. The trimming was always a borrow; the lower-casing was not, and it
/// was the whole of the cost.
pub fn normalize_host(host: &str) -> Cow<'_, str> {
    // Every trailing dot, not just one: a name may arrive carrying more than
    // the single dot of a fully-qualified spelling, and leaving one behind
    // makes it a different string than the pattern it names.
    let host = host.trim_end_matches('.');
    // An IPv6 literal is bracketed in a `Host` header — that is how its port is
    // told apart from the address — and may be written the same way in a
    // config. The brackets are not part of the name, so both sides lose them
    // here and a pattern spelled `[::1]` matches a request for `[::1]:8080`.
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(host.to_ascii_lowercase())
    } else {
        Cow::Borrowed(host)
    }
}

/// The folded form of a *pattern*.
///
/// The case is folded, as for a host, and the trailing dots and the brackets
/// are taken off — but not when taking them off would leave the catch-all.
/// `*.`, `*..` and `[*]` all fold to `*`, and a pattern that means "every
/// host" where the configuration said something narrower is the one mistake
/// this rule must not make: such a pattern keeps its own shape here, and so
/// matches nothing rather than everything.
///
/// Borrows when there is nothing to fold, for the reason
/// [`normalize_host`] gives.
pub fn normalize_pattern(pattern: &str) -> Cow<'_, str> {
    let folded = normalize_host(pattern);
    if folded == "*" && pattern != "*" {
        // The fold would have widened it into the catch-all.
        Cow::Owned(pattern.to_ascii_lowercase())
    } else {
        folded
    }
}

/// Whether a (already folded) host matches a (already folded) pattern.
///
/// The one host-matching rule: an exact name, a `*.suffix` wildcard, or the
/// bare `*` catch-all. The apex is not under the wildcard, which is what DNS
/// means by `*.example.com`.
///
/// A `*` followed by anything but a dot matches nothing. Such a pattern is
/// refused where it is configured, by [`pattern_error`], so reaching that
/// branch means the pattern came from somewhere that skipped the check — and
/// the one thing it must not do is quietly match more than it says.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix('*') {
        None => pattern == host,
        // `*` on its own is the catch-all: how "send everything here" is
        // spelled now that there is no default backend.
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('.')
            .and_then(|suffix| host.strip_suffix(suffix))
            // The label boundary: the apex itself is not under the wildcard,
            // which is what DNS means by `*.example.com`.
            .is_some_and(|prefix| prefix.ends_with('.')),
    }
}

/// Why `pattern` cannot be matched with, or `None` when it can.
///
/// Checked when a config is loaded rather than left to the matcher, because the
/// failure mode of a loose wildcard is silent: `allow_hosts = ["*iakl.top"]`
/// looks like it names one domain and in fact authorizes every host ending in
/// those letters, `eviliakl.top` included. Refusing to start is the only
/// answer an operator can see.
///
/// A leading dot is refused for the same reason, and it is the one spelling
/// that used to be accepted on the client and never worked: `.example.com` is
/// the *suffix* spelling the operating system's own resolver mechanisms use
/// (`/etc/resolver/example.com`, a systemd-resolved routing domain), not a
/// pattern here. A pattern is a name (`example.com`), a dotted wildcard
/// (`*.example.com`) or the catch-all (`*`).
pub fn pattern_error(pattern: &str) -> Option<String> {
    if pattern.is_empty() {
        return Some("is empty; name the host, or use \"*\" for every host".to_string());
    }

    // A bare dot is an empty name: the trailing dots are folded away, and what
    // is left names nothing.
    if pattern.trim_end_matches('.').is_empty() {
        return Some("is empty; name the host, or use \"*\" for every host".to_string());
    }

    if let Some(rest) = pattern.strip_prefix('.').filter(|rest| !rest.is_empty()) {
        return Some(format!(
            "\"{pattern}\" starts with a dot, which is the suffix spelling a resolver uses \
             and not a pattern: write \"{rest}\" for that host, or \"*.{rest}\" for its \
             subdomains"
        ));
    }

    // A pattern that folds into the catch-all is not the catch-all: `*.`,
    // `*..` and `[*]` all do. A pattern that means "every host" where the
    // configuration said something narrower is the one mistake this rule must
    // not make — it is refused here, where an operator can see it, and matched
    // as nothing there.
    //
    // This refusal comes first, ahead of the wildcard's own shape: a spelling
    // that folds into the catch-all is refused for that reason whichever way
    // it is written, and the catch-all is the reason an operator can act on.
    let folds_to_catch_all =
        pattern.contains('*') && pattern != "*" && normalize_host(pattern) == "*";
    if folds_to_catch_all {
        return Some(catch_all_message(pattern));
    }

    // Not a wildcard at all, so there is nothing a `*` could get wrong.
    let rest = pattern.strip_prefix('*')?;
    match rest.strip_prefix('.') {
        None if rest.is_empty() => {}
        Some(suffix) if !suffix.is_empty() => {}
        _ => {
            return Some(format!(
                "\"{pattern}\" has to be \"*\" or start with \"*.\": the dot is what marks the \
                 label boundary, and without it the pattern also matches any host that merely \
                 ends in the same letters"
            ));
        }
    }
    None
}

/// The refusal for a pattern that is the catch-all in another spelling.
fn catch_all_message(pattern: &str) -> String {
    format!(
        "\"{pattern}\" is the catch-all \"*\" in another spelling, and that means every host: \
         write \"*\" for every host, or a name for the host you mean"
    )
}

/// Whether `host` matches any of `patterns`.
///
/// The list is held as it was configured — a pattern may still carry its `*` —
/// and the host is folded once. Each pattern is folded as it is examined, and
/// **a pattern that is already folded costs nothing to examine**: the fold
/// borrows it rather than copying it. That is the whole cost of this call
/// for a list of names written the way names are usually written.
///
/// A pattern that [`pattern_error`] would refuse matches nothing here, which
/// is the safe direction: a configuration that was never meant to be loaded
/// cannot widen what a client proxies.
pub fn host_matches_any(patterns: &[String], host: &str) -> bool {
    let host = normalize_host(host);
    patterns.iter().any(|pattern| {
        let folded = normalize_pattern(pattern);
        host_matches(&folded, &host)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(p: &str) -> String {
        normalize_host(p).into_owned()
    }

    /// A name that is already folded is borrowed, not copied.
    ///
    /// This is the whole point of the fold returning a [`Cow`]: a request
    /// carries a name that is already in the shape a pattern is written in,
    /// and asking whether it matches used to allocate for every pattern it
    /// was compared against.
    #[test]
    fn a_folded_name_is_borrowed_rather_than_copied() {
        assert!(
            matches!(normalize_host("example.com"), Cow::Borrowed(_)),
            "a name with nothing to fold is handed back as it came in"
        );
        assert!(
            matches!(normalize_pattern("*.example.com"), Cow::Borrowed(_)),
            "and so is a pattern"
        );
        assert!(
            matches!(normalize_host("Example.com"), Cow::Owned(_)),
            "a name with a capital letter needs a copy"
        );
        assert!(
            matches!(normalize_pattern("*.Example.com"), Cow::Owned(_)),
            "and so does a pattern"
        );
    }

    #[test]
    fn an_exact_pattern_matches_only_itself() {
        assert!(host_matches(&pattern("example.com"), "example.com"));
        assert!(!host_matches(&pattern("example.com"), "www.example.com"));
        assert!(!host_matches(&pattern("example.com"), "notexample.com"));
    }

    #[test]
    fn a_wildcard_covers_the_subdomains_and_not_the_apex() {
        let p = pattern("*.example.com");
        assert!(host_matches(&p, "www.example.com"));
        assert!(host_matches(&p, "a.b.example.com"));
        assert!(!host_matches(&p, "example.com"));
        // The label boundary is what keeps a host that merely ends in the same
        // letters out.
        assert!(!host_matches(&p, "notexample.com"));
    }

    #[test]
    fn the_catch_all_matches_everything() {
        assert!(host_matches(&pattern("*"), "example.com"));
        assert!(host_matches(&pattern("*"), ""));
    }

    #[test]
    fn a_wildcard_without_a_dot_matches_nothing() {
        // The pattern is refused where it is configured; the matcher must not
        // fall back to a bare `ends_with` when one slips through.
        let p = pattern("*example.com");
        assert!(!host_matches(&p, "notexample.com"));
        assert!(!host_matches(&p, "example.com"));
        assert!(pattern_error("*example.com").is_some());
    }

    #[test]
    fn names_are_folded_before_they_are_compared() {
        assert!(host_matches(
            &pattern("EXAMPLE.com"),
            &pattern("example.com")
        ));
        assert!(host_matches(
            &pattern("example.com"),
            &pattern("Example.COM")
        ));
        // A fully-qualified trailing dot is the same name.
        assert!(host_matches(
            &pattern("example.com"),
            &pattern("example.com.")
        ));
        // And an IPv6 literal is the same name with or without its brackets.
        assert!(host_matches(&pattern("[::1]"), &pattern("::1")));
    }

    #[test]
    fn only_the_bare_star_and_a_dotted_wildcard_are_accepted() {
        assert!(pattern_error("*").is_none());
        assert!(pattern_error("*.example.com").is_none());
        assert!(pattern_error("example.com").is_none());
        assert!(pattern_error("").is_some());
        assert!(pattern_error("*example.com").is_some());
        assert!(pattern_error("*.").is_some());
    }

    #[test]
    fn a_leading_dot_is_the_resolver_spelling_and_not_a_pattern() {
        // The spelling the operating system's own mechanisms use, where a
        // resolver file for `example.com` covers the apex and its subdomains.
        // It is not a pattern here, and it never was on the server.
        assert!(pattern_error(".example.com").is_some());
        assert!(pattern_error(".").is_some());
        // And it matches nothing, rather than quietly matching the name.
        let p = pattern(".example.com");
        assert!(!host_matches(&p, "example.com"));
        assert!(!host_matches(&p, "www.example.com"));
    }

    #[test]
    fn a_list_is_matched_with_the_same_rule() {
        let patterns = vec![pattern("example.com"), pattern("*.other.test")];
        assert!(host_matches_any(&patterns, "example.com"));
        assert!(host_matches_any(&patterns, "www.other.test"));
        assert!(!host_matches_any(&patterns, "www.example.com"));
        assert!(!host_matches_any(&patterns, "other.test"));
    }

    #[test]
    fn a_list_may_carry_its_own_wildcards() {
        // The list is held as it was configured, so the `*` is still on it.
        let patterns = vec!["*.example.com".to_string()];
        assert!(host_matches_any(&patterns, "www.example.com"));
        assert!(!host_matches_any(&patterns, "example.com"));
    }

    /// A pattern that folds into the catch-all is not the catch-all.
    ///
    /// `*.`, `*..` and `[*]` all fold to `*`, and a pattern that means "every
    /// host" where the configuration said something narrower is the one mistake
    /// this rule must not make: a route that serves every host, or a client's
    /// allow-list that authorizes every host, because of a spelling nobody
    /// meant.
    #[test]
    fn a_pattern_that_folds_into_the_catch_all_matches_nothing() {
        for pattern in ["*.", "*..", "[*]"] {
            assert!(
                pattern_error(pattern).is_some(),
                "{pattern:?} is the catch-all in another spelling and must be refused"
            );
            let folded = normalize_pattern(pattern);
            assert!(!host_matches(&folded, "example.com"), "{pattern:?}");
            assert!(!host_matches(&folded, "www.example.com"), "{pattern:?}");
            assert!(
                !host_matches_any(&[pattern.to_string()], "example.com"),
                "{pattern:?}"
            );
        }
        // The catch-all itself is still the catch-all.
        assert!(pattern_error("*").is_none());
        assert!(host_matches(&normalize_pattern("*"), "example.com"));
        assert!(host_matches_any(&["*".to_string()], "example.com"));
    }

    /// The fold takes the case and the trailing dots off a pattern, and the
    /// shape of a pattern that folds into the catch-all is kept.
    #[test]
    fn a_pattern_keeps_its_shape_when_it_is_folded() {
        assert_eq!(normalize_pattern("EXAMPLE.com."), "example.com");
        assert_eq!(normalize_pattern("*.example.com."), "*.example.com");
        assert_eq!(normalize_pattern("*."), "*.");
        assert_eq!(normalize_pattern("[*]"), "[*]");
    }
}

//! Which pools serve a name.
//!
//! The group is asked for a host far more often than it is asked for a
//! backend, and the answer is the one rule the proxy uses: the exact name
//! first, and after it the most specific wildcard that covers the name.

use nexapipe_proto::normalize_host;

use std::collections::HashMap;
use std::sync::Arc;

use super::DomainPools;
use super::EndpointGroup;

/// The wildcard patterns of a set of domains, keyed by the name they cover.
///
/// `*.example.com` is keyed by `example.com`, and the catch-all `*` by the
/// empty string. A pattern that is not a wildcard is left out: the lookup
/// finds an exactly-named domain in the map itself, and a pattern that is not
/// a wildcard cannot cover a name that map did not find.
///
/// A pattern that matches nothing is left out too — `*.` is the catch-all in
/// another spelling, and the rule in `nexapipe-proto` refuses it and matches
/// it with nothing. It must not be given the catch-all's own key, which is
/// what it would otherwise be indexed under.
pub(super) fn wildcards_of(
    domains: &HashMap<String, Arc<DomainPools>>,
) -> HashMap<String, Arc<DomainPools>> {
    let mut wildcards = HashMap::new();
    for (pattern, pools) in domains {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // A pattern with an **empty** suffix — `*.` — is the catch-all in
            // another spelling, and the rule in `nexapipe-proto` refuses it
            // and matches it with nothing: a configuration that was never
            // meant to be loaded cannot widen what a client proxies.
            //
            // It is not a wildcard here either, so it is not indexed: the
            // catch-all is keyed by the empty name, and a pattern that
            // matches nothing must not be given that key — it would answer
            // for every host, and it would do so by whichever of the two the
            // map happened to be walked in first.
            if !suffix.is_empty() {
                wildcards.insert(suffix.to_string(), pools.clone());
            }
        } else if pattern == "*" {
            wildcards.insert(String::new(), pools.clone());
        }
    }
    wildcards
}

impl EndpointGroup {
    /// The mapping that serves `host`, by the one rule the proxy uses.
    ///
    /// The same question the membership check asks, asked the same way: the
    /// client tunnels `www.example.com` because `*.example.com` covers it, and
    /// the backend it is sent to is named by that same list. A lookup that
    /// knew only exact names and parent labels would not find the
    /// `*.example.com` mapping at all — the request would go to the default
    /// backend or to none: the two halves of one client disagreeing about a
    /// pattern the configuration spells once.
    ///
    /// The exact name comes first, and a wildcard only after it: a bare
    /// pattern is that name and nothing else, so `example.com` never answers
    /// for `www.example.com`. Where more than one wildcard covers the host,
    /// the most specific one answers — the longest suffix, the way DNS reads
    /// a name.
    pub(super) fn pools_for(&self, host: &str) -> Option<&Arc<DomainPools>> {
        let host = normalize_host(host);

        if let Some(pools) = self.domains.get(host.as_ref()) {
            return Some(pools);
        }

        // The name's **label-aligned** suffixes, longest first. A pattern
        // `*.example.com` covers the names that end with `example.com` at a
        // label boundary, and those are exactly the suffixes below — so the
        // first one that is in the index is the longest pattern that covers
        // the name, which is the answer the scan gave.
        let mut suffix = host.as_ref();
        while let Some((_, rest)) = suffix.split_once('.') {
            suffix = rest;
            if let Some(pools) = self.wildcards.get(suffix) {
                return Some(pools);
            }
        }
        // The catch-all, `*`, covers everything, and is keyed by nothing.
        self.wildcards.get("")
    }
}

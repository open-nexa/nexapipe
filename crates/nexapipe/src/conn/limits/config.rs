//! Where the ceilings come from.
//!
//! Three sources name them: the `[limits]` section of the configuration file,
//! the environment, and the default neither of them names. This file is the
//! part that reads the first two and settles on the number the server runs
//! with, so that every accept path and every body reader asks the same
//! question and gets the same answer.

use super::budget::{DEFAULT_MAX_BODY_BYTES_GLOBAL, ENV_MAX_BODY_BYTES_GLOBAL};
use super::connections::{
    DEFAULT_MAX_CONNECTIONS_GLOBAL, DEFAULT_MAX_CONNECTIONS_PER_PEER, ENV_MAX_CONNECTIONS_GLOBAL,
    ENV_MAX_CONNECTIONS_PER_PEER,
};
use super::streams::{DEFAULT_MAX_STREAMS_GLOBAL, ENV_MAX_STREAMS_GLOBAL};
use serde::Deserialize;

/// The `[limits]` section: the ceilings the whole process runs under.
///
/// Every key is optional, and every default is the constant the server used
/// before this section existed, so a config that does not mention `[limits]`
/// behaves exactly as it did — the section is a way to *write down* a ceiling,
/// not a new one.
///
/// **Unknown keys are refused here**, for the reason they are refused under
/// `[peers]`: a misspelled limit is a limit that silently does not apply, and
/// the process then runs with a ceiling nobody wrote down. Refused at load,
/// where the error names the key, rather than ignored at runtime, where
/// nothing would say so.
///
/// **A zero is refused at startup**, in [`Limits::resolve`]: it would refuse
/// every connection, which is a typo rather than a setting.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Concurrent connections one peer may hold.
    pub max_connections_per_peer: Option<usize>,
    /// Concurrent connections the whole process may hold.
    pub max_connections_global: Option<usize>,
    /// Concurrent streams the whole process may have in flight.
    pub max_streams_global: Option<usize>,
    /// Bytes of request bodies the whole process may hold at once.
    ///
    /// The same ceiling covers the per-stream copy buffers: the budget is the
    /// process's ceiling on the bytes it holds, and a copy buffer is one of
    /// them. A peer that opens many streams pays for those buffers out of
    /// this budget, which is what makes the ceiling the process's memory
    /// ceiling rather than only a ceiling on request bodies.
    pub max_body_bytes: Option<usize>,
}

/// What the environment says about the ceilings.
///
/// Read once at startup, like everything else here. A value that is not a
/// positive number is a warning and not an outage: the environment is set in
/// a Dockerfile or a shell profile, and a bad value there should not keep the
/// server from starting — the default is used instead and the log says so.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnvCaps {
    pub max_connections_per_peer: Option<usize>,
    pub max_connections_global: Option<usize>,
    pub max_streams_global: Option<usize>,
    pub max_body_bytes: Option<usize>,
}

impl EnvCaps {
    /// Reads the four environment variables that name these ceilings.
    pub fn from_environment() -> Self {
        Self {
            max_connections_per_peer: cap_from_env(ENV_MAX_CONNECTIONS_PER_PEER),
            max_connections_global: cap_from_env(ENV_MAX_CONNECTIONS_GLOBAL),
            max_streams_global: cap_from_env(ENV_MAX_STREAMS_GLOBAL),
            max_body_bytes: cap_from_env(ENV_MAX_BODY_BYTES_GLOBAL),
        }
    }
}

/// The ceilings the process runs with, resolved once at startup.
///
/// The file answers "was this key written?"; this answers "how much may this
/// process do at once?", which is the question every accept path and every
/// body reader actually asks. Reading either side of the config directly would
/// put an `.unwrap_or(...)` in each of them, and one of them would eventually
/// disagree with the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_connections_per_peer: usize,
    pub max_connections_global: usize,
    pub max_streams_global: usize,
    pub max_body_bytes: usize,
}

impl Limits {
    /// Resolves the ceilings from the config and the environment.
    ///
    /// **The environment wins over the config.** It is the last thing an
    /// operator sets, and in a container it is often the only thing they can
    /// set without editing a file the image does not own. A key both name is
    /// a *warning* rather than a refusal: the effective ceilings are logged at
    /// startup, so the ambiguity is visible rather than silent, and refusing to
    /// boot over a resource knob is a heavier hand than this deserves.
    ///
    /// **A zero in the config is refused at startup**, because it would refuse
    /// every connection and the file is somewhere the operator can read the
    /// error. It is refused *before* the environment is consulted: the rule is
    /// that the environment overrides a value that works, not one that does
    /// not, so a zero in the file is a typo whether or not a variable happens
    /// to name the same key. The environment keeps the older rule of ignoring
    /// a value it cannot use, because a bad variable in a Dockerfile should
    /// not take the listener offline.
    pub fn resolve(config: &LimitsConfig, env: &EnvCaps) -> anyhow::Result<Self> {
        Ok(Self {
            max_connections_per_peer: resolve_one(
                "[limits] max_connections_per_peer",
                config.max_connections_per_peer,
                env.max_connections_per_peer,
                ENV_MAX_CONNECTIONS_PER_PEER,
                DEFAULT_MAX_CONNECTIONS_PER_PEER,
            )?,
            max_connections_global: resolve_one(
                "[limits] max_connections_global",
                config.max_connections_global,
                env.max_connections_global,
                ENV_MAX_CONNECTIONS_GLOBAL,
                DEFAULT_MAX_CONNECTIONS_GLOBAL,
            )?,
            max_streams_global: resolve_one(
                "[limits] max_streams_global",
                config.max_streams_global,
                env.max_streams_global,
                ENV_MAX_STREAMS_GLOBAL,
                DEFAULT_MAX_STREAMS_GLOBAL,
            )?,
            max_body_bytes: resolve_one(
                "[limits] max_body_bytes",
                config.max_body_bytes,
                env.max_body_bytes,
                ENV_MAX_BODY_BYTES_GLOBAL,
                DEFAULT_MAX_BODY_BYTES_GLOBAL,
            )?,
        })
    }
}

/// One ceiling, from whichever source names it.
///
/// The order is the environment, then the config, then the default — see
/// [`Limits::resolve`] for why the environment outranks the file.
fn resolve_one(
    key: &str,
    from_config: Option<usize>,
    from_env: Option<usize>,
    env_var: &str,
    default: usize,
) -> anyhow::Result<usize> {
    // A zero from the environment is ignored rather than obeyed: it would
    // refuse everything, and the environment is a source an operator cannot
    // always edit. [`EnvCaps::from_environment`] already drops such a value,
    // so this is the belt to that braces.
    let from_env = from_env.filter(|value| *value > 0);
    if let Some(value) = from_config {
        if value == 0 {
            // Refused before the environment is consulted, on purpose. The
            // rule is "the environment overrides a value that works, not one
            // that does not": a zero is refused whatever else names the key,
            // because it is a typo in a file the operator can read, and a typo
            // hidden behind an environment variable is a typo that waits for
            // the day the variable goes away.
            anyhow::bail!(
                "{key} is 0: a ceiling of 0 would refuse every connection rather than bound them, \
                 which is a typo rather than a setting. The smallest useful value is 1. It is \
                 refused even when {env_var} is set, because the environment overrides a value \
                 that works, not one that does not"
            );
        }
        if let Some(env_value) = from_env {
            tracing::warn!(
                "{env_var}={env_value} and {key}={value} are both set; the environment wins and the \
                 config's value is ignored. Remove one of them to say which was meant"
            );
            return Ok(env_value);
        }
        return Ok(value);
    }
    Ok(from_env.unwrap_or(default))
}

/// One env var to one cap, with the same "a bad value is a warning, not an
/// outage" rule the config file follows for a number it cannot use.
///
/// `None` means the variable is absent or unusable, and the caller falls back
/// to the config or the default.
fn cap_from_env(var: &str) -> Option<usize> {
    let Ok(raw) = std::env::var(var) else {
        return None;
    };
    match parse_max(&raw) {
        Some(max) => Some(max),
        None => {
            tracing::warn!("{var}={raw} is not a positive number, ignoring it");
            None
        }
    }
}

/// A cap, or `None` when `raw` is not a positive number.
///
/// Split out from [`max_connections_per_peer`] so the parsing is testable
/// without touching the process environment.
pub(super) fn parse_max(raw: &str) -> Option<usize> {
    match raw.trim().parse::<usize>() {
        // Zero would refuse every connection, which is a typo rather than a
        // setting: falling back keeps one bad env var from taking the listener
        // offline.
        Ok(0) | Err(_) => None,
        Ok(n) => Some(n),
    }
}

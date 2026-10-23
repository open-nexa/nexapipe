//! The strategy: what the operator asked the machine's DNS to do.
//!
//! The choice is made where it can be seen — in the settings — and the
//! program does not change it afterwards.

use anyhow::Result;

/// What the operator asked the machine's DNS to do.
///
/// The strategy is chosen by the person who set the app up, not by whatever the
/// platform happened to allow. Two machines that could both be scoped, one
/// choosing the global strategy and one not, differ in ways nobody can see
/// afterwards — so the choice is made where it can be seen, and it is not
/// changed afterwards by the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsStrategy {
    /// Only the configured domains resolve through the TUN. Everything else
    /// keeps resolving where it always did. The default, and the one that
    /// leaves the machine's own names alone.
    #[default]
    Scoped,
    /// Every query on the machine goes to the TUN resolver.
    Global,
    /// The machine's DNS is not touched at all. The local DNS server still
    /// runs, so a PAC file or a hosts entry can point at it.
    None,
}

impl DnsStrategy {
    /// The spelling in the configuration and in the settings page.
    pub fn name(&self) -> &'static str {
        match self {
            DnsStrategy::Scoped => "scoped",
            DnsStrategy::Global => "global",
            DnsStrategy::None => "none",
        }
    }

    /// Reads the spelling.
    ///
    /// A value that is present but unknown is **refused**, the way the rest of
    /// the settings are: this one says what happens to the machine's DNS, and
    /// a typo must not be read as "leave it alone" or "replace all of it" —
    /// those are two very different machines.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "scoped" => Ok(DnsStrategy::Scoped),
            "global" => Ok(DnsStrategy::Global),
            "none" => Ok(DnsStrategy::None),
            other => anyhow::bail!(
                "unknown DNS strategy {other:?}; expected \"scoped\", \"global\" or \"none\""
            ),
        }
    }
}

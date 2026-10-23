//! The status of a link, and how it is written down.
//!
//! A link is a path to a peer: direct, over a relay, or through a custom
//! one. The panel shows which, and the round-trip time the connection
//! measured — which is only a measurement when the connection says so.

use iroh::EndpointId;
use iroh::endpoint::Connection;

use serde::{Deserialize, Serialize};

/// How traffic currently reaches a backend: direct, or through a relay.
///
/// iroh keeps several paths open per connection and marks exactly one of them *selected* — the
/// path application data actually takes. That, and not "a direct path exists", decides the
/// label: a connection that has opened a UDP path but still routes over the relay is a relay
/// connection until iroh promotes it.
///
/// This is the **runtime** answer on purpose. The relay URL in the configuration (or in an
/// invite) only names a relay that *may* be used; it says nothing about whether the hole punch
/// succeeded, so a UI must never infer the icon from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// The selected path is a direct UDP path to the backend.
    Direct,
    /// The selected path goes through a relay server.
    Relay,
    /// No path is known: nothing has connected yet, or the connection has no path.
    #[default]
    Unknown,
}

impl LinkKind {
    /// The stable name sent across the JNI and Tauri boundaries.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Unknown => "unknown",
        }
    }

    /// Tolerant by design: this only ever feeds an icon, so an unfamiliar spelling means
    /// [`Self::Unknown`] rather than an error.
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "direct" => Self::Direct,
            "relay" => Self::Relay,
            _ => Self::Unknown,
        }
    }

    /// Reads the kind off a live connection.
    ///
    /// A closed connection has no path left to report, so the caller gets [`Self::Unknown`]
    /// instead of a stale answer.
    pub fn of(conn: &Connection) -> Self {
        if conn.close_reason().is_some() {
            return Self::Unknown;
        }

        let paths = conn.paths();
        for path in paths.iter() {
            if path.is_selected() {
                return if path.is_ip() {
                    Self::Direct
                } else if path.is_relay() {
                    Self::Relay
                } else {
                    Self::Unknown
                };
            }
        }

        // Paths are open but none is selected (the handshake is still settling). A direct path,
        // once opened, is the one iroh will promote, so it outranks an also-open relay path.
        let mut has_relay = false;
        for path in paths.iter() {
            if path.is_ip() {
                return Self::Direct;
            }
            has_relay |= path.is_relay();
        }
        if has_relay {
            Self::Relay
        } else {
            Self::Unknown
        }
    }
}

/// How a backend is reached right now, and how long a round trip takes.
///
/// The two belong together: the round trip is only meaningful for the path
/// that is carrying the traffic, and the path can change under the reading —
/// a direct path that opens replaces a relay one, and with it the latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkStatus {
    /// Whether traffic goes straight to the peer or through a relay.
    pub kind: LinkKind,
    /// The round-trip time of the path carrying the traffic.
    ///
    /// `None` means "not measured": a connection that has just opened has no
    /// sample yet, a closed one has none either, and a path iroh cannot
    /// measure — a relay that does not report — has none at all. It is not a
    /// zero, and a UI must not draw it as one.
    ///
    /// The reading is also `None` while the path still carries quinn's initial
    /// guess rather than a measurement — see `rtt_of`.
    pub rtt: Option<std::time::Duration>,
}

impl LinkStatus {
    /// Reads both halves off a live connection.
    ///
    /// A closed connection has no path left to report, so the caller gets
    /// [`LinkStatus::default`] rather than a stale answer.
    pub fn of(conn: &Connection) -> Self {
        let kind = LinkKind::of(conn);
        if kind == LinkKind::Unknown {
            return Self::default();
        }
        Self {
            kind,
            rtt: rtt_of(conn),
        }
    }
}

/// The wire form of one link reading: `<endpoint id>=<kind>/<rtt in ms>`.
///
/// The JNI boundary carries the readings in this form and the Kotlin side reads
/// them back: the id, the kind, and the round trip in whole milliseconds.
/// `-` stands for a reading with no sample, so that an unmeasured path is not
/// read as a round trip of zero milliseconds.
///
/// A function of its own so that the form is testable without an endpoint:
/// the Kotlin decoder has its own tests, and the two halves of a contract
/// that only one side tests can drift apart without anything failing.
pub fn encode_link_status(id: &EndpointId, status: &LinkStatus) -> String {
    let rtt = match status.rtt {
        Some(rtt) => rtt.as_millis().to_string(),
        None => "-".to_string(),
    };
    format!("{}={}/{}", id, status.kind.as_str(), rtt)
}

/// The round-trip time of the path carrying the traffic, if it can be read.
///
/// The selected path is the one the traffic takes, so that is the one whose
/// latency is worth showing.
///
/// Two readings are not measurements, and are reported as `None` rather than
/// as a number:
///
/// - **quinn's guess.** The RTT estimator of a path starts at the transport's
///   [`INITIAL_RTT`](crate::transport::INITIAL_RTT) and holds it until the
///   path has something to say. A path selected a moment ago — a direct path
///   that just won hole punching, a relay path that just became the selected
///   one — therefore reads as the guess, which is a number nobody measured.
/// - **anything below a millisecond.** The UI draws whole milliseconds, and a
///   reading that rounds to zero is drawn as a number nobody made.
///
/// The guess is recognised by its value, and quinn leaves it in more than one
/// way. A path validation measures the round trip of its challenge and puts
/// that in its place, which is a measurement of its own and is reported as
/// one; a path opened for the same peer address while another validated path
/// to that address exists starts from that path's conservative estimate rather
/// than from the initial RTT — quinn looks for a validated path on the same
/// network path, so a direct path and a relay path do not seed each other. A
/// round trip that happens to land exactly on the initial RTT is reported as
/// no measurement at all.
pub(super) fn rtt_of(conn: &Connection) -> Option<std::time::Duration> {
    let paths = conn.paths();
    for path in paths.iter() {
        if path.is_selected() {
            let rtt = conn.rtt(path.id())?;
            return measured_rtt(rtt);
        }
    }
    None
}

/// The round trip of a path, when it is a measurement rather than a guess.
///
/// Split out of [`rtt_of`] so that a reading can be taken off a path the
/// caller names rather than off whichever one is selected now: the two halves
/// of a reading describe one path, and the selection can move under the
/// reading.
pub(super) fn measured_rtt(rtt: std::time::Duration) -> Option<std::time::Duration> {
    is_measured_rtt(rtt).then_some(rtt)
}

/// Whether `rtt` is a measured round-trip time rather than a guess.
///
/// Split out from [`rtt_of`] so the rule can be tested without a live
/// connection: reading it off a connection needs an endpoint, and the rule is
/// the part that has to be right.
///
/// The rule is the value, so it is exact in one direction only: a round trip
/// that lands exactly on the initial RTT is reported as no measurement.
pub(super) fn is_measured_rtt(rtt: std::time::Duration) -> bool {
    rtt != crate::transport::INITIAL_RTT && rtt >= std::time::Duration::from_millis(1)
}

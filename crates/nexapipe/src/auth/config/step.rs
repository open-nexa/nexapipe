//! The rule about a TOTP step being used twice.
//!
//! A time-based code is valid for a window, and every code in that window
//! is a valid answer. Using the same one twice is not, so the last step
//! that was accepted is remembered and a step that does not move forward
//! is refused.

/// What became of a step.
///
/// The two answers are different in kind, and the caller needs both: a step
/// that was refused is **not** a failed attempt — it is a code from an earlier
/// step, which is not a guess — and a step that was accepted may or may not
/// have moved the memory, and only a moved memory is worth a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepVerdict {
    /// The step was accepted.
    Accepted {
        /// Whether the memory moved: the state file has to be written when it
        /// did, and left alone when it did not.
        moved: bool,
    },
    /// The step was refused: it has been used already.
    Refused,
}

/// Whether `step` may be used given the last accepted one, and what the last
/// accepted one is afterwards.
///
/// **A step that is behind the last accepted one is refused.** That is the
/// code of an *earlier* step, and it is still inside the acceptance window:
/// the window is about how far the clocks may differ, not about whether a code
/// has been used. So this is what refuses a replay of the previous step's
/// code.
///
/// **The same step again is allowed**, and it has to be. A client that opens
/// several connections in the same step sends the same code for each of them
/// — the protocol is chosen at the handshake, so a client that speaks HTTP
/// and L4 holds a connection for each — and refusing the second would leave
/// the client with connections it cannot open, over a rule that buys
/// nothing: a captured response is already useless on another connection,
/// because its signature covers the challenge issued for this one, and
/// anybody who can sign holds the seed and can compute a code anyway.
///
/// The check and the record are one operation on purpose: a caller that
/// checked and then recorded could let two connections through between the
/// two.
pub(super) fn accept_step(last: &mut Option<u64>, step: u64) -> StepVerdict {
    match *last {
        Some(previous) if step < previous => StepVerdict::Refused,
        _ => {
            let moved = *last != Some(step);
            *last = Some(step);
            StepVerdict::Accepted { moved }
        }
    }
}

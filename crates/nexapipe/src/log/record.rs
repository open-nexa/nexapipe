//! The access record, and the sinks that take it.
//!
//! The access log is a **line**: a fixed set of columns, written to a file,
//! read by a script that splits it on spaces. That is the right shape for a
//! log and the wrong shape for an audit trail — a deployment that has to hand
//! its records to a SIEM, or keep them in a database, needs the facts rather
//! than the rendering of them.
//!
//! This module is the other half of that: the same facts as a record, and a
//! sink that takes one. The core's own destination is the file the
//! configuration names; another one is registered by whoever needs the records
//! somewhere else, and the core neither knows nor cares where they end up.
//!
//! # The redaction is the same on both sides
//!
//! The line redacts a query string before it reaches the file, and so does the
//! record: the target it carries is the redacted one, computed by the same
//! expressions. Redacting the file and not the record would only move the
//! leak next door, which is what the line's own comment says about the
//! tracing event.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, OnceLock, RwLock};

use super::access::FlowDetail;
use crate::conn::peers::PeerIdentity;

/// One proxied request, as a record rather than a line.
///
/// The line in the log file is a rendering of this. A sink takes the record
/// and never sees the format, so a change to the line's columns does not
/// change what such a sink is given.
#[derive(Clone, Debug)]
pub struct AccessRecord {
    /// The id of this request. One per request, never per connection.
    pub request_id: String,
    /// Where the connection came from.
    pub remote_addr: String,
    /// The method — or the protocol, for a flow that was not a request.
    pub method: String,
    /// The URI, with its query values redacted.
    pub uri: String,
    /// The status.
    pub status: u16,
    /// How long it took.
    pub duration_ms: u64,
    /// How many bytes went back.
    pub bytes_sent: usize,
    /// Who made it, when the connection was authenticated.
    ///
    /// `None` for a request that arrived on the plaintext listener, and for
    /// every request of a deployment with 2FA off: those have no client to
    /// name, and a record that said one anyway would be a record of a guess.
    pub identity: Option<PeerIdentity>,
    /// What the flow said about itself, when it said anything.
    pub detail: Option<FlowDetail>,
}

/// Where access records go.
///
/// A sink is handed the record and does whatever the deployment needs with it:
/// ship it to a SIEM, keep it in a database, count it.
///
/// **A sink runs on the writer thread, not on the request's own task.** A sink
/// that reaches the network has to do its own bounding — a timeout, a queue of
/// its own — because a sink that blocks holds up every record behind it, and
/// the writer thread is the only thing between a slow destination and the
/// process.
pub trait AccessSink: Send + Sync + 'static {
    /// Takes one record.
    fn emit(&self, record: &AccessRecord);
}

/// The sinks somebody registered.
static ACCESS_SINKS: RwLock<Vec<Arc<dyn AccessSink>>> = RwLock::new(Vec::new());

/// Registers a sink for the access records.
///
/// Called once, at startup, before the first request is served: a sink
/// registered later sees the records that come after it and not the ones
/// already queued.
pub fn add_access_sink(sink: Arc<dyn AccessSink>) {
    let mut sinks = ACCESS_SINKS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    sinks.push(sink);
}

/// Whether anybody wants the records.
pub(super) fn has_sinks() -> bool {
    !ACCESS_SINKS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty()
}

/// Hands the record to every registered sink.
fn dispatch_to_sinks(record: &AccessRecord) {
    let sinks = ACCESS_SINKS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for sink in sinks.iter() {
        sink.emit(record);
    }
}

/// The thread that hands the records to the sinks, and the queue in front of it.
///
/// A thread of its own, rather than the one that writes the log file: a sink
/// that reaches the network must not be able to hold up the file, and the file
/// must not be able to hold up the sink. The two destinations are independent,
/// and the queue in front of each of them is bounded on its own.
///
/// Started with the first record rather than at `init`, so a deployment with
/// no sink never starts the thread.
static RECORD_WRITER: OnceLock<SyncSender<Box<AccessRecord>>> = OnceLock::new();

/// How many records may be waiting for the writer thread.
///
/// Bounded for the reason the line queue is: the queue is fed by request
/// handlers and drained by one thread, so an unbounded queue makes memory the
/// place a slow destination goes. A record refused here is dropped and
/// counted.
const RECORD_QUEUE: usize = 4096;

/// Records dropped because the queue was full.
static DROPPED_ACCESS_RECORDS: AtomicU64 = AtomicU64::new(0);

/// `None` when the thread could not be started, which the caller treats as
/// "deliver it here instead": failing to spawn a thread must not lose the
/// record.
fn record_writer() -> Option<&'static SyncSender<Box<AccessRecord>>> {
    if RECORD_WRITER.get().is_none() {
        let (sender, receiver) = sync_channel::<Box<AccessRecord>>(RECORD_QUEUE);
        match std::thread::Builder::new()
            .name("nexapipe-access-records".to_string())
            .spawn(move || {
                while let Ok(record) = receiver.recv() {
                    dispatch_to_sinks(&record);
                }
            }) {
            Ok(_) => {
                // A racing caller loses here and drops its sender, which ends
                // the thread it just spawned.
                let _ = RECORD_WRITER.set(sender);
            }
            Err(e) => eprintln!("nexapipe: no access record writer thread: {e}"),
        }
    }

    RECORD_WRITER.get()
}

/// Queues one record for the sinks.
pub(super) fn dispatch(record: AccessRecord) {
    let record = Box::new(record);
    match record_writer() {
        Some(writer) => match writer.try_send(record) {
            Ok(()) => {}
            // The destination is behind the traffic. Waiting would put the
            // delay on the request that happened to be logging, which is the
            // thing the writer thread exists to prevent, so the record goes
            // and the count stands in for it.
            Err(TrySendError::Full(_)) => {
                DROPPED_ACCESS_RECORDS.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                eprintln!("nexapipe: access record writer is gone");
            }
        },
        None => {
            // No thread, so no queue: the record goes to the sinks here rather
            // than nowhere.
            dispatch_to_sinks(&record);
        }
    }
}

# Vendored smoltcp (0.12.0) — local patch

This directory is a vendored copy of `smoltcp` 0.12.0 from crates.io, wired in via
`[patch.crates-io]` in the workspace root `Cargo.toml`.

## Why

Without the patch, real-world TCP traffic through the Android TUN proxy can trigger:

```
RUST PANIC: attempt to subtract sequence numbers with underflow
  at smoltcp-0.12.0/src/wire/tcp.rs:81:13
```

The panic comes from the unguarded `self.remote_last_seq - self.local_seq_no`
subtraction in the TCP transmit path (`socket/tcp.rs`). When the remote ACKs
beyond what we have sent (possible with retransmissions / stale segments), the
sequence subtraction underflows and panics, killing the smoltcp stack task and
tearing down the whole TUN tunnel a few seconds after connecting.

## Local changes vs upstream 0.12.0

- `src/wire/tcp.rs` (`Sub for SeqNumber`): removed the bogus `result < 0` panic.
  TCP sequence numbers are modular 2^32 — there is no meaningful underflow.
  The subtraction now returns the wrapping difference as `usize`, matching
  the wrapping comparison used by `PartialOrd`.
- `src/socket/tcp.rs` (`last_scaled_window`): added an underflow guard.
  When `next_ack` has advanced past `last_ack + last_win` (possible with
  retransmissions or stale segments), the adjusted window is clamped to 0
  instead of wrapping to a huge value.
- `src/socket/tcp.rs` (transmit path): guard the `remote_last_seq - local_seq_no`
  subtraction so an underflow yields `0` (nothing new to send) instead of
  calling the now-safe `Sub`.
- `src/socket/tcp.rs` (trace log): the same subtraction is repeated in a
  `tcp_trace!`; it now uses the same guarded expression.

Everything else is byte-for-byte upstream 0.12.0.

## Rules

- Do not edit this copy for anything but the four fixes above. It is a vendored
  crate, not a fork: a local "improvement" silently diverges from upstream and
  makes the next re-vendor a manual merge.
- Any change here goes in this file, with the reason and the upstream state.

## Dropping the patch

This patch exists only because released smoltcp 0.12.0 panics on modular
sequence-number subtraction. Once upstream ships a release that no longer
panics, the vendored copy — and this directory — can go away:

1. Check upstream (`smoltcp` master, and the changelog of the release you want
   to move to) for the two spots this patch touches:
   - `src/wire/tcp.rs`: `impl Sub for SeqNumber` — must not panic on a negative
     difference (sequence numbers are modular 2^32).
   - `src/socket/tcp.rs`: `last_scaled_window` and the transmit-path
     `remote_last_seq - local_seq_no` subtraction — must be guarded or
     saturating.
2. Remove the `[patch.crates-io]` entry from the workspace root `Cargo.toml`
   and run `cargo update -p smoltcp`, so the crates.io version is used again.
3. Actually exercise it: bring the TUN proxy up (Android or desktop) and push
   real traffic through it, including a lossy link. The panic this patch guards
   only appeared seconds into a real connection, never in a unit test.
4. Delete `third_party/smoltcp/` and this file.

Until upstream releases the fix, the patch is load-bearing: without it the TUN
tunnel disconnects a few seconds after connecting.

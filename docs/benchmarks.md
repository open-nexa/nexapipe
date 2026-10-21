# Benchmarks

Three benches, on the paths that carry user traffic. They exist because until
they landed every performance claim in this repository was an expectation
rather than a result — the reasoning behind that is in
[`size-perf-roadmap.md`](size-perf-roadmap.md) §F1.

| Bench | Where | What it measures |
|---|---|---|
| `l4_forward` | `crates/nexapipe/benches/l4_forward.rs` | the copy loop of an L4 flow: bytes from the tunnel to the backend and back |
| `tun_pump` | `crates/nexapipe-client/benches/tun_pump.rs` | the TUN's per-packet cost: the DNS path, the virtual-address bookkeeping, and the whole path with a packet in and an answer out |
| `forwarding_path` | `crates/nexapipe-client/benches/forwarding_path.rs` | the end-to-end path: an application, the local proxy, the tunnel, and the copy loop |

None of them needs a network. The backends are loopback TCP echoes, the TUN
device is a `tokio::io::duplex` pair standing in for the fd, and the two iroh
endpoints the forwarding path needs talk to each other over the loopback
interface. That is deliberate: a bench that needs the internet fails on a
runner without it, and a bench that fails is a bench nobody runs.

## Running them

```bash
# Everything. The client's benches are behind its `tun-proxy` feature, which
# is also what `local-proxy` needs.
cargo bench --workspace --features nexapipe-client/tun-proxy

# The same, without the plots and the HTML report. The flag reaches criterion
# alone now, so it is worth knowing about: a run that only wants the numbers
# does not have to write a report to do it.
cargo bench --workspace --features nexapipe-client/tun-proxy -- --noplot

# One of them.
cargo bench -p nexapipe --bench l4_forward
cargo bench -p nexapipe-client --features tun-proxy --bench tun_pump
cargo bench -p nexapipe-client --features local-proxy --bench forwarding_path
```

The release profile of the root workspace is `opt-level = 3` with LTO, so the
first build takes a while and every run after it is fast.

`cargo bench --workspace` runs the criterion targets and nothing else: the
crates carry no `#[bench]` function, and cargo's default bench target for a
crate is a harness with nothing in it — built and *run* in the release profile,
which is the slowest profile there is. Each crate says so with `bench = false`
on its library and binary targets.

It also means the arguments after `--` reach criterion alone. `--noplot` is a
criterion flag, and the default harness refuses an option it does not know and
exits 101 — which is how the CI job used to fail, on `nexapipe --lib`, before
a single benchmark had run.

Criterion writes its report to `target/criterion/<group>/<bench>/` and prints
the numbers it found. The useful parts are the time per iteration, the
throughput, and — when a baseline exists — the change against it:

```bash
# Record a baseline to compare against later.
cargo bench -p nexapipe --bench l4_forward -- --save-baseline before

# Compare against it.
cargo bench -p nexapipe --bench l4_forward -- --baseline before
```

## What each bench measures, and what it does not

**`l4_forward`** establishes the flow first and starts the clock when the
payload does, so what it measures is the copy loop and not the price of
opening a flow. The handshake is a fixed cost per flow rather than a rate,
and the tests cover what it does.

**`tun_pump`** has three parts, from the inside out:

- `dns_query` — the query the system resolver sends, answered from the
  virtual address pool.
- `ip_mapping` — the bookkeeping behind those answers: one address per
  domain, and the reverse lookup that turns a packet's destination back into
  a name.
- `tun_packet` — the whole path, with the query arriving as an IP packet on
  the TUN device and the answer leaving as one. The stack in the middle is
  smoltcp's; what is measured around it is ours.

**`forwarding_path`** is the only bench that reflects what a user experiences:
the request crosses the proxy's accept loop, the tunnel handshake, the tunnel
itself and the copy loop on the way back. The far side is an iroh endpoint on
the same host that speaks the L4 framing and echoes.

## What this is not

- **Not a budget.** Nothing here fails a build when a number gets worse. A
  number that is only reported is worth having; a number that fails the build
  before anyone trusts it gets deleted. The budget is a later step
  (`size-perf-roadmap.md` §F3), and it belongs to whoever has run these
  enough times to know what normal variance looks like.
- **Not a comparison between machines.** Criterion's numbers are only
  meaningful on the machine that produced them. The CI job runs them on the
  same runners every time so that two runs can be compared with each other,
  not so that a number in a log can be compared with a number from a laptop.
- **Not a profile.** These say how long a path takes, not where the time goes.
  When one of them says a path got slower, that is the signal to go and look
  for the reason — with a profiler, not with another bench.

## The rule about what counts as a result

A roadmap that only ever adds benchmarks is a plan to feel better without
knowing anything. **"We measured and it is already fast enough" is a
successful outcome** — and it is a result, because it is the first thing in
this repository that says so with numbers behind it.

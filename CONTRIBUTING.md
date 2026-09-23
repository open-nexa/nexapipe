# Contributing to NexaPipe

Thanks for looking. This document is the short version of how to get from a
clone to a merged change, plus a list of work that is genuinely open.

## Where things live

NexaPipe is one workspace plus two app repositories wired in as submodules:

| Directory | What it is | Lives in |
| --- | --- | --- |
| `crates/nexapipe/` | The server: iroh endpoint, L7 router, TLS passthrough, L4 tunnel, 2FA | this repo |
| `crates/nexapipe-client/` | The client library (`rlib` + `cdylib` + UniFFI) | this repo |
| `crates/nexapipe-proto/` | The L4 wire format, dependency-free and shared by both sides | this repo |
| `ui-android/` | Android app (Kotlin + Compose), submodule | `open-nexa/nexa-android` |
| `ui-desktop/` | Tauri 2 desktop app (Vue 3), submodule | `open-nexa/nexa-desktop` |

A change to the wire format touches `crates/nexapipe-proto/` and **both** sides —
never hand-encode it on one end.

Clone with submodules, or `ui-android/` and `ui-desktop/` arrive empty:

```bash
git clone --recurse-submodules https://github.com/open-nexa/nexapipe.git
```

## Getting set up

```bash
cargo build                              # the workspace
cargo test --workspace                   # all Rust tests
cargo run -p nexapipe -- --config config.toml
```

`config.toml` is gitignored; start from `config.toml.2fa.example`.

Checks that CI cannot cover, and that are easy to forget:

```bash
cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy
cd ui-desktop/src-tauri && cargo check
cd ui-android && ./gradlew.bat :app:compileDebugKotlin
```

`crates/nexapipe-client/src/tun_proxy.rs` is `cfg(target_os = "android")`, so a
host build never compiles it — that `cargo ndk` line is the only thing that
type-checks it. `ui-desktop/src-tauri` is a separate cargo project, so the
workspace lint gate does not cover it either.

## Before you open a pull request

```bash
cargo clippy --workspace --all-targets    # kept at zero warnings
cargo fmt --all -- --check                # report drift only
```

Do **not** run `cargo fmt --all`: the tree has pre-existing drift in files you
did not touch, and a formatting-only diff buries your change. Format your own
file instead —

```bash
rustfmt --edition 2024 <path>
```

Other house rules:

- One logical change per commit, with a descriptive subject —
  `fix(local-proxy): handle CONNECT tunnel close`, not `update`.
- Platform code stays behind cargo features (`jni`, `local-proxy`, `tun-proxy`,
  `uniffi`). The `uniffi` bindings are proc-macro based, so there is no UDL file
  to regenerate; the module is `uniffi_bindings.rs` (a module named `uniffi`
  would shadow the crate of the same name at the crate root).
- `third_party/smoltcp` is vendored with a patch and wired through
  `[patch.crates-io]`. Do not edit it.
- Inline comments are in English.
- New behaviour comes with a test; the L4 tests drive `l4::serve_stream` over a
  `tokio::io::duplex` pair, so a TCP or UDP flow can be tested without iroh.

## Good first issues

Bounded, real, and each one is useful on its own. Comments welcome before you
start — say which one you are taking.

**1. Allow-list client public keys** — any peer that learns the Node ID can
complete the QUIC handshake. Add `endpoint_ids` under `[auth.clients.<id>]`,
matched against `conn.remote_id()` in `handle_connection`
(`crates/nexapipe/src/conn/mod.rs`). This is the single change that turns "knows
the Node ID" into "is a registered device". *Medium.*

**2. Per-client authorization** — an authenticated client can reach every route.
Add an optional `allow_hosts` per client and enforce it in the HTTP lookup
(`crates/nexapipe/src/routes/`) and the L4 lookup
(`crates/nexapipe/src/l4/mod.rs`). It does not need to become a full ACL engine;
"different people reach different backends" is enough. *Medium.*

**3. Per-device credentials** — 2FA is one symmetric secret shared by every
device enrolled under a `client_id`, so a single device cannot be revoked and
anyone who scans an invite QR becomes a legitimate client. Moving the primary
credential to the device's own iroh key (with TOTP as an optional second factor)
fixes both. *Hard, and the largest item here.*

**4. Wire UDP on the desktop TUN** — Android carries UDP flows
(`crates/nexapipe-client/src/tun_proxy.rs`); the desktop path in
`crates/nexapipe/src/proxy/dns.rs` maps addresses but never opens a UDP flow.
*Hard.*

**5. `https://` backends in `http` mode** — they are rejected at startup
(`validate_http_backend` in `crates/nexapipe/src/config.rs`), so the
proxy-to-backend hop is always plaintext. Accepting them lets an operator keep
that hop encrypted when the backend is on another host. *Medium.*

**6. Screenshots and a short demo** — the repo has no images at all. A
screenshot of the Android flow (scan invite → reach a service) and one of the
desktop app would do more for the project than several of the items above.
*Easy, and no Rust required.*

## Labels

Mostly so that `good first issue` actually means something. That label is
reserved for work that has a defined outcome, does not need project-wide context
to start, and has someone willing to answer questions on it — like the seven
listed above.

| Label | Means |
| --- | --- |
| `good first issue` | Bounded, self-contained, mentorship available |
| `help wanted` | Worth doing, but nobody on the project has time for it |
| `bug` / `enhancement` / `documentation` | Type of work |
| `security` | Touches the boundary described in the README |
| `needs-triage` | Nobody has looked at it yet |
| `area:server` `area:client` `area:proto` `area:android` `area:desktop` | Which component |
| `blocked:needs-decision` | Waiting on a maintainer call, not on code |

GitHub has no label file in the repository, so they are created through the API:

```bash
gh label create "good first issue" --color 7057ff --description "Bounded, self-contained, mentorship available"
gh label create "help wanted"      --color 008672 --description "Worth doing, no maintainer has time for it"
gh label create "security"         --color b60205 --description "Touches the security boundary"
gh label create "needs-triage"     --color ededed --description "Nobody has looked at it yet"
gh label create "blocked:needs-decision" --color fbca04 --description "Waiting on a maintainer call, not on code"
for a in server client proto android desktop; do
  gh label create "area:$a" --color c5def5 --description "Component: $a"
done
```

## Reporting security issues

See [Security boundary](README.md#security-boundary) for the known gaps. If you
find something exploitable, contact a maintainer directly rather than opening a
public issue.

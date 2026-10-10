# NexaPipe roadmap

Short version: the architecture is sound and genuinely differentiated; what is
missing is operational maturity. This document records where NexaPipe stands
against the market, what is broken or missing today, and the order in which we
intend to fix it.

| | |
|---|---|
| Last updated | 2026-10-10 (Phase 3's six deliverables have shipped; entries closed by v0.6.0 marked in §1, §4, §5 and §9; a full security and stability audit is recorded in [§4.9](#49-security-and-stability-audit-2026-10-10-p0p1) and its three capability items in [§6](#hardening-sweep--after-v060)) |
| Scope | server, client library, Android and desktop apps. Community-maintained targets follow [Platform policy](#5-platform-policy). |
| Status | Living document. Items come from code audits and reviews. |

Artifact size and performance are tracked separately, in
[`size-perf-roadmap.md`](size-perf-roadmap.md) — they are engineering
execution rather than product direction, and a section here would grow to a
size that buries the product decisions below.

Roadmap items are labelled `P0` / `P1` / `P2` for severity, not for priority of
implementation — the ordering comes from [Sequencing principles](#sequencing-principles).

### How to read this roadmap

This document is a statement of direction, not a schedule. There are no dates or
durations attached to anything below, and that is deliberate. The single useful
sentence it offers somebody evaluating NexaPipe is: **that does not work today,
but it is already planned** — meaning "these are the gaps we acknowledge and
intend to close", as opposed to the ones we never will.

Read each phase as "this comes before that", not "this ships in N weeks". Being
listed here means the gap is understood and accepted as something to solve; being
absent does not mean nobody has noticed it — raise it in an issue. See
[Non-goals](#7-non-goals) for the things we are consciously not doing.

**A defect is not a roadmap item.** Broken behaviour is fixed when it is found,
not scheduled; this document holds capability work only. Where an audit found
basic defects, they were fixed and are noted in
[section 4](#4-self-review-what-is-missing) for the record, not for planning.

---

## 1. Where NexaPipe stands

NexaPipe makes four claims that, together, nothing else on the market makes:
it never terminates TLS, it has no control plane, it can hole-punch instead of
renting a server, and it links into someone else's application as a library.

Those claims interlock. Remove one and the product becomes "frp with less
tooling": terminating TLS turns it into a Traefik competitor, a control plane
turns it into self-hosted Pangolin, and dropping the library angle gives up the
part no SaaS can copy.

The gap is not architectural, it is maturity:

- Identity now goes as far as the device. Each device under a client is issued a
  TOTP secret of its own at enrollment, so revoking one leaves the others
  working, and `nexapipe client list|add|revoke --device` does it without anyone
  editing `config.toml`. Every install asks for that secret under a name of its
  own — the desktop after its hostname, Android after the device model — so a
  device is reachable from somewhere other than an operator's shell, and one
  that is struck out loses the connections it already holds instead of keeping
  them until it hangs up. Both were the halves
  [Phase 3](#phase-3--v060-one-device-at-a-time) still owed, and both shipped in
  v0.6.0; the kind of credential stays a TOTP secret for now, which is what
  §4.3 is about.
- Platform coverage has closed both of its holes: IPv6 inside the TUN and a
  second Android ABI shipped in v0.4.0, and the desktop TUN does UDP. (This
  list used to claim it did not. See [4.5](#45-protocols-and-transport-p1p2).)
- Release hygiene is thinner than the rest: `CHANGELOG.md` arrived with v0.3.0,
  and a published container image and a documented self-hosted relay came with
  v0.5.0. What is still missing is a package manager — nothing in Homebrew,
  winget or scoop.

Until those are addressed, "you do not need to rent a server" is a claim that
benefits a narrow audience, because the fallback path (relay) is undocumented
and the discovery path still leans on third-party infrastructure.

That list is what the audit found *after* the defects it also found were fixed —
the tunnel logging nothing, a health check that emptied a pool on one failed
probe, and a shutdown that dropped connections on a timer. Those are not
planning items; see [section 4](#4-self-review-what-is-missing).

---

## 2. Competitive landscape

Four categories, roughly as of 2026-09.

| Category | Examples | Public server to rent | Visitor installs a client | Where TLS ends | Control plane | Embeddable |
|---|---|---|---|---|---|---|
| **A. SaaS tunnels** | ngrok, Cloudflare Tunnel, Tailscale Funnel, zrok.io, LocalXpose, bore.pub | no (theirs) | **no** — their killer feature | vendor edge | vendor-hosted | no |
| **B. Self-hosted reverse-proxy tunnels** | **frp**, **rathole**, **Pangolin**, bore, sish, chisel, tunnelto, nps, Inlets | **yes** | no | your reverse proxy | varies (frp has none, Pangolin has a strong one) | no |
| **C. Mesh VPN / ZTNA** | Tailscale, Headscale, NetBird, ZeroTier, Twingate, EasyTier | yes for self-hosted | yes | you (except Funnel) | yes | tsnet (Go) |
| **D. Peer-to-peer exposure** | **NexaPipe**, zrok private shares, EasyTier, frp xtcp, Tailscale direct | ideally no | yes | depends | ideally none | NexaPipe only |

Notable facts about the field:

- **frp** (Go, roughly 100k stars) is the default answer for self-hosted tunnels:
  HTTP/HTTPS/TCP/UDP/WebSocket, a web dashboard, custom domains, load balancing,
  plugins, several auth schemes, and a peer-to-peer mode (`xtcp`). It ships no
  identity layer — you put something in front of it.
- **rathole** (Rust, roughly 10k stars) positions itself as the fast, small frp
  alternative: Noise encryption by default, a binary that can be ~500 KB, hot
  reload, TCP and UDP, no dashboard.
- **Pangolin** (AGPL-3, roughly 19k stars) is the closest thing to a direct
  competitor. WireGuard (Gerbil) + Traefik + a site connector (Newt) + a control
  plane, with SSO/OIDC, PIN and password gates, one-time-email access, expiring
  share links, geolocation and IP rules, CrowdSec integration and audit logs.
  It has since grown private-resource access (SSH/RDP/databases), i.e. ZTNA.
  It made "self-hosted Cloudflare Tunnel" a product rather than a weekend project.
- **Cloudflare Tunnel** is free, speaks QUIC by default now, and Access policies
  can be attached at no cost (up to 50 users). The price is structural: TLS is
  terminated at their edge, and they must see plaintext to run WAF and routing.
- **Tailscale / NetBird** solve device networking, with per-seat pricing on
  Tailscale (Standard is about $8/user/month) and a fully self-hostable NetBird
  that even includes its own reverse proxy. Public exposure is deliberately
  limited: Funnel publishes a handful of ports, Headscale has no Funnel at all.
- **zrok** (built on OpenZiti) adds file and directory sharing and private
  peer-to-peer shares, self-hostable, with a Go SDK.

Comparison against NexaPipe specifically:

| Dimension | **NexaPipe** | frp | rathole | Pangolin | Cloudflare Tunnel | Tailscale / NetBird | zrok |
|---|---|---|---|---|---|---|---|
| Public server to rent | ideally no (hole punching) | yes | yes | yes | no | yes | no / yes |
| Visitor installs nothing | **no** | yes | yes | yes | yes | no (except Funnel) | yes |
| TLS termination | **the backend** | yours | yours | Traefik | Cloudflare edge | Funnel / yours | yours |
| Control plane | **none** | none | none | **strong** | yes | yes | yes |
| Identity granularity | shared TOTP + per-device secrets + host allowlist | bring your own | none | **SSO, OIDC, share links, audit** | Access (SSO) | IdP + ACLs | identity + private shares |
| Observability | access log naming client *and* device, `/metrics` with byte counters and latency buckets | dashboard | none | dashboard + Traefik metrics | rich | rich | some |
| Embeddable | **rlib / JNI / UniFFI** | no | no | no | no | tsnet (Go) | Go SDK |
| UDP | yes (Android TUN and desktop TUN) | yes | yes | yes | no | yes | yes |
| Transport | iroh / QUIC | TCP, KCP, QUIC | TCP + Noise | WireGuard | QUIC | WireGuard | OpenZiti |

Read it this way: NexaPipe is the only entry that is green on "no TLS
termination", "no control plane" and "embeddable" simultaneously, and it is the
weakest entry on the three columns where adoption actually happens — visitor
needs nothing installed, identity and authorization, observability.

---

## 3. Which parts of the moat hold

**Holds, and is scarce.**

1. **Never terminating TLS.** Every category-A and most category-B competitors
   terminate; only the backend holding the certificate gives true end-to-end
   encryption. This is the strongest line in the security story.
2. **Embeddable as a library** (rlib, cdylib for Android JNI, UniFFI bindings).
   Only zrok's Go SDK and tsnet come close, and neither covers all three shapes.
3. **No account, no control plane.** Headscale only moves the control plane into
   your own hands; it still exists.

**Holds only partly.**

4. **"Nothing to rent."** Three constraints, two of which the README already
   admits:
   - Hole punching succeeds most of the time, not always; everything else goes
     through a relay.
   - Running your own relay is possible (`relay_mode = "custom"`) but there is no
     deployment guide, no compose file, no image. The fallback path is a footnote.
   - iroh still resolves Endpoint IDs through `dns.iroh.link` and cannot stop
     talking to n0 relays on the far side, so "no third-party infrastructure" is
     not literally true today.

   Making self-hosted relay a first-class deployment is therefore a roadmap item,
   not a docs cleanup.

**Not ours to fight.**

5. Visitors installing nothing, anycast, DDoS absorption, WAF, multi-tenancy and
   billing. That is the business of owning an edge network.

---

## 4. Self-review: what is missing

Severity here describes the user impact of leaving it alone.

Basic defects — the kind that makes a deployment hard to run rather than limited
in what it can do — are **not** listed here: they are fixed when they are found,
and an earlier draft of this document was wrong to schedule them. The ones found
by the audit that produced this document are already fixed:

- HTTP requests over the iroh tunnel were logged nowhere at all, which made the
  main traffic path invisible. The tunnel path now emits the same access log
  lines as the plaintext listener, including WebSocket upgrades (`101`) and
  unroutable hosts (`404`).
- `failure_threshold` was stored and logged but never consulted, so a single
  failed probe emptied a backend pool. It is now the count that takes a backend
  out of rotation, and `[health_check]` makes probing switchable — a backend with
  no health endpoint is a supported deployment, not a broken one.
- Shutdown was two `sleep`s. It now counts the connections both accept loops
  spawned and waits for them, with a bound so a stuck peer cannot hold the
  process open.

What follows is what is *missing*, i.e. capability work. [4.9](#49-security-and-stability-audit-2026-10-10-p0p1) is the exception: it holds
the defects a later audit found *open*, because an audit's findings belong
somewhere even though they are fixed rather than scheduled.

### 4.1 Backend handling (P2)

| # | Gap | Where |
|---|---|---|
| C3 | **Still open.** HTTP/1.1 only towards backends: the client is `legacy::Client<HttpConnector>` with only `http1_*` configuration, `https://` backends are rejected at load time, and there is no retry and no circuit breaking. The *configurable timeout* half is done (v0.4.0): `[timeouts] connect_secs` / `response_secs`, each optional and defaulted to the constant it replaced. | `http/mod.rs:13-32` |
| C4 | **Partly closed in v0.4.0.** `least_conn` exists, and an all-unhealthy pool now refuses instead of falling back to the first — except a pool of one, which is still handed out because there is nothing to choose between. Still open: no retry, no circuit breaking, and `least_conn` counts requests rather than sockets (see the note at `http::proxy_request`). | `lb/mod.rs` |
| C7 | **Closed in v0.5.0, apart from the one mode that cannot be.** A route serving `http` *and* another mode shares one pool, so the other modes always did inherit its health — and since v0.4.0 they answer `BackendFailed` / hang up when it is empty. `passthrough` and `tcp` routes are probed now, by connecting to them: a TLS backend by completing its handshake, which says a process is listening and nothing about whether it works. A `udp`-only route is still not probed, because there is nothing to connect to and a probe that invented a datagram would report an answer no backend gave. | `health/mod.rs` |

### 4.2 Observability beyond the access log (P1)

The access log now covers every path, and `/metrics`, `/healthz`, a request ID
and a span per request cover the instance: see R7. v0.5.0 added the two things a
dashboard reads: `/metrics` carries `nexapipe_traffic_bytes_total` for what this
instance has served and accepted, and the desktop lists, per node, whether it
answered its last probe and how much it has carried. **The latency buckets
shipped in v0.6.0.** Request duration is a histogram —
`nexapipe_request_duration_ms_bucket{le="…"}` beside `_sum` and `_count`, over
fixed boundaries from 1 ms to 10 s plus `+Inf` — so a p99 is read off the scrape
rather than divided out by hand. What is still missing is an OpenTelemetry
exporter, and latency on either client: neither the desktop nor Android shows
how long a request took, and `/metrics` is still the only place that does. The
exporter, and client-side latency, are not planned for this release.

### 4.3 Identity and authorization (P1)

Authentication is a TOTP secret. **The shared-secret half closed in v0.6.0:**
what a `client_id` carries now is its own `secret` plus a table of devices, each
with a secret of its own issued at enrollment, and each revocable without
touching the others. The README stopped saying that too, and both halves that
[Phase 3](#phase-3--v060-one-device-at-a-time) still owed the model have landed
since: a revoked device no longer keeps the connections it already holds, and
every client answers as one named device of itself. There is still no mTLS, no
OIDC and no API keys.

The same release closed the audit trail half for the server side: an access line
names the client *and* the device that made the request, which it could not do
before because a `client_id` did not survive the handshake.

The `v=2` invite, with its one-shot enrollment token, is what downgraded "leaked
URL means leaked credential forever" to "leaked URL is revocable and
short-lived", and enrollment is where a device name comes from now. The direction
it points at is unchanged: per-device keys signed by the server, with TOTP as a
human second factor rather than the device identity itself.

**Phase 3 took the first half of that step, and it has landed: one credential per
device**, issued at enrollment and revocable on its own, with the credential
still a TOTP secret and the handshake still the HMAC it is today. The second half
is the *kind* of credential — per-device key pairs, and TOTP demoted to a second
factor a human supplies — and it stays out of this release because it also means
new material in both credential stores and a factor an unattended service cannot
answer. Of the other half of making revocation true, closing the connections a
revoked device already holds has landed. So has putting a name on the wire from
the clients rather than from `--device` alone: each install answers as one named
device of itself, which is what makes per-device revocation reachable from
somewhere other than an operator's shell.

### 4.4 Operations and distribution (P1)

- **The write half of the management surface shipped in v0.6.0**, as CLI
  subcommands: `nexapipe client list|add|revoke`, each device-scoped with
  `--device`, writing through the same config lock the writers already used.
  `/v1/*` stays GET-only on purpose — the admin token is one opaque value with
  no scope and no rotation, and giving it something to change in the same release
  as the thing it would change is how a read-only surface becomes the way in.
- Hot reload rules are one table in both READMEs as of v0.3.0, including what
  needs a restart. What is still uneven is enforcement, not documentation.
- Distribution stopped being download-only in v0.5.0: a container image is
  published to GHCR with the release archives, and `docs/self-hosted-relay.md`
  takes a relay from nothing to running — including a systemd unit for it, which
  v0.6.0 added, and the server has one of its own in both READMEs as of the same
  release. Still missing: any of Homebrew / winget / scoop, which it does not.
  See R6.
- Engineering hygiene: `CHANGELOG.md` exists as of v0.3.0; tests run on Linux
  and macOS; **the root workspace is *tested* on Windows as of v0.6.0** — the
  job used to be `windows-check`, a `cargo check`, so the integration tests
  compiled for `x86_64-pc-windows-msvc` and nothing ever ran them, and a bug
  that only surfaces in a running test reached a tag before CI saw one. It is
  `windows-test` now and runs the same `cargo test --workspace --locked` the
  other two do; the Android lint baseline still pins 32 historical findings; no
  fuzzing, no benchmarks; the vendored smoltcp patch needs long-term tracking.

### 4.5 Protocols and transport (P1/P2)

- **IPv6 inside the TUN shipped in v0.4.0** — R10, on both clients. An AAAA
  query in the Internet class now gets a real answer, 16 bytes of RDATA out of
  a virtual pool (`crates/nexapipe-client/src/tun_proxy.rs:1324-1340`,
  `:1472-1475`). Android routes `fd00:10:0:1::/64` into the TUN and always has
  a pool (`:135-146`, `:430-438`). The desktop is best effort: `configure_ipv6`
  has to set the address per platform and may be refused, and when it is, AAAA
  is answered with nothing — which a resolver reads as "use A", not as an
  address no route leads to
  (`ui-desktop/src-tauri/src/proxy/tun_proxy.rs:307-337`).
- **The desktop TUN does UDP** — one `l4::open_udp` bi-stream per flow, through
  the same smoltcp stack the Android client runs
  (`ui-desktop/src-tauri/src/proxy/tun_proxy.rs`). This list used to claim
  otherwise and was wrong. The local proxy, which is the `--local-proxy` mode
  rather than the TUN, still speaks `CONNECT` only — a different path, and not
  the same gap.
- The iroh endpoint binds `0.0.0.0` on the configured port, and `[::]` beside
  it when `[iroh] bind_ipv6` is set — a second socket rather than a
  replacement, and one that is allowed to fail so a host without IPv6 still
  starts. Both need `bind_port`: without a fixed port there is nothing to keep
  the two families on, and the flag is ignored
  (`crates/nexapipe/src/config.rs:101`, `proxy/mod.rs:326-345`).

The iroh dependency boundaries used to belong on this list — discovery via
`dns.iroh.link`, far-side n0 relays. They are documented in
`docs/iroh-boundaries.md` as of v0.3.0, so what remains is the exposure itself,
not the absence of a description of it.

### 4.6 Client resilience (P1)

Health is probed every 30 s and, as of v0.5.0, it is read: which node the next
request goes to is decided by who answered last, and a node that could not be
dialled is marked down where the request noticed rather than waiting for the
next probe to find out. Failover is still request-level — drop the stale
connection and retry three times, `open_stream_with_retry` at
`local_proxy.rs:473`, `OPEN_ATTEMPTS = 3` at `:119`, each attempt bounded by
`[timeouts] connect_secs` — and `preconnect_report` still decides only whether
startup succeeded.

**R9 shipped in v0.5.0, by a narrower route than this section proposed.** It
asked for dead nodes to be *removed* from rotation, which needs `EndpointGroup`
to have interior mutability (`endpoint_group.rs:106-109`) and so changes the
ownership of all nine places that hold an `Arc` of it. Choosing among the nodes
that are up gets the same behaviour for the cost of a signature: `select` takes
one flag per candidate and answers `Option<usize>`, so "none of them" is a
distinguishable answer for the first time — index `0` was always a working
answer to "which backend". A single backend that is down is still dialled,
because refusing to dial the only node turns "down" into "no service at all" for
a deployment with nothing to fail over to. The group is still not mutable, so
what this bought is selection, not removal: a node that is down keeps its slot
in the list and is skipped.

### 4.7 Client-side credential protection (P0)

Both clients hold the material that authenticates a node — endpoint ID, ticket,
TOTP secret, enrollment token, relay auth token. This is the only item here
rated P0: the exposure is a credential disclosure, not a missing convenience.

Both clients already encrypted credentials at rest — the desktop with a
keychain-held master key, Android with the Keystore — and neither asked anything
before handing them back. Stating that precisely mattered because it decided
what the work was: **the vault existed, the door did not.** Android's door
shipped in v0.3.0 and the desktop's in v0.4.0, so both halves of R14 are now
built. Both doors have since been watched running on every platform they claim
to support, so what is recorded below is closed rather than merely built.

*Since*, and that word is load-bearing: the verification happened **after**
those versions shipped, not alongside them. `docs/releases/v0.4.0.html` still
says what was true on the day it was published — Windows and Linux had not been
seen — and has deliberately been left saying so. It describes a release; this
page describes where things stand.

| # | Gap | Where |
|---|---|---|
| C8 | **Desktop: closed in v0.4.0.** The ticket and the endpoint ID join the TOTP secret, the enrollment token and the relay bearer in the encrypted store — a payload left over from an older build is migrated into it on the way in — and reading any of it back now costs an answer from the operating system: one trait, three platform modules, and a two-minute window in memory. A keychain item whose access control requires user presence on macOS, Windows Hello with a `LogonUserW` fallback on Windows, PAM with a password the UI collects on Linux. A machine with nothing to confirm anybody with is refused rather than downgraded. **Confirmed on all three platforms since**: the window is pinned by unit tests, and the prompt has since been driven by hand on macOS, Windows and Linux. | `ui-desktop/src-tauri/src/gate.rs` and `gate/{macos,windows,linux}.rs`; `credentials.rs` for the store |
| C9 | **Closed with C8, in v0.4.0.** Masks come from `credentials::mask` in Rust, so a value is never in the renderer that is drawing it shortened; an invite is accepted by `accept_invite`, which files the credentials itself and answers with a receipt carrying none of them; and `reveal_credential` / `reveal_node_id` are the only two commands that answer with a whole value, which is what makes them the two the door stands in front of. | `ui-desktop/src-tauri/src/credentials.rs`, `src/lib.rs` |
| C10 | **Android asks first, as of v0.3.0.** At-rest storage was never the problem — `SecretStore` already wrapped values with Keystore AES-256-GCM. What was missing was the prompt, and `auth/CredentialGate.kt` now supplies one in front of the TOTP secret, its `otpauth` export and any change to the relay configuration, refusing a device enrolled with neither a biometric nor a screen lock. **Confirmed on a device**: CI gives compile, unit tests and lint, and the prompt has been watched running past `BiometricPrompt` itself. | `ui-android/.../auth/CredentialGate.kt`, `ui/EndpointDetailScreen.kt`, `ui/VpnControlScreen.kt` |

The direction is that **authentication is delegated to the operating system, and
no secret reaches the UI that the OS has not authenticated**:

- **No application password.** NexaPipe must never hold a credential of its own,
  so there is nothing to forget and nothing to reset. The consequence to state
  plainly in the UI is the price of that: if the OS-side key is lost — Keychain
  reset, cleared app data, a new machine — the ciphertext is unreadable for good
  and the node has to be re-imported from its invite.
- **One interface, per-platform native primitives**, following the shape RustDesk
  uses (a platform module per OS behind a single trait): Authorization Services
  on macOS, Windows Hello via `UserConsentVerifier` with a `LogonUserW` fallback
  on machines without it, PAM on Linux, `BiometricPrompt` with
  `DEVICE_CREDENTIAL` on Android. No third-party Tauri plugin; this means
  accepting a native build dependency on Linux.
- **Do not build a second vault on desktop.** The keychain-held master key and
  the encrypted credential file already exist; the ticket and the endpoint ID
  join the values already in it, and the work is the gate in front of reads.
  Android is the mirror image: `SecretStore` already encrypts at rest, so there
  too the work is the door.
- **Masks are produced on the Rust side.** A mask computed in the renderer is not
  a mask — the plaintext is still in the renderer, one console away.
- The lock is **mandatory, not a setting**, and an upgrade from an older version
  lands locked.
- **Scope boundary: the lock protects configuration disclosure and modification,
  not proxy state.** Starting, stopping and restarting the proxy is never gated.
  That forces a two-level model — a short-lived UI unlock state plus a
  process-scoped credential cache cleared only when the process exits — so a
  locked UI never breaks a proxy that is running or being restarted.

Two non-goals worth recording now. The Android Keystore key must **not** be
gated on user authentication: `setUserAuthenticationRequired(true)` would leave
an unattended VPN unable to read its own credentials after reboot and break
automatic reconnect — only the UI door is locked. And a device with neither a
biometric nor a screen-lock credential enrolled cannot be authenticated by
anything, so it is refused rather than downgraded.

### 4.8 Client DNS resolution (P1)

The TUN answers DNS itself: a query that is not for one of its own virtual IPs is
forwarded to the configured resolvers, and the answer is kept for as long as its
own records say it is good. The cache was a first implementation whose semantics
were incomplete — nothing crashed or lost data, but a name could resolve to an
address that was no longer the right one. All four gaps below were closed in
v0.4.0: the cache now answers only what it actually holds.

| # | Gap | Where |
|---|---|---|
| C11 | **Closed in v0.4.0.** The cache key ignored QCLASS: the question is parsed into a name and a QTYPE, and the class was neither checked nor part of the key, so a query in another class was answered from an entry cached for `IN`. The class is part of the key now. | `crates/nexapipe-client/src/tun_proxy.rs` |
| C12 | **Closed in v0.4.0.** The cache was not scoped to the resolvers that answered, so changing the DNS servers in the configuration kept serving what the previous ones said. It is scoped to them now. | `crates/nexapipe-client/src/tun_proxy.rs` |
| C13 | **Closed in v0.4.0.** A cached answer was not aged: a hit rewrote the transaction ID and nothing else, so a record fetched with a 300s TTL was handed back with the full 300s still on it even when it was 290s old. A hit now rewrites each record's TTL to the part that is left. | `crates/nexapipe-client/src/tun_proxy.rs` |
| C14 | **Closed in v0.4.0.** A zero TTL was cached anyway — TTLs were clamped into 1–300s, so a record the server said not to cache was kept for a second. A zero TTL is not cached now. | `crates/nexapipe-client/src/tun_proxy.rs` |

What is already right, and should stay right: the TTL kept is the shortest among
the answer's records rather than the first or the longest, an error or an empty
answer is not cached at all, the table is bounded, and the transaction ID is
rewritten on every hit so a cached answer does not look to the application like
no answer.

### 4.9 Security and stability audit, 2026-10-10 (P0/P1)

A read-only review of the whole tree — server, client library, wire format, both
apps, the Dockerfiles and CI — run on 2026-10-10 at `24937db`. It found 7 high,
30 medium and 20 low findings; the review itself is at
`.workbuddy/CODE_REVIEW-2026-10-10.md`, a working file rather than part of the
repository tree, which is why the record of it lives here.

Two things about it are worth saying up front.

The first is what it did **not** find. There is no open-proxy or SSRF surface on
the server: the address an L4 flow dials comes from the route's `backends`, and
the host and port a client sends are a selector, never a destination. No
credential is committed to the repository, and the real `config.toml` is not
tracked. The server has no `unsafe` and no `unwrap` on a production path. The
authentication, 2FA and ACL work holds up under reading: constant-time
comparison, a per-handshake nonce that makes a captured response unreplayable,
lockout accounting held under the same write lock as the verification it counts,
and a refusal that is indistinguishable from having no route. The vendored
smoltcp patch is minimal, documented, and still load-bearing — upstream has not
fixed what it works around.

The second is that **most of what it did find is defects, and defects are not
scheduled.** They are listed below so the audit stays reproducible; each one is
fixed rather than sequenced, and none of them appears in
[section 6](#6-roadmap). Nine of them were fixed over the days that followed,
on branches cut from `c1db94b` and later, and the table marks them; the rest
are open and unscheduled. Three items from the same audit are capability work,
and those are in [§6](#hardening-sweep--after-v060).

| P | Defect, open as of the audit | Where |
|---|---|---|
| P0 | **The desktop build never gets the smoltcp patch.** `ui-desktop/src-tauri` is its own workspace — the root `Cargo.toml` excludes it — so `[patch.crates-io]` does not reach it and its lockfile resolves smoltcp 0.12.0 from crates.io. `tun-proxy` is precisely the feature that runs the patched transmit path, so the panic `third_party/smoltcp/PATCHES.md` exists to prevent is reachable on the one client that ships a desktop TUN. | `Cargo.toml:7`, `:24-25`; `ui-desktop/src-tauri/Cargo.lock` (`source = registry`) — fixed on `fix/desktop-smoltcp-patch` |
| P0 | **The macOS build deletes the CSP.** Platform configs merge as JSON Merge Patch, where `null` means *remove*, so `"csp": null` drops the baseline policy — on the build whose webview holds 35 command permissions, `put_credential` and `clear_credentials` among them. The other two platforms keep it. | `ui-desktop/src-tauri/tauri.macos.conf.json:28-30`, `tauri.conf.json:29`, `capabilities/default.json:22-58` — fixed on `fix/desktop-macos-csp` |
| P0 | **No global ceiling on connections or streams.** The only limit is per `EndpointId`, and an endpoint id is a public key: 64 connections × 256 streams, times as many peers as an attacker cares to generate, is unbounded tasks and memory taken from every tenant on the process. The comment in `limits.rs` says so — per-peer is what it is for. | `crates/nexapipe/src/conn/limits.rs:1-21`, `conn/mod.rs:1596-1597` |
| P0 | **TUN flows have no budget on the client.** The UDP reassembly buffer has no stated bound: `decode_frame` accepts any `u16` length, so a frame can announce 65 535 bytes and then arrive at whatever pace the far side chooses. TCP flows have no cap at all, though UDP has `MAX_UDP_FLOWS`. On Android the TUN is system-wide, so any installed application can exhaust the device. | `crates/nexapipe-client/src/tun_proxy.rs:1211`, `:765`; `crates/nexapipe-proto/src/udp.rs:50` — fixed on `fix/tun-flow-budgets` |
| P0 | **A Keystore failure falls back to plaintext.** All three fallback branches of `seal` return the input unchanged and the caller writes it straight into `SharedPreferences`; `unseal` returns an unmarked value as it stands, so once a secret is in the clear it stays in the clear. What the fix adds is the question before the write — the fallback itself is kept, because refusing to store would cut the user off from their own endpoint. | `ui-android/.../SecretStore.kt:107-140`, `SettingsManager.kt:209` — fixed on `fix/android-credential-downgrade-confirm` |
| P1 | **Timeouts that are not deadlines.** The streamed-response loop has none once the headers are in; the plaintext listener never bounds a request-body read, though the iroh path does; the UDP tunnel re-arms its idle timer on every read, so a trickle renews it forever; the local proxy's header loop is per-read rather than total, and its TLS ClientHello read has no timeout at all. Each one pins a slot, a backend lease and a task. | `crates/nexapipe/src/http/mod.rs:646`, `:244-265`, `l4/mod.rs:491`; `crates/nexapipe-client/src/local_proxy.rs:659-697`, `:1275-1286` |
| P1 | **A control that fails open.** `[peers]` is the section where a typo is a security change rather than a lost setting: `allowd` is dropped by serde, `allow` is then `None`, and an absent allow-list means every peer passes — with no warning at startup. `[auth]` already refuses unknown keys for exactly this reason, in a comment that makes the argument; `[peers]` should meet it. — fixed on `fix/peers-refuse-unknown-keys` | `crates/nexapipe/src/config.rs:490-514`, `conn/allow_list.rs:34-38` |
| P1 | **Privileged execution through predictable files in a shared directory.** Windows writes the `.bat` it elevates into `temp_dir()` with `File::create` rather than an exclusive one, and `cmd.exe` reads a batch file line by line — so the gap between writing it and the UAC prompt being answered is a gap in which what runs as Administrator can be changed. The installer hook is worse: its script names are fixed, not randomised. The elevation result file sits in the same directory and is written with `fs::write`, which follows a symlink. | `ui-desktop/src-tauri/src/service/platform.rs:486-493`, `:727-739`; `windows/hooks.nsh:41-43`; `src/service/elevate.rs:302-312` |
| P1 | **No ACL on Windows where there is a mode check on Unix.** `write_private` sets `0o600` on Unix and calls `fs::write` everywhere else, and `reject_world_readable` is a no-op off Unix — so the IPC token and the credential file are created with inherited permissions and never checked before being read. The token path can also be pointed anywhere by an environment variable. | `ui-desktop/src-tauri/src/service/ipc_token.rs:462-480`, `credentials.rs:815-837` |
| P1 | **`preconnect` counts its grace period outside its own timeout.** `wait_for_auth_required` can wait six seconds *after* the eight-second `PRECONNECT_TIMEOUT` has elapsed, and both callers wrap the whole call in eight — so a handshake slower than about two seconds has its fresh connection dropped unpooled and its backend recorded as unreachable, which a multi-backend group reports as no backend answering. | `crates/nexapipe-client/src/connection_pool.rs:529-549`, `:556-565` — fixed on `fix/preconnect-budget-covers-grace` |
| P1 | **One JNI entry without a panic barrier.** Every entry point that drives the runtime catches unwinds except `nativeStopTunProxy`; a panic there unwinds out of `extern "system"`, which on Android is a native crash rather than a Java exception — the thing the file's own header comment forbids. — fixed on `fix/android-stop-tun-panic-guard` | `crates/nexapipe-client/src/jni.rs:2566-2572` |
| P1 | **Blocking the main thread.** `stopVPN` calls `nativeStopTunProxy` directly, and both `onDestroy` and `ACTION_STOP` reach it on the main thread — the two paths `onRevoke` was deliberately moved off it for. | `ui-android/.../vpn/NexaVpnService.kt:159-161`, `:225-227`, `:293-297` — fixed on `fix/android-stop-vpn-off-main-thread` |
| P1 | **Containers run as root with the configuration writable.** Neither Dockerfile sets `USER`, and `docker-compose.yaml` bind-mounts the host `./config` — the file holding the 2FA secrets — read-write into the container. | `Dockerfile:47`, `Dockerfile-aarch64:48`, `docker-compose.yaml:31` |
| P1 | **A QR file carrying a secret is written world-readable, and over whatever is already there.** `--qr-out` wrote with `fs::write`, which truncates and follows a symlink, and made the file private only afterwards — so in between it was readable by anyone watching, and a name put there first could aim the write at another file. It now creates with `create_new` and the mode in the same call, and refuses a path that exists. | `crates/nexapipe/src/main.rs:1540-1549` — fixed on `fix/qr-out-create-private` |
| P2 | **Secrets that outlive their use.** TOTP secrets, enrollment tokens and the relay bearer sit in process-wide `String`s on the client and are never zeroized; `auth.rs` derives `Debug` over them where `provisioning.rs` deliberately does not; a response parser computes its body offset from a lossy UTF-8 conversion and then slices the original bytes. | `crates/nexapipe-client/src/jni.rs:29`, `:44-51`; `auth.rs:76`, `:124`, `:489`; `http.rs:127-144` |
| P2 | **Supply chain hygiene.** Actions pinned by tag rather than SHA; base images by floating tag, one from a self-hosted registry; `cargo build` in the Dockerfiles without `--locked`, though CI has it everywhere; images published with no signature and no provenance; `workflow_dispatch` input interpolated into a `run:` block. | `.github/workflows/*.yml`; `Dockerfile:1`, `:18`; `Dockerfile-aarch64:24`; `release.yml:137`, `:529`, `:1059-1161` |

---

## 5. Platform policy

Supported targets today are **Linux, macOS and Windows** (server and desktop app)
and **Android** (`arm64-v8a` and `x86_64`, one APK per ABI).

**iOS is not a supported platform and will not be developed or maintained by this
project.** The UniFFI bindings exist because they cost nothing to keep compiling,
not because an Apple client is planned. Do not read `ui-*` conventions, or the
iOS-specific `webpki-roots` dependency in `crates/nexapipe-client/Cargo.toml`, as
intent to ship one.

Community-contributed iOS code is welcome, with these expectations:

1. It lives in its own directory (`ui-ios/`) with a README that states plainly
   that it is community-maintained and receives no support commitment.
2. It must build through the existing UniFFI bindings and must not force iOS-only
   conditional compilation into shared crates beyond what already exists.
3. CI must stay green without an iOS job. If a contribution needs a macOS runner
   or Apple tooling to stay compiling, that job is opt-in and owned by whoever
   contributed it.
4. No guarantee of review capacity, release artifacts, or App Store work from the
   maintainers. Contributions that cannot be kept compiling by their author will
   eventually be removed.

Android was widened beyond `arm64-v8a` in v0.4.0 — one APK per ABI, `arm64-v8a`
and `x86_64`, so an emulator has something to install — as normal roadmap work,
unlike iOS. `run_android.ps1 -Abi x86_64` builds and installs that one.

---

## 6. Roadmap

### Sequencing principles

1. **Make it safe for a team.** Authorization granularity, a management surface,
   distribution and operations documentation decide whether this stays a personal
   tool.
2. **Then widen it.** Platform coverage and client resilience.
3. **Only then attack "someone with no client can visit".** It is the single
   biggest adoption gap and also the easiest place to destroy the positioning, so
   it comes last and as a separate, opt-in component.

Defects are not sequenced here. A proxy that logs nothing, empties a backend pool
on one failed probe, or drops connections because it shut down on a timer is not
missing a feature — it is broken, and it gets fixed.

### Phase 0 — v0.3.0, "operable"

| ID | Deliverable | Notes |
|---|---|---|
| R14 | **Local credential lock** | Gate every surface that can read or change a full endpoint ID, ticket, TOTP secret or enrollment token behind system authentication (Touch ID / Face / Windows Hello / PAM / Android biometric, falling back to the OS account credential where those are absent). Desktop: bring the ticket and the endpoint ID into the encrypted credential store that already exists ([4.7](#47-client-side-credential-protection-p0)), gate every read behind the OS prompt, and mask in Rust rather than in the renderer. Android: gate the endpoint detail screen and the 2FA export. Mandatory, with no opt-out; the dashboard keeps showing masked values and stays unlocked; proxy start/stop is explicitly *not* gated. See [4.7](#47-client-side-credential-protection-p0) |
| R4 | **Management surface** | Loopback-only admin API for read-only state (routes, clients, connections, health, direct ratio), with write operations going through CLI subcommands (`client add\|revoke\|list`, `route list`, `status`); shares the hot-reload path; token-authenticated like the desktop IPC token |
| R5 | **Per-device identity** | Move from "one client, one shared secret" to **per-device key pairs** issued by the server and revocable individually, with TOTP demoted to a human second factor; add a minimal audit log (who, when, which host) |
| R6 | **Operations and distribution** | Self-hosted relay as a first-class deployment (derper + compose + docs, including relay authentication); systemd unit in the docs; publish a container image; land in at least two of Homebrew, winget and scoop |
| R7 | **Instance metrics** | `/metrics` and `/healthz` on the auxiliary listener, gated by config rather than by a cargo feature (see the note below); a request ID on every access line and on every HTTP response as `x-request-id`; a tracing span per request. The access log answers "what happened", not "how is this instance doing". Gauges for connections, streams, backend health and the direct-vs-relayed ratio |
| R8 | **Boundary documentation** | State plainly what still depends on third-party infrastructure today (Endpoint ID discovery, far-side relays) so the sovereignty story is not oversold |

R14 and R15 carry high IDs because they were added after R13 was written; each
sits in the phase its notes put it in, not later.

**Progress.** R8 has shipped whole, as `docs/iroh-boundaries.md`. R7 has shipped
whole: `/metrics` and `/healthz` on the auxiliary listener, a request ID on every
access line and on every HTTP response, and a span around every request. It is
gated by config — `[admin] listen_addr` and `[metrics] enabled` — rather than by
the cargo feature R7 asked for, which would have added a build and a test
matrix to a choice nobody recompiles to make. R4 has shipped as far
as reading goes — the `/v1/*` endpoints and `nexapipe status`; the write half
(`client add|revoke`) still waits on R5's identity model. R14 has shipped on both
clients now: Android in v0.3.0, where `auth/CredentialGate.kt` puts the OS prompt
in front of the TOTP secret, its `otpauth` export and any change to the relay
configuration; and the desktop half in v0.4.0, which was the one item here that
moved to Phase 1 because it needs a per-OS platform module and a native build
dependency on Linux — ticket and endpoint ID into the encrypted store, masks
computed in Rust, and a native prompt on each of macOS, Windows and Linux. See
[4.7](#47-client-side-credential-protection-p0).

**Done when:** revoke one of three devices and the other two keep working —
which is R5, **shipped in v0.6.0**, and the read-only half of R4 shipped
without it, its write half landing with it as `nexapipe client list|add|revoke`;
a newcomer brings up a self-hosted relay from the docs without asking
anyone; and no *Android* surface renders a full secret without the operating
system having authenticated the user first (shipped in v0.3.0). The desktop
equivalent is carried by Phase 1 below, and shipped in v0.4.0.

### Phase 1 — v0.4.0, "wider"

| ID | Deliverable | Notes |
|---|---|---|
| R9 | **Client resilience** | Background reconnect, node health probing, automatic removal of dead nodes, and the results exposed through the R7 metrics |
| R10 | **Transport parity** | IPv6 inside the TUN (virtual IPv6 addresses plus AAAA answers). The UDP half of this was already done — the old note claiming otherwise was wrong |
| R11 | **Android ABI coverage** | Ship `x86_64` alongside `arm64-v8a`, or at least document why not |
| R12 | **Backend handling** | Configurable connect/read/idle timeouts towards backends, `least_conn` for the pool, and an explicit failure when every backend is unhealthy instead of falling back to the first — see [4.1](#41-backend-handling-p2) |
| R15 | **Client DNS cache semantics** | Make the cache answer only what it actually holds: key it on QCLASS as well as name and type, scope it to the resolvers that produced the answer, rewrite each record's TTL on every hit to the part that is left, and stop caching a zero TTL — see [4.8](#48-client-dns-resolution-p1) |

Per [Platform policy](#5-platform-policy), no iOS work is planned in this phase. A
contributed iOS client would be accepted and clearly marked community-maintained.

**Progress.** Four of the five shipped in v0.4.0, one of them half:

- **R12** backend handling — `[timeouts]`, `least_conn`, and a refusal when
  every backend of a multi-backend route is down.
- **R15** the client DNS cache.
- **R10** transport parity: IPv6 inside the TUN, on Android and on the desktop,
  plus `[iroh] bind_ipv6` on the server. The UDP half of this turned out to be
  already done, so this was the IPv6 half alone.
- **R11** the second Android ABI: one APK per ABI, `arm64-v8a` and `x86_64`.
- **R9** client resilience, the first half: the backends are probed on a timer,
  the probe doubles as the reconnect, and the results are exposed as
  `EndpointGroup::health_snapshot()`. **A dead backend is still handed out** —
  the balancer picks by index into a list it cannot change, so removing one
  needs the group to become mutable, which is a change to every holder of it.
  That is the half that did not ship, and the reason is structural rather than
  a matter of time. The results are also **not** exposed through the R7 metrics:
  those are the server's, and the client has no metrics module of its own.
  **The second half shipped in v0.5.0**, by the narrower route in
  [4.6](#46-client-resilience-p1); the results are now read by whoever picks the
  next node, and the desktop shows them. The client still has no metrics module —
  its counters are read over IPC, not scraped.

One more thing landed in v0.4.0 that is not one of the five: the desktop half of
**R14**, which came here from Phase 0 (§4.7, C8 and C9). It is counted
separately because it is the one item this release finished from the phase
*before*, rather than one of the five this phase opened with.

**Done when:** Android and desktop both complete HTTP, TLS passthrough and UDP
round trips against one server, over both IPv4 and IPv6 — the IPv6 half is R10
and **shipped in v0.4.0**, though it has only been verified by unit tests and
on macOS by hand, since CI has no routable IPv6 — and no desktop surface renders
a full credential without the operating system having authenticated the user
first, which is the half of R14 that came here from Phase 0 and **shipped in
v0.4.0**. The second half of R9 above shipped in v0.5.0, so this phase is
closed.

### Phase 2 — v0.5.0, "observable"

No deliverable was opened for this release. It is what the sections above had
left standing, and the one thing Phase 1 handed over half-done:

| ID | What it was | Notes |
|---|---|---|
| R9 | **Client resilience, the second half** | Health decides which node the next request goes to, and a node that could not be dialled is marked down by the request that found out rather than by the probe thirty seconds later. `select` answers `Option<usize>`, so "none of them" is sayable for the first time. The group is still not mutable, so a down node is skipped rather than removed. See [4.6](#46-client-resilience-p1) |
| C7 | **A probe for the backends that cannot answer `GET /health`** | `passthrough` and `tcp` routes are probed by connecting, a TLS backend by completing its handshake. A `udp`-only route is deliberately still unprobed. See [4.1](#41-backend-handling-p2) |
| — | **Traffic you can see** | The client counts what each node carried, the desktop shows it per node, the Android notification shows live rates, and the server's `/metrics` gained `nexapipe_traffic_bytes_total`. The number is tunnel payload: no headers, nothing discarded, and nothing counted twice — the TUN interface pump is deliberately not instrumented. See [4.2](#42-observability-beyond-the-access-log-p1) |
| R6 | **Distribution, three of its four parts** | A container image published to GHCR with the release archives, a self-hosted relay documented end to end, and a systemd unit for the relay there and for the server in both READMEs. Still open: any of Homebrew, winget and scoop. See [4.4](#44-operations-and-distribution-p1) |
| — | **The root workspace compiles on Windows** | It had no Windows job at all, so `crates/*` had never been built for `x86_64-pc-windows-msvc` outside a release tag. Check only, no tests: the integration tests spawn the binary and reach for `cfg(unix)` fixtures. See [4.4](#44-operations-and-distribution-p1) |

The desktop credential door is not one of these either, though it ships in the
same release: it is the rest of R14 — the whole Config page, rather than the two
commands that could answer with a whole value — so it belongs to the phase that
opened R14, not to this one.

**Done when:** a node that stops answering stops receiving requests without
waiting for the next probe; an operator can say how much an instance carried
without reading the access log; and a newcomer brings up their own relay from
the docs without asking anyone. The first two are shipped. The relay page is
written but has not been followed end to end on a machine that had nothing on it
— which is the one claim here nobody has tested. The Android notification is
not in that position: its rates have been watched running on a device, rather
than resting on unit tests and compilation alone.

### Phase 3 — v0.6.0, "one device at a time"

No new deliverable is opened for this release. It is the item Phase 0 left that
had never started — R5 — and the write half of R4 that was waiting on it, plus
three things small enough that deferring them costs more than doing them. Four
are whole now — see **Progress** below.

| ID | Deliverable | Notes |
|---|---|---|
| R5 | **Per-device credentials** | **Shipped.** One secret per device under a client, issued at enrollment and revocable on its own, instead of one secret shared by every device that names the same `client_id`: the device table, the per-device lookup in the handshake and the `--device` flags are all in `main`, and a `[auth.clients.<id>]` carrying only `secret` keeps working exactly as it did — that is the path a peer naming no device takes, and the path every config written before this release is on. A device struck out no longer keeps the connection it already held: the reload that notices what left `[auth]` closes it. What each client does now is send one — the decision under Phase 3 is how an install decides what to answer as. See [4.3](#43-identity-and-authorization-p1) |
| R5 | **A minimal audit log** | **Shipped.** Who — client *and* device — reached which host, when, and with what outcome. The identity survives the handshake now (`conn/mod.rs`), so an access line and `/v1/connections` can say whose request they are reporting; it used to carry an ACL snapshot and a Node ID and nothing else |
| R4 | **The write half, as CLI subcommands** | **Shipped.** `nexapipe client list\|add\|revoke`, device-scoped, through the writers that already took the config lock; the loopback endpoints stayed GET-only, because widening a token that has no scope in the same release as the thing it would be changing is how a management surface becomes the way in |
| — | **Latency you can read** | **Shipped.** `/metrics` renders `_bucket{le="…"}` beside `_sum` and `_count`, hand-written to keep the exposition dependency-free, so a p99 is read rather than divided out. It carries no labels beyond `le` and no `{route}`: what it answers is "what is this instance's latency", which is the question the meter was missing |
| — | **A systemd unit in the docs** | **Shipped.** `docs/self-hosted-relay.md` carries a unit for the relay and both READMEs one for the server, each with the directives dated so a reader can tell what assumes how old a systemd. The server's is the harder of the two to make safe: it writes back into its own config — 2FA counters, an enrolled device — and writes its admin token beside it, so it keeps a named account and one writable directory rather than the `DynamicUser` the relay can run under. See [4.4](#44-operations-and-distribution-p1) |
| — | **Windows runs the tests** | **Shipped.** The job was `windows-check`, a `cargo check --workspace --all-targets`, so the integration tests compiled for `x86_64-pc-windows-msvc` and nothing executed them — a bug that only appears when they run reached a tag before CI saw one. It is `windows-test` now and runs the same command the Linux and macOS runners do. See [4.4](#44-operations-and-distribution-p1) |

**Progress.** All six are whole. Whole: the identity threading that lets
an access line and `/v1/connections` name client *and* device (R5, audit log),
`client list|add|revoke` with `--device` (R4), latency buckets on `/metrics`,
`windows-test` actually running the tests, and a systemd unit for the relay in
that page and for the server in both READMEs. R5's device table is whole too: a
secret per device, looked up per device at the handshake, and a revoke that
reaches the connections the device already holds, not only the next one it
dials.

What stood here last was a decision rather than a defect: **no client sent a
device name.** The wire has carried `device_id` since the enrollment work —
`Option`, so a peer that names none takes the client's own secret exactly as it
always did — but the client library never grew the field, so every device was
the device that names none, and per-device credentials were reachable from
`--device` and from nothing else. Giving each install a name was small in the
library and larger in the apps: something had to decide what the name is, carry
it beside the credential rather than inside it, and keep answering as nobody for
the credentials that were never issued to a device. Each of them does now.

**Done when:** revoking one of three devices leaves the other two working,
without anybody editing `config.toml` by hand, and a connection that device
already had open closes when it happens; `nexapipe status` and the access log
can both say which device reached which host; and a p99 can be read off
`/metrics` without summing anything by hand.

Three things are deliberately *not* in this release, and saying which is the
point of listing them:

- **Not per-device key pairs.** §4.3's direction is keys signed by the server,
  with TOTP as a human second factor. This release makes revocation true and
  leaves the kind of credential alone: a key pair also means new material in both
  credential stores and a factor an unattended service cannot supply, and putting
  both in one release is how "revoke one device" turns into a release that ships
  nothing.
- **Not a write API.** `client add\|revoke` arrives as subcommands, not as
  `POST /v1/clients`. The admin token is one opaque value with no scope and no
  rotation, and giving it something to change is a decision of its own.
- **Not package managers.** Homebrew, winget and scoop are each a day of
  manifest and then a tap or bucket that somebody has to own. After this release
  they are the only part of R6 still open.

### Hardening sweep — after v0.6.0

Three findings of the [2026-10-10 audit](#49-security-and-stability-audit-2026-10-10-p0p1)
are not defects. Each is work with a shape of its own rather than a line to
change, and they are the only part of that audit that belongs in a plan at all.
They carry high IDs because they were written after R13, like R14 and R15.

| ID | Deliverable | Notes |
|---|---|---|
| R16 | **A resource budget for the process** | A global ceiling on concurrent connections and in-flight streams to sit beside the per-peer one, plus a global budget for bytes held in request bodies. The per-peer limit answers *"one peer cannot crowd out the rest"*; nothing today answers *"the process cannot be crowded out"*, and an `EndpointId` is a public key. Configurable, defaulted generously enough for a client that opens a connection per in-flight request |
| R17 | **One deadline per phase** | A single place that says how long a header read, a body read, a response stream, an L4 flow and a tunnel may take, covering both listeners and both clients — so the six timeout gaps in §4.9 close once and stay closed. A per-read timeout that re-arms on every read is what lets a one-byte trickle hold a slot indefinitely; a phase deadline is not |
| R18 | **Supply chain verification** | `cargo deny` beside the two `cargo audit` jobs — advisories are the only thing `audit` checks, and this tree has a vendored crate, two lockfiles and several duplicate versions — actions pinned to SHAs, base images by digest, `--locked` in the Dockerfiles, and signed images with provenance. None of it changes what NexaPipe does; it decides whether a release can say where it came from |

No phase number is attached to these: it is a sweep, not a release, and it
competes with R13 for the same attention. What puts it ahead is that R13 is still
behind its own gate — the premise has not been validated — while this is what the
tree says about itself today.

### Phase 4 — v1.0, "reachable without our client" (exploratory)

| ID | Deliverable | Notes |
|---|---|---|
| R13 | **`nexapipe-edge`, a separate optional binary** | Deployed on a host with a public address (possibly beside the relay), it gives visitors who will not install anything an ordinary `https://` URL. Separate process, off by default, certificates left to ACME or Caddy — the core keeps its "never terminates TLS" property. Scope: hostname to route mapping and basic access control |

Gate: validate the premise first. If "visitors must install a client" turns out
not to be the main reason people walk away, this stays shelved.

### Phase 3.5 — v0.6.1, "weighed"

No new capability is opened for this release, and that is the point: it exists
because the artifact-size work in [`size-perf-roadmap.md`](size-perf-roadmap.md)
needs a measurement before it can change anything, and three of the four shipped
artifacts have never had their size written down. One item, no user-visible
feature behind it.

| ID | Deliverable | Notes |
|---|---|---|
| S1 | **Size and benchmark reporting in CI** | A `size-report` job recording every shipped artifact — server archives per target, desktop bundles, both APKs, the `.so` per ABI, `dist` — with `cargo bloat` attribution beside it, plus criterion baselines for the L4 forward, the TUN pump and the end-to-end forwarding path. Nothing is optimized until this lands: the desktop alone is an unknown, because `ui-desktop/src-tauri` is excluded from the root workspace and therefore builds with cargo's default profile, where `opt-level = 3`, LTO and `strip` are set. Full detail and the reasoning behind the ordering is in [`size-perf-roadmap.md`](size-perf-roadmap.md) |

S2 (the desktop release profile), S3 (Android R8) and F2 (optimizing whatever
the benchmarks find) all follow this, and deliberately not in the same release:
the desktop profile is a near-free win and the R8 work is not, and bundling
them means a shrinker regression rolls back the free win too.

**Done when:** every artifact `release.yml` publishes has a size recorded in CI,
and a PR that adds a dependency says what it cost.

### Dependencies

```text
R8 boundary docs ─────────────────────────────────────► shipped in v0.3.0
R7 metrics ───────────────────────────────────────────► shipped in v0.3.0
R14 credential lock ── Android ───────────────────────► shipped in v0.3.0
                    └── desktop ──────────────────────► shipped in v0.4.0
R4 management ── R5 per-device ──┬── R6 distribution ──► v0.4.0
        (read-only shipped in v0.3.0; the write half waits on R5)
                                              │
      R9 resilience ── R15 DNS cache ──┬── R10 transport ── R11 Android ABI ──► v0.4.0
                                       └── R12 backends ──────────────────────►
                                              │
                                              ├── R9 second half ─────────────► v0.5.0
                                              ├── C7 probe ───────────────────► v0.5.0
                                              ├── R6 image + relay docs ──────► v0.5.0
                                              ├── R7 byte counters ──────────► v0.5.0
                                              │
                                              ├── R5 per-device ─────────────► v0.6.0
                                              ├── R5 audit log ──────────────► v0.6.0
                                              ├── R4 client CLI ─────────────► v0.6.0
                                              ├── latency buckets ───────────► v0.6.0
                                              ├── systemd unit ──────────────► v0.6.0
                                              ├── Windows runs the tests ────► v0.6.0
                                              │
                              R13 edge (after validation) ──► v1.0

        S1 measure ──┬── S2 desktop profile ──┐          (size-perf-roadmap.md)
                     └── S3 Android R8 ───────┴── S4 budget gate
        F1 benches ──────► F2 targeted work ───► F3 perf budget
```

Of that row, R15, R12, R10 and R11 shipped in v0.4.0. R9 shipped its probing
half there and its selection half in v0.5.0 — see the progress note under
Phase 1 and the table under [Phase 2](#phase-2--v050-observable). R6 is nearly
done: the image, the relay docs and both systemd units landed — only the package
managers are still open after them. R5's
credentials and the write half of R4 are in `main`; what that phase still owes
is the other half of making revocation true, which the dependencies graph does
not separate out because the two halves share a deliverable. R13 keeps its id
and its gate; what moved is the phase number above it, because v0.6.0 was
inserted beneath it. The size and performance chain at the bottom is not part of
this document's numbering: it is `S*` and `F*` rather than `R*`, and its detail
lives in [`size-perf-roadmap.md`](size-perf-roadmap.md). Only S1 lands in
[v0.6.1](#phase-35--v061-weighed), because nothing else in that document can be
verified until S1 says what the artifacts weigh today.

---

## 7. Non-goals

- **Terminating TLS in the core.** Certificates belong to the backend (Caddy).
  The exploratory edge component is deliberately a separate binary.
- **Becoming a general mesh VPN.** No full L3 mesh, no arbitrary internal-IP
  reachability. Category C already does that better; the routing model stays
  hostname-based.
- **WAF, DDoS mitigation, anycast.** Those need an edge network.
- **Multi-tenancy and billing.** Same reason there is no control plane.

---

## 8. How we know this worked

| Measure | Today | Target |
|---|---|---|
| First deploy to first successful request | requires reading the config reference, generating a secret, an invite and an import | under 10 minutes on one quickstart page |
| Time to locate a failing backend | the access log covers every path, but there is nothing to aggregate | 5 minutes with metrics and structured logs |
| Direct-connection rate | unmeasured | opt-in client telemetry: direct vs relayed, one-way latency — so "nothing to rent" becomes a number we can publish |
| Platform coverage | Android (one ABI) + desktop | TUN speaks IPv6, Android ships a second ABI (the desktop TUN already does UDP) |
| Revoking one device | rotating the shared secret, which is every device using that client | one device, including a connection it already holds; the others keep working |
| Full secret rendered without authentication | both clients ask the operating system first — Android as of v0.3.0, desktop as of v0.4.0 — and both have been watched running on every platform they support | zero: every surface that can reach a full value asks the operating system to authenticate the user first |
| Release rhythm | one `CHANGELOG.md` as of v0.3.0, and no released version carries an entry older than its own tag | regular minor releases, each with a readable CHANGELOG |
| Artifact size and speed | three of the four shipped artifacts have never been weighed, nothing in CI measures size, and there is no benchmark anywhere | every artifact reported per PR, a budget that gates once a release has shipped clean, and three benches — see [`size-perf-roadmap.md`](size-perf-roadmap.md) |

---

## 9. Evidence index

Every gap listed above was confirmed against the tree on 2026-09-28, and each
entry here was re-checked on 2026-09-29 against what v0.3.0 actually shipped.
The gaps [Phase 3](#phase-3--v060-one-device-at-a-time) opens were confirmed
the same way on 2026-10-07, against the tree at `8abc38c`.
Entries closed since the audit are marked in place rather than deleted: the
audit that found them stays reproducible, and the before and after stay visible
side by side. The three fixed defects are recorded in
[section 4](#4-self-review-what-is-missing) and in the commit history.

A second audit, read-only and covering the whole tree including CI and the
Dockerfiles, was run on 2026-10-10 against `24937db`. Most of its findings are
**open rather than fixed**, so they are recorded in
[4.9](#49-security-and-stability-audit-2026-10-10-p0p1) and in the last row
below — the four fixed later that day are marked where they sit; the three that
are capability work rather than defects are in
[§6](#hardening-sweep--after-v060) as R16–R18.

| Topic | Location |
|---|---|
| HTTP/1.1-only backend client | `crates/nexapipe/src/http/mod.rs:13-32` |
| Load balancing strategies and fallback | `crates/nexapipe/src/lb/mod.rs:6-9,83-90` |
| Health checks skipped for three route modes | *closed in v0.5.0, apart from the one mode that cannot be.* Was "`passthrough`, `tcp` and `udp` routes are never probed" at `crates/nexapipe/src/proxy/mod.rs:58-65`. Now `passthrough` and `tcp` routes get a TCP connect probe — liveness rather than health, and a TLS listener is hung up on mid-handshake — while a `udp`-only route is deliberately left unprobed, because inventing a datagram would report an answer no backend gave (`crates/nexapipe/src/health/mod.rs:30-47`, `:193-197`). |
| No IPv6 in the TUN | *closed in v0.4.0.* Was "AAAA queries are answered empty (`ANCOUNT=0`)" at `crates/nexapipe-client/src/tun_proxy.rs:1178-1180`. Now an AAAA query in the Internet class gets a 16-byte answer out of a virtual pool (`:1324-1340`, `:1472-1475`), on both clients; the desktop's pool is best effort, since `configure_ipv6` may be refused per platform. |
| Client DNS cache semantics | `crates/nexapipe-client/src/tun_proxy.rs:1269` (question parsed without QCLASS), `:1542-1543` with the clamp at `:1664` (TTL bounds), `:1551` (cache key), `:1571-1587` (a hit rewrites the transaction ID only) |
| No node health or reconnect | `crates/nexapipe-client/src/endpoint_group.rs` (no health state); retry at `local_proxy.rs:267` |
| Metrics and admin surface | *closed in v0.3.0.* Was "no `prometheus`/`metrics` match anywhere in the tree; CLI subcommands limited to those in `main.rs:30-144`". Now `crates/nexapipe/src/metrics.rs` (counters and hand-written exposition), `src/admin/` (`/healthz`, `/metrics`, `/v1/*` behind `<config>.admin-token`) and `src/status.rs` (`nexapipe status`). **The write subcommands arrived in v0.6.0** — `client add\|revoke`, device-scoped, as subcommands rather than as endpoints, so the token stayed GET-only. The same release added what R7 asked for beside the gauges: a request ID per request (`log::next_request_id`, on the access line and as `x-request-id`) and a span around each one. |
| CHANGELOG, image publication | *closed in v0.5.0.* `CHANGELOG.md` has been at the repository root since v0.3.0; the image half lands with this release, where `build-image` pushes one leg per architecture by digest and `publish-image` merges them into a single multi-arch manifest under `ghcr.io/open-nexa/nexapipe` — `:latest` only for a tag with no prerelease suffix (`.github/workflows/release.yml:1018`, `:1097`). |
| iroh version and boundary conditions | `Cargo.toml:38` asks for `^1.0.1` and `Cargo.lock` resolves 1.2.0 — a caret range, not the pin an earlier note here claimed. The boundaries themselves are documented in `docs/iroh-boundaries.md`, linked from the `[iroh]` section of both READMEs. |
| No iOS answer despite the bindings | `crates/nexapipe-client/Cargo.toml:58-59` carries an iOS-scoped `webpki-roots` dependency; no Apple target or app exists |
| Desktop: credentials encrypted, but ungated | `ui-desktop/src-tauri/src/credentials.rs` (keychain master key + `credentials.v1.json`, covers TOTP secret, enrollment token, relay token) versus `ui-desktop/src/stores/config.ts` (`ticket` and `endpointId` still persisted in cleartext `localStorage`; nothing prompts before a read) |
| Masking that is not masking | `ui-desktop/src/app/shell/SideBarFooter.vue:59` puts the full node ID in a tooltip while showing the short form; the dashboard and config pages return short values in full |
| Android: encrypted at rest, no gate in front | `ui-android/.../SecretStore.kt` (Keystore AES-256-GCM, `v1:` prefix) versus `ui/EndpointDetailScreen.kt` (shows and edits the 2FA secret, ~349-416, and exports an `otpauth` URI) |
| One credential per client, not per device | ***closed in v0.6.0.*** Was "`crates/nexapipe/src/auth/config.rs:54` (`clients: HashMap<String, ClientAuth>`), `:102` (the one `secret`); `auth/totp.rs:66` (looked up by the name off the wire, with no binding to the connecting peer); `conn/mod.rs:784-936` (`enroll_client` overwrites that one secret, which is why enrolling a device rotates every other one). Nothing is keyed by device: every `device` match in `crates/nexapipe/` is prose — a comment, a log line, the CLI's own banner at `main.rs:819` ("there is no per-device revocation") — or a client id in a test fixture (`config.rs:2706`)". Now a client carries a `devices` table beside its own `secret`, each entry with a secret of its own, and the handshake looks up whichever of the two the peer asked for. Enrolling one device rotates that device and leaves the others alone, and a `revoke` reaches the connections it already holds: the reload that notices what left `[auth]` closes them, rather than waiting for the peer to dial again. Every client names a device of its own now — see **Progress** under [Phase 3](#phase-3--v060-one-device-at-a-time) |
| No audit trail | ***closed in v0.6.0, for what the server can say from its own side.*** Was "the two `audit` matches under `crates/` are both unrelated — `metrics.rs:8` ("an audit surface", about a dependency) and `nexapipe-client/src/transport.rs:201`. `client_id` does not survive the handshake: `conn/mod.rs:156-165` hands `handle_bidi_stream` an ACL snapshot and a Node ID, so the three `log_access` calls at `:326`, `:402` and `:427` cannot say whose request they are logging, and `/v1/connections` (`admin/mod.rs:376-400`) reports no client at all". Now the connection carries the authenticated client *and* device, so every access line has both to draw on and `/v1/connections` answers who is connected rather than only how many. What is still missing is the *per-request* operator view — nothing aggregates those lines, and there is no exporter to send them anywhere: see [4.2](#42-observability-beyond-the-access-log-p1) |
| Latency as a sum, not buckets | ***closed in v0.6.0.*** Was "`crates/nexapipe/src/metrics.rs:96` (one `AtomicU64`), `:177-181` (the single `fetch_add`), `:335-344` (rendered as a plain counter, with the reason for that written immediately above it). No `histogram`, `bucket` or `prometheus` crate anywhere in the tree". Now `request_duration_ms` is twelve buckets over fixed boundaries with `+Inf` above them, accumulated per boundary and rendered cumulative on the way out so a partially-collected request cannot make the series non-monotonic (`:105-120`, `:426-459`). Still written by hand, so still no dependency added — and no `opentelemetry`/`otlp` match outside this document, which is a separate gap and still an open one |
| No unit, and Windows compiles only | ***closed in v0.6.0.*** Was "no `*.service` in the repository or the docs; `docs/self-hosted-relay.md:103-107` starts the relay as a foreground command, and the only unit generated anywhere is the desktop service's, at runtime (`ui-desktop/src-tauri/src/service/platform.rs:887-906`, `Restart=on-failure`). Windows: `.github/workflows/ci.yml:122-140` runs `cargo check --workspace --all-targets --locked`, with the note at `:138` that the tests are compiled and not run". Now `docs/self-hosted-relay.md` carries a unit for the relay and both READMEs one for the server, each with the directives dated so a reader can tell what assumes how old a systemd — and `ci.yml` runs `cargo test --workspace --locked` on `windows-latest` under the name `windows-test`. What R6 still owes is not a unit but a package manager |
| Security and stability audit, 2026-10-10 | ***mostly open and not scheduled — these are defects, but nine were fixed over the days that followed.*** 7 high, 30 medium and 20 low findings; the five P0s are the desktop build resolving `smoltcp` from crates.io because the root `[patch.crates-io]` never reaches it (`Cargo.toml:7`, `:24-25` versus `ui-desktop/src-tauri/Cargo.lock`), `tauri.macos.conf.json:28-30` removing the baseline CSP from a webview holding 35 command permissions, `crates/nexapipe/src/conn/limits.rs:1-21` limiting per peer and not per process, `crates/nexapipe-client/src/tun_proxy.rs:1211` growing a reassembly buffer with no bound while `:765` spawns TCP flows with no cap, and `ui-android/.../SecretStore.kt:107-140` returning plaintext when the Keystore is unavailable. What the audit cleared is recorded beside them: no open-proxy or SSRF surface, no committed credential, no `unsafe` or production-path `unwrap` in the server, and authentication, 2FA and ACL that hold up under reading. Nine were fixed over the days that followed, on branches cut from `c1db94b` and later: the macOS CSP deletion (`fix/desktop-macos-csp`), the `[peers]` control that failed open (`fix/peers-refuse-unknown-keys`), the JNI entry with no panic barrier (`fix/android-stop-tun-panic-guard`), `--qr-out` writing a secret world-readable and over an existing file (`fix/qr-out-create-private`), the desktop build reaching the vendored `smoltcp` patch (`fix/desktop-smoltcp-patch`), a budget per TUN flow (`fix/tun-flow-budgets`), the native stop leaving the main thread (`fix/android-stop-vpn-off-main-thread`), a credential no longer stored unencrypted without being asked (`fix/android-credential-downgrade-confirm`) and a preconnect budget that covers both of its halves (`fix/preconnect-budget-covers-grace`). Full review with all 63 findings and their fixes: `.workbuddy/CODE_REVIEW-2026-10-10.md`. See [4.9](#49-security-and-stability-audit-2026-10-10-p0p1) |

# NexaPipe roadmap

Short version: the architecture is sound and genuinely differentiated; what is
missing is operational maturity. This document records where NexaPipe stands
against the market, what is broken or missing today, and the order in which we
intend to fix it.

| | |
|---|---|
| Last updated | 2026-09-29 (phases renumbered for v0.3.0; entries closed by it marked in §9) |
| Scope | server, client library, Android and desktop apps. Community-maintained targets follow [Platform policy](#5-platform-policy). |
| Status | Living document. Items come from code audits and reviews. |

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

- Identity is one shared TOTP secret per client, so revoking one device means
  rotating every device using that client.
- Platform coverage has real holes: no IPv6 inside the TUN, a single Android
  ABI. (The desktop TUN does UDP; this list used to claim it did not. See
  [4.5](#45-protocols-and-transport-p1p2).)
- Release hygiene is thin: `CHANGELOG.md` arrived with v0.3.0, but there is
  still no published container image (the Dockerfiles build locally only), no
  package manager distribution, and no documented way to run your own relay.

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
| Identity granularity | shared TOTP + host allowlist | bring your own | none | **SSO, OIDC, share links, audit** | Access (SSO) | IdP + ACLs | identity + private shares |
| Observability | **access log only** | dashboard | none | dashboard + Traefik metrics | rich | rich | some |
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

What follows is what is *missing*, i.e. capability work.

### 4.1 Backend handling (P2)

| # | Gap | Where |
|---|---|---|
| C3 | **Still open.** HTTP/1.1 only towards backends: the client is `legacy::Client<HttpConnector>` with only `http1_*` configuration, `https://` backends are rejected at load time, and there is no retry and no circuit breaking. The *configurable timeout* half is done (v0.4.0): `[timeouts] connect_secs` / `response_secs`, each optional and defaulted to the constant it replaced. | `http/mod.rs:13-32` |
| C4 | **Partly closed in v0.4.0.** `least_conn` exists, and an all-unhealthy pool now refuses instead of falling back to the first — except a pool of one, which is still handed out because there is nothing to choose between. Still open: no retry, no circuit breaking, and `least_conn` counts requests rather than sockets (see the note at `http::proxy_request`). | `lb/mod.rs` |
| C7 | **Narrower than it read.** `passthrough`, `tcp` and `udp` routes are never probed, but a route serving `http` *and* another mode shares one pool, so the other modes do inherit its health — and in v0.4.0 they answer `BackendFailed` / hang up when it is empty. What is missing is a probe for the modes that cannot answer `GET /health`. | `proxy/mod.rs:58-65` |

### 4.2 Observability beyond the access log (P1)

The access log now covers every path, and `/metrics`, `/healthz`, a request ID
and a span per request cover the instance: see R7. What is still missing is an
OpenTelemetry exporter, and a desktop UI that shows no traffic, latency or
per-node health view.

### 4.3 Identity and authorization (P1)

Authentication is a symmetric TOTP secret per `client_id`. Devices sharing a
client share a secret, so revoking one device rotates all of them — the README
says so. There is no per-device identity, no mTLS, no OIDC, no API keys, and no
audit trail of who reached which host.

The direction is already right: the `v=2` invite with a one-shot enrollment token
downgraded "leaked URL means leaked credential forever" to "leaked URL is
revocable and short-lived". The next step is per-device keys signed by the server,
with TOTP as a human second factor rather than the device identity itself.

### 4.4 Operations and distribution (P1)

- The management surface is read-only for now: `/v1/*` and `nexapipe status`
  answer "which routes are live" and "who is connected", but nothing can change
  them — adding or revoking a client still means editing `config.toml` by hand
  or generating an invite from the CLI. Writes wait on R5's identity model.
- Hot reload rules are one table in both READMEs as of v0.3.0, including what
  needs a restart. What is still uneven is enforcement, not documentation.
- Distribution is download-only: GitHub release archives, a signed APK and
  desktop bundles. No container image publication, no systemd unit in the docs,
  no Homebrew / winget / scoop packages, no documented self-hosted relay.
- Engineering hygiene: `CHANGELOG.md` exists as of v0.3.0; the test suite runs
  on Linux and macOS runners, while Windows is `cargo check` only; the Android
  lint baseline still pins 32 historical findings; no fuzzing, no benchmarks;
  the vendored smoltcp patch needs long-term tracking.

### 4.5 Protocols and transport (P1/P2)

- **No IPv6 inside the TUN**: AAAA queries are answered empty (`ANCOUNT=0`).
  `crates/nexapipe-client/src/tun_proxy.rs:1178-1180`
- **The desktop TUN does UDP** — one `l4::open_udp` bi-stream per flow, through
  the same smoltcp stack the Android client runs
  (`ui-desktop/src-tauri/src/proxy/tun_proxy.rs`). This list used to claim
  otherwise and was wrong. The local proxy, which is the `--local-proxy` mode
  rather than the TUN, still speaks `CONNECT` only — a different path, and not
  the same gap. What is actually missing here is IPv6, above, which makes R10
  smaller than this section once made it look.
- The iroh endpoint binds `0.0.0.0` unconditionally; there is no IPv6 knob.
  `proxy/mod.rs:220`

The iroh dependency boundaries used to belong on this list — discovery via
`dns.iroh.link`, far-side n0 relays. They are documented in
`docs/iroh-boundaries.md` as of v0.3.0, so what remains is the exposure itself,
not the absence of a description of it.

### 4.6 Client resilience (P1)

No background reconnect loop, no node health probing, and dead nodes are never
removed from rotation (`endpoint_group.rs` keeps no health state). Multi-node
failover is request-level only: drop the stale connection and retry three times
— `open_stream_with_retry` at `local_proxy.rs:473`, `OPEN_ATTEMPTS = 3` at
`:119`, each attempt bounded by `[timeouts] connect_secs`. Health is consulted
exactly once, before anything starts: `endpoint_group.rs:577-679`
`preconnect_report` decides whether startup succeeded and is never asked again.

*Not started as of v0.4.0* — R9, and the item this phase drops first. The
structural cost is that `EndpointGroup` has no interior mutability
(`endpoint_group.rs:106-109`), so nothing can add or remove a node while it is
in use.

### 4.7 Client-side credential protection (P0)

Both clients hold the material that authenticates a node — endpoint ID, ticket,
TOTP secret, enrollment token, relay auth token. This is the only item here
rated P0: the exposure is a credential disclosure, not a missing convenience.

Both clients already encrypted credentials at rest — the desktop with a
keychain-held master key, Android with the Keystore — and neither asked anything
before handing them back. Stating that precisely mattered because it decided
what the work was: **the vault existed, the door did not.** Android's door
shipped in v0.3.0 and the desktop's in v0.4.0, so both halves of R14 are now
built. What neither half has is a prompt that has been watched running on every
platform it claims to support.

| # | Gap | Where |
|---|---|---|
| C8 | **Desktop: closed in v0.4.0.** The ticket and the endpoint ID join the TOTP secret, the enrollment token and the relay bearer in the encrypted store — a payload left over from an older build is migrated into it on the way in — and reading any of it back now costs an answer from the operating system: one trait, three platform modules, and a two-minute window in memory. A keychain item whose access control requires user presence on macOS, Windows Hello with a `LogonUserW` fallback on Windows, PAM with a password the UI collects on Linux. A machine with nothing to confirm anybody with is refused rather than downgraded. **Not confirmed on Windows or Linux**: the window is pinned by unit tests and the macOS prompt has been driven by hand, but neither of the other two has been watched running. | `ui-desktop/src-tauri/src/gate.rs` and `gate/{macos,windows,linux}.rs`; `credentials.rs` for the store |
| C9 | **Closed with C8, in v0.4.0.** Masks come from `credentials::mask` in Rust, so a value is never in the renderer that is drawing it shortened; an invite is accepted by `accept_invite`, which files the credentials itself and answers with a receipt carrying none of them; and `reveal_credential` / `reveal_node_id` are the only two commands that answer with a whole value, which is what makes them the two the door stands in front of. | `ui-desktop/src-tauri/src/credentials.rs`, `src/lib.rs` |
| C10 | **Android asks first, as of v0.3.0.** At-rest storage was never the problem — `SecretStore` already wrapped values with Keystore AES-256-GCM. What was missing was the prompt, and `auth/CredentialGate.kt` now supplies one in front of the TOTP secret, its `otpauth` export and any change to the relay configuration, refusing a device enrolled with neither a biometric nor a screen lock. **Not confirmed on a device**: CI could give compile, unit tests and lint, but nothing past `BiometricPrompt` itself has been seen running. | `ui-android/.../auth/CredentialGate.kt`, `ui/EndpointDetailScreen.kt`, `ui/VpnControlScreen.kt` |

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

---

## 5. Platform policy

Supported targets today are **Linux, macOS and Windows** (server and desktop app)
and **Android** (only `arm64-v8a` is shipped).

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

Widening Android beyond `arm64-v8a` (at minimum `x86_64`, for emulators and the
long tail of Intel-based devices) is treated as normal roadmap work, unlike iOS.

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
which is R5, **not yet started**, and the read-only half of R4 shipped without
it; a newcomer brings up a self-hosted relay from the docs without asking
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
v0.4.0**. The one thing still open from this phase is the second half of R9
above.

### Phase 2 — v1.0, "reachable without our client" (exploratory)

| ID | Deliverable | Notes |
|---|---|---|
| R13 | **`nexapipe-edge`, a separate optional binary** | Deployed on a host with a public address (possibly beside the relay), it gives visitors who will not install anything an ordinary `https://` URL. Separate process, off by default, certificates left to ACME or Caddy — the core keeps its "never terminates TLS" property. Scope: hostname to route mapping and basic access control |

Gate: validate the premise first. If "visitors must install a client" turns out
not to be the main reason people walk away, this stays shelved.

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
                              R13 edge (after validation) ──► v1.0
```

Of that row, R15, R12, R10 and R11 shipped in v0.4.0. R9 shipped its probing
half; the half that removes a dead backend from rotation did not, and stays
here for the next release. See the progress note under Phase 1.

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
| Full secret rendered without authentication | both clients ask the operating system first — Android as of v0.3.0, desktop as of v0.4.0 — and neither has been watched running on every platform it supports | zero: every surface that can reach a full value asks the operating system to authenticate the user first |
| Release rhythm | one `CHANGELOG.md` as of v0.3.0, and no released version carries an entry older than its own tag | regular minor releases, each with a readable CHANGELOG |

---

## 9. Evidence index

Every gap listed above was confirmed against the tree on 2026-09-28, and each
entry here was re-checked on 2026-09-29 against what v0.3.0 actually shipped.
Entries closed since the audit are marked in place rather than deleted: the
audit that found them stays reproducible, and the before and after stay visible
side by side. The three fixed defects are recorded in
[section 4](#4-self-review-what-is-missing) and in the commit history.

| Topic | Location |
|---|---|
| HTTP/1.1-only backend client | `crates/nexapipe/src/http/mod.rs:13-32` |
| Load balancing strategies and fallback | `crates/nexapipe/src/lb/mod.rs:6-9,83-90` |
| Health checks skipped for three route modes | `crates/nexapipe/src/proxy/mod.rs:58-65` |
| No IPv6 in the TUN | `crates/nexapipe-client/src/tun_proxy.rs:1178-1180` |
| Client DNS cache semantics | `crates/nexapipe-client/src/tun_proxy.rs:1269` (question parsed without QCLASS), `:1542-1543` with the clamp at `:1664` (TTL bounds), `:1551` (cache key), `:1571-1587` (a hit rewrites the transaction ID only) |
| No node health or reconnect | `crates/nexapipe-client/src/endpoint_group.rs` (no health state); retry at `local_proxy.rs:267` |
| Metrics and admin surface | *closed in v0.3.0.* Was "no `prometheus`/`metrics` match anywhere in the tree; CLI subcommands limited to those in `main.rs:30-144`". Now `crates/nexapipe/src/metrics.rs` (counters and hand-written exposition), `src/admin/` (`/healthz`, `/metrics`, `/v1/*` behind `<config>.admin-token`) and `src/status.rs` (`nexapipe status`). The write subcommands (`client add\|revoke`) are still absent. The same release added what R7 asked for beside the gauges: a request ID per request (`log::next_request_id`, on the access line and as `x-request-id`) and a span around each one. |
| CHANGELOG, image publication | *half closed in v0.3.0.* `CHANGELOG.md` exists at the repository root; image publication does not, and `.github/workflows/release.yml` still produces archives, desktop bundles and the APK only. |
| iroh version and boundary conditions | `Cargo.toml:38` asks for `^1.0.1` and `Cargo.lock` resolves 1.2.0 — a caret range, not the pin an earlier note here claimed. The boundaries themselves are documented in `docs/iroh-boundaries.md`, linked from the `[iroh]` section of both READMEs. |
| No iOS answer despite the bindings | `crates/nexapipe-client/Cargo.toml:58-59` carries an iOS-scoped `webpki-roots` dependency; no Apple target or app exists |
| Desktop: credentials encrypted, but ungated | `ui-desktop/src-tauri/src/credentials.rs` (keychain master key + `credentials.v1.json`, covers TOTP secret, enrollment token, relay token) versus `ui-desktop/src/stores/config.ts` (`ticket` and `endpointId` still persisted in cleartext `localStorage`; nothing prompts before a read) |
| Masking that is not masking | `ui-desktop/src/app/shell/SideBarFooter.vue:59` puts the full node ID in a tooltip while showing the short form; the dashboard and config pages return short values in full |
| Android: encrypted at rest, no gate in front | `ui-android/.../SecretStore.kt` (Keystore AES-256-GCM, `v1:` prefix) versus `ui/EndpointDetailScreen.kt` (shows and edits the 2FA secret, ~349-416, and exports an `otpauth` URI) |

# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
One tag releases everything at once: the server archives, the desktop bundles
and the signed Android APK come out of `.github/workflows/release.yml`.

For what comes next, and for why some things are deliberately not planned, see
[docs/ROADMAP.md](docs/ROADMAP.md).

## [0.6.0] — 2026-10-11

A readable version of this release, with downloads, is published at
<https://open-nexa.github.io/nexapipe/v0.6.0.html>. The page itself
lives in `docs/releases/`, and only that directory reaches the site.

Two configuration keys are added and none is removed or renamed, so a
`config.toml` that works on 0.5.0 loads unchanged on 0.6.0, and a client written
before devices existed answers exactly as it did. Four things behave
differently without being configured to: `/metrics` no longer carries the
request-duration counter it used to, a device struck out loses the connections
it is already holding, a revoked peer is closed with a new code — `6` — and an
enrollment that would replace a device already in the table is refused.

### Added

- **One credential per device, rather than one shared by every device that
  names a client.** `[auth.clients.<id>]` gains a `devices` table: each entry
  carries a secret of its own, issued at enrollment and revocable on its own, so
  striking one out no longer rotates the rest. The credential is still a TOTP
  secret and the handshake still HMAC-SHA256 over `nonce ‖ timestamp`; what
  changed is which secret is looked up. A client entry carrying only `secret`
  keeps working exactly as it did.

- **A client names the device it is speaking as.** Each install answers as one
  named device of itself: the desktop after its hostname, Android after the
  device model, eight random characters behind either so two machines sharing a
  name do not collide. The name is claimed at enrollment and nowhere else — the
  server refuses a device it has no secret filed for — so existing credentials
  carry on answering as they do today and nothing re-enrolls on its own.

- **An access line says whose request it was.** Every access line ends with
  `client=… device=…`, and `/v1/connections` answers who is connected rather
  than only how many. A request that never authenticated gets neither field.

- **`nexapipe client list|add|revoke`**, each with `--device`, writing
  `config.toml` through the same lock the server reads it with, so a running
  instance picks the change up on its next reload. `/v1/*` stays read-only on
  purpose: its token is one opaque value, with no scope and no rotation.

- **`[auth.clients.<id>].unnamed_device_allowed`** (default `true`): set to
  `false`, a peer that names no device is refused rather than answered under the
  client's shared secret — the one path a device cannot be taken off by being
  revoked, since nothing in the table belongs to it alone.

- **A systemd unit for the server** in both READMEs, beside the Docker section.
  It keeps a named account and one writable directory, because this server
  writes back into its own config — the 2FA counters, an enrolled device — and
  writes its admin token beside it. The relay has had a unit in
  `docs/self-hosted-relay.md` since earlier in this release.

- Desktop: session totals, and a page that lists the connections a running proxy
  is holding (#90).
- Desktop: a running proxy says what quitting should do (#88).
- CI: the root workspace is *tested* on Windows, not only compiled (#97).
- Docs: a systemd unit for the relay (#95); what v0.6.0 shipped, in the roadmap
  sections that describe it (#123); which secret an enrollment rotates (#124);
  a size and performance roadmap (#136).
- CI: dependabot's per-dependency version pull requests are replaced by one
  weekly dependency issue (#127).

### Changed

- **`/metrics` reports request latency as a histogram.**
  `nexapipe_request_duration_ms_bucket{le="…"}` beside `_sum` and `_count`
  replaces `nexapipe_request_duration_ms_total`, which carried the same sum under
  a name a histogram cannot have: a p99 no longer takes arithmetic. The
  boundaries are fixed at 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000 and
  10000 milliseconds, plus `+Inf`. A scrape looking for the old counter will not
  find it.
- **The workspace declares the Rust version it needs: 1.89.** The build has
  depended on it since the config write started taking a file lock — `File::lock`
  is stable from there — and a build on an older toolchain used to fail with a
  missing method somewhere in a crate rather than with the toolchain it was
  missing it from.
- **The desktop TUN shares DNS and address space with other TUN apps**, rather
  than taking both over (#87).
- Dependencies: one batched upgrade across the workspace (#85).

### Fixed

- **A device struck out kept the connections it already held.** Revocation
  rewrote `config.toml` and stopped there: the device could not connect again,
  but it went on serving on everything it had open until it hung up — which is
  the one thing revocation is for. The reload that notices what left `[auth]`
  closes them now, at both levels: a client that left takes every device under
  it, a device that left takes only its own. They go with a new close code,
  `REVOKED = 6`, which both clients turn into an error saying the credential is
  gone and that trying again is not going to help.
- A name outside the hijack is answered through the host's own resolver, instead
  of the TUN swallowing it (#105).
- Desktop: an empty window is no longer shown while the app starts (#91); the
  TUN resolver is the exclusive DNS route on Linux (#92); a service an upgrade
  left behind is put back (#93); a stopped macOS service stays stopped (#86);
  the connecting indicator breathes with Reduce Motion on (#89); the webview is
  granted the permission it needs to read the service version (#100); the window
  is shown before the first frame is waited for (#106).
- Desktop: a launch that produced no frame sent no start-up timings at all. The
  wait after `show()` had no end, so a window the compositor never drew never
  reached the `finally` that sends them either. It is bounded at two seconds now
  and reports whether a frame came.
- Desktop (macOS): the bundle carries the content security policy the other two
  platforms use. Platform configs merge as JSON Merge Patch, in which `null`
  means *remove the key* — so `app.security.csp = null` deleted the policy
  rather than relaxing it, and the macOS app ran with none.
- `[peers]` refuses a key it does not recognise (#130). `allow` is the section's
  only key and an absent one means unrestricted, so `allowd = [...]` was dropped
  by serde and left a server that looked restricted and was not.
- Android: `nativeStopTunProxy` was the one JNI entry point with no barrier
  against unwinding (#129), and it ran on the main thread while the VPN was
  being switched off (#135). A device id that could not be stored was reported
  as stored (#147).
- Android: a credential is no longer stored unencrypted without being asked
  (#139). A device with no keystore can still connect; only storing without
  asking is gone.
- TUN: each flow has a budget (#134). A UDP frame could promise 65 535 bytes and
  arrive a byte at a time, and TCP flows had no ceiling at all — 256 now, the
  same ceiling the local HTTP proxy uses.
- Desktop: the desktop build gets the vendored `smoltcp` patch (#133).
  `ui-desktop/src-tauri` is its own workspace, so the root `[patch.crates-io]`
  never reached it and the desktop TUN ran the upstream code.
- A backend that answers slowly is no longer reported unreachable (#137): the
  preconnect budget covered the connect alone and not the wait for a 2FA
  refusal, which ran for up to six seconds more.
- Server: an enrollment could take over a device that was already there (#140);
  a name the table holds is refused now, and `--force` replaces one on purpose.
  A connection stamped the client rather than the device that made it, so every
  device under a client shared one `last_used` (#141). A peer could be connected
  before it was revocable — registration happens under the auth lock now (#144).
- Server: a write to `config.toml` was readable by everyone for as long as it
  took and followed a symlink to reach the file (#146); `--qr-out` had both
  problems and overwrote whatever was at the path (#131); `client add` reported
  a secret it had not written (#143).
- Client: a TOTP period that does not fit a `u32` is refused at enrollment
  (#148) rather than narrowed with `as u32`, which made every code afterwards
  wrong for a step the two ends disagreed about.
- A peer listing takes one reading of the clock for the whole list rather than
  one per entry (#138).
- Desktop: a tunnel whose DNS was never hijacked ran as though it had been, and
  a restore that wrote to no network service was reported as a success (#142).

## [0.5.0] — 2026-10-07

A readable version of this release, with downloads, is published at
<https://open-nexa.github.io/nexapipe/v0.5.0.html>. The page itself
lives in `docs/releases/`, and only that directory reaches the site.

No configuration key changed and no default moved: a `config.toml` that works on
0.4.0 loads unchanged on 0.5.0. One thing behaves differently without being
configured to — a `passthrough` or `tcp` backend that refuses TCP connections is
reported unhealthy now, and skipped in a route with more than one backend, where
it previously looked healthy and failed on the request.

### Added

- **Health decides which node the next request goes to.** 0.4.0 started probing
  the nodes and writing down what came back, and nothing read those records: the
  balancer still picked by index into a list nothing could change, so a node that
  had been dead for an hour went on receiving its share of the traffic.
  Selection takes one flag per candidate and answers `Option<usize>`, so "none of
  them" is an answer it can give — index 0 was always a valid reply to "which
  node", which is why the old code could never say no. A request that fails to
  dial marks the node down where the failure was noticed, rather than waiting up
  to thirty seconds for the probe to find out. A single node that is down is
  still dialled: refusing to dial the only node turns "down" into "no service at
  all" for a deployment with nothing to fail over to.

- **A `passthrough` or `tcp` backend is asked whether it answers.** Only `http`
  routes were probed, so a TLS listener behind a passthrough route had no health
  at all and surfaced as a connect error on whichever flow tried it first. Both
  are probed by connecting now — a TLS backend by completing its handshake —
  which is deliberately the smaller claim: something is listening, not that it
  works. A `udp`-only route is still not probed, and now for a stated reason:
  every probe available is one every backend would fail, and a pool emptied by a
  check that could never have succeeded is worse than an unchecked one.

- **The server counts the bytes it carries.**
  `nexapipe_traffic_bytes_total{direction="sent"|"received"}` on `/metrics`, and
  the same two numbers in `/v1/status`. They are counted on the client leg and
  nowhere else — the one place where one number means one thing across paths
  this different — and an HTTP response takes its count from what the access log
  already printed, so the log line and the Prometheus number cannot disagree.
  What is counted is tunnel payload: no protocol headers, nothing discarded,
  nothing counted twice.

- **Both clients report what each node carried, and whether it answered.** The
  desktop lists a node's health beside its traffic — whether it answered the last
  probe, how long it has been unreachable, how much it has carried — and the
  Android notification shows live up and down rates.

- **A container image is published with the release.**
  `ghcr.io/open-nexa/nexapipe`, one multi-arch manifest for `linux/amd64` and
  `linux/arm64`, under the same tag that already drives the archives, the desktop
  bundles and the APK. `docker-compose.yaml` names it, so `docker compose up`
  pulls rather than builds; `--build` still builds locally under the same name.

- **`docs/self-hosted-relay.md`: how to run your own relay**, and how to point
  NexaPipe at it. It does not remove the third-party dependency — only changes
  whom you depend on.

### Changed

- **The desktop credential door now stands in front of the whole Config page.**
  Confirming who is at the keyboard — Touch ID or the account password on macOS,
  Windows Hello or the account password on Windows, PAM on Linux — is what opens
  the page, rather than something each reveal button asks for on its own. A shut
  page renders none of it: no nodes, no connection strings, no two-factor
  secrets, no relay, so there is nothing on the screen and nothing in the
  document to read out of it. The window is still two minutes and still shuts
  itself; the button at the top of the page opens it again, and shuts it early.

- **The relay settings moved from Settings to Config.** Which relay this machine
  dials is part of how it connects, not a preference about how the app looks, and
  a custom relay's bearer token is a credential — so it now sits with the rest of
  the connection configuration, behind the same door.

- **macOS stopped using the keychain.** Reading a keychain entry is an access
  macOS asks about with a sheet of its own — at startup, again whenever the app's
  signature changes, and once more for every prompt — which is how one unlock
  turned into two sheets, and how a locked page once came up with no way out.
  The master key now lives in the same `0600` file the other platforms fall back
  to, and is moved out of the keychain on the first launch rather than replaced,
  so nothing already stored becomes unreadable. The door asks Authorization
  Services instead — the framework a System Settings pane uses to put a lock on a
  page, which brings its own sheet and asks nothing of the keychain. The right
  it asks for is `system.privilege.admin`, because the policy database defines
  it `shared = false`: a shared right (`system.preferences` is the trap) keeps
  its credential in the session for its timeout, and any authentication that
  landed there — an unlock of System Settings counts — would let the page open
  with no sheet at all.

### Fixed

- **Service shutdown is graceful on every platform rather than one.** The Unix
  service process had no signal handling at all, so `launchctl unload`,
  `systemctl stop` and the shutdown broadcast each simply killed it: UNIX signals
  are handled now, and DNS restore, self-heal and exit hooks exist on all three
  platforms rather than on Windows alone. macOS gets an explicit `ExitTimeOut`,
  and Windows a service entry point matching what the `nexa-service` binary
  already did.

- **CI compiles the root workspace on Windows**, which it never did — only the
  desktop crate had a Windows job. Check only, no tests: the integration tests
  spawn the binary and reach for `cfg(unix)` fixtures.

### Fixed

- **The machine's DNS no longer outlives the tunnel.** Three separate gaps each
  leaked on their own: a run that died before its teardown left the system DNS
  pointed at the TUN with nothing to undo it at the next start, and on macOS and
  Linux there was no self-heal at all; quitting skipped the restore entirely,
  because nothing handled the exit events, so Cmd+Q left the machine pointed at a
  tunnel that no longer existed. Only the `…254` host address of a candidate
  block counts as ours now, never the `/24` around it — `10.0.0.0/24` is both a
  candidate block and the subnet a great many home LANs use.

- **A password the operating system did not accept said nothing.** Asking and
  being refused came back as "the door is shut", which the UI read as its own
  instruction to stay quiet: a wrong password, a dismissed prompt or a failed
  fingerprint left the page exactly as it had been, and the button that was
  pressed answered for nothing. A press that does nothing now says why — the
  locked page reports whether the password was not accepted or the device did
  not confirm, and the password field carries that line when it opens again.

- **On Linux a password that was not accepted left the page looking unanswered
  for as long as PAM took to refuse it.** The dialog closed the moment the
  password was typed, which made it look as though the answer had already come
  back, and the refusal then turned up seconds later on the page behind. The
  password is now checked while the dialog is still open: the wait is said out
  loud on the button, and the answer lands in the field it was typed in. PAM
  still takes its time over a password it refuses — that delay is deliberate —
  but nothing looks broken while it does.

- **Copying a value the door had just opened came back as "could not copy".**
  Those copies wrote straight to the asynchronous clipboard API, which WebKit
  refuses once the document is not focused — and confirming who is at the
  keyboard takes long enough to lose it. Every copy in the app now goes through
  the same writer, which writes natively through the operating system's own
  clipboard — no focus, scheme or gesture required — and falls back to the
  asynchronous API and then a selection with the legacy command. A value that
  never arrived also stopped being reported as a clipboard failure, which sent
  the user looking at the wrong thing.

- **The loading spinner never turned on a Mac with Reduce Motion on.** The
  accessibility rule that stills every animation flattened it along with
  everything ornamental, and a spinner that does not turn is a button that
  looks dead. A spinner is the state rather than decoration — there is no other
  way to say "working" — so it is exempt from the stop now. The pulse next to
  the proxy's status is not: the status text already says "Starting", so that
  one is decoration and still respects the setting.

- **macOS ran the window with a title bar of its own on top of the app's.** The
  macOS build asked for native decorations without the title bar style that makes
  them transparent, so the system's bar sat above the one the app draws — two
  title bars, and two sets of close and minimize buttons, one at each end of the
  window. The window now asks for the overlay style: the traffic lights stay
  where macOS puts them, over the left of the app's own bar, and the app stops
  drawing a second set.

- **Server: an invalid health-check path panicked instead of failing the
  probe.**

## [0.4.0] — 2026-09-30

A readable version of this release, with downloads, is published at
<https://open-nexa.github.io/nexapipe/v0.4.0.html>. The page itself
lives in `docs/releases/`, and only that directory reaches the site.

### Added

- **A door in front of the credentials the desktop app holds.** Showing a TOTP
  secret, a node's connection string or this endpoint's Node ID now asks the
  operating system to confirm the user first — Touch ID or the account
  password on macOS, Windows Hello or the account password on Windows, PAM on
  Linux — and stays open for two minutes afterwards. Sealing the store at rest
  and masking what crosses into the UI were answers to "is this value on the
  screen"; this is the other half, and the one neither of them could answer:
  *who* is asking. There is deliberately no app password, because a credential
  of its own would be one more thing to forget, reset and attack — what gates
  the surfaces is what gates the machine. A machine with nothing to confirm
  anybody with refuses rather than handing the value over, which is the one
  outcome this exists to prevent. The proxy is unaffected: it still starts and
  reopens its endpoints after a reboot with nobody at the keyboard, because
  the window is two minutes of memory that never leaves this process and is
  never handed to the service. This is the desktop half of the Android app's
  credential lock, which shipped in 0.3.0; both ask the operating system and
  both stay open for two minutes, but not in front of the same surfaces — here
  it is this endpoint's Node ID and a node's connection string, there the TOTP
  secret, its `otpauth` export and the relay configuration.
- `least_conn` as a third load-balancing strategy, alongside `round_robin` and
  `random`: pick the healthy backend with the fewest requests outstanding to it,
  under a lease released when the flow finishes. Ties rotate rather than taking
  the first index, because a tie almost always means nothing is running — and
  taking the first index would then send everything to one backend, which is the
  load this strategy exists to spread. It counts requests, not sockets, because
  how many connections the pooled HTTP client is holding open is not something
  this process can see.
- **IPv6 inside the tunnel.** A proxied domain answered an AAAA query with
  nothing, which made every resolver that prefers IPv6 fall back to A to get
  anywhere. Both families are now answered, each from a pool of its own: `A`
  from `10.0.1.16+` as before, `AAAA` from `fd00:10:0:1::16+`, a ULA block the
  VPN routes into the TUN for itself (Android; the desktop uses
  `fd00:198:18::/64`), and the packet path looks a destination up in whichever
  family it arrived on. A ULA rather than a global address so that an address
  which escapes the tunnel is a dead end, and only that one /64 is claimed —
  the device's own IPv6 traffic still goes to the physical network. On the
  desktop the address is configured per platform and may be refused (a service
  account, an image with IPv6 off); when it is, AAAA is answered with the empty
  reply that sends the resolver back to A rather than with an address nothing
  routes, and the log says which happened.
- `[iroh] bind_ipv6`: bind `[::]` on the configured `bind_port` as well as
  `0.0.0.0`. It adds a socket rather than replacing one, so no client loses the
  route it has, and the IPv6 bind is not required — a host with no IPv6 starts
  and logs it instead of refusing to. Ignored without `bind_port`, which is
  also logged rather than left looking as though it worked.
- **The backends are asked whether they still answer.** Every 30 seconds, with
  up to 5 seconds of jitter, each backend is probed in parallel and the result
  recorded — `EndpointGroup::health_snapshot()` is what a UI polls. Until now
  a group dialled once, at startup, and never again, so a backend that stopped
  answering was discovered by the request that needed it, which on a phone is
  an app that has already timed out. The probe is also the reconnect: the pool
  drops a connection idle for a minute, so a round keeps one warm to a backend
  nobody has talked to. A failure is logged when it starts and then every
  tenth probe, because a backend down for an hour has failed a hundred of
  them. **A dead backend is still handed out**, which is the other half of this
  and is not done: the balancer picks by index into a list it cannot change, so
  removing one needs the group to become mutable — a change to every holder of
  it, and the item this release leaves for the next one.
- **A second Android ABI.** The APK was `arm64-v8a` only, which left an
  emulator — the x86_64 images that run acceptably on a development machine —
  with nothing to install. There are now two APKs, one per ABI, rather than one
  carrying both: a fat APK would make every phone download the x86_64 library
  to get the arm64 one. Each carries its own version code (the base with the
  ABI as its low digit), because two artifacts of one version cannot both claim
  the same one. `run_android.ps1 -Abi x86_64` builds and installs that one;
  without it the local loop would face two APKs and no way to choose.
- `[timeouts]`: `connect_secs` (default `10`) and `response_secs` (default `30`),
  each covering one step of talking to a backend and neither bounding the whole
  request — once a response head arrives, streaming its body can run as long as
  it needs. `connect_secs` is the one deadline behind every dial in the server,
  which used to be four copies of ten seconds. Read once at startup; `0` and
  anything past `3600` are refused at load.

### Changed

- **A route whose backends are all unhealthy now depends on how many there are.**
  One backend is still handed out, because with nothing to choose between the
  health information buys nothing and refusing would answer for every request to
  that route. Several, all down, refuse without dialling: the answer is already
  known, so a connect timeout was only ever spent delivering this refusal late.
- A refused HTTP request distinguishes why. No route serves the host: `404`, as
  before. The route exists and nothing behind it is healthy: `503` — the route is
  configured correctly and something downstream is down, which is a different
  thing to open. An L4 flow says the same on the wire with `Status::BackendFailed`
  rather than `NoRoute`, which would have told the client its request was
  misconfigured at the moment it was correct.

### Fixed

- The DNS cache in the TUN proxy (`crates/nexapipe-client/src/tun_proxy.rs`)
  answered more than it knew: entries were keyed without QCLASS, so one class was
  served from another's answer; they were not keyed on the resolvers that
  produced them; a hit rewrote only the transaction ID, so a long-lived answer
  went back out with its full TTL again; and a zero TTL got a one-second floor
  instead of not being cached. Those tests are now executed in CI, which had only
  been compiling them.
- The desktop app's claim that the OS keychain holds the credential store's
  master key was not true on Linux: `keyring` had no Linux backend, so the key
  was a `0600` file beside the encrypted credentials. Linux now uses the Secret
  Service, and an install that already had a file key keeps it — the same key
  moves into the keychain, because a fresh one would leave every credential in
  the store undecryptable.
- The desktop app's `localStorage` payload no longer holds a node's connection
  string. A ticket is a credential — it names an endpoint *and* carries how to
  reach it — and it was written in the clear beside the rest of the config,
  while the TOTP secret, the enrollment token and the relay bearer had already
  moved into the encrypted store. Both spellings now live there too, a payload
  left over from an older build is migrated into it on the way in, and a node
  whose connection string is in neither is dropped — after the store has been
  asked, which is the only moment that question has an answer. An older build
  reading the new payload finds no connection string and drops the node, so
  downgrading means re-importing the invite.
- The desktop app masked its credentials in the wrong place. The renderer
  already held the value it was shortening, so a mask computed there was a mask
  over a string sitting in that process's own memory — and an invite was worse:
  its TOTP secret and its enrollment token were handed to the frontend in full,
  so the page could work out which node the invite belonged to. Masks are now
  computed in Rust (`credentials::mask`) and what crosses into the renderer is
  the projection; an invite is accepted by `accept_invite`, which puts the
  credentials in the store itself and answers with a receipt carrying none of
  them. The Node ID is masked the same way, and `reveal_credential` and
  `reveal_node_id` are now the only two commands that answer with a whole value
  — which is what makes them the two the OS lock has to sit in front of.
- **Android: Nexa no longer disconnects another app's VPN without asking.**
  Android allows one `VpnService` TUN per user, and `establish()` revokes
  whoever holds the slot without asking anybody. Nexa only checked whether a VPN
  was the *default* network, so a per-app or split-tunnel VPN was invisible to
  the guard and was dropped silently — and even when one was seen the only
  outcome was a refusal, so running Nexa beside another VPN meant stopping that
  app by hand. Every VPN Android reports is now detected (`allNetworks` with
  `TRANSPORT_VPN`), and the first `establish()` asks: take over, or cancel, with
  an optional "remember my choice" that the settings can take back. An
  always-on VPN is refused outright and says why, because Android restores it
  immediately and it may be a work-profile VPN the user is not allowed to break.
  Taking the slot is never automatic: a rebuild after a network switch does not
  take it back.

## [0.3.0] — 2026-09-29

A readable version of this release, with downloads, is published at
<https://open-nexa.github.io/nexapipe/v0.3.0.html>. The page itself
lives in `docs/releases/`, and only that directory reaches the site.

### Added

- An auxiliary listener, bound only when `[admin] listen_addr` is set and only
  ever on loopback: `GET /healthz` for liveness and, while `[metrics] enabled`
  is true, `GET /metrics` in Prometheus text format. A non-loopback bind
  is refused at startup rather than warned about, and unlike `[server] expose`
  there is no escape hatch: what it answers names your routes, clients and
  backends.
- Instance metrics on it: connections (total, active, and by whether the path is
  direct or relayed — read from iroh rather than guessed at a socket address,
  so "nothing to rent" is a number rather than a claim), requests by status
  class and the milliseconds they took, L4 flows by protocol and status,
  backends in and out of rotation, work still in flight, and uptime. The
  exposition is written by hand, so no `prometheus` crate was added and
  `Cargo.lock` is untouched. `/metrics` with metrics off is `404` rather than an
  empty body, so a scraper can tell "disabled" from "no traffic yet".
- A read-only management surface behind a generated token: `GET /v1/status`,
  `/v1/routes`, `/v1/clients`, `/v1/connections` and `/v1/health`, as JSON.
  The token is written to `<config>.admin-token` on first start; there is
  deliberately no key for it in the config, because a credential in the file an
  operator edits, copies and commits is what this design avoids. No token means
  `503`, not an open door.
- `nexapipe status` — asks a running instance those five endpoints and prints
  them grouped, or as one document with `--json`. It is a client of the same
  endpoints rather than a second reader of the config, so the running instance
  stays the one thing that decides what its state is.
- A door in front of the credentials the Android app holds: the TOTP secret of
  an endpoint, its `otpauth` export, and any change to the relay configuration
  now ask Android to confirm the user first — a biometric where there is one,
  the screen-lock credential otherwise — and stay shut for two minutes after
  one confirmation. `SecretStore` already sealed them at rest; what was missing
  was anything asking before handing them back. A device enrolled with neither
  a biometric nor a screen lock is refused rather than downgraded, and the way
  out is one tap away. Proxy start and stop are deliberately not gated: the VPN
  has to come back after a reboot with nobody present.
- A request ID: 32 hex digits per request, one per entry point rather than one
  per connection, appended to that request's access line and carried by a
  `request` tracing span that also holds its method, URI and status. The access
  log has always answered "what happened"; until now it could not say which of
  its lines belonged to the response somebody is looking at.
- `docs/iroh-boundaries.md` — what still depends on third-party infrastructure
  whatever `relay_mode` says. Two README sections oversold what a mode buys:
  `custom` constrains this endpoint only, and Endpoint ID discovery still
  queries `dns.iroh.link` in every mode. Both READMEs now point here instead of
  repeating the caveat.
- This CHANGELOG. 0.2.0 shipped without one, so its entry below is
  retrospective; 0.3.0 is the first release recorded in it as it happened.

### Changed

- Hot-reload rules, previously scattered across the configuration sections, are
  one table in both READMEs: what a reload applies, and what needs a restart.
- The access log line ends with `id=<hex>`. Appended rather than inserted, so
  every field before it keeps the column it had and a script that splits on
  spaces still finds the host, the status and the duration where it did.
- HTTP responses carry `x-request-id`, the same id the access line records. A
  backend that sends its own is dropped rather than duplicated, so there is one
  id to quote and it is ours. An L4 flow and a TLS passthrough are tunnels
  rather than requests: they get an id on the access line and the span, and
  have no HTTP response to put a header on.

### Fixed

- Both READMEs quoted the iroh version wrongly in two ways at once: as pinned at
  1.0.1, when it is declared `^1.0.1` and `Cargo.lock` resolves 1.2.0. The line
  now defers to `docs/iroh-boundaries.md`, which states it correctly.

## [0.2.0] — 2026-09-28

A hardening release: a full review of the tree — server, client library, Android
and desktop — produced a batch of security and correctness fixes, alongside
configurable health checks, a draining shutdown, and access logs on the iroh
tunnel path. It carries **breaking changes**: `default_backend` is removed, and
the server now refuses some configs it used to "fix" silently.

This entry is retrospective: 0.2.0 shipped before this file existed.

### Added

- Health checks are configurable. `[health_check] enabled = false` turns probing
  off, so a backend with no health endpoint is a supported deployment instead of
  a source of log noise (#47).
- CodeQL scanning, with a config in `.github/codeql/codeql-config.yml` (#47).
- `docs/ROADMAP.md` — where the project stands, what is missing, and in what
  order it is meant to be fixed (#47).
- `third_party/smoltcp/PATCHES.md`, documenting the vendored smoltcp patch that
  `third_party/` exists to carry (#48).
- Android: a lint baseline with `warningsAsErrors`, so a *new* lint warning
  fails CI while a recorded one stays quiet (#48).

### Changed

- Shutdown drains instead of sleeping. It counts the connections both accept
  loops spawned and waits for them, with a bound so a stuck peer cannot hold the
  process open (#47).
- The iroh path is logged at startup, including the relay that actually took
  effect (#47).
- Release artifact names are unified across the server archives, the desktop
  bundles and the APK, under one rule (`<product>-<version>-<platform>.<ext>`)
  (#47).
- Hardening across the server and the client: stricter config validation,
  request handling and connection-lifecycle handling; secret scanning through
  `.gitleaks.toml`; hardened Dockerfiles and per-platform build scripts (#50).

### Fixed

- A single failed health probe emptied a backend pool. `failure_threshold` was
  stored and logged but never consulted; it is now the count that takes a
  backend out of rotation (#47).
- Android: the credential key is no longer regenerated when the keystore reports
  an error. On API 26 generating a key under an existing alias deletes that
  entry first, so one transient failure used to make every stored credential
  unreadable (#51).

### Removed

- The top-level `default_backend`. A config that still names it is refused at
  startup rather than silently ignored, so an existing config cannot quietly
  start answering 404 where it used to forward. "Send everything here" is now
  spelled as a catch-all route, `host_pattern = "*"` (#48).

## [0.1.1] — 2026-09-27

### Added

- `[peers]` Node ID allow-list. A malformed entry is fatal rather than dropped:
  a list whose whole purpose is to refuse strangers must not silently come out
  shorter than it was written (#44).
- 2FA can be enabled on a running server. `[auth] enabled` moves on a config
  reload, taking effect for connections opened after it (#44).

### Changed

- The Rust tree is formatted with rustfmt, and the CI format check is now
  blocking (#46).

### Fixed

- Line endings pinned with `.gitattributes`, so a checkout on another platform
  stops producing diffs that are only line endings (#45).
- The Chinese README re-synced with the English one (#45).

## [0.1.0] — 2026-09-26

The first tagged release, and the release that turned NexaPipe into a monorepo.

### Added

- The server, the client library and the L4 wire format (#1, `6d97ad0`).
- 2FA (TOTP) authentication with diagnostics, unified relay configuration, and
  per-platform packaging (#1).
- One-time enrollment invites, so a leaked invite URL stops being a credential
  forever: the first device to scan one trades it for a freshly generated secret
  (#31).
- Per-client host authorization (#15).
- The Android and desktop apps, imported with their full git history from their
  former standalone repos, with unified CI and release pipelines (#15).

### Fixed

- Release pipeline unblocked; comments and docs are English only (#33).

# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
One tag releases everything at once: the server archives, the desktop bundles
and the signed Android APK come out of `.github/workflows/release.yml`.

For what comes next, and for why some things are deliberately not planned, see
[docs/ROADMAP.md](docs/ROADMAP.md).

## [Unreleased]

Nothing yet.

## [0.3.0] — 2026-09-29

0.2.0 was never tagged, so what was recorded against it ships here: one tag,
everything since 0.1.1, with those entries merged into this one. A readable
version of this release, with downloads, lives in
[docs/releases/v0.3.0.html](docs/releases/v0.3.0.html).

### Added

- An auxiliary listener, bound only when `[admin] listen_addr` is set and only
  ever on loopback: `GET /healthz` for liveness and, while `[metrics] enabled`
  is true, `GET /metrics` in Prometheus text format (#52). A non-loopback bind
  is refused at startup rather than warned about, and unlike `[server] expose`
  there is no escape hatch: what it answers names your routes, clients and
  backends.
- Instance metrics on it: connections (total, active, and by whether the path is
  direct or relayed — read from iroh rather than guessed at a socket address,
  so "nothing to rent" is a number rather than a claim), requests by status
  class and the milliseconds they took, L4 flows by protocol and status,
  backends in and out of rotation, work still in flight, and uptime (#52). The
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
- `docs/iroh-boundaries.md` — what still depends on third-party infrastructure
  whatever `relay_mode` says. Two README sections oversold what a mode buys:
  `custom` constrains this endpoint only, and Endpoint ID discovery still
  queries `dns.iroh.link` in every mode. Both READMEs now point here instead of
  repeating the caveat. The same pass corrected the iroh version there, which
  was wrong twice over: it is declared `^1.0.1`, not pinned, and `Cargo.lock`
  resolves 1.2.0.
- This CHANGELOG, starting with a retrospective 0.2.0 entry distilled from the
  commits since 0.1.1.
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

- Hot-reload rules, previously scattered across the configuration sections, are
  one table in both READMEs: what a reload applies, and what needs a restart.
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

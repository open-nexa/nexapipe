# Repository Guidelines

Nexapipe is a Rust workspace: an iroh/QUIC-based proxy server forwarding HTTP/WebSocket traffic to backends, plus a multi-platform client library used by the Android and desktop apps. TLS is terminated by the backend (Caddy &co), not here: the server copies TLS sessions to a passthrough route selected by SNI (`src/passthrough.rs`) and holds no certificates. Raw TCP and UDP flows reach a route's backend through the L4 tunnel, which the client opens with a `0x05` preface stating protocol, host and port (`crates/nexapipe-proto` defines that wire format for both sides; `src/l4/` is the server half, the client's `src/l4.rs` the other).

## Project Structure & Module Organization

- `crates/nexapipe/` — Server binary and library. Entry point `src/main.rs` (clap CLI: `--local-proxy`, `--generate-secret`); config in `src/config.rs`; iroh connection handling in `src/conn/` (which dispatches on a stream's first byte); HTTP/WebSocket proxying in `src/http/` and `src/proxy/`; TLS/byte passthrough in `src/passthrough.rs`; raw TCP/UDP flows in `src/l4/`; shared byte-copying helpers in `src/stream_util.rs`; routing in `src/routes/` and `src/lb/`; health checks in `src/health/`.
- `crates/nexapipe-proto/` — The L4 wire format, dependency-free so both the server and the client link the same code: `preface.rs` (magic/version/proto/host/port plus the status byte) and `udp.rs` (`u16`-length datagram framing). Change it here, never by hand on one side.
- `crates/nexapipe-client/` — Client library (`lib` + `cdylib`). Connection pooling in `connection_pool.rs`, domain-to-endpoint mapping in `endpoint_group.rs`, HTTP/CONNECT/WebSocket tunneling in `local_proxy.rs`, the L4 tunnel client in `l4.rs`, smoltcp-based TUN proxy in `tun_proxy.rs`, per-domain TUN virtual IPs in `virtual_ip.rs`, JNI bindings in `jni.rs`, UniFFI bindings in `uniffi_bindings.rs`.
- `ui-android/` — Android app (Kotlin); VPN/TUN orchestration lives in `app/src/main/java/com/nexa/pipe/vpn/NexaVpnService.kt` and calls the Rust client via JNI.
- `ui-desktop/` — Tauri 2 desktop app (Vue 3 + TypeScript, Rust backend in `src-tauri/`).
- Root — workspace `Cargo.toml`, `config.toml`, Dockerfiles, and the per-platform local build scripts (`build_dmg.sh` macOS, `build_deb.sh` Linux, `build_windows.ps1` Windows, `run_android.ps1` Android debug loop). Each mirrors the matching CI job: `--version` reproduces the tag-derived version, and `build_deb.sh` runs the same `verify-deb.sh` check as the Linux CI job.

This is a monorepo: `ui-android/` and `ui-desktop/` are plain directories (their git histories were preserved via `git subtree` when they were imported from the former standalone repos `open-nexa/nexa-android` / `open-nexa/nexa-desktop`), not submodules — commit app changes directly here, alongside the server crates. One tag (e.g. `v0.2.0`) releases the server archives, the desktop bundles and the signed APK together from `.github/workflows/release.yml`.

## Build, Test, and Development Commands

- `cargo build` — build the workspace.
- `cargo run -p nexapipe -- --config config.toml` — start the server.
- `cargo run -p nexapipe -- --local-proxy` — client local-proxy mode.
- `cargo test --workspace` — run all Rust tests.
- `cargo fmt` and `cargo clippy --workspace` — format and lint.
- Android: `run_android.ps1` (cargo-ndk cdylib build with `jni,local-proxy,tun-proxy` + install/run on a device), `ui-android\gradlew.bat :app:compileDebugKotlin`.
- Desktop: `cd ui-desktop && npm run tauri:dev` (dev) / `npm run tauri:build` (release); for a release-like package use `build_dmg.sh` / `build_deb.sh` / `build_windows.ps1` from the root.

`crates/nexapipe-client/src/tun_proxy.rs` is shared by Android (fd entry, `TunProxy::new`) and the desktop (`TunProxy::with_io`); only the fd plumbing is android-gated inside. Host `cargo check -p nexapipe-client --features tun-proxy` covers the shared code, but the Android half still needs an explicit cross-check after touching the TUN or the L4 client:

```bash
cargo ndk -t arm64-v8a --platform 26 check -p nexapipe-client --features jni,local-proxy,tun-proxy
```

`cargo test -p nexapipe-client --features tun-proxy` still runs on any host: it exercises the platform-independent parts of that feature, today `virtual_ip.rs`.

## Coding Style & Naming Conventions

- Rust edition 2024, default `rustfmt` (4-space indent).
- Rust naming: `snake_case` items, `CamelCase` types, `SCREAMING_SNAKE_CASE` constants; use `anyhow` for errors and gate logging behind `#[cfg(feature = "tracing")]` or the `jni_log!` macro.
- Kotlin: 4-space indent, `camelCase`, follow Android lint.
- **English only.** Comments, doc comments, log and error messages, docs, config examples, commit messages and PR descriptions are written in English, even when the conversation with the user is in Chinese.
- The **only** exception is real i18n: `ui-android/app/src/main/res/values-zh-rCN/strings.xml`, `ui-desktop/src/i18n/locales/zh-CN.json`, a language's own name in its own script (the `zh-CN` entry in `ui-desktop/src/i18n/index.ts`, the "Bilingual UI" line in `ui-desktop/README.md`), and code or tests whose point is handling non-ASCII text (the percent-encoding test in `crates/nexapipe/src/auth/otpauth.rs`). Do not add Chinese anywhere else — not in a Rust, Kotlin or Vue comment, not in `README.md` or a CI workflow, not in a log line, not in a `config.toml*` example.
- Keep platform code behind features: `jni`, `local-proxy`, `tun-proxy`, `uniffi`.

## Testing Guidelines

- Tests use `#[test]` / `#[tokio::test]`; the server crate's integration tests spawn the built binary with the `duct` dev-dependency and use `tempfile` for scratch configs.
- Name tests descriptively, e.g. `handles_ws_upgrade()`.
- The L4 tests drive `l4::serve_stream` over a `tokio::io::duplex` pair and the client's `l4::open_*` against the same, so a TCP or UDP flow can be tested end to end without an iroh endpoint.
- Run `cargo test --workspace`; for Android changes, compile-verify with `gradlew :app:compileDebugKotlin`.

## Task Execution Workflow (MANDATORY)

Do not jump straight into edits. For any task that writes something:

1. **Plan first.** Restate the goal, read the relevant code/config, then produce a concrete plan: which files change, what each change does, what could break, and how it will be verified (build/test/lint commands, CI jobs).
2. **Ask before acting.** Present that plan and wait for explicit approval. Surface assumptions, alternatives and risks; when several approaches exist, list them and let the owner choose.
3. **Execute only after approval** and stay inside the agreed scope. Stop and re-ask if the task grows, uncovers a bigger problem, or needs files that were not in the plan. Work happens in a worktree created off the newest `main` (see Git Workflow — Worktrees & Branch Base), never in the main checkout.

No approval is needed for read-only work: answering questions, reading files, searching, explaining code, or producing a report / scan-only listing. Anything that writes, deletes, or has external effects does need it.

## Git Safety Rules (MANDATORY)

- **Never push or write to a remote.** No `git push`, force-push, remote-add-then-push, remote branch deletion, or `gh release ...`. Local commits only; the owner pushes themselves.
- **Never `git commit` automatically.** Committing belongs to the owner. When the work is verified, stop, summarize the change and hand over a suggested commit message — do not run `git commit`, `git commit -a`, or an implicit "stage then commit".
- Do not run history/discard commands (`git reset --hard`, `git checkout --`, `git clean -fd`, `git stash` without being asked, branch switches that drop work) unless explicitly requested.
- The only exception is an explicit instruction in the current task, e.g. the user says "push it" / "commit it" / "please push". "Tests pass, so push it" style inference is NOT authorization.
- Before any action with remote/public side effects (releases, tag deletion, etc.), ask first, act later.

## Pre-Push Review (MANDATORY)

- **A subagent must review the change before any push.** Before `git push` — including a branch that opens or updates a PR — dispatch a review subagent (`Agent` with `subagent_type: "general-purpose"`) and hand it the base ref. It reviews correctness, not style.
- **Hand it everything the push would carry: the committed range *and* whatever is still uncommitted.** The agent does not commit on its own, so the change usually sits in the working tree, and a three-dot `git diff <base>...HEAD` omits it entirely:

  ```bash
  git diff <base>...HEAD   # the committed commits on top of <base>
  git diff <base>          # the same, plus staged and unstaged working-tree changes
  git status --porcelain   # untracked files, which neither diff form can show
  ```

  Never review a three-dot diff alone: against a branch whose change is uncommitted it returns an empty diff, the reviewer has nothing to look at, and the push goes out unreviewed.
- **What the reviewer must produce:** a verdict of `APPROVED` or `CHANGES REQUESTED`, and every finding carrying `file:line`, why it is a bug, and a concrete failure scenario. "Looks fine to me" is not a verdict.
- **`APPROVED` may still carry non-blocking observations; `CHANGES REQUESTED` means at least one blocking finding is open.** Style, formatting, naming and refactors — anything `cargo fmt` and `cargo clippy` already cover — are reported as non-blocking and never turn the verdict into `CHANGES REQUESTED`.
- **A blocking finding stops the push.** Fix it, re-run the affected build/test/lint, review again, then push. Repeat until the verdict is `APPROVED`. Never push while a blocking finding is open.
- **Report the verdict.** State the verdict, the findings and the fixes in the reply that accompanies the push, so the owner sees what was checked.
- **A green review is not permission to push.** This gate is a precondition for pushing, not an authorization: the commit and the push still need the explicit instruction described in Git Safety Rules.
- **Documentation-only changes still get a skim** — a reviewer may pass them quickly, but a change is never pushed unreviewed.

## Git Workflow — Worktrees & Branch Base (MANDATORY)

- **Anything that changes code must be done in a dedicated git worktree, never in the main checkout.** The main checkout is `/Users/ipine/rust/nexapipe` and stays on `main`. This covers code, docs, configuration and CI files — every write goes through a branch in a worktree. Only read-only work may happen in the main checkout: reading, searching, explaining code, answering questions, producing a report or a scan-only listing.
- **Every new branch is based on the newest `main`.** Do not start from the local `main` ref alone: the fork's `main` regularly lags upstream. Resolve the upstream head first, fetch it into the fork, and branch off that commit:

  ```bash
  gh api repos/open-nexa/nexapipe/commits/main --jq .sha   # -> <sha>
  git fetch --no-tags origin <sha>
  git worktree add /Users/ipine/WorkBuddy/Worktrees/nexapipe/<branch> -b <branch> <sha>
  cd /Users/ipine/WorkBuddy/Worktrees/nexapipe/<branch>
  git merge-base --is-ancestor <sha> HEAD   # verify the branch really sits on newest main
  ```

  If the upstream lookup is unreachable, degrade to a fast-forward update of the local `main` (`git fetch --no-tags origin main`, fast-forward only — never `reset --hard`) and state explicitly in the reply which commit was used as the base.
- **Worktree location:** `/Users/ipine/WorkBuddy/Worktrees/nexapipe/<branch-name>` for every working branch. Keep `<repo>/.workbuddy/` worktrees for throwaway simulations only (merge rehearsals, release-note scratch): those are git-ignored and expire with the task.
- **Exception — a fix to an open PR reuses that PR's branch and worktree.** When the task is fixing a bug in an existing open PR, work on that PR's own head branch, in that branch's existing worktree. Do not open a fresh branch and do not create a second worktree for it: the fix belongs in the PR that carries the defect, not in a parallel branch that has to be cherry-picked afterwards. Locate the worktree with `git worktree list` before starting, and check `git status` in it — if it holds unrelated uncommitted work, stop and ask instead of mixing the fix into it. The "newest `main`" rule above governs new branches only; a PR branch keeps its own base and history.
- Set the worktree up only after the plan is approved; until then stay read-only.
- **Never delete a worktree on your own initiative**, least of all one holding unpushed commits — ask first. After a reboot, `/private/tmp` is gone, so run `git worktree prune` before rebuilding anything that referenced it.

## Working Files & Plan Documents (MANDATORY)

- **Temporary plan / fix / patch documents written by the agent go to `.workbuddy/` (git-ignored), never into the repository tree** (no `PLAN.md`, `TODO.md`, `docs/*plan*`, `docs/*fix*`, `docs/*patch*`, etc. in tracked paths).
- Only durable, curated docs belong in the repo (e.g. `AGENTS.md`, `CONTRIBUTING.md`, architecture decision records). One-off reasoning and step-by-step plans live in the conversation or `.workbuddy/` and expire with the task.
- Put "why this change" explanations in the commit message or PR description, not in a sidecar plan file.

## Commit & Pull Request Guidelines

- The agent does **not** create commits on its own initiative (see Git Safety Rules). The one exception is an explicit instruction in the current task — "commit it" means commit; a passing verification run does not. Otherwise, hand the owner a ready-to-use commit message and let them commit.
- The history uses short generic subjects (e.g. `update`); prefer focused, descriptive messages like `fix(local-proxy): handle CONNECT tunnel close` or `feat(conn): add connection keepalive`.
- Keep one logical change per commit.
- Pull requests: describe what and why, link related issues, and add screenshots/videos for UI or VPN behavior changes.
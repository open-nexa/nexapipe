<!--
One logical change per pull request. If you are doing two unrelated things, open
two — a PR that is easy to review is a PR that gets merged.
-->

## What this changes

<!-- A few sentences. What behaves differently after this, and why. -->

## Why

<!-- The reason, not just the symptom. Link the issue it closes: Closes #123 -->

## How it was verified

<!-- What you ran, and what you observed. Delete what does not apply. -->

- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets` (kept at zero warnings)
- [ ] `rustfmt --edition 2024 <your file>` — not `cargo fmt --all`, which reformats
      files you never touched
- [ ] `cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy`
      (only if you touched the TUN or L4 client: a host build never compiles it)
- [ ] `cd ui-desktop/src-tauri && cargo check` (only if you touched the desktop app)
- [ ] Tests added for new behaviour
- [ ] README updated if behaviour visible to users changed

## Notes for the reviewer

<!--
Anything that will otherwise cost the reviewer ten minutes: a trade-off you
chose, a platform you could not test, a follow-up you deliberately left out.
-->

## Screenshots

<!-- Required for UI changes. The repo currently has none, so this is welcome. -->

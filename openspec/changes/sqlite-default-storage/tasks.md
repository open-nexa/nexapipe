# Tasks

## 1. The store seam

- [x] 1.1 Branch the work from the newest `upstream/main` — the in-flight device-invite work touches `crates/nexapipe/src/storage/`, so this branch waits for it to land — and verify `git merge-base --is-ancestor upstream/main HEAD` succeeds
- [x] 1.2 Add `put_config` to the `Storage` trait in `crates/nexapipe/src/storage/mod.rs`, documented as the one whole-document write, and verify `cargo check -p nexapipe --all-targets` still compiles with the trait method unimplemented
- [x] 1.3 Implement `put_config` for the file store in `crates/nexapipe/src/storage/file.rs` — render the model with `Config::to_toml_text` and write it through the existing `with_lock` — and verify a test that writes a configuration into an empty file store and reads the same configuration back
- [x] 1.4 Implement `put_config` for the SQLite store in `crates/nexapipe/src/storage/sqlite.rs` — `Rows::of` then `write_rows`, so the revision moves with the write — and verify a test that writes a configuration, reads it back, and sees the revision move

## 2. The default store

- [x] 2.1 Move `storage-sqlite` into the default features of `crates/nexapipe/Cargo.toml` and verify `cargo build -p nexapipe` produces a binary that reports a sqlite store when asked for one
- [x] 2.2 Derive the default database path from the directory of the configuration file in `crates/nexapipe/src/storage/open.rs` — `<dir of --config>/nexapipe.db` — and verify a unit test that a configuration at `/tmp/x/config.toml` yields `/tmp/x/nexapipe.db`
- [x] 2.3 Make `storage::choose` fall back to the SQLite store when the operator names no store, keeping `--storage toml`, `--storage sqlite`, `NEXAPIPE_STORAGE` and `NEXAPIPE_STORAGE_URL` working as they do — and verify a test for each of the four spellings
- [x] 2.4 Keep the file-only build working and verify `cargo check -p nexapipe --no-default-features --all-targets` compiles, with the sqlite store refusing to open with the message it gives today

## 3. The legacy import

- [x] 3.1 Add `storage::import_legacy_config` — it reads the store, returns nothing when the store already holds a configuration, and otherwise parses `<dir of --config>/config.toml` with `Config::from_toml_text` — and verify a test that an empty store with a file beside it comes back holding that configuration
- [x] 3.2 Write the parsed configuration into the store with `put_config`, leave the file untouched, and verify a test that the file is still at its path after the import and that a second call imports nothing
- [x] 3.3 Refuse the import when the file cannot be parsed, naming the reason, and leave the store holding no configuration — and verify a test with a file carrying an unknown key
- [x] 3.4 Report the import through the log channel in `crates/nexapipe/src/main.rs`, after `log::init`, the way the "wrote a minimal configuration" notice is reported — and verify the message names the file, the database and which one is read from now

## 4. Verification and documentation

- [x] 4.1 Run `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo test --workspace --locked`, and verify they pass
- [x] 4.2 Run `cargo deny check licenses bans sources` and `cargo audit` against both lockfiles, and verify the advisory set is unchanged — the SQLite ignore stays, with the same reason
- [x] 4.3 Update the CI workflow so the server builds with the default features and a second job builds with `--no-default-features`, and verify both jobs are green
- [x] 4.4 Update `README.md`, `README.zh-CN.md` and `config.toml.example` to say that the configuration lives in a database by default, and how to point the server at a file store instead — and verify the documented commands are the ones the binary accepts

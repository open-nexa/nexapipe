# Proposal

## Why

The SQLite store landed behind the `storage-sqlite` feature and is opt-in, so every deployment still keeps its whole configuration in one TOML file that is rewritten as a blob on every credential change. The file store cannot give what the management surface is about to need: a write that touches one entity and leaves the rest alone, and a revision that moves with that write. Making the database the default store turns the configuration from a document into rows, and leaves the TOML as the interchange format it was always better suited for.

## What Changes

- **BREAKING** The SQLite store becomes the default store. A deployment that says nothing about where its configuration lives now gets a database instead of a `config.toml`.
- **BREAKING** `storage-sqlite` becomes a default feature of the `nexapipe` crate: every build carries the database store, and `--storage sqlite` stops being a flag that needs a special build to be useful.
- The default database path is derived from the configuration directory — `NEXAPIPE_CONFIG_DIR` points at a directory and the database is `nexapipe.db` inside it, and without that variable the database is `./nexapipe.db`. `--storage-url` and `NEXAPIPE_STORAGE_URL` still override it.
- A `config.toml` sitting next to a brand-new database is imported into it once, on the first start that finds the database empty. The file is left exactly where it is, so `--storage toml` still opens it, and the import is reported loudly — from that moment on the file is not what the server reads.
- The file store is kept, and `--storage toml` still selects it. It is no longer the default; it is the store a deployment picks when it wants its configuration in a file it can edit by hand.
- `Storage` gains a way to write a whole configuration, so a document can be loaded into a store and not only read out of one.

### Out of scope

- The PostgreSQL store. It stays refused at startup with the message it has always given.
- Removing the file store, or deprecating it. A laptop and a single-container deployment both still want a configuration they can read with `cat`.
- The management API and the web console. They are a separate change, and this one is what they build on.
- How the configuration is modelled. The typed model and the TOML codec stay exactly as they are; this change only decides where the model is kept.
- Rotating or migrating an existing database. The import covers a first start with an empty database, not an upgrade of a populated one.

## Capabilities

### New Capabilities

- `config-storage`: Where the configuration of a running instance lives, which store is chosen when the operator does not say, and how a configuration written for the file store reaches a database store.

### Modified Capabilities

None. This is the first specification in the project, so every capability it introduces is new.

## Impact

- `crates/nexapipe/Cargo.toml` — `storage-sqlite` becomes a default feature; `sqlx` and `libsqlite3-sys` are in every build rather than only in the ones that asked for the feature.
- `crates/nexapipe/src/storage/open.rs` — the default store, the default database path, and the first-start import.
- `crates/nexapipe/src/storage/mod.rs` — the `Storage` trait gains the write-a-whole-configuration method.
- `crates/nexapipe/src/storage/sqlite.rs` — the new method, and the import.
- `crates/nexapipe/src/storage/file.rs` — the new method.
- `crates/nexapipe/src/main.rs` — the `--storage` default and the report of the one-time import.
- `crates/nexapipe/src/config/` — the TOML codec, reused as the import format.
- The dependency policy. `libsqlite3-sys` and the bundled SQLite behind it are now in every server binary rather than only in the builds that enabled the feature, which widens the reach of the advisory already ignored in `deny.toml`. Its exposure does not change: the crafted file the advisory needs has to sit next to the database, and that directory already holds the client seeds and the endpoint key.

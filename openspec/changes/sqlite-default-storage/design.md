# Design

## Context

The SQLite store exists and works: six tables, a revision the watcher compares, writes that touch one entity rather than the whole document. It is behind the `storage-sqlite` feature, so it is opt-in, and `storage::choose` falls back to `StorageKind::Toml` when the operator says nothing. The file store keeps the whole configuration in one TOML file, and every credential change rewrites it.

What the store does not have yet is a way to be handed a whole configuration. `Storage` speaks entities — `write_client_secret`, `write_device_credential`, `remove_client` — and a document — `config()` returns the configuration as text, `ensure_config` writes the default when there is none — but there is no whole-document write that is not "write the default configuration".

The other half of the context is where the configuration file is. `--config` names it, its default is computed from `NEXAPIPE_CONFIG_DIR` (`<dir>/config.toml`) and is otherwise `./config.toml`, and the docker setup binds `/app/config` and sets `NEXAPIPE_CONFIG_DIR=/app/config`. The file store, the lock file beside it and the legacy import all want the same anchor.

## Goals / Non-Goals

**Goals:**

- A deployment that says nothing about its store ends up on the database, and says so.
- The database path is derived from one place, not configured separately from the configuration file.
- A `config.toml` written by an earlier version reaches the database without the operator having to do anything, and without the file being taken away from them.
- The store seam keeps working: every store can be handed a configuration, and both stores implement it.

**Non-Goals:**

- The PostgreSQL store. It keeps refusing to start with the message it has now.
- Removing or deprecating the file store.
- Any change to the configuration model or to the TOML codec. The import reuses the codec exactly as the file store does.
- Migrating a database that already holds a configuration. The import is for a store that holds none.

## Decisions

### The database lives beside the configuration file

The database path is `<directory of the configuration file>/nexapipe.db`, and `--config` keeps naming the configuration file.

**Why:** one anchor. The file store, the lock file, the legacy `config.toml` and the database all then live in one directory that an operator can look at, back up and copy. A separate `--storage-url` default would have to be derived from a second variable, and the two would drift: a container that mounts `/app/config` would have to set both `NEXAPIPE_CONFIG_DIR` and `NEXAPIPE_STORAGE_URL` to point at the same place.

**Alternatives:** deriving the path from `NEXAPIPE_CONFIG_DIR` alone would break the moment an operator passes `--config /somewhere/else/config.toml`, and the database would be somewhere the file is not. Keeping the path under a platform data directory (`~/.local/share/nexapipe/`) would put the credentials somewhere the operator's existing backup does not cover, and would make the docker mount a second thing to configure.

`--storage-url` and `NEXAPIPE_STORAGE_URL` still override the derived path, and the override wins over the derivation.

### The import is a step, not a side effect of opening

`storage::import_legacy_config(store, config_path)` is called explicitly by `main.rs` after the store is opened and before the configuration is loaded. It returns the path it imported from, or nothing.

**Why:** opening a store is a thing a lot of code does, and only one of those callers — a server start — wants a migration to happen. A side effect inside `storage::open` would fire for `nexapipe client list` as well, and a command that only reads would be able to write to the database. Making it an explicit step also makes it testable without a server.

**Alternative:** doing the import inside `ensure_config`, which already writes the default configuration when the store holds none. Rejected: `ensure_config` is given the default template, and the legacy file has to win over that template. Overloading it with "or this file, if it is there" would make a method whose name says "default" do two different things.

### The store seam grows one whole-document write

`Storage` gains `put_config(&self, config: &Config)`, which makes the given configuration the one the store holds.

**Why:** the import needs to write a whole configuration into a store, and it must not go around the trait: the file store and the database store have to stay interchangeable, and the write has to move the revision in the database so the watcher reloads.

**The model, not the text.** `config()` returns the configuration as text because the readers of it are readers of a document; `put_config` takes the model because the writer has already validated it. The import parses the legacy file with `Config::from_toml_text` — which is where an unknown key becomes an error — and hands the parsed model to the store. Handing over the raw text instead would mean parsing the same file twice and would leave the store to re-derive a validation the caller already did.

The trait's other document-level methods (`config()`, `ensure_config`) keep speaking text; `put_config` is the one whole-document write and it speaks the model, because it is the only one that is handed something already checked.

### The file is left where it is

The import does not rename, move or delete the legacy file.

**Why:** the file store still exists, and `--storage toml` has to still open the file the operator's tools know. Renaming it would turn "I want to go back to the file" into a recovery operation. Leaving it also means the import is reversible: pointing the server at the file store brings the old configuration straight back.

The cost is that a file that is no longer read sits next to the database, and an operator who edits it will see no effect. That is why the import is reported: the message names the file, names the database, and says which one is read from now.

### The import fires once, on emptiness

The import runs when the store holds no configuration. After it has run the store holds one, so it cannot fire again. No marker row, no flag file.

**Why:** emptiness is the state the import is about — "there is a configuration somewhere and the store has none" — and it is the same state `ensure_config` uses to write the default configuration. A marker would be a second thing that can be out of step with the store's contents.

**Alternative:** a marker in the `meta` table recording that the import ran. Rejected: it would have to be written for stores that hold a configuration already, which means every fresh database gets a row written into it before anything else happens, and the marker would then have to be kept in step with the contents by hand.

### The import is reported through the log channel

`main.rs` keeps the path the import returned and reports it after `log::init`, the same way the "wrote a minimal configuration" notice is reported today.

**Why:** the notice is server-mode output, and server-mode advisories go through the log rather than raw stdout. The import happens before the log exists — the configuration has to be loaded before the log can be set up, and the configuration is what the import fills — so the fact has to be carried across that gap rather than printed at the moment it happens.

### The feature becomes a default, and the file-only build stays buildable

`storage-sqlite` moves into the crate's default features, and `--no-default-features` still builds a server that has only the file store.

**Why:** a store that has to be switched on at build time is a store nobody uses by accident, and "the database is the default" is only true if the binary that ships has it. The CI job that builds with the feature becomes the default build, and a second job with `--no-default-features` keeps the file-only path honest — it is the configuration `nexapipe` falls back to when it is built without the database.

**Consequence for the dependency policy.** `libsqlite3-sys` and the SQLite it bundles are now in every server binary rather than only in the ones that enabled the feature, which widens the reach of `RUSTSEC-2026-0459`. The advisory's exposure does not widen with it: the crafted `-wal` file it needs has to sit next to the database, and that directory already holds the client seeds and the endpoint key. The ignore in `deny.toml` stays, with the reason unchanged.

**Alternative considered:** `sqlite-unbundled`, which links the system SQLite instead of the bundled one and so does not ship the vulnerable copy. Rejected for the default, because it makes the build depend on a system SQLite that Alpine, musl and the Windows builds do not all have, and because the system SQLite is not necessarily newer than the bundled one — 3.54.0 is recent enough that a distribution's copy may be older. It stays available as a cargo feature for a deployment that wants it.

## Risks / Trade-offs

- **The default changes under a deployment that says nothing.** → The change is reported on every start that touches a fresh database, and the file store is one flag away. The rollback is `--storage toml`, which reads the file the deployment already had.
- **An operator edits the legacy file and sees no effect.** → The import report names the file and the database and says which is read. The file is left in place, so deleting the database and starting again brings the file back.
- **Two instances start at once against the same empty database.** → Both may import; they import the same file, so the outcome is the same configuration. The database store has no lock file to take, unlike the file store; this is a property of the seam and is not fixed here.
- **The bundled SQLite reaches more binaries.** → The advisory's ignore already carries the reason, and the exposure is unchanged. Revisit when sqlx allows `libsqlite3-sys >= 0.39.0`.
- **The configuration now lives where a `cat` cannot read it.** → `nexapipe config export` (the CLI change that follows) writes it back out as TOML. Until then, the file store remains the readable one.

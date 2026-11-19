# Tasks

## 1. The application

- [x] 1.1 Create `ui-web/` with the same shape as `ui-desktop/` — `package.json`, `vite.config.ts`, `tsconfig.json`, `index.html`, `src/` — and verify `npm ci && npm run build` produces a bundle in `ui-web/dist/`
- [x] 1.2 Set up the i18n the desktop application has, with an English locale and a `zh-CN` locale, and verify `npm run lint:i18n` reports no string missing from either
- [x] 1.3 Set up the lint and the type check, and verify `npm run build` fails on a type error and `npm run lint` fails on a lint error
- [x] 1.4 Add the CI job that builds the console and runs its checks, and verify the job is green and that `npm audit --omit=dev --audit-level=high` reports nothing

## 2. The pages

- [x] 2.1 Add the API client — every request carries the admin token as a bearer, every write carries the header `X-NexaPipe-Admin: 1`, and the token is kept in the browser's local storage — and verify a store test that a write carries the header and a read does not need it
- [x] 2.2 Add the overview page, showing the uptime, the counters, the open connections and the backend pools, and verify it renders the values the API answered with
- [x] 2.3 Add the routes page, showing the live route table, and verify it renders one row per route
- [x] 2.4 Add the clients page, showing the clients and their devices and never a secret, and verify it renders the device names and no secret
- [x] 2.5 Add the two write paths — issuing a credential and dropping one, adding a route and removing one — and verify each one asks the API and refreshes the page it changed
- [x] 2.6 Add the way the operator pastes the token, and verify the console asks for it before its first request and keeps it afterwards

## 3. The instance serves the console

- [x] 3.1 Add `console_dir` to `AdminConfig` in `crates/nexapipe/src/config/schema.rs`, and verify a configuration without it loads and a configuration with it loads
- [x] 3.2 Serve the files in the console directory at `/` in `crates/nexapipe/src/admin/mod.rs`, with the content type each extension asks for, and verify a request for the index returns the index and a request for a hashed asset returns that asset
- [x] 3.3 Refuse a path that would leave the console directory, and verify a request naming `../` in it is refused and nothing outside the directory is served
- [x] 3.4 Answer the console's path with "not found" when no console directory is configured, and verify the rest of the listener is unchanged — `/healthz`, `/metrics` and `/v1/*` answer as they did

## 4. The console's API

- [x] 4.1 Add the `/api/*` namespace to `crates/nexapipe/src/admin/mod.rs`, answering with JSON and never with a cross-origin allowance, and verify a response carries no `Access-Control-Allow-Origin` header
- [x] 4.2 Refuse a request whose host is not loopback, and verify a request with a host that is not a loopback address is refused and one with `127.0.0.1:PORT` or `localhost:PORT` is answered
- [x] 4.3 Refuse a request without the admin token, and verify one without a bearer is refused and one with the right bearer is answered
- [x] 4.4 Refuse a write without the header `X-NexaPipe-Admin: 1`, and verify a `POST` without it is refused and one with it is carried out
- [x] 4.5 Answer the five reads from the functions the `/v1/*` namespace already uses, and verify the two namespaces answer the same document for the same question

## 5. The storage seam grows the routes

- [x] 5.1 Add `write_route` and `remove_route` to the `Storage` trait in `crates/nexapipe/src/storage/mod.rs`, and verify a store that does not implement them does not compile
- [x] 5.2 Implement them for the file store in `crates/nexapipe/src/storage/file.rs`, under the lock the other writes take, and verify a test that adds and removes a route and reads the file back
- [x] 5.3 Implement them for the SQLite store in `crates/nexapipe/src/storage/sqlite.rs`, writing the routes table row by row and moving the revision with the write, and verify a test that adds and removes a route and sees the revision move
- [x] 5.4 Wire the console's route writes and client writes through those methods, and verify a running instance picks the change up after its next reload

## 6. Shipping and verification

- [ ] 6.1 Copy `ui-web/dist` into the container image and point `[admin] console_dir` at it, and verify the image serves the console and that an image without the console still starts
- [x] 6.2 Run `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo test --workspace --locked`, and verify they pass
- [x] 6.3 Document the console in `README.md` and `README.zh-CN.md` — what it is, how to turn it on, and that it is served from the loopback listener — and verify the documented configuration is the one the binary accepts
- [x] 6.4 Note the console in `CHANGELOG.md`, and verify the note says which release it arrives in

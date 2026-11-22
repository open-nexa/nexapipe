# Design

## Context

The admin listener is already the place where an instance talks about itself: `GET /healthz`, `GET /metrics` and the token-guarded `GET /v1/*`. It is loopback-only, the token is generated on the first start and kept in the store, and the module's own documentation says the `/v1/*` half "answers questions and nothing else" — adding and revoking are `nexapipe client add` and `nexapipe client revoke`, which write the configuration through the same lock the server takes.

Two things the listener does not have yet: anything that writes, and anything that is a page rather than a document. Both are wanted by the same operator at the same moment — looking at the route table and adding a client to it.

The frontend conventions are already set by `ui-desktop/`: Vue 3 with `vue-i18n`, TypeScript, Vite, ESLint, and store tests run through a small script rather than a test framework.

## Goals / Non-Goals

**Goals:**

- An operator with a browser on the machine can see what an instance is doing and change its clients and its routes.
- Nothing the console does opens a hole the listener does not already have: no cross-origin access, no write without the token, no answer to a request that was addressed somewhere else.
- The console is an ordinary web application: buildable, type-checked, linted and translated like the desktop one.

**Non-Goals:**

- Editing the settings.
- Accounts, sessions, roles, or reaching an instance on another machine.
- Embedding the console in the desktop application or in the server binary.
- Replacing the command line.

## Decisions

### The console is a separate application in `ui-web/`

A Vue 3 and TypeScript application built with Vite, with its own `package.json`, its own lockfile, its own lint and its own tests — the same shape as `ui-desktop/`.

**Why:** the desktop application is a Tauri application with a Rust backend of its own and a client for the instance; the console is a plain page that talks to one instance over HTTP. They share the framework and the i18n conventions and nothing else, and merging them would put a web application that needs no desktop runtime inside a bundle that needs one.

**Why not a second tab in the desktop application:** the desktop application is for an operator who installed it; the console is for an operator with a browser and a shell on the machine the server runs on. Many of them will never install the desktop application.

### The instance serves it from a directory

`[admin] console_dir` names a directory; the listener serves the files in it at `/`.

**Why:** the bundle is a build artifact, and a build artifact belongs next to the binary rather than inside it. Embedding it would put an npm build in the middle of every `cargo build`, and the server crate would have to carry a bundler.

**Why a directory and not a path to a single file:** a bundle is a directory of files — an index, a script, a stylesheet, assets with hashed names in them. Naming the directory says where the bundle is; the listener works out the rest.

**The router is a hash router,** so every path the console needs is a path inside the index, and the server has no fallback to invent.

**Why not serve the console from a separate static host:** then the console's requests to the instance would be cross-origin, and the instance would have to send a cross-origin allowance to make them work. That allowance is the thing this design is built to avoid.

### The console's API is a second namespace, `/api/*`

`/v1/*` stays exactly as it is: token-guarded, read-only, the surface `nexapipe status` and the scripts use. `/api/*` is the console's door: the same token, the same JSON, and the ability to write.

**Why not extend `/v1/*`:** `/v1/*` has a stated invariant — it answers questions and changes nothing — and that invariant is why the token can stay an opaque value with no scope. Giving that same token write access over the credential store is the change the invariant exists to prevent.

**Why not have the console use `/v1/*` for reads and `/api/*` for writes:** the two doors would then answer the same questions, and a script would have to know which door a question lives behind. Better that each door answers everything it is asked.

**The reads are not written twice.** The admin module already builds the route table, the client list, the connections and the health as JSON in named functions; both namespaces call them.

### Three guards, in this order

A request to `/api/*` is answered only when all three hold:

1. **The host is loopback.** The `Host` header's host part must be a loopback address or `localhost`. This is the DNS-rebinding guard: a page on a domain the attacker controls, resolving to `127.0.0.1`, arrives with that domain in the `Host` header and is refused. The listener already refuses to bind a non-loopback address, so this checks that the request was addressed to the loopback listener and not merely delivered to it.
2. **The token is there.** The same bearer token `/v1/*` takes.
3. **A write says it is a write.** Anything that is not a read carries `X-NexaPipe-Admin: 1`.

**Why the header rather than nothing:** a browser will not let a page on another origin add a custom header to a request without asking the server first, and the server answers no preflight and sends no cross-origin allowance. So the header is a thing a cross-origin page cannot send, which makes the write half of the API unreachable from one.

**Why the token at all, when the host is loopback:** because loopback is not the operator. Every process on the machine — and every user on a shared machine — can reach a loopback port. The token is what a process that is not the operator does not have. This is the same perimeter the token file has today.

**Why the order:** the host is checked first because it costs nothing and refuses the rebinding attempt before anything else looks at the request.

### The operator pastes the token; the server never puts it in the page

The console keeps the token in the browser's local storage and sends it as a bearer on every request.

**Why not serve the page with the token in it:** the token file's permissions are what keep another user on a shared machine out of the management surface. A page with the token in it would hand that token to anyone who can fetch the page — which is anyone on the machine — and the permissions would stop protecting anything.

**Why not read the token file from the browser:** the browser is not the operator's shell, and the token is in the store, which may be a database.

**The cost, named:** the operator pastes it once. It is one step, and it is the same token `nexapipe status` uses.

### The console's pages

The five reads the instance already answers, and the two writes:

- **Overview** — uptime, counters, what is enabled, the open connections, the backend pools.
- **Routes** — the live route table, and adding and removing a route.
- **Clients** — the clients and their devices, issuing a credential and dropping one.

**Why not a page per read:** the reads answer different questions about one instance, and an operator looking at the instance looks at all of them. Five pages for five endpoints would be five times the navigation for the same information.

### The writes go through the storage seam, and the seam grows two methods

The clients are already entities in the `Storage` trait: `write_client_secret`, `write_device_credential`, `remove_client`, `remove_device`. The routes are not — the trait has no way to write one — so it grows `write_route` and `remove_route`.

**A route is addressed by the id the route list gives it.** The schema permits two entries with the same host and path when their modes or backends differ, so a name made of host and path alone cannot say which one a removal or an edit means. `GET /api/routes` puts an id on each row, and both stores resolve it to exactly that row.

**Why through the seam:** the server reads the configuration through the seam, so a change the console makes has to be a change the seam can see. A write that went around the trait would be a write the server's watcher does not know about, and the console would show a change the instance has not made.

**Why the trait grows rather than the console rewriting the configuration:** a write that re-rendered the whole configuration would take a route somebody added while the server was running with it — the reason the SQLite store writes by entity in the first place.

**The revision moves with the write,** so the running instance reloads the way it reloads for a credential the command line issued. That is the existing mechanism and it is not changed.

### The bundle ships beside the binary

The bundle is a directory of files, and it is **mounted** rather than copied into the image: `ui-web/dist` is built on the host, mounted read-only at `/app/console`, and the configuration points `[admin] console_dir` at it.

**Why mounted and not copied in:** the image would otherwise carry a node toolchain to build a bundle that changes with every commit, and the build context would carry the console's `node_modules` — tens of megabytes the image has no use for. Mounted, the image is the same image whether or not a console is wanted, the bundle is rebuilt with `npm run build` rather than with the release, and a deployment that does not configure `console_dir` serves no console.

**Why not embed:** see above — an npm build inside every cargo build.

## Risks / Trade-offs

- **The token sits in the browser's local storage.** → Any script running on the console's origin could read it. The console serves nothing but itself, loads nothing from another origin, and is sent a content security policy that says so; the loopback listener is the only origin it has.
- **A write from another local process is possible with the token.** → The token is the same authority `nexapipe status` already has, and the token file's permissions are the perimeter, exactly as they are today. A process that cannot read the token file cannot write.
- **The console and the command line can write at the same time.** → The stores already take a lock per write and move a revision with it; the console's writes go through the same methods the command line uses, so they serialize the same way.
- **The bundle has to be built and shipped.** → A build step on the host and a mount into the container, and a configuration key that points at the result. A deployment that does not configure `console_dir` serves no console, and nothing else changes.
- **The console can only manage an instance on this machine.** → That is the listener's own rule, and the design keeps it rather than widening it.
- **The routes a console writes have to survive the configuration model.** → The console writes the same route type the configuration file holds, so a route written in the console and a route written in the file are the same thing.

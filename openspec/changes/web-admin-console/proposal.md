# Proposal

## Why

The management surface is a set of `GET /v1/*` endpoints and a command line. That is enough to ask a running instance what it is doing and enough to change the credentials, but not enough to *look* at an instance: an operator who wants to see the route table, the clients and the open connections has to read a terminal dump, and an operator who wants to add a client has to be at a shell. The listener that already answers those questions is loopback-only and already running; a console on it makes the same questions answerable as questions.

## What Changes

- A new `ui-web/` application: Vue 3 and TypeScript, built with Vite, laid out like the desktop application.
- The admin listener serves the console's static files at `/`, from a directory named in the configuration. With no directory configured, nothing is served and the listener is exactly what it is today.
- A new `/api/*` namespace on the same listener: JSON, reads and writes, for the console.
- A request to `/api/*` is answered only when it is addressed to a loopback host, carries the admin token, and — if it writes — carries the header `X-NexaPipe-Admin: 1`. The listener sends no cross-origin allowance at all, so a page on another origin can neither read an answer nor make a write.
- The console can read the instance — status, routes, clients, connections, backend health — and can change the two things that change most often: the clients and the routes. Those changes go through the storage seam, so a running instance picks them up through the reload it already does.
- `/v1/*` is unchanged: token-guarded, read-only, and the surface `nexapipe status` and the scripts use. The console's API is a second door with the same authority and one thing more — it can write.

### Out of scope

- Editing the settings. The configuration has more than thirty keys and each of them has a rule; the first version changes the two things that change most often and leaves the rest to the command line and the configuration file.
- Accounts, sessions and roles. The listener is loopback-only, there is one operator, and the token is the whole of the authority.
- The PostgreSQL store.
- Serving the console from anywhere but the admin listener, or embedding it in the desktop application. The desktop application manages an instance that may be on another machine.
- Replacing the command line. Everything the console can do, the command line still does.
- A console that reaches a remote instance. The listener refuses a host that is not loopback, and that is the point.

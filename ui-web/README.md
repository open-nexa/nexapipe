# NexaPipe console

The browser console for a running NexaPipe instance: what it is doing, who is
connected to it, and the two things an operator changes most often — the
clients that may connect and the routes it serves.

It is a page, not a service. The instance serves it from its own loopback
listener, next to the API it talks to, so the two are on the same origin and
no cross-origin allowance is ever needed.

## What it is not

- **It is not a remote console.** The instance refuses a request that was not
  addressed to a loopback host, and the listener it serves from is bound to
  loopback anyway.
- **It is not a replacement for the command line.** Everything the console can
  do, `nexapipe` still does. The console is for looking; the command line is
  for scripting.
- **It does not edit the settings.** The configuration has more than thirty
  keys and each of them has a rule. The first version changes the clients and
  the routes and leaves the rest to the command line and the configuration
  file.

## The token

The console asks for the admin token the instance wrote when it first started.
It is kept in the browser's local storage and sent with every request.

The token is not put into the page the instance serves. The token file's
permissions are what keep another user on a shared machine out of the
management surface, and a token in the page would hand it to anyone who can
fetch the page — which is anyone on the machine.

## Development

```bash
npm ci
npm run dev
```

The dev server proxies `/api` to `http://127.0.0.1:8080`. Point it somewhere
else with `NEXAPIPE_ADMIN`:

```bash
NEXAPIPE_ADMIN=http://127.0.0.1:9090 npm run dev
```

## Checks

```bash
npm run build        # vue-tsc --noEmit && vite build
npm run lint:i18n    # en.json and zh-CN.json must have the same keys
npm run test:stores  # the store tests
```

The store tests are plain Node tests run through Vite's own SSR build — the
tree has no test runner, and the store's imports are extensionless.

## Building for the instance

```bash
npm run build
```

The result is `dist/`. The instance serves that directory when
`[admin] console_dir` names it.

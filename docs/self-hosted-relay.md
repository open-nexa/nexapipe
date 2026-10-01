# Running your own relay

Most connections NexaPipe makes hole-punch and never touch a relay. The ones
that do not — roughly one in ten, by the numbers the README quotes — fall back
to a relay, and by default that relay is one of the four n0 operates. Running
your own is what turns "the fallback is somebody else's machine" into "the
fallback is mine", and it costs one process on a host you already have.

It does not turn NexaPipe into something with no third party in it. Endpoint ID
discovery still asks n0 where to send QUIC packets, and a peer that advertises
an N0 relay is still dialled through it. Read
[What still depends on third-party infrastructure](iroh-boundaries.md) before
you decide what your relay bought you; this page is deliberately silent about
those two, because owning the relay does not change either of them.

| | |
|---|---|
| Applies to | The relay server is `iroh-relay` 1.2.0 — `Cargo.lock` resolves `iroh` and `iroh-relay` at 1.2.0 |
| Upstream sources | [iroh-relay 1.2.0 on docs.rs](https://docs.rs/crate/iroh-relay/1.2.0), the [README at tag v1.2.0](https://github.com/n0-computer/iroh/blob/v1.2.0/iroh-relay/README.md), [`src/main.rs` at v1.2.0](https://github.com/n0-computer/iroh/blob/v1.2.0/iroh-relay/src/main.rs), [`src/defaults.rs` at v1.2.0](https://github.com/n0-computer/iroh/blob/v1.2.0/iroh-relay/src/defaults.rs) |
| Last verified | 2026-10-01, against the upstream sources above and this tree |

**This page has not been verified end to end by the maintainers; the NexaPipe
side is taken from the code, the relay side from upstream docs.** No one has run
the commands below in this project's CI. Where upstream and this tree could not
be made to agree, that disagreement is written down here rather than papered
over.

## Where the relay server comes from

The relay server upstream ships today is the `iroh-relay` crate. Older notes —
including item **R6** in [docs/ROADMAP.md](ROADMAP.md) — call it "derper", which
was its name in the pre-1.0 `iroh-net` layout. Nothing named `derper` ships from
the 1.x tree: the crate, the binary the releases publish and everything the
current docs mention are `iroh-relay`, and looking for the old name is how an
afternoon goes missing.

There is **no official container image.** The
[iroh docs page on relays](https://docs.iroh.computer/concepts/relays) points at
two upstream sources and neither of them is an image: the crate source
(`n0-computer/iroh` under `iroh-relay/`) and
[the binary releases](https://github.com/n0-computer/iroh/releases). The
releases publish one archive per target — at the version this tree locks, that
is `iroh-relay-v1.2.0-x86_64-unknown-linux-gnu.tar.gz` (a `musl` build and
`aarch64` and Darwin builds ship alongside it), so the honest deployment shape
today is a binary plus your own unit file, not `docker compose up`.

If you would rather build than download, upstream's own instructions do it from
the iroh checkout — note the `cd ../`, which makes this a workspace build rather
than a crate build, so it needs the whole repository, not just `iroh-relay/`:

```bash
cd ../
cargo build \
  --profile optimized-release \
  --package iroh-relay \
  --features server
# binary lands at target/optimized-release/iroh-relay
```

Keeping to **the same version your endpoints speak** is worth doing: this tree's
`Cargo.lock` resolves `iroh` and `iroh-relay` at 1.2.0, and pinning the relay to
that tag is the only combination anyone here can reason about. Upstream's
current release is newer than what this tree links, and whether the two ends
still agree across that gap is not something this page can tell you.

## Starting it

The binary takes exactly two flags — `--dev` and `-c` / `--config-path` — so
everything that decides how it behaves lives in the TOML file you point it at.

`--dev` is for a laptop. Its own help text says it "will ignore any config file
fields pertaining to TLS": rather than binding HTTPS it serves plain HTTP on
`[::]:3340`, or on `http_bind_addr` if you set one explicitly. QUIC address
discovery stays off, because `enable_quic_addr_discovery` defaults to `false`,
and turning it on under `--dev` requires a certificate you made yourself and is
outright incompatible with `cert_mode = "LetsEncrypt"`. A production relay needs
none of this; upstream's local-testing notes are where to read the details.

A production config needs `[tls]`, because without it every relay service runs
over plain HTTP. Let's Encrypt is the case you almost certainly want — the relay
gets its own certificate, your endpoints keep talking `https://`, and there is
nothing for you to renew by hand:

```toml
# /etc/iroh-relay.toml
enable_relay = true                      # the default; the point of running this process

http_bind_addr = "[::]:80"               # the default: [::]:80 with no tls, and the
                                         # socket a captive-portal probe still answers on
                                         # once tls exists

[tls]
cert_mode = "LetsEncrypt"
hostname = "relay.example.com"           # a string or a list; what the cert is issued for
contact = "you@example.com"              # a bare address; it must not be empty
https_bind_addr = "[::]:443"             # the default: http_bind_addr's IP on port 443

# Everything reachable from the internet can reach this relay until you say
# otherwise. See the next section.
access = "everyone"
```

Then:

```bash
iroh-relay --config-path /etc/iroh-relay.toml
```

`cert_mode` has no default, so once a `[tls]` section exists, leaving it out is
an error rather than a guess. `hostname` defaults to empty and `contact` to
absent, which `LetsEncrypt` mode refuses — `LetsEncrypt needs a contact email` —
so both have to be written; the relay adds the `mailto:` around your address
itself, so it goes in as a bare one. The two other spellings of `cert_mode`
are `"Manual"` (reads `./default.crt` and `./default.key`, or whatever `manual_cert_path` /
`manual_key_path` name — useful behind your own reverse proxy or automation) and
`"Reloading"`, which is `Manual` plus re-reading the same pair of files on a
timer so a rotation does not need a restart.

### What to open

Three kinds of listener, and only the first is the relay:

| Port | What it is | Open it? |
|---|---|---|
| TCP 80 / 443 | The relay itself — HTTP services when `tls` is absent, HTTPS when it is not. | Both, on the public interface. |
| TCP 9090 | Metrics. `enable_metrics` defaults to `true` and `metrics_bind_addr` defaults to the HTTP address's IP on port 9090. | Not publicly. Scrape it over a tunnel, or set `enable_metrics = false`. |
| UDP `quic_bind_addr` | QUIC address discovery, off by default (`enable_quic_addr_discovery = false`). | Only if you turn it on. |

Those defaults come from `defaults.rs`: `DEFAULT_HTTP_PORT = 80`,
`DEFAULT_HTTPS_PORT = 443`, `DEFAULT_METRICS_PORT = 9090`,
`DEFAULT_RELAY_QUIC_PORT = 7842`. One honest wrinkle — upstream's README says
the dev-mode QUIC server runs on **7824**, the constant says **7842**. Rather
than copy either number into your firewall rules by eye, set `quic_bind_addr`
explicitly and open what you set.

**There is no STUN knob.** Guides written against the pre-1.0 layout tell you to
open UDP 3478 for STUN and put `stun_port = 3478` in the config — see, for
example, the old
[local relay node doc](https://github.com/n0-computer/iroh/blob/730f71736e863c9f310960f29c971dc5afdea1e2/iroh-net/docs/local_relay_node.md).
`ServerConfig` in 1.2.0 has three fields — `relay`, `quic`, `metrics_addr` — and
none of them is STUN. Do not go looking for it, and treat any relay tutorial
that mentions `stun_port` as written for a different generation.

## Keeping other people off it

The default is `access = "everyone"`, which is a fine answer for a relay whose
capacity you do not care about and a poor one for a relay you are paying for or
bound by the terms of. Four modes are configured through the single `access`
key:

```toml
# By identity: name the endpoint IDs (public keys) of your own machines.
access.allowlist = ["<endpoint-id>", "<endpoint-id>"]
# Or invert it.
access.denylist = ["<endpoint-id>"]

# By bearer token. This is the one NexaPipe can speak — see below.
access.shared_token = ["token-a", "token-b"]

# By asking something you wrote, per connection, every time.
access.http.url = "https://your-auth-service.example.com/relay-auth"
```

`allowlist` / `denylist` are the strongest answer and the most work: every
endpoint that may use the relay has to be named, and NexaPipe prints the Node ID
an endpoint is using at startup, which is where you read them from. `http` keeps
those decisions in your own service, at the cost of a round trip per connection.
`shared_token` is the lightest, and upstream is blunt about its one limit: it
does not support revocation other than updating the config and restarting the
service.

`shared_token` is the mode that lines up with NexaPipe's own key. Upstream
accepts it as an `Authorization: Bearer <token>` header or a `?token=` query
parameter, and NexaPipe's `relay_auth_token` becomes exactly that header: the
config is handed to `RelayConfig::with_auth_token`
([`crates/nexapipe-client/src/relay.rs`](../crates/nexapipe-client/src/relay.rs)),
whose documentation says the token is sent as `Authorization: Bearer TOKEN` on
the WebSocket upgrade request. So one string in each side's config is the whole
setup. It can also be set on the relay side by the `IROH_RELAY_ACCESS_TOKEN`
environment variable, which replaces the list in the file and wins over it.

## Pointing the server at it

Three keys under `[iroh]`, and nothing else:

```toml
[iroh]
relay_mode = "custom"
relay_url  = "https://relay.example.com"
relay_auth_token = "the-shared-token"     # only if the relay asks for one
```

Four things the code does with those keys, each of which decides whether you
get a working relay or a startup error.

`custom` with no `relay_url` is refused at startup, with
`relay_mode = "custom" requires a non-empty relay_url`. There is no silent
fallback to the N0 relays, which is deliberate: you asked for your own relay,
and quietly borrowing somebody else's is not what that means.

An n0-operated URL under `custom` is rejected too. `*.relay.n0.iroh.link` comes
back with an error telling you to use `pinned` or `default` instead, which keeps
reading the config enough to answer "am I off the official relays?" without
running anything.

`custom` is exclusive. It hands iroh a relay map holding exactly one relay and
replaces the preset's map rather than adding to it, so no N0 relay survives as a
home relay or as a net_report probe target. This is also where the token lands:
it is attached with `with_auth_token`, and a value that trims down to empty
counts as none rather than as an empty bearer.

And `[iroh]` is read once at startup. The endpoint is bound once, so changing
any of the three takes a restart — unlike routes, which the watcher picks up
within seconds.

One consequence of writing a token here: `relay_auth_token` is a credential, and
a `config.toml` holding one that is readable or writable by another account makes
the server **refuse to start**. `chmod 600 config.toml`. This is the same check
that covers a TOTP seed and `[iroh] secret_key`.

### Checking it took effect

Every entry point that resolves a relay mode logs one line describing what took
effect, written by `RelayModeSpec::describe()`. The server and the desktop app
print this one:

```text
Relay: custom (https://relay.example.com/, auth_token=set)
```

The trailing slash is how iroh renders a `RelayUrl`, not a typo in your config —
the assertion in `crates/nexapipe-client/src/relay.rs` expects
`https://relay.example.com/`, and `describe()` prints the URL as iroh prints it.

The Android app prints the same string with `[iroh] relay:` in front of it.
`auth_token=none` means your token did not make it: the value is trimmed, so a
token that is only whitespace reads as absent.

Read that line rather than the config file, because it is what the process
resolved after validation. Its *absence* on the server means the opposite of
what you might expect — no relay keys at all resolves to iroh's own default, not
to a refusal, so a server that prints nothing is still using every N0 relay.
What the line proves once it prints is which mode was installed; it does not
prove the relay answered, because nothing dials it on your behalf and reports.

The neighbour line is worth watching for the opposite reason:
`[iroh] relay_url ... is set but this mode does not use one; ignoring it` means
the URL is stale next to a mode that never reads it — which is how a config
moved to `pinned` last month keeps looking like it points at your relay.

For whether traffic is actually arriving, watch the relay's own metrics listener
(TCP 9090 by default, see above) and keep it off the public interface.

## The clients have to be told too

A relay carries traffic between two endpoints, and **each endpoint uses the
relay configuration it was given** — so setting `custom` on the server alone
does not move client traffic off the N0 relays. Both clients resolve the same
three names through the same `RelayModeSpec`, and both default to `pinned` when
nothing is configured:

| Client | Where the same three keys live |
|---|---|
| Server (`nexapipe`) | `[iroh] relay_mode` / `relay_url` / `relay_auth_token`. Restart-only. |
| Desktop (`ui-desktop`) | The Config page's relay section — a mode select and a URL field behind the same credential door that protects the rest of the connection settings. |
| Android (`ui-android`) | The stored `relay_mode` / `relay_url` / `relay_auth_token` preferences, which reach the library through `nativeSetRelayConfig` before the endpoint is started. |

One route in particular does not survive this section: **an invite cannot carry
a relay token.** `--generate-invite` puts `relay=` in the link from the server's
own `[iroh] relay_url` when that resolves to `custom`, but the field is
documented as *a hint only*, there is no token field in the invite at all, and
even importing an invite into the desktop passes an explicit "apply relay"
choice rather than doing it silently. A relay protected by `shared_token` is
therefore configured directly on every client, or is not protected usefully.

## What owning the relay does not change

Restating this here rather than leaving it to the other page, because it is the
part people assume:

- **Endpoint ID discovery still goes to n0.** Turning a Node ID into "where do
  I send QUIC packets" queries `dns.iroh.link`, over HTTPS and over DNS, and it
  does that regardless of `relay_mode`; no NexaPipe setting turns it off. iroh
  1.2.0 has `clear_address_lookup()`; NexaPipe does not call it.
- **A peer's advertised relay is still dialled.** `allowed_relay_urls()` — the
  set you would build an address filter from — has no production caller, so
  `custom` bounds *this* endpoint and nothing else. If your requirement is "no
  traffic of mine or my peers touches an n0 relay", `disabled` with successful
  hole punching is still the only answer that ships, and it fails outright when
  punching does not succeed.
- **A relay is still a relay.** It cannot read what it carries — the traffic is
  QUIC end to end — but it does see that your endpoints talk, when, and roughly
  how much. What you bought is not invisibility; it is that the other party is
  you.

Full reasoning in
[What still depends on third-party infrastructure](iroh-boundaries.md).

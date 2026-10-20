# What still depends on third-party infrastructure

NexaPipe claims there is no server to rent, no control plane and no certificate
to hold. That claim is true of the parts NexaPipe owns. It is not true of
everything underneath: the transport is iroh, and iroh leans on infrastructure
n0 operates in two places — Endpoint ID discovery and the relay. Both are now
things a configuration can answer for.

This page is the honest boundary. It exists because the alternative is a
sovereignty story that sounds stronger than it is.

| | |
|---|---|
| Applies to | iroh 1.x — `Cargo.toml` asks for `^1.0.1`, `Cargo.lock` resolves 1.3.0 |
| Last verified | 2026-10-21 |

## The short version

| What | Who operates it | Can you turn it off? |
|---|---|---|
| Endpoint ID discovery | n0 (`dns.iroh.link`) | **Yes** — `discovery = "none"`, on the server and on both clients |
| Relay transport, `relay_mode = "default"` | n0 | Yes — `custom`, `pinned` or `disabled` |
| A relay you run yourself | you | That is `relay_mode = "custom"` |
| A relay a *peer* advertises | whoever the peer uses | Yes — `custom` refuses it, and `disabled` cannot use it at all |
| Certificates | you, at your backend | N/A — NexaPipe never holds one |

## 1. Endpoint ID discovery

A Node ID is a public key, not an address. Turning one into "where do I send
QUIC packets" is a lookup, and with the default discovery that means asking
n0's `dns.iroh.link` twice over: once as an HTTPS request through Pkarr, and
once as a DNS query. Both go out concurrently and their answers are merged, so
a result arrives when either one gets through.

That lookup is the one piece of n0's infrastructure a relay setting does not
reach — running your own relay does not remove it — so it has a setting of its
own:

```toml
[iroh]
discovery = "none"
```

`none` takes the address-lookup services off the endpoint (iroh's
`clear_address_lookup()`). The endpoint then neither publishes its address to
n0 nor resolves anyone else's through it.

**What it costs.** A Node ID on its own is no longer enough to reach the
endpoint. A peer has to bring an address of its own — a ticket, which is what
`--generate-invite` produces, or an explicit `EndpointAddr`. That is the trade:
no third party learns which Node ID is being asked about, and nothing about
this endpoint goes to a lookup service, in exchange for handing the address
over instead of looking it up.

**What it does not cost.** Hole punching, direct addresses and the relay you
configured are untouched. Only the "ask somebody where they are" step goes
away.

The clients have the same switch: the desktop takes it as part of the proxy
configuration, and the Android app has it next to the relay mode. Absent, both
keep the default, which is `n0`.

## 2. Relays

Four modes, and what each one bounds:

- **`default`** — every N0 relay, home relay chosen by latency. It can migrate
  between relays, which drops the connections routed through it.
- **`pinned`** — one fixed N0 relay (`https://aps1-1.relay.n0.iroh.link.`,
  Singapore). Still operated by n0; useful when relay migration is worse than a
  slightly slower relay.
- **`custom`** — one relay you run, and only that one, both as this endpoint's
  home relay and as a probe target. Pointing it at a `*.relay.n0.iroh.link` URL
  is rejected.
- **`disabled`** — no relay transport at all. Stronger than it sounds: you also
  cannot dial a peer through *its* relay.

**What `custom` buys.** iroh's `relay_mode` only bounds the relay *this*
endpoint registers with and probes through: a peer that hands over an address
naming somebody else's relay would still be dialled through it, and a peer
named only by a Node ID would be looked up through n0 and dialled through
whatever n0 answered with. A `custom` client now refuses both:

- a peer whose address names a relay other than yours is not dialled;
- a peer named only by a Node ID is not dialled at all, because finding its
  address means asking n0.

So a `custom` client reaches its peer through your relay and nothing else — and
it reaches it by ticket, because that is what carries an address. Both ends of
a self-hosted deployment point at the same relay, and the ticket names it.

**What `custom` still does not buy.** It says nothing about what the *server*
publishes. A server in `custom` mode still publishes its address — its relay
included — to n0's lookup service, which is how a client with a bare Node ID
finds it at all. `discovery = "none"` is what stops that, and the two settings
together are the fully sovereign deployment: your relay, your own address
lookup, and tickets instead of Node IDs.

## 3. What is left to do

Running your own relay is a documented deployment — see
[Running your own relay](self-hosted-relay.md), which covers getting the relay
server up and pointing both ends of a connection at it. It is not yet a
packaged one: there is no official container image upstream, so what you get is
a binary and whatever unit file, reverse proxy or firewall you put around it,
and that guide has not been verified end to end by this project. That packaging
gap is the rest of roadmap item **R6**.

## 4. Checking what your instance actually did

Startup logs one line naming the mode that took effect:

```text
Relay: custom (https://relay.example.com, auth_token=set)
Discovery: none (no lookup; a peer is reachable only by ticket or explicit address)
```

Those strings come from `RelayModeSpec::describe()` and
`DiscoveryMode::describe()`. Prefer them over reading the config file, because
they are what the process resolved, after validation and after the "a mode that
does not use a URL" warnings.

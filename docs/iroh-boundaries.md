# What still depends on third-party infrastructure

NexaPipe claims there is no server to rent, no control plane and no certificate
to hold. That claim is true of the parts NexaPipe owns. It is not true of
everything underneath: the transport is iroh, and iroh leans on infrastructure
n0 operates in two places. One of them — Endpoint ID discovery — **no
NexaPipe configuration can switch off**. The other, the relay, is what
`relay_mode` is for.

This page is the honest boundary. It exists because the alternative is a
sovereignty story that sounds stronger than it is.

| | |
|---|---|
| Applies to | iroh 1.x — `Cargo.toml` asks for `^1.0.1`, `Cargo.lock` resolves 1.2.0 |
| Last verified | 2026-09-29 |

## The short version

| What | Who operates it | Can you turn it off? |
|---|---|---|
| Endpoint ID discovery | n0 (`dns.iroh.link`) | **No** — no switch NexaPipe exposes, though iroh 1.2.0 does have `clear_address_lookup()` |
| Relay transport, `relay_mode = "default"` | n0 | Yes — `custom`, `pinned` or `disabled` |
| A relay you run yourself | you | That is `relay_mode = "custom"` |
| A relay a *peer* advertises | whoever the peer uses | Only with `disabled` — see below |
| Certificates | you, at your backend | N/A — NexaPipe never holds one |

## 1. Endpoint ID discovery

A Node ID is a public key, not an address. Turning one into "where do I send
QUIC packets" is a lookup, and with the default discovery that means asking
n0's `dns.iroh.link` twice over: once as an HTTPS request through Pkarr, and
once as a DNS query. Both go out concurrently and their answers are merged, so
a result arrives when either one gets through.

That happens regardless of `relay_mode`. Running your own relay does not remove
it. iroh 1.2.0 does have a way to switch it off —
`endpoint::Builder::clear_address_lookup()` — but NexaPipe does not call it and
exposes no setting that would, so as this ships there is no switch.

What follows from that:

- A Node ID on its own is not enough to connect when both lookups are
  unreachable. Filtering the DNS query alone does not stop discovery: the HTTPS
  request goes to a different service and can still answer on its own. Hand
  over a full ticket or an explicit address instead — that is what
  `--generate-invite` produces.
- The lookup lets a third party see that some host asked about some Node ID, and
  when. It does not reveal what was sent afterwards.
- The Android client exposes DNS server overrides partly for this reason.

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

**What `custom` does not buy as the code ships today.** A peer's address may
advertise an N0 relay, and nothing on the shipped path filters it out:
`RelayModeSpec::allowed_relay_urls()` — the set written to feed an address
filter — has no production caller. So `custom` bounds the relay this endpoint
registers with and probes through, and `disabled` is the only mode that removes
relay dialling entirely.

Read that as: if you need "no traffic of mine or of my peers touches an n0
relay", `disabled` with successful hole punching is the only current answer, and
it fails outright when punching does not succeed.

## 3. What is left to do

Running your own relay is a documented deployment — see
[Running your own relay](self-hosted-relay.md), which covers getting the relay
server up and pointing both ends of a connection at it. It is not yet a
packaged one: there is no official container image upstream, so what you get is
a binary and whatever unit file, reverse proxy or firewall you put around it,
and that guide has not been verified end to end by this project. That packaging
gap is the rest of roadmap item **R6**. Wiring the address filter so `custom`
also bounds peer-advertised relays is the same shape of gap — the pieces exist,
the wiring does not.

## 4. Checking what your instance actually did

Startup logs one line naming the mode that took effect:

```text
Relay: custom (https://relay.example.com, auth_token=set)
```

That string comes from `RelayModeSpec::describe()`. Prefer it over reading the
config file, because it is what the process resolved, after validation and after
the "a mode that does not use a URL" warnings.

# nexapipe-proto

The wire formats the [nexapipe](https://github.com/open-nexa/nexapipe) client and
server share.

Both sides link this crate, so neither can disagree with the other about what a
preface is, how a datagram is framed, how a handshake message is shaped, or what
a challenge is signed over. A rule written down once here is a rule both sides
follow.

## What is in it

| Module | What it defines |
|---|---|
| `preface` | The `0x05` preface that opens an L4 tunnel: magic, version, protocol, host, port |
| `udp` | The `u16`-length datagram framing a UDP flow carries |
| `auth` | The handshake messages, the challenge a response answers, and the close codes |
| `secret` | `SecretString` and `SecretBytes`: values that wipe themselves when they go out of scope |
| `tls` | The ClientHello reader that finds the SNI, and the record and handshake constants |
| `host` | The host spelling both sides fold the same way |
| `alpn` | The ALPN identifiers the client and the server agree on |
| `deadline` | The phase budgets both sides run under |
| `protocol` | The protocol names, and the set of ALPNs a build accepts |

## Using it

You normally do not depend on this crate directly: `nexapipe-client` links it,
and so does the server. It is published because a third party that speaks the
protocol — another client, another server, a test harness — needs the same
definitions rather than a copy of them.

```toml
[dependencies]
nexapipe-proto = "1.0"
```

The crate has no dependencies of its own beyond `serde`, `serde_json`,
`zeroize`, `hmac` and `sha2`, all of which every build that links it already
pulls in.

## Licence

MIT. See the `LICENSE` file in the package.

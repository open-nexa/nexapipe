# Every base image is pinned by digest, not by tag: a tag is a name that can
# be moved to different content at any time, and a digest is the content
# itself. `rust:alpine` here is the 1.x-alpine3.24 image built on 2026-10-15.
#
# To move to a newer image, resolve the digest of the tag you want and replace
# it here — leaving the tag in place, so the line still says what it is:
#   docker buildx imagetools inspect rust:alpine --format '{{.Manifest.Digest}}'
FROM rust:alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS builder

RUN apk add --no-cache musl-dev gcc make cmake ninja perl coreutils

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# `[patch.crates-io]` points at the vendored smoltcp fork, so it has to be in
# the build context as well.
COPY third_party ./third_party

# The client crate lists both `lib` and `cdylib` as its crate types, and cargo builds the
# cdylib slot even when the client is only a dependency here. musl turns crt-static on by
# default, which leaves rustc unable to produce one, so expect this and move on:
#   warning: dropping unsupported crate type `cdylib` for target `...-unknown-linux-musl`
# The binary links the rlib, which is built either way; nothing is missing.
#
# --locked: the build uses the lockfile in this repository and refuses to
# resolve anything else. Without it a build that cannot reach the index, or
# that sees a newer version than the lockfile pins, silently produces a
# different binary than the one the lockfile describes.
RUN cargo build --release --locked -p nexapipe

# alpine:3.24, pinned by digest like the builder above.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache ca-certificates tzdata

# The proxy needs no privileges: the plaintext listener is off by default, the
# TLS port belongs to the backend (Caddy), and the iroh port is an ephemeral UDP
# one. Running it as root bought nothing and cost the usual thing — a server
# reachable from the internet holding the 2FA seeds and the endpoint identity,
# where any code execution is instant root.
#
# uid 1000 rather than a named account, because the bind mounts below are owned
# by whoever ran `mkdir` on the host and that is very often uid 1000 already; a
# different uid is the case where the write fails, so the README has every setup
# run `sudo chown -R 1000:1000 config secrets logs` on the host. **Upgrading an
# existing deployment** needs that before the first start — files created by the
# previous root-running image stay root-owned, which is also why it takes
# `sudo`, and a 0600 key the new user cannot open is a start that fails on a
# first-run identity.
RUN adduser -D -u 1000 -h /app nexapipe

WORKDIR /app

# Default location of the log files; docker-compose mounts a volume on top.
RUN mkdir -p /app/logs

# Where docker-compose mounts the config directory.
RUN mkdir -p /app/config

# Where docker-compose mounts the secrets directory holding the endpoint
# identity (NEXAPIPE_IROH_SECRET_KEY_FILE points [iroh] at /app/secrets/iroh.key).
RUN mkdir -p /app/secrets

COPY --from=builder /app/target/release/nexapipe /usr/local/bin/nexapipe

# Owned by the runtime user, because all three are bind-mounted on top at run
# time and what matters is the host directory's ownership — this only makes an
# un-mounted `docker run` work.
RUN chown -R nexapipe:nexapipe /app/logs /app/config /app/secrets

# iroh carries every authenticated client, so nothing has to be published for
# HTTP. The plaintext listener ([server] listen_addr) is closed by default, and
# the TLS port belongs to the backend (Caddy), which this container only
# connects out to. Expose a UDP port here only if you pinned one with
# [iroh] bind_port.
#
# config.toml is **not** copied in: it holds the 2FA secrets under
# [auth.clients], which are the whole credential for the iroh listener. It is
# mounted at run time (see docker-compose.yaml) so it never lands in an image
# layer. The mount is a *directory* — /app/config — because a single-file bind
# mount is pinned to one inode and stops following the file the moment anything
# replaces it.

USER nexapipe

ENTRYPOINT ["nexapipe"]
CMD ["--config", "/app/config/config.toml"]

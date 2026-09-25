FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev gcc make cmake ninja perl coreutils

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# `[patch.crates-io]` points at the vendored smoltcp fork, so it has to be in
# the build context as well.
COPY third_party ./third_party

RUN cargo build --release -p nexapipe

FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Default location of the log files; docker-compose mounts a volume on top.
RUN mkdir -p /app/logs

COPY --from=builder /app/target/release/nexapipe /usr/local/bin/nexapipe

# iroh carries every authenticated client, so nothing has to be published for
# HTTP. The plaintext listener ([server] listen_addr) is closed by default, and
# the TLS port belongs to the backend (Caddy), which this container only
# connects out to. Expose a UDP port here only if you pinned one with
# [iroh] bind_port.
#
# config.toml is **not** copied in: it holds the 2FA secrets under
# [auth.clients], which are the whole credential for the iroh listener. It is
# mounted at run time (see docker-compose.yaml) so it never lands in an image
# layer.

ENTRYPOINT ["nexapipe"]
CMD ["--config", "/app/config.toml"]

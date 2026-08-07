# syntax=docker/dockerfile:1

# Local demo stack for caddy-openappsec.
#
# One Dockerfile, two build targets (selected from docker-compose.yml):
#   target caddy      (default) — Caddy v2.11.4 with the openappsec module
#                                 compiled in via xcaddy
#   target mockengine           — the scriptable mock open-appsec engine
#
# The compose wiring uses the "socket" (TCP) transport because it is the only
# transport that works across containers; production deployments would use
# the linux "shm" transport with shared-memory paths instead of tcp:// URLs.

# --- shared dependency-cache stage -----------------------------------------
# golang:1.25-alpine (musl) is the standard base for xcaddy/caddy builds and
# ships the full toolchain (gcc, git, ca-certificates) needed for CGO-enabled
# caddy builds.
FROM golang:1.25-alpine AS modcache
WORKDIR /src
COPY go.mod go.sum ./
# Warm the module cache before copying sources so dependency downloads are
# cached across rebuilds.
RUN go mod download

# --- mockengine: final image for the mockengine service ---------------------
FROM modcache AS mockengine
COPY . .
RUN CGO_ENABLED=0 go build -o /mockengine ./cmd/mockengine
# No ENTRYPOINT: docker-compose.yml passes the full command
# ["/mockengine", "-transport", "socket", ...].

# --- caddy-builder: xcaddy compile stage ------------------------------------
FROM modcache AS caddy-builder
# git is required by xcaddy's go get for some module resolutions (the
# official caddy:builder image does the same).
RUN apk add --no-cache git \
    && go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
COPY . .
# The module's go.mod requires caddy v2.11.4, but a bare `xcaddy build`
# would `go get` the latest caddy release and Go's MVS would then pick the
# newer version over the module's own requirement. Pinning the version here
# makes the build deterministic and identical to what the module is tested
# against. The local replacement form `--with <module>=/src` compiles the
# module from this repository.
RUN xcaddy build \
    --with github.com/caddyserver/caddy/v2@v2.11.4 \
    --with github.com/580132/caddy-openappsec=/src

# --- caddy: runtime image ----------------------------------------------------
FROM alpine:3.20 AS caddy
RUN apk add --no-cache ca-certificates
COPY --from=caddy-builder /src/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
EXPOSE 80 443 2019
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1:80/ || exit 1
ENTRYPOINT ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

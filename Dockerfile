# Base images are pinned by digest; update tag and digest together.
FROM --platform=$BUILDPLATFORM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS builder

ENV GOTOOLCHAIN=local

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ./ /app

ARG TARGETARCH
ARG TARGETOS
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-w -s -X main.version=${VERSION}" -o /app/bin/main . \
    && mkdir -p /data-skel

# Minimal image for HTTP(S) backends (e.g. a Trino MCP server reachable over
# the network): no shell or package manager, runs as non-root (uid 65532).
# Build with: docker build --target minimal .
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS minimal

COPY --from=builder /app/bin/main /usr/local/bin/mcp-auth-proxy
COPY --from=builder --chown=65532:65532 --chmod=700 /data-skel /data
# Non-root processes cannot bind ports below 1024 on Kubernetes.
ENV DATA_PATH=/data LISTEN=:8080 TLS_LISTEN=:8443
EXPOSE 8080 8443
USER 65532:65532

ENTRYPOINT [ "/usr/local/bin/mcp-auth-proxy" ]

# Full image (default) with Python and Node.js for stdio MCP servers launched
# by the proxy (npx/uvx). Runs as non-root (uid 10001).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS full

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 python3-pip nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --home-dir /home/app app \
    && mkdir -p /data && chown app:app /data && chmod 700 /data

COPY --from=builder /app/bin/main /usr/local/bin/mcp-auth-proxy
# Non-root processes cannot bind ports below 1024 on Kubernetes.
ENV DATA_PATH=/data HOME=/home/app LISTEN=:8080 TLS_LISTEN=:8443
EXPOSE 8080 8443
USER 10001:10001

ENTRYPOINT [ "/usr/local/bin/mcp-auth-proxy" ]

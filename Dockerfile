# syntax=docker/dockerfile:1
# ==============================================================================
# Stage 1: Build Client Zero-Knowledge Go WASM Enclave + Integrity Manifest
# ==============================================================================
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS wasm-builder
ENV GOTOOLCHAIN=auto \
    CGO_ENABLED=0
RUN apk add --no-cache nodejs
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/wasm ./cmd/wasm
COPY internal ./internal
COPY web/scripts/build-wasm.mjs ./web/scripts/build-wasm.mjs
RUN node web/scripts/build-wasm.mjs

# ==============================================================================
# Stage 2: Build Frontend Static Assets + SHA-384 Subresource Integrity (SRI)
# ==============================================================================
FROM --platform=$BUILDPLATFORM node:24-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY --from=wasm-builder /src/web/public/sns-zk.wasm.gz ./public/sns-zk.wasm.gz
COPY --from=wasm-builder /src/web/src/zk/wasm_exec.js ./src/zk/wasm_exec.js
COPY --from=wasm-builder /src/web/src/zk/wasmIntegrity.json ./src/zk/wasmIntegrity.json
ENV SNS_PREBUILT_WASM=1
RUN npm run build

# ==============================================================================
# Stage 3: Build Self-Contained Blind Zero-Knowledge Go Server Binary
# ==============================================================================
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS go-builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV GOTOOLCHAIN=auto \
    CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=web-builder /src/web/dist ./web/dist
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/sns-server ./cmd/server

# ==============================================================================
# Stage 4: Minimal Non-Root Production Runtime Image
# ==============================================================================
FROM alpine:3.24
LABEL org.opencontainers.image.title="ServerNeedSafe" \
      org.opencontainers.image.description="Zero-Knowledge E2EE Multi-Server SSH/SFTP Management (Server-Root Compromise Resistant)" \
      org.opencontainers.image.source="https://github.com/icaruszezen/ServerNeedSafe"

RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S sns && adduser -S -G sns -u 10001 sns && \
    mkdir -p /data && chown -R sns:sns /data

COPY --from=go-builder /out/sns-server /usr/local/bin/sns-server

USER sns
WORKDIR /data

ENV SNS_ADDR="0.0.0.0:8080" \
    SNS_DATA_DIR="/data" \
    SNS_SESSION_TTL="8h"

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/sns-server"]

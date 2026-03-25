# Multi-stage build for objects-node.
# Build context must be the repository root:
#   docker build -f docker/node.Dockerfile -t objects-node .

# --- Builder stage ---
FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release -p objects-node \
    && strip target/release/objects-node

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/objects-node /usr/local/bin/objects-node

ENV OBJECTS_API_BIND=0.0.0.0
ENV OBJECTS_DATA_DIR=/data

VOLUME /data

# 3420 = HTTP API, 7824/udp = QUIC transport
EXPOSE 3420 7824/udp

HEALTHCHECK --interval=5s --timeout=3s --start-period=90s --retries=3 \
  CMD curl -sf http://localhost:3420/health || exit 1

ENTRYPOINT ["objects-node"]

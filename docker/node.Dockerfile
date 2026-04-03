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

RUN cargo build --release -p objects-node -p objects-health \
    && strip target/release/objects-node \
    && strip target/release/objects-health

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/objects-node /usr/local/bin/objects-node
COPY --from=builder /src/target/release/objects-health /usr/local/bin/objects-health

ENV OBJECTS_DATA_DIR=/data

VOLUME /data

# 7824/udp = QUIC transport (irpc + sync)
EXPOSE 7824/udp

# Health check via irpc probe (same pattern as grpc-health-probe)
HEALTHCHECK --interval=10s --timeout=5s --start-period=90s --retries=3 \
  CMD objects-health || exit 1

ENTRYPOINT ["objects-node"]

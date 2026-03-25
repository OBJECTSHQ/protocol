# Multi-stage build for objects-registry.
# Build context: workspace root (run with -f docker/registry.Dockerfile .)

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY bins bins
COPY proto proto

# sqlx::migrate!() embeds migrations at compile time
RUN cargo build --release -p objects-registry

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/objects-registry /usr/local/bin/objects-registry

ENV DATABASE_URL=sqlite:///data/registry.db
ENV RUST_LOG=objects_registry=info

VOLUME /data
EXPOSE 8080

CMD ["objects-registry"]

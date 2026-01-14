# OBJECTS Protocol

Design engineering protocol for modern craftspeople.

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/OBJECTSHQ/protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/OBJECTSHQ/protocol/actions)

## What is OBJECTS?

OBJECTS is an API for building design apps with identity and sync built in. Developers get a network of users and their data through simple API calls. The protocol handles discovery, connections, and sync regardless of NAT, firewalls, or network topology.

Data is stored locally and synced peer-to-peer over QUIC with automatic hole-punching and relay fallback. Identity and data belong to users, not apps.

## Capabilities

- **Identity** — Passkey and wallet-based identities with human-readable handles
- **Sync** — Content-addressed blob transfer with BLAKE3 verification
- **Metadata** — Replicated key-value store with set reconciliation
- **Offline-first** — Work independently, sync when connected
- **End-to-end Encrypted** — All data and communications encrypted by default

## Getting Started

```bash
# Clone and build
git clone https://github.com/objectshq/protocol
cd protocol
cargo build --workspace

# Run tests
cargo test --workspace

# Run the CLI
cargo run -p objects-cli -- --help
```

## Repository Structure

```
crates/
├── objects-identity   # Identity ID derivation, signatures, handle validation
├── objects-data       # Asset, Project, Reference types
├── objects-transport  # Iroh wrapper, ALPN config, peer discovery
└── objects-sync       # Blob + metadata sync

bins/
├── objects-cli        # CLI tool
├── objects-node       # Node daemon
└── objects-registry   # Identity registry service
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

# OBJECTS Protocol

Design engineering protocol for modern craftspeople.

[![Docs](https://img.shields.io/badge/read%20the%20docs-red?logo=bookstack&logoColor=white)](https://docs.objects.foundation)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-2024%20edition-orange?logo=rust)](https://www.rust-lang.org)
[![CI](https://github.com/OBJECTSHQ/protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OBJECTSHQ/protocol/actions/workflows/ci.yml)
[![Chat](https://img.shields.io/badge/convos-join%20the%20chat-lightgrey?logo=chatwoot&logoColor=white)](https://popup.convos.org/v2?i=CoICCj8BvlZwfPJmGJ7SWjGWHg1-z2hw4SWQSoJUHu_vqdniVG9n-FkAULKGxMx7y_ptFfeo8uomGsZtVH-9FdwpTcsSIBdXr9yNAWiXrNMdpR9tCP-JAJWwEAJ7nl7K3spYJV0XGgp5SFJXb0poZWs4IgdPQkpFQ1RTKgAyhQFodHRwczovL2NvbnZvcy1hc3NldHMtY29udm9zLW90ci1wcm9kLTIwMjUwODI2MTY0MjA4NDA5ODAwMDAwMDE5LnMzLnVzLWVhc3QtMi5hbWF6b25hd3MuY29tL2Q3YTFm*YTE4LTM5MmEtNDMwYS1hNGEwLWY0ODUyNTA3ZGJmYy5qcGVnEkEuzQ9ibSJX53hppf9zPGU10FTNaWezxdt0UflTRgFDjiYZmXHFn9K8XqmR0nLn_I-C-aFtOCuDWkNNp15eQXVPAQ)
[![Follow on Bluesky](https://img.shields.io/badge/bluesky-@objects.app-blue?logo=bluesky)](https://bsky.app/profile/objects.app)
[![Follow on X](https://img.shields.io/badge/@OBJECTS____-black?logo=x)](https://x.com/OBJECTS____)

## What is OBJECTS?

OBJECTS is a protocol for building physical design apps with identity and sync built in. Developers get a network of users and their data through simple API calls. The protocol handles discovery, connections, and sync regardless of NAT, firewalls, or network topology.

Data is stored locally and synced peer-to-peer over QUIC with automatic hole-punching and relay fallback. Identity and data belong to users, not apps.

## Capabilities

- **Identity** — Passkey and wallet-based identities with human-readable handles
- **Sync** — Content-addressed blob transfer with BLAKE3 verification
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
├── objects-identity    # Identity ID derivation, signatures, handle validation
├── objects-data        # Asset, Project, Reference types
├── objects-transport   # Iroh wrapper, ALPN config, peer discovery
├── objects-sync        # Blob + metadata sync
└── objects-test-utils  # Shared test utilities and fixtures

bins/
├── objects-cli         # CLI tool
├── objects-node        # Node daemon
└── objects-registry    # Identity registry service

proto/
└── objects/            # Protobuf definitions (identity/v1, data/v1)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines. Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

[Report a Bug](https://github.com/OBJECTSHQ/protocol/issues/new?template=bug_report.yml) · [Request a Feature](https://github.com/OBJECTSHQ/protocol/issues/new?template=feature_request.yml) · [Open a Pull Request](https://github.com/OBJECTSHQ/protocol/compare)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE) at your option.

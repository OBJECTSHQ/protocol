# AGENTS.md

Instructions for AI coding agents working on the OBJECTS Protocol.

## Project Overview

OBJECTS Protocol is a decentralized identity and data sync system for design engineering. Rust monorepo using Cargo workspaces, built on Iroh for P2P networking.

**Stack:** Rust 2021 edition, Iroh 0.33, Protocol Buffers (prost), Tokio async runtime, PostgreSQL (registry only)

**Network:** ALPN `/objects/0.1`, Discovery topic `/objects/devnet/0.1/discovery`, Relay `https://relay.objects.network`

## Commands

```bash
# Build
cargo build --workspace
cargo build -p objects-identity        # Single crate

# Test
cargo test --workspace
cargo test -p objects-identity          # Single crate
cargo test identity_derivation          # Single test

# Lint
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check

# Generate protobufs
cargo build -p objects-identity --features codegen

# Run binaries
cargo run -p objects-cli -- identity create
cargo run -p objects-node
cargo run -p objects-registry
```

## Architecture

```
crates/
├── objects-identity/    # Identity ID derivation, signatures, handle validation
├── objects-transport/   # Iroh wrapper, ALPN config, peer discovery
├── objects-sync/        # Blob + metadata sync (wraps iroh-blobs, iroh-docs)
└── objects-data/        # Asset, Project, Reference types, SignedAsset

bins/
├── objects-cli/         # CLI tool for all operations
├── objects-node/        # Node daemon (transport + sync)
└── objects-registry/    # Centralized registry service (REST + gRPC)

proto/
└── objects/             # Protobuf definitions (identity/v1, data/v1)
```

**Dependency order:** identity → data → transport → sync → node/cli

## Identity Protocol (RFC-001)

Identity ID derivation:
```
identity_id = "obj_" || base58(truncate(sha256(signer_public_key || nonce), 15))
```

- `signer_public_key`: 33 bytes, compressed SEC1 format
- `nonce`: 8 bytes, cryptographically random
- Result: exactly 24 characters (`obj_` + 20 base58)

**Test vector:**
```
Input:
  signer_public_key: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
  nonce: 0102030405060708
Output:
  identity_id: obj_5KJvsngHeMpm88rD
```

**Handle rules:** 1-30 chars, lowercase alphanumeric + underscore + period, no leading `_` or `.`, no trailing `.`, no consecutive `..`

**Signer types:** PASSKEY (secp256r1/P-256), WALLET (secp256k1 + EIP-712)

## SignedAsset Verification

SignedAsset must include nonce for author_id derivation verification:

```rust
pub struct SignedAsset {
    pub asset: Asset,
    pub signature: Signature,
    pub nonce: [u8; 8],  // Required for author_id verification
}
```

Verification steps:
1. Verify signature over message using signer public key
2. Derive identity_id from signature.public_key + nonce
3. Confirm derived ID matches asset.author_id

## Storage Conventions

Entry key format for Sync layer:
```
/project                    → Project metadata
/assets/{id}                → Asset record
/refs/{id}                  → Reference record
```

## Boundaries

**Always:**
- Verify signatures locally (no registry dependency for asset verification)
- Use test vectors from RFC-001 Appendix B for identity tests
- Include nonce in SignedAsset for author_id derivation
- Use BLAKE3 for content hashes, SHA-256 for identity derivation

**Ask first:**
- Adding new signer types beyond PASSKEY/WALLET
- Modifying wire formats (Protocol Buffers schemas)
- Changes to network parameters (ALPN, discovery topic)

**Never:**
- Skip signature verification on entries or announcements
- Store private keys in logs or error messages
- Make registry required for local asset verification
- Use mainnet discovery topic (`/objects/mainnet/...`) - we're on devnet

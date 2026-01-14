# AGENTS.md

Instructions for AI coding agents working on the OBJECTS Protocol.

## Project Overview

OBJECTS Protocol is a decentralized identity and data sync system for design engineering. Rust monorepo using Cargo workspaces, built on Iroh for P2P networking.

**Stack:** Rust 2024 edition, Iroh 0.95, Protocol Buffers (prost), Tokio async runtime, PostgreSQL (registry only)

**Network:** ALPN `/objects/0.1`, Discovery topic `/objects/devnet/0.1/discovery`, Relay `https://relay.objects.foundation`

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
cargo fmt --all -- --check              # Check formatting
cargo fmt --all                          # Fix formatting

# Generate protobufs
cargo build -p objects-identity --features codegen

# Run binaries
cargo run -p objects-cli -- identity create
cargo run -p objects-node
cargo run -p objects-registry

# Dev tools (install with: cargo install <tool>)
cargo nextest run                       # Fast parallel test runner
cargo watch -x check -x test            # Auto-rebuild on changes
cargo machete                           # Find unused dependencies
cargo audit                             # Security vulnerability scan
cargo expand                            # Debug macro expansions
cargo deny check                        # License/dependency policy
cargo tarpaulin                         # Code coverage
cargo upgrade                           # Update Cargo.toml versions (cargo-edit)
```

## Code Quality & Formatting

**Always format code before committing:**

```bash
cargo fmt --all
git add -u
git commit -m "your message"
```

**Recommended setup:**
- Configure your editor to format on save
- Optional: Set up a pre-commit git hook to enforce formatting

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
- Result: 23-25 characters (`obj_` + 19-21 base58)

**Test vector:**
```
Input:
  signer_public_key: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
  nonce: 0102030405060708
Derivation:
  sha256: 3a26513646a95b6cefac3cbe0a6b8053401956aaaa4c374e1f83521be5ab0a1f
  truncated: 3a26513646a95b6cefac3cbe0a6b80
  base58: 2dMiYc8RhnYkorPc5pVh9
Output:
  identity_id: obj_2dMiYc8RhnYkorPc5pVh9
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

## Dependencies

**Core Principle:** Always prefer battle-tested, widely-adopted libraries over custom implementations. This applies to ALL aspects of the codebase: cryptography, networking, testing, data structures, API frameworks, etc.

### Battle-Tested Libraries

| Purpose | Library | Notes |
|---------|---------|-------|
| Hex encoding | `hex` | Never roll custom hex |
| Ethereum/EIP-191 | `alloy-primitives` | Replaces deprecated ethers-rs |
| WebAuthn/Passkey | `webauthn-rs-core` | Security audited by SUSE |
| P-256 ECDSA | `p256` | RustCrypto, constant-time |
| secp256k1 | `k256` | RustCrypto, constant-time |
| Random bytes | `rand` with `OsRng` | OS-provided entropy |
| Hashing | `sha2`, `blake3` | Standard implementations |
| P2P networking | `iroh` | Built by n0, handles Ed25519 crypto |
| REST API testing | `tower::ServiceExt::oneshot()` | Official Axum pattern |

### Finding Battle-Tested Solutions

When adding new functionality or facing implementation choices:

1. **Use Context7 to research:** Query for latest documentation and best practices
   - Example: "How to test Axum REST APIs 2025"
   - Example: "Latest alloy.rs EIP-191 signature verification"

2. **Prefer official recommendations:** Follow patterns from official docs and examples
   - Axum testing → Use `tower::ServiceExt::oneshot()`
   - Iroh networking → Use their crypto primitives, don't wrap them

3. **Verify with ecosystem:** Check if a library is:
   - Actively maintained (recent commits, releases)
   - Widely adopted (used by major projects)
   - Security audited (when relevant)
   - Well documented (official docs, examples)

4. **When in doubt, ask:** Use the general-purpose agent to research before implementing

### Dependency Rules

- **Never implement cryptographic primitives manually**
- **Never roll custom implementations** of well-solved problems (hex encoding, base64, etc.)
- **Always check for CVEs** before adding new dependencies (`cargo audit`)
- **Prefer libraries with security audits** for auth/crypto/networking
- **Pin major versions** in workspace dependencies
- **Use Context7** to ensure you're using the latest APIs and best practices

## Agent Execution

**Parallel execution:** When multiple independent operations are needed, execute them in parallel using multiple tool calls in a single message. Examples:
- Reading multiple files simultaneously
- Running independent searches across different areas
- Building/testing multiple crates at once

**Sequential execution:** Chain dependent operations with `&&`:
```bash
cargo build --workspace && cargo test --workspace && cargo clippy --workspace
```

**Use subagents for:**
- Exploring unfamiliar parts of the codebase (`Explore` agent)
- Planning complex multi-step implementations (`Plan` agent)
- Code review before commits (`code-reviewer` agent)

## Boundaries

**Always:**
- Verify signatures locally (no registry dependency for asset verification)
- Use test vectors from RFC-001 Appendix B for identity tests
- Include nonce in SignedAsset for author_id derivation
- Use BLAKE3 for content hashes, SHA-256 for identity derivation
- Use well-tested libraries for cryptographic operations

**Ask first:**
- Adding new signer types beyond PASSKEY/WALLET
- Modifying wire formats (Protocol Buffers schemas)
- Changes to network parameters (ALPN, discovery topic)

**Never:**
- Skip signature verification on entries or announcements
- Store private keys in logs or error messages
- Make registry required for local asset verification
- Use mainnet discovery topic (`/objects/mainnet/...`) - we're on devnet

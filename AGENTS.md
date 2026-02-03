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

## Version Control

We use [Jujutsu](https://github.com/martinvonz/jj) (jj) for version control with Git colocated mode.

**Documentation:**
- **Overview & Quick Start:** [.claude/skills/jujutsu/SKILL.md](.claude/skills/jujutsu/SKILL.md)
- **Workflows & Patterns:** [.claude/skills/jujutsu/workflows.md](.claude/skills/jujutsu/workflows.md) - Complete workflows for commits, PRs, stacked PRs with jj-spr, rebasing, and conflict resolution
- **Command Reference:** [.claude/skills/jujutsu/commands-reference.md](.claude/skills/jujutsu/commands-reference.md) - Detailed command documentation
- **Revset Syntax:** [.claude/skills/jujutsu/revsets.md](.claude/skills/jujutsu/revsets.md) - Query language for selecting commits

**Key workflows:**
- Creating stacked PRs: See workflows.md § "Using jj-spr for Stacked PRs"
- Handling review feedback: See workflows.md § "Handling Review Feedback"
- Landing PRs in order: See workflows.md § "Landing PRs (In Order)"
- Continuing work on unmerged stacks: Follow Meta/Google pattern in workflows.md

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

## Dependencies

**Core Principle:** Always prefer battle-tested, widely-adopted libraries over custom implementations. This applies to ALL aspects of the codebase: cryptography, networking, testing, data structures, API frameworks, etc.

### Battle-Tested Libraries

| Purpose | Library | Notes |
|---------|---------|-------|
| Hex encoding | `hex` | Never roll custom hex |
| Ethereum/EIP-191 | `alloy-primitives` | Replaces deprecated ethers-rs |
| P-256 ECDSA (WebAuthn) | `p256` | RustCrypto, audited by zkSecurity 2025 |
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

## API Design Patterns

### Encoding Standards

**Default encoding for wire formats (CLI ↔ Node ↔ Registry):**
- **Base64** is the standard for binary data over JSON APIs
  - Signatures, public keys, nonces, authenticator data, client data JSON
  - Use `base64::engine::general_purpose::STANDARD` from workspace dependency
- **Hex** is used for display/logging only
  - Identity IDs, content hashes (for human readability)
  - Never use hex in API request/response bodies

**Example:**
```rust
// Wire format: base64
let public_key_b64 = base64::Engine::encode(
    &base64::engine::general_purpose::STANDARD,
    &public_key_bytes
);

// Display format: hex
let identity_id_hex = hex::encode(&identity_id_bytes);
```

### Accessor Methods for Enums

**Always use accessor methods instead of pattern matching** to extract data from public enum types. This maintains encapsulation and provides a stable API.

**Good:**
```rust
// objects-identity/src/signature.rs
impl Signature {
    pub fn signature_bytes(&self) -> &[u8] { ... }
    pub fn public_key_bytes(&self) -> Option<&[u8]> { ... }
    pub fn authenticator_data(&self) -> Option<&[u8]> { ... }
    pub fn client_data_json(&self) -> Option<&[u8]> { ... }
}

// Usage in CLI
let sig_b64 = base64::encode(signature.signature_bytes());
let pk_b64 = signature.public_key_bytes()
    .map(|pk| base64::encode(pk));
```

**Bad:**
```rust
// Exposing internal structure via pattern matching
match signature {
    Signature::Passkey { signature, public_key, .. } => { ... }
}
```

### Type Consistency Across Layers

**CLI, Node, and Registry must use identical types for API contracts.** When the registry defines a request/response type, the node and CLI must match exactly.

**Example:** The `SignatureData` type must be identical in:
- `bins/objects-cli/src/types.rs`
- `bins/objects-node/src/api/client.rs`
- `bins/objects-registry/src/api/rest/types.rs` (as `SignatureRequest`)

This ensures:
- Serialization compatibility
- No translation errors at layer boundaries
- Consistent field naming and encoding

When updating signature formats or API contracts:
1. Update registry types first (source of truth)
2. Update node client types to match
3. Update CLI types to match
4. Rebuild all three layers together

## Test Utilities

Use shared test utilities from `objects-test-utils` instead of duplicating helpers.

```rust
use objects_test_utils::{crypto, identity, data};

#[test]
fn my_test() {
    let id = identity::test_identity_id();  // RFC-001 canonical vector
    let bundle = data::signed_asset_passkey("asset-123");
    assert!(bundle.signed_asset.verify().is_ok());
}
```

**Available modules:**
- `crypto` - Keypairs, nonces, encryption keys, deterministic test data
- `time` - Timestamps and time utilities
- `identity` - Identity factories and RFC-001 test vectors
- `data` - Asset, Project, Reference, SignedAsset factories
- `transport` - Endpoint and network config factories
- `sync` - SyncEngine utilities

## Test Patterns

**Cryptographic test data:**
- Use proper encoding patterns for cryptographic data (hashes, challenges, keys)
- Generate test data using `crypto::deterministic_bytes()` with `hex::encode()`, not string literals
- Test data should mirror production data flow: bytes → encoding

```rust
// Good: Mirrors production (BLAKE3 outputs bytes, then hex-encoded)
let content_hash = hex::encode(crypto::deterministic_bytes(42)); // 32 bytes → 64 hex chars

// Bad: String literal doesn't reflect actual data flow
let content_hash = "deadbeef".repeat(8);
```

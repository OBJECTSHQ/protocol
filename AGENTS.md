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
/jj:commit "your message"
```

**Formatting is automatic:**
- Code is formatted on save in most editors
- Use `cargo fmt --all` before commits to ensure consistency
- Jujutsu hooks automatically track file changes

## Version Control (Jujutsu)

**This project uses Jujutsu (jj)** for version control with autonomous commit stacking and curation.

**Available commands:**
```bash
# Commit workflow
/jj:commit                          # Auto-generate message from changed files
/jj:commit "feat: add user auth"    # Stack commit with custom message

# Curation
/jj:squash                          # Merge current commit into parent
/jj:squash abc123                   # Merge specific revision
/jj:split test                      # Split tests into separate commit
/jj:split docs                      # Split documentation
/jj:split "*.md"                    # Split by glob pattern

# Pull requests
jj spr diff                         # Create or update PR from current commit
jj spr list                         # List open PRs and review status
jj spr land                         # Merge PR after approval and clean up
jj spr amend                        # Update commit message from GitHub PR
jj spr close                        # Close PR without merging

# Maintenance
/jj:cleanup                         # Remove empty workspaces

# Manual operations (when needed)
jj log                              # View commit history
jj diff                             # See current changes
jj undo                             # Undo last operation
```

**Workflow philosophy:**
1. **Implementation phase:** Make messy commits frequently as you work (`/jj:commit`)
2. **Curation phase:** Clean up before review using `/jj:split` and `/jj:squash`
3. **PR submission:** Submit curated commits with `jj spr diff`
4. **Everything is undoable:** Use `jj undo` to reverse any operation

**When agents should commit:**
- After implementing a logical unit of work (even if messy)
- After adding tests for a feature
- After fixing a bug or adding documentation
- Use `/jj:commit` without message for auto-generated commit messages

**When agents should curate:**
- Before requesting code review
- When commits mix concerns (implementation + tests + docs)
- Use `/jj:split test` to separate tests from implementation
- Use `/jj:squash` to merge WIP/fixup commits

**When agents should create PRs:**
- After curating commits into clean, focused history
- When a feature/fix is complete and ready for review
- **CRITICAL:** Ensure commit has a description before running `jj spr diff`
  - Undescribed commits cause `jj spr diff` to create PRs from the parent commit
  - Use `/jj:commit "message"` or `jj describe -m "message"` first
- Commit message becomes PR title/description automatically
- After PR approval, use `jj spr land` to merge and clean up

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
- Use test utilities from `objects-test-utils` for canonical test vectors
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

## Test Utilities

Use shared test utilities from `objects-test-utils` instead of duplicating helpers.

```rust
use objects_test_utils::{crypto, identity, data};

#[test]
fn my_test() {
    let id = identity::test_identity_id();  // Canonical test vector
    let bundle = data::signed_asset_passkey("asset-123");
    assert!(bundle.signed_asset.verify().is_ok());
}
```

**Available modules:**
- `crypto` - Keypairs, nonces, encryption keys, deterministic test data
- `time` - Timestamps and time utilities
- `identity` - Identity factories and canonical test vectors
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

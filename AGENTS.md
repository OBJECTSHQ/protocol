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

## Jujutsu Workflow

We use [Jujutsu](https://github.com/martinvonz/jj) (jj) for version control. Jujutsu provides automatic rebasing, easy amendments, and simplified stacked workflows.

### Core Concepts

**Changes vs Branches**: In jj, you work with changes (commits) in a stack. No manual branch creation needed - changes automatically track their parents.

**Automatic Rebasing**: When you edit any change in the stack, all descendants automatically rebase. No manual `git rebase` required.

**Working Copy**: Unlike git, your working copy is automatically committed to the current change as you work.

### Essential Commands

**Creating changes:**
```bash
jj new                                     # Create new change on current
jj new -m "Description"                    # Create with message
jj new main -m "Description"               # Create from specific parent
jj describe                                # Open editor to write description
jj describe -m "New description"           # Set description directly
```

**Viewing state:**
```bash
jj st                                      # Current change status
jj log                                     # Change history tree
jj log -r 'all()' -n 10                   # Last 10 changes
jj show <change-id>                        # Show change details
jj diff                                    # Show current changes
jj diff -r <change-id>                     # Show specific change's diff
```

**Navigating changes:**
```bash
jj edit <change-id>                        # Switch to change (like git checkout)
jj prev                                    # Move to parent change
jj next                                    # Move to child change
jj new                                     # Create new change and move to it
```

**Modifying changes:**
```bash
jj describe -m "Updated message"           # Change description
jj squash                                  # Squash into parent
jj squash --from <id> --into <id>         # Squash specific changes
jj abandon <change-id>                     # Remove change from history
jj rebase -r <change-id> -d <dest-id>     # Move change to new parent
```

**Git integration:**
```bash
jj git fetch                               # Fetch from remote
jj git push                                # Push to remote
jj bookmark create <name>                  # Create bookmark (like git branch)
jj bookmark list                           # List bookmarks
jj bookmark set main -r <change-id>        # Move bookmark to change
```

**Operations (undo/redo):**
```bash
jj op log                                  # View operation history
jj op undo                                 # Undo last operation
jj op restore <operation-id>               # Restore to specific operation
```

### Daily Workflow

**Starting new work:**
```bash
# Update from remote
jj git fetch

# Create new change from main
jj new main -m "feat: Add new feature"

# Make your changes, they auto-commit to working copy
# When ready to stack more work:
jj new -m "feat: Add related feature"
```

**Building a change stack:**
```bash
jj new main -m "feat: Add config types"
# Implement config types
jj new -m "feat: Add config loading"
# Implement config loading
jj new -m "feat: Add state persistence"
# Implement state persistence

# Result: main → config types → config loading → state persistence
```

**Fixing issues in the stack:**
```bash
# Show your stack
jj log

# Jump to change that needs fixes
jj edit <change-id>

# Make fixes (auto-committed to working copy)

# Update description if needed
jj describe -m "Updated description"

# Return to top of stack (descendants auto-rebase)
jj new
```

### Submitting PRs with jj-spr

We use [jj-spr](https://github.com/LucioFranco/jj-spr) to create and manage stacked PRs.

**First-time setup:**
```bash
jj spr init                                # Interactive setup (run once per repo)
```

**Submitting a stack of PRs:**
```bash
# From the top of your stack, submit all changes at once
jj edit <top-change-id>
jj spr diff --all

# This creates one PR per change, properly stacked
# PRs auto-generated with spr/* branch names
```

**What jj-spr does automatically:**
- Creates remote branches with `spr/username/` prefix
- Opens GitHub PRs for each change in the stack
- Sets up PR dependencies (each PR based on the previous)
- Tracks PRs by change ID in commit messages

**Updating PRs after amendments:**
```bash
# 1. Edit the change that needs updates
jj edit <change-id>

# 2. Make your changes (auto-committed to working copy)

# 3. Update the PR by pushing to its spr/* branch
#    First, track the remote branch if not already tracked
jj bookmark track spr/username/description --remote=origin

#    Then point it to your updated change and push
jj bookmark set spr/username/description -r <change-id> --allow-backwards
jj git push --bookmark spr/username/description

# Descendants automatically rebase - no manual work needed
```

**Key principles:**
- Don't manually create bookmarks/branches - jj-spr handles this
- Don't run `jj spr` again after initial submission - just push bookmark updates
- Change IDs track your work - jj-spr uses these to know which PR to update
- All changes in your working copy are automatically committed

### After PR Merges

```bash
# Fetch latest main
jj git fetch

# Abandon merged change (marks it as integrated)
jj abandon <merged-change-id>

# Your remaining stack automatically rebases onto new main
# Continue working on next changes
```

### Advanced Patterns

**Parallel work on different features:**
```bash
# Current stack: feat/config → feat/state → feat/api
# Want to start new feature from main

jj new main -m "feat: New independent feature"
# Both stacks exist independently
```

**Squashing multiple changes:**
```bash
jj squash --from <child-id> --into <parent-id>
# Descendants auto-rebase onto squashed change
```

**Reordering changes in stack:**
```bash
# Move change B to come before change A
jj rebase -r <change-b-id> -d <parent-of-a-id>
jj rebase -r <change-a-id> -d <change-b-id>
# Rest of stack follows automatically
```

**Creating bookmarks for important points:**
```bash
jj bookmark create feature-name          # Create at current change
jj bookmark create feature-name -r <id>  # Create at specific change
jj new feature-name -m "Next change"     # Create change from bookmark
```

### Quick Reference: Git → Jujutsu

| Git Command | Jujutsu Equivalent |
|-------------|-------------------|
| `git status` | `jj st` |
| `git log --graph` | `jj log` |
| `git checkout -b feat/name` | `jj new -m "Description"` |
| `git checkout feat/name` | `jj edit <change-id>` |
| `git commit -m "message"` | `jj describe -m "message"` |
| `git commit --amend` | (automatic in working copy) |
| `git rebase main` | (automatic when parent changes) |
| `git push origin feat/name` | `jj spr` |
| `git reset --hard HEAD~1` | `jj abandon @` |
| `git reflog` | `jj op log` |

### Tips

- Use `jj log` frequently to visualize your change stack
- Changes auto-commit as you work - no need to manually save
- Edit any change without fear - descendants rebase automatically
- Let jj-spr handle PR creation and updates
- `jj abandon` is safe - recover via `jj op log` and `jj op restore`
- Use descriptive messages with `jj describe -m` - they become PR titles
- `jj st` shows what's changed in your working copy
- Operations are recoverable - `jj op undo` is your friend

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

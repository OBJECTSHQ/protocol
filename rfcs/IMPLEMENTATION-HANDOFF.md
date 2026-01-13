# OBJECTS v0.1 Implementation Handoff

Context and decisions from the RFC review session to bootstrap implementation.

---

## Key Decisions

### Identity & Verification

| Decision | Rationale |
|----------|-----------|
| Local signature verification | Decentralized, works offline, no SPOF |
| Registry is optional lookup | For handle resolution and discovery only |
| No access control in v0.1 | Simplifies model, avoids revocation complexity |
| User = author of own files | Single-user authorship, no permission system |
| Sharing = copying via tickets | Data is copied, not "granted access" - can't revoke |

### Architecture

| Decision | Rationale |
|----------|-----------|
| Monorepo with Cargo workspace | Simpler coordination, atomic changes |
| Private crates (not on crates.io) | Internal use only for v0.1 |
| GCP deployment | Startup credits available, Cloud Run simplifies containers |
| Centralized registry service | For handle uniqueness and discovery |
| Iroh for transport/sync | Battle-tested, handles NAT traversal |

### Network

| Parameter | Value |
|-----------|-------|
| ALPN | `/objects/0.1` |
| Discovery Topic | `/objects/devnet/0.1/discovery` (NOT mainnet) |
| Relay | `https://relay.objects.network` |
| Registry | `https://registry.objects.network` |

---

## Repo Structure to Scaffold

```
objects-protocol/
├── Cargo.toml                    # Workspace root
├── README.md
├── rfcs/                         # Specifications (move from docs repo)
│   ├── RFC-000-overview.md
│   ├── RFC-001-identity.md
│   ├── RFC-002-transport.md
│   ├── RFC-003-sync.md
│   ├── RFC-004-data.md
│   ├── DEVNET-CHECKLIST.md
│   └── IMPLEMENTATION-HANDOFF.md
│
├── crates/
│   ├── objects-identity/         # Identity types, signatures, ID derivation
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── id.rs             # Identity ID derivation
│   │       ├── handle.rs         # Handle validation
│   │       ├── signer.rs         # Passkey/wallet signer types
│   │       ├── signature.rs      # Signature creation/verification
│   │       └── proto.rs          # Generated protobuf types
│   │
│   ├── objects-transport/        # Iroh wrapper, ALPN, discovery
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── endpoint.rs       # Connection management
│   │       ├── discovery.rs      # Gossip announcements
│   │       └── config.rs         # Network parameters
│   │
│   ├── objects-sync/             # Thin wrapper over iroh-blobs/iroh-docs
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── blobs.rs          # Blob sync operations
│   │       ├── docs.rs           # Metadata sync operations
│   │       └── tickets.rs        # Ticket creation/redemption
│   │
│   └── objects-data/             # Asset, Project, Reference, SignedAsset
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── asset.rs
│           ├── project.rs
│           ├── reference.rs
│           ├── signed.rs         # SignedAsset wrapper
│           └── proto.rs          # Generated protobuf types
│
├── bins/
│   ├── objects-cli/              # CLI tool
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       └── commands/
│   │           ├── identity.rs
│   │           ├── project.rs
│   │           ├── asset.rs
│   │           ├── sync.rs
│   │           └── ticket.rs
│   │
│   ├── objects-node/             # Node daemon
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs
│   │
│   └── objects-registry/         # Registry service (REST + gRPC)
│       ├── Cargo.toml
│       ├── Dockerfile
│       └── src/
│           ├── main.rs
│           ├── api/              # REST endpoints
│           ├── grpc/             # gRPC service
│           └── db/               # Postgres operations
│
├── proto/                        # Protobuf definitions
│   ├── objects/
│   │   ├── identity/
│   │   │   └── v1/
│   │   │       └── identity.proto
│   │   └── data/
│   │       └── v1/
│   │           └── data.proto
│   └── buf.yaml                  # Buf configuration
│
└── docker/
    ├── Dockerfile.relay
    ├── Dockerfile.node
    └── docker-compose.yml        # Local development
```

---

## Root Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "crates/*",
    "bins/*",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourorg/objects-protocol"

[workspace.dependencies]
# OBJECTS crates
objects-identity = { path = "crates/objects-identity" }
objects-transport = { path = "crates/objects-transport" }
objects-sync = { path = "crates/objects-sync" }
objects-data = { path = "crates/objects-data" }

# Iroh
iroh = "0.33"
iroh-blobs = "0.33"
iroh-docs = "0.33"
iroh-gossip = "0.33"
iroh-relay = "0.33"

# Crypto
ed25519-dalek = "2"
p256 = "0.13"
blake3 = "1"
sha2 = "0.10"
bs58 = "0.5"

# Async
tokio = { version = "1", features = ["full"] }
futures = "0.3"

# Serialization
prost = "0.13"
prost-types = "0.13"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Web/API
axum = "0.7"
tonic = "0.12"
tower = "0.4"
reqwest = { version = "0.12", features = ["json"] }

# Database
sqlx = { version = "0.8", features = ["postgres", "runtime-tokio"] }

# CLI
clap = { version = "4", features = ["derive"] }

# Error handling
anyhow = "1"
thiserror = "1"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"
```

---

## Implementation Order

### Phase 1: Core Types (Week 1)

1. **objects-identity**
   - Identity ID derivation (test against RFC-001 vectors)
   - Handle validation
   - Signature types (don't need full verification yet)

2. **objects-data**
   - Asset, Project, Reference structs
   - SignedAsset wrapper
   - Protobuf serialization

### Phase 2: Registry (Week 2)

3. **objects-registry**
   - Database schema
   - REST endpoints (Create, Get, Resolve)
   - Signature verification
   - Deploy to GCP Cloud Run

### Phase 3: Transport & Sync (Week 3)

4. **objects-transport**
   - Iroh endpoint wrapper
   - ALPN configuration
   - Discovery announcements

5. **objects-sync**
   - Blob operations
   - Doc/replica operations
   - Ticket handling

### Phase 4: Node & CLI (Week 4)

6. **objects-node**
   - Combine transport + sync
   - Connect to relay
   - Join discovery topic

7. **objects-cli**
   - Basic commands
   - Identity creation flow
   - Project/asset operations

### Phase 5: Integration (Week 5)

8. Deploy bootstrap nodes
9. End-to-end testing
10. Documentation

---

## Critical Implementation Notes

### SignedAsset Verification

The SignedAsset must include the `nonce` so verifiers can confirm author_id derivation:

```rust
pub struct SignedAsset {
    pub asset: Asset,
    pub signature: Signature,
    pub nonce: [u8; 8],  // Required for author_id verification
}

impl SignedAsset {
    pub fn verify(&self) -> Result<(), VerifyError> {
        // 1. Verify signature over message
        let message = format!(
            "OBJECTS Identity Protocol v1\nAction: Sign Asset\nIdentity: {}\nAsset: {}\nTimestamp: {}",
            self.asset.author_id,
            hex::encode(&self.asset.content_hash),
            self.asset.created_at
        );
        self.signature.verify(message.as_bytes())?;

        // 2. Verify author_id derives from pubkey + nonce
        let derived_id = derive_identity_id(&self.signature.public_key, &self.nonce);
        if derived_id != self.asset.author_id {
            return Err(VerifyError::AuthorIdMismatch);
        }

        Ok(())
    }
}
```

### Discovery Topic

Use `/objects/devnet/0.1/discovery` for devnet. RFC-002 has been updated. When ready for mainnet, change to `/objects/mainnet/0.1/discovery`.

### Registry is Optional for Verification

Nodes verify SignedAsset locally. Registry lookups are only for:
- Resolving `@handle` to identity ID
- Displaying identity metadata in UI
- Checking if handle is taken (during creation)

Do NOT require registry for asset acceptance.

### Iroh Relay

You're running your own relay at `relay.objects.network`. The Iroh relay binary is separate from the Iroh library. See: https://github.com/n0-computer/iroh/tree/main/iroh-relay

---

## Test Vectors

From RFC-001 Appendix B - use these for unit tests:

**Identity ID Derivation:**
```
Input:
  signer_public_key: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
  nonce: 0102030405060708

Output:
  identity_id: obj_5KJvsngHeMpm88rD
```

**Handle Validation:**
```
Valid: montez, alice_123, montez.studio, design.co_lab
Invalid: _alice, .alice, alice., alice..bob, Alice, admin
```

---

## Questions to Resolve During Implementation

1. **Passkey integration** - How to get public key from WebAuthn credential in CLI vs browser?
2. **Key storage** - Where does the CLI store the user's private key locally?
3. **Conflict resolution** - When two devices edit the same asset offline, which wins?
4. **Blob garbage collection** - When to delete unreferenced blobs?

These don't block starting - resolve as you encounter them.

---

## Links

- Iroh docs: https://iroh.computer/docs
- Iroh GitHub: https://github.com/n0-computer/iroh
- iroh-relay: https://github.com/n0-computer/iroh/tree/main/iroh-relay
- GCP Cloud Run: https://cloud.google.com/run/docs
- GCP startup credits: https://cloud.google.com/startup

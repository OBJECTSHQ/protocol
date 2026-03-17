# Test Coverage Audit

What our full test suite verifies, organized by developer workflow.

**Total: 230 tests across 6 crates and 3 binaries.**

---

## What's Tested

### Identity Workflow

- Create identity from passkey (P-256/WebAuthn) or wallet (secp256k1/EIP-191)
- RFC-001 ID derivation determinism + canonical test vector
- Handle validation (format, reserved words, length, case)
- Message format correctness for all signed operations
- Vault key derivation (namespace + encryption keys)
- 11 proptest invariants on ID format and handle rules

### Asset Workflow

- Create asset -> sign with passkey or wallet -> verify signature
- Tamper detection (wrong nonce, modified content hash, signature replay)
- Multiple assets from same identity
- JSON serialization roundtrip preserves signature validity
- Storage key generation (`/assets/{id}`, `/refs/{id}`)
- 15 proptest invariants on validation and RFC compliance

### Project Workflow

- Create project from replica ID (RFC-004 derivation)
- Project ID validation (32 hex chars)
- Timestamp ordering invariant (`created_at <= updated_at`)
- Store/retrieve projects in docs replicas
- Multi-asset projects with references between assets
- Cross-project references

### Sharing (Tickets)

- Create blob tickets and doc tickets
- Parse ticket strings back to typed tickets
- CLI: create ticket -> redeem ticket (success + invalid + expired)
- Download from invalid ticket fails gracefully

### Transport (P2P Networking)

- Endpoint creation with defaults, custom key, custom config
- Two endpoints connect via QUIC (StaticProvider + concurrent accept)
- Bidirectional and unidirectional streams
- Multiple concurrent streams on one connection
- Connection close propagation
- Connect to invalid address fails/times out
- ALPN, discovery topic, relay URL constants match RFCs
- 16 proptest invariants on config bounds and determinism

### Sync (Blobs + Docs)

- Add blob from bytes and from file -> read back by hash
- Docs: create replica -> set entry -> get entry -> query by prefix
- Docs: multiple authors same replica, concurrent writes (same + different keys)
- Docs: replica deletion
- Store/retrieve Project and Asset objects in docs
- Two-node harness: independent sync engines, ticket creation
- Sync with unreachable peer doesn't panic

### Node E2E (Full Stack)

- Health, status, identity, peers, projects endpoints
- CORS headers present
- Two nodes discover each other via gossip
- CLI client communicates with node
- Two nodes operate independently
- Registry integration (store + retrieve identities)
- Blob add/retrieve, doc CRUD, ticket creation through nodes

### CLI

- Config init, save/load roundtrip, env var overrides
- Health/status with running node and down node
- Identity create/show (including `@` prefix stripping)
- Project create/list/get
- Asset add/list (including file-not-found)
- Ticket create/redeem (including error cases)

### Registry

- Create identity with passkey and wallet signature verification
- Duplicate handle -> 409 conflict
- Resolve identity by handle
- 10 concurrent creates with same handle -> exactly 1 succeeds
- 10 concurrent creates with same ID -> exactly 1 succeeds
- Concurrent wallet linking -> exactly 1 succeeds

### Encryption

- Catalog entry encrypt -> decrypt roundtrip
- Wrong key detection, tampered ciphertext detection
- Nonce uniqueness (same plaintext -> different ciphertext)

---

## Test Counts by Category

| Category | Count | Purpose |
|----------|-------|---------|
| Identity & Signatures | 31 | RFC-001 compliance, handle validation, message formats, vault derivation |
| Data Types & Storage | 51 | Assets, projects, references, encryption, serialization |
| Transport & Network | 26 | Endpoints, connections, streams, discovery, configuration |
| Sync & Blobs | 22 | Blob operations, docs replicas, tickets, storage |
| CLI Commands | 30 | Config, health, identity, projects, assets, tickets |
| E2E & Integration | 19 | Full stack workflows, multi-node sync, API endpoints |
| Concurrency | 3 | Race conditions, handle conflicts, concurrent writes |
| Test Utils | 15 | Validates crypto, time, identity test fixtures |
| Property-Based | 33 | Invariants, determinism, RFC compliance with proptest |
| **Total** | **230** | |

---

## What's NOT Tested (Gaps)

### Multi-node sync (the big gap)

No test actually syncs data between two nodes. `two_node_sync.rs` creates two engines but only tests single-node operations. The E2E sync tests also only operate on one node at a time. The workflow "Node A creates project -> shares ticket -> Node B redeems ticket -> data appears on Node B" is untested.

### Asset content flow end-to-end

No test goes: upload file -> sign asset -> store in project -> share -> download on other node. The pieces are tested individually but never composed.

### Identity lifecycle across layers

No test goes: CLI `identity create` -> Node forwards to Registry -> Registry verifies signature -> identity persisted -> CLI `identity show` retrieves it. The E2E tests check individual endpoints but not the full round trip.

### Handle changes and wallet linking through the stack

Message formats exist for `change_handle` and `link_wallet`, but no integration test exercises these through Node -> Registry.

### Gossip discovery end-to-end

`test_peer_discovery_between_nodes` exists but the actual "I published my node, you discovered me, now we can sync" flow isn't tested.

### Error recovery

No tests for: node restarts with persisted state, reconnection after disconnect, partial sync recovery, database connection loss handling.

### CLI with real node (not mock)

All CLI integration tests use mock HTTP servers. No test runs the CLI against a real `TestNode`.

### Registry: update and delete operations

Only create and read are tested. No update identity, delete identity, or pagination tests.

# RFC-003: OBJECTS Sync Protocol

```
RFC:           003
Title:         OBJECTS Sync Protocol
Version:       0.1
Status:        Draft
Author:        OBJECTS Protocol Team
Created:       2026-01-10
```

---

## Status of This Memo

This document specifies the OBJECTS Sync Protocol version 0.1, defining how nodes synchronize data across the network. This is a draft specification subject to change.

Distribution of this memo is unlimited.

---

## Abstract

This document defines the OBJECTS Sync Protocol, a system for synchronizing content-addressed data between nodes in the OBJECTS network. The protocol normatively references Iroh for blob transfer and metadata synchronization, introducing OBJECTS-specific patterns for sync discovery and consistency guarantees. Sync operates above the Transport layer (RFC-002) and provides the foundation for the Data layer (RFC-004).

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Overview](#2-protocol-overview)
3. [Blob Sync](#3-blob-sync)
4. [Metadata Sync](#4-metadata-sync)
5. [Sync Discovery](#5-sync-discovery)
6. [Consistency Model](#6-consistency-model)
7. [Operational Requirements](#7-operational-requirements)
8. [Security Considerations](#8-security-considerations)
9. [References](#9-references)
10. [Appendix A: Implementation Notes](#appendix-a-implementation-notes)
11. [Appendix B: Changelog](#appendix-b-changelog)

---

## 1. Introduction

### 1.1. Motivation

Design data exists across multiple devices, collaborators, and applications. Users need their data to move seamlessly between contexts without manual transfer or central coordination. The Sync layer provides the mechanism for nodes to discover, request, and verify data from peers.

### 1.2. Scope

This document specifies:

- Blob synchronization via content-addressed transfer
- Metadata synchronization via set reconciliation
- Sync discovery mechanisms
- Consistency guarantees

This document does NOT specify:

- Data schemas or semantics (see RFC-004: Data)
- Organizational primitives (projects, collections)
- Application-level conflict resolution UI
- Identity verification for authorship (see RFC-001: Identity)

### 1.3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

| Term | Definition |
|------|------------|
| Blob | An opaque sequence of bytes, identified by its BLAKE3 hash |
| Entry | A metadata record associating a key with a blob reference |
| Replica | A local copy of a set of entries that syncs with peers |
| Sync | The process of reconciling data between nodes |
| Hash | A BLAKE3 digest (32 bytes) serving as content address |
| Verified Streaming | Incremental verification of blob content during transfer |

---

## 2. Protocol Overview

### 2.1. Design Goals

| Goal | Description |
|------|-------------|
| Content-Addressed | All data identified by cryptographic hash |
| Incremental | Transfer only what's missing, verify as you go |
| Offline-First | Nodes operate independently, sync when connected |
| Transport-Agnostic | Works over any RFC-002 compliant transport |
| Consistency | Eventual consistency with deterministic merge |

### 2.2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│              (Apps that consume OBJECTS data)                │
├─────────────────────────────────────────────────────────────┤
│                    DATA LAYER (RFC-004)                      │
│              (Schemas, types, organization)                  │
├─────────────────────────────────────────────────────────────┤
│                    SYNC LAYER (this RFC)                     │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Blob Sync   │  │ Metadata Sync│  │  Sync Discovery  │   │
│  │              │  │              │  │                  │   │
│  │  - Transfer  │  │  - Entries   │  │  - Explicit      │   │
│  │  - Verify    │  │  - Reconcile │  │  - Tickets       │   │
│  │  - Resume    │  │  - Merge     │  │                  │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                    IROH (Normative Reference)                │
│                    iroh-blobs, iroh-docs                     │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER (RFC-002)                 │
│              QUIC connections, relay, discovery              │
└─────────────────────────────────────────────────────────────┘
```

### 2.3. Sync Primitives

The protocol defines two complementary sync mechanisms:

| Mechanism | Purpose | Iroh Primitive |
|-----------|---------|----------------|
| Blob Sync | Transfer binary content | iroh-blobs |
| Metadata Sync | Reconcile structured entries | iroh-docs |

Blob Sync handles raw data transfer with verification. Metadata Sync handles the index of what data exists and where it lives.

---

## 3. Blob Sync

Blob Sync transfers content-addressed binary data between nodes.

**Source:** iroh-blobs (normative reference)

This section describes how OBJECTS uses iroh-blobs. Wire formats and protocol details are defined by iroh-blobs; this section is informative.

### 3.1. Content Addressing

All blobs are identified by their BLAKE3 hash.

#### 3.1.1. Hash Format

```
hash = BLAKE3(content)
```

| Property | Value |
|----------|-------|
| Algorithm | BLAKE3 |
| Output size | 32 bytes (256 bits) |
| Encoding | Hex (64 characters) or binary |

#### 3.1.2. Properties

- **Deterministic**: Same content always produces same hash
- **Collision-resistant**: Computationally infeasible to find two inputs with same hash
- **Incremental**: BLAKE3 supports verified streaming

### 3.2. Verified Streaming

Blob transfer uses BLAKE3 verified streaming with BAO (BLAKE3 Authenticated Output).

#### 3.2.1. Chunk Structure

| Parameter | Value |
|-----------|-------|
| Chunk size | 1024 bytes |
| Chunk group size | 16 KiB (16 chunks) |
| Verification granularity | Per chunk group |

#### 3.2.2. Transfer Semantics

Nodes requesting a blob:

1. MUST specify the expected hash
2. MUST verify content incrementally during transfer
3. MUST reject content that fails verification within 16 KiB
4. MAY request byte ranges for partial/resumed transfer

Nodes providing a blob:

1. MUST provide content matching the requested hash
2. MUST support range requests for resumable transfer
3. SHOULD provide outboard data (hash tree) for verification

### 3.3. Blob Operations

#### 3.3.1. Request

A node requests a blob by hash:

```
BlobRequest {
    hash: BLAKE3Hash,       // 32 bytes
    ranges: Option<Ranges>, // Optional byte ranges
}
```

#### 3.3.2. Response

A node responds with verified streaming data:

```
BlobResponse {
    hash: BLAKE3Hash,       // Confirms requested hash
    size: u64,              // Total content size
    data: Stream<Chunk>,    // Verified chunk stream
}
```

### 3.4. Collections

A Collection is an ordered list of blobs treated as a unit.

**Source:** iroh-blobs HashSeq (normative reference)

#### 3.4.1. Structure

```
Collection = [Link, Link, Link, ...]

Where:
  Link = BLAKE3Hash (32 bytes)
```

#### 3.4.2. Use Cases

- Multi-file transfers (e.g., CAD assembly with parts)
- Atomic updates (all-or-nothing sync)
- Chunked large files

---

## 4. Metadata Sync

Metadata Sync reconciles structured entries between nodes.

**Source:** iroh-docs (normative reference)

This section describes how OBJECTS uses iroh-docs. Wire formats and protocol details are defined by iroh-docs; this section is informative.

### 4.1. Entry Model

An Entry associates a key with a blob reference.

#### 4.1.1. Entry Structure

| Field | Type | Description |
|-------|------|-------------|
| key | bytes | Application-defined key (path, ID, etc.) |
| author | Ed25519PublicKey | Signing key of entry creator |
| hash | BLAKE3Hash | Reference to blob content |
| size | u64 | Size of referenced blob |
| timestamp | u64 | Unix timestamp (microseconds) |

#### 4.1.2. Entry Identity

Entries are uniquely identified by the tuple:

```
(replica_id, author, key)
```

Multiple authors MAY write to the same key. Each author's entry is preserved independently.

### 4.2. Replica

A Replica is a local collection of entries that syncs with peers.

#### 4.2.1. Replica Identity

```
ReplicaId = Ed25519PublicKey (32 bytes)
```

The ReplicaId is derived from a keypair. Possession of the private key grants write capability.

#### 4.2.2. Capabilities

| Capability | Grants |
|------------|--------|
| Write | Create/update entries, requires private key |
| Read | Fetch and verify entries |
| Sync | Participate in reconciliation |

### 4.3. Set Reconciliation

Nodes sync entries using range-based set reconciliation.

**Source:** Aljoscha Meyer, "Range-Based Set Reconciliation" (arXiv:2212.13567)

#### 4.3.1. Algorithm Overview

1. Nodes exchange fingerprints of entry ranges
2. Differing ranges are recursively subdivided
3. Process continues until missing entries identified
4. Missing entries transferred directly

#### 4.3.2. Properties

- **Efficient**: Transfer proportional to differences, not total size
- **Symmetric**: Either node can initiate
- **Resumable**: Interrupted sync continues from last state

### 4.4. Entry Operations

#### 4.4.1. Write

A node creates or updates an entry:

```
EntryWrite {
    key: bytes,
    hash: BLAKE3Hash,
    size: u64,
    signature: Ed25519Signature,
}
```

Entries MUST be signed by the author's private key.

#### 4.4.2. Query

A node queries entries by:

- Key prefix (e.g., all entries under `/parts/`)
- Author (entries by specific author)
- Time range (entries modified within window)

---

## 5. Sync Discovery

Sync Discovery enables nodes to find and initiate data synchronization with peers.

### 5.1. Relationship to Transport Discovery

RFC-002 Transport defines **peer discovery** — how nodes find other nodes in the network. Sync Discovery is distinct:

| Concern | Layer | Purpose |
|---------|-------|---------|
| Peer discovery | Transport (RFC-002) | Find nodes to connect to |
| Sync discovery | Sync (this RFC) | Find data to synchronize |

A node may be reachable (transport) but have no relevant data (sync). Sync Discovery bridges this gap.

### 5.2. Discovery Mechanisms

| Mechanism | Use Case |
|-----------|----------|
| Explicit | Direct request to connected peer |
| Ticket | Share-able token encoding data location |

### 5.3. Explicit Sync

Once connected via RFC-002 Transport, nodes request sync directly:

```
1. Node A connects to Node B (RFC-002)
2. Node A sends SyncRequest for specific replica or blob
3. Nodes perform sync protocol
```

No additional discovery step is required if the initiating node knows what data it wants.

### 5.4. Tickets

A Ticket encodes everything needed to sync specific data.

**Source:** Iroh tickets (normative reference)

Tickets use Iroh's encoding and wire format. This section describes ticket semantics; format details are defined by Iroh.

#### 5.4.1. Blob Ticket

Encodes a content-addressed blob and where to fetch it:

| Field | Type | Description |
|-------|------|-------------|
| hash | BLAKE3Hash | Content hash of blob |
| format | BlobFormat | Raw (single blob) or HashSeq (collection) |
| node_addr | NodeAddr | Peer that has the blob |

#### 5.4.2. Doc Ticket

Encodes a replica and capability to access it:

| Field | Type | Description |
|-------|------|-------------|
| capability | Capability | Read or Write access |
| nodes | Vec&lt;NodeAddr&gt; | Peers that have the replica |

The capability field encodes the replica ID and, for write access, the secret key.

#### 5.4.3. Ticket Encoding

Tickets are serialized using Iroh's encoding:

- **Format:** Base32 string, human-readable prefix
- **Prefix:** `blob` for blob tickets, `doc` for doc tickets
- **Example:** `blobaaaa...` or `docaaaa...`

Tickets are designed for:
- Copy/paste sharing
- QR code encoding
- URL embedding

#### 5.4.4. Ticket Security

| Ticket Type | Contains | Grants |
|-------------|----------|--------|
| Blob ticket | Hash + peer | Read access to specific blob |
| Doc ticket (read) | Replica ID + peer | Read access to all entries |
| Doc ticket (write) | Replica secret + peer | Write access to replica |

Nodes MUST treat write tickets as secrets. Sharing a write ticket grants full write access to the replica.

### 5.5. Vault Discovery Pattern (Private Vaults)

Applications MAY use the User Vault pattern (RFC-004 Section 4.4) for private, decentralized project discovery.

#### 5.5.1. Vault Access Flow (Capability-Based)

**IMPORTANT:** Applications CANNOT derive vault namespace ID themselves. They MUST request vault access from the user's wallet/keyring.

```
1. User authenticates to app (signs challenge with identity signer)
2. App requests vault access from wallet/keyring
3. Wallet derives vault namespace ID from identity secret key (HKDF-SHA256)
4. Wallet creates read-only DocTicket:
   - capability: Capability::Read(namespace_id)
   - nodes: user's device addresses
5. Wallet returns DocTicket to app
6. App syncs vault replica using ticket
7. App queries encrypted catalog entries: /catalog/*
8. App requests catalog decryption key from wallet
9. Wallet returns catalog_encryption_key (derived with namespace)
10. App decrypts entries, discovers project replica IDs
11. App syncs each discovered project replica
```

**Capability Ticket Format:**

Wallet creates read-only ticket for vault access:

```rust
DocTicket {
    capability: Capability::Read(namespace_id),  // Derived from signing key
    nodes: Vec<NodeAddr>,  // User's device addresses
}
```

#### 5.5.2. Cold Start Discovery

On first app launch, vault replica may not be in local sync cache. Applications SHOULD:

1. Request vault ticket from wallet (wallet derives namespace ID from signing key)
2. Query bootstrap nodes for vault availability using provided namespace ID
3. Sync vault via DocTicket from wallet
4. Request decryption key from wallet
5. Cache decrypted catalog locally for future app launches

**Privacy Note:** Without the identity signing key, vault namespace ID cannot be computed. Apps depend entirely on wallet to provide access.

#### 5.5.3. Vault Availability and Hosting

Vault replicas MAY be hosted by:
- User's devices (phones, laptops, tablets) - where wallet/keyring runs
- User's self-hosted nodes
- Foundation-operated seed nodes (optional, for redundancy)
- Third-party vault hosting services (optional, user's choice)

The protocol does not mandate vault hosting location. Vaults sync via standard Iroh docs replication (Section 3).

**Fallback Strategies:**

If vault is unavailable (user offline, no seed nodes):
- Apps SHOULD fall back to explicit project ticket sharing
- Apps SHOULD cache previously discovered projects
- Apps MAY prompt user to enable vault seeding

#### 5.5.4. Implementation Note

This specification normatively references [Iroh](https://docs.iroh.computer/) for blob transfer and docs sync. The protocol is designed such that the Data layer (RFC-004) remains independent of the Sync implementation. Alternative sync layers could implement RFC-003's requirements using different primitives (e.g., IPFS, Willow Protocol, custom P2P) without changing the Data layer schemas or vault derivation algorithm.

---

## 6. Consistency Model

### 6.1. Eventual Consistency

The protocol provides eventual consistency:

> If no new updates are made, all nodes will eventually converge to the same state.

### 6.2. Convergence Guarantees

| Property | Guarantee |
|----------|-----------|
| Delivery | All entries eventually reach all interested nodes |
| Agreement | Nodes with same entries derive same state |
| Availability | Nodes operate independently when disconnected |

### 6.3. Conflict Semantics

When multiple authors write to the same key:

1. All entries are preserved (multi-value)
2. Entries are distinguishable by author
3. Applications MAY implement resolution strategies
4. Protocol does NOT automatically discard entries

#### 6.3.1. Resolution Strategies (Informative)

Applications MAY implement:

| Strategy | Description |
|----------|-------------|
| Last-write-wins | Entry with latest timestamp wins |
| Author-priority | Designated author's entry preferred |
| Merge | Application-specific merge logic |
| Manual | User chooses between versions |

The protocol preserves all entries to enable any strategy.

### 6.4. Ordering

The protocol does NOT guarantee causal ordering. Entries may arrive in any order. Applications requiring ordering MUST implement it at the Data layer.

---

## 7. Operational Requirements

### 7.1. Storage

Nodes MUST:

- Store blobs by content hash
- Store entries with full metadata
- Support queries by key, author, and time range

Nodes SHOULD:

- Deduplicate blobs (same hash stored once)
- Index entries for efficient queries
- Garbage collect unreferenced blobs

### 7.2. Bandwidth

Nodes MUST:

- Support resumable blob transfers
- Implement set reconciliation for entry sync
- Respect peer bandwidth constraints

Nodes SHOULD:

- Batch small transfers
- Prioritize user-requested data
- Implement backpressure for large syncs

### 7.3. Connection Management

Sync operations use connections established via RFC-002 Transport.

| Parameter | Recommendation |
|-----------|----------------|
| Streams per sync | 1-10 concurrent |
| Retry policy | Exponential backoff, max 5 minutes |
| Timeout | 30 seconds for handshake, unlimited for transfer |

---

## 8. Security Considerations

### 8.1. Threat Model

| Threat | Mitigation |
|--------|------------|
| Data tampering | BLAKE3 verification on all blobs |
| Entry forgery | Ed25519 signatures on all entries |
| Replay attacks | Timestamps in entries and announcements |
| Unauthorized write | Capability model (private key required) |
| Data enumeration | Replica ID needed to discover entries |

### 8.2. Content Verification

All blob content is verified against its hash. A node MUST reject:

- Content that does not match requested hash
- Entries with invalid signatures
- Announcements with invalid signatures

### 8.3. Capability Security

Write capability requires possession of replica private key. Nodes MUST:

- Verify entry signatures before accepting
- Never accept unsigned entries
- Protect private keys from exposure

### 8.4. Privacy Considerations

| Aspect | Consideration |
|--------|---------------|
| Content hashes | Public; reveal nothing about content |
| Entry keys | May contain application-specific paths |
| Author keys | Pseudonymous; linkable across entries |
| Sync patterns | Nodes can observe who syncs what |

The protocol does not provide content encryption. Applications requiring confidentiality MUST encrypt at the Data layer.

---

## 9. References

### 9.1. Normative References

| Reference | Title |
|-----------|-------|
| [RFC 2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [IROH-BLOBS] | Iroh Blobs Protocol. https://docs.iroh.computer/protocols/blobs |
| [IROH-DOCS] | Iroh Docs Protocol. https://docs.rs/iroh-docs |
| [IROH-TICKETS] | Iroh Ticket Format. https://docs.rs/iroh-blobs/latest/iroh_blobs/ticket |
| [BLAKE3] | BLAKE3 Cryptographic Hash Function. https://blake3.io |
| [RFC-002] | OBJECTS Transport Protocol Specification |

### 9.2. Informative References

| Reference | Title |
|-----------|-------|
| [MEYER-2022] | Range-Based Set Reconciliation. arXiv:2212.13567 |
| [RFC-001] | OBJECTS Identity Protocol Specification |
| [RFC-004] | OBJECTS Data Protocol Specification (planned) |

---

## Appendix A: Implementation Notes

### A.1. Iroh Dependency

This specification assumes implementations use Iroh or a compatible library.

```rust
use iroh_blobs::{Hash, BlobFormat};
use iroh_docs::{Replica, Entry};

// Fetch a blob
let content = blobs.read_to_bytes(hash).await?;

// Sync a replica
let sync = docs.sync(replica_id, peers).await?;
```

### A.2. Sync Flow Example

```
Node A                                           Node B
   │                                                │
   │──── Connect (RFC-002 Transport) ──────────────►│
   │                                                │
   │──── SyncRequest { replica_id } ───────────────►│
   │                                                │
   │◄─── Set Reconciliation (ranges, fingerprints) ─│
   │                                                │
   │──── Missing entries ──────────────────────────►│
   │◄─── Missing entries ───────────────────────────│
   │                                                │
   │──── BlobRequest { hash } ─────────────────────►│
   │◄─── BlobResponse { verified stream } ──────────│
   │                                                │
   │         Sync complete                          │
```

### A.3. Ticket Usage

Tickets enable out-of-band data sharing:

```rust
use iroh_blobs::ticket::BlobTicket;
use iroh_docs::ticket::DocTicket;

// Create a blob ticket for sharing
let ticket = BlobTicket::new(hash, format, node_addr);
let ticket_string = ticket.to_string(); // "blobaaaa..."

// Parse a received ticket
let ticket: BlobTicket = ticket_string.parse()?;
let content = blobs.download(ticket).await?;
```

Tickets are self-contained — recipients need no prior knowledge of the network to fetch the data.

---

## Appendix B: Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-01-10 | Initial draft |

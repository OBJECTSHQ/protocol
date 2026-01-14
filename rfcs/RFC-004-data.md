# RFC-004: OBJECTS Data Protocol

```
RFC:           004
Title:         OBJECTS Data Protocol
Version:       0.1
Status:        Draft
Author:        OBJECTS Protocol Team
Created:       2026-01-11
```

---

## Status of This Memo

This document specifies the OBJECTS Data Protocol version 0.1, defining the data types, schemas, and organizational primitives for the OBJECTS network. This is a draft specification subject to change.

Distribution of this memo is unlimited.

---

## Abstract

This document defines the OBJECTS Data Protocol, a system for representing and organizing design content. The protocol defines core data types (Asset, Project, Reference) and their wire format (Protocol Buffers). These data structures are defined independently of the underlying sync mechanism, enabling applications to work with design data regardless of how it is stored or transmitted. An appendix describes conventions for persisting these types via the Sync layer (RFC-003).

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Overview](#2-protocol-overview)
3. [Data Types](#3-data-types)
4. [Storage Conventions](#4-storage-conventions)
   - 4.4. [User Vault](#44-user-vault)
5. [Operations](#5-operations)
6. [Versioning](#6-versioning)
7. [Security Considerations](#7-security-considerations)
8. [References](#8-references)
9. [Appendix A: Protocol Buffers Definitions](#appendix-a-protocol-buffers-definitions)
10. [Appendix B: Changelog](#appendix-b-changelog)

---

## 1. Introduction

### 1.1. Motivation

Design engineering applications need a common vocabulary for representing design content. Without shared data types, each application invents its own schemas, preventing interoperability. The Data layer defines this shared vocabulary for physical design: versioned assets, organizational projects, and typed references between them.

The data structures are defined independently of storage or sync mechanisms. This separation enables:

- Applications to work with data in memory, on disk, or over the network
- Alternative sync implementations without changing the data model
- Clear testing and validation of data structures in isolation

### 1.2. Scope

This document specifies:

- Core data types: Asset, Project, Reference
- Wire format using Protocol Buffers
- Semantics and validation rules
- Operations for creating and managing data

This document does NOT specify:

- File format parsing or conversion
- User interface requirements
- Access control beyond Sync layer capabilities (RFC-003)

### 1.3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

| Term | Definition |
|------|------------|
| Asset | A versioned unit of content with metadata |
| Project | An organizational grouping of assets |
| Reference | A typed link between assets |
| Content Hash | BLAKE3 hash identifying content by its bytes |
| Author | Identity that created or modified a record |

---

## 2. Protocol Overview

### 2.1. Design Goals

| Goal | Description |
|------|-------------|
| Structured | Defined schemas for protocol primitives |
| Minimal | Only essential primitives defined |
| Opinionated | Fixed fields ensure interoperability across applications |
| Interoperable | Common vocabulary enables data exchange across applications |

### 2.2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│              (CAD tools, design managers, viewers)           │
├─────────────────────────────────────────────────────────────┤
│                    DATA LAYER (this RFC)                     │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │    Asset     │  │   Project    │  │    Reference     │   │
│  │              │  │              │  │                  │   │
│  │  - Content   │  │  - Assets    │  │  - Source        │   │
│  │  - Metadata  │  │  - Members   │  │  - Target        │   │
│  │  - Author    │  │  - Ownership │  │  - Type          │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                    SYNC LAYER (RFC-003)                      │
│              Blobs, Entries, Replicas, Tickets               │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER (RFC-002)                 │
│              QUIC connections, relay, discovery              │
└─────────────────────────────────────────────────────────────┘
```

### 2.3. Data Types Overview

The protocol defines three core types:

| Type | Purpose | Example |
|------|---------|---------|
| Asset | A versioned unit of content | CAD file, render, BOM |
| Project | Organizational grouping | "Motor Assembly v2" |
| Reference | Typed link between assets | Assembly contains part |

These types are sufficient for most design workflows while remaining simple enough for quick adoption.

### 2.4. Relationship to Sync

Data types map to Sync primitives (RFC-003):

| Data Type | Sync Primitive | Relationship |
|-----------|----------------|--------------|
| Asset | Entry + Blob | Entry metadata points to blob content |
| Project | Replica | Project scope = Replica sync scope |
| Reference | Entry | Reference stored as entry in project |

---

## 3. Data Types

### 3.1. Asset

An Asset is the fundamental unit of content in OBJECTS.

#### 3.1.1. Definition

An Asset represents a versioned piece of content with associated metadata. The content is stored as a blob; the Asset record contains metadata and a reference to that blob.

#### 3.1.2. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | REQUIRED | Unique identifier within project |
| name | string | REQUIRED | Human-readable name |
| author_id | string | REQUIRED | Identity ID of the asset creator (RFC-001) |
| content_hash | bytes | REQUIRED | BLAKE3 hash of content blob (32 bytes) |
| content_size | uint64 | REQUIRED | Size of content in bytes |
| format | string | OPTIONAL | MIME type or format identifier |
| created_at | uint64 | REQUIRED | Creation timestamp (Unix seconds) |
| updated_at | uint64 | REQUIRED | Last update timestamp (Unix seconds) |

#### 3.1.3. Wire Format

```protobuf
message Asset {
  // REQUIRED. Unique identifier within the project.
  // Format: alphanumeric with hyphens, max 64 characters.
  string id = 1;

  // REQUIRED. Human-readable name.
  string name = 2;

  // REQUIRED. Identity ID of the asset creator (RFC-001).
  string author_id = 3;

  // REQUIRED. BLAKE3 hash of the content blob. Exactly 32 bytes.
  bytes content_hash = 4;

  // REQUIRED. Size of the content blob in bytes.
  uint64 content_size = 5;

  // OPTIONAL. MIME type or format identifier (e.g., "model/step", "image/png").
  string format = 6;

  // REQUIRED. Unix timestamp (seconds) when asset was created.
  uint64 created_at = 7;

  // REQUIRED. Unix timestamp (seconds) when asset was last updated.
  uint64 updated_at = 8;
}

// SignedAsset wraps an Asset with authorship proof.
// See RFC-001 Appendix D for signature verification.
message SignedAsset {
  Asset asset = 1;
  Signature signature = 2;  // RFC-001 Signature type
  bytes nonce = 3;          // 8 bytes, required for identity derivation verification
}
```

#### 3.1.4. Content Hash as Version

The `content_hash` field serves as a version identifier:

- Same content = same hash = same version
- Different content = different hash = different version
- No separate version numbering required

Applications MAY implement additional versioning semantics using Reference entries (see DERIVED_FROM).

### 3.2. Project

A Project is an organizational grouping of assets.

#### 3.2.1. Definition

A Project corresponds to a Sync layer Replica (RFC-003). All assets within a project are entries in that replica. Sharing a project means sharing the replica's doc ticket.

#### 3.2.2. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | REQUIRED | Unique identifier (derived from ReplicaId) |
| name | string | REQUIRED | Human-readable name |
| description | string | OPTIONAL | Project description |
| owner_id | string | REQUIRED | Identity ID of the project owner (RFC-001) |
| created_at | uint64 | REQUIRED | Creation timestamp (Unix seconds) |
| updated_at | uint64 | REQUIRED | Last update timestamp (Unix seconds) |

#### 3.2.3. Wire Format

```protobuf
message Project {
  // REQUIRED. Unique identifier for the project.
  // Derived from the ReplicaId (hex-encoded first 16 bytes).
  string id = 1;

  // REQUIRED. Human-readable name.
  string name = 2;

  // OPTIONAL. Project description.
  string description = 3;

  // REQUIRED. Identity ID of the project owner (RFC-001).
  string owner_id = 4;

  // REQUIRED. Unix timestamp (seconds) when project was created.
  uint64 created_at = 5;

  // REQUIRED. Unix timestamp (seconds) when project was last updated.
  uint64 updated_at = 6;
}
```

#### 3.2.4. Project = Replica

A Project maps 1:1 with a Sync layer Replica:

| Project Concept | Replica Concept |
|-----------------|-----------------|
| Project ID | Derived from ReplicaId |
| Project members | Holders of replica capability |
| Project assets | Entries in replica |
| Project sharing | Doc ticket |

This means:

- Creating a project creates a replica
- Sharing a project shares the doc ticket
- Project sync scope = replica sync scope
- Write access = replica write capability

### 3.3. Reference

A Reference is a typed link between assets.

#### 3.3.1. Definition

References express relationships between assets. They enable dependency graphs, assembly structures, and derived-from chains without embedding data.

#### 3.3.2. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | REQUIRED | Unique identifier within project |
| source_asset_id | string | REQUIRED | ID of the source asset |
| target_asset_id | string | REQUIRED | ID of the target asset |
| target_content_hash | bytes | OPTIONAL | Specific version of target (32 bytes) |
| reference_type | ReferenceType | REQUIRED | Type of relationship |
| created_at | uint64 | REQUIRED | Creation timestamp (Unix seconds) |

#### 3.3.3. Reference Types

| Type | Value | Description |
|------|-------|-------------|
| UNSPECIFIED | 0 | Unknown relationship |
| CONTAINS | 1 | Source contains target (assembly → part) |
| DEPENDS_ON | 2 | Source depends on target |
| DERIVED_FROM | 3 | Source is derived from target (version chain) |
| REFERENCES | 4 | Generic reference |

#### 3.3.4. Wire Format

```protobuf
enum ReferenceType {
  REFERENCE_TYPE_UNSPECIFIED = 0;
  REFERENCE_TYPE_CONTAINS = 1;
  REFERENCE_TYPE_DEPENDS_ON = 2;
  REFERENCE_TYPE_DERIVED_FROM = 3;
  REFERENCE_TYPE_REFERENCES = 4;
}

message Reference {
  // REQUIRED. Unique identifier within the project.
  string id = 1;

  // REQUIRED. ID of the source asset.
  string source_asset_id = 2;

  // REQUIRED. ID of the target asset.
  string target_asset_id = 3;

  // OPTIONAL. BLAKE3 hash of the specific target version.
  // If omitted, reference is to "latest" version of target.
  bytes target_content_hash = 4;

  // REQUIRED. Type of relationship.
  ReferenceType reference_type = 5;

  // REQUIRED. Unix timestamp (seconds) when reference was created.
  uint64 created_at = 6;
}
```

#### 3.3.5. Cross-Project References

References MAY point to assets in other projects by including the target project ID:

```protobuf
message CrossProjectReference {
  // REQUIRED. Unique identifier within the project.
  string id = 1;

  // REQUIRED. ID of the source asset (in this project).
  string source_asset_id = 2;

  // REQUIRED. ID of the target project.
  string target_project_id = 3;

  // REQUIRED. ID of the target asset in the target project.
  string target_asset_id = 4;

  // OPTIONAL. Specific version of target.
  bytes target_content_hash = 5;

  // REQUIRED. Type of relationship.
  ReferenceType reference_type = 6;

  // REQUIRED. Unix timestamp (seconds).
  uint64 created_at = 7;
}
```

---

## 4. Storage Conventions

### 4.1. Entry Key Format

Data types are stored as Sync layer entries with structured keys.

#### 4.1.1. Key Schema

```
/{type}/{id}
```

| Component | Description |
|-----------|-------------|
| type | Data type: `project`, `assets`, `refs` |
| id | Record identifier |

#### 4.1.2. Examples

```
/project                    → Project metadata
/assets/motor-mount         → Asset record
/assets/gear-assembly       → Asset record
/refs/assembly-to-part-1    → Reference record
/refs/assembly-to-part-2    → Reference record
```

### 4.2. Entry Content

Entry blobs contain serialized Protocol Buffers messages.

#### 4.2.1. Encoding

```
entry.blob = protobuf.serialize(Asset | Project | Reference)
```

Nodes MUST:

- Serialize using Protocol Buffers binary format
- Use the schemas defined in this specification
- Validate required fields before storing

#### 4.2.2. Content Type

The entry key prefix indicates the content type:

| Key Prefix | Content Type |
|------------|--------------|
| `/project` | Project message |
| `/assets/` | Asset message |
| `/refs/` | Reference message |

### 4.3. Asset Content Storage

Asset content (the actual file data) is stored separately from Asset metadata.

#### 4.3.1. Storage Model

```
Entry: /assets/motor-mount
  └── Blob: Asset { content_hash: 0xabc123... }
              │
              └──► Blob: [actual file bytes]
                   Hash: 0xabc123...
```

The Asset entry references the content blob by hash. Nodes fetch the content blob separately via Blob Sync (RFC-003).

### 4.4. User Vault

#### 4.4.1. Definition

A User Vault is a special-purpose replica containing an encrypted catalog of all projects owned by an identity. The vault enables cross-app project discovery without centralized infrastructure while preserving user privacy.

#### 4.4.2. Vault Namespace Derivation (Private)

**Privacy-by-Default:** Vault replica namespace is derived from the identity's **signing key secret**, not from the public identity ID. Only the identity owner can compute the vault namespace.

**Derivation Algorithm:**

```
Input: signer_secret_bytes (32 bytes, from secp256r1 or secp256k1 signing key)
Info: "OBJECTS-protocol-vault-namespace-v1"

Step 1: HKDF-Extract-and-Expand
  hkdf = HKDF-SHA256(ikm=signer_secret_bytes, salt=None)
  okm = hkdf.expand(info, 64 bytes)

Step 2: Split output
  namespace_seed = okm[0:32]
  catalog_encryption_key = okm[32:64]

Step 3: Derive Iroh namespace keypair
  namespace_secret = Ed25519SecretKey::from_bytes(namespace_seed)
  namespace_id = namespace_secret.verifying_key()  // Public key

Output:
  - Vault ReplicaId = namespace_id (NamespaceId, 32 bytes)
  - Vault write capability = namespace_secret (NamespaceSecret)
  - Catalog encryption key = catalog_encryption_key (32 bytes)
```

**Properties:**
- **Private:** Only identity owner (who has signing key) can compute vault ID
- **Deterministic:** Same signing key → same vault namespace
- **No storage:** All keys derived on-demand from signing key
- **Multi-purpose:** Single HKDF invocation provides namespace + encryption keys

**Security Note:** This derivation MUST only occur in wallet/keyring/passkey services that possess the identity signing key. Applications MUST NOT attempt to derive vault keys themselves. Applications request vault access via capability tickets from the user's wallet.

#### 4.4.3. Catalog Entry Schema

Vault entries use key format: `/catalog/{project_id}`

Entry value is an **encrypted** `ProjectCatalogEntry`:

**Protobuf Schema (plaintext):**

```protobuf
message ProjectCatalogEntry {
  // REQUIRED. Unique project identifier.
  string project_id = 1;

  // REQUIRED. NamespaceId of the project replica (32 bytes).
  bytes replica_id = 2;

  // REQUIRED. Human-readable project name.
  string project_name = 3;

  // REQUIRED. Unix timestamp (seconds) when project was created.
  uint64 created_at = 4;
}
```

**Storage Format:**

```
Entry Key: /catalog/{project_id}
Entry Value: nonce (24 bytes) || XChaCha20-Poly1305(ProjectCatalogEntry)
```

Encryption: XChaCha20-Poly1305 AEAD with key derived from signing key (Section 4.4.2).

#### 4.4.4. Vault Access Control and Privacy

**Write Access:**
- Requires vault namespace secret (derived from identity signing key)
- Only identity owner can write to vault
- Implemented by wallet/keyring/passkey services

**Read Access:**
- Requires vault namespace ID (derived from identity signing key)
- Only identity owner can compute namespace ID
- Apps request read-only DocTicket from user's wallet

**Privacy Guarantees:**

| Aspect | Privacy Level | Mechanism |
|--------|---------------|-----------|
| Vault ID | Private | HKDF from secret key |
| Catalog entry keys | Private | Keys visible only after vault access |
| Catalog entry values | Private | XChaCha20-Poly1305 encryption |
| Project replica IDs | Private | Encrypted in catalog entries |

**No public enumeration:** Without the identity signing key, vault namespace ID cannot be computed. This prevents:
- Discovering what projects exist
- Enumerating user's project count
- Correlating vaults across identities

#### 4.4.5. Vault Lifecycle

**Creation:**
Vault created automatically when user creates their first project. Wallet/keyring derives namespace secret, creates replica.

**Updates:**
Vault updated by wallet/keyring when:
- New project created → add encrypted catalog entry
- Project renamed → update encrypted catalog entry
- Project deleted → remove catalog entry

**Synchronization:**
Vault syncs via standard Iroh docs protocol (RFC-003). User's devices (wallet instances) sync vault state via P2P replication.

**Cross-App Discovery:**
1. User authenticates to new app
2. App requests vault access from wallet
3. Wallet derives namespace ID, creates read-only DocTicket
4. App syncs vault replica using ticket
5. App requests decryption key from wallet
6. Wallet provides catalog encryption key
7. App decrypts catalog entries, discovers projects

#### 4.4.6. Security Considerations

**Key Material:**
- Vault namespace secret = signing key secret → Same recovery requirements as identity
- Key compromise = vault write capability compromised
- Multi-signer support (RFC-001 Section 5.6) will enable vault recovery

**Privacy Trade-off:**
- **Pro:** Full privacy for project catalog
- **Con:** No public portfolio discovery (users must explicitly share if desired)
- **Migration:** Can add opt-in public catalog mode in v0.2

---

## 5. Operations

### 5.1. Create Project

Creates a new project (and underlying replica).

#### 5.1.1. Procedure

1. Generate new Ed25519 keypair for replica
2. Derive project ID from ReplicaId
3. Create Project record with metadata
4. Store Project entry at `/project`

#### 5.1.2. Postconditions

- New replica exists
- Project entry stored at `/project`
- Creator has write capability

### 5.2. Create Asset

Adds an asset to a project.

#### 5.2.1. Procedure

1. Generate asset ID (or use provided ID)
2. Store content blob via Blob Sync
3. Create Asset record with content hash
4. Store Asset entry at `/assets/{id}`

#### 5.2.2. Preconditions

- Write capability for project replica
- Content blob available

#### 5.2.3. Postconditions

- Content blob stored
- Asset entry stored
- Asset queryable by ID

### 5.3. Update Asset

Updates an existing asset's content or metadata.

#### 5.3.1. Procedure

1. Store new content blob (if content changed)
2. Create new Asset record with updated fields
3. Update Asset entry at `/assets/{id}`

#### 5.3.2. Semantics

Updates are last-write-wins based on entry timestamp. The Sync layer preserves all author versions; applications resolve conflicts.

### 5.4. Create Reference

Creates a link between assets.

#### 5.4.1. Procedure

1. Generate reference ID
2. Create Reference record
3. Store Reference entry at `/refs/{id}`

#### 5.4.2. Validation

Applications SHOULD verify:

- Source asset exists
- Target asset exists (for same-project references)
- Reference type is appropriate

---

## 6. Versioning

### 6.1. Content Versioning

Asset versions are identified by content hash. Same content = same version.

#### 6.1.1. Version History

To maintain version history, applications create `DERIVED_FROM` references:

```
Asset v3 (hash: 0xdef...)
  └── Reference: DERIVED_FROM → Asset v2 (hash: 0xabc...)
       └── Reference: DERIVED_FROM → Asset v1 (hash: 0x123...)
```

#### 6.1.2. Querying History

Applications traverse `DERIVED_FROM` references to build version chains.

### 6.2. Schema Versioning

Protocol Buffers provides schema evolution via field numbers:

- New fields are added with new numbers
- Old fields are never removed (deprecated instead)
- Unknown fields are preserved

This specification uses package `objects.data.v1`. Future versions will use `objects.data.v2`, etc.

---

## 7. Security Considerations

### 7.1. Authorization

Data operations inherit Sync layer capabilities:

| Operation | Required Capability |
|-----------|---------------------|
| Read assets | Read capability (ReplicaId) |
| Create/update assets | Write capability (private key) |
| Create references | Write capability |
| Share project | Ability to share doc ticket |

### 7.2. Content Integrity

Asset content is verified by BLAKE3 hash. Nodes MUST verify content matches `content_hash` before accepting.

### 7.3. Metadata Validation

Applications SHOULD validate:

- Required fields are present
- Field values are within expected ranges
- Reference targets exist

The protocol does not enforce validation; applications implement it.

### 7.4. Cross-Project References

Cross-project references can point to assets the local node cannot access. Applications MUST handle:

- Target project not synced
- Target asset not found
- Permission denied on target

---

## 8. References

### 8.1. Normative References

| Reference | Title |
|-----------|-------|
| [RFC 2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [PROTOBUF] | Protocol Buffers Language Guide. https://protobuf.dev |
| [RFC-003] | OBJECTS Sync Protocol Specification |
| [BLAKE3] | BLAKE3 Cryptographic Hash Function. https://blake3.io |

### 8.2. Informative References

| Reference | Title |
|-----------|-------|
| [RFC-001] | OBJECTS Identity Protocol Specification |
| [RFC-002] | OBJECTS Transport Protocol Specification |

---

## Appendix A: Protocol Buffers Definitions

Complete schema definition:

```protobuf
syntax = "proto3";
package objects.data.v1;

// Asset represents a versioned unit of content.
message Asset {
  string id = 1;
  string name = 2;
  string author_id = 3;
  bytes content_hash = 4;
  uint64 content_size = 5;
  string format = 6;
  uint64 created_at = 7;
  uint64 updated_at = 8;
}

// SignedAsset wraps an Asset with authorship proof.
message SignedAsset {
  Asset asset = 1;
  Signature signature = 2;
  bytes nonce = 3;
}

// Signature imported from objects.identity.v1 (RFC-001).

// Project represents an organizational grouping of assets.
message Project {
  string id = 1;
  string name = 2;
  string description = 3;
  string owner_id = 4;
  uint64 created_at = 5;
  uint64 updated_at = 6;
}

// ProjectCatalogEntry represents a project in the user's vault catalog.
// This message is encrypted with XChaCha20-Poly1305 before storage.
// Stored in user vault replica at key: /catalog/{project_id}
message ProjectCatalogEntry {
  // REQUIRED. Unique project identifier.
  string project_id = 1;

  // REQUIRED. NamespaceId of the project replica (32 bytes).
  bytes replica_id = 2;

  // REQUIRED. Human-readable project name.
  string project_name = 3;

  // REQUIRED. Unix timestamp (seconds) when project was created.
  uint64 created_at = 4;
}

// ReferenceType defines the type of relationship between assets.
enum ReferenceType {
  REFERENCE_TYPE_UNSPECIFIED = 0;
  REFERENCE_TYPE_CONTAINS = 1;
  REFERENCE_TYPE_DEPENDS_ON = 2;
  REFERENCE_TYPE_DERIVED_FROM = 3;
  REFERENCE_TYPE_REFERENCES = 4;
}

// Reference represents a typed link between assets.
message Reference {
  string id = 1;
  string source_asset_id = 2;
  string target_asset_id = 3;
  bytes target_content_hash = 4;
  ReferenceType reference_type = 5;
  uint64 created_at = 6;
}

// CrossProjectReference represents a link to an asset in another project.
message CrossProjectReference {
  string id = 1;
  string source_asset_id = 2;
  string target_project_id = 3;
  string target_asset_id = 4;
  bytes target_content_hash = 5;
  ReferenceType reference_type = 6;
  uint64 created_at = 7;
}
```

---

## Appendix B: Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-01-11 | Initial draft |

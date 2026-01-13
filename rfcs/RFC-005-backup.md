# RFC-005: OBJECTS Backup Protocol

```
RFC:           005
Title:         OBJECTS Backup Protocol
Version:       0.1
Status:        Draft (Target: v0.2)
Author:        OBJECTS Protocol Team
Created:       2026-01-12
```

---

## Status of This Memo

This document specifies the OBJECTS Backup Protocol, defining how users register replicas with always-on backup nodes for offline availability. This feature is planned for v0.2.

Distribution of this memo is unlimited.

---

## Abstract

This document defines the OBJECTS Backup Protocol, a system for registering user-owned replicas with always-on backup nodes. Backup nodes act as persistent peers that store encrypted data and enable sync when user devices are offline. The protocol includes per-identity storage quotas, registration via signed tickets, and optional self-hosting.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Overview](#2-protocol-overview)
3. [Data Structures](#3-data-structures)
4. [Operations](#4-operations)
5. [Quota Management](#5-quota-management)
6. [Security Considerations](#6-security-considerations)
7. [Self-Hosting](#7-self-hosting)
8. [References](#8-references)
9. [Appendix A: API Reference](#appendix-a-api-reference)

---

## 1. Introduction

### 1.1. Motivation

Peer-to-peer sync requires at least one peer to be online. When all of a user's devices are offline, data cannot sync. This creates UX friction:

- User edits on laptop, closes it
- User opens phone, laptop is unreachable
- Phone has stale data until laptop comes back online

Backup nodes solve this by providing always-on peers that store user data and enable sync regardless of device availability.

### 1.2. Scope

This document specifies:

- Backup node registration and authentication
- Storage quota model
- Sync behavior between devices and backup nodes
- Self-hosting requirements

This document does NOT specify:

- Encryption schemes (uses existing blob encryption)
- Sync protocol details (see RFC-003)
- Payment for additional storage (future work)

### 1.3. Terminology

| Term | Definition |
|------|------------|
| Backup Node | An always-on peer that stores replicas for offline availability |
| Registration | The process of authorizing a backup node to sync a replica |
| Quota | Storage limit per identity (default: 1 GB) |
| Self-Hosted | A backup node operated by the user rather than OBJECTS |

---

## 2. Protocol Overview

### 2.1. Design Goals

| Goal | Description |
|------|-------------|
| Always Available | Backup nodes are online 24/7 |
| Private | Backup nodes store encrypted data, cannot read contents |
| Per-User | Each identity has isolated storage with quota |
| Optional | Users can operate without backup (local-only mode) |
| Self-Hostable | Users can run their own backup nodes |

### 2.2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         User Devices                         │
│                                                              │
│    ┌──────────┐         ┌──────────┐         ┌──────────┐   │
│    │  Laptop  │◄───────►│  Phone   │◄───────►│  Tablet  │   │
│    └────┬─────┘         └────┬─────┘         └────┬─────┘   │
│         │                    │                    │         │
└─────────┼────────────────────┼────────────────────┼─────────┘
          │                    │                    │
          │    P2P sync when devices online        │
          │                    │                    │
          ▼                    ▼                    ▼
     ┌─────────────────────────────────────────────────┐
     │              OBJECTS Backup Service              │
     │                                                  │
     │  ┌─────────────────────────────────────────┐    │
     │  │          Backup Node (Iroh peer)        │    │
     │  │                                         │    │
     │  │  - Registered replicas                  │    │
     │  │  - Encrypted blob storage               │    │
     │  │  - Always online                        │    │
     │  └─────────────────────────────────────────┘    │
     │                                                  │
     │  ┌─────────────────────────────────────────┐    │
     │  │          Quota & Auth Service           │    │
     │  │                                         │    │
     │  │  - Identity verification                │    │
     │  │  - Storage tracking                     │    │
     │  │  - Registration API                     │    │
     │  └─────────────────────────────────────────┘    │
     │                                                  │
     └─────────────────────────────────────────────────┘
```

### 2.3. Sync Behavior

Backup nodes participate in sync as regular Iroh peers:

1. User registers replica with backup node (provides ticket)
2. Backup node joins replica using ticket
3. Backup node syncs blobs and entries like any peer
4. When user devices are offline, backup node retains data
5. When user devices come online, they sync with backup node

```
Device A offline    Device B online    Backup Node
     │                   │                  │
     │                   │──── sync ───────►│
     │                   │                  │ (stores data)
     │                   │                  │
     │              (goes offline)          │
     │                                      │
(comes online)                              │
     │                                      │
     │◄──────────── sync ──────────────────│
     │                                      │
     │ (now has Device B's changes)        │
```

---

## 3. Data Structures

### 3.1. BackupRegistration

A signed request to register a replica with the backup service.

#### 3.1.1. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| identity_id | string | REQUIRED | Identity registering the backup |
| replica_id | string | REQUIRED | Namespace ID of the replica |
| ticket | string | REQUIRED | Doc ticket granting sync access |
| timestamp | uint64 | REQUIRED | Unix timestamp (seconds) |
| signature | Signature | REQUIRED | Identity signature over registration |

#### 3.1.2. Wire Format

```protobuf
syntax = "proto3";
package objects.backup.v1;

message BackupRegistration {
  string identity_id = 1;
  string replica_id = 2;
  string ticket = 3;
  uint64 timestamp = 4;
  Signature signature = 5;
}
```

#### 3.1.3. Signature Message

The signature is computed over:

```
OBJECTS Identity Protocol v1
Action: Register Backup
Identity: {identity_id}
Replica: {replica_id}
Timestamp: {timestamp}
```

### 3.2. StorageQuota

Tracks storage usage for an identity.

#### 3.2.1. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| identity_id | string | REQUIRED | Identity this quota belongs to |
| bytes_used | uint64 | REQUIRED | Current blob storage usage |
| bytes_limit | uint64 | REQUIRED | Maximum allowed storage |
| replica_count | uint32 | REQUIRED | Number of registered replicas |

#### 3.2.2. Wire Format

```protobuf
message StorageQuota {
  string identity_id = 1;
  uint64 bytes_used = 2;
  uint64 bytes_limit = 3;
  uint32 replica_count = 4;
}
```

### 3.3. BackupStatus

Status of a registered replica.

```protobuf
message BackupStatus {
  string replica_id = 1;
  uint64 bytes_stored = 2;
  uint64 entry_count = 3;
  uint64 last_sync = 4;      // Unix timestamp of last sync activity
  BackupState state = 5;
}

enum BackupState {
  BACKUP_STATE_UNSPECIFIED = 0;
  BACKUP_STATE_SYNCING = 1;
  BACKUP_STATE_SYNCED = 2;
  BACKUP_STATE_PAUSED = 3;   // Quota exceeded
  BACKUP_STATE_ERROR = 4;
}
```

---

## 4. Operations

### 4.1. Register Replica

Registers a replica for backup.

#### 4.1.1. Preconditions

- Identity exists (verified via registry or signature)
- Ticket is valid for the replica
- Identity has not exceeded replica limit
- Identity has available storage quota

#### 4.1.2. Procedure

```
1. Client constructs BackupRegistration
2. Client signs registration with identity key
3. Client submits to backup service
4. Service verifies signature
5. Service checks quota
6. Service joins replica using ticket
7. Service begins syncing
```

#### 4.1.3. Errors

| Condition | Description |
|-----------|-------------|
| INVALID_SIGNATURE | Signature verification failed |
| QUOTA_EXCEEDED | Storage limit reached |
| REPLICA_LIMIT | Maximum replicas per identity reached |
| INVALID_TICKET | Ticket invalid or expired |
| ALREADY_REGISTERED | Replica already registered |

### 4.2. Unregister Replica

Removes a replica from backup.

#### 4.2.1. Procedure

```
1. Client signs unregister request
2. Service verifies signature
3. Service leaves replica
4. Service deletes stored blobs (after grace period)
5. Service updates quota
```

#### 4.2.2. Grace Period

Deleted replicas retain data for 7 days before permanent deletion. This allows recovery from accidental unregistration.

### 4.3. Query Status

Returns backup status for an identity's replicas.

No signature required for read-only status queries (identity_id in path).

---

## 5. Quota Management

### 5.1. Default Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Storage | 1 GB | Blob storage only |
| Replicas | 10 | Maximum registered replicas |
| Retention | 30 days | Minimum retention for synced data |

### 5.2. What Counts Against Quota

| Counts | Does Not Count |
|--------|----------------|
| Blob content | Entry metadata |
| File attachments | Signatures |
| Asset content | Sync overhead |

Quota is measured by unique blob bytes. Blobs shared across replicas are counted once.

### 5.3. Quota Enforcement

When quota is exceeded:

1. Existing data is retained
2. New blob syncs are rejected
3. Entry syncs continue (metadata only)
4. BackupState set to PAUSED
5. User notified via status API

```rust
async fn should_accept_blob(&self, identity: &str, size: u64) -> bool {
    let quota = self.get_quota(identity).await;
    quota.bytes_used + size <= quota.bytes_limit
}
```

### 5.4. Quota Reclamation

When blobs are deleted from all replicas:

1. Blob marked for deletion
2. After 24 hours, blob permanently deleted
3. Quota updated

---

## 6. Security Considerations

### 6.1. Threat Model

| Threat | Mitigation |
|--------|------------|
| Unauthorized registration | Signature verification against identity |
| Storage abuse | Per-identity quotas |
| Data exposure | E2E encryption (backup node cannot read data) |
| Replay attacks | Timestamp validation |

### 6.2. Data Privacy

Backup nodes store:

| Data | Visibility to Backup Node |
|------|---------------------------|
| Blob content | Encrypted, opaque bytes |
| Blob hashes | Visible (content-addressed) |
| Entry keys | Visible (for sync protocol) |
| Entry values | Encrypted, opaque bytes |
| Identity IDs | Visible (for quota tracking) |
| Replica IDs | Visible (for sync) |

Backup nodes cannot:

- Read file contents
- Understand project structure
- Determine asset types or names
- See who user shares with

### 6.3. Authentication

All mutating operations require identity signature:

- Register: proves identity owns the ticket
- Unregister: proves identity authorized to remove

Read operations (status, quota) use identity_id in path without signature for simplicity.

---

## 7. Self-Hosting

### 7.1. Overview

Users may operate their own backup nodes for:

- Greater storage capacity
- Data sovereignty
- Geographic preferences
- Cost control

### 7.2. Requirements

Self-hosted backup nodes:

- Run the `objects-backup` binary
- Have stable internet connectivity
- Have sufficient storage
- Are reachable by user devices

### 7.3. Configuration

```toml
# objects-backup.toml

[node]
# Node keypair (generated on first run)
data_dir = "/var/lib/objects-backup"

[network]
# Connect to OBJECTS relay for NAT traversal
relay_url = "https://relay.objects.network"

[storage]
# Where to store blobs
path = "/var/lib/objects-backup/blobs"

# No quota enforcement for self-hosted (optional)
quota_enabled = false

[api]
# Optional API for status/management
enabled = true
bind = "127.0.0.1:8081"
```

### 7.4. Docker Deployment

```yaml
# docker-compose.yml
version: '3'
services:
  objects-backup:
    image: ghcr.io/objects-protocol/objects-backup:latest
    volumes:
      - backup-data:/var/lib/objects-backup
    ports:
      - "7824:7824/udp"  # QUIC
      - "8081:8081"      # API (optional)
    environment:
      - OBJECTS_RELAY_URL=https://relay.objects.network
    restart: unless-stopped

volumes:
  backup-data:
```

### 7.5. Registration with Self-Hosted

Users register replicas directly with their backup node:

```bash
# Get backup node's NodeId
objects-backup info
# Output: NodeId: n0de_abc123...

# On user device, register with self-hosted backup
objects backup register --node n0de_abc123... --project "My Project"
```

---

## 8. References

### 8.1. Normative References

| Reference | Title |
|-----------|-------|
| [RFC-001] | OBJECTS Identity Protocol |
| [RFC-003] | OBJECTS Sync Protocol |

### 8.2. Informative References

| Reference | Title |
|-----------|-------|
| [Anytype] | Anytype Self-Hosting Documentation |
| [Waku Store] | 13/WAKU2-STORE Protocol Specification |
| [Iroh] | Iroh Protocol Specification |

---

## Appendix A: API Reference

### A.1. REST API

Base URL: `https://backup.objects.network/v1`

#### A.1.1. Register Replica

```
POST /v1/replicas
```

**Request:**

```json
{
  "identity_id": "obj_5KJvsngHeMpm88rD",
  "replica_id": "namespace_abc123...",
  "ticket": "docabc123...",
  "timestamp": 1704542400,
  "signature": {
    "signer_type": "PASSKEY",
    "signature": "<base64>",
    "public_key": "<base64>",
    "authenticator_data": "<base64>",
    "client_data_json": "<base64>"
  }
}
```

**Response (201):**

```json
{
  "replica_id": "namespace_abc123...",
  "state": "SYNCING",
  "bytes_stored": 0,
  "entry_count": 0
}
```

#### A.1.2. Unregister Replica

```
DELETE /v1/replicas/{replica_id}
```

**Request:**

```json
{
  "identity_id": "obj_5KJvsngHeMpm88rD",
  "timestamp": 1704542500,
  "signature": {...}
}
```

**Response (200):**

```json
{
  "replica_id": "namespace_abc123...",
  "state": "DELETED",
  "deletion_at": 1705147300
}
```

#### A.1.3. Get Backup Status

```
GET /v1/identities/{identity_id}/backups
```

**Response (200):**

```json
{
  "identity_id": "obj_5KJvsngHeMpm88rD",
  "replicas": [
    {
      "replica_id": "namespace_abc123...",
      "state": "SYNCED",
      "bytes_stored": 52428800,
      "entry_count": 42,
      "last_sync": 1704542600
    }
  ]
}
```

#### A.1.4. Get Quota

```
GET /v1/identities/{identity_id}/quota
```

**Response (200):**

```json
{
  "identity_id": "obj_5KJvsngHeMpm88rD",
  "bytes_used": 52428800,
  "bytes_limit": 1073741824,
  "replica_count": 1,
  "replica_limit": 10
}
```

#### A.1.5. Error Responses

```json
{
  "error": {
    "code": "QUOTA_EXCEEDED",
    "message": "Storage quota exceeded (1.0 GB used of 1.0 GB limit)"
  }
}
```

| Status | Code | Condition |
|--------|------|-----------|
| 400 | INVALID_SIGNATURE | Signature verification failed |
| 400 | INVALID_TICKET | Ticket invalid or malformed |
| 404 | NOT_FOUND | Replica or identity not found |
| 409 | ALREADY_REGISTERED | Replica already registered |
| 409 | QUOTA_EXCEEDED | Storage limit reached |
| 409 | REPLICA_LIMIT | Maximum replicas reached |

---

## Appendix B: Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-01-12 | Initial draft |

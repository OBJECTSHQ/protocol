# RFC-000: OBJECTS Protocol Overview

```
RFC:           000
Title:         OBJECTS Protocol Overview
Version:       0.1
Status:        Draft
Author:        OBJECTS Protocol Team
Created:       2026-01-11
```

---

## Status of This Memo

This document provides an architectural overview of the OBJECTS Protocol. It describes how the protocol layers fit together and clarifies key concepts. This is an informational document; normative requirements are specified in individual layer RFCs.

Distribution of this memo is unlimited.

---

## Abstract

OBJECTS is a peer-to-peer protocol for collaborative design engineering. It enables designers, engineers, and makers to share, version, and collaborate on physical design data (CAD files, assemblies, BOMs) without centralized platforms. The protocol is organized into four layers: Identity, Transport, Sync, and Data.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Architecture](#2-architecture)
3. [Protocol Layers](#3-protocol-layers)
4. [Key Concepts](#4-key-concepts)
5. [Conformance](#5-conformance)
6. [References](#6-references)

---

## 1. Introduction

### 1.1. Problem

Design data is trapped in platforms. Switching tools means re-uploading, re-organizing, and losing collaboration history. Engineers waste time on file management instead of design. Version control for physical design is fragmented and platform-specific.

### 1.2. Solution

OBJECTS provides a protocol for design data that is:

- **User-owned**: Identities and data belong to users, not platforms
- **Peer-to-peer**: Direct collaboration without central servers
- **Offline-first**: Work locally, sync when connected
- **Interoperable**: Common data formats enable tool-to-tool exchange

### 1.3. Audience

This document is for:

- Application developers building on OBJECTS
- Protocol implementers
- Anyone seeking to understand the overall architecture

---

## 2. Architecture

### 2.1. Layer Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│              (CAD tools, design managers, viewers)           │
├─────────────────────────────────────────────────────────────┤
│                    DATA LAYER (RFC-004)                      │
│                 Asset, Project, Reference                    │
├─────────────────────────────────────────────────────────────┤
│                    SYNC LAYER (RFC-003)                      │
│              Blobs, Entries, Replicas, Tickets               │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER (RFC-002)                 │
│              QUIC connections, relay, discovery              │
├─────────────────────────────────────────────────────────────┤
│                    IDENTITY LAYER (RFC-001)                  │
│              Passkeys, wallets, handles, registry            │
└─────────────────────────────────────────────────────────────┘
```

### 2.2. Layer Responsibilities

| Layer | RFC | Responsibility |
|-------|-----|----------------|
| Identity | RFC-001 | User accounts, authentication, handles |
| Transport | RFC-002 | Peer-to-peer connectivity, NAT traversal |
| Sync | RFC-003 | Content-addressed data synchronization |
| Data | RFC-004 | Design-specific data types and schemas |

### 2.3. Layer Independence

Each layer has a distinct concern:

- **Identity** is orthogonal to transport. An identity can authenticate across different transport mechanisms.
- **Transport** handles connectivity without understanding what data is being sent.
- **Sync** provides content-addressed storage and replication without understanding the data semantics.
- **Data** defines schemas and operations without specifying how data is stored or transmitted.

---

## 3. Protocol Layers

### 3.1. Identity (RFC-001)

The identity layer provides portable, user-owned identities.

**Key features:**
- Passkey-first authentication (WebAuthn)
- Optional wallet linking for payments
- Human-readable handles (`@username`)
- Pseudonymous by default

**Primary concepts:**
- Identity ID: Unique identifier derived from signing key
- Handle: Human-readable alias
- Signer: Passkey or wallet used for authentication

### 3.2. Transport (RFC-002)

The transport layer provides peer-to-peer connectivity.

**Key features:**
- QUIC-based connections with TLS 1.3
- Relay-assisted NAT traversal
- Peer discovery via gossip

**Primary concepts:**
- Node: A running instance of OBJECTS software
- NodeId: Ed25519 public key identifying a node
- Relay: Server that assists with NAT traversal

### 3.3. Sync (RFC-003)

The sync layer provides content-addressed data synchronization.

**Key features:**
- BLAKE3 content addressing
- Verified streaming with incremental verification
- Set reconciliation for efficient sync
- Capability-based access control

**Primary concepts:**
- Blob: Content-addressed binary data
- Entry: Key-value record with author signature
- Replica: Collection of entries that syncs with peers
- Ticket: Encoded capability for sharing data

### 3.4. Data (RFC-004)

The data layer provides structure for design content.

**Key features:**
- Optimized for physical design workflows
- Minimal, extensible primitives
- Project = Replica mapping

**Primary concepts:**
- Asset: Versioned unit of content (CAD file, render, BOM)
- Project: Organizational grouping of assets
- Reference: Typed link between assets

---

## 4. Key Concepts

### 4.1. Nodes vs Identities

OBJECTS distinguishes between **nodes** and **identities**:

| Concept | Layer | Description | Persistence |
|---------|-------|-------------|-------------|
| Node | Transport | Running software instance | Ephemeral (per device/session) |
| Identity | Identity | User account | Persistent (cross-device) |

A **node** is a computer participating in the network. Nodes have NodeIds derived from Ed25519 keypairs. A node can restart with a different NodeId.

An **identity** is a user account. Identities have Identity IDs derived from signing keys (passkey or wallet). An identity persists across devices and sessions.

**Relationship:**
- One identity can operate from multiple nodes (e.g., laptop and phone)
- One node typically serves one identity at a time
- Transport authenticates nodes; applications authenticate identities

### 4.2. Projects and Replicas

A **project** (Data layer) maps 1:1 to a **replica** (Sync layer):

| Project Concept | Replica Concept |
|-----------------|-----------------|
| Project ID | Derived from ReplicaId |
| Project assets | Entries in replica |
| Project sharing | Doc ticket |
| Write access | Replica write capability |

This mapping is intentional and simplifies the mental model: one project = one sync scope.

### 4.3. Content Addressing

All content is addressed by BLAKE3 hash:

```
hash = BLAKE3(content)
```

This provides:
- **Deduplication**: Same content stored once
- **Integrity**: Content verified against hash
- **Versioning**: Different content = different hash

### 4.4. Capability-Based Security

Access control is capability-based:

| Capability | Grants |
|------------|--------|
| ReplicaId (public) | Read access to replica |
| Replica private key | Write access to replica |
| Doc ticket | Shareable read or write access |

Capabilities are unforgeable and can be shared. Possession of a capability grants the associated access.

---

## 5. Conformance

### 5.1. Conformance Levels

| Level | Requirements |
|-------|--------------|
| Minimal | Transport + Sync (can receive and store data) |
| Standard | Transport + Sync + Data (understands OBJECTS data types) |
| Full | All layers including Identity |

### 5.2. Required vs Optional

Each RFC specifies MUST/SHOULD/MAY requirements. Implementations MUST implement all MUST requirements for their conformance level.

---

## 6. References

### 6.1. Normative References

| Reference | Title |
|-----------|-------|
| [RFC-001] | OBJECTS Identity Protocol |
| [RFC-002] | OBJECTS Transport Protocol |
| [RFC-003] | OBJECTS Sync Protocol |
| [RFC-004] | OBJECTS Data Protocol |

### 6.2. Informative References

| Reference | Title |
|-----------|-------|
| [QUIC] | IETF QUIC Transport Protocol |
| [BLAKE3] | BLAKE3 Cryptographic Hash Function |
| [WebAuthn] | Web Authentication API |
| [iroh] | iroh: Peer-to-peer that works. https://iroh.computer |

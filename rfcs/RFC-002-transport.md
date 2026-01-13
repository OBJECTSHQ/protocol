# RFC-002: OBJECTS Transport Protocol

```
RFC:           002
Title:         OBJECTS Transport Protocol
Version:       0.1
Status:        Draft
Author:        OBJECTS Protocol Team
Created:       2025-01-08
```

---

## Status of This Memo

This document specifies the OBJECTS Transport Protocol version 0.1, defining how nodes establish connections, discover peers, and maintain network membership. This is a draft specification subject to change.

Distribution of this memo is unlimited.

---

## Abstract

This document defines the OBJECTS Transport Protocol, a system for peer-to-peer connectivity in the OBJECTS network. The protocol normatively references Iroh for connection semantics and introduces OBJECTS-specific identifiers for protocol negotiation and peer discovery. Transport is the foundation layer upon which Sync, Data, and Identity layers operate.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Overview](#2-protocol-overview)
3. [Data Structures](#3-data-structures)
4. [Network Configuration](#4-network-configuration)
5. [Peer Discovery](#5-peer-discovery)
6. [Operational Requirements](#6-operational-requirements)
7. [Security Considerations](#7-security-considerations)
8. [References](#8-references)
9. [Appendix A: Implementation Notes](#appendix-a-implementation-notes)
10. [Appendix B: Changelog](#appendix-b-changelog)

---

## 1. Introduction

### 1.1. Motivation

Decentralized applications require reliable peer-to-peer connectivity that works across NATs, firewalls, and mobile networks. Rather than defining novel transport mechanisms, OBJECTS builds on Iroh — a production-ready implementation of QUIC-based networking with relay-assisted NAT traversal.

### 1.2. Scope

This document specifies:

- Node addressing and identification
- Connection establishment via Iroh
- Peer discovery mechanisms
- Network configuration for mainnet participation

This document does NOT specify:

- Data synchronization (see RFC-003: Sync)
- Message formats for application data (see RFC-003: Sync)
- Identity verification (see RFC-001: Identity)
- Asset schemas (see RFC-004: Data)

### 1.3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

| Term | Definition |
|------|------------|
| Node | A participant in the OBJECTS network running a conforming implementation |
| NodeId | A 32-byte Ed25519 public key uniquely identifying a node |
| NodeAddr | A structure containing a NodeId plus addressing hints (relay URL, direct addresses) |
| Endpoint | The local connection manager that handles incoming/outgoing connections |
| Connection | An authenticated QUIC connection between two nodes |
| Relay | A server that assists with NAT traversal and connection establishment |
| Discovery Topic | A gossip topic used for peer discovery |
| ALPN | Application-Layer Protocol Negotiation, used during QUIC handshake |

---

## 2. Protocol Overview

### 2.1. Design Goals

| Goal | Description |
|------|-------------|
| Simplicity | Leverage Iroh's battle-tested connection model |
| Mobile-first | QUIC provides reliable connectivity on mobile networks |
| NAT traversal | Relay-assisted holepunching for universal reachability |
| Single network | All conforming nodes participate in one shared network |

### 2.2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│              (Apps that consume OBJECTS data)                │
├─────────────────────────────────────────────────────────────┤
│                    IDENTITY LAYER (RFC-001)                  │
│                    DATA LAYER (RFC-004)                      │
│                    SYNC LAYER (RFC-003)                      │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER (this RFC)                │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │   Addressing │  │  Connection  │  │    Discovery     │   │
│  │              │  │              │  │                  │   │
│  │  - NodeId    │  │  - Endpoint  │  │  - Bootstrap     │   │
│  │  - NodeAddr  │  │  - Streams   │  │  - Gossip topic  │   │
│  │  - Pkarr DNS │  │  - ALPN      │  │  - Announcements │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                    IROH (Normative Reference)                │
│              QUIC connections, relay, holepunching           │
├─────────────────────────────────────────────────────────────┤
│                    QUIC/UDP (RFC 9000)                       │
└─────────────────────────────────────────────────────────────┘
```

### 2.3. Connection Flow

```
Node A                           Relay                        Node B
   │                               │                             │
   │──── Connect to relay ────────►│                             │
   │                               │◄──── Connect to relay ──────│
   │                               │                             │
   │──── Request connection to B ─►│                             │
   │                               │──── Holepunch coords ──────►│
   │                               │                             │
   │◄─────────── Direct QUIC connection (if possible) ─────────►│
   │                               │                             │
   │◄─────────── Or relayed connection ────────────────────────►│
   │                               │                             │
   │         ALPN: /objects/0.1                                  │
   │◄────────────── Authenticated connection ──────────────────►│
```

### 2.4. Protocol Negotiation

Protocol version negotiation occurs during QUIC handshake via ALPN (Application-Layer Protocol Negotiation).

| ALPN Identifier | Protocol Version |
|-----------------|------------------|
| `/objects/0.1`  | This specification |

A conforming node MUST advertise `/objects/0.1` during connection establishment. Nodes SHOULD reject connections that do not negotiate a recognized ALPN identifier.

---

## 3. Data Structures

### 3.1. NodeId

A NodeId is a 32-byte Ed25519 public key that uniquely identifies a node.

**Source:** Iroh (normative reference)

#### 3.1.1. Format

```
NodeId := Ed25519PublicKey (32 bytes)
```

#### 3.1.2. Encoding

NodeIds are encoded as:

| Format | Description |
|--------|-------------|
| Binary | 32 raw bytes |
| Text | z-base-32 encoding for human readability |

### 3.2. NodeAddr

A NodeAddr contains the information needed to establish a connection to a node.

**Source:** Iroh (normative reference)

#### 3.2.1. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| node_id | NodeId | REQUIRED | The node's public key (32 bytes) |
| relay_url | URL | OPTIONAL | The node's preferred relay server |
| direct_addresses | list of SocketAddr | OPTIONAL | Known direct addresses |

#### 3.2.2. Wire Format

```
NodeAddr {
    node_id: NodeId,
    relay_url: Option<Url>,
    direct_addresses: Vec<SocketAddr>,
}
```

A NodeAddr with only a `node_id` can be resolved via Pkarr DNS lookup (see Section 5.2).

### 3.3. Endpoint

An Endpoint manages connections for a node.

**Source:** Iroh (normative reference)

The Endpoint:

- Binds to local UDP sockets
- Manages the node's keypair (NodeId)
- Handles incoming connection requests
- Establishes outgoing connections
- Coordinates with relays for NAT traversal

### 3.4. Connection

A Connection represents an authenticated QUIC connection to a peer.

**Source:** Iroh (normative reference)

Connections provide:

- Bidirectional streams (`open_bi`, `accept_bi`)
- Unidirectional streams (`open_uni`, `accept_uni`)
- Connection metadata (remote NodeId, connection type)

### 3.5. DiscoveryAnnouncement

A signed message broadcast on the discovery topic to announce node presence.

**Source:** OBJECTS (this specification)

#### 3.5.1. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| node_id | NodeId | REQUIRED | Announcing node's public key |
| relay_url | URL | OPTIONAL | Announcing node's relay |
| timestamp | uint64 | REQUIRED | Unix timestamp in seconds |
| signature | bytes | REQUIRED | Ed25519 signature (64 bytes) |

#### 3.5.2. Wire Format

```
DiscoveryAnnouncement {
    node_id: NodeId,
    relay_url: Option<Url>,
    timestamp: u64,
    signature: Ed25519Signature,
}
```

#### 3.5.3. Signature

The signature MUST be computed over the concatenation:

```
signed_data = node_id || relay_url_bytes || timestamp_be

Where:
  node_id = 32 bytes
  relay_url_bytes = UTF-8 encoded URL (0 bytes if absent)
  timestamp_be = 8 bytes, big-endian
```

---

## 4. Network Configuration

### 4.1. Mainnet Parameters

All conforming nodes MUST use the following network parameters to participate in the OBJECTS mainnet:

| Parameter | Value |
|-----------|-------|
| ALPN Identifier | `/objects/0.1` |
| Relay URL | `https://relay.objects.network` |
| Discovery Topic | `/objects/devnet/0.1/discovery` |

### 4.2. Bootstrap Nodes

Nodes joining the network for the first time MUST connect to at least one bootstrap node to initiate peer discovery.

**Bootstrap NodeIds:**

```
TBD - Bootstrap node public keys will be published before mainnet launch
```

Bootstrap nodes:

- Are operated by the OBJECTS Foundation
- Maintain high availability
- Participate in the discovery topic
- Do not have special protocol privileges

### 4.3. Relay Infrastructure

The OBJECTS relay (`relay.objects.network`) provides:

- NAT traversal assistance via holepunching coordination
- Fallback relaying when direct connections fail
- Connection to the discovery gossip network

Nodes SHOULD include the OBJECTS relay URL in their published NodeAddr. Nodes MAY operate additional relays for redundancy.

---

## 5. Peer Discovery

### 5.1. Overview

Peer discovery allows nodes to find and connect to other participants in the OBJECTS network. Discovery uses a two-phase approach:

1. **Bootstrap:** Connect to known bootstrap nodes
2. **Gossip:** Join discovery topic, learn about additional peers

### 5.2. NodeAddr Resolution

Given a NodeId, nodes resolve the corresponding NodeAddr via Pkarr DNS.

#### 5.2.1. Resolution Procedure

```
1. Encode NodeId as z-base-32
2. Query: <z32-node-id>.dns.iroh.link
3. Receive: relay_url, direct_addresses
4. Construct NodeAddr
```

This resolution is handled by Iroh's discovery mechanisms.

### 5.3. Discovery Topic

Nodes MUST join the discovery topic after establishing their first connection:

```
Topic: /objects/devnet/0.1/discovery
```

The discovery topic uses iroh-gossip for message dissemination. Nodes periodically announce their presence and learn about other nodes through gossip propagation.

### 5.4. Announcement Behavior

#### 5.4.1. Publishing

Nodes SHOULD broadcast a `DiscoveryAnnouncement`:

- Immediately upon joining the network
- At least once per hour thereafter
- After any change to relay URL or direct addresses

#### 5.4.2. Receiving

Nodes receiving announcements:

- MUST verify the Ed25519 signature before accepting
- SHOULD discard announcements older than 24 hours
- SHOULD maintain a local peer table of recently seen nodes
- SHOULD implement rate limiting to prevent flooding

### 5.5. Extensibility

The discovery mechanisms specified in this document (bootstrap nodes and gossip-based announcements) represent the initial discovery strategy for OBJECTS v0.1. This design prioritizes operational simplicity for early network deployment.

#### 5.5.1. Future Discovery Mechanisms

Future protocol versions MAY introduce additional discovery mechanisms, including but not limited to:

| Mechanism | Description |
|-----------|-------------|
| DHT-based discovery | Distributed hash table for peer lookup without centralized bootstrap |
| Local discovery | mDNS/DNS-SD for peers on the same local network |
| Topic-based rendezvous | Finding peers by shared interest or data availability |

#### 5.5.2. Compatibility Requirements

Implementations adding new discovery mechanisms:

- MUST continue to support bootstrap and gossip discovery for interoperability
- MUST NOT require peers to implement new mechanisms for basic connectivity
- SHOULD treat additional mechanisms as supplementary discovery sources

#### 5.5.3. Discovery Abstraction

Implementations SHOULD abstract discovery behind a common interface to facilitate future extension:

```
Discovery sources are additive. A node MAY use multiple discovery
mechanisms simultaneously. Peer addresses learned from any valid
source are equivalent for connection purposes.
```

This allows the network to evolve toward greater decentralization as operational experience is gained and the network grows.

---

## 6. Operational Requirements

### 6.1. Connection Limits

Conforming nodes:

- MUST support at least 100 concurrent streams per connection
- SHOULD accept at least 50 simultaneous peer connections
- MAY impose additional limits based on resource constraints

### 6.2. Timeouts

Conforming nodes MUST use Iroh's default timeout behavior:

| Parameter | Default | Description |
|-----------|---------|-------------|
| Idle timeout | 30 seconds | Close connection if no stream activity |
| Keep-alive | 15 seconds | Interval for NAT binding maintenance |
| Connection timeout | 30 seconds | Maximum time for connection establishment |

Implementations MAY adjust these values but MUST document deviations.

### 6.3. Error Handling

Transport-level errors follow Iroh's error semantics. Common error conditions:

| Error | Condition |
|-------|-----------|
| DialFailed | Unable to establish connection (no route, refused) |
| RelayNotAvailable | Cannot reach configured relay |
| Timeout | Connection or operation timed out |
| RemoteClosed | Peer closed the connection |
| ProtocolMismatch | ALPN negotiation failed |

OBJECTS reserves application error codes `0x4F42` through `0x4F5A` (ASCII "OB" prefix) for future protocol-specific errors.

---

## 7. Security Considerations

### 7.1. Threat Model

| Threat | Mitigation |
|--------|------------|
| Node impersonation | QUIC handshake authenticates NodeId cryptographically |
| Traffic eavesdropping | All traffic encrypted via QUIC TLS 1.3 |
| Discovery spoofing | Announcements are Ed25519 signed |
| Announcement flooding | Rate limiting on discovery topic |
| Relay compromise | Relay cannot read message contents (E2E encrypted) |

### 7.2. Authentication

All connections are authenticated via the QUIC handshake. The remote node's NodeId is cryptographically verified — a node cannot impersonate another node's public key.

### 7.3. Encryption

All traffic is encrypted using QUIC's TLS 1.3 integration. Connection contents are not visible to relays or network observers.

### 7.4. Relay Trust Model

Relays can observe:

- That two NodeIds are communicating
- Timing and volume of traffic

Relays cannot observe:

- Message contents (encrypted end-to-end)
- Which higher-layer protocols are in use

Nodes SHOULD treat relay operators as semi-trusted. Future protocol versions MAY introduce relay diversity or anonymity features.

### 7.5. Discovery Security

Discovery announcements are signed to prevent spoofing. Nodes MUST verify signatures before accepting announcements.

Nodes SHOULD implement:

- Rate limiting on incoming announcements
- Blacklisting of misbehaving peers
- Resource accounting for relay usage

---

## 8. References

### 8.1. Normative References

| Reference | Title |
|-----------|-------|
| [RFC 2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [RFC 9000] | QUIC: A UDP-Based Multiplexed and Secure Transport |
| [RFC 8446] | The Transport Layer Security (TLS) Protocol Version 1.3 |
| [IROH] | Iroh Protocol Specification, n0 Inc. https://iroh.computer/docs |

### 8.2. Informative References

| Reference | Title |
|-----------|-------|
| [PKARR] | Public Key Addressable Resource Records. https://pkarr.org |
| [RFC-001] | OBJECTS Identity Protocol Specification |
| [RFC-003] | OBJECTS Sync Protocol Specification (planned) |
| [RFC-004] | OBJECTS Data Protocol Specification (planned) |

---

## Appendix A: Implementation Notes

### A.1. Iroh Dependency

This specification assumes implementations use Iroh or a compatible library. The Iroh Rust crate (`iroh`) provides reference implementations:

```rust
use iroh::{Endpoint, NodeAddr, NodeId};

// Create endpoint
let endpoint = Endpoint::builder()
    .alpns(vec![b"/objects/0.1".to_vec()])
    .relay_url("https://relay.objects.network")
    .bind()
    .await?;

// Connect to peer
let conn = endpoint.connect(node_addr, b"/objects/0.1").await?;
```

### A.2. Discovery Implementation

Discovery can be implemented using iroh-gossip:

```rust
use iroh_gossip::{Gossip, TopicId};

let topic = TopicId::from_bytes(b"/objects/devnet/0.1/discovery");
let gossip = Gossip::new(endpoint.clone());

// Join discovery topic
gossip.join(topic, bootstrap_nodes).await?;

// Announce presence
gossip.broadcast(topic, announcement.encode()).await?;
```

### A.3. Compatibility

Implementations not using Iroh directly MUST:

- Implement QUIC per [RFC 9000]
- Support relay-assisted NAT traversal compatible with Iroh relays
- Use Ed25519 for node identity
- Implement iroh-gossip wire format for discovery

---

## Appendix B: Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2025-01-08 | Initial draft |

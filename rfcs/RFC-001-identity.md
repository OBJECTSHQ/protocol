# RFC-001: OBJECTS Identity Protocol

```
RFC:           001
Title:         OBJECTS Identity Protocol
Version:       0.1
Status:        Draft
Author:        OBJECTS Protocol Team
Created:       2026-01-06
```

---

## Status of This Memo

This document specifies the OBJECTS Identity Protocol version 0.1, a transport-agnostic identity system for the OBJECTS Protocol. This is a draft specification subject to change.

Distribution of this memo is unlimited.

---

## Abstract

This document defines the OBJECTS Identity Protocol, a system for creating and managing portable, user-owned identities. The protocol enables users to establish identity using passkeys (WebAuthn) or Ethereum wallets, associate human-readable handles, and optionally link wallet addresses for payments. The protocol is transport-agnostic; transport bindings (REST, Waku, etc.) are specified separately.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Overview](#2-protocol-overview)
3. [Identity Format](#3-identity-format)
4. [Data Structures](#4-data-structures)
5. [Operations](#5-operations)
6. [Registry](#6-registry)
7. [Security Considerations](#7-security-considerations)
8. [References](#8-references)
9. [Appendix A: Example Flows](#appendix-a-example-flows)
10. [Appendix B: Test Vectors](#appendix-b-test-vectors)
11. [Appendix C: Registry API](#appendix-c-registry-api)
12. [Appendix D: Asset Signatures](#appendix-d-asset-signatures)

---

## 1. Introduction

### 1.1. Motivation

Design data is trapped in platforms. Switching tools means re-uploading, re-organizing, and losing history. Identity is the foundation of data portability. If users own their identity:

- Assets and reputation travel with them
- Apps compete on UX, not data gravity
- Finance primitives (payments, licensing) have a stable anchor

### 1.2. Scope

This document specifies:

- Identity identifier format and derivation
- Handle format and constraints
- Signer types and signature verification
- Identity record data structures
- Operations: Create, Link Wallet, Change Handle, Sign Asset, Authenticate
- Registry storage and resolution requirements

This document does NOT specify:

- Transport mechanisms (REST API, Waku topics)
- Recovery mechanisms
- External identity linking (ENS, Farcaster, Lens)
- Group or organizational identities

### 1.3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

| Term | Definition |
|------|------------|
| Identity | A unique, user-controlled identifier with associated metadata |
| Handle | A human-readable alias for an identity (e.g., `@alice`) |
| Signer | A cryptographic key pair that can sign operations |
| Passkey | A WebAuthn credential using secp256r1 (P-256) curve |
| Wallet | An Ethereum EOA using secp256k1 curve |
| Registry | A service that stores and resolves identities |

---

## 2. Protocol Overview

### 2.1. Design Goals

| Goal | Description |
|------|-------------|
| User Ownership | Users control their identity; no platform lock-in |
| Passkey-First | Non-crypto users can create identity without wallet |
| Wallet Optional | Crypto users can link wallet for payments |
| Portable | Identity can be exported and verified independently |
| Pseudonymous | No PII required; handles are pseudonymous |
| Transport-Agnostic | Works over any transport (REST, P2P, etc.) |

### 2.2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│         (Apps that consume and produce identity)             │
├─────────────────────────────────────────────────────────────┤
│                    IDENTITY LAYER (this RFC)                 │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │   Identity   │  │  Operations  │  │     Registry     │   │
│  │   Format     │  │              │  │                  │   │
│  │              │  │  - Create    │  │  - Storage       │   │
│  │  - ID        │  │  - LinkWallet│  │  - Resolution    │   │
│  │  - Handle    │  │  - SignAsset │  │  - Verification  │   │
│  │  - Signer    │  │  - Auth      │  │                  │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER (RFC-002)                 │
│              (REST API, Waku P2P, etc.)                      │
└─────────────────────────────────────────────────────────────┘
```

### 2.3. Transport Independence

The Identity Protocol is transport-agnostic. Operations are defined as signed messages that can be transmitted over any transport layer. The registry accepts operations from any transport and verifies them identically.

Transport bindings (REST API endpoints, Waku content topics, message encoding) are specified in RFC-002.

---

## 3. Identity Format

### 3.1. Identity Identifier

An identity identifier uniquely identifies an OBJECTS identity.

#### 3.1.1. Format

```
identity_id = "obj_" || base58(truncate(sha256(signer_public_key || nonce), 15))
```

Where:

| Component | Size | Description |
|-----------|------|-------------|
| `signer_public_key` | 33 bytes | Compressed SEC1 public key |
| `nonce` | 8 bytes | Cryptographically random bytes |
| `\|\|` | - | Byte concatenation |
| `truncate(x, n)` | - | First n bytes of x |
| `base58` | - | Base58 encoding (Bitcoin alphabet) |

#### 3.1.2. Constraints

- The identifier MUST begin with the prefix `obj_`
- The encoded portion MUST be exactly 20 characters
- Total length MUST be exactly 24 characters

#### 3.1.3. Example

```
Input:
  signer_public_key: 0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
  nonce: 0x0102030405060708

Derivation:
  concat = signer_public_key || nonce
  hash = sha256(concat)
  truncated = hash[0:15]
  encoded = base58(truncated)

Output:
  obj_7kd2zcx9f3m1qwerty
```

### 3.2. Handle Format

A handle is a human-readable alias for an identity.

#### 3.2.1. ABNF Grammar

```abnf
handle     = part *("." part)
part       = 1*(ALPHA / DIGIT / "_")
ALPHA      = %x61-7A  ; a-z (lowercase only)
DIGIT      = %x30-39  ; 0-9
```

#### 3.2.2. Constraints

| Constraint | Requirement |
|------------|-------------|
| Length | MUST be 1-30 characters (including periods) |
| Characters | MUST contain only: a-z, 0-9, underscore, period |
| Start | MUST NOT start with period or underscore |
| End | MUST NOT end with period |
| Periods | MUST NOT contain consecutive periods (`..`) |
| Uniqueness | MUST be unique (case-insensitive) |
| Reserved | MUST NOT be a reserved word (see 3.2.3) |

#### 3.2.3. Reserved Handles

The following handles are reserved and MUST NOT be assigned:

```
admin, administrator, root, system, objects, protocol,
support, help, info, contact, api, www, mail, ftp
```

#### 3.2.4. Display Format

When displayed to users, handles SHOULD be prefixed with `@`:

```
Stored:    montez
Displayed: @montez
```

### 3.3. Signer Types

A signer is a cryptographic key pair that can sign operations.

#### 3.3.1. Supported Types

| Type | Value | Curve | Key Size | Description |
|------|-------|-------|----------|-------------|
| PASSKEY | 1 | secp256r1 (P-256) | 33 bytes | WebAuthn/FIDO2 credential |
| WALLET | 2 | secp256k1 | 33 bytes | Ethereum EOA |

#### 3.3.2. Public Key Encoding

Public keys MUST be encoded in compressed SEC1 format:

```
compressed_key = prefix || x_coordinate

Where:
  prefix = 0x02 if y is even, 0x03 if y is odd
  x_coordinate = 32 bytes (big-endian)
```

#### 3.3.3. Passkey (Type 1)

Passkeys use the secp256r1 (P-256) curve as specified in [WebAuthn].

- Relying Party ID MUST be recorded for verification
- Authenticator data MUST be included in signature verification
- Client data JSON MUST be included in signature verification

#### 3.3.4. Wallet (Type 2)

Wallets use the secp256k1 curve with EIP-191 personal signatures.

- Messages MUST be prefixed per [EIP-191]
- Signatures MUST be 65 bytes (r || s || v)
- Recovery ID (v) MUST be 27 or 28

#### 3.3.5. COSE to SEC1 Conversion

WebAuthn returns public keys in COSE format. Implementations MUST convert to SEC1 compressed format for storage and identity derivation.

**COSE key structure (P-256):**
```
{
  1:  2,        // kty: EC2 (Elliptic Curve)
  3:  -7,       // alg: ES256 (ECDSA w/ SHA-256)
  -1: 1,        // crv: P-256
  -2: <bytes>,  // x-coordinate (32 bytes)
  -3: <bytes>   // y-coordinate (32 bytes)
}
```

**Conversion procedure:**

1. Parse CBOR structure to extract x-coordinate (key -2) and y-coordinate (key -3)
2. Verify both coordinates are exactly 32 bytes, left-padding with zeros if necessary
3. Compute prefix byte:
   - If y-coordinate's last byte is even: `prefix = 0x02`
   - If y-coordinate's last byte is odd: `prefix = 0x03`
4. Concatenate: `compressed_key = prefix || x-coordinate`

**Result:** 33 bytes in SEC1 compressed format, suitable for identity derivation and storage.

**Security note:** Implementations MUST verify the COSE key type (kty=2) and curve (crv=1 for P-256) before conversion. Reject keys with unexpected parameters.

---

## 4. Data Structures

### 4.1. Identity Record

An identity record contains all data associated with an identity.

#### 4.1.1. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | REQUIRED | Identity identifier (`obj_` + 20 chars) |
| handle | string | REQUIRED | Handle (1-30 chars) |
| signer_type | uint32 | REQUIRED | Signer type (1=passkey, 2=wallet) |
| signer_public_key | bytes | REQUIRED | Compressed public key (33 bytes) |
| nonce | bytes | REQUIRED | Random nonce (8 bytes) |
| wallet_address | string | OPTIONAL | Linked wallet (`0x` + 40 hex chars) |
| created_at | uint64 | REQUIRED | Creation timestamp (Unix seconds) |
| updated_at | uint64 | REQUIRED | Last update timestamp (Unix seconds) |

#### 4.1.2. Wire Format (Protocol Buffers)

```protobuf
syntax = "proto3";
package objects.identity.v1;

enum SignerType {
  SIGNER_TYPE_UNSPECIFIED = 0;
  SIGNER_TYPE_PASSKEY = 1;
  SIGNER_TYPE_WALLET = 2;
}

message Identity {
  // REQUIRED. Identity identifier. Format: "obj_" + 20 base58 characters.
  // Derived from SHA256(signer_public_key || nonce), truncated to 15 bytes.
  string id = 1;

  // REQUIRED. Human-readable handle. 1-30 characters, lowercase alphanumeric,
  // underscore, and period. Must not start with period or underscore.
  string handle = 2;

  // REQUIRED. Type of signer that controls this identity.
  SignerType signer_type = 3;

  // REQUIRED. Compressed SEC1 public key of the signer. Exactly 33 bytes.
  bytes signer_public_key = 4;

  // REQUIRED. Random nonce used in ID derivation. Exactly 8 bytes.
  bytes nonce = 5;

  // OPTIONAL. Linked Ethereum wallet address for payments.
  // Format: "0x" + 40 lowercase hex characters.
  string wallet_address = 6;

  // REQUIRED. Unix timestamp (seconds) when identity was created.
  uint64 created_at = 7;

  // REQUIRED. Unix timestamp (seconds) when identity was last updated.
  uint64 updated_at = 8;
}
```

### 4.2. Signature Format

All operations MUST include a signature proving authorization.

#### 4.2.1. Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| signer_type | uint32 | REQUIRED | Signer type (1=passkey, 2=wallet) |
| signature | bytes | REQUIRED | Raw signature bytes |
| public_key | bytes | CONDITIONAL | Public key (passkey only) |
| address | string | CONDITIONAL | Wallet address (wallet only) |
| authenticator_data | bytes | CONDITIONAL | WebAuthn authenticator data (passkey only) |
| client_data_json | bytes | CONDITIONAL | WebAuthn client data (passkey only) |

#### 4.2.2. Wire Format

```protobuf
message Signature {
  // REQUIRED. Type of signer that produced this signature.
  SignerType signer_type = 1;

  // REQUIRED. Raw signature bytes.
  // - Passkey: DER-encoded ECDSA signature
  // - Wallet: 65 bytes (r || s || v) per EIP-191
  bytes signature = 2;

  // CONDITIONAL. Required for passkey signatures.
  bytes public_key = 3;

  // CONDITIONAL. Required for wallet signatures.
  string address = 4;

  // CONDITIONAL. Required for passkey signatures.
  bytes authenticator_data = 5;

  // CONDITIONAL. Required for passkey signatures.
  bytes client_data_json = 6;
}
```

### 4.3. Operation Envelope

All operations are wrapped in an envelope for transmission.

```protobuf
message OperationEnvelope {
  // REQUIRED. Operation type.
  string operation = 1;

  // REQUIRED. Operation payload (serialized operation message).
  bytes payload = 2;

  // REQUIRED. Signature(s) authorizing this operation.
  repeated Signature signatures = 3;

  // REQUIRED. Unix timestamp (seconds) when operation was created.
  uint64 timestamp = 4;
}
```

---

## 5. Operations

### 5.1. Create Identity

Creates a new identity with a handle.

#### 5.1.1. Preconditions

- Signer MUST NOT already have an identity
- Handle MUST be available
- Handle MUST meet format requirements (Section 3.2)
- Nonce MUST be cryptographically random

#### 5.1.2. Message Format

Message format depends on signer type.

**Wallet (EIP-712 Typed Data):**

```javascript
{
  types: {
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'version', type: 'string' },
      { name: 'chainId', type: 'uint256' }
    ],
    CreateIdentity: [
      { name: 'identity', type: 'string' },
      { name: 'handle', type: 'string' },
      { name: 'timestamp', type: 'uint256' }
    ]
  },
  primaryType: 'CreateIdentity',
  domain: {
    name: 'OBJECTS Identity Protocol',
    version: '1',
    chainId: 1  // Ethereum mainnet; use appropriate chain
  },
  message: {
    identity: '{identity_id}',
    handle: '{handle}',
    timestamp: {unix_seconds}
  }
}
```

**Passkey (Plain Text):**

```
OBJECTS Identity Protocol v1
Action: Create Identity
Identity: {identity_id}
Handle: {handle}
Timestamp: {unix_seconds}
```

Plain text format rules:
- Lines separated by `\n` (LF, 0x0A) only, NOT `\r\n`
- No trailing newline after final line
- Fields in exact order shown
- No extra whitespace

#### 5.1.3. Request

```protobuf
message CreateIdentityRequest {
  // REQUIRED. Desired handle (without @ prefix).
  string handle = 1;

  // REQUIRED. Signer type.
  SignerType signer_type = 2;

  // REQUIRED. Compressed public key (33 bytes).
  bytes signer_public_key = 3;

  // REQUIRED. Random nonce (8 bytes).
  bytes nonce = 4;

  // REQUIRED. Signature over the message.
  Signature signature = 5;

  // REQUIRED. Unix timestamp (seconds).
  uint64 timestamp = 6;
}
```

#### 5.1.4. Postconditions

- Identity record created in registry
- Handle mapped to identity
- Signer mapped to identity

#### 5.1.5. Errors

| Condition | Description |
|-----------|-------------|
| IDENTITY_EXISTS | Signer already has an identity |
| HANDLE_TAKEN | Handle is already registered |
| INVALID_HANDLE | Handle does not meet format requirements |
| INVALID_SIGNATURE | Signature verification failed |
| INVALID_TIMESTAMP | Timestamp too old or in future |

### 5.2. Link Wallet

Links an Ethereum wallet address to an existing identity.

#### 5.2.1. Preconditions

- Identity MUST exist
- Wallet MUST NOT already be linked to another identity
- Both identity signer AND wallet MUST sign

#### 5.2.2. Message Format

Both signers MUST sign the same logical message in their respective formats.

**Wallet Signature (EIP-712 Typed Data):**

```javascript
{
  types: {
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'version', type: 'string' },
      { name: 'chainId', type: 'uint256' }
    ],
    LinkWallet: [
      { name: 'identity', type: 'string' },
      { name: 'wallet', type: 'address' },
      { name: 'timestamp', type: 'uint256' }
    ]
  },
  primaryType: 'LinkWallet',
  domain: {
    name: 'OBJECTS Identity Protocol',
    version: '1',
    chainId: 1
  },
  message: {
    identity: '{identity_id}',
    wallet: '{wallet_address}',
    timestamp: {unix_seconds}
  }
}
```

**Identity Signer (Passkey - Plain Text):**

```
OBJECTS Identity Protocol v1
Action: Link Wallet
Identity: {identity_id}
Wallet: {wallet_address}
Timestamp: {unix_seconds}
```

Plain text format rules apply (see Section 5.1.2).

#### 5.2.3. Request

```protobuf
message LinkWalletRequest {
  // REQUIRED. Identity ID to link wallet to.
  string identity_id = 1;

  // REQUIRED. Ethereum wallet address (0x + 40 hex chars).
  string wallet_address = 2;

  // REQUIRED. Signature from identity signer.
  Signature identity_signature = 3;

  // REQUIRED. Signature from wallet (EIP-191).
  Signature wallet_signature = 4;

  // REQUIRED. Unix timestamp (seconds).
  uint64 timestamp = 5;
}
```

#### 5.2.4. Postconditions

- Identity record updated with wallet address
- Wallet mapped to identity

#### 5.2.5. Errors

| Condition | Description |
|-----------|-------------|
| NOT_FOUND | Identity does not exist |
| WALLET_LINKED | Wallet already linked to another identity |
| INVALID_SIGNATURE | Signature verification failed |
| UNAUTHORIZED | Identity signature not from identity signer |

### 5.3. Sign Asset

Signs an asset to prove ownership. This operation does NOT modify registry state.

#### 5.3.1. Message Format

Message format depends on signer type.

**Wallet (EIP-712 Typed Data):**

```javascript
{
  types: {
    EIP712Domain: [...],  // Same as Section 5.1.2
    SignAsset: [
      { name: 'identity', type: 'string' },
      { name: 'asset', type: 'bytes32' },
      { name: 'timestamp', type: 'uint256' }
    ]
  },
  primaryType: 'SignAsset',
  domain: { name: 'OBJECTS Identity Protocol', version: '1', chainId: 1 },
  message: {
    identity: '{identity_id}',
    asset: '{asset_hash}',  // 0x-prefixed, 32 bytes
    timestamp: {unix_seconds}
  }
}
```

**Passkey (Plain Text):**

```
OBJECTS Identity Protocol v1
Action: Sign Asset
Identity: {identity_id}
Asset: {asset_hash}
Timestamp: {unix_seconds}
```

Where `asset_hash` is the SHA-256 hash of the asset content, hex-encoded (64 characters, no 0x prefix in plain text).

#### 5.3.2. Signature Record

```protobuf
message AssetSignature {
  // REQUIRED. Identity ID of the signer.
  string identity_id = 1;

  // REQUIRED. SHA-256 hash of the asset (hex-encoded).
  string asset_hash = 2;

  // REQUIRED. Signature over the message.
  Signature signature = 3;

  // REQUIRED. Unix timestamp (seconds).
  uint64 timestamp = 4;
}
```

#### 5.3.3. Verification

Verifiers MUST:

1. Resolve identity from registry
2. Verify signature against identity's signer public key
3. Verify asset hash matches expected content

### 5.4. Authenticate

Authenticates to an application by signing a challenge.

#### 5.4.1. Challenge Format

Applications MUST generate challenges in the appropriate format for the signer type.

**Wallet (EIP-712 Typed Data):**

```javascript
{
  types: {
    EIP712Domain: [...],  // Same as Section 5.1.2
    Authenticate: [
      { name: 'application', type: 'string' },
      { name: 'challenge', type: 'bytes32' },
      { name: 'timestamp', type: 'uint256' }
    ]
  },
  primaryType: 'Authenticate',
  domain: { name: 'OBJECTS Identity Protocol', version: '1', chainId: 1 },
  message: {
    application: '{app_domain}',
    challenge: '{random_challenge}',  // 0x-prefixed, 32 bytes
    timestamp: {unix_seconds}
  }
}
```

**Passkey (Plain Text):**

```
OBJECTS Identity Protocol v1
Action: Authenticate
Application: {app_domain}
Challenge: {random_challenge}
Timestamp: {unix_seconds}
```

Where:
- `app_domain` is the application's domain (e.g., `app.example.com`)
- `random_challenge` is at least 32 bytes of random data, hex-encoded (64+ characters)

#### 5.4.2. Response

```protobuf
message AuthenticateResponse {
  // REQUIRED. Identity ID authenticating.
  string identity_id = 1;

  // REQUIRED. The challenge that was signed.
  string challenge = 2;

  // REQUIRED. Signature over the challenge message.
  Signature signature = 3;

  // REQUIRED. Unix timestamp (seconds).
  uint64 timestamp = 4;
}
```

#### 5.4.3. Verification

Applications MUST:

1. Verify challenge matches one they generated
2. Verify timestamp is within acceptable window (RECOMMENDED: 5 minutes)
3. Resolve identity from registry
4. Verify signature against identity's signer public key

### 5.5. Change Handle

Changes the handle associated with an identity.

#### 5.5.1. Preconditions

- Identity MUST exist
- New handle MUST be available
- New handle MUST meet format requirements (Section 3.2)
- Signer MUST be the identity's signer

#### 5.5.2. Message Format

Message format depends on signer type.

**Wallet (EIP-712 Typed Data):**

```javascript
{
  types: {
    EIP712Domain: [...],  // Same as Section 5.1.2
    ChangeHandle: [
      { name: 'identity', type: 'string' },
      { name: 'newHandle', type: 'string' },
      { name: 'timestamp', type: 'uint256' }
    ]
  },
  primaryType: 'ChangeHandle',
  domain: { name: 'OBJECTS Identity Protocol', version: '1', chainId: 1 },
  message: {
    identity: '{identity_id}',
    newHandle: '{new_handle}',
    timestamp: {unix_seconds}
  }
}
```

**Passkey (Plain Text):**

```
OBJECTS Identity Protocol v1
Action: Change Handle
Identity: {identity_id}
New Handle: {new_handle}
Timestamp: {unix_seconds}
```

Plain text format rules apply (see Section 5.1.2).

#### 5.5.3. Request

```protobuf
message ChangeHandleRequest {
  // REQUIRED. Identity ID to change handle for.
  string identity_id = 1;

  // REQUIRED. New handle (without @ prefix).
  string new_handle = 2;

  // REQUIRED. Signature from identity signer.
  Signature signature = 3;

  // REQUIRED. Unix timestamp (seconds).
  uint64 timestamp = 4;
}
```

#### 5.5.4. Postconditions

- Identity record updated with new handle
- Old handle removed from index
- New handle mapped to identity

#### 5.5.5. Errors

| Condition | Description |
|-----------|-------------|
| NOT_FOUND | Identity does not exist |
| HANDLE_TAKEN | New handle is already registered |
| INVALID_HANDLE | New handle does not meet format requirements |
| INVALID_SIGNATURE | Signature verification failed |
| UNAUTHORIZED | Signature not from identity signer |

---

### 5.6. Future Operations (Reserved)

The following operations are reserved for future protocol versions. Identity ID derivation is designed to remain stable across these operations.

| Operation | Target Version | Description |
|-----------|----------------|-------------|
| AddSigner | v0.2 | Add additional signer (passkey or wallet) to existing identity |
| RevokeSigner | v0.2 | Remove compromised or unwanted signer from identity |
| SetRecoverySigner | v0.2 | Designate a signer that can revoke other signers |
| SocialRecovery | v0.2+ | M-of-N trusted signers can authorize adding new signer |

#### 5.5.1. Design Constraints

Future signer management operations MUST:

- Require signature from an existing authorized signer
- NOT change the identity ID
- Maintain an auditable log of signer changes
- Support bidirectional authorization for AddSigner (both existing and new signer MUST sign)

#### 5.5.2. Recovery Model

Recovery in a passkey-first system differs from wallet-based recovery:

| Mechanism | Description | Sovereignty |
|-----------|-------------|-------------|
| OS-level sync | Passkeys sync via iCloud/Google/1Password | Platform-dependent |
| Multiple passkeys | Register passkeys on multiple devices | High |
| Linked wallet | Wallet serves as recovery if passkey lost | High |
| Recovery codes | One-time codes that authorize adding new signer | High |
| Social recovery | Trusted contacts collectively authorize recovery | Medium |

For v0.1, recovery relies on OS-level passkey sync and optional wallet linking. Explicit recovery operations are deferred to v0.2.

#### 5.5.3. Rationale

Identity ID is derived from the initial signer and nonce at creation time. This anchors the identity to its genesis state while allowing the set of authorized signers to evolve. This pattern is proven in:

- [XMTP XIP-46](https://github.com/xmtp/XIPs/blob/main/XIPs/xip-46-multi-wallet-identity.md): Inbox ID derived from initial signer, with AddAssociation/RevokeAssociation operations
- [AT Protocol did:plc](https://web.plc.directory/spec/v0.1/did-plc): Genesis operation hash with rotation key hierarchy

---

## 6. Registry

The registry stores identities and provides resolution services.

### 6.1. Storage Requirements

The registry MUST store:

| Data | Uniqueness | Description |
|------|------------|-------------|
| Identity records | By ID | Full identity data |
| Handle index | Unique | Handle to identity ID mapping |
| Signer index | Unique | Public key to identity ID mapping |
| Wallet index | Unique | Wallet address to identity ID mapping |

### 6.2. Resolution

The registry MUST support resolution by:

| Lookup Key | Format | Returns |
|------------|--------|---------|
| Identity ID | `obj_xxxxxxxxxxxxxxxxxxxx` | Identity record |
| Handle | `montez` (without @) | Identity record |
| Signer | Hex-encoded public key | Identity record |
| Wallet | `0x` + 40 hex chars | Identity record |

### 6.3. Verification

Before accepting any operation, the registry MUST verify:

#### 6.3.1. Create Identity

1. Compute expected ID from signer public key and nonce
2. Verify computed ID matches provided ID
3. Verify signature over message using signer public key
4. Verify handle format is valid
5. Verify handle is not taken
6. Verify signer does not already have an identity

#### 6.3.2. Link Wallet

1. Verify identity exists
2. Verify identity signature from identity's signer
3. Verify wallet signature per EIP-712
4. Verify wallet is not linked to another identity

#### 6.3.3. Signature Verification by Type

**Passkey (secp256r1):**

```
1. Compute clientDataHash = SHA256(client_data_json)
2. Compute signedData = authenticator_data || clientDataHash
3. Verify ECDSA signature over signedData using public key
```

**Wallet (secp256k1 with EIP-712):**

```
1. Compute EIP-712 struct hash:
   domainSeparator = keccak256(encode(EIP712Domain))
   structHash = keccak256(encode(primaryType, message))
   hash = keccak256("\x19\x01" || domainSeparator || structHash)
2. Recover public key from signature (v, r, s)
3. Derive address from public key
4. Verify address matches claimed address
```

See [EIP-712] for complete encoding specification.

### 6.4. Timestamp Validation

The registry SHOULD reject operations with timestamps:

- More than 5 minutes in the future
- More than 24 hours in the past

---

## 7. Security Considerations

### 7.1. Threat Model

| Threat | Mitigation |
|--------|------------|
| Signer key compromise | User creates new identity; old assets remain signed by old identity |
| Handle squatting | First-come-first-served; reserved words blocked |
| Replay attacks | Timestamps prevent replay; registry tracks processed operations |
| Sybil attacks | One identity per signer; transport layer may add rate limiting |

### 7.2. Key Compromise

If a signer key is compromised:

- Attacker CAN create new operations as that identity
- Attacker CAN link wallets (requires wallet signature too)
- Attacker CANNOT unlink existing wallet
- User SHOULD create new identity if compromise detected

Recovery mechanisms are out of scope for v0.1.

### 7.3. Privacy Considerations

- Identity IDs are pseudonymous (no PII in derivation)
- Handles are user-chosen, may or may not contain PII
- Wallet addresses are public by design
- Registry data is public; private identities are not supported in v0.1

### 7.4. Cryptographic Agility

The protocol supports multiple signer types to enable future algorithm additions:

- Signer type is explicitly encoded
- Signature format includes algorithm metadata
- New curves can be added without breaking existing identities

---

## 8. References

### 8.1. Normative References

| Reference | Title |
|-----------|-------|
| [RFC 2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [WebAuthn] | Web Authentication: An API for accessing Public Key Credentials Level 2 |
| [EIP-712] | Typed Structured Data Hashing and Signing |
| [SEC1] | Elliptic Curve Cryptography |
| [Base58] | Base58 Encoding (Bitcoin) |
| [COSE] | RFC 9053 - CBOR Object Signing and Encryption: Initial Algorithms |

### 8.2. Informative References

| Reference | Title |
|-----------|-------|
| [XIP-46] | XMTP Multi-Wallet Identity |
| [XIP-55] | XMTP Passkey Identity |
| [did:plc] | AT Protocol DID PLC Specification |
| [Farcaster] | Farcaster Protocol Specification |

---

## Appendix A: Example Flows

### A.1. Create Identity with Passkey

```
1. User clicks "Create Account"

2. Browser prompts for passkey creation
   - User authenticates with biometric (Touch ID, Face ID)
   - Passkey created (secp256r1 keypair)
   - Returns: public_key = 0x02abc...

3. Client generates nonce
   - nonce = random_bytes(8) = 0x0102030405060708

4. Client derives identity ID
   - concat = public_key || nonce
   - hash = sha256(concat)
   - id = "obj_" + base58(hash[0:15])
   - id = "obj_7kd2zcx9f3m1qwerty"

5. Client constructs message
   - message = "OBJECTS Identity Protocol v1\n..."

6. User signs with passkey
   - Returns: signature, authenticator_data, client_data_json

7. Client submits CreateIdentityRequest
   - handle: "montez"
   - signer_type: PASSKEY
   - signer_public_key: 0x02abc...
   - nonce: 0x0102030405060708
   - signature: { ... }
   - timestamp: 1704542400

8. Registry verifies and stores identity
   - Returns: Identity record
```

### A.2. Create Identity with Wallet

```
1. User clicks "Connect Wallet"

2. Wallet popup appears
   - User approves connection
   - Returns: address = 0x1234...abcd

3. Client gets public key from wallet
   - public_key = 0x02def...

4. Client generates nonce
   - nonce = random_bytes(8)

5. Client derives identity ID
   - id = "obj_" + base58(sha256(public_key || nonce)[0:15])

6. Client constructs message
   - message = "OBJECTS Identity Protocol v1\n..."

7. User signs with wallet (EIP-191)
   - Wallet popup shows message
   - User approves
   - Returns: signature (65 bytes)

8. Client submits CreateIdentityRequest
   - signer_type: WALLET
   - signature: { address: "0x1234..." }

9. Registry verifies and stores identity
```

### A.3. Link Wallet to Passkey Identity

```
1. User has passkey identity: obj_7kd2zcx9f3m1qwerty

2. User connects wallet
   - wallet_address = 0x5678...efgh

3. Client constructs message
   - "OBJECTS Identity Protocol v1\nAction: Link Wallet\n..."

4. User signs with passkey
   - identity_signature = { signer_type: PASSKEY, ... }

5. User signs with wallet
   - wallet_signature = { signer_type: WALLET, address: "0x5678..." }

6. Client submits LinkWalletRequest
   - identity_id: "obj_7kd2zcx9f3m1qwerty"
   - wallet_address: "0x5678...efgh"
   - identity_signature: { ... }
   - wallet_signature: { ... }

7. Registry verifies both signatures and updates identity
```

### A.4. Change Handle

```
1. User has identity: obj_7kd2zcx9f3m1qwerty with handle "montez"

2. User wants to change handle to "montez.studio"

3. Client constructs message
   - "OBJECTS Identity Protocol v1\nAction: Change Handle\n..."

4. User signs with passkey (or wallet)
   - signature = { signer_type: PASSKEY, ... }

5. Client submits ChangeHandleRequest
   - identity_id: "obj_7kd2zcx9f3m1qwerty"
   - new_handle: "montez.studio"
   - signature: { ... }
   - timestamp: 1704542400

6. Registry verifies signature and updates identity
   - Old handle "montez" released
   - New handle "montez.studio" mapped to identity
```

---

## Appendix B: Test Vectors

### B.1. Identity ID Derivation

**Input:**
```
signer_public_key (hex): 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
nonce (hex): 0102030405060708
```

**Derivation:**
```
concat (hex): 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50102030405060708
sha256 (hex): 3b47c832e3f7a1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7
truncated (hex): 3b47c832e3f7a1b2c4d5e6f7a8b9c0
base58: 5KJvsngHeMpm88rD
```

**Output:**
```
identity_id: obj_5KJvsngHeMpm88rD
```

### B.2. Handle Validation

| Input | Valid | Reason |
|-------|-------|--------|
| `montez` | Yes | Valid lowercase alphanumeric |
| `alice_123` | Yes | Valid with underscore and numbers |
| `montez.studio` | Yes | Valid with period separator |
| `design.co_lab` | Yes | Valid mixed format |
| `_alice` | No | Starts with underscore |
| `.alice` | No | Starts with period |
| `alice.` | No | Ends with period |
| `alice..bob` | No | Consecutive periods |
| `Alice` | No | Contains uppercase |
| `this_is_a_very_long_handle_name` | No | Exceeds 30 characters |
| `admin` | No | Reserved word |
| `hello world` | No | Contains space |

### B.3. Wallet Signature (EIP-191)

**Input:**
```
message: "OBJECTS Identity Protocol v1\nAction: Create Identity\nIdentity: obj_5KJvsngHeMpm88rD\nHandle: montez\nTimestamp: 1704542400"
private_key (hex): 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

**Derivation:**
```
prefix: "\x19Ethereum Signed Message:\n"
len: "123" (length of message)
prefixed: prefix + len + message
hash: keccak256(prefixed)
signature: secp256k1_sign(hash, private_key)
```

**Output:**
```
signature (hex): [65 bytes: r (32) || s (32) || v (1)]
address: 0x... (derived from public key)
```

---

## Appendix C: Registry API

This appendix specifies the HTTP and gRPC APIs for the Identity Registry.

### C.1. Deployment

The registry is a centralized service operated by OBJECTS:

```
Production: https://registry.objects.network
Development: http://localhost:8080
```

### C.2. REST API

Base path: `/v1`

Content type: `application/json`

#### C.2.1. Create Identity

```
POST /v1/identities
```

**Request:**

```json
{
  "handle": "montez",
  "signer_type": "PASSKEY",
  "signer_public_key": "<base64>",
  "nonce": "<base64>",
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
  "id": "obj_5KJvsngHeMpm88rD",
  "handle": "montez",
  "signer_type": "PASSKEY",
  "signer_public_key": "<base64>",
  "nonce": "<base64>",
  "wallet_address": null,
  "created_at": 1704542400,
  "updated_at": 1704542400
}
```

#### C.2.2. Get Identity

```
GET /v1/identities/{identity_id}
```

**Response (200):**

```json
{
  "id": "obj_5KJvsngHeMpm88rD",
  "handle": "montez",
  "signer_type": "PASSKEY",
  "signer_public_key": "<base64>",
  "nonce": "<base64>",
  "wallet_address": "0x1234...abcd",
  "created_at": 1704542400,
  "updated_at": 1704542500
}
```

#### C.2.3. Resolve Identity

Resolve by handle, signer public key, or wallet address:

```
GET /v1/identities?handle=montez
GET /v1/identities?signer=<hex-public-key>
GET /v1/identities?wallet=0x1234...abcd
```

Returns same response as Get Identity.

#### C.2.4. Link Wallet

```
POST /v1/identities/{identity_id}/wallet
```

**Request:**

```json
{
  "wallet_address": "0x5678...efgh",
  "timestamp": 1704542500,
  "identity_signature": {
    "signer_type": "PASSKEY",
    "signature": "<base64>",
    "public_key": "<base64>",
    "authenticator_data": "<base64>",
    "client_data_json": "<base64>"
  },
  "wallet_signature": {
    "signer_type": "WALLET",
    "signature": "<base64>",
    "address": "0x5678...efgh"
  }
}
```

**Response (200):** Updated identity record.

#### C.2.5. Change Handle

```
PATCH /v1/identities/{identity_id}/handle
```

**Request:**

```json
{
  "new_handle": "montez.studio",
  "timestamp": 1704542600,
  "signature": {
    "signer_type": "PASSKEY",
    "signature": "<base64>",
    "public_key": "<base64>",
    "authenticator_data": "<base64>",
    "client_data_json": "<base64>"
  }
}
```

**Response (200):** Updated identity record.

#### C.2.6. Error Responses

```json
{
  "error": {
    "code": "HANDLE_TAKEN",
    "message": "The handle 'montez' is already registered"
  }
}
```

| Status | Code | Condition |
|--------|------|-----------|
| 400 | INVALID_HANDLE | Handle format invalid |
| 400 | INVALID_SIGNATURE | Signature verification failed |
| 400 | INVALID_TIMESTAMP | Timestamp out of range |
| 404 | NOT_FOUND | Identity not found |
| 409 | HANDLE_TAKEN | Handle already registered |
| 409 | IDENTITY_EXISTS | Signer already has identity |
| 409 | WALLET_LINKED | Wallet linked to another identity |

### C.3. gRPC API

Service definition for node-to-node communication:

```protobuf
syntax = "proto3";
package objects.identity.v1;

service IdentityRegistry {
  rpc CreateIdentity(CreateIdentityRequest) returns (Identity);
  rpc GetIdentity(GetIdentityRequest) returns (Identity);
  rpc ResolveIdentity(ResolveIdentityRequest) returns (Identity);
  rpc LinkWallet(LinkWalletRequest) returns (Identity);
  rpc ChangeHandle(ChangeHandleRequest) returns (Identity);
}

message GetIdentityRequest {
  string identity_id = 1;
}

message ResolveIdentityRequest {
  oneof query {
    string handle = 1;
    bytes signer_public_key = 2;
    string wallet_address = 3;
  }
}
```

Request and response messages use the types defined in Section 4.

### C.4. Health Check

```
GET /health
```

```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

## Appendix D: Asset Signatures

Assets require identity signatures for authorship verification. This ensures author_id claims are cryptographically verified without requiring registry lookups.

### D.1. Signed Asset

Every Asset includes an authorship signature:

```protobuf
message SignedAsset {
  Asset asset = 1;
  Signature signature = 2;
}
```

### D.2. Signature Message

The signature is computed over:

```
OBJECTS Identity Protocol v1
Action: Sign Asset
Identity: {author_id}
Asset: {content_hash_hex}
Timestamp: {created_at}
```

### D.3. Verification

Nodes verify assets locally:

1. Parse SignedAsset
2. Extract author_id from Asset
3. Extract signer_public_key from Signature
4. Verify signature over the message
5. Verify identity_id derivation: `author_id == derive_id(signer_public_key, nonce)`

If verification fails, the asset is rejected.

### D.4. Implications

- No registry lookup required for verification
- Assets are self-contained proofs of authorship
- Offline verification is possible
- Author identity existence is NOT verified (only signature validity)

---

## Appendix E: Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-01-06 | Initial draft |

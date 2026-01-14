-- Create identities table for OBJECTS Protocol registry
-- RFC-001: Identity Protocol

CREATE TABLE identities (
    -- Primary key: obj_ + 19-21 base58 characters
    id VARCHAR(25) PRIMARY KEY,

    -- Handle: 1-30 chars, validated by application
    handle VARCHAR(30) NOT NULL,

    -- Signer type: 1=PASSKEY, 2=WALLET
    signer_type SMALLINT NOT NULL,

    -- Compressed SEC1 public key (33 bytes)
    signer_public_key BYTEA NOT NULL,

    -- Nonce used in identity derivation (8 bytes)
    nonce BYTEA NOT NULL,

    -- Linked wallet address (0x + 40 hex), nullable
    wallet_address VARCHAR(42),

    -- Unix timestamps in seconds
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,

    -- Constraints
    CONSTRAINT valid_id CHECK (id ~ '^obj_[1-9A-HJ-NP-Za-km-z]{19,21}$'),
    CONSTRAINT valid_signer_type CHECK (signer_type IN (1, 2)),
    CONSTRAINT valid_public_key_len CHECK (octet_length(signer_public_key) = 33),
    CONSTRAINT valid_nonce_len CHECK (octet_length(nonce) = 8),
    CONSTRAINT valid_wallet_address CHECK (
        wallet_address IS NULL OR wallet_address ~ '^0x[a-fA-F0-9]{40}$'
    )
);

-- Handle uniqueness (case-insensitive)
CREATE UNIQUE INDEX idx_identities_handle_lower ON identities (LOWER(handle));

-- Signer uniqueness (one identity per signer public key)
CREATE UNIQUE INDEX idx_identities_signer ON identities (signer_public_key);

-- Wallet uniqueness (one identity per wallet, case-insensitive, excluding nulls)
CREATE UNIQUE INDEX idx_identities_wallet ON identities (LOWER(wallet_address))
    WHERE wallet_address IS NOT NULL;

-- Index for timestamp-based queries (DESC ordering for recent-first queries)
-- This index supports potential future admin endpoints that list recent identities,
-- such as "GET /admin/identities?limit=100" for monitoring and moderation.
-- The DESC ordering optimizes queries that want newest identities first.
CREATE INDEX idx_identities_created_at ON identities (created_at DESC);

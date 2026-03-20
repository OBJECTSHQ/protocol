-- Create identities table for OBJECTS Protocol registry
-- RFC-001: Identity Protocol

CREATE TABLE IF NOT EXISTS identities (
    -- Primary key: obj_ + 19-21 base58 characters
    id VARCHAR(25) PRIMARY KEY,

    -- Handle: 1-30 chars, validated by application
    handle VARCHAR(30) NOT NULL,

    -- Signer type: 1=PASSKEY, 2=WALLET
    signer_type SMALLINT NOT NULL CHECK (signer_type IN (1, 2)),

    -- Compressed SEC1 public key (33 bytes)
    signer_public_key BLOB NOT NULL CHECK (length(signer_public_key) = 33),

    -- Nonce used in identity derivation (8 bytes)
    nonce BLOB NOT NULL CHECK (length(nonce) = 8),

    -- Linked wallet address (0x + 40 hex), nullable
    wallet_address VARCHAR(42),

    -- Unix timestamps in seconds
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- Handle uniqueness (SQLite COLLATE NOCASE for case-insensitive)
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_handle_lower ON identities (handle COLLATE NOCASE);

-- Signer uniqueness (one identity per signer public key)
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_signer ON identities (signer_public_key);

-- Wallet uniqueness (one identity per wallet, case-insensitive, excluding nulls)
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_wallet ON identities (wallet_address COLLATE NOCASE)
    WHERE wallet_address IS NOT NULL;

-- Index for timestamp-based queries (DESC ordering for recent-first queries)
CREATE INDEX IF NOT EXISTS idx_identities_created_at ON identities (created_at DESC);

//! Database queries for OBJECTS Registry.

use sqlx::PgPool;

use crate::db::models::IdentityRow;
use crate::error::{RegistryError, Result};

/// Insert a new identity record.
///
/// Returns the inserted row on success.
/// Returns `HandleTaken` or `SignerExists` on unique constraint violation.
///
/// # Atomicity
/// This function uses a single INSERT statement, which is inherently atomic.
/// A database transaction is not needed because:
/// - The operation is a single statement (INSERT into one table)
/// - Either the entire insert succeeds or fails completely
/// - Unique constraints are enforced atomically by PostgreSQL
/// - No related tables need to be updated in the current schema
///
/// If future schema changes add related tables (e.g., audit logs, identity history),
/// this function should be updated to use a transaction via `pool.begin()`.
pub async fn insert_identity(pool: &PgPool, row: &IdentityRow) -> Result<IdentityRow> {
    let result = sqlx::query_as::<_, IdentityRow>(
        r#"
        INSERT INTO identities (
            id, handle, signer_type, signer_public_key, nonce,
            wallet_address, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(&row.id)
    .bind(&row.handle)
    .bind(row.signer_type)
    .bind(&row.signer_public_key)
    .bind(&row.nonce)
    .bind(&row.wallet_address)
    .bind(row.created_at)
    .bind(row.updated_at)
    .fetch_one(pool)
    .await;

    match result {
        Ok(row) => Ok(row),
        Err(sqlx::Error::Database(db_err)) => {
            // Check for unique constraint violations
            if let Some(constraint) = db_err.constraint() {
                if constraint.contains("handle") {
                    return Err(RegistryError::HandleTaken(row.handle.clone()));
                }
                if constraint.contains("signer") {
                    return Err(RegistryError::SignerExists);
                }
            }
            Err(RegistryError::Database(sqlx::Error::Database(db_err)))
        }
        Err(e) => Err(RegistryError::Database(e)),
    }
}

/// Get an identity by ID.
pub async fn get_identity_by_id(pool: &PgPool, id: &str) -> Result<IdentityRow> {
    sqlx::query_as::<_, IdentityRow>("SELECT * FROM identities WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RegistryError::NotFound(id.to_string()))
}

/// Get an identity by handle (case-insensitive).
pub async fn get_identity_by_handle(pool: &PgPool, handle: &str) -> Result<IdentityRow> {
    sqlx::query_as::<_, IdentityRow>("SELECT * FROM identities WHERE LOWER(handle) = LOWER($1)")
        .bind(handle)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RegistryError::NotFound(format!("handle:{}", handle)))
}

/// Get an identity by signer public key.
pub async fn get_identity_by_signer(pool: &PgPool, public_key: &[u8]) -> Result<IdentityRow> {
    sqlx::query_as::<_, IdentityRow>("SELECT * FROM identities WHERE signer_public_key = $1")
        .bind(public_key)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RegistryError::NotFound("signer".to_string()))
}

/// Get an identity by wallet address.
pub async fn get_identity_by_wallet(pool: &PgPool, wallet_address: &str) -> Result<IdentityRow> {
    sqlx::query_as::<_, IdentityRow>(
        "SELECT * FROM identities WHERE LOWER(wallet_address) = LOWER($1)",
    )
    .bind(wallet_address)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| RegistryError::NotFound(format!("wallet:{}", wallet_address)))
}

/// Update an identity's wallet address.
///
/// Returns `WalletLinked` if the wallet is already linked to another identity.
pub async fn update_identity_wallet(
    pool: &PgPool,
    id: &str,
    wallet_address: &str,
    updated_at: i64,
) -> Result<IdentityRow> {
    let result = sqlx::query_as::<_, IdentityRow>(
        r#"
        UPDATE identities
        SET wallet_address = $1, updated_at = $2
        WHERE id = $3
        RETURNING *
        "#,
    )
    .bind(wallet_address)
    .bind(updated_at)
    .bind(id)
    .fetch_one(pool)
    .await;

    match result {
        Ok(row) => Ok(row),
        Err(sqlx::Error::Database(db_err)) => {
            if let Some(constraint) = db_err.constraint()
                && constraint.contains("wallet")
            {
                return Err(RegistryError::WalletLinked(wallet_address.to_string()));
            }
            Err(RegistryError::Database(sqlx::Error::Database(db_err)))
        }
        Err(sqlx::Error::RowNotFound) => Err(RegistryError::NotFound(id.to_string())),
        Err(e) => Err(RegistryError::Database(e)),
    }
}

/// Update an identity's handle.
///
/// Returns `HandleTaken` if the new handle is already in use.
pub async fn update_identity_handle(
    pool: &PgPool,
    id: &str,
    new_handle: &str,
    updated_at: i64,
) -> Result<IdentityRow> {
    let result = sqlx::query_as::<_, IdentityRow>(
        r#"
        UPDATE identities
        SET handle = $1, updated_at = $2
        WHERE id = $3
        RETURNING *
        "#,
    )
    .bind(new_handle)
    .bind(updated_at)
    .bind(id)
    .fetch_one(pool)
    .await;

    match result {
        Ok(row) => Ok(row),
        Err(sqlx::Error::Database(db_err)) => {
            if let Some(constraint) = db_err.constraint()
                && constraint.contains("handle")
            {
                return Err(RegistryError::HandleTaken(new_handle.to_string()));
            }
            Err(RegistryError::Database(sqlx::Error::Database(db_err)))
        }
        Err(sqlx::Error::RowNotFound) => Err(RegistryError::NotFound(id.to_string())),
        Err(e) => Err(RegistryError::Database(e)),
    }
}

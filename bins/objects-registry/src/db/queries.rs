//! Database queries for OBJECTS Registry.

use sqlx::SqlitePool;

use crate::db::models::IdentityRow;
use crate::error::{RegistryError, Result};

/// Insert a new identity record.
///
/// Returns the inserted row on success.
/// Returns `IdentityExists`, `HandleTaken`, or `SignerExists` on unique constraint violation.
///
/// # Atomicity
/// This function uses a single INSERT statement, which SQLite executes atomically.
/// A database transaction is not needed because:
/// - The operation is a single INSERT statement
/// - SQLite enforces uniqueness constraints atomically at the database level
/// - Either the entire insert succeeds or fails completely (no partial writes)
///
/// If future schema changes require coordinated writes across multiple tables
/// (e.g., audit logs, identity history), this function should be updated to use
/// an explicit transaction via `pool.begin()`.
pub async fn insert_identity(pool: &SqlitePool, row: &IdentityRow) -> Result<IdentityRow> {
    let result = sqlx::query(
        r#"
        INSERT INTO identities (
            id, handle, signer_type, signer_public_key, nonce,
            wallet_address, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            // Fetch and return the inserted row
            get_identity_by_id(pool, &row.id).await
        }
        Err(sqlx::Error::Database(db_err)) => {
            let msg = db_err.message().to_lowercase();
            if msg.contains("unique") || msg.contains("constraint") {
                if msg.contains("identities.id") || msg.contains("pkey") {
                    return Err(RegistryError::IdentityExists(row.id.clone()));
                }
                if msg.contains("handle") {
                    return Err(RegistryError::HandleTaken(row.handle.clone()));
                }
                if msg.contains("signer") {
                    return Err(RegistryError::SignerExists);
                }
                // Generic unique constraint — try to detect by index name
                return Err(RegistryError::Database(sqlx::Error::Database(db_err)));
            }
            Err(RegistryError::Database(sqlx::Error::Database(db_err)))
        }
        Err(e) => Err(RegistryError::Database(e)),
    }
}

/// Get an identity by ID.
pub async fn get_identity_by_id(pool: &SqlitePool, id: &str) -> Result<IdentityRow> {
    sqlx::query_as::<_, IdentityRow>("SELECT * FROM identities WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RegistryError::NotFound(id.to_string()))
}

/// Get an identity by handle (case-insensitive).
pub async fn get_identity_by_handle(pool: &SqlitePool, handle: &str) -> Result<IdentityRow> {
    sqlx::query_as::<_, IdentityRow>("SELECT * FROM identities WHERE handle = ? COLLATE NOCASE")
        .bind(handle)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RegistryError::NotFound(format!("handle:{}", handle)))
}

/// Get an identity by signer public key.
pub async fn get_identity_by_signer(pool: &SqlitePool, public_key: &[u8]) -> Result<IdentityRow> {
    sqlx::query_as::<_, IdentityRow>("SELECT * FROM identities WHERE signer_public_key = ?")
        .bind(public_key)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RegistryError::NotFound("signer".to_string()))
}

/// Get an identity by wallet address.
pub async fn get_identity_by_wallet(
    pool: &SqlitePool,
    wallet_address: &str,
) -> Result<IdentityRow> {
    sqlx::query_as::<_, IdentityRow>(
        "SELECT * FROM identities WHERE wallet_address = ? COLLATE NOCASE",
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
    pool: &SqlitePool,
    id: &str,
    wallet_address: &str,
    updated_at: i64,
) -> Result<IdentityRow> {
    let result = sqlx::query(
        r#"
        UPDATE identities
        SET wallet_address = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(wallet_address)
    .bind(updated_at)
    .bind(id)
    .execute(pool)
    .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return Err(RegistryError::NotFound(id.to_string()));
            }
            get_identity_by_id(pool, id).await
        }
        Err(sqlx::Error::Database(db_err)) => {
            let msg = db_err.message().to_lowercase();
            if (msg.contains("unique") || msg.contains("constraint")) && msg.contains("wallet") {
                return Err(RegistryError::WalletLinked(wallet_address.to_string()));
            }
            Err(RegistryError::Database(sqlx::Error::Database(db_err)))
        }
        Err(e) => Err(RegistryError::Database(e)),
    }
}

/// Update an identity's handle.
///
/// Returns `HandleTaken` if the new handle is already in use.
pub async fn update_identity_handle(
    pool: &SqlitePool,
    id: &str,
    new_handle: &str,
    updated_at: i64,
) -> Result<IdentityRow> {
    let result = sqlx::query(
        r#"
        UPDATE identities
        SET handle = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(new_handle)
    .bind(updated_at)
    .bind(id)
    .execute(pool)
    .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return Err(RegistryError::NotFound(id.to_string()));
            }
            get_identity_by_id(pool, id).await
        }
        Err(sqlx::Error::Database(db_err)) => {
            let msg = db_err.message().to_lowercase();
            if (msg.contains("unique") || msg.contains("constraint")) && msg.contains("handle") {
                return Err(RegistryError::HandleTaken(new_handle.to_string()));
            }
            Err(RegistryError::Database(sqlx::Error::Database(db_err)))
        }
        Err(e) => Err(RegistryError::Database(e)),
    }
}

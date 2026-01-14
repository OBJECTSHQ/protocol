//! REST API handlers for OBJECTS Registry.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use objects_identity::IdentityId;
use sqlx::PgPool;
use tracing::error;

use crate::api::rest::types::*;
use crate::config::Config;
use crate::db::{self, signer_type_to_i16, IdentityRow};
use crate::error::{RegistryError, Result};
use crate::verification;

/// Shared state for handlers.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}

/// Health check endpoint.
///
/// # Endpoint
/// `GET /health`
///
/// # Response
/// Returns a JSON object with status "ok".
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Create a new identity.
///
/// # Endpoint
/// `POST /v1/identities`
///
/// # Request Body
/// [`CreateIdentityRequest`] containing:
/// - `signer_public_key`: Base64-encoded compressed SEC1 public key (33 bytes)
/// - `nonce`: Base64-encoded random nonce (8 bytes) for identity derivation
/// - `signer_type`: "PASSKEY" or "WALLET"
/// - `handle`: Desired handle (1-30 chars, lowercase alphanumeric + underscore + period)
/// - `timestamp`: Unix timestamp in seconds
/// - `signature`: Signature object containing signature data and optional public key
///
/// # Verification Steps
/// 1. Parses and validates public key and nonce format
/// 2. Derives identity ID from public key + nonce per RFC-001
/// 3. Validates handle format and checks for reserved words
/// 4. Verifies timestamp is within acceptable bounds (5 min future, 24 hours past)
/// 5. Verifies signature over the create identity message
/// 6. Verifies signature public key matches request public key (passkey only)
/// 7. Inserts identity into database
///
/// # Returns
/// - `201 Created` with [`IdentityResponse`] on success
/// - `400 Bad Request` for validation errors
/// - `409 Conflict` if handle, signer, or ID already exists
pub async fn create_identity(
    State(state): State<AppState>,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<(StatusCode, Json<IdentityResponse>)> {
    // 1. Parse and validate inputs
    let public_key: [u8; 33] =
        decode_base64_array(&req.signer_public_key, "signer_public_key")
            .map_err(RegistryError::InvalidSignature)?;

    let nonce: [u8; 8] = decode_base64_array(&req.nonce, "nonce")
        .map_err(RegistryError::InvalidSignature)?;

    let signer_type =
        parse_signer_type(&req.signer_type).map_err(RegistryError::InvalidSignature)?;

    // 2. Derive expected identity ID
    let derived_id = IdentityId::derive(&public_key, &nonce);

    // 3. Validate handle format
    let handle = verification::verify_handle(&req.handle)?;

    // 4. Verify timestamp bounds
    verification::verify_timestamp(req.timestamp, &state.config)?;

    // 5. Build message and verify signature
    let message = verification::create_identity_message(
        derived_id.as_str(),
        handle.as_str(),
        req.timestamp,
    );

    let signature = req
        .signature
        .to_signature(signer_type)
        .map_err(RegistryError::InvalidSignature)?;

    verification::verify_signature(&signature, message.as_bytes())?;

    // 6. Verify signature public key matches request public key (for passkey)
    verification::verify_public_key_matches(&signature, &public_key)?;

    // 7. Insert into database
    let row = IdentityRow {
        id: derived_id.to_string(),
        handle: handle.to_string(),
        signer_type: signer_type_to_i16(signer_type),
        signer_public_key: public_key.to_vec(),
        nonce: nonce.to_vec(),
        wallet_address: None,
        created_at: req.timestamp as i64,
        updated_at: req.timestamp as i64,
    };

    let identity = db::insert_identity(&state.pool, &row).await?;

    let identity_id = identity.id.clone();
    let response = identity.try_into().map_err(|e| {
        error!("Data integrity error: failed to convert IdentityRow {} to response: {}", identity_id, e);
        RegistryError::Internal(format!("database contains invalid identity record {}: {}", identity_id, e))
    })?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get an identity by ID.
///
/// # Endpoint
/// `GET /v1/identities/{id}`
///
/// # Path Parameters
/// - `id`: Identity ID (e.g., "obj_2dMiYc8RhnYkorPc5pVh9")
///
/// # Returns
/// - `200 OK` with [`IdentityResponse`] on success
/// - `404 Not Found` if identity does not exist
pub async fn get_identity(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<IdentityResponse>> {
    let identity = db::get_identity_by_id(&state.pool, &id).await?;
    let identity_id = identity.id.clone();
    let response = identity.try_into().map_err(|e| {
        error!("Data integrity error: failed to convert IdentityRow {} to response: {}", identity_id, e);
        RegistryError::Internal(format!("database contains invalid identity record {}: {}", identity_id, e))
    })?;
    Ok(Json(response))
}

/// Resolve an identity by handle, signer, or wallet.
///
/// # Endpoint
/// `GET /v1/identities`
///
/// # Query Parameters
/// Exactly one of the following must be provided:
/// - `handle`: Identity handle (e.g., "montez")
/// - `signer`: Base64-encoded signer public key
/// - `wallet`: Ethereum wallet address (e.g., "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb")
///
/// # Returns
/// - `200 OK` with [`IdentityResponse`] on success
/// - `400 Bad Request` if no query parameter provided or multiple provided
/// - `404 Not Found` if identity does not exist
pub async fn resolve_identity(
    State(state): State<AppState>,
    Query(query): Query<ResolveQuery>,
) -> Result<Json<IdentityResponse>> {
    // Validate that exactly one query parameter is provided
    let param_count = [
        query.handle.is_some(),
        query.signer.is_some(),
        query.wallet.is_some(),
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    if param_count == 0 {
        return Err(RegistryError::BadRequest(
            "must provide one of: handle, signer, or wallet query parameter".to_string(),
        ));
    }

    if param_count > 1 {
        return Err(RegistryError::BadRequest(
            "must provide exactly one query parameter, received multiple".to_string(),
        ));
    }

    let identity = if let Some(handle) = query.handle {
        match db::get_identity_by_handle(&state.pool, &handle).await {
            Ok(identity) => identity,
            Err(RegistryError::NotFound(_)) => {
                return Err(RegistryError::NotFound(format!("handle:{}", handle)))
            }
            Err(RegistryError::Database(e)) => {
                error!("Database error during identity lookup by handle: {}", e);
                return Err(RegistryError::Database(e));
            }
            Err(e) => return Err(e),
        }
    } else if let Some(signer) = query.signer {
        let public_key = BASE64
            .decode(&signer)
            .map_err(|e| RegistryError::InvalidSignature(format!("invalid signer base64: {}", e)))?;
        match db::get_identity_by_signer(&state.pool, &public_key).await {
            Ok(identity) => identity,
            Err(RegistryError::NotFound(_)) => {
                return Err(RegistryError::NotFound("signer".to_string()))
            }
            Err(RegistryError::Database(e)) => {
                error!("Database error during identity lookup by signer: {}", e);
                return Err(RegistryError::Database(e));
            }
            Err(e) => return Err(e),
        }
    } else {
        // We validated param_count == 1, so wallet must be Some
        let wallet = query.wallet.unwrap();
        match db::get_identity_by_wallet(&state.pool, &wallet).await {
            Ok(identity) => identity,
            Err(RegistryError::NotFound(_)) => {
                return Err(RegistryError::NotFound(format!("wallet:{}", wallet)))
            }
            Err(RegistryError::Database(e)) => {
                error!("Database error during identity lookup by wallet: {}", e);
                return Err(RegistryError::Database(e));
            }
            Err(e) => return Err(e),
        }
    };

    let identity_id = identity.id.clone();
    let response = identity.try_into().map_err(|e| {
        error!("Data integrity error: failed to convert IdentityRow {} to response: {}", identity_id, e);
        RegistryError::Internal(format!("database contains invalid identity record {}: {}", identity_id, e))
    })?;
    Ok(Json(response))
}

/// Link a wallet to an identity.
///
/// # Endpoint
/// `POST /v1/identities/{id}/wallet`
///
/// # Path Parameters
/// - `id`: Identity ID to link the wallet to
///
/// # Request Body
/// [`LinkWalletRequest`] containing:
/// - `wallet_address`: Ethereum wallet address (0x + 40 hex chars)
/// - `timestamp`: Unix timestamp in seconds
/// - `identity_signature`: Signature from the identity's signer over the link message
/// - `wallet_signature`: Signature from the wallet over the link message
///
/// # Verification Steps
/// 1. Fetches the existing identity by ID
/// 2. Verifies timestamp is within acceptable bounds
/// 3. Builds the link wallet message
/// 4. Verifies the identity signature using the identity's signer public key
/// 5. Verifies the wallet signature using the wallet address
/// 6. Updates the identity with the linked wallet address
///
/// # Returns
/// - `200 OK` with updated [`IdentityResponse`] on success
/// - `400 Bad Request` for validation errors
/// - `404 Not Found` if identity does not exist
/// - `409 Conflict` if wallet is already linked to another identity
pub async fn link_wallet(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<LinkWalletRequest>,
) -> Result<Json<IdentityResponse>> {
    // 1. Fetch existing identity
    let identity = db::get_identity_by_id(&state.pool, &id).await?;

    // 2. Verify timestamp
    verification::verify_timestamp(req.timestamp, &state.config)?;

    // 3. Validate wallet address format
    verification::verify_wallet_address(&req.wallet_address)?;

    // 4. Build message
    let message = verification::link_wallet_message(&id, &req.wallet_address, req.timestamp);

    // 5. Get identity's signer type
    let identity_signer_type = identity.signer_type_enum().ok_or_else(|| {
        RegistryError::Internal(format!("unknown signer type: {}", identity.signer_type))
    })?;

    // 6. Verify identity signature (from identity's signer)
    let identity_sig = req
        .identity_signature
        .to_signature(identity_signer_type)
        .map_err(RegistryError::InvalidSignature)?;

    verification::verify_signature(&identity_sig, message.as_bytes())?;
    verification::verify_public_key_matches(&identity_sig, &identity.signer_public_key)?;

    // 7. Verify wallet signature (always wallet type)
    let wallet_sig = req
        .wallet_signature
        .to_signature(objects_identity::SignerType::Wallet)
        .map_err(RegistryError::InvalidSignature)?;

    verification::verify_signature(&wallet_sig, message.as_bytes())?;

    // 8. Update identity
    let updated =
        db::update_identity_wallet(&state.pool, &id, &req.wallet_address, req.timestamp as i64)
            .await?;

    let identity_id = updated.id.clone();
    let response = updated.try_into().map_err(|e| {
        error!("Data integrity error: failed to convert IdentityRow {} to response: {}", identity_id, e);
        RegistryError::Internal(format!("database contains invalid identity record {}: {}", identity_id, e))
    })?;
    Ok(Json(response))
}

/// Change an identity's handle.
///
/// # Endpoint
/// `PATCH /v1/identities/{id}/handle`
///
/// # Path Parameters
/// - `id`: Identity ID whose handle should be changed
///
/// # Request Body
/// [`ChangeHandleRequest`] containing:
/// - `new_handle`: Desired new handle (1-30 chars, lowercase alphanumeric + underscore + period)
/// - `timestamp`: Unix timestamp in seconds
/// - `signature`: Signature from the identity's signer over the change handle message
///
/// # Verification Steps
/// 1. Fetches the existing identity by ID
/// 2. Validates the new handle format and checks for reserved words
/// 3. Verifies timestamp is within acceptable bounds
/// 4. Builds the change handle message
/// 5. Verifies the signature using the identity's signer public key
/// 6. Updates the identity with the new handle
///
/// # Returns
/// - `200 OK` with updated [`IdentityResponse`] on success
/// - `400 Bad Request` for validation errors
/// - `404 Not Found` if identity does not exist
/// - `409 Conflict` if new handle is already taken
pub async fn change_handle(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ChangeHandleRequest>,
) -> Result<Json<IdentityResponse>> {
    // 1. Fetch existing identity
    let identity = db::get_identity_by_id(&state.pool, &id).await?;

    // 2. Validate new handle format
    let new_handle = verification::verify_handle(&req.new_handle)?;

    // 3. Verify timestamp
    verification::verify_timestamp(req.timestamp, &state.config)?;

    // 4. Build message
    let message =
        verification::change_handle_message(&id, new_handle.as_str(), req.timestamp);

    // 5. Get identity's signer type
    let signer_type = identity.signer_type_enum().ok_or_else(|| {
        RegistryError::Internal(format!("unknown signer type: {}", identity.signer_type))
    })?;

    // 6. Verify signature
    let signature = req
        .signature
        .to_signature(signer_type)
        .map_err(RegistryError::InvalidSignature)?;

    verification::verify_signature(&signature, message.as_bytes())?;
    verification::verify_public_key_matches(&signature, &identity.signer_public_key)?;

    // 7. Update identity
    let updated =
        db::update_identity_handle(&state.pool, &id, new_handle.as_str(), req.timestamp as i64)
            .await?;

    let identity_id = updated.id.clone();
    let response = updated.try_into().map_err(|e| {
        error!("Data integrity error: failed to convert IdentityRow {} to response: {}", identity_id, e);
        RegistryError::Internal(format!("database contains invalid identity record {}: {}", identity_id, e))
    })?;
    Ok(Json(response))
}

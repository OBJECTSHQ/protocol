//! REST API handlers for OBJECTS Registry.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use objects_identity::IdentityId;
use sqlx::PgPool;

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
/// GET /health
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Create a new identity.
/// POST /v1/identities
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

    let response = identity
        .try_into()
        .map_err(RegistryError::Internal)?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get an identity by ID.
/// GET /v1/identities/{id}
pub async fn get_identity(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<IdentityResponse>> {
    let identity = db::get_identity_by_id(&state.pool, &id).await?;
    let response = identity
        .try_into()
        .map_err(RegistryError::Internal)?;
    Ok(Json(response))
}

/// Resolve an identity by handle, signer, or wallet.
/// GET /v1/identities?handle=X or ?signer=X or ?wallet=X
pub async fn resolve_identity(
    State(state): State<AppState>,
    Query(query): Query<ResolveQuery>,
) -> Result<Json<IdentityResponse>> {
    let identity = if let Some(handle) = query.handle {
        db::get_identity_by_handle(&state.pool, &handle).await?
    } else if let Some(signer) = query.signer {
        let public_key = BASE64
            .decode(&signer)
            .map_err(|e| RegistryError::InvalidSignature(format!("invalid signer base64: {}", e)))?;
        db::get_identity_by_signer(&state.pool, &public_key).await?
    } else if let Some(wallet) = query.wallet {
        db::get_identity_by_wallet(&state.pool, &wallet).await?
    } else {
        return Err(RegistryError::InvalidSignature(
            "must provide handle, signer, or wallet query parameter".to_string(),
        ));
    };

    let response = identity
        .try_into()
        .map_err(RegistryError::Internal)?;
    Ok(Json(response))
}

/// Link a wallet to an identity.
/// POST /v1/identities/{id}/wallet
pub async fn link_wallet(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<LinkWalletRequest>,
) -> Result<Json<IdentityResponse>> {
    // 1. Fetch existing identity
    let identity = db::get_identity_by_id(&state.pool, &id).await?;

    // 2. Verify timestamp
    verification::verify_timestamp(req.timestamp, &state.config)?;

    // 3. Build message
    let message = verification::link_wallet_message(&id, &req.wallet_address, req.timestamp);

    // 4. Get identity's signer type
    let identity_signer_type = identity.signer_type_enum().ok_or_else(|| {
        RegistryError::Internal(format!("unknown signer type: {}", identity.signer_type))
    })?;

    // 5. Verify identity signature (from identity's signer)
    let identity_sig = req
        .identity_signature
        .to_signature(identity_signer_type)
        .map_err(RegistryError::InvalidSignature)?;

    verification::verify_signature(&identity_sig, message.as_bytes())?;
    verification::verify_public_key_matches(&identity_sig, &identity.signer_public_key)?;

    // 6. Verify wallet signature (always wallet type)
    let wallet_sig = req
        .wallet_signature
        .to_signature(objects_identity::SignerType::Wallet)
        .map_err(RegistryError::InvalidSignature)?;

    verification::verify_signature(&wallet_sig, message.as_bytes())?;

    // 7. Update identity
    let updated =
        db::update_identity_wallet(&state.pool, &id, &req.wallet_address, req.timestamp as i64)
            .await?;

    let response = updated
        .try_into()
        .map_err(RegistryError::Internal)?;
    Ok(Json(response))
}

/// Change an identity's handle.
/// PATCH /v1/identities/{id}/handle
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

    let response = updated
        .try_into()
        .map_err(RegistryError::Internal)?;
    Ok(Json(response))
}

use crate::client::NodeClient;
use crate::error::CliError;
use crate::types::{CreateIdentityRequest, SignatureData};
use objects_identity::{
    IdentityId, PasskeySigningKey, generate_nonce, message::create_identity_message,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn create(handle: String, client: &NodeClient) -> Result<(), CliError> {
    // Remove @ prefix if user provided it
    let handle = handle.trim_start_matches('@');

    println!("Creating identity @{}...", handle);
    println!("  Generating signing key...");

    // For now, use passkey signer (CLI default)
    // TODO: Add --signer-type flag to choose wallet
    let signing_key = PasskeySigningKey::generate();
    let public_key_bytes = signing_key.public_key();

    // Convert public key to [u8; 33]
    let public_key: [u8; 33] = public_key_bytes
        .try_into()
        .map_err(|_| CliError::Config("Public key must be 33 bytes".to_string()))?;

    let public_key_hex = signing_key.public_key_hex();
    println!("  Public key: {}", public_key_hex);

    // Generate nonce
    let nonce = generate_nonce();

    // Derive identity ID from public key + nonce
    let identity_id = IdentityId::derive(&public_key, &nonce);

    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CliError::Config(format!("System time error: {}", e)))?
        .as_secs();

    // Create message to sign using RFC-001 format
    let message = create_identity_message(identity_id.as_str(), handle, timestamp);

    // Sign the message (returns a Signature::Passkey with WebAuthn data)
    let signature = signing_key.sign(message.as_bytes());

    // Extract all fields using accessor methods (consistent with Signature API)
    let signature_data = SignatureData {
        signature: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.signature_bytes(),
        ),
        public_key: signature
            .public_key_bytes()
            .map(|pk| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk)),
        authenticator_data: signature
            .authenticator_data()
            .map(|ad| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ad)),
        client_data_json: signature
            .client_data_json()
            .map(|cd| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, cd)),
        address: signature.address().map(|a| a.to_string()),
    };

    // Create request with base64-encoded values
    let request = CreateIdentityRequest {
        handle: handle.to_string(),
        signer_type: "PASSKEY".to_string(),
        signer_public_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &public_key,
        ),
        nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce),
        timestamp: timestamp as i64,
        signature: signature_data,
    };

    let response = client.create_identity(request).await?;

    println!("✓ Identity created");
    println!("  ID:     {}", response.id);
    println!("  Handle: {}", response.handle);
    println!("  Nonce:  {}", response.nonce);
    println!("  Signer: {}", response.signer_type);

    // TODO: Save signing key to keystore
    println!("\n⚠️  Warning: Signing key is ephemeral and will be lost");
    println!("  Key storage will be implemented in a future update");

    Ok(())
}

pub async fn show(client: &NodeClient) -> Result<(), CliError> {
    match client.get_identity().await {
        Ok(response) => {
            println!("Identity:");
            println!("  ID:     {}", response.id);
            println!("  Handle: {}", response.handle);
            println!("  Nonce:  {}", response.nonce);
            println!("  Signer: {}", response.signer_type);
        }
        Err(CliError::NotFound(_)) => {
            println!("No identity registered.");
            println!("Run 'objects identity create --handle <name>' to create one.");
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

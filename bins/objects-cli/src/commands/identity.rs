use crate::client::NodeClient;
use crate::error::CliError;
use crate::types::{CreateIdentityRequest, SignatureData};
use base64::Engine as _;
use objects_identity::{
    Ed25519SigningKey, IdentityId, generate_nonce, message::create_identity_message,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper function to encode bytes as base64.
fn to_base64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub async fn create(handle: String, client: &NodeClient) -> Result<(), CliError> {
    // Remove @ prefix if user provided it
    let handle = handle.trim_start_matches('@');

    println!("Creating identity @{}...", handle);
    println!("  Generating signing key...");

    let signing_key = Ed25519SigningKey::generate();
    let public_key = signing_key.public_key_bytes();
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

    // Sign the message
    let signature = signing_key.sign(message.as_bytes());

    let signature_data = SignatureData {
        signature: to_base64(signature.signature_bytes()),
        public_key: to_base64(signature.public_key_bytes()),
    };

    // Create request with base64-encoded values
    let request = CreateIdentityRequest {
        handle: handle.to_string(),
        signer_public_key: to_base64(&public_key),
        nonce: to_base64(&nonce),
        timestamp,
        signature: signature_data,
    };

    let response = client.create_identity(request).await?;

    println!("Identity created");
    println!("  ID:     {}", response.id);
    println!("  Handle: {}", response.handle);
    println!("  Nonce:  {}", response.nonce);

    // TODO: Save signing key to keystore
    println!("\n  Warning: Signing key is ephemeral and will be lost");
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
        }
        Err(CliError::NotFound(_)) => {
            println!("No identity registered.");
            println!("Run 'objects identity create --handle <name>' to create one.");
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

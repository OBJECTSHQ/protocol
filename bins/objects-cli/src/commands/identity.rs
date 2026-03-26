use crate::client::NodeClient;
use crate::error::CliError;
use serde::Serialize;

/// Request sent from CLI to node. Just a handle — the node generates the key.
#[derive(Debug, Serialize)]
struct CreateIdentityRequest {
    handle: String,
}

pub async fn create(handle: String, client: &NodeClient) -> Result<(), CliError> {
    // Remove @ prefix if user provided it
    let handle = handle.trim_start_matches('@');

    println!("Creating identity @{}...", handle);
    println!("  Key generation happens on the node (key never leaves the device)");

    let request = CreateIdentityRequest {
        handle: handle.to_string(),
    };

    let response = client.create_identity_simple(request).await?;

    println!("Identity created");
    println!("  ID:     {}", response.id);
    println!("  Handle: {}", response.handle);
    println!("  Nonce:  {}", response.nonce);

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

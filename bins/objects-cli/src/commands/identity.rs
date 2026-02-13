use crate::client::NodeClient;
use crate::error::CliError;
use crate::types::CreateIdentityRequest;

pub async fn create(handle: String, client: &NodeClient) -> Result<(), CliError> {
    // Normalize handle (ensure @ prefix)
    let handle = if handle.starts_with('@') {
        handle
    } else {
        format!("@{}", handle)
    };

    println!("Creating identity {}...", handle);

    let request = CreateIdentityRequest { handle };
    let response = client.create_identity(request).await?;

    println!("✓ Identity created");
    println!("  ID:     {}", response.id);
    println!("  Handle: {}", response.handle);
    println!("  Nonce:  {}", response.nonce);
    println!("  Signer: {}", response.signer_type);

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

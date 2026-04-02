use crate::error::CliError;
use objects_core::node_api::NodeApi;

pub async fn create(handle: String, client: &NodeApi) -> Result<(), CliError> {
    let handle = handle.trim_start_matches('@');

    println!("Creating identity @{}...", handle);
    println!("  Key generation happens on the node (key never leaves the device)");

    let response = client.create_identity(handle).await?;

    println!("Identity created");
    println!("  ID:     {}", response.id);
    println!("  Handle: {}", response.handle);
    println!("  Nonce:  {}", response.nonce);

    Ok(())
}

pub async fn rename(new_handle: String, client: &NodeApi) -> Result<(), CliError> {
    let new_handle = new_handle.trim_start_matches('@');

    println!("Renaming identity to @{}...", new_handle);

    let response = client.rename_identity(new_handle).await?;

    println!("Identity renamed");
    println!("  ID:     {}", response.id);
    println!("  Handle: {}", response.handle);

    Ok(())
}

pub async fn show(client: &NodeApi) -> Result<(), CliError> {
    match client.get_identity().await {
        Ok(response) => {
            println!("Identity:");
            println!("  ID:     {}", response.id);
            println!("  Handle: {}", response.handle);
            println!("  Nonce:  {}", response.nonce);
        }
        Err(e) if e.to_string().contains("not found") => {
            println!("No identity registered.");
            println!("Run 'objects identity create --handle <name>' to create one.");
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

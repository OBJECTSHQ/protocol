//! Vault commands — list, sync, and pull projects from the encrypted vault.

use crate::client::NodeClient;
use crate::error::CliError;

/// List all projects in the vault catalog.
pub async fn list(client: &NodeClient) -> Result<(), CliError> {
    let response = client.vault_list().await?;

    if response.entries.is_empty() {
        println!("Vault is empty. Create a project to add it to your vault.");
        return Ok(());
    }

    println!("Vault ({} projects):", response.entries.len());
    for entry in &response.entries {
        let status = if entry.local { "local" } else { "remote" };
        println!("  {} [{}]", entry.name, status);
        println!("    ID: {}", entry.project_id);
    }

    Ok(())
}

/// Trigger vault metadata sync with peers.
pub async fn sync(client: &NodeClient) -> Result<(), CliError> {
    let result = client.vault_sync().await?;
    println!(
        "Vault sync: {}",
        result["status"].as_str().unwrap_or("done")
    );
    Ok(())
}

/// Pull a specific project from the vault (download from remote peer).
pub async fn pull(project_id: String, client: &NodeClient) -> Result<(), CliError> {
    println!(
        "Pulling project {}...",
        &project_id[..16.min(project_id.len())]
    );
    let result = client.vault_pull(&project_id).await?;
    println!("Pull: {}", result["status"].as_str().unwrap_or("complete"));
    Ok(())
}

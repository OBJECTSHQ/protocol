//! Vault commands — list, sync, and pull projects from the encrypted vault.

use crate::error::CliError;
use objects_core::node_api::NodeApi;

pub async fn list(client: &NodeApi) -> Result<(), CliError> {
    let response = CliError::from_rpc(client.list_vault().await)?;

    if response.entries.is_empty() {
        println!("Vault is empty. Create a project first.");
        return Ok(());
    }

    println!("Vault ({} project(s)):", response.entries.len());
    for entry in &response.entries {
        let status = if entry.local { "local" } else { "remote" };
        println!("  {} [{}] {}", entry.name, status, &entry.project_id[..16]);
    }

    Ok(())
}

pub async fn sync(client: &NodeApi) -> Result<(), CliError> {
    let response = CliError::from_rpc(client.sync_vault().await)?;
    println!("Vault sync: {}", response.status);
    Ok(())
}

pub async fn pull(project_id: String, client: &NodeApi) -> Result<(), CliError> {
    let response = CliError::from_rpc(client.pull_vault_project(&project_id).await)?;
    println!(
        "Vault pull: {} (project {})",
        response.status, response.project_id
    );
    Ok(())
}

//! Asset commands.

use crate::client::NodeClient;
use std::path::Path;

/// Add an asset to a project.
pub async fn add(project_id: String, file: String, client: &NodeClient) -> anyhow::Result<()> {
    let path = Path::new(&file);
    if !path.exists() {
        anyhow::bail!("File not found: {}", file);
    }

    let asset = client.add_asset(&project_id, path).await?;

    println!("Asset added:");
    println!("  ID: {}", asset.id);
    println!("  Filename: {}", asset.filename);
    println!("  Type: {}", asset.content_type);
    println!("  Size: {} bytes", asset.size);
    println!("  Hash: {}", asset.content_hash);
    Ok(())
}

/// List assets in a project.
pub async fn list(project_id: String, client: &NodeClient) -> anyhow::Result<()> {
    let response = client.list_assets(&project_id).await?;

    if response.assets.is_empty() {
        println!("No assets in project");
        return Ok(());
    }

    println!("Assets ({}):", response.assets.len());
    for asset in response.assets {
        println!("  {} - {} ({} bytes)", asset.id, asset.filename, asset.size);
    }
    Ok(())
}

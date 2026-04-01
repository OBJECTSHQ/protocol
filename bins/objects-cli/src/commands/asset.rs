//! Asset commands.

use objects_core::node_api::NodeApi;

pub async fn add(project_id: String, file: String, _client: &NodeApi) -> anyhow::Result<()> {
    let path = std::path::Path::new(&file);
    if !path.exists() {
        anyhow::bail!("File not found: {}", file);
    }

    // TODO: Implement streaming asset upload via irpc
    // The NodeApi needs add_asset() with client-streaming support
    println!(
        "Asset upload not yet available via irpc (project: {}, file: {})",
        project_id, file
    );

    Ok(())
}

pub async fn list(project_id: String, client: &NodeApi) -> anyhow::Result<()> {
    let response = client
        .list_assets(&project_id)
        .await?
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if response.assets.is_empty() {
        println!("No assets in project.");
        return Ok(());
    }

    println!("Assets ({}):", response.assets.len());
    for asset in &response.assets {
        println!("  {} — {} ({} bytes)", asset.id, asset.filename, asset.size);
    }

    Ok(())
}

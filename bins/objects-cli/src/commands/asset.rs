//! Asset commands.

use crate::error::CliError;
use objects_core::node_api::NodeApi;

pub async fn add(project_id: String, file: String, client: &NodeApi) -> Result<(), CliError> {
    let path = std::path::Path::new(&file);
    if !path.exists() {
        return Err(CliError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", file),
        )));
    }

    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed".to_string());

    let content_type = new_mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();

    let data = std::fs::read(path)?;
    println!("Uploading {} ({} bytes)...", filename, data.len());

    let response = client
        .add_asset(&project_id, &filename, &content_type, data.into())
        .await?;

    println!("Asset added:");
    println!("  ID:   {}", response.id);
    println!("  File: {}", response.filename);
    println!("  Type: {}", response.content_type);
    println!("  Size: {} bytes", response.size);

    Ok(())
}

pub async fn list(project_id: String, client: &NodeApi) -> Result<(), CliError> {
    let response = client.list_assets(&project_id).await?;

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

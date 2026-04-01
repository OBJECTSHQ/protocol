use crate::error::CliError;
use objects_core::node_api::NodeApi;

pub async fn run(client: &NodeApi) -> Result<(), CliError> {
    // Health check
    match client.health().await {
        Ok(_) => println!("✓ Node is running"),
        Err(_) => {
            println!("✗ Node not reachable");
            println!("  Start node with: cargo run -p objects-node");
            return Ok(());
        }
    }

    // Detailed status
    let status = client.status().await.map_err(CliError::Connection)?;

    println!("\nNode Status:");
    println!("  Node ID: {}", status.node_id);
    println!("  Relay:   {}", status.relay_url);
    println!("  Peers:   {}", status.peer_count);

    if let Some(id) = status.identity {
        println!("\nIdentity:");
        println!("  ID:     {}", id.id);
        println!("  Handle: {}", id.handle);
    } else {
        println!("\nIdentity: Not registered");
    }

    Ok(())
}

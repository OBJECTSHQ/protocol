use crate::client::NodeClient;
use crate::error::CliError;

pub async fn run(client: &NodeClient) -> Result<(), CliError> {
    // Health check
    match client.health().await {
        Ok(_) => println!("✓ Node is running"),
        Err(_) => {
            println!("✗ Node not reachable");
            println!("  Start node with: cargo run -p objects-node");
            return Ok(()); // Not an error, just info
        }
    }

    // Detailed status
    let status = client.status().await?;

    println!("\nNode Status:");
    println!("  Node ID: {}", status.node_id);
    println!("  Relay:   {}", status.relay_url);
    println!("  Peers:   {}", status.peer_count);

    if let Some(id) = status.identity {
        println!("\nIdentity:");
        println!("  ID:     {}", id.id);
        println!("  Handle: {}", id.handle);
        println!("  Signer: {}", id.signer_type);
    } else {
        println!("\nIdentity: Not registered");
    }

    Ok(())
}

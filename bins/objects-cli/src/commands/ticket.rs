//! Ticket commands.

use crate::client::NodeClient;

/// Create a share ticket for a project.
pub async fn create(project_id: String, client: &NodeClient) -> anyhow::Result<()> {
    let response = client.create_ticket(&project_id).await?;

    println!("Ticket created:");
    println!("{}", response.ticket);
    Ok(())
}

/// Redeem a share ticket.
pub async fn redeem(ticket: String, client: &NodeClient) -> anyhow::Result<()> {
    let project = client.redeem_ticket(&ticket).await?;

    println!("Project synced:");
    println!("  ID: {}", project.id);
    println!("  Name: {}", project.name);
    if let Some(desc) = project.description {
        println!("  Description: {}", desc);
    }
    println!("  Owner: {}", project.owner_id);
    Ok(())
}

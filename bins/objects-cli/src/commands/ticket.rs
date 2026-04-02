//! Ticket commands.

use crate::error::CliError;
use objects_core::node_api::NodeApi;

pub async fn create(project_id: String, client: &NodeApi) -> Result<(), CliError> {
    let response = client.create_ticket(&project_id).await?;

    println!("Ticket created:");
    println!("{}", response.ticket);

    Ok(())
}

pub async fn redeem(ticket: String, client: &NodeApi) -> Result<(), CliError> {
    let response = client.redeem_ticket(&ticket).await?;

    println!("Ticket redeemed — project imported:");
    println!("  ID:   {}", response.id);
    println!("  Name: {}", response.name);

    Ok(())
}

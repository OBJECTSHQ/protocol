//! Ticket commands.

use objects_core::node_api::NodeApi;

pub async fn create(project_id: String, client: &NodeApi) -> anyhow::Result<()> {
    let response = client
        .create_ticket(&project_id)
        .await?
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Ticket created:");
    println!("{}", response.ticket);

    Ok(())
}

pub async fn redeem(ticket: String, client: &NodeApi) -> anyhow::Result<()> {
    let response = client
        .redeem_ticket(&ticket)
        .await?
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Ticket redeemed — project imported:");
    println!("  ID:   {}", response.id);
    println!("  Name: {}", response.name);

    Ok(())
}

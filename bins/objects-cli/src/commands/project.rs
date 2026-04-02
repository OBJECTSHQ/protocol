use crate::error::CliError;
use objects_core::node_api::NodeApi;

pub async fn create(
    name: String,
    description: Option<String>,
    client: &NodeApi,
) -> Result<(), CliError> {
    println!("Creating project '{}'...", name);

    let response = client.create_project(&name, description.as_deref()).await?;

    println!("Project created");
    println!("  ID:          {}", response.id);
    println!("  Name:        {}", response.name);
    if let Some(desc) = &response.description {
        println!("  Description: {}", desc);
    }
    println!("  Owner:       {}", response.owner_id);

    Ok(())
}

pub async fn list(client: &NodeApi) -> Result<(), CliError> {
    let response = client.list_projects().await?;

    if response.projects.is_empty() {
        println!("No projects found.");
        println!("Create one with: objects project create --name \"My Project\"");
        return Ok(());
    }

    println!("Projects ({}):", response.projects.len());
    for project in &response.projects {
        println!("  {} - {}", &project.id[..16], project.name);
    }

    Ok(())
}

pub async fn get(id: String, client: &NodeApi) -> Result<(), CliError> {
    let response = client.get_project(&id).await?;

    println!("Project: {}", response.name);
    println!("  ID:          {}", response.id);
    if let Some(desc) = &response.description {
        println!("  Description: {}", desc);
    }
    println!("  Owner:       {}", response.owner_id);
    println!("  Created:     {}", response.created_at);
    println!("  Updated:     {}", response.updated_at);

    Ok(())
}

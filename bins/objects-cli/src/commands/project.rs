//! Project command handlers.

use crate::client::NodeClient;
use crate::error::CliError;
use crate::types::CreateProjectRequest;

/// Create a new project.
pub async fn create(
    name: String,
    description: Option<String>,
    client: &NodeClient,
) -> Result<(), CliError> {
    println!("Creating project '{}'...", name);

    let request = CreateProjectRequest { name, description };

    let response = client.create_project(request).await?;

    println!("✓ Project created");
    println!("  ID:          {}", response.id);
    println!("  Name:        {}", response.name);
    if let Some(desc) = &response.description {
        println!("  Description: {}", desc);
    }
    println!("  Owner:       {}", response.owner_id);
    println!("  Created:     {}", response.created_at);

    Ok(())
}

/// List all projects.
pub async fn list(client: &NodeClient) -> Result<(), CliError> {
    let response = client.list_projects().await?;

    if response.projects.is_empty() {
        println!("No projects found.");
        println!("Run 'objects project create --name <name>' to create one.");
    } else {
        println!("Projects ({}):", response.projects.len());
        println!();
        for project in response.projects {
            println!("  {} - {}", project.id, project.name);
            if let Some(desc) = &project.description {
                println!("    {}", desc);
            }
        }
    }

    Ok(())
}

/// Get a project by ID.
pub async fn get(id: String, client: &NodeClient) -> Result<(), CliError> {
    let response = client.get_project(&id).await?;

    println!("Project:");
    println!("  ID:          {}", response.id);
    println!("  Name:        {}", response.name);
    if let Some(desc) = &response.description {
        println!("  Description: {}", desc);
    }
    println!("  Owner:       {}", response.owner_id);
    println!("  Created:     {}", response.created_at);
    println!("  Updated:     {}", response.updated_at);

    Ok(())
}

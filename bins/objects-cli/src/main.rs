//! CLI tool for OBJECTS Protocol.

use clap::{Parser, Subcommand};
use objects_cli::{client::NodeClient, commands, config::Config};

#[derive(Parser)]
#[command(name = "objects")]
#[command(about = "OBJECTS Protocol CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new node
    Init,
    /// Show node status
    Status,
    /// Identity operations
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },
    /// Project operations
    Project {
        #[command(subcommand)]
        command: ProjectCommands,
    },
    /// Asset operations
    Asset {
        #[command(subcommand)]
        command: AssetCommands,
    },
    /// Vault operations (cross-device project discovery)
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    /// Sync with peers
    Sync,
    /// Ticket operations
    Ticket {
        #[command(subcommand)]
        command: TicketCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Create a new identity
    Create {
        /// Handle for the identity
        #[arg(long)]
        handle: String,
    },
    /// Rename your handle
    Rename {
        /// New handle
        new_handle: String,
    },
    /// Show current identity
    Show,
}

#[derive(Subcommand)]
enum ProjectCommands {
    /// Create a new project
    Create {
        /// Name of the project
        #[arg(short, long)]
        name: String,
        /// Optional description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// List all projects
    List,
    /// Get a project by ID
    Get {
        /// Project ID (64 hex characters)
        id: String,
    },
}

#[derive(Subcommand)]
enum AssetCommands {
    /// Add an asset to a project
    Add {
        /// Project ID (64 hex characters)
        #[arg(short, long)]
        project: String,
        /// Path to the file
        file: String,
    },
    /// List assets in a project
    List {
        /// Project ID (64 hex characters)
        #[arg(short, long)]
        project: String,
    },
}

#[derive(Subcommand)]
enum VaultCommands {
    /// List projects in the vault
    List,
    /// Sync vault metadata with peers
    Sync,
    /// Pull a specific project from the vault
    Pull {
        /// Project ID (64 hex characters)
        project_id: String,
    },
}

#[derive(Subcommand)]
enum TicketCommands {
    /// Create a share ticket for a project
    Create {
        /// Project ID (64 hex characters)
        #[arg(short, long)]
        project: String,
    },
    /// Redeem a share ticket
    Redeem {
        /// The ticket string
        ticket: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            commands::init::run().await?;
        }
        Commands::Status => {
            let config = Config::load()?;
            let client = NodeClient::new(config.api_url());
            commands::status::run(&client).await?;
        }
        Commands::Identity { command } => {
            let config = Config::load()?;
            let client = NodeClient::new(config.api_url());
            match command {
                IdentityCommands::Create { handle } => {
                    commands::identity::create(handle, &client).await?;
                }
                IdentityCommands::Rename { new_handle } => {
                    commands::identity::rename(new_handle, &client).await?;
                }
                IdentityCommands::Show => {
                    commands::identity::show(&client).await?;
                }
            }
        }
        Commands::Project { command } => {
            let config = Config::load()?;
            let client = NodeClient::new(config.api_url());
            match command {
                ProjectCommands::Create { name, description } => {
                    commands::project::create(name, description, &client).await?;
                }
                ProjectCommands::List => {
                    commands::project::list(&client).await?;
                }
                ProjectCommands::Get { id } => {
                    commands::project::get(id, &client).await?;
                }
            }
        }
        Commands::Asset { command } => {
            let config = Config::load()?;
            let client = NodeClient::new(config.api_url());
            match command {
                AssetCommands::Add { project, file } => {
                    commands::asset::add(project, file, &client).await?;
                }
                AssetCommands::List { project } => {
                    commands::asset::list(project, &client).await?;
                }
            }
        }
        Commands::Vault { command } => {
            let config = Config::load()?;
            let client = NodeClient::new(config.api_url());
            match command {
                VaultCommands::List => {
                    commands::vault::list(&client).await?;
                }
                VaultCommands::Sync => {
                    commands::vault::sync(&client).await?;
                }
                VaultCommands::Pull { project_id } => {
                    commands::vault::pull(project_id, &client).await?;
                }
            }
        }
        Commands::Sync => {
            println!("Syncing with peers...");
            // TODO: Sync
        }
        Commands::Ticket { command } => {
            let config = Config::load()?;
            let client = NodeClient::new(config.api_url());
            match command {
                TicketCommands::Create { project } => {
                    commands::ticket::create(project, &client).await?;
                }
                TicketCommands::Redeem { ticket } => {
                    commands::ticket::redeem(ticket, &client).await?;
                }
            }
        }
    }

    Ok(())
}

use crate::config::Config;
use crate::error::CliError;
use std::fs;

pub async fn run() -> Result<(), CliError> {
    println!("Initializing OBJECTS CLI...");

    let config = Config::default();
    let data_dir = config.data_dir();

    let dir_existed = data_dir.exists();
    fs::create_dir_all(&data_dir)?;
    if dir_existed {
        println!("  Exists:  {}", data_dir.display());
    } else {
        println!("  Created: {}", data_dir.display());
    }

    let config_path = Config::config_path();
    if !config_path.exists() {
        config.save(&config_path)?;
        println!("  Created: {}", config_path.display());
    } else {
        println!("  Exists:  {}", config_path.display());
    }

    println!("\n✓ Initialization complete");
    println!("  Run 'objects status' to check node connectivity");

    Ok(())
}

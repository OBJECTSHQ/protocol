use objects_cli::commands;
use objects_cli::config::Config;
use serial_test::serial;
use temp_env::with_var;
use tempfile::tempdir;

#[test]
#[serial]
fn test_init_creates_structure() {
    let temp = tempdir().unwrap();
    let temp_path = temp.path().to_str().unwrap().to_string();

    with_var("HOME", Some(&temp_path), || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            commands::init::run().await.unwrap();

            let objects_dir = temp.path().join(".objects");
            assert!(objects_dir.exists());

            let config_file = objects_dir.join("config.toml");
            assert!(config_file.exists());
        });
    });
}

#[test]
#[serial]
fn test_init_idempotent() {
    let temp = tempdir().unwrap();
    let temp_path = temp.path().to_str().unwrap().to_string();

    with_var("HOME", Some(&temp_path), || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            commands::init::run().await.unwrap();
            let result = commands::init::run().await;

            assert!(result.is_ok());
        });
    });
}

#[test]
#[serial]
fn test_init_config_has_defaults() {
    let temp = tempdir().unwrap();
    let temp_path = temp.path().to_str().unwrap().to_string();

    with_var("HOME", Some(&temp_path), || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            commands::init::run().await.unwrap();

            let config_file = temp.path().join(".objects/config.toml");
            let config = Config::from_file(&config_file).unwrap();

            assert_eq!(config.api_url(), "http://127.0.0.1:3420");
            assert!(config.cli.api_token.is_none());
        });
    });
}

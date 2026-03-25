use objects_cli::config::Config;
use serial_test::serial;
use temp_env::with_var;
use tempfile::tempdir;

#[test]
fn test_default_config() {
    let config = Config::default();
    assert_eq!(config.node.api_port, 3420);
    assert_eq!(config.node.api_bind, "127.0.0.1");
    assert_eq!(config.api_url(), "http://127.0.0.1:3420");
    assert!(config.cli.api_token.is_none());
}

#[test]
fn test_api_url_construction() {
    let config = Config::default();
    assert_eq!(config.api_url(), "http://127.0.0.1:3420");
}

#[test]
fn test_save_load_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");

    let config = Config::default();
    config.save(&path).unwrap();

    let loaded = Config::from_file(&path).unwrap();
    assert_eq!(loaded.node.api_port, config.node.api_port);
    assert_eq!(loaded.node.api_bind, config.node.api_bind);
    assert_eq!(loaded.network.relay_url, config.network.relay_url);
}

#[test]
fn test_save_load_custom_config() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");

    let mut config = Config::default();
    config.node.api_port = 8080;
    config.node.api_bind = "0.0.0.0".to_string();
    config.cli.api_token = Some("token123".to_string());

    config.save(&path).unwrap();

    let loaded = Config::from_file(&path).unwrap();
    assert_eq!(loaded.node.api_port, 8080);
    assert_eq!(loaded.node.api_bind, "0.0.0.0");
    assert_eq!(loaded.cli.api_token, Some("token123".to_string()));
}

#[test]
fn test_save_creates_directory() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("subdir/config.toml");

    let config = Config::default();
    config.save(&path).unwrap();

    assert!(path.exists());
}

#[test]
fn test_config_parse_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad_config.toml");

    std::fs::write(&path, "invalid toml [[[").unwrap();

    let result = Config::from_file(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Parse error"));
}

#[test]
#[serial]
fn test_env_override_api_url() {
    with_var("OBJECTS_API_URL", Some("http://custom:9000"), || {
        let mut config = Config::default();
        config.apply_env();
        assert_eq!(config.api_url(), "http://custom:9000");
    });
}

#[test]
#[serial]
fn test_env_override_api_token() {
    with_var("OBJECTS_API_TOKEN", Some("test_token_123"), || {
        let mut config = Config::default();
        config.apply_env();
        assert_eq!(config.cli.api_token, Some("test_token_123".to_string()));
    });
}

#[test]
#[serial]
fn test_env_override_data_dir() {
    with_var("OBJECTS_DATA_DIR", Some("/tmp/test_objects"), || {
        let mut config = Config::default();
        config.apply_env();
        assert_eq!(config.node.data_dir, "/tmp/test_objects");
    });
}

#[test]
#[serial]
fn test_env_override_api_port() {
    with_var("OBJECTS_API_PORT", Some("8080"), || {
        let mut config = Config::default();
        config.apply_env();
        assert_eq!(config.node.api_port, 8080);
        assert_eq!(config.api_url(), "http://127.0.0.1:8080");
    });
}

#[test]
fn test_data_dir_method() {
    let config = Config::default();
    let data_dir = config.data_dir();
    assert!(data_dir.to_str().unwrap().ends_with(".objects"));
}

#[test]
fn test_config_sections() {
    let config = Config::default();

    // Verify all sections have defaults
    assert!(!config.node.data_dir.is_empty());
    assert!(!config.network.relay_url.is_empty());
    assert!(!config.network.discovery_topic.is_empty());
    assert!(config.storage.max_blob_size_mb > 0);
    assert!(config.storage.max_total_size_gb > 0);
    assert!(!config.identity.registry_url.is_empty());
}

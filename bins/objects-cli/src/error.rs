use objects_core::node_api::NodeApiError;
use objects_core::rpc::proto::RpcError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Api(#[from] NodeApiError),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl From<RpcError> for CliError {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::NotFound(msg) => CliError::NotFound(msg),
            other => CliError::Api(NodeApiError::Rpc(other)),
        }
    }
}

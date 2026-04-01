use objects_core::rpc::proto::RpcError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),

    #[error("Connection error: {0}")]
    Connection(#[from] irpc::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl CliError {
    /// Convert a double-Result from NodeApi into a flat CliError.
    pub fn from_rpc<T>(result: Result<Result<T, RpcError>, irpc::Error>) -> Result<T, CliError> {
        match result {
            Ok(Ok(val)) => Ok(val),
            Ok(Err(rpc_err)) => match rpc_err {
                RpcError::NotFound(msg) => Err(CliError::NotFound(msg)),
                other => Err(CliError::Rpc(other)),
            },
            Err(irpc_err) => Err(CliError::Connection(irpc_err)),
        }
    }
}

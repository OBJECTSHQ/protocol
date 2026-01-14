//! Database layer for OBJECTS Registry.

mod models;
mod pool;
mod queries;

pub use models::{signer_type_to_i16, IdentityRow};
pub use pool::create_pool;
pub use queries::*;

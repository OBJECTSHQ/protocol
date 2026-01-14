//! REST API for OBJECTS Registry.

pub mod handlers;
mod routes;
mod types;

pub use routes::create_router;

//! OBJECTS Protocol Core Engine
//!
//! This crate contains the embeddable core of the OBJECTS node.
//! It can be used as a library in desktop apps (Tauri), mobile apps,
//! or as the backing engine for the standalone `objects-node` daemon.

pub mod api;
pub mod config;
pub mod defaults;
pub mod rpc;
pub mod service;
pub mod state;

pub use config::NodeConfig;
pub use state::NodeState;

//! irpc protocol definition for the OBJECTS node RPC service.
//!
//! Defines the [`NodeProtocol`] enum — all operations the node supports,
//! expressed as irpc request variants with typed response channels.
//!
//! This protocol can be used:
//! - **In-process** via tokio channels (embedded in desktop/mobile apps)
//! - **Over QUIC** via irpc-iroh (CLI → node, or node → node)

pub mod proto;

pub use proto::*;

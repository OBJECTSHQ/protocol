//! UniFFI bindings for the OBJECTS Protocol.
//!
//! This crate exposes [`ObjectsNode`] to Kotlin and Swift via Mozilla's
//! [uniffi](https://mozilla.github.io/uniffi-rs/) framework. It compiles to
//! a shared library (`.dylib`, `.so`, `.dll`) that the generated Kotlin/Swift
//! wrappers load at runtime.
//!
//! # Quick start (Kotlin)
//!
//! ```kotlin
//! val node = ObjectsNode.start("/path/to/data")
//! val identity = node.createIdentity("alice")
//! val projects = node.listProjects()
//! node.shutdown()
//! ```
//!
//! # Quick start (Swift)
//!
//! ```swift
//! let node = try ObjectsNode.start(dataDir: "/path/to/data")
//! let identity = try await node.createIdentity(handle: "alice")
//! let projects = try await node.listProjects()
//! node.shutdown()
//! ```

uniffi::setup_scaffolding!();

pub mod error;
pub mod node;
pub mod types;

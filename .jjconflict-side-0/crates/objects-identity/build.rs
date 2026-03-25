//! Build script for objects-identity.
//!
//! Compiles Protocol Buffer definitions to Rust code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only compile protos if the codegen feature is enabled or if the proto.rs doesn't exist
    #[cfg(feature = "codegen")]
    {
        let proto_root = std::path::Path::new("../../proto");
        let proto_file = proto_root.join("objects/identity/v1/identity.proto");

        println!("cargo:rerun-if-changed={}", proto_file.display());

        prost_build::Config::new()
            .out_dir("src/")
            .compile_protos(&[proto_file], &[proto_root])?;

        // Rename the generated file to proto.rs
        let generated = std::path::Path::new("src/objects.identity.v1.rs");
        if generated.exists() {
            std::fs::rename(generated, "src/proto.rs")?;
        }
    }

    Ok(())
}

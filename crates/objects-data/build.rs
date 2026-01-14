//! Build script for objects-data.
//!
//! Compiles Protocol Buffer definitions to Rust code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only compile protos if the codegen feature is enabled
    #[cfg(feature = "codegen")]
    {
        let proto_root = std::path::Path::new("../../proto");
        let proto_file = proto_root.join("objects/data/v1/data.proto");

        println!("cargo:rerun-if-changed={}", proto_file.display());

        prost_build::Config::new()
            .out_dir("src/")
            .extern_path(".objects.identity.v1", "::objects_identity::proto")
            .compile_protos(&[proto_file], &[proto_root])?;

        // Rename the generated file to proto.rs
        let generated = std::path::Path::new("src/objects.data.v1.rs");
        if generated.exists() {
            std::fs::rename(generated, "src/proto.rs")?;
        }
    }

    Ok(())
}

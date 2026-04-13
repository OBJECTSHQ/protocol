//! Build script for objects-core.
//!
//! Compiles the node service Protocol Buffer definitions to Rust code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "codegen")]
    {
        let proto_root = std::path::Path::new("../../proto");
        let proto_file = proto_root.join("objects/node/v1/node.proto");

        println!("cargo:rerun-if-changed={}", proto_file.display());

        let mut config = prost_build::Config::new();
        config.out_dir("src/");

        // Add serde derives so proto types work with irpc's serde-based wire format.
        config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

        // Map proto bytes fields to Vec<u8> (default prost behavior).
        // serde will serialize Vec<u8> as an array; for irpc wire format this is fine.

        config.compile_protos(&[proto_file], &[proto_root])?;

        // Rename the generated file to proto_gen.rs
        let generated = std::path::Path::new("src/objects.node.v1.rs");
        if generated.exists() {
            std::fs::rename(generated, "src/proto_gen.rs")?;
        }
    }

    Ok(())
}

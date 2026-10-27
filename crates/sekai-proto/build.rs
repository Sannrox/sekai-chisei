/// Compiles the workspace contract in `../../proto`, the only committed copy.
/// Path and git dependencies build inside a full checkout and find it there.
/// A standalone build (for example a future registry package) must stage the
/// files into this crate's gitignored `proto/` first; while publishing is off
/// the crate is workspace-only.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = ["../../proto", "proto"]
        .into_iter()
        .find(|root| std::path::Path::new(root).join("sekai.proto").exists())
        .ok_or("sekai.proto not found in ../../proto or a staged proto/")?;
    for name in ["sekai.proto", "chisei.proto"] {
        println!("cargo:rerun-if-changed={proto_root}/{name}");
    }
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[serde(rename_all = \"camelCase\")]")
        // Fields added after a message shipped default when JSON callers
        // (the MCP adapter) omit them.
        .field_attribute(
            "sekai.CreateDefinitionProposalRequest.major_revision",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.DefinitionProposal.major_revision",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.CreateDefinitionProposalRequest.migration_plan_digest",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.DefinitionConsumerImpactPath.blocking",
            "#[serde(default)]",
        )
        .field_attribute("sekai.ExportDefinition.every_ms", "#[serde(default)]")
        .compile_protos(
            &[
                format!("{proto_root}/sekai.proto"),
                format!("{proto_root}/chisei.proto"),
            ],
            &[proto_root.to_string()],
        )?;
    Ok(())
}

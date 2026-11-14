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
        // New RPCs stay additive for downstream `impl SekaiService` /
        // `impl ChiseiService`: omitted methods return UNIMPLEMENTED.
        .generate_default_stubs(true)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[serde(rename_all = \"camelCase\")]")
        // HTTP proto JSON keeps the previous untagged property cells
        // (`{"title":"hello"}`) alongside the generated oneof form.
        .type_attribute(
            "sekai.PropertyValue",
            "#[serde(from = \"crate::property_json::Wire\", into = \"crate::property_json::Wire\")]",
        )
        // Nested inputs of stable RPCs on the HTTP/JSON projection: proto3
        // JSON may omit any default-valued field, and the projection only
        // fills defaults for the top-level request (#2266).
        .type_attribute("sekai.GovernedDocumentAdmission", "#[serde(default)]")
        .type_attribute("sekai.DocumentRenditionAttachment", "#[serde(default)]")
        .type_attribute("sekai.ContentReference", "#[serde(default)]")
        // Generated messages may gain fields. Downstream constructs them with
        // `..Default::default()` so a new field stays additive.
        //
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
            "sekai.CreateDefinitionProposalRequest.dataset_proposals",
            "#[serde(default)]",
        )
        // Omitted when empty, so a v1 proposal serializes as before (#2222).
        .field_attribute(
            "sekai.DefinitionProposal.dataset_proposals",
            "#[serde(default, skip_serializing_if = \"Vec::is_empty\")]",
        )
        .field_attribute(
            "sekai.DefinitionConsumerImpactPath.blocking",
            "#[serde(default)]",
        )
        .field_attribute("sekai.ExportDefinition.every_ms", "#[serde(default)]")
        .field_attribute("sekai.SourceBatch.source_id", "#[serde(default)]")
        .field_attribute(
            "sekai.ExportDefinition.delivery_source_id",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.DeliverableExportArtifact.delivery_source_id",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.ObjectSetDescriptor.property_filters",
            "#[serde(default)]",
        )
        .field_attribute("sekai.ObjectSetDescriptor.order_by", "#[serde(default)]")
        .field_attribute("sekai.ObjectSetDescriptor.descending", "#[serde(default)]")
        .field_attribute("sekai.ObjectSetDescriptor.limit", "#[serde(default)]")
        .field_attribute("sekai.ObjectSetDescriptor.traversal", "#[serde(default)]")
        .field_attribute("sekai.ObjectSetDescriptor.hops", "#[serde(default)]")
        .field_attribute("sekai.ObjectSetDescriptor.aggregation", "#[serde(default)]")
        .field_attribute("sekai.ObjectSetDescriptor.cost_limit", "#[serde(default)]")
        .field_attribute(
            "sekai.EvaluateObjectSetRequest.page_token",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.EvaluateObjectSetRequest.required_freshness_ms",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.EvaluateObjectSetResponse.source",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.EvaluateObjectSetResponse.query_digest",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.EvaluateObjectSetResponse.object_versions",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.EvaluateObjectSetResponse.outcome",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.ListDecisionsResponse.earliest_retained_seq",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.ListDecisionsResponse.retained_from_ms",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.ListObjectChangesResponse.earliest_retained_seq",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.ListObjectChangesResponse.retained_from_ms",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.VerifyAttestationResponse.archived",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.VerifyAttestationResponse.archived_at_ms",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.ClaimAgentTurnRequest.accepts_continuation",
            "#[serde(default)]",
        )
        .field_attribute(
            "sekai.ListClaimableAgentTurnsRequest.accepts_continuation",
            "#[serde(default)]",
        )
        .compile_protos(
            &[
                format!("{proto_root}/sekai.proto"),
                format!("{proto_root}/chisei.proto"),
            ],
            &[proto_root.to_string()],
        )?;
    Ok(())
}

//! Grouped integration-test source set (#1308).
//!
//! Reference build-system analog: one Test task per source set. Each
//! self-contained `tests/*.rs` file is a module of this binary. Process-global
//! Prometheus recorder tests and `crate::`-coupled adapter, example, and
//! ratchet tests stay separate `[[test]]` targets.

mod action_approval_adr;
mod action_binding_adr;
mod action_binding_backend_conformance;
mod action_governance_backend_conformance;
mod agent_instruction_sync;
mod autonomous_envelope_adr;
mod capability_authoring;
mod capability_package_adr;
mod capability_package_backend_conformance;
mod chisei_budget_backend_conformance;
mod chisei_eval_backend_conformance;
mod chisei_evaluation_execution_backend_conformance;
mod chisei_evaluation_manifest_backend_conformance;
mod chisei_evaluation_plan_backend_conformance;
mod chisei_execution_backend_conformance;
mod chisei_external_action_backend_conformance;
mod chisei_external_permit_backend_conformance;
mod chisei_gateway_audit_backend_conformance;
mod chisei_governed_subject_provenance_backend_conformance;
mod chisei_gunshi_backend_conformance;
mod chisei_kioku_backend_conformance;
mod chisei_model_release_evidence_backend_conformance;
mod chisei_model_review_backend_conformance;
mod chisei_plane_process_adr;
mod chisei_policy_backend_conformance;
mod chisei_policy_shadow_backend_conformance;
mod chisei_portfolio_backend_conformance;
mod chisei_postgres_inventory_conformance;
mod chisei_routing_profile_backend_conformance;
mod client_package_adr;
mod client_package_backend_conformance;
mod combined_boot_operator_docs;
mod combined_two_store;
mod compatibility_matrix;
mod compatibility_matrix_adr;
mod concurrent_source_ingestion;
mod connector_certification_adr;
mod connector_certification_backend_conformance;
mod connector_template;
mod coordination_backend_conformance;
mod data_dir_store_layout;
mod data_quality_rule_adr;
mod dataset_health_backend_conformance;
mod dataset_rows_backend_conformance;
mod decision_backend_conformance;
mod definition_branch_backend_conformance;
mod definition_consumer_impact_adr;
mod definition_lifecycle_backend_conformance;
mod definition_migration_adr;
mod definition_migration_backend_conformance;
mod definition_proposal_adr;
mod deploy_tenkai_manifest;
mod dual_runtime_storage_adr;
mod enterprise_identity_contract;
mod epistemic_descriptor_proto;
mod epistemic_federation_conformance;
mod epistemic_interop_conformance;
mod epistemic_metadata_conformance;
mod evidence_backend_conformance;
mod experimental_rpc_operator_docs;
mod federation_backend_conformance;
mod federation_network_adr;
mod game_ai_players;
mod game_demo_report;
mod game_governance_pack;
mod game_reference_actions;
mod game_soak;
mod gateway_http_smoke;
mod geospatial_query_adr;
mod governed_fact_backend_conformance;
mod governed_image_adr;
mod governed_image_backend_conformance;
mod graph_backend_conformance;
mod guarded_mutation_backend_conformance;
mod host_executor_permit_conformance;
mod hosted_provider_smoke;
mod identity_assertion_conformance;
mod integration_contract;
mod lakehouse_snapshot_adr;
mod managed_shikigami_routing_fixture;
mod mcp_adapter;
mod mcp_definition_branch;
mod model_platform_adr;
mod model_release_evidence_adr;
mod namespace_model_review_adr;
mod namespace_object_generation_adr;
mod native_server_smoke;
mod object_change_operation_backend_conformance;
mod object_change_subscription_adr;
mod object_log_host_adr;
mod object_log_identity_adr;
mod object_path_benchmark;
mod object_security_backend_conformance;
mod object_security_property_grant_adr;
mod object_security_property_read_adr;
mod object_security_value_instance_adr;
mod object_set_adr;
mod object_sync_backend_conformance;
mod ollama_e2e;
mod ontology_export;
mod ontology_import;
mod open_table_backend_conformance;
mod operation_correlation_adr;
mod parked_work_backend_conformance;
mod partitioned_transform_io_adr;
mod perf_gate_cli;
mod performance_manifest;
mod policy_decision_pdp;
mod postgres_bind_hygiene;
mod product_loop_backend_conformance;
mod reference_workload_sharing;
mod relation_cardinality_adr;
mod relational_source_family_adr;
mod replica_conformance_adapter;
mod replica_safety_budget;
mod replica_safety_closeout;
mod replica_safety_credentials;
mod replica_safety_eval;
mod replica_safety_harness;
mod replica_safety_leases;
mod retention_dedup_backend_conformance;
mod reusable_sekai_backend_conformance;
mod rpc_maturity;
mod rpc_maturity_adr;
mod runtime_claim_client;
mod sample_observation_readback_docs;
mod sdk_external_consumer;
mod sekai_postgres_inventory_conformance;
mod sekaictl_alias_removal;
mod sekaictl_evaluation_compare;
mod sekaictl_evaluation_plan;
mod sekaictl_learning_pin;
mod sekaictl_semantic_reads;
mod service_file_ceilings;
mod service_principal_backend_conformance;
mod source_ingestion_benchmark;
mod source_registry_backend_conformance;
mod source_type_descriptor_adr;
mod source_type_descriptor_catalog;
mod source_type_descriptor_research;
mod source_type_registered_batches;
mod split_pool_budget;
mod sqlite_only_surfaces;
mod store_relocate_online;
mod team_namespace_backend_conformance;
mod tenant_isolation_conformance;
mod two_plane_processes;
mod warehouse_projection_adr;
mod workflow_action_adr;

#[path = "support/postgres_scratch.rs"]
mod postgres_scratch;

const SEPARATE_TARGETS: &[&str] = &[
    "auth_signals",
    "autonomous_envelope_adapters",
    "batch_harness_conformance",
    "chisei_runtime_db_ratchet",
    "db_signals",
    "dedup_signals",
    "deploy_kubernetes_manifest",
    "emit_git_version",
    "epistemic_replication_example",
    "evidence_adapters",
    "gateway_cache_signals",
    "lakehouse_snapshot_adapters",
    "model_platform_adapters",
    "object_sync_adapters",
    "observability",
    "resilience_load",
    "sekai_chisei_import_ratchet",
    "source_writeback_example",
    "warehouse_projection_adapters",
    "warehouse_table_ingest",
    "warehouse_table_writeback",
    "workflow_action_adapters",
];

/// Former self-contained `tests/*.rs` files compile as modules of `it`.
/// The `mod` declarations above are the grouped list; `SEPARATE_TARGETS`
/// mirrors the manifest's `[[test]]` targets. A `tests/*.rs` file that is
/// neither is a silent miss under `autotests = false`, so it fails by name.
#[test]
fn grouped_it_target_discovers_former_self_contained_tests() {
    use std::collections::BTreeSet;

    assert_eq!(
        env!("CARGO_CRATE_NAME"),
        "it",
        "this file must be the `it` test binary, not a leftover autodiscovered crate"
    );

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(
        manifest.contains("autotests = false"),
        "root package must disable integration-test autodiscovery"
    );

    let mut declared_tests = BTreeSet::new();
    let mut in_test = false;
    let mut current_name: Option<String> = None;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_test = trimmed == "[[test]]";
            current_name = None;
            continue;
        }
        if !in_test {
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix("name = \"")
            .and_then(|s| s.strip_suffix('"'))
        {
            current_name = Some(name.to_string());
        }
        if trimmed.starts_with("path = \"tests/")
            && let Some(name) = current_name.take()
        {
            declared_tests.insert(name);
        }
    }
    assert!(
        declared_tests.remove("it"),
        "Cargo.toml must declare the grouped `it` target"
    );

    // `mod name;` lines of this file, minus `#[path]` support modules.
    let it_src = std::fs::read_to_string(root.join("tests/it.rs")).unwrap();
    let mut grouped = BTreeSet::new();
    let mut after_path_attr = false;
    for line in it_src.lines() {
        if let Some(name) = line.strip_prefix("mod ").and_then(|s| s.strip_suffix(';'))
            && !after_path_attr
        {
            grouped.insert(name.to_string());
        }
        after_path_attr = line.starts_with("#[path");
    }

    let files: BTreeSet<String> = std::fs::read_dir(root.join("tests"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs"))
        .map(|path| path.file_stem().unwrap().to_str().unwrap().to_string())
        .filter(|name| name != "it")
        .collect();
    let separate: BTreeSet<String> = SEPARATE_TARGETS.iter().map(|s| s.to_string()).collect();

    let unlisted: Vec<_> = files
        .iter()
        .filter(|name| !grouped.contains(*name) && !declared_tests.contains(*name))
        .collect();
    let both: Vec<_> = grouped.intersection(&declared_tests).collect();
    let targets_without_file: Vec<_> = declared_tests.difference(&files).collect();
    let separate_not_in_manifest: Vec<_> = separate.difference(&declared_tests).collect();
    let manifest_not_in_separate: Vec<_> = declared_tests.difference(&separate).collect();
    assert!(
        unlisted.is_empty()
            && both.is_empty()
            && targets_without_file.is_empty()
            && separate_not_in_manifest.is_empty()
            && manifest_not_in_separate.is_empty(),
        "integration-test layout drift:\n  \
         neither `mod` in tests/it.rs nor [[test]]: {unlisted:?}\n  \
         both grouped and [[test]]: {both:?}\n  \
         [[test]] without tests/<name>.rs: {targets_without_file:?}\n  \
         SEPARATE_TARGETS missing from Cargo.toml: {separate_not_in_manifest:?}\n  \
         [[test]] missing from SEPARATE_TARGETS: {manifest_not_in_separate:?}"
    );
}

//! Grouped integration-test source set (#1308).
//!
//! Palantir `gradle-baseline` analog: one Test task per source set. Each
//! self-contained `tests/*.rs` file is a module of this binary. Process-global
//! Prometheus recorder tests and `crate::`-coupled adapter, example, and
//! ratchet tests stay separate `[[test]]` targets.

mod action_approval_adr;
mod action_binding_adr;
mod action_governance_backend_conformance;
mod agent_instruction_sync;
mod autonomous_envelope_adr;
mod capability_authoring;
mod capability_package_adr;
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
mod chisei_kioku_backend_conformance;
mod chisei_plane_process_adr;
mod chisei_policy_backend_conformance;
mod chisei_portfolio_backend_conformance;
mod chisei_postgres_inventory_conformance;
mod chisei_routing_profile_backend_conformance;
mod client_package_adr;
mod combined_boot_operator_docs;
mod combined_two_store;
mod compatibility_matrix;
mod compatibility_matrix_adr;
mod concurrent_source_ingestion;
mod connector_certification_adr;
mod coordination_backend_conformance;
mod data_dir_store_layout;
mod data_quality_rule_adr;
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
mod epistemic_federation_conformance;
mod epistemic_interop_conformance;
mod epistemic_metadata_conformance;
mod evidence_backend_conformance;
mod experimental_rpc_operator_docs;
mod federation_network_adr;
mod gateway_http_smoke;
mod geospatial_query_adr;
mod governed_fact_backend_conformance;
mod governed_image_adr;
mod graph_backend_conformance;
mod guarded_mutation_backend_conformance;
mod host_executor_permit_conformance;
mod hosted_provider_smoke;
mod identity_assertion_conformance;
mod integration_contract;
mod lakehouse_snapshot_adr;
mod managed_shikigami_routing_fixture;
mod mcp_adapter;
mod model_platform_adr;
mod native_server_smoke;
mod object_change_subscription_adr;
mod object_log_host_adr;
mod object_security_backend_conformance;
mod object_security_property_grant_adr;
mod object_security_property_read_adr;
mod object_security_value_instance_adr;
mod object_set_adr;
mod object_sync_backend_conformance;
mod ollama_e2e;
mod operation_correlation_adr;
mod parked_work_backend_conformance;
mod perf_gate_cli;
mod performance_manifest;
mod policy_decision_pdp;
mod postgres_bind_hygiene;
mod product_loop_backend_conformance;
mod relation_cardinality_adr;
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
mod sample_observation_readback_docs;
mod sdk_external_consumer;
mod sekai_postgres_inventory_conformance;
mod sekaictl_alias_removal;
mod sekaictl_evaluation_compare;
mod sekaictl_evaluation_plan;
mod sekaictl_learning_pin;
mod sekaictl_semantic_reads;
mod service_file_ceilings;
mod source_ingestion_benchmark;
mod source_type_descriptor_adr;
mod source_type_descriptor_catalog;
mod source_type_descriptor_research;
mod source_type_registered_batches;
mod split_pool_budget;
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

const GROUPED_MODULES: &[&str] = &[
    "action_approval_adr",
    "action_binding_adr",
    "action_governance_backend_conformance",
    "agent_instruction_sync",
    "autonomous_envelope_adr",
    "capability_authoring",
    "capability_package_adr",
    "chisei_budget_backend_conformance",
    "chisei_eval_backend_conformance",
    "chisei_evaluation_execution_backend_conformance",
    "chisei_evaluation_manifest_backend_conformance",
    "chisei_evaluation_plan_backend_conformance",
    "chisei_execution_backend_conformance",
    "chisei_external_action_backend_conformance",
    "chisei_external_permit_backend_conformance",
    "chisei_gateway_audit_backend_conformance",
    "chisei_governed_subject_provenance_backend_conformance",
    "chisei_kioku_backend_conformance",
    "chisei_plane_process_adr",
    "chisei_policy_backend_conformance",
    "chisei_portfolio_backend_conformance",
    "chisei_postgres_inventory_conformance",
    "chisei_routing_profile_backend_conformance",
    "client_package_adr",
    "combined_boot_operator_docs",
    "combined_two_store",
    "compatibility_matrix",
    "compatibility_matrix_adr",
    "concurrent_source_ingestion",
    "connector_certification_adr",
    "coordination_backend_conformance",
    "data_dir_store_layout",
    "data_quality_rule_adr",
    "decision_backend_conformance",
    "definition_branch_backend_conformance",
    "definition_consumer_impact_adr",
    "definition_lifecycle_backend_conformance",
    "definition_migration_adr",
    "definition_migration_backend_conformance",
    "definition_proposal_adr",
    "deploy_tenkai_manifest",
    "dual_runtime_storage_adr",
    "enterprise_identity_contract",
    "epistemic_federation_conformance",
    "epistemic_interop_conformance",
    "epistemic_metadata_conformance",
    "evidence_backend_conformance",
    "experimental_rpc_operator_docs",
    "federation_network_adr",
    "gateway_http_smoke",
    "geospatial_query_adr",
    "governed_fact_backend_conformance",
    "governed_image_adr",
    "graph_backend_conformance",
    "guarded_mutation_backend_conformance",
    "host_executor_permit_conformance",
    "hosted_provider_smoke",
    "identity_assertion_conformance",
    "integration_contract",
    "lakehouse_snapshot_adr",
    "managed_shikigami_routing_fixture",
    "mcp_adapter",
    "model_platform_adr",
    "native_server_smoke",
    "object_change_subscription_adr",
    "object_log_host_adr",
    "object_security_backend_conformance",
    "object_security_property_grant_adr",
    "object_security_property_read_adr",
    "object_security_value_instance_adr",
    "object_set_adr",
    "object_sync_backend_conformance",
    "ollama_e2e",
    "operation_correlation_adr",
    "parked_work_backend_conformance",
    "perf_gate_cli",
    "performance_manifest",
    "policy_decision_pdp",
    "postgres_bind_hygiene",
    "product_loop_backend_conformance",
    "relation_cardinality_adr",
    "replica_conformance_adapter",
    "replica_safety_budget",
    "replica_safety_closeout",
    "replica_safety_credentials",
    "replica_safety_eval",
    "replica_safety_harness",
    "replica_safety_leases",
    "retention_dedup_backend_conformance",
    "reusable_sekai_backend_conformance",
    "rpc_maturity",
    "rpc_maturity_adr",
    "sample_observation_readback_docs",
    "sdk_external_consumer",
    "sekai_postgres_inventory_conformance",
    "sekaictl_alias_removal",
    "sekaictl_evaluation_compare",
    "sekaictl_evaluation_plan",
    "sekaictl_learning_pin",
    "sekaictl_semantic_reads",
    "service_file_ceilings",
    "source_ingestion_benchmark",
    "source_type_descriptor_adr",
    "source_type_descriptor_catalog",
    "source_type_descriptor_research",
    "source_type_registered_batches",
    "split_pool_budget",
    "store_relocate_online",
    "team_namespace_backend_conformance",
    "tenant_isolation_conformance",
    "two_plane_processes",
    "warehouse_projection_adr",
    "workflow_action_adr",
];

/// Former self-contained `tests/*.rs` files compile as modules of `it`.
/// A new file that is neither listed here nor as a `[[test]]` target is a
/// silent miss under `autotests = false`.
#[test]
fn grouped_it_target_discovers_former_self_contained_tests() {
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

    let it_src = std::fs::read_to_string(root.join("tests/it.rs")).unwrap();
    let mut declared_tests = std::collections::BTreeSet::new();
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
        declared_tests.contains("it"),
        "Cargo.toml must declare the grouped `it` target"
    );
    assert!(
        declared_tests.contains("gateway_cache_signals"),
        "gateway_cache_signals must remain its own test executable"
    );

    let mut files = Vec::new();
    for entry in std::fs::read_dir(root.join("tests")).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        if name != "it" {
            files.push(name);
        }
    }
    files.sort();

    let mut missing_mods = Vec::new();
    let mut missing_targets = Vec::new();
    let mut unexpected = Vec::new();
    for name in &files {
        if GROUPED_MODULES.contains(&name.as_str()) {
            if !it_src.contains(&format!("mod {name};")) {
                missing_mods.push(name.clone());
            }
            if declared_tests.contains(name) {
                unexpected.push(format!("{name} grouped but also a [[test]] target"));
            }
        } else if SEPARATE_TARGETS.contains(&name.as_str()) {
            if !declared_tests.contains(name) {
                missing_targets.push(name.clone());
            }
            if it_src.contains(&format!("mod {name};")) {
                unexpected.push(format!("{name} must stay a separate binary"));
            }
        } else {
            unexpected.push(format!("{name} is neither grouped nor a separate target"));
        }
    }
    assert!(
        missing_mods.is_empty() && missing_targets.is_empty() && unexpected.is_empty(),
        "integration-test layout drift:\n  missing mods: {missing_mods:?}\n  missing [[test]]: {missing_targets:?}\n  unexpected: {unexpected:?}"
    );

    for name in SEPARATE_TARGETS {
        assert!(
            declared_tests.contains(*name),
            "{name} must remain a separate test executable"
        );
    }
    assert_eq!(GROUPED_MODULES.len(), 113);
    assert_eq!(SEPARATE_TARGETS.len(), 21);
}

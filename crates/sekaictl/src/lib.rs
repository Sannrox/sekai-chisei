//! Operator CLI for the Sekai Chisei control plane.
//!
//! This crate is the `sekaictl` binary. It talks to a running plane over
//! authenticated gRPC and opens local stores through `chisei-core` and
//! `sekai-core`. It does not depend on the server library.

pub mod action_cli;
pub mod attest_cli;
pub mod audit_export_cli;
pub mod autonomous_envelope_cli;
pub mod budget_cli;
pub mod capability_package_cli;
mod cli_args;
pub mod client_package_cli;
pub mod compatibility_cli;
pub mod compatibility_matrix;
pub mod compliance_cli;
pub mod compliance_pack;
pub mod connector_certification_cli;
pub mod connector_template;
pub mod credential_cli;
pub mod decision_trend_cli;
pub mod document_cli;
pub mod evaluation_plan_cli;
pub mod event_stream_cli;
pub mod federation_cli;
pub mod federation_network_cli;
pub mod geospatial_cli;
pub mod governed_subject_cli;
pub mod gunshi_cli;
pub mod image_cli;
pub mod inbox_cli;
pub mod lakehouse_snapshot_cli;
pub mod launch;
pub mod learning_cli;
pub mod model_platform_cli;
pub mod model_release_evidence_cli;
pub mod model_review_cli;
pub mod models_cli;
pub mod onboarding;
pub mod ontology_draft;
pub mod ontology_export;
pub mod ontology_import;
pub mod ontology_inspect;
pub mod ontology_product_cli;
pub mod open_table_cli;
pub mod probe_cli;
pub mod probe_runner;
pub mod probe_spec;
pub mod quality_cli;
pub mod receipt_chain_cli;
pub mod receipt_cli;
pub mod replay_cli;
pub mod report_cli;
pub mod retention_cli;
pub mod source_webhook_cli;
pub mod team_cli;
pub mod transform_cli;
pub mod unmarked_cli;
pub mod value_flags;
pub mod warehouse_projection_cli;
pub mod weekly_report_cli;
pub mod workflow_action_cli;

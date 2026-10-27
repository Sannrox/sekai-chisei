//! Chisei persistence: the store handle, its per-family ports, the backend
//! traits, and their SQLite and PostgreSQL implementations. It sits above
//! `sekai_core::db` (Sekai persistence, which never names it, ADR 0096) and beside
//! `crate::chisei`, whose domain code reaches it only through `ChiseiStore`
//! and its ports (ADR 0083 rule 6).

pub mod chisei;
pub mod chisei_eval_backend;
pub mod chisei_external_action;
pub mod chisei_external_permit;
pub mod chisei_kioku;
pub mod chisei_model_release_evidence;
pub mod chisei_model_review;
pub mod chisei_portfolio;
pub mod chisei_portfolio_backend;
pub mod chisei_routing_profile;
mod data_quality_store;
pub mod eval_run;
mod evaluation_execution;
mod evaluation_manifest;
mod evaluation_plan;
pub mod ext;
mod handle;
mod learning_change_store;
pub mod policy_shadow;
#[cfg(test)]
mod portfolio_route_test_cases;
mod ports;
mod postgres_chisei_receipts;
mod postgres_eval;
mod postgres_evaluation_execution;
mod postgres_evaluation_manifest;
mod postgres_evaluation_plan;
mod postgres_external_action;
mod postgres_external_permit;
mod postgres_kioku;
mod postgres_model_release_evidence;
mod postgres_model_review;
mod postgres_portfolio;
mod postgres_routing_profile;
mod postgres_usage_ledger;
pub mod runtime;
pub use runtime::ChiseiRuntimeDb;

#[cfg(test)]
pub use handle::paired_memory;
pub use handle::{ChiseiStore, split_shared_runtime};
pub use ports::{
    ChiseiBudgetStore, ChiseiDataQualityStore, ChiseiDecisionStore, ChiseiEvalStore,
    ChiseiEvaluationStore, ChiseiEvolveStore, ChiseiExternalActionStore, ChiseiGatewayStore,
    ChiseiGovernedSubjectStore, ChiseiGunshiStore, ChiseiKiokuStore, ChiseiLearningChangeStore,
    ChiseiModelReleaseEvidenceStore, ChiseiModelReviewStore, ChiseiObservationStore,
    ChiseiPermitStore, ChiseiPolicyShadowStore, ChiseiPortfolioStore, ChiseiReceiptStore,
    ChiseiRoutingProfileStore,
};

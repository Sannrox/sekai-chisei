//! Chisei persistence traits over [`ChiseiStore`] (ADR 0083 rule 6).
//!
//! Chisei code reaches its own tables through these per-family traits instead
//! of the backend facade. Each method mirrors the backend method of the same
//! name and delegates to it unchanged, so SQLite and PostgreSQL behavior,
//! errors, and idempotency stay exactly as before. Sekai facts are not part of
//! these traits; Chisei reads them through `crate::chisei::sekai_facts`.

#![allow(clippy::too_many_arguments)]

use ed25519_dalek::VerifyingKey;

use super::ChiseiStore;
use crate::chisei::eval;
use crate::chisei::external_action::{
    AuthorizationClaim, AuthorizationRecord, ExternalActionRequest,
};
use crate::chisei::external_permit::{
    ExternalPermitPolicy, HostContext, Permit, Redemption, RedemptionTiming,
};
use crate::chisei::kioku::{
    CandidateDerivation, HumanMemoryReview, KiokuEvidenceLink, KiokuEvidenceReassessmentRequest,
    KiokuEvidenceReassessmentResult, KiokuMemory, MemoryImpactEvaluation, MemoryLifecycleEvent,
    MemoryLifecycleSweep, MemoryOutcomeAssignment, MemoryOutcomeObservation,
    MemoryRetrievalRequest, MemoryValidation, RetrievedMemory,
};
use crate::chisei::portfolio::{FrontierPoint, Objective, Observation, RouteSelection};
use crate::chisei::receipt::OperationReceipt;
use crate::db::chisei_operation_reservation::OperationReservation;
use crate::sekai::audit::{Decision, DecisionFilter};
use crate::sekai::evidence::EvidenceClassification;

/// Declares a Chisei persistence trait and implements it for [`ChiseiStore`]
/// by forwarding each method to the backend method of the same name.
macro_rules! chisei_store_trait {
    (
        $(#[$meta:meta])*
        pub trait $name:ident {
            $(fn $method:ident(&self $(, $arg:ident: $ty:ty)* $(,)?) -> $ret:ty;)*
        }
    ) => {
        $(#[$meta])*
        pub trait $name {
            $(fn $method(&self $(, $arg: $ty)*) -> $ret;)*
        }

        impl $name for ChiseiStore {
            $(fn $method(&self $(, $arg: $ty)*) -> $ret {
                self.inner.$method($($arg),*)
            })*
        }
    };
}

/// Decision ledger rows Chisei records. Combined Split writes these to the
/// Sekai dest (ADR 0083 rule 1); Shared and Chisei-only keep them on `inner`.
pub trait ChiseiDecisionStore {
    fn record_decision(&self, decision: &Decision) -> Result<(), String>;
    fn list_decisions(&self, filter: &DecisionFilter) -> Result<Vec<Decision>, String>;
    fn get_decision(&self, id: &str) -> Result<Option<Decision>, String>;
    fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String>;
    fn record_decisions_idempotently_by(
        &self,
        decisions: &[Decision],
        equivalent: impl Fn(&Decision, &Decision) -> bool,
    ) -> Result<(), String>;
    fn list_decisions_for_action_namespace(
        &self,
        action: &str,
        namespace: &str,
    ) -> Result<Vec<Decision>, String>;
}

impl ChiseiDecisionStore for ChiseiStore {
    fn record_decision(&self, decision: &Decision) -> Result<(), String> {
        self.decision_runtime().record_decision(decision)
    }
    fn list_decisions(&self, filter: &DecisionFilter) -> Result<Vec<Decision>, String> {
        self.decision_runtime().list_decisions(filter)
    }
    fn get_decision(&self, id: &str) -> Result<Option<Decision>, String> {
        self.decision_runtime().get_decision(id)
    }
    fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String> {
        self.decision_runtime()
            .record_decisions_idempotently(decisions)
    }
    fn record_decisions_idempotently_by(
        &self,
        decisions: &[Decision],
        equivalent: impl Fn(&Decision, &Decision) -> bool,
    ) -> Result<(), String> {
        self.decision_runtime()
            .record_decisions_idempotently_by(decisions, equivalent)
    }
    fn list_decisions_for_action_namespace(
        &self,
        action: &str,
        namespace: &str,
    ) -> Result<Vec<Decision>, String> {
        self.decision_runtime()
            .list_decisions_for_action_namespace(action, namespace)
    }
}

chisei_store_trait! {
    /// Budget limits, reservations, usage, and transfers.
    pub trait ChiseiBudgetStore {
        fn budget_set_limit_scoped(&self, scope_id: &str, metric: &str, max_amount: i64, period_type: &str, home_site_id: &str, pool_id: &str) -> Result<(), String>;
        fn budget_set_pool_ceiling(&self, pool_id: &str, metric: &str, max_amount: i64, period_type: &str) -> Result<(), String>;
        fn budget_check_chain_for_site(&self, scope_id: &str, metric: &str, amount: i64, now_ms: i64, require_home_pin: bool, local_site_id: &str, partition_simulated: bool) -> Result<(), String>;
        fn budget_check_and_reserve_chain_for_site(&self, scope_id: &str, metric: &str, amount: i64, now_ms: i64, idempotency_key: Option<&str>, require_home_pin: bool, local_site_id: &str, partition_simulated: bool) -> Result<(), String>;
        fn budget_adjust_chain_for_site(&self, scope_id: &str, metric: &str, delta: i64, now_ms: i64, require_home_pin: bool, local_site_id: &str) -> Result<(), String>;
        fn budget_assert_home_writable(&self, scope_id: &str, metric: &str, local_site_id: &str) -> Result<(), String>;
        fn budget_record_idempotent(&self, scope_id: &str, metric: &str, amount: i64, idempotency_key: &str, now_ms: i64) -> Result<bool, String>;
        fn budget_usage(&self, scope_id: &str, metric: &str, now_ms: i64) -> Result<(i64, i64, String), String>;
        fn budget_namespace_pressure(&self, namespace: &str, metric: &str, now_ms: i64) -> Result<i32, String>;
        fn budget_get_transfer(&self, transfer_id: &str) -> Result<Option<crate::db::chisei_budget::BudgetTransferRecord>, String>;
        fn budget_transfer_capacity(&self, transfer_id: &str, metric: &str, from_scope_id: &str, to_scope_id: &str, amount: i64, actor: &str, now_ms: i64) -> Result<crate::db::chisei_budget::BudgetTransferRecord, String>;
        fn budget_record_transfer_refused(&self, transfer_id: &str, metric: &str, from_scope_id: &str, to_scope_id: &str, amount: i64, actor: &str, reason: &str, now_ms: i64) -> Result<crate::db::chisei_budget::BudgetTransferRecord, String>;
    }
}

chisei_store_trait! {
    /// Operation receipts and cross-store operation reservations.
    pub trait ChiseiReceiptStore {
        fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String>;
        fn get_operation_receipt(&self, operation_id: &str) -> Result<Option<OperationReceipt>, String>;
        fn find_operation_receipt_by_request_id(&self, request_id: &str) -> Result<Option<OperationReceipt>, String>;
        fn put_operation_reservation(&self, reservation: &OperationReservation) -> Result<OperationReservation, String>;
        fn get_operation_reservation(&self, namespace: &str, operation_id: &str) -> Result<Option<OperationReservation>, String>;
        fn list_pending_operation_reservations(&self, limit: usize) -> Result<Vec<OperationReservation>, String>;
    }
}

chisei_store_trait! {
    /// Kioku memories, evidence links, lifecycle, and outcomes.
    pub trait ChiseiKiokuStore {
        fn insert_kioku_memory(&self, memory: &KiokuMemory, evidence: &[KiokuEvidenceLink]) -> Result<(), String>;
        fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String>;
        fn list_kioku_candidates(&self, namespace: &str, operation_class: Option<&str>, limit: usize) -> Result<Vec<KiokuMemory>, String>;
        fn produce_kioku_candidate(&self, input: CandidateDerivation) -> Result<KiokuMemory, String>;
        fn validate_kioku_candidate(&self, id: &str, version: u32) -> Result<MemoryValidation, String>;
        fn review_kioku_candidate(&self, id: &str, version: u32, review: HumanMemoryReview) -> Result<KiokuMemory, String>;
        fn disable_kioku_memory(&self, id: &str, version: u32, actor: &str, rationale: &str, recorded_at_ms: i64) -> Result<KiokuMemory, String>;
        fn reassess_kioku_memory(&self, request: KiokuEvidenceReassessmentRequest) -> Result<KiokuEvidenceReassessmentResult, String>;
        fn list_kioku_evidence(&self, id: &str, version: u32) -> Result<Vec<KiokuEvidenceLink>, String>;
        fn list_kioku_lifecycle_events(&self, id: &str, version: u32) -> Result<Vec<MemoryLifecycleEvent>, String>;
        fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String>;
        fn sweep_kioku_lifecycle(&self, actor: &str, now_ms: i64) -> Result<MemoryLifecycleSweep, String>;
        fn retrieve_kioku_memories(&self, request: &MemoryRetrievalRequest) -> Result<Vec<RetrievedMemory>, String>;
        fn kioku_authorized_classification_ceiling(&self, namespace: &str, actor: &str) -> Result<EvidenceClassification, String>;
        fn record_kioku_holdout(&self, id: &str, version: u32, operation_id: &str, actor: &str, now_ms: i64) -> Result<(), String>;
        fn record_kioku_outcome(&self, observation: &MemoryOutcomeObservation) -> Result<bool, String>;
        fn list_kioku_outcome_assignments(&self, operation_id: &str) -> Result<Vec<MemoryOutcomeAssignment>, String>;
        fn evaluate_kioku_impact_if_ready(&self, id: &str, version: u32, minimum_samples_per_arm: usize, regression_threshold: f64, actor: &str, now_ms: i64) -> Result<Option<MemoryImpactEvaluation>, String>;
        fn put_operation_receipt_with_kioku_holdouts(&self, receipt: &OperationReceipt, holdouts: &[(String, u32)], actor: &str, recorded_at_ms: i64) -> Result<(), String>;
    }
}

chisei_store_trait! {
    /// External permits, redemptions, delegation, and kill switches.
    pub trait ChiseiPermitStore {
        fn put_permit(&self, permit: &Permit, idempotency_key: &str, issued_by: &str) -> Result<Permit, String>;
        fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String>;
        fn redeem_permit(&self, permit: &Permit, context: &HostContext, trusted_key: &VerifyingKey, idempotency_key: &str, execution_id: &str, host_site_id: &str, now_ms: i64) -> Result<Redemption, String>;
        fn redeem_or_reconcile_permit(&self, permit: &Permit, context: &HostContext, trusted_key: &VerifyingKey, idempotency_key: &str, execution_id: &str, host_site_id: &str, timing: RedemptionTiming) -> Result<Redemption, String>;
        fn replay_redemption(&self, permit: &Permit, idempotency_key: &str, execution_id: &str) -> Result<Option<Redemption>, String>;
        fn revoke_permit(&self, handle: &str, actor: &str, reason: &str, now_ms: i64) -> Result<bool, String>;
        fn validate_permit_state(&self, permit: &Permit) -> Result<(), String>;
        fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String>;
        fn set_permit_kill_switch(&self, kind: &str, value: &str, enabled: bool, reason: &str, now_ms: i64) -> Result<bool, String>;
        fn set_external_permit_policy(&self, policy: &ExternalPermitPolicy, now_ms: i64) -> Result<(), String>;
    }
}

chisei_store_trait! {
    /// External action authorizations and blast-radius accounting.
    pub trait ChiseiExternalActionStore {
        fn claim_external_action_authorization(&self, request: &ExternalActionRequest, request_digest: &str, authorization_id: &str, now_ms: i64) -> Result<AuthorizationClaim, String>;
        fn put_external_action_authorization(&self, record: &AuthorizationRecord) -> Result<(), String>;
        fn compare_and_swap_external_action_authorization(&self, expected: &AuthorizationRecord, next: &AuthorizationRecord) -> Result<bool, String>;
        fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String>;
        fn release_external_action_blast_radius(&self, authorization_id: &str, request: &ExternalActionRequest) -> Result<(), String>;
    }
}

chisei_store_trait! {
    /// Evaluation suites, runs, and iterations.
    pub trait ChiseiEvalStore {
        fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String>;
        fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String>;
        fn get_eval_suite_record_for_gate(&self, id: &str) -> Result<Option<eval::Suite>, String>;
        fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String>;
        fn append_feedback_eval_suite(&self, suite: &eval::Suite) -> Result<(), String>;
        fn put_eval_run(&self, run: &eval::Run) -> Result<(), String>;
        fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String>;
        fn get_latest_eval_run_record_for_gate(&self, suite_id: &str, config_ref: &str, max_timestamp_ms: i64) -> Result<Option<eval::Run>, String>;
        fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String>;
        fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String>;
        fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String>;
        fn list_eval_iteration_records(&self, suite_id: &str) -> Result<Vec<eval::Iteration>, String>;
        fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String>;
        fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String>;
    }
}

chisei_store_trait! {
    /// Sample observations awaiting scoring.
    pub trait ChiseiObservationStore {
        fn put_sample_observation(&self, obs: &crate::chisei::scoring::SampleObservation) -> Result<(), String>;
        fn list_unscored_observations(&self, limit: i32) -> Result<Vec<crate::chisei::scoring::SampleObservation>, String>;
        fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String>;
        fn delete_observation(&self, request_id: &str) -> Result<(), String>;
    }
}

chisei_store_trait! {
    /// Portfolio observations, objectives, and routes.
    pub trait ChiseiPortfolioStore {
        fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String>;
        fn portfolio_points(&self, namespace: &str, task_class: &str) -> Result<Vec<FrontierPoint>, String>;
        fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String>;
        fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String>;
        fn portfolio_damped_route(&self, namespace: &str, task_class: &str, proposed_model: &str, proposed_prompt_variant: &str, now_ms: i64, force: bool) -> Result<RouteSelection, String>;
    }
}

chisei_store_trait! {
    /// Data-quality rules and results.
    pub trait ChiseiDataQualityStore {
        fn put_data_quality_rule(&self, record: &crate::chisei::data_quality::DataQualityRule) -> Result<(), String>;
        fn get_data_quality_rule(&self, namespace: &str, rule_id: &str) -> Result<Option<crate::chisei::data_quality::DataQualityRule>, String>;
        fn list_data_quality_rules(&self, namespace: Option<&str>) -> Result<Vec<crate::chisei::data_quality::DataQualityRule>, String>;
        fn put_data_quality_result(&self, record: &crate::chisei::data_quality::DataQualityResult) -> Result<(), String>;
        fn get_data_quality_result(&self, result_id: &str) -> Result<Option<crate::chisei::data_quality::DataQualityResult>, String>;
        fn list_data_quality_results(&self, namespace: Option<&str>) -> Result<Vec<crate::chisei::data_quality::DataQualityResult>, String>;
    }
}

chisei_store_trait! {
    /// Learning-change records.
    pub trait ChiseiLearningChangeStore {
        fn put_learning_change(&self, record: &crate::chisei::learning_change::LearningChange) -> Result<(), String>;
        fn get_learning_change(&self, change_id: &str) -> Result<Option<crate::chisei::learning_change::LearningChange>, String>;
        fn list_learning_changes(&self, namespace: Option<&str>) -> Result<Vec<crate::chisei::learning_change::LearningChange>, String>;
    }
}

chisei_store_trait! {
    /// Gunshi allocation state.
    pub trait ChiseiGunshiStore {
        fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String>;
        fn put_gunshi_allocation_state_cas(&self, namespace: &str, revision_id: &str, changed_at_ms: i64, state_json: &str, expected_revision: Option<&str>) -> Result<bool, String>;
    }
}

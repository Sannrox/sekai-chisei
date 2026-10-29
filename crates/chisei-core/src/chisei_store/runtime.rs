//! Chisei-typed `RuntimeDb` methods. They live here, next to the Chisei stores
//! they dispatch to, so `sekai_core::db` never names Chisei (ADR 0096).
#![allow(clippy::too_many_arguments)]

use crate::chisei::eval;
use crate::chisei::evaluation_execution::EvaluationExecutionIndex;
use crate::chisei::evolve;
use crate::chisei::external_action::{
    AuthorizationClaim, AuthorizationRecord, ExternalActionRequest, ExternalActionSekaiDbExt,
};
use crate::chisei::external_permit::{
    ExternalPermitPolicy, ExternalPermitSekaiDbExt, HostContext, Permit, Redemption,
    RedemptionTiming,
};
use crate::chisei::kioku::*;
use crate::chisei::portfolio::{FrontierPoint, Objective, Observation, RouteSelection};
use crate::chisei_store::ext::*;
use crate::sekai_principal::SekaiPrincipalRuntimeDbExt;
use ed25519_dalek::VerifyingKey;
use sekai_core::db::runtime_db::RuntimeDb;
use sekai_core::sekai::evidence::EvidenceClassification;
use sekai_domain::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use sekai_types::governed_subject_provenance::ExportRecord;
use sekai_types::principal::PrincipalContext;

use super::operation_reservation::OperationReservation;

fn verify_evaluation_manifest(
    manifest: crate::chisei::evaluation_manifest::ResolvedEvaluationManifest,
) -> Result<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest, String> {
    let canonical = crate::chisei::evaluation_manifest::prepare_manifest(manifest.clone())
        .map_err(|error| format!("invalid persisted evaluation manifest: {error}"))?;
    if canonical != manifest {
        return Err("persisted evaluation manifest content binding is invalid".into());
    }
    Ok(manifest)
}

pub struct EvaluationManifestWrite {
    pub manifest: crate::chisei::evaluation_manifest::ResolvedEvaluationManifest,
    pub request_id: String,
    pub request_digest: String,
}

#[cfg(any(test, feature = "gateway-test-support"))]
thread_local! {
    /// Hosted routing-profile catalog reads on this thread (#1185-#1187).
    pub static HOSTED_PROFILE_LISTS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

pub trait ChiseiRuntimeDb {
    fn with_evaluation_resolution_snapshot<T, E, F, M>(
        &self,
        operation: F,
        map_db_error: M,
    ) -> Result<
        (
            T,
            Option<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest>,
        ),
        E,
    >
    where
        F: FnOnce() -> Result<(T, Option<EvaluationManifestWrite>), E>,
        M: Fn(String) -> E;

    fn get_evaluation_execution_index(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<EvaluationExecutionIndex>, String>;

    fn create_evaluation_execution(
        &self,
        index: &EvaluationExecutionIndex,
        receipt: &OperationReceipt,
    ) -> Result<EvaluationExecutionIndex, String>;

    fn list_kioku_lifecycle_events_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<MemoryLifecycleEvent>, String>;

    fn list_kioku_outcomes_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<MemoryOutcomeObservation>, String>;

    fn abandon_external_action_claim(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
    ) -> Result<(), String>;

    fn claim_external_action_authorization(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
        authorization_id: &str,
        now_ms: i64,
    ) -> Result<AuthorizationClaim, String>;

    fn compare_and_swap_external_action_authorization(
        &self,
        expected: &AuthorizationRecord,
        next: &AuthorizationRecord,
    ) -> Result<bool, String>;

    fn disable_kioku_memory(
        &self,
        id: &str,
        version: u32,
        actor: &str,
        rationale: &str,
        recorded_at_ms: i64,
    ) -> Result<KiokuMemory, String>;

    fn evaluate_kioku_impact_if_ready(
        &self,
        id: &str,
        version: u32,
        minimum_samples_per_arm: usize,
        regression_threshold: f64,
        actor: &str,
        now_ms: i64,
    ) -> Result<Option<MemoryImpactEvaluation>, String>;

    fn get_external_action_authorization_by_id(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AuthorizationRecord>, String>;

    fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String>;

    fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String>;

    fn reassess_kioku_memory(
        &self,
        request: KiokuEvidenceReassessmentRequest,
    ) -> Result<KiokuEvidenceReassessmentResult, String>;

    fn reassess_kioku_memory_after_graph_auth(
        &self,
        request: KiokuEvidenceReassessmentRequest,
    ) -> Result<KiokuEvidenceReassessmentResult, String>;

    fn authorize_kioku_retrieval(&self, request: &MemoryRetrievalRequest) -> Result<(), String>;

    fn authorize_kioku_evidence(
        &self,
        request: &KiokuEvidenceAuthorizationRequest,
    ) -> Result<(), String>;

    fn put_evaluator_definition(
        &self,
        definition: crate::chisei::evaluation_plan::EvaluatorDefinition,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::chisei::evaluation_plan::EvaluatorDefinition, String>;

    fn get_evaluator_definition(
        &self,
        definition_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluatorDefinition>, String>;

    fn list_evaluator_definitions(
        &self,
        namespace: &str,
        evaluator_id: Option<&str>,
    ) -> Result<Vec<crate::chisei::evaluation_plan::EvaluatorDefinition>, String>;

    fn get_evaluator_availability(
        &self,
        definition_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluatorAvailability>, String>;

    #[allow(clippy::too_many_arguments)]
    fn set_evaluator_availability(
        &self,
        definition_id: &str,
        state: &str,
        superseded_by_definition_id: &str,
        reason: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::chisei::evaluation_plan::EvaluatorAvailability, String>;

    fn put_evaluation_plan(
        &self,
        plan: crate::chisei::evaluation_plan::EvaluationPlan,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::chisei::evaluation_plan::EvaluationPlan, String>;

    fn get_evaluation_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest>, String>;

    fn get_evaluation_manifest_for_request(
        &self,
        namespace: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_manifest::EvaluationManifestReplay>, String>;

    fn put_evaluation_manifest(
        &self,
        manifest: &crate::chisei::evaluation_manifest::ResolvedEvaluationManifest,
        request_id: &str,
        request_digest: &str,
    ) -> Result<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest, String>;

    fn get_evaluation_plan(
        &self,
        plan_version_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluationPlan>, String>;

    fn list_evaluation_plans(
        &self,
        namespace: &str,
        plan_id: Option<&str>,
    ) -> Result<Vec<crate::chisei::evaluation_plan::EvaluationPlan>, String>;

    fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String>;

    fn list_kioku_candidates(
        &self,
        namespace: &str,
        operation_class: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KiokuMemory>, String>;

    fn list_kioku_candidate_page(
        &self,
        namespace: &str,
        limit: usize,
        cursor: Option<&crate::chisei::kioku::KiokuCandidateCursor>,
    ) -> Result<Vec<KiokuMemory>, String>;

    fn list_kioku_evidence(&self, id: &str, version: u32)
    -> Result<Vec<KiokuEvidenceLink>, String>;

    fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String>;

    fn list_kioku_outcome_assignments(
        &self,
        operation_id: &str,
    ) -> Result<Vec<MemoryOutcomeAssignment>, String>;

    fn list_unscored_observations(
        &self,
        limit: i32,
    ) -> Result<Vec<crate::chisei::scoring::SampleObservation>, String>;

    fn put_external_action_authorization(&self, record: &AuthorizationRecord)
    -> Result<(), String>;

    fn put_hosted_routing_profile(
        &self,
        profile: &crate::chisei::routing_profiles::HostedRoutingProfile,
    ) -> Result<(), String>;

    fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::routing_profiles::HostedRoutingProfile>, String>;

    fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn list_all_hosted_routing_profiles(
        &self,
    ) -> Result<Vec<crate::chisei::routing_profiles::HostedRoutingProfile>, String>;

    fn start_policy_shadow(
        &self,
        shadow: &crate::chisei::policy_shadow::PolicyShadow,
    ) -> Result<(), String>;

    fn stop_policy_shadow(
        &self,
        namespace: &str,
        shadow_id: Option<&str>,
        unclaimed_at_ms: Option<i64>,
    ) -> Result<bool, String>;

    fn claim_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn confirm_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        claimed_at_ms: i64,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn find_policy_shadow(
        &self,
        scopes: &[String],
    ) -> Result<Option<crate::chisei::policy_shadow::PolicyShadow>, String>;

    fn record_policy_shadow_observation(
        &self,
        shadow_id: &str,
        sample: &crate::chisei::policy_shadow::ShadowSample,
    ) -> Result<(), String>;

    fn policy_shadow_report(
        &self,
        namespace: &str,
    ) -> Result<Option<crate::chisei::policy_shadow::PolicyShadowReport>, String>;

    fn put_model_review_record(
        &self,
        record: &crate::chisei::model_review::ModelReviewRecord,
    ) -> Result<(), String>;

    fn insert_model_review_record_if_absent(
        &self,
        record: &crate::chisei::model_review::ModelReviewRecord,
    ) -> Result<bool, String>;

    fn get_model_review_record(
        &self,
        namespace: &str,
        provider: &str,
        model: &str,
        artifact_digest: &str,
    ) -> Result<Option<crate::chisei::model_review::ModelReviewRecord>, String>;

    fn list_model_review_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_review::ModelReviewRecord>, String>;

    fn put_family_enablement_record(
        &self,
        record: &crate::chisei::model_review::FamilyEnablementRecord,
    ) -> Result<(), String>;

    fn insert_family_enablement_record_if_absent(
        &self,
        record: &crate::chisei::model_review::FamilyEnablementRecord,
    ) -> Result<bool, String>;

    fn get_family_enablement_record(
        &self,
        namespace: &str,
        region_label: &str,
        family_id: &str,
    ) -> Result<Option<crate::chisei::model_review::FamilyEnablementRecord>, String>;

    fn list_family_enablement_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_review::FamilyEnablementRecord>, String>;

    fn model_review_row_count(&self) -> Result<i64, String>;

    fn family_enablement_row_count(&self) -> Result<i64, String>;

    fn put_model_release_trust(
        &self,
        roots: &crate::chisei::model_release_evidence::EvaluationTrustRoots,
        updated_at_ms: i64,
    ) -> Result<(), String>;

    fn get_model_release_trust(
        &self,
    ) -> Result<Option<crate::chisei::model_release_evidence::EvaluationTrustRoots>, String>;

    fn put_model_runtime_evidence(
        &self,
        evidence: &crate::chisei::model_release_evidence::ModelRuntimeEvidence,
        ingested_at_ms: i64,
    ) -> Result<(), String>;

    fn get_model_runtime_evidence(
        &self,
        identity: &crate::chisei::model_release_evidence::ModelReleaseIdentity,
    ) -> Result<Option<String>, String>;

    fn put_model_evaluation_export(
        &self,
        evidence: &crate::chisei::model_release_evidence::ModelEvaluationEvidence,
        exported_at_ms: i64,
    ) -> Result<(), String>;

    fn get_model_evaluation_export(
        &self,
        identity: &crate::chisei::model_release_evidence::ModelReleaseIdentity,
    ) -> Result<Option<String>, String>;

    fn put_model_release_feedback(
        &self,
        record: &crate::chisei::model_release_evidence::ModelReleaseFeedback,
    ) -> Result<(), String>;

    fn list_model_release_feedback(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_release_evidence::ModelReleaseFeedback>, String>;

    fn put_sample_observation(
        &self,
        obs: &crate::chisei::scoring::SampleObservation,
    ) -> Result<(), String>;

    fn get_sample_observation(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String>;

    fn get_sample_observation_in_namespace(
        &self,
        request_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String>;

    fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String>;

    fn record_kioku_outcome(&self, observation: &MemoryOutcomeObservation) -> Result<bool, String>;

    fn redeem_or_reconcile_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        timing: RedemptionTiming,
    ) -> Result<Redemption, String>;

    fn release_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
    ) -> Result<(), String>;

    fn reserve_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
        max_mutations: Option<u32>,
        max_deletes: Option<u32>,
    ) -> Result<(), String>;

    fn review_kioku_candidate(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String>;

    fn review_kioku_candidate_after_graph_auth(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String>;

    fn set_external_permit_policy(
        &self,
        policy: &ExternalPermitPolicy,
        now_ms: i64,
    ) -> Result<(), String>;

    fn validate_kioku_candidate(&self, id: &str, version: u32) -> Result<MemoryValidation, String>;

    fn put_learning_change(
        &self,
        record: &crate::chisei::learning_change::LearningChange,
    ) -> Result<(), String>;

    fn get_learning_change(
        &self,
        change_id: &str,
    ) -> Result<Option<crate::chisei::learning_change::LearningChange>, String>;

    fn list_learning_changes(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::learning_change::LearningChange>, String>;

    fn put_data_quality_rule(
        &self,
        record: &crate::chisei::data_quality::DataQualityRule,
    ) -> Result<(), String>;

    fn get_data_quality_rule(
        &self,
        namespace: &str,
        rule_id: &str,
    ) -> Result<Option<crate::chisei::data_quality::DataQualityRule>, String>;

    fn list_data_quality_rules(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::data_quality::DataQualityRule>, String>;

    fn put_data_quality_result(
        &self,
        record: &crate::chisei::data_quality::DataQualityResult,
    ) -> Result<(), String>;

    fn get_data_quality_result(
        &self,
        result_id: &str,
    ) -> Result<Option<crate::chisei::data_quality::DataQualityResult>, String>;

    fn list_data_quality_results(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::data_quality::DataQualityResult>, String>;

    fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String>;

    fn get_latest_eval_run_record_for_gate(
        &self,
        suite_id: &str,
        config_ref: &str,
        max_timestamp_ms: i64,
    ) -> Result<Option<eval::Run>, String>;

    fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String>;

    fn get_eval_suite_record_for_gate(&self, id: &str) -> Result<Option<eval::Suite>, String>;

    fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String>;

    fn list_eval_iteration_records(&self, suite_id: &str) -> Result<Vec<eval::Iteration>, String>;

    fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String>;

    fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String>;

    fn portfolio_damped_route(
        &self,
        namespace: &str,
        task_class: &str,
        proposed_model: &str,
        proposed_prompt_variant: &str,
        now_ms: i64,
        force: bool,
    ) -> Result<RouteSelection, String>;

    fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String>;

    fn portfolio_points(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String>;

    fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String>;

    fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String>;

    fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String>;

    fn put_eval_run(&self, run: &eval::Run) -> Result<(), String>;

    fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String>;

    fn append_feedback_eval_suite(&self, suite: &eval::Suite) -> Result<(), String>;

    fn retrieve_kioku_memories(
        &self,
        request: &MemoryRetrievalRequest,
    ) -> Result<Vec<RetrievedMemory>, String>;

    fn retrieve_kioku_memories_after_graph_auth(
        &self,
        request: &MemoryRetrievalRequest,
    ) -> Result<Vec<RetrievedMemory>, String>;

    fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String>;

    fn produce_kioku_candidate(&self, input: CandidateDerivation) -> Result<KiokuMemory, String>;

    fn sweep_kioku_lifecycle(
        &self,
        actor: &str,
        now_ms: i64,
    ) -> Result<MemoryLifecycleSweep, String>;

    fn count_active_kioku_promotions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
    ) -> Result<i64, String>;

    fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String>;

    fn authorize_operation_reporter(
        &self,
        operation_id: &str,
        principal: &str,
        event_kinds: Vec<ReceiptEventKind>,
    ) -> Result<bool, String>;

    fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String>;

    fn claim_gateway_request_alias_dispatch(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
        dispatch_token: &str,
    ) -> Result<bool, String>;

    fn delete_observation(&self, request_id: &str) -> Result<(), String>;

    fn find_gateway_receipt_by_logical_operation_id(
        &self,
        operation_id: &str,
        attempt: Option<u32>,
    ) -> Result<Option<OperationReceipt>, String>;

    fn find_operation_receipt_by_lookup_request_id(
        &self,
        request_id: &str,
        caller_scope: Option<&str>,
        initiating_actor: Option<&str>,
    ) -> Result<Option<OperationReceipt>, String>;

    fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String>;

    fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String>;

    fn kioku_authorized_classification_ceiling(
        &self,
        namespace: &str,
        actor: &str,
    ) -> Result<EvidenceClassification, String>;

    fn list_evolve_task_records(&self) -> Result<Vec<evolve::TaskRecord>, String>;

    fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String>;

    fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String>;

    fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String>;

    fn put_evolve_task(&self, task: &evolve::TaskRecord) -> Result<(), String>;

    fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String>;

    fn put_gunshi_allocation_state_cas(
        &self,
        namespace: &str,
        revision_id: &str,
        changed_at_ms: i64,
        state_json: &str,
        expected_revision: Option<&str>,
    ) -> Result<bool, String>;

    fn put_operation_receipt_with_kioku_holdouts(
        &self,
        receipt: &OperationReceipt,
        holdouts: &[(String, u32)],
        actor: &str,
        recorded_at_ms: i64,
    ) -> Result<(), String>;

    fn put_permit(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        issued_by: &str,
    ) -> Result<Permit, String>;

    fn replay_permit(
        &self,
        authorization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Permit>, String>;

    fn replay_redemption(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        execution_id: &str,
    ) -> Result<Option<Redemption>, String>;

    fn reserve_gateway_request_alias(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
    ) -> Result<bool, String>;

    fn revoke_permit(
        &self,
        handle: &str,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn set_permit_kill_switch(
        &self,
        kind: &str,
        value: &str,
        enabled: bool,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String>;

    fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String>;

    fn validate_permit_state(&self, permit: &Permit) -> Result<(), String>;

    fn record_kioku_holdout(
        &self,
        id: &str,
        version: u32,
        operation_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String>;

    fn redeem_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        now_ms: i64,
    ) -> Result<Redemption, String>;

    fn put_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
        record: &ExportRecord,
    ) -> Result<(ExportRecord, bool), String>;

    fn get_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
    ) -> Result<Option<ExportRecord>, String>;

    fn get_operation_reservation(
        &self,
        namespace: &str,
        operation_id: &str,
    ) -> Result<Option<OperationReservation>, String>;

    fn put_operation_reservation(
        &self,
        reservation: &OperationReservation,
    ) -> Result<OperationReservation, String>;

    fn settle_pending_reservation(
        &self,
        next: &OperationReservation,
        refund_metric: Option<&str>,
    ) -> Result<Option<OperationReservation>, String>;

    fn list_pending_operation_reservations(
        &self,
        limit: usize,
    ) -> Result<Vec<OperationReservation>, String>;
}

impl ChiseiRuntimeDb for RuntimeDb {
    fn with_evaluation_resolution_snapshot<T, E, F, M>(
        &self,
        operation: F,
        map_db_error: M,
    ) -> Result<
        (
            T,
            Option<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest>,
        ),
        E,
    >
    where
        F: FnOnce() -> Result<(T, Option<EvaluationManifestWrite>), E>,
        M: Fn(String) -> E,
    {
        match self {
            Self::Sqlite(db) if db.is_persistent() => {
                let mut connection = db.conn();
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|error| map_db_error(error.to_string()))?;
                let (value, write) = operation()?;
                let stored = write
                    .map(|write| {
                        verify_evaluation_manifest(write.manifest.clone())
                            .map_err(&map_db_error)?;
                        let stored =
                            crate::chisei_store::evaluation_manifest::put_evaluation_manifest_in_transaction(
                                &transaction,
                                &write.manifest,
                                &write.request_id,
                                &write.request_digest,
                            )
                            .map_err(&map_db_error)?;
                        verify_evaluation_manifest(stored).map_err(&map_db_error)
                    })
                    .transpose()?;
                transaction
                    .commit()
                    .map_err(|error| map_db_error(error.to_string()))?;
                Ok((value, stored))
            }
            Self::Sqlite(_) => {
                // The single-connection in-memory backend is a test fixture;
                // holding its only connection while calling the normal read
                // APIs would deadlock. Production SQLite uses the locked path.
                let (value, write) = operation()?;
                let stored = write
                    .map(|write| {
                        self.put_evaluation_manifest(
                            &write.manifest,
                            &write.request_id,
                            &write.request_digest,
                        )
                        .map_err(&map_db_error)
                    })
                    .transpose()?;
                Ok((value, stored))
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                if db.max_connections() < 2 {
                    return Err(map_db_error(
                        "evaluation resolution requires at least two PostgreSQL connections".into(),
                    ));
                }
                let mut connection = db.connection().map_err(&map_db_error)?;
                let mut transaction = connection
                    .transaction()
                    .map_err(|error| map_db_error(error.to_string()))?;
                // SHARE-lock every mutable community table consulted by live
                // resolution that exists on this dest. Combined Split Chisei
                // dests omit Sekai graph tables. SHARE blocks concurrent
                // INSERT/UPDATE/DELETE while pooled readers stay usable. The
                // manifest/request tables remain governed by their advisory
                // idempotency locks.
                sekai_core::db::postgres::lock_existing_evaluation_resolution_tables(
                    &mut transaction,
                )
                .map_err(&map_db_error)?;
                let (value, write) = operation()?;
                let stored = write
                    .map(|write| {
                        verify_evaluation_manifest(write.manifest.clone())
                            .map_err(&map_db_error)?;
                        let stored = crate::chisei_store::postgres_evaluation_manifest::put_evaluation_manifest_in_transaction(
                            &mut transaction,
                            &write.manifest,
                            &write.request_id,
                            &write.request_digest,
                        )
                        .map_err(&map_db_error)?;
                        verify_evaluation_manifest(stored).map_err(&map_db_error)
                    })
                    .transpose()?;
                transaction
                    .commit()
                    .map_err(|error| map_db_error(error.to_string()))?;
                Ok((value, stored))
            }),
        }
    }

    fn get_evaluation_execution_index(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<EvaluationExecutionIndex>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluation_execution_index(manifest_digest),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_evaluation_execution_index(manifest_digest)
            }),
        }
    }

    fn create_evaluation_execution(
        &self,
        index: &EvaluationExecutionIndex,
        receipt: &OperationReceipt,
    ) -> Result<EvaluationExecutionIndex, String> {
        match self {
            Self::Sqlite(db) => db.create_evaluation_execution(index, receipt),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.create_evaluation_execution(index, receipt)
            }),
        }
    }

    fn list_kioku_lifecycle_events_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<MemoryLifecycleEvent>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_lifecycle_events_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_kioku_lifecycle_events_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    limit,
                )
            }),
        }
    }

    fn list_kioku_outcomes_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<MemoryOutcomeObservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_outcomes_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_kioku_outcomes_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    limit,
                )
            }),
        }
    }

    fn abandon_external_action_claim(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.abandon_external_action_claim(request, request_digest),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.abandon_external_action_claim(request, request_digest)
            }),
        }
    }

    fn claim_external_action_authorization(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
        authorization_id: &str,
        now_ms: i64,
    ) -> Result<AuthorizationClaim, String> {
        match self {
            Self::Sqlite(db) => db.claim_external_action_authorization(
                request,
                request_digest,
                authorization_id,
                now_ms,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.claim_external_action_authorization(
                    request,
                    request_digest,
                    authorization_id,
                    now_ms,
                )
            }),
        }
    }

    fn compare_and_swap_external_action_authorization(
        &self,
        expected: &AuthorizationRecord,
        next: &AuthorizationRecord,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.compare_and_swap_external_action_authorization(expected, next),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.compare_and_swap_external_action_authorization(expected, next)
            }),
        }
    }

    fn disable_kioku_memory(
        &self,
        id: &str,
        version: u32,
        actor: &str,
        rationale: &str,
        recorded_at_ms: i64,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => {
                db.disable_kioku_memory(id, version, actor, rationale, recorded_at_ms)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.disable_kioku_memory(id, version, actor, rationale, recorded_at_ms)
            }),
        }
    }

    fn evaluate_kioku_impact_if_ready(
        &self,
        id: &str,
        version: u32,
        minimum_samples_per_arm: usize,
        regression_threshold: f64,
        actor: &str,
        now_ms: i64,
    ) -> Result<Option<MemoryImpactEvaluation>, String> {
        match self {
            Self::Sqlite(db) => db.evaluate_kioku_impact_if_ready(
                id,
                version,
                minimum_samples_per_arm,
                regression_threshold,
                actor,
                now_ms,
            ),
            Self::Postgres(_) => Err(
                "evaluate_kioku_impact_if_ready is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    fn get_external_action_authorization_by_id(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AuthorizationRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_external_action_authorization_by_id(authorization_id),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_external_action_authorization_by_id(authorization_id)
            }),
        }
    }

    fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
        match self {
            Self::Sqlite(db) => db.get_external_permit_policy(scope),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_external_permit_policy(scope))
            }
        }
    }

    fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.get_kioku_memory(id, version),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_kioku_memory(id, version))
            }
        }
    }

    fn reassess_kioku_memory(
        &self,
        request: KiokuEvidenceReassessmentRequest,
    ) -> Result<KiokuEvidenceReassessmentResult, String> {
        match self {
            Self::Sqlite(db) => {
                crate::chisei_store::chisei_kioku::ChiseiKiokuBackend::reassess_kioku_memory(
                    db.as_ref(),
                    request,
                )
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                crate::chisei_store::chisei_kioku::ChiseiKiokuBackend::reassess_kioku_memory(
                    db.as_ref(),
                    request,
                )
            }),
        }
    }

    fn reassess_kioku_memory_after_graph_auth(
        &self,
        request: KiokuEvidenceReassessmentRequest,
    ) -> Result<KiokuEvidenceReassessmentResult, String> {
        match self {
            Self::Sqlite(db) => {
                crate::chisei_store::chisei_kioku::ChiseiKiokuBackend::reassess_kioku_memory_after_graph_auth(
                    db.as_ref(),
                    request,
                )
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                crate::chisei_store::chisei_kioku::ChiseiKiokuBackend::reassess_kioku_memory_after_graph_auth(
                    db.as_ref(),
                    request,
                )
            }),
        }
    }

    fn authorize_kioku_retrieval(&self, request: &MemoryRetrievalRequest) -> Result<(), String> {
        let actor = request.actor.trim();
        let namespace = request.namespace.trim();
        let authorized_ceiling = self.kioku_authorized_classification_ceiling(namespace, actor)?;
        if request.classification_ceiling > authorized_ceiling {
            return Err("requested memory classification exceeds actor grant".into());
        }
        let principal = PrincipalContext::from_credential(actor);
        for object_id in &request.context_object_ids {
            if self.get_object(object_id)?.is_none() {
                return Err(format!("context object {object_id} not found"));
            }
            let grants = self.list_principal_grants(object_id)?;
            if !grants.is_empty() && !principal.holds_grant(&grants) {
                return Err(format!(
                    "actor is not authorized for context object {object_id}"
                ));
            }
        }
        Ok(())
    }

    fn authorize_kioku_evidence(
        &self,
        request: &KiokuEvidenceAuthorizationRequest,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.authorize_kioku_evidence(request),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.authorize_kioku_evidence(request))
            }
        }
    }

    fn put_evaluator_definition(
        &self,
        definition: crate::chisei::evaluation_plan::EvaluatorDefinition,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::chisei::evaluation_plan::EvaluatorDefinition, String> {
        match self {
            Self::Sqlite(db) => db.put_evaluator_definition(definition, actor, now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.put_evaluator_definition(definition, actor, now_ms)
            }),
        }
    }

    fn get_evaluator_definition(
        &self,
        definition_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluatorDefinition>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluator_definition(definition_id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_evaluator_definition(definition_id))
            }
        }
    }

    fn list_evaluator_definitions(
        &self,
        namespace: &str,
        evaluator_id: Option<&str>,
    ) -> Result<Vec<crate::chisei::evaluation_plan::EvaluatorDefinition>, String> {
        match self {
            Self::Sqlite(db) => db.list_evaluator_definitions(namespace, evaluator_id),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_evaluator_definitions(namespace, evaluator_id)
            }),
        }
    }

    fn get_evaluator_availability(
        &self,
        definition_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluatorAvailability>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluator_availability(definition_id),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_evaluator_availability(definition_id)
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn set_evaluator_availability(
        &self,
        definition_id: &str,
        state: &str,
        superseded_by_definition_id: &str,
        reason: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::chisei::evaluation_plan::EvaluatorAvailability, String> {
        match self {
            Self::Sqlite(db) => db.set_evaluator_availability(
                definition_id,
                state,
                superseded_by_definition_id,
                reason,
                request_id,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.set_evaluator_availability(
                    definition_id,
                    state,
                    superseded_by_definition_id,
                    reason,
                    request_id,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    fn put_evaluation_plan(
        &self,
        plan: crate::chisei::evaluation_plan::EvaluationPlan,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::chisei::evaluation_plan::EvaluationPlan, String> {
        match self {
            Self::Sqlite(db) => db.put_evaluation_plan(plan, actor, now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.put_evaluation_plan(plan, actor, now_ms)
            }),
        }
    }

    fn get_evaluation_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest>, String>
    {
        let manifest = match self {
            Self::Sqlite(db) => db.get_evaluation_manifest(manifest_digest),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_evaluation_manifest(manifest_digest)
            }),
        }?;
        manifest
            .map(|manifest| {
                if manifest.manifest_digest != manifest_digest {
                    return Err(
                        "persisted evaluation manifest digest does not match its storage key"
                            .into(),
                    );
                }
                verify_evaluation_manifest(manifest)
            })
            .transpose()
    }

    fn get_evaluation_manifest_for_request(
        &self,
        namespace: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_manifest::EvaluationManifestReplay>, String> {
        let replay = match self {
            Self::Sqlite(db) => {
                db.get_evaluation_manifest_for_request(namespace, actor, request_id)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_evaluation_manifest_for_request(namespace, actor, request_id)
            }),
        }?;
        replay
            .map(|mut replay| {
                replay.manifest = verify_evaluation_manifest(replay.manifest)?;
                Ok(replay)
            })
            .transpose()
    }

    fn put_evaluation_manifest(
        &self,
        manifest: &crate::chisei::evaluation_manifest::ResolvedEvaluationManifest,
        request_id: &str,
        request_digest: &str,
    ) -> Result<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest, String> {
        verify_evaluation_manifest(manifest.clone())?;
        let stored = match self {
            Self::Sqlite(db) => db.put_evaluation_manifest(manifest, request_id, request_digest),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.put_evaluation_manifest(manifest, request_id, request_digest)
            }),
        }?;
        let stored = verify_evaluation_manifest(stored)?;
        if stored.manifest_digest != manifest.manifest_digest {
            return Err("evaluation manifest digest conflicts with stored content".into());
        }
        Ok(stored)
    }

    fn get_evaluation_plan(
        &self,
        plan_version_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluationPlan>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluation_plan(plan_version_id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_evaluation_plan(plan_version_id))
            }
        }
    }

    fn list_evaluation_plans(
        &self,
        namespace: &str,
        plan_id: Option<&str>,
    ) -> Result<Vec<crate::chisei::evaluation_plan::EvaluationPlan>, String> {
        match self {
            Self::Sqlite(db) => db.list_evaluation_plans(namespace, plan_id),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_evaluation_plans(namespace, plan_id)
            }),
        }
    }

    fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_external_action_authorizations(),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_external_action_authorizations())
            }
        }
    }

    fn list_kioku_candidates(
        &self,
        namespace: &str,
        operation_class: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_candidates(namespace, operation_class, limit),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_kioku_candidates(namespace, operation_class, limit)
            }),
        }
    }

    fn list_kioku_candidate_page(
        &self,
        namespace: &str,
        limit: usize,
        cursor: Option<&crate::chisei::kioku::KiokuCandidateCursor>,
    ) -> Result<Vec<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_candidate_page(namespace, limit, cursor),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_kioku_candidate_page(namespace, limit, cursor)
            }),
        }
    }

    fn list_kioku_evidence(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<KiokuEvidenceLink>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_evidence(id, version),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_kioku_evidence(id, version))
            }
        }
    }

    fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_lifecycle_events(id, version),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_kioku_lifecycle_events(id, version)
            }),
        }
    }

    fn list_kioku_outcome_assignments(
        &self,
        operation_id: &str,
    ) -> Result<Vec<MemoryOutcomeAssignment>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_outcome_assignments(operation_id),
            Self::Postgres(_) => Err(
                "list_kioku_outcome_assignments is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    fn list_unscored_observations(
        &self,
        limit: i32,
    ) -> Result<Vec<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_unscored_observations(limit),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_unscored_observations(limit))
            }
        }
    }

    fn put_external_action_authorization(
        &self,
        record: &AuthorizationRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_external_action_authorization(record),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.put_external_action_authorization(record)
            }),
        }
    }

    fn put_hosted_routing_profile(
        &self,
        profile: &crate::chisei::routing_profiles::HostedRoutingProfile,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_routing_profile::ChiseiRoutingProfileBackend;
        match self {
            Self::Sqlite(db) => db.put_hosted_routing_profile(profile),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiRoutingProfileBackend::put_hosted_routing_profile(db.as_ref(), profile)
            }),
        }
    }

    fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::routing_profiles::HostedRoutingProfile>, String> {
        use crate::chisei_store::chisei_routing_profile::ChiseiRoutingProfileBackend;
        #[cfg(any(test, feature = "gateway-test-support"))]
        HOSTED_PROFILE_LISTS.with(|lists| lists.set(lists.get() + 1));
        match self {
            Self::Sqlite(db) => db.list_hosted_routing_profiles(namespace),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiRoutingProfileBackend::list_hosted_routing_profiles(db.as_ref(), namespace)
            }),
        }
    }

    fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        use crate::chisei_store::chisei_routing_profile::ChiseiRoutingProfileBackend;
        match self {
            Self::Sqlite(db) => db.revoke_hosted_routing_profile(namespace, profile_id, now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiRoutingProfileBackend::revoke_hosted_routing_profile(
                    db.as_ref(),
                    namespace,
                    profile_id,
                    now_ms,
                )
            }),
        }
    }

    fn list_all_hosted_routing_profiles(
        &self,
    ) -> Result<Vec<crate::chisei::routing_profiles::HostedRoutingProfile>, String> {
        use crate::chisei_store::chisei_routing_profile::ChiseiRoutingProfileBackend;
        match self {
            Self::Sqlite(db) => db.list_all_hosted_routing_profiles(),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiRoutingProfileBackend::list_all_hosted_routing_profiles(db.as_ref())
            }),
        }
    }

    fn start_policy_shadow(
        &self,
        shadow: &crate::chisei::policy_shadow::PolicyShadow,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.start_policy_shadow(shadow),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.start_policy_shadow(shadow))
            }
        }
    }

    fn stop_policy_shadow(
        &self,
        namespace: &str,
        shadow_id: Option<&str>,
        unclaimed_at_ms: Option<i64>,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.stop_policy_shadow(namespace, shadow_id, unclaimed_at_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.stop_policy_shadow(namespace, shadow_id, unclaimed_at_ms)
            }),
        }
    }

    fn claim_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.claim_policy_shadow_activation(namespace, shadow_id, now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.claim_policy_shadow_activation(namespace, shadow_id, now_ms)
            }),
        }
    }

    fn confirm_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        claimed_at_ms: i64,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.confirm_policy_shadow_activation(namespace, shadow_id, claimed_at_ms, now_ms)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.confirm_policy_shadow_activation(namespace, shadow_id, claimed_at_ms, now_ms)
            }),
        }
    }

    fn find_policy_shadow(
        &self,
        scopes: &[String],
    ) -> Result<Option<crate::chisei::policy_shadow::PolicyShadow>, String> {
        match self {
            Self::Sqlite(db) => db.find_policy_shadow(scopes),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.find_policy_shadow(scopes))
            }
        }
    }

    fn record_policy_shadow_observation(
        &self,
        shadow_id: &str,
        sample: &crate::chisei::policy_shadow::ShadowSample,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_policy_shadow_observation(shadow_id, sample),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.record_policy_shadow_observation(shadow_id, sample)
            }),
        }
    }

    fn policy_shadow_report(
        &self,
        namespace: &str,
    ) -> Result<Option<crate::chisei::policy_shadow::PolicyShadowReport>, String> {
        match self {
            Self::Sqlite(db) => db.policy_shadow_report(namespace),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.policy_shadow_report(namespace))
            }
        }
    }

    fn put_model_review_record(
        &self,
        record: &crate::chisei::model_review::ModelReviewRecord,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.put_model_review_record(record),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::put_model_review_record(db.as_ref(), record)
            }),
        }
    }

    fn insert_model_review_record_if_absent(
        &self,
        record: &crate::chisei::model_review::ModelReviewRecord,
    ) -> Result<bool, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.insert_model_review_record_if_absent(record),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::insert_model_review_record_if_absent(db.as_ref(), record)
            }),
        }
    }

    fn get_model_review_record(
        &self,
        namespace: &str,
        provider: &str,
        model: &str,
        artifact_digest: &str,
    ) -> Result<Option<crate::chisei::model_review::ModelReviewRecord>, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => {
                db.get_model_review_record(namespace, provider, model, artifact_digest)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::get_model_review_record(
                    db.as_ref(),
                    namespace,
                    provider,
                    model,
                    artifact_digest,
                )
            }),
        }
    }

    fn list_model_review_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_review::ModelReviewRecord>, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.list_model_review_records(namespace),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::list_model_review_records(db.as_ref(), namespace)
            }),
        }
    }

    fn put_family_enablement_record(
        &self,
        record: &crate::chisei::model_review::FamilyEnablementRecord,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.put_family_enablement_record(record),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::put_family_enablement_record(db.as_ref(), record)
            }),
        }
    }

    fn insert_family_enablement_record_if_absent(
        &self,
        record: &crate::chisei::model_review::FamilyEnablementRecord,
    ) -> Result<bool, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.insert_family_enablement_record_if_absent(record),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::insert_family_enablement_record_if_absent(
                    db.as_ref(),
                    record,
                )
            }),
        }
    }

    fn get_family_enablement_record(
        &self,
        namespace: &str,
        region_label: &str,
        family_id: &str,
    ) -> Result<Option<crate::chisei::model_review::FamilyEnablementRecord>, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.get_family_enablement_record(namespace, region_label, family_id),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::get_family_enablement_record(
                    db.as_ref(),
                    namespace,
                    region_label,
                    family_id,
                )
            }),
        }
    }

    fn list_family_enablement_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_review::FamilyEnablementRecord>, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.list_family_enablement_records(namespace),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::list_family_enablement_records(db.as_ref(), namespace)
            }),
        }
    }

    fn model_review_row_count(&self) -> Result<i64, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.model_review_row_count(),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::model_review_row_count(db.as_ref())
            }),
        }
    }

    fn family_enablement_row_count(&self) -> Result<i64, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.family_enablement_row_count(),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::family_enablement_row_count(db.as_ref())
            }),
        }
    }

    fn put_model_release_trust(
        &self,
        roots: &crate::chisei::model_release_evidence::EvaluationTrustRoots,
        updated_at_ms: i64,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.put_model_release_trust(roots, updated_at_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::put_model_release_trust(
                    db.as_ref(),
                    roots,
                    updated_at_ms,
                )
            }),
        }
    }

    fn get_model_release_trust(
        &self,
    ) -> Result<Option<crate::chisei::model_release_evidence::EvaluationTrustRoots>, String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.get_model_release_trust(),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::get_model_release_trust(db.as_ref())
            }),
        }
    }

    fn put_model_runtime_evidence(
        &self,
        evidence: &crate::chisei::model_release_evidence::ModelRuntimeEvidence,
        ingested_at_ms: i64,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.put_model_runtime_evidence(evidence, ingested_at_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::put_model_runtime_evidence(
                    db.as_ref(),
                    evidence,
                    ingested_at_ms,
                )
            }),
        }
    }

    fn get_model_runtime_evidence(
        &self,
        identity: &crate::chisei::model_release_evidence::ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.get_model_runtime_evidence(identity),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::get_model_runtime_evidence(db.as_ref(), identity)
            }),
        }
    }

    fn put_model_evaluation_export(
        &self,
        evidence: &crate::chisei::model_release_evidence::ModelEvaluationEvidence,
        exported_at_ms: i64,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.put_model_evaluation_export(evidence, exported_at_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::put_model_evaluation_export(
                    db.as_ref(),
                    evidence,
                    exported_at_ms,
                )
            }),
        }
    }

    fn get_model_evaluation_export(
        &self,
        identity: &crate::chisei::model_release_evidence::ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.get_model_evaluation_export(identity),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::get_model_evaluation_export(
                    db.as_ref(),
                    identity,
                )
            }),
        }
    }

    fn put_model_release_feedback(
        &self,
        record: &crate::chisei::model_release_evidence::ModelReleaseFeedback,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.put_model_release_feedback(record),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::put_model_release_feedback(db.as_ref(), record)
            }),
        }
    }

    fn list_model_release_feedback(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_release_evidence::ModelReleaseFeedback>, String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.list_model_release_feedback(namespace),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::list_model_release_feedback(
                    db.as_ref(),
                    namespace,
                )
            }),
        }
    }

    fn put_sample_observation(
        &self,
        obs: &crate::chisei::scoring::SampleObservation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_sample_observation(obs),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.put_sample_observation(obs))
            }
        }
    }

    fn get_sample_observation(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.get_sample_observation(request_id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_sample_observation(request_id))
            }
        }
    }

    fn get_sample_observation_in_namespace(
        &self,
        request_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.get_sample_observation_in_namespace(request_id, namespace),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_sample_observation_in_namespace(request_id, namespace)
            }),
        }
    }

    fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_lifecycle_event(event),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.record_kioku_lifecycle_event(event))
            }
        }
    }

    fn record_kioku_outcome(&self, observation: &MemoryOutcomeObservation) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_outcome(observation),
            Self::Postgres(_) => Err(
                "record_kioku_outcome is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    fn redeem_or_reconcile_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        timing: RedemptionTiming,
    ) -> Result<Redemption, String> {
        match self {
            Self::Sqlite(db) => db.redeem_or_reconcile_permit(
                permit,
                context,
                trusted_key,
                idempotency_key,
                execution_id,
                host_site_id,
                timing,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.redeem_or_reconcile_permit(
                    permit,
                    context,
                    trusted_key,
                    idempotency_key,
                    execution_id,
                    host_site_id,
                    timing,
                )
            }),
        }
    }

    fn release_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_external_action_blast_radius(authorization_id, request),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.release_external_action_blast_radius(authorization_id, request)
            }),
        }
    }

    fn reserve_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
        max_mutations: Option<u32>,
        max_deletes: Option<u32>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.reserve_external_action_blast_radius(
                authorization_id,
                request,
                max_mutations,
                max_deletes,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.reserve_external_action_blast_radius(
                    authorization_id,
                    request,
                    max_mutations,
                    max_deletes,
                )
            }),
        }
    }

    fn review_kioku_candidate(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => db.review_kioku_candidate(id, version, review),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.review_kioku_candidate(id, version, review)
            }),
        }
    }

    fn review_kioku_candidate_after_graph_auth(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => db.review_kioku_candidate_after_graph_auth(id, version, review),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.review_kioku_candidate_after_graph_auth(id, version, review)
            }),
        }
    }

    fn set_external_permit_policy(
        &self,
        policy: &ExternalPermitPolicy,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_external_permit_policy(policy, now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.set_external_permit_policy(policy, now_ms)
            }),
        }
    }

    fn validate_kioku_candidate(&self, id: &str, version: u32) -> Result<MemoryValidation, String> {
        match self {
            Self::Sqlite(db) => db.validate_kioku_candidate(id, version),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.validate_kioku_candidate(id, version))
            }
        }
    }

    fn put_learning_change(
        &self,
        record: &crate::chisei::learning_change::LearningChange,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_learning_change(record),
            Self::Postgres(_) => Err(crate::chisei::learning_change::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn get_learning_change(
        &self,
        change_id: &str,
    ) -> Result<Option<crate::chisei::learning_change::LearningChange>, String> {
        match self {
            Self::Sqlite(db) => db.get_learning_change(change_id),
            Self::Postgres(_) => Err(crate::chisei::learning_change::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn list_learning_changes(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::learning_change::LearningChange>, String> {
        match self {
            Self::Sqlite(db) => db.list_learning_changes(namespace),
            Self::Postgres(_) => Err(crate::chisei::learning_change::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn put_data_quality_rule(
        &self,
        record: &crate::chisei::data_quality::DataQualityRule,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_data_quality_rule(record),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn get_data_quality_rule(
        &self,
        namespace: &str,
        rule_id: &str,
    ) -> Result<Option<crate::chisei::data_quality::DataQualityRule>, String> {
        match self {
            Self::Sqlite(db) => db.get_data_quality_rule(namespace, rule_id),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn list_data_quality_rules(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::data_quality::DataQualityRule>, String> {
        match self {
            Self::Sqlite(db) => db.list_data_quality_rules(namespace),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn put_data_quality_result(
        &self,
        record: &crate::chisei::data_quality::DataQualityResult,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_data_quality_result(record),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn get_data_quality_result(
        &self,
        result_id: &str,
    ) -> Result<Option<crate::chisei::data_quality::DataQualityResult>, String> {
        match self {
            Self::Sqlite(db) => db.get_data_quality_result(result_id),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn list_data_quality_results(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::data_quality::DataQualityResult>, String> {
        match self {
            Self::Sqlite(db) => db.list_data_quality_results(namespace),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_run_record(id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_eval_run_record(id))
            }
        }
    }

    fn get_latest_eval_run_record_for_gate(
        &self,
        suite_id: &str,
        config_ref: &str,
        max_timestamp_ms: i64,
    ) -> Result<Option<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => {
                db.get_latest_eval_run_record_for_gate(suite_id, config_ref, max_timestamp_ms)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_latest_eval_run_record_for_gate(suite_id, config_ref, max_timestamp_ms)
            }),
        }
    }

    fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_suite_record(id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_eval_suite_record(id))
            }
        }
    }

    fn get_eval_suite_record_for_gate(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_suite_record_for_gate(id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_eval_suite_record_for_gate(id))
            }
        }
    }

    fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_eval_iteration_records(),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_all_eval_iteration_records())
            }
        }
    }

    fn list_eval_iteration_records(&self, suite_id: &str) -> Result<Vec<eval::Iteration>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_iteration_records(suite_id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_eval_iteration_records(suite_id))
            }
        }
    }

    fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_run_records(suite_id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_eval_run_records(suite_id))
            }
        }
    }

    fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_suite_records(),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_eval_suite_records())
            }
        }
    }

    fn portfolio_damped_route(
        &self,
        namespace: &str,
        task_class: &str,
        proposed_model: &str,
        proposed_prompt_variant: &str,
        now_ms: i64,
        force: bool,
    ) -> Result<RouteSelection, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_damped_route(
                namespace,
                task_class,
                proposed_model,
                proposed_prompt_variant,
                now_ms,
                force,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.portfolio_damped_route(
                    namespace,
                    task_class,
                    proposed_model,
                    proposed_prompt_variant,
                    now_ms,
                    force,
                )
            }),
        }
    }

    fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_objective(namespace),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.portfolio_objective(namespace))
            }
        }
    }

    fn portfolio_points(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_points(namespace, task_class),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.portfolio_points(namespace, task_class))
            }
        }
    }

    fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.portfolio_record_observation(observation),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.portfolio_record_observation(observation)
            }),
        }
    }

    fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.portfolio_set_objective(objective),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.portfolio_set_objective(objective))
            }
        }
    }

    fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_iteration(iteration),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.put_eval_iteration(iteration))
            }
        }
    }

    fn put_eval_run(&self, run: &eval::Run) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_run(run),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| db.put_eval_run(run)),
        }
    }

    fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_suite(suite),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.put_eval_suite(suite))
            }
        }
    }

    fn append_feedback_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.append_feedback_eval_suite(suite),
            Self::Postgres(_) => Err(
                "append_feedback_eval_suite is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    fn retrieve_kioku_memories(
        &self,
        request: &MemoryRetrievalRequest,
    ) -> Result<Vec<RetrievedMemory>, String> {
        match self {
            Self::Sqlite(db) => db.retrieve_kioku_memories(request),
            Self::Postgres(_) => Err(
                "retrieve_kioku_memories is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    fn retrieve_kioku_memories_after_graph_auth(
        &self,
        request: &MemoryRetrievalRequest,
    ) -> Result<Vec<RetrievedMemory>, String> {
        match self {
            Self::Sqlite(db) => db.retrieve_kioku_memories_after_graph_auth(request),
            Self::Postgres(_) => Err(
                "retrieve_kioku_memories is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_kioku_memory(memory, evidence),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.insert_kioku_memory(memory, evidence))
            }
        }
    }

    fn produce_kioku_candidate(&self, input: CandidateDerivation) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => db.produce_kioku_candidate(input),
            Self::Postgres(_) => Err(
                "produce_kioku_candidate is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    fn sweep_kioku_lifecycle(
        &self,
        actor: &str,
        now_ms: i64,
    ) -> Result<MemoryLifecycleSweep, String> {
        match self {
            Self::Sqlite(db) => db.sweep_kioku_lifecycle(actor, now_ms),
            Self::Postgres(_) => Err(
                "sweep_kioku_lifecycle is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    fn count_active_kioku_promotions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
    ) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.count_active_kioku_promotions_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.count_active_kioku_promotions_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                )
            }),
        }
    }

    fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String> {
        match self {
            Self::Sqlite(db) => db.append_operation_receipt_event(operation_id, event),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.append_operation_receipt_event(operation_id, event)
            }),
        }
    }

    fn authorize_operation_reporter(
        &self,
        operation_id: &str,
        principal: &str,
        event_kinds: Vec<ReceiptEventKind>,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.authorize_operation_reporter(operation_id, principal, event_kinds)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.authorize_operation_reporter(operation_id, principal, event_kinds)
            }),
        }
    }

    fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.bump_observation_attempts(request_id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.bump_observation_attempts(request_id))
            }
        }
    }

    fn claim_gateway_request_alias_dispatch(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
        dispatch_token: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.claim_gateway_request_alias_dispatch(
                caller_scope,
                request_alias,
                request_id,
                operation_id,
                dispatch_token,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.claim_gateway_request_alias_dispatch(
                    caller_scope,
                    request_alias,
                    request_id,
                    operation_id,
                    dispatch_token,
                )
            }),
        }
    }

    fn delete_observation(&self, request_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_observation(request_id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.delete_observation(request_id))
            }
        }
    }

    fn find_gateway_receipt_by_logical_operation_id(
        &self,
        operation_id: &str,
        attempt: Option<u32>,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => {
                db.find_gateway_receipt_by_logical_operation_id(operation_id, attempt)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.find_gateway_receipt_by_logical_operation_id(operation_id, attempt)
            }),
        }
    }

    fn find_operation_receipt_by_lookup_request_id(
        &self,
        request_id: &str,
        caller_scope: Option<&str>,
        initiating_actor: Option<&str>,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.find_operation_receipt_by_lookup_request_id(
                request_id,
                caller_scope,
                initiating_actor,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.find_operation_receipt_by_lookup_request_id(
                    request_id,
                    caller_scope,
                    initiating_actor,
                )
            }),
        }
    }

    fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.find_operation_receipt_by_request_id(request_id),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.find_operation_receipt_by_request_id(request_id)
            }),
        }
    }

    fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_operation_receipt(receipt),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.insert_operation_receipt(receipt))
            }
        }
    }

    fn kioku_authorized_classification_ceiling(
        &self,
        namespace: &str,
        actor: &str,
    ) -> Result<EvidenceClassification, String> {
        match self {
            Self::Sqlite(db) => db.kioku_authorized_classification_ceiling(namespace, actor),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.kioku_authorized_classification_ceiling(namespace, actor)
            }),
        }
    }

    fn list_evolve_task_records(&self) -> Result<Vec<evolve::TaskRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_evolve_task_records(),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_evolve_task_records())
            }
        }
    }

    fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_eval_iterations_for_suite(suite_id, keep),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.prune_eval_iterations_for_suite(suite_id, keep)
            }),
        }
    }

    fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_eval_runs_for_suite(suite_id, keep),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.prune_eval_runs_for_suite(suite_id, keep)
            }),
        }
    }

    fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String> {
        match self {
            Self::Sqlite(db) => db.put_delegated_permit(permit, issued_by),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_delegated_permit(permit, issued_by))
            }
        }
    }

    fn put_evolve_task(&self, task: &evolve::TaskRecord) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_evolve_task(task),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.put_evolve_task(task))
            }
        }
    }

    fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.get_gunshi_allocation_state(namespace),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.get_gunshi_allocation_state(namespace))
            }
        }
    }

    fn put_gunshi_allocation_state_cas(
        &self,
        namespace: &str,
        revision_id: &str,
        changed_at_ms: i64,
        state_json: &str,
        expected_revision: Option<&str>,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.put_gunshi_allocation_state_cas(
                namespace,
                revision_id,
                changed_at_ms,
                state_json,
                expected_revision,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.put_gunshi_allocation_state_cas(
                    namespace,
                    revision_id,
                    changed_at_ms,
                    state_json,
                    expected_revision,
                )
            }),
        }
    }

    fn put_operation_receipt_with_kioku_holdouts(
        &self,
        receipt: &OperationReceipt,
        holdouts: &[(String, u32)],
        actor: &str,
        recorded_at_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_operation_receipt_with_kioku_holdouts(receipt, holdouts, actor, recorded_at_ms),
            Self::Postgres(_) => Err("put_operation_receipt_with_kioku_holdouts is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    fn put_permit(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        issued_by: &str,
    ) -> Result<Permit, String> {
        match self {
            Self::Sqlite(db) => db.put_permit(permit, idempotency_key, issued_by),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.put_permit(permit, idempotency_key, issued_by)
            }),
        }
    }

    fn replay_permit(
        &self,
        authorization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Permit>, String> {
        match self {
            Self::Sqlite(db) => db.replay_permit(authorization_id, idempotency_key),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.replay_permit(authorization_id, idempotency_key)
            }),
        }
    }

    fn replay_redemption(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        execution_id: &str,
    ) -> Result<Option<Redemption>, String> {
        match self {
            Self::Sqlite(db) => db.replay_redemption(permit, idempotency_key, execution_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.replay_redemption(permit, idempotency_key, execution_id)
            }),
        }
    }

    fn reserve_gateway_request_alias(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.reserve_gateway_request_alias(
                caller_scope,
                request_alias,
                request_id,
                operation_id,
            ),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.reserve_gateway_request_alias(
                    caller_scope,
                    request_alias,
                    request_id,
                    operation_id,
                )
            }),
        }
    }

    fn revoke_permit(
        &self,
        handle: &str,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.revoke_permit(handle, actor, reason, now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.revoke_permit(handle, actor, reason, now_ms)
            }),
        }
    }

    fn set_permit_kill_switch(
        &self,
        kind: &str,
        value: &str,
        enabled: bool,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.set_permit_kill_switch(kind, value, enabled, reason, now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.set_permit_kill_switch(kind, value, enabled, reason, now_ms)
            }),
        }
    }

    fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_delegation_chain(permit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.validate_delegation_chain(permit))
            }
        }
    }

    fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_permit_for_delegation(permit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.validate_permit_for_delegation(permit))
            }
        }
    }

    fn validate_permit_state(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_permit_state(permit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.validate_permit_state(permit))
            }
        }
    }

    fn record_kioku_holdout(
        &self,
        id: &str,
        version: u32,
        operation_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_holdout(id, version, operation_id, actor, now_ms),
            Self::Postgres(_) => Err(
                "record_kioku_holdout is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    fn redeem_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        now_ms: i64,
    ) -> Result<Redemption, String> {
        match self {
            Self::Sqlite(db) => db.redeem_permit(
                permit,
                context,
                trusted_key,
                idempotency_key,
                execution_id,
                host_site_id,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.redeem_permit(
                    permit,
                    context,
                    trusted_key,
                    idempotency_key,
                    execution_id,
                    host_site_id,
                    now_ms,
                )
            }),
        }
    }

    fn put_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
        record: &ExportRecord,
    ) -> Result<(ExportRecord, bool), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_subject_provenance_export(actor, export_id, record),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.put_governed_subject_provenance_export(actor, export_id, record)
            }),
        }
    }

    fn get_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
    ) -> Result<Option<ExportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_subject_provenance_export(actor, export_id),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_governed_subject_provenance_export(actor, export_id)
            }),
        }
    }

    fn get_operation_reservation(
        &self,
        namespace: &str,
        operation_id: &str,
    ) -> Result<Option<OperationReservation>, String> {
        match self {
            Self::Sqlite(db) => db.get_operation_reservation(namespace, operation_id),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_operation_reservation(namespace, operation_id)
            }),
        }
    }

    fn put_operation_reservation(
        &self,
        reservation: &OperationReservation,
    ) -> Result<OperationReservation, String> {
        match self {
            Self::Sqlite(db) => db.put_operation_reservation(reservation),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.put_operation_reservation(reservation))
            }
        }
    }

    fn settle_pending_reservation(
        &self,
        next: &OperationReservation,
        refund_metric: Option<&str>,
    ) -> Result<Option<OperationReservation>, String> {
        match self {
            Self::Sqlite(db) => db.settle_pending_reservation(next, refund_metric),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.settle_pending_reservation(next, refund_metric)
            }),
        }
    }

    fn list_pending_operation_reservations(
        &self,
        limit: usize,
    ) -> Result<Vec<OperationReservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_pending_operation_reservations(limit),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_pending_operation_reservations(limit)
            }),
        }
    }
}

#[cfg(test)]
mod evaluation_resolution_snapshot_tests {
    use super::ChiseiRuntimeDb;
    use sekai_core::db::runtime_db::RuntimeDb;
    use sekai_core::domain::Object;
    use std::collections::HashMap;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    #[test]
    fn persistent_sqlite_snapshot_excludes_concurrent_prerequisite_writes() {
        let path = std::env::temp_dir().join(format!(
            "sekai-evaluation-snapshot-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let path_string = path.to_string_lossy().into_owned();
        let db = RuntimeDb::Sqlite(Arc::new(
            crate::chisei_store::open_sekai_with_chisei_schema(&path_string),
        ));
        let resolver_db = db.clone();
        let writer_db = db.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let resolver = std::thread::spawn(move || {
            resolver_db
                .with_evaluation_resolution_snapshot(
                    || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok::<_, String>(((), None))
                    },
                    |error| error,
                )
                .unwrap();
        });
        entered_rx.recv().unwrap();
        let (written_tx, written_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            writer_db
                .create_object(&Object {
                    id: "concurrent-prerequisite".into(),
                    kind: "document".into(),
                    name: "Concurrent prerequisite".into(),
                    namespace: "acme".into(),
                    external_id: "document:concurrent".into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                })
                .unwrap();
            written_tx.send(()).unwrap();
        });
        assert!(written_rx.recv_timeout(Duration::from_millis(100)).is_err());
        release_tx.send(()).unwrap();
        written_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        resolver.join().unwrap();
        writer.join().unwrap();
        drop(db);
        std::fs::remove_file(path).ok();
    }
}

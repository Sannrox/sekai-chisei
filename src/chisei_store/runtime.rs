//! Chisei-typed `RuntimeDb` methods. They live here, next to the Chisei stores
//! they dispatch to, so `crate::db` never names Chisei (ADR 0096).
#![allow(clippy::too_many_arguments)]

use crate::chisei::eval;
use crate::chisei::evaluation_execution::EvaluationExecutionIndex;
use crate::chisei::external_action::{
    AuthorizationClaim, AuthorizationRecord, ExternalActionRequest,
};
use crate::chisei::external_permit::{
    ExternalPermitPolicy, HostContext, Permit, Redemption, RedemptionTiming,
};
use crate::chisei::kioku::*;
use crate::chisei::portfolio::{FrontierPoint, Objective, Observation, RouteSelection};
use crate::chisei_store::chisei_kioku::ChiseiKiokuBackend;
use crate::db::runtime_db::RuntimeDb;
use ed25519_dalek::VerifyingKey;
use sekai_domain::receipt::OperationReceipt;
use sekai_types::principal::PrincipalContext;

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

pub(crate) struct EvaluationManifestWrite {
    pub manifest: crate::chisei::evaluation_manifest::ResolvedEvaluationManifest,
    pub request_id: String,
    pub request_digest: String,
}

#[cfg(test)]
thread_local! {
    /// Hosted routing-profile catalog reads on this thread (#1185-#1187).
    pub(crate) static HOSTED_PROFILE_LISTS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

impl RuntimeDb {
    pub(crate) fn with_evaluation_resolution_snapshot<T, E, F, M>(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
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
                crate::db::postgres::lock_existing_evaluation_resolution_tables(&mut transaction)
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

    pub fn get_evaluation_execution_index(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<EvaluationExecutionIndex>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluation_execution_index(manifest_digest),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_evaluation_execution_index(manifest_digest)
            }),
        }
    }

    pub fn create_evaluation_execution(
        &self,
        index: &EvaluationExecutionIndex,
        receipt: &OperationReceipt,
    ) -> Result<EvaluationExecutionIndex, String> {
        match self {
            Self::Sqlite(db) => db.create_evaluation_execution(index, receipt),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_evaluation_execution(index, receipt))
            }
        }
    }

    pub fn list_kioku_lifecycle_events_in_window(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_kioku_lifecycle_events_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    limit,
                )
            }),
        }
    }

    pub fn list_kioku_outcomes_in_window(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_kioku_outcomes_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    limit,
                )
            }),
        }
    }

    pub fn abandon_external_action_claim(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.abandon_external_action_claim(request, request_digest),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.abandon_external_action_claim(request, request_digest)
            }),
        }
    }

    pub fn claim_external_action_authorization(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_external_action_authorization(
                    request,
                    request_digest,
                    authorization_id,
                    now_ms,
                )
            }),
        }
    }

    pub fn compare_and_swap_external_action_authorization(
        &self,
        expected: &AuthorizationRecord,
        next: &AuthorizationRecord,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.compare_and_swap_external_action_authorization(expected, next),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.compare_and_swap_external_action_authorization(expected, next)
            }),
        }
    }

    pub fn disable_kioku_memory(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.disable_kioku_memory(id, version, actor, rationale, recorded_at_ms)
            }),
        }
    }

    pub fn evaluate_kioku_impact_if_ready(
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

    pub fn get_external_action_authorization_by_id(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AuthorizationRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_external_action_authorization_by_id(authorization_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_external_action_authorization_by_id(authorization_id)
            }),
        }
    }

    pub fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
        match self {
            Self::Sqlite(db) => db.get_external_permit_policy(scope),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_external_permit_policy(scope))
            }
        }
    }

    pub fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.get_kioku_memory(id, version),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_kioku_memory(id, version))
            }
        }
    }

    pub fn reassess_kioku_memory(
        &self,
        request: KiokuEvidenceReassessmentRequest,
    ) -> Result<KiokuEvidenceReassessmentResult, String> {
        match self {
            Self::Sqlite(db) => db.reassess_kioku_memory(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.reassess_kioku_memory(request))
            }
        }
    }

    pub fn reassess_kioku_memory_after_graph_auth(
        &self,
        request: KiokuEvidenceReassessmentRequest,
    ) -> Result<KiokuEvidenceReassessmentResult, String> {
        match self {
            Self::Sqlite(db) => db.reassess_kioku_memory_after_graph_auth(request),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reassess_kioku_memory_after_graph_auth(request)
            }),
        }
    }

    pub fn authorize_kioku_retrieval(
        &self,
        request: &MemoryRetrievalRequest,
    ) -> Result<(), String> {
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

    pub fn authorize_kioku_evidence(
        &self,
        request: &KiokuEvidenceAuthorizationRequest,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.authorize_kioku_evidence(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.authorize_kioku_evidence(request))
            }
        }
    }

    pub fn put_evaluator_definition(
        &self,
        definition: crate::chisei::evaluation_plan::EvaluatorDefinition,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::chisei::evaluation_plan::EvaluatorDefinition, String> {
        match self {
            Self::Sqlite(db) => db.put_evaluator_definition(definition, actor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_evaluator_definition(definition, actor, now_ms)
            }),
        }
    }

    pub fn get_evaluator_definition(
        &self,
        definition_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluatorDefinition>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluator_definition(definition_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_evaluator_definition(definition_id))
            }
        }
    }

    pub fn list_evaluator_definitions(
        &self,
        namespace: &str,
        evaluator_id: Option<&str>,
    ) -> Result<Vec<crate::chisei::evaluation_plan::EvaluatorDefinition>, String> {
        match self {
            Self::Sqlite(db) => db.list_evaluator_definitions(namespace, evaluator_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_evaluator_definitions(namespace, evaluator_id)
            }),
        }
    }

    pub fn get_evaluator_availability(
        &self,
        definition_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluatorAvailability>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluator_availability(definition_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_evaluator_availability(definition_id))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_evaluator_availability(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
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

    pub fn put_evaluation_plan(
        &self,
        plan: crate::chisei::evaluation_plan::EvaluationPlan,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::chisei::evaluation_plan::EvaluationPlan, String> {
        match self {
            Self::Sqlite(db) => db.put_evaluation_plan(plan, actor, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_evaluation_plan(plan, actor, now_ms))
            }
        }
    }

    pub fn get_evaluation_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest>, String>
    {
        let manifest = match self {
            Self::Sqlite(db) => db.get_evaluation_manifest(manifest_digest),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_evaluation_manifest(manifest_digest))
            }
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

    pub fn get_evaluation_manifest_for_request(
        &self,
        namespace: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_manifest::EvaluationManifestReplay>, String> {
        let replay = match self {
            Self::Sqlite(db) => {
                db.get_evaluation_manifest_for_request(namespace, actor, request_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
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

    pub fn put_evaluation_manifest(
        &self,
        manifest: &crate::chisei::evaluation_manifest::ResolvedEvaluationManifest,
        request_id: &str,
        request_digest: &str,
    ) -> Result<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest, String> {
        verify_evaluation_manifest(manifest.clone())?;
        let stored = match self {
            Self::Sqlite(db) => db.put_evaluation_manifest(manifest, request_id, request_digest),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_evaluation_manifest(manifest, request_id, request_digest)
            }),
        }?;
        let stored = verify_evaluation_manifest(stored)?;
        if stored.manifest_digest != manifest.manifest_digest {
            return Err("evaluation manifest digest conflicts with stored content".into());
        }
        Ok(stored)
    }

    pub fn get_evaluation_plan(
        &self,
        plan_version_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluationPlan>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluation_plan(plan_version_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_evaluation_plan(plan_version_id))
            }
        }
    }

    pub fn list_evaluation_plans(
        &self,
        namespace: &str,
        plan_id: Option<&str>,
    ) -> Result<Vec<crate::chisei::evaluation_plan::EvaluationPlan>, String> {
        match self {
            Self::Sqlite(db) => db.list_evaluation_plans(namespace, plan_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_evaluation_plans(namespace, plan_id))
            }
        }
    }

    pub fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_external_action_authorizations(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_external_action_authorizations())
            }
        }
    }

    pub fn list_kioku_candidates(
        &self,
        namespace: &str,
        operation_class: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_candidates(namespace, operation_class, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_kioku_candidates(namespace, operation_class, limit)
            }),
        }
    }

    pub fn list_kioku_candidate_page(
        &self,
        namespace: &str,
        limit: usize,
        cursor: Option<&crate::chisei::kioku::KiokuCandidateCursor>,
    ) -> Result<Vec<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_candidate_page(namespace, limit, cursor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_kioku_candidate_page(namespace, limit, cursor)
            }),
        }
    }

    pub fn list_kioku_evidence(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<KiokuEvidenceLink>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_evidence(id, version),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_kioku_evidence(id, version))
            }
        }
    }

    pub fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_lifecycle_events(id, version),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_kioku_lifecycle_events(id, version))
            }
        }
    }

    pub fn list_kioku_outcome_assignments(
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

    pub fn list_unscored_observations(
        &self,
        limit: i32,
    ) -> Result<Vec<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_unscored_observations(limit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_unscored_observations(limit))
            }
        }
    }

    pub fn put_external_action_authorization(
        &self,
        record: &AuthorizationRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_external_action_authorization(record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_external_action_authorization(record))
            }
        }
    }

    pub fn put_hosted_routing_profile(
        &self,
        profile: &crate::chisei::routing_profiles::HostedRoutingProfile,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_routing_profile::ChiseiRoutingProfileBackend;
        match self {
            Self::Sqlite(db) => db.put_hosted_routing_profile(profile),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiRoutingProfileBackend::put_hosted_routing_profile(db.as_ref(), profile)
            }),
        }
    }

    pub fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::routing_profiles::HostedRoutingProfile>, String> {
        use crate::chisei_store::chisei_routing_profile::ChiseiRoutingProfileBackend;
        #[cfg(test)]
        HOSTED_PROFILE_LISTS.with(|lists| lists.set(lists.get() + 1));
        match self {
            Self::Sqlite(db) => db.list_hosted_routing_profiles(namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiRoutingProfileBackend::list_hosted_routing_profiles(db.as_ref(), namespace)
            }),
        }
    }

    pub fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        use crate::chisei_store::chisei_routing_profile::ChiseiRoutingProfileBackend;
        match self {
            Self::Sqlite(db) => db.revoke_hosted_routing_profile(namespace, profile_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiRoutingProfileBackend::revoke_hosted_routing_profile(
                    db.as_ref(),
                    namespace,
                    profile_id,
                    now_ms,
                )
            }),
        }
    }

    pub fn list_all_hosted_routing_profiles(
        &self,
    ) -> Result<Vec<crate::chisei::routing_profiles::HostedRoutingProfile>, String> {
        use crate::chisei_store::chisei_routing_profile::ChiseiRoutingProfileBackend;
        match self {
            Self::Sqlite(db) => db.list_all_hosted_routing_profiles(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiRoutingProfileBackend::list_all_hosted_routing_profiles(db.as_ref())
            }),
        }
    }

    pub fn start_policy_shadow(
        &self,
        shadow: &crate::chisei::policy_shadow::PolicyShadow,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.start_policy_shadow(shadow),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.start_policy_shadow(shadow))
            }
        }
    }

    pub fn stop_policy_shadow(
        &self,
        namespace: &str,
        shadow_id: Option<&str>,
        unclaimed_at_ms: Option<i64>,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.stop_policy_shadow(namespace, shadow_id, unclaimed_at_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.stop_policy_shadow(namespace, shadow_id, unclaimed_at_ms)
            }),
        }
    }

    pub fn claim_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.claim_policy_shadow_activation(namespace, shadow_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_policy_shadow_activation(namespace, shadow_id, now_ms)
            }),
        }
    }

    pub fn confirm_policy_shadow_activation(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.confirm_policy_shadow_activation(namespace, shadow_id, claimed_at_ms, now_ms)
            }),
        }
    }

    pub fn find_policy_shadow(
        &self,
        scopes: &[String],
    ) -> Result<Option<crate::chisei::policy_shadow::PolicyShadow>, String> {
        match self {
            Self::Sqlite(db) => db.find_policy_shadow(scopes),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_policy_shadow(scopes))
            }
        }
    }

    pub fn record_policy_shadow_observation(
        &self,
        shadow_id: &str,
        sample: &crate::chisei::policy_shadow::ShadowSample,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_policy_shadow_observation(shadow_id, sample),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.record_policy_shadow_observation(shadow_id, sample)
            }),
        }
    }

    pub fn policy_shadow_report(
        &self,
        namespace: &str,
    ) -> Result<Option<crate::chisei::policy_shadow::PolicyShadowReport>, String> {
        match self {
            Self::Sqlite(db) => db.policy_shadow_report(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.policy_shadow_report(namespace))
            }
        }
    }

    pub fn put_model_review_record(
        &self,
        record: &crate::chisei::model_review::ModelReviewRecord,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.put_model_review_record(record),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::put_model_review_record(db.as_ref(), record)
            }),
        }
    }

    pub fn insert_model_review_record_if_absent(
        &self,
        record: &crate::chisei::model_review::ModelReviewRecord,
    ) -> Result<bool, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.insert_model_review_record_if_absent(record),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::insert_model_review_record_if_absent(db.as_ref(), record)
            }),
        }
    }

    pub fn get_model_review_record(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
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

    pub fn list_model_review_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_review::ModelReviewRecord>, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.list_model_review_records(namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::list_model_review_records(db.as_ref(), namespace)
            }),
        }
    }

    pub fn put_family_enablement_record(
        &self,
        record: &crate::chisei::model_review::FamilyEnablementRecord,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.put_family_enablement_record(record),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::put_family_enablement_record(db.as_ref(), record)
            }),
        }
    }

    pub fn insert_family_enablement_record_if_absent(
        &self,
        record: &crate::chisei::model_review::FamilyEnablementRecord,
    ) -> Result<bool, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.insert_family_enablement_record_if_absent(record),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::insert_family_enablement_record_if_absent(
                    db.as_ref(),
                    record,
                )
            }),
        }
    }

    pub fn get_family_enablement_record(
        &self,
        namespace: &str,
        region_label: &str,
        family_id: &str,
    ) -> Result<Option<crate::chisei::model_review::FamilyEnablementRecord>, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.get_family_enablement_record(namespace, region_label, family_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::get_family_enablement_record(
                    db.as_ref(),
                    namespace,
                    region_label,
                    family_id,
                )
            }),
        }
    }

    pub fn list_family_enablement_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_review::FamilyEnablementRecord>, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.list_family_enablement_records(namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::list_family_enablement_records(db.as_ref(), namespace)
            }),
        }
    }

    pub fn model_review_row_count(&self) -> Result<i64, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.model_review_row_count(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::model_review_row_count(db.as_ref())
            }),
        }
    }

    pub fn family_enablement_row_count(&self) -> Result<i64, String> {
        use crate::chisei_store::chisei_model_review::ChiseiModelReviewBackend;
        match self {
            Self::Sqlite(db) => db.family_enablement_row_count(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReviewBackend::family_enablement_row_count(db.as_ref())
            }),
        }
    }

    pub fn put_model_release_trust(
        &self,
        roots: &crate::chisei::model_release_evidence::EvaluationTrustRoots,
        updated_at_ms: i64,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.put_model_release_trust(roots, updated_at_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::put_model_release_trust(
                    db.as_ref(),
                    roots,
                    updated_at_ms,
                )
            }),
        }
    }

    pub fn get_model_release_trust(
        &self,
    ) -> Result<Option<crate::chisei::model_release_evidence::EvaluationTrustRoots>, String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.get_model_release_trust(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::get_model_release_trust(db.as_ref())
            }),
        }
    }

    pub fn put_model_runtime_evidence(
        &self,
        evidence: &crate::chisei::model_release_evidence::ModelRuntimeEvidence,
        ingested_at_ms: i64,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.put_model_runtime_evidence(evidence, ingested_at_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::put_model_runtime_evidence(
                    db.as_ref(),
                    evidence,
                    ingested_at_ms,
                )
            }),
        }
    }

    pub fn get_model_runtime_evidence(
        &self,
        identity: &crate::chisei::model_release_evidence::ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.get_model_runtime_evidence(identity),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::get_model_runtime_evidence(db.as_ref(), identity)
            }),
        }
    }

    pub fn put_model_evaluation_export(
        &self,
        evidence: &crate::chisei::model_release_evidence::ModelEvaluationEvidence,
        exported_at_ms: i64,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.put_model_evaluation_export(evidence, exported_at_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::put_model_evaluation_export(
                    db.as_ref(),
                    evidence,
                    exported_at_ms,
                )
            }),
        }
    }

    pub fn get_model_evaluation_export(
        &self,
        identity: &crate::chisei::model_release_evidence::ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.get_model_evaluation_export(identity),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::get_model_evaluation_export(
                    db.as_ref(),
                    identity,
                )
            }),
        }
    }

    pub fn put_model_release_feedback(
        &self,
        record: &crate::chisei::model_release_evidence::ModelReleaseFeedback,
    ) -> Result<(), String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.put_model_release_feedback(record),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::put_model_release_feedback(db.as_ref(), record)
            }),
        }
    }

    pub fn list_model_release_feedback(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::chisei::model_release_evidence::ModelReleaseFeedback>, String> {
        use crate::chisei_store::chisei_model_release_evidence::ChiseiModelReleaseEvidenceBackend;
        match self {
            Self::Sqlite(db) => db.list_model_release_feedback(namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ChiseiModelReleaseEvidenceBackend::list_model_release_feedback(
                    db.as_ref(),
                    namespace,
                )
            }),
        }
    }

    pub fn put_sample_observation(
        &self,
        obs: &crate::chisei::scoring::SampleObservation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_sample_observation(obs),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_sample_observation(obs))
            }
        }
    }

    pub fn get_sample_observation(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.get_sample_observation(request_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_sample_observation(request_id))
            }
        }
    }

    pub fn get_sample_observation_in_namespace(
        &self,
        request_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.get_sample_observation_in_namespace(request_id, namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_sample_observation_in_namespace(request_id, namespace)
            }),
        }
    }

    pub fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_lifecycle_event(event),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.record_kioku_lifecycle_event(event))
            }
        }
    }

    pub fn record_kioku_outcome(
        &self,
        observation: &MemoryOutcomeObservation,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_outcome(observation),
            Self::Postgres(_) => Err(
                "record_kioku_outcome is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn redeem_or_reconcile_permit(
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
            Self::Postgres(_) => Err(
                "redeem_or_reconcile_permit is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn release_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_external_action_blast_radius(authorization_id, request),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_external_action_blast_radius(authorization_id, request)
            }),
        }
    }

    pub fn reserve_external_action_blast_radius(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reserve_external_action_blast_radius(
                    authorization_id,
                    request,
                    max_mutations,
                    max_deletes,
                )
            }),
        }
    }

    pub fn review_kioku_candidate(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => db.review_kioku_candidate(id, version, review),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.review_kioku_candidate(id, version, review))
            }
        }
    }

    pub fn review_kioku_candidate_after_graph_auth(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => db.review_kioku_candidate_after_graph_auth(id, version, review),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.review_kioku_candidate_after_graph_auth(id, version, review)
            }),
        }
    }

    pub fn set_external_permit_policy(
        &self,
        policy: &ExternalPermitPolicy,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_external_permit_policy(policy, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.set_external_permit_policy(policy, now_ms))
            }
        }
    }

    pub fn validate_kioku_candidate(
        &self,
        id: &str,
        version: u32,
    ) -> Result<MemoryValidation, String> {
        match self {
            Self::Sqlite(db) => db.validate_kioku_candidate(id, version),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.validate_kioku_candidate(id, version))
            }
        }
    }

    pub fn put_learning_change(
        &self,
        record: &crate::chisei::learning_change::LearningChange,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_learning_change(record),
            Self::Postgres(_) => Err(crate::chisei::learning_change::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_learning_change(
        &self,
        change_id: &str,
    ) -> Result<Option<crate::chisei::learning_change::LearningChange>, String> {
        match self {
            Self::Sqlite(db) => db.get_learning_change(change_id),
            Self::Postgres(_) => Err(crate::chisei::learning_change::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn list_learning_changes(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::learning_change::LearningChange>, String> {
        match self {
            Self::Sqlite(db) => db.list_learning_changes(namespace),
            Self::Postgres(_) => Err(crate::chisei::learning_change::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_data_quality_rule(
        &self,
        record: &crate::chisei::data_quality::DataQualityRule,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_data_quality_rule(record),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_data_quality_rule(
        &self,
        namespace: &str,
        rule_id: &str,
    ) -> Result<Option<crate::chisei::data_quality::DataQualityRule>, String> {
        match self {
            Self::Sqlite(db) => db.get_data_quality_rule(namespace, rule_id),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn list_data_quality_rules(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::data_quality::DataQualityRule>, String> {
        match self {
            Self::Sqlite(db) => db.list_data_quality_rules(namespace),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_data_quality_result(
        &self,
        record: &crate::chisei::data_quality::DataQualityResult,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_data_quality_result(record),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_data_quality_result(
        &self,
        result_id: &str,
    ) -> Result<Option<crate::chisei::data_quality::DataQualityResult>, String> {
        match self {
            Self::Sqlite(db) => db.get_data_quality_result(result_id),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn list_data_quality_results(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::chisei::data_quality::DataQualityResult>, String> {
        match self {
            Self::Sqlite(db) => db.list_data_quality_results(namespace),
            Self::Postgres(_) => Err(crate::chisei::data_quality::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_run_record(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_eval_run_record(id)),
        }
    }

    pub fn get_latest_eval_run_record_for_gate(
        &self,
        suite_id: &str,
        config_ref: &str,
        max_timestamp_ms: i64,
    ) -> Result<Option<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => {
                db.get_latest_eval_run_record_for_gate(suite_id, config_ref, max_timestamp_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_latest_eval_run_record_for_gate(suite_id, config_ref, max_timestamp_ms)
            }),
        }
    }

    pub fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_suite_record(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_eval_suite_record(id)),
        }
    }

    pub fn get_eval_suite_record_for_gate(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_suite_record_for_gate(id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_eval_suite_record_for_gate(id))
            }
        }
    }

    pub fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_eval_iteration_records(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_all_eval_iteration_records())
            }
        }
    }

    pub fn list_eval_iteration_records(
        &self,
        suite_id: &str,
    ) -> Result<Vec<eval::Iteration>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_iteration_records(suite_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_eval_iteration_records(suite_id))
            }
        }
    }

    pub fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_run_records(suite_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_eval_run_records(suite_id))
            }
        }
    }

    pub fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_suite_records(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_eval_suite_records()),
        }
    }

    pub fn portfolio_damped_route(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
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

    pub fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_objective(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.portfolio_objective(namespace))
            }
        }
    }

    pub fn portfolio_points(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_points(namespace, task_class),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.portfolio_points(namespace, task_class))
            }
        }
    }

    pub fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.portfolio_record_observation(observation),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.portfolio_record_observation(observation))
            }
        }
    }

    pub fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.portfolio_set_objective(objective),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.portfolio_set_objective(objective))
            }
        }
    }

    pub fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_iteration(iteration),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_eval_iteration(iteration))
            }
        }
    }

    pub fn put_eval_run(&self, run: &eval::Run) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_run(run),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_eval_run(run)),
        }
    }

    pub fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_suite(suite),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_eval_suite(suite)),
        }
    }

    pub fn append_feedback_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.append_feedback_eval_suite(suite),
            Self::Postgres(_) => Err(
                "append_feedback_eval_suite is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn retrieve_kioku_memories(
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

    pub fn retrieve_kioku_memories_after_graph_auth(
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

    pub fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_kioku_memory(memory, evidence),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.insert_kioku_memory(memory, evidence))
            }
        }
    }

    pub fn produce_kioku_candidate(
        &self,
        input: CandidateDerivation,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => db.produce_kioku_candidate(input),
            Self::Postgres(_) => Err(
                "produce_kioku_candidate is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn sweep_kioku_lifecycle(
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
}

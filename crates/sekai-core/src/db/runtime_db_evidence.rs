//! Dual-backend community-store dispatch for evidence.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn record_decision(&self, decision: &Decision) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decision(decision),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.record_decision(decision)),
        }
    }

    pub fn list_decisions(&self, filter: &DecisionFilter) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_decisions(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_decisions(filter)),
        }
    }

    pub fn list_compliance_decisions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_compliance_decisions_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_compliance_decisions_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    limit,
                )
            }),
        }
    }

    pub fn evidence_lifecycle_history(
        &self,
        submission_id: &str,
    ) -> Result<Vec<EvidenceLifecycleState>, String> {
        match self {
            Self::Sqlite(db) => db.evidence_lifecycle_history(submission_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.evidence_lifecycle_history(submission_id))
            }
        }
    }

    pub fn get_attestation(&self, id: &str) -> Result<Option<PolicyAttestation>, String> {
        match self {
            Self::Sqlite(db) => db.get_attestation(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_attestation(id)),
        }
    }

    pub fn get_dedup_request(
        &self,
        request_id: &str,
        operation: &str,
    ) -> Result<Option<RequestDedup>, String> {
        match self {
            Self::Sqlite(db) => db.get_dedup_request(request_id, operation),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_dedup_request(request_id, operation))
            }
        }
    }

    pub fn get_evidence_projection_object_id(
        &self,
        submission_id: &str,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.get_evidence_projection_object_id(submission_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_evidence_projection_object_id(submission_id)
            }),
        }
    }

    pub fn get_evidence_submission(
        &self,
        submission_id: &str,
    ) -> Result<Option<EvidenceSubmissionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_evidence_submission(submission_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_evidence_submission(submission_id))
            }
        }
    }

    pub fn list_attestations(
        &self,
        decision_id: Option<&str>,
        policy_scope: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<PolicyAttestation>, String> {
        match self {
            Self::Sqlite(db) => db.list_attestations(decision_id, policy_scope, limit, offset),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_attestations(decision_id, policy_scope, limit, offset)
            }),
        }
    }

    pub fn list_evidence_submissions(
        &self,
        filter: &EvidenceSubmissionFilter,
    ) -> Result<Vec<EvidenceSubmissionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_evidence_submissions(filter),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_evidence_submissions(filter))
            }
        }
    }

    pub fn list_evidence_submissions_for_text(
        &self,
        namespace: &str,
        principals: &[&str],
        allowed_markings: &[&str],
        trusted: bool,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<EvidenceSubmissionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_evidence_submissions_for_text(
                namespace,
                principals,
                allowed_markings,
                trusted,
                limit,
                offset,
            ),
            Self::Postgres(_) => Err(
                "authorization-built text evidence visibility is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn project_evidence_submission(
        &self,
        submission_id: &str,
        now_ms: i64,
    ) -> Result<EvidenceProjectionOutcome, String> {
        match self {
            Self::Sqlite(db) => db.project_evidence_submission(submission_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.project_evidence_submission(submission_id, now_ms)
            }),
        }
    }

    pub fn reconcile_missing_execution_evidence(
        &self,
        now_ms: i64,
    ) -> Result<Vec<ExecutionEvidenceAlert>, String> {
        match self {
            Self::Sqlite(db) => db.reconcile_missing_execution_evidence(now_ms),
            // Redemptions live on the Chisei plane; evidence state lives on
            // Sekai. Dest-pair PostgreSQL cannot join them on one connection,
            // so do not report an empty success after permit redeem is live.
            Self::Postgres(_) => Err(
                "reconcile_missing_execution_evidence is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn record_decision_with_attestation(
        &self,
        decision: &crate::sekai::audit::Decision,
        attestation: Option<&PolicyAttestation>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decision_with_attestation(decision, attestation),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.record_decision_with_attestation(decision, attestation)
            }),
        }
    }

    pub fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decisions_idempotently(decisions),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.record_decisions_idempotently(decisions))
            }
        }
    }

    pub fn record_dedup_request(&self, request: &RequestDedup) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_dedup_request(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.record_dedup_request(request))
            }
        }
    }

    pub fn record_execution_evidence(&self, submission_id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.record_execution_evidence(submission_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.record_execution_evidence(submission_id))
            }
        }
    }

    pub fn is_evidence_schema_registered(
        &self,
        schema_id: &str,
        schema_version: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.is_evidence_schema_registered(schema_id, schema_version),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.is_evidence_schema_registered(schema_id, schema_version)
            }),
        }
    }

    pub fn register_evidence_schema(
        &self,
        definition: &EvidenceSchemaDefinition,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.register_evidence_schema(definition, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.register_evidence_schema(definition, now_ms))
            }
        }
    }

    pub fn reject_evidence_submission(
        &self,
        submission_id: &str,
        now_ms: i64,
        code: &str,
        summary: &str,
    ) -> Result<EvidenceAdmission, String> {
        match self {
            Self::Sqlite(db) => db.reject_evidence_submission(submission_id, now_ms, code, summary),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reject_evidence_submission(submission_id, now_ms, code, summary)
            }),
        }
    }

    pub fn submit_evidence(
        &self,
        envelope: &EvidenceEnvelope,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<EvidenceAdmission, String> {
        match self {
            Self::Sqlite(db) => db.submit_evidence(envelope, authenticated_producer, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.submit_evidence(envelope, authenticated_producer, now_ms)
            }),
        }
    }

    pub fn upsert_evidence_producer(
        &self,
        capability: &EvidenceProducerCapability,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_evidence_producer(capability, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_evidence_producer(capability, now_ms))
            }
        }
    }

    pub fn validate_execution_evidence_envelope(
        &self,
        envelope: &crate::sekai::evidence::EvidenceEnvelope,
        authenticated_producer: &str,
    ) -> Result<Option<ExecutionEvidence>, String> {
        match self {
            Self::Sqlite(db) => {
                db.validate_execution_evidence_envelope(envelope, authenticated_producer)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.validate_execution_evidence_envelope(envelope, authenticated_producer)
            }),
        }
    }

    pub fn verify_attestation(&self, id: &str) -> Result<AttestationVerification, String> {
        match self {
            Self::Sqlite(db) => db.verify_attestation(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.verify_attestation(id)),
        }
    }

    pub fn verify_ledger(&self) -> Result<LedgerVerification, String> {
        match self {
            Self::Sqlite(db) => db.verify_ledger(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.verify_ledger()),
        }
    }

    pub fn get_decision(&self, id: &str) -> Result<Option<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.get_decision(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_decision(id)),
        }
    }

    pub fn insert_task_observation(&self, observation: &TaskObservation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_task_observation(observation),
            Self::Postgres(_) => Err(
                "insert_task_observation is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_task_observations_for_component(
        &self,
        component_id: &str,
    ) -> Result<Vec<TaskObservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_task_observations_for_component(component_id),
            Self::Postgres(_) => Err("list_task_observations_for_component is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_usable_evidence_classes_for_targets(
        &self,
        target_object_ids: &[String],
        now_ms: i64,
    ) -> Result<Vec<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.list_usable_evidence_classes_for_targets(target_object_ids, now_ms),
            Self::Postgres(_) => Err("list_usable_evidence_classes_for_targets is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_usable_evidence_for_targets(
        &self,
        target_object_ids: &[String],
        allowed_evidence_classes: &[(String, String)],
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<UsableEvidenceContext>, String> {
        match self {
            Self::Sqlite(db) => db.list_usable_evidence_for_targets(target_object_ids, allowed_evidence_classes, now_ms, limit),
            Self::Postgres(_) => Err("list_usable_evidence_for_targets is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn record_decisions_idempotently_by(
        &self,
        decisions: &[Decision],
        equivalent: impl Fn(&Decision, &Decision) -> bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decisions_idempotently_by(decisions, equivalent),
            Self::Postgres(_) => Err("record_decisions_idempotently_by is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn get_task_observation_baseline(
        &self,
        component_id: &str,
    ) -> Result<Option<TaskObservationBaseline>, String> {
        match self {
            Self::Sqlite(db) => db.get_task_observation_baseline(component_id),
            Self::Postgres(_) => Err(
                "get_task_observation_baseline is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn insert_task_observation_baseline(
        &self,
        component_id: &str,
        namespace: &str,
        baseline: &TaskObservationBaseline,
        created: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_task_observation_baseline(component_id, namespace, baseline, created),
            Self::Postgres(_) => Err("insert_task_observation_baseline is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn get_lineage(
        &self,
        object_id: &str,
        max_nodes: usize,
    ) -> Result<crate::sekai::lineage::LineageResult, String> {
        match self {
            Self::Sqlite(db) => crate::sekai::lineage::get_lineage(db, object_id, max_nodes),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_lineage(object_id, max_nodes))
            }
        }
    }

    pub fn get_lineage_with_policy_context(
        &self,
        object_id: &str,
        max_nodes: usize,
        context: &PrincipalPolicyContext,
    ) -> Result<crate::sekai::lineage::LineageResult, String> {
        match self {
            Self::Sqlite(db) => crate::sekai::lineage::get_lineage_with_policy_context(
                db, object_id, max_nodes, context,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_lineage_with_policy_context(object_id, max_nodes, context)
            }),
        }
    }

    pub fn insert_attestation(&self, a: &PolicyAttestation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_attestation(a),
            Self::Postgres(_) => {
                Err("insert_attestation is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }
}

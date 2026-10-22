//! Dual-backend community store used by the public control plane.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use crate::db::postgres::PostgresDb;
use crate::db::sekai::{PrincipalCredential, SekaiDb};
use postgres::GenericClient;
use std::sync::Arc;

#[cfg(test)]
pub(crate) mod source_batch_auth_counters {
    use std::cell::Cell;

    thread_local! {
        pub static LOOKUP_QUERIES: Cell<usize> = const { Cell::new(0) };
        pub static POLICY_LOOKUPS: Cell<usize> = const { Cell::new(0) };
    }
}

use crate::db::chisei_operation_reservation::OperationReservation;
use crate::db::definition_branch::DefinitionBranchBackend;
use crate::db::object_sync::ObjectSyncBackend;
use crate::domain::{Direction, Link, ListFilter, Object};
use crate::sekai::action_policy::ActionPolicy;
use crate::sekai::attestation::{AttestationVerification, PolicyAttestation};
use crate::sekai::audit::{Decision, DecisionFilter, ObjectChange};
use crate::sekai::coordination::*;
use crate::sekai::dataset::{Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable};
use crate::sekai::dataset_health::{
    DatasetAlert, DatasetHealthCheck, DatasetHealthResult, DatasetHealthState,
};
use crate::sekai::dataset_version::{DatasetRollback, DatasetVersion};
use crate::sekai::deduplication::*;
use crate::sekai::definition_branch::*;
use crate::sekai::definition_proposal::*;
use crate::sekai::evidence::{EvidenceClassification, EvidenceEnvelope, EvidenceLifecycleState};
use crate::sekai::evidence_projection::EvidenceProjectionOutcome;
use crate::sekai::evidence_store::{
    EvidenceAdmission, EvidenceProducerCapability, EvidenceSchemaDefinition,
    EvidenceSubmissionFilter, EvidenceSubmissionRecord, UsableEvidenceContext,
};
use crate::sekai::execution_evidence::*;
use crate::sekai::external_permit::{HostContext, Permit, Redemption};
use crate::sekai::function::Function;
use crate::sekai::handoff::*;
use crate::sekai::lease::{Lease, LeaseError};
use crate::sekai::ledger::*;
use crate::sekai::object_security::{
    ObjectSecurityActivation, ObjectSecurityPolicy, ObjectSecurityPolicyRevision,
    PrincipalPolicyContext, PropertyGrantAccess,
};
use crate::sekai::object_sync::{SourceBatch, SourceBatchResult, SourceSyncState};
use crate::sekai::observation::{TaskObservation, TaskObservationBaseline, *};
use crate::sekai::ontology::*;
use crate::sekai::retention::*;
use crate::sekai::schema::*;
use crate::sekai::security::*;
use ed25519_dalek::VerifyingKey;
use sekai_domain::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use sekai_types::evolve;
use sekai_types::governed_subject_provenance::ExportRecord;
use sekai_types::principal::PrincipalContext;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Instant;

#[derive(Clone)]
pub enum RuntimeDb {
    Sqlite(Arc<SekaiDb>),
    Postgres(Arc<PostgresDb>),
}

impl std::fmt::Debug for RuntimeDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sqlite(_) => "RuntimeDb::Sqlite",
            Self::Postgres(_) => "RuntimeDb::Postgres",
        })
    }
}

pub(crate) const ACTION_BINDINGS_UNAVAILABLE: &str =
    "action bindings are unavailable on the PostgreSQL community runtime";

impl RuntimeDb {
    /// Connection-pool ceiling used as the gRPC `spawn_blocking` bound.
    pub(crate) fn connection_pool_max(&self) -> u32 {
        match self {
            Self::Sqlite(db) => db.as_ref().pool_max_size(),
            Self::Postgres(db) => db.as_ref().max_connections(),
        }
    }

    /// Labels this store's connection-pool signals with the plane it serves.
    pub(crate) fn set_pool_plane(&self, plane: crate::obs::labels::PoolPlane) {
        match self {
            RuntimeDb::Sqlite(db) => db.set_pool_plane(plane),
            RuntimeDb::Postgres(db) => db.set_pool_plane(plane),
        }
    }

    pub fn put_object_security_policy(
        &self,
        policy: &ObjectSecurityPolicy,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityPolicyRevision, String> {
        match self {
            Self::Sqlite(db) => {
                db.put_object_security_policy(policy, actor, idempotency_key, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_object_security_policy(policy, actor, idempotency_key, now_ms)
            }),
        }
    }

    pub fn get_object_security_policy(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRevision>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_security_policy(namespace, revision_digest),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_object_security_policy(namespace, revision_digest)
            }),
        }
    }

    pub fn activate_object_security_policies(
        &self,
        namespace: &str,
        policies: &BTreeMap<String, String>,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityActivation, String> {
        match self {
            Self::Sqlite(db) => db.activate_object_security_policies(
                namespace,
                policies,
                actor,
                idempotency_key,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.activate_object_security_policies(
                    namespace,
                    policies,
                    actor,
                    idempotency_key,
                    now_ms,
                )
            }),
        }
    }

    pub fn get_object_security_activation(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityActivation>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_security_activation(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_object_security_activation(namespace))
            }
        }
    }

    pub fn has_object_security_activations(&self) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.has_object_security_activations(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.has_object_security_activations())
            }
        }
    }

    pub fn record_policy_decision(
        &self,
        record: &crate::sekai::policy_decision::PolicyDecisionRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_policy_decision(record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.record_policy_decision(record))
            }
        }
    }

    pub fn query_policy_decisions(
        &self,
        query: &crate::sekai::policy_decision::PolicyDecisionQuery,
    ) -> Result<Vec<crate::sekai::policy_decision::PolicyDecisionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.query_policy_decisions(query),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.query_policy_decisions(query))
            }
        }
    }

    pub fn register_object_type_datasource(
        &self,
        binding: &crate::sekai::object_type_index::ObjectTypeDatasource,
        created_at_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.register_object_type_datasource(binding, created_at_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.register_object_type_datasource(binding, created_at_ms)
            }),
        }
    }

    pub fn get_object_type_datasource(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Option<crate::sekai::object_type_index::ObjectTypeDatasource>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_type_datasource(namespace, kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_object_type_datasource(namespace, kind))
            }
        }
    }

    pub fn apply_object_type_index(
        &self,
        namespace: &str,
        kind: &str,
        full_rebuild: bool,
        now_ms: i64,
    ) -> Result<crate::sekai::object_type_index::ReindexReport, String> {
        match self {
            Self::Sqlite(db) => db.apply_object_type_index(namespace, kind, full_rebuild, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.apply_object_type_index(namespace, kind, full_rebuild, now_ms)
            }),
        }
    }

    pub fn put_object_type_index_edit(
        &self,
        edit: &crate::sekai::object_type_index::ObjectTypeIndexEdit,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_object_type_index_edit(edit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_object_type_index_edit(edit))
            }
        }
    }

    pub fn object_log_migration_identities(&self) -> Result<Vec<(String, String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.object_log_migration_identities(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_log_migration_identities())
            }
        }
    }

    pub fn object_type_index_status(
        &self,
        namespace: &str,
        kind: &str,
        now_ms: i64,
    ) -> Result<Option<crate::sekai::object_type_index::ObjectTypeIndexStatus>, String> {
        match self {
            Self::Sqlite(db) => db.object_type_index_status(namespace, kind, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.object_type_index_status(namespace, kind, now_ms)
            }),
        }
    }

    pub fn list_visible_index_members(
        &self,
        namespace: &str,
        kind: &str,
        query: &RowQuery,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, String> {
        self.list_visible_index_members_projected(namespace, kind, query, None)
    }

    pub fn list_visible_index_members_projected(
        &self,
        namespace: &str,
        kind: &str,
        query: &RowQuery,
        needed: Option<&[String]>,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_visible_index_members_projected(namespace, kind, query, needed)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_visible_index_members_projected(namespace, kind, query, needed)
            }),
        }
    }

    pub fn count_visible_index_members(&self, namespace: &str, kind: &str) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.count_visible_index_members(namespace, kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.count_visible_index_members(namespace, kind))
            }
        }
    }

    pub fn hop_projection_ready(&self, namespace: &str, kind: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.hop_projection_ready(namespace, kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.hop_projection_ready(namespace, kind))
            }
        }
    }

    pub fn hop_projection_kinds_ready(
        &self,
        namespace: &str,
        kinds: &[&str],
        published: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.hop_projection_kinds_ready(namespace, kinds, published),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.hop_projection_kinds_ready(namespace, kinds, published)
            }),
        }
    }

    pub fn set_hop_projection_ready(
        &self,
        namespace: &str,
        kind: &str,
        ready: bool,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_hop_projection_ready(namespace, kind, ready, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_hop_projection_ready(namespace, kind, ready, now_ms)
            }),
        }
    }

    pub fn invalidate_namespace_hop_projection(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.invalidate_namespace_hop_projection(namespace, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.invalidate_namespace_hop_projection(namespace, now_ms)
            }),
        }
    }

    pub fn count_index_join_rows(&self, namespace: &str, kind: &str) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.count_index_join_rows(namespace, kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.count_index_join_rows(namespace, kind))
            }
        }
    }

    pub fn list_index_join_children(
        &self,
        namespace: &str,
        kind: &str,
        property: &str,
        values: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.list_index_join_children(namespace, kind, property, values),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_index_join_children(namespace, kind, property, values)
            }),
        }
    }

    pub fn list_index_members_by_keys(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, String> {
        self.list_index_members_by_keys_projected(namespace, kind, keys, None)
    }

    pub fn list_index_members_by_keys_projected(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
        needed: Option<&[String]>,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_index_members_by_keys_projected(namespace, kind, keys, needed)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_index_members_by_keys_projected(namespace, kind, keys, needed)
            }),
        }
    }

    pub fn list_index_member_idents(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.list_index_member_idents(namespace, kind, keys),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_index_member_idents(namespace, kind, keys)
            }),
        }
    }

    pub fn put_governed_transform(
        &self,
        transform: &crate::sekai::governed_transform::GovernedTransform,
        created_at_ms: i64,
    ) -> Result<(), String> {
        self.put_governed_transform_owned(transform, created_at_ms, "")
    }

    pub fn put_governed_transform_owned(
        &self,
        transform: &crate::sekai::governed_transform::GovernedTransform,
        created_at_ms: i64,
        tenant_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.put_governed_transform_owned(transform, created_at_ms, tenant_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_governed_transform_owned(transform, created_at_ms, tenant_id)
            }),
        }
    }

    pub fn get_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::GovernedTransform>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_transform(namespace, transform_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_governed_transform(namespace, transform_id)
            }),
        }
    }

    pub fn admitted_isolated_transform(
        &self,
        run_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::GovernedTransform>, String> {
        match self {
            Self::Sqlite(db) => db.admitted_isolated_transform(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.admitted_isolated_transform(run_id))
            }
        }
    }

    pub fn run_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        incremental: bool,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        self.run_governed_transform_owned(namespace, transform_id, incremental, now_ms, "", "")
    }

    pub fn run_governed_transform_owned(
        &self,
        namespace: &str,
        transform_id: &str,
        incremental: bool,
        now_ms: i64,
        tenant_id: &str,
        expected_definition_digest: &str,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        match self {
            Self::Sqlite(db) => db.run_governed_transform_owned(
                namespace,
                transform_id,
                incremental,
                now_ms,
                tenant_id,
                expected_definition_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.run_governed_transform_owned(
                    namespace,
                    transform_id,
                    incremental,
                    now_ms,
                    tenant_id,
                    expected_definition_digest,
                )
            }),
        }
    }

    pub fn get_governed_transform_run(
        &self,
        run_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_transform_run(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_governed_transform_run(run_id))
            }
        }
    }

    pub fn list_governed_transforms(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::governed_transform::GovernedTransform>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_transforms(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_governed_transforms(namespace))
            }
        }
    }

    pub fn list_governed_transform_runs(
        &self,
        namespace: &str,
        limit: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_transform_runs(namespace, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_transform_runs(namespace, limit)
            }),
        }
    }

    /// Admits unowned in-process work. Owned Put-tenant in-process work is
    /// listed by [`Self::list_due_owned_in_process_transforms`] and committed
    /// after Tick admits on `quota_runtime()`.
    pub fn tick_governed_transforms(
        &self,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.tick_governed_transforms(now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.tick_governed_transforms(now_ms))
            }
        }
    }

    pub fn list_due_owned_in_process_transforms(
        &self,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::DueOwnedInProcessTransform>, String> {
        match self {
            Self::Sqlite(db) => db.list_due_owned_in_process_transforms(now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_due_owned_in_process_transforms(now_ms))
            }
        }
    }

    pub fn commit_due_owned_in_process_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        now_ms: i64,
        expected_tenant_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.commit_due_owned_in_process_transform(
                namespace,
                transform_id,
                now_ms,
                expected_tenant_id,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.commit_due_owned_in_process_transform(
                    namespace,
                    transform_id,
                    now_ms,
                    expected_tenant_id,
                )
            }),
        }
    }

    pub fn get_transform_output_state(
        &self,
        namespace: &str,
        dataset_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::TransformOutputState>, String> {
        match self {
            Self::Sqlite(db) => db.get_transform_output_state(namespace, dataset_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_transform_output_state(namespace, dataset_id)
            }),
        }
    }

    pub fn set_transform_namespace_concurrency(
        &self,
        namespace: &str,
        max_concurrent: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_transform_namespace_concurrency(namespace, max_concurrent),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_transform_namespace_concurrency(namespace, max_concurrent)
            }),
        }
    }

    pub fn note_source_change(
        &self,
        namespace: &str,
        object_or_dataset_ids: &[String],
        cause: &str,
        cause_ref: &str,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => {
                db.note_source_change(namespace, object_or_dataset_ids, cause, cause_ref, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.note_source_change(namespace, object_or_dataset_ids, cause, cause_ref, now_ms)
            }),
        }
    }

    pub fn cancel_governed_transform_run(
        &self,
        run_id: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        match self {
            Self::Sqlite(db) => db.cancel_governed_transform_run(run_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.cancel_governed_transform_run(run_id, now_ms)
            }),
        }
    }

    pub fn list_claimable_transform_work(
        &self,
        namespace: &str,
        now_ms: i64,
        limit: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformWork>, String> {
        match self {
            Self::Sqlite(db) => db.list_claimable_transform_work(namespace, now_ms, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_claimable_transform_work(namespace, now_ms, limit)
            }),
        }
    }

    pub fn claim_transform_work(
        &self,
        namespace: &str,
        runtime_id: &str,
        run_id: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<
        Option<(
            crate::sekai::governed_transform::TransformWork,
            crate::sekai::governed_transform::GovernedTransform,
        )>,
        String,
    > {
        match self {
            Self::Sqlite(db) => {
                db.claim_transform_work(namespace, runtime_id, run_id, ttl_ms, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_transform_work(namespace, runtime_id, run_id, ttl_ms, now_ms)
            }),
        }
    }

    pub fn claim_transform_work_outcome(
        &self,
        namespace: &str,
        runtime_id: &str,
        run_id: &str,
        ttl_ms: i64,
        now_ms: i64,
        skip_run_ids: &[String],
    ) -> Result<crate::sekai::governed_transform::ClaimTransformWorkOutcome, String> {
        match self {
            Self::Sqlite(db) => db.claim_transform_work_outcome(
                namespace,
                runtime_id,
                run_id,
                ttl_ms,
                now_ms,
                skip_run_ids,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_transform_work_outcome(
                    namespace,
                    runtime_id,
                    run_id,
                    ttl_ms,
                    now_ms,
                    skip_run_ids,
                )
            }),
        }
    }

    pub fn release_transform_claim(
        &self,
        run_id: &str,
        runtime_id: &str,
        claim_generation: i64,
        fencing_token: &str,
        now_ms: i64,
        restore_lease_expiry: bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_transform_claim(
                run_id,
                runtime_id,
                claim_generation,
                fencing_token,
                now_ms,
                restore_lease_expiry,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_transform_claim(
                    run_id,
                    runtime_id,
                    claim_generation,
                    fencing_token,
                    now_ms,
                    restore_lease_expiry,
                )
            }),
        }
    }

    pub fn put_transform_quota_hold(
        &self,
        run_id: &str,
        tenant_id: &str,
        reserved_concurrency: bool,
        claim_generation: i64,
        fencing_token: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.put_transform_quota_hold(
                run_id,
                tenant_id,
                reserved_concurrency,
                claim_generation,
                fencing_token,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_transform_quota_hold(
                    run_id,
                    tenant_id,
                    reserved_concurrency,
                    claim_generation,
                    fencing_token,
                )
            }),
        }
    }

    pub fn restore_transform_quota_hold(
        &self,
        run_id: &str,
        tenant_id: &str,
        reserved_concurrency: bool,
        claim_generation: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.restore_transform_quota_hold(
                run_id,
                tenant_id,
                reserved_concurrency,
                claim_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.restore_transform_quota_hold(
                    run_id,
                    tenant_id,
                    reserved_concurrency,
                    claim_generation,
                )
            }),
        }
    }

    pub fn restore_abandoned_quota_hold(
        &self,
        run_id: &str,
        tenant_id: &str,
        reserved_concurrency: bool,
        refund_request: bool,
        refund_tokens: i32,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.restore_abandoned_quota_hold(
                run_id,
                tenant_id,
                reserved_concurrency,
                refund_request,
                refund_tokens,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.restore_abandoned_quota_hold(
                    run_id,
                    tenant_id,
                    reserved_concurrency,
                    refund_request,
                    refund_tokens,
                )
            }),
        }
    }

    pub fn reclaim_transform_quota_hold(
        &self,
        run_id: &str,
        claim_generation: i64,
        fencing_token: &str,
    ) -> Result<Option<(String, bool, i64)>, String> {
        match self {
            Self::Sqlite(db) => {
                db.reclaim_transform_quota_hold(run_id, claim_generation, fencing_token)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reclaim_transform_quota_hold(run_id, claim_generation, fencing_token)
            }),
        }
    }

    pub fn take_transform_quota_hold(
        &self,
        run_id: &str,
        claim_generation: Option<i64>,
        older_than: bool,
    ) -> Result<Option<(String, bool, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.take_transform_quota_hold(run_id, claim_generation, older_than),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.take_transform_quota_hold(run_id, claim_generation, older_than)
            }),
        }
    }

    pub fn take_retryable_quota_hold(
        &self,
        run_id: &str,
        claim_generation: i64,
    ) -> Result<Option<crate::db::governed_transform::TakenTransformQuotaHold>, String> {
        match self {
            Self::Sqlite(db) => db.take_retryable_quota_hold(run_id, claim_generation),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.take_retryable_quota_hold(run_id, claim_generation)
            }),
        }
    }

    pub fn list_retryable_quota_holds(&self) -> Result<Vec<(String, String, bool, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.list_retryable_quota_holds(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_retryable_quota_holds())
            }
        }
    }

    pub fn peek_transform_quota_hold(
        &self,
        run_id: &str,
        claim_generation: i64,
    ) -> Result<Option<(String, bool, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.peek_transform_quota_hold(run_id, claim_generation),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.peek_transform_quota_hold(run_id, claim_generation)
            }),
        }
    }

    pub fn defer_transform_work(&self, run_id: &str, now_ms: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.defer_transform_work(run_id, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.defer_transform_work(run_id, now_ms))
            }
        }
    }

    pub fn bind_transform_work_tenant(
        &self,
        run_id: &str,
        tenant_id: &str,
        claim_generation: i64,
        fencing_token: &str,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => {
                db.bind_transform_work_tenant(run_id, tenant_id, claim_generation, fencing_token)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.bind_transform_work_tenant(run_id, tenant_id, claim_generation, fencing_token)
            }),
        }
    }

    pub fn list_transform_usage_pending(&self) -> Result<Vec<(String, String, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.list_transform_usage_pending(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_transform_usage_pending())
            }
        }
    }

    pub fn transform_usage_pending(&self, run_id: &str) -> Result<Option<(String, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.transform_usage_pending(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_usage_pending(run_id))
            }
        }
    }

    pub fn take_transform_usage_pending(&self, run_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.take_transform_usage_pending(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.take_transform_usage_pending(run_id))
            }
        }
    }

    pub fn transform_work_tenant(&self, run_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.transform_work_tenant(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_work_tenant(run_id))
            }
        }
    }

    pub fn transform_quota_owner(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.transform_quota_owner(namespace, transform_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.transform_quota_owner(namespace, transform_id)
            }),
        }
    }

    pub fn heartbeat_transform_work(
        &self,
        run_id: &str,
        runtime_id: &str,
        claim_generation: i64,
        fencing_token: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformWork, String> {
        match self {
            Self::Sqlite(db) => db.heartbeat_transform_work(
                run_id,
                runtime_id,
                claim_generation,
                fencing_token,
                ttl_ms,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.heartbeat_transform_work(
                    run_id,
                    runtime_id,
                    claim_generation,
                    fencing_token,
                    ttl_ms,
                    now_ms,
                )
            }),
        }
    }

    pub fn read_transform_run_input(
        &self,
        command: &crate::sekai::governed_transform::WriteTransformRunCommand,
        alias: &str,
        after_alias: &str,
        after_row_id: i64,
        limit: i64,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRunInputRow>, String> {
        match self {
            Self::Sqlite(db) => db.read_transform_run_input(
                command,
                alias,
                after_alias,
                after_row_id,
                limit,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.read_transform_run_input(
                    command,
                    alias,
                    after_alias,
                    after_row_id,
                    limit,
                    now_ms,
                )
            }),
        }
    }

    pub fn write_transform_run(
        &self,
        command: crate::sekai::governed_transform::WriteTransformRunCommand,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        match self {
            Self::Sqlite(db) => db.write_transform_run(command, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.write_transform_run(command, now_ms))
            }
        }
    }

    pub fn peek_streaming_transform_apply(
        &self,
        run_id: &str,
        runtime_id: &str,
        claim_generation: i64,
        fencing_token: &str,
        checkpoint: &str,
        now_ms: i64,
    ) -> Result<
        Option<crate::sekai::streaming_transform_apply::StreamingTransformApplyReceipt>,
        crate::sekai::streaming_transform_apply::StreamingApplyError,
    > {
        match self {
            Self::Sqlite(db) => db.peek_streaming_transform_apply(
                run_id,
                runtime_id,
                claim_generation,
                fencing_token,
                checkpoint,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.peek_streaming_transform_apply(
                    run_id,
                    runtime_id,
                    claim_generation,
                    fencing_token,
                    checkpoint,
                    now_ms,
                )
            }),
        }
    }

    pub fn apply_streaming_transform_batch(
        &self,
        batch: crate::sekai::streaming_transform_apply::StreamingTransformApplyBatch,
        actor: &str,
        now_ms: i64,
    ) -> Result<
        crate::sekai::streaming_transform_apply::StreamingTransformApplyReceipt,
        crate::sekai::streaming_transform_apply::StreamingApplyError,
    > {
        match self {
            Self::Sqlite(db) => db.apply_streaming_transform_batch(batch, actor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.apply_streaming_transform_batch(batch, actor, now_ms)
            }),
        }
    }

    pub fn preview_governed_transform(
        &self,
        transform: &crate::sekai::governed_transform::GovernedTransform,
        row_cap: usize,
        now_ms: i64,
        tenant_id: &str,
        column_allowlists: &std::collections::HashMap<String, Vec<String>>,
    ) -> Result<crate::sekai::governed_transform::PreviewGovernedTransformResult, String> {
        match self {
            Self::Sqlite(db) => db.preview_governed_transform(
                transform,
                row_cap,
                now_ms,
                tenant_id,
                column_allowlists,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.preview_governed_transform(
                    transform,
                    row_cap,
                    now_ms,
                    tenant_id,
                    column_allowlists,
                )
            }),
        }
    }

    pub fn get_preview_governed_transform(
        &self,
        preview_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::PreviewGovernedTransformResult>, String>
    {
        match self {
            Self::Sqlite(db) => db.get_preview_governed_transform(preview_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_preview_governed_transform(preview_id))
            }
        }
    }

    pub fn get_preview_column_allowlists(
        &self,
        preview_id: &str,
    ) -> Result<std::collections::HashMap<String, Vec<String>>, String> {
        match self {
            Self::Sqlite(db) => db.get_preview_column_allowlists(preview_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_preview_column_allowlists(preview_id))
            }
        }
    }

    pub fn put_purpose_authorization(
        &self,
        authorization: &crate::sekai::purpose_authorization::PurposeAuthorization,
    ) -> Result<crate::sekai::purpose_authorization::PurposeAuthorization, String> {
        match self {
            Self::Sqlite(db) => db.put_purpose_authorization(authorization),
            Self::Postgres(_) => Err(
                "purpose authorizations are unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn revoke_purpose_authorization(
        &self,
        authorization_id: &str,
        revoked_at_ms: i64,
    ) -> Result<crate::sekai::purpose_authorization::PurposeAuthorization, String> {
        match self {
            Self::Sqlite(db) => db.revoke_purpose_authorization(authorization_id, revoked_at_ms),
            Self::Postgres(_) => Err(
                "purpose authorizations are unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn find_purpose_authorization(
        &self,
        actor: &str,
        purpose: &str,
        namespace: &str,
        kind: &str,
        activation_digest: &str,
        now_ms: i64,
    ) -> Result<Option<crate::sekai::purpose_authorization::PurposeAuthorization>, String> {
        match self {
            Self::Sqlite(db) => db.find_purpose_authorization(
                actor,
                purpose,
                namespace,
                kind,
                activation_digest,
                now_ms,
            ),
            Self::Postgres(_) => Err(
                "purpose authorizations are unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn put_classification_lattice(
        &self,
        lattice: &crate::sekai::classification_lattice::ClassificationLattice,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::classification_lattice::ClassificationLattice, String> {
        match self {
            Self::Sqlite(db) => db.put_classification_lattice(lattice, actor, now_ms),
            Self::Postgres(_) => Err(
                "classification lattices are unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn get_classification_lattice(
        &self,
        namespace: &str,
    ) -> Result<Option<crate::sekai::classification_lattice::ClassificationLattice>, String> {
        match self {
            Self::Sqlite(db) => db.get_classification_lattice(namespace),
            Self::Postgres(_) => Ok(None),
        }
    }

    pub fn classification_lattice_recorded_at_ms(
        &self,
        namespace: &str,
    ) -> Result<Option<i64>, String> {
        match self {
            Self::Sqlite(db) => db.classification_lattice_recorded_at_ms(namespace),
            Self::Postgres(_) => Ok(None),
        }
    }

    pub fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
        match self {
            Self::Sqlite(db) => db.object_query_cursor_key(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.object_query_cursor_key()),
        }
    }

    pub fn active_object_policy(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Option<ObjectSecurityPolicy>, String> {
        #[cfg(test)]
        source_batch_auth_counters::POLICY_LOOKUPS.with(|c| c.set(c.get() + 1));
        let Some(activation) = self.get_object_security_activation(namespace)? else {
            return Ok(None);
        };
        let Some(digest) = activation.policies.get(kind) else {
            return Err(
                "object_security_denied: activated namespace has no policy for kind".into(),
            );
        };
        let Some(revision) = self.get_object_security_policy(namespace, digest)? else {
            return Err("object_security_denied: active policy revision unavailable".into());
        };
        ObjectSecurityPolicy::from_canonical_input(&revision.canonical_policy_json)
            .map(Some)
            .map_err(|_| "object_security_denied: active policy revision is invalid".into())
    }

    pub fn project_object_property_grants(&self, mut object: Object) -> Result<Object, String> {
        if let Some(policy) = self.active_object_policy(&object.namespace, &object.kind)? {
            policy.project_visible_properties(&mut object);
            policy.project_visible_value_instances(&mut object);
        }
        Ok(object)
    }

    pub fn reject_ungranted_property_query(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
        properties: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<(), String> {
        let properties = properties
            .into_iter()
            .map(|property| property.as_ref().to_string())
            .filter(|property| !property.is_empty())
            .collect::<Vec<_>>();
        if properties.is_empty() {
            return Ok(());
        }
        let namespaces = match namespace.filter(|value| !value.is_empty()) {
            Some(namespace) => vec![namespace.to_string()],
            None => self.list_activated_object_security_namespaces()?,
        };
        let kind = kind.filter(|value| !value.is_empty());
        for namespace in namespaces {
            let Some(activation) = self.get_object_security_activation(&namespace)? else {
                continue;
            };
            let kinds = match kind {
                Some(kind) if activation.policies.contains_key(kind) => vec![kind.to_string()],
                Some(_) => continue,
                None => activation.policies.keys().cloned().collect(),
            };
            for kind in kinds {
                let policy = match self.active_object_policy(&namespace, &kind) {
                    Ok(Some(policy)) => policy,
                    Ok(None) => continue,
                    Err(error) => return Err(error),
                };
                for property in &properties {
                    if !policy.allows_property_access(property, PropertyGrantAccess::Read) {
                        return Err("object_security_denied: property filter is not granted".into());
                    }
                }
            }
        }
        Ok(())
    }

    pub fn reject_ungranted_value_instance_query(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
        cells: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> Result<(), String> {
        let cells = cells
            .into_iter()
            .map(|(property, value)| (property.as_ref().to_string(), value.as_ref().to_string()))
            .filter(|(property, _)| !property.is_empty())
            .collect::<Vec<_>>();
        if cells.is_empty() {
            return Ok(());
        }
        let namespaces = match namespace.filter(|value| !value.is_empty()) {
            Some(namespace) => vec![namespace.to_string()],
            None => self.list_activated_object_security_namespaces()?,
        };
        let kind = kind.filter(|value| !value.is_empty());
        for namespace in namespaces {
            let Some(activation) = self.get_object_security_activation(&namespace)? else {
                continue;
            };
            let kinds = match kind {
                Some(kind) if activation.policies.contains_key(kind) => vec![kind.to_string()],
                Some(_) => continue,
                None => activation.policies.keys().cloned().collect(),
            };
            for kind in kinds {
                let policy = match self.active_object_policy(&namespace, &kind) {
                    Ok(Some(policy)) => policy,
                    Ok(None) => continue,
                    Err(error) => return Err(error),
                };
                for (property, value) in &cells {
                    if !policy.allows_value_instance_query(
                        property,
                        value,
                        crate::sekai::object_security::PropertyGrantAccess::Read,
                    ) {
                        return Err("object_security_denied: property filter is not granted".into());
                    }
                }
            }
        }
        Ok(())
    }

    fn retain_granted_value_instance_matches(
        &self,
        objects: Vec<Object>,
        cells: &[(String, String)],
    ) -> Result<Vec<Object>, String> {
        if cells.is_empty() {
            return Ok(objects);
        }
        let mut kept = Vec::with_capacity(objects.len());
        for object in objects {
            let Some(policy) = self.active_object_policy(&object.namespace, &object.kind)? else {
                kept.push(object);
                continue;
            };
            if cells.iter().all(|(property, value)| {
                object.properties.get(property).is_some_and(|stored| {
                    stored == value
                        && policy.allows_value_instance_access(
                            &object.id,
                            property,
                            stored,
                            crate::sekai::object_security::PropertyGrantAccess::Read,
                        )
                })
            }) {
                kept.push(object);
            }
        }
        Ok(kept)
    }

    fn value_instance_grants_active(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
    ) -> Result<bool, String> {
        let namespaces = match namespace.filter(|value| !value.is_empty()) {
            Some(namespace) => vec![namespace.to_string()],
            None => self.list_activated_object_security_namespaces()?,
        };
        let kind = kind.filter(|value| !value.is_empty());
        for namespace in namespaces {
            let Some(activation) = self.get_object_security_activation(&namespace)? else {
                continue;
            };
            let kinds = match kind {
                Some(kind) if activation.policies.contains_key(kind) => vec![kind.to_string()],
                Some(_) => continue,
                None => activation.policies.keys().cloned().collect(),
            };
            for kind in kinds {
                if self
                    .active_object_policy(&namespace, &kind)?
                    .is_some_and(|policy| policy.value_instance_grants_enforced())
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn reject_value_instance_sort(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
    ) -> Result<(), String> {
        // Storage ORDER BY would rank hidden cells. Fail closed while cell
        // grants are enforced rather than sorting an unauthorized projection.
        if self.value_instance_grants_active(namespace, kind)? {
            return Err("object_security_denied: property filter is not granted".into());
        }
        Ok(())
    }

    fn reject_value_instance_filter_ops(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
        filters: &[crate::domain::PropertyFilter],
    ) -> Result<(), String> {
        if filters
            .iter()
            .all(|filter| filter.op.is_empty() || filter.op == "eq")
            || !self.value_instance_grants_active(namespace, kind)?
        {
            return Ok(());
        }
        Err("object_security_denied: property filter is not granted".into())
    }

    pub fn list_activated_object_security_namespaces(&self) -> Result<Vec<String>, String> {
        match self {
            Self::Sqlite(db) => db.list_activated_object_security_namespaces(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_activated_object_security_namespaces())
            }
        }
    }

    pub fn get_definition_revision(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<DefinitionRevision>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_definition_revision(
                db.as_ref(),
                namespace,
                revision_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_revision(
                    db.as_ref(),
                    namespace,
                    revision_digest,
                )
            }),
        }
    }

    pub fn get_definition_members(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Vec<DefinitionMember>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_definition_members(
                db.as_ref(),
                namespace,
                revision_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_members(
                    db.as_ref(),
                    namespace,
                    revision_digest,
                )
            }),
        }
    }

    pub fn get_definition_member(
        &self,
        namespace: &str,
        revision_digest: &str,
        member_kind: &str,
        member_id: &str,
    ) -> Result<Option<DefinitionMember>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_definition_member(
                db.as_ref(),
                namespace,
                revision_digest,
                member_kind,
                member_id,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_member(
                    db.as_ref(),
                    namespace,
                    revision_digest,
                    member_kind,
                    member_id,
                )
            }),
        }
    }

    pub fn get_definition_branch(
        &self,
        namespace: &str,
        branch_id: &str,
    ) -> Result<Option<DefinitionBranch>, String> {
        match self {
            Self::Sqlite(db) => {
                DefinitionBranchBackend::get_definition_branch(db.as_ref(), namespace, branch_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_branch(db.as_ref(), namespace, branch_id)
            }),
        }
    }

    pub fn create_definition_branch(
        &self,
        request: &CreateDefinitionBranch,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::create_definition_branch(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::create_definition_branch(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn apply_definition_branch_edit(
        &self,
        request: &ApplyDefinitionBranchEdit,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::apply_definition_branch_edit(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::apply_definition_branch_edit(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn seed_published_definition_revision(
        &self,
        revision: &DefinitionRevision,
        members: &[DefinitionMember],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::seed_published_definition_revision(
                db.as_ref(),
                revision,
                members,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::seed_published_definition_revision(
                    db.as_ref(),
                    revision,
                    members,
                )
            }),
        }
    }

    pub fn execute_definition_fact_migration(
        &self,
        request: &crate::sekai::definition_migration::ExecuteFactMigration,
        actor: &str,
        policy_context: &PrincipalPolicyContext,
        now_ms: i64,
    ) -> Result<crate::sekai::definition_migration::FactMigrationResult, String> {
        match self {
            Self::Sqlite(db) => {
                db.execute_definition_fact_migration(request, actor, policy_context, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.execute_definition_fact_migration(request, actor, policy_context, now_ms)
            }),
        }
    }

    pub fn get_definition_fact_migration(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<Option<crate::sekai::definition_migration::FactMigrationResult>, String> {
        match self {
            Self::Sqlite(db) => db.get_definition_fact_migration(namespace, migration_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_definition_fact_migration(namespace, migration_id)
            }),
        }
    }

    pub fn count_definition_fact_migration_audit(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.count_definition_fact_migration_audit(namespace, migration_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.count_definition_fact_migration_audit(namespace, migration_id)
            }),
        }
    }

    pub fn get_published_definition_revision(
        &self,
        namespace: &str,
    ) -> Result<Option<DefinitionRevision>, String> {
        match self {
            Self::Sqlite(db) => {
                DefinitionBranchBackend::get_published_definition_revision(db.as_ref(), namespace)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_published_definition_revision(db.as_ref(), namespace)
            }),
        }
    }

    pub fn list_published_definition_revisions(
        &self,
        namespace: &str,
        member_kind: &str,
        member_id: &str,
        page_token: &str,
        page_size: i32,
    ) -> Result<(Vec<PublishedDefinitionRevisionHistoryEntry>, String), String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::list_published_definition_revisions(
                db.as_ref(),
                namespace,
                member_kind,
                member_id,
                page_token,
                page_size,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::list_published_definition_revisions(
                    db.as_ref(),
                    namespace,
                    member_kind,
                    member_id,
                    page_token,
                    page_size,
                )
            }),
        }
    }

    pub fn get_definition_proposal(
        &self,
        namespace: &str,
        proposal_id: &str,
    ) -> Result<Option<DefinitionProposal>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_definition_proposal(
                db.as_ref(),
                namespace,
                proposal_id,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_proposal(
                    db.as_ref(),
                    namespace,
                    proposal_id,
                )
            }),
        }
    }

    pub fn create_definition_proposal(
        &self,
        request: &CreateDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::create_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::create_definition_proposal(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn propose_definition_import(
        &self,
        request: &crate::sekai::definition_proposal::ProposeDefinitionImport,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::propose_definition_import(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::propose_definition_import(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn propose_definition_rollback(
        &self,
        request: &ProposeDefinitionRollback,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::propose_definition_rollback(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::propose_definition_rollback(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn approve_definition_proposal(
        &self,
        request: &ApproveDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::approve_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::approve_definition_proposal(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn merge_definition_proposal(
        &self,
        request: &MergeDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let result = match self {
            Self::Sqlite(db) => DefinitionBranchBackend::merge_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::merge_definition_proposal(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }?;
        if matches!(result, DefinitionWriteResult::MergeProposal { .. }) {
            self.invalidate_namespace_hop_projection(&request.namespace, now_ms)?;
        }
        Ok(result)
    }

    pub fn close_definition_proposal(
        &self,
        request: &CloseDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::close_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::close_definition_proposal(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn put_service_principal(
        &self,
        registration: &crate::sekai::service_principal::ServicePrincipalRegistration,
    ) -> Result<Option<crate::sekai::service_principal::ServicePrincipalRegistration>, String> {
        match self {
            Self::Sqlite(db) => db.put_service_principal(registration),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_service_principal(registration))
            }
        }
    }

    pub fn get_service_principal(
        &self,
        principal: &str,
    ) -> Result<Option<crate::sekai::service_principal::ServicePrincipalRegistration>, String> {
        match self {
            Self::Sqlite(db) => db.get_service_principal(principal),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_service_principal(principal))
            }
        }
    }

    pub fn delete_service_principal(
        &self,
        principal: &str,
        tenant_id: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_service_principal(principal, tenant_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_service_principal(principal, tenant_id)
            }),
        }
    }

    pub fn put_agent_definition_certification(
        &self,
        certification: &crate::sekai::agent_promotion::AgentDefinitionCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::put_agent_definition_certification(
                db.as_ref(),
                certification,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::put_agent_definition_certification(
                    db.as_ref(),
                    certification,
                )
            }),
        }
    }

    pub fn get_agent_definition_certification(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<crate::sekai::agent_promotion::AgentDefinitionCertification>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_agent_definition_certification(
                db.as_ref(),
                namespace,
                revision_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_agent_definition_certification(
                    db.as_ref(),
                    namespace,
                    revision_digest,
                )
            }),
        }
    }

    pub fn put_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
        record: &ExportRecord,
    ) -> Result<(ExportRecord, bool), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_subject_provenance_export(actor, export_id, record),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_governed_subject_provenance_export(actor, export_id, record)
            }),
        }
    }

    pub fn get_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
    ) -> Result<Option<ExportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_subject_provenance_export(actor, export_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_governed_subject_provenance_export(actor, export_id)
            }),
        }
    }

    /// In-memory SQLite store for tests.
    pub fn memory() -> Self {
        Self::Sqlite(Arc::new(SekaiDb::new(":memory:").expect("memory sqlite")))
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Sqlite(_) => "sqlite",
            Self::Postgres(_) => "postgres",
        }
    }

    pub fn db_lock_poisoned_total(&self) -> u64 {
        match self {
            Self::Sqlite(db) => db.db_lock_poisoned_total(),
            Self::Postgres(_) => 0,
        }
    }

    pub fn enterprise_extension(&self) -> Option<&Arc<dyn crate::enterprise::EnterpriseExtension>> {
        match self {
            Self::Sqlite(db) => db.enterprise_extension(),
            Self::Postgres(_) => None,
        }
    }

    pub fn as_sqlite(&self) -> Option<&SekaiDb> {
        match self {
            Self::Sqlite(db) => Some(db.as_ref()),
            Self::Postgres(_) => None,
        }
    }

    pub fn as_sqlite_arc(&self) -> Option<Arc<SekaiDb>> {
        match self {
            Self::Sqlite(db) => Some(db.clone()),
            Self::Postgres(_) => None,
        }
    }

    pub fn require_sqlite_arc(&self) -> Result<Arc<SekaiDb>, String> {
        self.as_sqlite_arc().ok_or_else(|| {
            "this code path still requires the SQLite community store; PostgreSQL dual-wiring is incomplete for this operation"
                .into()
        })
    }

    pub fn ping(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.ping(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.ping()),
        }
    }

    pub fn apply_source_batch(
        &self,
        batch: &SourceBatch,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<SourceBatchResult, String> {
        self.apply_source_batch_with_policy_generation(
            batch,
            authenticated_producer,
            now_ms,
            None,
            None,
        )
    }

    pub fn apply_source_batch_with_policy_generation(
        &self,
        batch: &SourceBatch,
        authenticated_producer: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
        authorized_objects: Option<&[Object]>,
    ) -> Result<SourceBatchResult, String> {
        match self {
            Self::Sqlite(db) => db.apply_source_batch_with_policy_generation(
                batch,
                authenticated_producer,
                now_ms,
                expected_policy_generation,
                authorized_objects,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.apply_source_batch_with_policy_generation(
                    batch,
                    authenticated_producer,
                    now_ms,
                    expected_policy_generation,
                    authorized_objects,
                )
            }),
        }
    }

    pub fn get_source_sync_state(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<SourceSyncState>, String> {
        match self {
            Self::Sqlite(db) => ObjectSyncBackend::get_source_sync_state(
                db.as_ref(),
                namespace,
                source_instance,
                type_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ObjectSyncBackend::get_source_sync_state(
                    db.as_ref(),
                    namespace,
                    source_instance,
                    type_digest,
                )
            }),
        }
    }

    pub fn list_active_credentials(&self) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_active_credentials(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_active_credentials()),
        }
    }

    pub fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.get_principal_credential(token_hash),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_principal_credential(token_hash))
            }
        }
    }

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

    pub fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_object(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_object(id)),
        }
    }

    pub fn get_object_with_policy_context(
        &self,
        id: &str,
        context: &PrincipalPolicyContext,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_with_policy_context(id, context),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_object_with_policy_context(id, context))
            }
        }
    }

    pub fn list_objects_by_ids_with_policy_context(
        &self,
        ids: &[String],
        principals: &[&str],
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => {
                crate::db::graph::GraphBackend::list_objects_by_ids_with_policy_context(
                    db.as_ref(),
                    ids,
                    principals,
                    context,
                )
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                crate::db::graph::GraphBackend::list_objects_by_ids_with_policy_context(
                    db.as_ref(),
                    ids,
                    principals,
                    context,
                )
            }),
        }
    }

    pub fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_operation_receipt(receipt),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_operation_receipt(receipt))
            }
        }
    }

    pub fn export_receipt_chain(
        &self,
        namespace: &str,
    ) -> Result<sekai_types::receipt_chain::ReceiptChainBundle, String> {
        match self {
            Self::Sqlite(db) => db.export_receipt_chain(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.export_receipt_chain(namespace))
            }
        }
    }

    pub fn get_operation_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.get_operation_receipt(operation_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_operation_receipt(operation_id))
            }
        }
    }

    pub fn get_operation_reservation(
        &self,
        namespace: &str,
        operation_id: &str,
    ) -> Result<Option<OperationReservation>, String> {
        match self {
            Self::Sqlite(db) => db.get_operation_reservation(namespace, operation_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_operation_reservation(namespace, operation_id)
            }),
        }
    }

    pub fn put_operation_reservation(
        &self,
        reservation: &OperationReservation,
    ) -> Result<OperationReservation, String> {
        match self {
            Self::Sqlite(db) => db.put_operation_reservation(reservation),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_operation_reservation(reservation))
            }
        }
    }

    pub fn list_pending_operation_reservations(
        &self,
        limit: usize,
    ) -> Result<Vec<OperationReservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_pending_operation_reservations(limit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_pending_operation_reservations(limit))
            }
        }
    }

    /// List operation receipts for a namespace overlapping `[start, end)`.
    ///
    /// Open receipts (`completed_at_ms` unset) overlap only while
    /// `started_at_ms` is within
    /// [`OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS`](crate::db::chisei_receipt::OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS)
    /// of `start`. That keeps in-flight harvest visible without letting
    /// abandoned opens accumulate across every later window.
    pub fn list_operation_receipts_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.list_operation_receipts_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_operation_receipts_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    limit,
                )
            }),
        }
    }

    pub fn count_active_kioku_promotions_in_window(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.count_active_kioku_promotions_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                )
            }),
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

    pub fn acquire_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        match self {
            Self::Sqlite(db) => db.acquire_lease(
                namespace, key, owner, ttl_ms, request_id, actor, site_id, now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.acquire_lease(
                    namespace, key, owner, ttl_ms, request_id, actor, site_id, now_ms,
                )
            }),
        }
    }

    pub fn add_blast_radius(
        &self,
        work_unit: &str,
        mutations: u32,
        deletes: u32,
    ) -> Result<(u32, u32), String> {
        match self {
            Self::Sqlite(db) => db.add_blast_radius(work_unit, mutations, deletes),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.add_blast_radius(work_unit, mutations, deletes)
            }),
        }
    }

    pub fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String> {
        match self {
            Self::Sqlite(db) => db.append_operation_receipt_event(operation_id, event),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.append_operation_receipt_event(operation_id, event)
            }),
        }
    }

    pub fn append_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.append_rows(dataset_id, rows),
            Self::Postgres(_) => {
                Err("append_rows is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn append_run_event(&self, event: &RunEvent) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.append_run_event(event),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.append_run_event(event)),
        }
    }

    pub fn authorize_operation_reporter(
        &self,
        operation_id: &str,
        principal: &str,
        event_kinds: Vec<ReceiptEventKind>,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.authorize_operation_reporter(operation_id, principal, event_kinds)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.authorize_operation_reporter(operation_id, principal, event_kinds)
            }),
        }
    }

    pub fn budget_adjust_chain(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_adjust_chain(scope_id, metric, delta, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_adjust_chain(scope_id, metric, delta, now_ms)
            }),
        }
    }

    pub fn budget_check_and_reserve_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_and_reserve_chain(scope_id, metric, amount, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_check_and_reserve_chain(scope_id, metric, amount, now_ms)
            }),
        }
    }

    pub fn budget_check_and_reserve_chain_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_and_reserve_chain_idempotent(
                scope_id,
                metric,
                amount,
                now_ms,
                idempotency_key,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_check_and_reserve_chain_idempotent(
                    scope_id,
                    metric,
                    amount,
                    now_ms,
                    idempotency_key,
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_check_and_reserve_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: Option<&str>,
        require_home_pin: bool,
        local_site_id: &str,
        partition_simulated: bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_and_reserve_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                idempotency_key,
                require_home_pin,
                local_site_id,
                partition_simulated,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_check_and_reserve_chain_for_site(
                    scope_id,
                    metric,
                    amount,
                    now_ms,
                    idempotency_key,
                    require_home_pin,
                    local_site_id,
                    partition_simulated,
                )
            }),
        }
    }

    pub fn budget_check_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_chain(scope_id, metric, amount, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_check_chain(scope_id, metric, amount, now_ms)
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_check_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
        partition_simulated: bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                require_home_pin,
                local_site_id,
                partition_simulated,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_check_chain_for_site(
                    scope_id,
                    metric,
                    amount,
                    now_ms,
                    require_home_pin,
                    local_site_id,
                    partition_simulated,
                )
            }),
        }
    }

    pub fn budget_assert_home_writable(
        &self,
        scope_id: &str,
        metric: &str,
        local_site_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_assert_home_writable(scope_id, metric, local_site_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_assert_home_writable(scope_id, metric, local_site_id)
            }),
        }
    }

    pub fn budget_adjust_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_adjust_chain_for_site(
                scope_id,
                metric,
                delta,
                now_ms,
                require_home_pin,
                local_site_id,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_adjust_chain_for_site(
                    scope_id,
                    metric,
                    delta,
                    now_ms,
                    require_home_pin,
                    local_site_id,
                )
            }),
        }
    }

    pub fn budget_set_limit_scoped(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
        home_site_id: &str,
        pool_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_set_limit_scoped(
                scope_id,
                metric,
                max_amount,
                period_type,
                home_site_id,
                pool_id,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_set_limit_scoped(
                    scope_id,
                    metric,
                    max_amount,
                    period_type,
                    home_site_id,
                    pool_id,
                )
            }),
        }
    }

    pub fn budget_set_pool_ceiling(
        &self,
        pool_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.budget_set_pool_ceiling(pool_id, metric, max_amount, period_type)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_set_pool_ceiling(pool_id, metric, max_amount, period_type)
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_transfer_capacity(
        &self,
        transfer_id: &str,
        metric: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::db::chisei_budget::BudgetTransferRecord, String> {
        match self {
            Self::Sqlite(db) => db.budget_transfer_capacity(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_transfer_capacity(
                    transfer_id,
                    metric,
                    from_scope_id,
                    to_scope_id,
                    amount,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_record_transfer_refused(
        &self,
        transfer_id: &str,
        metric: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<crate::db::chisei_budget::BudgetTransferRecord, String> {
        match self {
            Self::Sqlite(db) => db.budget_record_transfer_refused(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                reason,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_record_transfer_refused(
                    transfer_id,
                    metric,
                    from_scope_id,
                    to_scope_id,
                    amount,
                    actor,
                    reason,
                    now_ms,
                )
            }),
        }
    }

    pub fn budget_get_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<Option<crate::db::chisei_budget::BudgetTransferRecord>, String> {
        match self {
            Self::Sqlite(db) => db.budget_get_transfer(transfer_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.budget_get_transfer(transfer_id))
            }
        }
    }

    pub fn budget_limits_for_scope(
        &self,
        scope_id: &str,
    ) -> Result<Vec<(String, String, i64, String)>, String> {
        match self {
            Self::Sqlite(db) => db.budget_limits_for_scope(scope_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.budget_limits_for_scope(scope_id))
            }
        }
    }

    pub fn budget_namespace_pressure(
        &self,
        namespace: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.budget_namespace_pressure(namespace, metric, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_namespace_pressure(namespace, metric, now_ms)
            }),
        }
    }

    pub fn budget_record_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.budget_record_idempotent(scope_id, metric, amount, idempotency_key, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_record_idempotent(scope_id, metric, amount, idempotency_key, now_ms)
            }),
        }
    }

    pub fn budget_set_limit(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_set_limit(scope_id, metric, max_amount, period_type),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.budget_set_limit(scope_id, metric, max_amount, period_type)
            }),
        }
    }

    pub fn budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String> {
        match self {
            Self::Sqlite(db) => db.budget_usage(scope_id, metric, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.budget_usage(scope_id, metric, now_ms))
            }
        }
    }

    pub fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.bump_observation_attempts(request_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.bump_observation_attempts(request_id))
            }
        }
    }

    pub fn cancel_work_unit(
        &self,
        work_unit_id: &str,
        cancel_reason: &str,
        now_ms: i64,
    ) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.cancel_work_unit(work_unit_id, cancel_reason, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.cancel_work_unit(work_unit_id, cancel_reason, now_ms)
            }),
        }
    }

    pub fn claim_gateway_request_alias_dispatch(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
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

    pub fn complete_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.complete_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.complete_work_unit(work_unit_id, now_ms))
            }
        }
    }

    pub fn contention_scope_chain(&self, scope_id: &str) -> Result<Vec<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.contention_scope_chain(scope_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.contention_scope_chain(scope_id))
            }
        }
    }

    pub fn create_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_contention_scope(scope),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_contention_scope(scope))
            }
        }
    }

    pub fn create_dataset(&self, d: &Dataset) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_dataset(d),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_dataset(d)),
        }
    }

    /// Stores an operator-only function. A revision with an LLM step is stored only by
    /// `publish_function_revision` once its evaluation gate allows it.
    pub fn create_function(&self, f: &Function) -> Result<(), String> {
        if crate::sekai::function::has_llm_step(f) {
            return Err(crate::sekai::function::LLM_FUNCTION_REQUIRES_GATE.into());
        }
        self.store_function(f)
    }

    /// Stores a revision whose evaluation gate allowed it and records its approval.
    /// Callers must have checked the gate against this revision's digest. Re-publishing
    /// the stored revision only approves it; a different stored revision of the same name
    /// is refused. The row is written before the approval, so a failure leaves nothing
    /// newly invokable.
    pub(crate) fn publish_gated_function(&self, f: &Function) -> Result<(), String> {
        let digest = crate::sekai::function::function_digest(f);
        match self.get_function(&f.name)? {
            Some(stored) if crate::sekai::function::function_digest(&stored) == digest => {}
            Some(_) => return Err("function already exists".into()),
            None => self.store_function(f)?,
        }
        match self {
            Self::Sqlite(db) => db.approve_function_gate(&digest, &f.name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.approve_function_gate(&digest, &f.name))
            }
        }
    }

    /// Whether this revision's digest passed an allowing evaluation gate. Rows stored
    /// before approvals were recorded have none, so they stay unapproved.
    pub fn function_gate_approved(&self, f: &Function) -> Result<bool, String> {
        let digest = crate::sekai::function::function_digest(f);
        match self {
            Self::Sqlite(db) => db.function_gate_approved(&digest),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.function_gate_approved(&digest))
            }
        }
    }

    fn store_function(&self, f: &Function) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_function(f),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_function(f)),
        }
    }

    pub fn set_write_freeze(
        &self,
        freeze: &crate::sekai::write_freeze::WriteFreeze,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_write_freeze(freeze),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.set_write_freeze(freeze)),
        }
    }

    pub fn set_write_freeze_with_decision(
        &self,
        freeze: &crate::sekai::write_freeze::WriteFreeze,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_write_freeze_with_decision(freeze, decision),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_write_freeze_with_decision(freeze, decision)
            }),
        }
    }

    pub fn list_write_freezes(
        &self,
    ) -> Result<Vec<crate::sekai::write_freeze::WriteFreeze>, String> {
        match self {
            Self::Sqlite(db) => db.list_write_freezes(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_write_freezes()),
        }
    }

    pub fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_grant(grant),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_grant(grant)),
        }
    }

    pub fn create_grant_with_decision(
        &self,
        grant: &Grant,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_grant_with_decision(grant, decision),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_grant_with_decision(grant, decision))
            }
        }
    }

    pub fn set_namespace_grant_policy(&self, policy: &NamespaceGrantPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_namespace_grant_policy(policy),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.set_namespace_grant_policy(policy))
            }
        }
    }

    /// Stamp namespace grant policy and refresh the in-memory access cache.
    /// Storage updates existing open-ended grants; the cache would otherwise
    /// keep `not_after_ms = 0` until process restart.
    ///
    /// There is no public policy RPC. Call this on a quiet store (tests or
    /// operator setup). CreateGrant and this refresh are not a concurrent
    /// production pair.
    pub fn apply_namespace_grant_policy(
        &self,
        security: &SecurityChecker,
        policy: &NamespaceGrantPolicy,
    ) -> Result<(), String> {
        self.set_namespace_grant_policy(policy)?;
        security.reload(|| self.list_all_grants())?;
        Ok(())
    }

    pub fn namespace_grant_policy(
        &self,
        namespace: &str,
    ) -> Result<Option<NamespaceGrantPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.namespace_grant_policy(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.namespace_grant_policy(namespace))
            }
        }
    }

    pub fn create_handoff(
        &self,
        manifest: &HandoffManifest,
        request_id: &str,
    ) -> Result<HandoffManifest, String> {
        match self {
            Self::Sqlite(db) => db.create_handoff(manifest, request_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_handoff(manifest, request_id))
            }
        }
    }

    pub fn create_link(&self, l: &Link) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_link(l),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_link(l)),
        }
    }

    pub fn create_link_once(&self, l: &Link) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.create_link_once(l),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_link_once(l)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_link_with_authorized_endpoints(
        &self,
        l: &Link,
        expected_from: &Object,
        expected_to: &Object,
        from_generation: Option<&str>,
        to_generation: Option<&str>,
        fail_if_exists: bool,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.create_link_with_authorized_endpoints(
                l,
                expected_from,
                expected_to,
                from_generation,
                to_generation,
                fail_if_exists,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_link_with_authorized_endpoints(
                    l,
                    expected_from,
                    expected_to,
                    from_generation,
                    to_generation,
                    fail_if_exists,
                )
            }),
        }
    }

    pub fn create_managed_team_credential(
        &self,
        principal: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<PrincipalCredential, String> {
        match self {
            Self::Sqlite(db) => db.create_managed_team_credential(principal, token_hash, now),
            Self::Postgres(_) => Err(
                "create_managed_team_credential is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn create_object(&self, o: &Object) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_object(o),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_object(o)),
        }
    }

    pub fn create_object_with_audit(&self, object: &Object, actor: &str) -> Result<(), String> {
        self.create_object_with_authorized_policy(object, actor, None)
    }

    pub fn create_object_with_authorized_policy(
        &self,
        object: &Object,
        actor: &str,
        expected_policy_generation: Option<&str>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.create_object_with_authorized_policy(object, actor, expected_policy_generation)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_object_with_authorized_policy(object, actor, expected_policy_generation)
            }),
        }
    }

    pub fn create_governed_object_with_audit(
        &self,
        object: &Object,
        actor: &str,
        history_identity_property: &str,
        history_identity: &str,
        predecessor_property: &str,
        predecessor_id: &str,
        max_objects: usize,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_governed_object_with_audit(
                object,
                actor,
                history_identity_property,
                history_identity,
                predecessor_property,
                predecessor_id,
                max_objects,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_governed_object_with_audit(
                    object,
                    actor,
                    history_identity_property,
                    history_identity,
                    predecessor_property,
                    predecessor_id,
                    max_objects,
                )
            }),
        }
    }

    pub fn create_virtual_table(&self, vt: &VirtualTable) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_virtual_table(vt),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_virtual_table(vt)),
        }
    }

    pub fn create_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_work_unit(work_unit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_work_unit(work_unit))
            }
        }
    }

    pub fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.delete_grant(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_grant(id)),
        }
    }

    pub fn delete_interface(&self, name: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_interface(name),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_interface(name)),
        }
    }

    pub fn delete_link(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_link(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_link(id)),
        }
    }

    pub fn delete_link_with_authorized_endpoints(
        &self,
        id: &str,
        expected_from: &Object,
        expected_to: &Object,
        from_generation: Option<&str>,
        to_generation: Option<&str>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_link_with_authorized_endpoints(
                id,
                expected_from,
                expected_to,
                from_generation,
                to_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_link_with_authorized_endpoints(
                    id,
                    expected_from,
                    expected_to,
                    from_generation,
                    to_generation,
                )
            }),
        }
    }

    pub fn delete_object_type(&self, kind: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_type(kind),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_object_type(kind)),
        }
    }

    pub fn delete_object_with_audit(
        &self,
        id: &str,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        self.delete_object_with_authorized_snapshot(id, None, actor, None)
    }

    pub fn delete_object_with_authorized_snapshot(
        &self,
        id: &str,
        expected: Option<&Object>,
        actor: &str,
        expected_policy_generation: Option<&str>,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_with_authorized_snapshot(
                id,
                expected,
                actor,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_object_with_authorized_snapshot(
                    id,
                    expected,
                    actor,
                    expected_policy_generation,
                )
            }),
        }
    }

    pub fn delete_observation(&self, request_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_observation(request_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.delete_observation(request_id))
            }
        }
    }

    pub fn delete_ontology_class_with_audit(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_ontology_class_with_audit(name, actor),
            Self::Postgres(_) => Err("delete_ontology_class_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn delete_ontology_relation_with_audit(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_ontology_relation_with_audit(name, actor),
            Self::Postgres(_) => Err("delete_ontology_relation_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn ensure_team_namespace(
        &self,
        namespace: &str,
        principal: &str,
        member_role: Role,
        actor: &str,
    ) -> Result<(Object, Vec<Grant>), String> {
        match self {
            Self::Sqlite(db) => db.ensure_team_namespace(namespace, principal, member_role, actor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.ensure_team_namespace(namespace, principal, member_role, actor)
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

    pub fn fail_work_unit(
        &self,
        work_unit_id: &str,
        failure_reason: &str,
        now_ms: i64,
    ) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.fail_work_unit(work_unit_id, failure_reason, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.fail_work_unit(work_unit_id, failure_reason, now_ms)
            }),
        }
    }

    pub fn find_all_by_external_id(&self, external_id: &str) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_all_by_external_id(external_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_all_by_external_id(external_id))
            }
        }
    }

    pub fn find_all_by_external_ids_in_namespace(
        &self,
        namespace: &str,
        external_ids: &[String],
    ) -> Result<Vec<Object>, String> {
        #[cfg(test)]
        if !external_ids.is_empty() {
            source_batch_auth_counters::LOOKUP_QUERIES.with(|c| c.set(c.get() + 1));
        }
        match self {
            Self::Sqlite(db) => db.find_all_by_external_ids_in_namespace(namespace, external_ids),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_all_by_external_ids_in_namespace(namespace, external_ids)
            }),
        }
    }

    pub fn find_all_by_external_id_with_policy_context(
        &self,
        external_id: &str,
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => {
                db.find_all_by_external_id_with_policy_context(external_id, context)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_all_by_external_id_with_policy_context(external_id, context)
            }),
        }
    }

    pub fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_by_external_id(external_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_by_external_id(external_id))
            }
        }
    }

    pub fn find_by_property(
        &self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_by_property(kind, key, value),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_by_property(kind, key, value))
            }
        }
    }

    pub fn find_by_property_with_policy_context(
        &self,
        kind: &str,
        key: &str,
        value: &str,
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Object>, String> {
        self.reject_ungranted_property_query(None, Some(kind), [key])?;
        self.reject_ungranted_value_instance_query(None, Some(kind), [(key, value)])?;
        let rows = match self {
            Self::Sqlite(db) => db.find_by_property_with_policy_context(kind, key, value, context),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_by_property_with_policy_context(kind, key, value, context)
            }),
        }?;
        self.retain_granted_value_instance_matches(rows, &[(key.to_string(), value.to_string())])
    }

    pub fn find_gateway_receipt_by_logical_operation_id(
        &self,
        operation_id: &str,
        attempt: Option<u32>,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => {
                db.find_gateway_receipt_by_logical_operation_id(operation_id, attempt)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_gateway_receipt_by_logical_operation_id(operation_id, attempt)
            }),
        }
    }

    pub fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_namespace_boundary(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_namespace_boundary(namespace))
            }
        }
    }

    pub fn find_operation_receipt_by_lookup_request_id(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_operation_receipt_by_lookup_request_id(
                    request_id,
                    caller_scope,
                    initiating_actor,
                )
            }),
        }
    }

    pub fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.find_operation_receipt_by_request_id(request_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_operation_receipt_by_request_id(request_id)
            }),
        }
    }

    pub fn get_action_policy(&self, scope: &str) -> Result<Option<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_policy(scope),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_action_policy(scope)),
        }
    }

    pub fn get_attestation(&self, id: &str) -> Result<Option<PolicyAttestation>, String> {
        match self {
            Self::Sqlite(db) => db.get_attestation(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_attestation(id)),
        }
    }

    pub fn get_blast_radius(&self, work_unit: &str) -> Result<(u32, u32), String> {
        match self {
            Self::Sqlite(db) => db.get_blast_radius(work_unit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_blast_radius(work_unit))
            }
        }
    }

    pub fn get_contention_scope(&self, id: &str) -> Result<Option<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.get_contention_scope(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_contention_scope(id)),
        }
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_dataset(id)),
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

    pub fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        match self {
            Self::Sqlite(db) => db.get_function(name),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_function(name)),
        }
    }

    pub fn get_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.get_grant(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_grant(id)),
        }
    }

    pub fn get_handoff(&self, id: &str) -> Result<Option<HandoffManifest>, String> {
        match self {
            Self::Sqlite(db) => db.get_handoff(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_handoff(id)),
        }
    }

    pub fn get_handoff_by_request(
        &self,
        creator_principal: &str,
        request_id: &str,
    ) -> Result<Option<(String, HandoffManifest)>, String> {
        match self {
            Self::Sqlite(db) => db.get_handoff_by_request(creator_principal, request_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_handoff_by_request(creator_principal, request_id)
            }),
        }
    }

    pub fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>, LeaseError> {
        match self {
            Self::Sqlite(db) => db.get_lease(namespace, key),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_lease(namespace, key)),
        }
    }

    pub fn get_link(&self, id: &str) -> Result<Option<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_link(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_link(id)),
        }
    }

    pub fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_linked_objects(object_id, relation, dir),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_linked_objects(object_id, relation, dir))
            }
        }
    }

    pub fn get_linked_objects_with_policy_context(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => {
                db.get_linked_objects_with_policy_context(object_id, relation, dir, context)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_linked_objects_with_policy_context(object_id, relation, dir, context)
            }),
        }
    }

    pub fn get_links(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links(object_id, relation, dir),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_links(object_id, relation, dir))
            }
        }
    }

    /// At most `limit` links, so a caller can bound the read itself, not only its result.
    pub fn get_links_with_policy_context_limited(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        context: &PrincipalPolicyContext,
        limit: usize,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links_with_policy_context_limited(
                object_id,
                relation,
                dir,
                context,
                Some(limit),
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_links_with_policy_context_limited(
                    object_id,
                    relation,
                    dir,
                    context,
                    Some(limit),
                )
            }),
        }
    }

    pub fn get_links_with_policy_context(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links_with_policy_context(object_id, relation, dir, context),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_links_with_policy_context(object_id, relation, dir, context)
            }),
        }
    }

    pub fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_class(name),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_ontology_class(name)),
        }
    }

    pub fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_relation(name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_ontology_relation(name))
            }
        }
    }

    pub fn get_work_unit(&self, id: &str) -> Result<Option<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.get_work_unit(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_work_unit(id)),
        }
    }

    pub fn get_work_unit_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.get_work_unit_by_idempotency_key(idempotency_key),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_work_unit_by_idempotency_key(idempotency_key)
            }),
        }
    }

    pub fn guarded_create_object(
        &self,
        object: &Object,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, LeaseError> {
        self.guarded_create_object_with_policy(
            object, namespace, key, token, request_id, actor, now_ms, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_create_object_with_policy(
        &self,
        object: &Object,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
    ) -> Result<Object, LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_create_object_with_policy(
                object,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.guarded_create_object_with_policy(
                    object,
                    namespace,
                    key,
                    token,
                    request_id,
                    actor,
                    now_ms,
                    expected_policy_generation,
                )
            }),
        }
    }

    pub fn guarded_delete_object(
        &self,
        object_id: &str,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), LeaseError> {
        self.guarded_delete_object_with_policy(
            object_id, expected, namespace, key, token, request_id, actor, now_ms, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_delete_object_with_policy(
        &self,
        object_id: &str,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
    ) -> Result<(), LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_delete_object_with_policy(
                object_id,
                expected,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.guarded_delete_object_with_policy(
                    object_id,
                    expected,
                    namespace,
                    key,
                    token,
                    request_id,
                    actor,
                    now_ms,
                    expected_policy_generation,
                )
            }),
        }
    }

    pub fn guarded_object_replay(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        operation: &str,
        target_id: &str,
        request_object: &Object,
    ) -> Result<Option<Object>, LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_object_replay(
                namespace,
                key,
                token,
                request_id,
                operation,
                target_id,
                request_object,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.guarded_object_replay(
                    namespace,
                    key,
                    token,
                    request_id,
                    operation,
                    target_id,
                    request_object,
                )
            }),
        }
    }

    pub fn guarded_update_object(
        &self,
        object: &Object,
        request_object: &Object,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, LeaseError> {
        self.guarded_update_object_with_policy(
            object,
            request_object,
            expected,
            namespace,
            key,
            token,
            request_id,
            actor,
            now_ms,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_update_object_with_policy(
        &self,
        object: &Object,
        request_object: &Object,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
    ) -> Result<Object, LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_update_object_with_policy(
                object,
                request_object,
                expected,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.guarded_update_object_with_policy(
                    object,
                    request_object,
                    expected,
                    namespace,
                    key,
                    token,
                    request_id,
                    actor,
                    now_ms,
                    expected_policy_generation,
                )
            }),
        }
    }

    pub fn handoff_is_superseded(&self, id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.handoff_is_superseded(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.handoff_is_superseded(id)),
        }
    }

    pub fn heartbeat_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.heartbeat_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.heartbeat_work_unit(work_unit_id, now_ms))
            }
        }
    }

    pub fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_operation_receipt(receipt),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.insert_operation_receipt(receipt))
            }
        }
    }

    pub fn is_team_principal(&self, principal: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.is_team_principal(principal),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.is_team_principal(principal))
            }
        }
    }

    pub fn kioku_authorized_classification_ceiling(
        &self,
        namespace: &str,
        actor: &str,
    ) -> Result<EvidenceClassification, String> {
        match self {
            Self::Sqlite(db) => db.kioku_authorized_classification_ceiling(namespace, actor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.kioku_authorized_classification_ceiling(namespace, actor)
            }),
        }
    }

    pub fn list_action_policies(&self) -> Result<Vec<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_policies(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_action_policies()),
        }
    }

    pub fn put_governed_action_type(
        &self,
        type_def: crate::sekai::governed_action_type::GovernedActionType,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_action_type::GovernedActionType, String> {
        match self {
            Self::Sqlite(db) => db.put_governed_action_type(type_def, actor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_governed_action_type(type_def, actor, now_ms)
            }),
        }
    }

    pub fn get_governed_action_type(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
    ) -> Result<Option<crate::sekai::governed_action_type::GovernedActionType>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_action_type(namespace, type_id, version),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_governed_action_type(namespace, type_id, version)
            }),
        }
    }

    pub fn list_governed_action_types(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        enabled_only: bool,
    ) -> Result<Vec<crate::sekai::governed_action_type::GovernedActionType>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_action_types(namespace, type_id, enabled_only),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_action_types(namespace, type_id, enabled_only)
            }),
        }
    }

    pub fn set_governed_action_type_enabled(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
        enabled: bool,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_action_type::GovernedActionType, String> {
        match self {
            Self::Sqlite(db) => {
                db.set_governed_action_type_enabled(namespace, type_id, version, enabled, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_governed_action_type_enabled(namespace, type_id, version, enabled, now_ms)
            }),
        }
    }

    pub fn require_enabled_governed_action_type(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
    ) -> Result<crate::sekai::governed_action_type::GovernedActionType, String> {
        match self {
            Self::Sqlite(db) => {
                db.require_enabled_governed_action_type(namespace, type_id, version)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.require_enabled_governed_action_type(namespace, type_id, version)
            }),
        }
    }

    pub fn put_action_instance(
        &self,
        instance: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<crate::sekai::action_instance::ActionInstance, String> {
        match self {
            Self::Sqlite(db) => db.put_action_instance(instance),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_action_instance(instance))
            }
        }
    }

    pub fn put_decision_memory(
        &self,
        memory: &crate::sekai::decision_memory::DecisionMemory,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_decision_memory(memory),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_decision_memory(memory))
            }
        }
    }

    pub fn list_decision_memory(
        &self,
        namespace: &str,
        type_id: &str,
    ) -> Result<Vec<crate::sekai::decision_memory::DecisionMemory>, String> {
        self.list_decision_memory_page(namespace, type_id, 0, i64::MAX)
    }

    pub fn list_decision_memory_page(
        &self,
        namespace: &str,
        type_id: &str,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<crate::sekai::decision_memory::DecisionMemory>, String> {
        match self {
            Self::Sqlite(db) => db.list_decision_memory_page(namespace, type_id, offset, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_decision_memory_page(namespace, type_id, offset, limit)
            }),
        }
    }

    pub fn get_decision_memory(
        &self,
        memory_id: &str,
    ) -> Result<Option<crate::sekai::decision_memory::DecisionMemory>, String> {
        match self {
            Self::Sqlite(db) => db.get_decision_memory(memory_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_decision_memory(memory_id))
            }
        }
    }

    pub fn mark_decision_memory_superseded(&self, memory_id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.mark_decision_memory_superseded(memory_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.mark_decision_memory_superseded(memory_id))
            }
        }
    }

    pub fn put_action_binding(
        &self,
        binding: &crate::sekai::action_binding::ActionBinding,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::action_binding::ActionBinding, String> {
        match self {
            Self::Sqlite(db) => db.put_action_binding(binding, actor, now_ms),
            Self::Postgres(_) => Err(ACTION_BINDINGS_UNAVAILABLE.into()),
        }
    }

    pub fn get_action_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<
        Option<(
            crate::sekai::action_binding::ActionBinding,
            crate::sekai::action_binding::ActionBindingCursor,
        )>,
        String,
    > {
        match self {
            Self::Sqlite(db) => db.get_action_binding(namespace, binding_id),
            Self::Postgres(_) => Err(ACTION_BINDINGS_UNAVAILABLE.into()),
        }
    }

    pub fn advance_action_binding_cursor(
        &self,
        binding: &crate::sekai::action_binding::ActionBinding,
        cursor: &crate::sekai::action_binding::ActionBindingCursor,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.advance_action_binding_cursor(binding, cursor, now_ms),
            Self::Postgres(_) => Err(ACTION_BINDINGS_UNAVAILABLE.into()),
        }
    }

    pub fn decide_parked_action_instance(
        &self,
        decided: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.decide_parked_action_instance(decided),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.decide_parked_action_instance(decided))
            }
        }
    }

    pub fn update_parked_action_instance(
        &self,
        instance: &crate::sekai::action_instance::ActionInstance,
        expected_assignee: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.transition_action_instance(
                crate::sekai::action_instance::STATUS_PARKED,
                instance,
                expected_assignee,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.transition_action_instance(
                    crate::sekai::action_instance::STATUS_PARKED,
                    instance,
                    expected_assignee,
                )
            }),
        }
    }

    pub fn grant_parked_action_instance(
        &self,
        granted: &crate::sekai::action_instance::ActionInstance,
        target_object_id: &str,
        parked_object_digest: &str,
        write: Option<&crate::sekai::action_instance::ParkedGrantWrite>,
        actor: &str,
    ) -> Result<crate::sekai::action_instance::ParkedGrantOutcome, String> {
        match self {
            Self::Sqlite(db) => db.grant_parked_action_instance(
                granted,
                target_object_id,
                parked_object_digest,
                write,
                actor,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.grant_parked_action_instance(
                    granted,
                    target_object_id,
                    parked_object_digest,
                    write,
                    actor,
                )
            }),
        }
    }

    /// Returns a granted instance to `parked` when its grant could not be
    /// recorded, so the decision can be retried.
    pub fn repark_action_instance(
        &self,
        parked: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.transition_action_instance(
                crate::sekai::action_instance::STATUS_ADMITTED,
                parked,
                &parked.review.assignee,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.transition_action_instance(
                    crate::sekai::action_instance::STATUS_ADMITTED,
                    parked,
                    &parked.review.assignee,
                )
            }),
        }
    }

    pub fn delete_action_instance(&self, instance_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_action_instance(instance_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.delete_action_instance(instance_id))
            }
        }
    }

    pub fn get_action_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance(instance_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_action_instance(instance_id))
            }
        }
    }

    pub fn get_action_instance_by_operation_id(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance_by_operation_id(operation_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_action_instance_by_operation_id(operation_id)
            }),
        }
    }

    pub fn get_action_instance_by_idempotency(
        &self,
        namespace: &str,
        idempotency_key: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance_by_idempotency(namespace, idempotency_key),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_action_instance_by_idempotency(namespace, idempotency_key)
            }),
        }
    }

    pub fn list_action_instances(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_instance::ActionInstance>, String> {
        self.list_action_instances_page(namespace, type_id, status, limit, 0)
    }

    pub fn list_action_instances_page(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_action_instances_page(namespace, type_id, status, limit, offset)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_action_instances_page(namespace, type_id, status, limit, offset)
            }),
        }
    }

    pub fn put_action_effects(
        &self,
        effects: &[crate::sekai::action_effect::ActionEffect],
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.put_action_effects(effects),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_action_effects(effects))
            }
        }
    }

    pub fn get_action_effect(
        &self,
        effect_id: &str,
    ) -> Result<Option<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_effect(effect_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_action_effect(effect_id))
            }
        }
    }

    pub fn list_action_effects_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_effects_for_instance(instance_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_action_effects_for_instance(instance_id)
            }),
        }
    }

    pub fn list_pending_runtime_dispatch_effects(
        &self,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        self.list_pending_runtime_dispatch_effects_page(namespace, limit, None)
    }

    pub fn list_pending_runtime_dispatch_effects_page(
        &self,
        namespace: &str,
        limit: usize,
        cursor: Option<(i64, &str)>,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_pending_runtime_dispatch_effects_page(namespace, limit, cursor)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_pending_runtime_dispatch_effects_page(namespace, limit, cursor)
            }),
        }
    }

    pub fn list_claimable_action_work(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        self.list_claimable_action_work_page(namespace, runtime_id, now_ms, limit, None)
    }

    pub fn list_claimable_action_work_page(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
        cursor: Option<(i64, &str)>,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_claimable_action_work_page(namespace, runtime_id, now_ms, limit, cursor)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_claimable_action_work_page(namespace, runtime_id, now_ms, limit, cursor)
            }),
        }
    }

    pub fn claim_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        request_id: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        match self {
            Self::Sqlite(db) => {
                db.claim_action_work(effect_id, runtime_id, request_id, ttl_ms, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_action_work(effect_id, runtime_id, request_id, ttl_ms, now_ms)
            }),
        }
    }

    pub fn heartbeat_action_claim(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        match self {
            Self::Sqlite(db) => db.heartbeat_action_claim(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                ttl_ms,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.heartbeat_action_claim(
                    effect_id,
                    runtime_id,
                    generation,
                    fencing_token,
                    ttl_ms,
                    now_ms,
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ack_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        outcome: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        match self {
            Self::Sqlite(db) => db.ack_action_work(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                outcome,
                reason,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.ack_action_work(
                    effect_id,
                    runtime_id,
                    generation,
                    fencing_token,
                    outcome,
                    reason,
                    now_ms,
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn park_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        reason: &str,
        request_id: &str,
        checkpoint_store_id: &str,
        checkpoint_ref: &str,
        checkpoint_digest: &str,
        parked_by: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::parked_work::ParkResult, String> {
        match self {
            Self::Sqlite(db) => db.park_action_work(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                reason,
                request_id,
                checkpoint_store_id,
                checkpoint_ref,
                checkpoint_digest,
                parked_by,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.park_action_work(
                    effect_id,
                    runtime_id,
                    generation,
                    fencing_token,
                    reason,
                    request_id,
                    checkpoint_store_id,
                    checkpoint_ref,
                    checkpoint_digest,
                    parked_by,
                    now_ms,
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_parked_resolution(
        &self,
        effect_id: &str,
        expected_park_generation: u64,
        input_json: &str,
        reason: &str,
        request_id: &str,
        submitted_by: &str,
        policy_version: &str,
        status: &str,
        approval_id: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::parked_work::ResolutionResult, String> {
        match self {
            Self::Sqlite(db) => db.submit_parked_resolution(
                effect_id,
                expected_park_generation,
                input_json,
                reason,
                request_id,
                submitted_by,
                policy_version,
                status,
                approval_id,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.submit_parked_resolution(
                    effect_id,
                    expected_park_generation,
                    input_json,
                    reason,
                    request_id,
                    submitted_by,
                    policy_version,
                    status,
                    approval_id,
                    now_ms,
                )
            }),
        }
    }

    pub fn invoke_parked_resolution(
        &self,
        resolution_action_id: &str,
        effect_id: &str,
        park_generation: u64,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::parked_work::ActionWorkContinuation, String> {
        match self {
            Self::Sqlite(db) => db.invoke_parked_resolution(
                resolution_action_id,
                effect_id,
                park_generation,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.invoke_parked_resolution(
                    resolution_action_id,
                    effect_id,
                    park_generation,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn mark_parked_resolution_accounted(
        &self,
        resolution_action_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.mark_parked_resolution_accounted(resolution_action_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.mark_parked_resolution_accounted(resolution_action_id)
            }),
        }
    }

    pub fn reserve_parked_resolution_execution(
        &self,
        resolution_action_id: &str,
        effect_id: &str,
        park_generation: u64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.reserve_parked_resolution_execution(
                resolution_action_id,
                effect_id,
                park_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reserve_parked_resolution_execution(
                    resolution_action_id,
                    effect_id,
                    park_generation,
                )
            }),
        }
    }

    pub fn authorize_parked_resolution_approval(
        &self,
        resolution_action_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.authorize_parked_resolution_approval(resolution_action_id, approval_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.authorize_parked_resolution_approval(resolution_action_id, approval_id)
            }),
        }
    }

    pub fn bind_parked_resolution_approval(
        &self,
        resolution_action_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.bind_parked_resolution_approval(resolution_action_id, approval_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.bind_parked_resolution_approval(resolution_action_id, approval_id)
            }),
        }
    }

    pub fn reject_parked_resolution(
        &self,
        approval_id: &str,
        status: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.reject_parked_resolution(approval_id, status, actor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reject_parked_resolution(approval_id, status, actor, now_ms)
            }),
        }
    }

    pub fn get_active_continuation(
        &self,
        effect: &crate::sekai::action_effect::ActionEffect,
    ) -> Result<
        Option<(
            crate::sekai::parked_work::ActionWorkContinuation,
            crate::sekai::parked_work::ActionWorkPark,
        )>,
        String,
    > {
        match self {
            Self::Sqlite(db) => db.get_active_continuation(effect),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_active_continuation(effect))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn report_action_claim_event(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        kind: &str,
        checkpoint_digest: &str,
        reason_code: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.report_action_claim_event(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                kind,
                checkpoint_digest,
                reason_code,
                request_id,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.report_action_claim_event(
                    effect_id,
                    runtime_id,
                    generation,
                    fencing_token,
                    kind,
                    checkpoint_digest,
                    reason_code,
                    request_id,
                    now_ms,
                )
            }),
        }
    }

    pub fn list_all_grants(&self) -> Result<Vec<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_grants(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_all_grants()),
        }
    }

    pub fn list_all_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_objects(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_all_objects(filter)),
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

    pub fn list_contention_scopes(&self) -> Result<Vec<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.list_contention_scopes(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_contention_scopes()),
        }
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        match self {
            Self::Sqlite(db) => db.list_datasets(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_datasets()),
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

    pub fn list_evolve_task_records(&self) -> Result<Vec<evolve::TaskRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_evolve_task_records(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_evolve_task_records())
            }
        }
    }

    pub fn list_functions(&self) -> Result<Vec<Function>, String> {
        match self {
            Self::Sqlite(db) => db.list_functions(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_functions()),
        }
    }

    pub fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.list_grants(object_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_grants(object_id)),
        }
    }

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String> {
        match self {
            Self::Sqlite(db) => db.list_interfaces(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_interfaces()),
        }
    }

    pub fn list_links_by_relation(&self, relation: &str) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.list_links_by_relation(relation),
            Self::Postgres(_) => Err(
                "list_links_by_relation is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_namespace_roles_for_principal(
        &self,
        principal: &str,
    ) -> Result<Vec<(String, Role)>, String> {
        match self {
            Self::Sqlite(db) => db.list_namespace_roles_for_principal(principal),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_namespace_roles_for_principal(principal)
            }),
        }
    }

    pub fn list_object_types_with_errors(
        &self,
    ) -> Result<(Vec<ObjectType>, HashMap<String, String>), String> {
        match self {
            Self::Sqlite(db) => db.list_object_types_with_errors(),
            // PostgreSQL rows are validated on write and a corrupt row fails
            // the read outright, so there are no per-row load errors to report.
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_object_types().map(|types| (types, HashMap::new()))
            }),
        }
    }

    pub fn list_objects_with_total_for_principals(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
    ) -> Result<(Vec<Object>, i32), String> {
        match self {
            Self::Sqlite(db) => {
                db.list_objects_with_total_for_principals(filter, principals, excluded_kinds)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_objects_with_total_for_principals(filter, principals, excluded_kinds)
            }),
        }
    }

    pub fn list_objects_with_total_for_policy_context(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
        context: &PrincipalPolicyContext,
    ) -> Result<(Vec<Object>, i32), String> {
        let mut queried = filter
            .property_filters
            .iter()
            .map(|property_filter| property_filter.key.clone())
            .collect::<Vec<_>>();
        if let Some(property) = filter.order_by.strip_prefix("property:")
            && !property.is_empty()
        {
            queried.push(property.to_string());
        }
        self.reject_ungranted_property_query(
            filter.namespace.as_deref(),
            filter.kind.as_deref(),
            queried.clone(),
        )?;
        if !filter
            .order_by
            .strip_prefix("property:")
            .unwrap_or("")
            .is_empty()
        {
            self.reject_value_instance_sort(filter.namespace.as_deref(), filter.kind.as_deref())?;
        }
        self.reject_value_instance_filter_ops(
            filter.namespace.as_deref(),
            filter.kind.as_deref(),
            &filter.property_filters,
        )?;
        let cells = filter
            .property_filters
            .iter()
            .map(|property_filter| (property_filter.key.clone(), property_filter.value.clone()))
            .collect::<Vec<_>>();
        self.reject_ungranted_value_instance_query(
            filter.namespace.as_deref(),
            filter.kind.as_deref(),
            cells
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )?;
        let cell_page = !cells.is_empty()
            && self.value_instance_grants_active(
                filter.namespace.as_deref(),
                filter.kind.as_deref(),
            )?;
        if !cell_page {
            let (rows, total) = match self {
                Self::Sqlite(db) => db.list_objects_with_total_for_policy_context(
                    filter,
                    principals,
                    excluded_kinds,
                    context,
                ),
                Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                    db.list_objects_with_total_for_policy_context(
                        filter,
                        principals,
                        excluded_kinds,
                        context,
                    )
                }),
            }?;
            return self
                .retain_granted_value_instance_matches(rows, &cells)
                .map(|rows| (rows, total));
        }
        // Paginate the authorized relation. Callers such as
        // `list_objects_with_marking` overwrite offset/limit to their scan
        // window (offset starts at 0) and apply the user page after marking
        // and purpose filters. `limit == i32::MAX` means the full authorized
        // set, matching storage `list_all_objects`.
        let offset = usize::try_from(filter.offset.max(0)).unwrap_or(0);
        let limit = if filter.limit == i32::MAX {
            usize::MAX
        } else if filter.limit <= 0 {
            crate::domain::DEFAULT_LIST_LIMIT as usize
        } else {
            filter.limit.min(crate::domain::MAX_LIST_LIMIT) as usize
        };
        let mut authorized = Vec::new();
        let mut total = 0usize;
        let mut storage_offset = 0i32;
        loop {
            let mut storage_filter = filter.clone();
            storage_filter.limit = crate::domain::MAX_LIST_LIMIT;
            storage_filter.offset = storage_offset;
            let (page, _) = match self {
                Self::Sqlite(db) => db.list_objects_with_total_for_policy_context(
                    &storage_filter,
                    principals,
                    excluded_kinds,
                    context,
                ),
                Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                    db.list_objects_with_total_for_policy_context(
                        &storage_filter,
                        principals,
                        excluded_kinds,
                        context,
                    )
                }),
            }?;
            let page_len = page.len();
            for object in self.retain_granted_value_instance_matches(page, &cells)? {
                if total >= offset && authorized.len() < limit {
                    authorized.push(object);
                }
                total = total.saturating_add(1);
            }
            if page_len < crate::domain::MAX_LIST_LIMIT as usize {
                break;
            }
            storage_offset = storage_offset.saturating_add(crate::domain::MAX_LIST_LIMIT);
            if storage_offset >= i32::MAX - crate::domain::MAX_LIST_LIMIT {
                break;
            }
        }
        Ok((authorized, i32::try_from(total).unwrap_or(i32::MAX)))
    }

    pub fn list_objects_with_text_visibility(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
        allowed_markings: &[&str],
        trusted: bool,
    ) -> Result<(Vec<Object>, i32), String> {
        match self {
            Self::Sqlite(db) => db.list_objects_with_text_visibility(
                filter,
                principals,
                excluded_kinds,
                allowed_markings,
                trusted,
            ),
            Self::Postgres(_) => Err(
                "authorization-built text visibility is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_objects_with_text_visibility_page(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
        allowed_markings: &[&str],
        trusted: bool,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_objects_with_text_visibility_page(
                filter,
                principals,
                excluded_kinds,
                allowed_markings,
                trusted,
            ),
            Self::Postgres(_) => Err(
                "authorization-built text visibility is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_ontology_classes(&self) -> Result<Vec<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_classes(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_ontology_classes()),
        }
    }

    pub fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_relations(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_ontology_relations()),
        }
    }

    pub fn list_readable_ontology_classes(
        &self,
        principals: &[String],
        deadline: Instant,
        limit: u32,
    ) -> Result<Vec<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.list_readable_ontology_classes(principals, deadline, limit),
            Self::Postgres(_) => Err(
                "list_readable_ontology_classes is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_readable_ontology_relations(
        &self,
        principals: &[String],
        deadline: Instant,
        limit: u32,
    ) -> Result<Vec<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.list_readable_ontology_relations(principals, deadline, limit),
            Self::Postgres(_) => Err("list_readable_ontology_relations is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_reservations(
        &self,
        filter: &ReservationFilter,
    ) -> Result<Vec<Reservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_reservations(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_reservations(filter)),
        }
    }

    pub fn list_run_events(
        &self,
        work_unit_id: &str,
        limit: i32,
        after: i64,
        event_types: &[String],
        page_token: Option<&str>,
    ) -> Result<Vec<RunEvent>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_run_events(work_unit_id, limit, after, event_types, page_token)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_run_events(work_unit_id, limit, after, event_types, page_token)
            }),
        }
    }

    pub fn list_unbound_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_unbound_credentials(principal, status),
            // Community storage has no tenant binding, so every credential
            // is unbound, the same as SQLite.
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_credentials(principal, status))
            }
        }
    }

    pub fn list_virtual_tables(&self) -> Result<Vec<VirtualTable>, String> {
        match self {
            Self::Sqlite(db) => db.list_virtual_tables(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_virtual_tables()),
        }
    }

    pub fn list_visible_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        match self {
            Self::Sqlite(db) => db.list_visible_object_changes(object_id, limit, offset),
            Self::Postgres(_) => Err(
                "list_visible_object_changes is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn namespace_object_generation(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.namespace_object_generation(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.namespace_object_generation(namespace))
            }
        }
    }

    pub fn object_change_watermark(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.object_change_watermark(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_change_watermark(namespace))
            }
        }
    }

    pub fn object_change_oldest_seq(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.object_change_oldest_seq(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_change_oldest_seq(namespace))
            }
        }
    }

    pub fn list_committed_object_mutations_after(
        &self,
        namespace: &str,
        after_seq: u64,
        limit: i32,
    ) -> Result<Vec<crate::sekai::object_change_subscription::CommittedObjectMutation>, String>
    {
        let rows = match self {
            Self::Sqlite(db) => {
                db.list_committed_object_mutations_after(namespace, after_seq, limit)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_committed_object_mutations_after(namespace, after_seq, limit)
            }),
        }?;
        Ok(rows
            .into_iter()
            .map(|(change, seq, object_kind, object_namespace)| {
                crate::sekai::object_change_subscription::CommittedObjectMutation {
                    change,
                    seq,
                    object_kind,
                    object_namespace,
                }
            })
            .collect())
    }

    pub fn list_work_units(&self, filter: &WorkUnitFilter) -> Result<Vec<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.list_work_units(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_work_units(filter)),
        }
    }

    pub fn load_ontology_registry(&self) -> Result<OntologyRegistry, String> {
        match self {
            Self::Sqlite(db) => db.load_ontology_registry(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                Ok(OntologyRegistry::from_parts(
                    db.list_ontology_classes()?,
                    db.list_ontology_relations()?,
                ))
            }),
        }
    }

    pub fn object_change_kind(&self, object_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.object_change_kind(object_id),
            Self::Postgres(_) => {
                Err("object_change_kind is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn object_change_namespace(&self, object_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.object_change_namespace(object_id),
            Self::Postgres(_) => Err(
                "object_change_namespace is unavailable on the PostgreSQL community runtime".into(),
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

    pub fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_eval_iterations_for_suite(suite_id, keep),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.prune_eval_iterations_for_suite(suite_id, keep)
            }),
        }
    }

    pub fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_eval_runs_for_suite(suite_id, keep),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.prune_eval_runs_for_suite(suite_id, keep))
            }
        }
    }

    pub fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String> {
        match self {
            Self::Sqlite(db) => db.put_delegated_permit(permit, issued_by),
            Self::Postgres(_) => Err(
                "put_delegated_permit is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn put_evolve_task(&self, task: &evolve::TaskRecord) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_evolve_task(task),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_evolve_task(task)),
        }
    }

    pub fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.get_gunshi_allocation_state(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_gunshi_allocation_state(namespace))
            }
        }
    }

    pub fn put_gunshi_allocation_state_cas(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
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

    pub fn put_operation_receipt_with_kioku_holdouts(
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

    pub fn put_permit(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        issued_by: &str,
    ) -> Result<Permit, String> {
        match self {
            Self::Sqlite(db) => db.put_permit(permit, idempotency_key, issued_by),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_permit(permit, idempotency_key, issued_by)
            }),
        }
    }

    pub fn query_rows(
        &self,
        dataset_id: &str,
        q: &RowQuery,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        match self {
            Self::Sqlite(db) => db.query_rows(dataset_id, q),
            Self::Postgres(_) => {
                Err("query_rows is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn list_dataset_versions(&self, dataset_id: &str) -> Result<Vec<DatasetVersion>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_versions(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_dataset_versions(dataset_id))
            }
        }
    }

    pub fn get_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<DatasetVersion, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset_version(dataset_id, version_id, as_of_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_dataset_version(dataset_id, version_id, as_of_ms)
            }),
        }
    }

    pub fn query_dataset_version_rows(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        Ok(self
            .load_dataset_version(dataset_id, version_id, as_of_ms)?
            .1)
    }

    pub fn load_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<(DatasetVersion, Vec<HashMap<String, String>>), String> {
        match self {
            Self::Sqlite(db) => db.load_dataset_version(dataset_id, version_id, as_of_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.load_dataset_version(dataset_id, version_id, as_of_ms)
            }),
        }
    }

    pub fn create_dataset_branch(
        &self,
        request: &crate::sekai::dataset_branch::CreateDatasetBranch,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranch, String> {
        match self {
            Self::Sqlite(db) => db.create_dataset_branch(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_dataset_branch(request))
            }
        }
    }

    pub fn list_dataset_branches(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<crate::sekai::dataset_branch::DatasetBranch>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_branches(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_dataset_branches(dataset_id))
            }
        }
    }

    pub fn dataset_branch_rows(
        &self,
        dataset_id: &str,
        name: &str,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        match self {
            Self::Sqlite(db) => db.dataset_branch_rows(dataset_id, name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.dataset_branch_rows(dataset_id, name))
            }
        }
    }

    pub fn write_dataset_branch_rows(
        &self,
        dataset_id: &str,
        name: &str,
        rows: &[HashMap<String, String>],
        replace: bool,
    ) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.write_dataset_branch_rows(dataset_id, name, rows, replace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.write_dataset_branch_rows(dataset_id, name, rows, replace)
            }),
        }
    }

    pub fn compare_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
        tenant: &str,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchDiff, String> {
        match self {
            Self::Sqlite(db) => db.compare_dataset_branch(dataset_id, name, tenant),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.compare_dataset_branch(dataset_id, name, tenant)
            }),
        }
    }

    pub fn delete_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
        tenant: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_dataset_branch(dataset_id, name, tenant),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_dataset_branch(dataset_id, name, tenant)
            }),
        }
    }

    pub fn propose_dataset_branch(
        &self,
        request: &crate::sekai::dataset_branch::ProposeDatasetBranch,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchProposal, String> {
        match self {
            Self::Sqlite(db) => db.propose_dataset_branch(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.propose_dataset_branch(request))
            }
        }
    }

    pub fn get_dataset_branch_proposal(
        &self,
        dataset_id: &str,
        id: &str,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchProposal, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset_branch_proposal(dataset_id, id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_dataset_branch_proposal(dataset_id, id))
            }
        }
    }

    pub fn merge_dataset_branch(
        &self,
        request: &crate::sekai::dataset_branch::MergeDatasetBranch,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchProposal, String> {
        match self {
            Self::Sqlite(db) => db.merge_dataset_branch(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.merge_dataset_branch(request))
            }
        }
    }

    pub fn run_governed_transform_on_branch(
        &self,
        namespace: &str,
        transform_id: &str,
        branch: &str,
        actor: &str,
        tenant: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchRun, String> {
        match self {
            Self::Sqlite(db) => db.run_governed_transform_on_branch(
                namespace,
                transform_id,
                branch,
                actor,
                tenant,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.run_governed_transform_on_branch(
                    namespace,
                    transform_id,
                    branch,
                    actor,
                    tenant,
                    now_ms,
                )
            }),
        }
    }

    pub fn rollback_dataset(&self, request: &DatasetRollback) -> Result<DatasetVersion, String> {
        match self {
            Self::Sqlite(db) => db.rollback_dataset(request),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.rollback_dataset(request)),
        }
    }

    pub fn dataset_version_retention(&self, dataset_id: &str) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.dataset_version_retention(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.dataset_version_retention(dataset_id))
            }
        }
    }

    pub fn set_dataset_version_retention(
        &self,
        dataset_id: &str,
        retain_count: i32,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_dataset_version_retention(dataset_id, retain_count),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_dataset_version_retention(dataset_id, retain_count)
            }),
        }
    }

    pub fn put_dataset_health_check(&self, check: &DatasetHealthCheck) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_dataset_health_check(check),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_dataset_health_check(check))
            }
        }
    }

    pub fn list_dataset_health_checks(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<DatasetHealthCheck>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_health_checks(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_dataset_health_checks(dataset_id))
            }
        }
    }

    pub fn list_dataset_health_results(
        &self,
        dataset_id: &str,
        version_id: &str,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_health_results(dataset_id, version_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_dataset_health_results(dataset_id, version_id)
            }),
        }
    }

    pub fn dataset_health_state(&self, dataset_id: &str) -> Result<DatasetHealthState, String> {
        match self {
            Self::Sqlite(db) => db.dataset_health_state(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.dataset_health_state(dataset_id))
            }
        }
    }

    pub fn list_dataset_alerts(&self, dataset_id: &str) -> Result<Vec<DatasetAlert>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_alerts(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_dataset_alerts(dataset_id))
            }
        }
    }

    pub fn run_dataset_health_checks(
        &self,
        dataset_id: &str,
        now_ms: i64,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        match self {
            Self::Sqlite(db) => db.run_dataset_health_checks(dataset_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.run_dataset_health_checks(dataset_id, now_ms)
            }),
        }
    }

    pub fn reconcile_missing_execution_evidence(
        &self,
        now_ms: i64,
    ) -> Result<Vec<ExecutionEvidenceAlert>, String> {
        match self {
            Self::Sqlite(db) => db.reconcile_missing_execution_evidence(now_ms),
            // Permit redemption fails closed on PostgreSQL, so no redeemed
            // action can be waiting for host evidence.
            Self::Postgres(_) => Ok(Vec::new()),
        }
    }

    pub fn reconcile_work_units(
        &self,
        now_ms: i64,
        filter: &ReconcileFilter,
    ) -> Result<ReconcileSummary, String> {
        match self {
            Self::Sqlite(db) => db.reconcile_work_units(now_ms, filter),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.reconcile_work_units(now_ms, filter))
            }
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
            Self::Postgres(_) => Err(
                "record_execution_evidence is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn refresh_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        match self {
            Self::Sqlite(db) => db.refresh_lease(
                namespace, key, token, ttl_ms, request_id, actor, site_id, now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.refresh_lease(
                    namespace, key, token, ttl_ms, request_id, actor, site_id, now_ms,
                )
            }),
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
            Self::Postgres(_) => Err(
                "reject_evidence_submission is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn release_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        match self {
            Self::Sqlite(db) => {
                db.release_lease(namespace, key, token, request_id, actor, site_id, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_lease(namespace, key, token, request_id, actor, site_id, now_ms)
            }),
        }
    }

    pub fn release_reservations_for_work_unit(
        &self,
        work_unit_id: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.release_reservations_for_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_reservations_for_work_unit(work_unit_id, now_ms)
            }),
        }
    }

    pub fn replay_permit(
        &self,
        authorization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Permit>, String> {
        match self {
            Self::Sqlite(db) => db.replay_permit(authorization_id, idempotency_key),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.replay_permit(authorization_id, idempotency_key)
            }),
        }
    }

    pub fn replay_redemption(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        execution_id: &str,
    ) -> Result<Option<Redemption>, String> {
        match self {
            Self::Sqlite(db) => db.replay_redemption(permit, idempotency_key, execution_id),
            Self::Postgres(_) => {
                Err("replay_redemption is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn reserve_gateway_request_alias(
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reserve_gateway_request_alias(
                    caller_scope,
                    request_alias,
                    request_id,
                    operation_id,
                )
            }),
        }
    }

    pub fn resolve_action_policy(
        &self,
        actor: &str,
        namespace: &str,
        project: &str,
    ) -> Result<Option<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.resolve_action_policy(actor, namespace, project),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.resolve_action_policy(actor, namespace, project)
            }),
        }
    }

    pub fn revoke_handoff(
        &self,
        id: &str,
        actor: &str,
        reason: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<HandoffManifest, String> {
        match self {
            Self::Sqlite(db) => db.revoke_handoff(id, actor, reason, request_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.revoke_handoff(id, actor, reason, request_id, now_ms)
            }),
        }
    }

    pub fn revoke_permit(
        &self,
        handle: &str,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.revoke_permit(handle, actor, reason, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.revoke_permit(handle, actor, reason, now_ms))
            }
        }
    }

    pub fn revoke_principal_credential(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.revoke_principal_credential(principal),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.revoke_principal_credential(principal))
            }
        }
    }

    pub fn rotate_managed_team_credential(
        &self,
        principal: &str,
        token_hash: &str,
    ) -> Result<PrincipalCredential, String> {
        match self {
            Self::Sqlite(db) => db.rotate_managed_team_credential(principal, token_hash),
            Self::Postgres(_) => Err(
                "rotate_managed_team_credential is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn rotate_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
    ) -> Result<PrincipalCredential, String> {
        match self {
            Self::Sqlite(db) => db.rotate_principal_credential(principal, token_hash),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.rotate_principal_credential(principal, token_hash)
            }),
        }
    }

    pub fn set_permit_kill_switch(
        &self,
        kind: &str,
        value: &str,
        enabled: bool,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.set_permit_kill_switch(kind, value, enabled, reason, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_permit_kill_switch(kind, value, enabled, reason, now_ms)
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

    pub fn takeover_expired_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at_ms: i64,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        match self {
            Self::Sqlite(db) => db.takeover_expired_lease(
                namespace,
                key,
                owner,
                expected_token,
                expected_expires_at_ms,
                ttl_ms,
                request_id,
                actor,
                site_id,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.takeover_expired_lease(
                    namespace,
                    key,
                    owner,
                    expected_token,
                    expected_expires_at_ms,
                    ttl_ms,
                    request_id,
                    actor,
                    site_id,
                    now_ms,
                )
            }),
        }
    }

    pub fn try_admit_work_unit(
        &self,
        work_unit_id: &str,
        lease_owner: &str,
        now_ms: i64,
    ) -> Result<AdmissionResult, String> {
        match self {
            Self::Sqlite(db) => db.try_admit_work_unit(work_unit_id, lease_owner, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.try_admit_work_unit(work_unit_id, lease_owner, now_ms)
            }),
        }
    }

    pub fn update_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_contention_scope(scope),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.update_contention_scope(scope))
            }
        }
    }

    pub fn update_dataset(&self, d: &Dataset) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_dataset(d),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.update_dataset(d)),
        }
    }

    pub fn update_object(&self, o: &Object) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_object(o),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.update_object(o)),
        }
    }

    pub fn update_object_with_audit(
        &self,
        object: &Object,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        self.update_object_with_authorized_snapshot(object, None, actor, None)
    }

    pub fn update_object_with_authorized_snapshot(
        &self,
        object: &Object,
        expected: Option<&Object>,
        actor: &str,
        expected_policy_generation: Option<&str>,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.update_object_with_authorized_snapshot(
                object,
                expected,
                actor,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                let Some(existing) = db.get_object(&object.id)? else {
                    return Ok(None);
                };
                if let Some(expected) = expected
                    && !existing.persisted_state_matches(expected)
                {
                    return Err(crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION.into());
                }
                db.update_object_with_audit_if_revision(
                    object,
                    actor,
                    existing.updated,
                    expected_policy_generation,
                    expected,
                )
            }),
        }
    }

    pub fn upsert_action_policy(&self, policy: &ActionPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_action_policy(policy),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_action_policy(policy))
            }
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

    pub fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_interface(interface),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_interface(interface))
            }
        }
    }

    pub fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_object_type(object_type),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_object_type(object_type))
            }
        }
    }

    pub fn upsert_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_class_with_audit(class, actor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.upsert_ontology_class_with_audit(class, actor)
            }),
        }
    }

    pub fn upsert_ontology_relation_with_audit(
        &self,
        relation: &OntologyRelation,
        actor: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_relation_with_audit(relation, actor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.upsert_ontology_relation_with_audit(relation, actor)
            }),
        }
    }

    pub fn upsert_projected_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
        source_grants: &[Grant],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_projected_ontology_class_with_audit(class, actor, source_grants),
            Self::Postgres(_) => Err("upsert_projected_ontology_class_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_delegation_chain(permit),
            Self::Postgres(_) => Err(
                "validate_delegation_chain is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn validate_execution_evidence_envelope(
        &self,
        envelope: &crate::sekai::evidence::EvidenceEnvelope,
        authenticated_producer: &str,
    ) -> Result<Option<ExecutionEvidence>, String> {
        match self {
            Self::Sqlite(db) => db.validate_execution_evidence_envelope(envelope, authenticated_producer),
            Self::Postgres(_) => Err("validate_execution_evidence_envelope is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_permit_for_delegation(permit),
            Self::Postgres(_) => Err(
                "validate_permit_for_delegation is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn validate_permit_state(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_permit_state(permit),
            Self::Postgres(_) => Err(
                "validate_permit_state is unavailable on the PostgreSQL community runtime".into(),
            ),
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
            Self::Postgres(_) => {
                Err("verify_ledger is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn update_operation_receipt<F>(
        &self,
        operation_id: &str,
        update: F,
    ) -> Result<OperationReceipt, String>
    where
        F: FnOnce(&mut OperationReceipt) -> Result<(), String>,
    {
        match self {
            Self::Sqlite(db) => db.update_operation_receipt(operation_id, update),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.update_operation_receipt(operation_id, update)
            }),
        }
    }

    /// SQLite-only raw connection access for legacy internals/tests.
    pub fn with_sqlite_conn<R>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> R,
    ) -> Result<R, String> {
        match self {
            Self::Sqlite(db) => {
                let conn = db.conn();
                Ok(f(&conn))
            }
            Self::Postgres(_) => Err("raw SQLite connection is unavailable on PostgreSQL".into()),
        }
    }

    pub fn get_decision(&self, id: &str) -> Result<Option<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.get_decision(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_decision(id)),
        }
    }

    pub fn put_peer_trust_root(
        &self,
        root: &crate::sekai::peer_import::PeerTrustRoot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_peer_trust_root(root),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_peer_trust_root(root)),
        }
    }

    pub fn list_peer_trust_roots(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::peer_import::PeerTrustRoot>, String> {
        match self {
            Self::Sqlite(db) => db.list_peer_trust_roots(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_peer_trust_roots(namespace))
            }
        }
    }

    pub fn put_peer_import(
        &self,
        record: &crate::sekai::peer_import::PeerImportRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_peer_import(record),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_peer_import(record)),
        }
    }

    pub fn get_peer_import(
        &self,
        import_id: &str,
    ) -> Result<Option<crate::sekai::peer_import::PeerImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_peer_import(import_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_peer_import(import_id))
            }
        }
    }

    pub fn put_federation_local_site(
        &self,
        site: &crate::sekai::federation_profile::LocalSiteIdentity,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_local_site(site),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_local_site(site))
            }
        }
    }

    pub fn get_federation_local_site(
        &self,
    ) -> Result<Option<crate::sekai::federation_profile::LocalSiteIdentity>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_local_site(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_local_site())
            }
        }
    }

    pub fn put_federation_peer(
        &self,
        peer: &crate::sekai::federation_profile::FederationPeer,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_peer(peer),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_federation_peer(peer)),
        }
    }

    pub fn get_federation_peer(
        &self,
        peer_site_id: &str,
    ) -> Result<Option<crate::sekai::federation_profile::FederationPeer>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_peer(peer_site_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_peer(peer_site_id))
            }
        }
    }

    pub fn list_federation_peers(
        &self,
    ) -> Result<Vec<crate::sekai::federation_profile::FederationPeer>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_peers(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_federation_peers()),
        }
    }

    pub fn put_federation_namespace_grant(
        &self,
        grant: &crate::sekai::namespace_snapshot::PeerNamespaceGrant,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_namespace_grant(grant),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_namespace_grant(grant))
            }
        }
    }

    pub fn get_federation_namespace_grant(
        &self,
        grant_id: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::PeerNamespaceGrant>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_namespace_grant(grant_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_namespace_grant(grant_id))
            }
        }
    }

    pub fn list_federation_namespace_grants(
        &self,
        namespace: Option<&str>,
        peer_site_id: Option<&str>,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::PeerNamespaceGrant>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_namespace_grants(namespace, peer_site_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_federation_namespace_grants(namespace, peer_site_id)
            }),
        }
    }

    pub fn reserve_federation_snapshot_sequence(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.reserve_federation_snapshot_sequence(namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reserve_federation_snapshot_sequence(namespace)
            }),
        }
    }

    pub fn put_federation_snapshot_export(
        &self,
        export: &crate::sekai::namespace_snapshot::SnapshotExportRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_snapshot_export(export),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_snapshot_export(export))
            }
        }
    }

    pub fn put_federation_snapshot_import(
        &self,
        record: &crate::sekai::namespace_snapshot::SnapshotImportRecord,
        facts: &[crate::sekai::namespace_snapshot::SnapshotFact],
        conflicts: &[crate::sekai::federation_conflict::FederationConflict],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_snapshot_import(record, facts, conflicts),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_federation_snapshot_import(record, facts, conflicts)
            }),
        }
    }

    pub fn get_federation_snapshot_import(
        &self,
        import_id: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_snapshot_import(import_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_snapshot_import(import_id))
            }
        }
    }

    pub fn latest_federation_snapshot_import(
        &self,
        peer_site_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.latest_federation_snapshot_import(peer_site_id, namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.latest_federation_snapshot_import(peer_site_id, namespace)
            }),
        }
    }

    pub fn list_federation_snapshot_imports(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_snapshot_imports(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_federation_snapshot_imports(namespace))
            }
        }
    }

    pub fn list_federation_snapshot_facts(
        &self,
        import_id: &str,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::SnapshotFact>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_snapshot_facts(import_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_federation_snapshot_facts(import_id))
            }
        }
    }

    pub fn put_federation_conflict(
        &self,
        record: &crate::sekai::federation_conflict::FederationConflict,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_conflict(record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_conflict(record))
            }
        }
    }

    pub fn get_federation_conflict(
        &self,
        conflict_id: &str,
    ) -> Result<Option<crate::sekai::federation_conflict::FederationConflict>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_conflict(conflict_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_conflict(conflict_id))
            }
        }
    }

    pub fn list_federation_conflicts(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::sekai::federation_conflict::FederationConflict>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_conflicts(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_federation_conflicts(namespace))
            }
        }
    }

    pub fn put_federation_revocation(
        &self,
        record: &crate::sekai::federation_revocation::FederationRevocation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_revocation(record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_revocation(record))
            }
        }
    }

    pub fn get_network_contract(
        &self,
        namespace: &str,
        contract_id: &str,
    ) -> Result<Option<crate::sekai::federation_network::NetworkContract>, String> {
        match self {
            Self::Sqlite(db) => db.get_network_contract(namespace, contract_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_network_contract(namespace, contract_id))
            }
        }
    }

    pub fn put_network_contract(
        &self,
        contract: &crate::sekai::federation_network::NetworkContract,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_network_contract(contract),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_network_contract(contract))
            }
        }
    }

    pub fn cas_network_contract(
        &self,
        expected: &crate::sekai::federation_network::NetworkContract,
        next: &crate::sekai::federation_network::NetworkContract,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_network_contract(expected, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.cas_network_contract(expected, next))
            }
        }
    }

    pub fn get_network_exchange(
        &self,
        namespace: &str,
        contract_id: &str,
        exchange_id: &str,
    ) -> Result<Option<crate::sekai::federation_network::NetworkExchange>, String> {
        match self {
            Self::Sqlite(db) => db.get_network_exchange(namespace, contract_id, exchange_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_network_exchange(namespace, contract_id, exchange_id)
            }),
        }
    }

    pub fn put_network_exchange(
        &self,
        item: &crate::sekai::federation_network::NetworkExchange,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_network_exchange(item),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_network_exchange(item))
            }
        }
    }

    pub fn get_workflow_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<crate::sekai::workflow_action::WorkflowActionBinding>, String> {
        match self {
            Self::Sqlite(db) => db.get_workflow_binding(namespace, binding_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_workflow_binding(namespace, binding_id))
            }
        }
    }

    pub fn get_workflow_callback(
        &self,
        namespace: &str,
        binding_id: &str,
        cursor: u64,
    ) -> Result<Option<crate::sekai::workflow_action::WorkflowCallback>, String> {
        match self {
            Self::Sqlite(db) => db.get_workflow_callback(namespace, binding_id, cursor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_workflow_callback(namespace, binding_id, cursor)
            }),
        }
    }

    pub fn get_workflow_command(
        &self,
        namespace: &str,
        binding_id: &str,
        command: &str,
        expected_cursor: u64,
    ) -> Result<Option<crate::sekai::workflow_action::WorkflowCommandRecord>, String> {
        match self {
            Self::Sqlite(db) => {
                db.get_workflow_command(namespace, binding_id, command, expected_cursor)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_workflow_command(namespace, binding_id, command, expected_cursor)
            }),
        }
    }

    pub fn commit_workflow_transition(
        &self,
        expected: Option<&crate::sekai::workflow_action::WorkflowActionBinding>,
        next: &crate::sekai::workflow_action::WorkflowActionBinding,
        callback: Option<&crate::sekai::workflow_action::WorkflowCallback>,
        command: &crate::sekai::workflow_action::WorkflowCommandRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_workflow_transition(expected, next, callback, command),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.commit_workflow_transition(expected, next, callback, command)
            }),
        }
    }

    pub fn get_connector_certification(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<crate::sekai::connector_certification::ConnectorCertification>, String> {
        match self {
            Self::Sqlite(db) => db.get_connector_certification(namespace, certification_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_connector_certification(namespace, certification_id)
            }),
        }
    }

    pub fn list_connector_certifications(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::connector_certification::ConnectorCertification>, String> {
        match self {
            Self::Sqlite(db) => db.list_connector_certifications(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_connector_certifications(namespace))
            }
        }
    }

    pub fn commit_connector_certifications(
        &self,
        certifications: &[&crate::sekai::connector_certification::ConnectorCertification],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_connector_certifications(certifications),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.commit_connector_certifications(certifications)
            }),
        }
    }

    pub fn cas_connector_certification(
        &self,
        expected: &crate::sekai::connector_certification::ConnectorCertification,
        next: &crate::sekai::connector_certification::ConnectorCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_connector_certification(expected, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.cas_connector_certification(expected, next))
            }
        }
    }

    pub fn get_warehouse_projection(
        &self,
        namespace: &str,
        projection_id: &str,
    ) -> Result<Option<crate::sekai::warehouse_projection::WarehouseProjection>, String> {
        match self {
            Self::Sqlite(db) => db.get_warehouse_projection(namespace, projection_id),
            Self::Postgres(_) => {
                Err(crate::sekai::warehouse_projection::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn put_warehouse_projection(
        &self,
        projection: &crate::sekai::warehouse_projection::WarehouseProjection,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_warehouse_projection(projection),
            Self::Postgres(_) => {
                Err(crate::sekai::warehouse_projection::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn commit_warehouse_export(
        &self,
        expected: &crate::sekai::warehouse_projection::WarehouseProjection,
        next: &crate::sekai::warehouse_projection::WarehouseProjection,
        page: Option<&crate::sekai::warehouse_projection::WarehousePage>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_warehouse_export(expected, next, page),
            Self::Postgres(_) => {
                Err(crate::sekai::warehouse_projection::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn get_lakehouse_snapshot(
        &self,
        namespace: &str,
        snapshot_id: &str,
    ) -> Result<Option<crate::sekai::lakehouse_snapshot::LakehouseSnapshot>, String> {
        match self {
            Self::Sqlite(db) => db.get_lakehouse_snapshot(namespace, snapshot_id),
            Self::Postgres(_) => Err(crate::sekai::lakehouse_snapshot::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_lakehouse_snapshot(
        &self,
        snapshot: &crate::sekai::lakehouse_snapshot::LakehouseSnapshot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_lakehouse_snapshot(snapshot),
            Self::Postgres(_) => Err(crate::sekai::lakehouse_snapshot::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn cas_lakehouse_snapshot(
        &self,
        expected: &crate::sekai::lakehouse_snapshot::LakehouseSnapshot,
        next: &crate::sekai::lakehouse_snapshot::LakehouseSnapshot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_lakehouse_snapshot(expected, next),
            Self::Postgres(_) => Err(crate::sekai::lakehouse_snapshot::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_model_platform_certification(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<crate::sekai::model_platform::ModelPlatformCertification>, String> {
        match self {
            Self::Sqlite(db) => db.get_model_platform_certification(namespace, certification_id),
            Self::Postgres(_) => Err(crate::sekai::model_platform::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_model_platform_certification(
        &self,
        certification: &crate::sekai::model_platform::ModelPlatformCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_model_platform_certification(certification),
            Self::Postgres(_) => Err(crate::sekai::model_platform::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn cas_model_platform_certification(
        &self,
        expected: &crate::sekai::model_platform::ModelPlatformCertification,
        next: &crate::sekai::model_platform::ModelPlatformCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_model_platform_certification(expected, next),
            Self::Postgres(_) => Err(crate::sekai::model_platform::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_autonomous_envelope(
        &self,
        namespace: &str,
        envelope_id: &str,
    ) -> Result<Option<crate::sekai::autonomous_envelope::AutonomousEnvelope>, String> {
        match self {
            Self::Sqlite(db) => db.get_autonomous_envelope(namespace, envelope_id),
            Self::Postgres(_) => {
                Err(crate::sekai::autonomous_envelope::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn put_autonomous_envelope(
        &self,
        envelope: &crate::sekai::autonomous_envelope::AutonomousEnvelope,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_autonomous_envelope(envelope),
            Self::Postgres(_) => {
                Err(crate::sekai::autonomous_envelope::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn cas_autonomous_envelope(
        &self,
        expected: &crate::sekai::autonomous_envelope::AutonomousEnvelope,
        next: &crate::sekai::autonomous_envelope::AutonomousEnvelope,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_autonomous_envelope(expected, next),
            Self::Postgres(_) => {
                Err(crate::sekai::autonomous_envelope::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn get_agent_autonomy(
        &self,
        namespace: &str,
        principal: &str,
        type_id: &str,
    ) -> Result<Option<crate::sekai::agent_autonomy::AgentAutonomyGrant>, String> {
        match self {
            Self::Sqlite(db) => db.get_agent_autonomy(namespace, principal, type_id),
            Self::Postgres(_) => Err(crate::sekai::agent_autonomy::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_agent_autonomy(
        &self,
        grant: &crate::sekai::agent_autonomy::AgentAutonomyGrant,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_agent_autonomy(grant),
            Self::Postgres(_) => Err(crate::sekai::agent_autonomy::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_agent_autonomy_with_receipt(
        &self,
        grant: &crate::sekai::agent_autonomy::AgentAutonomyGrant,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_agent_autonomy_with_receipt(grant, decision),
            Self::Postgres(_) => Err(crate::sekai::agent_autonomy::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_federation_revocation(
        &self,
        revocation_id: &str,
    ) -> Result<Option<crate::sekai::federation_revocation::FederationRevocation>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_revocation(revocation_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_revocation(revocation_id))
            }
        }
    }

    pub fn list_federation_revocations(
        &self,
        subject_kind: Option<&str>,
    ) -> Result<Vec<crate::sekai::federation_revocation::FederationRevocation>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_revocations(subject_kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_federation_revocations(subject_kind))
            }
        }
    }

    pub fn get_source_type_descriptor(
        &self,
        namespace: &str,
        digest: &str,
    ) -> Result<Option<crate::sekai::source_type_descriptor::StoredSourceTypeDescriptor>, String>
    {
        match self {
            Self::Sqlite(db) => db.get_source_type_descriptor(namespace, digest),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_source_type_descriptor(namespace, digest)
            }),
        }
    }

    pub fn put_source_type_descriptor(
        &self,
        descriptor: &crate::sekai::source_type_descriptor::StoredSourceTypeDescriptor,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_source_type_descriptor(descriptor),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_source_type_descriptor(descriptor))
            }
        }
    }

    pub fn cas_source_type_descriptor(
        &self,
        expected: &crate::sekai::source_type_descriptor::StoredSourceTypeDescriptor,
        next: &crate::sekai::source_type_descriptor::StoredSourceTypeDescriptor,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_source_type_descriptor(expected, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.cas_source_type_descriptor(expected, next))
            }
        }
    }

    pub fn put_source_webhook_key(
        &self,
        pin: &crate::sekai::source_webhook::SourceWebhookKeyPin,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_source_webhook_key(pin),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_source_webhook_key(pin))
            }
        }
    }

    pub fn get_source_webhook_key(
        &self,
        namespace: &str,
        source_instance: &str,
        key_id: &str,
    ) -> Result<Option<crate::sekai::source_webhook::SourceWebhookKeyPin>, String> {
        match self {
            Self::Sqlite(db) => db.get_source_webhook_key(namespace, source_instance, key_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_source_webhook_key(namespace, source_instance, key_id)
            }),
        }
    }

    pub fn list_source_webhook_keys(
        &self,
        namespace: Option<&str>,
        source_instance: Option<&str>,
    ) -> Result<Vec<crate::sekai::source_webhook::SourceWebhookKeyPin>, String> {
        match self {
            Self::Sqlite(db) => db.list_source_webhook_keys(namespace, source_instance),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_source_webhook_keys(namespace, source_instance)
            }),
        }
    }

    pub fn put_open_table_source(
        &self,
        source: &crate::sekai::open_table::OpenTableSource,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_open_table_source(source),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_open_table_source(source))
            }
        }
    }

    pub fn get_open_table_source(
        &self,
        source_id: &str,
    ) -> Result<Option<crate::sekai::open_table::OpenTableSource>, String> {
        match self {
            Self::Sqlite(db) => db.get_open_table_source(source_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_open_table_source(source_id))
            }
        }
    }

    pub fn put_open_table_snapshot(
        &self,
        snapshot: &crate::sekai::open_table::OpenTableSnapshot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_open_table_snapshot(snapshot),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_open_table_snapshot(snapshot))
            }
        }
    }

    pub fn get_open_table_snapshot(
        &self,
        source_id: &str,
    ) -> Result<Option<crate::sekai::open_table::OpenTableSnapshot>, String> {
        match self {
            Self::Sqlite(db) => db.get_open_table_snapshot(source_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_open_table_snapshot(source_id))
            }
        }
    }

    pub fn put_event_stream_binding(
        &self,
        binding: &crate::sekai::event_stream::EventStreamBinding,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_event_stream_binding(binding),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_event_stream_binding(binding))
            }
        }
    }

    pub fn get_event_stream_binding(
        &self,
        stream_id: &str,
    ) -> Result<Option<crate::sekai::event_stream::EventStreamBinding>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_stream_binding(stream_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_event_stream_binding(stream_id))
            }
        }
    }

    pub fn advance_event_stream_checkpoint(
        &self,
        next: &crate::sekai::event_stream::EventStreamCheckpoint,
        expected: &crate::sekai::event_stream::EventStreamCheckpoint,
        definition_digest: &str,
        admitted: Option<&[crate::sekai::event_stream::StreamEvent]>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.advance_event_stream_checkpoint(next, expected, definition_digest, admitted)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_event_stream_checkpoint(next, expected, definition_digest, admitted)
            }),
        }
    }

    pub fn ensure_event_stream_admitted_events(
        &self,
        batch: &crate::sekai::event_stream::EventStreamBatch,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.ensure_event_stream_admitted_events(batch),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.ensure_event_stream_admitted_events(batch))
            }
        }
    }

    pub fn verify_event_stream_admitted_events(
        &self,
        stream_id: &str,
        generation: u64,
        feed_epoch: &str,
        events: &[crate::sekai::event_stream::StreamEvent],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.verify_event_stream_admitted_events(stream_id, generation, feed_epoch, events)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.verify_event_stream_admitted_events(stream_id, generation, feed_epoch, events)
            }),
        }
    }

    pub fn get_event_stream_checkpoint(
        &self,
        stream_id: &str,
    ) -> Result<Option<crate::sekai::event_stream::EventStreamCheckpoint>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_stream_checkpoint(stream_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_event_stream_checkpoint(stream_id))
            }
        }
    }

    pub fn put_event_subscription(
        &self,
        subscription: &crate::sekai::event_subscription::EventSubscription,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_event_subscription(subscription),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_event_subscription(subscription))
            }
        }
    }

    pub fn get_event_subscription(
        &self,
        namespace: &str,
        subscription_id: &str,
    ) -> Result<Option<crate::sekai::event_subscription::EventSubscription>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_subscription(namespace, subscription_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_event_subscription(namespace, subscription_id)
            }),
        }
    }

    pub fn revoke_event_subscription_record(
        &self,
        namespace: &str,
        subscription_id: &str,
        owner: &str,
    ) -> Result<crate::sekai::event_subscription::EventSubscription, String> {
        match self {
            Self::Sqlite(db) => db.revoke_event_subscription(namespace, subscription_id, owner),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.revoke_event_subscription(namespace, subscription_id, owner)
            }),
        }
    }

    pub fn advance_event_subscription_cursor(
        &self,
        next: &crate::sekai::event_subscription::EventSubscription,
        expected: &crate::sekai::event_subscription::EventSubscription,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.advance_event_subscription_cursor(next, expected),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_event_subscription_cursor(next, expected)
            }),
        }
    }

    pub fn put_governed_document(
        &self,
        document: &crate::sekai::document::GovernedDocument,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_document(document),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_governed_document(document))
            }
        }
    }

    pub fn get_governed_document(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Option<crate::sekai::document::GovernedDocument>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_document(namespace, document_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_governed_document(namespace, document_id)
            }),
        }
    }

    pub fn put_governed_rendition(
        &self,
        rendition: &crate::sekai::document::DocumentRendition,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_rendition(rendition),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_governed_rendition(rendition))
            }
        }
    }

    pub fn list_governed_renditions(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Vec<crate::sekai::document::DocumentRendition>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_renditions(namespace, document_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_renditions(namespace, document_id)
            }),
        }
    }

    pub fn update_governed_document(
        &self,
        namespace: &str,
        document_id: &str,
        update: impl FnOnce(
            crate::sekai::document::GovernedDocument,
        ) -> Result<crate::sekai::document::GovernedDocument, String>,
    ) -> Result<crate::sekai::document::GovernedDocument, String> {
        match self {
            Self::Sqlite(db) => db.update_governed_document(namespace, document_id, update),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.update_governed_document(namespace, document_id, update)
            }),
        }
    }

    pub fn get_client_package(
        &self,
        namespace: &str,
        package_id: &str,
    ) -> Result<Option<crate::sekai::client_package::ClientPackage>, String> {
        match self {
            Self::Sqlite(db) => db.get_client_package(namespace, package_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_client_package(namespace, package_id))
            }
        }
    }

    pub fn list_client_packages(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::client_package::ClientPackage>, String> {
        match self {
            Self::Sqlite(db) => db.list_client_packages(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_client_packages(namespace))
            }
        }
    }

    pub fn commit_client_packages(
        &self,
        packages: &[&crate::sekai::client_package::ClientPackage],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_client_packages(packages),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.commit_client_packages(packages))
            }
        }
    }

    pub fn get_capability_package(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<crate::sekai::capability_package::CapabilityPackageCertification>, String>
    {
        match self {
            Self::Sqlite(db) => db.get_capability_package(namespace, certification_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_capability_package(namespace, certification_id)
            }),
        }
    }

    pub fn list_capability_packages(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::capability_package::CapabilityPackageCertification>, String> {
        match self {
            Self::Sqlite(db) => db.list_capability_packages(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_capability_packages(namespace))
            }
        }
    }

    pub fn commit_capability_packages(
        &self,
        packages: &[&crate::sekai::capability_package::CapabilityPackageCertification],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_capability_packages(packages),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.commit_capability_packages(packages))
            }
        }
    }

    pub fn cas_capability_package(
        &self,
        expected: &crate::sekai::capability_package::CapabilityPackageCertification,
        next: &crate::sekai::capability_package::CapabilityPackageCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_capability_package(expected, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.cas_capability_package(expected, next))
            }
        }
    }

    pub fn put_governed_image(
        &self,
        image: &crate::sekai::image::GovernedImage,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image(image),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_governed_image(image)),
        }
    }

    pub fn get_governed_image(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Option<crate::sekai::image::GovernedImage>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_image(namespace, image_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_governed_image(namespace, image_id))
            }
        }
    }

    pub fn put_governed_image_rendition(
        &self,
        rendition: &crate::sekai::image::ImageRendition,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image_rendition(rendition),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_governed_image_rendition(rendition))
            }
        }
    }

    pub fn list_governed_image_renditions(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Vec<crate::sekai::image::ImageRendition>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_image_renditions(namespace, image_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_image_renditions(namespace, image_id)
            }),
        }
    }

    pub fn tombstone_governed_image(
        &self,
        image: &crate::sekai::image::GovernedImage,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.tombstone_governed_image(image),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.tombstone_governed_image(image))
            }
        }
    }

    pub fn put_governed_image_annotation(
        &self,
        annotation: &crate::sekai::image::ImageAnnotation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image_annotation(annotation),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_governed_image_annotation(annotation))
            }
        }
    }

    pub fn list_governed_image_annotations(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Vec<crate::sekai::image::ImageAnnotation>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_image_annotations(namespace, image_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_image_annotations(namespace, image_id)
            }),
        }
    }

    pub fn get_links_limited(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        limit: usize,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links_limited(object_id, relation, dir, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_links_limited(object_id, relation, dir, limit)
            }),
        }
    }

    pub fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_type(kind),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_object_type(kind)),
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

    pub fn list_decisions_for_action_namespace(
        &self,
        action: &str,
        namespace: &str,
    ) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_decisions_for_action_namespace(action, namespace),
            Self::Postgres(_) => Err("list_decisions_for_action_namespace is unavailable on the PostgreSQL community runtime".into()),
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

    pub fn list_work_unit_decisions(
        &self,
        work_unit_id: &str,
        request_ids: &BTreeSet<String>,
    ) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_work_unit_decisions(work_unit_id, request_ids),
            Self::Postgres(_) => Err(
                "list_work_unit_decisions is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn principal_credentials_activity_epoch(&self) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.principal_credentials_activity_epoch(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.principal_credentials_activity_epoch())
            }
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

    pub fn record_object_changes(&self, changes: &[ObjectChange]) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_object_changes(changes),
            Self::Postgres(_) => Err(
                "record_object_changes is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_credentials(principal, status),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_credentials(principal, status))
            }
        }
    }

    pub fn create_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<PrincipalCredential, String> {
        match self {
            Self::Sqlite(db) => db.create_principal_credential(principal, token_hash, now),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_principal_credential(principal, token_hash, now)
            }),
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

    pub fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_retention_policy(policy),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.set_retention_policy(policy))
            }
        }
    }

    pub fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.list_retention_policies(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_retention_policies()),
        }
    }

    pub fn erase_subject(
        &self,
        request: &SubjectErasureRequest,
    ) -> Result<SubjectErasureResult, String> {
        match self {
            Self::Sqlite(db) => db.erase_subject(request),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.erase_subject(request)),
        }
    }

    pub fn archive_retained_records(
        &self,
        archive_path: impl AsRef<Path>,
        now: i64,
    ) -> Result<ArchiveRun, String> {
        match self {
            Self::Sqlite(db) => db.archive_retained_records(archive_path, now),
            Self::Postgres(_) => Err(
                "archive_retained_records is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn run_retention(&self, now: i64) -> Result<RetentionRun, String> {
        match self {
            Self::Sqlite(db) => db.run_retention(now),
            Self::Postgres(_) => {
                Err("run_retention is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn purge_old_records(&self, before: i64) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.purge_old_records(before),
            Self::Postgres(_) => {
                Err("purge_old_records is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn record_object_change(&self, c: &ObjectChange) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_object_change(c),
            Self::Postgres(_) => Err(
                "record_object_change is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        match self {
            Self::Sqlite(db) => db.list_object_changes(object_id, limit, offset),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_object_changes(object_id, limit, offset)
            }),
        }
    }

    pub fn record_kioku_holdout(
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

    pub fn redeem_permit(
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
            Self::Postgres(_) => {
                Err("redeem_permit is unavailable on the PostgreSQL community runtime".into())
            }
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

    pub fn upsert_ontology_class(&self, class: &OntologyClass) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_class(class),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_ontology_class(class))
            }
        }
    }

    pub fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_relation(relation),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_ontology_relation(relation))
            }
        }
    }

    pub fn update_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_work_unit(work_unit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.update_work_unit(work_unit))
            }
        }
    }

    pub fn lease_audit_count(&self, namespace: &str, key: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.lease_audit_count(namespace, key),
            Self::Postgres(_) => {
                Err("lease_audit_count is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_objects(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_objects(filter)),
        }
    }

    /// One unfiltered page without `excluded_kinds`; the kinds are internal constants.
    pub fn list_objects_excluding_kinds(
        &self,
        filter: &ListFilter,
        excluded_kinds: &[&str],
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_objects_excluding_kinds(filter, excluded_kinds),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_objects_excluding_kinds(filter, excluded_kinds)
            }),
        }
    }

    pub fn delete_object(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_object(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_object(id)),
        }
    }

    pub fn abort_unreceipted_object_create(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.abort_unreceipted_object_create(id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.abort_unreceipted_object_create(id))
            }
        }
    }

    pub fn migrate_all(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_all(),
            Self::Postgres(_) => {
                Err("migrate_all is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn migrate_schema_types(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_schema_types(),
            Self::Postgres(_) => Err(
                "migrate_schema_types is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn conn(&self) -> crate::db::sekai::SqliteConn {
        match self {
            Self::Sqlite(db) => db.conn(),
            Self::Postgres(_) => panic!("conn() is only available for the SQLite community store"),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn migrate_audit(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_audit(),
            Self::Postgres(_) => {
                Err("migrate_audit is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    /// Test helper used by gateway setup fixtures.
    #[cfg(feature = "gateway-test-support")]
    #[doc(hidden)]
    pub fn gateway_test_budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String> {
        match self {
            Self::Sqlite(db) => db.gateway_test_budget_usage(scope_id, metric, now_ms),
            Self::Postgres(_) => Err(
                "gateway_test_budget_usage is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }
}

#[cfg(test)]
mod evaluation_resolution_snapshot_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn persistent_sqlite_snapshot_excludes_concurrent_prerequisite_writes() {
        let path = std::env::temp_dir().join(format!(
            "sekai-evaluation-snapshot-{}.db",
            uuid::Uuid::new_v4().simple()
        ));
        let path_string = path.to_string_lossy().into_owned();
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path_string).unwrap()));
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

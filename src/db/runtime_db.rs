//! Dual-backend community store used by the public control plane.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use crate::db::postgres::PostgresDb;
use crate::db::sekai::{PrincipalCredential, SekaiDb};
use postgres::GenericClient;
use std::sync::Arc;

use crate::chisei::eval;
use crate::chisei::evaluation_execution::EvaluationExecutionIndex;
use crate::chisei::evolve;
use crate::chisei::external_action::{
    AuthorizationClaim, AuthorizationRecord, ExternalActionRequest,
};
use crate::chisei::external_permit::{
    ExternalPermitPolicy, HostContext, Permit, Redemption, RedemptionTiming,
};
use crate::chisei::governed_subject_provenance::ExportRecord;
use crate::chisei::kioku::*;
use crate::chisei::portfolio::{FrontierPoint, Objective, Observation, RouteSelection};
use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use crate::chisei::scoring::SampleObservation;
use crate::db::chisei_kioku::ChiseiKiokuBackend;
use crate::db::definition_branch::DefinitionBranchBackend;
use crate::db::object_sync::ObjectSyncBackend;
use crate::domain::{Direction, Link, ListFilter, Object};
use crate::sekai::action_policy::ActionPolicy;
use crate::sekai::attestation::{AttestationVerification, PolicyAttestation};
use crate::sekai::audit::{Decision, DecisionFilter, ObjectChange};
use crate::sekai::coordination::*;
use crate::sekai::dataset::{Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable};
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
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Instant;

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

impl RuntimeDb {
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
            Self::Postgres(db) => {
                db.put_object_security_policy(policy, actor, idempotency_key, now_ms)
            }
        }
    }

    pub fn get_object_security_policy(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRevision>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_security_policy(namespace, revision_digest),
            Self::Postgres(db) => db.get_object_security_policy(namespace, revision_digest),
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
            Self::Postgres(db) => db.activate_object_security_policies(
                namespace,
                policies,
                actor,
                idempotency_key,
                now_ms,
            ),
        }
    }

    pub fn get_object_security_activation(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityActivation>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_security_activation(namespace),
            Self::Postgres(db) => db.get_object_security_activation(namespace),
        }
    }

    pub fn has_object_security_activations(&self) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.has_object_security_activations(),
            Self::Postgres(db) => db.has_object_security_activations(),
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

    pub fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
        match self {
            Self::Sqlite(db) => db.object_query_cursor_key(),
            Self::Postgres(db) => db.object_query_cursor_key(),
        }
    }

    pub fn active_object_policy(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Option<ObjectSecurityPolicy>, String> {
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
            Self::Postgres(db) => db.list_activated_object_security_namespaces(),
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
            Self::Postgres(db) => DefinitionBranchBackend::get_definition_revision(
                db.as_ref(),
                namespace,
                revision_digest,
            ),
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
            Self::Postgres(db) => DefinitionBranchBackend::get_definition_members(
                db.as_ref(),
                namespace,
                revision_digest,
            ),
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
            Self::Postgres(db) => {
                DefinitionBranchBackend::get_definition_branch(db.as_ref(), namespace, branch_id)
            }
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
            Self::Postgres(db) => DefinitionBranchBackend::create_definition_branch(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
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
            Self::Postgres(db) => DefinitionBranchBackend::apply_definition_branch_edit(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
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
            Self::Postgres(db) => DefinitionBranchBackend::seed_published_definition_revision(
                db.as_ref(),
                revision,
                members,
            ),
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
            Self::Postgres(db) => {
                db.execute_definition_fact_migration(request, actor, policy_context, now_ms)
            }
        }
    }

    pub fn get_definition_fact_migration(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<Option<crate::sekai::definition_migration::FactMigrationResult>, String> {
        match self {
            Self::Sqlite(db) => db.get_definition_fact_migration(namespace, migration_id),
            Self::Postgres(db) => db.get_definition_fact_migration(namespace, migration_id),
        }
    }

    pub fn count_definition_fact_migration_audit(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.count_definition_fact_migration_audit(namespace, migration_id),
            Self::Postgres(db) => db.count_definition_fact_migration_audit(namespace, migration_id),
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
            Self::Postgres(db) => {
                DefinitionBranchBackend::get_published_definition_revision(db.as_ref(), namespace)
            }
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
            Self::Postgres(db) => DefinitionBranchBackend::get_definition_proposal(
                db.as_ref(),
                namespace,
                proposal_id,
            ),
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
            Self::Postgres(db) => DefinitionBranchBackend::create_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
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
            Self::Postgres(db) => DefinitionBranchBackend::approve_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
        }
    }

    pub fn merge_definition_proposal(
        &self,
        request: &MergeDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::merge_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => DefinitionBranchBackend::merge_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
        }
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
            Self::Postgres(db) => DefinitionBranchBackend::close_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
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
            Self::Postgres(db) => {
                db.put_governed_subject_provenance_export(actor, export_id, record)
            }
        }
    }

    pub fn get_governed_subject_provenance_export(
        &self,
        actor: &str,
        export_id: &str,
    ) -> Result<Option<ExportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_subject_provenance_export(actor, export_id),
            Self::Postgres(db) => db.get_governed_subject_provenance_export(actor, export_id),
        }
    }

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
                            crate::db::evaluation_manifest::put_evaluation_manifest_in_transaction(
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
            Self::Postgres(db) => {
                if db.max_connections() < 2 {
                    return Err(map_db_error(
                        "evaluation resolution requires at least two PostgreSQL connections".into(),
                    ));
                }
                let mut connection = db.connection().map_err(&map_db_error)?;
                let mut transaction = connection
                    .transaction()
                    .map_err(|error| map_db_error(error.to_string()))?;
                // These are every mutable community table consulted by live
                // resolution. SHARE blocks concurrent INSERT/UPDATE/DELETE
                // while allowing the existing read APIs to use pooled
                // connections. The manifest/request tables remain governed by
                // their advisory idempotency locks.
                transaction
                    .batch_execute(
                        "LOCK TABLE
                            sekai_objects,
                            sekai_links,
                            sekai_grants,
                            sekai_evidence_submissions,
                            chisei_evaluator_definitions,
                            chisei_evaluator_availability,
                            chisei_evaluation_plans
                         IN SHARE MODE",
                    )
                    .map_err(|error| map_db_error(error.to_string()))?;
                let (value, write) = operation()?;
                let stored = write
                    .map(|write| {
                        verify_evaluation_manifest(write.manifest.clone())
                            .map_err(&map_db_error)?;
                        let stored = crate::db::postgres_evaluation_manifest::put_evaluation_manifest_in_transaction(
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
            }
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
            Self::Postgres(db) => db.ping(),
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
            Self::Postgres(db) => db.apply_source_batch_with_policy_generation(
                batch,
                authenticated_producer,
                now_ms,
                expected_policy_generation,
                authorized_objects,
            ),
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
            Self::Postgres(db) => ObjectSyncBackend::get_source_sync_state(
                db.as_ref(),
                namespace,
                source_instance,
                type_digest,
            ),
        }
    }

    pub fn list_active_credentials(&self) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_active_credentials(),
            Self::Postgres(db) => db.list_active_credentials(),
        }
    }

    pub fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.get_principal_credential(token_hash),
            Self::Postgres(db) => db.get_principal_credential(token_hash),
        }
    }

    pub fn record_decision(&self, decision: &Decision) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decision(decision),
            Self::Postgres(db) => db.record_decision(decision),
        }
    }

    pub fn list_decisions(&self, filter: &DecisionFilter) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_decisions(filter),
            Self::Postgres(db) => db.list_decisions(filter),
        }
    }

    pub fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_object(id),
            Self::Postgres(db) => db.get_object(id),
        }
    }

    pub fn get_object_with_policy_context(
        &self,
        id: &str,
        context: &PrincipalPolicyContext,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_with_policy_context(id, context),
            Self::Postgres(db) => db.get_object_with_policy_context(id, context),
        }
    }

    pub fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_operation_receipt(receipt),
            Self::Postgres(db) => db.put_operation_receipt(receipt),
        }
    }

    pub fn get_operation_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.get_operation_receipt(operation_id),
            Self::Postgres(db) => db.get_operation_receipt(operation_id),
        }
    }

    pub fn get_evaluation_execution_index(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<EvaluationExecutionIndex>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluation_execution_index(manifest_digest),
            Self::Postgres(db) => db.get_evaluation_execution_index(manifest_digest),
        }
    }

    pub fn create_evaluation_execution(
        &self,
        index: &EvaluationExecutionIndex,
        receipt: &OperationReceipt,
    ) -> Result<EvaluationExecutionIndex, String> {
        match self {
            Self::Sqlite(db) => db.create_evaluation_execution(index, receipt),
            Self::Postgres(db) => db.create_evaluation_execution(index, receipt),
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
            Self::Postgres(db) => db.list_operation_receipts_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
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
            Self::Postgres(db) => db.count_active_kioku_promotions_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
            ),
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
            Self::Postgres(db) => db.list_kioku_lifecycle_events_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
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
            Self::Postgres(db) => db.list_kioku_outcomes_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
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
            Self::Postgres(db) => db.list_compliance_decisions_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
        }
    }

    pub fn abandon_external_action_claim(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.abandon_external_action_claim(request, request_digest),
            Self::Postgres(db) => db.abandon_external_action_claim(request, request_digest),
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
            Self::Postgres(db) => db.acquire_lease(
                namespace, key, owner, ttl_ms, request_id, actor, site_id, now_ms,
            ),
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
            Self::Postgres(db) => db.add_blast_radius(work_unit, mutations, deletes),
        }
    }

    pub fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String> {
        match self {
            Self::Sqlite(db) => db.append_operation_receipt_event(operation_id, event),
            Self::Postgres(db) => db.append_operation_receipt_event(operation_id, event),
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
            Self::Postgres(db) => db.append_run_event(event),
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
            Self::Postgres(db) => {
                db.authorize_operation_reporter(operation_id, principal, event_kinds)
            }
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
            Self::Postgres(db) => db.budget_adjust_chain(scope_id, metric, delta, now_ms),
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
            Self::Postgres(db) => {
                db.budget_check_and_reserve_chain(scope_id, metric, amount, now_ms)
            }
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
            Self::Postgres(db) => db.budget_check_and_reserve_chain_idempotent(
                scope_id,
                metric,
                amount,
                now_ms,
                idempotency_key,
            ),
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
            Self::Postgres(db) => db.budget_check_and_reserve_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                idempotency_key,
                require_home_pin,
                local_site_id,
                partition_simulated,
            ),
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
            Self::Postgres(db) => db.budget_check_chain(scope_id, metric, amount, now_ms),
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
            Self::Postgres(db) => db.budget_check_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                require_home_pin,
                local_site_id,
                partition_simulated,
            ),
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
            Self::Postgres(db) => db.budget_assert_home_writable(scope_id, metric, local_site_id),
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
            Self::Postgres(db) => db.budget_adjust_chain_for_site(
                scope_id,
                metric,
                delta,
                now_ms,
                require_home_pin,
                local_site_id,
            ),
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
            Self::Postgres(db) => db.budget_set_limit_scoped(
                scope_id,
                metric,
                max_amount,
                period_type,
                home_site_id,
                pool_id,
            ),
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
            Self::Postgres(db) => {
                db.budget_set_pool_ceiling(pool_id, metric, max_amount, period_type)
            }
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
            Self::Postgres(db) => db.budget_transfer_capacity(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                now_ms,
            ),
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
            Self::Postgres(db) => db.budget_record_transfer_refused(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                reason,
                now_ms,
            ),
        }
    }

    pub fn budget_get_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<Option<crate::db::chisei_budget::BudgetTransferRecord>, String> {
        match self {
            Self::Sqlite(db) => db.budget_get_transfer(transfer_id),
            Self::Postgres(db) => db.budget_get_transfer(transfer_id),
        }
    }

    pub fn budget_limits_for_scope(
        &self,
        scope_id: &str,
    ) -> Result<Vec<(String, String, i64, String)>, String> {
        match self {
            Self::Sqlite(db) => db.budget_limits_for_scope(scope_id),
            Self::Postgres(_) => Err(
                "budget_limits_for_scope is unavailable on the PostgreSQL community runtime".into(),
            ),
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
            Self::Postgres(db) => db.budget_namespace_pressure(namespace, metric, now_ms),
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
            Self::Postgres(db) => {
                db.budget_record_idempotent(scope_id, metric, amount, idempotency_key, now_ms)
            }
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
            Self::Postgres(db) => db.budget_set_limit(scope_id, metric, max_amount, period_type),
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
            Self::Postgres(db) => db.budget_usage(scope_id, metric, now_ms),
        }
    }

    pub fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.bump_observation_attempts(request_id),
            Self::Postgres(db) => db.bump_observation_attempts(request_id),
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
            Self::Postgres(db) => db.cancel_work_unit(work_unit_id, cancel_reason, now_ms),
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
            Self::Postgres(db) => db.claim_external_action_authorization(
                request,
                request_digest,
                authorization_id,
                now_ms,
            ),
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
            Self::Postgres(db) => db.claim_gateway_request_alias_dispatch(
                caller_scope,
                request_alias,
                request_id,
                operation_id,
                dispatch_token,
            ),
        }
    }

    pub fn compare_and_swap_external_action_authorization(
        &self,
        expected: &AuthorizationRecord,
        next: &AuthorizationRecord,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.compare_and_swap_external_action_authorization(expected, next),
            Self::Postgres(db) => db.compare_and_swap_external_action_authorization(expected, next),
        }
    }

    pub fn complete_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.complete_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => db.complete_work_unit(work_unit_id, now_ms),
        }
    }

    pub fn contention_scope_chain(&self, scope_id: &str) -> Result<Vec<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.contention_scope_chain(scope_id),
            Self::Postgres(db) => db.contention_scope_chain(scope_id),
        }
    }

    pub fn create_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_contention_scope(scope),
            Self::Postgres(db) => db.create_contention_scope(scope),
        }
    }

    pub fn create_dataset(&self, d: &Dataset) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_dataset(d),
            Self::Postgres(db) => db.create_dataset(d),
        }
    }

    pub fn create_function(&self, f: &Function) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_function(f),
            Self::Postgres(db) => db.create_function(f),
        }
    }

    pub fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_grant(grant),
            Self::Postgres(db) => db.create_grant(grant),
        }
    }

    pub fn create_handoff(
        &self,
        manifest: &HandoffManifest,
        request_id: &str,
    ) -> Result<HandoffManifest, String> {
        match self {
            Self::Sqlite(db) => db.create_handoff(manifest, request_id),
            Self::Postgres(db) => db.create_handoff(manifest, request_id),
        }
    }

    pub fn create_link(&self, l: &Link) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_link(l),
            Self::Postgres(db) => db.create_link(l),
        }
    }

    pub fn create_link_once(&self, l: &Link) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.create_link_once(l),
            Self::Postgres(db) => db.create_link_once(l),
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
            Self::Postgres(db) => db.create_link_with_authorized_endpoints(
                l,
                expected_from,
                expected_to,
                from_generation,
                to_generation,
                fail_if_exists,
            ),
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
            Self::Postgres(db) => db.create_object(o),
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
            Self::Postgres(db) => {
                db.create_object_with_authorized_policy(object, actor, expected_policy_generation)
            }
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
            Self::Postgres(db) => db.create_governed_object_with_audit(
                object,
                actor,
                history_identity_property,
                history_identity,
                predecessor_property,
                predecessor_id,
                max_objects,
            ),
        }
    }

    pub fn create_virtual_table(&self, vt: &VirtualTable) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_virtual_table(vt),
            Self::Postgres(db) => db.create_virtual_table(vt),
        }
    }

    pub fn create_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_work_unit(work_unit),
            Self::Postgres(db) => db.create_work_unit(work_unit),
        }
    }

    pub fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.delete_grant(id),
            Self::Postgres(db) => db.delete_grant(id),
        }
    }

    pub fn delete_interface(&self, name: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_interface(name),
            Self::Postgres(db) => db.delete_interface(name),
        }
    }

    pub fn delete_link(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_link(id),
            Self::Postgres(db) => db.delete_link(id),
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
            Self::Postgres(db) => db.delete_link_with_authorized_endpoints(
                id,
                expected_from,
                expected_to,
                from_generation,
                to_generation,
            ),
        }
    }

    pub fn delete_object_type(&self, kind: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_type(kind),
            Self::Postgres(db) => db.delete_object_type(kind),
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
            Self::Postgres(db) => db.delete_object_with_authorized_snapshot(
                id,
                expected,
                actor,
                expected_policy_generation,
            ),
        }
    }

    pub fn delete_observation(&self, request_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_observation(request_id),
            Self::Postgres(db) => db.delete_observation(request_id),
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
            Self::Postgres(db) => {
                db.disable_kioku_memory(id, version, actor, rationale, recorded_at_ms)
            }
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
            Self::Postgres(db) => {
                db.ensure_team_namespace(namespace, principal, member_role, actor)
            }
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

    pub fn evidence_lifecycle_history(
        &self,
        submission_id: &str,
    ) -> Result<Vec<EvidenceLifecycleState>, String> {
        match self {
            Self::Sqlite(db) => db.evidence_lifecycle_history(submission_id),
            Self::Postgres(db) => db.evidence_lifecycle_history(submission_id),
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
            Self::Postgres(db) => db.fail_work_unit(work_unit_id, failure_reason, now_ms),
        }
    }

    pub fn find_all_by_external_id(&self, external_id: &str) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_all_by_external_id(external_id),
            Self::Postgres(db) => db.find_all_by_external_id(external_id),
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
            Self::Postgres(db) => {
                db.find_all_by_external_id_with_policy_context(external_id, context)
            }
        }
    }

    pub fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_by_external_id(external_id),
            Self::Postgres(db) => db.find_by_external_id(external_id),
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
            Self::Postgres(db) => db.find_by_property(kind, key, value),
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
            Self::Postgres(db) => {
                db.find_by_property_with_policy_context(kind, key, value, context)
            }
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
            Self::Postgres(db) => {
                db.find_gateway_receipt_by_logical_operation_id(operation_id, attempt)
            }
        }
    }

    pub fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_namespace_boundary(namespace),
            Self::Postgres(db) => db.find_namespace_boundary(namespace),
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
            Self::Postgres(db) => db.find_operation_receipt_by_lookup_request_id(
                request_id,
                caller_scope,
                initiating_actor,
            ),
        }
    }

    pub fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.find_operation_receipt_by_request_id(request_id),
            Self::Postgres(db) => db.find_operation_receipt_by_request_id(request_id),
        }
    }

    pub fn get_action_policy(&self, scope: &str) -> Result<Option<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_policy(scope),
            Self::Postgres(db) => db.get_action_policy(scope),
        }
    }

    pub fn get_attestation(&self, id: &str) -> Result<Option<PolicyAttestation>, String> {
        match self {
            Self::Sqlite(db) => db.get_attestation(id),
            Self::Postgres(db) => db.get_attestation(id),
        }
    }

    pub fn get_blast_radius(&self, work_unit: &str) -> Result<(u32, u32), String> {
        match self {
            Self::Sqlite(db) => db.get_blast_radius(work_unit),
            Self::Postgres(db) => db.get_blast_radius(work_unit),
        }
    }

    pub fn get_contention_scope(&self, id: &str) -> Result<Option<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.get_contention_scope(id),
            Self::Postgres(db) => db.get_contention_scope(id),
        }
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset(id),
            Self::Postgres(db) => db.get_dataset(id),
        }
    }

    pub fn get_dedup_request(
        &self,
        request_id: &str,
        operation: &str,
    ) -> Result<Option<RequestDedup>, String> {
        match self {
            Self::Sqlite(db) => db.get_dedup_request(request_id, operation),
            Self::Postgres(db) => db.get_dedup_request(request_id, operation),
        }
    }

    pub fn get_evidence_projection_object_id(
        &self,
        submission_id: &str,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.get_evidence_projection_object_id(submission_id),
            Self::Postgres(db) => db.get_evidence_projection_object_id(submission_id),
        }
    }

    pub fn get_evidence_submission(
        &self,
        submission_id: &str,
    ) -> Result<Option<EvidenceSubmissionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_evidence_submission(submission_id),
            Self::Postgres(db) => db.get_evidence_submission(submission_id),
        }
    }

    pub fn get_external_action_authorization_by_id(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AuthorizationRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_external_action_authorization_by_id(authorization_id),
            Self::Postgres(db) => db.get_external_action_authorization_by_id(authorization_id),
        }
    }

    pub fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
        match self {
            Self::Sqlite(db) => db.get_external_permit_policy(scope),
            Self::Postgres(db) => db.get_external_permit_policy(scope),
        }
    }

    pub fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        match self {
            Self::Sqlite(db) => db.get_function(name),
            Self::Postgres(db) => db.get_function(name),
        }
    }

    pub fn get_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.get_grant(id),
            Self::Postgres(db) => db.get_grant(id),
        }
    }

    pub fn get_handoff(&self, id: &str) -> Result<Option<HandoffManifest>, String> {
        match self {
            Self::Sqlite(db) => db.get_handoff(id),
            Self::Postgres(db) => db.get_handoff(id),
        }
    }

    pub fn get_handoff_by_request(
        &self,
        creator_principal: &str,
        request_id: &str,
    ) -> Result<Option<(String, HandoffManifest)>, String> {
        match self {
            Self::Sqlite(db) => db.get_handoff_by_request(creator_principal, request_id),
            Self::Postgres(db) => db.get_handoff_by_request(creator_principal, request_id),
        }
    }

    pub fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.get_kioku_memory(id, version),
            Self::Postgres(db) => db.get_kioku_memory(id, version),
        }
    }

    pub fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>, LeaseError> {
        match self {
            Self::Sqlite(db) => db.get_lease(namespace, key),
            Self::Postgres(db) => db.get_lease(namespace, key),
        }
    }

    pub fn get_link(&self, id: &str) -> Result<Option<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_link(id),
            Self::Postgres(db) => db.get_link(id),
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
            Self::Postgres(db) => db.get_linked_objects(object_id, relation, dir),
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
            Self::Postgres(db) => {
                db.get_linked_objects_with_policy_context(object_id, relation, dir, context)
            }
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
            Self::Postgres(db) => db.get_links(object_id, relation, dir),
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
            Self::Postgres(db) => {
                db.get_links_with_policy_context(object_id, relation, dir, context)
            }
        }
    }

    pub fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_class(name),
            Self::Postgres(db) => db.get_ontology_class(name),
        }
    }

    pub fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_relation(name),
            Self::Postgres(db) => db.get_ontology_relation(name),
        }
    }

    pub fn get_work_unit(&self, id: &str) -> Result<Option<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.get_work_unit(id),
            Self::Postgres(db) => db.get_work_unit(id),
        }
    }

    pub fn get_work_unit_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.get_work_unit_by_idempotency_key(idempotency_key),
            Self::Postgres(db) => db.get_work_unit_by_idempotency_key(idempotency_key),
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
            Self::Postgres(db) => db.guarded_create_object_with_policy(
                object,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
                expected_policy_generation,
            ),
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
            Self::Postgres(db) => db.guarded_delete_object_with_policy(
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
            Self::Postgres(db) => db.guarded_object_replay(
                namespace,
                key,
                token,
                request_id,
                operation,
                target_id,
                request_object,
            ),
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
            Self::Postgres(db) => db.guarded_update_object_with_policy(
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
        }
    }

    pub fn handoff_is_superseded(&self, id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.handoff_is_superseded(id),
            Self::Postgres(db) => db.handoff_is_superseded(id),
        }
    }

    pub fn heartbeat_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.heartbeat_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => db.heartbeat_work_unit(work_unit_id, now_ms),
        }
    }

    pub fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_operation_receipt(receipt),
            Self::Postgres(db) => db.insert_operation_receipt(receipt),
        }
    }

    pub fn is_team_principal(&self, principal: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.is_team_principal(principal),
            Self::Postgres(db) => db.is_team_principal(principal),
        }
    }

    pub fn kioku_authorized_classification_ceiling(
        &self,
        namespace: &str,
        actor: &str,
    ) -> Result<EvidenceClassification, String> {
        match self {
            Self::Sqlite(db) => db.kioku_authorized_classification_ceiling(namespace, actor),
            Self::Postgres(db) => db.kioku_authorized_classification_ceiling(namespace, actor),
        }
    }

    pub fn reassess_kioku_memory(
        &self,
        request: KiokuEvidenceReassessmentRequest,
    ) -> Result<KiokuEvidenceReassessmentResult, String> {
        match self {
            Self::Sqlite(db) => db.reassess_kioku_memory(request),
            Self::Postgres(db) => db.reassess_kioku_memory(request),
        }
    }

    pub fn authorize_kioku_evidence(
        &self,
        request: &KiokuEvidenceAuthorizationRequest,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.authorize_kioku_evidence(request),
            Self::Postgres(db) => db.authorize_kioku_evidence(request),
        }
    }

    pub fn list_action_policies(&self) -> Result<Vec<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_policies(),
            Self::Postgres(db) => db.list_action_policies(),
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
            Self::Postgres(db) => db.put_evaluator_definition(definition, actor, now_ms),
        }
    }

    pub fn get_evaluator_definition(
        &self,
        definition_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluatorDefinition>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluator_definition(definition_id),
            Self::Postgres(db) => db.get_evaluator_definition(definition_id),
        }
    }

    pub fn list_evaluator_definitions(
        &self,
        namespace: &str,
        evaluator_id: Option<&str>,
    ) -> Result<Vec<crate::chisei::evaluation_plan::EvaluatorDefinition>, String> {
        match self {
            Self::Sqlite(db) => db.list_evaluator_definitions(namespace, evaluator_id),
            Self::Postgres(db) => db.list_evaluator_definitions(namespace, evaluator_id),
        }
    }

    pub fn get_evaluator_availability(
        &self,
        definition_id: &str,
    ) -> Result<Option<crate::chisei::evaluation_plan::EvaluatorAvailability>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluator_availability(definition_id),
            Self::Postgres(db) => db.get_evaluator_availability(definition_id),
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
            Self::Postgres(db) => db.set_evaluator_availability(
                definition_id,
                state,
                superseded_by_definition_id,
                reason,
                request_id,
                actor,
                now_ms,
            ),
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
            Self::Postgres(db) => db.put_evaluation_plan(plan, actor, now_ms),
        }
    }

    pub fn get_evaluation_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<crate::chisei::evaluation_manifest::ResolvedEvaluationManifest>, String>
    {
        let manifest = match self {
            Self::Sqlite(db) => db.get_evaluation_manifest(manifest_digest),
            Self::Postgres(db) => db.get_evaluation_manifest(manifest_digest),
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
            Self::Postgres(db) => {
                db.get_evaluation_manifest_for_request(namespace, actor, request_id)
            }
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
            Self::Postgres(db) => db.put_evaluation_manifest(manifest, request_id, request_digest),
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
            Self::Postgres(db) => db.get_evaluation_plan(plan_version_id),
        }
    }

    pub fn list_evaluation_plans(
        &self,
        namespace: &str,
        plan_id: Option<&str>,
    ) -> Result<Vec<crate::chisei::evaluation_plan::EvaluationPlan>, String> {
        match self {
            Self::Sqlite(db) => db.list_evaluation_plans(namespace, plan_id),
            Self::Postgres(db) => db.list_evaluation_plans(namespace, plan_id),
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
            Self::Postgres(db) => db.put_governed_action_type(type_def, actor, now_ms),
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
            Self::Postgres(db) => db.get_governed_action_type(namespace, type_id, version),
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
            Self::Postgres(db) => db.list_governed_action_types(namespace, type_id, enabled_only),
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
            Self::Postgres(db) => {
                db.set_governed_action_type_enabled(namespace, type_id, version, enabled, now_ms)
            }
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
            Self::Postgres(db) => {
                db.require_enabled_governed_action_type(namespace, type_id, version)
            }
        }
    }

    pub fn put_action_instance(
        &self,
        instance: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<crate::sekai::action_instance::ActionInstance, String> {
        match self {
            Self::Sqlite(db) => db.put_action_instance(instance),
            Self::Postgres(db) => db.put_action_instance(instance),
        }
    }

    pub fn delete_action_instance(&self, instance_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_action_instance(instance_id),
            Self::Postgres(db) => db.delete_action_instance(instance_id),
        }
    }

    pub fn get_action_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance(instance_id),
            Self::Postgres(db) => db.get_action_instance(instance_id),
        }
    }

    pub fn get_action_instance_by_operation_id(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance_by_operation_id(operation_id),
            Self::Postgres(db) => db.get_action_instance_by_operation_id(operation_id),
        }
    }

    pub fn get_action_instance_by_idempotency(
        &self,
        namespace: &str,
        idempotency_key: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance_by_idempotency(namespace, idempotency_key),
            Self::Postgres(db) => db.get_action_instance_by_idempotency(namespace, idempotency_key),
        }
    }

    pub fn list_action_instances(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_instances(namespace, type_id, status, limit),
            Self::Postgres(db) => db.list_action_instances(namespace, type_id, status, limit),
        }
    }

    pub fn put_action_effects(
        &self,
        effects: &[crate::sekai::action_effect::ActionEffect],
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.put_action_effects(effects),
            Self::Postgres(db) => db.put_action_effects(effects),
        }
    }

    pub fn get_action_effect(
        &self,
        effect_id: &str,
    ) -> Result<Option<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_effect(effect_id),
            Self::Postgres(db) => db.get_action_effect(effect_id),
        }
    }

    pub fn list_action_effects_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_effects_for_instance(instance_id),
            Self::Postgres(db) => db.list_action_effects_for_instance(instance_id),
        }
    }

    pub fn list_pending_runtime_dispatch_effects(
        &self,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.list_pending_runtime_dispatch_effects(namespace, limit),
            Self::Postgres(db) => db.list_pending_runtime_dispatch_effects(namespace, limit),
        }
    }

    pub fn list_claimable_action_work(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.list_claimable_action_work(namespace, runtime_id, now_ms, limit),
            Self::Postgres(db) => {
                db.list_claimable_action_work(namespace, runtime_id, now_ms, limit)
            }
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
            Self::Postgres(db) => {
                db.claim_action_work(effect_id, runtime_id, request_id, ttl_ms, now_ms)
            }
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
            Self::Postgres(db) => db.heartbeat_action_claim(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                ttl_ms,
                now_ms,
            ),
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
            Self::Postgres(db) => db.ack_action_work(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                outcome,
                reason,
                now_ms,
            ),
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
            Self::Postgres(db) => db.park_action_work(
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
            Self::Postgres(db) => db.submit_parked_resolution(
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
            Self::Postgres(db) => db.invoke_parked_resolution(
                resolution_action_id,
                effect_id,
                park_generation,
                actor,
                now_ms,
            ),
        }
    }

    pub fn mark_parked_resolution_accounted(
        &self,
        resolution_action_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.mark_parked_resolution_accounted(resolution_action_id),
            Self::Postgres(db) => db.mark_parked_resolution_accounted(resolution_action_id),
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
            Self::Postgres(db) => db.reserve_parked_resolution_execution(
                resolution_action_id,
                effect_id,
                park_generation,
            ),
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
            Self::Postgres(db) => {
                db.authorize_parked_resolution_approval(resolution_action_id, approval_id)
            }
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
            Self::Postgres(db) => {
                db.bind_parked_resolution_approval(resolution_action_id, approval_id)
            }
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
            Self::Postgres(db) => db.reject_parked_resolution(approval_id, status, actor, now_ms),
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
            Self::Postgres(db) => db.get_active_continuation(effect),
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
            Self::Postgres(db) => db.report_action_claim_event(
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
        }
    }

    pub fn list_all_grants(&self) -> Result<Vec<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_grants(),
            Self::Postgres(db) => db.list_all_grants(),
        }
    }

    pub fn list_all_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_objects(filter),
            Self::Postgres(_) => {
                Err("list_all_objects is unavailable on the PostgreSQL community runtime".into())
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
            Self::Postgres(db) => db.list_attestations(decision_id, policy_scope, limit, offset),
        }
    }

    pub fn list_contention_scopes(&self) -> Result<Vec<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.list_contention_scopes(),
            Self::Postgres(db) => db.list_contention_scopes(),
        }
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        match self {
            Self::Sqlite(db) => db.list_datasets(),
            Self::Postgres(db) => db.list_datasets(),
        }
    }

    pub fn list_evidence_submissions(
        &self,
        filter: &EvidenceSubmissionFilter,
    ) -> Result<Vec<EvidenceSubmissionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_evidence_submissions(filter),
            Self::Postgres(db) => db.list_evidence_submissions(filter),
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
            Self::Postgres(db) => db.list_evolve_task_records(),
        }
    }

    pub fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_external_action_authorizations(),
            Self::Postgres(db) => db.list_external_action_authorizations(),
        }
    }

    pub fn list_functions(&self) -> Result<Vec<Function>, String> {
        match self {
            Self::Sqlite(db) => db.list_functions(),
            Self::Postgres(db) => db.list_functions(),
        }
    }

    pub fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.list_grants(object_id),
            Self::Postgres(db) => db.list_grants(object_id),
        }
    }

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String> {
        match self {
            Self::Sqlite(db) => db.list_interfaces(),
            Self::Postgres(db) => db.list_interfaces(),
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
            Self::Postgres(db) => db.list_kioku_candidates(namespace, operation_class, limit),
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
            Self::Postgres(db) => db.list_kioku_candidate_page(namespace, limit, cursor),
        }
    }

    pub fn list_kioku_evidence(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<KiokuEvidenceLink>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_evidence(id, version),
            Self::Postgres(db) => db.list_kioku_evidence(id, version),
        }
    }

    pub fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_lifecycle_events(id, version),
            Self::Postgres(db) => db.list_kioku_lifecycle_events(id, version),
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
            Self::Postgres(_) => Err("list_namespace_roles_for_principal is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_object_types_with_errors(
        &self,
    ) -> Result<(Vec<ObjectType>, HashMap<String, String>), String> {
        match self {
            Self::Sqlite(db) => db.list_object_types_with_errors(),
            Self::Postgres(_) => Err(
                "list_object_types_with_errors is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
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
            Self::Postgres(db) => {
                let _ = excluded_kinds;
                db.list_objects_with_total_for_principals(filter, principals)
            }
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
                Self::Postgres(db) => db.list_objects_with_total_for_policy_context(
                    filter,
                    principals,
                    excluded_kinds,
                    context,
                ),
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
                Self::Postgres(db) => db.list_objects_with_total_for_policy_context(
                    &storage_filter,
                    principals,
                    excluded_kinds,
                    context,
                ),
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
            Self::Postgres(db) => db.list_ontology_classes(),
        }
    }

    pub fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_relations(),
            Self::Postgres(db) => db.list_ontology_relations(),
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
            Self::Postgres(db) => db.list_reservations(filter),
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
            Self::Postgres(db) => {
                db.list_run_events(work_unit_id, limit, after, event_types, page_token)
            }
        }
    }

    pub fn list_unbound_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_unbound_credentials(principal, status),
            Self::Postgres(_) => Err(
                "list_unbound_credentials is unavailable on the PostgreSQL community runtime"
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
            Self::Postgres(db) => db.list_unscored_observations(limit),
        }
    }

    pub fn list_virtual_tables(&self) -> Result<Vec<VirtualTable>, String> {
        match self {
            Self::Sqlite(db) => db.list_virtual_tables(),
            Self::Postgres(db) => db.list_virtual_tables(),
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

    pub fn list_work_units(&self, filter: &WorkUnitFilter) -> Result<Vec<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.list_work_units(filter),
            Self::Postgres(db) => db.list_work_units(filter),
        }
    }

    pub fn load_ontology_registry(&self) -> Result<OntologyRegistry, String> {
        match self {
            Self::Sqlite(db) => db.load_ontology_registry(),
            Self::Postgres(_) => Err(
                "load_ontology_registry is unavailable on the PostgreSQL community runtime".into(),
            ),
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
            Self::Postgres(db) => db.project_evidence_submission(submission_id, now_ms),
        }
    }

    pub fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_eval_iterations_for_suite(suite_id, keep),
            Self::Postgres(db) => db.prune_eval_iterations_for_suite(suite_id, keep),
        }
    }

    pub fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_eval_runs_for_suite(suite_id, keep),
            Self::Postgres(db) => db.prune_eval_runs_for_suite(suite_id, keep),
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
            Self::Postgres(db) => db.put_evolve_task(task),
        }
    }

    pub fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.get_gunshi_allocation_state(namespace),
            Self::Postgres(_) => Err(
                "get_gunshi_allocation_state is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
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
            Self::Postgres(_) => Err(
                "put_gunshi_allocation_state_cas is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_external_action_authorization(
        &self,
        record: &AuthorizationRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_external_action_authorization(record),
            Self::Postgres(db) => db.put_external_action_authorization(record),
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
            Self::Postgres(db) => db.put_permit(permit, idempotency_key, issued_by),
        }
    }

    pub fn put_sample_observation(
        &self,
        obs: &crate::chisei::scoring::SampleObservation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_sample_observation(obs),
            Self::Postgres(db) => db.put_sample_observation(obs),
        }
    }

    pub fn get_sample_observation(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.get_sample_observation(request_id),
            Self::Postgres(db) => db.get_sample_observation(request_id),
        }
    }

    pub fn get_sample_observation_in_namespace(
        &self,
        request_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.get_sample_observation_in_namespace(request_id, namespace),
            Self::Postgres(db) => db.get_sample_observation_in_namespace(request_id, namespace),
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

    pub fn reconcile_missing_execution_evidence(
        &self,
        now_ms: i64,
    ) -> Result<Vec<ExecutionEvidenceAlert>, String> {
        match self {
            Self::Sqlite(db) => db.reconcile_missing_execution_evidence(now_ms),
            Self::Postgres(_) => Err("reconcile_missing_execution_evidence is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn reconcile_work_units(
        &self,
        now_ms: i64,
        filter: &ReconcileFilter,
    ) -> Result<ReconcileSummary, String> {
        match self {
            Self::Sqlite(db) => db.reconcile_work_units(now_ms, filter),
            Self::Postgres(db) => db.reconcile_work_units(now_ms, filter),
        }
    }

    pub fn record_decision_with_attestation(
        &self,
        decision: &crate::sekai::audit::Decision,
        attestation: Option<&PolicyAttestation>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decision_with_attestation(decision, attestation),
            Self::Postgres(db) => db.record_decision_with_attestation(decision, attestation),
        }
    }

    pub fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decisions_idempotently(decisions),
            Self::Postgres(db) => db.record_decisions_idempotently(decisions),
        }
    }

    pub fn record_dedup_request(&self, request: &RequestDedup) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_dedup_request(request),
            Self::Postgres(db) => db.record_dedup_request(request),
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

    pub fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_lifecycle_event(event),
            Self::Postgres(db) => db.record_kioku_lifecycle_event(event),
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
            Self::Postgres(db) => db.refresh_lease(
                namespace, key, token, ttl_ms, request_id, actor, site_id, now_ms,
            ),
        }
    }

    pub fn is_evidence_schema_registered(
        &self,
        schema_id: &str,
        schema_version: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.is_evidence_schema_registered(schema_id, schema_version),
            Self::Postgres(db) => db.is_evidence_schema_registered(schema_id, schema_version),
        }
    }

    pub fn register_evidence_schema(
        &self,
        definition: &EvidenceSchemaDefinition,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.register_evidence_schema(definition, now_ms),
            Self::Postgres(db) => db.register_evidence_schema(definition, now_ms),
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

    pub fn release_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_external_action_blast_radius(authorization_id, request),
            Self::Postgres(db) => {
                db.release_external_action_blast_radius(authorization_id, request)
            }
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
            Self::Postgres(db) => {
                db.release_lease(namespace, key, token, request_id, actor, site_id, now_ms)
            }
        }
    }

    pub fn release_reservations_for_work_unit(
        &self,
        work_unit_id: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.release_reservations_for_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => db.release_reservations_for_work_unit(work_unit_id, now_ms),
        }
    }

    pub fn replay_permit(
        &self,
        authorization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Permit>, String> {
        match self {
            Self::Sqlite(db) => db.replay_permit(authorization_id, idempotency_key),
            Self::Postgres(db) => db.replay_permit(authorization_id, idempotency_key),
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
            Self::Postgres(db) => db.reserve_external_action_blast_radius(
                authorization_id,
                request,
                max_mutations,
                max_deletes,
            ),
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
            Self::Postgres(db) => db.reserve_gateway_request_alias(
                caller_scope,
                request_alias,
                request_id,
                operation_id,
            ),
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
            Self::Postgres(db) => db.resolve_action_policy(actor, namespace, project),
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
            Self::Postgres(db) => db.review_kioku_candidate(id, version, review),
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
            Self::Postgres(db) => db.revoke_handoff(id, actor, reason, request_id, now_ms),
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
            Self::Postgres(db) => db.revoke_permit(handle, actor, reason, now_ms),
        }
    }

    pub fn revoke_principal_credential(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.revoke_principal_credential(principal),
            Self::Postgres(db) => db.revoke_principal_credential(principal),
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
            Self::Postgres(db) => db.rotate_principal_credential(principal, token_hash),
        }
    }

    pub fn set_external_permit_policy(
        &self,
        policy: &ExternalPermitPolicy,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_external_permit_policy(policy, now_ms),
            Self::Postgres(db) => db.set_external_permit_policy(policy, now_ms),
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
            Self::Postgres(db) => db.set_permit_kill_switch(kind, value, enabled, reason, now_ms),
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
            Self::Postgres(db) => db.submit_evidence(envelope, authenticated_producer, now_ms),
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
            Self::Postgres(db) => db.takeover_expired_lease(
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
            Self::Postgres(db) => db.try_admit_work_unit(work_unit_id, lease_owner, now_ms),
        }
    }

    pub fn update_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_contention_scope(scope),
            Self::Postgres(db) => db.update_contention_scope(scope),
        }
    }

    pub fn update_dataset(&self, d: &Dataset) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_dataset(d),
            Self::Postgres(db) => db.update_dataset(d),
        }
    }

    pub fn update_object(&self, o: &Object) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_object(o),
            Self::Postgres(db) => db.update_object(o),
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
            Self::Postgres(db) => {
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
            }
        }
    }

    pub fn upsert_action_policy(&self, policy: &ActionPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_action_policy(policy),
            Self::Postgres(db) => db.upsert_action_policy(policy),
        }
    }

    pub fn upsert_evidence_producer(
        &self,
        capability: &EvidenceProducerCapability,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_evidence_producer(capability, now_ms),
            Self::Postgres(db) => db.upsert_evidence_producer(capability, now_ms),
        }
    }

    pub fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_interface(interface),
            Self::Postgres(db) => db.upsert_interface(interface),
        }
    }

    pub fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_object_type(object_type),
            Self::Postgres(db) => db.upsert_object_type(object_type),
        }
    }

    pub fn upsert_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_class_with_audit(class, actor),
            Self::Postgres(_) => Err("upsert_ontology_class_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn upsert_ontology_relation_with_audit(
        &self,
        relation: &OntologyRelation,
        actor: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_relation_with_audit(relation, actor),
            Self::Postgres(_) => Err("upsert_ontology_relation_with_audit is unavailable on the PostgreSQL community runtime".into()),
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

    pub fn validate_kioku_candidate(
        &self,
        id: &str,
        version: u32,
    ) -> Result<MemoryValidation, String> {
        match self {
            Self::Sqlite(db) => db.validate_kioku_candidate(id, version),
            Self::Postgres(db) => db.validate_kioku_candidate(id, version),
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
            Self::Postgres(db) => db.verify_attestation(id),
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
            Self::Postgres(db) => db.update_operation_receipt(operation_id, update),
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
            Self::Postgres(db) => db.get_decision(id),
        }
    }

    pub fn put_peer_trust_root(
        &self,
        root: &crate::sekai::peer_import::PeerTrustRoot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_peer_trust_root(root),
            Self::Postgres(_) => {
                Err("put_peer_trust_root is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn list_peer_trust_roots(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::peer_import::PeerTrustRoot>, String> {
        match self {
            Self::Sqlite(db) => db.list_peer_trust_roots(namespace),
            Self::Postgres(_) => Err(
                "list_peer_trust_roots is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn put_peer_import(
        &self,
        record: &crate::sekai::peer_import::PeerImportRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_peer_import(record),
            Self::Postgres(_) => {
                Err("put_peer_import is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn get_peer_import(
        &self,
        import_id: &str,
    ) -> Result<Option<crate::sekai::peer_import::PeerImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_peer_import(import_id),
            Self::Postgres(_) => {
                Err("get_peer_import is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn put_federation_local_site(
        &self,
        site: &crate::sekai::federation_profile::LocalSiteIdentity,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_local_site(site),
            Self::Postgres(_) => Err(
                "put_federation_local_site is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn get_federation_local_site(
        &self,
    ) -> Result<Option<crate::sekai::federation_profile::LocalSiteIdentity>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_local_site(),
            Self::Postgres(_) => Err(
                "get_federation_local_site is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_federation_peer(
        &self,
        peer: &crate::sekai::federation_profile::FederationPeer,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_peer(peer),
            Self::Postgres(_) => {
                Err("put_federation_peer is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn get_federation_peer(
        &self,
        peer_site_id: &str,
    ) -> Result<Option<crate::sekai::federation_profile::FederationPeer>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_peer(peer_site_id),
            Self::Postgres(_) => {
                Err("get_federation_peer is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn list_federation_peers(
        &self,
    ) -> Result<Vec<crate::sekai::federation_profile::FederationPeer>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_peers(),
            Self::Postgres(_) => Err(
                "list_federation_peers is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn put_federation_namespace_grant(
        &self,
        grant: &crate::sekai::namespace_snapshot::PeerNamespaceGrant,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_namespace_grant(grant),
            Self::Postgres(_) => Err(
                "put_federation_namespace_grant is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn get_federation_namespace_grant(
        &self,
        grant_id: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::PeerNamespaceGrant>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_namespace_grant(grant_id),
            Self::Postgres(_) => Err(
                "get_federation_namespace_grant is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_federation_namespace_grants(
        &self,
        namespace: Option<&str>,
        peer_site_id: Option<&str>,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::PeerNamespaceGrant>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_namespace_grants(namespace, peer_site_id),
            Self::Postgres(_) => Err(
                "list_federation_namespace_grants is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn reserve_federation_snapshot_sequence(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.reserve_federation_snapshot_sequence(namespace),
            Self::Postgres(_) => Err(
                "reserve_federation_snapshot_sequence is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_federation_snapshot_export(
        &self,
        export: &crate::sekai::namespace_snapshot::SnapshotExportRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_snapshot_export(export),
            Self::Postgres(_) => Err(
                "put_federation_snapshot_export is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
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
            Self::Postgres(_) => Err(
                "put_federation_snapshot_import is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn get_federation_snapshot_import(
        &self,
        import_id: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_snapshot_import(import_id),
            Self::Postgres(_) => Err(
                "get_federation_snapshot_import is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn latest_federation_snapshot_import(
        &self,
        peer_site_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.latest_federation_snapshot_import(peer_site_id, namespace),
            Self::Postgres(_) => Err(
                "latest_federation_snapshot_import is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_federation_snapshot_imports(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_snapshot_imports(namespace),
            Self::Postgres(_) => Err(
                "list_federation_snapshot_imports is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_federation_snapshot_facts(
        &self,
        import_id: &str,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::SnapshotFact>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_snapshot_facts(import_id),
            Self::Postgres(_) => Err(
                "list_federation_snapshot_facts is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_federation_conflict(
        &self,
        record: &crate::sekai::federation_conflict::FederationConflict,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_conflict(record),
            Self::Postgres(_) => {
                Err(crate::sekai::federation_conflict::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn get_federation_conflict(
        &self,
        conflict_id: &str,
    ) -> Result<Option<crate::sekai::federation_conflict::FederationConflict>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_conflict(conflict_id),
            Self::Postgres(_) => {
                Err(crate::sekai::federation_conflict::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn list_federation_conflicts(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::sekai::federation_conflict::FederationConflict>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_conflicts(namespace),
            Self::Postgres(_) => {
                Err(crate::sekai::federation_conflict::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn put_federation_revocation(
        &self,
        record: &crate::sekai::federation_revocation::FederationRevocation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_revocation(record),
            Self::Postgres(_) => {
                Err(crate::sekai::federation_revocation::POSTGRES_UNAVAILABLE.into())
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
            Self::Postgres(_) => Err(crate::sekai::federation_network::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_network_contract(
        &self,
        contract: &crate::sekai::federation_network::NetworkContract,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_network_contract(contract),
            Self::Postgres(_) => Err(crate::sekai::federation_network::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn cas_network_contract(
        &self,
        expected: &crate::sekai::federation_network::NetworkContract,
        next: &crate::sekai::federation_network::NetworkContract,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_network_contract(expected, next),
            Self::Postgres(_) => Err(crate::sekai::federation_network::POSTGRES_UNAVAILABLE.into()),
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
            Self::Postgres(_) => Err(crate::sekai::federation_network::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_network_exchange(
        &self,
        item: &crate::sekai::federation_network::NetworkExchange,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_network_exchange(item),
            Self::Postgres(_) => Err(crate::sekai::federation_network::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_workflow_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<crate::sekai::workflow_action::WorkflowActionBinding>, String> {
        match self {
            Self::Sqlite(db) => db.get_workflow_binding(namespace, binding_id),
            Self::Postgres(_) => Err(crate::sekai::workflow_action::POSTGRES_UNAVAILABLE.into()),
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
            Self::Postgres(_) => Err(crate::sekai::workflow_action::POSTGRES_UNAVAILABLE.into()),
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
            Self::Postgres(_) => Err(crate::sekai::workflow_action::POSTGRES_UNAVAILABLE.into()),
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
            Self::Postgres(_) => Err(crate::sekai::workflow_action::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_connector_certification(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<crate::sekai::connector_certification::ConnectorCertification>, String> {
        match self {
            Self::Sqlite(db) => db.get_connector_certification(namespace, certification_id),
            Self::Postgres(_) => {
                Err(crate::sekai::connector_certification::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn list_connector_certifications(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::connector_certification::ConnectorCertification>, String> {
        match self {
            Self::Sqlite(db) => db.list_connector_certifications(namespace),
            Self::Postgres(_) => {
                Err(crate::sekai::connector_certification::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn commit_connector_certifications(
        &self,
        certifications: &[&crate::sekai::connector_certification::ConnectorCertification],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_connector_certifications(certifications),
            Self::Postgres(_) => {
                Err(crate::sekai::connector_certification::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn cas_connector_certification(
        &self,
        expected: &crate::sekai::connector_certification::ConnectorCertification,
        next: &crate::sekai::connector_certification::ConnectorCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_connector_certification(expected, next),
            Self::Postgres(_) => {
                Err(crate::sekai::connector_certification::POSTGRES_UNAVAILABLE.into())
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

    pub fn get_federation_revocation(
        &self,
        revocation_id: &str,
    ) -> Result<Option<crate::sekai::federation_revocation::FederationRevocation>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_revocation(revocation_id),
            Self::Postgres(_) => {
                Err(crate::sekai::federation_revocation::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn list_federation_revocations(
        &self,
        subject_kind: Option<&str>,
    ) -> Result<Vec<crate::sekai::federation_revocation::FederationRevocation>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_revocations(subject_kind),
            Self::Postgres(_) => {
                Err(crate::sekai::federation_revocation::POSTGRES_UNAVAILABLE.into())
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

    pub fn put_source_webhook_key(
        &self,
        pin: &crate::sekai::source_webhook::SourceWebhookKeyPin,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_source_webhook_key(pin),
            Self::Postgres(_) => Err(
                "put_source_webhook_key is unavailable on the PostgreSQL community runtime".into(),
            ),
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
            Self::Postgres(_) => Err(
                "get_source_webhook_key is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_source_webhook_keys(
        &self,
        namespace: Option<&str>,
        source_instance: Option<&str>,
    ) -> Result<Vec<crate::sekai::source_webhook::SourceWebhookKeyPin>, String> {
        match self {
            Self::Sqlite(db) => db.list_source_webhook_keys(namespace, source_instance),
            Self::Postgres(_) => Err(
                "list_source_webhook_keys is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_open_table_source(
        &self,
        source: &crate::sekai::open_table::OpenTableSource,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_open_table_source(source),
            Self::Postgres(_) => Err(crate::sekai::open_table::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_open_table_source(
        &self,
        source_id: &str,
    ) -> Result<Option<crate::sekai::open_table::OpenTableSource>, String> {
        match self {
            Self::Sqlite(db) => db.get_open_table_source(source_id),
            Self::Postgres(_) => Err(crate::sekai::open_table::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_open_table_snapshot(
        &self,
        snapshot: &crate::sekai::open_table::OpenTableSnapshot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_open_table_snapshot(snapshot),
            Self::Postgres(_) => Err(crate::sekai::open_table::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_open_table_snapshot(
        &self,
        source_id: &str,
    ) -> Result<Option<crate::sekai::open_table::OpenTableSnapshot>, String> {
        match self {
            Self::Sqlite(db) => db.get_open_table_snapshot(source_id),
            Self::Postgres(_) => Err(crate::sekai::open_table::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_event_stream_binding(
        &self,
        binding: &crate::sekai::event_stream::EventStreamBinding,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_event_stream_binding(binding),
            Self::Postgres(_) => Err(crate::sekai::event_stream::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_event_stream_binding(
        &self,
        stream_id: &str,
    ) -> Result<Option<crate::sekai::event_stream::EventStreamBinding>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_stream_binding(stream_id),
            Self::Postgres(_) => Err(crate::sekai::event_stream::POSTGRES_UNAVAILABLE.into()),
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
            Self::Postgres(_) => Err(crate::sekai::event_stream::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn ensure_event_stream_admitted_events(
        &self,
        batch: &crate::sekai::event_stream::EventStreamBatch,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.ensure_event_stream_admitted_events(batch),
            Self::Postgres(_) => Err(crate::sekai::event_stream::POSTGRES_UNAVAILABLE.into()),
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
            Self::Postgres(_) => Err(crate::sekai::event_stream::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_event_stream_checkpoint(
        &self,
        stream_id: &str,
    ) -> Result<Option<crate::sekai::event_stream::EventStreamCheckpoint>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_stream_checkpoint(stream_id),
            Self::Postgres(_) => Err(crate::sekai::event_stream::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_event_subscription(
        &self,
        subscription: &crate::sekai::event_subscription::EventSubscription,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_event_subscription(subscription),
            Self::Postgres(_) => Err(crate::sekai::event_subscription::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_event_subscription(
        &self,
        namespace: &str,
        subscription_id: &str,
    ) -> Result<Option<crate::sekai::event_subscription::EventSubscription>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_subscription(namespace, subscription_id),
            Self::Postgres(_) => Err(crate::sekai::event_subscription::POSTGRES_UNAVAILABLE.into()),
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
            Self::Postgres(_) => Err(crate::sekai::event_subscription::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn advance_event_subscription_cursor(
        &self,
        next: &crate::sekai::event_subscription::EventSubscription,
        expected: &crate::sekai::event_subscription::EventSubscription,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.advance_event_subscription_cursor(next, expected),
            Self::Postgres(_) => Err(crate::sekai::event_subscription::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_governed_document(
        &self,
        document: &crate::sekai::document::GovernedDocument,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_document(document),
            Self::Postgres(_) => Err(crate::sekai::document::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_governed_document(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Option<crate::sekai::document::GovernedDocument>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_document(namespace, document_id),
            Self::Postgres(_) => Err(crate::sekai::document::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_governed_rendition(
        &self,
        rendition: &crate::sekai::document::DocumentRendition,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_rendition(rendition),
            Self::Postgres(_) => Err(crate::sekai::document::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn list_governed_renditions(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Vec<crate::sekai::document::DocumentRendition>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_renditions(namespace, document_id),
            Self::Postgres(_) => Err(crate::sekai::document::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn delete_governed_renditions(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_governed_renditions(namespace, document_id),
            Self::Postgres(_) => Err(crate::sekai::document::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_client_package(
        &self,
        namespace: &str,
        package_id: &str,
    ) -> Result<Option<crate::sekai::client_package::ClientPackage>, String> {
        match self {
            Self::Sqlite(db) => db.get_client_package(namespace, package_id),
            Self::Postgres(_) => Err(crate::sekai::client_package::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn list_client_packages(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::client_package::ClientPackage>, String> {
        match self {
            Self::Sqlite(db) => db.list_client_packages(namespace),
            Self::Postgres(_) => Err(crate::sekai::client_package::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn commit_client_packages(
        &self,
        packages: &[&crate::sekai::client_package::ClientPackage],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_client_packages(packages),
            Self::Postgres(_) => Err(crate::sekai::client_package::POSTGRES_UNAVAILABLE.into()),
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
            Self::Postgres(_) => Err(crate::sekai::capability_package::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn list_capability_packages(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::capability_package::CapabilityPackageCertification>, String> {
        match self {
            Self::Sqlite(db) => db.list_capability_packages(namespace),
            Self::Postgres(_) => Err(crate::sekai::capability_package::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn commit_capability_packages(
        &self,
        packages: &[&crate::sekai::capability_package::CapabilityPackageCertification],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_capability_packages(packages),
            Self::Postgres(_) => Err(crate::sekai::capability_package::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn cas_capability_package(
        &self,
        expected: &crate::sekai::capability_package::CapabilityPackageCertification,
        next: &crate::sekai::capability_package::CapabilityPackageCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_capability_package(expected, next),
            Self::Postgres(_) => Err(crate::sekai::capability_package::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_governed_image(
        &self,
        image: &crate::sekai::image::GovernedImage,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image(image),
            Self::Postgres(_) => Err(crate::sekai::image::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_governed_image(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Option<crate::sekai::image::GovernedImage>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_image(namespace, image_id),
            Self::Postgres(_) => Err(crate::sekai::image::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_governed_image_rendition(
        &self,
        rendition: &crate::sekai::image::ImageRendition,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image_rendition(rendition),
            Self::Postgres(_) => Err(crate::sekai::image::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn list_governed_image_renditions(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Vec<crate::sekai::image::ImageRendition>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_image_renditions(namespace, image_id),
            Self::Postgres(_) => Err(crate::sekai::image::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn tombstone_governed_image(
        &self,
        image: &crate::sekai::image::GovernedImage,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.tombstone_governed_image(image),
            Self::Postgres(_) => Err(crate::sekai::image::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_governed_image_annotation(
        &self,
        annotation: &crate::sekai::image::ImageAnnotation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image_annotation(annotation),
            Self::Postgres(_) => Err(crate::sekai::image::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn list_governed_image_annotations(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Vec<crate::sekai::image::ImageAnnotation>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_image_annotations(namespace, image_id),
            Self::Postgres(_) => Err(crate::sekai::image::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_run_record(id),
            Self::Postgres(db) => db.get_eval_run_record(id),
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
            Self::Postgres(db) => {
                db.get_latest_eval_run_record_for_gate(suite_id, config_ref, max_timestamp_ms)
            }
        }
    }

    pub fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_suite_record(id),
            Self::Postgres(db) => db.get_eval_suite_record(id),
        }
    }

    pub fn get_eval_suite_record_for_gate(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_suite_record_for_gate(id),
            Self::Postgres(db) => db.get_eval_suite_record_for_gate(id),
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
            Self::Postgres(db) => db.get_links_limited(object_id, relation, dir, limit),
        }
    }

    pub fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_type(kind),
            Self::Postgres(db) => db.get_object_type(kind),
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

    pub fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_eval_iteration_records(),
            Self::Postgres(db) => db.list_all_eval_iteration_records(),
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

    pub fn list_eval_iteration_records(
        &self,
        suite_id: &str,
    ) -> Result<Vec<eval::Iteration>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_iteration_records(suite_id),
            Self::Postgres(db) => db.list_eval_iteration_records(suite_id),
        }
    }

    pub fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_run_records(suite_id),
            Self::Postgres(db) => db.list_eval_run_records(suite_id),
        }
    }

    pub fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_suite_records(),
            Self::Postgres(db) => db.list_eval_suite_records(),
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
            Self::Postgres(db) => db.portfolio_damped_route(
                namespace,
                task_class,
                proposed_model,
                proposed_prompt_variant,
                now_ms,
                force,
            ),
        }
    }

    pub fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_objective(namespace),
            Self::Postgres(db) => db.portfolio_objective(namespace),
        }
    }

    pub fn portfolio_points(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_points(namespace, task_class),
            Self::Postgres(db) => db.portfolio_points(namespace, task_class),
        }
    }

    pub fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.portfolio_record_observation(observation),
            Self::Postgres(db) => db.portfolio_record_observation(observation),
        }
    }

    pub fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.portfolio_set_objective(objective),
            Self::Postgres(db) => db.portfolio_set_objective(objective),
        }
    }

    pub fn principal_credentials_activity_epoch(&self) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.principal_credentials_activity_epoch(),
            Self::Postgres(db) => db.principal_credentials_activity_epoch(),
        }
    }

    pub fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_iteration(iteration),
            Self::Postgres(db) => db.put_eval_iteration(iteration),
        }
    }

    pub fn put_eval_run(&self, run: &eval::Run) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_run(run),
            Self::Postgres(db) => db.put_eval_run(run),
        }
    }

    pub fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_suite(suite),
            Self::Postgres(db) => db.put_eval_suite(suite),
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

    pub fn list_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_credentials(principal, status),
            Self::Postgres(db) => db.list_credentials(principal, status),
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
            Self::Postgres(db) => db.create_principal_credential(principal, token_hash, now),
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
            Self::Postgres(db) => db.get_lineage(object_id, max_nodes),
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
            Self::Postgres(db) => db.get_lineage_with_policy_context(object_id, max_nodes, context),
        }
    }

    pub fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_retention_policy(policy),
            Self::Postgres(db) => db.set_retention_policy(policy),
        }
    }

    pub fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.list_retention_policies(),
            Self::Postgres(db) => db.list_retention_policies(),
        }
    }

    pub fn erase_subject(
        &self,
        request: &SubjectErasureRequest,
    ) -> Result<SubjectErasureResult, String> {
        match self {
            Self::Sqlite(db) => db.erase_subject(request),
            Self::Postgres(db) => db.erase_subject(request),
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
            Self::Postgres(db) => db.list_object_changes(object_id, limit, offset),
        }
    }

    pub fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_kioku_memory(memory, evidence),
            Self::Postgres(db) => db.insert_kioku_memory(memory, evidence),
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
            Self::Postgres(db) => db.upsert_ontology_class(class),
        }
    }

    pub fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_relation(relation),
            Self::Postgres(db) => db.upsert_ontology_relation(relation),
        }
    }

    pub fn update_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_work_unit(work_unit),
            Self::Postgres(db) => db.update_work_unit(work_unit),
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
            Self::Postgres(db) => db.list_objects(filter),
        }
    }

    pub fn delete_object(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_object(id),
            Self::Postgres(db) => db.delete_object(id),
        }
    }

    pub fn abort_unreceipted_object_create(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.abort_unreceipted_object_create(id),
            Self::Postgres(db) => db.abort_unreceipted_object_create(id),
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

    pub fn conn(&self) -> r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> {
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

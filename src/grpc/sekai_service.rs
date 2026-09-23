#![allow(clippy::result_large_err, clippy::collapsible_if, clippy::manual_clamp)]

#[path = "action_binding.rs"]
mod action_binding;
#[path = "authorized_link_mutation.rs"]
mod authorized_link_mutation;
#[path = "authorized_query_lifecycle.rs"]
mod authorized_query_lifecycle;
#[path = "capability_discovery.rs"]
mod capability_discovery;
#[path = "catalog_invocation.rs"]
mod catalog_invocation;
#[path = "computed_response.rs"]
mod computed_response;
#[path = "definition_consumer_impact.rs"]
mod definition_consumer_impact;
#[path = "object_change_subscription.rs"]
mod object_change_subscription;
#[path = "object_mutation_lifecycle.rs"]
mod object_mutation_lifecycle;
#[path = "object_set_query.rs"]
mod object_set_query;
#[path = "ontology_definition_lifecycle.rs"]
mod ontology_definition_lifecycle;
#[path = "schema_definition_lifecycle.rs"]
mod schema_definition_lifecycle;
#[path = "scored_knowledge_admission.rs"]
mod scored_knowledge_admission;
#[cfg(test)]
use scored_knowledge_admission::{
    learning_id as scoring_learning_id, source_request_id as knowledge_source_request_id,
};
#[path = "semantic_retrieval_lifecycle.rs"]
mod semantic_retrieval_lifecycle;
#[path = "sekai_service_support_access.rs"]
mod support_access;
use support_access::*;
#[path = "sekai_service_support_mapping.rs"]
mod support_mapping;
use support_mapping::*;
#[path = "sekai_service_support_domain.rs"]
mod support_domain;
use support_domain::*;
#[path = "sekai_service_support_credentials.rs"]
mod support_credentials;
use support_credentials::*;
#[path = "sekai_service_rpc_actions.rs"]
mod rpc_actions;
#[path = "sekai_service_rpc_coordination.rs"]
mod rpc_coordination;
#[path = "sekai_service_rpc_data.rs"]
mod rpc_data;
#[path = "sekai_service_rpc_definitions.rs"]
mod rpc_definitions;
#[path = "sekai_service_rpc_leases.rs"]
mod rpc_leases;
#[path = "sekai_service_rpc_objects.rs"]
mod rpc_objects;
#[path = "sekai_service_rpc_retrieval.rs"]
mod rpc_retrieval;

use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

use super::pb::sekai::sekai_service_server::SekaiService;
use super::pb::sekai::*;
use super::visible_page::{VisiblePageError, scan_visible_page};
use crate::chisei::epistemic_descriptor::{
    EPISTEMIC_DESCRIPTOR_VERSION, EpistemicDescriptor as DomainEpistemicDescriptor,
};
use crate::chisei::scoring::{KnowledgeWriteOutcome, KnowledgeWriteRequest, KnowledgeWriter};
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain;
use crate::gateway_keys::hash_gateway_key;
use crate::sekai::action::RiskClass;
use crate::sekai::action_policy::{self, ActionDecision};
use crate::sekai::action_work_lifecycle::{
    AckActionWork as AckActionWorkCommand, ActionWorkLifecycle, ActionWorkLifecycleError,
    ClaimActionWork as ClaimActionWorkCommand, HeartbeatActionClaim as HeartbeatActionClaimCommand,
    ReportActionClaimEvent as ReportActionClaimEventCommand,
};
use crate::sekai::attestation;
use crate::sekai::capability;
use crate::sekai::definition_branch as definition_branch_domain;
use crate::sekai::definition_diff as definition_diff_domain;
use crate::sekai::definition_proposal as definition_proposal_domain;
use crate::sekai::evidence as evidence_domain;
use crate::sekai::evidence_admission_lifecycle::{
    EvidenceAdmissionLifecycle, EvidenceAdmissionLifecycleError, EvidenceAdmissionOutcome,
};
#[cfg(test)]
use crate::sekai::evidence_store::EvidenceProducerCapability as DomainEvidenceProducerCapability;
use crate::sekai::evidence_store::{
    EvidenceSchemaDefinition as DomainEvidenceSchemaDefinition, EvidenceSubmissionFilter,
    EvidenceSubmissionRecord as DomainEvidenceSubmissionRecord,
};
use crate::sekai::governed_facts as governed_fact_domain;
use crate::sekai::handoff as handoff_domain;
use crate::sekai::handoff_lifecycle::{
    CreateHandoff as CreateHandoffCommand, HandoffLifecycle, HandoffLifecycleError,
    RevokeHandoff as RevokeHandoffCommand,
};
use crate::sekai::lease_lifecycle::{
    AcquireLease as AcquireLeaseCommand, GetLease as GetLeaseCommand, GuardedMutationPrecondition,
    GuardedMutationTarget, LeaseLifecycle, LeaseLifecycleError,
    RefreshLease as RefreshLeaseCommand, ReleaseLease as ReleaseLeaseCommand,
    TakeoverExpiredLease as TakeoverExpiredLeaseCommand,
};
use crate::sekai::markings;
use crate::sekai::object_mutation::{
    LeasePrecondition as MutationLeasePrecondition, MutationPersistenceError, ObjectMutation,
};
use crate::sekai::object_sync as source_sync_domain;
use crate::sekai::schema::{self, SchemaRegistry};
use crate::sekai::security::SecurityChecker;
use crate::sekai::work_unit_lifecycle::{
    AdmitWorkUnit, CreateAuthorizationTarget, CreateWorkUnit, CreateWorkUnitError,
    ReconcileWorkUnits, TransitionWorkUnit, WorkUnitLifecycle, WorkUnitLifecycleError,
    WorkUnitTransition,
};
use crate::sekai::{
    audit, compute, coordination, dataset, function, ontology, retrieval, security, semantic,
};
use uuid::Uuid;

use self::catalog_invocation::CatalogInvocation;
use self::object_mutation_lifecycle::{
    GuardedCreateObjectRequest, GuardedDeleteObjectRequest, GuardedUpdateObjectRequest,
};
use self::schema_definition_lifecycle::{
    SchemaDefinitionLifecycle, SchemaDefinitionLifecycleError,
};

const REDACTED_VALUE: &str = "[redacted]";

fn map_schema_definition_lifecycle_error(error: SchemaDefinitionLifecycleError) -> Status {
    match error {
        SchemaDefinitionLifecycleError::Unavailable(error) => Status::internal(error),
        SchemaDefinitionLifecycleError::InvalidDefinition(error)
        | SchemaDefinitionLifecycleError::InvalidComputedProperty(error) => {
            Status::invalid_argument(error)
        }
        SchemaDefinitionLifecycleError::Persistence(error) => Status::internal(error),
    }
}

pub struct SekaiServiceImpl {
    pub(super) db: crate::db::store::SekaiStore,
    pub(super) security: Arc<SecurityChecker>,
    pub(super) schema_definitions: SchemaDefinitionLifecycle,
    pub(super) gateway_schema_principals: Vec<String>,
    /// Region/site pin from `SEKAI_SITE_ID` (default `"local"`).
    pub(super) site_id: String,
    pub(super) object_query_cursor_key: [u8; 32],
    pub(super) object_index_engine: crate::sekai::object_index_engine::ObjectIndexEngineKind,
    pub(super) object_index_dual_read: bool,
    pub(super) object_log_dual_read: crate::sekai::object_log::ObjectLogDualRead,
    pub(super) cross_store:
        Option<std::sync::Arc<crate::chisei::cross_store_admission::CrossStoreAdmission>>,
}

impl SekaiServiceImpl {
    pub fn new(db: crate::db::store::SekaiStore) -> Self {
        Self::new_with_gateway_schema_principals(db, Vec::new())
    }

    pub fn new_with_gateway_schema_principals(
        db: crate::db::store::SekaiStore,
        gateway_schema_principals: Vec<String>,
    ) -> Self {
        let security = Arc::new(SecurityChecker::new());
        let grants = db.runtime().list_all_grants().unwrap_or_default();
        security.load(&grants);
        let schema_definitions = SchemaDefinitionLifecycle::load(db.runtime_arc());
        let object_query_cursor_key = db
            .runtime()
            .object_query_cursor_key()
            .expect("initialize durable object query cursor key");
        Self {
            db,
            security,
            schema_definitions,
            gateway_schema_principals,
            site_id: crate::sekai::lease::DEFAULT_SITE_ID.into(),
            object_query_cursor_key,
            object_index_engine: crate::sekai::object_index_engine::ObjectIndexEngineKind::from_env(
            ),
            object_index_dual_read:
                crate::sekai::object_index_engine::ObjectIndexEngineKind::dual_read_from_env(),
            object_log_dual_read: crate::sekai::object_log::ObjectLogDualRead::from_env(),
            cross_store: None,
        }
    }

    pub fn with_cross_store_admission(
        mut self,
        clerk: std::sync::Arc<crate::chisei::cross_store_admission::CrossStoreAdmission>,
    ) -> Self {
        self.cross_store = Some(clerk);
        self
    }

    pub fn with_site_id(mut self, site_id: impl Into<String>) -> Self {
        self.site_id = site_id.into();
        self
    }

    fn catalog_metadata_value(req: &Request<impl prost::Message>, key: &str) -> Option<String> {
        req.metadata()
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    /// Begin a receipt-attributed catalog invocation for a semantic capability.
    /// Returns `None` when the caller did not send `x-sekai-capability` (direct RPC).
    /// Live discovery is rechecked; a previously observed catalog is never a grant.
    fn begin_semantic_catalog_invocation<'a>(
        &'a self,
        req: &Request<impl prost::Message>,
        expected_capability: &str,
        namespace: &str,
        principals: &[String],
    ) -> Result<Option<(String, CatalogInvocation<'a>)>, Status> {
        let Some(capability_name) = Self::catalog_metadata_value(req, "x-sekai-capability") else {
            return Ok(None);
        };
        let catalog_namespace = Self::catalog_metadata_value(req, "x-sekai-namespace")
            .unwrap_or_else(|| namespace.to_string());
        if catalog_namespace.is_empty() {
            return Err(Status::invalid_argument(
                "catalog semantic invocation requires namespace",
            ));
        }
        if catalog_namespace != namespace && !namespace.is_empty() {
            return Err(Status::invalid_argument(
                "catalog namespace metadata must match request namespace",
            ));
        }
        let namespace = if namespace.is_empty() {
            catalog_namespace.as_str()
        } else {
            namespace
        };
        let operation_id = Self::catalog_metadata_value(req, "x-sekai-operation-id")
            .unwrap_or_else(|| format!("catalog-invocation-{}", Uuid::new_v4().simple()));
        let catalog_version = Self::catalog_metadata_value(req, "x-sekai-catalog-version");
        let actor = principals.first().cloned().unwrap_or_default();

        let visible = self
            .discoverable_capabilities(namespace, principals)?
            .into_iter()
            .any(|entry| entry.name == capability_name && capability_name == expected_capability);
        if !visible {
            CatalogInvocation::record_refusal(
                self.db.runtime(),
                &operation_id,
                namespace,
                &actor,
                &capability_name,
                catalog_version.as_deref(),
                "capability_unavailable",
            )?;
            return Err(Status::failed_precondition("capability unavailable"));
        }

        let invocation = CatalogInvocation::begin(
            self.db.runtime(),
            operation_id.clone(),
            namespace,
            actor,
            capability_name,
            catalog_version,
        )?;
        Ok(Some((operation_id, invocation)))
    }
}

const DEFAULT_LIST_LIMIT: i32 = domain::DEFAULT_LIST_LIMIT;
const MAX_LIST_LIMIT: i32 = domain::MAX_LIST_LIMIT;

/// Internal governance object kinds that must never be created, mutated, read,
/// or listed through the generic object CRUD RPCs. They hold policy and
/// blast-radius counters and are managed only through dedicated RPCs plus
/// server-internal DB paths.
const RESERVED_GOVERNANCE_KINDS: &[&str] = &[
    action_policy::ACTION_POLICY_KIND,
    action_policy::BLAST_RADIUS_KIND,
    // Retired pre-1.0 state is purged on startup, so this name must never be
    // reusable through generic CRUD.
    "action_approval",
    crate::domain::KIND_CAPABILITY,
    crate::domain::KIND_EXTERNAL_EVIDENCE,
    governed_fact_domain::PROFILE_KIND,
    governed_fact_domain::FACT_KIND,
    governed_fact_domain::WAIVER_KIND,
];

const MAX_GOVERNED_VISIBILITY_WORK: usize = 8_192;

#[tonic::async_trait]
impl SekaiService for SekaiServiceImpl {
    async fn acquire_lease(
        &self,
        req: Request<AcquireLeaseRequest>,
    ) -> Result<Response<AcquireLeaseResponse>, Status> {
        rpc_leases::acquire_lease(self, req).await
    }

    async fn get_lease(
        &self,
        req: Request<GetLeaseRequest>,
    ) -> Result<Response<GetLeaseResponse>, Status> {
        rpc_leases::get_lease(self, req).await
    }

    async fn refresh_lease(
        &self,
        req: Request<RefreshLeaseRequest>,
    ) -> Result<Response<RefreshLeaseResponse>, Status> {
        rpc_leases::refresh_lease(self, req).await
    }

    async fn release_lease(
        &self,
        req: Request<ReleaseLeaseRequest>,
    ) -> Result<Response<ReleaseLeaseResponse>, Status> {
        rpc_leases::release_lease(self, req).await
    }

    async fn takeover_expired_lease(
        &self,
        req: Request<TakeoverExpiredLeaseRequest>,
    ) -> Result<Response<TakeoverExpiredLeaseResponse>, Status> {
        rpc_leases::takeover_expired_lease(self, req).await
    }

    async fn apply_source_batch(
        &self,
        req: Request<ApplySourceBatchRequest>,
    ) -> Result<Response<ApplySourceBatchResponse>, Status> {
        rpc_leases::apply_source_batch(self, req).await
    }

    async fn get_source_sync_state(
        &self,
        req: Request<GetSourceSyncStateRequest>,
    ) -> Result<Response<GetSourceSyncStateResponse>, Status> {
        rpc_leases::get_source_sync_state(self, req).await
    }

    async fn register_source_type_descriptor(
        &self,
        req: Request<RegisterSourceTypeDescriptorRequest>,
    ) -> Result<Response<RegisterSourceTypeDescriptorResponse>, Status> {
        rpc_leases::register_source_type_descriptor(self, req).await
    }

    async fn inspect_source_type_descriptor(
        &self,
        req: Request<InspectSourceTypeDescriptorRequest>,
    ) -> Result<Response<InspectSourceTypeDescriptorResponse>, Status> {
        rpc_leases::inspect_source_type_descriptor(self, req).await
    }

    async fn retire_source_type_descriptor(
        &self,
        req: Request<RetireSourceTypeDescriptorRequest>,
    ) -> Result<Response<RetireSourceTypeDescriptorResponse>, Status> {
        rpc_leases::retire_source_type_descriptor(self, req).await
    }

    async fn create_definition_branch(
        &self,
        req: Request<CreateDefinitionBranchRequest>,
    ) -> Result<Response<CreateDefinitionBranchResponse>, Status> {
        rpc_definitions::create_definition_branch(self, req).await
    }

    async fn get_definition_branch(
        &self,
        req: Request<GetDefinitionBranchRequest>,
    ) -> Result<Response<GetDefinitionBranchResponse>, Status> {
        rpc_definitions::get_definition_branch(self, req).await
    }

    async fn apply_definition_branch_edit(
        &self,
        req: Request<ApplyDefinitionBranchEditRequest>,
    ) -> Result<Response<ApplyDefinitionBranchEditResponse>, Status> {
        rpc_definitions::apply_definition_branch_edit(self, req).await
    }

    async fn create_definition_proposal(
        &self,
        req: Request<CreateDefinitionProposalRequest>,
    ) -> Result<Response<CreateDefinitionProposalResponse>, Status> {
        rpc_definitions::create_definition_proposal(self, req).await
    }

    async fn get_definition_proposal(
        &self,
        req: Request<GetDefinitionProposalRequest>,
    ) -> Result<Response<GetDefinitionProposalResponse>, Status> {
        rpc_definitions::get_definition_proposal(self, req).await
    }

    async fn approve_definition_proposal(
        &self,
        req: Request<ApproveDefinitionProposalRequest>,
    ) -> Result<Response<ApproveDefinitionProposalResponse>, Status> {
        rpc_definitions::approve_definition_proposal(self, req).await
    }

    async fn merge_definition_proposal(
        &self,
        req: Request<MergeDefinitionProposalRequest>,
    ) -> Result<Response<MergeDefinitionProposalResponse>, Status> {
        rpc_definitions::merge_definition_proposal(self, req).await
    }

    async fn close_definition_proposal(
        &self,
        req: Request<CloseDefinitionProposalRequest>,
    ) -> Result<Response<CloseDefinitionProposalResponse>, Status> {
        rpc_definitions::close_definition_proposal(self, req).await
    }

    async fn get_published_definition_revision(
        &self,
        req: Request<GetPublishedDefinitionRevisionRequest>,
    ) -> Result<Response<GetPublishedDefinitionRevisionResponse>, Status> {
        rpc_definitions::get_published_definition_revision(self, req).await
    }

    async fn compare_definition_revisions(
        &self,
        req: Request<CompareDefinitionRevisionsRequest>,
    ) -> Result<Response<CompareDefinitionRevisionsResponse>, Status> {
        rpc_definitions::compare_definition_revisions(self, req).await
    }

    async fn report_definition_consumer_impact(
        &self,
        req: Request<ReportDefinitionConsumerImpactRequest>,
    ) -> Result<Response<ReportDefinitionConsumerImpactResponse>, Status> {
        rpc_definitions::report_definition_consumer_impact(self, req).await
    }

    async fn classify_definition_revision_compatibility(
        &self,
        req: Request<ClassifyDefinitionRevisionCompatibilityRequest>,
    ) -> Result<Response<ClassifyDefinitionRevisionCompatibilityResponse>, Status> {
        rpc_definitions::classify_definition_revision_compatibility(self, req).await
    }

    async fn execute_definition_fact_migration(
        &self,
        req: Request<ExecuteDefinitionFactMigrationRequest>,
    ) -> Result<Response<ExecuteDefinitionFactMigrationResponse>, Status> {
        rpc_definitions::execute_definition_fact_migration(self, req).await
    }

    async fn get_definition_fact_migration(
        &self,
        req: Request<GetDefinitionFactMigrationRequest>,
    ) -> Result<Response<GetDefinitionFactMigrationResponse>, Status> {
        rpc_definitions::get_definition_fact_migration(self, req).await
    }

    async fn create_handoff(
        &self,
        req: Request<CreateHandoffRequest>,
    ) -> Result<Response<CreateHandoffResponse>, Status> {
        rpc_definitions::create_handoff(self, req).await
    }

    async fn revoke_handoff(
        &self,
        req: Request<RevokeHandoffRequest>,
    ) -> Result<Response<RevokeHandoffResponse>, Status> {
        rpc_definitions::revoke_handoff(self, req).await
    }

    async fn create_object(
        &self,
        req: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        rpc_objects::create_object(self, req).await
    }

    async fn get_object(
        &self,
        req: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        rpc_objects::get_object(self, req).await
    }
    async fn update_object(
        &self,
        req: Request<UpdateObjectRequest>,
    ) -> Result<Response<UpdateObjectResponse>, Status> {
        rpc_objects::update_object(self, req).await
    }

    async fn delete_object(
        &self,
        req: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        rpc_objects::delete_object(self, req).await
    }

    async fn list_objects(
        &self,
        req: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        rpc_objects::list_objects(self, req).await
    }

    async fn evaluate_object_set(
        &self,
        req: Request<EvaluateObjectSetRequest>,
    ) -> Result<Response<EvaluateObjectSetResponse>, Status> {
        rpc_objects::evaluate_object_set(self, req).await
    }
    async fn register_object_type_datasource(
        &self,
        req: Request<RegisterObjectTypeDatasourceRequest>,
    ) -> Result<Response<RegisterObjectTypeDatasourceResponse>, Status> {
        rpc_objects::register_object_type_datasource(self, req).await
    }
    async fn reindex_object_type(
        &self,
        req: Request<ReindexObjectTypeRequest>,
    ) -> Result<Response<ReindexObjectTypeResponse>, Status> {
        rpc_objects::reindex_object_type(self, req).await
    }
    async fn get_object_type_index_status(
        &self,
        req: Request<GetObjectTypeIndexStatusRequest>,
    ) -> Result<Response<GetObjectTypeIndexStatusResponse>, Status> {
        rpc_objects::get_object_type_index_status(self, req).await
    }
    async fn put_object_type_index_edit(
        &self,
        req: Request<PutObjectTypeIndexEditRequest>,
    ) -> Result<Response<PutObjectTypeIndexEditResponse>, Status> {
        rpc_objects::put_object_type_index_edit(self, req).await
    }
    async fn read_object_change_subscription(
        &self,
        req: Request<ReadObjectChangeSubscriptionRequest>,
    ) -> Result<Response<ReadObjectChangeSubscriptionResponse>, Status> {
        rpc_objects::read_object_change_subscription(self, req).await
    }
    async fn put_object_security_policy_revision(
        &self,
        req: Request<PutObjectSecurityPolicyRevisionRequest>,
    ) -> Result<Response<PutObjectSecurityPolicyRevisionResponse>, Status> {
        rpc_objects::put_object_security_policy_revision(self, req).await
    }

    async fn get_object_security_policy_revision(
        &self,
        req: Request<GetObjectSecurityPolicyRevisionRequest>,
    ) -> Result<Response<GetObjectSecurityPolicyRevisionResponse>, Status> {
        rpc_objects::get_object_security_policy_revision(self, req).await
    }

    async fn activate_object_security_policies(
        &self,
        req: Request<ActivateObjectSecurityPoliciesRequest>,
    ) -> Result<Response<ActivateObjectSecurityPoliciesResponse>, Status> {
        rpc_objects::activate_object_security_policies(self, req).await
    }

    async fn get_object_security_activation(
        &self,
        req: Request<GetObjectSecurityActivationRequest>,
    ) -> Result<Response<GetObjectSecurityActivationResponse>, Status> {
        rpc_objects::get_object_security_activation(self, req).await
    }

    async fn put_purpose_authorization(
        &self,
        req: Request<PutPurposeAuthorizationRequest>,
    ) -> Result<Response<PutPurposeAuthorizationResponse>, Status> {
        rpc_objects::put_purpose_authorization(self, req).await
    }

    async fn revoke_purpose_authorization(
        &self,
        req: Request<RevokePurposeAuthorizationRequest>,
    ) -> Result<Response<RevokePurposeAuthorizationResponse>, Status> {
        rpc_objects::revoke_purpose_authorization(self, req).await
    }

    async fn put_classification_lattice(
        &self,
        req: Request<PutClassificationLatticeRequest>,
    ) -> Result<Response<PutClassificationLatticeResponse>, Status> {
        rpc_objects::put_classification_lattice(self, req).await
    }

    async fn get_classification_lattice(
        &self,
        req: Request<GetClassificationLatticeRequest>,
    ) -> Result<Response<GetClassificationLatticeResponse>, Status> {
        rpc_objects::get_classification_lattice(self, req).await
    }

    async fn simulate_object_policy_change(
        &self,
        req: Request<SimulateObjectPolicyChangeRequest>,
    ) -> Result<Response<SimulateObjectPolicyChangeResponse>, Status> {
        rpc_objects::simulate_object_policy_change(self, req).await
    }

    async fn query_object_policy_audit(
        &self,
        req: Request<QueryObjectPolicyAuditRequest>,
    ) -> Result<Response<QueryObjectPolicyAuditResponse>, Status> {
        rpc_objects::query_object_policy_audit(self, req).await
    }

    async fn find_by_external_id(
        &self,
        req: Request<FindByExternalIdRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        rpc_objects::find_by_external_id(self, req).await
    }
    async fn find_by_property(
        &self,
        req: Request<FindByPropertyRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        rpc_objects::find_by_property(self, req).await
    }
    async fn create_link(
        &self,
        req: Request<CreateLinkRequest>,
    ) -> Result<Response<CreateLinkResponse>, Status> {
        rpc_objects::create_link(self, req).await
    }
    async fn delete_link(
        &self,
        req: Request<DeleteLinkRequest>,
    ) -> Result<Response<DeleteLinkResponse>, Status> {
        rpc_objects::delete_link(self, req).await
    }
    async fn get_links(
        &self,
        req: Request<GetLinksRequest>,
    ) -> Result<Response<GetLinksResponse>, Status> {
        rpc_objects::get_links(self, req).await
    }
    async fn get_linked_objects(
        &self,
        req: Request<GetLinkedObjectsRequest>,
    ) -> Result<Response<GetLinkedObjectsResponse>, Status> {
        rpc_objects::get_linked_objects(self, req).await
    }
    async fn traverse(
        &self,
        req: Request<TraverseRequest>,
    ) -> Result<Response<TraverseResponse>, Status> {
        rpc_retrieval::traverse(self, req).await
    }
    async fn retrieve_context(
        &self,
        req: Request<RetrieveContextRequest>,
    ) -> Result<Response<RetrieveContextResponse>, Status> {
        rpc_retrieval::retrieve_context(self, req).await
    }
    async fn expand_relations(
        &self,
        req: Request<ExpandRelationsRequest>,
    ) -> Result<Response<ExpandRelationsResponse>, Status> {
        rpc_retrieval::expand_relations(self, req).await
    }

    async fn explain_derivation(
        &self,
        req: Request<ExplainDerivationRequest>,
    ) -> Result<Response<ExplainDerivationResponse>, Status> {
        rpc_retrieval::explain_derivation(self, req).await
    }

    async fn discover_capabilities(
        &self,
        req: Request<DiscoverCapabilitiesRequest>,
    ) -> Result<Response<DiscoverCapabilitiesResponse>, Status> {
        rpc_retrieval::discover_capabilities(self, req).await
    }

    async fn get_governed_fact_version(
        &self,
        req: Request<GetGovernedFactVersionRequest>,
    ) -> Result<Response<GetGovernedFactVersionResponse>, Status> {
        rpc_retrieval::get_governed_fact_version(self, req).await
    }

    async fn resolve_invariant_set(
        &self,
        req: Request<ResolveInvariantSetRequest>,
    ) -> Result<Response<ResolveInvariantSetResponse>, Status> {
        rpc_retrieval::resolve_invariant_set(self, req).await
    }

    async fn list_schema_types(
        &self,
        req: Request<ListSchemaTypesRequest>,
    ) -> Result<Response<ListSchemaTypesResponse>, Status> {
        rpc_retrieval::list_schema_types(self, req).await
    }
    async fn create_schema_type(
        &self,
        req: Request<CreateSchemaTypeRequest>,
    ) -> Result<Response<CreateSchemaTypeResponse>, Status> {
        rpc_retrieval::create_schema_type(self, req).await
    }
    async fn list_ontology_classes(
        &self,
        req: Request<ListOntologyClassesRequest>,
    ) -> Result<Response<ListOntologyClassesResponse>, Status> {
        rpc_retrieval::list_ontology_classes(self, req).await
    }

    async fn get_ontology_class(
        &self,
        req: Request<GetOntologyClassRequest>,
    ) -> Result<Response<GetOntologyClassResponse>, Status> {
        rpc_retrieval::get_ontology_class(self, req).await
    }

    async fn create_ontology_class(
        &self,
        req: Request<CreateOntologyClassRequest>,
    ) -> Result<Response<CreateOntologyClassResponse>, Status> {
        rpc_retrieval::create_ontology_class(self, req).await
    }

    async fn delete_ontology_class(
        &self,
        req: Request<DeleteOntologyClassRequest>,
    ) -> Result<Response<DeleteOntologyClassResponse>, Status> {
        rpc_retrieval::delete_ontology_class(self, req).await
    }

    async fn list_ontology_relations(
        &self,
        req: Request<ListOntologyRelationsRequest>,
    ) -> Result<Response<ListOntologyRelationsResponse>, Status> {
        rpc_retrieval::list_ontology_relations(self, req).await
    }

    async fn get_ontology_relation(
        &self,
        req: Request<GetOntologyRelationRequest>,
    ) -> Result<Response<GetOntologyRelationResponse>, Status> {
        rpc_retrieval::get_ontology_relation(self, req).await
    }

    async fn create_ontology_relation(
        &self,
        req: Request<CreateOntologyRelationRequest>,
    ) -> Result<Response<CreateOntologyRelationResponse>, Status> {
        rpc_retrieval::create_ontology_relation(self, req).await
    }

    async fn delete_ontology_relation(
        &self,
        req: Request<DeleteOntologyRelationRequest>,
    ) -> Result<Response<DeleteOntologyRelationResponse>, Status> {
        rpc_retrieval::delete_ontology_relation(self, req).await
    }

    async fn put_governed_action_type(
        &self,
        req: Request<PutGovernedActionTypeRequest>,
    ) -> Result<Response<PutGovernedActionTypeResponse>, Status> {
        rpc_actions::put_governed_action_type(self, req).await
    }

    async fn get_governed_action_type(
        &self,
        req: Request<GetGovernedActionTypeRequest>,
    ) -> Result<Response<GetGovernedActionTypeResponse>, Status> {
        rpc_actions::get_governed_action_type(self, req).await
    }

    async fn list_governed_action_types(
        &self,
        req: Request<ListGovernedActionTypesRequest>,
    ) -> Result<Response<ListGovernedActionTypesResponse>, Status> {
        rpc_actions::list_governed_action_types(self, req).await
    }

    async fn set_governed_action_type_enabled(
        &self,
        req: Request<SetGovernedActionTypeEnabledRequest>,
    ) -> Result<Response<SetGovernedActionTypeEnabledResponse>, Status> {
        rpc_actions::set_governed_action_type_enabled(self, req).await
    }

    async fn submit_action_instance(
        &self,
        req: Request<SubmitActionInstanceRequest>,
    ) -> Result<Response<SubmitActionInstanceResponse>, Status> {
        rpc_actions::submit_action_instance(self, req).await
    }

    async fn decide_action_instance(
        &self,
        req: Request<DecideActionInstanceRequest>,
    ) -> Result<Response<DecideActionInstanceResponse>, Status> {
        rpc_actions::decide_action_instance(self, req).await
    }

    async fn put_action_binding(
        &self,
        req: Request<PutActionBindingRequest>,
    ) -> Result<Response<PutActionBindingResponse>, Status> {
        self.put_action_binding_definition(req).await
    }

    async fn run_action_binding(
        &self,
        req: Request<RunActionBindingRequest>,
    ) -> Result<Response<RunActionBindingResponse>, Status> {
        self.run_action_binding_once(req).await
    }

    async fn describe_object_action(
        &self,
        req: Request<DescribeObjectActionRequest>,
    ) -> Result<Response<DescribeObjectActionResponse>, Status> {
        rpc_actions::describe_object_action(self, req).await
    }

    async fn preview_object_action(
        &self,
        req: Request<PreviewObjectActionRequest>,
    ) -> Result<Response<PreviewObjectActionResponse>, Status> {
        rpc_actions::preview_object_action(self, req).await
    }

    async fn get_action_instance(
        &self,
        req: Request<GetActionInstanceRequest>,
    ) -> Result<Response<GetActionInstanceResponse>, Status> {
        rpc_actions::get_action_instance(self, req).await
    }

    async fn list_action_instances(
        &self,
        req: Request<ListActionInstancesRequest>,
    ) -> Result<Response<ListActionInstancesResponse>, Status> {
        rpc_actions::list_action_instances(self, req).await
    }

    async fn get_action_effect(
        &self,
        req: Request<GetActionEffectRequest>,
    ) -> Result<Response<GetActionEffectResponse>, Status> {
        rpc_actions::get_action_effect(self, req).await
    }

    async fn list_action_effects(
        &self,
        req: Request<ListActionEffectsRequest>,
    ) -> Result<Response<ListActionEffectsResponse>, Status> {
        rpc_actions::list_action_effects(self, req).await
    }

    async fn list_claimable_action_work(
        &self,
        req: Request<ListClaimableActionWorkRequest>,
    ) -> Result<Response<ListClaimableActionWorkResponse>, Status> {
        rpc_actions::list_claimable_action_work(self, req).await
    }

    async fn claim_action_work(
        &self,
        req: Request<ClaimActionWorkRequest>,
    ) -> Result<Response<ClaimActionWorkResponse>, Status> {
        rpc_actions::claim_action_work(self, req).await
    }

    async fn heartbeat_action_claim(
        &self,
        req: Request<HeartbeatActionClaimRequest>,
    ) -> Result<Response<HeartbeatActionClaimResponse>, Status> {
        rpc_actions::heartbeat_action_claim(self, req).await
    }

    async fn ack_action_work(
        &self,
        req: Request<AckActionWorkRequest>,
    ) -> Result<Response<AckActionWorkResponse>, Status> {
        rpc_actions::ack_action_work(self, req).await
    }

    async fn report_action_claim_event(
        &self,
        req: Request<ReportActionClaimEventRequest>,
    ) -> Result<Response<ReportActionClaimEventResponse>, Status> {
        rpc_actions::report_action_claim_event(self, req).await
    }

    async fn set_action_policy(
        &self,
        req: Request<SetActionPolicyRequest>,
    ) -> Result<Response<SetActionPolicyResponse>, Status> {
        rpc_actions::set_action_policy(self, req).await
    }

    async fn get_action_policy(
        &self,
        req: Request<GetActionPolicyRequest>,
    ) -> Result<Response<GetActionPolicyResponse>, Status> {
        rpc_actions::get_action_policy(self, req).await
    }

    async fn list_action_policies(
        &self,
        req: Request<ListActionPoliciesRequest>,
    ) -> Result<Response<ListActionPoliciesResponse>, Status> {
        rpc_actions::list_action_policies(self, req).await
    }

    async fn get_lineage(
        &self,
        req: Request<GetLineageRequest>,
    ) -> Result<Response<GetLineageResponse>, Status> {
        rpc_actions::get_lineage(self, req).await
    }
    async fn create_contention_scope(
        &self,
        req: Request<CreateContentionScopeRequest>,
    ) -> Result<Response<CreateContentionScopeResponse>, Status> {
        rpc_coordination::create_contention_scope(self, req).await
    }
    async fn update_contention_scope(
        &self,
        req: Request<UpdateContentionScopeRequest>,
    ) -> Result<Response<UpdateContentionScopeResponse>, Status> {
        rpc_coordination::update_contention_scope(self, req).await
    }
    async fn get_contention_scope(
        &self,
        req: Request<GetContentionScopeRequest>,
    ) -> Result<Response<GetContentionScopeResponse>, Status> {
        rpc_coordination::get_contention_scope(self, req).await
    }
    async fn list_contention_scopes(
        &self,
        req: Request<ListContentionScopesRequest>,
    ) -> Result<Response<ListContentionScopesResponse>, Status> {
        rpc_coordination::list_contention_scopes(self, req).await
    }
    async fn create_work_unit(
        &self,
        req: Request<CreateWorkUnitRequest>,
    ) -> Result<Response<CreateWorkUnitResponse>, Status> {
        rpc_coordination::create_work_unit(self, req).await
    }
    async fn get_work_unit(
        &self,
        req: Request<GetWorkUnitRequest>,
    ) -> Result<Response<GetWorkUnitResponse>, Status> {
        rpc_coordination::get_work_unit(self, req).await
    }
    async fn list_work_units(
        &self,
        req: Request<ListWorkUnitsRequest>,
    ) -> Result<Response<ListWorkUnitsResponse>, Status> {
        rpc_coordination::list_work_units(self, req).await
    }
    async fn try_admit_work_unit(
        &self,
        req: Request<TryAdmitWorkUnitRequest>,
    ) -> Result<Response<TryAdmitWorkUnitResponse>, Status> {
        rpc_coordination::try_admit_work_unit(self, req).await
    }
    async fn heartbeat_work_unit(
        &self,
        req: Request<HeartbeatWorkUnitRequest>,
    ) -> Result<Response<HeartbeatWorkUnitResponse>, Status> {
        rpc_coordination::heartbeat_work_unit(self, req).await
    }
    async fn complete_work_unit(
        &self,
        req: Request<CompleteWorkUnitRequest>,
    ) -> Result<Response<CompleteWorkUnitResponse>, Status> {
        rpc_coordination::complete_work_unit(self, req).await
    }
    async fn fail_work_unit(
        &self,
        req: Request<FailWorkUnitRequest>,
    ) -> Result<Response<FailWorkUnitResponse>, Status> {
        rpc_coordination::fail_work_unit(self, req).await
    }
    async fn cancel_work_unit(
        &self,
        req: Request<CancelWorkUnitRequest>,
    ) -> Result<Response<CancelWorkUnitResponse>, Status> {
        rpc_coordination::cancel_work_unit(self, req).await
    }
    async fn list_reservations(
        &self,
        req: Request<ListReservationsRequest>,
    ) -> Result<Response<ListReservationsResponse>, Status> {
        rpc_coordination::list_reservations(self, req).await
    }
    async fn list_run_events(
        &self,
        req: Request<ListRunEventsRequest>,
    ) -> Result<Response<ListRunEventsResponse>, Status> {
        rpc_coordination::list_run_events(self, req).await
    }
    async fn reconcile_work_units(
        &self,
        req: Request<ReconcileWorkUnitsRequest>,
    ) -> Result<Response<ReconcileWorkUnitsResponse>, Status> {
        rpc_coordination::reconcile_work_units(self, req).await
    }
    async fn create_function(
        &self,
        req: Request<CreateFunctionRequest>,
    ) -> Result<Response<CreateFunctionResponse>, Status> {
        rpc_data::create_function(self, req).await
    }
    async fn list_functions(
        &self,
        req: Request<ListFunctionsRequest>,
    ) -> Result<Response<ListFunctionsResponse>, Status> {
        rpc_data::list_functions(self, req).await
    }
    async fn invoke_function(
        &self,
        req: Request<InvokeFunctionRequest>,
    ) -> Result<Response<InvokeFunctionResponse>, Status> {
        rpc_data::invoke_function(self, req).await
    }
    async fn create_dataset(
        &self,
        req: Request<CreateDatasetRequest>,
    ) -> Result<Response<CreateDatasetResponse>, Status> {
        rpc_data::create_dataset(self, req).await
    }
    async fn put_governed_transform(
        &self,
        req: Request<PutGovernedTransformRequest>,
    ) -> Result<Response<PutGovernedTransformResponse>, Status> {
        rpc_data::put_governed_transform(self, req).await
    }
    async fn run_governed_transform(
        &self,
        req: Request<RunGovernedTransformRequest>,
    ) -> Result<Response<RunGovernedTransformResponse>, Status> {
        rpc_data::run_governed_transform(self, req).await
    }
    async fn get_governed_transform_run(
        &self,
        req: Request<GetGovernedTransformRunRequest>,
    ) -> Result<Response<GetGovernedTransformRunResponse>, Status> {
        rpc_data::get_governed_transform_run(self, req).await
    }
    async fn update_dataset(
        &self,
        req: Request<UpdateDatasetRequest>,
    ) -> Result<Response<UpdateDatasetResponse>, Status> {
        rpc_data::update_dataset(self, req).await
    }
    async fn list_datasets(
        &self,
        req: Request<ListDatasetsRequest>,
    ) -> Result<Response<ListDatasetsResponse>, Status> {
        rpc_data::list_datasets(self, req).await
    }
    async fn append_rows(
        &self,
        req: Request<AppendRowsRequest>,
    ) -> Result<Response<AppendRowsResponse>, Status> {
        rpc_data::append_rows(self, req).await
    }
    async fn query_rows(
        &self,
        req: Request<QueryRowsRequest>,
    ) -> Result<Response<QueryRowsResponse>, Status> {
        rpc_data::query_rows(self, req).await
    }
    async fn create_virtual_table(
        &self,
        req: Request<CreateVirtualTableRequest>,
    ) -> Result<Response<CreateVirtualTableResponse>, Status> {
        rpc_data::create_virtual_table(self, req).await
    }
    async fn list_virtual_tables(
        &self,
        req: Request<ListVirtualTablesRequest>,
    ) -> Result<Response<ListVirtualTablesResponse>, Status> {
        rpc_data::list_virtual_tables(self, req).await
    }
    async fn create_grant(
        &self,
        req: Request<CreateGrantRequest>,
    ) -> Result<Response<CreateGrantResponse>, Status> {
        rpc_data::create_grant(self, req).await
    }
    async fn delete_grant(
        &self,
        req: Request<DeleteGrantRequest>,
    ) -> Result<Response<DeleteGrantResponse>, Status> {
        rpc_data::delete_grant(self, req).await
    }
    async fn list_grants(
        &self,
        req: Request<ListGrantsRequest>,
    ) -> Result<Response<ListGrantsResponse>, Status> {
        rpc_data::list_grants(self, req).await
    }
    async fn check_access(
        &self,
        req: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        rpc_data::check_access(self, req).await
    }
    async fn ensure_team_namespace(
        &self,
        req: Request<EnsureTeamNamespaceRequest>,
    ) -> Result<Response<EnsureTeamNamespaceResponse>, Status> {
        rpc_data::ensure_team_namespace(self, req).await
    }
    async fn record_decision(
        &self,
        req: Request<RecordDecisionRequest>,
    ) -> Result<Response<RecordDecisionResponse>, Status> {
        rpc_data::record_decision(self, req).await
    }
    async fn list_decisions(
        &self,
        req: Request<ListDecisionsRequest>,
    ) -> Result<Response<ListDecisionsResponse>, Status> {
        rpc_data::list_decisions(self, req).await
    }
    async fn list_object_changes(
        &self,
        req: Request<ListObjectChangesRequest>,
    ) -> Result<Response<ListObjectChangesResponse>, Status> {
        rpc_data::list_object_changes(self, req).await
    }

    async fn get_attestation(
        &self,
        req: Request<GetAttestationRequest>,
    ) -> Result<Response<GetAttestationResponse>, Status> {
        rpc_data::get_attestation(self, req).await
    }

    async fn list_attestations(
        &self,
        req: Request<ListAttestationsRequest>,
    ) -> Result<Response<ListAttestationsResponse>, Status> {
        rpc_data::list_attestations(self, req).await
    }

    async fn verify_attestation(
        &self,
        req: Request<VerifyAttestationRequest>,
    ) -> Result<Response<VerifyAttestationResponse>, Status> {
        rpc_data::verify_attestation(self, req).await
    }

    async fn create_credential(
        &self,
        req: Request<CreateCredentialRequest>,
    ) -> Result<Response<CreateCredentialResponse>, Status> {
        rpc_data::create_credential(self, req).await
    }

    async fn rotate_credential(
        &self,
        req: Request<RotateCredentialRequest>,
    ) -> Result<Response<RotateCredentialResponse>, Status> {
        rpc_data::rotate_credential(self, req).await
    }

    async fn revoke_credential(
        &self,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        rpc_data::revoke_credential(self, req).await
    }

    async fn list_credentials(
        &self,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        rpc_data::list_credentials(self, req).await
    }

    async fn register_evidence_schema(
        &self,
        req: Request<RegisterEvidenceSchemaRequest>,
    ) -> Result<Response<RegisterEvidenceSchemaResponse>, Status> {
        rpc_data::register_evidence_schema(self, req).await
    }

    async fn list_evidence_adapters(
        &self,
        req: Request<crate::grpc::pb::sekai::ListEvidenceAdaptersRequest>,
    ) -> Result<Response<crate::grpc::pb::sekai::ListEvidenceAdaptersResponse>, Status> {
        rpc_data::list_evidence_adapters(self, req).await
    }

    async fn submit_evidence(
        &self,
        req: Request<SubmitEvidenceRequest>,
    ) -> Result<Response<SubmitEvidenceResponse>, Status> {
        rpc_data::submit_evidence(self, req).await
    }

    async fn get_evidence_submission(
        &self,
        req: Request<GetEvidenceSubmissionRequest>,
    ) -> Result<Response<GetEvidenceSubmissionResponse>, Status> {
        rpc_data::get_evidence_submission(self, req).await
    }

    async fn list_evidence_submissions(
        &self,
        req: Request<ListEvidenceSubmissionsRequest>,
    ) -> Result<Response<ListEvidenceSubmissionsResponse>, Status> {
        rpc_data::list_evidence_submissions(self, req).await
    }

    async fn get_provenance_report(
        &self,
        req: Request<GetProvenanceReportRequest>,
    ) -> Result<Response<GetProvenanceReportResponse>, Status> {
        rpc_data::get_provenance_report(self, req).await
    }
}

type RequestEnterpriseContext = crate::enterprise::AuthenticatedContext;

#[async_trait::async_trait]
impl KnowledgeWriter for SekaiServiceImpl {
    async fn write_knowledge(
        &self,
        request: &KnowledgeWriteRequest,
    ) -> Result<KnowledgeWriteOutcome, String> {
        scored_knowledge_admission::admit(self, request).await
    }
}

#[cfg(test)]
#[path = "sekai_service_tests.rs"]
mod tests;

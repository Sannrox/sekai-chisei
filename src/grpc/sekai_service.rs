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
#[path = "catalog_rpc.rs"]
mod catalog_rpc;
#[path = "computed_response.rs"]
mod computed_response;
#[path = "data_export_rpc.rs"]
mod data_export_rpc;
use data_export_rpc::{
    EXPORT_BATCH, ExportCaller, ExportStream, ExportWriter, PreparedExport, export_grantee,
    run_export,
};
#[path = "definition_bundle_apply_rpc.rs"]
mod definition_bundle_apply_rpc;
#[path = "definition_change_bundle_rpc.rs"]
mod definition_change_bundle_rpc;
#[path = "definition_consumer_impact.rs"]
mod definition_consumer_impact;
#[path = "embedding_spec_rpc.rs"]
mod embedding_spec_rpc;
#[path = "explain_value_rpc.rs"]
mod explain_value_rpc;
#[path = "fence_binding.rs"]
mod fence_binding;
#[path = "graph_explore_rpc.rs"]
mod graph_explore_rpc;
#[path = "media_upload_rpc.rs"]
mod media_upload_rpc;
#[path = "object_change_subscription.rs"]
mod object_change_subscription;
#[path = "object_comment_rpc.rs"]
mod object_comment_rpc;
#[path = "object_mutation_lifecycle.rs"]
mod object_mutation_lifecycle;
#[path = "object_set_query.rs"]
mod object_set_query;
#[path = "ontology_changelog_rpc.rs"]
mod ontology_changelog_rpc;
#[path = "ontology_definition_lifecycle.rs"]
mod ontology_definition_lifecycle;
#[path = "schema_definition_lifecycle.rs"]
mod schema_definition_lifecycle;
#[path = "scored_knowledge_admission.rs"]
mod scored_knowledge_admission;
#[path = "search_rpc.rs"]
mod search_rpc;
#[path = "sync_scope_rpc.rs"]
mod sync_scope_rpc;
#[cfg(test)]
use scored_knowledge_admission::{
    learning_id as scoring_learning_id, source_request_id as knowledge_source_request_id,
};
#[path = "sekai_service_db_work.rs"]
mod db_work;
#[path = "ontology_health_rpc.rs"]
mod ontology_health_rpc;
use db_work::db_work_limiter;
#[path = "semantic_retrieval_lifecycle.rs"]
mod semantic_retrieval_lifecycle;
#[path = "sekai_service_support_access.rs"]
mod support_access;
#[path = "trust_score_rpc.rs"]
mod trust_score_rpc;
use support_access::*;
#[path = "sekai_service_support_mapping.rs"]
mod support_mapping;
use support_mapping::*;
pub(crate) use support_mapping::{from_proto_grant, from_proto_obj, from_proto_schema_type};
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
#[path = "sekai_service_rpc_definition_package.rs"]
mod rpc_definition_package;
#[path = "sekai_service_rpc_definitions.rs"]
mod rpc_definitions;
#[path = "sekai_service_rpc_leases.rs"]
mod rpc_leases;
#[path = "sekai_service_rpc_objects.rs"]
mod rpc_objects;
#[path = "sekai_service_rpc_retrieval.rs"]
mod rpc_retrieval;
#[path = "sekai_service_rpc_service_principals.rs"]
mod rpc_service_principals;

use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::pin::Pin;
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
use sekai_domain::gateway_keys::hash_gateway_key;
use uuid::Uuid;

use self::catalog_invocation::CatalogInvocation;
use self::object_mutation_lifecycle::{
    GuardedCreateObjectRequest, GuardedDeleteObjectRequest, GuardedUpdateObjectRequest,
};
use self::schema_definition_lifecycle::{
    SchemaDefinitionLifecycle, map_schema_definition_lifecycle_error,
};

const REDACTED_VALUE: &str = "[redacted]";

#[derive(Clone)]
pub struct SekaiServiceImpl {
    pub(super) db: crate::db::store::SekaiStore,
    pub(super) security: Arc<SecurityChecker>,
    /// Bounds DB `spawn_blocking` work to the store connection pool.
    db_work: Arc<tokio::sync::Semaphore>,
    pub(super) schema_definitions: SchemaDefinitionLifecycle,
    pub(super) gateway_schema_principals: Vec<String>,
    /// Region/site pin from `SEKAI_SITE_ID` (default `"local"`).
    pub(super) site_id: String,
    pub(super) object_query_cursor_key: [u8; 32],
    pub(super) object_index_engine: crate::sekai::object_index_engine::ObjectIndexEngineKind,
    pub(super) object_index_dual_read: bool,
    pub(super) object_log_dual_read: crate::sekai::object_log::ObjectLogDualRead,
    pub(super) cross_store:
        Option<std::sync::Arc<crate::composition::cross_store_admission::CrossStoreAdmission>>,
    /// Signs runtime tokens for granted Action work claims; none issues none.
    pub(super) runtime_token_authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    pub(super) dry_run_host: Option<Arc<dyn crate::sekai::agent_dry_run::AgentDryRunHost>>,
    /// User grants intersect the agent ceiling at claim and apply (#1563).
    pub(super) enforce_agent_ceiling: bool,
    /// Embeds hybrid Search queries (#1582); none refuses hybrid mode.
    pub(super) embedding_route: Option<crate::composition::embedding_catch_up::EmbeddingRoute>,
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
        let db_work = db_work_limiter(&db);
        Self {
            db,
            security,
            db_work,
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
            runtime_token_authority: None,
            dry_run_host: None,
            embedding_route: None,
            enforce_agent_ceiling: false,
        }
    }

    /// Mint runtime tokens in Action work claim responses with `authority`,
    /// the same key the authentication boundary verifies them with.
    pub fn with_runtime_token_authority(
        mut self,
        authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    ) -> Self {
        self.runtime_token_authority = authority;
        self
    }

    pub fn with_agent_ceiling(mut self, enforce: bool) -> Self {
        self.enforce_agent_ceiling = enforce;
        self
    }

    pub fn with_dry_run_host(
        mut self,
        host: Option<Arc<dyn crate::sekai::agent_dry_run::AgentDryRunHost>>,
    ) -> Self {
        self.dry_run_host = host;
        self
    }

    pub fn with_embedding_route(
        mut self,
        route: crate::composition::embedding_catch_up::EmbeddingRoute,
    ) -> Self {
        self.embedding_route = Some(route);
        self
    }

    pub fn with_cross_store_admission(
        mut self,
        clerk: std::sync::Arc<crate::composition::cross_store_admission::CrossStoreAdmission>,
    ) -> Self {
        self.cross_store = Some(clerk);
        self
    }

    /// Budget and usage live on the Chisei store in a split layout.
    pub(crate) fn quota_runtime(&self) -> std::sync::Arc<crate::db::runtime_db::RuntimeDb> {
        self.cross_store
            .as_ref()
            .map(|clerk| clerk.chisei_runtime_arc())
            .unwrap_or_else(|| self.db.runtime_arc())
    }

    pub fn with_site_id(mut self, site_id: impl Into<String>) -> Self {
        self.site_id = site_id.into();
        self
    }
}

const DEFAULT_LIST_LIMIT: i32 = domain::DEFAULT_LIST_LIMIT;
const MAX_LIST_LIMIT: i32 = domain::MAX_LIST_LIMIT;

const MAX_GOVERNED_VISIBILITY_WORK: usize = 8_192;

#[tonic::async_trait]
impl SekaiService for SekaiServiceImpl {
    type ReadTransformRunInputsStream = Pin<
        Box<dyn futures_util::Stream<Item = Result<ReadTransformRunInputsResponse, Status>> + Send>,
    >;
    type ExportDatasetVersionStream = ExportStream;
    type ExportObjectSetStream = ExportStream;
    type FetchExportArtifactStream = ExportStream;

    async fn grant_namespace_export(
        &self,
        req: Request<GrantNamespaceExportRequest>,
    ) -> Result<Response<GrantNamespaceExportResponse>, Status> {
        self.grant_namespace_export_rpc(req).await
    }

    async fn revoke_namespace_export(
        &self,
        req: Request<RevokeNamespaceExportRequest>,
    ) -> Result<Response<RevokeNamespaceExportResponse>, Status> {
        self.revoke_namespace_export_rpc(req).await
    }

    async fn export_object_set(
        &self,
        req: Request<ExportObjectSetRequest>,
    ) -> Result<Response<Self::ExportObjectSetStream>, Status> {
        self.export_object_set_rpc(req).await
    }

    async fn export_dataset_version(
        &self,
        req: Request<ExportDatasetVersionRequest>,
    ) -> Result<Response<Self::ExportDatasetVersionStream>, Status> {
        self.export_dataset_version_rpc(req).await
    }

    async fn put_export_definition(
        &self,
        req: Request<PutExportDefinitionRequest>,
    ) -> Result<Response<PutExportDefinitionResponse>, Status> {
        self.put_export_definition_rpc(req).await
    }

    async fn get_export_definition(
        &self,
        req: Request<GetExportDefinitionRequest>,
    ) -> Result<Response<GetExportDefinitionResponse>, Status> {
        self.get_export_definition_rpc(req).await
    }

    async fn delete_export_definition(
        &self,
        req: Request<DeleteExportDefinitionRequest>,
    ) -> Result<Response<DeleteExportDefinitionResponse>, Status> {
        self.delete_export_definition_rpc(req).await
    }

    async fn run_export_definition(
        &self,
        req: Request<RunExportDefinitionRequest>,
    ) -> Result<Response<RunExportDefinitionResponse>, Status> {
        self.run_export_definition_rpc(req).await
    }

    async fn list_deliverable_export_artifacts(
        &self,
        req: Request<ListDeliverableExportArtifactsRequest>,
    ) -> Result<Response<ListDeliverableExportArtifactsResponse>, Status> {
        self.list_deliverable_export_artifacts_rpc(req).await
    }

    async fn fetch_export_artifact(
        &self,
        req: Request<FetchExportArtifactRequest>,
    ) -> Result<Response<Self::FetchExportArtifactStream>, Status> {
        self.fetch_export_artifact_rpc(req).await
    }

    async fn acknowledge_export_delivery(
        &self,
        req: Request<AcknowledgeExportDeliveryRequest>,
    ) -> Result<Response<AcknowledgeExportDeliveryResponse>, Status> {
        self.acknowledge_export_delivery_rpc(req).await
    }

    async fn get_export_receipt(
        &self,
        req: Request<GetExportReceiptRequest>,
    ) -> Result<Response<GetExportReceiptResponse>, Status> {
        self.get_export_receipt_rpc(req).await
    }

    async fn put_export_fingerprint_policy(
        &self,
        req: Request<PutExportFingerprintPolicyRequest>,
    ) -> Result<Response<PutExportFingerprintPolicyResponse>, Status> {
        self.put_export_fingerprint_policy_rpc(req).await
    }

    async fn get_export_fingerprint_policy(
        &self,
        req: Request<GetExportFingerprintPolicyRequest>,
    ) -> Result<Response<GetExportFingerprintPolicyResponse>, Status> {
        self.get_export_fingerprint_policy_rpc(req).await
    }

    async fn trace_export(
        &self,
        req: Request<TraceExportRequest>,
    ) -> Result<Response<TraceExportResponse>, Status> {
        self.trace_export_rpc(req).await
    }

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

    async fn list_source_batch_transactions(
        &self,
        req: Request<ListSourceBatchTransactionsRequest>,
    ) -> Result<Response<ListSourceBatchTransactionsResponse>, Status> {
        rpc_leases::list_source_batch_transactions(self, req).await
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

    async fn get_definition_member(
        &self,
        req: Request<GetDefinitionMemberRequest>,
    ) -> Result<Response<GetDefinitionMemberResponse>, Status> {
        rpc_definitions::get_definition_member(self, req).await
    }

    async fn put_definition_certification(
        &self,
        req: Request<PutDefinitionCertificationRequest>,
    ) -> Result<Response<PutDefinitionCertificationResponse>, Status> {
        rpc_definitions::put_definition_certification(self, req).await
    }

    async fn get_definition_certification_gate(
        &self,
        req: Request<GetDefinitionCertificationGateRequest>,
    ) -> Result<Response<GetDefinitionCertificationGateResponse>, Status> {
        rpc_definitions::get_definition_certification_gate(self, req).await
    }

    async fn dry_run_agent(
        &self,
        req: Request<DryRunAgentRequest>,
    ) -> Result<Response<DryRunAgentResponse>, Status> {
        rpc_definitions::dry_run_agent(self, req).await
    }

    async fn run_agent_shadow(
        &self,
        req: Request<RunAgentShadowRequest>,
    ) -> Result<Response<RunAgentShadowResponse>, Status> {
        rpc_definitions::run_agent_shadow(self, req).await
    }

    async fn get_agent_shadow_report(
        &self,
        req: Request<GetAgentShadowReportRequest>,
    ) -> Result<Response<GetAgentShadowReportResponse>, Status> {
        rpc_definitions::get_agent_shadow_report(self, req).await
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

    async fn list_published_definition_revisions(
        &self,
        req: Request<ListPublishedDefinitionRevisionsRequest>,
    ) -> Result<Response<ListPublishedDefinitionRevisionsResponse>, Status> {
        rpc_definitions::list_published_definition_revisions(self, req).await
    }

    async fn propose_definition_rollback(
        &self,
        req: Request<ProposeDefinitionRollbackRequest>,
    ) -> Result<Response<ProposeDefinitionRollbackResponse>, Status> {
        rpc_definitions::propose_definition_rollback(self, req).await
    }

    async fn export_definition_package(
        &self,
        req: Request<ExportDefinitionPackageRequest>,
    ) -> Result<Response<ExportDefinitionPackageResponse>, Status> {
        rpc_definition_package::export_definition_package(self, req).await
    }

    async fn import_definition_package(
        &self,
        req: Request<ImportDefinitionPackageRequest>,
    ) -> Result<Response<ImportDefinitionPackageResponse>, Status> {
        rpc_definition_package::import_definition_package(self, req).await
    }

    async fn compare_definition_revisions(
        &self,
        req: Request<CompareDefinitionRevisionsRequest>,
    ) -> Result<Response<CompareDefinitionRevisionsResponse>, Status> {
        rpc_definitions::compare_definition_revisions(self, req).await
    }

    async fn get_ontology_changelog(
        &self,
        req: Request<GetOntologyChangelogRequest>,
    ) -> Result<Response<GetOntologyChangelogResponse>, Status> {
        ontology_changelog_rpc::get_ontology_changelog(self, req).await
    }

    async fn report_definition_consumer_impact(
        &self,
        req: Request<ReportDefinitionConsumerImpactRequest>,
    ) -> Result<Response<ReportDefinitionConsumerImpactResponse>, Status> {
        rpc_definitions::report_definition_consumer_impact(self, req).await
    }

    async fn get_ontology_lint_report(
        &self,
        req: Request<GetOntologyLintReportRequest>,
    ) -> Result<Response<GetOntologyLintReportResponse>, Status> {
        rpc_definitions::get_ontology_lint_report(self, req).await
    }

    async fn get_ontology_health(
        &self,
        req: Request<GetOntologyHealthRequest>,
    ) -> Result<Response<GetOntologyHealthResponse>, Status> {
        ontology_health_rpc::get_ontology_health(self, req).await
    }

    async fn record_ontology_health_snapshot(
        &self,
        req: Request<RecordOntologyHealthSnapshotRequest>,
    ) -> Result<Response<RecordOntologyHealthSnapshotResponse>, Status> {
        ontology_health_rpc::record_ontology_health_snapshot(self, req).await
    }

    async fn list_ontology_health_trend(
        &self,
        req: Request<ListOntologyHealthTrendRequest>,
    ) -> Result<Response<ListOntologyHealthTrendResponse>, Status> {
        ontology_health_rpc::list_ontology_health_trend(self, req).await
    }

    async fn generate_definition_change_bundle(
        &self,
        req: Request<GenerateDefinitionChangeBundleRequest>,
    ) -> Result<Response<GenerateDefinitionChangeBundleResponse>, Status> {
        self.generate_visible_definition_change_bundle(req).await
    }

    async fn dry_run_definition_change_bundle(
        &self,
        req: Request<DryRunDefinitionChangeBundleRequest>,
    ) -> Result<Response<DryRunDefinitionChangeBundleResponse>, Status> {
        rpc_data::dry_run_definition_change_bundle(self, req).await
    }

    async fn apply_definition_change_bundle(
        &self,
        req: Request<ApplyDefinitionChangeBundleRequest>,
    ) -> Result<Response<ApplyDefinitionChangeBundleResponse>, Status> {
        definition_bundle_apply_rpc::apply_definition_change_bundle(self, req).await
    }

    async fn get_definition_bundle_apply(
        &self,
        req: Request<GetDefinitionBundleApplyRequest>,
    ) -> Result<Response<GetDefinitionBundleApplyResponse>, Status> {
        definition_bundle_apply_rpc::get_definition_bundle_apply(self, req).await
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
    async fn search(
        &self,
        req: Request<SearchRequest>,
    ) -> Result<Response<SearchResponse>, Status> {
        search_rpc::search(self, req).await
    }
    async fn get_search_index_status(
        &self,
        req: Request<GetSearchIndexStatusRequest>,
    ) -> Result<Response<GetSearchIndexStatusResponse>, Status> {
        search_rpc::get_search_index_status(self, req).await
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

    async fn put_embedding_spec(
        &self,
        req: Request<PutEmbeddingSpecRequest>,
    ) -> Result<Response<PutEmbeddingSpecResponse>, Status> {
        embedding_spec_rpc::put_embedding_spec(self, req).await
    }

    async fn list_embedding_specs(
        &self,
        req: Request<ListEmbeddingSpecsRequest>,
    ) -> Result<Response<ListEmbeddingSpecsResponse>, Status> {
        embedding_spec_rpc::list_embedding_specs(self, req).await
    }

    async fn delete_embedding_spec(
        &self,
        req: Request<DeleteEmbeddingSpecRequest>,
    ) -> Result<Response<DeleteEmbeddingSpecResponse>, Status> {
        embedding_spec_rpc::delete_embedding_spec(self, req).await
    }

    async fn simulate_object_policy_change(
        &self,
        req: Request<SimulateObjectPolicyChangeRequest>,
    ) -> Result<Response<SimulateObjectPolicyChangeResponse>, Status> {
        rpc_objects::simulate_object_policy_change(self, req).await
    }

    async fn query_counterfactual_view(
        &self,
        req: Request<QueryCounterfactualViewRequest>,
    ) -> Result<Response<QueryCounterfactualViewResponse>, Status> {
        rpc_objects::query_counterfactual_view(self, req).await
    }

    async fn put_trust_scoring_rule(
        &self,
        req: Request<PutTrustScoringRuleRequest>,
    ) -> Result<Response<PutTrustScoringRuleResponse>, Status> {
        trust_score_rpc::put_trust_scoring_rule(self, req).await
    }

    async fn get_trust_scoring_rule(
        &self,
        req: Request<GetTrustScoringRuleRequest>,
    ) -> Result<Response<GetTrustScoringRuleResponse>, Status> {
        trust_score_rpc::get_trust_scoring_rule(self, req).await
    }

    async fn score_object_trust(
        &self,
        req: Request<ScoreObjectTrustRequest>,
    ) -> Result<Response<ScoreObjectTrustResponse>, Status> {
        trust_score_rpc::score_object_trust(self, req).await
    }

    async fn begin_media_upload(
        &self,
        req: Request<BeginMediaUploadRequest>,
    ) -> Result<Response<MediaUploadStatus>, Status> {
        media_upload_rpc::begin_media_upload(self, req).await
    }

    async fn upload_media_chunk(
        &self,
        req: Request<UploadMediaChunkRequest>,
    ) -> Result<Response<MediaUploadStatus>, Status> {
        media_upload_rpc::upload_media_chunk(self, req).await
    }

    async fn complete_media_upload(
        &self,
        req: Request<CompleteMediaUploadRequest>,
    ) -> Result<Response<MediaUploadStatus>, Status> {
        media_upload_rpc::complete_media_upload(self, req).await
    }

    async fn get_media_upload(
        &self,
        req: Request<GetMediaUploadRequest>,
    ) -> Result<Response<MediaUploadStatus>, Status> {
        media_upload_rpc::get_media_upload(self, req).await
    }

    async fn read_media(
        &self,
        req: Request<ReadMediaRequest>,
    ) -> Result<Response<ReadMediaResponse>, Status> {
        media_upload_rpc::read_media(self, req).await
    }

    async fn put_sync_scope(
        &self,
        req: Request<PutSyncScopeRequest>,
    ) -> Result<Response<SyncScopeResponse>, Status> {
        sync_scope_rpc::put_sync_scope(self, req).await
    }

    async fn read_sync_snapshot(
        &self,
        req: Request<ReadSyncSnapshotRequest>,
    ) -> Result<Response<ReadSyncSnapshotResponse>, Status> {
        sync_scope_rpc::read_sync_snapshot(self, req).await
    }

    async fn read_sync_deltas(
        &self,
        req: Request<ReadSyncDeltasRequest>,
    ) -> Result<Response<ReadSyncDeltasResponse>, Status> {
        sync_scope_rpc::read_sync_deltas(self, req).await
    }

    async fn create_object_comment(
        &self,
        req: Request<CreateObjectCommentRequest>,
    ) -> Result<Response<CreateObjectCommentResponse>, Status> {
        object_comment_rpc::create_object_comment(self, req).await
    }

    async fn update_object_comment(
        &self,
        req: Request<UpdateObjectCommentRequest>,
    ) -> Result<Response<UpdateObjectCommentResponse>, Status> {
        object_comment_rpc::update_object_comment(self, req).await
    }

    async fn list_object_comments(
        &self,
        req: Request<ListObjectCommentsRequest>,
    ) -> Result<Response<ListObjectCommentsResponse>, Status> {
        object_comment_rpc::list_object_comments(self, req).await
    }

    async fn list_comment_mentions(
        &self,
        req: Request<ListCommentMentionsRequest>,
    ) -> Result<Response<ListCommentMentionsResponse>, Status> {
        object_comment_rpc::list_comment_mentions(self, req).await
    }

    async fn register_catalog_entry(
        &self,
        req: Request<RegisterCatalogEntryRequest>,
    ) -> Result<Response<RegisterCatalogEntryResponse>, Status> {
        catalog_rpc::register_catalog_entry(self, req).await
    }

    async fn get_catalog_entry_lineage(
        &self,
        req: Request<GetCatalogEntryLineageRequest>,
    ) -> Result<Response<GetCatalogEntryLineageResponse>, Status> {
        catalog_rpc::get_catalog_entry_lineage(self, req).await
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
    async fn expand_neighborhood(
        &self,
        req: Request<ExpandNeighborhoodRequest>,
    ) -> Result<Response<ExpandNeighborhoodResponse>, Status> {
        graph_explore_rpc::expand_neighborhood(self, req).await
    }
    async fn find_paths(
        &self,
        req: Request<FindPathsRequest>,
    ) -> Result<Response<FindPathsResponse>, Status> {
        graph_explore_rpc::find_paths(self, req).await
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

    async fn put_fence_binding(
        &self,
        req: Request<PutFenceBindingRequest>,
    ) -> Result<Response<PutFenceBindingResponse>, Status> {
        self.put_fence_binding_definition(req).await
    }

    async fn run_fence_binding(
        &self,
        req: Request<RunFenceBindingRequest>,
    ) -> Result<Response<RunFenceBindingResponse>, Status> {
        self.run_fence_binding_once(req).await
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

    async fn create_plan_intent(
        &self,
        req: Request<CreatePlanIntentRequest>,
    ) -> Result<Response<CreatePlanIntentResponse>, Status> {
        rpc_actions::create_plan_intent(self, req).await
    }

    async fn propose_plan(
        &self,
        req: Request<ProposePlanRequest>,
    ) -> Result<Response<ProposePlanResponse>, Status> {
        rpc_actions::propose_plan(self, req).await
    }

    async fn simulate_plan(
        &self,
        req: Request<SimulatePlanRequest>,
    ) -> Result<Response<SimulatePlanResponse>, Status> {
        rpc_actions::simulate_plan(self, req).await
    }

    async fn get_plan(
        &self,
        req: Request<GetPlanRequest>,
    ) -> Result<Response<GetPlanResponse>, Status> {
        rpc_actions::get_plan(self, req).await
    }

    async fn submit_plan_review(
        &self,
        req: Request<SubmitPlanReviewRequest>,
    ) -> Result<Response<SubmitPlanReviewResponse>, Status> {
        rpc_actions::submit_plan_review(self, req).await
    }

    async fn decide_plan_review(
        &self,
        req: Request<DecidePlanReviewRequest>,
    ) -> Result<Response<DecidePlanReviewResponse>, Status> {
        rpc_actions::decide_plan_review(self, req).await
    }

    async fn execute_action_plan(
        &self,
        req: Request<ExecuteActionPlanRequest>,
    ) -> Result<Response<ExecuteActionPlanResponse>, Status> {
        rpc_actions::execute_action_plan(self, req).await
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

    async fn put_service_principal(
        &self,
        req: Request<PutServicePrincipalRequest>,
    ) -> Result<Response<PutServicePrincipalResponse>, Status> {
        rpc_service_principals::put_service_principal(self, req).await
    }

    async fn get_service_principal(
        &self,
        req: Request<GetServicePrincipalRequest>,
    ) -> Result<Response<GetServicePrincipalResponse>, Status> {
        rpc_service_principals::get_service_principal(self, req).await
    }

    async fn delete_service_principal(
        &self,
        req: Request<DeleteServicePrincipalRequest>,
    ) -> Result<Response<DeleteServicePrincipalResponse>, Status> {
        rpc_service_principals::delete_service_principal(self, req).await
    }

    async fn issue_service_principal_token(
        &self,
        req: Request<IssueServicePrincipalTokenRequest>,
    ) -> Result<Response<IssueServicePrincipalTokenResponse>, Status> {
        rpc_service_principals::issue_service_principal_token(self, req).await
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
    async fn preview_governed_transform(
        &self,
        req: Request<PreviewGovernedTransformRequest>,
    ) -> Result<Response<PreviewGovernedTransformResponse>, Status> {
        rpc_data::preview_governed_transform(self, req).await
    }
    async fn get_governed_transform_run(
        &self,
        req: Request<GetGovernedTransformRunRequest>,
    ) -> Result<Response<GetGovernedTransformRunResponse>, Status> {
        rpc_data::get_governed_transform_run(self, req).await
    }
    async fn list_governed_transforms(
        &self,
        req: Request<ListGovernedTransformsRequest>,
    ) -> Result<Response<ListGovernedTransformsResponse>, Status> {
        rpc_data::list_governed_transforms(self, req).await
    }
    async fn list_governed_transform_runs(
        &self,
        req: Request<ListGovernedTransformRunsRequest>,
    ) -> Result<Response<ListGovernedTransformRunsResponse>, Status> {
        rpc_data::list_governed_transform_runs(self, req).await
    }
    async fn list_claimable_transform_work(
        &self,
        req: Request<ListClaimableTransformWorkRequest>,
    ) -> Result<Response<ListClaimableTransformWorkResponse>, Status> {
        rpc_data::list_claimable_transform_work(self, req).await
    }
    async fn claim_transform_work(
        &self,
        req: Request<ClaimTransformWorkRequest>,
    ) -> Result<Response<ClaimTransformWorkResponse>, Status> {
        rpc_data::claim_transform_work(self, req).await
    }
    async fn heartbeat_transform_claim(
        &self,
        req: Request<HeartbeatTransformClaimRequest>,
    ) -> Result<Response<HeartbeatTransformClaimResponse>, Status> {
        rpc_data::heartbeat_transform_claim(self, req).await
    }
    async fn read_transform_run_inputs(
        &self,
        req: Request<ReadTransformRunInputsRequest>,
    ) -> Result<Response<Self::ReadTransformRunInputsStream>, Status> {
        rpc_data::read_transform_run_inputs(self, req).await
    }
    async fn write_transform_run_result(
        &self,
        req: Request<WriteTransformRunResultRequest>,
    ) -> Result<Response<WriteTransformRunResultResponse>, Status> {
        rpc_data::write_transform_run_result(self, req).await
    }
    async fn apply_streaming_transform_batch(
        &self,
        req: Request<ApplyStreamingTransformBatchRequest>,
    ) -> Result<Response<ApplyStreamingTransformBatchResponse>, Status> {
        rpc_data::apply_streaming_transform_batch(self, req).await
    }
    async fn tick_governed_transforms(
        &self,
        req: Request<TickGovernedTransformsRequest>,
    ) -> Result<Response<TickGovernedTransformsResponse>, Status> {
        rpc_data::tick_governed_transforms(self, req).await
    }
    async fn get_transform_output_state(
        &self,
        req: Request<GetTransformOutputStateRequest>,
    ) -> Result<Response<GetTransformOutputStateResponse>, Status> {
        rpc_data::get_transform_output_state(self, req).await
    }
    async fn cancel_governed_transform_run(
        &self,
        req: Request<CancelGovernedTransformRunRequest>,
    ) -> Result<Response<CancelGovernedTransformRunResponse>, Status> {
        rpc_data::cancel_governed_transform_run(self, req).await
    }
    async fn admit_governed_document(
        &self,
        req: Request<AdmitGovernedDocumentRequest>,
    ) -> Result<Response<AdmitGovernedDocumentResponse>, Status> {
        rpc_data::admit_governed_document(self, req).await
    }
    async fn attach_governed_document_rendition(
        &self,
        req: Request<AttachGovernedDocumentRenditionRequest>,
    ) -> Result<Response<AttachGovernedDocumentRenditionResponse>, Status> {
        rpc_data::attach_governed_document_rendition(self, req).await
    }
    async fn get_governed_document(
        &self,
        req: Request<GetGovernedDocumentRequest>,
    ) -> Result<Response<GetGovernedDocumentResponse>, Status> {
        rpc_data::get_governed_document(self, req).await
    }
    async fn hold_governed_document(
        &self,
        req: Request<HoldGovernedDocumentRequest>,
    ) -> Result<Response<HoldGovernedDocumentResponse>, Status> {
        rpc_data::hold_governed_document(self, req).await
    }
    async fn release_governed_document_hold(
        &self,
        req: Request<ReleaseGovernedDocumentHoldRequest>,
    ) -> Result<Response<ReleaseGovernedDocumentHoldResponse>, Status> {
        rpc_data::release_governed_document_hold(self, req).await
    }
    async fn expire_governed_document(
        &self,
        req: Request<ExpireGovernedDocumentRequest>,
    ) -> Result<Response<ExpireGovernedDocumentResponse>, Status> {
        rpc_data::expire_governed_document(self, req).await
    }
    async fn delete_governed_document(
        &self,
        req: Request<DeleteGovernedDocumentRequest>,
    ) -> Result<Response<DeleteGovernedDocumentResponse>, Status> {
        rpc_data::delete_governed_document(self, req).await
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
    async fn list_dataset_versions(
        &self,
        req: Request<ListDatasetVersionsRequest>,
    ) -> Result<Response<ListDatasetVersionsResponse>, Status> {
        rpc_data::list_dataset_versions(self, req).await
    }
    async fn get_dataset_version(
        &self,
        req: Request<GetDatasetVersionRequest>,
    ) -> Result<Response<GetDatasetVersionResponse>, Status> {
        rpc_data::get_dataset_version(self, req).await
    }
    async fn create_dataset_branch(
        &self,
        req: Request<CreateDatasetBranchRequest>,
    ) -> Result<Response<CreateDatasetBranchResponse>, Status> {
        rpc_data::create_dataset_branch(self, req).await
    }
    async fn list_dataset_branches(
        &self,
        req: Request<ListDatasetBranchesRequest>,
    ) -> Result<Response<ListDatasetBranchesResponse>, Status> {
        rpc_data::list_dataset_branches(self, req).await
    }
    async fn delete_dataset_branch(
        &self,
        req: Request<DeleteDatasetBranchRequest>,
    ) -> Result<Response<DeleteDatasetBranchResponse>, Status> {
        rpc_data::delete_dataset_branch(self, req).await
    }
    async fn compare_dataset_branch(
        &self,
        req: Request<CompareDatasetBranchRequest>,
    ) -> Result<Response<CompareDatasetBranchResponse>, Status> {
        rpc_data::compare_dataset_branch(self, req).await
    }
    async fn propose_dataset_branch_merge(
        &self,
        req: Request<ProposeDatasetBranchMergeRequest>,
    ) -> Result<Response<ProposeDatasetBranchMergeResponse>, Status> {
        rpc_data::propose_dataset_branch_merge(self, req).await
    }
    async fn merge_dataset_branch(
        &self,
        req: Request<MergeDatasetBranchRequest>,
    ) -> Result<Response<MergeDatasetBranchResponse>, Status> {
        rpc_data::merge_dataset_branch(self, req).await
    }
    async fn run_governed_transform_on_branch(
        &self,
        req: Request<RunGovernedTransformOnBranchRequest>,
    ) -> Result<Response<RunGovernedTransformOnBranchResponse>, Status> {
        rpc_data::run_governed_transform_on_branch(self, req).await
    }
    async fn replay_governed_transform(
        &self,
        req: Request<ReplayGovernedTransformRequest>,
    ) -> Result<Response<ReplayGovernedTransformResponse>, Status> {
        rpc_data::replay_governed_transform(self, req).await
    }
    async fn get_transform_replay(
        &self,
        req: Request<GetTransformReplayRequest>,
    ) -> Result<Response<GetTransformReplayResponse>, Status> {
        rpc_data::get_transform_replay(self, req).await
    }
    async fn rollback_dataset(
        &self,
        req: Request<RollbackDatasetRequest>,
    ) -> Result<Response<RollbackDatasetResponse>, Status> {
        rpc_data::rollback_dataset(self, req).await
    }
    async fn put_dataset_health_check(
        &self,
        req: Request<PutDatasetHealthCheckRequest>,
    ) -> Result<Response<PutDatasetHealthCheckResponse>, Status> {
        rpc_data::put_dataset_health_check(self, req).await
    }
    async fn list_dataset_health_checks(
        &self,
        req: Request<ListDatasetHealthChecksRequest>,
    ) -> Result<Response<ListDatasetHealthChecksResponse>, Status> {
        rpc_data::list_dataset_health_checks(self, req).await
    }
    async fn list_dataset_health_results(
        &self,
        req: Request<ListDatasetHealthResultsRequest>,
    ) -> Result<Response<ListDatasetHealthResultsResponse>, Status> {
        rpc_data::list_dataset_health_results(self, req).await
    }
    async fn run_dataset_health_checks(
        &self,
        req: Request<RunDatasetHealthChecksRequest>,
    ) -> Result<Response<RunDatasetHealthChecksResponse>, Status> {
        rpc_data::run_dataset_health_checks(self, req).await
    }
    async fn list_dataset_alerts(
        &self,
        req: Request<ListDatasetAlertsRequest>,
    ) -> Result<Response<ListDatasetAlertsResponse>, Status> {
        rpc_data::list_dataset_alerts(self, req).await
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
    async fn set_write_freeze(
        &self,
        req: Request<SetWriteFreezeRequest>,
    ) -> Result<Response<SetWriteFreezeResponse>, Status> {
        rpc_data::set_write_freeze(self, req).await
    }
    async fn list_write_freezes(
        &self,
        req: Request<ListWriteFreezesRequest>,
    ) -> Result<Response<ListWriteFreezesResponse>, Status> {
        rpc_data::list_write_freezes(self, req).await
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

    async fn explain_value(
        &self,
        req: Request<ExplainValueRequest>,
    ) -> Result<Response<ExplainValueResponse>, Status> {
        explain_value_rpc::explain_value(self, req).await
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

#[cfg(test)]
#[path = "sekai_service_tests.rs"]
mod tests;

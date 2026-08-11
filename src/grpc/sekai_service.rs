#![allow(clippy::result_large_err, clippy::collapsible_if, clippy::manual_clamp)]

#[path = "action_approval_execution.rs"]
mod action_approval_execution;
#[path = "action_execution.rs"]
mod action_execution;
#[path = "catalog_invocation.rs"]
mod catalog_invocation;
#[path = "object_mutation_lifecycle.rs"]
mod object_mutation_lifecycle;
#[path = "ontology_definition_lifecycle.rs"]
mod ontology_definition_lifecycle;
#[path = "semantic_retrieval_lifecycle.rs"]
mod semantic_retrieval_lifecycle;

use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

use super::pb::sekai::sekai_service_server::SekaiService;
use super::pb::sekai::*;
use super::visible_page::{VisiblePageError, scan_visible_page};
use crate::chisei::epistemic_descriptor::{
    EPISTEMIC_DESCRIPTOR_VERSION, EpistemicDescriptor as DomainEpistemicDescriptor,
};
#[cfg(test)]
use crate::chisei::receipt::ReceiptEventKind;
use crate::chisei::scoring::{KnowledgeWriteOutcome, KnowledgeWriteRequest, KnowledgeWriter};
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain;
use crate::gateway_keys::hash_gateway_key;
use crate::sekai::action::{self, ActionExecutor, RiskClass};
use crate::sekai::action_approval;
use crate::sekai::action_approval_lifecycle::{
    ActionApprovalLifecycle, ApprovalLifecycleError, DenyAction as DenyActionCommand,
};
use crate::sekai::action_lifecycle::ActionLimitExceeded;
use crate::sekai::action_policy::{self, ActionDecision};
use crate::sekai::action_work_lifecycle::{
    AckActionWork as AckActionWorkCommand, ActionWorkLifecycle, ActionWorkLifecycleError,
    ClaimActionWork as ClaimActionWorkCommand, HeartbeatActionClaim as HeartbeatActionClaimCommand,
    ReportActionClaimEvent as ReportActionClaimEventCommand,
};
use crate::sekai::attestation;
use crate::sekai::capability;
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
use crate::sekai::schema::{self, SchemaRegistry};
use crate::sekai::security::SecurityChecker;
use crate::sekai::work_unit_lifecycle::{
    AdmitWorkUnit, TransitionWorkUnit, WorkUnitLifecycle, WorkUnitLifecycleError,
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

const REDACTED_VALUE: &str = "[redacted]";

pub struct SekaiServiceImpl {
    db: Arc<RuntimeDb>,
    actions: Arc<RwLock<ActionExecutor>>,
    action_type_mutation: Arc<Mutex<()>>,
    security: Arc<SecurityChecker>,
    schema: Arc<RwLock<SchemaRegistry>>,
    schema_unavailable_error: Arc<RwLock<Option<String>>>,
    schema_load_errors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    budget: Option<Arc<crate::chisei::budget::BudgetTracker>>,
    gateway_schema_principals: Vec<String>,
    /// Region/site pin from `SEKAI_SITE_ID` (default `"local"`).
    site_id: String,
}

impl SekaiServiceImpl {
    pub fn new(db: Arc<RuntimeDb>) -> Self {
        Self::new_with_gateway_schema_principals(db, Vec::new())
    }

    pub fn new_with_gateway_schema_principals(
        db: Arc<RuntimeDb>,
        gateway_schema_principals: Vec<String>,
    ) -> Self {
        let security = Arc::new(SecurityChecker::new());
        let grants = db.list_all_grants().unwrap_or_default();
        security.load(&grants);
        let action_types = match db.list_action_types() {
            Ok(action_types) => action_types,
            Err(error) => {
                tracing::error!(%error, "failed to load action types");
                Vec::new()
            }
        };
        let actions = match ActionExecutor::from_action_types(action_types) {
            Ok(actions) => actions,
            Err(error) => {
                tracing::error!(%error, "failed to initialize action registry");
                ActionExecutor::new()
            }
        };
        let (types, schema_unavailable_error, schema_load_errors) =
            match db.list_object_types_with_errors() {
                Ok((types, errors)) => {
                    for (kind, error) in &errors {
                        tracing::error!(kind, %error, "failed to load schema type");
                    }
                    (types, None, errors)
                }
                Err(error) => {
                    tracing::error!(%error, "failed to load schema types");
                    (Vec::new(), Some(error), std::collections::HashMap::new())
                }
            };
        let interfaces = match db.list_interfaces() {
            Ok(interfaces) => interfaces,
            Err(error) => {
                tracing::error!(%error, "failed to load interfaces");
                Vec::new()
            }
        };
        let registry = SchemaRegistry::from_types_and_interfaces(types, interfaces);
        let schema = Arc::new(RwLock::new(registry));
        Self {
            db,
            actions: Arc::new(RwLock::new(actions)),
            action_type_mutation: Arc::new(Mutex::new(())),
            security,
            schema,
            schema_unavailable_error: Arc::new(RwLock::new(schema_unavailable_error)),
            schema_load_errors: Arc::new(RwLock::new(schema_load_errors)),
            budget: None,
            gateway_schema_principals,
            site_id: crate::sekai::lease::DEFAULT_SITE_ID.into(),
        }
    }

    /// Construct sharing a chisei budget tracker so governed actions can be
    /// metered against action-class budgets (Plan 9, Phase C).
    pub fn with_budget(
        db: Arc<RuntimeDb>,
        budget: Arc<crate::chisei::budget::BudgetTracker>,
    ) -> Self {
        let mut svc = Self::new(db);
        svc.budget = Some(budget);
        svc
    }

    pub fn with_budget_and_gateway_schema_principals(
        db: Arc<RuntimeDb>,
        budget: Arc<crate::chisei::budget::BudgetTracker>,
        gateway_schema_principals: Vec<String>,
    ) -> Self {
        let mut svc = Self::new_with_gateway_schema_principals(db, gateway_schema_principals);
        svc.budget = Some(budget);
        svc
    }

    pub fn with_site_id(mut self, site_id: impl Into<String>) -> Self {
        self.site_id = site_id.into();
        self
    }

    /// Reload the graph-action registry from durable storage before a request
    /// uses it. Action definitions are shared across service instances, so a
    /// process-local registration update cannot be the source of truth.
    fn refresh_action_registry(&self) -> Result<(), Status> {
        let _mutation = self
            .action_type_mutation
            .lock()
            .map_err(|_| Status::internal("action registry mutation unavailable"))?;
        let action_types = self.db.list_action_types().map_err(Status::internal)?;
        let refreshed = ActionExecutor::from_action_types(action_types)
            .map_err(|error| Status::internal(format!("action registry unavailable: {error}")))?;
        *self
            .actions
            .write()
            .map_err(|_| Status::internal("action registry unavailable"))? = refreshed;
        Ok(())
    }

    fn require_schema_kind_loaded(&self, kind: &str) -> Result<(), Status> {
        self.recover_schema_registry()?;
        let errors = self
            .schema_load_errors
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        if let Some(error) = errors.get(kind) {
            return Err(Status::internal(format!(
                "schema type {kind} unavailable: {error}"
            )));
        }
        Ok(())
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
                &self.db,
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
            &self.db,
            operation_id.clone(),
            namespace,
            actor,
            capability_name,
            catalog_version,
        )?;
        Ok(Some((operation_id, invocation)))
    }

    fn discoverable_capabilities(
        &self,
        namespace: &str,
        principals: &[String],
    ) -> Result<Vec<CapabilityEntry>, Status> {
        self.refresh_action_registry()?;
        check_team_namespace(&self.db, principals, namespace, false)
            .map_err(|_| Status::permission_denied("capability discovery denied"))?;
        let can_write_namespace =
            check_team_namespace(&self.db, principals, namespace, true).is_ok();

        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("capability catalog unavailable"))?;
        let visible_types = schema
            .all()
            .into_iter()
            .filter(|object_type| {
                !is_reserved_governance_kind(&object_type.kind)
                    && check_read(
                        &self.security,
                        &schema_object_id(&object_type.kind),
                        principals,
                    )
                    .is_ok()
            })
            .collect::<Vec<_>>();
        let visible_kinds = visible_types
            .iter()
            .map(|object_type| object_type.kind.as_str())
            .collect::<std::collections::HashSet<_>>();

        let mut entries = visible_types
            .iter()
            .map(object_query_capability)
            .collect::<Vec<_>>();
        entries.push(traverse_capability());
        entries.push(expand_relations_capability());
        entries.push(retrieve_context_capability());
        entries.push(explain_derivation_capability());
        entries.push(kioku_candidates_capability());

        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let resolved_policy = self
            .db
            .resolve_action_policy(actor, namespace, namespace)
            .map_err(|_| Status::internal("capability catalog unavailable"))?;
        let policy_mutation_limit = resolved_policy
            .as_ref()
            .and_then(|policy| policy.max_mutations_per_work_unit);
        let policy_delete_limit = resolved_policy
            .as_ref()
            .and_then(|policy| policy.max_deletes_per_work_unit);
        let actions = self
            .actions
            .read()
            .map_err(|_| Status::internal("capability catalog unavailable"))?;
        for action_type in actions.capability_action_types() {
            if !can_write_namespace {
                continue;
            }
            if !action_type.target_kind.is_empty()
                && action_type.target_kind != "*"
                && !visible_kinds.contains(action_type.target_kind.as_str())
            {
                continue;
            }
            if action_type.ops.iter().any(|op| {
                op.op == "create_object"
                    && !op.property.is_empty()
                    && !visible_kinds.contains(op.property.as_str())
            }) {
                continue;
            }
            if check_read(
                &self.security,
                &action_object_id(&action_type.name),
                principals,
            )
            .is_err()
            {
                continue;
            }
            let risk = actions.action_risk_class(&action_type.name);
            let (mutation_count, delete_count) =
                actions.action_op_counts(&action_type.name, &HashMap::new());
            let limits = ActionCapabilityLimits {
                mutation_count,
                delete_count,
                policy_mutation_limit,
                policy_delete_limit,
            };
            let decision = resolved_policy
                .as_ref()
                .map(|policy| policy.decide(&action_type.name, risk))
                .unwrap_or(ActionDecision::Allow);
            if decision == ActionDecision::Deny {
                continue;
            }
            if action_type.name == "create_object" {
                for object_type in visible_types
                    .iter()
                    .filter(|object_type| object_type.kind != "namespace")
                {
                    entries.push(create_object_capability(
                        &action_type,
                        object_type,
                        risk,
                        decision == ActionDecision::RequireApproval,
                        limits,
                    ));
                }
                continue;
            }
            entries.push(action_capability(
                format!("sekai.actions.{}", action_type.name),
                action_type,
                risk,
                decision == ActionDecision::RequireApproval,
                limits,
            ));
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    /// Execute an action's effect (target auth + schema validation + mutation +
    /// audit) without policy gating. Used to resume an approved held action.
    /// `principals` are the identities re-checked for write access at execution
    /// time. Returns the executor's success message.
    fn run_action_effect(
        &self,
        action_name: &str,
        params: &HashMap<String, String>,
        actor: &str,
        principals: &[String],
    ) -> Result<String, Status> {
        if self.db.enterprise_extension().is_some() {
            return Err(Status::failed_precondition(
                "enterprise action resumption requires a durable approval identity contract",
            ));
        }
        self.refresh_action_registry()?;
        let tenant_context: Option<RequestEnterpriseContext> = None;
        let actions = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let mask_missing_link = actions.masks_missing_link(action_name);
        let sensitive_params = actions.sensitive_param_names(action_name);
        let target_ids = actions
            .target_ids(&self.db, action_name, params)
            .map_err(|err| {
                if mask_missing_link && err == "link not found" {
                    Status::permission_denied("write denied")
                } else {
                    Status::invalid_argument(err)
                }
            })?;
        if actions.creates_namespace(action_name, params) {
            return Err(Status::permission_denied(
                "namespace objects must be managed through EnsureTeamNamespace",
            ));
        }
        for target_id in &target_ids {
            if let Some(target) = self.db.get_object(target_id).map_err(Status::internal)? {
                enforce_namespace_tenant_context(
                    &self.db,
                    tenant_context.as_ref(),
                    &target.namespace,
                    true,
                )?;
                check_team_namespace(&self.db, principals, &target.namespace, true)?;
            }
            check_write(&self.security, target_id, principals)?;
        }
        if let Some(namespace) = params.get("namespace") {
            enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), namespace, true)?;
            check_team_namespace(&self.db, principals, namespace, true)?;
        } else if action_name == "create_object"
            && (tenant_context.is_some() || is_managed_team_principal(&self.db, principals)?)
        {
            return Err(Status::permission_denied(
                "team object creation requires a canonical namespace",
            ));
        }
        let schema_kinds = actions
            .schema_kinds(&self.db, action_name, params)
            .map_err(Status::invalid_argument)?;
        ensure_action_schema_kinds_allowed(&schema_kinds)?;
        for kind in schema_kinds {
            self.require_schema_kind_loaded(&kind)?;
        }
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        actions
            .validate_action_schema(action_name, &schema)
            .map_err(Status::invalid_argument)?;
        let schema_restricted_property =
            schema_restricted_action_property(&self.db, &schema, params);
        let provisional_learning_grant = (action_name
            == crate::sekai::learning::RECORD_LEARNING_ACTION)
            .then(|| security::Grant {
                id: String::new(),
                object_id: params.get("id").cloned().unwrap_or_default(),
                principal: actor.to_string(),
                role: security::Role::Admin,
                created: now_millis(),
            })
            .filter(|grant| !grant.object_id.is_empty());
        if let Some(grant) = &provisional_learning_grant {
            self.security.add_grant(grant);
        }
        let msg = match actions.execute(&self.db, &schema, action_name, params, actor) {
            Ok(msg) => msg,
            Err(error) => {
                if let Some(grant) = &provisional_learning_grant {
                    self.security
                        .remove_grant(&grant.object_id, &grant.principal);
                }
                return Err(Status::invalid_argument(error));
            }
        };
        drop(actions);
        drop(schema);
        self.refresh_security_after_action(action_name, params, actor)?;
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now_millis(),
                actor: actor.to_string(),
                action: action_name.to_string(),
                reason: "execute_action".into(),
                evidence: redact_action_evidence(
                    params,
                    &sensitive_params,
                    schema_restricted_property,
                ),
                target_id: target_ids.first().cloned().unwrap_or_default(),
                outcome: redact_action_outcome(
                    action_name,
                    params,
                    &msg,
                    schema_restricted_property,
                ),
            })
            .map_err(Status::internal)?;
        Ok(msg)
    }

    fn refresh_security_after_action(
        &self,
        action_name: &str,
        params: &HashMap<String, String>,
        actor: &str,
    ) -> Result<(), Status> {
        if action_name != crate::sekai::learning::RECORD_LEARNING_ACTION {
            return Ok(());
        }
        let learning_id = params
            .get("id")
            .ok_or_else(|| Status::internal("record_learning id missing after execution"))?;
        let grants = self.db.list_grants(learning_id).map_err(Status::internal)?;
        if grants.is_empty() {
            return Err(Status::internal(
                "record_learning completed without a learning ACL",
            ));
        }
        self.security.remove_grant(learning_id, actor);
        for grant in &grants {
            self.security.add_grant(grant);
        }
        Ok(())
    }

    fn resolve_computed_for_response(
        &self,
        mut object: domain::Object,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<domain::Object, Status> {
        let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        compute::resolve_schema_computed_with_filter(&mut object, &self.db, &schema, |candidate| {
            !is_reserved_governance_kind(&candidate.kind)
                && check_team_namespace(&self.db, principals, &candidate.namespace, false).is_ok()
                && enforce_namespace_tenant_context(
                    &self.db,
                    tenant_context,
                    &candidate.namespace,
                    false,
                )
                .is_ok()
                && self.security.can_access(&candidate.id, &refs)
                && object_passes_marking(&self.db, candidate, principals).unwrap_or(false)
        })
        .map_err(Status::internal)?;
        Ok(redact_restricted_properties(
            object,
            &schema,
            &self.security,
            principals,
        ))
    }

    fn resolve_computed_for_responses(
        &self,
        objects: Vec<domain::Object>,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<Vec<domain::Object>, Status> {
        objects
            .into_iter()
            .map(|object| self.resolve_computed_for_response(object, principals, tenant_context))
            .collect()
    }

    fn recover_schema_registry(&self) -> Result<(), Status> {
        let current_error = self
            .schema_unavailable_error
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        if current_error.is_none() {
            return Ok(());
        }

        match (
            self.db.list_object_types_with_errors(),
            self.db.list_interfaces(),
        ) {
            (Ok((types, errors)), Ok(interfaces)) => {
                for (kind, error) in &errors {
                    tracing::error!(kind, %error, "failed to load schema type");
                }
                *self
                    .schema
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? =
                    SchemaRegistry::from_types_and_interfaces(types, interfaces);
                *self
                    .schema_load_errors
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? = errors;
                *self
                    .schema_unavailable_error
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? = None;
                Ok(())
            }
            (Err(error), _) | (_, Err(error)) => {
                *self
                    .schema_unavailable_error
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? =
                    Some(error.clone());
                Err(Status::internal(format!(
                    "schema registry unavailable: {error}"
                )))
            }
        }
    }
}

fn base_capability(
    name: String,
    description: String,
    kind: &str,
    input_type: &str,
    output_type: &str,
) -> CapabilityEntry {
    let product_tier = capability_product_tier(&name).to_string();
    CapabilityEntry {
        name,
        description,
        kind: kind.to_string(),
        lifecycle_state: "active".to_string(),
        contract_version: capability::CONTRACT_VERSION.to_string(),
        minimum_compatible_version: capability::CONTRACT_VERSION.to_string(),
        maximum_compatible_version: capability::CONTRACT_VERSION.to_string(),
        replacement_capability: String::new(),
        input_type: input_type.to_string(),
        output_type: output_type.to_string(),
        required_scopes: Vec::new(),
        policy_decision_points: Vec::new(),
        risk_class: String::new(),
        approval_behavior: "none".to_string(),
        limits: Vec::new(),
        object_type: None,
        action_type: None,
        evidence_requirements: Vec::new(),
        product_tier,
    }
}

/// Product tier for catalog discovery (#386 / research #383).
/// Orthogonal to backend inventory completeness.
fn capability_product_tier(name: &str) -> &'static str {
    match name {
        semantic::CAPABILITY_EXPAND_RELATIONS
        | semantic::CAPABILITY_RETRIEVE_CONTEXT
        | semantic::CAPABILITY_EXPLAIN_DERIVATION => "core",
        "sekai.relations.traverse" => "core",
        other if other.starts_with("sekai.objects.query.") => "core",
        other if other.starts_with("sekai.actions.") => "advanced",
        other if other.contains("kioku") => "experimental",
        _ => "advanced",
    }
}

fn object_query_capability(object_type: &schema::ObjectType) -> CapabilityEntry {
    let mut entry = base_capability(
        format!("sekai.objects.query.{}", object_type.kind),
        format!("List authorized {} objects.", object_type.kind),
        "query",
        "sekai.ListObjectsRequest",
        "sekai.ListObjectsResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "schema_visibility".into(),
        "object_acl".into(),
    ];
    entry.object_type = Some(to_proto_schema_type(object_type));
    entry
}

fn traverse_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        "sekai.relations.traverse".into(),
        "Traverse authorized object relations with bounded depth.".into(),
        "query",
        "sekai.TraverseRequest",
        "sekai.TraverseResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec!["namespace_access".into(), "object_acl".into()];
    entry.limits = vec![CapabilityLimit {
        name: "max_depth".into(),
        value: 10,
    }];
    entry
}

fn semantic_reasoning_limits() -> Vec<CapabilityLimit> {
    vec![
        CapabilityLimit {
            name: "max_depth".into(),
            value: u64::from(retrieval::MAX_DEPTH),
        },
        CapabilityLimit {
            name: "max_links".into(),
            value: u64::from(retrieval::MAX_LINKS),
        },
        CapabilityLimit {
            name: "max_objects".into(),
            value: u64::from(retrieval::MAX_OBJECTS),
        },
        CapabilityLimit {
            name: "max_source_rows".into(),
            value: u64::from(retrieval::MAX_SOURCE_ROWS),
        },
        CapabilityLimit {
            name: "max_derived_rows".into(),
            value: u64::from(retrieval::MAX_DERIVED_ROWS),
        },
        CapabilityLimit {
            name: "max_derivation_steps".into(),
            value: u64::from(retrieval::MAX_DERIVATION_STEPS),
        },
        CapabilityLimit {
            name: "max_time_ms".into(),
            value: u64::from(retrieval::MAX_TIME_MS),
        },
        CapabilityLimit {
            name: "max_explanation_bytes".into(),
            value: retrieval::MAX_EXPLANATION_BYTES,
        },
        CapabilityLimit {
            name: "reasoning_profile_version".into(),
            value: semantic::REASONING_PROFILE_VERSION,
        },
        CapabilityLimit {
            name: "ontology_contract_version".into(),
            value: semantic::ONTOLOGY_CONTRACT_VERSION,
        },
        CapabilityLimit {
            name: "supports_asserted_only".into(),
            value: 1,
        },
        CapabilityLimit {
            name: "supports_entailment".into(),
            value: 1,
        },
    ]
}

fn epistemic_projection_limits() -> [CapabilityLimit; 6] {
    [
        CapabilityLimit {
            name: "epistemic_descriptor_source_refs".into(),
            value: crate::chisei::epistemic_descriptor::MAX_SOURCE_REFS as u64,
        },
        CapabilityLimit {
            name: "epistemic_descriptor_source_digests".into(),
            value: crate::chisei::epistemic_descriptor::MAX_SOURCE_DIGESTS as u64,
        },
        CapabilityLimit {
            name: "epistemic_descriptor_source_rows".into(),
            value: crate::chisei::epistemic_descriptor::MAX_SOURCE_ROWS as u64,
        },
        CapabilityLimit {
            name: "epistemic_descriptor_max_bytes".into(),
            value: crate::chisei::epistemic_descriptor::MAX_DESCRIPTOR_BYTES as u64,
        },
        CapabilityLimit {
            name: "backend_sqlite_entailment".into(),
            value: 1,
        },
        CapabilityLimit {
            name: "backend_postgres_entailment".into(),
            value: 0,
        },
    ]
}

fn expand_relations_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        semantic::CAPABILITY_EXPAND_RELATIONS.into(),
        "Expand authorized relations from a root in asserted or entailment mode.".into(),
        "retrieval",
        "sekai.ExpandRelationsRequest",
        "sekai.ExpandRelationsResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "classification".into(),
        "ontology_acl".into(),
    ];
    entry.limits = semantic_reasoning_limits();
    entry.limits.extend(epistemic_projection_limits());
    entry.evidence_requirements = vec![
        "derivation_steps".into(),
        "source_fact_ids".into(),
        "ontology_revision".into(),
        "truncation_metadata".into(),
        "epistemic_descriptor_projection".into(),
    ];
    entry
}

fn retrieve_context_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        semantic::CAPABILITY_RETRIEVE_CONTEXT.into(),
        "Retrieve bounded, authorized context candidates with provenance.".into(),
        "retrieval",
        "sekai.RetrieveContextRequest",
        "sekai.RetrieveContextResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "classification".into(),
        "ontology_acl".into(),
    ];
    entry.limits = semantic_reasoning_limits();
    entry.limits.extend(epistemic_projection_limits());
    entry.evidence_requirements = vec![
        "derivation_steps".into(),
        "source_fact_ids".into(),
        "ontology_revision".into(),
        "truncation_metadata".into(),
        "epistemic_descriptor_projection".into(),
    ];
    entry
}

fn explain_derivation_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        semantic::CAPABILITY_EXPLAIN_DERIVATION.into(),
        "Explain an authorized derivation path without hidden policy inputs.".into(),
        "retrieval",
        "sekai.ExplainDerivationRequest",
        "sekai.ExplainDerivationResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "classification".into(),
        "ontology_acl".into(),
    ];
    entry.limits = semantic_reasoning_limits();
    entry.limits.extend(epistemic_projection_limits());
    entry.evidence_requirements = vec![
        "derivation_steps".into(),
        "source_fact_ids".into(),
        "ontology_revision".into(),
        "explicit_rules_only".into(),
        "epistemic_descriptor_projection".into(),
    ];
    entry
}

fn kioku_candidates_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        "chisei.kioku.candidates.list".into(),
        "List namespace-scoped Kioku candidates with their validation evidence.".into(),
        "retrieval",
        "chisei.ListKiokuCandidatesRequest",
        "chisei.ListKiokuCandidatesResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "memory:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "memory_lifecycle".into(),
        "classification".into(),
    ];
    entry.evidence_requirements = vec![
        "attributable_evidence_link".into(),
        "resolvable_source_operation".into(),
        "candidate_validation".into(),
    ];
    entry.limits = vec![CapabilityLimit {
        name: "max_results".into(),
        value: 100,
    }];
    entry
}

#[derive(Clone, Copy)]
struct ActionCapabilityLimits {
    mutation_count: u32,
    delete_count: u32,
    policy_mutation_limit: Option<u32>,
    policy_delete_limit: Option<u32>,
}

fn action_capability(
    capability_name: String,
    action_type: action::ActionTypeDef,
    risk: RiskClass,
    approval_required: bool,
    limits: ActionCapabilityLimits,
) -> CapabilityEntry {
    let mut entry = base_capability(
        capability_name,
        action_type.description.clone(),
        "action",
        "sekai.ExecuteActionRequest",
        "sekai.ExecuteActionResponse",
    );
    entry.required_scopes = vec!["namespace:write".into(), "object:write".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "action_policy".into(),
        "budget".into(),
        "approval".into(),
    ];
    entry.risk_class = risk.as_str().to_string();
    entry.approval_behavior = if approval_required {
        "required".into()
    } else {
        "may_require".into()
    };
    entry.limits.push(CapabilityLimit {
        name: "max_mutations_per_invocation".into(),
        value: u64::from(limits.mutation_count),
    });
    if limits.delete_count > 0 {
        entry.limits.push(CapabilityLimit {
            name: "max_deletes_per_invocation".into(),
            value: u64::from(limits.delete_count),
        });
    }
    if let Some(limit) = limits.policy_mutation_limit {
        entry.limits.push(CapabilityLimit {
            name: "max_mutations_per_work_unit".into(),
            value: u64::from(limit),
        });
    }
    if let Some(limit) = limits.policy_delete_limit {
        entry.limits.push(CapabilityLimit {
            name: "max_deletes_per_work_unit".into(),
            value: u64::from(limit),
        });
    }
    if action_type.name == crate::sekai::learning::RECORD_LEARNING_ACTION {
        entry.limits.extend([
            CapabilityLimit {
                name: "score_min".into(),
                value: 0,
            },
            CapabilityLimit {
                name: "score_max".into(),
                value: 100,
            },
        ]);
    }
    entry.action_type = Some(to_proto_action_type(&action_type));
    entry
}

fn create_object_capability(
    base_action_type: &action::ActionTypeDef,
    object_type: &schema::ObjectType,
    risk: RiskClass,
    approval_required: bool,
    limits: ActionCapabilityLimits,
) -> CapabilityEntry {
    let mut action_type = base_action_type.clone();
    action_type.target_kind = object_type.kind.clone();
    action_type.description = format!(
        "Create a schema-governed {} object in an authorized namespace.",
        object_type.kind
    );
    action_type.params = vec![
        action::ActionParamDef {
            name: "id".into(),
            param_type: schema::PropertyType::String,
            required: true,
            enum_values: Vec::new(),
        },
        action::ActionParamDef {
            name: "kind".into(),
            param_type: schema::PropertyType::Enum,
            required: true,
            enum_values: vec![object_type.kind.clone()],
        },
        action::ActionParamDef {
            name: "name".into(),
            param_type: schema::PropertyType::String,
            required: true,
            enum_values: Vec::new(),
        },
        action::ActionParamDef {
            name: "namespace".into(),
            param_type: schema::PropertyType::String,
            required: true,
            enum_values: Vec::new(),
        },
        action::ActionParamDef {
            name: "external_id".into(),
            param_type: schema::PropertyType::String,
            required: false,
            enum_values: Vec::new(),
        },
    ];
    action_type.params.extend(
        object_type
            .properties
            .iter()
            .filter(|property| {
                !matches!(
                    property.name.as_str(),
                    "id" | "kind" | "name" | "namespace" | "external_id"
                )
            })
            .map(|property| action::ActionParamDef {
                name: property.name.clone(),
                param_type: property.prop_type.clone(),
                required: property.required,
                enum_values: property.enum_values.clone(),
            }),
    );
    let mut entry = action_capability(
        format!("sekai.actions.create_object.{}", object_type.kind),
        action_type,
        risk,
        approval_required,
        limits,
    );
    entry.object_type = Some(to_proto_schema_type(object_type));
    entry
}

fn map_capability_error(error: capability::CatalogError) -> Status {
    match error {
        capability::CatalogError::UnsupportedContractVersion => {
            Status::failed_precondition("unsupported capability catalog contract version")
        }
        capability::CatalogError::CatalogVersionUnavailable => {
            Status::aborted("capability catalog version unavailable")
        }
        capability::CatalogError::InvalidPageToken => {
            Status::invalid_argument("invalid capability catalog page token")
        }
    }
}

fn caller_principals(req: &Request<impl std::any::Any>) -> Vec<String> {
    if let Some(context) = req
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        return vec![context.principal.subject.clone()];
    }
    req.metadata()
        .get("x-principal")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            let principals = v
                .split(',')
                .map(str::trim)
                .filter(|principal| !principal.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if principals.is_empty() {
                vec!["anonymous".to_string()]
            } else {
                principals
            }
        })
        .unwrap_or_else(|| vec!["anonymous".to_string()])
}

fn work_unit_from_metadata(req: &Request<impl std::any::Any>) -> String {
    req.metadata()
        .get("x-chisei-work-unit")
        .or_else(|| req.metadata().get("x-chisei-task-id"))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

fn require_authenticated(principals: &[String]) -> Result<(), Status> {
    if principals.is_empty() || principals.iter().all(|principal| principal == "anonymous") {
        return Err(Status::unauthenticated("principal required"));
    }
    Ok(())
}

fn require_evidence_admin(security: &SecurityChecker, principals: &[String]) -> Result<(), Status> {
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("evidence", &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("evidence admin required"))
}

fn can_operate_evidence_submission(
    security: &SecurityChecker,
    submission: &DomainEvidenceSubmissionRecord,
    principals: &[String],
) -> bool {
    principals
        .iter()
        .any(|principal| principal == &submission.producer_identity)
        || require_evidence_admin(security, principals).is_ok()
}

fn parse_evidence_classification(
    value: &str,
) -> Result<evidence_domain::EvidenceClassification, Status> {
    match value.trim() {
        "public" => Ok(evidence_domain::EvidenceClassification::Public),
        "internal" => Ok(evidence_domain::EvidenceClassification::Internal),
        "confidential" => Ok(evidence_domain::EvidenceClassification::Confidential),
        "restricted" => Ok(evidence_domain::EvidenceClassification::Restricted),
        _ => Err(Status::invalid_argument("invalid evidence classification")),
    }
}

fn parse_evidence_intent(value: &str) -> Result<evidence_domain::EvidenceIntent, Status> {
    match value.trim() {
        "upsert" => Ok(evidence_domain::EvidenceIntent::Upsert),
        "retract" => Ok(evidence_domain::EvidenceIntent::Retract),
        "mark_stale" => Ok(evidence_domain::EvidenceIntent::MarkStale),
        _ => Err(Status::invalid_argument("invalid evidence intent")),
    }
}

fn parse_evidence_signal(value: &str) -> Result<evidence_domain::EvidenceSignal, Status> {
    match value.trim() {
        "acceptance" => Ok(evidence_domain::EvidenceSignal::Acceptance),
        "verification" => Ok(evidence_domain::EvidenceSignal::Verification),
        "delivery" => Ok(evidence_domain::EvidenceSignal::Delivery),
        "regression" => Ok(evidence_domain::EvidenceSignal::Regression),
        "resource_use" => Ok(evidence_domain::EvidenceSignal::ResourceUse),
        "operational_health" => Ok(evidence_domain::EvidenceSignal::OperationalHealth),
        "other" => Ok(evidence_domain::EvidenceSignal::Other),
        _ => Err(Status::invalid_argument("invalid evidence signal")),
    }
}

fn parse_schema_compatibility(value: &str) -> Result<evidence_domain::SchemaCompatibility, Status> {
    match value.trim() {
        "exact" => Ok(evidence_domain::SchemaCompatibility::Exact),
        "backward_compatible" => Ok(evidence_domain::SchemaCompatibility::BackwardCompatible),
        _ => Err(Status::invalid_argument(
            "invalid evidence schema compatibility",
        )),
    }
}

fn optional_nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn from_proto_evidence_envelope(
    envelope: EvidenceEnvelope,
) -> Result<evidence_domain::EvidenceEnvelope, Status> {
    let confidence_bps = u16::try_from(envelope.confidence_bps)
        .map_err(|_| Status::invalid_argument("confidence_bps out of range"))?;
    let content = serde_json::from_slice(&envelope.content_json)
        .map_err(|_| Status::invalid_argument("content_json must contain valid JSON"))?;
    let causality = envelope
        .causality
        .map(|causality| evidence_domain::EvidenceCausality {
            operation_id: optional_nonempty(causality.operation_id),
            parent_operation_id: optional_nonempty(causality.parent_operation_id),
            attempt_id: optional_nonempty(causality.attempt_id),
            model_call_id: optional_nonempty(causality.model_call_id),
            subject_references: causality.subject_references,
            trace_context: causality.trace_context.into_iter().collect(),
        });
    Ok(evidence_domain::EvidenceEnvelope {
        contract_version: envelope.contract_version,
        source_type: envelope.source_type,
        source_instance: envelope.source_instance,
        source_record_id: envelope.source_record_id,
        source_version: envelope.source_version,
        source_sequence: envelope.source_sequence,
        target: evidence_domain::EvidenceTarget {
            namespace: envelope.namespace,
            object_external_id: envelope.target_external_id,
            object_kind: envelope.target_kind,
        },
        evidence_type: envelope.evidence_type,
        signal: parse_evidence_signal(&envelope.signal)?,
        schema_id: envelope.schema_id,
        schema_version: envelope.schema_version,
        schema_compatibility: parse_schema_compatibility(&envelope.schema_compatibility)?,
        observed_at_ms: envelope.observed_at_ms,
        collected_at_ms: envelope.collected_at_ms,
        expires_at_ms: envelope.expires_at_ms,
        content,
        relationships: envelope
            .relationships
            .into_iter()
            .map(|relationship| evidence_domain::EvidenceRelationship {
                relation: relationship.relation,
                target_source_type: relationship.target_source_type,
                target_source_instance: relationship.target_source_instance,
                target_source_record_id: relationship.target_source_record_id,
            })
            .collect(),
        producer_identity: envelope.producer_identity,
        confidence_bps,
        classification: parse_evidence_classification(&envelope.classification)?,
        provenance: envelope.provenance.into_iter().collect(),
        idempotency_key: envelope.idempotency_key,
        content_digest: envelope.content_digest,
        intent: parse_evidence_intent(&envelope.intent)?,
        causality,
    })
}

#[cfg(test)]
fn evidence_content_is_readable(state: evidence_domain::EvidenceLifecycleState) -> bool {
    matches!(
        state,
        evidence_domain::EvidenceLifecycleState::Available
            | evidence_domain::EvidenceLifecycleState::Superseded
            | evidence_domain::EvidenceLifecycleState::Retracted
            | evidence_domain::EvidenceLifecycleState::Stale
    )
}

fn to_proto_evidence_submission(
    submission: &DomainEvidenceSubmissionRecord,
) -> EvidenceSubmissionRecord {
    EvidenceSubmissionRecord {
        id: submission.id.clone(),
        producer_identity: submission.producer_identity.clone(),
        source_type: submission.source_type.clone(),
        source_instance: submission.source_instance.clone(),
        source_record_id: submission.source_record_id.clone(),
        source_version: submission.source_version.clone(),
        source_sequence: submission.source_sequence,
        namespace: submission.namespace.clone(),
        target_external_id: submission.target_external_id.clone(),
        target_kind: submission.target_kind.clone(),
        evidence_type: submission.evidence_type.clone(),
        schema_id: submission.schema_id.clone(),
        schema_version: submission.schema_version.clone(),
        content_digest: submission.content_digest.clone(),
        classification: submission.classification.as_str().into(),
        intent: match submission.intent {
            evidence_domain::EvidenceIntent::Upsert => "upsert",
            evidence_domain::EvidenceIntent::Retract => "retract",
            evidence_domain::EvidenceIntent::MarkStale => "mark_stale",
        }
        .into(),
        lifecycle_state: submission.lifecycle_state.as_str().into(),
        rejection_code: submission.rejection_code.clone().unwrap_or_default(),
        rejection_summary: submission.rejection_summary.clone().unwrap_or_default(),
        observed_at_ms: submission.observed_at_ms,
        collected_at_ms: submission.collected_at_ms,
        expires_at_ms: submission.expires_at_ms,
        received_at_ms: submission.received_at_ms,
        updated_at_ms: submission.updated_at_ms,
        descriptor: Some(to_proto_epistemic_descriptor(
            &DomainEpistemicDescriptor::from_external_evidence(submission),
        )),
    }
}

fn to_proto_epistemic_descriptor(descriptor: &DomainEpistemicDescriptor) -> EpistemicDescriptor {
    debug_assert!(descriptor.validate().is_ok());
    EpistemicDescriptor {
        contract_version: descriptor.contract_version.clone(),
        origin_class: descriptor.origin_class.as_str().into(),
        evidence_status: descriptor.evidence_status.as_str().into(),
        lifecycle_status: descriptor.lifecycle_status.as_str().into(),
        producer_confidence_bps: descriptor.producer_confidence_bps.map(u32::from),
        confidence_basis: descriptor.confidence_basis.clone().unwrap_or_default(),
        observed_at_ms: descriptor.observed_at_ms,
        derivation_ref: descriptor.derivation_ref.clone().unwrap_or_default(),
        source_refs: descriptor.source_refs.clone(),
        source_digests: descriptor.source_digests.clone(),
        source_row_count: descriptor.source_row_count,
        source_rows_truncated: descriptor.source_rows_truncated,
        supporting_evidence_count: descriptor.supporting_evidence_count,
        contradicting_evidence_count: descriptor.contradicting_evidence_count,
    }
}

fn to_proto_evidence_submission_result(
    outcome: EvidenceAdmissionOutcome,
) -> EvidenceSubmissionResult {
    EvidenceSubmissionResult {
        submission: Some(to_proto_evidence_submission(&outcome.submission)),
        admitted: outcome.admitted,
        deduplicated: outcome.deduplicated,
        projected: outcome
            .projection
            .is_some_and(|projection| projection.projected),
    }
}

fn map_evidence_admission_lifecycle_error(error: EvidenceAdmissionLifecycleError) -> Status {
    match error {
        EvidenceAdmissionLifecycleError::Admission(_) => {
            Status::internal("evidence admission failed")
        }
        EvidenceAdmissionLifecycleError::Rejection(_) => {
            Status::internal("evidence rejection failed")
        }
        EvidenceAdmissionLifecycleError::Projection(_) => {
            Status::internal("evidence projection failed")
        }
        EvidenceAdmissionLifecycleError::ExecutionRecording(error) => {
            Status::failed_precondition(error)
        }
        EvidenceAdmissionLifecycleError::ResultResolution(error) => Status::internal(error),
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn redact_action_evidence(
    params: &std::collections::HashMap<String, String>,
    sensitive_params: &std::collections::HashSet<String>,
    schema_restricted_property: Option<bool>,
) -> std::collections::HashMap<String, String> {
    params
        .iter()
        // Reserved evidence keys are written by the attestation binding, not
        // by callers; a param with the same name must not be able to plant a
        // fake attestation reference in the audit log.
        .filter(|(key, _)| {
            key.as_str() != attestation::EVIDENCE_ATTESTATION_ID
                && key.as_str() != attestation::EVIDENCE_ATTESTATION_HASH
        })
        .map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            let sensitive_property = params
                .get("key")
                .or_else(|| params.get("property"))
                .map(|property| {
                    schema_restricted_property.unwrap_or_else(|| is_sensitive_name(property))
                })
                .unwrap_or(false);
            let value = if is_sensitive_name(&lower)
                || sensitive_params.contains(key)
                || ((lower == "value" || lower == "new_value") && sensitive_property)
            {
                "[redacted]".to_string()
            } else {
                value.clone()
            };
            (key.clone(), value)
        })
        .collect()
}

fn redact_action_outcome(
    action: &str,
    params: &std::collections::HashMap<String, String>,
    outcome: &str,
    schema_restricted_property: Option<bool>,
) -> String {
    if action == "set_property"
        && params
            .get("key")
            .map(|property| {
                schema_restricted_property.unwrap_or_else(|| is_sensitive_name(property))
            })
            .unwrap_or(false)
    {
        return format!(
            "set {}.{} = [redacted]",
            params.get("id").cloned().unwrap_or_default(),
            params.get("key").cloned().unwrap_or_default()
        );
    }
    outcome.to_string()
}

fn schema_restricted_action_property(
    db: &RuntimeDb,
    schema: &schema::SchemaRegistry,
    params: &std::collections::HashMap<String, String>,
) -> Option<bool> {
    let property_name = params.get("key").or_else(|| params.get("property"))?;
    let object_id = params.get("id").or_else(|| params.get("object_id"))?;
    let object = db.get_object(object_id).ok().flatten()?;
    let object_type = schema.get(&object.kind)?;
    let property = object_type
        .properties
        .iter()
        .find(|property| property.name == *property_name)?;
    Some(schema::is_restricted_property_classification(
        &property.classification,
    ))
}

fn is_sensitive_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains("password")
        || lower.contains("passphrase")
        || lower.contains("passwd")
        || lower.contains("credential")
}

fn check_read(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_access(object_id, &refs) {
        return Err(Status::permission_denied("access denied"));
    }
    Ok(())
}

fn resolve_principal_authority(
    db: &RuntimeDb,
    principals: &[String],
) -> Result<markings::PrincipalAuthority, Status> {
    let primary = principals.first().map(String::as_str).unwrap_or_default();
    if let Some(trusted) = markings::trusted_service_authority(primary) {
        return Ok(trusted);
    }
    let external_id = markings::principal_profile_external_id(primary);
    // Prefer an explicit kind-matched sealed profile over any colliding
    // external_id on ordinary objects (external IDs are indexed, not unique).
    let candidates = db
        .find_all_by_external_id(&external_id)
        .map_err(Status::internal)?;
    let mut trusted = Vec::new();
    for object in &candidates {
        if object.kind != markings::PRINCIPAL_PROFILE_KIND {
            continue;
        }
        if object
            .properties
            .get(markings::PRINCIPAL_PROFILE_SEALED_PROPERTY)
            .is_none_or(|value| value != "true")
        {
            continue;
        }
        let grants = db.list_grants(&object.id).map_err(Status::internal)?;
        if grants
            .iter()
            .any(|grant| matches!(grant.role, security::Role::Admin))
        {
            trusted.push(object);
        }
    }
    if trusted.len() > 1 {
        return Err(Status::failed_precondition(
            "multiple trusted principal profiles found; resolve duplicates before marking checks",
        ));
    }
    markings::principal_authority_from_profile(primary, trusted.first().copied())
        .map_err(Status::internal)
}

fn object_passes_marking(
    db: &RuntimeDb,
    object: &domain::Object,
    principals: &[String],
) -> Result<bool, Status> {
    let marking = markings::object_classification(object).map_err(Status::invalid_argument)?;
    if marking.is_none() {
        return Ok(true);
    }
    let authority = resolve_principal_authority(db, principals)?;
    let result = markings::evaluate_marking_access("visibility", marking, &authority);
    Ok(result.decision != markings::MarkingDecision::Deny)
}

/// ACL-visible list with marking filter, exact marking-visible totals, and
/// offset/limit applied over the filtered set.
fn list_objects_with_marking<F>(
    db: &RuntimeDb,
    filter: &domain::ListFilter,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    resolve: F,
) -> Result<(Vec<domain::Object>, i32), Status>
where
    F: FnOnce(
        Vec<domain::Object>,
        &[String],
        Option<&RequestEnterpriseContext>,
    ) -> Result<Vec<domain::Object>, Status>,
{
    let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    let requested_limit = if filter.limit <= 0 {
        domain::DEFAULT_LIST_LIMIT as usize
    } else {
        (filter.limit as usize).min(domain::MAX_LIST_LIMIT as usize)
    };
    let requested_offset = filter.offset.max(0) as usize;
    let mut scan_offset = 0i32;
    let mut visible_index = 0usize;
    let mut collected = Vec::new();
    let mut visible_total = 0i32;
    loop {
        let mut scan_filter = filter.clone();
        scan_filter.offset = scan_offset;
        scan_filter.limit = domain::MAX_LIST_LIMIT;
        let (page, principal_total) = db
            .list_objects_with_total_for_principals(
                &scan_filter,
                &principal_refs,
                RESERVED_GOVERNANCE_KINDS,
            )
            .map_err(Status::internal)?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len() as i32;
        for object in page {
            if !object_passes_marking(db, &object, principals).unwrap_or(false) {
                continue;
            }
            if visible_index >= requested_offset && collected.len() < requested_limit {
                collected.push(object);
            }
            visible_index = visible_index.saturating_add(1);
            visible_total = visible_total.saturating_add(1);
        }
        scan_offset = scan_offset.saturating_add(page_len);
        if scan_offset >= principal_total {
            break;
        }
    }
    let objects = resolve(collected, principals, tenant_context)?;
    Ok((objects, visible_total))
}

fn validate_principal_profile_object(obj: &Object) -> Result<(), Status> {
    if obj.kind != markings::PRINCIPAL_PROFILE_KIND {
        return Ok(());
    }
    let expected = markings::principal_profile_external_id(&obj.name);
    if obj.external_id != expected {
        return Err(Status::invalid_argument(format!(
            "principal_profile external_id must be {expected}"
        )));
    }
    if let Some(ceiling) = obj
        .properties
        .get(markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY)
    {
        markings::parse_optional_classification(ceiling).map_err(Status::invalid_argument)?;
    }
    if let Some(purposes) = obj
        .properties
        .get(markings::PRINCIPAL_ALLOWED_PURPOSES_PROPERTY)
    {
        let domain = from_proto_obj(obj);
        markings::principal_authority_from_profile(&obj.name, Some(&domain))
            .map_err(Status::invalid_argument)?;
        let _ = purposes;
    }
    Ok(())
}

fn enforce_object_marking_access(
    db: &RuntimeDb,
    object: &domain::Object,
    principals: &[String],
    operation_id: &str,
) -> Result<markings::MarkingCheckResult, Status> {
    let marking = markings::object_classification(object).map_err(Status::invalid_argument)?;
    let authority = resolve_principal_authority(db, principals)?;
    let result = markings::evaluate_marking_access(operation_id, marking, &authority);
    if result.decision == markings::MarkingDecision::Deny {
        // Generic denial — do not leak marking details to unauthorized callers.
        return Err(Status::permission_denied("access denied"));
    }
    Ok(result)
}

fn record_marking_or_purpose_decision(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    target_id: &str,
    decision_id: &str,
    outcome: &str,
    evidence: HashMap<String, String>,
) -> Result<(), Status> {
    db.record_decision(&audit::Decision {
        id: decision_id.into(),
        timestamp: now_millis(),
        actor: actor.into(),
        action: action.into(),
        reason: "classification marking / purpose gate".into(),
        evidence,
        target_id: target_id.into(),
        outcome: outcome.into(),
    })
    .map_err(Status::internal)
}

fn check_write(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_write(object_id, &refs) {
        return Err(Status::permission_denied("write denied"));
    }
    Ok(())
}

fn validate_object_kind_change_access(
    db: &RuntimeDb,
    security: &SecurityChecker,
    principals: &[String],
    existing: &domain::Object,
    updated: &domain::Object,
) -> Result<(), Status> {
    if existing.kind == updated.kind {
        return Ok(());
    }
    let ontology = db.load_ontology_registry().map_err(Status::internal)?;
    let mut linked = db
        .get_links(&updated.id, "", &domain::Direction::Outgoing)
        .map_err(Status::internal)?;
    linked.extend(
        db.get_links(&updated.id, "", &domain::Direction::Incoming)
            .map_err(Status::internal)?,
    );
    for link in linked {
        if ontology
            .constraints_for_mapped_relation(&link.relation)
            .is_empty()
        {
            continue;
        }
        for endpoint_id in [&link.from_id, &link.to_id] {
            if endpoint_id == &updated.id {
                continue;
            }
            let endpoint = db
                .get_object(endpoint_id)
                .map_err(Status::internal)?
                .ok_or(Status::failed_precondition("link endpoint unavailable"))?;
            check_team_namespace(db, principals, &endpoint.namespace, false)?;
            check_read(security, &endpoint.id, principals)?;
        }
        if ontology
            .constraints_for_mapped_relation(&link.relation)
            .into_iter()
            .any(|constraint| {
                let introduces_domain_violation = link.from_id == updated.id
                    && ontology.kind_satisfies_class(&existing.kind, &constraint.domain)
                    && !ontology.kind_satisfies_class(&updated.kind, &constraint.domain);
                let introduces_range_violation = link.to_id == updated.id
                    && ontology.kind_satisfies_class(&existing.kind, &constraint.range)
                    && !ontology.kind_satisfies_class(&updated.kind, &constraint.range);
                introduces_domain_violation || introduces_range_violation
            })
        {
            return Err(Status::failed_precondition(
                "link endpoints violate ontology constraint",
            ));
        }
    }
    Ok(())
}

fn check_object_admin(
    db: &RuntimeDb,
    security: &SecurityChecker,
    object: &domain::Object,
    principals: &[String],
) -> Result<(), Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(());
    }
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    if security.can_admin(&object.id, &refs) {
        return Ok(());
    }
    let memberships = team_namespace_memberships(db, principals)?;
    if memberships
        .iter()
        .any(|(namespace, role)| namespace == &object.namespace && *role == security::Role::Admin)
    {
        return Ok(());
    }
    Err(Status::permission_denied("admin access denied"))
}

fn check_object_namespace_access(
    db: &RuntimeDb,
    principals: &[String],
    object_id: &str,
    write: bool,
) -> Result<(), Status> {
    let namespace = match db.get_object(object_id).map_err(Status::internal)? {
        Some(object) => Some(object.namespace),
        None => db
            .object_change_namespace(object_id)
            .map_err(Status::internal)?,
    };
    match namespace {
        Some(namespace) => check_team_namespace(db, principals, &namespace, write),
        None if is_managed_team_principal(db, principals)? => {
            Err(Status::permission_denied("namespace access denied"))
        }
        None => Ok(()),
    }
}

fn team_namespace_memberships(
    db: &RuntimeDb,
    principals: &[String],
) -> Result<Vec<(String, security::Role)>, Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(Vec::new());
    }
    let mut memberships = Vec::new();
    for principal in principals {
        memberships.extend(
            db.list_namespace_roles_for_principal(principal)
                .map_err(Status::internal)?,
        );
    }
    Ok(memberships)
}

fn is_managed_team_principal(db: &RuntimeDb, principals: &[String]) -> Result<bool, Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(false);
    }
    for principal in principals {
        if db.is_team_principal(principal).map_err(Status::internal)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_team_namespace(
    db: &RuntimeDb,
    principals: &[String],
    namespace: &str,
    write: bool,
) -> Result<(), Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(());
    }
    let canonical = namespace.trim();
    if canonical.is_empty() || canonical != namespace {
        return if is_managed_team_principal(db, principals)? {
            Err(Status::permission_denied(
                "team principals require a canonical namespace",
            ))
        } else {
            Ok(())
        };
    }
    let boundary = db
        .find_namespace_boundary(canonical)
        .map_err(Status::internal)?;
    let team_managed_namespace = boundary.as_ref().is_some_and(|object| {
        object
            .properties
            .get("team_managed")
            .is_some_and(|value| value == "true")
    });
    if !team_managed_namespace && !is_managed_team_principal(db, principals)? {
        return Ok(());
    }
    let memberships = team_namespace_memberships(db, principals)?;
    let authorized = memberships.iter().any(|(member_namespace, role)| {
        member_namespace == canonical
            && (!write || matches!(role, security::Role::Editor | security::Role::Admin))
    });
    if authorized {
        Ok(())
    } else {
        Err(Status::permission_denied("namespace access denied"))
    }
}

fn check_dataset_access(
    db: &RuntimeDb,
    security: &SecurityChecker,
    principals: &[String],
    dataset: &dataset::Dataset,
    write: bool,
) -> Result<(), Status> {
    if dataset.object_id.is_empty() {
        if is_managed_team_principal(db, principals)? {
            return Err(Status::permission_denied(
                "team principals cannot access unbound global datasets",
            ));
        }
        return Ok(());
    }
    let object = match db
        .get_object(&dataset.object_id)
        .map_err(Status::internal)?
    {
        Some(object) => object,
        None if is_managed_team_principal(db, principals)? => {
            return Err(Status::permission_denied(
                "team dataset binding object is unavailable",
            ));
        }
        None => {
            return if write {
                check_write(security, &dataset.object_id, principals)
            } else {
                check_read(security, &dataset.object_id, principals)
            };
        }
    };
    check_team_namespace(db, principals, &object.namespace, write)?;
    if write {
        check_write(security, &object.id, principals)
    } else {
        check_read(security, &object.id, principals)
    }
}

fn check_schema_admin(
    security: &SecurityChecker,
    kind: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("schema", &refs)
        || security.can_admin(&schema_object_id(kind), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("schema admin required"))
}

fn check_action_admin(
    security: &SecurityChecker,
    name: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("action", &refs)
        || security.can_admin(&action_object_id(name), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("action admin required"))
}

fn principal_matches(owner_principal: &str, principals: &[String]) -> bool {
    !owner_principal.is_empty()
        && principals
            .iter()
            .any(|principal| principal == owner_principal)
}

fn check_scope_read(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    if principal_matches(&scope.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("scope access denied"))
    }
}

fn check_scope_write(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    check_scope_read(scope, principals)
}

fn check_work_unit_read(
    db: &RuntimeDb,
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_object_namespace_access(db, principals, &work_unit.target_object_id, false)?;
        check_read(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit access denied"))
    }
}

fn check_work_unit_write(
    db: &RuntimeDb,
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_object_namespace_access(db, principals, &work_unit.target_object_id, true)?;
        check_write(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit write denied"))
    }
}

const DEFAULT_LIST_LIMIT: i32 = domain::DEFAULT_LIST_LIMIT;
const MAX_LIST_LIMIT: i32 = domain::MAX_LIST_LIMIT;

fn read_limit_offset(limit: i32, offset: i32) -> Result<(i32, i32), Status> {
    if offset < 0 {
        return Err(Status::invalid_argument("offset must be >= 0"));
    }
    let effective_limit = if limit <= 0 {
        DEFAULT_LIST_LIMIT
    } else {
        limit.min(MAX_LIST_LIMIT)
    };
    Ok((effective_limit, offset))
}

fn parse_property_operator(op: &str) -> Result<&'static str, Status> {
    match op.to_lowercase().as_str() {
        "eq" => Ok("eq"),
        "ne" | "neq" => Ok("ne"),
        "gt" => Ok("gt"),
        "gte" => Ok("gte"),
        "lt" => Ok("lt"),
        "lte" => Ok("lte"),
        "contains" => Ok("contains"),
        "prefix" => Ok("prefix"),
        "in" => Ok("in"),
        other => Err(Status::invalid_argument(format!(
            "unsupported property operator: {other}"
        ))),
    }
}

fn parse_order_by(order_by: &str) -> Result<String, Status> {
    if order_by.is_empty() {
        return Ok(String::new());
    }
    let normalized = order_by.trim().to_lowercase();
    if normalized == "name" || normalized == "created" || normalized == "updated" {
        return Ok(normalized);
    }
    if let Some((prefix, key)) = order_by.trim().split_once(':') {
        if !prefix.eq_ignore_ascii_case("property") {
            return Err(Status::invalid_argument("unsupported order_by"));
        }
        if !domain::is_valid_property_key(key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        return Ok(format!("property:{}", key.trim()));
    }
    Err(Status::invalid_argument("unsupported order_by"))
}

fn parse_list_filter(f: ListFilter) -> Result<domain::ListFilter, Status> {
    let (limit, offset) = read_limit_offset(f.limit, f.offset)?;
    let mut property_filters = Vec::new();
    for pf in f.property_filters {
        if !domain::is_valid_property_key(&pf.key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        property_filters.push(domain::PropertyFilter {
            key: pf.key,
            op: parse_property_operator(&pf.op)?.to_string(),
            value: pf.value,
        });
    }
    let interface_filter = parse_interface_filter(f.interface_filter)?;
    let order_by = parse_order_by(&f.order_by)?;
    Ok(domain::ListFilter {
        kind: if f.kind.is_empty() {
            None
        } else {
            Some(f.kind)
        },
        name: if f.name.is_empty() {
            None
        } else {
            Some(f.name)
        },
        namespace: if f.namespace.is_empty() {
            None
        } else {
            Some(f.namespace)
        },
        property_filters,
        interface_filter,
        limit,
        offset,
        order_by,
        descending: f.descending,
    })
}

fn parse_interface_filter(interface_filter: Vec<String>) -> Result<Vec<String>, Status> {
    let mut parsed = Vec::new();
    for interface_name in interface_filter {
        if interface_name.trim().is_empty() {
            return Err(Status::invalid_argument("interface name required"));
        }
        parsed.push(interface_name);
    }
    Ok(parsed)
}

fn to_proto_obj(o: &domain::Object) -> Object {
    Object {
        id: o.id.clone(),
        kind: o.kind.clone(),
        name: o.name.clone(),
        namespace: o.namespace.clone(),
        external_id: o.external_id.clone(),
        properties: o.properties.clone(),
        created: o.created,
        updated: o.updated,
    }
}

fn can_read_restricted_properties(
    security: &SecurityChecker,
    object: &domain::Object,
    principals: &[String],
) -> bool {
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
    {
        return true;
    }
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    security.can_admin(&object.id, &refs)
}

fn redact_restricted_properties(
    mut object: domain::Object,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
) -> domain::Object {
    if can_read_restricted_properties(security, &object, principals) {
        return object;
    }
    let Some(object_type) = schema.get(&object.kind) else {
        return object;
    };
    for property in &object_type.properties {
        if schema::is_restricted_property_classification(&property.classification)
            && object.properties.contains_key(&property.name)
        {
            object
                .properties
                .insert(property.name.clone(), REDACTED_VALUE.to_string());
        }
    }
    object
}

fn restricted_property_names_for_kind(
    schema: &schema::SchemaRegistry,
    kind: &str,
) -> std::collections::HashSet<String> {
    if kind.is_empty() {
        return schema
            .all()
            .iter()
            .flat_map(|object_type| {
                object_type
                    .properties
                    .iter()
                    .filter(|property| {
                        schema::is_restricted_property_classification(&property.classification)
                    })
                    .map(|property| property.name.clone())
                    .collect::<Vec<_>>()
            })
            .collect();
    }
    schema
        .get(kind)
        .map(|object_type| {
            object_type
                .properties
                .iter()
                .filter(|property| {
                    schema::is_restricted_property_classification(&property.classification)
                })
                .map(|property| property.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn principals_can_query_restricted_properties(principals: &[String]) -> bool {
    principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
}

fn ensure_property_query_allowed(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    kind: &str,
    properties: impl IntoIterator<Item = String>,
) -> Result<(), Status> {
    if principals_can_query_restricted_properties(principals) {
        return Ok(());
    }
    let restricted = restricted_property_names_for_kind(schema, kind);
    if restricted.is_empty() {
        return Ok(());
    }
    if let Some(property) = properties
        .into_iter()
        .find(|property| restricted.contains(property))
    {
        return Err(Status::permission_denied(format!(
            "restricted property filter denied: {property}"
        )));
    }
    Ok(())
}

fn queried_order_property(order_by: &str) -> Option<String> {
    order_by
        .strip_prefix("property:")
        .filter(|property| !property.is_empty())
        .map(ToOwned::to_owned)
}

fn preserve_redacted_restricted_properties(
    db: &RuntimeDb,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
    object: &mut domain::Object,
) -> Result<(), Status> {
    if can_read_restricted_properties(security, object, principals) {
        return Ok(());
    }
    let Some(existing) = db.get_object(&object.id).map_err(Status::internal)? else {
        return Ok(());
    };
    let mut restricted = restricted_property_names_for_kind(schema, &object.kind);
    restricted.extend(restricted_property_names_for_kind(schema, &existing.kind));
    if object.kind != existing.kind
        && restricted
            .iter()
            .any(|property| existing.properties.contains_key(property))
    {
        return Err(Status::permission_denied(
            "restricted property mutation denied",
        ));
    }
    for property in restricted {
        if let Some(existing_value) = existing.properties.get(&property) {
            object.properties.insert(property, existing_value.clone());
        } else {
            object.properties.remove(&property);
        }
    }
    Ok(())
}

fn ensure_restricted_create_properties_allowed(
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
    object: &domain::Object,
) -> Result<(), Status> {
    if can_read_restricted_properties(security, object, principals) {
        return Ok(());
    }
    let restricted = restricted_property_names_for_kind(schema, &object.kind);
    if let Some(property) = restricted.into_iter().find(|property| {
        object
            .properties
            .get(property)
            .is_some_and(|value| !value.is_empty())
    }) {
        return Err(Status::permission_denied(format!(
            "restricted property mutation denied: {property}"
        )));
    }
    Ok(())
}

fn redact_object_change_values(
    change: audit::ObjectChange,
    object_id: &str,
    kind: &str,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
) -> ObjectChange {
    let object = domain::Object {
        id: object_id.into(),
        kind: kind.into(),
        name: String::new(),
        namespace: String::new(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 0,
        updated: 0,
    };
    let restricted = if can_read_restricted_properties(security, &object, principals) {
        std::collections::HashSet::new()
    } else {
        restricted_property_names_for_kind(schema, kind)
    };
    let should_redact = change
        .field
        .strip_prefix("properties.")
        .is_some_and(|property| restricted.contains(property));
    ObjectChange {
        id: change.id,
        object_id: change.object_id,
        field: change.field,
        old_value: if should_redact {
            REDACTED_VALUE.into()
        } else {
            change.old_value
        },
        new_value: if should_redact {
            REDACTED_VALUE.into()
        } else {
            change.new_value
        },
        changed_by: change.changed_by,
        timestamp: change.timestamp,
    }
}

fn to_proto_link(l: &domain::Link) -> Link {
    Link {
        id: l.id.clone(),
        from_id: l.from_id.clone(),
        to_id: l.to_id.clone(),
        relation: l.relation.clone(),
        created: l.created,
    }
}

fn from_proto_obj(o: &Object) -> domain::Object {
    domain::Object {
        id: o.id.clone(),
        kind: o.kind.clone(),
        name: o.name.clone(),
        namespace: o.namespace.clone(),
        external_id: o.external_id.clone(),
        properties: o.properties.clone(),
        created: o.created,
        updated: o.updated,
    }
}

fn to_proto_schema_type(object_type: &schema::ObjectType) -> ObjectType {
    ObjectType {
        kind: object_type.kind.clone(),
        description: object_type.description.clone(),
        properties: object_type
            .properties
            .iter()
            .map(to_proto_property_def)
            .collect(),
        is_builtin: object_type.is_builtin,
        implements: object_type.implements.clone(),
    }
}

fn to_proto_property_def(property: &schema::PropertyDef) -> PropertyDef {
    PropertyDef {
        name: property.name.clone(),
        r#type: property.prop_type.as_str().to_string(),
        required: property.required,
        description: property.description.clone(),
        enum_values: property.enum_values.clone(),
        link_kind: property.link_kind.clone(),
        compute_expr: property.compute_expr.clone(),
        classification: schema::normalize_property_classification(&property.classification)
            .to_string(),
        struct_fields: property
            .struct_fields
            .iter()
            .map(to_proto_struct_field_def)
            .collect(),
    }
}

fn to_proto_struct_field_def(field: &schema::StructFieldDef) -> StructFieldDef {
    StructFieldDef {
        name: field.name.clone(),
        r#type: field.prop_type.as_str().to_string(),
        required: field.required,
        description: field.description.clone(),
        enum_values: field.enum_values.clone(),
    }
}

fn from_proto_schema_type(object_type: &ObjectType) -> Result<schema::ObjectType, Status> {
    let properties = object_type
        .properties
        .iter()
        .map(from_proto_property_def)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(schema::ObjectType {
        kind: object_type.kind.clone(),
        description: object_type.description.clone(),
        properties,
        is_builtin: object_type.is_builtin,
        implements: object_type.implements.clone(),
    })
}

fn from_proto_property_def(property: &PropertyDef) -> Result<schema::PropertyDef, Status> {
    let prop_type = schema::PropertyType::parse(&property.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown property type: {}", property.r#type))
    })?;
    Ok(schema::PropertyDef {
        name: property.name.clone(),
        prop_type,
        required: property.required,
        description: property.description.clone(),
        enum_values: property.enum_values.clone(),
        link_kind: property.link_kind.clone(),
        compute_expr: property.compute_expr.clone(),
        classification: schema::normalize_property_classification(&property.classification)
            .to_string(),
        struct_fields: property
            .struct_fields
            .iter()
            .map(from_proto_struct_field_def)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn from_proto_struct_field_def(field: &StructFieldDef) -> Result<schema::StructFieldDef, Status> {
    let prop_type = schema::PropertyType::parse(&field.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown struct field type: {}", field.r#type))
    })?;
    Ok(schema::StructFieldDef {
        name: field.name.clone(),
        prop_type,
        required: field.required,
        description: field.description.clone(),
        enum_values: field.enum_values.clone(),
    })
}

fn ontology_class_object_id(name: &str) -> String {
    format!("ontology:class:{name}")
}

fn ontology_relation_object_id(name: &str) -> String {
    format!("ontology:relation:{name}")
}

fn check_ontology_admin(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("ontology", &refs)
        // Schema admins govern the object model the ontology projects from, so
        // they may administer the ontology as well.
        || security.can_admin("schema", &refs)
        || security.can_admin(object_id, &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("ontology admin required"))
}

fn check_ontology_class_read(
    security: &SecurityChecker,
    class: &ontology::OntologyClass,
    principals: &[String],
) -> Result<(), Status> {
    check_read(security, &ontology_class_object_id(&class.name), principals)?;
    for reference in class
        .superclasses
        .iter()
        .chain(&class.equivalent_classes)
        .chain(&class.disjoint_classes)
    {
        check_read(security, &ontology_class_object_id(reference), principals)?;
    }
    Ok(())
}

fn check_ontology_relation_read(
    security: &SecurityChecker,
    relation: &ontology::OntologyRelation,
    principals: &[String],
) -> Result<(), Status> {
    check_read(
        security,
        &ontology_relation_object_id(&relation.name),
        principals,
    )?;
    for endpoint in [&relation.domain, &relation.range] {
        check_read(security, &ontology_class_object_id(endpoint), principals)?;
    }
    if !relation.inverse.is_empty() {
        check_read(
            security,
            &ontology_relation_object_id(&relation.inverse),
            principals,
        )?;
    }
    Ok(())
}

fn ontology_link_violations(
    registry: &ontology::OntologyRegistry,
    relation: &ontology::OntologyRelation,
    from_kind: &str,
    to_kind: &str,
) -> (bool, bool) {
    (
        !registry.kind_satisfies_class(from_kind, &relation.domain),
        !registry.kind_satisfies_class(to_kind, &relation.range),
    )
}

fn validate_mapped_link(
    registry: &ontology::OntologyRegistry,
    mapped_relation: &str,
    from_kind: &str,
    to_kind: &str,
) -> Result<(), Status> {
    if registry
        .constraints_for_mapped_relation(mapped_relation)
        .into_iter()
        .any(|relation| {
            let (domain, range) = ontology_link_violations(registry, relation, from_kind, to_kind);
            domain || range
        })
    {
        return Err(Status::failed_precondition(
            "link endpoints violate ontology constraint",
        ));
    }
    Ok(())
}

fn map_graph_mutation_error(error: String) -> Status {
    if error == "link endpoints violate ontology constraint" {
        Status::failed_precondition(error)
    } else {
        Status::internal(error)
    }
}

fn check_ontology_grant_target(
    db: &RuntimeDb,
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<bool, Status> {
    let exists = if let Some(name) = object_id.strip_prefix("ontology:class:") {
        db.get_ontology_class(name)
            .map_err(Status::internal)?
            .is_some()
    } else if let Some(name) = object_id.strip_prefix("ontology:relation:") {
        db.get_ontology_relation(name)
            .map_err(Status::internal)?
            .is_some()
    } else {
        return Ok(false);
    };
    if !exists {
        return Err(Status::not_found("grant target not found"));
    }
    check_ontology_admin(security, object_id, principals)?;
    Ok(true)
}

fn to_proto_ontology_property(property: &ontology::OntologyProperty) -> OntologyProperty {
    OntologyProperty {
        name: property.name.clone(),
        r#type: property.prop_type.as_str().to_string(),
        required: property.required,
        description: property.description.clone(),
    }
}

fn from_proto_ontology_property(
    property: &OntologyProperty,
) -> Result<ontology::OntologyProperty, Status> {
    let prop_type = schema::PropertyType::parse(&property.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown property type: {}", property.r#type))
    })?;
    Ok(ontology::OntologyProperty {
        name: property.name.clone(),
        prop_type,
        required: property.required,
        description: property.description.clone(),
    })
}

fn to_proto_ontology_class(class: &ontology::OntologyClass) -> OntologyClass {
    OntologyClass {
        name: class.name.clone(),
        description: class.description.clone(),
        superclasses: class.superclasses.clone(),
        equivalent_classes: class.equivalent_classes.clone(),
        disjoint_classes: class.disjoint_classes.clone(),
        properties: class
            .properties
            .iter()
            .map(to_proto_ontology_property)
            .collect(),
        is_builtin: class.is_builtin,
        mapped_kind: class.mapped_kind.clone(),
    }
}

fn from_proto_ontology_class(class: &OntologyClass) -> Result<ontology::OntologyClass, Status> {
    let properties = class
        .properties
        .iter()
        .map(from_proto_ontology_property)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ontology::OntologyClass {
        name: class.name.clone(),
        description: class.description.clone(),
        superclasses: class.superclasses.clone(),
        equivalent_classes: class.equivalent_classes.clone(),
        disjoint_classes: class.disjoint_classes.clone(),
        properties,
        is_builtin: class.is_builtin,
        mapped_kind: class.mapped_kind.clone(),
    })
}

fn to_proto_ontology_relation(relation: &ontology::OntologyRelation) -> OntologyRelation {
    OntologyRelation {
        name: relation.name.clone(),
        description: relation.description.clone(),
        domain: relation.domain.clone(),
        range: relation.range.clone(),
        cardinality: Some(Cardinality {
            min: relation.cardinality.min,
            max: relation.cardinality.max,
        }),
        inverse: relation.inverse.clone(),
        transitive: relation.transitive,
        is_builtin: relation.is_builtin,
        mapped_relation: relation.mapped_relation.clone(),
    }
}

fn from_proto_ontology_relation(
    relation: &OntologyRelation,
) -> Result<ontology::OntologyRelation, Status> {
    let cardinality = relation
        .cardinality
        .as_ref()
        .map(|cardinality| ontology::Cardinality {
            min: cardinality.min,
            max: cardinality.max,
        })
        .unwrap_or_default();
    Ok(ontology::OntologyRelation {
        name: relation.name.clone(),
        description: relation.description.clone(),
        domain: relation.domain.clone(),
        range: relation.range.clone(),
        cardinality,
        inverse: relation.inverse.clone(),
        transitive: relation.transitive,
        is_builtin: relation.is_builtin,
        mapped_relation: relation.mapped_relation.clone(),
    })
}

fn schema_object_id(kind: &str) -> String {
    format!("schema:{kind}")
}

fn action_object_id(name: &str) -> String {
    format!("action:{name}")
}

/// Internal governance object kinds that must never be created, mutated, read,
/// or listed through the generic object CRUD RPCs. They hold policy, held-action
/// params (potentially sensitive), and blast-radius counters, and are managed
/// only through their dedicated RPCs + server-internal DB paths. Exposing them
/// via CRUD would leak held params and let callers forge policy or tamper with
/// blast-radius counters.
const RESERVED_GOVERNANCE_KINDS: &[&str] = &[
    action_policy::ACTION_POLICY_KIND,
    action_policy::BLAST_RADIUS_KIND,
    action_approval::ACTION_APPROVAL_KIND,
    crate::domain::KIND_CAPABILITY,
    crate::domain::KIND_EXTERNAL_EVIDENCE,
    governed_fact_domain::PROFILE_KIND,
    governed_fact_domain::FACT_KIND,
    governed_fact_domain::WAIVER_KIND,
];
const ERASED_NAMESPACE: &str = "[erased]";

fn is_reserved_governance_kind(kind: &str) -> bool {
    RESERVED_GOVERNANCE_KINDS.contains(&kind)
}

fn ensure_action_schema_kinds_allowed(kinds: &[String]) -> Result<(), Status> {
    if kinds.iter().any(|kind| is_reserved_governance_kind(kind)) {
        return Err(Status::permission_denied(
            "reserved governance kinds require dedicated APIs",
        ));
    }
    Ok(())
}

/// Resolve the namespace used for action-policy scope resolution: prefer the
/// namespace of an existing target object, falling back to a `namespace` param
/// (used by `create_object` before the object exists).
fn action_policy_namespace(
    db: &RuntimeDb,
    target_ids: &[String],
    params: &std::collections::HashMap<String, String>,
) -> String {
    for id in target_ids {
        if let Ok(Some(object)) = db.get_object(id) {
            if object.kind == "namespace" {
                let namespace = object
                    .external_id
                    .strip_prefix("namespace:")
                    .map(str::trim)
                    .filter(|namespace| !namespace.is_empty())
                    .unwrap_or_else(|| object.name.trim());
                if !namespace.is_empty() {
                    return namespace.to_string();
                }
            }
            if !object.namespace.trim().is_empty() {
                return object.namespace;
            }
        }
    }
    params
        .get("namespace")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
}

fn approval_lifecycle_status(error: ApprovalLifecycleError) -> Status {
    match error {
        ApprovalLifecycleError::NotFound => Status::not_found("approval not found"),
        ApprovalLifecycleError::Terminal { id, status } => {
            Status::failed_precondition(format!("approval {id} is already {status}"))
        }
        ApprovalLifecycleError::PolicyDenied => {
            Status::failed_precondition("action policy now denies this approval")
        }
        ApprovalLifecycleError::Limit(ActionLimitExceeded::Internal(error))
        | ApprovalLifecycleError::Storage(error) => Status::internal(error),
        ApprovalLifecycleError::Limit(ActionLimitExceeded::BlastRadius { work_unit, .. }) => {
            Status::resource_exhausted(format!(
                "blast-radius cap exceeded for work unit {work_unit}"
            ))
        }
        ApprovalLifecycleError::Limit(ActionLimitExceeded::Budget { subject, .. }) => {
            Status::resource_exhausted(format!("action budget exhausted for {subject}"))
        }
        ApprovalLifecycleError::InvalidArgument(error) => Status::invalid_argument(error),
        ApprovalLifecycleError::FailedPrecondition(error) => Status::failed_precondition(error),
        ApprovalLifecycleError::ReferencedNotFound(error) => Status::not_found(error),
        ApprovalLifecycleError::PermissionDenied(error) => Status::permission_denied(error),
        ApprovalLifecycleError::Unauthenticated(error) => Status::unauthenticated(error),
        ApprovalLifecycleError::AlreadyExists(error) => Status::already_exists(error),
        ApprovalLifecycleError::ResourceExhausted(error) => Status::resource_exhausted(error),
        ApprovalLifecycleError::Unavailable(error) => Status::unavailable(error),
    }
}

fn approval_adapter_error(status: Status) -> ApprovalLifecycleError {
    match status.code() {
        tonic::Code::InvalidArgument => {
            ApprovalLifecycleError::InvalidArgument(status.message().into())
        }
        tonic::Code::FailedPrecondition => {
            ApprovalLifecycleError::FailedPrecondition(status.message().into())
        }
        tonic::Code::PermissionDenied => {
            ApprovalLifecycleError::PermissionDenied(status.message().into())
        }
        tonic::Code::Unauthenticated => {
            ApprovalLifecycleError::Unauthenticated(status.message().into())
        }
        tonic::Code::AlreadyExists => {
            ApprovalLifecycleError::AlreadyExists(status.message().into())
        }
        tonic::Code::ResourceExhausted => {
            ApprovalLifecycleError::ResourceExhausted(status.message().into())
        }
        tonic::Code::Unavailable => ApprovalLifecycleError::Unavailable(status.message().into()),
        tonic::Code::NotFound => {
            ApprovalLifecycleError::ReferencedNotFound(status.message().into())
        }
        _ => ApprovalLifecycleError::Storage(status.message().into()),
    }
}

fn action_work_lifecycle_status(error: ActionWorkLifecycleError) -> Status {
    match error {
        ActionWorkLifecycleError::InvalidArgument(message) => Status::invalid_argument(message),
        ActionWorkLifecycleError::FailedPrecondition(message) => {
            Status::failed_precondition(message)
        }
        ActionWorkLifecycleError::AlreadyExists(message) => Status::already_exists(message),
        ActionWorkLifecycleError::NotFound(message) => Status::not_found(message),
        ActionWorkLifecycleError::Internal(message) => Status::internal(message),
    }
}

fn to_proto_attestation(a: &attestation::PolicyAttestation) -> PolicyAttestation {
    PolicyAttestation {
        id: a.id.clone(),
        decision_id: a.decision_id.clone(),
        policy_kind: a.policy_kind.clone(),
        policy_scope: a.policy_scope.clone(),
        policy_version: a.policy_version.clone(),
        policy_snapshot: a.policy_snapshot.clone(),
        inputs: a.inputs.clone(),
        decision: a.decision.clone(),
        content_hash: a.content_hash.clone(),
        created: a.created,
    }
}

fn to_proto_action_approval(approval: &action_approval::ActionApproval) -> ActionApproval {
    ActionApproval {
        id: approval.id.clone(),
        status: approval.status.as_str().to_string(),
        actor: approval.actor.clone(),
        action: approval.action.clone(),
        params: approval.redacted_params(),
        work_unit: approval.work_unit.clone(),
        policy_scope: approval.policy_scope.clone(),
        risk_class: approval.risk_class.clone(),
        target_id: approval.target_id.clone(),
        created: approval.created,
        updated: approval.updated,
        decided_by: approval.decided_by.clone(),
        outcome: approval.outcome.clone(),
    }
}

fn to_proto_action_policy(policy: &action_policy::ActionPolicy) -> ActionPolicy {
    ActionPolicy {
        scope: policy.scope.clone(),
        default_decision: policy.default_decision.as_str().to_string(),
        action_overrides: policy
            .action_overrides
            .iter()
            .map(|(name, decision)| (name.clone(), decision.as_str().to_string()))
            .collect(),
        risk_overrides: policy
            .risk_overrides
            .iter()
            .map(|(risk, decision)| (risk.as_str().to_string(), decision.as_str().to_string()))
            .collect(),
        max_mutations_per_work_unit: policy.max_mutations_per_work_unit.unwrap_or(0),
        max_deletes_per_work_unit: policy.max_deletes_per_work_unit.unwrap_or(0),
    }
}

fn from_proto_action_policy(policy: &ActionPolicy) -> Result<action_policy::ActionPolicy, Status> {
    let scope = policy.scope.trim();
    if scope.is_empty() {
        return Err(Status::invalid_argument("policy scope required"));
    }
    let default_decision = if policy.default_decision.trim().is_empty() {
        ActionDecision::Allow
    } else {
        ActionDecision::parse(&policy.default_decision)
            .ok_or_else(|| Status::invalid_argument("invalid default_decision"))?
    };
    let mut action_overrides = HashMap::new();
    for (name, decision) in &policy.action_overrides {
        let decision = ActionDecision::parse(decision).ok_or_else(|| {
            Status::invalid_argument(format!("invalid decision for action {name}"))
        })?;
        action_overrides.insert(name.clone(), decision);
    }
    let mut risk_overrides = HashMap::new();
    for (risk, decision) in &policy.risk_overrides {
        let parsed_risk = action::RiskClass::parse(risk)
            .ok_or_else(|| Status::invalid_argument(format!("invalid risk class {risk}")))?;
        let decision = ActionDecision::parse(decision)
            .ok_or_else(|| Status::invalid_argument(format!("invalid decision for risk {risk}")))?;
        risk_overrides.insert(parsed_risk, decision);
    }
    Ok(action_policy::ActionPolicy {
        scope: scope.to_string(),
        default_decision,
        action_overrides,
        risk_overrides,
        max_mutations_per_work_unit: (policy.max_mutations_per_work_unit > 0)
            .then_some(policy.max_mutations_per_work_unit),
        max_deletes_per_work_unit: (policy.max_deletes_per_work_unit > 0)
            .then_some(policy.max_deletes_per_work_unit),
    })
}

fn to_proto_action_type(action_type: &action::ActionTypeDef) -> ActionTypeDef {
    ActionTypeDef {
        name: action_type.name.clone(),
        description: action_type.description.clone(),
        params: action_type
            .params
            .iter()
            .map(to_proto_action_param)
            .collect(),
        ops: action_type.ops.iter().map(to_proto_action_op).collect(),
        target_kind: action_type.target_kind.clone(),
        created: action_type.created,
        required_purpose: action_type.required_purpose.clone(),
    }
}

fn from_proto_action_type(action_type: &ActionTypeDef) -> Result<action::ActionTypeDef, Status> {
    let params = action_type
        .params
        .iter()
        .map(from_proto_action_param)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(action::ActionTypeDef {
        name: action_type.name.clone(),
        description: action_type.description.clone(),
        params,
        ops: action_type.ops.iter().map(from_proto_action_op).collect(),
        target_kind: action_type.target_kind.clone(),
        created: action_type.created,
        required_purpose: action_type.required_purpose.trim().to_string(),
    })
}

fn from_proto_action_param(param: &ActionParamDef) -> Result<action::ActionParamDef, Status> {
    let param_type = schema::PropertyType::parse(&param.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown action param type: {}", param.r#type))
    })?;
    Ok(action::ActionParamDef {
        name: param.name.clone(),
        param_type,
        required: param.required,
        enum_values: param.enum_values.clone(),
    })
}

fn from_proto_action_op(op: &ActionOp) -> action::ActionOp {
    action::ActionOp {
        op: op.op.clone(),
        property: op.property.clone(),
        value_from: op.value_from.clone(),
        relation: op.relation.clone(),
    }
}

fn to_proto_action_param(param: &action::ActionParamDef) -> ActionParamDef {
    ActionParamDef {
        name: param.name.clone(),
        r#type: param.param_type.as_str().to_string(),
        required: param.required,
        enum_values: param.enum_values.clone(),
    }
}

fn to_proto_action_op(op: &action::ActionOp) -> ActionOp {
    ActionOp {
        op: op.op.clone(),
        property: op.property.clone(),
        value_from: op.value_from.clone(),
        relation: op.relation.clone(),
    }
}

fn validate_computed_property_functions(
    db: &RuntimeDb,
    object_type: &schema::ObjectType,
) -> Result<(), Status> {
    for property in &object_type.properties {
        if property.prop_type != schema::PropertyType::Computed || property.compute_expr.is_empty()
        {
            continue;
        }
        if db
            .get_function(&property.compute_expr)
            .map_err(Status::internal)?
            .is_none()
        {
            return Err(Status::invalid_argument(format!(
                "computed property {} references unknown function {}",
                property.name, property.compute_expr
            )));
        }
    }
    Ok(())
}

fn to_proto_dataset(d: &dataset::Dataset) -> Dataset {
    Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| ColumnDef {
                name: c.name.clone(),
                r#type: c.col_type.clone(),
                classification: c.classification.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}

fn from_proto_dataset(d: &Dataset) -> dataset::Dataset {
    dataset::Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| dataset::ColumnDef {
                name: c.name.clone(),
                col_type: c.r#type.clone(),
                classification: c.classification.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}

fn from_proto_row_filters(filters: &[RowFilter]) -> Vec<dataset::RowFilter> {
    filters
        .iter()
        .map(|f| dataset::RowFilter {
            column: f.column.clone(),
            op: f.op.clone(),
            value: f.value.clone(),
        })
        .collect()
}

fn to_proto_virtual_table(vt: &dataset::VirtualTable) -> VirtualTable {
    VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: vt
            .filters
            .iter()
            .map(|f| RowFilter {
                column: f.column.clone(),
                op: f.op.clone(),
                value: f.value.clone(),
            })
            .collect(),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}

fn from_proto_virtual_table(vt: &VirtualTable) -> dataset::VirtualTable {
    dataset::VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: from_proto_row_filters(&vt.filters),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}

fn to_proto_function(f: &function::Function) -> Function {
    Function {
        name: f.name.clone(),
        description: f.description.clone(),
        params: f
            .params
            .iter()
            .map(|p| FuncParam {
                name: p.name.clone(),
                r#type: p.param_type.clone(),
                required: p.required,
            })
            .collect(),
        pipeline: f
            .pipeline
            .iter()
            .map(|s| PipelineStep {
                op: s.op.clone(),
                kind: s.kind.clone(),
                property: s.property.clone(),
                value: s.value.clone(),
                relation: s.relation.clone(),
                dir: s.dir.clone(),
                func: s.func.clone(),
                field: s.field.clone(),
                r#as: s.alias.clone(),
            })
            .collect(),
        created: f.created,
    }
}

fn from_proto_function(f: &Function) -> function::Function {
    function::Function {
        name: f.name.clone(),
        description: f.description.clone(),
        params: f
            .params
            .iter()
            .map(|p| function::FuncParam {
                name: p.name.clone(),
                param_type: p.r#type.clone(),
                required: p.required,
            })
            .collect(),
        pipeline: f
            .pipeline
            .iter()
            .map(|s| function::PipelineStep {
                op: s.op.clone(),
                kind: s.kind.clone(),
                property: s.property.clone(),
                value: s.value.clone(),
                relation: s.relation.clone(),
                dir: s.dir.clone(),
                func: s.func.clone(),
                field: s.field.clone(),
                alias: s.r#as.clone(),
            })
            .collect(),
        created: f.created,
    }
}

fn to_proto_grant(g: &security::Grant) -> Grant {
    Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role: g.role.as_str().to_string(),
        created: g.created,
    }
}

fn to_proto_contention_scope(scope: &coordination::ContentionScope) -> ContentionScope {
    ContentionScope {
        id: scope.id.clone(),
        name: scope.name.clone(),
        parent_scope_id: scope.parent_scope_id.clone(),
        max_concurrency: scope.max_concurrency,
        admission_policy: scope.admission_policy.clone(),
        heartbeat_ttl_seconds: scope.heartbeat_ttl_seconds,
        timeout_seconds: scope.timeout_seconds,
        owner_principal: scope.owner_principal.clone(),
        created: scope.created,
        updated: scope.updated,
    }
}

fn from_proto_contention_scope(scope: &ContentionScope) -> coordination::ContentionScope {
    coordination::ContentionScope {
        id: scope.id.clone(),
        name: scope.name.clone(),
        parent_scope_id: scope.parent_scope_id.clone(),
        max_concurrency: scope.max_concurrency,
        admission_policy: scope.admission_policy.clone(),
        heartbeat_ttl_seconds: scope.heartbeat_ttl_seconds,
        timeout_seconds: scope.timeout_seconds,
        owner_principal: scope.owner_principal.clone(),
        created: scope.created,
        updated: scope.updated,
    }
}

fn to_proto_work_unit(work_unit: &coordination::WorkUnit) -> WorkUnit {
    WorkUnit {
        id: work_unit.id.clone(),
        kind: work_unit.kind.clone(),
        actor: work_unit.actor.clone(),
        target_object_id: work_unit.target_object_id.clone(),
        status: work_unit.status.clone(),
        requested_spec: work_unit.requested_spec.clone(),
        scope_id: work_unit.scope_id.clone(),
        priority: work_unit.priority,
        timeout_seconds: work_unit.timeout_seconds,
        heartbeat_ttl_seconds: work_unit.heartbeat_ttl_seconds,
        created_at: work_unit.created_at,
        admitted_at: work_unit.admitted_at,
        started_at: work_unit.started_at,
        finished_at: work_unit.finished_at,
        last_heartbeat_at: work_unit.last_heartbeat_at,
        failure_reason: work_unit.failure_reason.clone(),
        cancel_reason: work_unit.cancel_reason.clone(),
        owner_principal: work_unit.owner_principal.clone(),
        creator_principal: work_unit.creator_principal.clone(),
        idempotency_key: work_unit.idempotency_key.clone(),
        updated_at: work_unit.updated_at,
    }
}

fn from_proto_work_unit(work_unit: &WorkUnit) -> coordination::WorkUnit {
    coordination::WorkUnit {
        id: work_unit.id.clone(),
        kind: work_unit.kind.clone(),
        actor: work_unit.actor.clone(),
        target_object_id: work_unit.target_object_id.clone(),
        status: work_unit.status.clone(),
        requested_spec: work_unit.requested_spec.clone(),
        scope_id: work_unit.scope_id.clone(),
        priority: work_unit.priority,
        timeout_seconds: work_unit.timeout_seconds,
        heartbeat_ttl_seconds: work_unit.heartbeat_ttl_seconds,
        created_at: work_unit.created_at,
        admitted_at: work_unit.admitted_at,
        started_at: work_unit.started_at,
        finished_at: work_unit.finished_at,
        last_heartbeat_at: work_unit.last_heartbeat_at,
        failure_reason: work_unit.failure_reason.clone(),
        cancel_reason: work_unit.cancel_reason.clone(),
        owner_principal: work_unit.owner_principal.clone(),
        creator_principal: work_unit.creator_principal.clone(),
        idempotency_key: work_unit.idempotency_key.clone(),
        updated_at: work_unit.updated_at,
    }
}

fn to_proto_reservation(reservation: &coordination::Reservation) -> Reservation {
    Reservation {
        id: reservation.id.clone(),
        work_unit_id: reservation.work_unit_id.clone(),
        scope_id: reservation.scope_id.clone(),
        status: reservation.status.clone(),
        lease_owner: reservation.lease_owner.clone(),
        leased_at: reservation.leased_at,
        expires_at: reservation.expires_at,
        released_at: reservation.released_at,
        created_at: reservation.created_at,
    }
}

fn to_proto_run_event(event: &coordination::RunEvent) -> RunEvent {
    RunEvent {
        id: event.id.clone(),
        work_unit_id: event.work_unit_id.clone(),
        event_type: event.event_type.clone(),
        message: event.message.clone(),
        evidence: event.evidence.clone(),
        created_at: event.created_at,
    }
}

fn from_proto_work_unit_filter(filter: &WorkUnitFilter) -> coordination::WorkUnitFilter {
    coordination::WorkUnitFilter {
        status: if filter.status.is_empty() {
            None
        } else {
            Some(filter.status.clone())
        },
        actor: if filter.actor.is_empty() {
            None
        } else {
            Some(filter.actor.clone())
        },
        scope_id: if filter.scope_id.is_empty() {
            None
        } else {
            Some(filter.scope_id.clone())
        },
        target_object_id: if filter.target_object_id.is_empty() {
            None
        } else {
            Some(filter.target_object_id.clone())
        },
        owner_principal: if filter.owner_principal.is_empty() {
            None
        } else {
            Some(filter.owner_principal.clone())
        },
        statuses: filter.statuses.clone(),
        created_after: filter.created_after,
        updated_after: filter.updated_after,
        creator_principal: if filter.creator_principal.is_empty() {
            None
        } else {
            Some(filter.creator_principal.clone())
        },
        page_token: if filter.page_token.is_empty() {
            None
        } else {
            Some(filter.page_token.clone())
        },
        limit: filter.limit,
        offset: filter.offset,
    }
}

fn dedup_principal(principals: &[String]) -> String {
    principals.first().cloned().unwrap_or_default()
}

fn trim_page<T>(items: &mut Vec<T>, limit: i32) {
    if limit > 0 && items.len() > limit as usize {
        items.truncate(limit as usize);
    }
}

fn initialize_work_unit_for_create(work_unit: &mut coordination::WorkUnit, principal: &str) {
    if work_unit.owner_principal.is_empty() {
        work_unit.owner_principal = principal.into();
    }
    if work_unit.creator_principal.is_empty() {
        work_unit.creator_principal = principal.into();
    }
    work_unit.status = coordination::WORK_UNIT_STATUS_PENDING.into();
    work_unit.admitted_at = 0;
    work_unit.started_at = 0;
    work_unit.finished_at = 0;
    work_unit.last_heartbeat_at = 0;
    work_unit.failure_reason.clear();
    work_unit.cancel_reason.clear();
    work_unit.updated_at = work_unit.created_at;
}

fn to_domain_handoff_reference(reference: &HandoffReference) -> handoff_domain::HandoffReference {
    handoff_domain::HandoffReference {
        kind: reference.kind.clone(),
        id: reference.id.clone(),
        version: reference.version.clone(),
        omitted: reference.omitted,
        omission_reason: reference.omission_reason.clone(),
    }
}

fn to_proto_handoff_reference(reference: &handoff_domain::HandoffReference) -> HandoffReference {
    HandoffReference {
        kind: reference.kind.clone(),
        id: reference.id.clone(),
        version: reference.version.clone(),
        omitted: reference.omitted,
        omission_reason: reference.omission_reason.clone(),
    }
}

fn to_proto_handoff(manifest: &handoff_domain::HandoffManifest) -> HandoffManifest {
    HandoffManifest {
        id: manifest.id.clone(),
        namespace: manifest.namespace.clone(),
        parent_operation_id: manifest.parent_operation_id.clone(),
        parent_attempt_id: manifest.parent_attempt_id.clone(),
        parent_work_unit_id: manifest.parent_work_unit_id.clone(),
        references: manifest
            .references
            .iter()
            .map(to_proto_handoff_reference)
            .collect(),
        creator_principal: manifest.creator_principal.clone(),
        intended_principal: manifest.intended_principal.clone(),
        intended_scope: manifest.intended_scope.clone(),
        purpose: manifest.purpose.clone(),
        created_at_ms: manifest.created_at_ms,
        expires_at_ms: manifest.expires_at_ms,
        digest: manifest.digest.clone(),
        supersedes_manifest_id: manifest.supersedes_manifest_id.clone(),
        revoked: manifest.revoked,
    }
}

fn reference_content_digest(value: &impl serde::Serialize) -> Result<String, Status> {
    let bytes = serde_json::to_vec(value).map_err(|error| Status::internal(error.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn handoff_reference_available(
    service: &SekaiServiceImpl,
    reference: &handoff_domain::HandoffReference,
    namespace: &str,
    principals: &[String],
    now_ms: i64,
) -> Result<bool, Status> {
    let available = match reference.kind.as_str() {
        "operation_receipt" => {
            if let Some(receipt) = service
                .db
                .get_operation_receipt(&reference.id)
                .map_err(Status::internal)?
            {
                let version = reference_content_digest(&receipt)?;
                receipt.namespace == namespace
                    && version == reference.version
                    && principals.iter().any(|p| {
                        p == &receipt.initiating_actor || matches!(p.as_str(), "root" | "local")
                    })
            } else {
                false
            }
        }
        "work_unit" => service
            .db
            .get_work_unit(&reference.id)
            .map_err(Status::internal)?
            .is_some_and(|work_unit| {
                reference_content_digest(&work_unit).is_ok_and(|digest| digest == reference.version)
                    // Unbound work units have no namespace fact to match to the
                    // manifest. Owner readability alone must not widen scope.
                    && !work_unit.target_object_id.is_empty()
                    && service
                        .db
                        .get_object(&work_unit.target_object_id)
                        .is_ok_and(|object| {
                            object.is_some_and(|object| object.namespace == namespace)
                        })
                    && check_work_unit_read(&service.db, &service.security, &work_unit, principals)
                        .is_ok()
            }),
        "object" => service
            .db
            .get_object(&reference.id)
            .map_err(Status::internal)?
            .is_some_and(|object| {
                object.namespace == namespace
                    && reference_content_digest(&object)
                        .is_ok_and(|digest| digest == reference.version)
                    && check_team_namespace(&service.db, principals, namespace, false).is_ok()
                    && check_read(&service.security, &object.id, principals).is_ok()
            }),
        "evidence_submission" => {
            if let Some(submission) = service
                .db
                .get_evidence_submission(&reference.id)
                .map_err(Status::internal)?
            {
                let projected = service
                    .db
                    .get_evidence_projection_object_id(&reference.id)
                    .map_err(Status::internal)?;
                submission.namespace == namespace
                    && submission.content_digest == reference.version
                    && submission.lifecycle_state.is_usable()
                    && submission
                        .expires_at_ms
                        .is_none_or(|expiry| expiry > now_ms)
                    && projected
                        .is_some_and(|id| check_read(&service.security, &id, principals).is_ok())
            } else {
                false
            }
        }
        "kioku" => {
            let Ok(version) = reference.version.parse::<u32>() else {
                return Ok(false);
            };
            if let Some(memory) = service
                .db
                .get_kioku_memory(&reference.id, version)
                .map_err(Status::internal)?
            {
                memory.namespace == namespace
                    && memory.state == crate::chisei::kioku::MemoryLifecycleState::Active
                    && memory.expires_at_ms.is_none_or(|expiry| expiry > now_ms)
                    && memory
                        .retention_until_ms
                        .is_none_or(|retention| retention > now_ms)
                    && principals.iter().any(|principal| {
                        service
                            .db
                            .kioku_authorized_classification_ceiling(namespace, principal)
                            .is_ok_and(|ceiling| memory.classification <= ceiling)
                    })
            } else {
                false
            }
        }
        _ => false,
    };
    Ok(available)
}

fn map_handoff_lifecycle_error(error: HandoffLifecycleError) -> Status {
    match error {
        HandoffLifecycleError::InvalidArgument(message) => Status::invalid_argument(message),
        HandoffLifecycleError::AlreadyExists(message) => Status::already_exists(message),
        HandoffLifecycleError::FailedPrecondition(message) => Status::failed_precondition(message),
        HandoffLifecycleError::NotFound(message) => Status::not_found(message),
        HandoffLifecycleError::Storage(message) => Status::internal(message),
    }
}

fn aggregate_reconcile_summary(
    summary: &mut coordination::ReconcileSummary,
    next: coordination::ReconcileSummary,
) {
    summary.work_units_reconciled += next.work_units_reconciled;
    summary.reservations_released += next.reservations_released;
    summary.details.extend(next.details);
}

fn reconcile_owned_scope(
    db: &RuntimeDb,
    now_ms: i64,
    scope_id: String,
    dry_run: bool,
    limit: i32,
    summary: &mut coordination::ReconcileSummary,
) -> Result<(), Status> {
    if limit > 0 && summary.work_units_reconciled >= limit {
        return Ok(());
    }
    let remaining = if limit > 0 {
        limit - summary.work_units_reconciled
    } else {
        0
    };
    let next = db
        .reconcile_work_units(
            now_ms,
            &coordination::ReconcileFilter {
                dry_run,
                work_unit_id: None,
                scope_id: Some(scope_id),
                limit: remaining,
            },
        )
        .map_err(Status::internal)?;
    aggregate_reconcile_summary(summary, next);
    Ok(())
}

fn from_proto_grant(g: &Grant) -> Result<security::Grant, Status> {
    let role = security::Role::parse(&g.role).ok_or(Status::invalid_argument("invalid role"))?;
    Ok(security::Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role,
        created: g.created,
    })
}

fn from_proto_context_root(root: ContextRoot) -> Result<retrieval::RetrievalRoot, Status> {
    let configured = [
        !root.object_id.is_empty(),
        !root.external_id.is_empty(),
        !root.link_id.is_empty(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count();
    if configured != 1 {
        return Err(Status::invalid_argument(
            "each context root must set exactly one of object_id, external_id, or link_id",
        ));
    }
    if !root.object_id.is_empty() {
        Ok(retrieval::RetrievalRoot::Object(root.object_id))
    } else if !root.external_id.is_empty() {
        Ok(retrieval::RetrievalRoot::External(root.external_id))
    } else {
        Ok(retrieval::RetrievalRoot::Link(root.link_id))
    }
}

fn map_retrieval_error(error: retrieval::RetrievalError) -> Status {
    match error {
        retrieval::RetrievalError::InvalidArgument(message) => Status::invalid_argument(message),
        retrieval::RetrievalError::Storage(message) => Status::internal(message),
    }
}

fn map_lease_error(error: crate::sekai::lease::LeaseError) -> Status {
    use crate::sekai::lease::LeaseError;
    match error {
        LeaseError::Invalid(message) => Status::invalid_argument(message),
        LeaseError::Conflict(message) => Status::already_exists(message),
        LeaseError::Stale(message) => Status::failed_precondition(message),
        LeaseError::NotExpired => Status::failed_precondition("lease has not expired"),
        LeaseError::Storage(message) => Status::internal(message),
        LeaseError::Mutation(message) if message == "not found" => Status::not_found(message),
        LeaseError::Mutation(message) => Status::failed_precondition(message),
    }
}

fn map_lease_lifecycle_error(error: LeaseLifecycleError) -> Status {
    match error {
        LeaseLifecycleError::InvalidArgument(message) => Status::invalid_argument(message),
        LeaseLifecycleError::FailedPrecondition(message) => Status::failed_precondition(message),
        LeaseLifecycleError::PermissionDenied(message) => Status::permission_denied(message),
        LeaseLifecycleError::NotFound(message) => Status::not_found(message),
        LeaseLifecycleError::Storage(message) => Status::internal(message),
        LeaseLifecycleError::Lease(error) => map_lease_error(error),
    }
}

fn map_work_unit_lifecycle_error(error: WorkUnitLifecycleError) -> Status {
    match error {
        WorkUnitLifecycleError::NotFound(message) => Status::not_found(message),
        WorkUnitLifecycleError::FailedPrecondition(message) => Status::failed_precondition(message),
        WorkUnitLifecycleError::Storage(message) => Status::internal(message),
    }
}

fn transition_work_unit<'a>(
    db: &RuntimeDb,
    principals: &[String],
    work_unit_id: &str,
    request_id: &str,
    transition: WorkUnitTransition<'a>,
) -> Result<coordination::WorkUnit, Status> {
    let principal = dedup_principal(principals);
    WorkUnitLifecycle::new(db)
        .transition(TransitionWorkUnit {
            work_unit_id,
            request_id,
            principal: &principal,
            transition,
            now_ms: chrono::Utc::now().timestamp_millis(),
        })
        .map_err(map_work_unit_lifecycle_error)
}

fn map_mutation_persistence_error(error: MutationPersistenceError) -> Status {
    match error {
        MutationPersistenceError::Graph(error) => map_graph_mutation_error(error),
        MutationPersistenceError::Lease(error) => map_lease_error(error),
        MutationPersistenceError::NotFound => Status::not_found("not found"),
    }
}

fn to_proto_lease(lease: &crate::sekai::lease::Lease) -> Lease {
    Lease {
        namespace: lease.namespace.clone(),
        key: lease.key.clone(),
        generation: lease.generation,
        fencing_token: lease.fencing_token.clone(),
        owner: lease.owner.clone(),
        status: lease.status.clone(),
        acquired_at_ms: lease.acquired_at_ms,
        refreshed_at_ms: lease.refreshed_at_ms,
        expires_at_ms: lease.expires_at_ms,
        released_at_ms: lease.released_at_ms,
        site_id: lease.site_id.clone(),
    }
}

fn authorize_namespace_action_admin(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<String, Status> {
    require_authenticated(principals)?;
    check_team_namespace(&service.db, principals, namespace, true)?;
    check_action_admin(
        &service.security,
        &format!("governed_action:{namespace}"),
        principals,
    )?;
    principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))
}

fn to_proto_governed_fact(fact: &governed_fact_domain::GovernedFactVersion) -> GovernedFactVersion {
    GovernedFactVersion {
        contract_version: fact.input.contract_version.clone(),
        object_id: fact.object_id.clone(),
        namespace: fact.input.namespace.clone(),
        fact_id: fact.input.fact_id.clone(),
        version: fact.input.version.clone(),
        fact_type: fact.input.fact_type.as_str().into(),
        statement: fact.input.statement.clone(),
        applicability: Some(GovernedFactApplicability {
            subject_profiles: fact.input.applicability.subject_profiles.clone(),
            subject_refs: fact.input.applicability.subject_refs.clone(),
        }),
        verification: Some(InvariantVerificationContract {
            predicate_kind: fact.input.verification.predicate_kind.clone(),
            input_schema: fact.input.verification.input_schema.clone(),
            result_schema: fact.input.verification.result_schema.clone(),
            evidence_types: fact.input.verification.evidence_types.clone(),
        }),
        requirement_version_ids: fact.input.requirement_version_ids.clone(),
        evidence_refs: fact.input.evidence_refs.clone(),
        source_ref: fact.input.source_ref.clone(),
        effective_from_ms: fact.input.effective_from_ms,
        supersedes_object_id: fact.input.supersedes_object_id.clone(),
        content_digest: fact.content_digest.clone(),
        created_by: fact.created_by.clone(),
        created_at_ms: fact.created_at_ms,
        access_marking: fact.input.access_marking.clone(),
        status: fact.input.status.clone(),
    }
}

fn to_proto_governed_waiver(
    waiver: &governed_fact_domain::GovernedWaiverVersion,
) -> GovernedWaiverVersion {
    GovernedWaiverVersion {
        contract_version: waiver.input.contract_version.clone(),
        object_id: waiver.object_id.clone(),
        namespace: waiver.input.namespace.clone(),
        waiver_id: waiver.input.waiver_id.clone(),
        version: waiver.input.version.clone(),
        invariant_version_ids: waiver.input.invariant_version_ids.clone(),
        applicability: Some(GovernedFactApplicability {
            subject_profiles: waiver.input.applicability.subject_profiles.clone(),
            subject_refs: waiver.input.applicability.subject_refs.clone(),
        }),
        reason: waiver.input.reason.clone(),
        evidence_refs: waiver.input.evidence_refs.clone(),
        source_ref: waiver.input.source_ref.clone(),
        valid_from_ms: waiver.input.valid_from_ms,
        expires_at_ms: waiver.input.expires_at_ms,
        supersedes_object_id: waiver.input.supersedes_object_id.clone(),
        content_digest: waiver.content_digest.clone(),
        created_by: waiver.created_by.clone(),
        created_at_ms: waiver.created_at_ms,
        access_marking: waiver.input.access_marking.clone(),
    }
}

fn to_proto_invariant_set(
    invariant_set: &governed_fact_domain::ResolvedInvariantSet,
) -> ResolvedInvariantSet {
    ResolvedInvariantSet {
        contract_version: invariant_set.contract_version.clone(),
        set_id: invariant_set.set_id.clone(),
        set_digest: invariant_set.set_digest.clone(),
        profile_digest: invariant_set.profile_digest.clone(),
        namespace: invariant_set.namespace.clone(),
        subject_profile: invariant_set.subject_profile.clone(),
        subject_ref: invariant_set.subject_ref.clone(),
        evaluation_time_ms: invariant_set.evaluation_time_ms,
        requirements: invariant_set
            .requirements
            .iter()
            .map(to_proto_governed_fact)
            .collect(),
        invariants: invariant_set
            .invariants
            .iter()
            .map(to_proto_governed_fact)
            .collect(),
        waivers: invariant_set
            .waivers
            .iter()
            .map(to_proto_governed_waiver)
            .collect(),
    }
}

const MAX_GOVERNED_VISIBILITY_WORK: usize = 8_192;

fn governed_reference_tree_visible(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    object_id: &str,
    visibility_cache: &mut HashMap<String, bool>,
    work: &mut usize,
) -> Result<bool, Status> {
    struct Frame {
        id: String,
        references: Option<Vec<String>>,
        next_reference: usize,
    }

    if let Some(visible) = visibility_cache.get(object_id) {
        return Ok(*visible);
    }
    let mut stack = vec![Frame {
        id: object_id.into(),
        references: None,
        next_reference: 0,
    }];
    let mut active = std::collections::BTreeSet::new();
    while !stack.is_empty() {
        let frame_index = stack.len() - 1;
        let id = stack[frame_index].id.clone();
        if stack[frame_index].references.is_none() {
            if *work >= MAX_GOVERNED_VISIBILITY_WORK {
                return Err(Status::resource_exhausted(
                    "governed reference visibility work exceeds its bound",
                ));
            }
            *work += 1;
            if !active.insert(id.clone()) {
                return Ok(false);
            }
            let object = service.db.get_object(&id).map_err(Status::internal)?;
            let visible = object.as_ref().is_some_and(|object| {
                object.namespace == namespace
                    && check_team_namespace(&service.db, principals, namespace, false).is_ok()
                    && check_read(&service.security, &id, principals).is_ok()
                    && object_passes_marking(&service.db, object, principals).unwrap_or(false)
            });
            if !visible {
                active.remove(&id);
                visibility_cache.insert(id, false);
                stack.pop();
                continue;
            }
            stack[frame_index].references =
                Some(governed_object_references(object.as_ref().unwrap())?);
        }
        let next_reference = stack[frame_index]
            .references
            .as_ref()
            .and_then(|references| references.get(stack[frame_index].next_reference).cloned());
        let Some(reference) = next_reference else {
            active.remove(&id);
            visibility_cache.insert(id, true);
            stack.pop();
            continue;
        };
        match visibility_cache.get(&reference).copied() {
            Some(true) => stack[frame_index].next_reference += 1,
            Some(false) => {
                active.remove(&id);
                visibility_cache.insert(id, false);
                stack.pop();
            }
            None if active.contains(&reference) => return Ok(false),
            None => stack.push(Frame {
                id: reference,
                references: None,
                next_reference: 0,
            }),
        }
    }
    Ok(visibility_cache.get(object_id).copied().unwrap_or(false))
}

fn governed_object_references(object: &domain::Object) -> Result<Vec<String>, Status> {
    if object.kind == governed_fact_domain::FACT_KIND {
        let fact = governed_fact_domain::fact_from_object(object).map_err(Status::data_loss)?;
        Ok(fact
            .input
            .requirement_version_ids
            .iter()
            .chain(fact.input.evidence_refs.iter())
            .chain(
                (!fact.input.supersedes_object_id.is_empty())
                    .then_some(&fact.input.supersedes_object_id),
            )
            .cloned()
            .collect())
    } else if object.kind == governed_fact_domain::WAIVER_KIND {
        let waiver = governed_fact_domain::waiver_from_object(object).map_err(Status::data_loss)?;
        Ok(waiver
            .input
            .invariant_version_ids
            .iter()
            .chain(waiver.input.evidence_refs.iter())
            .chain(
                (!waiver.input.supersedes_object_id.is_empty())
                    .then_some(&waiver.input.supersedes_object_id),
            )
            .cloned()
            .collect())
    } else {
        Ok(Vec::new())
    }
}

fn governed_object_for_read(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    object_id: &str,
    expected_kind: &str,
) -> Result<domain::Object, Status> {
    let object = service
        .db
        .get_object(object_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("governed fact not found"))?;
    if object.kind != expected_kind
        || enforce_namespace_tenant_context(&service.db, tenant_context, &object.namespace, false)
            .is_err()
        || check_team_namespace(&service.db, principals, &object.namespace, false).is_err()
        || check_read(&service.security, object_id, principals).is_err()
        || !object_passes_marking(&service.db, &object, principals).unwrap_or(false)
    {
        return Err(Status::not_found("governed fact not found"));
    }
    if matches!(
        object.kind.as_str(),
        governed_fact_domain::FACT_KIND | governed_fact_domain::WAIVER_KIND
    ) {
        let mut visibility_cache = HashMap::new();
        let mut visibility_work = 0;
        if !governed_reference_tree_visible(
            service,
            principals,
            &object.namespace,
            object_id,
            &mut visibility_cache,
            &mut visibility_work,
        )? {
            return Err(Status::not_found("governed fact not found"));
        }
    }
    Ok(object)
}

fn list_visible_governed_objects(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    kind: &str,
    visibility_cache: &mut HashMap<String, bool>,
    visibility_work: &mut usize,
) -> Result<Vec<domain::Object>, Status> {
    let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    let mut offset = 0i32;
    let mut visible = Vec::new();
    loop {
        let filter = domain::ListFilter {
            kind: Some(kind.into()),
            namespace: Some(namespace.into()),
            limit: domain::MAX_LIST_LIMIT,
            offset,
            ..domain::ListFilter::default()
        };
        let (page, total) = service
            .db
            .list_objects_with_total_for_principals(&filter, &principal_refs, &[])
            .map_err(Status::internal)?;
        if page.is_empty() {
            break;
        }
        offset = offset.saturating_add(page.len() as i32);
        for object in page {
            if object_passes_marking(&service.db, &object, principals).unwrap_or(false)
                && governed_reference_tree_visible(
                    service,
                    principals,
                    namespace,
                    &object.id,
                    visibility_cache,
                    visibility_work,
                )?
            {
                visible.push(object);
                if visible.len() > governed_fact_domain::MAX_FACTS_PER_NAMESPACE {
                    return Err(Status::resource_exhausted(
                        "authorized governed-fact inventory exceeds its bound",
                    ));
                }
            }
        }
        if offset >= total {
            break;
        }
    }
    Ok(visible)
}

fn from_proto_governed_action_type(
    proto: super::pb::sekai::GovernedActionType,
) -> Result<crate::sekai::governed_action_type::GovernedActionType, Status> {
    let domain = crate::sekai::governed_action_type::GovernedActionType {
        namespace: proto.namespace,
        type_id: proto.type_id,
        version: proto.version,
        description: proto.description,
        parameter_schema_json: proto.parameter_schema_json,
        allowed_effect_kinds: proto.allowed_effect_kinds,
        policy_scope: proto.policy_scope,
        budget_scope: proto.budget_scope,
        enabled: proto.enabled,
        created_by: proto.created_by,
        created_at_ms: proto.created_at_ms,
        updated_at_ms: proto.updated_at_ms,
        disabled_at_ms: proto.disabled_at_ms,
    };
    Ok(domain)
}

fn to_proto_governed_action_type(
    domain: &crate::sekai::governed_action_type::GovernedActionType,
) -> super::pb::sekai::GovernedActionType {
    super::pb::sekai::GovernedActionType {
        namespace: domain.namespace.clone(),
        type_id: domain.type_id.clone(),
        version: domain.version.clone(),
        description: domain.description.clone(),
        parameter_schema_json: domain.parameter_schema_json.clone(),
        allowed_effect_kinds: domain.allowed_effect_kinds.clone(),
        policy_scope: domain.policy_scope.clone(),
        budget_scope: domain.budget_scope.clone(),
        enabled: domain.enabled,
        created_by: domain.created_by.clone(),
        created_at_ms: domain.created_at_ms,
        updated_at_ms: domain.updated_at_ms,
        disabled_at_ms: domain.disabled_at_ms,
    }
}

fn to_proto_action_instance(
    domain: &crate::sekai::action_instance::ActionInstance,
) -> super::pb::sekai::ActionInstance {
    super::pb::sekai::ActionInstance {
        instance_id: domain.instance_id.clone(),
        namespace: domain.namespace.clone(),
        type_id: domain.type_id.clone(),
        version: domain.version.clone(),
        principal: domain.principal.clone(),
        parameters_json: domain.parameters_json.clone(),
        request_digest: domain.request_digest.clone(),
        idempotency_key: domain.idempotency_key.clone(),
        operation_id: domain.operation_id.clone(),
        status: domain.status.clone(),
        deny_reason: domain.deny_reason.clone(),
        evidence_submission_ids: domain.evidence_submission_ids.clone(),
        policy_decision: domain.policy_decision.clone(),
        budget_decision: domain.budget_decision.clone(),
        created_at_ms: domain.created_at_ms,
        decided_at_ms: domain.decided_at_ms,
    }
}

fn to_proto_action_effect(
    domain: &crate::sekai::action_effect::ActionEffect,
) -> super::pb::sekai::ActionEffect {
    super::pb::sekai::ActionEffect {
        effect_id: domain.effect_id.clone(),
        instance_id: domain.instance_id.clone(),
        namespace: domain.namespace.clone(),
        operation_id: domain.operation_id.clone(),
        kind: domain.kind.clone(),
        status: domain.status.clone(),
        payload_json: domain.payload_json.clone(),
        failure_reason: domain.failure_reason.clone(),
        created_at_ms: domain.created_at_ms,
        updated_at_ms: domain.updated_at_ms,
        claim_owner: domain.claim_owner.clone(),
        claim_generation: domain.claim_generation,
        claim_fencing_token: domain.claim_fencing_token.clone(),
        claim_expires_at_ms: domain.claim_expires_at_ms,
        claim_request_id: domain.claim_request_id.clone(),
        park_generation: domain.park_generation,
        active_resolution_id: domain.active_resolution_id.clone(),
        claim_attempt_count: domain.claim_attempt_count,
        lease_expiry_count: domain.lease_expiry_count,
        park_count: domain.park_count,
        lifecycle_state: domain.effective_lifecycle_state().into(),
        retry_policy_version: domain.retry_policy_version.clone(),
        retry_policy_digest: domain.retry_policy_digest.clone(),
        max_claim_attempts: domain.max_claim_attempts,
        max_lease_expiries: domain.max_lease_expiries,
        max_park_cycles: domain.max_park_cycles,
    }
}

fn to_proto_action_work_park(value: &crate::sekai::parked_work::ActionWorkPark) -> ActionWorkPark {
    ActionWorkPark {
        park_id: value.park_id.clone(),
        effect_id: value.effect_id.clone(),
        namespace: value.namespace.clone(),
        operation_id: value.operation_id.clone(),
        park_generation: value.park_generation,
        claim_generation: value.claim_generation,
        checkpoint_ref: value.checkpoint_ref.clone(),
        checkpoint_digest: value.checkpoint_digest.clone(),
        reason: value.reason.clone(),
        parked_by: value.parked_by.clone(),
        parked_at_ms: value.parked_at_ms,
        request_id: value.request_id.clone(),
        request_digest: value.request_digest.clone(),
        checkpoint_store_id: value.checkpoint_store_id.clone(),
    }
}

fn to_proto_action_work_continuation(
    value: &crate::sekai::parked_work::ActionWorkContinuation,
) -> ActionWorkContinuation {
    ActionWorkContinuation {
        resolution_id: value.resolution_id.clone(),
        effect_id: value.effect_id.clone(),
        namespace: value.namespace.clone(),
        operation_id: value.operation_id.clone(),
        park_generation: value.park_generation,
        input_json: value.input_json.clone(),
        input_digest: value.input_digest.clone(),
        park_id: value.park_id.clone(),
        resolution_action_id: value.resolution_action_id.clone(),
        resolution_input_id: value.resolution_input_id.clone(),
        reason: value.reason.clone(),
        decided_by: value.decided_by.clone(),
        decided_at_ms: value.decided_at_ms,
        request_id: value.request_id.clone(),
    }
}

fn authorize_action_instance_submit(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<String, Status> {
    require_authenticated(principals)?;
    check_team_namespace(&service.db, principals, namespace, true)?;
    principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))
}

fn authorize_action_instance_read(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<(), Status> {
    require_authenticated(principals)?;
    check_team_namespace(&service.db, principals, namespace, false)?;
    Ok(())
}

#[tonic::async_trait]
impl SekaiService for SekaiServiceImpl {
    async fn acquire_lease(
        &self,
        req: Request<AcquireLeaseRequest>,
    ) -> Result<Response<AcquireLeaseResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &input.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &input.namespace, true)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let lease = LeaseLifecycle::new(&self.db, &self.security, &self.site_id)
            .acquire(AcquireLeaseCommand {
                namespace: &input.namespace,
                key: &input.key,
                owner: &input.owner,
                ttl_ms: input.ttl_ms,
                request_id: &input.request_id,
                actor: &actor,
                principals: &principals,
                now_ms: now_millis(),
            })
            .map_err(map_lease_lifecycle_error)?;
        Ok(Response::new(AcquireLeaseResponse {
            lease: Some(to_proto_lease(&lease)),
        }))
    }

    async fn get_lease(
        &self,
        req: Request<GetLeaseRequest>,
    ) -> Result<Response<GetLeaseResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &input.namespace,
            false,
        )?;
        check_team_namespace(&self.db, &principals, &input.namespace, false)?;
        let lease = LeaseLifecycle::new(&self.db, &self.security, &self.site_id)
            .get(GetLeaseCommand {
                namespace: &input.namespace,
                key: &input.key,
                principals: &principals,
            })
            .map_err(map_lease_lifecycle_error)?;
        Ok(Response::new(GetLeaseResponse {
            lease: Some(to_proto_lease(&lease)),
        }))
    }

    async fn refresh_lease(
        &self,
        req: Request<RefreshLeaseRequest>,
    ) -> Result<Response<RefreshLeaseResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &input.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &input.namespace, true)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let lease = LeaseLifecycle::new(&self.db, &self.security, &self.site_id)
            .refresh(RefreshLeaseCommand {
                namespace: &input.namespace,
                key: &input.key,
                fencing_token: &input.fencing_token,
                ttl_ms: input.ttl_ms,
                request_id: &input.request_id,
                actor: &actor,
                principals: &principals,
                now_ms: now_millis(),
            })
            .map_err(map_lease_lifecycle_error)?;
        Ok(Response::new(RefreshLeaseResponse {
            lease: Some(to_proto_lease(&lease)),
        }))
    }

    async fn release_lease(
        &self,
        req: Request<ReleaseLeaseRequest>,
    ) -> Result<Response<ReleaseLeaseResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &input.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &input.namespace, true)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let lease = LeaseLifecycle::new(&self.db, &self.security, &self.site_id)
            .release(ReleaseLeaseCommand {
                namespace: &input.namespace,
                key: &input.key,
                fencing_token: &input.fencing_token,
                request_id: &input.request_id,
                actor: &actor,
                principals: &principals,
                now_ms: now_millis(),
            })
            .map_err(map_lease_lifecycle_error)?;
        Ok(Response::new(ReleaseLeaseResponse {
            lease: Some(to_proto_lease(&lease)),
        }))
    }

    async fn takeover_expired_lease(
        &self,
        req: Request<TakeoverExpiredLeaseRequest>,
    ) -> Result<Response<TakeoverExpiredLeaseResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &input.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &input.namespace, true)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let lease = LeaseLifecycle::new(&self.db, &self.security, &self.site_id)
            .takeover_expired(TakeoverExpiredLeaseCommand {
                namespace: &input.namespace,
                key: &input.key,
                owner: &input.owner,
                expected_fencing_token: &input.expected_fencing_token,
                expected_expires_at_ms: input.expected_expires_at_ms,
                ttl_ms: input.ttl_ms,
                request_id: &input.request_id,
                actor: &actor,
                principals: &principals,
                now_ms: now_millis(),
            })
            .map_err(map_lease_lifecycle_error)?;
        Ok(Response::new(TakeoverExpiredLeaseResponse {
            lease: Some(to_proto_lease(&lease)),
        }))
    }

    async fn create_handoff(
        &self,
        req: Request<CreateHandoffRequest>,
    ) -> Result<Response<CreateHandoffResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let proto = inner
            .manifest
            .ok_or(Status::invalid_argument("manifest required"))?;
        check_team_namespace(&self.db, &principals, &proto.namespace, true)?;
        let creator = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        let manifest = handoff_domain::HandoffManifest {
            schema_version: handoff_domain::HANDOFF_VERSION.into(),
            id: proto.id,
            namespace: proto.namespace,
            parent_operation_id: proto.parent_operation_id,
            parent_attempt_id: proto.parent_attempt_id,
            parent_work_unit_id: proto.parent_work_unit_id,
            references: proto
                .references
                .iter()
                .map(to_domain_handoff_reference)
                .collect(),
            creator_principal: creator,
            intended_principal: proto.intended_principal,
            intended_scope: proto.intended_scope,
            purpose: proto.purpose,
            created_at_ms: proto.created_at_ms,
            expires_at_ms: proto.expires_at_ms,
            digest: proto.digest,
            supersedes_manifest_id: proto.supersedes_manifest_id,
            revoked: false,
        };
        let current_time = now_millis();
        let namespace = manifest.namespace.clone();
        let stored = HandoffLifecycle::new(&self.db)
            .create(
                CreateHandoffCommand {
                    manifest,
                    request_id: &inner.request_id,
                    principals: &principals,
                    now_ms: current_time,
                },
                |reference| {
                    handoff_reference_available(
                        self,
                        reference,
                        &namespace,
                        &principals,
                        current_time,
                    )
                    .map_err(|status| HandoffLifecycleError::Storage(status.to_string()))
                },
            )
            .map_err(map_handoff_lifecycle_error)?;
        Ok(Response::new(CreateHandoffResponse {
            manifest: Some(to_proto_handoff(&stored)),
        }))
    }

    async fn revoke_handoff(
        &self,
        req: Request<RevokeHandoffRequest>,
    ) -> Result<Response<RevokeHandoffResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let revoked = HandoffLifecycle::new(&self.db)
            .revoke(RevokeHandoffCommand {
                manifest_id: &inner.manifest_id,
                reason: &inner.reason,
                request_id: &inner.request_id,
                principals: &principals,
                now_ms: now_millis(),
            })
            .map_err(map_handoff_lifecycle_error)?;
        Ok(Response::new(RevokeHandoffResponse {
            manifest: Some(to_proto_handoff(&revoked)),
        }))
    }

    async fn create_object(
        &self,
        req: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        let (metadata, extensions, input) = req.into_parts();
        let CreateObjectRequest {
            object,
            lease_precondition,
        } = input;
        let mutation = Request::from_parts(
            metadata,
            extensions,
            GuardedCreateObjectRequest {
                object,
                lease_precondition,
            },
        );
        let response = self.guarded_create_object(mutation).await?;
        Ok(Response::new(CreateObjectResponse {
            object: response.into_inner().object,
        }))
    }

    async fn get_object(
        &self,
        req: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let id = req.into_inner().id;
        let obj = self
            .db
            .get_object(&id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), &obj.namespace, false)
            .map_err(|_| Status::not_found("not found"))?;
        check_team_namespace(&self.db, &principals, &obj.namespace, false)?;
        check_read(&self.security, &id, &principals)?;
        if is_reserved_governance_kind(&obj.kind) {
            return Err(Status::not_found("not found"));
        }
        let marking = enforce_object_marking_access(
            &self.db,
            &obj,
            &principals,
            &format!("get_object:{}", obj.id),
        )?;
        if marking.decision != markings::MarkingDecision::NotApplicable {
            let actor = principals.first().cloned().unwrap_or_default();
            let mut evidence = HashMap::new();
            if let Some(value) = &marking.object_classification {
                evidence.insert("object_classification".into(), value.clone());
            }
            if let Some(value) = &marking.principal_ceiling {
                evidence.insert("principal_ceiling".into(), value.clone());
            }
            evidence.insert("detail".into(), marking.detail.clone());
            record_marking_or_purpose_decision(
                &self.db,
                &actor,
                "marking.read",
                &obj.id,
                &marking.decision_id,
                "allowed",
                evidence,
            )?;
        }
        let obj = self.resolve_computed_for_response(obj, &principals, tenant_context.as_ref())?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    async fn update_object(
        &self,
        req: Request<UpdateObjectRequest>,
    ) -> Result<Response<UpdateObjectResponse>, Status> {
        let (metadata, extensions, input) = req.into_parts();
        let UpdateObjectRequest {
            object,
            lease_precondition,
        } = input;
        let mutation = Request::from_parts(
            metadata,
            extensions,
            GuardedUpdateObjectRequest {
                object,
                lease_precondition,
            },
        );
        let response = self.guarded_update_object(mutation).await?;
        Ok(Response::new(UpdateObjectResponse {
            object: response.into_inner().object,
        }))
    }

    async fn delete_object(
        &self,
        req: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        let (metadata, extensions, input) = req.into_parts();
        let DeleteObjectRequest {
            id,
            lease_precondition,
        } = input;
        let mutation = Request::from_parts(
            metadata,
            extensions,
            GuardedDeleteObjectRequest {
                id,
                lease_precondition,
            },
        );
        self.guarded_delete_object(mutation).await?;
        Ok(Response::new(DeleteObjectResponse {}))
    }

    async fn list_objects(
        &self,
        req: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let invoked_capability = req
            .metadata()
            .get("x-sekai-capability")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let requested_operation_id = req
            .metadata()
            .get("x-sekai-operation-id")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let catalog_version = req
            .metadata()
            .get("x-sekai-catalog-version")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let filter = parse_list_filter(req.into_inner().filter.unwrap_or_default())?;
        if tenant_context.is_some() {
            let namespace = filter.namespace.as_deref().ok_or_else(|| {
                Status::permission_denied("tenant context requires an explicit namespace filter")
            })?;
            enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), namespace, false)?;
        }
        let operation_id = invoked_capability.as_ref().map(|_| {
            requested_operation_id
                .unwrap_or_else(|| format!("catalog-invocation-{}", Uuid::new_v4().simple()))
        });
        let mut receipt_guard = None;
        if let Some(capability_name) = &invoked_capability {
            let namespace = filter.namespace.as_deref().ok_or_else(|| {
                Status::invalid_argument("catalog invocation requires a namespace filter")
            })?;
            let kind = filter.kind.as_deref().ok_or_else(|| {
                Status::invalid_argument("catalog object query requires a kind filter")
            })?;
            let operation_id = operation_id.as_ref().unwrap();
            let actor = principals.first().cloned().unwrap_or_default();
            receipt_guard = Some(CatalogInvocation::begin(
                &self.db,
                operation_id.clone(),
                namespace,
                actor,
                capability_name.clone(),
                catalog_version.clone(),
            )?);
            let expected = format!("sekai.objects.query.{kind}");
            if capability_name != &expected
                || !self
                    .discoverable_capabilities(namespace, &principals)?
                    .iter()
                    .any(|entry| entry.name == *capability_name)
            {
                return Err(Status::failed_precondition("capability unavailable"));
            }
        }
        if is_managed_team_principal(&self.db, &principals)? {
            let namespace = filter.namespace.as_deref().ok_or_else(|| {
                Status::permission_denied("team principals must filter by namespace")
            })?;
            check_team_namespace(&self.db, &principals, namespace, false)?;
        }
        // Never expose internal governance objects through generic listing.
        if filter
            .kind
            .as_deref()
            .is_some_and(is_reserved_governance_kind)
        {
            return Ok(Response::new(ListObjectsResponse {
                objects: Vec::new(),
                total: 0,
            }));
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            let mut queried_properties = filter
                .property_filters
                .iter()
                .map(|property_filter| property_filter.key.clone())
                .collect::<Vec<_>>();
            if let Some(order_property) = queried_order_property(&filter.order_by) {
                queried_properties.push(order_property);
            }
            ensure_property_query_allowed(
                &schema,
                &principals,
                filter.kind.as_deref().unwrap_or_default(),
                queried_properties,
            )?;
        }
        // The API now defaults paging at 100 rows when no limit is provided;
        // DB callers using list_objects(&filter) remain unchanged.
        let (objects, total) = list_objects_with_marking(
            &self.db,
            &filter,
            &principals,
            tenant_context.as_ref(),
            |objects, principals, tenant_context| {
                self.resolve_computed_for_responses(objects, principals, tenant_context)
            },
        )?;
        let mut response = Response::new(ListObjectsResponse {
            objects: objects.iter().map(to_proto_obj).collect(),
            total,
        });
        if let (Some(_), Some(operation_id)) =
            (invoked_capability.as_deref(), operation_id.as_deref())
        {
            receipt_guard
                .as_mut()
                .unwrap()
                .finalize("allow", "succeeded")?;
            response.metadata_mut().insert(
                "x-sekai-operation-id",
                operation_id
                    .parse()
                    .map_err(|_| Status::internal("invalid operation id"))?,
            );
        }
        Ok(response)
    }
    async fn find_by_external_id(
        &self,
        req: Request<FindByExternalIdRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let external_id = req.into_inner().external_id;
        let obj = if tenant_context.is_some() {
            self.db
                .find_all_by_external_id(&external_id)
                .map_err(Status::internal)?
                .into_iter()
                .find(|candidate| {
                    !is_reserved_governance_kind(&candidate.kind)
                        && enforce_namespace_tenant_context(
                            &self.db,
                            tenant_context.as_ref(),
                            &candidate.namespace,
                            false,
                        )
                        .is_ok()
                        && check_team_namespace(&self.db, &principals, &candidate.namespace, false)
                            .is_ok()
                        && check_read(&self.security, &candidate.id, &principals).is_ok()
                        && object_passes_marking(&self.db, candidate, &principals).unwrap_or(false)
                })
        } else {
            self.db
                .find_by_external_id(&external_id)
                .map_err(Status::internal)?
        }
        .ok_or(Status::not_found("not found"))?;
        if is_reserved_governance_kind(&obj.kind) {
            return Err(Status::not_found("not found"));
        }
        enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), &obj.namespace, false)
            .map_err(|_| Status::not_found("not found"))?;
        check_team_namespace(&self.db, &principals, &obj.namespace, false)?;
        check_read(&self.security, &obj.id, &principals)?;
        enforce_object_marking_access(
            &self.db,
            &obj,
            &principals,
            &format!("find_by_external_id:{}", obj.id),
        )?;
        let obj = self.resolve_computed_for_response(obj, &principals, tenant_context.as_ref())?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    async fn find_by_property(
        &self,
        req: Request<FindByPropertyRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let r = req.into_inner();
        if is_reserved_governance_kind(&r.kind) {
            return Ok(Response::new(ListObjectsResponse {
                objects: Vec::new(),
                total: 0,
            }));
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_property_query_allowed(&schema, &principals, &r.kind, [r.key.clone()])?;
        }
        let objs = self
            .db
            .find_by_property(&r.kind, &r.key, &r.value)
            .map_err(Status::internal)?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        let filtered = self.security.filter_objects(&objs, &refs);
        let filtered = filtered
            .into_iter()
            .filter(|object| {
                check_team_namespace(&self.db, &principals, &object.namespace, false).is_ok()
                    && enforce_namespace_tenant_context(
                        &self.db,
                        tenant_context.as_ref(),
                        &object.namespace,
                        false,
                    )
                    .is_ok()
                    && object_passes_marking(&self.db, object, &principals).unwrap_or(false)
            })
            .collect::<Vec<_>>();
        let filtered = self.resolve_computed_for_responses(
            filtered.into_iter().cloned().collect(),
            &principals,
            tenant_context.as_ref(),
        )?;
        Ok(Response::new(ListObjectsResponse {
            objects: filtered.iter().map(to_proto_obj).collect(),
            total: filtered.len() as i32,
        }))
    }
    async fn create_link(
        &self,
        req: Request<CreateLinkRequest>,
    ) -> Result<Response<CreateLinkResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let fail_if_exists = inner.fail_if_exists;
        let l = inner
            .link
            .ok_or(Status::invalid_argument("link required"))?;
        let mut endpoints = Vec::with_capacity(2);
        for object_id in [&l.from_id, &l.to_id] {
            let object = self
                .db
                .get_object(object_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("link endpoint not found"))?;
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &object.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &object.namespace, true)?;
            check_write(&self.security, object_id, &principals)?;
            enforce_object_marking_access(
                &self.db,
                &object,
                &principals,
                &format!("create_link:{object_id}"),
            )?;
            endpoints.push(object);
        }
        if self.db.get_link(&l.id).map_err(Status::internal)?.is_none() {
            let ontology = self.db.load_ontology_registry().map_err(Status::internal)?;
            validate_mapped_link(
                &ontology,
                &l.relation,
                &endpoints[0].kind,
                &endpoints[1].kind,
            )?;
        }
        let dl = domain::Link {
            id: l.id.clone(),
            from_id: l.from_id.clone(),
            to_id: l.to_id.clone(),
            relation: l.relation.clone(),
            created: l.created,
        };
        if fail_if_exists {
            if !self
                .db
                .create_link_once(&dl)
                .map_err(map_graph_mutation_error)?
            {
                return Err(Status::already_exists("link already exists"));
            }
        } else {
            self.db.create_link(&dl).map_err(map_graph_mutation_error)?;
        }
        Ok(Response::new(CreateLinkResponse { link: Some(l) }))
    }
    async fn delete_link(
        &self,
        req: Request<DeleteLinkRequest>,
    ) -> Result<Response<DeleteLinkResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        let Some(link) = self.db.get_link(&id).map_err(Status::internal)? else {
            return Ok(Response::new(DeleteLinkResponse {}));
        };
        for object_id in [&link.from_id, &link.to_id] {
            let object = self
                .db
                .get_object(object_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("link endpoint not found"))?;
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &object.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &object.namespace, true)?;
            check_write(&self.security, object_id, &principals)?;
            enforce_object_marking_access(
                &self.db,
                &object,
                &principals,
                &format!("delete_link:{object_id}"),
            )?;
        }
        self.db.delete_link(&id).map_err(Status::internal)?;
        Ok(Response::new(DeleteLinkResponse {}))
    }
    async fn get_links(
        &self,
        req: Request<GetLinksRequest>,
    ) -> Result<Response<GetLinksResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let r = req.into_inner();
        let root = self
            .db
            .get_object(&r.object_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), &root.namespace, false)
            .map_err(|_| Status::not_found("not found"))?;
        check_team_namespace(&self.db, &principals, &root.namespace, false)?;
        check_read(&self.security, &root.id, &principals)?;
        enforce_object_marking_access(
            &self.db,
            &root,
            &principals,
            &format!("get_links:{}", root.id),
        )?;
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let links = self
            .db
            .get_links(&r.object_id, &r.relation, &dir)
            .map_err(Status::internal)?;
        let links = links
            .into_iter()
            .filter(|link| {
                [&link.from_id, &link.to_id].into_iter().all(|object_id| {
                    self.db
                        .get_object(object_id)
                        .ok()
                        .flatten()
                        .is_some_and(|object| {
                            check_team_namespace(&self.db, &principals, &object.namespace, false)
                                .is_ok()
                                && enforce_namespace_tenant_context(
                                    &self.db,
                                    tenant_context.as_ref(),
                                    &object.namespace,
                                    false,
                                )
                                .is_ok()
                                && check_read(&self.security, object_id, &principals).is_ok()
                                && object_passes_marking(&self.db, &object, &principals)
                                    .unwrap_or(false)
                        })
                })
            })
            .collect::<Vec<_>>();
        Ok(Response::new(GetLinksResponse {
            links: links.iter().map(to_proto_link).collect(),
        }))
    }
    async fn get_linked_objects(
        &self,
        req: Request<GetLinkedObjectsRequest>,
    ) -> Result<Response<GetLinkedObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let r = req.into_inner();
        let root = self
            .db
            .get_object(&r.object_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), &root.namespace, false)
            .map_err(|_| Status::not_found("not found"))?;
        check_team_namespace(&self.db, &principals, &root.namespace, false)?;
        check_read(&self.security, &root.id, &principals)?;
        enforce_object_marking_access(
            &self.db,
            &root,
            &principals,
            &format!("get_linked_objects:{}", root.id),
        )?;
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let objs = self
            .db
            .get_linked_objects(&r.object_id, &r.relation, &dir)
            .map_err(Status::internal)?;
        let objs = objs
            .into_iter()
            .filter(|object| {
                check_team_namespace(&self.db, &principals, &object.namespace, false).is_ok()
                    && enforce_namespace_tenant_context(
                        &self.db,
                        tenant_context.as_ref(),
                        &object.namespace,
                        false,
                    )
                    .is_ok()
                    && check_read(&self.security, &object.id, &principals).is_ok()
                    && object_passes_marking(&self.db, object, &principals).unwrap_or(false)
            })
            .collect();
        let objs =
            self.resolve_computed_for_responses(objs, &principals, tenant_context.as_ref())?;
        Ok(Response::new(GetLinkedObjectsResponse {
            objects: objs.iter().map(to_proto_obj).collect(),
        }))
    }
    async fn traverse(
        &self,
        req: Request<TraverseRequest>,
    ) -> Result<Response<TraverseResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let q = req
            .into_inner()
            .query
            .ok_or(Status::invalid_argument("query required"))?;
        let gq = crate::sekai::query::GraphQuery {
            start_id: q.start_id,
            start_external_id: q.start_external_id,
            relations: q.relations,
            direction: if q.direction == "incoming" {
                domain::Direction::Incoming
            } else {
                domain::Direction::Outgoing
            },
            max_depth: q.max_depth,
            kind_filter: q.kind_filter,
            interface_filter: q.interface_filter,
            property_filter: q.property_filter,
        };
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        let queried_properties = gq.property_filter.keys().cloned().collect::<Vec<_>>();
        if gq.kind_filter.is_empty() {
            ensure_property_query_allowed(&schema, &principals, "", queried_properties)?;
        } else {
            for kind in &gq.kind_filter {
                ensure_property_query_allowed(
                    &schema,
                    &principals,
                    kind,
                    queried_properties.clone(),
                )?;
            }
        }
        let mut res = crate::sekai::query::traverse(&self.db, &gq, Some(&schema))
            .map_err(Status::internal)?;
        drop(schema);
        res.objects.retain(|object| {
            check_team_namespace(&self.db, &principals, &object.namespace, false).is_ok()
                && enforce_namespace_tenant_context(
                    &self.db,
                    tenant_context.as_ref(),
                    &object.namespace,
                    false,
                )
                .is_ok()
                && check_read(&self.security, &object.id, &principals).is_ok()
                && object_passes_marking(&self.db, object, &principals).unwrap_or(false)
        });
        let visible_ids = res
            .objects
            .iter()
            .map(|object| object.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        res.links.retain(|link| {
            visible_ids.contains(link.from_id.as_str()) && visible_ids.contains(link.to_id.as_str())
        });
        res.objects =
            self.resolve_computed_for_responses(res.objects, &principals, tenant_context.as_ref())?;
        Ok(Response::new(TraverseResponse {
            result: Some(GraphResult {
                objects: res.objects.iter().map(to_proto_obj).collect(),
                links: res.links.iter().map(to_proto_link).collect(),
            }),
        }))
    }
    async fn retrieve_context(
        &self,
        req: Request<RetrieveContextRequest>,
    ) -> Result<Response<RetrieveContextResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let namespace = Self::catalog_metadata_value(&req, "x-sekai-namespace").unwrap_or_default();
        let mut receipt_guard = self.begin_semantic_catalog_invocation(
            &req,
            semantic::CAPABILITY_RETRIEVE_CONTEXT,
            &namespace,
            &principals,
        )?;
        let operation_id = receipt_guard
            .as_ref()
            .map(|(operation_id, _)| operation_id.clone());
        let result = self.execute_retrieve_context(&principals, req.into_inner());
        match result {
            Ok(response) => {
                if let Some((_, guard)) = receipt_guard.as_mut() {
                    guard.finalize("allow", "succeeded")?;
                }
                let mut response = Response::new(response);
                if let Some(operation_id) = operation_id.as_deref() {
                    response.metadata_mut().insert(
                        "x-sekai-operation-id",
                        operation_id
                            .parse()
                            .map_err(|_| Status::internal("invalid operation id"))?,
                    );
                }
                Ok(response)
            }
            Err(status) => Err(status),
        }
    }
    async fn expand_relations(
        &self,
        req: Request<ExpandRelationsRequest>,
    ) -> Result<Response<ExpandRelationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let namespace = req.get_ref().namespace.trim().to_string();
        if namespace.is_empty() || namespace != req.get_ref().namespace {
            return Err(Status::invalid_argument("canonical namespace required"));
        }
        check_team_namespace(&self.db, &principals, &namespace, false)?;
        let mut receipt_guard = self.begin_semantic_catalog_invocation(
            &req,
            semantic::CAPABILITY_EXPAND_RELATIONS,
            &namespace,
            &principals,
        )?;
        let operation_id = receipt_guard
            .as_ref()
            .map(|(operation_id, _)| operation_id.clone());
        let inner = req.into_inner();
        let root = inner
            .root
            .ok_or_else(|| Status::invalid_argument("root required"))?;
        let reasoning_mode =
            retrieval::ReasoningMode::parse(&inner.reasoning_mode).map_err(map_retrieval_error)?;
        let retrieved = self.execute_retrieve_context(
            &principals,
            RetrieveContextRequest {
                roots: vec![root],
                relations: inner.relations,
                direction: inner.direction,
                max_depth: inner.max_depth,
                max_objects: inner.max_objects,
                max_links: inner.max_links,
                kind_filter: inner.kind_filter,
                reasoning_mode: inner.reasoning_mode,
                max_source_rows: inner.max_source_rows,
                max_derived_rows: inner.max_derived_rows,
                max_derivation_steps: inner.max_derivation_steps,
                max_time_ms: inner.max_time_ms,
                max_explanation_bytes: inner.max_explanation_bytes,
            },
        )?;
        // Keep expansion results inside the requested namespace boundary.
        let candidates = retrieved
            .candidates
            .into_iter()
            .filter(|candidate| {
                candidate.object.as_ref().is_some_and(|object| {
                    object.namespace == namespace || object.namespace.is_empty()
                })
            })
            .collect::<Vec<_>>();
        let visible_ids = candidates
            .iter()
            .filter_map(|candidate| candidate.object.as_ref().map(|object| object.id.as_str()))
            .collect::<std::collections::HashSet<_>>();
        let links = retrieved
            .links
            .into_iter()
            .filter(|link| {
                visible_ids.contains(link.from_id.as_str())
                    && visible_ids.contains(link.to_id.as_str())
            })
            .collect::<Vec<_>>();
        if let Some((_, guard)) = receipt_guard.as_mut() {
            guard.finalize("allow", "succeeded")?;
        }
        let mut response = Response::new(ExpandRelationsResponse {
            candidates,
            links,
            truncated: retrieved.truncated,
            unresolved_roots: retrieved.unresolved_roots,
            denied_objects: retrieved.denied_objects,
            truncated_objects: retrieved.truncated_objects,
            truncated_links: retrieved.truncated_links,
            truncation_reasons: retrieved.truncation_reasons,
            source_rows: retrieved.source_rows,
            derived_rows: retrieved.derived_rows,
            ontology_revision: retrieved.ontology_revision,
            reasoning_mode: semantic::reasoning_mode_label(reasoning_mode).into(),
            epistemic_descriptor_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
        });
        if let Some(operation_id) = operation_id.as_deref() {
            response.metadata_mut().insert(
                "x-sekai-operation-id",
                operation_id
                    .parse()
                    .map_err(|_| Status::internal("invalid operation id"))?,
            );
        }
        Ok(response)
    }

    async fn explain_derivation(
        &self,
        req: Request<ExplainDerivationRequest>,
    ) -> Result<Response<ExplainDerivationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let namespace = req.get_ref().namespace.trim().to_string();
        if namespace.is_empty() || namespace != req.get_ref().namespace {
            return Err(Status::invalid_argument("canonical namespace required"));
        }
        check_team_namespace(&self.db, &principals, &namespace, false)?;
        let mut receipt_guard = self.begin_semantic_catalog_invocation(
            &req,
            semantic::CAPABILITY_EXPLAIN_DERIVATION,
            &namespace,
            &principals,
        )?;
        let operation_id = receipt_guard
            .as_ref()
            .map(|(operation_id, _)| operation_id.clone());
        let inner = req.into_inner();
        let from = inner
            .from
            .ok_or_else(|| Status::invalid_argument("from root required"))?;
        let to = inner
            .to
            .ok_or_else(|| Status::invalid_argument("to root required"))?;
        let to_root = from_proto_context_root(to.clone())?;
        let reasoning_mode =
            retrieval::ReasoningMode::parse(&inner.reasoning_mode).map_err(map_retrieval_error)?;
        let retrieved = self.execute_retrieve_context(
            &principals,
            RetrieveContextRequest {
                roots: vec![from],
                relations: inner.relations,
                direction: inner.direction,
                max_depth: if inner.max_depth == 0 {
                    retrieval::MAX_DEPTH
                } else {
                    inner.max_depth
                },
                max_objects: inner.max_objects,
                max_links: inner.max_links,
                kind_filter: Vec::new(),
                reasoning_mode: inner.reasoning_mode,
                max_source_rows: inner.max_source_rows,
                max_derived_rows: inner.max_derived_rows,
                max_derivation_steps: inner.max_derivation_steps,
                max_time_ms: inner.max_time_ms,
                max_explanation_bytes: inner.max_explanation_bytes,
            },
        )?;

        let mut found_explanation = None;
        for candidate in &retrieved.candidates {
            let Some(object) = candidate.object.as_ref() else {
                continue;
            };
            if object.namespace != namespace && !object.namespace.is_empty() {
                continue;
            }
            let matches = match &to_root {
                retrieval::RetrievalRoot::Object(id) => object.id == *id,
                retrieval::RetrievalRoot::External(external_id) => {
                    object.external_id == *external_id
                }
                retrieval::RetrievalRoot::Link(link_id) => retrieved.links.iter().any(|link| {
                    link.id == *link_id && (link.from_id == object.id || link.to_id == object.id)
                }),
            };
            if matches {
                found_explanation = candidate.explanation.clone();
                break;
            }
        }

        let mut evidence_refs = Vec::new();
        if let Some(explanation) = found_explanation.as_ref() {
            evidence_refs.extend(explanation.source_fact_ids.iter().cloned());
            for step in &explanation.steps {
                for fact in &step.source_fact_ids {
                    if !evidence_refs.contains(fact) {
                        evidence_refs.push(fact.clone());
                    }
                }
            }
        }
        evidence_refs.sort();
        evidence_refs.dedup();

        if let Some((_, guard)) = receipt_guard.as_mut() {
            guard.finalize("allow", "succeeded")?;
        }
        let found = found_explanation.is_some();
        let descriptor = found_explanation.as_ref().map(|explanation| {
            to_proto_epistemic_descriptor(&DomainEpistemicDescriptor::from_graph_projection(
                explanation.derived,
                &explanation.source_fact_ids,
                &explanation.ontology_revision,
                retrieved
                    .truncation_reasons
                    .iter()
                    .any(|reason| reason == "source_rows"),
            ))
        });
        let mut response = Response::new(ExplainDerivationResponse {
            explanation: found_explanation,
            found,
            truncated: retrieved.truncated,
            truncation_reasons: retrieved.truncation_reasons,
            ontology_revision: retrieved.ontology_revision,
            reasoning_mode: semantic::reasoning_mode_label(reasoning_mode).into(),
            evidence_refs,
            descriptor,
        });
        if let Some(operation_id) = operation_id.as_deref() {
            response.metadata_mut().insert(
                "x-sekai-operation-id",
                operation_id
                    .parse()
                    .map_err(|_| Status::internal("invalid operation id"))?,
            );
        }
        Ok(response)
    }

    async fn discover_capabilities(
        &self,
        req: Request<DiscoverCapabilitiesRequest>,
    ) -> Result<Response<DiscoverCapabilitiesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let namespace = inner.namespace.trim();
        if namespace.is_empty() || namespace != inner.namespace {
            return Err(Status::invalid_argument("canonical namespace required"));
        }
        let requested_tier = inner.product_tier_filter.trim();
        if !requested_tier.is_empty()
            && !matches!(requested_tier, "all" | "core" | "advanced" | "experimental")
        {
            return Err(Status::invalid_argument(
                "product_tier_filter must be empty or one of all|core|advanced|experimental",
            ));
        }
        let tier_filter = if requested_tier.is_empty() {
            "core"
        } else {
            requested_tier
        };
        let contract_version = capability::negotiate_contract_version(&inner.contract_version)
            .map_err(map_capability_error)?;
        let mut entries = self.discoverable_capabilities(namespace, &principals)?;
        if tier_filter != "all" {
            entries.retain(|entry| {
                let tier = if entry.product_tier.trim().is_empty() {
                    "advanced"
                } else {
                    entry.product_tier.as_str()
                };
                tier == tier_filter
            });
        }
        let mut context = principals.clone();
        context.sort();
        context.dedup();
        context.insert(0, namespace.to_string());
        context.push(format!("product_tier:{tier_filter}"));
        let canonical_entries = entries
            .iter()
            .map(Message::encode_to_vec)
            .collect::<Vec<_>>();
        let catalog_version = capability::snapshot_version(&context, &canonical_entries);
        let offset =
            capability::resolve_offset(&inner.catalog_version, &inner.page_token, &catalog_version)
                .map_err(map_capability_error)?;
        let page_size = capability::page_size(inner.page_size);
        let end = offset.saturating_add(page_size).min(entries.len());
        let capabilities = entries.get(offset..end).unwrap_or_default().to_vec();
        let next_page_token = capability::next_page_token(&catalog_version, end, entries.len());

        Ok(Response::new(DiscoverCapabilitiesResponse {
            capabilities,
            contract_version: contract_version.to_string(),
            catalog_version,
            next_page_token,
            total_size: entries.len().min(u32::MAX as usize) as u32,
            cache_scope: "authorization_context".into(),
        }))
    }

    async fn get_governed_fact_version(
        &self,
        req: Request<GetGovernedFactVersionRequest>,
    ) -> Result<Response<GetGovernedFactVersionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let object_id = req.into_inner().object_id;
        let object = governed_object_for_read(
            self,
            &principals,
            tenant_context.as_ref(),
            &object_id,
            governed_fact_domain::FACT_KIND,
        )?;
        let fact = governed_fact_domain::fact_from_object(&object).map_err(Status::data_loss)?;
        Ok(Response::new(GetGovernedFactVersionResponse {
            fact: Some(to_proto_governed_fact(&fact)),
        }))
    }

    async fn resolve_invariant_set(
        &self,
        req: Request<ResolveInvariantSetRequest>,
    ) -> Result<Response<ResolveInvariantSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let inner = req.into_inner();
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &inner.namespace,
            false,
        )?;
        check_team_namespace(&self.db, &principals, &inner.namespace, false)?;
        let profile_object = governed_object_for_read(
            self,
            &principals,
            tenant_context.as_ref(),
            &governed_fact_domain::profile_object_id(&inner.namespace),
            governed_fact_domain::PROFILE_KIND,
        )?;
        let profile = governed_fact_domain::profile_from_object(&profile_object)
            .map_err(Status::data_loss)?;
        let mut visibility_cache = HashMap::new();
        let mut visibility_work = 0;
        let facts = list_visible_governed_objects(
            self,
            &principals,
            &inner.namespace,
            governed_fact_domain::FACT_KIND,
            &mut visibility_cache,
            &mut visibility_work,
        )?
        .iter()
        .map(governed_fact_domain::fact_from_object)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Status::data_loss)?;
        let waivers = list_visible_governed_objects(
            self,
            &principals,
            &inner.namespace,
            governed_fact_domain::WAIVER_KIND,
            &mut visibility_cache,
            &mut visibility_work,
        )?
        .iter()
        .map(governed_fact_domain::waiver_from_object)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Status::data_loss)?;
        let invariant_set = governed_fact_domain::resolve_invariant_set(
            &profile,
            facts,
            waivers,
            &inner.subject_profile,
            &inner.subject_ref,
            inner.evaluation_time_ms,
            inner.max_items as usize,
        )
        .map_err(|error| {
            if error.contains("exceeds") {
                Status::resource_exhausted(error)
            } else if error.contains("history is ambiguous") {
                Status::failed_precondition("governed fact resolution unavailable")
            } else {
                Status::invalid_argument(error)
            }
        })?;
        Ok(Response::new(ResolveInvariantSetResponse {
            invariant_set: Some(to_proto_invariant_set(&invariant_set)),
        }))
    }

    async fn list_schema_types(
        &self,
        req: Request<ListSchemaTypesRequest>,
    ) -> Result<Response<ListSchemaTypesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let types = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .all()
            .iter()
            .filter(|object_type| {
                check_read(
                    &self.security,
                    &schema_object_id(&object_type.kind),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_schema_type)
            .collect();
        Ok(Response::new(ListSchemaTypesResponse { types }))
    }
    async fn create_schema_type(
        &self,
        req: Request<CreateSchemaTypeRequest>,
    ) -> Result<Response<CreateSchemaTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let object_type = req
            .into_inner()
            .r#type
            .ok_or(Status::invalid_argument("schema type required"))?;
        let parsed = from_proto_schema_type(&object_type)?;
        check_schema_admin(&self.security, &parsed.kind, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema::validate_object_type_definition(&parsed, registry.get(&parsed.kind), &registry)
                .map_err(Status::invalid_argument)?;
        }
        validate_computed_property_functions(&self.db, &parsed)?;
        self.db
            .upsert_object_type(&parsed)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .register(parsed.clone());
        self.schema_load_errors
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&parsed.kind);
        Ok(Response::new(CreateSchemaTypeResponse {
            r#type: Some(to_proto_schema_type(&parsed)),
        }))
    }
    async fn list_ontology_classes(
        &self,
        req: Request<ListOntologyClassesRequest>,
    ) -> Result<Response<ListOntologyClassesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let classes = self
            .db
            .list_ontology_classes()
            .map_err(Status::internal)?
            .iter()
            .filter(|class| check_ontology_class_read(&self.security, class, &principals).is_ok())
            .map(to_proto_ontology_class)
            .collect();
        Ok(Response::new(ListOntologyClassesResponse { classes }))
    }

    async fn get_ontology_class(
        &self,
        req: Request<GetOntologyClassRequest>,
    ) -> Result<Response<GetOntologyClassResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("class name required"));
        }
        check_read(
            &self.security,
            &ontology_class_object_id(&name),
            &principals,
        )?;
        let class = self
            .db
            .get_ontology_class(&name)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("ontology class not found"))?;
        check_ontology_class_read(&self.security, &class, &principals)?;
        Ok(Response::new(GetOntologyClassResponse {
            class: Some(to_proto_ontology_class(&class)),
        }))
    }

    async fn create_ontology_class(
        &self,
        req: Request<CreateOntologyClassRequest>,
    ) -> Result<Response<CreateOntologyClassResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let proto = req
            .into_inner()
            .class
            .ok_or(Status::invalid_argument("class required"))?;
        let parsed = from_proto_ontology_class(&proto)?;
        let parsed = self.create_ontology_class_definition(&principals, parsed)?;
        Ok(Response::new(CreateOntologyClassResponse {
            class: Some(to_proto_ontology_class(&parsed)),
        }))
    }

    async fn delete_ontology_class(
        &self,
        req: Request<DeleteOntologyClassRequest>,
    ) -> Result<Response<DeleteOntologyClassResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("class name required"));
        }
        self.delete_ontology_class_definition(&principals, &name)?;
        Ok(Response::new(DeleteOntologyClassResponse {}))
    }

    async fn list_ontology_relations(
        &self,
        req: Request<ListOntologyRelationsRequest>,
    ) -> Result<Response<ListOntologyRelationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let relations = self
            .db
            .list_ontology_relations()
            .map_err(Status::internal)?
            .iter()
            .filter(|relation| {
                check_ontology_relation_read(&self.security, relation, &principals).is_ok()
            })
            .map(to_proto_ontology_relation)
            .collect();
        Ok(Response::new(ListOntologyRelationsResponse { relations }))
    }

    async fn get_ontology_relation(
        &self,
        req: Request<GetOntologyRelationRequest>,
    ) -> Result<Response<GetOntologyRelationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("relation name required"));
        }
        check_read(
            &self.security,
            &ontology_relation_object_id(&name),
            &principals,
        )?;
        let relation = self
            .db
            .get_ontology_relation(&name)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("ontology relation not found"))?;
        check_ontology_relation_read(&self.security, &relation, &principals)?;
        Ok(Response::new(GetOntologyRelationResponse {
            relation: Some(to_proto_ontology_relation(&relation)),
        }))
    }

    async fn create_ontology_relation(
        &self,
        req: Request<CreateOntologyRelationRequest>,
    ) -> Result<Response<CreateOntologyRelationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let proto = req
            .into_inner()
            .relation
            .ok_or(Status::invalid_argument("relation required"))?;
        let parsed = from_proto_ontology_relation(&proto)?;
        let parsed = self.create_ontology_relation_definition(&principals, parsed)?;
        Ok(Response::new(CreateOntologyRelationResponse {
            relation: Some(to_proto_ontology_relation(&parsed)),
        }))
    }

    async fn delete_ontology_relation(
        &self,
        req: Request<DeleteOntologyRelationRequest>,
    ) -> Result<Response<DeleteOntologyRelationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("relation name required"));
        }
        self.delete_ontology_relation_definition(&principals, &name)?;
        Ok(Response::new(DeleteOntologyRelationResponse {}))
    }

    async fn create_action_type(
        &self,
        req: Request<CreateActionTypeRequest>,
    ) -> Result<Response<CreateActionTypeResponse>, Status> {
        // This is intentionally a compatibility path for the legacy graph
        // mutation DSL. It must not map ActionTypeDef into GovernedActionType:
        // the two registries have different execution semantics.
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let action_type = req
            .into_inner()
            .action_type
            .ok_or(Status::invalid_argument("action_type required"))?;
        let parsed = from_proto_action_type(&action_type)?;
        check_action_admin(&self.security, &parsed.name, &principals)?;
        {
            action::validate_action_type_definition(
                &parsed,
                ActionExecutor::new().has_action(&parsed.name),
            )
            .map_err(Status::invalid_argument)?;
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            action::validate_action_type_against_schema(&parsed, &schema)
                .map_err(Status::invalid_argument)?;
        }
        let stored = {
            let _mutation = self
                .action_type_mutation
                .lock()
                .map_err(|_| Status::internal("action registry mutation unavailable"))?;
            let stored = self
                .db
                .upsert_action_type(&parsed)
                .map_err(Status::internal)?;
            self.actions
                .write()
                .map_err(|_| Status::internal("action registry unavailable"))?
                .register_action_type(stored.clone())
                .map_err(Status::invalid_argument)?;
            stored
        };
        Ok(Response::new(CreateActionTypeResponse {
            action_type: Some(to_proto_action_type(&stored)),
        }))
    }

    async fn list_action_types(
        &self,
        req: Request<ListActionTypesRequest>,
    ) -> Result<Response<ListActionTypesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        self.refresh_action_registry()?;
        let action_types = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .list_action_types()
            .iter()
            .filter(|action_type| {
                check_read(
                    &self.security,
                    &action_object_id(&action_type.name),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_action_type)
            .collect();
        Ok(Response::new(ListActionTypesResponse { action_types }))
    }

    async fn delete_action_type(
        &self,
        req: Request<DeleteActionTypeRequest>,
    ) -> Result<Response<DeleteActionTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("name required"));
        }
        check_action_admin(&self.security, &name, &principals)?;
        let _mutation = self
            .action_type_mutation
            .lock()
            .map_err(|_| Status::internal("action registry mutation unavailable"))?;
        if self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .has_action(&name)
            && ActionExecutor::new().has_action(&name)
        {
            return Err(Status::invalid_argument("cannot delete builtin action"));
        }
        self.db
            .delete_action_type(&name)
            .map_err(Status::internal)?;
        self.actions
            .write()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .remove_action_type(&name);
        Ok(Response::new(DeleteActionTypeResponse {}))
    }

    async fn put_governed_action_type(
        &self,
        req: Request<PutGovernedActionTypeRequest>,
    ) -> Result<Response<PutGovernedActionTypeResponse>, Status> {
        // Governed Action type registry (#396).
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let proto = inner
            .r#type
            .ok_or_else(|| Status::invalid_argument("type required"))?;
        let actor = authorize_namespace_action_admin(self, &principals, &proto.namespace)?;
        let domain = from_proto_governed_action_type(proto)?;
        let existing = self
            .db
            .get_governed_action_type(&domain.namespace, &domain.type_id, &domain.version)
            .map_err(Status::internal)?;
        if existing.is_none() {
            domain.validate().map_err(Status::invalid_argument)?;
        }
        let stored = self
            .db
            .put_governed_action_type(domain, &actor, now_millis())
            .map_err(|e| {
                if e.contains("immutable")
                    || e.contains("required")
                    || e.contains("unknown effect")
                    || e.contains("duplicate effect")
                    || e.contains("parameter_schema_json")
                    || e.contains("must not contain whitespace")
                {
                    Status::invalid_argument(e)
                } else {
                    Status::internal(e)
                }
            })?;
        Ok(Response::new(PutGovernedActionTypeResponse {
            r#type: Some(to_proto_governed_action_type(&stored)),
        }))
    }

    async fn get_governed_action_type(
        &self,
        req: Request<GetGovernedActionTypeRequest>,
    ) -> Result<Response<GetGovernedActionTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_team_namespace(&self.db, &principals, &inner.namespace, true)?;
        check_action_admin(
            &self.security,
            &format!("governed_action:{}", inner.namespace),
            &principals,
        )?;
        let stored = self
            .db
            .get_governed_action_type(&inner.namespace, &inner.type_id, &inner.version)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("governed action type not found"))?;
        Ok(Response::new(GetGovernedActionTypeResponse {
            r#type: Some(to_proto_governed_action_type(&stored)),
        }))
    }

    async fn list_governed_action_types(
        &self,
        req: Request<ListGovernedActionTypesRequest>,
    ) -> Result<Response<ListGovernedActionTypesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_team_namespace(&self.db, &principals, &inner.namespace, true)?;
        check_action_admin(
            &self.security,
            &format!("governed_action:{}", inner.namespace),
            &principals,
        )?;
        let type_id = if inner.type_id.trim().is_empty() {
            None
        } else {
            Some(inner.type_id.as_str())
        };
        let types = self
            .db
            .list_governed_action_types(&inner.namespace, type_id, inner.enabled_only)
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_governed_action_type)
            .collect();
        Ok(Response::new(ListGovernedActionTypesResponse { types }))
    }

    async fn set_governed_action_type_enabled(
        &self,
        req: Request<SetGovernedActionTypeEnabledRequest>,
    ) -> Result<Response<SetGovernedActionTypeEnabledResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let _actor = authorize_namespace_action_admin(self, &principals, &inner.namespace)?;
        let stored = self
            .db
            .set_governed_action_type_enabled(
                &inner.namespace,
                &inner.type_id,
                &inner.version,
                inner.enabled,
                now_millis(),
            )
            .map_err(|e| {
                if e.contains("not found") {
                    Status::not_found(e)
                } else {
                    Status::internal(e)
                }
            })?;
        Ok(Response::new(SetGovernedActionTypeEnabledResponse {
            r#type: Some(to_proto_governed_action_type(&stored)),
        }))
    }

    async fn submit_action_instance(
        &self,
        req: Request<SubmitActionInstanceRequest>,
    ) -> Result<Response<SubmitActionInstanceResponse>, Status> {
        use crate::sekai::action_instance_admission::{
            ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
        };

        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let inner = req.into_inner();
        let namespace = inner.namespace.trim().to_string();
        if namespace.is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        let actor = authorize_action_instance_submit(self, &principals, &namespace)?;
        enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), &namespace, true)?;

        let outcome = ActionInstanceAdmission::new(
            &self.db,
            self.budget.as_ref().map(std::convert::AsRef::as_ref),
        )
        .admit(
            ActionInstanceAdmissionRequest {
                namespace,
                type_id: inner.type_id,
                version: inner.version,
                parameters_json: inner.parameters_json,
                idempotency_key: inner.idempotency_key,
                evidence_submission_ids: inner.evidence_submission_ids,
            },
            &actor,
            now_millis(),
        )
        .map_err(|error| match error {
            ActionInstanceAdmissionError::InvalidArgument(message) => {
                Status::invalid_argument(message)
            }
            ActionInstanceAdmissionError::FailedPrecondition(message) => {
                Status::failed_precondition(message)
            }
            ActionInstanceAdmissionError::AlreadyExists(message) => Status::already_exists(message),
            ActionInstanceAdmissionError::Internal(message) => Status::internal(message),
        })?;
        Ok(Response::new(SubmitActionInstanceResponse {
            instance: Some(to_proto_action_instance(&outcome.instance)),
            replay: outcome.replay,
        }))
    }

    async fn get_action_instance(
        &self,
        req: Request<GetActionInstanceRequest>,
    ) -> Result<Response<GetActionInstanceResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let stored = if !inner.instance_id.trim().is_empty() {
            self.db
                .get_action_instance(&inner.instance_id)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::not_found("action instance not found"))?
        } else if !inner.namespace.trim().is_empty() && !inner.idempotency_key.trim().is_empty() {
            self.db
                .get_action_instance_by_idempotency(&inner.namespace, &inner.idempotency_key)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::not_found("action instance not found"))?
        } else {
            return Err(Status::invalid_argument(
                "instance_id or (namespace, idempotency_key) required",
            ));
        };
        authorize_action_instance_read(self, &principals, &stored.namespace)?;
        Ok(Response::new(GetActionInstanceResponse {
            instance: Some(to_proto_action_instance(&stored)),
        }))
    }

    async fn list_action_instances(
        &self,
        req: Request<ListActionInstancesRequest>,
    ) -> Result<Response<ListActionInstancesResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        if inner.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        authorize_action_instance_read(self, &principals, &inner.namespace)?;
        let type_id = if inner.type_id.trim().is_empty() {
            None
        } else {
            Some(inner.type_id.as_str())
        };
        let status = if inner.status.trim().is_empty() {
            None
        } else {
            Some(inner.status.as_str())
        };
        let limit = if inner.limit == 0 {
            100
        } else {
            inner.limit as usize
        };
        let instances = self
            .db
            .list_action_instances(&inner.namespace, type_id, status, limit)
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_action_instance)
            .collect();
        Ok(Response::new(ListActionInstancesResponse { instances }))
    }

    async fn get_action_effect(
        &self,
        req: Request<GetActionEffectRequest>,
    ) -> Result<Response<GetActionEffectResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        if inner.effect_id.trim().is_empty() {
            return Err(Status::invalid_argument("effect_id required"));
        }
        let stored = self
            .db
            .get_action_effect(&inner.effect_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action effect not found"))?;
        authorize_action_instance_read(self, &principals, &stored.namespace)?;
        Ok(Response::new(GetActionEffectResponse {
            effect: Some(to_proto_action_effect(&stored)),
        }))
    }

    async fn list_action_effects(
        &self,
        req: Request<ListActionEffectsRequest>,
    ) -> Result<Response<ListActionEffectsResponse>, Status> {
        use crate::sekai::action_effect::EFFECT_STATUS_PENDING;
        use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;

        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let effects = if !inner.instance_id.trim().is_empty() {
            let listed = self
                .db
                .list_action_effects_for_instance(&inner.instance_id)
                .map_err(Status::internal)?;
            if let Some(first) = listed.first() {
                authorize_action_instance_read(self, &principals, &first.namespace)?;
            } else {
                require_authenticated(&principals)?;
            }
            listed
        } else if !inner.namespace.trim().is_empty()
            && (inner.kind.is_empty() || inner.kind == EFFECT_KIND_RUNTIME_DISPATCH)
            && (inner.status.is_empty() || inner.status == EFFECT_STATUS_PENDING)
        {
            authorize_action_instance_read(self, &principals, &inner.namespace)?;
            let limit = if inner.limit == 0 {
                100
            } else {
                inner.limit as usize
            };
            self.db
                .list_pending_runtime_dispatch_effects(&inner.namespace, limit)
                .map_err(Status::internal)?
        } else {
            return Err(Status::invalid_argument(
                "instance_id or namespace (pending runtime_dispatch) required",
            ));
        };
        Ok(Response::new(ListActionEffectsResponse {
            effects: effects.iter().map(to_proto_action_effect).collect(),
        }))
    }

    async fn list_claimable_action_work(
        &self,
        req: Request<ListClaimableActionWorkRequest>,
    ) -> Result<Response<ListClaimableActionWorkResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        if inner.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        authorize_action_instance_read(self, &principals, &inner.namespace)?;
        let runtime = if crate::sekai::action_effect::runtime_id_is_blank(&inner.runtime_id) {
            None
        } else {
            Some(inner.runtime_id.as_str())
        };
        let limit = if inner.limit == 0 {
            100
        } else {
            inner.limit as usize
        };
        let effects = ActionWorkLifecycle::new(&self.db)
            .list_claimable(&inner.namespace, runtime, now_millis(), limit)
            .map_err(action_work_lifecycle_status)?
            .iter()
            .map(to_proto_action_effect)
            .collect();
        Ok(Response::new(ListClaimableActionWorkResponse { effects }))
    }

    async fn claim_action_work(
        &self,
        req: Request<ClaimActionWorkRequest>,
    ) -> Result<Response<ClaimActionWorkResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        if inner.effect_id.trim().is_empty() {
            return Err(Status::invalid_argument("effect_id required"));
        }
        if crate::sekai::action_effect::runtime_id_is_blank(&inner.runtime_id) {
            return Err(Status::invalid_argument("runtime_id required"));
        }
        if inner.request_id.trim().is_empty() {
            return Err(Status::invalid_argument("request_id required"));
        }
        let existing = self
            .db
            .get_action_effect(&inner.effect_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action effect not found"))?;
        // Claim requires namespace write so only authorized hosts can take work.
        check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let claimed = ActionWorkLifecycle::new(&self.db)
            .claim(
                ClaimActionWorkCommand {
                    effect_id: &inner.effect_id,
                    runtime_id: &inner.runtime_id,
                    request_id: &inner.request_id,
                    ttl_ms: inner.ttl_ms,
                },
                &actor,
                now_millis(),
            )
            .map_err(action_work_lifecycle_status)?;
        Ok(Response::new(ClaimActionWorkResponse {
            effect: Some(to_proto_action_effect(&claimed.effect)),
            continuation: claimed
                .continuation
                .as_ref()
                .map(to_proto_action_work_continuation),
            park: claimed.park.as_ref().map(to_proto_action_work_park),
        }))
    }

    async fn heartbeat_action_claim(
        &self,
        req: Request<HeartbeatActionClaimRequest>,
    ) -> Result<Response<HeartbeatActionClaimResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_action_effect(&inner.effect_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action effect not found"))?;
        check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let stored = ActionWorkLifecycle::new(&self.db)
            .heartbeat(
                HeartbeatActionClaimCommand {
                    effect_id: &inner.effect_id,
                    runtime_id: &inner.runtime_id,
                    claim_generation: inner.claim_generation,
                    fencing_token: &inner.fencing_token,
                    ttl_ms: inner.ttl_ms,
                },
                &actor,
                now_millis(),
            )
            .map_err(action_work_lifecycle_status)?;
        Ok(Response::new(HeartbeatActionClaimResponse {
            effect: Some(to_proto_action_effect(&stored)),
        }))
    }

    async fn ack_action_work(
        &self,
        req: Request<AckActionWorkRequest>,
    ) -> Result<Response<AckActionWorkResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_action_effect(&inner.effect_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action effect not found"))?;
        check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
        let now = now_millis();
        let actor = principals.first().cloned().unwrap_or_default();
        let acked = ActionWorkLifecycle::new(&self.db)
            .ack(
                AckActionWorkCommand {
                    effect_id: &inner.effect_id,
                    runtime_id: &inner.runtime_id,
                    claim_generation: inner.claim_generation,
                    fencing_token: &inner.fencing_token,
                    outcome: &inner.outcome,
                    reason: &inner.reason,
                    request_id: &inner.request_id,
                    checkpoint_store_id: &inner.checkpoint_store_id,
                    checkpoint_ref: &inner.checkpoint_ref,
                    checkpoint_digest: &inner.checkpoint_digest,
                },
                &actor,
                now,
            )
            .map_err(action_work_lifecycle_status)?;
        Ok(Response::new(AckActionWorkResponse {
            effect: Some(to_proto_action_effect(&acked.effect)),
            park: acked.park.as_ref().map(to_proto_action_work_park),
            replay: acked.replay,
        }))
    }

    async fn report_action_claim_event(
        &self,
        req: Request<ReportActionClaimEventRequest>,
    ) -> Result<Response<ReportActionClaimEventResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let effect = self
            .db
            .get_action_effect(&inner.effect_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("action effect not found"))?;
        check_team_namespace(&self.db, &principals, &effect.namespace, true)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let replay = ActionWorkLifecycle::new(&self.db)
            .report_event(
                ReportActionClaimEventCommand {
                    effect_id: &inner.effect_id,
                    runtime_id: &inner.runtime_id,
                    claim_generation: inner.claim_generation,
                    fencing_token: &inner.fencing_token,
                    kind: &inner.kind,
                    checkpoint_digest: &inner.checkpoint_digest,
                    reason_code: &inner.reason_code,
                    request_id: &inner.request_id,
                },
                &actor,
                now_millis(),
            )
            .map_err(action_work_lifecycle_status)?;
        Ok(Response::new(ReportActionClaimEventResponse { replay }))
    }

    async fn execute_action(
        &self,
        req: Request<ExecuteActionRequest>,
    ) -> Result<Response<ExecuteActionResponse>, Status> {
        if self.db.enterprise_extension().is_some() {
            return Err(Status::failed_precondition(
                "enterprise action execution requires a durable approval identity contract",
            ));
        }
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let mut work_unit = work_unit_from_metadata(&req);
        let invoked_capability = req
            .metadata()
            .get("x-sekai-capability")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let operation_id = invoked_capability.as_ref().map(|_| {
            req.metadata()
                .get("x-sekai-operation-id")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("catalog-invocation-{}", Uuid::new_v4().simple()))
        });
        let catalog_version = req
            .metadata()
            .get("x-sekai-catalog-version")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let catalog_namespace = req
            .metadata()
            .get("x-sekai-namespace")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        if let Some(operation_id) = operation_id.as_deref() {
            if work_unit.is_empty() {
                work_unit = operation_id.to_string();
            } else if work_unit != operation_id {
                return Err(Status::invalid_argument(
                    "catalog operation and work-unit correlation must match",
                ));
            }
        }
        let inner = req.into_inner();
        let dry_run = inner.dry_run;
        let r = inner
            .request
            .ok_or(Status::invalid_argument("request required"))?;
        self.refresh_action_registry()?;
        let invocation_namespace = catalog_namespace.as_deref().unwrap_or_else(|| {
            r.params
                .get("namespace")
                .map(String::as_str)
                .unwrap_or_default()
        });
        if let Some(capability_name) = &invoked_capability {
            if invocation_namespace.is_empty() {
                return Err(Status::invalid_argument(
                    "catalog action invocation requires namespace",
                ));
            }
            let entry = self
                .discoverable_capabilities(invocation_namespace, &principals)?
                .into_iter()
                .find(|entry| {
                    entry.name == *capability_name
                        && entry.action_type.as_ref().is_some_and(|action| {
                            action.name == r.action
                                && (r.action != "create_object"
                                    || r.params.get("kind") == Some(&action.target_kind))
                        })
                });
            if entry.is_none() {
                if let Some(operation_id) = operation_id.as_deref() {
                    let actor = principals.first().map(String::as_str).unwrap_or_default();
                    CatalogInvocation::record_refusal(
                        &self.db,
                        operation_id,
                        invocation_namespace,
                        actor,
                        capability_name,
                        catalog_version.as_deref(),
                        "capability_unavailable",
                    )?;
                }
                return Err(Status::failed_precondition("capability unavailable"));
            }
        }
        let mut receipt_guard = if let Some((capability_name, operation_id)) =
            invoked_capability.as_ref().zip(operation_id.as_ref())
        {
            let actor = principals.first().cloned().unwrap_or_default();
            Some(CatalogInvocation::begin(
                &self.db,
                operation_id.clone(),
                invocation_namespace,
                actor,
                capability_name.clone(),
                catalog_version.clone(),
            )?)
        } else {
            None
        };
        let execution = action_execution::ActionExecution::new(self);
        let admitted = execution.admit(
            &r,
            &principals,
            tenant_context.as_ref(),
            &work_unit,
            invoked_capability.is_some().then_some(invocation_namespace),
        )?;
        let result = execution.execute(r, dry_run, admitted, receipt_guard.as_mut());
        let result = match result {
            Ok(result) => result,
            Err(mut status) => {
                if let Some(operation_id) = operation_id.as_deref() {
                    status.metadata_mut().insert(
                        "x-sekai-operation-id",
                        operation_id
                            .parse()
                            .map_err(|_| Status::internal("invalid operation id"))?,
                    );
                }
                return Err(status);
            }
        };
        let mut response = Response::new(ExecuteActionResponse {
            result: Some(result),
        });
        if let Some(operation_id) = operation_id.as_deref() {
            response.metadata_mut().insert(
                "x-sekai-operation-id",
                operation_id
                    .parse()
                    .map_err(|_| Status::internal("invalid operation id"))?,
            );
        }
        Ok(response)
    }
    async fn set_action_policy(
        &self,
        req: Request<SetActionPolicyRequest>,
    ) -> Result<Response<SetActionPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy = req
            .into_inner()
            .policy
            .ok_or(Status::invalid_argument("policy required"))?;
        let domain_policy = from_proto_action_policy(&policy)?;
        check_action_admin(&self.security, &domain_policy.scope, &principals)?;
        self.db
            .upsert_action_policy(&domain_policy)
            .map_err(Status::internal)?;
        Ok(Response::new(SetActionPolicyResponse {
            policy: Some(to_proto_action_policy(&domain_policy)),
        }))
    }

    async fn get_action_policy(
        &self,
        req: Request<GetActionPolicyRequest>,
    ) -> Result<Response<GetActionPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        check_action_admin(&self.security, &r.scope, &principals)?;
        let policy = self
            .db
            .get_action_policy(&r.scope)
            .map_err(Status::internal)?;
        Ok(Response::new(GetActionPolicyResponse {
            policy: policy.map(|policy| to_proto_action_policy(&policy)),
        }))
    }

    async fn list_action_policies(
        &self,
        req: Request<ListActionPoliciesRequest>,
    ) -> Result<Response<ListActionPoliciesResponse>, Status> {
        let principals = caller_principals(&req);
        check_action_admin(&self.security, "", &principals)?;
        let policies = self.db.list_action_policies().map_err(Status::internal)?;
        Ok(Response::new(ListActionPoliciesResponse {
            policies: policies.iter().map(to_proto_action_policy).collect(),
        }))
    }

    async fn approve_action(
        &self,
        req: Request<ApproveActionRequest>,
    ) -> Result<Response<ApproveActionResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let approval = ActionApprovalLifecycle::new(&self.db, self.budget.as_deref())
            .load(&r.approval_id)
            .map_err(approval_lifecycle_status)?;
        check_action_admin(&self.security, &approval.policy_scope, &principals)?;
        let approver = principals.first().cloned().unwrap_or_default();
        let outcome = action_approval_execution::ActionApprovalExecution::new(self)
            .approve(&r.approval_id, &approver)
            .map_err(approval_lifecycle_status)?;
        let approval = outcome.approval;
        let msg = outcome.message;

        if let Err(error) = CatalogInvocation::resolve_approval(
            &self.db,
            &approval.work_unit,
            &approval.id,
            &approval.decided_by,
            "approved",
            Some(&approval.action),
            "succeeded",
        ) {
            tracing::error!(
                operation_id = approval.work_unit,
                approval_id = approval.id,
                error = %error,
                "approved action committed but catalog receipt projection failed"
            );
        }

        Ok(Response::new(ApproveActionResponse {
            result: Some(ActionResult {
                action: approval.action.clone(),
                message: msg,
                dry_run: false,
                planned_ops: Vec::new(),
                decision: "approved".into(),
                approval_id: approval.id.clone(),
            }),
            approval: Some(to_proto_action_approval(&approval)),
        }))
    }

    async fn deny_action(
        &self,
        req: Request<DenyActionRequest>,
    ) -> Result<Response<DenyActionResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let lifecycle = ActionApprovalLifecycle::new(&self.db, self.budget.as_deref());
        let approval = lifecycle
            .load(&r.approval_id)
            .map_err(approval_lifecycle_status)?;
        check_action_admin(&self.security, &approval.policy_scope, &principals)?;
        let decided_by = principals.first().cloned().unwrap_or_default();
        let approval = lifecycle
            .deny(DenyActionCommand {
                approval_id: &r.approval_id,
                decided_by: &decided_by,
                reason: &r.reason,
                now_ms: now_millis(),
            })
            .map_err(approval_lifecycle_status)?;
        if let Err(error) = CatalogInvocation::resolve_approval(
            &self.db,
            &approval.work_unit,
            &approval.id,
            &approval.decided_by,
            "denied",
            None,
            "denied",
        ) {
            tracing::error!(
                operation_id = approval.work_unit,
                approval_id = approval.id,
                error = %error,
                "approval denial committed but catalog receipt projection failed"
            );
        }
        Ok(Response::new(DenyActionResponse {
            approval: Some(to_proto_action_approval(&approval)),
        }))
    }

    async fn list_pending_approvals(
        &self,
        req: Request<ListPendingApprovalsRequest>,
    ) -> Result<Response<ListPendingApprovalsResponse>, Status> {
        let principals = caller_principals(&req);
        check_action_admin(&self.security, "", &principals)?;
        let r = req.into_inner();
        let status = match r.status.trim().to_ascii_lowercase().as_str() {
            "" | "pending" => Some(action_approval::ApprovalStatus::Pending),
            "all" => None,
            other => Some(
                action_approval::ApprovalStatus::parse(other)
                    .ok_or_else(|| Status::invalid_argument("invalid status filter"))?,
            ),
        };
        let approvals = self
            .db
            .list_action_approvals(status)
            .map_err(Status::internal)?;
        Ok(Response::new(ListPendingApprovalsResponse {
            approvals: approvals.iter().map(to_proto_action_approval).collect(),
        }))
    }

    async fn get_lineage(
        &self,
        req: Request<GetLineageRequest>,
    ) -> Result<Response<GetLineageResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let root = self
            .db
            .get_object(&r.object_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        check_team_namespace(&self.db, &principals, &root.namespace, false)?;
        check_read(&self.security, &root.id, &principals)?;
        enforce_object_marking_access(
            &self.db,
            &root,
            &principals,
            &format!("get_lineage:{}", root.id),
        )?;
        let res = self
            .db
            .get_lineage(&r.object_id, r.max_nodes as usize)
            .map_err(Status::internal)?;
        let visible_nodes = res
            .nodes
            .iter()
            .filter(|node| {
                check_team_namespace(&self.db, &principals, &node.object.namespace, false).is_ok()
                    && check_read(&self.security, &node.object.id, &principals).is_ok()
                    && object_passes_marking(&self.db, &node.object, &principals).unwrap_or(false)
            })
            .collect::<Vec<_>>();
        let objects = self.resolve_computed_for_responses(
            visible_nodes
                .iter()
                .map(|node| node.object.clone())
                .collect(),
            &principals,
            None,
        )?;
        let nodes = visible_nodes
            .iter()
            .zip(objects.iter())
            .map(|(n, object)| LineageNode {
                object: Some(to_proto_obj(object)),
                role: n.role.clone(),
                ephemeral: n.ephemeral,
            })
            .collect::<Vec<_>>();
        let visible_ids = nodes
            .iter()
            .filter_map(|node| node.object.as_ref().map(|object| object.id.as_str()))
            .collect::<std::collections::HashSet<_>>();
        let edges = res
            .edges
            .iter()
            .filter(|edge| {
                visible_ids.contains(edge.from.as_str()) && visible_ids.contains(edge.to.as_str())
            })
            .map(|e| LineageEdge {
                from: e.from.clone(),
                to: e.to.clone(),
                relation: e.relation.clone(),
            })
            .collect();
        Ok(Response::new(GetLineageResponse {
            result: Some(LineageResult {
                nodes,
                edges,
                truncated: res.truncated,
            }),
        }))
    }
    async fn create_contention_scope(
        &self,
        req: Request<CreateContentionScopeRequest>,
    ) -> Result<Response<CreateContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        if is_managed_team_principal(&self.db, &principals)? {
            return Err(Status::permission_denied(
                "managed team principals cannot create global contention scopes",
            ));
        }
        let inner = req.into_inner();
        let mut scope = inner
            .scope
            .ok_or(Status::invalid_argument("scope required"))
            .map(|scope| from_proto_contention_scope(&scope))?;
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if let Some(existing) = self
            .db
            .get_dedup_request(&inner.request_id, "create_contention_scope")
            .map_err(Status::internal)?
            .filter(|record| record.principal == owner)
        {
            let scope = self
                .db
                .get_contention_scope(&existing.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            return Ok(Response::new(CreateContentionScopeResponse {
                scope: Some(to_proto_contention_scope(&scope)),
            }));
        }
        if scope.owner_principal.is_empty() {
            scope.owner_principal = owner;
        }
        self.db
            .create_contention_scope(&scope)
            .map_err(Status::invalid_argument)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "create_contention_scope".into(),
                principal: dedup_principal(&principals),
                scope_id: scope.id.clone(),
                work_unit_id: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CreateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn update_contention_scope(
        &self,
        req: Request<UpdateContentionScopeRequest>,
    ) -> Result<Response<UpdateContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let scope = inner
            .scope
            .ok_or(Status::invalid_argument("scope required"))
            .map(|scope| from_proto_contention_scope(&scope))?;
        let existing = self
            .db
            .get_contention_scope(&scope.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_write(&existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "update_contention_scope")
            .map_err(Status::internal)?
        {
            if record.scope_id == scope.id && record.principal == dedup_principal(&principals) {
                let scope = self
                    .db
                    .get_contention_scope(&scope.id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("scope not found"))?;
                return Ok(Response::new(UpdateContentionScopeResponse {
                    scope: Some(to_proto_contention_scope(&scope)),
                }));
            }
        }
        self.db
            .update_contention_scope(&scope)
            .map_err(Status::invalid_argument)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "update_contention_scope".into(),
                principal: dedup_principal(&principals),
                scope_id: scope.id.clone(),
                work_unit_id: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(UpdateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn get_contention_scope(
        &self,
        req: Request<GetContentionScopeRequest>,
    ) -> Result<Response<GetContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let scope = self
            .db
            .get_contention_scope(&req.into_inner().id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_read(&scope, &principals)?;
        Ok(Response::new(GetContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn list_contention_scopes(
        &self,
        req: Request<ListContentionScopesRequest>,
    ) -> Result<Response<ListContentionScopesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let scopes = self
            .db
            .list_contention_scopes()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|scope| check_scope_read(scope, &principals).is_ok())
            .map(|scope| to_proto_contention_scope(&scope))
            .collect();
        Ok(Response::new(ListContentionScopesResponse { scopes }))
    }
    async fn create_work_unit(
        &self,
        req: Request<CreateWorkUnitRequest>,
    ) -> Result<Response<CreateWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let mut work_unit = inner
            .work_unit
            .ok_or(Status::invalid_argument("work_unit required"))
            .map(|work_unit| from_proto_work_unit(&work_unit))?;
        let principal = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if let Some(existing) = self
            .db
            .get_dedup_request(&inner.request_id, "create_work_unit")
            .map_err(Status::internal)?
            .filter(|record| record.principal == principal)
        {
            let work_unit = self
                .db
                .get_work_unit(&existing.work_unit_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("work unit not found"))?;
            return Ok(Response::new(CreateWorkUnitResponse {
                work_unit: Some(to_proto_work_unit(&work_unit)),
            }));
        }
        if !work_unit.idempotency_key.is_empty() {
            if let Some(existing) = self
                .db
                .get_work_unit_by_idempotency_key(&work_unit.idempotency_key)
                .map_err(Status::internal)?
            {
                check_work_unit_read(&self.db, &self.security, &existing, &principals)?;
                return Ok(Response::new(CreateWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&existing)),
                }));
            }
        }
        if !work_unit.target_object_id.is_empty() {
            check_object_namespace_access(
                &self.db,
                &principals,
                &work_unit.target_object_id,
                true,
            )?;
            check_write(&self.security, &work_unit.target_object_id, &principals)?;
        } else if is_managed_team_principal(&self.db, &principals)? {
            return Err(Status::permission_denied(
                "team work units require a namespace-bound target object",
            ));
        }
        let scope = self
            .db
            .get_contention_scope(&work_unit.scope_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_read(&scope, &principals)?;
        initialize_work_unit_for_create(&mut work_unit, &principal);
        self.db
            .create_work_unit(&work_unit)
            .map_err(Status::invalid_argument)?;
        let event = coordination::RunEvent {
            id: format!("evt:{}:created:{}", work_unit.id, work_unit.created_at),
            work_unit_id: work_unit.id.clone(),
            event_type: "created".into(),
            message: "work unit created".into(),
            evidence: std::collections::HashMap::from([(
                "scope_id".into(),
                work_unit.scope_id.clone(),
            )]),
            created_at: work_unit.created_at,
        };
        self.db.append_run_event(&event).map_err(Status::internal)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "create_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CreateWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn get_work_unit(
        &self,
        req: Request<GetWorkUnitRequest>,
    ) -> Result<Response<GetWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let work_unit = self
            .db
            .get_work_unit(&req.into_inner().id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.db, &self.security, &work_unit, &principals)?;
        Ok(Response::new(GetWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn list_work_units(
        &self,
        req: Request<ListWorkUnitsRequest>,
    ) -> Result<Response<ListWorkUnitsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let filter = req.into_inner().filter.unwrap_or_default();
        let limit = filter.limit;
        let mut work_units = self
            .db
            .list_work_units(&from_proto_work_unit_filter(&filter))
            .map_err(Status::internal)?
            .into_iter()
            .filter(|work_unit| {
                check_work_unit_read(&self.db, &self.security, work_unit, &principals).is_ok()
            })
            .collect::<Vec<_>>();
        let next_page_token = if limit > 0 && work_units.len() > limit as usize {
            let next = work_units
                .get((limit as usize).saturating_sub(1))
                .map(|work_unit| coordination::make_page_token(work_unit.created_at, &work_unit.id))
                .unwrap_or_default();
            trim_page(&mut work_units, limit);
            next
        } else {
            String::new()
        };
        Ok(Response::new(ListWorkUnitsResponse {
            work_units: work_units.iter().map(to_proto_work_unit).collect(),
            next_page_token,
        }))
    }
    async fn try_admit_work_unit(
        &self,
        req: Request<TryAdmitWorkUnitRequest>,
    ) -> Result<Response<TryAdmitWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let work_unit = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.db, &self.security, &work_unit, &principals)?;
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let principal = dedup_principal(&principals);
        let result = WorkUnitLifecycle::new(&self.db)
            .admit(AdmitWorkUnit {
                work_unit_id: &work_unit_id,
                request_id: &inner.request_id,
                principal: &principal,
                lease_owner: &owner,
                now_ms,
            })
            .map_err(map_work_unit_lifecycle_error)?;
        Ok(Response::new(TryAdmitWorkUnitResponse {
            admitted: result.admitted,
            queue_position: result.queue_position,
            reason: result.reason,
            work_unit: Some(to_proto_work_unit(&result.work_unit)),
            reservations: result
                .reservations
                .iter()
                .map(to_proto_reservation)
                .collect(),
        }))
    }
    async fn heartbeat_work_unit(
        &self,
        req: Request<HeartbeatWorkUnitRequest>,
    ) -> Result<Response<HeartbeatWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.db, &self.security, &existing, &principals)?;
        let work_unit = transition_work_unit(
            &self.db,
            &principals,
            &work_unit_id,
            &inner.request_id,
            WorkUnitTransition::Heartbeat,
        )?;
        Ok(Response::new(HeartbeatWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn complete_work_unit(
        &self,
        req: Request<CompleteWorkUnitRequest>,
    ) -> Result<Response<CompleteWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.db, &self.security, &existing, &principals)?;
        let work_unit = transition_work_unit(
            &self.db,
            &principals,
            &work_unit_id,
            &inner.request_id,
            WorkUnitTransition::Complete,
        )?;
        Ok(Response::new(CompleteWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn fail_work_unit(
        &self,
        req: Request<FailWorkUnitRequest>,
    ) -> Result<Response<FailWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.db, &self.security, &existing, &principals)?;
        let work_unit = transition_work_unit(
            &self.db,
            &principals,
            &inner.work_unit_id,
            &inner.request_id,
            WorkUnitTransition::Fail(&inner.failure_reason),
        )?;
        Ok(Response::new(FailWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn cancel_work_unit(
        &self,
        req: Request<CancelWorkUnitRequest>,
    ) -> Result<Response<CancelWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.db, &self.security, &existing, &principals)?;
        let work_unit = transition_work_unit(
            &self.db,
            &principals,
            &inner.work_unit_id,
            &inner.request_id,
            WorkUnitTransition::Cancel(&inner.cancel_reason),
        )?;
        Ok(Response::new(CancelWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn list_reservations(
        &self,
        req: Request<ListReservationsRequest>,
    ) -> Result<Response<ListReservationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let reservations = self
            .db
            .list_reservations(&coordination::ReservationFilter {
                work_unit_id: if inner.work_unit_id.is_empty() {
                    None
                } else {
                    Some(inner.work_unit_id)
                },
                scope_id: if inner.scope_id.is_empty() {
                    None
                } else {
                    Some(inner.scope_id)
                },
                status: if inner.status.is_empty() {
                    None
                } else {
                    Some(inner.status)
                },
            })
            .map_err(Status::internal)?;
        let mut visible = Vec::new();
        for reservation in reservations {
            if let Some(work_unit) = self
                .db
                .get_work_unit(&reservation.work_unit_id)
                .map_err(Status::internal)?
            {
                if check_work_unit_read(&self.db, &self.security, &work_unit, &principals).is_ok() {
                    visible.push(to_proto_reservation(&reservation));
                }
            }
        }
        Ok(Response::new(ListReservationsResponse {
            reservations: visible,
        }))
    }
    async fn list_run_events(
        &self,
        req: Request<ListRunEventsRequest>,
    ) -> Result<Response<ListRunEventsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.db, &self.security, &work_unit, &principals)?;
        let limit = inner.limit;
        let mut events = self
            .db
            .list_run_events(
                &inner.work_unit_id,
                inner.limit,
                inner.after,
                &inner.event_types,
                if inner.page_token.is_empty() {
                    None
                } else {
                    Some(inner.page_token.as_str())
                },
            )
            .map_err(Status::internal)?
            .into_iter()
            .collect::<Vec<_>>();
        let next_page_token = if limit > 0 && events.len() > limit as usize {
            let next = events
                .get((limit as usize).saturating_sub(1))
                .map(|event| coordination::make_page_token(event.created_at, &event.id))
                .unwrap_or_default();
            trim_page(&mut events, limit);
            next
        } else {
            String::new()
        };
        Ok(Response::new(ListRunEventsResponse {
            events: events.iter().map(to_proto_run_event).collect(),
            next_page_token,
        }))
    }
    async fn reconcile_work_units(
        &self,
        req: Request<ReconcileWorkUnitsRequest>,
    ) -> Result<Response<ReconcileWorkUnitsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let summary = if !inner.work_unit_id.is_empty() {
            let work_unit = self
                .db
                .get_work_unit(&inner.work_unit_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("work unit not found"))?;
            let scope = self
                .db
                .get_contention_scope(&work_unit.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            check_scope_write(&scope, &principals)?;
            if !inner.scope_id.is_empty() && inner.scope_id != work_unit.scope_id {
                return Ok(Response::new(ReconcileWorkUnitsResponse {
                    work_units_reconciled: 0,
                    reservations_released: 0,
                    details: Vec::new(),
                }));
            }
            self.db
                .reconcile_work_units(
                    now_ms,
                    &coordination::ReconcileFilter {
                        dry_run: inner.dry_run,
                        work_unit_id: Some(inner.work_unit_id),
                        scope_id: if inner.scope_id.is_empty() {
                            None
                        } else {
                            Some(inner.scope_id)
                        },
                        limit: inner.limit,
                    },
                )
                .map_err(Status::internal)?
        } else if !inner.scope_id.is_empty() {
            let scope = self
                .db
                .get_contention_scope(&inner.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            check_scope_write(&scope, &principals)?;
            self.db
                .reconcile_work_units(
                    now_ms,
                    &coordination::ReconcileFilter {
                        dry_run: inner.dry_run,
                        work_unit_id: None,
                        scope_id: Some(inner.scope_id),
                        limit: inner.limit,
                    },
                )
                .map_err(Status::internal)?
        } else {
            let mut owned_scope_ids: Vec<String> = self
                .db
                .list_contention_scopes()
                .map_err(Status::internal)?
                .into_iter()
                .filter(|scope| principal_matches(&scope.owner_principal, &principals))
                .map(|scope| scope.id)
                .collect();
            owned_scope_ids.sort();
            if owned_scope_ids.is_empty() {
                return Err(Status::permission_denied(
                    "reconcile requires scope ownership",
                ));
            }
            let mut summary = coordination::ReconcileSummary::default();
            for scope_id in owned_scope_ids {
                reconcile_owned_scope(
                    &self.db,
                    now_ms,
                    scope_id,
                    inner.dry_run,
                    inner.limit,
                    &mut summary,
                )?;
            }
            summary
        };
        Ok(Response::new(ReconcileWorkUnitsResponse {
            work_units_reconciled: summary.work_units_reconciled,
            reservations_released: summary.reservations_released,
            details: summary
                .details
                .iter()
                .map(|detail| ReconciliationDetail {
                    work_unit_id: detail.work_unit_id.clone(),
                    reservation_id: detail.reservation_id.clone(),
                    reason: detail.reason.clone(),
                    action: detail.action.clone(),
                })
                .collect(),
        }))
    }
    async fn create_function(
        &self,
        req: Request<CreateFunctionRequest>,
    ) -> Result<Response<CreateFunctionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        if is_managed_team_principal(&self.db, &principals)? {
            return Err(Status::permission_denied(
                "team principals cannot create global stored functions",
            ));
        }
        let function = req
            .into_inner()
            .function
            .ok_or(Status::invalid_argument("function required"))?;
        let parsed = from_proto_function(&function);
        self.db
            .create_function(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateFunctionResponse {
            function: Some(to_proto_function(&parsed)),
        }))
    }
    async fn list_functions(
        &self,
        req: Request<ListFunctionsRequest>,
    ) -> Result<Response<ListFunctionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        if is_managed_team_principal(&self.db, &principals)? {
            return Err(Status::permission_denied(
                "team principals cannot list global stored functions",
            ));
        }
        let functions = self
            .db
            .list_functions()
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_function)
            .collect();
        Ok(Response::new(ListFunctionsResponse { functions }))
    }
    async fn create_dataset(
        &self,
        req: Request<CreateDatasetRequest>,
    ) -> Result<Response<CreateDatasetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let dataset = req
            .into_inner()
            .dataset
            .ok_or(Status::invalid_argument("dataset required"))?;
        let parsed = from_proto_dataset(&dataset);
        check_dataset_access(&self.db, &self.security, &principals, &parsed, true)?;
        self.db
            .create_dataset(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateDatasetResponse {
            dataset: Some(to_proto_dataset(&parsed)),
        }))
    }
    async fn update_dataset(
        &self,
        req: Request<UpdateDatasetRequest>,
    ) -> Result<Response<UpdateDatasetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let dataset = req
            .into_inner()
            .dataset
            .ok_or(Status::invalid_argument("dataset required"))?;
        let parsed = from_proto_dataset(&dataset);
        let existing = self
            .db
            .get_dataset(&parsed.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        check_dataset_access(&self.db, &self.security, &principals, &existing, true)?;
        if existing.object_id.is_empty() {
            let root = principals.iter().any(|principal| principal == "root");
            let trusted_gateway = parsed.id == "llm_calls"
                && principals.iter().any(|principal| {
                    principal == "chisei-gateway"
                        || self.gateway_schema_principals.contains(principal)
                });
            if !root && !trusted_gateway {
                return Err(Status::permission_denied(
                    "unbound dataset updates require the gateway service principal",
                ));
            }
        }
        check_dataset_access(&self.db, &self.security, &principals, &parsed, true)?;
        self.db.update_dataset(&parsed).map_err(Status::internal)?;
        let updated = self
            .db
            .get_dataset(&parsed.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        Ok(Response::new(UpdateDatasetResponse {
            dataset: Some(to_proto_dataset(&updated)),
        }))
    }
    async fn list_datasets(
        &self,
        req: Request<ListDatasetsRequest>,
    ) -> Result<Response<ListDatasetsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let datasets = self
            .db
            .list_datasets()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|dataset| {
                check_dataset_access(&self.db, &self.security, &principals, dataset, false).is_ok()
            })
            .collect::<Vec<_>>()
            .iter()
            .map(to_proto_dataset)
            .collect();
        Ok(Response::new(ListDatasetsResponse { datasets }))
    }
    async fn append_rows(
        &self,
        req: Request<AppendRowsRequest>,
    ) -> Result<Response<AppendRowsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let dataset = self
            .db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        check_dataset_access(&self.db, &self.security, &principals, &dataset, true)?;
        let rows: Vec<_> = inner.rows.into_iter().map(|r| r.values).collect();
        let count = self
            .db
            .append_rows(&inner.dataset_id, &rows)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(AppendRowsResponse { count }))
    }
    async fn query_rows(
        &self,
        req: Request<QueryRowsRequest>,
    ) -> Result<Response<QueryRowsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let dataset = self
            .db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        check_dataset_access(&self.db, &self.security, &principals, &dataset, false)?;
        let query = inner.query.unwrap_or_default();
        let rows = self
            .db
            .query_rows(
                &inner.dataset_id,
                &dataset::RowQuery {
                    filters: from_proto_row_filters(&query.filters),
                    columns: query.columns,
                    limit: query.limit,
                    offset: query.offset,
                },
            )
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(QueryRowsResponse {
            rows: rows.into_iter().map(|values| Row { values }).collect(),
        }))
    }
    async fn create_virtual_table(
        &self,
        req: Request<CreateVirtualTableRequest>,
    ) -> Result<Response<CreateVirtualTableResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let table = req
            .into_inner()
            .table
            .ok_or(Status::invalid_argument("table required"))?;
        let parsed = from_proto_virtual_table(&table);
        let dataset = self
            .db
            .get_dataset(&parsed.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        check_dataset_access(&self.db, &self.security, &principals, &dataset, true)?;
        self.db
            .create_virtual_table(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateVirtualTableResponse {
            table: Some(to_proto_virtual_table(&parsed)),
        }))
    }
    async fn list_virtual_tables(
        &self,
        req: Request<ListVirtualTablesRequest>,
    ) -> Result<Response<ListVirtualTablesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tables = self
            .db
            .list_virtual_tables()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|table| {
                self.db
                    .get_dataset(&table.dataset_id)
                    .ok()
                    .flatten()
                    .map(|dataset| {
                        check_dataset_access(&self.db, &self.security, &principals, &dataset, false)
                            .is_ok()
                    })
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>()
            .iter()
            .map(to_proto_virtual_table)
            .collect();
        Ok(Response::new(ListVirtualTablesResponse { tables }))
    }
    async fn create_grant(
        &self,
        req: Request<CreateGrantRequest>,
    ) -> Result<Response<CreateGrantResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let grant = req
            .into_inner()
            .grant
            .ok_or(Status::invalid_argument("grant required"))?;
        let parsed = from_proto_grant(&grant)?;
        if check_ontology_grant_target(&self.db, &self.security, &parsed.object_id, &principals)? {
            self.db
                .create_grant(&parsed)
                .map_err(Status::invalid_argument)?;
            self.security.add_grant(&parsed);
            return Ok(Response::new(CreateGrantResponse {
                grant: Some(to_proto_grant(&parsed)),
            }));
        }
        let target = self
            .db
            .get_object(&parsed.object_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::invalid_argument("grant target object does not exist"))?;
        if target.kind == "namespace" {
            require_credential_admin(&principals)?;
        } else {
            check_team_namespace(&self.db, &principals, &target.namespace, true)?;
        }
        check_object_admin(&self.db, &self.security, &target, &principals)?;
        self.db
            .create_grant(&parsed)
            .map_err(Status::invalid_argument)?;
        self.security.add_grant(&parsed);
        Ok(Response::new(CreateGrantResponse {
            grant: Some(to_proto_grant(&parsed)),
        }))
    }
    async fn delete_grant(
        &self,
        req: Request<DeleteGrantRequest>,
    ) -> Result<Response<DeleteGrantResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        let existing = self
            .db
            .get_grant(&id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("grant not found"))?;
        if check_ontology_grant_target(&self.db, &self.security, &existing.object_id, &principals)?
        {
            let deleted = self.db.delete_grant(&id).map_err(Status::internal)?;
            if let Some(grant) = deleted {
                self.security
                    .remove_grant(&grant.object_id, &grant.principal);
            }
            return Ok(Response::new(DeleteGrantResponse {}));
        }
        let target = self
            .db
            .get_object(&existing.object_id)
            .map_err(Status::internal)?;
        if target
            .as_ref()
            .is_some_and(|object| object.kind == "namespace")
        {
            require_credential_admin(&principals)?;
        } else if let Some(target) = &target {
            check_team_namespace(&self.db, &principals, &target.namespace, true)?;
        }
        let target = target.ok_or(Status::not_found("grant target not found"))?;
        check_object_admin(&self.db, &self.security, &target, &principals)?;
        let deleted = self.db.delete_grant(&id).map_err(Status::internal)?;
        if let Some(grant) = deleted {
            self.security
                .remove_grant(&grant.object_id, &grant.principal);
        }
        Ok(Response::new(DeleteGrantResponse {}))
    }
    async fn list_grants(
        &self,
        req: Request<ListGrantsRequest>,
    ) -> Result<Response<ListGrantsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let object_id = req.into_inner().object_id;
        if check_ontology_grant_target(&self.db, &self.security, &object_id, &principals)? {
            let grants = self
                .db
                .list_grants(&object_id)
                .map_err(Status::internal)?
                .iter()
                .map(to_proto_grant)
                .collect();
            return Ok(Response::new(ListGrantsResponse { grants }));
        }
        let target = self
            .db
            .get_object(&object_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("grant target not found"))?;
        if target.kind == "namespace" {
            require_credential_admin(&principals)?;
        } else {
            check_team_namespace(&self.db, &principals, &target.namespace, true)?;
        }
        check_object_admin(&self.db, &self.security, &target, &principals)?;
        let grants = self
            .db
            .list_grants(&object_id)
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_grant)
            .collect();
        Ok(Response::new(ListGrantsResponse { grants }))
    }
    async fn check_access(
        &self,
        req: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_object_namespace_access(&self.db, &principals, &inner.object_id, false)?;
        check_read(&self.security, &inner.object_id, &principals)?;
        let refs: Vec<&str> = inner.principals.iter().map(String::as_str).collect();
        Ok(Response::new(CheckAccessResponse {
            allowed: self.security.can_access(&inner.object_id, &refs),
        }))
    }
    async fn ensure_team_namespace(
        &self,
        req: Request<EnsureTeamNamespaceRequest>,
    ) -> Result<Response<EnsureTeamNamespaceResponse>, Status> {
        let principals = caller_principals(&req);
        require_credential_admin(&principals)?;
        let inner = req.into_inner();
        let namespace = validate_credential_principal(&inner.namespace)?;
        let principal = validate_team_principal(&inner.principal)?;
        let role = security::Role::parse(&inner.role)
            .ok_or_else(|| Status::invalid_argument("role must be viewer, editor, or admin"))?;
        let actor = principals.first().map(String::as_str).unwrap_or("root");
        let (namespace, grants) = self
            .db
            .ensure_team_namespace(&namespace, &principal, role, actor)
            .map_err(Status::internal)?;
        for grant in &grants {
            self.security.add_grant(grant);
        }
        Ok(Response::new(EnsureTeamNamespaceResponse {
            namespace: Some(to_proto_obj(&namespace)),
            grants: grants.iter().map(to_proto_grant).collect(),
        }))
    }
    async fn record_decision(
        &self,
        req: Request<RecordDecisionRequest>,
    ) -> Result<Response<RecordDecisionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let mut decision = req
            .into_inner()
            .decision
            .ok_or_else(|| Status::invalid_argument("decision required"))?;
        decision.actor = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if decision.target_id.is_empty() {
            if is_managed_team_principal(&self.db, &principals)? {
                return Err(Status::permission_denied(
                    "team decisions require a namespace-bound target object",
                ));
            }
        } else {
            check_object_namespace_access(&self.db, &principals, &decision.target_id, true)?;
            check_write(&self.security, &decision.target_id, &principals)?;
        }
        if decision.id.is_empty() {
            decision.id = uuid::Uuid::new_v4().to_string();
        }
        // Clamp to server time: a client-supplied future timestamp would sit
        // above every later entry in the ledger and pin the purgeable prefix
        // forever (retention would silently stop).
        let now = now_millis();
        if decision.timestamp <= 0 || decision.timestamp > now {
            decision.timestamp = now;
        }
        // Reserved keys: only the server-side attestation binding may claim
        // one, otherwise a caller could dress up an arbitrary decision as
        // policy-attested.
        decision
            .evidence
            .remove(attestation::EVIDENCE_ATTESTATION_ID);
        decision
            .evidence
            .remove(attestation::EVIDENCE_ATTESTATION_HASH);
        self.db
            .record_decision(&audit::Decision {
                id: decision.id.clone(),
                timestamp: decision.timestamp,
                actor: decision.actor.clone(),
                action: decision.action.clone(),
                reason: decision.reason.clone(),
                evidence: decision.evidence.clone(),
                target_id: decision.target_id.clone(),
                outcome: decision.outcome.clone(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(RecordDecisionResponse {
            decision: Some(decision),
        }))
    }
    async fn list_decisions(
        &self,
        req: Request<ListDecisionsRequest>,
    ) -> Result<Response<ListDecisionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let visible_limit = if inner.limit > 0 {
            inner.limit as usize
        } else {
            100
        };
        let actor_filter = if inner.actor.is_empty() {
            None
        } else {
            Some(inner.actor.clone())
        };
        let action_filter = if inner.action.is_empty() {
            None
        } else {
            Some(inner.action.clone())
        };
        let target_filter = if inner.target_id.is_empty() {
            None
        } else {
            check_object_namespace_access(&self.db, &principals, &inner.target_id, false)?;
            check_read(&self.security, &inner.target_id, &principals)?;
            Some(inner.target_id.clone())
        };
        let managed_team_principal = is_managed_team_principal(&self.db, &principals)?;
        let decisions = scan_visible_page(
            visible_limit,
            0,
            |limit, offset| {
                self.db.list_decisions(&audit::DecisionFilter {
                    actor: actor_filter.clone(),
                    action: action_filter.clone(),
                    target_id: target_filter.clone(),
                    after: inner.after,
                    limit,
                    offset,
                })
            },
            |decision| {
                if decision.target_id.is_empty() {
                    if managed_team_principal {
                        return false;
                    }
                } else if check_object_namespace_access(
                    &self.db,
                    &principals,
                    &decision.target_id,
                    false,
                )
                .is_err()
                    || check_read(&self.security, &decision.target_id, &principals).is_err()
                {
                    return false;
                }
                true
            },
        )
        .map_err(|error| match error {
            VisiblePageError::Fetch(error) => Status::internal(error),
            VisiblePageError::ScanBudgetExhausted => Status::resource_exhausted(
                "decision visibility scan limit exceeded; refine filters",
            ),
        })?
        .into_iter()
        .map(|decision| Decision {
            id: decision.id,
            timestamp: decision.timestamp,
            actor: decision.actor,
            action: decision.action,
            reason: decision.reason,
            evidence: decision.evidence,
            target_id: decision.target_id,
            outcome: decision.outcome,
        })
        .collect();
        Ok(Response::new(ListDecisionsResponse { decisions }))
    }
    async fn list_object_changes(
        &self,
        req: Request<ListObjectChangesRequest>,
    ) -> Result<Response<ListObjectChangesResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_object_namespace_access(&self.db, &principals, &inner.object_id, false)?;
        check_read(&self.security, &inner.object_id, &principals)?;
        let object = self
            .db
            .get_object(&inner.object_id)
            .map_err(Status::internal)?;
        match object.as_ref() {
            Some(object) => {
                enforce_namespace_tenant_context(
                    &self.db,
                    tenant_context.as_ref(),
                    &object.namespace,
                    false,
                )
                .map_err(|_| Status::not_found("not found"))?;
                enforce_object_marking_access(
                    &self.db,
                    object,
                    &principals,
                    &format!("list_object_changes:{}", object.id),
                )?;
            }
            None if tenant_context.is_some() => {
                return Err(Status::not_found("not found"));
            }
            // Without a live object we cannot reconstruct access_marking.
            // Residual: ACL-only for orphan history until tombstones retain
            // access_marking (documented residual risk).
            None => {}
        }
        let object_kind = match object.as_ref() {
            Some(object) => Some(object.kind.clone()),
            None => self
                .db
                .object_change_kind(&inner.object_id)
                .map_err(Status::internal)?,
        };
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        let changes = self
            .db
            .list_visible_object_changes(&inner.object_id, inner.limit, inner.offset)
            .map_err(Status::internal)?
            .into_iter()
            .map(|change| {
                if let Some(kind) = object_kind.as_deref() {
                    redact_object_change_values(
                        change,
                        &inner.object_id,
                        kind,
                        &schema,
                        &self.security,
                        &principals,
                    )
                } else {
                    ObjectChange {
                        id: change.id,
                        object_id: change.object_id,
                        field: change.field,
                        old_value: change.old_value,
                        new_value: change.new_value,
                        changed_by: change.changed_by,
                        timestamp: change.timestamp,
                    }
                }
            })
            .collect();
        Ok(Response::new(ListObjectChangesResponse { changes }))
    }

    async fn get_attestation(
        &self,
        req: Request<GetAttestationRequest>,
    ) -> Result<Response<GetAttestationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        if id.trim().is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        let attestation = self
            .db
            .get_attestation(&id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("attestation not found"))?;
        // Attestations embed the full policy snapshot; reading policy content
        // is admin-gated like get_action_policy / list_action_policies.
        check_action_admin(&self.security, &attestation.policy_scope, &principals)?;
        Ok(Response::new(GetAttestationResponse {
            attestation: Some(to_proto_attestation(&attestation)),
        }))
    }

    async fn list_attestations(
        &self,
        req: Request<ListAttestationsRequest>,
    ) -> Result<Response<ListAttestationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let decision_id = (!inner.decision_id.trim().is_empty()).then_some(inner.decision_id);
        let policy_scope = (!inner.policy_scope.trim().is_empty()).then_some(inner.policy_scope);
        // Attestations embed full policy snapshots (admin-gated content).
        // With a scope filter the caller must be admin for that scope; without
        // one, only the scopes the caller administers are returned.
        if let Some(scope) = policy_scope.as_deref() {
            check_action_admin(&self.security, scope, &principals)?;
        }
        // Paginate over *visible* rows: scan the table in batches and apply
        // limit/offset after the admin filter, so partially-privileged
        // callers get stable pages (mirrors list_decisions). A scan cap
        // bounds the work when most rows are invisible to the caller.
        let visible_limit = if inner.limit > 0 {
            inner.limit as usize
        } else {
            100
        };
        let visible_offset = inner.offset.max(0) as usize;
        let attestations = scan_visible_page(
            visible_limit,
            visible_offset,
            |limit, offset| {
                self.db.list_attestations(
                    decision_id.as_deref(),
                    policy_scope.as_deref(),
                    limit,
                    offset,
                )
            },
            |attestation| {
                check_action_admin(&self.security, &attestation.policy_scope, &principals).is_ok()
            },
        )
        .map_err(|error| match error {
            VisiblePageError::Fetch(error) => Status::internal(error),
            VisiblePageError::ScanBudgetExhausted => Status::resource_exhausted(
                "attestation visibility scan limit exceeded; refine filters",
            ),
        })?
        .iter()
        .map(to_proto_attestation)
        .collect();
        Ok(Response::new(ListAttestationsResponse { attestations }))
    }

    async fn verify_attestation(
        &self,
        req: Request<VerifyAttestationRequest>,
    ) -> Result<Response<VerifyAttestationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        if id.trim().is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        // Verification results expose the replayed decision for a scope's
        // policy; gate like the other attestation reads.
        if let Some(attestation) = self.db.get_attestation(&id).map_err(Status::internal)? {
            check_action_admin(&self.security, &attestation.policy_scope, &principals)?;
        }
        let report = self.db.verify_attestation(&id).map_err(Status::internal)?;
        Ok(Response::new(VerifyAttestationResponse {
            ok: report.ok,
            found: report.found,
            hash_ok: report.hash_ok,
            replay_ok: report.replay_ok,
            replayed_decision: report.replayed_decision,
            decision_linked: report.decision_linked,
            error: report.error,
        }))
    }

    async fn create_credential(
        &self,
        req: Request<CreateCredentialRequest>,
    ) -> Result<Response<CreateCredentialResponse>, Status> {
        credential_admin_actor(&self.db, &req, "")?;
        let request = req.into_inner();
        let principal = if request.managed_team_principal {
            validate_team_principal(&request.principal)?
        } else {
            validate_new_credential_principal(&request.principal)?
        };
        let existing = self
            .db
            .list_unbound_credentials(Some(&principal), Some("active"));
        if !existing.map_err(Status::internal)?.is_empty() {
            return Err(Status::already_exists(format!(
                "active credential already exists for {principal:?}; rotate it instead"
            )));
        }
        let token = new_credential_token();
        let token_hash = hash_gateway_key(&token);
        let now = chrono::Utc::now().timestamp_millis();
        let credential = if request.managed_team_principal {
            self.db
                .create_managed_team_credential(&principal, &token_hash, now)
        } else {
            self.db
                .create_principal_credential(&principal, &token_hash, now)
        }
        .map_err(Status::internal)?;
        Ok(Response::new(CreateCredentialResponse {
            token,
            credential: Some(to_proto_credential(credential)),
        }))
    }

    async fn rotate_credential(
        &self,
        req: Request<RotateCredentialRequest>,
    ) -> Result<Response<RotateCredentialResponse>, Status> {
        credential_admin_actor(&self.db, &req, "")?;
        let request = req.into_inner();
        let principal = if request.managed_team_principal {
            validate_team_principal(&request.principal)?
        } else {
            validate_new_credential_principal(&request.principal)?
        };
        let existing = self
            .db
            .list_unbound_credentials(Some(&principal), Some("active"));
        if existing.map_err(Status::internal)?.is_empty() {
            return Err(Status::not_found(format!(
                "no active credential for {principal:?}"
            )));
        }
        let token = new_credential_token();
        let token_hash = hash_gateway_key(&token);
        let credential = if request.managed_team_principal {
            self.db
                .rotate_managed_team_credential(&principal, &token_hash)
                .map_err(Status::internal)
        } else {
            self.db
                .rotate_principal_credential(&principal, &token_hash)
                .map_err(Status::internal)
        }?;
        Ok(Response::new(RotateCredentialResponse {
            token,
            credential: Some(to_proto_credential(credential)),
        }))
    }

    async fn revoke_credential(
        &self,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        credential_admin_actor(&self.db, &req, "")?;
        let request = req.into_inner();
        let principal = validate_credential_principal(&request.principal)?;
        let credential = self
            .db
            .revoke_principal_credential(&principal)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found(format!("no active credential for {principal:?}")))?;
        Ok(Response::new(RevokeCredentialResponse {
            credential: Some(to_proto_credential(credential)),
        }))
    }

    async fn list_credentials(
        &self,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        credential_admin_actor(&self.db, &req, "")?;
        let credentials = self
            .db
            .list_unbound_credentials(None, None)
            .map_err(Status::internal)?
            .into_iter()
            .map(to_proto_credential)
            .collect();
        Ok(Response::new(ListCredentialsResponse { credentials }))
    }

    async fn register_evidence_schema(
        &self,
        req: Request<RegisterEvidenceSchemaRequest>,
    ) -> Result<Response<RegisterEvidenceSchemaResponse>, Status> {
        let principals = caller_principals(&req);
        require_evidence_admin(&self.security, &principals)?;
        let definition = req
            .into_inner()
            .definition
            .ok_or_else(|| Status::invalid_argument("definition required"))?;
        self.db
            .register_evidence_schema(
                &DomainEvidenceSchemaDefinition {
                    schema_id: definition.schema_id,
                    schema_version: definition.schema_version,
                    evidence_type: definition.evidence_type,
                    compatible_versions: definition.compatible_versions,
                },
                now_millis(),
            )
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(RegisterEvidenceSchemaResponse {}))
    }

    async fn list_evidence_adapters(
        &self,
        req: Request<crate::grpc::pb::sekai::ListEvidenceAdaptersRequest>,
    ) -> Result<Response<crate::grpc::pb::sekai::ListEvidenceAdaptersResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let registered_only = req.into_inner().registered_only;
        let mut adapters = Vec::new();
        for profile in crate::evidence_adapter_catalog::built_in_evidence_adapters() {
            let schema_registered = self
                .db
                .is_evidence_schema_registered(&profile.schema_id, &profile.schema_version)
                .map_err(Status::internal)?;
            if registered_only && !schema_registered {
                continue;
            }
            adapters.push(crate::grpc::pb::sekai::EvidenceAdapterProfile {
                adapter_id: profile.adapter_id,
                family: profile.family,
                evidence_type: profile.evidence_type,
                schema_id: profile.schema_id,
                schema_version: profile.schema_version,
                source_type: profile.source_type,
                signal: profile.signal,
                delivery: profile.delivery,
                requires_expiry: profile.requires_expiry,
                reference_example: profile.reference_example,
                description: profile.description,
                schema_registered,
            });
        }
        let families = crate::evidence_adapter_catalog::built_in_evidence_adapter_families()
            .into_iter()
            .filter(|family| {
                !registered_only
                    || family.adapter_ids.iter().any(|adapter_id| {
                        adapters
                            .iter()
                            .any(|adapter| adapter.adapter_id == *adapter_id)
                    })
            })
            .map(|family| crate::grpc::pb::sekai::EvidenceAdapterFamily {
                family: family.family,
                display_name: family.display_name,
                description: family.description,
                adapter_ids: family.adapter_ids,
            })
            .collect();
        Ok(Response::new(
            crate::grpc::pb::sekai::ListEvidenceAdaptersResponse { adapters, families },
        ))
    }

    async fn submit_evidence(
        &self,
        req: Request<SubmitEvidenceRequest>,
    ) -> Result<Response<SubmitEvidenceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let envelope = req
            .into_inner()
            .envelope
            .ok_or_else(|| Status::invalid_argument("envelope required"))?;
        let envelope = from_proto_evidence_envelope(envelope)?;
        if !principals.contains(&envelope.producer_identity) {
            return Err(Status::permission_denied(
                "authenticated producer must match envelope attribution",
            ));
        }
        let result = EvidenceAdmissionLifecycle::new(&self.db)
            .admit(&envelope, &envelope.producer_identity, now_millis())
            .map_err(map_evidence_admission_lifecycle_error)?;
        if let Some(object_id) = result
            .projection
            .as_ref()
            .and_then(|projection| projection.evidence_object_id.as_deref())
        {
            for grant in self.db.list_grants(object_id).map_err(Status::internal)? {
                self.security.add_grant(&grant);
            }
        }
        Ok(Response::new(SubmitEvidenceResponse {
            result: Some(to_proto_evidence_submission_result(result)),
        }))
    }

    async fn get_evidence_submission(
        &self,
        req: Request<GetEvidenceSubmissionRequest>,
    ) -> Result<Response<GetEvidenceSubmissionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let submission_id = req.into_inner().submission_id;
        let submission = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("evidence submission not found"))?;
        if !can_operate_evidence_submission(&self.security, &submission, &principals) {
            return Err(Status::permission_denied("evidence access denied"));
        }
        let history = self
            .db
            .evidence_lifecycle_history(&submission_id)
            .map_err(Status::internal)?
            .into_iter()
            .map(|state| state.as_str().to_string())
            .collect();
        Ok(Response::new(GetEvidenceSubmissionResponse {
            submission: Some(to_proto_evidence_submission(&submission)),
            lifecycle_history: history,
        }))
    }

    async fn list_evidence_submissions(
        &self,
        req: Request<ListEvidenceSubmissionsRequest>,
    ) -> Result<Response<ListEvidenceSubmissionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let is_admin = require_evidence_admin(&self.security, &principals).is_ok();
        let request = req.into_inner();
        let producer_identity = if is_admin {
            optional_nonempty(request.producer_identity)
        } else {
            let requested = optional_nonempty(request.producer_identity);
            if requested
                .as_ref()
                .is_some_and(|producer| !principals.contains(producer))
            {
                return Err(Status::permission_denied("evidence access denied"));
            }
            requested.or_else(|| {
                principals
                    .iter()
                    .find(|principal| principal.as_str() != "anonymous")
                    .cloned()
            })
        };
        let lifecycle_state = if request.lifecycle_state.trim().is_empty() {
            None
        } else {
            Some(
                evidence_domain::EvidenceLifecycleState::parse(request.lifecycle_state.trim())
                    .ok_or_else(|| Status::invalid_argument("invalid lifecycle_state"))?,
            )
        };
        let submissions = self
            .db
            .list_evidence_submissions(&EvidenceSubmissionFilter {
                producer_identity,
                source_instance: optional_nonempty(request.source_instance),
                namespace: optional_nonempty(request.namespace),
                lifecycle_state,
                target_external_id: optional_nonempty(request.target_external_id),
                evidence_type: optional_nonempty(request.evidence_type),
                limit: request.limit,
                offset: request.offset,
            })
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_evidence_submission)
            .collect();
        Ok(Response::new(ListEvidenceSubmissionsResponse {
            submissions,
        }))
    }

    async fn get_provenance_report(
        &self,
        req: Request<GetProvenanceReportRequest>,
    ) -> Result<Response<GetProvenanceReportResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let work_unit_id = req.into_inner().work_unit_id.trim().to_string();
        if work_unit_id.is_empty() {
            return Err(Status::invalid_argument("work_unit_id required"));
        }
        let work_unit = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.db, &self.security, &work_unit, &principals)?;
        let report = crate::provenance::assemble_report(&self.db, &work_unit_id)
            .map_err(Status::internal)?;
        Ok(Response::new(GetProvenanceReportResponse {
            report: crate::provenance::render_text(&report),
        }))
    }
}

fn require_credential_admin(principals: &[String]) -> Result<(), Status> {
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
    {
        return Ok(());
    }
    Err(Status::permission_denied("credential admin required"))
}

fn credential_admin_actor(
    db: &RuntimeDb,
    req: &Request<impl std::any::Any>,
    requested_tenant: &str,
) -> Result<(String, bool), Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let actor = principals
        .into_iter()
        .next()
        .ok_or_else(|| Status::unauthenticated("authenticated principal required"))?;
    let _ = (db, requested_tenant);
    require_credential_admin(std::slice::from_ref(&actor))?;
    Ok((actor, true))
}

type RequestEnterpriseContext = crate::enterprise::AuthenticatedContext;

fn request_tenant_context(
    _db: &RuntimeDb,
    req: &Request<impl std::any::Any>,
) -> Result<Option<RequestEnterpriseContext>, Status> {
    if let Some(context) = req
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        return Ok(Some(context.clone()));
    }
    Ok(None)
}

fn enforce_namespace_tenant_context(
    db: &RuntimeDb,
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    write: bool,
) -> Result<(), Status> {
    let Some(extension) = db.enterprise_extension() else {
        return Ok(());
    };
    let Some(context) = tenant_context else {
        return Ok(());
    };
    let action = if write {
        crate::enterprise::NamespaceAction::Write
    } else {
        crate::enterprise::NamespaceAction::Read
    };
    extension
        .authorize_authenticated_context(context, namespace, action)
        .map_err(extension_status)
}

fn extension_status(error: crate::enterprise::ExtensionError) -> Status {
    match error {
        crate::enterprise::ExtensionError::CredentialNotFound => {
            Status::unauthenticated("enterprise credential not found")
        }
        crate::enterprise::ExtensionError::Unauthenticated => {
            Status::unauthenticated("enterprise authentication failed")
        }
        crate::enterprise::ExtensionError::PermissionDenied => {
            Status::permission_denied("enterprise authorization denied")
        }
        crate::enterprise::ExtensionError::UnsupportedVersion => {
            Status::failed_precondition("unsupported enterprise identity contract version")
        }
        crate::enterprise::ExtensionError::Expired
        | crate::enterprise::ExtensionError::Revoked
        | crate::enterprise::ExtensionError::Replayed
        | crate::enterprise::ExtensionError::MembershipRevoked
        | crate::enterprise::ExtensionError::TenantSuspended
        | crate::enterprise::ExtensionError::InvalidState
        | crate::enterprise::ExtensionError::InvalidNonce
        | crate::enterprise::ExtensionError::InvalidRedirectUri
        | crate::enterprise::ExtensionError::InvalidPkce
        | crate::enterprise::ExtensionError::IssuerMismatch
        | crate::enterprise::ExtensionError::ResourceMismatch => {
            Status::permission_denied("enterprise credential validation failed")
        }
        crate::enterprise::ExtensionError::Unavailable(message) => Status::unavailable(message),
    }
}

fn validate_credential_principal(principal: &str) -> Result<String, Status> {
    let principal = principal.trim();
    if principal.is_empty()
        || !principal
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
    {
        return Err(Status::invalid_argument(
            "principal must match [a-zA-Z0-9._-]+",
        ));
    }
    Ok(principal.to_string())
}

fn validate_new_credential_principal(principal: &str) -> Result<String, Status> {
    let principal = validate_credential_principal(principal)?;
    if matches!(principal.as_str(), "root" | "local" | "anonymous") {
        return Err(Status::invalid_argument(format!(
            "principal {principal:?} is reserved for control-plane authentication"
        )));
    }
    Ok(principal)
}

fn validate_team_principal(principal: &str) -> Result<String, Status> {
    let principal = validate_new_credential_principal(principal)?;
    if principal == "chisei-gateway" {
        return Err(Status::invalid_argument(
            "principal \"chisei-gateway\" is reserved for gateway authentication",
        ));
    }
    Ok(principal)
}

fn new_credential_token() -> String {
    format!(
        "sekai_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

fn to_proto_credential(credential: crate::db::sekai::PrincipalCredential) -> CredentialRecord {
    CredentialRecord {
        id: credential.id,
        principal: credential.principal,
        status: credential.status,
        created: credential.created,
        rotated_at: credential.rotated_at,
        revoked_at: credential.revoked_at,
        tenant_id: String::new(),
    }
}

fn scoring_learning_id(namespace: &str, request_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"chisei.scoring.record_learning.v1");
    for value in [namespace, request_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    format!("learning:chisei.scoring:{encoded}")
}

fn bounded_knowledge_text(value: &str, max_chars: usize) -> String {
    let mut normalized = String::new();
    let mut chars: usize = 0;
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_whitespace() || character.is_control() {
            pending_space = !normalized.is_empty();
            continue;
        }
        if pending_space {
            if chars.saturating_add(1) >= max_chars {
                break;
            }
            normalized.push(' ');
            chars += 1;
        }
        pending_space = false;
        if chars >= max_chars {
            break;
        }
        normalized.push(character);
        chars += 1;
    }
    normalized
}

fn knowledge_source_request_id(request_id: &str) -> String {
    let trimmed = request_id.trim();
    if trimmed.chars().count() <= 256 && !trimmed.chars().any(char::is_control) {
        return trimmed.to_string();
    }
    let mut digest = Sha256::new();
    digest.update(b"chisei.scoring.source_request.v1");
    digest.update((request_id.len() as u64).to_be_bytes());
    digest.update(request_id.as_bytes());
    let encoded = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{encoded}")
}

#[async_trait::async_trait]
impl KnowledgeWriter for SekaiServiceImpl {
    async fn write_knowledge(
        &self,
        request: &KnowledgeWriteRequest,
    ) -> Result<KnowledgeWriteOutcome, String> {
        let namespace = request.namespace.trim();
        if namespace.is_empty() {
            return Err("knowledge write requires an observation namespace".into());
        }
        if request.request_id.trim().is_empty() {
            return Err("knowledge write requires a source request id".into());
        }

        let target = match self
            .db
            .find_by_external_id(&format!("namespace:{namespace}"))?
        {
            Some(target) if target.kind == "namespace" => target,
            Some(target) => {
                return Err(format!(
                    "namespace external id resolved to unexpected kind: {}",
                    target.kind
                ));
            }
            None => self
                .db
                .find_by_external_id(&format!("policy:{namespace}"))?
                .or(self
                    .db
                    .find_by_external_id(&format!("project:{namespace}"))?)
                .ok_or_else(|| format!("no governed target found for namespace: {namespace}"))?,
        };

        let learning_id = scoring_learning_id(namespace, &request.request_id);
        let passed = if request.passed { "true" } else { "false" };
        let mut reasoning = bounded_knowledge_text(&request.reasoning, 2_000);
        if reasoning.is_empty() {
            reasoning = format!(
                "The scoring judge recorded a {} outcome with score {}.",
                if request.passed { "passing" } else { "failing" },
                request.score.clamp(0, 100)
            );
        }
        let task_class = bounded_knowledge_text(&request.task_class, 128);
        let model = bounded_knowledge_text(&request.model, 256);
        let task_class = if task_class.is_empty() {
            "unclassified".to_string()
        } else {
            task_class
        };
        let model = if model.is_empty() {
            "unknown".to_string()
        } else {
            model
        };
        let title = format!(
            "Scored {task_class} task outcome: {}",
            if request.passed {
                "passed"
            } else {
                "needs correction"
            }
        );
        let prevention = if request.passed {
            format!("Preserve this evaluated behavior: {reasoning}")
        } else {
            format!("Before repeating this task, address: {reasoning}")
        };
        let params = HashMap::from([
            ("id".into(), learning_id.clone()),
            ("target_id".into(), target.id.clone()),
            ("title".into(), title),
            ("prevention".into(), prevention),
            ("reasoning".into(), reasoning),
            (
                "source_request_id".into(),
                knowledge_source_request_id(&request.request_id),
            ),
            ("score".into(), request.score.clamp(0, 100).to_string()),
            ("passed".into(), passed.into()),
            ("task_class".into(), task_class),
            ("model".into(), model),
            ("producer".into(), "chisei.scoring".into()),
            ("status".into(), "candidate".into()),
        ]);
        let mut rpc_request = Request::new(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
                params,
                actor: "chisei.scoring".into(),
            }),
            dry_run: false,
        });
        rpc_request.metadata_mut().insert(
            "x-principal",
            tonic::metadata::MetadataValue::from_static("chisei.scoring"),
        );
        rpc_request.metadata_mut().insert(
            "x-chisei-work-unit",
            tonic::metadata::MetadataValue::try_from(learning_id.as_str())
                .map_err(|error| format!("invalid knowledge work-unit metadata: {error}"))?,
        );

        match <Self as SekaiService>::execute_action(self, rpc_request).await {
            Ok(response) => {
                let result = response
                    .into_inner()
                    .result
                    .ok_or_else(|| "record_learning returned no action result".to_string())?;
                match result.decision.as_str() {
                    "allow" | "require_approval" => Ok(KnowledgeWriteOutcome::Accepted),
                    "deny" => Ok(KnowledgeWriteOutcome::PolicyDenied),
                    decision => Err(format!(
                        "record_learning returned unknown policy decision: {decision}"
                    )),
                }
            }
            Err(status)
                if status.code() == tonic::Code::PermissionDenied
                    && status.message().contains("denied by policy") =>
            {
                Ok(KnowledgeWriteOutcome::PolicyDenied)
            }
            Err(status) => Err(format!(
                "record_learning failed ({}): {}",
                status.code(),
                status.message()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        SekaiServiceImpl::new(db)
    }

    struct TestEnterpriseExtension;

    impl crate::enterprise::EnterpriseExtension for TestEnterpriseExtension {
        fn authenticate_bearer(
            &self,
            bearer_token: &str,
        ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError>
        {
            (bearer_token == "enterprise-token")
                .then(|| crate::enterprise::AuthenticatedPrincipal {
                    subject: "subject-a".into(),
                    credential_id: "credential-a".into(),
                })
                .ok_or(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn authenticate_context(
            &self,
            bearer_token: &str,
        ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError>
        {
            let principal = self.authenticate_bearer(bearer_token)?;
            Ok(crate::enterprise::AuthenticatedContext {
                contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
                tenant: Some(self.tenant_context(&principal)?),
                principal,
                credential_kind: crate::enterprise::CredentialKind::HumanSession,
                scopes: vec!["sekai.read".into(), "sekai.write".into()],
                issuer: "https://issuer.test".into(),
                resource: "https://sekai.test".into(),
                expires_at: 100,
            })
        }

        fn tenant_context(
            &self,
            principal: &crate::enterprise::AuthenticatedPrincipal,
        ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
            if principal.credential_id != "credential-a" {
                return Err(crate::enterprise::ExtensionError::Unauthenticated);
            }
            Ok(crate::enterprise::TenantContext {
                tenant_id: "tenant-test".into(),
                subject: principal.subject.clone(),
            })
        }

        fn authorize_namespace(
            &self,
            _context: &crate::enterprise::TenantContext,
            namespace: &str,
            _action: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            (namespace == "allowed")
                .then_some(())
                .ok_or(crate::enterprise::ExtensionError::PermissionDenied)
        }

        fn authorize_unscoped_namespace(
            &self,
            principal: &crate::enterprise::AuthenticatedPrincipal,
            namespace: &str,
            _action: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            (principal.credential_id == "community-credential" && namespace == "community")
                .then_some(())
                .ok_or(crate::enterprise::ExtensionError::PermissionDenied)
        }
    }

    #[test]
    fn injected_enterprise_extension_derives_context_and_authorizes_namespace() {
        let db = RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(TestEnterpriseExtension)),
            )
            .unwrap(),
        ));
        let mut request = Request::new(());
        request
            .extensions_mut()
            .insert(crate::enterprise::AuthenticatedContext {
                contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
                principal: crate::enterprise::AuthenticatedPrincipal {
                    subject: "subject-a".into(),
                    credential_id: "credential-a".into(),
                },
                credential_kind: crate::enterprise::CredentialKind::HumanSession,
                tenant: Some(crate::enterprise::TenantContext {
                    tenant_id: "tenant-test".into(),
                    subject: "subject-a".into(),
                }),
                scopes: vec!["sekai.read".into()],
                issuer: "https://issuer.test".into(),
                resource: "https://sekai.test".into(),
                expires_at: 100,
            });
        request
            .metadata_mut()
            .insert("x-principal", MetadataValue::from_static("attacker"));
        request.metadata_mut().insert(
            "x-sekai-tenant-id",
            MetadataValue::from_static("attacker-tenant"),
        );
        let tenant = request_tenant_context(&db, &request).unwrap().unwrap();
        assert_eq!(caller_principals(&request), ["subject-a"]);
        assert_eq!(
            tenant
                .tenant
                .as_ref()
                .map(|context| context.tenant_id.as_str()),
            Some("tenant-test")
        );
        assert!(enforce_namespace_tenant_context(&db, Some(&tenant), "allowed", false).is_ok());
        assert_eq!(
            enforce_namespace_tenant_context(&db, Some(&tenant), "denied", true)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn community_request_is_authorized_by_installed_enterprise_extension() {
        let db = RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(TestEnterpriseExtension)),
            )
            .unwrap(),
        ));
        let mut request = Request::new(());
        request
            .extensions_mut()
            .insert(crate::enterprise::AuthenticatedContext::machine(
                crate::enterprise::AuthenticatedPrincipal {
                    subject: "community-user".into(),
                    credential_id: "community-credential".into(),
                },
            ));

        let context = request_tenant_context(&db, &request).unwrap().unwrap();
        assert!(context.tenant.is_none());
        assert!(enforce_namespace_tenant_context(&db, Some(&context), "community", true).is_ok());
        assert_eq!(
            enforce_namespace_tenant_context(&db, Some(&context), "tenant-private", false)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    fn with_principal<T>(payload: T) -> Request<T> {
        with_named_principal(payload, "tester")
    }

    fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn widget_schema_type() -> ObjectType {
        ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            properties: vec![
                PropertyDef {
                    name: "name".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                },
                PropertyDef {
                    name: "color".into(),
                    r#type: "enum".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec!["red".into(), "blue".into()],
                    link_kind: "".into(),
                    compute_expr: "".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                },
            ],
            is_builtin: false,
            implements: vec![],
        }
    }

    fn widget_object(id: &str, properties: HashMap<String, String>) -> Object {
        Object {
            id: id.into(),
            kind: "widget".into(),
            name: "widget".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties,
            created: 0,
            updated: 0,
        }
    }

    fn grant_schema_admin(svc: &SekaiServiceImpl) {
        let grant = security::Grant {
            id: format!("schema-admin-{}", uuid::Uuid::new_v4().simple()),
            object_id: "schema".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn grant_ontology_admin(svc: &SekaiServiceImpl) {
        let grant = security::Grant {
            id: format!("ontology-admin-{}", uuid::Uuid::new_v4().simple()),
            object_id: "ontology".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn grant_ontology_reader(svc: &SekaiServiceImpl, object_id: &str) {
        let grant = security::Grant {
            id: format!("ontology-reader-{}", uuid::Uuid::new_v4().simple()),
            object_id: object_id.into(),
            principal: "tester".into(),
            role: security::Role::Viewer,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn ontology_class(name: &str) -> OntologyClass {
        OntologyClass {
            name: name.into(),
            description: String::new(),
            superclasses: vec![],
            equivalent_classes: vec![],
            disjoint_classes: vec![],
            properties: vec![],
            is_builtin: false,
            mapped_kind: String::new(),
        }
    }

    fn grant_action_admin(svc: &SekaiServiceImpl) {
        let grant = security::Grant {
            id: format!("action-admin-{}", uuid::Uuid::new_v4().simple()),
            object_id: "action".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn grant_object_role(
        svc: &SekaiServiceImpl,
        object_id: &str,
        principal: &str,
        role: security::Role,
    ) {
        let grant = security::Grant {
            id: format!("grant-{}", uuid::Uuid::new_v4().simple()),
            object_id: object_id.into(),
            principal: principal.into(),
            role,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn seed_domain_object(svc: &SekaiServiceImpl, id: &str) {
        svc.db
            .create_object(&domain::Object {
                id: id.into(),
                kind: "namespace".into(),
                name: id.into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
    }

    fn seed_scoring_namespace(svc: &SekaiServiceImpl, namespace: &str) -> String {
        let id = format!("namespace-{namespace}");
        svc.db
            .create_object(&domain::Object {
                id: id.clone(),
                kind: "namespace".into(),
                name: namespace.into(),
                namespace: String::new(),
                external_id: format!("namespace:{namespace}"),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        id
    }

    fn scored_knowledge_request(namespace: &str, request_id: &str) -> KnowledgeWriteRequest {
        KnowledgeWriteRequest {
            request_id: request_id.into(),
            namespace: namespace.into(),
            task_class: "primary".into(),
            model: "claude-opus-4-8".into(),
            score: 84,
            passed: true,
            reasoning: "The implementation satisfies the requested behavior.".into(),
        }
    }

    #[tokio::test]
    async fn execute_action_denies_ungranted_principal_even_when_actor_claims_owner() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "set_property".into(),
                        params: HashMap::from([
                            ("id".into(), "obj-1".into()),
                            ("key".into(), "status".into()),
                            ("value".into(), "done".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "bob",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn execute_action_allows_granted_principal() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: "bob".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn get_object_denies_marked_artifact_without_clearance() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "artifact-1".into(),
                kind: "artifact".into(),
                name: "secret".into(),
                namespace: "ns".into(),
                external_id: "artifact:1".into(),
                properties: HashMap::from([(
                    markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "confidential".into(),
                )]),
                created: 0,
                updated: 0,
            })
            .unwrap();
        // No grants on object => world-readable ACL, but marking fails closed.
        let err = svc
            .get_object(with_named_principal(
                GetObjectRequest {
                    id: "artifact-1".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn get_object_allows_marked_artifact_with_sufficient_ceiling() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "artifact-2".into(),
                kind: "artifact".into(),
                name: "secret".into(),
                namespace: "ns".into(),
                external_id: "artifact:2".into(),
                properties: HashMap::from([(
                    markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "confidential".into(),
                )]),
                created: 0,
                updated: 0,
            })
            .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "principal-alice".into(),
                kind: markings::PRINCIPAL_PROFILE_KIND.into(),
                name: "alice".into(),
                namespace: "ns".into(),
                external_id: markings::principal_profile_external_id("alice"),
                properties: HashMap::from([
                    (
                        markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        "confidential".into(),
                    ),
                    (
                        markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                        "true".into(),
                    ),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();
        // Credential-admin seal + Admin grant required for trust.
        grant_object_role(&svc, "principal-alice", "root", security::Role::Admin);
        let resp = svc
            .get_object(with_named_principal(
                GetObjectRequest {
                    id: "artifact-2".into(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.object.unwrap().id, "artifact-2");
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("marking.read".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(decisions.iter().any(|d| d.outcome == "allowed"));
    }

    #[tokio::test]
    async fn find_by_external_id_hides_marked_artifact_without_clearance() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "artifact-3".into(),
                kind: "artifact".into(),
                name: "secret".into(),
                namespace: "ns".into(),
                external_id: "artifact:hidden".into(),
                properties: HashMap::from([(
                    markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "restricted".into(),
                )]),
                created: 0,
                updated: 0,
            })
            .unwrap();
        let err = svc
            .find_by_external_id(with_named_principal(
                FindByExternalIdRequest {
                    external_id: "artifact:hidden".into(),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn execute_action_records_decision_with_authenticated_actor() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        let mut request = with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "password".into()),
                        ("value".into(), "secret-value".into()),
                    ]),
                    actor: "mallory".into(),
                }),
                dry_run: false,
            },
            "alice",
        );
        request
            .metadata_mut()
            .insert("x-chisei-work-unit", "successful-work".parse().unwrap());
        svc.execute_action(request).await.unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "alice");
        assert_eq!(decisions[0].target_id, "obj-1");
        assert_eq!(decisions[0].reason, "execute_action");
        assert_eq!(decisions[0].evidence["key"], "[redacted]");
        assert_eq!(decisions[0].evidence["value"], "[redacted]");
        assert_eq!(decisions[0].evidence["work_unit"], "successful-work");
        assert_eq!(decisions[0].evidence["risk_class"], "write");
        assert_eq!(decisions[0].evidence["decision"], "allow");
        assert_eq!(decisions[0].outcome, "set obj-1.password = [redacted]");
    }

    #[tokio::test]
    async fn record_decision_clamps_future_timestamp() {
        let svc = service();
        let future = now_millis() + 86_400_000;
        let recorded = svc
            .record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: String::new(),
                    timestamp: future,
                    actor: "tester".into(),
                    action: "act".into(),
                    reason: String::new(),
                    evidence: HashMap::new(),
                    target_id: String::new(),
                    outcome: "done".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        // A future timestamp would pin the ledger's purgeable prefix forever.
        assert!(recorded.timestamp < future);
        assert!(recorded.timestamp <= now_millis());
    }

    #[tokio::test]
    async fn record_decision_strips_reserved_attestation_evidence_keys() {
        let svc = service();
        let recorded = svc
            .record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: String::new(),
                    timestamp: 0,
                    actor: "tester".into(),
                    action: "act".into(),
                    reason: String::new(),
                    evidence: HashMap::from([
                        ("attestation_id".into(), "forged".into()),
                        ("attestation_hash".into(), "forged".into()),
                        ("note".into(), "kept".into()),
                    ]),
                    target_id: String::new(),
                    outcome: "done".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        assert!(!recorded.evidence.contains_key("attestation_id"));
        assert!(!recorded.evidence.contains_key("attestation_hash"));
        assert_eq!(recorded.evidence["note"], "kept");
        let stored = svc.db.get_decision(&recorded.id).unwrap().unwrap();
        assert!(!stored.evidence.contains_key("attestation_id"));
        assert!(!stored.evidence.contains_key("attestation_hash"));
    }

    #[tokio::test]
    async fn execute_action_set_property_respects_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "red".into()),
                ]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "set_property".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("key".into(), "color".into()),
                            ("value".into(), "green".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not in"));
        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "red");
        assert!(
            svc.db
                .list_decisions(&audit::DecisionFilter {
                    action: Some("set_property".into()),
                    ..Default::default()
                })
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn execute_action_create_object_accepts_schema_properties() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "create_object".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("kind".into(), "widget".into()),
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["name"], "spinner");
        assert_eq!(obj.properties["color"], "blue");
    }

    #[tokio::test]
    async fn struct_property_round_trips_through_create_update_and_list() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "ai_result".into(),
            r#type: "struct".into(),
            required: false,
            description: "AI generated compound value".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![
                StructFieldDef {
                    name: "value".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                },
                StructFieldDef {
                    name: "confidence".into(),
                    r#type: "float".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                },
                StructFieldDef {
                    name: "generated_at".into(),
                    r#type: "timestamp".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                },
            ],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();

        let initial_value =
            r#"{"value":"approve","confidence":0.91,"source_objects":["widget:1"]}"#;
        let created = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("ai_result".into(), initial_value.into()),
                    ]),
                )),
                lease_precondition: None,
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(created.properties["ai_result"], initial_value);

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "widget".into(),
                    limit: 10,
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects[0].properties["ai_result"], initial_value);

        let updated_value =
            r#"{"value":"reject","confidence":0.12,"generated_at":"2026-07-06T12:00:00Z"}"#;
        let mut updated = created;
        updated
            .properties
            .insert("ai_result".into(), updated_value.into());
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(updated),
            lease_precondition: None,
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-ai").unwrap().unwrap();
        assert_eq!(stored.properties["ai_result"], updated_value);

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai-invalid",
                    HashMap::from([
                        ("name".into(), "bad".into()),
                        ("color".into(), "blue".into()),
                        ("ai_result".into(), r#"{"value":"approve"}"#.into()),
                    ]),
                )),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("confidence"));

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai-type-mismatch",
                    HashMap::from([
                        ("name".into(), "bad".into()),
                        ("color".into(), "blue".into()),
                        (
                            "ai_result".into(),
                            r#"{"value":"approve","confidence":"high"}"#.into(),
                        ),
                    ]),
                )),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("expected float"));
    }

    #[tokio::test]
    async fn action_audit_prefers_schema_classification_over_name_heuristic() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "api_key_label".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        schema_type.properties.push(PropertyDef {
            name: "secret_note".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "sensitive".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "widget-audit".into(),
                kind: "widget".into(),
                name: "widget".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "blue".into()),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "widget-audit".into()),
                    ("key".into(), "api_key_label".into()),
                    ("value".into(), "public alias".into()),
                ]),
                actor: "".into(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "widget-audit".into()),
                    ("key".into(), "secret_note".into()),
                    ("value".into(), "launch code".into()),
                ]),
                actor: "".into(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        let public_decision = decisions
            .iter()
            .find(|decision| decision.outcome.contains("api_key_label"))
            .unwrap();
        let sensitive_decision = decisions
            .iter()
            .find(|decision| decision.outcome.contains("secret_note"))
            .unwrap();
        assert_eq!(public_decision.evidence["value"], "public alias");
        assert_eq!(
            public_decision.outcome,
            "set widget-audit.api_key_label = public alias"
        );
        assert_eq!(sensitive_decision.evidence["value"], "[redacted]");
        assert_eq!(
            sensitive_decision.outcome,
            "set widget-audit.secret_note = [redacted]"
        );
    }

    #[tokio::test]
    async fn execute_action_allows_local_principal_on_unrestricted_object() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "local".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "local",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "local");
    }

    #[tokio::test]
    async fn execute_action_create_link_requires_write_on_both_endpoints() {
        let svc = service();
        seed_domain_object(&svc, "from-1");
        seed_domain_object(&svc, "to-1");
        grant_object_role(&svc, "from-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "to-1", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "create_link".into(),
                        params: HashMap::from([
                            ("from_id".into(), "from-1".into()),
                            ("to_id".into(), "to-1".into()),
                            ("relation".into(), "depends_on".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("from-1->to-1").unwrap().is_none());
    }

    #[tokio::test]
    async fn execute_action_delete_link_requires_write_on_both_endpoints() {
        let svc = service();
        seed_domain_object(&svc, "from-1");
        seed_domain_object(&svc, "to-1");
        svc.db
            .create_link(&domain::Link {
                id: "link-1".into(),
                from_id: "from-1".into(),
                to_id: "to-1".into(),
                relation: "depends_on".into(),
                created: 0,
            })
            .unwrap();
        grant_object_role(&svc, "from-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "to-1", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "delete_link".into(),
                        params: HashMap::from([("id".into(), "link-1".into())]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "write denied");
        assert!(svc.db.get_link("link-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn execute_action_delete_link_hides_unknown_link() {
        let svc = service();

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "delete_link".into(),
                        params: HashMap::from([("id".into(), "missing-link".into())]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "write denied");
    }

    #[tokio::test]
    async fn dataset_rpc_round_trip() {
        let svc = service();
        let created = svc
            .create_dataset(with_principal(CreateDatasetRequest {
                dataset: Some(Dataset {
                    id: "ds1".into(),
                    name: "metrics".into(),
                    columns: vec![ColumnDef {
                        name: "value".into(),
                        r#type: "int".into(),
                        classification: "public".into(),
                    }],
                    object_id: "".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.dataset.unwrap().id, "ds1");

        let rows = vec![
            Row {
                values: HashMap::from([("value".into(), "1".into())]),
            },
            Row {
                values: HashMap::from([("value".into(), "2".into())]),
            },
        ];
        let append = svc
            .append_rows(with_principal(AppendRowsRequest {
                dataset_id: "ds1".into(),
                rows,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(append.count, 2);

        let queried = svc
            .query_rows(with_principal(QueryRowsRequest {
                dataset_id: "ds1".into(),
                query: Some(RowQuery {
                    filters: vec![RowFilter {
                        column: "value".into(),
                        op: "gte".into(),
                        value: "2".into(),
                    }],
                    columns: vec![],
                    limit: 0,
                    offset: 0,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(queried.rows.len(), 1);
    }

    #[tokio::test]
    async fn update_dataset_requires_write_access_to_existing_binding() {
        let svc = service();
        svc.create_dataset(with_principal(CreateDatasetRequest {
            dataset: Some(Dataset {
                id: "protected-dataset".into(),
                name: "original".into(),
                columns: vec![ColumnDef {
                    name: "value".into(),
                    r#type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: "protected-object".into(),
                created: 1,
            }),
        }))
        .await
        .unwrap();
        let grant = security::Grant {
            id: "dataset-owner".into(),
            object_id: "protected-object".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);

        let error = svc
            .update_dataset(with_named_principal(
                UpdateDatasetRequest {
                    dataset: Some(Dataset {
                        id: "protected-dataset".into(),
                        name: "hijacked".into(),
                        columns: vec![],
                        object_id: String::new(),
                        created: 999,
                    }),
                },
                "intruder",
            ))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        let stored = svc.db.get_dataset("protected-dataset").unwrap().unwrap();
        assert_eq!(stored.name, "original");
        assert_eq!(stored.object_id, "protected-object");
    }

    #[tokio::test]
    async fn update_unbound_dataset_requires_gateway_service_principal() {
        let mut svc = service();
        svc.gateway_schema_principals = vec!["gateway-prod".into()];
        svc.create_dataset(with_principal(CreateDatasetRequest {
            dataset: Some(Dataset {
                id: "llm_calls".into(),
                name: "original".into(),
                columns: vec![],
                object_id: String::new(),
                created: 1,
            }),
        }))
        .await
        .unwrap();
        let update = UpdateDatasetRequest {
            dataset: Some(Dataset {
                id: "llm_calls".into(),
                name: "updated".into(),
                columns: vec![ColumnDef {
                    name: "receipt_id".into(),
                    r#type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: String::new(),
                created: 999,
            }),
        };

        let error = svc
            .update_dataset(with_principal(update.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let updated = svc
            .update_dataset(with_named_principal(update, "gateway-prod"))
            .await
            .unwrap()
            .into_inner()
            .dataset
            .unwrap();
        assert_eq!(updated.name, "updated");
        assert_eq!(updated.columns[0].name, "receipt_id");
        assert_eq!(updated.created, 1);

        svc.create_dataset(with_principal(CreateDatasetRequest {
            dataset: Some(Dataset {
                id: "other-system-dataset".into(),
                name: "original".into(),
                columns: vec![],
                object_id: String::new(),
                created: 2,
            }),
        }))
        .await
        .unwrap();
        let error = svc
            .update_dataset(with_named_principal(
                UpdateDatasetRequest {
                    dataset: Some(Dataset {
                        id: "other-system-dataset".into(),
                        name: "hijacked".into(),
                        columns: vec![],
                        object_id: String::new(),
                        created: 2,
                    }),
                },
                "gateway-prod",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn computed_property_resolves_from_function_without_persisting() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "count_children".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![
                    PipelineStep {
                        op: "self".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "traverse".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "contains".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "child_count".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "cluster".into(),
                description: "Cluster".into(),
                properties: vec![PropertyDef {
                    name: "child_count".into(),
                    r#type: "computed".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "count_children".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                }],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "cluster-1".into(),
                kind: "cluster".into(),
                name: "cluster".into(),
                namespace: "".into(),
                external_id: "cluster:one".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "component-1".into(),
                kind: "component".into(),
                name: "component".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();
        svc.create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "cluster-component".into(),
                from_id: "cluster-1".into(),
                to_id: "component-1".into(),
                relation: "contains".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        let duplicate = svc
            .create_link(with_principal(CreateLinkRequest {
                fail_if_exists: true,
                link: Some(Link {
                    id: "cluster-component".into(),
                    from_id: "cluster-1".into(),
                    to_id: "component-1".into(),
                    relation: "contains".into(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(duplicate.code(), tonic::Code::AlreadyExists);

        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "cluster-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(got.properties["child_count"], "1");

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "cluster".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects[0].properties["child_count"], "1");

        let stored = svc.db.get_object("cluster-1").unwrap().unwrap();
        assert!(!stored.properties.contains_key("child_count"));
    }

    #[tokio::test]
    async fn computed_properties_respect_team_namespace_boundaries() {
        let svc = service();
        svc.ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "acme".into(),
                principal: "alice".into(),
                role: "viewer".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.create_function(with_named_principal(
            CreateFunctionRequest {
                function: Some(Function {
                    name: "count_team_children".into(),
                    pipeline: vec![
                        PipelineStep {
                            op: "self".into(),
                            ..Default::default()
                        },
                        PipelineStep {
                            op: "traverse".into(),
                            relation: "contains".into(),
                            ..Default::default()
                        },
                        PipelineStep {
                            op: "aggregate".into(),
                            func: "count".into(),
                            r#as: "child_count".into(),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(ObjectType {
                    kind: "team-cluster".into(),
                    properties: vec![PropertyDef {
                        name: "child_count".into(),
                        r#type: "computed".into(),
                        compute_expr: "count_team_children".into(),
                        classification: "public".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        for (id, kind, namespace) in [
            ("team-cluster", "team-cluster", "acme"),
            ("acme-child", "component", "acme"),
            ("beta-child", "component", "beta"),
        ] {
            svc.create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(Object {
                        id: id.into(),
                        kind: kind.into(),
                        name: id.into(),
                        namespace: namespace.into(),
                        ..Default::default()
                    }),
                    lease_precondition: None,
                },
                "local",
            ))
            .await
            .unwrap();
        }
        for child in ["acme-child", "beta-child"] {
            svc.create_link(with_named_principal(
                CreateLinkRequest {
                    fail_if_exists: false,
                    link: Some(Link {
                        id: format!("team-cluster->{child}"),
                        from_id: "team-cluster".into(),
                        to_id: child.into(),
                        relation: "contains".into(),
                        ..Default::default()
                    }),
                },
                "local",
            ))
            .await
            .unwrap();
        }

        let cluster = svc
            .get_object(with_named_principal(
                GetObjectRequest {
                    id: "team-cluster".into(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(cluster.properties["child_count"], "1");
    }

    #[tokio::test]
    async fn schema_type_rejects_unknown_computed_function() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(ObjectType {
                    kind: "cluster".into(),
                    description: "Cluster".into(),
                    properties: vec![PropertyDef {
                        name: "child_count".into(),
                        r#type: "computed".into(),
                        required: false,
                        description: "".into(),
                        enum_values: vec![],
                        link_kind: "".into(),
                        compute_expr: "missing_function".into(),
                        classification: "public".into(),
                        struct_fields: vec![],
                    }],
                    is_builtin: false,
                    implements: vec![],
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("missing_function"));
    }

    #[tokio::test]
    async fn unresolved_computed_property_hides_stored_value() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "ambiguous_child_count".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![
                    PipelineStep {
                        op: "self".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "first".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "second".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "cluster".into(),
                description: "Cluster".into(),
                properties: vec![PropertyDef {
                    name: "child_count".into(),
                    r#type: "computed".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "ambiguous_child_count".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                }],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "cluster-spoofed".into(),
                kind: "cluster".into(),
                name: "cluster".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([("child_count".into(), "spoofed".into())]),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();

        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "cluster-spoofed".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert!(!got.properties.contains_key("child_count"));

        let stored = svc.db.get_object("cluster-spoofed").unwrap().unwrap();
        assert_eq!(stored.properties["child_count"], "spoofed");
    }

    #[tokio::test]
    async fn object_mutations_record_audit_changes() {
        let svc = service();
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    id: "audit-1".into(),
                    kind: "component".into(),
                    name: "api".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::from([("status".into(), "todo".into())]),
                    created: 1,
                    updated: 1,
                }),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();

        svc.update_object(with_named_principal(
            UpdateObjectRequest {
                object: Some(Object {
                    id: "audit-1".into(),
                    kind: "component".into(),
                    name: "worker".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::from([("status".into(), "done".into())]),
                    created: 1,
                    updated: 2,
                }),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();

        svc.delete_object(with_named_principal(
            DeleteObjectRequest {
                id: "audit-1".into(),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_named_principal(
                ListObjectChangesRequest {
                    object_id: "audit-1".into(),
                    limit: 10,
                    offset: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert_eq!(changes.len(), 4);
        assert_eq!(
            changes
                .iter()
                .map(|change| change.field.as_str())
                .collect::<Vec<_>>(),
            vec!["_deleted", "properties.status", "name", "_created"]
        );
        assert!(changes.iter().all(|change| change.changed_by == "alice"));
        assert_eq!(changes[0].old_value, "component/worker");
        assert_eq!(changes[1].old_value, "todo");
        assert_eq!(changes[1].new_value, "done");
        assert_eq!(changes[2].old_value, "api");
        assert_eq!(changes[2].new_value, "worker");
    }

    #[tokio::test]
    async fn unified_direct_admission_preserves_reserved_ids_and_missing_updates() {
        let svc = service();
        let reserved = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "reserved-principal-id".into(),
                    kind: "component".into(),
                    name: "ordinary".into(),
                    namespace: "default".into(),
                    external_id: "principal:alice".into(),
                    properties: HashMap::from([(
                        markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                        "malformed".into(),
                    )]),
                    created: 1,
                    updated: 1,
                }),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(reserved.code(), tonic::Code::InvalidArgument);

        let missing = svc
            .update_object(with_principal(UpdateObjectRequest {
                object: Some(Object {
                    id: "missing".into(),
                    kind: "unloaded_kind".into(),
                    name: "missing".into(),
                    namespace: "default".into(),
                    external_id: "component:missing".into(),
                    properties: HashMap::from([(
                        markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                        "malformed".into(),
                    )]),
                    created: 1,
                    updated: 1,
                }),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn noop_update_does_not_record_audit_change() {
        let svc = service();
        let object = Object {
            id: "audit-noop".into(),
            kind: "component".into(),
            name: "api".into(),
            namespace: "default".into(),
            external_id: "component:api".into(),
            properties: HashMap::from([("status".into(), "todo".into())]),
            created: 1,
            updated: 1,
        };
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(object.clone()),
            lease_precondition: None,
        }))
        .await
        .unwrap();

        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(object),
            lease_precondition: None,
        }))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "audit-noop".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "_created");
    }

    #[tokio::test]
    async fn audit_insert_failure_rolls_back_create() {
        let svc = service();
        svc.db
            .conn()
            .execute("DROP TABLE sekai_object_changes", [])
            .unwrap();

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "audit-fail-closed".into(),
                    kind: "component".into(),
                    name: "api".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                }),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(svc.db.get_object("audit-fail-closed").unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_fails_closed_when_delete_audit_insert_fails() {
        let svc = service();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "delete-audit-fail".into(),
                kind: "component".into(),
                name: "api".into(),
                namespace: "default".into(),
                external_id: "component:api".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();
        svc.db
            .conn()
            .execute("DROP TABLE sekai_object_changes", [])
            .unwrap();

        let err = svc
            .delete_object(with_principal(DeleteObjectRequest {
                id: "delete-audit-fail".into(),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(svc.db.get_object("delete-audit-fail").unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_object_remains_idempotent_when_missing() {
        let svc = service();

        svc.delete_object(with_principal(DeleteObjectRequest {
            id: "missing-object".into(),
            lease_precondition: None,
        }))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "missing-object".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert!(changes.is_empty());
    }

    #[tokio::test]
    async fn schema_type_enforces_create_and_update() {
        let svc = service();
        grant_schema_admin(&svc);
        let created = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.r#type.unwrap().kind, "widget");

        let missing_required = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object("w1", HashMap::new())),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(missing_required.code(), tonic::Code::InvalidArgument);
        assert!(missing_required.message().contains("name"));

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "w1",
                HashMap::from([
                    ("name".into(), "first".into()),
                    ("color".into(), "red".into()),
                ]),
            )),
            lease_precondition: None,
        }))
        .await
        .unwrap();

        let invalid_update = svc
            .update_object(with_principal(UpdateObjectRequest {
                object: Some(widget_object(
                    "w1",
                    HashMap::from([
                        ("name".into(), "first".into()),
                        ("color".into(), "green".into()),
                    ]),
                )),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(invalid_update.code(), tonic::Code::InvalidArgument);
        assert!(invalid_update.message().contains("color"));
    }

    #[tokio::test]
    async fn untyped_kind_still_writes_and_schema_types_list() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-1".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();

        let listed = svc
            .list_schema_types(with_principal(ListSchemaTypesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(
            listed
                .types
                .iter()
                .any(|object_type| object_type.kind == "widget" && !object_type.is_builtin)
        );
        assert!(
            listed
                .types
                .iter()
                .any(|object_type| object_type.kind == "namespace" && object_type.is_builtin)
        );
    }

    #[tokio::test]
    async fn object_bound_lease_requires_target_object_authorization() {
        let svc = service();
        let target = Object {
            id: "coord-target".into(),
            kind: "component".into(),
            name: "target".into(),
            namespace: "default".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        svc.db
            .create_object_with_audit(&from_proto_obj(&target), "alice")
            .unwrap();
        grant_object_role(&svc, "coord-target", "alice", security::Role::Editor);

        let key = "object:coord-target".to_string();
        // Principal without object write cannot squat the coordination identity.
        let denied = svc
            .acquire_lease(with_named_principal(
                AcquireLeaseRequest {
                    namespace: "default".into(),
                    key: key.clone(),
                    owner: "bob".into(),
                    ttl_ms: 60_000,
                    request_id: "bob-acq".into(),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let lease = svc
            .acquire_lease(with_named_principal(
                AcquireLeaseRequest {
                    namespace: "default".into(),
                    key: key.clone(),
                    owner: "alice".into(),
                    ttl_ms: 60_000,
                    request_id: "alice-acq".into(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        assert_eq!(lease.key, key);
        assert!(!lease.fencing_token.is_empty());

        // Inspect also requires object read access.
        let inspect_denied = svc
            .get_lease(with_named_principal(
                GetLeaseRequest {
                    namespace: "default".into(),
                    key: key.clone(),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(inspect_denied.code(), tonic::Code::PermissionDenied);

        let got = svc
            .get_lease(with_named_principal(
                GetLeaseRequest {
                    namespace: "default".into(),
                    key: key.clone(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        assert_eq!(got.fencing_token, lease.fencing_token);

        // Wrong namespace fails closed even with object write rights.
        let wrong_ns = svc
            .acquire_lease(with_named_principal(
                AcquireLeaseRequest {
                    namespace: "other".into(),
                    key: key.clone(),
                    owner: "alice".into(),
                    ttl_ms: 60_000,
                    request_id: "wrong-ns".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(wrong_ns.code(), tonic::Code::PermissionDenied);

        // Missing object cannot be used as a coordination target.
        let missing = svc
            .acquire_lease(with_named_principal(
                AcquireLeaseRequest {
                    namespace: "default".into(),
                    key: "object:does-not-exist".into(),
                    owner: "alice".into(),
                    ttl_ms: 60_000,
                    request_id: "missing".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);

        // Stale token release fails closed; holder with object write can release.
        let stale = svc
            .release_lease(with_named_principal(
                ReleaseLeaseRequest {
                    namespace: "default".into(),
                    key: key.clone(),
                    fencing_token: "not-the-token".into(),
                    request_id: "stale".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::FailedPrecondition);

        svc.release_lease(with_named_principal(
            ReleaseLeaseRequest {
                namespace: "default".into(),
                key: key.clone(),
                fencing_token: lease.fencing_token,
                request_id: "release".into(),
            },
            "alice",
        ))
        .await
        .unwrap();

        // After release, a second authorized acquire succeeds (new generation).
        let again = svc
            .acquire_lease(with_named_principal(
                AcquireLeaseRequest {
                    namespace: "default".into(),
                    key: key.clone(),
                    owner: "alice".into(),
                    ttl_ms: 60_000,
                    request_id: "reacquire".into(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        assert!(again.generation >= 1);

        // Non-canonical object keys are rejected (no whitespace aliases).
        let non_canonical = svc
            .acquire_lease(with_named_principal(
                AcquireLeaseRequest {
                    namespace: "default".into(),
                    key: "object: coord-target".into(),
                    owner: "alice".into(),
                    ttl_ms: 60_000,
                    request_id: "non-canonical".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(non_canonical.code(), tonic::Code::InvalidArgument);

        // Object-bound lease cannot guard a different object mutation.
        let other = Object {
            id: "other-target".into(),
            kind: "component".into(),
            name: "other".into(),
            namespace: "default".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        svc.db
            .create_object_with_audit(&from_proto_obj(&other), "alice")
            .unwrap();
        grant_object_role(&svc, "other-target", "alice", security::Role::Editor);
        let mismatch = svc
            .guarded_update_object(with_named_principal(
                GuardedUpdateObjectRequest {
                    object: Some(other),
                    lease_precondition: Some(LeasePrecondition {
                        namespace: "default".into(),
                        key,
                        fencing_token: again.fencing_token,
                        request_id: "mismatch".into(),
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(mismatch.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn guarded_update_requires_object_and_lease_namespace_authorization() {
        let svc = service();
        let lease = svc
            .acquire_lease(with_named_principal(
                AcquireLeaseRequest {
                    namespace: "default".into(),
                    key: "environment".into(),
                    owner: "alice".into(),
                    ttl_ms: 60_000,
                    request_id: "acquire".into(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        let original = Object {
            id: "guarded-auth".into(),
            kind: "component".into(),
            name: "before".into(),
            namespace: "default".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        svc.db
            .create_object_with_audit(&from_proto_obj(&original), "alice")
            .unwrap();
        grant_object_role(&svc, "guarded-auth", "alice", security::Role::Editor);

        let mut updated = original.clone();
        updated.name = "after".into();
        updated.updated = 2;
        let precondition = LeasePrecondition {
            namespace: "default".into(),
            key: "environment".into(),
            fencing_token: lease.fencing_token,
            request_id: "update".into(),
        };
        svc.guarded_update_object(with_named_principal(
            GuardedUpdateObjectRequest {
                object: Some(updated.clone()),
                lease_precondition: Some(precondition.clone()),
            },
            "alice",
        ))
        .await
        .unwrap();

        updated.name = "unauthorized".into();
        let error = svc
            .guarded_update_object(with_named_principal(
                GuardedUpdateObjectRequest {
                    object: Some(updated),
                    lease_precondition: Some(LeasePrecondition {
                        request_id: "denied".into(),
                        ..precondition
                    }),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            svc.db.get_object("guarded-auth").unwrap().unwrap().name,
            "after"
        );
    }

    #[tokio::test]
    async fn update_object_with_lease_precondition_enforces_fencing() {
        // #388: Create/Update/DeleteObject with lease_precondition share Guarded* semantics.
        let svc = service();
        let lease = svc
            .acquire_lease(with_named_principal(
                AcquireLeaseRequest {
                    namespace: "default".into(),
                    key: "environment".into(),
                    owner: "alice".into(),
                    ttl_ms: 60_000,
                    request_id: "acquire-unified".into(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        let original = Object {
            id: "unified-guarded".into(),
            kind: "component".into(),
            name: "before".into(),
            namespace: "default".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        svc.db
            .create_object_with_audit(&from_proto_obj(&original), "alice")
            .unwrap();
        grant_object_role(&svc, "unified-guarded", "alice", security::Role::Editor);

        let mut updated = original.clone();
        updated.name = "fenced".into();
        updated.updated = 2;
        svc.update_object(with_named_principal(
            UpdateObjectRequest {
                object: Some(updated.clone()),
                lease_precondition: Some(LeasePrecondition {
                    namespace: "default".into(),
                    key: "environment".into(),
                    fencing_token: lease.fencing_token.clone(),
                    request_id: "update-unified".into(),
                }),
            },
            "alice",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.db.get_object("unified-guarded").unwrap().unwrap().name,
            "fenced"
        );

        updated.name = "stale".into();
        updated.updated = 3;
        let stale = svc
            .update_object(with_named_principal(
                UpdateObjectRequest {
                    object: Some(updated),
                    lease_precondition: Some(LeasePrecondition {
                        namespace: "default".into(),
                        key: "environment".into(),
                        fencing_token: "not-the-token".into(),
                        request_id: "update-stale".into(),
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            svc.db.get_object("unified-guarded").unwrap().unwrap().name,
            "fenced"
        );
    }

    #[tokio::test]
    async fn update_object_without_lease_precondition_remains_unguarded() {
        let svc = service();
        let original = Object {
            id: "unified-unguarded".into(),
            kind: "component".into(),
            name: "before".into(),
            namespace: "default".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        svc.db
            .create_object_with_audit(&from_proto_obj(&original), "alice")
            .unwrap();
        grant_object_role(&svc, "unified-unguarded", "alice", security::Role::Editor);

        let mut updated = original;
        updated.name = "after".into();
        updated.updated = 2;
        svc.update_object(with_named_principal(
            UpdateObjectRequest {
                object: Some(updated),
                lease_precondition: None,
            },
            "alice",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.db
                .get_object("unified-unguarded")
                .unwrap()
                .unwrap()
                .name,
            "after"
        );
    }

    #[tokio::test]
    async fn governed_action_type_registry_put_get_list_disable() {
        // #396: namespace-scoped governed Action type registry (not graph ActionType).
        let svc = service();
        grant_action_admin(&svc);
        let type_def = GovernedActionType {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            description: "Admit review".into(),
            parameter_schema_json:
                r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#
                    .into(),
            allowed_effect_kinds: vec!["runtime_dispatch".into(), "notify".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        };
        let put = svc
            .put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
                r#type: Some(type_def.clone()),
                request_id: "put-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .r#type
            .unwrap();
        assert!(put.enabled);
        assert_eq!(put.created_by, "tester");

        let mut invalid_schema = type_def.clone();
        invalid_schema.version = "2.0.0".into();
        invalid_schema.parameter_schema_json = r#"{"type":"object"}"#.into();
        let invalid_schema_error = svc
            .put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
                r#type: Some(invalid_schema),
                request_id: "put-invalid-schema".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(invalid_schema_error.code(), tonic::Code::InvalidArgument);

        let got = svc
            .get_governed_action_type(with_principal(GetGovernedActionTypeRequest {
                namespace: "acme".into(),
                type_id: "review.intake".into(),
                version: "1.0.0".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .r#type
            .unwrap();
        assert_eq!(got.type_id, "review.intake");

        let listed = svc
            .list_governed_action_types(with_principal(ListGovernedActionTypesRequest {
                namespace: "acme".into(),
                type_id: String::new(),
                enabled_only: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .types;
        assert_eq!(listed.len(), 1);

        // Version immutability
        let mut changed = type_def.clone();
        changed.description = "nope".into();
        let err = svc
            .put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
                r#type: Some(changed),
                request_id: "put-bad".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        svc.set_governed_action_type_enabled(with_principal(SetGovernedActionTypeEnabledRequest {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            enabled: false,
            request_id: "disable-1".into(),
        }))
        .await
        .unwrap();
        let deny = svc
            .db
            .require_enabled_governed_action_type("acme", "review.intake", "1.0.0")
            .unwrap_err();
        assert!(deny.contains("disabled"), "{deny}");

        // Unauthorized principal
        let denied = svc
            .put_governed_action_type(with_named_principal(
                PutGovernedActionTypeRequest {
                    r#type: Some(type_def),
                    request_id: "put-denied".into(),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn submit_action_instance_admit_replay_conflict_policy_budget() {
        // #397: submit/admit ActionInstance with idempotency, policy, budget.
        use crate::chisei::budget::{BudgetTracker, PeriodType};
        use crate::sekai::action_instance::{STATUS_ADMITTED, STATUS_DENIED, SUBMIT_POLICY_ACTION};

        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let budget = Arc::new(BudgetTracker::new(db.clone()));
        budget
            .set_limit("action:governed", 1, PeriodType::Daily)
            .unwrap();
        let svc = SekaiServiceImpl::with_budget(db, budget.clone());
        grant_action_admin(&svc);

        let type_def = GovernedActionType {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            description: "Admit review".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["runtime_dispatch".into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        };
        svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
            r#type: Some(type_def),
            request_id: "put-1".into(),
        }))
        .await
        .unwrap();

        let params = r#"{"summary":"ship it"}"#.to_string();
        let admit = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "review.intake".into(),
                version: "1.0.0".into(),
                parameters_json: params.clone(),
                idempotency_key: "idem-1".into(),
                evidence_submission_ids: vec!["ev-1".into()],
                request_id: "req-1".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!admit.replay);
        let inst = admit.instance.unwrap();
        assert_eq!(inst.status, STATUS_ADMITTED);
        assert!(!inst.instance_id.is_empty());
        assert!(!inst.operation_id.is_empty());
        assert!(!inst.request_digest.is_empty());
        assert_eq!(inst.evidence_submission_ids, vec!["ev-1".to_string()]);

        // Receipt spine bound to operation_id.
        let receipt = svc
            .db
            .get_operation_receipt(&inst.operation_id)
            .unwrap()
            .expect("operation receipt");
        assert_eq!(receipt.operation_class, "governed_action_instance");
        assert_eq!(receipt.namespace, "acme");

        // Idempotent replay
        let replay = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "review.intake".into(),
                version: "1.0.0".into(),
                parameters_json: params.clone(),
                idempotency_key: "idem-1".into(),
                evidence_submission_ids: vec!["ev-1".into()],
                request_id: "req-2".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(replay.replay);
        assert_eq!(replay.instance.unwrap().instance_id, inst.instance_id);

        // Key conflict on different digest
        let conflict = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "review.intake".into(),
                version: "1.0.0".into(),
                parameters_json: r#"{"summary":"other"}"#.into(),
                idempotency_key: "idem-1".into(),
                evidence_submission_ids: vec![],
                request_id: "req-3".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(conflict.code(), tonic::Code::AlreadyExists);

        // Get + list
        let got = svc
            .get_action_instance(with_principal(GetActionInstanceRequest {
                instance_id: inst.instance_id.clone(),
                namespace: String::new(),
                idempotency_key: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .instance
            .unwrap();
        assert_eq!(got.instance_id, inst.instance_id);

        let listed = svc
            .list_action_instances(with_principal(ListActionInstancesRequest {
                namespace: "acme".into(),
                type_id: "review.intake".into(),
                status: STATUS_ADMITTED.into(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner()
            .instances;
        assert_eq!(listed.len(), 1);

        // Budget deny (limit was 1; second distinct admit exhausts)
        let budget_denied = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "review.intake".into(),
                version: "1.0.0".into(),
                parameters_json: r#"{"summary":"second"}"#.into(),
                idempotency_key: "idem-budget".into(),
                evidence_submission_ids: vec![],
                request_id: "req-budget".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .instance
            .unwrap();
        assert_eq!(budget_denied.status, STATUS_DENIED);
        assert_eq!(budget_denied.budget_decision, "budget_exceeded");
        assert!(budget_denied.deny_reason.contains("budget"));

        // Policy deny
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::from([(
                    SUBMIT_POLICY_ACTION.into(),
                    action_policy::ActionDecision::Deny,
                )]),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let policy_denied = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "review.intake".into(),
                version: "1.0.0".into(),
                parameters_json: r#"{"summary":"policy"}"#.into(),
                idempotency_key: "idem-policy".into(),
                evidence_submission_ids: vec![],
                request_id: "req-policy".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .instance
            .unwrap();
        assert_eq!(policy_denied.status, STATUS_DENIED);
        assert_eq!(policy_denied.policy_decision, "deny");
        assert!(policy_denied.deny_reason.contains("policy"));
    }

    #[tokio::test]
    async fn submit_rejects_parameters_outside_governed_action_schema() {
        use crate::sekai::action_instance::STATUS_ADMITTED;

        let svc = service();
        grant_action_admin(&svc);
        svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
            r#type: Some(GovernedActionType {
                namespace: "acme".into(),
                type_id: "validated.action".into(),
                version: "1.0.0".into(),
                description: "validate action parameters".into(),
                parameter_schema_json: r#"{
                    "type":"object",
                    "properties":{
                        "mode":{"type":"string","enum":["safe","fast"]},
                        "label":{"type":"string","minLength":2,"maxLength":4},
                        "count":{"type":"integer","minimum":1,"maximum":3},
                        "ratio":{"type":"number","minimum":0.5,"maximum":1.5},
                        "enabled":{"type":"boolean"}
                    },
                    "required":["mode","label","count","ratio","enabled"],
                    "additionalProperties":false
                }"#
                .into(),
                allowed_effect_kinds: vec!["notify".into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
            }),
            request_id: "put-validated-action".into(),
        }))
        .await
        .unwrap();

        let invalid = [
            (
                "missing-required",
                r#"{"mode":"safe","label":"ok","count":1,"ratio":1.0}"#,
                "required",
            ),
            (
                "unknown-field",
                r#"{"mode":"safe","label":"ok","count":1,"ratio":1.0,"enabled":true,"extra":true}"#,
                "unknown",
            ),
            (
                "wrong-type",
                r#"{"mode":"safe","label":"ok","count":"1","ratio":1.0,"enabled":true}"#,
                "does not match type",
            ),
            (
                "invalid-enum",
                r#"{"mode":"slow","label":"ok","count":1,"ratio":1.0,"enabled":true}"#,
                "enum",
            ),
            (
                "out-of-range",
                r#"{"mode":"safe","label":"ok","count":4,"ratio":1.0,"enabled":true}"#,
                "outside",
            ),
            (
                "string-length",
                r#"{"mode":"safe","label":"s","count":1,"ratio":1.0,"enabled":true}"#,
                "length",
            ),
        ];
        for (key, parameters_json, expected_error) in invalid {
            let error = svc
                .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                    namespace: "acme".into(),
                    type_id: "validated.action".into(),
                    version: "1.0.0".into(),
                    parameters_json: parameters_json.into(),
                    idempotency_key: key.into(),
                    evidence_submission_ids: vec![],
                    request_id: format!("request-{key}"),
                }))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{key}");
            assert!(error.message().contains("action parameters invalid"));
            assert!(error.message().contains(expected_error), "{key}: {error}");
            assert!(
                svc.db
                    .get_action_instance_by_idempotency("acme", key)
                    .unwrap()
                    .is_none(),
                "{key} must not persist an ActionInstance"
            );
        }

        let duplicate_error = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "validated.action".into(),
                version: "1.0.0".into(),
                parameters_json: r#"{"mode":"safe","mode":"fast","label":"ok","count":1,"ratio":1.0,"enabled":true}"#.into(),
                idempotency_key: "duplicate-key".into(),
                evidence_submission_ids: vec![],
                request_id: "request-duplicate-key".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(duplicate_error.code(), tonic::Code::InvalidArgument);
        assert!(duplicate_error.message().contains("duplicate object keys"));
        assert!(
            svc.db
                .get_action_instance_by_idempotency("acme", "duplicate-key")
                .unwrap()
                .is_none()
        );

        let valid = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "validated.action".into(),
                version: "1.0.0".into(),
                parameters_json:
                    r#"{"mode":"safe","label":"ok","count":1,"ratio":1.0,"enabled":true}"#.into(),
                idempotency_key: "valid".into(),
                evidence_submission_ids: vec![],
                request_id: "request-valid".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .instance
            .unwrap();
        assert_eq!(valid.status, STATUS_ADMITTED);
        assert_eq!(
            svc.db
                .list_action_effects_for_instance(&valid.instance_id)
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn submit_rejects_invalid_materialized_effect_before_admit() {
        use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;

        let svc = service();
        grant_action_admin(&svc);
        svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
            r#type: Some(GovernedActionType {
                namespace: "acme".into(),
                type_id: "dispatch.nul".into(),
                version: "1.0.0".into(),
                description: "reject malformed effect".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
            }),
            request_id: "put-nul".into(),
        }))
        .await
        .unwrap();

        let error = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "dispatch.nul".into(),
                version: "1.0.0".into(),
                parameters_json: r#"{"runtime":"\u0000"}"#.into(),
                idempotency_key: "nul-admission".into(),
                evidence_submission_ids: vec![],
                request_id: "req-nul".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            svc.db
                .get_action_instance_by_idempotency("acme", "nul-admission")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn runtime_claim_api_exclusivity_and_ack() {
        // #399: claim exclusivity, fence, reclaim, ack.
        use crate::sekai::action_effect::{
            EFFECT_STATUS_CLAIMED, EFFECT_STATUS_COMPLETED, EFFECT_STATUS_PENDING,
        };
        use crate::sekai::action_instance::STATUS_ADMITTED;
        use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;

        let svc = service();
        grant_action_admin(&svc);
        svc.put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
            r#type: Some(GovernedActionType {
                namespace: "acme".into(),
                type_id: "dispatch.only".into(),
                version: "1.0.0".into(),
                description: "claim".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
            }),
            request_id: "put-claim".into(),
        }))
        .await
        .unwrap();
        let admit = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "dispatch.only".into(),
                version: "1.0.0".into(),
                parameters_json: r#"{"runtime":"shikigami"}"#.into(),
                idempotency_key: "claim-1".into(),
                evidence_submission_ids: vec![],
                request_id: "req-claim-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .instance
            .unwrap();
        assert_eq!(admit.status, STATUS_ADMITTED);

        let claimable = svc
            .list_claimable_action_work(with_principal(ListClaimableActionWorkRequest {
                namespace: "acme".into(),
                runtime_id: "shikigami".into(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner()
            .effects;
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].status, EFFECT_STATUS_PENDING);
        let effect_id = claimable[0].effect_id.clone();

        let claimed = svc
            .claim_action_work(with_principal(ClaimActionWorkRequest {
                effect_id: effect_id.clone(),
                runtime_id: "shikigami".into(),
                request_id: "c1".into(),
                ttl_ms: 60_000,
            }))
            .await
            .unwrap()
            .into_inner()
            .effect
            .unwrap();
        assert_eq!(claimed.status, EFFECT_STATUS_CLAIMED);
        assert_eq!(claimed.claim_generation, 1);

        let denied = svc
            .claim_action_work(with_principal(ClaimActionWorkRequest {
                effect_id: effect_id.clone(),
                runtime_id: "other".into(),
                request_id: "c2".into(),
                ttl_ms: 60_000,
            }))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::FailedPrecondition);

        let hb = svc
            .heartbeat_action_claim(with_principal(HeartbeatActionClaimRequest {
                effect_id: effect_id.clone(),
                runtime_id: "shikigami".into(),
                claim_generation: 1,
                fencing_token: claimed.claim_fencing_token.clone(),
                ttl_ms: 60_000,
            }))
            .await
            .unwrap()
            .into_inner()
            .effect
            .unwrap();
        assert!(hb.claim_expires_at_ms > claimed.claim_expires_at_ms - 1);

        let acked = svc
            .ack_action_work(with_principal(AckActionWorkRequest {
                effect_id: effect_id.clone(),
                runtime_id: "shikigami".into(),
                claim_generation: 1,
                fencing_token: claimed.claim_fencing_token.clone(),
                outcome: "completed".into(),
                reason: String::new(),
                request_id: String::new(),
                checkpoint_store_id: String::new(),
                checkpoint_ref: String::new(),
                checkpoint_digest: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .effect
            .unwrap();
        assert_eq!(acked.status, EFFECT_STATUS_COMPLETED);
        // #400: ack binds harvest/outcome onto the operation receipt spine.
        let receipt = svc
            .db
            .get_operation_receipt(&admit.operation_id)
            .unwrap()
            .expect("receipt");
        assert!(
            receipt
                .events
                .iter()
                .any(|e| e.kind == ReceiptEventKind::OutcomeRecorded)
        );
        let effects = svc
            .db
            .list_action_effects_for_instance(&admit.instance_id)
            .unwrap();
        let instance = svc
            .db
            .get_action_instance(&admit.instance_id)
            .unwrap()
            .unwrap();
        let view = crate::sekai::action_lifecycle::evaluate_action_lifecycle(
            &instance,
            &effects,
            Some(&receipt),
        );
        assert!(view.mismatches.is_empty(), "{:?}", view.mismatches);

        // Unauthorized principal denied
        let unauth = svc
            .claim_action_work(with_named_principal(
                ClaimActionWorkRequest {
                    effect_id: "nope".into(),
                    runtime_id: "shikigami".into(),
                    request_id: "x".into(),
                    ttl_ms: 1000,
                },
                "bob",
            ))
            .await;
        // may be not_found or permission depending on path; ensure not success for random id
        assert!(unauth.is_err());
    }

    #[tokio::test]
    async fn list_schema_types_requires_principal() {
        let svc = service();
        let err = svc
            .list_schema_types(Request::new(ListSchemaTypesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn create_schema_type_requires_schema_admin() {
        let svc = service();
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn create_action_type_compatibility_preserves_execute_action_semantics() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();

        let action = ActionTypeDef {
            name: "set_widget_color".into(),
            description: "Set a widget color through the graph action DSL.".into(),
            params: vec![ActionParamDef {
                name: "color".into(),
                r#type: "enum".into(),
                required: true,
                enum_values: vec!["red".into(), "blue".into()],
            }],
            ops: vec![ActionOp {
                op: "set_property".into(),
                property: "color".into(),
                value_from: "color".into(),
                relation: String::new(),
            }],
            target_kind: "widget".into(),
            created: 0,
            required_purpose: String::new(),
        };
        let created = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(action.clone()),
            }))
            .await
            .unwrap()
            .into_inner()
            .action_type
            .unwrap();
        let mut expected = action;
        expected.created = created.created;
        assert_eq!(created, expected);

        let mut replay = created.clone();
        replay.created = 0;
        let replayed = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(replay),
            }))
            .await
            .unwrap()
            .into_inner()
            .action_type
            .unwrap();
        assert_eq!(replayed.created, created.created);

        let mut replay_with_changed_timestamp = created.clone();
        replay_with_changed_timestamp.created = created.created + 999;
        let replayed_with_changed_timestamp = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(replay_with_changed_timestamp),
            }))
            .await
            .unwrap()
            .into_inner()
            .action_type
            .unwrap();
        assert_eq!(replayed_with_changed_timestamp.created, created.created);

        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-compat",
                HashMap::from([("name".into(), "compat".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-compat", "tester", security::Role::Editor);

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_widget_color".into(),
                params: HashMap::from([
                    ("id".into(), "widget-compat".into()),
                    ("color".into(), "blue".into()),
                ]),
                actor: "tester".into(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let object = svc.db.get_object("widget-compat").unwrap().unwrap();
        assert_eq!(object.properties.get("color"), Some(&"blue".into()));
    }

    #[tokio::test]
    async fn create_action_type_compatibility_requires_action_admin() {
        let svc = service();
        let err = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(ActionTypeDef {
                    name: "untrusted_action".into(),
                    description: String::new(),
                    params: vec![],
                    ops: vec![],
                    target_kind: "widget".into(),
                    created: 0,
                    required_purpose: String::new(),
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn execute_action_refreshes_definitions_from_shared_storage() {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let writer = SekaiServiceImpl::new(db.clone());
        writer
            .create_schema_type(with_named_principal(
                CreateSchemaTypeRequest {
                    r#type: Some(widget_schema_type()),
                },
                "local",
            ))
            .await
            .unwrap();
        let reader = SekaiServiceImpl::new(db.clone());
        let action = ActionTypeDef {
            name: "set_widget_color_shared".into(),
            description: "Set a widget color from another service instance.".into(),
            params: vec![ActionParamDef {
                name: "color".into(),
                r#type: "string".into(),
                required: true,
                enum_values: vec![],
            }],
            ops: vec![ActionOp {
                op: "set_property".into(),
                property: "color".into(),
                value_from: "color".into(),
                relation: String::new(),
            }],
            target_kind: "widget".into(),
            created: 0,
            required_purpose: String::new(),
        };
        writer
            .create_action_type(with_named_principal(
                CreateActionTypeRequest {
                    action_type: Some(action),
                },
                "local",
            ))
            .await
            .unwrap();
        writer
            .db
            .create_object(&from_proto_obj(&widget_object(
                "widget-shared",
                HashMap::from([("name".into(), "shared".into())]),
            )))
            .unwrap();

        reader
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "set_widget_color_shared".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-shared".into()),
                            ("color".into(), "blue".into()),
                        ]),
                        actor: "local".into(),
                    }),
                    dry_run: false,
                },
                "local",
            ))
            .await
            .unwrap();

        let object = reader.db.get_object("widget-shared").unwrap().unwrap();
        assert_eq!(object.properties.get("color"), Some(&"blue".into()));
    }

    #[tokio::test]
    async fn ontology_list_requires_authentication() {
        let svc = service();
        let err = svc
            .list_ontology_classes(Request::new(ListOntologyClassesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn create_ontology_class_requires_admin() {
        let svc = service();
        let err = svc
            .create_ontology_class(with_principal(CreateOntologyClassRequest {
                class: Some(ontology_class("Person")),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn ontology_list_hides_unreadable_definitions() {
        let svc = service();
        for name in ["Visible", "Hidden"] {
            svc.create_ontology_class(with_named_principal(
                CreateOntologyClassRequest {
                    class: Some(ontology_class(name)),
                },
                "local",
            ))
            .await
            .unwrap();
        }
        grant_ontology_reader(&svc, "ontology:class:Visible");
        let hidden_grant = security::Grant {
            id: format!("ontology-hidden-{}", uuid::Uuid::new_v4().simple()),
            object_id: "ontology:class:Hidden".into(),
            principal: "other-reader".into(),
            role: security::Role::Viewer,
            created: 0,
        };
        svc.db.create_grant(&hidden_grant).unwrap();
        svc.security.add_grant(&hidden_grant);

        let listed = svc
            .list_ontology_classes(with_principal(ListOntologyClassesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            listed
                .classes
                .iter()
                .map(|class| class.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Visible"]
        );

        let now = chrono::Utc::now();
        let artifact = crate::ontology_inspect::render_html(
            &crate::ontology_inspect::InspectionSnapshot::new(
                &crate::ontology_inspect::InspectConfig {
                    root: "visible-root".into(),
                    authorization_context: "tester-visible-scope".into(),
                    output: "unused.html".into(),
                    ttl_seconds: 60,
                    target: "authenticated-test-service".into(),
                },
                now,
                listed.classes,
                vec![],
                vec![],
                "test-revision".into(),
                "authorized-test-revision".into(),
            ),
        )
        .unwrap();
        assert!(artifact.contains("Visible"));
        assert!(!artifact.contains("Hidden"));
        assert!(!artifact.contains("denied_objects"));
        assert!(!artifact.contains("Bearer"));
    }

    #[tokio::test]
    async fn create_ontology_class_ensures_mapped_kind() {
        let svc = service();
        grant_ontology_admin(&svc);
        let mut incident = ontology_class("Incident");
        incident.mapped_kind = "incident_kind".into();
        incident.description = "Operational incident".into();

        // Kind must not exist yet.
        assert!(svc.schema.read().unwrap().get("incident_kind").is_none());

        let created = svc
            .create_ontology_class(with_principal(CreateOntologyClassRequest {
                class: Some(incident),
            }))
            .await
            .unwrap()
            .into_inner()
            .class
            .unwrap();
        assert_eq!(created.mapped_kind, "incident_kind");
        assert!(
            svc.schema.read().unwrap().get("incident_kind").is_some(),
            "mapped kind must be ensured for ontology-first product path"
        );

        // Creating an object of the ensured kind must validate.
        let obj = Object {
            id: "inc-ensure-1".into(),
            kind: "incident_kind".into(),
            name: "outage".into(),
            namespace: "demo".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 0,
            updated: 0,
        };
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(obj),
            lease_precondition: None,
        }))
        .await
        .expect("object create after kind ensure");
    }

    #[tokio::test]
    async fn ontology_class_crud_round_trip() {
        let svc = service();
        grant_ontology_admin(&svc);
        let mut person = ontology_class("Person");
        person.description = "A human".into();
        person.properties = vec![OntologyProperty {
            name: "email".into(),
            r#type: "string".into(),
            required: false,
            description: String::new(),
        }];

        let created = svc
            .create_ontology_class(with_principal(CreateOntologyClassRequest {
                class: Some(person),
            }))
            .await
            .unwrap()
            .into_inner()
            .class
            .unwrap();
        assert!(created.mapped_kind.is_empty());
        assert_eq!(created.properties.len(), 1);

        let fetched = svc
            .get_ontology_class(with_principal(GetOntologyClassRequest {
                name: "Person".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .class
            .unwrap();
        assert_eq!(fetched.description, "A human");

        let listed = svc
            .list_ontology_classes(with_principal(ListOntologyClassesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(listed.classes.iter().any(|class| class.name == "Person"));

        svc.delete_ontology_class(with_principal(DeleteOntologyClassRequest {
            name: "Person".into(),
        }))
        .await
        .unwrap();
        let err = svc
            .get_ontology_class(with_principal(GetOntologyClassRequest {
                name: "Person".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        let audit = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                target_id: Some("ontology:class:Person".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            audit
                .iter()
                .any(|decision| decision.action == "ontology.class.create")
        );
        assert!(
            audit
                .iter()
                .any(|decision| decision.action == "ontology.class.delete")
        );
        assert!(audit.iter().all(|decision| decision.actor == "tester"));
    }

    #[tokio::test]
    async fn create_ontology_class_rejects_unknown_superclass() {
        let svc = service();
        grant_ontology_admin(&svc);
        let mut engineer = ontology_class("Engineer");
        engineer.superclasses = vec!["Person".into()];
        let err = svc
            .create_ontology_class(with_principal(CreateOntologyClassRequest {
                class: Some(engineer),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("unknown superclass"));
    }

    #[tokio::test]
    async fn ontology_relation_requires_known_endpoints() {
        let svc = service();
        grant_ontology_admin(&svc);
        let relation = OntologyRelation {
            name: "works_for".into(),
            description: String::new(),
            domain: "Person".into(),
            range: "Company".into(),
            cardinality: None,
            inverse: String::new(),
            transitive: false,
            is_builtin: false,
            mapped_relation: String::new(),
        };
        // Endpoints do not exist yet.
        let err = svc
            .create_ontology_relation(with_principal(CreateOntologyRelationRequest {
                relation: Some(relation.clone()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        for name in ["Person", "Company"] {
            svc.create_ontology_class(with_principal(CreateOntologyClassRequest {
                class: Some(ontology_class(name)),
            }))
            .await
            .unwrap();
        }
        let created = svc
            .create_ontology_relation(with_principal(CreateOntologyRelationRequest {
                relation: Some(relation),
            }))
            .await
            .unwrap()
            .into_inner()
            .relation
            .unwrap();
        assert_eq!(created.domain, "Person");
        assert_eq!(created.range, "Company");
    }

    #[tokio::test]
    async fn ontology_mutations_cannot_reference_unreadable_definitions() {
        let svc = service();
        for name in ["Visible", "Hidden"] {
            svc.create_ontology_class(with_named_principal(
                CreateOntologyClassRequest {
                    class: Some(ontology_class(name)),
                },
                "local",
            ))
            .await
            .unwrap();
        }
        grant_ontology_admin(&svc);
        grant_object_role(
            &svc,
            "ontology:class:Hidden",
            "other-reader",
            security::Role::Viewer,
        );

        let mut child = ontology_class("Child");
        child.superclasses = vec!["Hidden".into()];
        let class_denied = svc
            .create_ontology_class(with_principal(CreateOntologyClassRequest {
                class: Some(child),
            }))
            .await
            .unwrap_err();
        assert_eq!(class_denied.code(), tonic::Code::PermissionDenied);

        let relation_denied = svc
            .create_ontology_relation(with_principal(CreateOntologyRelationRequest {
                relation: Some(OntologyRelation {
                    name: "reveals_hidden".into(),
                    description: String::new(),
                    domain: "Visible".into(),
                    range: "Hidden".into(),
                    cardinality: None,
                    inverse: String::new(),
                    transitive: false,
                    is_builtin: false,
                    mapped_relation: String::new(),
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(relation_denied.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn ontology_reads_hide_definitions_with_unreadable_references() {
        let svc = service();
        for name in ["Visible", "Hidden"] {
            svc.create_ontology_class(with_named_principal(
                CreateOntologyClassRequest {
                    class: Some(ontology_class(name)),
                },
                "local",
            ))
            .await
            .unwrap();
        }
        let mut child = ontology_class("Child");
        child.superclasses = vec!["Hidden".into()];
        svc.create_ontology_class(with_named_principal(
            CreateOntologyClassRequest { class: Some(child) },
            "local",
        ))
        .await
        .unwrap();
        svc.create_ontology_relation(with_named_principal(
            CreateOntologyRelationRequest {
                relation: Some(OntologyRelation {
                    name: "reveals_hidden".into(),
                    description: String::new(),
                    domain: "Visible".into(),
                    range: "Hidden".into(),
                    cardinality: None,
                    inverse: String::new(),
                    transitive: false,
                    is_builtin: false,
                    mapped_relation: String::new(),
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        grant_object_role(
            &svc,
            "ontology:class:Hidden",
            "other-reader",
            security::Role::Viewer,
        );

        let class_denied = svc
            .get_ontology_class(with_principal(GetOntologyClassRequest {
                name: "Child".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(class_denied.code(), tonic::Code::PermissionDenied);
        let relation_denied = svc
            .get_ontology_relation(with_principal(GetOntologyRelationRequest {
                name: "reveals_hidden".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(relation_denied.code(), tonic::Code::PermissionDenied);

        let classes = svc
            .list_ontology_classes(with_principal(ListOntologyClassesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(!classes.classes.iter().any(|class| class.name == "Child"));
        let relations = svc
            .list_ontology_relations(with_principal(ListOntologyRelationsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(relations.relations.is_empty());
    }

    #[tokio::test]
    async fn delete_ontology_class_blocked_by_relation_reference() {
        let svc = service();
        grant_ontology_admin(&svc);
        for name in ["Person", "Company"] {
            svc.create_ontology_class(with_principal(CreateOntologyClassRequest {
                class: Some(ontology_class(name)),
            }))
            .await
            .unwrap();
        }
        svc.create_ontology_relation(with_principal(CreateOntologyRelationRequest {
            relation: Some(OntologyRelation {
                name: "works_for".into(),
                description: String::new(),
                domain: "Person".into(),
                range: "Company".into(),
                cardinality: None,
                inverse: String::new(),
                transitive: false,
                is_builtin: false,
                mapped_relation: String::new(),
            }),
        }))
        .await
        .unwrap();
        let err = svc
            .delete_ontology_class(with_principal(DeleteOntologyClassRequest {
                name: "Company".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn delete_ontology_relation_blocked_by_inverse_reference() {
        let svc = service();
        grant_ontology_admin(&svc);
        for name in ["Person", "Company"] {
            svc.create_ontology_class(with_principal(CreateOntologyClassRequest {
                class: Some(ontology_class(name)),
            }))
            .await
            .unwrap();
        }
        for (name, domain, range, inverse) in [
            ("works_for", "Person", "Company", ""),
            ("employs", "Company", "Person", "works_for"),
        ] {
            svc.create_ontology_relation(with_principal(CreateOntologyRelationRequest {
                relation: Some(OntologyRelation {
                    name: name.into(),
                    description: String::new(),
                    domain: domain.into(),
                    range: range.into(),
                    cardinality: None,
                    inverse: inverse.into(),
                    transitive: false,
                    is_builtin: false,
                    mapped_relation: String::new(),
                }),
            }))
            .await
            .unwrap();
        }

        let incompatible_update = svc
            .create_ontology_relation(with_principal(CreateOntologyRelationRequest {
                relation: Some(OntologyRelation {
                    name: "works_for".into(),
                    description: String::new(),
                    domain: "Company".into(),
                    range: "Person".into(),
                    cardinality: None,
                    inverse: String::new(),
                    transitive: false,
                    is_builtin: false,
                    mapped_relation: String::new(),
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(incompatible_update.code(), tonic::Code::InvalidArgument);
        assert!(incompatible_update.message().contains("no longer reverse"));

        let err = svc
            .delete_ontology_relation(with_principal(DeleteOntologyRelationRequest {
                name: "works_for".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn ontology_delete_clears_durable_and_cached_grants() {
        let svc = service();
        for name in ["Person", "Company"] {
            svc.create_ontology_class(with_named_principal(
                CreateOntologyClassRequest {
                    class: Some(ontology_class(name)),
                },
                "local",
            ))
            .await
            .unwrap();
        }
        svc.create_ontology_relation(with_named_principal(
            CreateOntologyRelationRequest {
                relation: Some(OntologyRelation {
                    name: "works_for".into(),
                    description: String::new(),
                    domain: "Person".into(),
                    range: "Company".into(),
                    cardinality: None,
                    inverse: String::new(),
                    transitive: false,
                    is_builtin: false,
                    mapped_relation: String::new(),
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        for object_id in ["ontology:class:Person", "ontology:relation:works_for"] {
            grant_object_role(&svc, object_id, "tester", security::Role::Admin);
        }

        svc.delete_ontology_relation(with_principal(DeleteOntologyRelationRequest {
            name: "works_for".into(),
        }))
        .await
        .unwrap();
        svc.delete_ontology_class(with_principal(DeleteOntologyClassRequest {
            name: "Person".into(),
        }))
        .await
        .unwrap();

        for object_id in ["ontology:class:Person", "ontology:relation:works_for"] {
            assert!(svc.db.list_grants(object_id).unwrap().is_empty());
            assert!(svc.security.can_access(object_id, &["other-reader"]));
        }
    }

    #[tokio::test]
    async fn ontology_grants_are_managed_through_public_rpcs() {
        let svc = service();
        svc.create_ontology_class(with_named_principal(
            CreateOntologyClassRequest {
                class: Some(ontology_class("Restricted")),
            },
            "local",
        ))
        .await
        .unwrap();
        grant_ontology_admin(&svc);

        let created = svc
            .create_grant(with_principal(CreateGrantRequest {
                grant: Some(Grant {
                    id: "ontology-viewer".into(),
                    object_id: "ontology:class:Restricted".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .grant
            .unwrap();
        assert_eq!(created.principal, "alice");

        let grants = svc
            .list_grants(with_principal(ListGrantsRequest {
                object_id: "ontology:class:Restricted".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(grants.grants.len(), 1);
        svc.get_ontology_class(with_named_principal(
            GetOntologyClassRequest {
                name: "Restricted".into(),
            },
            "alice",
        ))
        .await
        .unwrap();

        svc.delete_grant(with_principal(DeleteGrantRequest {
            id: "ontology-viewer".into(),
        }))
        .await
        .unwrap();
        assert!(
            svc.db
                .list_grants("ontology:class:Restricted")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn schema_type_implements_interface_and_list_filters_by_interface() {
        let svc = service();
        grant_schema_admin(&svc);
        let interface = schema::InterfaceDef {
            name: "Trackable".into(),
            description: "Trackable object".into(),
            properties: vec![schema::PropertyDef {
                name: "tracking_id".into(),
                prop_type: schema::PropertyType::String,
                required: true,
                description: "".into(),
                enum_values: vec![],
                link_kind: "".into(),
                compute_expr: "".into(),
                classification: "public".into(),
                struct_fields: vec![],
            }],
            is_builtin: false,
        };
        svc.db.upsert_interface(&interface).unwrap();
        svc.schema.write().unwrap().register_interface(interface);

        let mut invalid_type = widget_schema_type();
        invalid_type.implements = vec!["Trackable".into()];
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(invalid_type),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("tracking_id"));

        let mut optional_required_property = widget_schema_type();
        optional_required_property.implements = vec!["Trackable".into()];
        optional_required_property.properties.push(PropertyDef {
            name: "tracking_id".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(optional_required_property),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("must be required"));

        let mut valid_type = widget_schema_type();
        valid_type.implements = vec!["Trackable".into()];
        valid_type.properties.push(PropertyDef {
            name: "tracking_id".into(),
            r#type: "string".into(),
            required: true,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(valid_type),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "tracked",
                HashMap::from([
                    ("name".into(), "tracked".into()),
                    ("tracking_id".into(), "trk-1".into()),
                ]),
            )),
            lease_precondition: None,
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-2".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    interface_filter: vec!["Trackable".into()],
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.total, 1);
        assert_eq!(listed.objects[0].id, "tracked");
    }

    #[tokio::test]
    async fn corrupt_schema_row_only_blocks_that_kind_until_repaired() {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        {
            let conn = db.conn();
            conn.execute(
                "INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                ("broken", "Broken schema", "[", 1_i64),
            )
            .unwrap();
        }
        let svc = SekaiServiceImpl::new(db.clone());
        grant_schema_admin(&svc);

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-1".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "broken-1".into(),
                    kind: "broken".into(),
                    name: "broken".into(),
                    namespace: "".into(),
                    external_id: "".into(),
                    properties: HashMap::new(),
                    created: 0,
                    updated: 0,
                }),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("broken"));

        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "broken".into(),
                description: "Repaired".into(),
                properties: vec![],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "broken-2".into(),
                kind: "broken".into(),
                name: "broken".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn user_defined_action_blocks_when_target_schema_failed_to_load() {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        db.migrate_schema_types().unwrap();
        {
            let conn = db.conn();
            conn.execute(
                "INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                ("broken", "Broken schema", "[", 1_i64),
            )
            .unwrap();
        }
        db.upsert_action_type(&action::ActionTypeDef {
            name: "touch_broken".into(),
            description: "".into(),
            params: vec![action::ActionParamDef {
                name: "value".into(),
                param_type: schema::PropertyType::String,
                required: true,
                enum_values: vec![],
            }],
            ops: vec![action::ActionOp {
                op: "set_property".into(),
                property: "status".into(),
                value_from: "value".into(),
                relation: "".into(),
            }],
            target_kind: "broken".into(),
            created: 1,
            required_purpose: String::new(),
        })
        .unwrap();
        let svc = SekaiServiceImpl::new(db.clone());
        svc.db
            .create_object(&domain::Object {
                id: "broken-1".into(),
                kind: "broken".into(),
                name: "broken".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        grant_object_role(&svc, "broken-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "touch_broken".into(),
                        params: HashMap::from([
                            ("id".into(), "broken-1".into()),
                            ("value".into(), "done".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("broken"));
        assert!(
            !svc.db
                .get_object("broken-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("status")
        );
    }

    #[tokio::test]
    async fn schema_table_read_failure_blocks_object_writes() {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_types", []).unwrap();
            conn.execute(
                "CREATE TABLE sekai_object_types (kind TEXT PRIMARY KEY)",
                [],
            )
            .unwrap();
        }
        let svc = SekaiServiceImpl::new(db.clone());

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "loose-1".into(),
                    kind: "loose".into(),
                    name: "loose".into(),
                    namespace: "".into(),
                    external_id: "".into(),
                    properties: HashMap::new(),
                    created: 0,
                    updated: 0,
                }),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("schema registry unavailable"));

        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_types", []).unwrap();
        }
        db.migrate_all().unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-2".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn malformed_object_row_returns_internal_and_next_request_succeeds() {
        let svc = service();
        {
            let conn = svc.db.conn();
            conn.execute(
                "INSERT INTO sekai_objects
                 (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                ("good", "widget", "good", "", "", "{}", 1000_i64, 1000_i64),
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sekai_objects
                 (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    "bad",
                    "widget",
                    "bad",
                    "",
                    "",
                    "{}",
                    "not-an-integer",
                    1000_i64,
                ),
            )
            .unwrap();
        }

        let err = svc
            .get_object(with_principal(GetObjectRequest { id: "bad".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);

        let good = svc
            .get_object(with_principal(GetObjectRequest { id: "good".into() }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(good.id, "good");
    }

    #[tokio::test]
    async fn grant_and_audit_rpcs_round_trip() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "o1".into(),
                kind: "note".into(),
                name: "target".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        let admin_grant = security::Grant {
            id: "admin".into(),
            object_id: "o1".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&admin_grant).unwrap();
        svc.security.add_grant(&admin_grant);
        svc.db
            .record_decision(&audit::Decision {
                id: "d1".into(),
                timestamp: 10,
                actor: "tester".into(),
                action: "create".into(),
                reason: "".into(),
                evidence: HashMap::new(),
                target_id: "o1".into(),
                outcome: "ok".into(),
            })
            .unwrap();
        svc.db
            .record_object_change(&audit::ObjectChange {
                id: "c1".into(),
                object_id: "o1".into(),
                field: "name".into(),
                old_value: "a".into(),
                new_value: "b".into(),
                changed_by: "tester".into(),
                timestamp: 11,
            })
            .unwrap();

        let created = svc
            .create_grant(with_principal(CreateGrantRequest {
                grant: Some(Grant {
                    id: "g1".into(),
                    object_id: "o1".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.grant.unwrap().principal, "alice");

        let access = svc
            .check_access(with_principal(CheckAccessRequest {
                object_id: "o1".into(),
                principals: vec!["alice".into()],
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(access.allowed);

        let recorded = svc
            .record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: "".into(),
                    timestamp: 0,
                    actor: "tester".into(),
                    action: "gateway.budget_denied".into(),
                    reason: "budget exceeded".into(),
                    evidence: HashMap::from([("user_id".into(), "agent:codex-app".into())]),
                    target_id: "o1".into(),
                    outcome: "denied".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        assert!(!recorded.id.is_empty());
        assert!(recorded.timestamp > 0);

        let listed = svc
            .list_decisions(with_principal(ListDecisionsRequest {
                actor: "tester".into(),
                action: "".into(),
                after: 0,
                limit: 10,
                target_id: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.decisions.len(), 2);

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "o1".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(changes.changes.len(), 1);
    }

    #[tokio::test]
    async fn control_plane_admin_can_recover_managed_acl() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "namespace:acme".into(),
                kind: "namespace".into(),
                name: "acme".into(),
                namespace: "acme".into(),
                external_id: "namespace:acme".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        let member_grant = security::Grant {
            id: "member".into(),
            object_id: "namespace:acme".into(),
            principal: "alice".into(),
            role: security::Role::Viewer,
            created: 0,
        };
        svc.db.create_grant(&member_grant).unwrap();
        svc.security.add_grant(&member_grant);

        svc.create_grant(with_named_principal(
            CreateGrantRequest {
                grant: Some(Grant {
                    id: "recovery".into(),
                    object_id: "namespace:acme".into(),
                    principal: "root".into(),
                    role: "admin".into(),
                    created: 1,
                }),
            },
            "local",
        ))
        .await
        .unwrap();

        assert!(svc.security.can_admin("namespace:acme", &["root"]));
    }

    #[tokio::test]
    async fn team_namespace_bootstrap_is_atomic_and_admin_only() {
        let svc = service();
        let denied = svc
            .ensure_team_namespace(with_named_principal(
                EnsureTeamNamespaceRequest {
                    namespace: "acme".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.find_namespace_boundary("acme").unwrap().is_none());

        let created = svc
            .ensure_team_namespace(with_named_principal(
                EnsureTeamNamespaceRequest {
                    namespace: "acme".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        let namespace = created.namespace.unwrap();
        assert_eq!(namespace.external_id, "namespace:acme");
        assert_eq!(created.grants.len(), 3);
        assert!(svc.security.can_access(&namespace.id, &["alice"]));

        let forged_namespace = svc
            .create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(Object {
                        id: "namespace-forged".into(),
                        kind: "namespace".into(),
                        name: "forged".into(),
                        namespace: "forged".into(),
                        external_id: "namespace:forged".into(),
                        properties: HashMap::new(),
                        created: 1,
                        updated: 1,
                    }),
                    lease_precondition: None,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(forged_namespace.code(), tonic::Code::PermissionDenied);

        let forged_external_id = svc
            .create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(Object {
                        id: "ordinary-object".into(),
                        kind: "note".into(),
                        name: "forged identity".into(),
                        namespace: "acme".into(),
                        external_id: "namespace:future".into(),
                        properties: HashMap::new(),
                        created: 1,
                        updated: 1,
                    }),
                    lease_precondition: None,
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(forged_external_id.code(), tonic::Code::InvalidArgument);

        let root_grant = created
            .grants
            .into_iter()
            .find(|grant| grant.principal == "root")
            .unwrap();
        let delete_root = svc
            .delete_grant(with_named_principal(
                DeleteGrantRequest { id: root_grant.id },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(delete_root.code(), tonic::Code::PermissionDenied);

        let delete_namespace = svc
            .delete_object(with_named_principal(
                DeleteObjectRequest {
                    id: namespace.id.clone(),
                    lease_precondition: None,
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(delete_namespace.code(), tonic::Code::FailedPrecondition);
        assert!(svc.db.find_namespace_boundary("acme").unwrap().is_some());

        svc.db
            .create_object(&domain::Object {
                id: "legacy-boundary".into(),
                kind: "namespace".into(),
                name: "legacy".into(),
                namespace: String::new(),
                external_id: "namespace:legacy".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        let adopted = svc
            .ensure_team_namespace(with_named_principal(
                EnsureTeamNamespaceRequest {
                    namespace: "legacy".into(),
                    principal: "bob".into(),
                    role: "viewer".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner()
            .namespace
            .unwrap();
        assert_eq!(adopted.namespace, "legacy");
        assert_eq!(
            adopted.properties.get("team_managed").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            svc.delete_object(with_named_principal(
                DeleteObjectRequest {
                    id: adopted.id,
                    lease_precondition: None
                },
                "local",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[tokio::test]
    async fn grants_cannot_preclaim_future_namespace_boundaries() {
        let svc = service();
        svc.ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "acme".into(),
                principal: "bob".into(),
                role: "editor".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(Object {
                        id: "namespace:future".into(),
                        kind: "note".into(),
                        name: "preclaim".into(),
                        namespace: "acme".into(),
                        ..Default::default()
                    }),
                    lease_precondition: None,
                },
                "bob",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
        let denied = svc
            .create_grant(with_named_principal(
                CreateGrantRequest {
                    grant: Some(Grant {
                        id: "orphan".into(),
                        object_id: "namespace:future".into(),
                        principal: "mallory".into(),
                        role: "admin".into(),
                        created: 1,
                    }),
                },
                "mallory",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::InvalidArgument);

        svc.db
            .create_grant(&security::Grant {
                id: "legacy-orphan".into(),
                object_id: "namespace:future".into(),
                principal: "mallory".into(),
                role: security::Role::Admin,
                created: 1,
            })
            .unwrap();
        let bootstrap = svc
            .ensure_team_namespace(with_named_principal(
                EnsureTeamNamespaceRequest {
                    namespace: "future".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(bootstrap.code(), tonic::Code::Internal);
        assert!(svc.db.find_namespace_boundary("future").unwrap().is_none());
    }

    #[tokio::test]
    async fn coordination_rpcs_round_trip() {
        let svc = service();
        let scope = svc
            .create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: "req-scope-1".into(),
                scope: Some(ContentionScope {
                    id: "scope-1".into(),
                    name: "build".into(),
                    parent_scope_id: String::new(),
                    max_concurrency: 1,
                    admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                    heartbeat_ttl_seconds: 30,
                    timeout_seconds: 60,
                    owner_principal: String::new(),
                    created: 100,
                    updated: 100,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .scope
            .unwrap();
        assert_eq!(scope.owner_principal, "tester");

        let work_unit = svc
            .create_work_unit(with_principal(CreateWorkUnitRequest {
                work_unit: Some(WorkUnit {
                    id: "wu-1".into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: "cargo test -q".into(),
                    scope_id: "scope-1".into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 101,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "idem-wu-1".into(),
                    updated_at: 101,
                }),
                request_id: "req-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(work_unit.owner_principal, "tester");

        let admitted = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-admit-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted);
        assert_eq!(admitted.reservations.len(), 1);

        let reservations = svc
            .list_reservations(with_principal(ListReservationsRequest {
                work_unit_id: "wu-1".into(),
                scope_id: String::new(),
                status: coordination::RESERVATION_STATUS_ACTIVE.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reservations.reservations.len(), 1);

        let heartbeat = svc
            .heartbeat_work_unit(with_principal(HeartbeatWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-heartbeat-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert!(heartbeat.last_heartbeat_at > 0);

        let completed = svc
            .complete_work_unit(with_principal(CompleteWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-complete-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(completed.status, coordination::WORK_UNIT_STATUS_COMPLETED);

        let events = svc
            .list_run_events(with_principal(ListRunEventsRequest {
                work_unit_id: "wu-1".into(),
                limit: 20,
                after: 0,
                event_types: vec![],
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == "created")
        );
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == "admitted")
        );
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == coordination::WORK_UNIT_STATUS_COMPLETED)
        );
    }

    #[tokio::test]
    async fn coordination_create_and_transition_requests_are_idempotent() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-idem".into(),
            scope: Some(ContentionScope {
                id: "scope-idem".into(),
                name: "idem".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();

        let create = CreateWorkUnitRequest {
            request_id: "req-create-idem".into(),
            work_unit: Some(WorkUnit {
                id: "wu-idem".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "echo hi".into(),
                scope_id: "scope-idem".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: 2,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "idem-key-1".into(),
                updated_at: 2,
            }),
        };
        let first = svc
            .create_work_unit(with_principal(create.clone()))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        let second = svc
            .create_work_unit(with_principal(create))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(first.id, second.id);

        let admit = TryAdmitWorkUnitRequest {
            work_unit_id: "wu-idem".into(),
            request_id: "req-admit-idem".into(),
        };
        let first_admit = svc
            .try_admit_work_unit(with_principal(admit.clone()))
            .await
            .unwrap()
            .into_inner();
        let second_admit = svc
            .try_admit_work_unit(with_principal(admit))
            .await
            .unwrap()
            .into_inner();
        assert!(first_admit.admitted);
        assert!(second_admit.admitted);

        let complete = CompleteWorkUnitRequest {
            work_unit_id: "wu-idem".into(),
            request_id: "req-complete-idem".into(),
        };
        let first_complete = svc
            .complete_work_unit(with_principal(complete.clone()))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        let second_complete = svc
            .complete_work_unit(with_principal(complete))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(
            first_complete.status,
            coordination::WORK_UNIT_STATUS_COMPLETED
        );
        assert_eq!(second_complete.status, first_complete.status);
    }

    #[tokio::test]
    async fn coordination_filters_paginates_and_dry_run_reconciles() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-filter".into(),
            scope: Some(ContentionScope {
                id: "scope-filter".into(),
                name: "filter".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 10,
                updated: 10,
            }),
        }))
        .await
        .unwrap();

        for (id, key, created_at) in [("wu-f1", "filter-1", 11), ("wu-f2", "filter-2", 12)] {
            svc.create_work_unit(with_principal(CreateWorkUnitRequest {
                request_id: format!("req-create-{}", id),
                work_unit: Some(WorkUnit {
                    id: id.into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: format!("spec {}", id),
                    scope_id: "scope-filter".into(),
                    priority: 0,
                    timeout_seconds: 1,
                    heartbeat_ttl_seconds: 1,
                    created_at,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: key.into(),
                    updated_at: created_at,
                }),
            }))
            .await
            .unwrap();
        }
        svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-f1".into(),
            request_id: "req-admit-f1".into(),
        }))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-f1").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-f1"],
            )
            .unwrap();

        let first_page = svc
            .list_work_units(with_principal(ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-filter".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![
                        coordination::WORK_UNIT_STATUS_PENDING.into(),
                        coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    ],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: String::new(),
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first_page.work_units.len(), 1);
        assert!(!first_page.next_page_token.is_empty());

        let second_page = svc
            .list_work_units(with_principal(ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-filter".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![
                        coordination::WORK_UNIT_STATUS_PENDING.into(),
                        coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    ],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: first_page.next_page_token,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second_page.work_units.len(), 1);

        let reconcile = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: true,
                work_unit_id: "wu-f1".into(),
                scope_id: String::new(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!reconcile.details.is_empty());

        let still_running = svc
            .get_work_unit(with_principal(GetWorkUnitRequest { id: "wu-f1".into() }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn create_work_unit_ignores_client_supplied_lifecycle_state() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-sanitize".into(),
            scope: Some(ContentionScope {
                id: "scope-sanitize".into(),
                name: "sanitize".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();

        let created = svc
            .create_work_unit(with_principal(CreateWorkUnitRequest {
                request_id: "req-create-sanitize".into(),
                work_unit: Some(WorkUnit {
                    id: "wu-sanitize".into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    requested_spec: "echo hi".into(),
                    scope_id: "scope-sanitize".into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 5,
                    admitted_at: 99,
                    started_at: 99,
                    finished_at: 99,
                    last_heartbeat_at: 99,
                    failure_reason: "boom".into(),
                    cancel_reason: "stop".into(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "sanitize-1".into(),
                    updated_at: 77,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();

        assert_eq!(created.status, coordination::WORK_UNIT_STATUS_PENDING);
        assert_eq!(created.admitted_at, 0);
        assert_eq!(created.started_at, 0);
        assert_eq!(created.finished_at, 0);
        assert_eq!(created.last_heartbeat_at, 0);
        assert!(created.failure_reason.is_empty());
        assert!(created.cancel_reason.is_empty());
        assert_eq!(created.updated_at, created.created_at);
    }

    #[tokio::test]
    async fn reconcile_requires_scope_ownership_for_target_scope() {
        let svc = service();
        for (scope_id, owner, created) in [("scope-a", "tester", 1), ("scope-b", "other", 2)] {
            svc.create_contention_scope(with_named_principal(
                CreateContentionScopeRequest {
                    request_id: format!("req-{}", scope_id),
                    scope: Some(ContentionScope {
                        id: scope_id.into(),
                        name: scope_id.into(),
                        parent_scope_id: String::new(),
                        max_concurrency: 1,
                        admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                        heartbeat_ttl_seconds: 1,
                        timeout_seconds: 1,
                        owner_principal: String::new(),
                        created,
                        updated: created,
                    }),
                },
                owner,
            ))
            .await
            .unwrap();
        }

        svc.create_work_unit(with_named_principal(
            CreateWorkUnitRequest {
                request_id: "req-wu-other".into(),
                work_unit: Some(WorkUnit {
                    id: "wu-other".into(),
                    kind: "build".into(),
                    actor: "other".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: "run".into(),
                    scope_id: "scope-b".into(),
                    priority: 0,
                    timeout_seconds: 1,
                    heartbeat_ttl_seconds: 1,
                    created_at: 10,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "other-1".into(),
                    updated_at: 10,
                }),
            },
            "other",
        ))
        .await
        .unwrap();
        svc.try_admit_work_unit(with_named_principal(
            TryAdmitWorkUnitRequest {
                work_unit_id: "wu-other".into(),
                request_id: "req-admit-other".into(),
            },
            "other",
        ))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-other").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-other"],
            )
            .unwrap();

        let denied = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: false,
                work_unit_id: String::new(),
                scope_id: "scope-b".into(),
                limit: 10,
            }))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let still_running = svc
            .get_work_unit(with_named_principal(
                GetWorkUnitRequest {
                    id: "wu-other".into(),
                },
                "other",
            ))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn reconcile_with_mismatched_scope_and_work_unit_returns_empty() {
        let svc = service();
        for scope in [
            ContentionScope {
                id: "scope-one".into(),
                name: "scope-one".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            },
            ContentionScope {
                id: "scope-two".into(),
                name: "scope-two".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 2,
                updated: 2,
            },
        ] {
            svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: format!("req-{}", scope.id),
                scope: Some(scope),
            }))
            .await
            .unwrap();
        }

        svc.create_work_unit(with_principal(CreateWorkUnitRequest {
            request_id: "req-wu-mismatch".into(),
            work_unit: Some(WorkUnit {
                id: "wu-mismatch".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "run".into(),
                scope_id: "scope-one".into(),
                priority: 0,
                timeout_seconds: 1,
                heartbeat_ttl_seconds: 1,
                created_at: 10,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "mismatch-1".into(),
                updated_at: 10,
            }),
        }))
        .await
        .unwrap();
        svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-mismatch".into(),
            request_id: "req-admit-mismatch".into(),
        }))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-mismatch").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-mismatch"],
            )
            .unwrap();

        let reconcile = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: false,
                work_unit_id: "wu-mismatch".into(),
                scope_id: "scope-two".into(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reconcile.work_units_reconciled, 0);
        assert_eq!(reconcile.reservations_released, 0);
        assert!(reconcile.details.is_empty());

        let still_running = svc
            .get_work_unit(with_principal(GetWorkUnitRequest {
                id: "wu-mismatch".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn list_objects_enforces_limit_and_returns_total() {
        let svc = service();
        for i in 0..1105 {
            let object = domain::Object {
                id: format!("obj-{i}"),
                kind: "query-demo".into(),
                name: format!("object-{i}"),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "backend".into())]),
                created: i64::from(i),
                updated: i64::from(i),
            };
            svc.db.create_object(&object).unwrap();
        }

        let response = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        order_by: "name".into(),
                        limit: 2000,
                        offset: 0,
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.total, 1105);
        assert_eq!(response.objects.len(), 1000);
    }

    #[tokio::test]
    async fn list_objects_omits_filter_uses_defaults() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "default-filter".into(),
                kind: "query-demo".into(),
                name: "default-filter".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "backend".into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();

        let response = svc
            .list_objects(with_named_principal(
                ListObjectsRequest { filter: None },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.total, 1);
        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "default-filter");
    }

    #[tokio::test]
    async fn list_objects_rejects_unknown_property_operator() {
        let svc = service();
        let err = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team".into(),
                            op: "nope".into(),
                            value: "backend".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_objects_rejects_invalid_property_key() {
        let svc = service();
        let err = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team.name".into(),
                            op: "eq".into(),
                            value: "backend".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn action_policy_set_get_list_round_trip() {
        let svc = service();
        grant_action_admin(&svc);

        let policy = ActionPolicy {
            scope: "agent:codex-app".into(),
            default_decision: "allow".into(),
            action_overrides: HashMap::from([("delete_link".to_string(), "deny".to_string())]),
            risk_overrides: HashMap::from([(
                "destructive".to_string(),
                "require_approval".to_string(),
            )]),
            max_mutations_per_work_unit: 0,
            max_deletes_per_work_unit: 5,
        };

        let stored = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(policy.clone()),
            }))
            .await
            .unwrap()
            .into_inner()
            .policy
            .unwrap();
        assert_eq!(stored.scope, "agent:codex-app");
        assert_eq!(stored.action_overrides.get("delete_link").unwrap(), "deny");

        let fetched = svc
            .get_action_policy(with_principal(GetActionPolicyRequest {
                scope: "agent:codex-app".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .policy
            .unwrap();
        assert_eq!(fetched.default_decision, "allow");
        assert_eq!(
            fetched.risk_overrides.get("destructive").unwrap(),
            "require_approval"
        );
        assert_eq!(fetched.max_deletes_per_work_unit, 5);

        let listed = svc
            .list_action_policies(with_principal(ListActionPoliciesRequest {}))
            .await
            .unwrap()
            .into_inner()
            .policies;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].scope, "agent:codex-app");
    }

    #[tokio::test]
    async fn action_policy_set_requires_action_admin() {
        let svc = service();
        // No action-admin grant for "tester".
        let err = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(ActionPolicy {
                    scope: "agent:codex-app".into(),
                    default_decision: "deny".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        // Nothing was persisted.
        assert!(
            svc.db
                .get_action_policy("agent:codex-app")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn action_policy_set_rejects_invalid_decision() {
        let svc = service();
        grant_action_admin(&svc);
        let err = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(ActionPolicy {
                    scope: "agent:codex-app".into(),
                    default_decision: "maybe".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn scoring_writer_records_private_typed_learning_and_retries_idempotently() {
        let svc = service();
        let namespace_id = seed_scoring_namespace(&svc, "acme");
        let request = scored_knowledge_request("acme", "request-42");
        let learning_id = scoring_learning_id("acme", "request-42");

        assert_eq!(
            svc.write_knowledge(&request).await.unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
        let learning = svc.db.get_object(&learning_id).unwrap().unwrap();
        assert_eq!(learning.kind, domain::KIND_LEARNING);
        assert_eq!(learning.namespace, "acme");
        assert_eq!(learning.name, "Scored learning");
        assert_eq!(learning.properties["producer"], "chisei.scoring");
        assert_eq!(learning.properties["status"], "candidate");
        assert_eq!(
            learning.properties["title"],
            "Scored primary task outcome: passed"
        );
        assert!(
            learning.properties["prevention"]
                .contains("The implementation satisfies the requested behavior.")
        );
        assert_eq!(learning.properties["source_request_id"], "request-42");
        let long_source = knowledge_source_request_id(&"x".repeat(300));
        assert!(long_source.starts_with("sha256:"));
        assert_eq!(long_source.chars().count(), 71);

        let link = svc
            .db
            .get_link(&format!("{learning_id}->{namespace_id}"))
            .unwrap()
            .unwrap();
        assert_eq!(link.from_id, learning_id);
        assert_eq!(link.to_id, namespace_id);
        assert_eq!(link.relation, domain::REL_TOUCHES);

        let grants = svc.db.list_grants(&learning.id).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].principal, "chisei.scoring");
        assert_eq!(grants[0].role, security::Role::Admin);

        // The action inserted the fallback ACL directly in its transaction. The service refreshes
        // its in-process checker before returning, so the learning is never left world-readable.
        let denied = svc
            .get_object(with_named_principal(
                GetObjectRequest {
                    id: learning.id.clone(),
                },
                "unrelated",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        // The same namespace/request pair produces the same id and the action's exact-retry path
        // does not duplicate the object, link, or grant.
        assert_eq!(
            svc.write_knowledge(&request).await.unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
        let learnings = svc
            .db
            .list_objects(&domain::ListFilter {
                kind: Some(domain::KIND_LEARNING.into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(learnings.len(), 1);
        assert_eq!(svc.db.list_grants(&learning.id).unwrap().len(), 1);

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some(crate::sekai::learning::RECORD_LEARNING_ACTION.into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 2);
        for field in [
            "title",
            "prevention",
            "reasoning",
            "source_request_id",
            "score",
            "passed",
            "task_class",
            "model",
            "producer",
            "status",
        ] {
            assert_eq!(decisions[0].evidence[field], "[redacted]");
        }
    }

    #[tokio::test]
    async fn scoring_writer_uses_a_project_target_when_namespace_object_is_absent() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "project-acme".into(),
                kind: "project".into(),
                name: "acme".into(),
                namespace: "acme".into(),
                external_id: "project:acme".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        let request = scored_knowledge_request("acme", "project-request");
        let learning_id = scoring_learning_id("acme", "project-request");

        assert_eq!(
            svc.write_knowledge(&request).await.unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
        assert!(svc.db.get_object(&learning_id).unwrap().is_some());
        assert!(
            svc.db
                .get_link(&format!("{learning_id}->project-acme"))
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn scoring_writer_uses_an_explicit_service_grant_for_protected_targets() {
        let svc = service();
        let target_id = seed_scoring_namespace(&svc, "acme");
        grant_object_role(&svc, &target_id, "namespace-owner", security::Role::Admin);
        let request = scored_knowledge_request("acme", "protected-request");

        assert!(svc.write_knowledge(&request).await.is_err());

        grant_object_role(&svc, &target_id, "chisei.scoring", security::Role::Editor);
        assert_eq!(
            svc.write_knowledge(&request).await.unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
    }

    #[tokio::test]
    async fn scoring_writer_obeys_namespace_deny_and_approval_policies() {
        let denied_svc = service();
        seed_scoring_namespace(&denied_svc, "denied");
        denied_svc
            .db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "denied".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::from([(
                    crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
                    action_policy::ActionDecision::Deny,
                )]),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let denied_request = scored_knowledge_request("denied", "request-denied");
        let denied_id = scoring_learning_id("denied", "request-denied");

        assert_eq!(
            denied_svc.write_knowledge(&denied_request).await.unwrap(),
            KnowledgeWriteOutcome::PolicyDenied
        );
        assert!(denied_svc.db.get_object(&denied_id).unwrap().is_none());
        let denied_decisions = denied_svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some(crate::sekai::learning::RECORD_LEARNING_ACTION.into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(denied_decisions.len(), 1);
        assert_eq!(denied_decisions[0].reason, "action_policy_denied");
        assert_eq!(denied_decisions[0].evidence["policy_scope"], "denied");

        let approval_svc = service();
        seed_scoring_namespace(&approval_svc, "approval");
        approval_svc
            .db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "approval".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::from([(
                    crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
                    action_policy::ActionDecision::RequireApproval,
                )]),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let approval_request = scored_knowledge_request("approval", "request-approval");
        let approval_id = scoring_learning_id("approval", "request-approval");

        assert_eq!(
            approval_svc
                .write_knowledge(&approval_request)
                .await
                .unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
        assert!(approval_svc.db.get_object(&approval_id).unwrap().is_none());
        let pending = approval_svc
            .db
            .list_action_approvals(Some(action_approval::ApprovalStatus::Pending))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].action,
            crate::sekai::learning::RECORD_LEARNING_ACTION
        );
        assert_eq!(pending[0].params["id"], approval_id);
        assert_eq!(pending[0].work_unit, approval_id);
    }

    #[tokio::test]
    async fn execute_action_denied_by_policy_is_blocked_and_audited() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny destructive ops for this agent scope.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // Create a link then attempt to delete it (destructive).
        svc.db
            .create_link(&domain::Link {
                id: "obj-1->obj-1".into(),
                from_id: "obj-1".into(),
                to_id: "obj-1".into(),
                relation: "self".into(),
                created: 0,
            })
            .unwrap();

        let mut request = with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "delete_link".into(),
                params: HashMap::from([("id".into(), "obj-1->obj-1".into())]),
                actor: String::new(),
            }),
            dry_run: false,
        });
        request
            .metadata_mut()
            .insert("x-chisei-work-unit", "denied-action-work".parse().unwrap());
        let err = svc.execute_action(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // Link still exists (no mutation).
        assert!(svc.db.get_link("obj-1->obj-1").unwrap().is_some());

        // Denial was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("delete_link".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "action_policy_denied");
        assert_eq!(decisions[0].evidence["risk_class"], "destructive");
        assert_eq!(decisions[0].evidence["decision"], "deny");
        assert_eq!(decisions[0].evidence["policy_scope"], "agent:tester");
        assert_eq!(decisions[0].evidence["work_unit"], "denied-action-work");

        // The denial carries a verifiable attestation of the policy applied.
        // Attestation reads expose the policy snapshot, so they are gated on
        // action admin like direct policy reads.
        let attestation_id = decisions[0].evidence["attestation_id"].clone();
        let denied = svc
            .get_attestation(with_principal(GetAttestationRequest {
                id: attestation_id.clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        let hidden = svc
            .list_attestations(with_principal(ListAttestationsRequest {
                decision_id: String::new(),
                policy_scope: String::new(),
                limit: 0,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .attestations;
        assert!(hidden.is_empty());

        grant_action_admin(&svc);
        let listed = svc
            .list_attestations(with_principal(ListAttestationsRequest {
                decision_id: decisions[0].id.clone(),
                policy_scope: String::new(),
                limit: 0,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .attestations;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, attestation_id);
        assert_eq!(listed[0].decision, "deny");
        assert_eq!(listed[0].policy_scope, "agent:tester");
        assert_eq!(listed[0].inputs["action"], "delete_link");
        assert_eq!(listed[0].inputs["risk_class"], "destructive");

        let report = svc
            .verify_attestation(with_principal(VerifyAttestationRequest {
                id: attestation_id,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(report.ok, "{}", report.error);
        assert!(report.hash_ok);
        assert!(report.replay_ok);
        assert!(report.decision_linked);
        assert_eq!(report.replayed_decision, "deny");
    }

    #[tokio::test]
    async fn list_attestations_paginates_over_visible_rows_only() {
        let svc = service();
        // tester administers scope-a only; scope-b attestations stay hidden.
        let grant = security::Grant {
            id: "scope-a-admin".into(),
            object_id: action_object_id("scope-a"),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);

        for (scope, created) in [
            ("scope-a", 300),
            ("scope-b", 250),
            ("scope-a", 200),
            ("scope-b", 150),
            ("scope-a", 100),
        ] {
            let attestation =
                attestation::build_action_attestation(attestation::ActionAttestationInput {
                    decision_id: &format!("dec-{scope}-{created}"),
                    policy: &action_policy::ActionPolicy::allow_all(scope),
                    action: "set_property",
                    actor: "tester",
                    risk: action::RiskClass::Write,
                    namespace: "default",
                    decision: action_policy::ActionDecision::Allow,
                    created,
                });
            svc.db.insert_attestation(&attestation).unwrap();
        }

        // limit/offset apply to visible rows: skipping 1 of the 3 visible
        // scope-a rows (created DESC) yields the 200 and 100 entries, even
        // though hidden scope-b rows are interleaved in the raw table order.
        let page = svc
            .list_attestations(with_principal(ListAttestationsRequest {
                decision_id: String::new(),
                policy_scope: String::new(),
                limit: 2,
                offset: 1,
            }))
            .await
            .unwrap()
            .into_inner()
            .attestations;
        assert_eq!(page.len(), 2);
        assert!(page.iter().all(|a| a.policy_scope == "scope-a"));
        assert_eq!(page[0].created, 200);
        assert_eq!(page[1].created, 100);
    }

    #[tokio::test]
    async fn execute_action_without_policy_records_no_attestation() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "ok".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert!(!decisions[0].evidence.contains_key("attestation_id"));
        assert!(
            svc.db
                .list_attestations(None, None, 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn execute_action_allowed_by_policy_executes() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny only destructive; writes (set_property) are allowed.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn execute_action_without_policy_is_allowed_backward_compatible() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // A deny-all policy for a *different* agent must not affect this caller.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:someone-else".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn execute_action_require_approval_holds_and_returns_pending() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let mut req = Request::new(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        });
        req.metadata_mut().insert(
            "x-principal",
            tonic::metadata::MetadataValue::try_from("tester").unwrap(),
        );
        req.metadata_mut().insert(
            "x-chisei-work-unit",
            tonic::metadata::MetadataValue::try_from("wu-1").unwrap(),
        );

        let result = svc
            .execute_action(req)
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(result.decision, "require_approval");
        assert!(!result.approval_id.is_empty());

        // No mutation happened.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));

        // A pending approval was persisted with work-unit + exact params.
        let pending = svc
            .db
            .list_action_approvals(Some(action_approval::ApprovalStatus::Pending))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, result.approval_id);
        assert_eq!(pending[0].action, "set_property");
        assert_eq!(pending[0].work_unit, "wu-1");
        assert_eq!(pending[0].params["value"], "done");

        // The hold was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "action_approval_pending");
    }

    #[tokio::test]
    async fn execute_action_dry_run_reports_plan_without_mutating() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");

        let result = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();

        assert!(result.dry_run);
        assert_eq!(result.decision, "allow");
        assert_eq!(result.planned_ops, vec!["set_property obj-1.status"]);

        // No mutation happened.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));

        // A dry-run decision was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "execute_action_dry_run");
        assert_eq!(decisions[0].evidence["dry_run"], "true");
    }

    #[tokio::test]
    async fn execute_action_dry_run_surfaces_deny_without_erroring() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // Dry-run returns the plan + decision even though the policy denies.
        let result = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(result.dry_run);
        assert_eq!(result.decision, "deny");
        assert_eq!(result.planned_ops.len(), 1);
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    fn hold_set_property(svc: &SekaiServiceImpl) -> String {
        // Set a require-approval policy and hold a set_property action.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let approval = action_approval::ActionApproval::pending(
            "tester",
            "set_property",
            HashMap::from([
                ("id".to_string(), "obj-1".to_string()),
                ("key".to_string(), "status".to_string()),
                ("value".to_string(), "done".to_string()),
            ]),
            "wu-1",
            "agent:tester",
            "write",
            "obj-1",
            1000,
        );
        svc.db.create_action_approval(&approval).unwrap();
        approval.id
    }

    #[tokio::test]
    async fn approve_action_resumes_execution_and_audits() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let response = svc
            .approve_action(with_principal(ApproveActionRequest {
                approval_id: id.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.result.unwrap().decision, "approved");
        assert_eq!(response.approval.unwrap().status, "approved");

        // The held action executed.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");

        // Approval recorded + no longer pending.
        assert!(
            svc.db
                .list_action_approvals(Some(action_approval::ApprovalStatus::Pending))
                .unwrap()
                .is_empty()
        );
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        let approved = decisions
            .iter()
            .find(|d| d.reason == "action_approval_approved")
            .unwrap();
        assert_eq!(approved.evidence["work_unit"], "wu-1");
        assert_eq!(approved.evidence["risk_class"], "write");
        assert_eq!(approved.evidence["decision"], "require_approval");
        assert_eq!(approved.evidence["approval_status"], "approved");
        assert!(decisions.iter().any(|d| d.reason == "execute_action"));
    }

    #[tokio::test]
    async fn deny_action_drops_hold_without_executing() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let approval = svc
            .deny_action(with_principal(DenyActionRequest {
                approval_id: id,
                reason: "not now".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .approval
            .unwrap();
        assert_eq!(approval.status, "denied");
        assert_eq!(approval.outcome, "not now");

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        let denied = decisions
            .iter()
            .find(|decision| decision.reason == "action_approval_denied")
            .unwrap();
        assert_eq!(denied.evidence["work_unit"], "wu-1");
        assert_eq!(denied.evidence["risk_class"], "write");
        assert_eq!(denied.evidence["decision"], "deny");

        // No mutation.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn approve_action_rechecks_policy_and_blocks_when_now_denied() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        // Tighten the policy to deny before approving.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let err = svc
            .approve_action(with_principal(ApproveActionRequest { approval_id: id }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        // Still not executed.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn approve_action_requires_admin() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);
        let err = svc
            .approve_action(with_principal(ApproveActionRequest { approval_id: id }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn list_pending_approvals_filters_by_status() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let pending = svc
            .list_pending_approvals(with_principal(ListPendingApprovalsRequest {
                status: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .approvals;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        // Sensitive params would be redacted; here plain values pass through.
        assert_eq!(pending[0].params["value"], "done");
    }

    fn work_unit_request(
        action: &str,
        params: HashMap<String, String>,
        wu: &str,
    ) -> Request<ExecuteActionRequest> {
        let mut req = Request::new(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: action.into(),
                params,
                actor: String::new(),
            }),
            dry_run: false,
        });
        req.metadata_mut().insert(
            "x-principal",
            tonic::metadata::MetadataValue::try_from("tester").unwrap(),
        );
        req.metadata_mut().insert(
            "x-chisei-work-unit",
            tonic::metadata::MetadataValue::try_from(wu).unwrap(),
        );
        req
    }

    #[tokio::test]
    async fn blast_radius_delete_cap_hard_stops_after_limit() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Allow everything but cap deletes at 1 per work unit.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: Some(1),
            })
            .unwrap();
        for link_id in ["obj-1->a", "obj-1->b"] {
            svc.db
                .create_link(&domain::Link {
                    id: link_id.into(),
                    from_id: "obj-1".into(),
                    to_id: "obj-1".into(),
                    relation: "self".into(),
                    created: 0,
                })
                .unwrap();
        }

        // First delete within cap succeeds.
        svc.execute_action(work_unit_request(
            "delete_link",
            HashMap::from([("id".into(), "obj-1->a".into())]),
            "wu-1",
        ))
        .await
        .unwrap();

        // Second delete exceeds the cap and is hard-stopped.
        let err = svc
            .execute_action(work_unit_request(
                "delete_link",
                HashMap::from([("id".into(), "obj-1->b".into())]),
                "wu-1",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        // The second link still exists.
        assert!(svc.db.get_link("obj-1->b").unwrap().is_some());

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("delete_link".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.reason == "action_blast_radius_exceeded")
        );
    }

    #[tokio::test]
    async fn blast_radius_counters_are_scoped_per_work_unit() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: Some(1),
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // First mutation on wu-1 succeeds.
        svc.execute_action(work_unit_request(
            "set_property",
            HashMap::from([
                ("id".into(), "obj-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), "a".into()),
            ]),
            "wu-1",
        ))
        .await
        .unwrap();

        // Second mutation on wu-1 exceeds the cap.
        let err = svc
            .execute_action(work_unit_request(
                "set_property",
                HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "b".into()),
                ]),
                "wu-1",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // A different work unit has its own counter and succeeds.
        svc.execute_action(work_unit_request(
            "set_property",
            HashMap::from([
                ("id".into(), "obj-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), "c".into()),
            ]),
            "wu-2",
        ))
        .await
        .unwrap();
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "c");
    }

    #[tokio::test]
    async fn action_class_budget_denies_when_exhausted() {
        use crate::chisei::budget::{BudgetTracker, PeriodType};
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let budget = Arc::new(BudgetTracker::new(db.clone()));
        // Allow 1 write action, then deny.
        budget
            .set_limit("action:write", 1, PeriodType::Daily)
            .unwrap();
        let svc = SekaiServiceImpl::with_budget(db, budget.clone());
        seed_domain_object(&svc, "obj-1");

        // First write consumes the budget.
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "a".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        // Second write is denied by the exhausted budget.
        let err = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "b".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // Usage reflects exactly one recorded action.
        assert_eq!(budget.get_usage("action:write").tokens_used, 1);

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.reason == "action_budget_exceeded")
        );
    }

    #[tokio::test]
    async fn governed_tool_call_is_policy_checked_via_execute_action() {
        use crate::sekai::tool_bridge::ToolCall;

        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny destructive tool-calls for this agent.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        svc.db
            .create_link(&domain::Link {
                id: "obj-1->obj-1".into(),
                from_id: "obj-1".into(),
                to_id: "obj-1".into(),
                relation: "self".into(),
                created: 0,
            })
            .unwrap();

        // An allowed write tool-call funnels through ExecuteAction and runs.
        let write_call = ToolCall::from_json_arguments(
            "set_property",
            r#"{"id":"obj-1","key":"status","value":"done"}"#,
        )
        .unwrap();
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: write_call.action_name().to_string(),
                params: write_call.to_action_params().unwrap(),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        assert_eq!(
            svc.db.get_object("obj-1").unwrap().unwrap().properties["status"],
            "done"
        );

        // A destructive tool-call is denied by policy at the same boundary.
        let delete_call =
            ToolCall::from_json_arguments("delete_link", r#"{"id":"obj-1->obj-1"}"#).unwrap();
        let err = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: delete_call.action_name().to_string(),
                    params: delete_call.to_action_params().unwrap(),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("obj-1->obj-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn reserved_governance_objects_are_hidden_from_generic_crud() {
        let svc = service();
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy::allow_all("agent:tester"))
            .unwrap();

        // CreateObject cannot forge a governance kind (policy escalation guard).
        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "forged".into(),
                    kind: "action_policy".into(),
                    name: "forged".into(),
                    namespace: String::new(),
                    external_id: "action_policy:agent:tester".into(),
                    properties: HashMap::from([("default_decision".into(), "allow".into())]),
                    created: 0,
                    updated: 0,
                }),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // find_by_external_id hides the governance object.
        let err = svc
            .find_by_external_id(with_principal(FindByExternalIdRequest {
                external_id: "action_policy:agent:tester".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // ListObjects filtered by the reserved kind returns nothing.
        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "action_policy".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects.len(), 0);
        assert_eq!(listed.total, 0);
    }

    #[tokio::test]
    async fn held_approval_params_not_readable_via_get_object() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let result = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("api_key".into(), "super-secret".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        let approval_id = result.approval_id;
        assert!(!approval_id.is_empty());

        // The stored approval object (raw params incl. the secret) is not
        // reachable through the generic GetObject RPC.
        let err = svc
            .get_object(with_principal(GetObjectRequest {
                id: approval_id.clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Nor via a broad ListObjects for the reserved kind.
        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "action_approval".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects.len(), 0);
    }

    #[tokio::test]
    async fn blast_radius_object_not_writable_via_update_object() {
        let svc = service();
        svc.db.add_blast_radius("wu-1", 1, 0).unwrap();
        let counter_id = svc
            .db
            .find_by_external_id("action_blast_radius:wu-1")
            .unwrap()
            .unwrap()
            .id;
        let err = svc
            .update_object(with_principal(UpdateObjectRequest {
                object: Some(Object {
                    id: counter_id,
                    kind: "widget".into(),
                    name: "tamper".into(),
                    namespace: String::new(),
                    external_id: String::new(),
                    properties: HashMap::from([("mutations".into(), "0".into())]),
                    created: 0,
                    updated: 0,
                }),
                lease_precondition: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(svc.db.get_blast_radius("wu-1").unwrap(), (1, 0));
    }

    #[tokio::test]
    async fn approved_action_is_metered_against_blast_radius() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: Some(1),
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let mut ids = Vec::new();
        for value in ["a", "b"] {
            let mut req = Request::new(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), value.to_string()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            });
            req.metadata_mut().insert(
                "x-principal",
                tonic::metadata::MetadataValue::try_from("tester").unwrap(),
            );
            req.metadata_mut().insert(
                "x-chisei-work-unit",
                tonic::metadata::MetadataValue::try_from("wu-1").unwrap(),
            );
            let result = svc
                .execute_action(req)
                .await
                .unwrap()
                .into_inner()
                .result
                .unwrap();
            ids.push(result.approval_id);
        }

        // First approval executes and consumes the single-mutation cap.
        svc.approve_action(with_principal(ApproveActionRequest {
            approval_id: ids[0].clone(),
        }))
        .await
        .unwrap();

        // Second approval is hard-stopped by the per-work-unit blast-radius cap.
        let err = svc
            .approve_action(with_principal(ApproveActionRequest {
                approval_id: ids[1].clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn retrieve_context_enforces_graph_visibility_and_response_redaction() {
        let svc = service();
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "secret_note".into(),
            r#type: "string".into(),
            required: false,
            description: String::new(),
            enum_values: Vec::new(),
            link_kind: String::new(),
            compute_expr: String::new(),
            classification: "sensitive".into(),
            struct_fields: Vec::new(),
        });
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(schema_type),
            },
            "root",
        ))
        .await
        .unwrap();

        for (id, external_id, secret) in [
            ("context-root", "widget:context-root", true),
            ("context-allowed", "widget:context-allowed", false),
            ("context-denied", "widget:context-denied", false),
            ("behind-denied", "widget:behind-denied", false),
            ("behind-governance", "widget:behind-governance", false),
        ] {
            let mut properties = HashMap::from([("name".into(), id.into())]);
            if secret {
                properties.insert("secret_note".into(), "launch code".into());
            }
            let mut object = widget_object(id, properties);
            object.external_id = external_id.into();
            svc.create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(object),
                    lease_precondition: None,
                },
                "root",
            ))
            .await
            .unwrap();
        }
        svc.db
            .create_object(&domain::Object {
                id: "internal-policy".into(),
                kind: action_policy::ACTION_POLICY_KIND.into(),
                name: "internal".into(),
                namespace: String::new(),
                external_id: "policy:internal".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        for link in [
            domain::Link {
                id: "context-visible-link".into(),
                from_id: "context-root".into(),
                to_id: "context-allowed".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "context-denied-link".into(),
                from_id: "context-root".into(),
                to_id: "context-denied".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "context-behind-denied-link".into(),
                from_id: "context-denied".into(),
                to_id: "behind-denied".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "context-governance-link".into(),
                from_id: "context-root".into(),
                to_id: "internal-policy".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "context-behind-governance-link".into(),
                from_id: "internal-policy".into(),
                to_id: "behind-governance".into(),
                relation: "contains".into(),
                created: 0,
            },
        ] {
            svc.db.create_link(&link).unwrap();
        }
        let denied_grant = security::Grant {
            id: "context-denied-grant".into(),
            object_id: "context-denied".into(),
            principal: "bob".into(),
            role: security::Role::Viewer,
            created: 0,
        };
        svc.db.create_grant(&denied_grant).unwrap();
        svc.security.add_grant(&denied_grant);

        let response = svc
            .retrieve_context(with_named_principal(
                RetrieveContextRequest {
                    roots: vec![ContextRoot {
                        external_id: "widget:context-root".into(),
                        ..Default::default()
                    }],
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    max_depth: 3,
                    max_objects: 20,
                    max_links: 20,
                    kind_filter: Vec::new(),
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        let candidate_ids = response
            .candidates
            .iter()
            .map(|candidate| candidate.object.as_ref().unwrap().id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(candidate_ids, vec!["context-root", "context-allowed"]);
        assert_eq!(response.candidates[0].depth, 0);
        assert_eq!(
            response.epistemic_descriptor_version,
            EPISTEMIC_DESCRIPTOR_VERSION
        );
        let root_descriptor = response.candidates[0].descriptor.as_ref().unwrap();
        assert_eq!(
            root_descriptor.origin_class,
            crate::chisei::epistemic_descriptor::OriginClass::Asserted.as_str()
        );
        assert_eq!(
            root_descriptor.evidence_status,
            crate::chisei::epistemic_descriptor::EvidenceStatus::Unknown.as_str()
        );
        assert_eq!(
            response.candidates[0].object.as_ref().unwrap().properties["secret_note"],
            REDACTED_VALUE
        );
        assert_eq!(response.denied_objects, 0);
        assert_eq!(response.unresolved_roots, 0);
        assert_eq!(response.links.len(), 1);
        assert_eq!(response.links[0].id, "context-visible-link");
        assert!(!response.truncated);

        let denied_root = svc
            .retrieve_context(with_named_principal(
                RetrieveContextRequest {
                    roots: vec![ContextRoot {
                        object_id: "context-denied".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(denied_root.candidates.is_empty());
        assert_eq!(denied_root.denied_objects, 0);
        assert_eq!(denied_root.unresolved_roots, 1);
    }

    #[tokio::test]
    async fn retrieve_context_rejects_ambiguous_roots() {
        let err = service()
            .retrieve_context(with_principal(RetrieveContextRequest {
                roots: vec![ContextRoot {
                    object_id: "one".into(),
                    external_id: "two".into(),
                    link_id: String::new(),
                }],
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn retrieve_context_requires_an_authenticated_principal() {
        let err = service()
            .retrieve_context(Request::new(RetrieveContextRequest {
                roots: vec![ContextRoot {
                    object_id: "one".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    async fn seed_semantic_catalog_graph(svc: &SekaiServiceImpl) {
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            },
            "local",
        ))
        .await
        .unwrap();
        for (id, external_id, namespace) in [
            ("sem-root", "widget:sem-root", "acme"),
            ("sem-allowed", "widget:sem-allowed", "acme"),
            ("sem-denied", "widget:sem-denied", "acme"),
        ] {
            let mut object = widget_object(
                id,
                HashMap::from([("name".into(), id.into()), ("color".into(), "red".into())]),
            );
            object.external_id = external_id.into();
            object.namespace = namespace.into();
            svc.create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(object),
                    lease_precondition: None,
                },
                "local",
            ))
            .await
            .unwrap();
        }
        for link in [
            domain::Link {
                id: "sem-visible-link".into(),
                from_id: "sem-root".into(),
                to_id: "sem-allowed".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "sem-denied-link".into(),
                from_id: "sem-root".into(),
                to_id: "sem-denied".into(),
                relation: "contains".into(),
                created: 0,
            },
        ] {
            svc.db.create_link(&link).unwrap();
        }
        let denied_grant = security::Grant {
            id: "sem-denied-grant".into(),
            object_id: "sem-denied".into(),
            principal: "bob".into(),
            role: security::Role::Viewer,
            created: 0,
        };
        svc.db.create_grant(&denied_grant).unwrap();
        svc.security.add_grant(&denied_grant);

        grant_ontology_admin(svc);
        svc.create_ontology_class(with_named_principal(
            CreateOntologyClassRequest {
                class: Some(OntologyClass {
                    name: "WidgetClass".into(),
                    description: "semantic widget".into(),
                    mapped_kind: "widget".into(),
                    ..Default::default()
                }),
            },
            "tester",
        ))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn semantic_capabilities_are_discoverable_with_bounds_and_versions() {
        let svc = service();
        seed_semantic_catalog_graph(&svc).await;
        let discovered = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    page_size: 200,
                    product_tier_filter: "all".into(),
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        let by_name = discovered
            .capabilities
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect::<HashMap<_, _>>();
        for name in [
            semantic::CAPABILITY_EXPAND_RELATIONS,
            semantic::CAPABILITY_RETRIEVE_CONTEXT,
            semantic::CAPABILITY_EXPLAIN_DERIVATION,
        ] {
            let entry = by_name
                .get(name)
                .unwrap_or_else(|| panic!("missing semantic capability {name}"));
            assert_eq!(entry.contract_version, capability::CONTRACT_VERSION);
            assert!(
                entry
                    .policy_decision_points
                    .iter()
                    .any(|point| point == "namespace_access")
            );
            let limits = entry
                .limits
                .iter()
                .map(|limit| (limit.name.as_str(), limit.value))
                .collect::<HashMap<_, _>>();
            assert_eq!(
                limits.get("reasoning_profile_version"),
                Some(&semantic::REASONING_PROFILE_VERSION)
            );
            assert_eq!(
                limits.get("ontology_contract_version"),
                Some(&semantic::ONTOLOGY_CONTRACT_VERSION)
            );
            assert_eq!(
                limits.get("max_depth"),
                Some(&(u64::from(retrieval::MAX_DEPTH)))
            );
            assert_eq!(limits.get("supports_entailment"), Some(&1));
        }
    }

    #[tokio::test]
    async fn credential_rpcs_manage_credentials_without_exposing_hashes() {
        let svc = service();
        let created = svc
            .create_credential(with_named_principal(
                CreateCredentialRequest {
                    principal: "agent-a".into(),
                    managed_team_principal: false,
                    tenant_id: String::new(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(created.token.starts_with("sekai_"));
        assert_eq!(created.credential.unwrap().principal, "agent-a");

        let rotated = svc
            .rotate_credential(with_named_principal(
                RotateCredentialRequest {
                    principal: "agent-a".into(),
                    managed_team_principal: false,
                    tenant_id: String::new(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_ne!(rotated.token, created.token);

        let listed = svc
            .list_credentials(with_named_principal(
                ListCredentialsRequest {
                    tenant_id: String::new(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.credentials.len(), 2);
        assert_eq!(
            listed
                .credentials
                .iter()
                .filter(|credential| credential.status == "active")
                .count(),
            1
        );

        let revoked = svc
            .revoke_credential(with_named_principal(
                RevokeCredentialRequest {
                    principal: "agent-a".into(),
                    tenant_id: String::new(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner()
            .credential
            .unwrap();
        assert_eq!(revoked.status, "revoked");
    }

    #[tokio::test]
    async fn credential_rpcs_require_control_plane_admin() {
        let error = service()
            .list_credentials(with_named_principal(
                ListCredentialsRequest {
                    tenant_id: String::new(),
                },
                "tester",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn managed_team_classification_is_atomic_with_credential_rotation() {
        let svc = service();
        svc.create_credential(with_named_principal(
            CreateCredentialRequest {
                principal: "team-agent".into(),
                managed_team_principal: false,
                tenant_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap();
        assert!(!svc.db.is_team_principal("team-agent").unwrap());

        svc.rotate_credential(with_named_principal(
            RotateCredentialRequest {
                principal: "team-agent".into(),
                managed_team_principal: true,
                tenant_id: String::new(),
            },
            "local",
        ))
        .await
        .unwrap();
        assert!(svc.db.is_team_principal("team-agent").unwrap());
        assert_eq!(
            svc.db
                .list_credentials(Some("team-agent"), Some("active"))
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn credential_rpcs_reject_privileged_principal_names() {
        for principal in ["root", "local", "anonymous"] {
            let error = service()
                .create_credential(with_named_principal(
                    CreateCredentialRequest {
                        principal: principal.into(),
                        managed_team_principal: false,
                        tenant_id: String::new(),
                    },
                    "local",
                ))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn managed_credentials_reject_reserved_gateway_principal() {
        let error = service()
            .create_credential(with_named_principal(
                CreateCredentialRequest {
                    principal: "chisei-gateway".into(),
                    managed_team_principal: true,
                    tenant_id: String::new(),
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn provenance_report_is_served_without_direct_database_access() {
        let svc = service();
        svc.create_contention_scope(with_named_principal(
            CreateContentionScopeRequest {
                request_id: "provenance-scope".into(),
                scope: Some(ContentionScope {
                    id: "provenance-scope".into(),
                    name: "provenance".into(),
                    max_concurrency: 1,
                    admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                    heartbeat_ttl_seconds: 30,
                    timeout_seconds: 60,
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.create_work_unit(with_named_principal(
            CreateWorkUnitRequest {
                request_id: "work-unit-1".into(),
                work_unit: Some(WorkUnit {
                    id: "work-unit-1".into(),
                    kind: "analysis".into(),
                    actor: "local".into(),
                    requested_spec: "assemble provenance".into(),
                    scope_id: "provenance-scope".into(),
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 1,
                    idempotency_key: "work-unit-1".into(),
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        let response = svc
            .get_provenance_report(with_named_principal(
                GetProvenanceReportRequest {
                    work_unit_id: "work-unit-1".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(response.report.contains("work-unit-1"));
    }

    async fn configured_evidence_service(with_target: bool) -> SekaiServiceImpl {
        let svc = service();
        svc.db
            .upsert_evidence_producer(
                &DomainEvidenceProducerCapability {
                    producer_identity: "producer:checks".into(),
                    config_version: 1,
                    source_types: vec!["verification_system".into()],
                    source_instances: vec!["checks-primary".into()],
                    namespaces: vec!["acme".into()],
                    evidence_types: vec!["verification.result".into()],
                    target_kinds: vec!["service".into()],
                    classification_ceiling: evidence_domain::EvidenceClassification::Confidential,
                    allowed_intents: vec![
                        evidence_domain::EvidenceIntent::Upsert,
                        evidence_domain::EvidenceIntent::Retract,
                        evidence_domain::EvidenceIntent::MarkStale,
                    ],
                    allow_operation_attachment: false,
                    replay_window_ms: 60_000,
                    max_clock_skew_ms: 1_000,
                    max_payload_bytes: 4_096,
                    max_relationships: 8,
                    rate_limit_per_minute: 100,
                    max_retained_submissions: 100_000,
                    revoked: false,
                },
                now_millis(),
            )
            .unwrap();
        svc.register_evidence_schema(with_named_principal(
            RegisterEvidenceSchemaRequest {
                definition: Some(EvidenceSchemaDefinition {
                    schema_id: "verification.result".into(),
                    schema_version: "1.0.0".into(),
                    evidence_type: "verification.result".into(),
                    compatible_versions: vec![],
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        if with_target {
            svc.db
                .create_object(&domain::Object {
                    id: "service-1".into(),
                    kind: "service".into(),
                    name: "payments".into(),
                    namespace: "acme".into(),
                    external_id: "service:payments".into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                })
                .unwrap();
        }
        svc
    }

    fn proto_evidence(record: &str, sequence: i64) -> EvidenceEnvelope {
        let content = serde_json::json!({"result": "passed", "sequence": sequence});
        EvidenceEnvelope {
            contract_version: evidence_domain::EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "verification_system".into(),
            source_instance: "checks-primary".into(),
            source_record_id: record.into(),
            source_version: format!("v{sequence}"),
            source_sequence: sequence,
            namespace: "acme".into(),
            target_external_id: "service:payments".into(),
            target_kind: "service".into(),
            evidence_type: "verification.result".into(),
            signal: "verification".into(),
            schema_id: "verification.result".into(),
            schema_version: "1.0.0".into(),
            schema_compatibility: "exact".into(),
            observed_at_ms: now_millis(),
            collected_at_ms: now_millis(),
            expires_at_ms: None,
            content_json: serde_json::to_vec(&content).unwrap(),
            relationships: vec![],
            producer_identity: "producer:checks".into(),
            confidence_bps: 9_000,
            classification: "internal".into(),
            provenance: HashMap::new(),
            idempotency_key: format!("delivery-{record}-{sequence}"),
            content_digest: crate::sekai::evidence_store::canonical_content_digest(&content)
                .unwrap(),
            intent: "upsert".into(),
            causality: None,
        }
    }

    #[tokio::test]
    async fn evidence_admission_lifecycle_projects_and_resolves_domain_outcome() {
        let svc = configured_evidence_service(true).await;
        let envelope = from_proto_evidence_envelope(proto_evidence("lifecycle-run", 1)).unwrap();

        let outcome = EvidenceAdmissionLifecycle::new(&svc.db)
            .admit(&envelope, "producer:checks", now_millis())
            .unwrap();

        assert!(outcome.admitted);
        assert!(!outcome.deduplicated);
        assert!(
            outcome
                .projection
                .as_ref()
                .is_some_and(|value| value.projected)
        );
        assert_eq!(outcome.submission.lifecycle_state.as_str(), "available");
        assert!(!outcome.execution_recorded);
    }

    #[tokio::test]
    async fn evidence_control_plane_authenticates_and_filters_inspection() {
        let svc = configured_evidence_service(true).await;
        let submitted = svc
            .submit_evidence(with_named_principal(
                SubmitEvidenceRequest {
                    envelope: Some(proto_evidence("run-1", 1)),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(submitted.admitted);
        assert!(submitted.projected);
        let submission = submitted.submission.unwrap();
        assert_eq!(submission.lifecycle_state, "available");
        let descriptor = submission.descriptor.as_ref().unwrap();
        assert_eq!(
            descriptor.origin_class,
            crate::chisei::epistemic_descriptor::OriginClass::Asserted.as_str()
        );
        assert_eq!(
            descriptor.evidence_status,
            crate::chisei::epistemic_descriptor::EvidenceStatus::Unknown.as_str()
        );
        assert_eq!(
            descriptor.lifecycle_status,
            crate::chisei::epistemic_descriptor::LifecycleStatus::Current.as_str()
        );
        assert_eq!(
            descriptor.source_digests,
            vec![submission.content_digest.clone()]
        );

        let inspected = svc
            .get_evidence_submission(with_named_principal(
                GetEvidenceSubmissionRequest {
                    submission_id: submission.id.clone(),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(inspected.lifecycle_history.last().unwrap(), "available");
        assert_eq!(
            inspected
                .submission
                .unwrap()
                .descriptor
                .unwrap()
                .lifecycle_status,
            crate::chisei::epistemic_descriptor::LifecycleStatus::Current.as_str()
        );
        let denied = svc
            .get_evidence_submission(with_named_principal(
                GetEvidenceSubmissionRequest {
                    submission_id: submission.id,
                },
                "producer:other",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let listed = svc
            .list_evidence_submissions(with_named_principal(
                ListEvidenceSubmissionsRequest {
                    producer_identity: String::new(),
                    source_instance: "checks-primary".into(),
                    namespace: "acme".into(),
                    lifecycle_state: "available".into(),
                    target_external_id: "service:payments".into(),
                    evidence_type: "verification.result".into(),
                    limit: 10,
                    offset: 0,
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.submissions.len(), 1);
    }

    #[test]
    fn evidence_content_lifecycle_is_fail_closed() {
        use evidence_domain::EvidenceLifecycleState::*;

        for state in [Available, Superseded, Retracted, Stale] {
            assert!(evidence_content_is_readable(state), "{state:?}");
        }
        for state in [
            Received,
            Validated,
            Deduplicated,
            Authorized,
            Projected,
            Rejected,
            Quarantined,
        ] {
            assert!(!evidence_content_is_readable(state), "{state:?}");
        }
    }

    #[test]
    fn reserved_governance_kinds_are_exclusion_safe() {
        // Every reserved kind must be ASCII alphanumeric/underscore so the
        // static SQL exclusion covers it; a kind with special characters would
        // fail the query closed rather than silently re-opening the leak.
        for kind in RESERVED_GOVERNANCE_KINDS {
            assert!(
                !kind.is_empty() && kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "reserved governance kind {kind:?} is not exclusion-safe"
            );
        }
    }

    #[tokio::test]
    async fn capability_discovery_requires_authentication_and_stable_version() {
        let svc = service();
        let unauthenticated = svc
            .discover_capabilities(Request::new(DiscoverCapabilitiesRequest {
                namespace: "acme".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);

        let blank_principal = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    ..Default::default()
                },
                ",",
            ))
            .await
            .unwrap_err();
        assert_eq!(blank_principal.code(), tonic::Code::Unauthenticated);

        let unsupported = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    contract_version: "2.0".into(),
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(unsupported.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            unsupported.message(),
            "unsupported capability catalog contract version"
        );
    }

    #[tokio::test]
    async fn capability_discovery_defaults_to_core_and_requires_explicit_expansion() {
        let svc = service();
        let core = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    page_size: 200,
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(!core.capabilities.is_empty());
        assert!(
            core.capabilities
                .iter()
                .all(|entry| entry.product_tier == "core")
        );

        let all = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    page_size: 200,
                    product_tier_filter: "all".into(),
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(all.total_size > core.total_size);
        assert!(
            all.capabilities
                .iter()
                .any(|entry| entry.product_tier != "core")
        );
    }

    #[tokio::test]
    async fn capability_discovery_rejects_a_stale_pinned_snapshot_without_metadata() {
        let svc = service();
        let first = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    page_size: 1,
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            },
            "local",
        ))
        .await
        .unwrap();

        let stale = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    catalog_version: first.catalog_version,
                    page_size: 1,
                    page_token: first.next_page_token,
                    product_tier_filter: String::new(),
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::Aborted);
        assert_eq!(stale.message(), "capability catalog version unavailable");
        assert!(!stale.message().contains("widget"));
    }

    #[tokio::test]
    async fn capability_catalog_never_advertises_or_executes_reserved_creation() {
        let svc = service();
        let catalog = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    page_size: 200,
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        for kind in RESERVED_GOVERNANCE_KINDS {
            assert!(catalog.capabilities.iter().all(|entry| {
                entry
                    .object_type
                    .as_ref()
                    .is_none_or(|object_type| object_type.kind != *kind)
                    && entry.name != format!("sekai.actions.create_object.{kind}")
            }));
        }

        let params = HashMap::from([
            ("id".into(), "forged-policy".into()),
            ("kind".into(), action_policy::ACTION_POLICY_KIND.into()),
            ("name".into(), "forged".into()),
            ("namespace".into(), "acme".into()),
        ]);
        let denied = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "create_object".into(),
                        params: params.clone(),
                        actor: String::new(),
                    }),
                    dry_run: false,
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_object("forged-policy").unwrap().is_none());

        let resumed = svc
            .run_action_effect("create_object", &params, "local", &["local".into()])
            .unwrap_err();
        assert_eq!(resumed.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_object("forged-policy").unwrap().is_none());
    }
}

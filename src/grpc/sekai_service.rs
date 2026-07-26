#![allow(clippy::result_large_err, clippy::collapsible_if, clippy::manual_clamp)]

use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

use super::pb::sekai::sekai_service_server::SekaiService;
use super::pb::sekai::*;
use crate::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    ReceiptSurface, UncoveredSurface,
};
use crate::chisei::scoring::{KnowledgeWriteOutcome, KnowledgeWriteRequest, KnowledgeWriter};
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain;
use crate::gateway_keys::hash_gateway_key;
use crate::sekai::action::{self, ActionExecutor, RiskClass};
use crate::sekai::action_approval;
use crate::sekai::action_policy::{self, ActionDecision};
use crate::sekai::attestation;
use crate::sekai::capability;
use crate::sekai::capability_package as package_domain;
use crate::sekai::evidence as evidence_domain;
use crate::sekai::evidence_projection::EvidenceProjectionOutcome;
use crate::sekai::evidence_store::{
    DEFAULT_MAX_RETAINED_EVIDENCE_SUBMISSIONS, EvidenceAdmission,
    EvidenceProducerCapability as DomainEvidenceProducerCapability,
    EvidenceSchemaDefinition as DomainEvidenceSchemaDefinition, EvidenceSubmissionFilter,
    EvidenceSubmissionRecord as DomainEvidenceSubmissionRecord,
};
use crate::sekai::handoff as handoff_domain;
use crate::sekai::markings;
use crate::sekai::schema::{self, SchemaRegistry};
use crate::sekai::security::SecurityChecker;
use crate::sekai::{
    audit, compute, coordination, dataset, function, ontology, retrieval, security,
};
use uuid::Uuid;

const REDACTED_VALUE: &str = "[redacted]";

pub struct SekaiServiceImpl {
    db: Arc<RuntimeDb>,
    actions: Arc<RwLock<ActionExecutor>>,
    security: Arc<SecurityChecker>,
    schema: Arc<RwLock<SchemaRegistry>>,
    schema_unavailable_error: Arc<RwLock<Option<String>>>,
    schema_load_errors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    budget: Option<Arc<crate::chisei::budget::BudgetTracker>>,
    gateway_schema_principals: Vec<String>,
}

struct CatalogReceiptGuard<'a> {
    service: &'a SekaiServiceImpl,
    operation_id: String,
    namespace: String,
    actor: String,
    capability_name: String,
    catalog_version: Option<String>,
    policy_decision: Option<String>,
    budget_decision: Option<String>,
    finalized: bool,
}

impl CatalogReceiptGuard<'_> {
    fn mark_policy_decided(&mut self, decision: &str) {
        self.policy_decision = Some(decision.to_string());
    }

    fn mark_budget_decided(&mut self, decision: &str) {
        self.budget_decision = Some(decision.to_string());
    }

    fn finalize(&mut self, decision: &str, outcome: &str) -> Result<(), Status> {
        self.service.record_catalog_invocation_receipt(
            &self.operation_id,
            &self.namespace,
            &self.actor,
            &self.capability_name,
            self.catalog_version.as_deref(),
            decision,
            outcome,
            false,
        )?;
        self.finalized = true;
        Ok(())
    }
}

impl Drop for CatalogReceiptGuard<'_> {
    fn drop(&mut self) {
        if !self.finalized {
            let budget_outcome = self
                .budget_decision
                .as_deref()
                .map(|decision| format!("invocation_failed_after_budget:{decision}"));
            let (decision, outcome) = if let Some(outcome) = budget_outcome.as_deref() {
                (self.policy_decision.as_deref().unwrap_or("allow"), outcome)
            } else {
                self.policy_decision
                    .as_deref()
                    .map(|decision| (decision, "invocation_failed_after_policy"))
                    .unwrap_or(("refuse", "invocation_failed"))
            };
            let _ = self.service.record_catalog_invocation_receipt(
                &self.operation_id,
                &self.namespace,
                &self.actor,
                &self.capability_name,
                self.catalog_version.as_deref(),
                decision,
                outcome,
                false,
            );
        }
    }
}

impl SekaiServiceImpl {
    #[allow(clippy::too_many_arguments)]
    fn record_catalog_invocation_receipt(
        &self,
        operation_id: &str,
        namespace: &str,
        actor: &str,
        capability_name: &str,
        catalog_version: Option<&str>,
        decision: &str,
        outcome: &str,
        insert_only: bool,
    ) -> Result<(), Status> {
        let now = now_millis();
        let started_at_ms = if insert_only {
            now
        } else {
            self.db
                .get_operation_receipt(operation_id)
                .map_err(Status::internal)?
                .map(|receipt| receipt.started_at_ms)
                .unwrap_or(now)
        };
        let event = |suffix: &str, parent: Option<&str>, kind: ReceiptEventKind, attributes| {
            OperationReceiptEvent {
                event_id: format!("{operation_id}:{suffix}"),
                operation_id: operation_id.into(),
                parent_event_id: parent.map(|value| format!("{operation_id}:{value}")),
                timestamp_ms: now,
                surface: kind.surface(),
                kind,
                actor: actor.into(),
                references: Vec::new(),
                attributes,
            }
        };
        let attributes =
            |key: &str, value: &str| BTreeMap::from([(key.to_string(), value.to_string())]);
        let outcome_attributes = || {
            if let Some(approval_id) = outcome.strip_prefix("approval_required:") {
                BTreeMap::from([
                    ("outcome".into(), "approval_required".into()),
                    ("approval_id".into(), approval_id.into()),
                ])
            } else {
                attributes("outcome", outcome)
            }
        };
        let mut intent_attributes = attributes("capability", capability_name);
        if let Some(catalog_version) = catalog_version.filter(|value| !value.trim().is_empty()) {
            intent_attributes.insert("reported_catalog_version".into(), catalog_version.into());
        }
        let mut intent = event(
            "intent",
            None,
            ReceiptEventKind::IntentRecorded,
            intent_attributes,
        );
        intent.timestamp_ms = started_at_ms;
        let (completed_at_ms, events, uncovered_surfaces) = if insert_only && decision == "pending"
        {
            (None, vec![intent], Vec::new())
        } else if decision == "refuse" {
            (
                Some(now),
                vec![
                    intent,
                    event(
                        "outcome",
                        Some("intent"),
                        ReceiptEventKind::OutcomeRecorded,
                        outcome_attributes(),
                    ),
                ],
                [
                    ReceiptSurface::Policy,
                    ReceiptSurface::Routing,
                    ReceiptSurface::Budget,
                ]
                .into_iter()
                .map(|surface| UncoveredSurface {
                    surface,
                    reason: "invocation failed before this decision point".into(),
                })
                .collect(),
            )
        } else if let Some(budget_decision) =
            outcome.strip_prefix("invocation_failed_after_budget:")
        {
            (
                Some(now),
                vec![
                    intent,
                    event(
                        "policy",
                        Some("intent"),
                        ReceiptEventKind::PolicyDecided,
                        attributes("decision", decision),
                    ),
                    event(
                        "routing",
                        Some("policy"),
                        ReceiptEventKind::RouteSelected,
                        attributes("route", "native"),
                    ),
                    event(
                        "budget",
                        Some("routing"),
                        ReceiptEventKind::BudgetDecided,
                        attributes("decision", budget_decision),
                    ),
                    event(
                        "outcome",
                        Some("budget"),
                        ReceiptEventKind::OutcomeRecorded,
                        attributes("outcome", "invocation_failed_after_budget"),
                    ),
                ],
                Vec::new(),
            )
        } else if outcome == "invocation_failed_after_policy" {
            (
                Some(now),
                vec![
                    intent,
                    event(
                        "policy",
                        Some("intent"),
                        ReceiptEventKind::PolicyDecided,
                        attributes("decision", decision),
                    ),
                    event(
                        "routing",
                        Some("policy"),
                        ReceiptEventKind::RouteSelected,
                        attributes("route", "native"),
                    ),
                    event(
                        "outcome",
                        Some("routing"),
                        ReceiptEventKind::OutcomeRecorded,
                        outcome_attributes(),
                    ),
                ],
                vec![UncoveredSurface {
                    surface: ReceiptSurface::Budget,
                    reason: "invocation failed before budget decision".into(),
                }],
            )
        } else {
            let budget_decision = match outcome.split_once(':').map_or(outcome, |value| value.0) {
                "dry_run" => "not_applicable_dry_run",
                "approval_required" => "deferred_pending_approval",
                "denied" | "capability_unavailable" => "not_applicable_policy_denied",
                _ => "checked_at_invocation",
            };
            (
                Some(now),
                vec![
                    intent,
                    event(
                        "policy",
                        Some("intent"),
                        ReceiptEventKind::PolicyDecided,
                        attributes("decision", decision),
                    ),
                    event(
                        "routing",
                        Some("policy"),
                        ReceiptEventKind::RouteSelected,
                        attributes("route", "native"),
                    ),
                    event(
                        "budget",
                        Some("routing"),
                        ReceiptEventKind::BudgetDecided,
                        attributes("decision", budget_decision),
                    ),
                    event(
                        "outcome",
                        Some("budget"),
                        ReceiptEventKind::OutcomeRecorded,
                        outcome_attributes(),
                    ),
                ],
                Vec::new(),
            )
        };
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.into(),
            parent_operation_id: None,
            namespace: namespace.into(),
            operation_class: "catalog_invocation".into(),
            initiating_actor: actor.into(),
            schema_version: capability::CONTRACT_VERSION.into(),
            policy_version: "live_invocation_check".into(),
            started_at_ms,
            completed_at_ms,
            events,
            uncovered_surfaces,
            reporter_grants: Vec::new(),
        };
        if insert_only {
            return self.db.insert_operation_receipt(&receipt).map_err(|error| {
                if error.contains("UNIQUE constraint failed") {
                    Status::already_exists("operation receipt already exists")
                } else {
                    Status::internal(error)
                }
            });
        } else {
            self.db.put_operation_receipt(&receipt)
        }
        .map_err(Status::internal)
    }

    fn resolve_catalog_approval_receipt(
        &self,
        operation_id: &str,
        approval_id: &str,
        actor: &str,
        decision: &str,
        action: Option<&str>,
        outcome: &str,
    ) -> Result<(), Status> {
        if operation_id.is_empty() {
            return Ok(());
        }
        let Some(mut receipt) = self
            .db
            .get_operation_receipt(operation_id)
            .map_err(Status::internal)?
        else {
            return Ok(());
        };
        if receipt.operation_class != "catalog_invocation"
            || !receipt.events.iter().any(|event| {
                event.kind == ReceiptEventKind::OutcomeRecorded
                    && event.attributes.get("approval_id").map(String::as_str) == Some(approval_id)
            })
        {
            return Ok(());
        }
        receipt
            .events
            .retain(|event| event.kind != ReceiptEventKind::OutcomeRecorded);
        let now = now_millis();
        let event =
            |suffix: &str,
             parent: &str,
             kind: ReceiptEventKind,
             attributes: BTreeMap<String, String>| OperationReceiptEvent {
                event_id: format!("{operation_id}:{suffix}"),
                operation_id: operation_id.into(),
                parent_event_id: Some(format!("{operation_id}:{parent}")),
                timestamp_ms: now,
                kind,
                surface: kind.surface(),
                actor: actor.into(),
                references: Vec::new(),
                attributes,
            };
        receipt.events.push(event(
            "approval",
            "budget",
            ReceiptEventKind::ApprovalDecided,
            BTreeMap::from([
                ("approval_id".into(), approval_id.into()),
                ("decision".into(), decision.into()),
            ]),
        ));
        let outcome_parent = if let Some(action) = action {
            receipt.events.push(event(
                "action",
                "approval",
                ReceiptEventKind::ActionPerformed,
                BTreeMap::from([("action".into(), action.into())]),
            ));
            "action"
        } else {
            "approval"
        };
        receipt.events.push(event(
            "outcome",
            outcome_parent,
            ReceiptEventKind::OutcomeRecorded,
            BTreeMap::from([("outcome".into(), outcome.into())]),
        ));
        receipt.completed_at_ms = Some(now);
        self.db
            .put_operation_receipt(&receipt)
            .map_err(Status::internal)
    }

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
            security,
            schema,
            schema_unavailable_error: Arc::new(RwLock::new(schema_unavailable_error)),
            schema_load_errors: Arc::new(RwLock::new(schema_load_errors)),
            budget: None,
            gateway_schema_principals,
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

    fn discoverable_capabilities(
        &self,
        namespace: &str,
        principals: &[String],
    ) -> Result<Vec<CapabilityEntry>, Status> {
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
        entries.push(retrieve_context_capability());
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
    fn admit_and_project_evidence(
        &self,
        envelope: &evidence_domain::EvidenceEnvelope,
        producer: &str,
        now_ms: i64,
    ) -> Result<EvidenceSubmissionResult, Status> {
        let mut admission = self
            .db
            .submit_evidence(envelope, producer, now_ms)
            .map_err(|_| Status::internal("evidence admission failed"))?;
        if admission.accepted
            && admission.submission.evidence_type
                == crate::sekai::execution_evidence::EXECUTION_EVIDENCE_TYPE
        {
            if let Err(error) = self
                .db
                .validate_execution_evidence_envelope(envelope, producer)
            {
                admission = self
                    .db
                    .reject_evidence_submission(
                        &admission.submission.id,
                        now_ms,
                        "invalid_execution_evidence",
                        &error,
                    )
                    .map_err(|_| Status::internal("evidence rejection failed"))?;
            }
        }
        let projection = if admission.accepted {
            Some(
                self.db
                    .project_evidence_submission(&admission.submission.id, now_ms)
                    .map_err(|_| Status::internal("evidence projection failed"))?,
            )
        } else {
            None
        };
        if let Some(object_id) = projection
            .as_ref()
            .and_then(|projection| projection.evidence_object_id.as_deref())
        {
            for grant in self.db.list_grants(object_id).map_err(Status::internal)? {
                self.security.add_grant(&grant);
            }
        }
        if admission.accepted
            && admission.submission.evidence_type
                == crate::sekai::execution_evidence::EXECUTION_EVIDENCE_TYPE
        {
            self.db
                .record_execution_evidence(&admission.submission.id)
                .map_err(Status::failed_precondition)?;
        }
        evidence_submission_result(&self.db, admission, projection)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_evidence_lifecycle_marker(
        &self,
        submission_id: String,
        source_version: String,
        source_sequence: i64,
        idempotency_key: String,
        observed_at_ms: i64,
        intent: evidence_domain::EvidenceIntent,
        principals: &[String],
    ) -> Result<EvidenceSubmissionResult, Status> {
        let original = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("evidence submission not found"))?;
        if !principals.contains(&original.producer_identity) {
            return Err(Status::permission_denied(
                "only the authenticated source producer may change evidence lifecycle",
            ));
        }
        if original.intent != evidence_domain::EvidenceIntent::Upsert
            || original.lifecycle_state != evidence_domain::EvidenceLifecycleState::Available
        {
            return Err(Status::failed_precondition(
                "only currently available source evidence can receive a lifecycle marker",
            ));
        }
        if source_version.trim().is_empty()
            || idempotency_key.trim().is_empty()
            || source_sequence <= original.source_sequence
        {
            return Err(Status::invalid_argument(
                "lifecycle marker requires a new source version, idempotency key, and higher source sequence",
            ));
        }
        let now_ms = now_millis();
        let mut marker = original
            .envelope
            .ok_or_else(|| Status::internal("available evidence envelope missing"))?;
        marker.source_version = source_version;
        marker.source_sequence = source_sequence;
        marker.observed_at_ms = if observed_at_ms == 0 {
            now_ms
        } else {
            observed_at_ms
        };
        marker.collected_at_ms = now_ms;
        marker.expires_at_ms = None;
        marker.relationships.clear();
        marker.content = serde_json::json!({
            "lifecycle_intent": match intent {
                evidence_domain::EvidenceIntent::Retract => "retract",
                evidence_domain::EvidenceIntent::MarkStale => "mark_stale",
                evidence_domain::EvidenceIntent::Upsert => "upsert",
            },
            "prior_content_digest": original.content_digest,
        });
        marker.content_digest =
            crate::sekai::evidence_store::canonical_content_digest(&marker.content)
                .map_err(Status::internal)?;
        marker.idempotency_key = idempotency_key;
        marker.intent = intent;
        marker
            .provenance
            .insert("lifecycle_marker".into(), "server_constructed".into());
        self.admit_and_project_evidence(&marker, &original.producer_identity, now_ms)
    }
}

fn base_capability(
    name: String,
    description: String,
    kind: &str,
    input_type: &str,
    output_type: &str,
) -> CapabilityEntry {
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

fn retrieve_context_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        "sekai.context.retrieve".into(),
        "Retrieve bounded, authorized context candidates.".into(),
        "retrieval",
        "sekai.RetrieveContextRequest",
        "sekai.RetrieveContextResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "classification".into(),
    ];
    entry.limits = vec![
        CapabilityLimit {
            name: "max_depth".into(),
            value: 3,
        },
        CapabilityLimit {
            name: "max_links".into(),
            value: 200,
        },
        CapabilityLimit {
            name: "max_objects".into(),
            value: 100,
        },
        CapabilityLimit {
            name: "max_source_rows".into(),
            value: 1000,
        },
        CapabilityLimit {
            name: "max_derived_rows".into(),
            value: 500,
        },
        CapabilityLimit {
            name: "max_derivation_steps".into(),
            value: 32,
        },
        CapabilityLimit {
            name: "max_time_ms".into(),
            value: 1000,
        },
        CapabilityLimit {
            name: "max_explanation_bytes".into(),
            value: 16 * 1024 * 1024,
        },
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

fn to_proto_evidence_envelope(envelope: &evidence_domain::EvidenceEnvelope) -> EvidenceEnvelope {
    EvidenceEnvelope {
        contract_version: envelope.contract_version.clone(),
        source_type: envelope.source_type.clone(),
        source_instance: envelope.source_instance.clone(),
        source_record_id: envelope.source_record_id.clone(),
        source_version: envelope.source_version.clone(),
        source_sequence: envelope.source_sequence,
        namespace: envelope.target.namespace.clone(),
        target_external_id: envelope.target.object_external_id.clone(),
        target_kind: envelope.target.object_kind.clone(),
        evidence_type: envelope.evidence_type.clone(),
        signal: envelope.signal.as_str().into(),
        schema_id: envelope.schema_id.clone(),
        schema_version: envelope.schema_version.clone(),
        schema_compatibility: match envelope.schema_compatibility {
            evidence_domain::SchemaCompatibility::Exact => "exact",
            evidence_domain::SchemaCompatibility::BackwardCompatible => "backward_compatible",
        }
        .into(),
        observed_at_ms: envelope.observed_at_ms,
        collected_at_ms: envelope.collected_at_ms,
        expires_at_ms: envelope.expires_at_ms,
        content_json: serde_json::to_vec(&envelope.content)
            .expect("validated evidence content must serialize"),
        relationships: envelope
            .relationships
            .iter()
            .map(|relationship| EvidenceRelationship {
                relation: relationship.relation.clone(),
                target_source_type: relationship.target_source_type.clone(),
                target_source_instance: relationship.target_source_instance.clone(),
                target_source_record_id: relationship.target_source_record_id.clone(),
            })
            .collect(),
        producer_identity: envelope.producer_identity.clone(),
        confidence_bps: u32::from(envelope.confidence_bps),
        classification: envelope.classification.as_str().into(),
        provenance: envelope.provenance.clone().into_iter().collect(),
        idempotency_key: envelope.idempotency_key.clone(),
        content_digest: envelope.content_digest.clone(),
        intent: match envelope.intent {
            evidence_domain::EvidenceIntent::Upsert => "upsert",
            evidence_domain::EvidenceIntent::Retract => "retract",
            evidence_domain::EvidenceIntent::MarkStale => "mark_stale",
        }
        .into(),
        causality: envelope
            .causality
            .as_ref()
            .map(|causality| EvidenceCausality {
                operation_id: causality.operation_id.clone().unwrap_or_default(),
                parent_operation_id: causality.parent_operation_id.clone().unwrap_or_default(),
                attempt_id: causality.attempt_id.clone().unwrap_or_default(),
                model_call_id: causality.model_call_id.clone().unwrap_or_default(),
                subject_references: causality.subject_references.clone(),
                trace_context: causality.trace_context.clone().into_iter().collect(),
            }),
    }
}

fn evidence_content_is_readable(state: evidence_domain::EvidenceLifecycleState) -> bool {
    matches!(
        state,
        evidence_domain::EvidenceLifecycleState::Available
            | evidence_domain::EvidenceLifecycleState::Superseded
            | evidence_domain::EvidenceLifecycleState::Retracted
            | evidence_domain::EvidenceLifecycleState::Stale
    )
}

fn from_proto_evidence_producer(
    capability: EvidenceProducerCapability,
) -> Result<DomainEvidenceProducerCapability, Status> {
    let max_payload_bytes = usize::try_from(capability.max_payload_bytes)
        .map_err(|_| Status::invalid_argument("max_payload_bytes out of range"))?;
    let max_relationships = usize::try_from(capability.max_relationships)
        .map_err(|_| Status::invalid_argument("max_relationships out of range"))?;
    let allowed_intents = capability
        .allowed_intents
        .iter()
        .map(|intent| parse_evidence_intent(intent))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DomainEvidenceProducerCapability {
        producer_identity: capability.producer_identity,
        config_version: capability.config_version,
        source_types: capability.source_types,
        source_instances: capability.source_instances,
        namespaces: capability.namespaces,
        evidence_types: capability.evidence_types,
        target_kinds: capability.target_kinds,
        classification_ceiling: parse_evidence_classification(&capability.classification_ceiling)?,
        allowed_intents,
        allow_operation_attachment: capability.allow_operation_attachment,
        replay_window_ms: capability.replay_window_ms,
        max_clock_skew_ms: capability.max_clock_skew_ms,
        max_payload_bytes,
        max_relationships,
        rate_limit_per_minute: capability.rate_limit_per_minute,
        max_retained_submissions: if capability.max_retained_submissions == 0 {
            DEFAULT_MAX_RETAINED_EVIDENCE_SUBMISSIONS
        } else {
            capability.max_retained_submissions
        },
        revoked: capability.revoked,
    })
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
    }
}

fn evidence_submission_result(
    db: &RuntimeDb,
    admission: EvidenceAdmission,
    projection: Option<EvidenceProjectionOutcome>,
) -> Result<EvidenceSubmissionResult, Status> {
    let submission = db
        .get_evidence_submission(&admission.submission.id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::internal("evidence submission disappeared"))?;
    Ok(EvidenceSubmissionResult {
        submission: Some(to_proto_evidence_submission(&submission)),
        admitted: admission.accepted,
        deduplicated: admission.deduplicated,
        projected: projection.is_some_and(|projection| projection.projected),
    })
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

fn temporal_assertion_to_proto(
    a: crate::sekai::temporal::TemporalAssertionVersion,
) -> TemporalAssertion {
    TemporalAssertion {
        assertion_id: a.assertion_id,
        version: a.version,
        namespace: a.namespace,
        subject_id: a.subject_id,
        predicate: a.predicate,
        object_ref: a.object_ref,
        payload_json: a.payload_json,
        valid_from: Some(TemporalBound {
            kind: a.valid_from.kind.as_str().into(),
            ms: a.valid_from.ms.unwrap_or(0),
        }),
        valid_to: Some(TemporalBound {
            kind: a.valid_to.kind.as_str().into(),
            ms: a.valid_to.ms.unwrap_or(0),
        }),
        recorded_from_revision: a.recorded_from_revision,
        recorded_to_revision: a.recorded_to_revision.unwrap_or(0),
        recorded_at_ms: a.recorded_at_ms,
        source_observed_at_ms: a.source_observed_at_ms.unwrap_or(0),
        source_id: a.source_id,
        actor: a.actor,
        evidence_ref: a.evidence_ref,
        lineage_ref: a.lineage_ref,
        is_backfill: a.is_backfill,
    }
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

fn check_interface_admin(
    security: &SecurityChecker,
    name: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("schema", &refs)
        || security.can_admin(&interface_object_id(name), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("interface admin required"))
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

fn to_proto_object_set(set: &domain::ObjectSet) -> ObjectSet {
    ObjectSet {
        id: set.id.clone(),
        name: set.name.clone(),
        description: set.description.clone(),
        filter: Some(to_proto_list_filter(&set.filter)),
        owner_principal: set.owner_principal.clone(),
        created: set.created,
    }
}

fn to_proto_list_filter(filter: &domain::ListFilter) -> ListFilter {
    ListFilter {
        kind: filter.kind.clone().unwrap_or_default(),
        name: filter.name.clone().unwrap_or_default(),
        namespace: filter.namespace.clone().unwrap_or_default(),
        property_filters: filter
            .property_filters
            .iter()
            .map(|pf| PropertyFilter {
                key: pf.key.clone(),
                op: pf.op.clone(),
                value: pf.value.clone(),
            })
            .collect(),
        limit: filter.limit,
        offset: filter.offset,
        order_by: filter.order_by.clone(),
        descending: filter.descending,
        interface_filter: filter.interface_filter.clone(),
    }
}

fn parse_set_filter_from_request(input: &ObjectSet) -> Result<domain::ListFilter, Status> {
    let filter = input
        .filter
        .clone()
        .ok_or(Status::invalid_argument("filter required"))?;
    let mut property_filters = Vec::new();
    for pf in filter.property_filters {
        if !domain::is_valid_property_key(&pf.key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        property_filters.push(domain::PropertyFilter {
            key: pf.key,
            op: parse_property_operator(&pf.op)?.to_string(),
            value: pf.value,
        });
    }
    let interface_filter = parse_interface_filter(filter.interface_filter)?;
    if filter.offset < 0 {
        return Err(Status::invalid_argument("offset must be >= 0"));
    }
    let order_by = parse_order_by(&filter.order_by)?;
    Ok(domain::ListFilter {
        kind: if filter.kind.is_empty() {
            None
        } else {
            Some(filter.kind)
        },
        name: if filter.name.is_empty() {
            None
        } else {
            Some(filter.name)
        },
        namespace: if filter.namespace.is_empty() {
            None
        } else {
            Some(filter.namespace)
        },
        property_filters,
        interface_filter,
        // Keep zero/negative input as "use runtime request default" for resolves.
        // Callers should treat persisted ObjectSet filters as declarative query
        // descriptors, not already-paginated result sets.
        limit: if filter.limit <= 0 {
            0
        } else {
            filter.limit.min(MAX_LIST_LIMIT)
        },
        offset: filter.offset.max(0),
        order_by,
        descending: filter.descending,
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

fn to_domain_object_set(
    input: ObjectSet,
    owner_principal: &str,
) -> Result<domain::ObjectSet, Status> {
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(Status::invalid_argument("name required"));
    }
    let requested_owner = input.owner_principal.clone();
    if !requested_owner.is_empty() && requested_owner != owner_principal {
        return Err(Status::invalid_argument("owner_principal mismatch"));
    }

    let filter = parse_set_filter_from_request(&input)?;
    let created = if input.created > 0 {
        input.created
    } else {
        now_millis()
    };
    let id = if input.id.is_empty() {
        format!("set-{}", Uuid::new_v4().simple())
    } else {
        input.id
    };
    Ok(domain::ObjectSet {
        id,
        name,
        description: input.description,
        filter,
        owner_principal: if requested_owner.is_empty() {
            owner_principal.to_string()
        } else {
            requested_owner
        },
        created,
    })
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

fn ensure_list_filter_query_allowed(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    filter: &domain::ListFilter,
) -> Result<(), Status> {
    let mut queried_properties = filter
        .property_filters
        .iter()
        .map(|property_filter| property_filter.key.clone())
        .collect::<Vec<_>>();
    if let Some(order_property) = queried_order_property(&filter.order_by) {
        queried_properties.push(order_property);
    }
    ensure_property_query_allowed(
        schema,
        principals,
        filter.kind.as_deref().unwrap_or_default(),
        queried_properties,
    )
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

fn ensure_function_allows_restricted_properties(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    function: &function::Function,
) -> Result<(), Status> {
    for step in &function.pipeline {
        match step.op.as_str() {
            "filter" if !step.property.is_empty() => {
                ensure_property_query_allowed(
                    schema,
                    principals,
                    &step.kind,
                    [step.property.clone()],
                )?;
            }
            "aggregate" | "transform" if !step.field.is_empty() => {
                ensure_property_query_allowed(schema, principals, "", [step.field.clone()])?;
            }
            _ => {}
        }
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

fn to_proto_interface(interface: &schema::InterfaceDef) -> InterfaceDef {
    InterfaceDef {
        name: interface.name.clone(),
        description: interface.description.clone(),
        properties: interface
            .properties
            .iter()
            .map(to_proto_property_def)
            .collect(),
        is_builtin: interface.is_builtin,
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

fn from_proto_interface(interface: &InterfaceDef) -> Result<schema::InterfaceDef, Status> {
    let properties = interface
        .properties
        .iter()
        .map(from_proto_property_def)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(schema::InterfaceDef {
        name: interface.name.clone(),
        description: interface.description.clone(),
        properties,
        is_builtin: interface.is_builtin,
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

fn interface_object_id(name: &str) -> String {
    format!("interface:{name}")
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

fn action_budget_subject(action_risk: &str, namespace: &str, actor: &str) -> String {
    let base = format!("action:{action_risk}");
    if namespace.trim().is_empty() {
        return base;
    }
    if actor.trim().is_empty() {
        return format!("{base}/project:{}", namespace.trim());
    }
    format!("{base}/project:{}/agent:{}", namespace.trim(), actor.trim())
}

/// Pin the policy that rendered an action decision as a replayable
/// attestation and bind it into the audit decision's evidence. The returned
/// record must be persisted atomically with the decision via
/// `record_decision_with_attestation`. No policy (implicit allow) means
/// there is nothing to attest.
#[allow(clippy::too_many_arguments)]
fn attest_action_decision(
    policy: Option<&action_policy::ActionPolicy>,
    decision_id: &str,
    action_name: &str,
    actor: &str,
    risk: RiskClass,
    namespace: &str,
    decision: ActionDecision,
    evidence: &mut HashMap<String, String>,
) -> Option<attestation::PolicyAttestation> {
    let policy = policy?;
    let record = attestation::build_action_attestation(attestation::ActionAttestationInput {
        decision_id,
        policy,
        action: action_name,
        actor,
        risk,
        namespace,
        decision,
        created: now_millis(),
    });
    evidence.insert(
        attestation::EVIDENCE_ATTESTATION_ID.into(),
        record.id.clone(),
    );
    evidence.insert(
        attestation::EVIDENCE_ATTESTATION_HASH.into(),
        record.content_hash.clone(),
    );
    Some(record)
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

fn validate_action_type_against_schema(
    action_type: &action::ActionTypeDef,
    schema: &SchemaRegistry,
) -> Result<(), Status> {
    action::validate_action_type_against_schema(action_type, schema)
        .map_err(Status::invalid_argument)
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

fn to_proto_snapshot(snapshot: &coordination::CoordinationSnapshot) -> CoordinationSnapshot {
    CoordinationSnapshot {
        pending_count: snapshot.pending_count,
        running_count: snapshot.running_count,
        stale_count: snapshot.stale_count,
        active_reservation_count: snapshot.active_reservation_count,
        oldest_pending_age_ms: snapshot.oldest_pending_age_ms,
        oldest_running_age_ms: snapshot.oldest_running_age_ms,
        stale_reservation_count: snapshot.stale_reservation_count,
        blocked_scopes: snapshot
            .blocked_scopes
            .iter()
            .map(|scope| ScopeBlockage {
                scope_id: scope.scope_id.clone(),
                scope_name: scope.scope_name.clone(),
                reason: scope.reason.clone(),
                pending_count: scope.pending_count,
                active_count: scope.active_count,
            })
            .collect(),
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

fn unavailable_reference(
    reference: &handoff_domain::HandoffReference,
) -> handoff_domain::HandoffReference {
    let mut unavailable = reference.clone();
    unavailable.id.clear();
    unavailable.version.clear();
    unavailable.omitted = true;
    unavailable.omission_reason = "unavailable".into();
    unavailable
}

fn redacted_omission(
    reference: &handoff_domain::HandoffReference,
) -> handoff_domain::HandoffReference {
    let mut omission = reference.clone();
    omission.id.clear();
    omission.version.clear();
    omission
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
    }
}

fn from_proto_package_manifest(
    manifest: CapabilityPackageManifest,
) -> Result<package_domain::CapabilityPackageManifest, Status> {
    let components = manifest
        .components
        .into_iter()
        .map(|component| {
            let definition = serde_json::from_str(&component.definition_json)
                .map_err(|_| Status::invalid_argument("component definition_json must be JSON"))?;
            Ok(package_domain::PackageComponent {
                kind: component.kind,
                name: component.name,
                definition,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let signature = manifest
        .signature
        .map(|signature| package_domain::PackageSignature {
            algorithm: signature.algorithm,
            signer_identity: signature.signer_identity,
            key_id: signature.key_id,
            signature_b64: signature.signature_b64,
        });
    let manifest = package_domain::CapabilityPackageManifest {
        manifest_version: manifest.manifest_version,
        name: manifest.name,
        version: manifest.version,
        components,
        signature,
    };
    manifest.validate().map_err(Status::invalid_argument)?;
    Ok(manifest)
}

fn to_proto_package_manifest(
    manifest: &package_domain::CapabilityPackageManifest,
) -> CapabilityPackageManifest {
    CapabilityPackageManifest {
        manifest_version: manifest.manifest_version.clone(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        components: manifest
            .components
            .iter()
            .map(|component| CapabilityPackageComponent {
                kind: component.kind.clone(),
                name: component.name.clone(),
                definition_json: serde_json::to_string(&component.definition)
                    .expect("JSON values always serialize"),
            })
            .collect(),
        signature: manifest
            .signature
            .as_ref()
            .map(|signature| CapabilityPackageSignature {
                algorithm: signature.algorithm.clone(),
                signer_identity: signature.signer_identity.clone(),
                key_id: signature.key_id.clone(),
                signature_b64: signature.signature_b64.clone(),
            }),
    }
}

fn to_proto_package_installation(
    installation: &package_domain::PackageInstallation,
) -> CapabilityPackageInstallation {
    CapabilityPackageInstallation {
        namespace: installation.namespace.clone(),
        package_name: installation.package_name.clone(),
        current_version: installation.current_version.clone(),
        previous_version: installation.previous_version.clone(),
        state: installation.state.clone(),
        installed_by: installation.installed_by.clone(),
        updated_by: installation.updated_by.clone(),
        installed_at_ms: installation.installed_at_ms,
        updated_at_ms: installation.updated_at_ms,
    }
}

fn to_proto_package_event(event: &package_domain::PackageLifecycleEvent) -> CapabilityPackageEvent {
    CapabilityPackageEvent {
        sequence: event.sequence,
        namespace: event.namespace.clone(),
        package_name: event.package_name.clone(),
        package_version: event.package_version.clone(),
        action: event.action.clone(),
        actor: event.actor.clone(),
        request_id: event.request_id.clone(),
        manifest_digest: event.manifest_digest.clone(),
        evidence: event.evidence.clone(),
        recorded_at_ms: event.recorded_at_ms,
    }
}

fn authorize_package_mutation(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<String, Status> {
    require_authenticated(principals)?;
    check_team_namespace(&service.db, principals, namespace, true)?;
    check_action_admin(
        &service.security,
        &format!("capability_package:{namespace}"),
        principals,
    )?;
    principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))
}

/// Lease keys that coordinate an existing object use this prefix so the
/// coordination identity cannot be squatted without object ACL access.
const OBJECT_BOUND_LEASE_KEY_PREFIX: &str = "object:";

/// Returns `Ok(Some(object_id))` for a canonical `object:<object_id>` key.
/// Non-canonical spellings (whitespace, empty id) are rejected so authorization
/// and persistence cannot diverge across distinct keys for one object.
fn object_bound_lease_target(key: &str) -> Result<Option<&str>, Status> {
    let Some(rest) = key.strip_prefix(OBJECT_BOUND_LEASE_KEY_PREFIX) else {
        return Ok(None);
    };
    if rest.is_empty() || rest != rest.trim() || rest.chars().any(char::is_whitespace) {
        return Err(Status::invalid_argument(
            "object-bound lease key must be exactly object:<object_id> with no whitespace",
        ));
    }
    Ok(Some(rest))
}

/// When the lease key is object-bound (`object:<object_id>`), authorize through
/// the target object ACL and require the lease namespace to match the object.
///
/// `allow_missing_target` is for `ReleaseLease` after a guarded delete: the
/// coordination row must still be releasable when the object audit identity is
/// gone and cannot be recreated.
fn authorize_object_bound_lease(
    db: &RuntimeDb,
    security: &SecurityChecker,
    principals: &[String],
    lease_namespace: &str,
    key: &str,
    write: bool,
    allow_missing_target: bool,
) -> Result<(), Status> {
    let Some(object_id) = object_bound_lease_target(key)? else {
        return Ok(());
    };
    let Some(object) = db.get_object(object_id).map_err(Status::internal)? else {
        return if allow_missing_target {
            // Namespace write was already enforced by the caller.
            Ok(())
        } else {
            Err(Status::not_found(format!(
                "object-bound lease target {object_id} not found"
            )))
        };
    };
    // ACL before namespace validation so inaccessible objects do not reveal
    // their home namespace via a distinct InvalidArgument error.
    if write {
        check_write(security, object_id, principals)?;
    } else {
        check_read(security, object_id, principals)?;
    }
    if object.namespace != lease_namespace {
        return Err(Status::permission_denied(
            "object-bound lease namespace must match the target object namespace",
        ));
    }
    Ok(())
}

/// Object-bound lease preconditions must name the same object being mutated
/// and the same namespace as that object.
fn enforce_object_bound_lease_precondition(
    key: &str,
    lease_namespace: &str,
    mutation_target_object_id: Option<&str>,
    mutation_target_namespace: Option<&str>,
) -> Result<(), Status> {
    let Some(bound_id) = object_bound_lease_target(key)? else {
        return Ok(());
    };
    match mutation_target_object_id {
        None => Err(Status::invalid_argument(
            "object-bound lease keys cannot guard object creation; use a free-form key",
        )),
        Some(target) if target != bound_id => Err(Status::failed_precondition(
            "object-bound lease key must match the mutation target object id",
        )),
        Some(_) => {
            if let Some(object_namespace) = mutation_target_namespace
                && object_namespace != lease_namespace
            {
                return Err(Status::failed_precondition(
                    "object-bound lease namespace must match the mutation target object namespace",
                ));
            }
            Ok(())
        }
    }
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
        authorize_object_bound_lease(
            &self.db,
            &self.security,
            &principals,
            &input.namespace,
            &input.key,
            true,
            false,
        )?;
        let actor = principals.first().cloned().unwrap_or_default();
        let lease = self
            .db
            .acquire_lease(
                &input.namespace,
                &input.key,
                &input.owner,
                input.ttl_ms,
                &input.request_id,
                &actor,
                now_millis(),
            )
            .map_err(map_lease_error)?;
        // Re-validate object-bound targets after persistence so a concurrent
        // delete cannot leave a freshly returned active lease without a live
        // target. Best-effort release if the race is detected.
        if let Ok(Some(object_id)) = object_bound_lease_target(&input.key)
            && self
                .db
                .get_object(object_id)
                .map_err(Status::internal)?
                .is_none()
        {
            let _ = self.db.release_lease(
                &input.namespace,
                &input.key,
                &lease.fencing_token,
                &format!("{}:race-cleanup", input.request_id),
                &actor,
                now_millis(),
            );
            return Err(Status::not_found(format!(
                "object-bound lease target {object_id} not found"
            )));
        }
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
        authorize_object_bound_lease(
            &self.db,
            &self.security,
            &principals,
            &input.namespace,
            &input.key,
            false,
            false,
        )?;
        let lease = self
            .db
            .get_lease(&input.namespace, &input.key)
            .map_err(map_lease_error)?
            .ok_or(Status::not_found("lease not found"))?;
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
        authorize_object_bound_lease(
            &self.db,
            &self.security,
            &principals,
            &input.namespace,
            &input.key,
            true,
            false,
        )?;
        let actor = principals.first().cloned().unwrap_or_default();
        let lease = self
            .db
            .refresh_lease(
                &input.namespace,
                &input.key,
                &input.fencing_token,
                input.ttl_ms,
                &input.request_id,
                &actor,
                now_millis(),
            )
            .map_err(map_lease_error)?;
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
        authorize_object_bound_lease(
            &self.db,
            &self.security,
            &principals,
            &input.namespace,
            &input.key,
            true,
            true,
        )?;
        let actor = principals.first().cloned().unwrap_or_default();
        let lease = self
            .db
            .release_lease(
                &input.namespace,
                &input.key,
                &input.fencing_token,
                &input.request_id,
                &actor,
                now_millis(),
            )
            .map_err(map_lease_error)?;
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
        authorize_object_bound_lease(
            &self.db,
            &self.security,
            &principals,
            &input.namespace,
            &input.key,
            true,
            false,
        )?;
        let actor = principals.first().cloned().unwrap_or_default();
        let lease = self
            .db
            .takeover_expired_lease(
                &input.namespace,
                &input.key,
                &input.owner,
                &input.expected_fencing_token,
                input.expected_expires_at_ms,
                input.ttl_ms,
                &input.request_id,
                &actor,
                now_millis(),
            )
            .map_err(map_lease_error)?;
        Ok(Response::new(TakeoverExpiredLeaseResponse {
            lease: Some(to_proto_lease(&lease)),
        }))
    }

    async fn guarded_create_object(
        &self,
        req: Request<GuardedCreateObjectRequest>,
    ) -> Result<Response<GuardedCreateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        let precondition = input
            .lease_precondition
            .ok_or(Status::invalid_argument("lease_precondition required"))?;
        let object = input
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if object.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        if object.kind == "namespace" {
            require_credential_admin(&principals)?;
            return Err(Status::failed_precondition(
                "namespace objects must be managed through EnsureTeamNamespace",
            ));
        }
        if object.id.starts_with("namespace:") || object.external_id.starts_with("namespace:") {
            return Err(Status::invalid_argument(
                "namespace:* identifiers are reserved for namespace boundaries",
            ));
        }
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &object.namespace,
            true,
        )?;
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &precondition.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &object.namespace, true)?;
        check_team_namespace(&self.db, &principals, &precondition.namespace, true)?;
        check_write(&self.security, &object.id, &principals)?;
        enforce_object_bound_lease_precondition(
            &precondition.key,
            &precondition.namespace,
            None,
            None,
        )?;
        let domain_object = from_proto_obj(&object);
        if let Some(value) = domain_object
            .properties
            .get(markings::OBJECT_CLASSIFICATION_PROPERTY)
        {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        if let Some(created) = self
            .db
            .guarded_object_replay(
                &precondition.namespace,
                &precondition.key,
                &precondition.fencing_token,
                &precondition.request_id,
                "create",
                &domain_object.id,
                &domain_object,
            )
            .map_err(map_lease_error)?
        {
            let created =
                self.resolve_computed_for_response(created, &principals, tenant_context.as_ref())?;
            return Ok(Response::new(GuardedCreateObjectResponse {
                object: Some(to_proto_obj(&created)),
            }));
        }
        if is_reserved_governance_kind(&domain_object.kind) {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        let mut domain_object = domain_object;
        if domain_object.kind == markings::PRINCIPAL_PROFILE_KIND {
            require_credential_admin(&principals)?;
            validate_principal_profile_object(&object)?;
            domain_object.properties.insert(
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            );
        } else {
            self.require_schema_kind_loaded(&domain_object.kind)?;
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema
                .validate(&domain_object)
                .map_err(Status::invalid_argument)?;
            ensure_restricted_create_properties_allowed(
                &schema,
                &self.security,
                &principals,
                &domain_object,
            )?;
            drop(schema);
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let created = self
            .db
            .guarded_create_object(
                &domain_object,
                &precondition.namespace,
                &precondition.key,
                &precondition.fencing_token,
                &precondition.request_id,
                actor,
                now_millis(),
            )
            .map_err(map_lease_error)?;
        if created.kind == markings::PRINCIPAL_PROFILE_KIND {
            let grant = security::Grant {
                id: format!("principal-profile-admin-{}", Uuid::new_v4().simple()),
                object_id: created.id.clone(),
                principal: if actor.is_empty() {
                    "root".into()
                } else {
                    actor.into()
                },
                role: security::Role::Admin,
                created: now_millis(),
            };
            if let Err(error) = self.db.create_grant(&grant) {
                let _ = self.db.delete_object(&created.id);
                return Err(Status::internal(error));
            }
            self.security.add_grant(&grant);
        }
        let created =
            self.resolve_computed_for_response(created, &principals, tenant_context.as_ref())?;
        Ok(Response::new(GuardedCreateObjectResponse {
            object: Some(to_proto_obj(&created)),
        }))
    }

    async fn guarded_update_object(
        &self,
        req: Request<GuardedUpdateObjectRequest>,
    ) -> Result<Response<GuardedUpdateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        let precondition = input
            .lease_precondition
            .ok_or(Status::invalid_argument("lease_precondition required"))?;
        let object = input
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if object.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        if object.external_id.starts_with("namespace:") && object.kind != "namespace" {
            return Err(Status::invalid_argument(
                "namespace:* external IDs are reserved for namespace boundaries",
            ));
        }
        let existing = self.db.get_object(&object.id).map_err(Status::internal)?;
        if object.kind == "namespace"
            || existing
                .as_ref()
                .is_some_and(|existing| existing.kind == "namespace")
        {
            require_credential_admin(&principals)?;
        }
        if object.kind == markings::PRINCIPAL_PROFILE_KIND
            || existing
                .as_ref()
                .is_some_and(|existing| existing.kind == markings::PRINCIPAL_PROFILE_KIND)
        {
            require_credential_admin(&principals)?;
            validate_principal_profile_object(&object)?;
        }
        if let Some(existing) = &existing {
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &existing.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
        }
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &object.namespace,
            true,
        )?;
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &precondition.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &object.namespace, true)?;
        check_team_namespace(&self.db, &principals, &precondition.namespace, true)?;
        check_write(&self.security, &object.id, &principals)?;
        if let Some(existing) = &existing {
            enforce_object_marking_access(
                &self.db,
                existing,
                &principals,
                &format!("guarded_update_object:{}", existing.id),
            )?;
        }
        enforce_object_bound_lease_precondition(
            &precondition.key,
            &precondition.namespace,
            Some(object.id.as_str()),
            Some(object.namespace.as_str()),
        )?;
        let mut domain_object = from_proto_obj(&object);
        if let Some(value) = domain_object
            .properties
            .get(markings::OBJECT_CLASSIFICATION_PROPERTY)
        {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        let request_object = domain_object.clone();
        if let Some(updated) = self
            .db
            .guarded_object_replay(
                &precondition.namespace,
                &precondition.key,
                &precondition.fencing_token,
                &precondition.request_id,
                "update",
                &request_object.id,
                &request_object,
            )
            .map_err(map_lease_error)?
        {
            enforce_object_marking_access(
                &self.db,
                &updated,
                &principals,
                &format!("guarded_update_object_replay:{}", updated.id),
            )?;
            let updated =
                self.resolve_computed_for_response(updated, &principals, tenant_context.as_ref())?;
            return Ok(Response::new(GuardedUpdateObjectResponse {
                object: Some(to_proto_obj(&updated)),
            }));
        }
        if is_reserved_governance_kind(&domain_object.kind)
            || existing
                .as_ref()
                .is_some_and(|existing| is_reserved_governance_kind(&existing.kind))
        {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        if domain_object.kind == markings::PRINCIPAL_PROFILE_KIND {
            domain_object.properties.insert(
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            );
        } else {
            self.require_schema_kind_loaded(&domain_object.kind)?;
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            if existing.is_some() {
                preserve_redacted_restricted_properties(
                    &self.db,
                    &schema,
                    &self.security,
                    &principals,
                    &mut domain_object,
                )?;
            }
            schema
                .validate(&domain_object)
                .map_err(Status::invalid_argument)?;
            drop(schema);
        }
        if let Some(existing) = &existing {
            validate_object_kind_change_access(
                &self.db,
                &self.security,
                &principals,
                existing,
                &domain_object,
            )?;
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let updated = self
            .db
            .guarded_update_object(
                &domain_object,
                &request_object,
                existing.as_ref(),
                &precondition.namespace,
                &precondition.key,
                &precondition.fencing_token,
                &precondition.request_id,
                actor,
                now_millis(),
            )
            .map_err(map_lease_error)?;
        let updated =
            self.resolve_computed_for_response(updated, &principals, tenant_context.as_ref())?;
        Ok(Response::new(GuardedUpdateObjectResponse {
            object: Some(to_proto_obj(&updated)),
        }))
    }

    async fn guarded_delete_object(
        &self,
        req: Request<GuardedDeleteObjectRequest>,
    ) -> Result<Response<GuardedDeleteObjectResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        let precondition = input
            .lease_precondition
            .ok_or(Status::invalid_argument("lease_precondition required"))?;
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &precondition.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &precondition.namespace, true)?;
        check_write(&self.security, &input.id, &principals)?;
        let expected = self.db.get_object(&input.id).map_err(Status::internal)?;
        enforce_object_bound_lease_precondition(
            &precondition.key,
            &precondition.namespace,
            Some(input.id.as_str()),
            expected.as_ref().map(|object| object.namespace.as_str()),
        )?;
        if let Some(existing) = &expected {
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &existing.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
            enforce_object_marking_access(
                &self.db,
                existing,
                &principals,
                &format!("guarded_delete_object:{}", existing.id),
            )?;
            if existing.kind == markings::PRINCIPAL_PROFILE_KIND {
                require_credential_admin(&principals)?;
            }
            if existing.kind == "namespace" {
                require_credential_admin(&principals)?;
                if existing
                    .properties
                    .get("team_managed")
                    .is_some_and(|value| value == "true")
                {
                    return Err(Status::failed_precondition(
                        "team-managed namespaces cannot be deleted through the generic object API",
                    ));
                }
            }
            if is_reserved_governance_kind(&existing.kind) {
                return Err(Status::permission_denied(
                    "object cannot be deleted through the guarded object API",
                ));
            }
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .guarded_delete_object(
                &input.id,
                expected.as_ref(),
                &precondition.namespace,
                &precondition.key,
                &precondition.fencing_token,
                &precondition.request_id,
                actor,
                now_millis(),
            )
            .map_err(map_lease_error)?;
        Ok(Response::new(GuardedDeleteObjectResponse {}))
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
        if proto.intended_scope != proto.namespace {
            return Err(Status::invalid_argument(
                "intended_scope must equal the manifest namespace",
            ));
        }
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
        manifest.validate().map_err(Status::invalid_argument)?;
        let request_digest = manifest
            .canonical_digest()
            .map_err(Status::invalid_argument)?;
        if let Some((existing_digest, existing)) = self
            .db
            .get_handoff_by_request(&manifest.creator_principal, &inner.request_id)
            .map_err(Status::internal)?
        {
            if existing_digest != request_digest {
                return Err(Status::already_exists(
                    "request_id is already bound to different handoff input",
                ));
            }
            return Ok(Response::new(CreateHandoffResponse {
                manifest: Some(to_proto_handoff(&existing)),
            }));
        }
        let current_time = now_millis();
        if manifest.created_at_ms > current_time.saturating_add(60_000)
            || manifest.expires_at_ms <= current_time
        {
            return Err(Status::invalid_argument(
                "handoff timestamps are outside the accepted window",
            ));
        }
        for reference in manifest
            .references
            .iter()
            .filter(|reference| !reference.omitted)
        {
            if !handoff_reference_available(
                self,
                reference,
                &manifest.namespace,
                &principals,
                current_time,
            )? {
                return Err(Status::failed_precondition(
                    "handoff contains an unavailable reference",
                ));
            }
        }
        if !manifest.supersedes_manifest_id.is_empty() {
            let predecessor = self
                .db
                .get_handoff(&manifest.supersedes_manifest_id)
                .map_err(Status::internal)?
                .ok_or(Status::failed_precondition(
                    "superseded handoff is unavailable",
                ))?;
            if predecessor.creator_principal != manifest.creator_principal
                || predecessor.intended_principal != manifest.intended_principal
                || predecessor.namespace != manifest.namespace
            {
                return Err(Status::failed_precondition(
                    "superseded handoff is unavailable",
                ));
            }
        }
        let stored = self
            .db
            .create_handoff(&manifest, &inner.request_id)
            .map_err(|error| {
                if error.contains("different handoff") {
                    Status::already_exists(error)
                } else {
                    Status::invalid_argument(error)
                }
            })?;
        Ok(Response::new(CreateHandoffResponse {
            manifest: Some(to_proto_handoff(&stored)),
        }))
    }

    async fn resolve_handoff(
        &self,
        req: Request<ResolveHandoffRequest>,
    ) -> Result<Response<ResolveHandoffResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let not_found = || Status::not_found("handoff not found");
        let manifest = self
            .db
            .get_handoff(&inner.manifest_id)
            .map_err(Status::internal)?
            .ok_or_else(not_found)?;
        if !principals.iter().any(|principal| {
            principal == &manifest.intended_principal
                || matches!(principal.as_str(), "root" | "local")
        }) || check_team_namespace(&self.db, &principals, &manifest.namespace, false).is_err()
        {
            return Err(not_found());
        }
        let now_ms = now_millis();
        if manifest.revoked
            || manifest.expires_at_ms <= now_ms
            || self
                .db
                .handoff_is_superseded(&manifest.id)
                .map_err(Status::internal)?
            || manifest.digest != manifest.canonical_digest().map_err(Status::data_loss)?
        {
            return Err(not_found());
        }
        let mut available = Vec::new();
        let mut omissions = Vec::new();
        for reference in &manifest.references {
            if reference.omitted {
                omissions.push(redacted_omission(reference));
            } else if handoff_reference_available(
                self,
                reference,
                &manifest.namespace,
                &principals,
                now_ms,
            )? {
                available.push(reference.clone());
            } else {
                omissions.push(unavailable_reference(reference));
            }
        }
        let mut projected_manifest = manifest.clone();
        projected_manifest.references = available.iter().chain(omissions.iter()).cloned().collect();
        Ok(Response::new(ResolveHandoffResponse {
            manifest: Some(to_proto_handoff(&projected_manifest)),
            available_references: available.iter().map(to_proto_handoff_reference).collect(),
            omissions: omissions.iter().map(to_proto_handoff_reference).collect(),
        }))
    }

    async fn revoke_handoff(
        &self,
        req: Request<RevokeHandoffRequest>,
    ) -> Result<Response<RevokeHandoffResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_handoff(&inner.manifest_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("handoff not found"))?;
        if !principals.iter().any(|principal| {
            principal == &existing.creator_principal
                || matches!(principal.as_str(), "root" | "local")
        }) {
            return Err(Status::not_found("handoff not found"));
        }
        let actor = principals.first().cloned().unwrap_or_default();
        let revoked = self
            .db
            .revoke_handoff(
                &inner.manifest_id,
                &actor,
                &inner.reason,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(RevokeHandoffResponse {
            manifest: Some(to_proto_handoff(&revoked)),
        }))
    }

    async fn create_object(
        &self,
        req: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let obj = req
            .into_inner()
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if obj.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        if obj.id.starts_with("namespace:") && obj.kind != "namespace" {
            return Err(Status::invalid_argument(
                "namespace:* object IDs are reserved for namespace boundaries",
            ));
        }
        if obj.external_id.starts_with("namespace:") && obj.kind != "namespace" {
            return Err(Status::invalid_argument(
                "namespace:* external IDs are reserved for namespace boundaries",
            ));
        }
        if obj
            .external_id
            .starts_with(markings::PRINCIPAL_PROFILE_EXTERNAL_ID_PREFIX)
            && obj.kind != markings::PRINCIPAL_PROFILE_KIND
        {
            return Err(Status::invalid_argument(
                "principal:* external IDs are reserved for principal_profile objects",
            ));
        }
        if obj.kind == "namespace" {
            require_credential_admin(&principals)?;
            return Err(Status::failed_precondition(
                "namespace objects must be managed through EnsureTeamNamespace",
            ));
        }
        if obj.kind == markings::PRINCIPAL_PROFILE_KIND {
            require_credential_admin(&principals)?;
            validate_principal_profile_object(&obj)?;
        }
        enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), &obj.namespace, true)?;
        check_team_namespace(&self.db, &principals, &obj.namespace, true)?;
        check_write(&self.security, &obj.id, &principals)?;
        let mut domain_obj = from_proto_obj(&obj);
        if is_reserved_governance_kind(&domain_obj.kind) {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        if domain_obj.kind == markings::PRINCIPAL_PROFILE_KIND {
            domain_obj.properties.insert(
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            );
        }
        if domain_obj.kind != markings::PRINCIPAL_PROFILE_KIND {
            self.require_schema_kind_loaded(&domain_obj.kind)?;
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema
                .validate(&domain_obj)
                .map_err(Status::invalid_argument)?;
            ensure_restricted_create_properties_allowed(
                &schema,
                &self.security,
                &principals,
                &domain_obj,
            )?;
            drop(schema);
        }
        if let Some(value) = domain_obj
            .properties
            .get(markings::OBJECT_CLASSIFICATION_PROPERTY)
        {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .create_object_with_audit(&domain_obj, actor)
            .map_err(Status::internal)?;
        if domain_obj.kind == markings::PRINCIPAL_PROFILE_KIND {
            // Profiles must not remain world-writable; seal with an admin grant.
            // If sealing fails, remove the object so we do not leave an unusable
            // world-open identity record.
            let grant = security::Grant {
                id: format!("principal-profile-admin-{}", Uuid::new_v4().simple()),
                object_id: domain_obj.id.clone(),
                principal: if actor.is_empty() {
                    "root".into()
                } else {
                    actor.into()
                },
                role: security::Role::Admin,
                created: now_millis(),
            };
            if let Err(error) = self.db.create_grant(&grant) {
                let _ = self.db.delete_object(&domain_obj.id);
                return Err(Status::internal(error));
            }
            self.security.add_grant(&grant);
        }
        let domain_obj =
            self.resolve_computed_for_response(domain_obj, &principals, tenant_context.as_ref())?;
        Ok(Response::new(CreateObjectResponse {
            object: Some(to_proto_obj(&domain_obj)),
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
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let obj = req
            .into_inner()
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if obj.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        if obj.external_id.starts_with("namespace:") && obj.kind != "namespace" {
            return Err(Status::invalid_argument(
                "namespace:* external IDs are reserved for namespace boundaries",
            ));
        }
        if obj.kind == "namespace"
            || self
                .db
                .get_object(&obj.id)
                .map_err(Status::internal)?
                .is_some_and(|existing| existing.kind == "namespace")
        {
            require_credential_admin(&principals)?;
        }
        let existing = self
            .db
            .get_object(&obj.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &existing.namespace,
            true,
        )?;
        enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), &obj.namespace, true)?;
        check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
        check_team_namespace(&self.db, &principals, &obj.namespace, true)?;
        check_write(&self.security, &obj.id, &principals)?;
        // Clearance required to mutate a marked object (including demoting it).
        enforce_object_marking_access(
            &self.db,
            &existing,
            &principals,
            &format!("update_object:{}", existing.id),
        )?;
        let mut domain_obj = from_proto_obj(&obj);
        if is_reserved_governance_kind(&domain_obj.kind)
            || self
                .db
                .get_object(&obj.id)
                .map_err(Status::internal)?
                .is_some_and(|existing| is_reserved_governance_kind(&existing.kind))
        {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        if domain_obj.kind == markings::PRINCIPAL_PROFILE_KIND
            || existing.kind == markings::PRINCIPAL_PROFILE_KIND
        {
            require_credential_admin(&principals)?;
            validate_principal_profile_object(&obj)?;
            domain_obj.properties.insert(
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            );
        }
        if domain_obj.kind != markings::PRINCIPAL_PROFILE_KIND {
            self.require_schema_kind_loaded(&domain_obj.kind)?;
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            preserve_redacted_restricted_properties(
                &self.db,
                &schema,
                &self.security,
                &principals,
                &mut domain_obj,
            )?;
            schema
                .validate(&domain_obj)
                .map_err(Status::invalid_argument)?;
            drop(schema);
        }
        if let Some(value) = domain_obj
            .properties
            .get(markings::OBJECT_CLASSIFICATION_PROPERTY)
        {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        if existing.kind != domain_obj.kind {
            let ontology = self.db.load_ontology_registry().map_err(Status::internal)?;
            let mut linked = self
                .db
                .get_links(&domain_obj.id, "", &domain::Direction::Outgoing)
                .map_err(Status::internal)?;
            linked.extend(
                self.db
                    .get_links(&domain_obj.id, "", &domain::Direction::Incoming)
                    .map_err(Status::internal)?,
            );
            for link in linked {
                if ontology
                    .constraints_for_mapped_relation(&link.relation)
                    .is_empty()
                {
                    continue;
                }
                if link.from_id != domain_obj.id {
                    let endpoint = self
                        .db
                        .get_object(&link.from_id)
                        .map_err(Status::internal)?
                        .ok_or(Status::failed_precondition("link endpoint unavailable"))?;
                    check_team_namespace(&self.db, &principals, &endpoint.namespace, false)?;
                    check_read(&self.security, &endpoint.id, &principals)?;
                }
                if link.to_id != domain_obj.id {
                    let endpoint = self
                        .db
                        .get_object(&link.to_id)
                        .map_err(Status::internal)?
                        .ok_or(Status::failed_precondition("link endpoint unavailable"))?;
                    check_team_namespace(&self.db, &principals, &endpoint.namespace, false)?;
                    check_read(&self.security, &endpoint.id, &principals)?;
                }
                if ontology
                    .constraints_for_mapped_relation(&link.relation)
                    .into_iter()
                    .any(|constraint| {
                        let introduces_domain_violation = link.from_id == domain_obj.id
                            && ontology.kind_satisfies_class(&existing.kind, &constraint.domain)
                            && !ontology.kind_satisfies_class(&domain_obj.kind, &constraint.domain);
                        let introduces_range_violation = link.to_id == domain_obj.id
                            && ontology.kind_satisfies_class(&existing.kind, &constraint.range)
                            && !ontology.kind_satisfies_class(&domain_obj.kind, &constraint.range);
                        introduces_domain_violation || introduces_range_violation
                    })
                {
                    return Err(Status::failed_precondition(
                        "link endpoints violate ontology constraint",
                    ));
                }
            }
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .update_object_with_audit(&domain_obj, actor)
            .map_err(map_graph_mutation_error)?
            .ok_or(Status::not_found("not found"))?;
        let domain_obj =
            self.resolve_computed_for_response(domain_obj, &principals, tenant_context.as_ref())?;
        Ok(Response::new(UpdateObjectResponse {
            object: Some(to_proto_obj(&domain_obj)),
        }))
    }
    async fn delete_object(
        &self,
        req: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let id = req.into_inner().id;
        let Some(existing) = self.db.get_object(&id).map_err(Status::internal)? else {
            return Ok(Response::new(DeleteObjectResponse {}));
        };
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &existing.namespace,
            true,
        )?;
        if existing.kind == "namespace" {
            require_credential_admin(&principals)?;
            if existing
                .properties
                .get("team_managed")
                .is_some_and(|value| value == "true")
            {
                return Err(Status::failed_precondition(
                    "team-managed namespaces cannot be deleted through the generic object API",
                ));
            }
        }
        if existing.kind == markings::PRINCIPAL_PROFILE_KIND {
            require_credential_admin(&principals)?;
        }
        check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
        check_write(&self.security, &id, &principals)?;
        enforce_object_marking_access(
            &self.db,
            &existing,
            &principals,
            &format!("delete_object:{id}"),
        )?;
        if self
            .db
            .get_object(&id)
            .map_err(Status::internal)?
            .is_some_and(|existing| is_reserved_governance_kind(&existing.kind))
        {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .delete_object_with_audit(&id, actor)
            .map_err(Status::internal)?;
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
            self.record_catalog_invocation_receipt(
                operation_id,
                namespace,
                &actor,
                capability_name,
                catalog_version.as_deref(),
                "pending",
                "invocation_started",
                true,
            )?;
            receipt_guard = Some(CatalogReceiptGuard {
                service: self,
                operation_id: operation_id.clone(),
                namespace: namespace.to_string(),
                actor,
                capability_name: capability_name.clone(),
                catalog_version: catalog_version.clone(),
                policy_decision: None,
                budget_decision: None,
                finalized: false,
            });
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
    async fn create_object_set(
        &self,
        req: Request<CreateObjectSetRequest>,
    ) -> Result<Response<CreateObjectSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let owner = principals.first().cloned().unwrap_or_default();
        let domain_set = to_domain_object_set(
            req.into_inner()
                .object_set
                .ok_or(Status::invalid_argument("object_set required"))?,
            owner.as_str(),
        )?;
        if is_managed_team_principal(&self.db, &principals)? {
            let namespace = domain_set.filter.namespace.as_deref().ok_or_else(|| {
                Status::permission_denied("team object sets must filter by namespace")
            })?;
            check_team_namespace(&self.db, &principals, namespace, false)?;
        }
        if domain_set
            .filter
            .kind
            .as_deref()
            .is_some_and(is_reserved_governance_kind)
        {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_list_filter_query_allowed(&schema, &principals, &domain_set.filter)?;
        }
        self.db.create_object_set(&domain_set).map_err(|e| {
            let duplicate_name = e.starts_with("UNIQUE constraint failed:")
                && e.contains("sekai_object_sets.owner_principal")
                && e.contains("sekai_object_sets.name");
            let duplicate_id =
                e.starts_with("UNIQUE constraint failed:") && e.contains("sekai_object_sets.id");
            if duplicate_name || duplicate_id {
                Status::already_exists("object set already exists")
            } else {
                Status::internal(e)
            }
        })?;
        Ok(Response::new(CreateObjectSetResponse {
            object_set: Some(to_proto_object_set(&domain_set)),
        }))
    }
    async fn list_object_sets(
        &self,
        req: Request<ListObjectSetsRequest>,
    ) -> Result<Response<ListObjectSetsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let sets = self
            .db
            .list_object_sets_for_principals(&principal_refs)
            .map_err(Status::internal)?
            .into_iter()
            .collect::<Vec<_>>();
        Ok(Response::new(ListObjectSetsResponse {
            object_sets: sets.iter().map(to_proto_object_set).collect(),
        }))
    }
    async fn delete_object_set(
        &self,
        req: Request<DeleteObjectSetRequest>,
    ) -> Result<Response<DeleteObjectSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        if id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        if self
            .db
            .delete_object_set_for_principals(&id, &principal_refs)
            .map_err(Status::internal)?
        {
            return Ok(Response::new(DeleteObjectSetResponse {}));
        }
        Err(Status::not_found("not found"))
    }
    async fn resolve_object_set(
        &self,
        req: Request<ResolveObjectSetRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let set = self
            .db
            .get_object_set(&inner.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        if !principal_matches(&set.owner_principal, &principals) {
            return Err(Status::not_found("not found"));
        }
        let mut filter = set.filter.clone();
        let (limit, _) = read_limit_offset(inner.limit, 0)?;
        if inner.limit > 0 || filter.limit <= 0 {
            filter.limit = limit;
        }
        if let Some(offset) = inner.offset {
            if offset < 0 {
                return Err(Status::invalid_argument("offset must be >= 0"));
            }
            filter.offset = offset;
        }
        if is_managed_team_principal(&self.db, &principals)? {
            let namespace = filter.namespace.as_deref().ok_or_else(|| {
                Status::permission_denied("team object sets must filter by namespace")
            })?;
            check_team_namespace(&self.db, &principals, namespace, false)?;
        }
        if tenant_context.is_some() {
            let namespace = filter.namespace.as_deref().ok_or_else(|| {
                Status::permission_denied("tenant context requires a namespace-scoped object set")
            })?;
            enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), namespace, false)?;
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_list_filter_query_allowed(&schema, &principals, &filter)?;
        }
        let (objects, total) = list_objects_with_marking(
            &self.db,
            &filter,
            &principals,
            tenant_context.as_ref(),
            |objects, principals, tenant_context| {
                self.resolve_computed_for_responses(objects, principals, tenant_context)
            },
        )?;
        Ok(Response::new(ListObjectsResponse {
            objects: objects.iter().map(to_proto_obj).collect(),
            total,
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
        let reasoning_started = std::time::Instant::now();
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let roots = inner
            .roots
            .into_iter()
            .map(from_proto_context_root)
            .collect::<Result<Vec<_>, _>>()?;
        let direction =
            retrieval::RetrievalDirection::parse(&inner.direction).map_err(map_retrieval_error)?;
        let reasoning_mode =
            retrieval::ReasoningMode::parse(&inner.reasoning_mode).map_err(map_retrieval_error)?;
        let mut query = retrieval::RetrievalQuery {
            roots,
            relations: inner.relations,
            direction,
            max_depth: inner.max_depth,
            max_objects: inner.max_objects,
            max_links: inner.max_links,
            kind_filter: inner.kind_filter,
            reasoning_mode,
            max_source_rows: inner.max_source_rows,
            max_derived_rows: inner.max_derived_rows,
            max_derivation_steps: inner.max_derivation_steps,
            max_time_ms: inner.max_time_ms,
            max_explanation_bytes: inner.max_explanation_bytes,
            initial_source_rows: 0,
            source_rows_truncated: false,
        };
        let reasoning_timeout =
            std::time::Duration::from_millis(u64::from(if query.max_time_ms == 0 {
                retrieval::DEFAULT_MAX_TIME_MS
            } else {
                query.max_time_ms.min(retrieval::MAX_TIME_MS)
            }));
        let reasoning_deadline = reasoning_started + reasoning_timeout;
        let ontology_row_limit = if query.max_source_rows == 0 {
            retrieval::DEFAULT_MAX_SOURCE_ROWS
        } else {
            query.max_source_rows.min(retrieval::MAX_SOURCE_ROWS)
        };
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        // Build one authorization-filtered immutable snapshot before inference.
        // Hidden definitions cannot influence closure, counts, explanations,
        // errors, or truncation metadata.
        let mut ontology_source_rows = 0u32;
        let mut ontology_source_truncated = false;
        let ontology = if reasoning_mode == retrieval::ReasoningMode::Entailment {
            let class_rows = match self.db.list_readable_ontology_classes(
                &principals,
                reasoning_deadline,
                ontology_row_limit.saturating_add(1),
            ) {
                Ok(classes) => classes,
                Err(_) if reasoning_started.elapsed() >= reasoning_timeout => Vec::new(),
                Err(error) => return Err(Status::internal(error)),
            };
            let mut classes = class_rows;
            if classes.len() > ontology_row_limit as usize {
                classes.truncate(ontology_row_limit as usize);
                ontology_source_truncated = true;
            }
            ontology_source_rows = classes.len().min(u32::MAX as usize) as u32;
            let mut classes = classes
                .into_iter()
                .take_while(|_| reasoning_started.elapsed() < reasoning_timeout)
                .filter(|class| {
                    check_read(
                        &self.security,
                        &ontology_class_object_id(&class.name),
                        &principals,
                    )
                    .is_ok()
                })
                .collect::<Vec<_>>();
            let visible_class_names = classes
                .iter()
                .map(|class| class.name.clone())
                .collect::<std::collections::HashSet<_>>();
            for class in &mut classes {
                class
                    .superclasses
                    .retain(|name| visible_class_names.contains(name));
                class
                    .equivalent_classes
                    .retain(|name| visible_class_names.contains(name));
                class
                    .disjoint_classes
                    .retain(|name| visible_class_names.contains(name));
            }
            let remaining_rows = ontology_row_limit.saturating_sub(ontology_source_rows);
            let relation_rows =
                if !ontology_source_truncated && reasoning_started.elapsed() < reasoning_timeout {
                    self.db
                        .list_readable_ontology_relations(
                            &principals,
                            reasoning_deadline,
                            remaining_rows.saturating_add(1),
                        )
                        .or_else(|error| {
                            if reasoning_started.elapsed() >= reasoning_timeout {
                                Ok(Vec::new())
                            } else {
                                Err(error)
                            }
                        })
                        .map_err(Status::internal)?
                } else {
                    Vec::new()
                };
            let mut relation_rows = relation_rows;
            if relation_rows.len() > remaining_rows as usize {
                relation_rows.truncate(remaining_rows as usize);
                ontology_source_truncated = true;
            }
            ontology_source_rows = ontology_source_rows
                .saturating_add(relation_rows.len().min(u32::MAX as usize) as u32);
            let mut relations = relation_rows
                .into_iter()
                .take_while(|_| reasoning_started.elapsed() < reasoning_timeout)
                .filter(|relation| {
                    check_read(
                        &self.security,
                        &ontology_relation_object_id(&relation.name),
                        &principals,
                    )
                    .is_ok()
                })
                .filter(|relation| {
                    visible_class_names.contains(&relation.domain)
                        && visible_class_names.contains(&relation.range)
                })
                .collect::<Vec<_>>();
            let visible_relation_names = relations
                .iter()
                .map(|relation| relation.name.clone())
                .collect::<std::collections::HashSet<_>>();
            for relation in &mut relations {
                if !relation.inverse.is_empty()
                    && !visible_relation_names.contains(&relation.inverse)
                {
                    relation.inverse.clear();
                }
            }
            Some(ontology::OntologyRegistry::from_parts(classes, relations))
        } else {
            None
        };
        query.initial_source_rows = ontology_source_rows;
        query.source_rows_truncated = ontology_source_truncated;
        let mut result = retrieval::retrieve_with_ontology_started(
            &self.db,
            &query,
            ontology.as_ref(),
            reasoning_started,
            |object| {
                self.security.can_access(&object.id, &principal_refs)
                    && check_team_namespace(&self.db, &principals, &object.namespace, false).is_ok()
                    && object_passes_marking(&self.db, object, &principals).unwrap_or(false)
            },
            |object| is_reserved_governance_kind(&object.kind),
        )
        .map_err(map_retrieval_error)?;
        if reasoning_mode == retrieval::ReasoningMode::Entailment {
            // Hidden objects are intentionally indistinguishable from absent
            // objects in inference metadata.
            result.denied_objects = 0;
            if reasoning_started.elapsed() >= reasoning_timeout
                && !result
                    .truncation_reasons
                    .iter()
                    .any(|reason| reason == "time")
            {
                result.truncation_reasons.push("time".into());
                result.truncated = true;
            }
        }
        for candidate in &mut result.candidates {
            candidate.object =
                self.resolve_computed_for_response(candidate.object.clone(), &principals, None)?;
        }

        Ok(Response::new(RetrieveContextResponse {
            candidates: result
                .candidates
                .iter()
                .map(|candidate| ContextCandidate {
                    object: Some(to_proto_obj(&candidate.object)),
                    depth: candidate.depth,
                    via_relation: candidate.via_relation.clone(),
                    affinity: candidate.affinity,
                    explanation: Some(ContextExplanation {
                        steps: candidate
                            .explanation
                            .steps
                            .iter()
                            .map(|step| ContextDerivationStep {
                                kind: step.kind.into(),
                                relation: step.relation.clone(),
                                from_id: step.from_id.clone(),
                                to_id: step.to_id.clone(),
                                source_fact_ids: step.source_fact_ids.clone(),
                                ontology_revision: step.ontology_revision.clone(),
                                rule: step.rule.into(),
                            })
                            .collect(),
                        source_fact_ids: candidate.explanation.source_fact_ids.clone(),
                        ontology_revision: candidate.explanation.ontology_revision.clone(),
                        derived: candidate.explanation.derived,
                    }),
                })
                .collect(),
            links: result.links.iter().map(to_proto_link).collect(),
            truncated: result.truncated,
            unresolved_roots: result.unresolved_roots,
            denied_objects: result.denied_objects,
            truncated_objects: result.truncated_objects,
            truncated_links: result.truncated_links,
            truncation_reasons: result.truncation_reasons,
            source_rows: result.source_rows,
            derived_rows: result.derived_rows,
            ontology_revision: result.ontology_revision,
        }))
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
        let contract_version = capability::negotiate_contract_version(&inner.contract_version)
            .map_err(map_capability_error)?;
        let entries = self.discoverable_capabilities(namespace, &principals)?;
        let mut context = principals.clone();
        context.sort();
        context.dedup();
        context.insert(0, namespace.to_string());
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

    async fn install_capability_package(
        &self,
        req: Request<InstallCapabilityPackageRequest>,
    ) -> Result<Response<InstallCapabilityPackageResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let actor = authorize_package_mutation(self, &principals, &inner.namespace)?;
        let manifest = from_proto_package_manifest(
            inner
                .manifest
                .ok_or_else(|| Status::invalid_argument("manifest required"))?,
        )?;
        let installation = self
            .db
            .install_capability_package(
                &inner.namespace,
                &manifest,
                &actor,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(InstallCapabilityPackageResponse {
            installation: Some(to_proto_package_installation(&installation)),
        }))
    }

    async fn set_capability_package_trust_policy(
        &self,
        req: Request<SetCapabilityPackageTrustPolicyRequest>,
    ) -> Result<Response<SetCapabilityPackageTrustPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let actor = authorize_package_mutation(self, &principals, &inner.namespace)?;
        let policy = self
            .db
            .set_capability_package_trust_policy(
                &inner.namespace,
                &inner.required_trust_level,
                &actor,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(SetCapabilityPackageTrustPolicyResponse {
            policy: Some(CapabilityPackageTrustPolicy {
                namespace: policy.namespace,
                required_trust_level: policy.required_trust_level,
                updated_by: policy.updated_by,
                updated_at_ms: policy.updated_at_ms,
            }),
        }))
    }

    async fn get_capability_package_trust_policy(
        &self,
        req: Request<GetCapabilityPackageTrustPolicyRequest>,
    ) -> Result<Response<GetCapabilityPackageTrustPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_team_namespace(&self.db, &principals, &inner.namespace, true)?;
        check_action_admin(
            &self.security,
            &format!("capability_package:{}", inner.namespace),
            &principals,
        )?;
        let policy = self
            .db
            .get_capability_package_trust_policy(&inner.namespace)
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(GetCapabilityPackageTrustPolicyResponse {
            policy: Some(CapabilityPackageTrustPolicy {
                namespace: policy.namespace,
                required_trust_level: policy.required_trust_level,
                updated_by: policy.updated_by,
                updated_at_ms: policy.updated_at_ms,
            }),
        }))
    }

    async fn put_capability_package_signer(
        &self,
        req: Request<PutCapabilityPackageSignerRequest>,
    ) -> Result<Response<PutCapabilityPackageSignerResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let actor = authorize_package_mutation(self, &principals, &inner.namespace)?;
        let signer = self
            .db
            .put_capability_package_signer(
                &inner.namespace,
                &inner.identity,
                &inner.key_id,
                &inner.public_key_b64,
                &actor,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(PutCapabilityPackageSignerResponse {
            signer: Some(CapabilityPackageSigner {
                namespace: signer.namespace,
                identity: signer.identity,
                key_id: signer.key_id,
                public_key_b64: signer.public_key_b64,
                created_by: signer.created_by,
                created_at_ms: signer.created_at_ms,
            }),
        }))
    }

    async fn list_capability_package_signers(
        &self,
        req: Request<ListCapabilityPackageSignersRequest>,
    ) -> Result<Response<ListCapabilityPackageSignersResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_team_namespace(&self.db, &principals, &inner.namespace, true)?;
        check_action_admin(
            &self.security,
            &format!("capability_package:{}", inner.namespace),
            &principals,
        )?;
        let signers = self
            .db
            .list_capability_package_signers(&inner.namespace)
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(ListCapabilityPackageSignersResponse {
            signers: signers
                .into_iter()
                .map(|signer| CapabilityPackageSigner {
                    namespace: signer.namespace,
                    identity: signer.identity,
                    key_id: signer.key_id,
                    public_key_b64: signer.public_key_b64,
                    created_by: signer.created_by,
                    created_at_ms: signer.created_at_ms,
                })
                .collect(),
        }))
    }

    async fn get_capability_package(
        &self,
        req: Request<GetCapabilityPackageRequest>,
    ) -> Result<Response<GetCapabilityPackageResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_team_namespace(&self.db, &principals, &inner.namespace, true)?;
        check_action_admin(
            &self.security,
            &format!("capability_package:{}", inner.namespace),
            &principals,
        )?;
        let installation = self
            .db
            .get_capability_package(&inner.namespace, &inner.package_name)
            .map_err(Status::internal)?;
        let events = self
            .db
            .list_capability_package_events(&inner.namespace, &inner.package_name)
            .map_err(Status::internal)?;
        let version = installation
            .as_ref()
            .map(|installation| installation.current_version.as_str())
            .or_else(|| events.last().map(|event| event.package_version.as_str()))
            .ok_or_else(|| Status::not_found("capability package not found"))?;
        let manifest = self
            .db
            .get_capability_package_manifest(&inner.namespace, &inner.package_name, version)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("capability package manifest missing"))?;
        Ok(Response::new(GetCapabilityPackageResponse {
            installation: installation.as_ref().map(to_proto_package_installation),
            manifest: Some(to_proto_package_manifest(&manifest)),
            events: events.iter().map(to_proto_package_event).collect(),
        }))
    }

    async fn evaluate_capability_package(
        &self,
        req: Request<CapabilityPackageTransitionRequest>,
    ) -> Result<Response<EvaluateCapabilityPackageResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let actor = authorize_package_mutation(self, &principals, &inner.namespace)?;
        let passed = self
            .db
            .evaluate_capability_package(
                &inner.namespace,
                &inner.package_name,
                &actor,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(EvaluateCapabilityPackageResponse { passed }))
    }

    async fn upgrade_capability_package(
        &self,
        req: Request<UpgradeCapabilityPackageRequest>,
    ) -> Result<Response<UpgradeCapabilityPackageResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let actor = authorize_package_mutation(self, &principals, &inner.namespace)?;
        let manifest = from_proto_package_manifest(
            inner
                .manifest
                .ok_or_else(|| Status::invalid_argument("manifest required"))?,
        )?;
        let installation = self
            .db
            .upgrade_capability_package(
                &inner.namespace,
                &manifest,
                &actor,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(UpgradeCapabilityPackageResponse {
            installation: Some(to_proto_package_installation(&installation)),
        }))
    }

    async fn rollback_capability_package(
        &self,
        req: Request<CapabilityPackageTransitionRequest>,
    ) -> Result<Response<CapabilityPackageTransitionResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let actor = authorize_package_mutation(self, &principals, &inner.namespace)?;
        let installation = self
            .db
            .rollback_capability_package(
                &inner.namespace,
                &inner.package_name,
                &actor,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(CapabilityPackageTransitionResponse {
            installation: Some(to_proto_package_installation(&installation)),
        }))
    }

    async fn disable_capability_package(
        &self,
        req: Request<CapabilityPackageTransitionRequest>,
    ) -> Result<Response<CapabilityPackageTransitionResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let actor = authorize_package_mutation(self, &principals, &inner.namespace)?;
        let installation = self
            .db
            .disable_capability_package(
                &inner.namespace,
                &inner.package_name,
                &actor,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(CapabilityPackageTransitionResponse {
            installation: Some(to_proto_package_installation(&installation)),
        }))
    }

    async fn uninstall_capability_package(
        &self,
        req: Request<CapabilityPackageTransitionRequest>,
    ) -> Result<Response<UninstallCapabilityPackageResponse>, Status> {
        let principals = caller_principals(&req);
        let inner = req.into_inner();
        let actor = authorize_package_mutation(self, &principals, &inner.namespace)?;
        self.db
            .uninstall_capability_package(
                &inner.namespace,
                &inner.package_name,
                &actor,
                &inner.request_id,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(UninstallCapabilityPackageResponse {}))
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
    async fn delete_schema_type(
        &self,
        req: Request<DeleteSchemaTypeRequest>,
    ) -> Result<Response<DeleteSchemaTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let kind = req.into_inner().kind;
        if kind.trim().is_empty() {
            return Err(Status::invalid_argument("kind required"));
        }
        check_schema_admin(&self.security, &kind, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            if registry
                .get(&kind)
                .map(|object_type| object_type.is_builtin)
                .unwrap_or(false)
            {
                return Err(Status::invalid_argument(
                    "cannot delete builtin schema type",
                ));
            }
        }
        self.db
            .delete_object_type(&kind)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&kind);
        self.schema_load_errors
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&kind);
        Ok(Response::new(DeleteSchemaTypeResponse {}))
    }

    async fn list_interfaces(
        &self,
        req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let interfaces = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .all_interfaces()
            .iter()
            .filter(|interface| {
                check_read(
                    &self.security,
                    &interface_object_id(&interface.name),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_interface)
            .collect();
        Ok(Response::new(ListInterfacesResponse { interfaces }))
    }

    async fn create_interface(
        &self,
        req: Request<CreateInterfaceRequest>,
    ) -> Result<Response<CreateInterfaceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let interface = req
            .into_inner()
            .interface
            .ok_or(Status::invalid_argument("interface required"))?;
        let parsed = from_proto_interface(&interface)?;
        check_interface_admin(&self.security, &parsed.name, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema::validate_interface_definition(&parsed, registry.get_interface(&parsed.name))
                .map_err(Status::invalid_argument)?;
            let mut updated_registry = registry.clone();
            updated_registry.register_interface(parsed.clone());
            for object_type in updated_registry.all() {
                if object_type
                    .implements
                    .iter()
                    .any(|interface| interface == &parsed.name)
                {
                    schema::validate_object_type_definition(
                        &object_type,
                        updated_registry.get(&object_type.kind),
                        &updated_registry,
                    )
                    .map_err(Status::invalid_argument)?;
                }
            }
        }
        self.db
            .upsert_interface(&parsed)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .register_interface(parsed.clone());
        Ok(Response::new(CreateInterfaceResponse {
            interface: Some(to_proto_interface(&parsed)),
        }))
    }

    async fn delete_interface(
        &self,
        req: Request<DeleteInterfaceRequest>,
    ) -> Result<Response<DeleteInterfaceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("interface name required"));
        }
        check_interface_admin(&self.security, &name, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            if registry
                .get_interface(&name)
                .map(|interface| interface.is_builtin)
                .unwrap_or(false)
            {
                return Err(Status::invalid_argument("cannot delete builtin interface"));
            }
            if registry.all().iter().any(|object_type| {
                object_type
                    .implements
                    .iter()
                    .any(|interface| interface == &name)
            }) {
                return Err(Status::failed_precondition(
                    "cannot delete interface while schema types implement it",
                ));
            }
        }
        self.db.delete_interface(&name).map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove_interface(&name);
        Ok(Response::new(DeleteInterfaceResponse {}))
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
        check_ontology_admin(
            &self.security,
            &ontology_class_object_id(&parsed.name),
            &principals,
        )?;
        for reference in parsed
            .superclasses
            .iter()
            .chain(&parsed.equivalent_classes)
            .chain(&parsed.disjoint_classes)
        {
            check_read(
                &self.security,
                &ontology_class_object_id(reference),
                &principals,
            )?;
        }
        if !parsed.mapped_kind.is_empty() {
            check_read(
                &self.security,
                &schema_object_id(&parsed.mapped_kind),
                &principals,
            )?;
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            if schema.get(&parsed.mapped_kind).is_none() {
                return Err(Status::invalid_argument("mapped schema kind not found"));
            }
        }
        let mut registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        let existing = registry.get_class(&parsed.name).cloned();
        // Validate against the rest of the ontology, not the prior version of
        // this same class, so cycle/reference checks are deterministic.
        registry.remove_class(&parsed.name);
        ontology::validate_class_definition(&parsed, existing.as_ref(), &registry)
            .map_err(Status::invalid_argument)?;
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .upsert_ontology_class_with_audit(&parsed, actor)
            .map_err(Status::internal)?;
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
        check_ontology_admin(
            &self.security,
            &ontology_class_object_id(&name),
            &principals,
        )?;
        let registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        // Refuse to orphan classes or relations that still reference this one.
        for class in registry.classes() {
            if class.name == name {
                continue;
            }
            if class
                .superclasses
                .iter()
                .chain(&class.equivalent_classes)
                .chain(&class.disjoint_classes)
                .any(|reference| reference == &name)
            {
                return Err(Status::failed_precondition(format!(
                    "class '{}' still references '{name}'",
                    class.name
                )));
            }
        }
        for relation in registry.relations() {
            if relation.domain == name || relation.range == name {
                return Err(Status::failed_precondition(format!(
                    "relation '{}' still uses '{name}' as domain or range",
                    relation.name
                )));
            }
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let object_id = ontology_class_object_id(&name);
        let grants = self.db.list_grants(&object_id).map_err(Status::internal)?;
        if !self
            .db
            .delete_ontology_class_with_audit(&name, actor)
            .map_err(Status::internal)?
        {
            return Err(Status::not_found("ontology class not found"));
        }
        for grant in &grants {
            self.security.remove_grant(&object_id, &grant.principal);
        }
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
        check_ontology_admin(
            &self.security,
            &ontology_relation_object_id(&parsed.name),
            &principals,
        )?;
        for endpoint in [&parsed.domain, &parsed.range] {
            check_read(
                &self.security,
                &ontology_class_object_id(endpoint),
                &principals,
            )?;
        }
        if !parsed.inverse.is_empty() {
            check_read(
                &self.security,
                &ontology_relation_object_id(&parsed.inverse),
                &principals,
            )?;
        }
        let mut registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        let existing = registry.get_relation(&parsed.name).cloned();
        registry.remove_relation(&parsed.name);
        ontology::validate_relation_definition(&parsed, existing.as_ref(), &registry)
            .map_err(Status::invalid_argument)?;
        for referencing in registry
            .relations()
            .into_iter()
            .filter(|relation| relation.inverse == parsed.name)
        {
            if referencing.domain != parsed.range || referencing.range != parsed.domain {
                return Err(Status::invalid_argument(format!(
                    "relation '{}' would no longer reverse inverse '{}'",
                    referencing.name, parsed.name
                )));
            }
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .upsert_ontology_relation_with_audit(&parsed, actor)
            .map_err(Status::internal)?;
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
        check_ontology_admin(
            &self.security,
            &ontology_relation_object_id(&name),
            &principals,
        )?;
        let registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        if let Some(referencing) = registry
            .relations()
            .into_iter()
            .find(|relation| relation.name != name && relation.inverse == name)
        {
            return Err(Status::failed_precondition(format!(
                "relation '{}' still uses '{name}' as its inverse",
                referencing.name
            )));
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let object_id = ontology_relation_object_id(&name);
        let grants = self.db.list_grants(&object_id).map_err(Status::internal)?;
        if !self
            .db
            .delete_ontology_relation_with_audit(&name, actor)
            .map_err(Status::internal)?
        {
            return Err(Status::not_found("ontology relation not found"));
        }
        for grant in &grants {
            self.security.remove_grant(&object_id, &grant.principal);
        }
        Ok(Response::new(DeleteOntologyRelationResponse {}))
    }

    async fn project_schema_to_ontology(
        &self,
        req: Request<ProjectSchemaToOntologyRequest>,
    ) -> Result<Response<ProjectSchemaToOntologyResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        check_ontology_admin(&self.security, "ontology", &principals)?;
        let projected = {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ontology::project_schema_registry(&schema).map_err(Status::invalid_argument)?
        };
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let existing_ontology = self.db.load_ontology_registry().map_err(Status::internal)?;
        let mut projection_plan = Vec::new();
        for mut class in projected.classes() {
            // Persisted ontology classes are user-owned; the builtin flag is a
            // schema concept and is not carried into storage.
            class.is_builtin = false;
            ontology::validate_class_definition(
                &class,
                existing_ontology.get_class(&class.name),
                &projected,
            )
            .map_err(Status::invalid_argument)?;
            let source_object_id = if class.mapped_kind.is_empty() {
                interface_object_id(&class.name)
            } else {
                schema_object_id(&class.mapped_kind)
            };
            check_read(&self.security, &source_object_id, &principals)?;
            let source_grants = self
                .db
                .list_grants(&source_object_id)
                .map_err(Status::internal)?;
            let ontology_object_id = ontology_class_object_id(&class.name);
            let previous_grants = self
                .db
                .list_grants(&ontology_object_id)
                .map_err(Status::internal)?;
            projection_plan.push((class, source_grants, ontology_object_id, previous_grants));
        }
        let mut classes = Vec::new();
        for (class, source_grants, ontology_object_id, previous_grants) in projection_plan {
            self.db
                .upsert_projected_ontology_class_with_audit(&class, actor, &source_grants)
                .map_err(Status::internal)?;
            for grant in &previous_grants {
                self.security
                    .remove_grant(&ontology_object_id, &grant.principal);
            }
            for grant in &source_grants {
                let projected_grant = security::Grant {
                    id: grant.id.clone(),
                    object_id: ontology_object_id.clone(),
                    principal: grant.principal.clone(),
                    role: grant.role.clone(),
                    created: grant.created,
                };
                self.security.add_grant(&projected_grant);
            }
            classes.push(to_proto_ontology_class(&class));
        }
        Ok(Response::new(ProjectSchemaToOntologyResponse { classes }))
    }

    async fn report_ontology_link_violations(
        &self,
        req: Request<ReportOntologyLinkViolationsRequest>,
    ) -> Result<Response<ReportOntologyLinkViolationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().ontology_relation;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("ontology relation required"));
        }
        // Authorize the ontology definition before loading or reporting any of
        // its endpoint details.
        check_read(
            &self.security,
            &ontology_relation_object_id(&name),
            &principals,
        )?;
        let registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        let relation = registry
            .get_relation(&name)
            .ok_or(Status::not_found("ontology relation not found"))?;
        check_ontology_relation_read(&self.security, relation, &principals)?;

        let mut violations = Vec::new();
        if !relation.mapped_relation.is_empty() {
            for link in self
                .db
                .list_links_by_relation(&relation.mapped_relation)
                .map_err(Status::internal)?
            {
                let Some(from) = self
                    .db
                    .get_object(&link.from_id)
                    .map_err(Status::internal)?
                else {
                    continue;
                };
                let Some(to) = self.db.get_object(&link.to_id).map_err(Status::internal)? else {
                    continue;
                };
                if check_team_namespace(&self.db, &principals, &from.namespace, false).is_err()
                    || check_team_namespace(&self.db, &principals, &to.namespace, false).is_err()
                    || check_read(&self.security, &from.id, &principals).is_err()
                    || check_read(&self.security, &to.id, &principals).is_err()
                    || !object_passes_marking(&self.db, &from, &principals).unwrap_or(false)
                    || !object_passes_marking(&self.db, &to, &principals).unwrap_or(false)
                {
                    continue;
                }
                let (domain_violation, range_violation) =
                    ontology_link_violations(&registry, relation, &from.kind, &to.kind);
                if domain_violation || range_violation {
                    violations.push(OntologyLinkViolation {
                        link_id: link.id,
                        from_id: link.from_id,
                        to_id: link.to_id,
                        relation: link.relation,
                        domain_violation,
                        range_violation,
                    });
                }
            }
        }
        Ok(Response::new(ReportOntologyLinkViolationsResponse {
            violations,
        }))
    }

    async fn create_action_type(
        &self,
        req: Request<CreateActionTypeRequest>,
    ) -> Result<Response<CreateActionTypeResponse>, Status> {
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
            validate_action_type_against_schema(&parsed, &schema)?;
        }
        let stored = self
            .db
            .upsert_action_type(&parsed)
            .map_err(Status::internal)?;
        self.actions
            .write()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .register_action_type(stored.clone())
            .map_err(Status::invalid_argument)?;
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
                    self.record_catalog_invocation_receipt(
                        operation_id,
                        invocation_namespace,
                        actor,
                        capability_name,
                        catalog_version.as_deref(),
                        "refuse",
                        "capability_unavailable",
                        true,
                    )?;
                }
                return Err(Status::failed_precondition("capability unavailable"));
            }
        }
        let mut receipt_guard = if let Some((capability_name, operation_id)) =
            invoked_capability.as_ref().zip(operation_id.as_ref())
        {
            let actor = principals.first().cloned().unwrap_or_default();
            self.record_catalog_invocation_receipt(
                operation_id,
                invocation_namespace,
                &actor,
                capability_name,
                catalog_version.as_deref(),
                "pending",
                "invocation_started",
                true,
            )?;
            Some(CatalogReceiptGuard {
                service: self,
                operation_id: operation_id.clone(),
                namespace: invocation_namespace.to_string(),
                actor,
                capability_name: capability_name.clone(),
                catalog_version: catalog_version.clone(),
                policy_decision: None,
                budget_decision: None,
                finalized: false,
            })
        } else {
            None
        };
        let actions = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let mask_missing_link = actions.masks_missing_link(&r.action);
        let sensitive_params = actions.sensitive_param_names(&r.action);
        let target_ids = actions
            .target_ids(&self.db, &r.action, &r.params)
            .map_err(|err| {
                if mask_missing_link && err == "link not found" {
                    Status::permission_denied("write denied")
                } else {
                    Status::invalid_argument(err)
                }
            })?;
        if invoked_capability.is_some() {
            for target_id in &target_ids {
                if let Some(target) = self.db.get_object(target_id).map_err(Status::internal)?
                    && target.namespace != invocation_namespace
                {
                    return Err(Status::failed_precondition(
                        "capability namespace does not match action target",
                    ));
                }
            }
            if let Some(namespace) = r.params.get("namespace")
                && namespace != invocation_namespace
            {
                return Err(Status::failed_precondition(
                    "capability namespace does not match action target",
                ));
            }
        }
        if actions.creates_namespace(&r.action, &r.params) {
            return Err(Status::permission_denied(
                "namespace objects must be managed through EnsureTeamNamespace",
            ));
        }
        for target_id in &target_ids {
            if let Some(target) = self.db.get_object(target_id).map_err(Status::internal)? {
                if target.kind == markings::PRINCIPAL_PROFILE_KIND {
                    return Err(Status::permission_denied(
                        "principal_profile objects require credential-admin CRUD paths",
                    ));
                }
                enforce_namespace_tenant_context(
                    &self.db,
                    tenant_context.as_ref(),
                    &target.namespace,
                    true,
                )?;
                check_team_namespace(&self.db, &principals, &target.namespace, true)?;
                // Marked targets require clearance for action execution too.
                let _ = enforce_object_marking_access(
                    &self.db,
                    &target,
                    &principals,
                    &format!("execute_action:{}:{}", r.action, target_id),
                )?;
            }
            check_write(&self.security, target_id, &principals)?;
        }
        // Reject invalid classification writes through set_property / fixed params
        // and registered action ops that set the classification property.
        if r.params
            .get("key")
            .is_some_and(|key| key == markings::OBJECT_CLASSIFICATION_PROPERTY)
        {
            if let Some(value) = r.params.get("value") {
                markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
            }
        }
        if let Some(value) = r.params.get(markings::OBJECT_CLASSIFICATION_PROPERTY) {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        if let Some(action_type) = actions.get_action_type(&r.action) {
            for op in &action_type.ops {
                if op.op == "set_property"
                    && op.property == markings::OBJECT_CLASSIFICATION_PROPERTY
                {
                    let value = if op.value_from.is_empty() {
                        r.params.get("value")
                    } else {
                        r.params.get(&op.value_from)
                    };
                    if let Some(value) = value {
                        markings::parse_optional_classification(value)
                            .map_err(Status::invalid_argument)?;
                    }
                }
            }
        }
        // Purpose gate for registered action types with required_purpose.
        {
            let required_purpose = actions
                .get_action_type(&r.action)
                .map(|action_type| action_type.required_purpose.clone())
                .unwrap_or_default();
            if !required_purpose.trim().is_empty() {
                let authority = resolve_principal_authority(&self.db, &principals)?;
                let purpose = markings::evaluate_purpose_access(
                    &format!("execute_action:{}", r.action),
                    &required_purpose,
                    &authority,
                );
                let actor = principals.first().cloned().unwrap_or_default();
                let mut evidence = HashMap::from([
                    ("required_purpose".into(), purpose.required_purpose.clone()),
                    ("detail".into(), purpose.detail.clone()),
                ]);
                if purpose.decision == markings::MarkingDecision::Deny {
                    evidence.insert("outcome".into(), "denied".into());
                    let _ = record_marking_or_purpose_decision(
                        &self.db,
                        &actor,
                        "purpose.execute",
                        target_ids.first().map(String::as_str).unwrap_or(""),
                        &purpose.decision_id,
                        "denied",
                        evidence,
                    );
                    return Err(Status::permission_denied("purpose not allow-listed"));
                }
                if purpose.decision == markings::MarkingDecision::Allow {
                    evidence.insert("outcome".into(), "allowed".into());
                    record_marking_or_purpose_decision(
                        &self.db,
                        &actor,
                        "purpose.execute",
                        target_ids.first().map(String::as_str).unwrap_or(""),
                        &purpose.decision_id,
                        "allowed",
                        evidence,
                    )?;
                }
            }
        }
        if let Some(namespace) = r.params.get("namespace") {
            enforce_namespace_tenant_context(&self.db, tenant_context.as_ref(), namespace, true)?;
            check_team_namespace(&self.db, &principals, namespace, true)?;
        } else if r.action == "create_object"
            && (tenant_context.is_some() || is_managed_team_principal(&self.db, &principals)?)
        {
            return Err(Status::permission_denied(
                "team object creation requires a canonical namespace",
            ));
        }
        let schema_kinds = actions
            .schema_kinds(&self.db, &r.action, &r.params)
            .map_err(Status::invalid_argument)?;
        ensure_action_schema_kinds_allowed(&schema_kinds)?;
        let actor = principals.first().cloned().unwrap_or_default();
        // Governed-action policy gate (Plan 9, Phase A). Resolved by
        // agent-then-namespace scope; no policy == allow (backward compatible).
        let action_risk = actions.action_risk_class(&r.action);
        let policy_namespace = action_policy_namespace(&self.db, &target_ids, &r.params);
        let resolved_policy = self
            .db
            .resolve_action_policy(&actor, &policy_namespace, &policy_namespace)
            .map_err(Status::internal)?;
        let (decision, policy_scope) = match &resolved_policy {
            _ if policy_namespace == ERASED_NAMESPACE => {
                (ActionDecision::Deny, ERASED_NAMESPACE.to_string())
            }
            Some(policy) => (policy.decide(&r.action, action_risk), policy.scope.clone()),
            None => (ActionDecision::Allow, String::new()),
        };
        if let Some(guard) = receipt_guard.as_mut() {
            guard.mark_policy_decided(decision.as_str());
        }
        let attested_policy = if policy_namespace == ERASED_NAMESPACE {
            None
        } else {
            resolved_policy.as_ref()
        };

        // Dry-run (Plan 9, Phase B): report the planned ops and the resolved
        // decision without executing or erroring, leaving the graph untouched.
        if dry_run {
            let planned_ops = actions
                .planned_ops(&r.action, &r.params)
                .map_err(Status::invalid_argument)?;
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("decision".into(), decision.as_str().into());
            evidence.insert("dry_run".into(), "true".into());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            if !policy_scope.is_empty() {
                evidence.insert("policy_scope".into(), policy_scope.clone());
            }
            let decision_id = uuid::Uuid::new_v4().to_string();
            let attested = attest_action_decision(
                attested_policy,
                &decision_id,
                &r.action,
                &actor,
                action_risk,
                &policy_namespace,
                decision,
                &mut evidence,
            );
            self.db
                .record_decision_with_attestation(
                    &audit::Decision {
                        id: decision_id,
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "execute_action_dry_run".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!(
                            "dry-run: {} planned op(s), decision={}",
                            planned_ops.len(),
                            decision.as_str()
                        ),
                    },
                    attested.as_ref(),
                )
                .map_err(Status::internal)?;
            let mut response = Response::new(ExecuteActionResponse {
                result: Some(ActionResult {
                    action: r.action,
                    message: format!("dry run: {} planned op(s)", planned_ops.len()),
                    dry_run: true,
                    planned_ops,
                    decision: decision.as_str().into(),
                    approval_id: String::new(),
                }),
            });
            if let (Some(_), Some(operation_id)) =
                (invoked_capability.as_deref(), operation_id.as_deref())
            {
                if let Err(error) = receipt_guard
                    .as_mut()
                    .unwrap()
                    .finalize(decision.as_str(), "dry_run")
                {
                    let mut status =
                        Status::internal(format!("catalog receipt finalization failed: {error}"));
                    status.metadata_mut().insert(
                        "x-sekai-operation-id",
                        operation_id
                            .parse()
                            .map_err(|_| Status::internal("invalid operation id"))?,
                    );
                    return Err(status);
                }
                response.metadata_mut().insert(
                    "x-sekai-operation-id",
                    operation_id
                        .parse()
                        .map_err(|_| Status::internal("invalid operation id"))?,
                );
            }
            return Ok(response);
        }

        if decision == ActionDecision::RequireApproval {
            // Phase B: hold the action for out-of-band approval instead of
            // executing. Persist the exact params so it can be resumed.
            let approval = action_approval::ActionApproval::pending(
                actor.clone(),
                r.action.clone(),
                r.params.clone(),
                work_unit.clone(),
                policy_scope.clone(),
                action_risk.as_str(),
                target_ids.first().cloned().unwrap_or_default(),
                now_millis(),
            );
            self.db
                .create_action_approval(&approval)
                .map_err(Status::internal)?;
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("policy_scope".into(), policy_scope.clone());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            evidence.insert("decision".into(), decision.as_str().into());
            evidence.insert("approval_id".into(), approval.id.clone());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            let decision_id = uuid::Uuid::new_v4().to_string();
            let attested = attest_action_decision(
                attested_policy,
                &decision_id,
                &r.action,
                &actor,
                action_risk,
                &policy_namespace,
                decision,
                &mut evidence,
            );
            self.db
                .record_decision_with_attestation(
                    &audit::Decision {
                        id: decision_id,
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "action_approval_pending".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!("held for approval: {}", approval.id),
                    },
                    attested.as_ref(),
                )
                .map_err(Status::internal)?;
            let mut response = Response::new(ExecuteActionResponse {
                result: Some(ActionResult {
                    action: r.action,
                    message: format!("action held for approval: {}", approval.id),
                    dry_run: false,
                    planned_ops: Vec::new(),
                    decision: decision.as_str().into(),
                    approval_id: approval.id.clone(),
                }),
            });
            if let (Some(_), Some(operation_id)) =
                (invoked_capability.as_deref(), operation_id.as_deref())
            {
                let approval_outcome = format!("approval_required:{}", approval.id);
                if let Err(error) = receipt_guard
                    .as_mut()
                    .unwrap()
                    .finalize(decision.as_str(), &approval_outcome)
                {
                    let mut status =
                        Status::internal(format!("catalog receipt finalization failed: {error}"));
                    status.metadata_mut().insert(
                        "x-sekai-operation-id",
                        operation_id
                            .parse()
                            .map_err(|_| Status::internal("invalid operation id"))?,
                    );
                    return Err(status);
                }
                response.metadata_mut().insert(
                    "x-sekai-operation-id",
                    operation_id
                        .parse()
                        .map_err(|_| Status::internal("invalid operation id"))?,
                );
            }
            return Ok(response);
        }

        if decision == ActionDecision::Deny {
            if invoked_capability.is_some() {
                receipt_guard
                    .as_mut()
                    .unwrap()
                    .finalize(decision.as_str(), "denied")?;
            }
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("policy_scope".into(), policy_scope.clone());
            evidence.insert("decision".into(), decision.as_str().into());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            let decision_id = uuid::Uuid::new_v4().to_string();
            let attested = attest_action_decision(
                attested_policy,
                &decision_id,
                &r.action,
                &actor,
                action_risk,
                &policy_namespace,
                decision,
                &mut evidence,
            );
            self.db
                .record_decision_with_attestation(
                    &audit::Decision {
                        id: decision_id,
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "action_policy_denied".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!("{} by action policy {}", decision.as_str(), policy_scope),
                    },
                    attested.as_ref(),
                )
                .map_err(Status::internal)?;
            return Err(Status::permission_denied(format!(
                "action {} denied by policy",
                r.action
            )));
        }

        // Blast-radius caps (Plan 9, Phase C): hard-stop runaway loops by
        // capping mutations/deletes per work unit. Only enforced when a policy
        // sets a cap and the call carries a work-unit attribution.
        let blast_caps = resolved_policy.as_ref().and_then(|policy| {
            match (
                policy.max_mutations_per_work_unit,
                policy.max_deletes_per_work_unit,
            ) {
                (None, None) => None,
                caps => Some(caps),
            }
        });
        let (op_mutations, op_deletes) = actions.action_op_counts(&r.action, &r.params);
        if !work_unit.is_empty()
            && let Some((max_mutations, max_deletes)) = blast_caps
        {
            let (used_mutations, used_deletes) = self
                .db
                .get_blast_radius(&work_unit)
                .map_err(Status::internal)?;
            let exceeds = |cap: Option<u32>, used: u32, add: u32| {
                cap.is_some_and(|cap| used.saturating_add(add) > cap)
            };
            if exceeds(max_deletes, used_deletes, op_deletes)
                || exceeds(max_mutations, used_mutations, op_mutations)
            {
                let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
                evidence.insert("risk_class".into(), action_risk.as_str().into());
                evidence.insert("policy_scope".into(), policy_scope.clone());
                evidence.insert("work_unit".into(), work_unit.clone());
                evidence.insert("used_mutations".into(), used_mutations.to_string());
                evidence.insert("used_deletes".into(), used_deletes.to_string());
                self.db
                    .record_decision(&audit::Decision {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "action_blast_radius_exceeded".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!("blast-radius cap exceeded for work unit {}", work_unit),
                    })
                    .map_err(Status::internal)?;
                return Err(Status::resource_exhausted(format!(
                    "blast-radius cap exceeded for work unit {}",
                    work_unit
                )));
            }
        }

        // Action-class budget (Plan 10, Phase A): meter effectful actions against
        // a hierarchical `action:<risk_class>` scope rooted at project and then
        // actor. No limit == allow.
        let budget_subject = action_budget_subject(action_risk.as_str(), &policy_namespace, &actor);
        if let Some(budget) = &self.budget
            && let Err(err) = budget.check(&budget_subject, 1)
        {
            if let Some(guard) = receipt_guard.as_mut() {
                guard.mark_budget_decided("budget_exceeded");
            }
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("budget_subject".into(), budget_subject.clone());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: actor.clone(),
                    action: r.action.clone(),
                    reason: "action_budget_exceeded".into(),
                    evidence,
                    target_id: target_ids.first().cloned().unwrap_or_default(),
                    outcome: err,
                })
                .map_err(Status::internal)?;
            return Err(Status::resource_exhausted(format!(
                "action budget exhausted for {}",
                budget_subject
            )));
        }
        if let Some(guard) = receipt_guard.as_mut() {
            guard.mark_budget_decided(if self.budget.is_some() {
                "allow"
            } else {
                "not_configured"
            });
        }
        for kind in schema_kinds {
            self.require_schema_kind_loaded(&kind)?;
        }
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        actions
            .validate_action_schema(&r.action, &schema)
            .map_err(Status::invalid_argument)?;
        let schema_restricted_property =
            schema_restricted_action_property(&self.db, &schema, &r.params);
        let provisional_learning_grant = (r.action
            == crate::sekai::learning::RECORD_LEARNING_ACTION)
            .then(|| security::Grant {
                id: String::new(),
                object_id: r.params.get("id").cloned().unwrap_or_default(),
                principal: actor.clone(),
                role: security::Role::Admin,
                created: now_millis(),
            })
            .filter(|grant| !grant.object_id.is_empty());
        if let Some(grant) = &provisional_learning_grant {
            self.security.add_grant(grant);
        }
        let msg = match actions.execute(&self.db, &schema, &r.action, &r.params, &actor) {
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
        self.refresh_security_after_action(&r.action, &r.params, &actor)?;
        let mut evidence =
            redact_action_evidence(&r.params, &sensitive_params, schema_restricted_property);
        evidence.insert("risk_class".into(), action_risk.as_str().into());
        evidence.insert("decision".into(), decision.as_str().into());
        if !policy_scope.is_empty() {
            evidence.insert("policy_scope".into(), policy_scope.clone());
        }
        if !work_unit.is_empty() {
            evidence.insert("work_unit".into(), work_unit.clone());
        }
        let decision_id = uuid::Uuid::new_v4().to_string();
        let attested = attest_action_decision(
            resolved_policy.as_ref(),
            &decision_id,
            &r.action,
            &actor,
            action_risk,
            &policy_namespace,
            decision,
            &mut evidence,
        );
        self.db
            .record_decision_with_attestation(
                &audit::Decision {
                    id: decision_id,
                    timestamp: now_millis(),
                    actor: actor.clone(),
                    action: r.action.clone(),
                    reason: "execute_action".into(),
                    evidence,
                    target_id: target_ids.first().cloned().unwrap_or_default(),
                    outcome: redact_action_outcome(
                        &r.action,
                        &r.params,
                        &msg,
                        schema_restricted_property,
                    ),
                },
                attested.as_ref(),
            )
            .map_err(Status::internal)?;
        // Record the effect against the work unit's blast-radius counters.
        if !work_unit.is_empty() && blast_caps.is_some() && (op_mutations > 0 || op_deletes > 0) {
            self.db
                .add_blast_radius(&work_unit, op_mutations, op_deletes)
                .map_err(Status::internal)?;
        }
        // Record action-class budget usage (one unit per executed action).
        if let Some(budget) = &self.budget {
            budget.record(&budget_subject, 1);
        }
        let mut response = Response::new(ExecuteActionResponse {
            result: Some(ActionResult {
                action: r.action,
                message: msg,
                dry_run: false,
                planned_ops: Vec::new(),
                decision: decision.as_str().into(),
                approval_id: String::new(),
            }),
        });
        if let (Some(_), Some(operation_id)) =
            (invoked_capability.as_deref(), operation_id.as_deref())
        {
            if let Err(error) = receipt_guard
                .as_mut()
                .unwrap()
                .finalize(decision.as_str(), "succeeded")
            {
                let mut status =
                    Status::internal(format!("catalog receipt finalization failed: {error}"));
                status.metadata_mut().insert(
                    "x-sekai-operation-id",
                    operation_id
                        .parse()
                        .map_err(|_| Status::internal("invalid operation id"))?,
                );
                return Err(status);
            }
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
        let mut approval = self
            .db
            .get_action_approval(&r.approval_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("approval not found"))?;
        check_action_admin(&self.security, &approval.policy_scope, &principals)?;
        if approval.status != action_approval::ApprovalStatus::Pending {
            return Err(Status::failed_precondition(format!(
                "approval {} is already {}",
                approval.id,
                approval.status.as_str()
            )));
        }
        let approver = principals.first().cloned().unwrap_or_default();

        // Re-check policy at execution time: a tightened policy that now denies
        // the action must block the resume even though it was approved.
        let target_ids = {
            let actions = self
                .actions
                .read()
                .map_err(|_| Status::internal("action registry unavailable"))?;
            actions
                .target_ids(&self.db, &approval.action, &approval.params)
                .unwrap_or_default()
        };
        let namespace = action_policy_namespace(&self.db, &target_ids, &approval.params);
        let action_risk = {
            let actions = self
                .actions
                .read()
                .map_err(|_| Status::internal("action registry unavailable"))?;
            actions.action_risk_class(&approval.action)
        };
        let resolved_policy = self
            .db
            .resolve_action_policy(&approval.actor, &namespace, &namespace)
            .map_err(Status::internal)?;
        let denying_policy = resolved_policy
            .as_ref()
            .filter(|policy| policy.decide(&approval.action, action_risk) == ActionDecision::Deny);
        if namespace == ERASED_NAMESPACE || denying_policy.is_some() {
            let mut evidence = HashMap::from([
                ("approval_id".to_string(), approval.id.clone()),
                (
                    "policy_scope".to_string(),
                    denying_policy
                        .map(|policy| policy.scope.clone())
                        .unwrap_or_else(|| namespace.clone()),
                ),
                ("risk_class".to_string(), action_risk.as_str().into()),
                ("decision".to_string(), "deny".into()),
            ]);
            if !approval.work_unit.is_empty() {
                evidence.insert("work_unit".into(), approval.work_unit.clone());
            }
            let decision_id = uuid::Uuid::new_v4().to_string();
            let attested = attest_action_decision(
                denying_policy,
                &decision_id,
                &approval.action,
                &approval.actor,
                action_risk,
                &namespace,
                ActionDecision::Deny,
                &mut evidence,
            );
            self.db
                .record_decision_with_attestation(
                    &audit::Decision {
                        id: decision_id,
                        timestamp: now_millis(),
                        actor: approver,
                        action: approval.action.clone(),
                        reason: "action_approval_policy_denied".into(),
                        evidence,
                        target_id: approval.target_id.clone(),
                        outcome: "policy now denies the held action".into(),
                    },
                    attested.as_ref(),
                )
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "action policy now denies this approval",
            ));
        }

        // Resumed actions must still be metered like the direct path: enforce
        // per-work-unit blast-radius caps and the action-class budget so
        // approval is not a governance bypass (Plan 9, Phase C).
        let (op_mutations, op_deletes) = {
            let actions = self
                .actions
                .read()
                .map_err(|_| Status::internal("action registry unavailable"))?;
            actions.action_op_counts(&approval.action, &approval.params)
        };
        let blast_caps = resolved_policy.as_ref().and_then(|policy| {
            match (
                policy.max_mutations_per_work_unit,
                policy.max_deletes_per_work_unit,
            ) {
                (None, None) => None,
                caps => Some(caps),
            }
        });
        if !approval.work_unit.is_empty()
            && let Some((max_mutations, max_deletes)) = blast_caps
        {
            let (used_mutations, used_deletes) = self
                .db
                .get_blast_radius(&approval.work_unit)
                .map_err(Status::internal)?;
            let exceeds = |cap: Option<u32>, used: u32, add: u32| {
                cap.is_some_and(|cap| used.saturating_add(add) > cap)
            };
            if exceeds(max_deletes, used_deletes, op_deletes)
                || exceeds(max_mutations, used_mutations, op_mutations)
            {
                return Err(Status::resource_exhausted(format!(
                    "blast-radius cap exceeded for work unit {}",
                    approval.work_unit
                )));
            }
        }
        let budget_subject =
            action_budget_subject(action_risk.as_str(), &namespace, &approval.actor);
        if let Some(budget) = &self.budget
            && budget.check(&budget_subject, 1).is_err()
        {
            let mut evidence =
                HashMap::from([("budget_subject".to_string(), budget_subject.clone())]);
            evidence.insert("risk_class".to_string(), action_risk.as_str().into());
            evidence.insert("decision".to_string(), "deny".into());
            if !approval.work_unit.is_empty() {
                evidence.insert("work_unit".into(), approval.work_unit.clone());
            }
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: approver,
                    action: approval.action.clone(),
                    reason: "action_budget_exceeded".into(),
                    evidence,
                    target_id: approval.target_id.clone(),
                    outcome: format!("action budget exhausted for {budget_subject}"),
                })
                .map_err(Status::internal)?;
            return Err(Status::resource_exhausted(format!(
                "action budget exhausted for {}",
                budget_subject
            )));
        }

        // Resume the effect, re-checking write access, markings, and purpose
        // for the original proposer (authority may have changed while held).
        let proposer = vec![approval.actor.clone()];
        let actions = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let resume_targets = actions
            .target_ids(&self.db, &approval.action, &approval.params)
            .map_err(Status::invalid_argument)?;
        for target_id in &resume_targets {
            if let Some(target) = self.db.get_object(target_id).map_err(Status::internal)? {
                enforce_object_marking_access(
                    &self.db,
                    &target,
                    &proposer,
                    &format!("approve_action:{}:{}", approval.action, target_id),
                )?;
            }
        }
        let required_purpose = actions
            .get_action_type(&approval.action)
            .map(|action_type| action_type.required_purpose.clone())
            .unwrap_or_default();
        if !required_purpose.trim().is_empty() {
            let authority = resolve_principal_authority(&self.db, &proposer)?;
            let purpose = markings::evaluate_purpose_access(
                &format!("approve_action:{}", approval.action),
                &required_purpose,
                &authority,
            );
            if purpose.decision == markings::MarkingDecision::Deny {
                let evidence = HashMap::from([
                    ("required_purpose".into(), purpose.required_purpose.clone()),
                    ("detail".into(), purpose.detail.clone()),
                    ("outcome".into(), "denied".into()),
                ]);
                let _ = record_marking_or_purpose_decision(
                    &self.db,
                    &approval.actor,
                    "purpose.execute",
                    approval.target_id.as_str(),
                    &purpose.decision_id,
                    "denied",
                    evidence,
                );
                return Err(Status::permission_denied("purpose not allow-listed"));
            }
            if purpose.decision == markings::MarkingDecision::Allow {
                let evidence = HashMap::from([
                    ("required_purpose".into(), purpose.required_purpose.clone()),
                    ("detail".into(), purpose.detail.clone()),
                    ("outcome".into(), "allowed".into()),
                ]);
                record_marking_or_purpose_decision(
                    &self.db,
                    &approval.actor,
                    "purpose.execute",
                    approval.target_id.as_str(),
                    &purpose.decision_id,
                    "allowed",
                    evidence,
                )?;
            }
        }
        drop(actions);
        let msg = self.run_action_effect(
            &approval.action,
            &approval.params,
            &approval.actor,
            &proposer,
        )?;

        // Record the effect against blast-radius counters and the action budget.
        if !approval.work_unit.is_empty()
            && blast_caps.is_some()
            && (op_mutations > 0 || op_deletes > 0)
        {
            let _ = self
                .db
                .add_blast_radius(&approval.work_unit, op_mutations, op_deletes);
        }
        if let Some(budget) = &self.budget {
            budget.record(&budget_subject, 1);
        }

        approval.status = action_approval::ApprovalStatus::Approved;
        approval.decided_by = principals.first().cloned().unwrap_or_default();
        approval.outcome = msg.clone();
        approval.updated = now_millis();
        self.db
            .update_action_approval(&approval)
            .map_err(Status::internal)?;
        // Attest the policy that permitted the resume, so the executed
        // outcome is as replayable as the hold decision was.
        let approval_policy_decision = resolved_policy
            .as_ref()
            .map(|policy| policy.decide(&approval.action, action_risk))
            .unwrap_or(ActionDecision::Allow);
        let mut evidence = HashMap::from([
            ("approval_id".to_string(), approval.id.clone()),
            ("risk_class".to_string(), action_risk.as_str().into()),
            (
                "decision".to_string(),
                approval_policy_decision.as_str().into(),
            ),
            ("approval_status".to_string(), "approved".into()),
        ]);
        if !approval.policy_scope.is_empty() {
            evidence.insert("policy_scope".into(), approval.policy_scope.clone());
        }
        if !approval.work_unit.is_empty() {
            evidence.insert("work_unit".into(), approval.work_unit.clone());
        }
        let decision_id = uuid::Uuid::new_v4().to_string();
        let attested = attest_action_decision(
            resolved_policy.as_ref(),
            &decision_id,
            &approval.action,
            &approval.actor,
            action_risk,
            &namespace,
            approval_policy_decision,
            &mut evidence,
        );
        self.db
            .record_decision_with_attestation(
                &audit::Decision {
                    id: decision_id,
                    timestamp: now_millis(),
                    actor: approval.decided_by.clone(),
                    action: approval.action.clone(),
                    reason: "action_approval_approved".into(),
                    evidence,
                    target_id: approval.target_id.clone(),
                    outcome: msg.clone(),
                },
                attested.as_ref(),
            )
            .map_err(Status::internal)?;

        if let Err(error) = self.resolve_catalog_approval_receipt(
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
        let mut approval = self
            .db
            .get_action_approval(&r.approval_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("approval not found"))?;
        check_action_admin(&self.security, &approval.policy_scope, &principals)?;
        if approval.status != action_approval::ApprovalStatus::Pending {
            return Err(Status::failed_precondition(format!(
                "approval {} is already {}",
                approval.id,
                approval.status.as_str()
            )));
        }
        approval.status = action_approval::ApprovalStatus::Denied;
        approval.decided_by = principals.first().cloned().unwrap_or_default();
        approval.outcome = if r.reason.trim().is_empty() {
            "denied".to_string()
        } else {
            r.reason.trim().to_string()
        };
        approval.updated = now_millis();
        self.db
            .update_action_approval(&approval)
            .map_err(Status::internal)?;
        let mut evidence = HashMap::from([
            ("approval_id".into(), approval.id.clone()),
            ("risk_class".into(), approval.risk_class.clone()),
            ("decision".into(), "deny".into()),
        ]);
        if !approval.policy_scope.is_empty() {
            evidence.insert("policy_scope".into(), approval.policy_scope.clone());
        }
        if !approval.work_unit.is_empty() {
            evidence.insert("work_unit".into(), approval.work_unit.clone());
        }
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now_millis(),
                actor: approval.decided_by.clone(),
                action: approval.action.clone(),
                reason: "action_approval_denied".into(),
                evidence,
                target_id: approval.target_id.clone(),
                outcome: approval.outcome.clone(),
            })
            .map_err(Status::internal)?;
        if let Err(error) = self.resolve_catalog_approval_receipt(
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
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "try_admit_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id
                && record.principal == dedup_principal(&principals)
            {
                let current = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                let reservations = self
                    .db
                    .list_reservations(&coordination::ReservationFilter {
                        work_unit_id: Some(work_unit_id.clone()),
                        status: Some(coordination::RESERVATION_STATUS_ACTIVE.into()),
                        ..Default::default()
                    })
                    .map_err(Status::internal)?;
                return Ok(Response::new(TryAdmitWorkUnitResponse {
                    admitted: current.status == coordination::WORK_UNIT_STATUS_RUNNING,
                    queue_position: 0,
                    reason: String::new(),
                    work_unit: Some(to_proto_work_unit(&current)),
                    reservations: reservations.iter().map(to_proto_reservation).collect(),
                }));
            }
        }
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        let result = self
            .db
            .try_admit_work_unit(&work_unit_id, &owner, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "try_admit_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: result.work_unit.scope_id.clone(),
                work_unit_id: result.work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
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
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "heartbeat_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(HeartbeatWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .heartbeat_work_unit(&work_unit_id, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "heartbeat_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
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
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "complete_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(CompleteWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .complete_work_unit(&work_unit_id, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "complete_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
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
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "fail_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == inner.work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&inner.work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(FailWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .fail_work_unit(
                &inner.work_unit_id,
                &inner.failure_reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "fail_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
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
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "cancel_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == inner.work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&inner.work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(CancelWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .cancel_work_unit(
                &inner.work_unit_id,
                &inner.cancel_reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "cancel_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CancelWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn release_reservation(
        &self,
        req: Request<ReleaseReservationRequest>,
    ) -> Result<Response<ReleaseReservationResponse>, Status> {
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
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "release_reservation")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                return Ok(Response::new(ReleaseReservationResponse { released: 0 }));
            }
        }
        let released = self
            .db
            .release_reservations_for_work_unit(
                &work_unit_id,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::internal)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "release_reservation".into(),
                principal: dedup_principal(&principals),
                scope_id: existing.scope_id.clone(),
                work_unit_id: existing.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(ReleaseReservationResponse { released }))
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
    async fn get_coordination_snapshot(
        &self,
        req: Request<GetCoordinationSnapshotRequest>,
    ) -> Result<Response<GetCoordinationSnapshotResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        if is_managed_team_principal(&self.db, &principals)? {
            return Err(Status::permission_denied(
                "the global coordination snapshot requires control-plane administration",
            ));
        }
        let visible_scopes = self
            .db
            .list_contention_scopes()
            .map_err(Status::internal)?
            .into_iter()
            .any(|scope| principal_matches(&scope.owner_principal, &principals));
        if !visible_scopes {
            return Err(Status::permission_denied(
                "snapshot requires scope ownership",
            ));
        }
        let snapshot = self
            .db
            .coordination_snapshot(chrono::Utc::now().timestamp_millis())
            .map_err(Status::internal)?;
        Ok(Response::new(GetCoordinationSnapshotResponse {
            snapshot: Some(to_proto_snapshot(&snapshot)),
        }))
    }
    // --- Remaining RPCs return unimplemented for now (wired in detail later) ---
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
    async fn execute_function(
        &self,
        req: Request<ExecuteFunctionRequest>,
    ) -> Result<Response<ExecuteFunctionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let function = self
            .db
            .get_function(&inner.name)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("function not found"))?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_function_allows_restricted_properties(&schema, &principals, &function)?;
        }
        let result = function::execute_with_filter(&self.db, &function, &inner.params, |object| {
            self.security.can_access(&object.id, &refs)
                && check_team_namespace(&self.db, &principals, &object.namespace, false).is_ok()
                && object_passes_marking(&self.db, object, &principals).unwrap_or(false)
        })
        .map_err(Status::invalid_argument)?;
        let objects = self.resolve_computed_for_responses(result.objects, &principals, None)?;
        Ok(Response::new(ExecuteFunctionResponse {
            result: Some(FunctionResult {
                objects: objects.iter().map(to_proto_obj).collect(),
                aggregates: result.aggregates,
            }),
        }))
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
        let batch_size = visible_limit.max(50).min(200);
        let max_scan = visible_limit.saturating_mul(10).max(200);
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
        let mut decisions = Vec::new();
        let mut offset = 0;
        let mut scanned = 0usize;
        let managed_team_principal = is_managed_team_principal(&self.db, &principals)?;
        while decisions.len() < visible_limit && scanned < max_scan {
            let batch = self
                .db
                .list_decisions(&audit::DecisionFilter {
                    actor: actor_filter.clone(),
                    action: action_filter.clone(),
                    target_id: target_filter.clone(),
                    after: inner.after,
                    limit: batch_size as i32,
                    offset,
                })
                .map_err(Status::internal)?;
            if batch.is_empty() {
                break;
            }
            scanned += batch.len();
            offset += batch.len() as i32;
            for decision in batch {
                if decision.target_id.is_empty() {
                    if managed_team_principal {
                        continue;
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
                    continue;
                }
                decisions.push(Decision {
                    id: decision.id,
                    timestamp: decision.timestamp,
                    actor: decision.actor,
                    action: decision.action,
                    reason: decision.reason,
                    evidence: decision.evidence,
                    target_id: decision.target_id,
                    outcome: decision.outcome,
                });
                if decisions.len() >= visible_limit {
                    break;
                }
            }
        }
        if decisions.len() < visible_limit && scanned >= max_scan {
            return Err(Status::resource_exhausted(
                "decision visibility scan limit exceeded; refine filters",
            ));
        }
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

    async fn discover_temporal_surfaces(
        &self,
        req: Request<DiscoverTemporalSurfacesRequest>,
    ) -> Result<Response<DiscoverTemporalSurfacesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let namespace = req.into_inner().namespace;
        let db = self
            .db
            .require_sqlite_arc()
            .map_err(Status::failed_precondition)?;
        let surfaces = db
            .discover_temporal_surfaces(&namespace)
            .map_err(Status::internal)?
            .into_iter()
            .map(|s| TemporalSurfaceDiscovery {
                namespace: s.namespace,
                surface_kind: s.surface_kind.as_str().into(),
                surface_name: s.surface_name,
                history_retained: s.history_retained,
                policy_version: s.policy_version,
                preserve_conflicts: s.preserve_conflicts,
            })
            .collect();
        Ok(Response::new(DiscoverTemporalSurfacesResponse { surfaces }))
    }

    async fn query_temporal_as_of(
        &self,
        req: Request<QueryTemporalAsOfRequest>,
    ) -> Result<Response<QueryTemporalAsOfResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        if inner.subject_id.is_empty() {
            return Err(Status::invalid_argument("subject_id required"));
        }
        // Authorization: current object ACL when the subject still exists.
        // Non-disclosure for denied subjects (same as GetObject).
        if let Some(object) = self
            .db
            .get_object(&inner.subject_id)
            .map_err(Status::internal)?
        {
            check_read(&self.security, &object.id, &principals)?;
            check_object_namespace_access(&self.db, &principals, &object.id, false)?;
        } else {
            // Orphan history: require an explicit ACL grant on the subject id
            // so counts/existence do not leak across principals without access.
            let refs: Vec<&str> = principals.iter().map(String::as_str).collect();
            if !self.security.can_access(&inner.subject_id, &refs) {
                return Ok(Response::new(QueryTemporalAsOfResponse {
                    assertions: vec![],
                    selected_revision: 0,
                    next_page_token: String::new(),
                    outcome: "not_retained".into(),
                }));
            }
        }

        let unknown_bounds =
            crate::sekai::temporal::UnknownBoundsPolicy::parse(&inner.unknown_bounds_policy)
                .map_err(Status::invalid_argument)?;
        let valid_at_ms = match inner.valid_at_kind.as_str() {
            "" => None,
            "known" => Some(inner.valid_at_ms),
            other => {
                return Err(Status::invalid_argument(format!(
                    "valid_at_kind must be empty or known, got {other}"
                )));
            }
        };
        let page_token = if inner.page_token.is_empty() {
            None
        } else {
            let parts: Vec<&str> = inner.page_token.split('\0').collect();
            if parts.len() != 2 {
                return Err(Status::invalid_argument(
                    "page_token must be assertion_id\\0version",
                ));
            }
            let version: i64 = parts[1]
                .parse()
                .map_err(|_| Status::invalid_argument("page_token version is not an integer"))?;
            Some((parts[0].to_string(), version))
        };
        let db = self
            .db
            .require_sqlite_arc()
            .map_err(Status::failed_precondition)?;
        let result = db
            .query_temporal_as_of(&crate::sekai::temporal::TemporalAsOfQuery {
                namespace: inner.namespace,
                subject_id: inner.subject_id,
                predicate: inner.predicate,
                recorded_revision: inner.recorded_revision,
                valid_at_ms,
                unknown_bounds,
                limit: i64::from(inner.limit),
                page_token,
            })
            .map_err(|e| {
                if e.contains("must be") || e.contains("future") || e.contains("limit") {
                    Status::invalid_argument(e)
                } else {
                    Status::internal(e)
                }
            })?;
        let next_page_token = result
            .next_page_token
            .map(|(id, ver)| format!("{id}\0{ver}"))
            .unwrap_or_default();
        Ok(Response::new(QueryTemporalAsOfResponse {
            assertions: result
                .assertions
                .into_iter()
                .map(temporal_assertion_to_proto)
                .collect(),
            selected_revision: result.selected_revision,
            next_page_token,
            outcome: result.outcome,
        }))
    }

    async fn diff_temporal_history(
        &self,
        req: Request<DiffTemporalHistoryRequest>,
    ) -> Result<Response<DiffTemporalHistoryResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        if inner.subject_id.is_empty() {
            return Err(Status::invalid_argument("subject_id required"));
        }
        if let Some(object) = self
            .db
            .get_object(&inner.subject_id)
            .map_err(Status::internal)?
        {
            check_read(&self.security, &object.id, &principals)?;
            check_object_namespace_access(&self.db, &principals, &object.id, false)?;
        } else {
            let refs: Vec<&str> = principals.iter().map(String::as_str).collect();
            if !self.security.can_access(&inner.subject_id, &refs) {
                return Ok(Response::new(DiffTemporalHistoryResponse {
                    opened: vec![],
                    closed: vec![],
                }));
            }
        }
        let db = self
            .db
            .require_sqlite_arc()
            .map_err(Status::failed_precondition)?;
        let result = db
            .diff_temporal_history(
                &inner.namespace,
                &inner.subject_id,
                &inner.predicate,
                inner.from_revision,
                inner.to_revision,
                i64::from(inner.limit),
            )
            .map_err(|e| {
                if e.contains("must be") || e.contains("limit") {
                    Status::invalid_argument(e)
                } else {
                    Status::internal(e)
                }
            })?;
        Ok(Response::new(DiffTemporalHistoryResponse {
            opened: result
                .opened
                .into_iter()
                .map(temporal_assertion_to_proto)
                .collect(),
            closed: result
                .closed
                .into_iter()
                .map(temporal_assertion_to_proto)
                .collect(),
        }))
    }

    async fn verify_audit_ledger(
        &self,
        req: Request<VerifyAuditLedgerRequest>,
    ) -> Result<Response<VerifyAuditLedgerResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        // The chain walk re-hashes every entry since the last purge anchor;
        // keep that off the async executor threads.
        let db = self.db.clone();
        let report = tokio::task::spawn_blocking(move || db.verify_ledger())
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map_err(Status::internal)?;
        Ok(Response::new(VerifyAuditLedgerResponse {
            ok: report.ok,
            entries_checked: report.entries_checked,
            first_bad_seq: report.first_bad_seq,
            error: report.error,
            anchor_seq: report.anchor_seq,
            head_seq: report.head_seq,
            head_hash: report.head_hash,
        }))
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
        let batch_size = visible_limit.clamp(50, 200);
        let max_scan = (visible_offset + visible_limit).saturating_mul(10).max(200);
        let mut attestations = Vec::new();
        let mut scanned = 0usize;
        let mut skipped = 0usize;
        let mut scan_offset = 0i32;
        while attestations.len() < visible_limit && scanned < max_scan {
            let batch = self
                .db
                .list_attestations(
                    decision_id.as_deref(),
                    policy_scope.as_deref(),
                    batch_size as i32,
                    scan_offset,
                )
                .map_err(Status::internal)?;
            if batch.is_empty() {
                break;
            }
            scan_offset += batch.len() as i32;
            scanned += batch.len();
            for attestation in &batch {
                if check_action_admin(&self.security, &attestation.policy_scope, &principals)
                    .is_err()
                {
                    continue;
                }
                if skipped < visible_offset {
                    skipped += 1;
                    continue;
                }
                if attestations.len() < visible_limit {
                    attestations.push(to_proto_attestation(attestation));
                }
            }
        }
        // A short page from an exhausted scan budget must not read like the
        // end of the data (matches list_decisions).
        if attestations.len() < visible_limit && scanned >= max_scan {
            return Err(Status::resource_exhausted(
                "attestation visibility scan limit exceeded; refine filters",
            ));
        }
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

    async fn export_assurance(
        &self,
        req: Request<ExportAssuranceRequest>,
    ) -> Result<Response<ExportAssuranceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        if inner.action.trim().is_empty() {
            return Err(Status::invalid_argument("action required"));
        }
        if inner.policy_scope.trim().is_empty() {
            return Err(Status::invalid_argument("policy_scope required"));
        }
        check_action_admin(&self.security, &inner.policy_scope, &principals)?;

        let limit = if inner.limit > 0 {
            inner.limit.min(200)
        } else {
            100
        };
        let decisions = self
            .db
            .list_decisions(&audit::DecisionFilter {
                actor: None,
                action: Some(inner.action),
                target_id: None,
                after: inner.after,
                limit,
                offset: 0,
            })
            .map_err(Status::internal)?;
        let mut records = Vec::with_capacity(decisions.len());
        for decision in decisions {
            if decision.target_id.is_empty()
                || check_read(&self.security, &decision.target_id, &principals).is_err()
            {
                continue;
            }
            let attestation = decision
                .evidence
                .get(attestation::EVIDENCE_ATTESTATION_ID)
                .map(String::as_str)
                .map(|id| self.db.get_attestation(id))
                .transpose()
                .map_err(Status::internal)?
                .flatten()
                .filter(|proof| proof.policy_scope == inner.policy_scope);
            let verification = if let Some(proof) = &attestation {
                let report = self
                    .db
                    .verify_attestation(&proof.id)
                    .map_err(Status::internal)?;
                Some(VerifyAttestationResponse {
                    ok: report.ok,
                    found: report.found,
                    hash_ok: report.hash_ok,
                    replay_ok: report.replay_ok,
                    replayed_decision: report.replayed_decision,
                    decision_linked: report.decision_linked,
                    error: report.error,
                })
            } else {
                Some(VerifyAttestationResponse {
                    ok: false,
                    found: false,
                    hash_ok: false,
                    replay_ok: false,
                    replayed_decision: String::new(),
                    decision_linked: false,
                    error: "no attestation for requested policy scope".into(),
                })
            };
            records.push(AssuranceRecord {
                decision: Some(Decision {
                    id: decision.id,
                    timestamp: decision.timestamp,
                    actor: decision.actor,
                    action: decision.action,
                    reason: decision.reason,
                    evidence: decision.evidence,
                    target_id: decision.target_id,
                    outcome: decision.outcome,
                }),
                attestation: attestation.as_ref().map(to_proto_attestation),
                verification,
            });
        }

        let db = self.db.clone();
        let ledger = tokio::task::spawn_blocking(move || db.verify_ledger())
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map_err(Status::internal)?;
        Ok(Response::new(ExportAssuranceResponse {
            records,
            ledger: Some(VerifyAuditLedgerResponse {
                ok: ledger.ok,
                entries_checked: ledger.entries_checked,
                first_bad_seq: ledger.first_bad_seq,
                error: ledger.error,
                anchor_seq: ledger.anchor_seq,
                head_seq: ledger.head_seq,
                head_hash: ledger.head_hash,
            }),
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

    #[cfg(any())]
    async fn create_tenant(
        &self,
        req: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        let actor = tenant_admin_actor(&req)?;
        let key = require_tenant_request_key(&req.get_ref().idempotency_key)?;
        let tenant = self
            .db
            .create_tenant(&actor, &key, chrono::Utc::now().timestamp_millis())
            .map_err(tenant_status)?;
        Ok(Response::new(CreateTenantResponse {
            tenant: Some(to_proto_tenant(tenant)),
        }))
    }

    #[cfg(any())]
    async fn get_tenant(
        &self,
        req: Request<GetTenantRequest>,
    ) -> Result<Response<GetTenantResponse>, Status> {
        tenant_admin_actor(&req)?;
        let id = require_tenant_id(&req.get_ref().tenant_id)?;
        let tenant = self
            .db
            .get_tenant(&id)
            .map_err(tenant_status)?
            .ok_or_else(|| Status::not_found("tenant not found"))?;
        Ok(Response::new(GetTenantResponse {
            tenant: Some(to_proto_tenant(tenant)),
        }))
    }

    #[cfg(any())]
    async fn suspend_tenant(
        &self,
        req: Request<SuspendTenantRequest>,
    ) -> Result<Response<SuspendTenantResponse>, Status> {
        let actor = tenant_admin_actor(&req)?;
        let id = require_tenant_id(&req.get_ref().tenant_id)?;
        let key = require_tenant_request_key(&req.get_ref().idempotency_key)?;
        let tenant = self
            .db
            .suspend_tenant(&id, &actor, &key, chrono::Utc::now().timestamp_millis())
            .map_err(tenant_status)?;
        Ok(Response::new(SuspendTenantResponse {
            tenant: Some(to_proto_tenant(tenant)),
        }))
    }

    #[cfg(any())]
    async fn reactivate_tenant(
        &self,
        req: Request<ReactivateTenantRequest>,
    ) -> Result<Response<ReactivateTenantResponse>, Status> {
        let actor = tenant_admin_actor(&req)?;
        let id = require_tenant_id(&req.get_ref().tenant_id)?;
        let key = require_tenant_request_key(&req.get_ref().idempotency_key)?;
        let tenant = self
            .db
            .reactivate_tenant(&id, &actor, &key, chrono::Utc::now().timestamp_millis())
            .map_err(tenant_status)?;
        Ok(Response::new(ReactivateTenantResponse {
            tenant: Some(to_proto_tenant(tenant)),
        }))
    }

    #[cfg(any())]
    async fn request_tenant_closure(
        &self,
        req: Request<RequestTenantClosureRequest>,
    ) -> Result<Response<RequestTenantClosureResponse>, Status> {
        let actor = tenant_admin_actor(&req)?;
        let id = require_tenant_id(&req.get_ref().tenant_id)?;
        let key = require_tenant_request_key(&req.get_ref().idempotency_key)?;
        let tenant = self
            .db
            .request_tenant_closure(&id, &actor, &key, chrono::Utc::now().timestamp_millis())
            .map_err(tenant_status)?;
        Ok(Response::new(RequestTenantClosureResponse {
            tenant: Some(to_proto_tenant(tenant)),
        }))
    }

    #[cfg(any())]
    async fn create_tenant_namespace(
        &self,
        req: Request<CreateTenantNamespaceRequest>,
    ) -> Result<Response<CreateTenantNamespaceResponse>, Status> {
        let actor = tenant_admin_actor(&req)?;
        let context = request_tenant_context(&req)?.ok_or_else(|| {
            Status::failed_precondition("tenant-owned namespaces are disabled in local mode")
        })?;
        let inner = req.into_inner();
        let namespace = validate_credential_principal(&inner.namespace)?;
        let tenant_id = require_tenant_id(&inner.tenant_id)?;
        if context != tenant_id {
            return Err(Status::permission_denied("tenant context mismatch"));
        }
        let migrated_from = if inner.migrated_from_namespace.trim().is_empty() {
            String::new()
        } else {
            validate_credential_principal(&inner.migrated_from_namespace)?
        };
        let ownership = self
            .db
            .bind_namespace_to_tenant(
                &namespace,
                &tenant_id,
                &migrated_from,
                &actor,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(tenant_status)?;
        Ok(Response::new(CreateTenantNamespaceResponse {
            ownership: Some(to_proto_namespace_ownership(ownership)),
        }))
    }

    #[cfg(any())]
    async fn get_namespace_ownership(
        &self,
        req: Request<GetNamespaceOwnershipRequest>,
    ) -> Result<Response<GetNamespaceOwnershipResponse>, Status> {
        let context = request_tenant_context(&req)?;
        let namespace = validate_credential_principal(&req.get_ref().namespace)?;
        enforce_namespace_tenant_context(&self.db, context.as_deref(), &namespace, false)?;
        let ownership = self
            .db
            .namespace_ownership(&namespace)
            .map_err(tenant_status)?
            .ok_or_else(|| Status::not_found("namespace ownership not found"))?;
        Ok(Response::new(GetNamespaceOwnershipResponse {
            ownership: Some(to_proto_namespace_ownership(ownership)),
        }))
    }

    #[cfg(any())]
    async fn create_tenant_membership(
        &self,
        req: Request<CreateTenantMembershipRequest>,
    ) -> Result<Response<CreateTenantMembershipResponse>, Status> {
        let (actor, platform_admin, tenant_id) = membership_authority(&req)?;
        let inner = req.into_inner();
        let requested_tenant = require_tenant_id(&inner.tenant_id)?;
        enforce_membership_tenant_scope(tenant_id.as_deref(), &requested_tenant)?;
        let subject_id = require_subject_id(&inner.subject_id)?;
        let role = membership_role(inner.role)?;
        let membership = self
            .db
            .create_tenant_membership(
                &requested_tenant,
                &subject_id,
                role,
                &actor,
                platform_admin,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(tenant_status)?;
        Ok(Response::new(CreateTenantMembershipResponse {
            membership: Some(to_proto_membership(membership)),
        }))
    }

    #[cfg(any())]
    async fn change_tenant_membership_role(
        &self,
        req: Request<ChangeTenantMembershipRoleRequest>,
    ) -> Result<Response<ChangeTenantMembershipRoleResponse>, Status> {
        let (actor, platform_admin, tenant_id) = membership_authority(&req)?;
        let inner = req.into_inner();
        let requested_tenant = require_tenant_id(&inner.tenant_id)?;
        enforce_membership_tenant_scope(tenant_id.as_deref(), &requested_tenant)?;
        let membership = self
            .db
            .change_tenant_membership_role(
                &requested_tenant,
                &require_subject_id(&inner.subject_id)?,
                membership_role(inner.role)?,
                &actor,
                platform_admin,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(tenant_status)?;
        Ok(Response::new(ChangeTenantMembershipRoleResponse {
            membership: Some(to_proto_membership(membership)),
        }))
    }

    #[cfg(any())]
    async fn list_tenant_memberships(
        &self,
        req: Request<ListTenantMembershipsRequest>,
    ) -> Result<Response<ListTenantMembershipsResponse>, Status> {
        let (actor, platform_admin, tenant_id) = membership_authority(&req)?;
        let requested_tenant = require_tenant_id(&req.get_ref().tenant_id)?;
        enforce_membership_tenant_scope(tenant_id.as_deref(), &requested_tenant)?;
        let memberships = self
            .db
            .list_tenant_memberships(&requested_tenant, &actor, platform_admin)
            .map_err(tenant_status)?;
        Ok(Response::new(ListTenantMembershipsResponse {
            memberships: memberships.into_iter().map(to_proto_membership).collect(),
        }))
    }

    #[cfg(any())]
    async fn revoke_tenant_membership(
        &self,
        req: Request<RevokeTenantMembershipRequest>,
    ) -> Result<Response<RevokeTenantMembershipResponse>, Status> {
        let (actor, platform_admin, tenant_id) = membership_authority(&req)?;
        let inner = req.into_inner();
        let requested_tenant = require_tenant_id(&inner.tenant_id)?;
        enforce_membership_tenant_scope(tenant_id.as_deref(), &requested_tenant)?;
        let membership = self
            .db
            .revoke_tenant_membership(
                &requested_tenant,
                &require_subject_id(&inner.subject_id)?,
                &actor,
                platform_admin,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(tenant_status)?;
        Ok(Response::new(RevokeTenantMembershipResponse {
            membership: Some(to_proto_membership(membership)),
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

    async fn register_evidence_producer(
        &self,
        req: Request<RegisterEvidenceProducerRequest>,
    ) -> Result<Response<RegisterEvidenceProducerResponse>, Status> {
        let principals = caller_principals(&req);
        require_evidence_admin(&self.security, &principals)?;
        let capability = req
            .into_inner()
            .capability
            .ok_or_else(|| Status::invalid_argument("capability required"))?;
        let capability = from_proto_evidence_producer(capability)?;
        self.db
            .upsert_evidence_producer(&capability, now_millis())
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(RegisterEvidenceProducerResponse {}))
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
        let result =
            self.admit_and_project_evidence(&envelope, &envelope.producer_identity, now_millis())?;
        Ok(Response::new(SubmitEvidenceResponse {
            result: Some(result),
        }))
    }

    async fn submit_evidence_batch(
        &self,
        req: Request<SubmitEvidenceBatchRequest>,
    ) -> Result<Response<SubmitEvidenceBatchResponse>, Status> {
        const MAX_BATCH: usize = 100;
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let envelopes = req.into_inner().envelopes;
        if envelopes.is_empty() || envelopes.len() > MAX_BATCH {
            return Err(Status::invalid_argument(
                "evidence batch must contain between 1 and 100 envelopes",
            ));
        }
        let envelopes = envelopes
            .into_iter()
            .map(from_proto_evidence_envelope)
            .collect::<Result<Vec<_>, _>>()?;
        if envelopes
            .iter()
            .any(|envelope| !principals.contains(&envelope.producer_identity))
        {
            return Err(Status::permission_denied(
                "authenticated producer must match every envelope attribution",
            ));
        }
        let mut results = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            results.push(self.admit_and_project_evidence(
                &envelope,
                &envelope.producer_identity,
                now_millis(),
            )?);
        }
        Ok(Response::new(SubmitEvidenceBatchResponse { results }))
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

    async fn get_evidence_submission_content(
        &self,
        req: Request<GetEvidenceSubmissionContentRequest>,
    ) -> Result<Response<GetEvidenceSubmissionContentResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let submission_id = req.into_inner().submission_id;
        let not_found = || Status::not_found("evidence submission content not found");
        let submission = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(not_found)?;
        if !evidence_content_is_readable(submission.lifecycle_state) {
            return Err(not_found());
        }
        let evidence_object_id = self
            .db
            .get_evidence_projection_object_id(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(not_found)?;
        let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        if !self.security.can_access(&evidence_object_id, &refs) {
            return Err(not_found());
        }
        let envelope = submission.envelope.as_ref().ok_or_else(not_found)?;
        let computed_digest =
            crate::sekai::evidence_store::canonical_content_digest(&envelope.content)
                .map_err(Status::internal)?;
        if computed_digest != submission.content_digest
            || envelope.content_digest != submission.content_digest
        {
            return Err(Status::data_loss(
                "retained evidence content digest mismatch",
            ));
        }
        Ok(Response::new(GetEvidenceSubmissionContentResponse {
            submission_id,
            envelope: Some(to_proto_evidence_envelope(envelope)),
            lifecycle_state: submission.lifecycle_state.as_str().into(),
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

    async fn replay_evidence_submission(
        &self,
        req: Request<ReplayEvidenceSubmissionRequest>,
    ) -> Result<Response<ReplayEvidenceSubmissionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let submission_id = req.into_inner().submission_id;
        let submission = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("evidence submission not found"))?;
        if !can_operate_evidence_submission(&self.security, &submission, &principals) {
            return Err(Status::permission_denied("evidence replay denied"));
        }
        let projection = self
            .db
            .project_evidence_submission(&submission_id, now_millis())
            .map_err(Status::failed_precondition)?;
        if let Some(object_id) = projection.evidence_object_id.as_deref() {
            for grant in self.db.list_grants(object_id).map_err(Status::internal)? {
                self.security.add_grant(&grant);
            }
        }
        let current = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::internal("evidence submission disappeared"))?;
        Ok(Response::new(ReplayEvidenceSubmissionResponse {
            result: Some(EvidenceSubmissionResult {
                submission: Some(to_proto_evidence_submission(&current)),
                admitted: current.lifecycle_state
                    != evidence_domain::EvidenceLifecycleState::Rejected,
                deduplicated: true,
                projected: projection.projected,
            }),
        }))
    }

    async fn retract_evidence(
        &self,
        req: Request<RetractEvidenceRequest>,
    ) -> Result<Response<RetractEvidenceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let request = req.into_inner();
        let result = self.create_evidence_lifecycle_marker(
            request.submission_id,
            request.source_version,
            request.source_sequence,
            request.idempotency_key,
            request.observed_at_ms,
            evidence_domain::EvidenceIntent::Retract,
            &principals,
        )?;
        Ok(Response::new(RetractEvidenceResponse {
            result: Some(result),
        }))
    }

    async fn mark_evidence_stale(
        &self,
        req: Request<MarkEvidenceStaleRequest>,
    ) -> Result<Response<MarkEvidenceStaleResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let request = req.into_inner();
        let result = self.create_evidence_lifecycle_marker(
            request.submission_id,
            request.source_version,
            request.source_sequence,
            request.idempotency_key,
            request.observed_at_ms,
            evidence_domain::EvidenceIntent::MarkStale,
            &principals,
        )?;
        Ok(Response::new(MarkEvidenceStaleResponse {
            result: Some(result),
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

#[cfg(any())]
fn tenant_admin_actor(req: &Request<impl std::any::Any>) -> Result<String, Status> {
    let principals = caller_principals(req);
    require_credential_admin(&principals)?;
    principals
        .into_iter()
        .find(|principal| matches!(principal.as_str(), "root" | "local"))
        .ok_or_else(|| Status::permission_denied("tenant admin required"))
}

#[cfg(any())]
fn require_tenant_id(value: &str) -> Result<String, Status> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value.starts_with("tenant_")
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(Status::invalid_argument("invalid tenant_id"));
    }
    Ok(value.to_string())
}

#[cfg(any())]
fn require_tenant_request_key(value: &str) -> Result<String, Status> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 {
        return Err(Status::invalid_argument(
            "idempotency_key must be 1..=200 characters",
        ));
    }
    Ok(value.to_string())
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

#[cfg(any())]
fn tenant_status(error: crate::sekai::tenant::TenantError) -> Status {
    use crate::sekai::tenant::TenantError;
    match error {
        TenantError::NotFound => Status::not_found("tenant not found"),
        TenantError::PermissionDenied => {
            Status::permission_denied("tenant membership authority required")
        }
        TenantError::LastOwner => {
            Status::failed_precondition("the last active tenant owner cannot be removed or demoted")
        }
        TenantError::Conflict(message) => Status::already_exists(message),
        TenantError::InvalidTransition { from, action } => Status::failed_precondition(format!(
            "cannot {action} tenant in {} state",
            from.as_str()
        )),
        TenantError::AdmissionBlocked(state) => Status::failed_precondition(format!(
            "tenant in {} state cannot admit new work",
            state.as_str()
        )),
        TenantError::Storage(message) => Status::internal(message),
    }
}

#[cfg(any())]
fn to_proto_tenant(record: crate::sekai::tenant::TenantRecord) -> TenantRecord {
    let state = match record.state {
        crate::sekai::tenant::TenantState::Active => TenantLifecycleState::Active,
        crate::sekai::tenant::TenantState::Suspended => TenantLifecycleState::Suspended,
        crate::sekai::tenant::TenantState::ClosurePending => TenantLifecycleState::ClosurePending,
    };
    TenantRecord {
        contract_version: record.contract_version,
        id: record.id,
        state: state as i32,
        created_at_ms: record.created_at_ms,
        updated_at_ms: record.updated_at_ms,
    }
}

#[cfg(any())]
fn to_proto_namespace_ownership(
    ownership: crate::sekai::tenant::NamespaceOwnership,
) -> NamespaceOwnership {
    NamespaceOwnership {
        contract_version: ownership.contract_version,
        namespace: ownership.namespace,
        tenant_id: ownership.tenant_id,
        migrated_from_namespace: ownership.migrated_from_namespace,
        created_at_ms: ownership.created_at_ms,
    }
}

#[cfg(any())]
fn membership_authority(
    req: &Request<impl std::any::Any>,
) -> Result<(String, bool, Option<String>), Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let actor = principals
        .into_iter()
        .next()
        .ok_or_else(|| Status::unauthenticated("authenticated principal required"))?;
    let platform_admin = matches!(actor.as_str(), "root" | "local");
    let tenant_id = request_tenant_context(req)?;
    if platform_admin {
        return Ok((actor, true, tenant_id));
    }
    let tenant = tenant_id
        .as_deref()
        .ok_or_else(|| Status::permission_denied("tenant context required"))?;
    let subject = actor.strip_prefix(&format!("{tenant}.")).unwrap_or(&actor);
    Ok((require_subject_id(subject)?, false, tenant_id))
}

#[cfg(any())]
fn enforce_membership_tenant_scope(
    tenant_context: Option<&str>,
    tenant_id: &str,
) -> Result<(), Status> {
    if tenant_context.is_some_and(|context| context != tenant_id) {
        Err(Status::permission_denied("tenant context mismatch"))
    } else {
        Ok(())
    }
}

#[cfg(any())]
fn require_subject_id(value: &str) -> Result<String, Status> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 200
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
    {
        return Err(Status::invalid_argument(
            "subject_id must match [a-zA-Z0-9._-]+ and be at most 200 characters",
        ));
    }
    Ok(value.to_string())
}

#[cfg(any())]
fn membership_role(value: i32) -> Result<crate::sekai::tenant::TenantRole, Status> {
    match TenantMembershipRole::try_from(value).ok() {
        Some(TenantMembershipRole::Owner) => Ok(crate::sekai::tenant::TenantRole::Owner),
        Some(TenantMembershipRole::Admin) => Ok(crate::sekai::tenant::TenantRole::Admin),
        Some(TenantMembershipRole::Member) => Ok(crate::sekai::tenant::TenantRole::Member),
        Some(TenantMembershipRole::BillingViewer) => {
            Ok(crate::sekai::tenant::TenantRole::BillingViewer)
        }
        _ => Err(Status::invalid_argument("tenant membership role required")),
    }
}

#[cfg(any())]
fn to_proto_membership(membership: crate::sekai::tenant::TenantMembership) -> TenantMembership {
    let role = match membership.role {
        crate::sekai::tenant::TenantRole::Owner => TenantMembershipRole::Owner,
        crate::sekai::tenant::TenantRole::Admin => TenantMembershipRole::Admin,
        crate::sekai::tenant::TenantRole::Member => TenantMembershipRole::Member,
        crate::sekai::tenant::TenantRole::BillingViewer => TenantMembershipRole::BillingViewer,
    };
    TenantMembership {
        contract_version: membership.contract_version,
        tenant_id: membership.tenant_id,
        subject_id: membership.subject_id,
        role: role as i32,
        active: membership.active,
        created_at_ms: membership.created_at_ms,
        updated_at_ms: membership.updated_at_ms,
        revoked_at_ms: membership.revoked_at_ms,
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

    #[cfg(any())]
    fn with_tenant_context<T>(payload: T, principal: &str, tenant_id: &str) -> Request<T> {
        let mut req = with_named_principal(payload, principal);
        req.metadata_mut()
            .insert("x-sekai-auth-source", MetadataValue::from_static("token"));
        req.metadata_mut().insert(
            "x-sekai-tenant-id",
            MetadataValue::try_from(tenant_id).unwrap(),
        );
        req
    }

    fn add_object_grant(
        svc: &SekaiServiceImpl,
        object_id: &str,
        principal: &str,
        role: security::Role,
    ) {
        let grant = security::Grant {
            id: format!("handoff-grant-{object_id}-{principal}"),
            object_id: object_id.into(),
            principal: principal.into(),
            role,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
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

    fn seed_object_kind(svc: &SekaiServiceImpl, id: &str, kind: &str) {
        svc.db
            .create_object(&domain::Object {
                id: id.into(),
                kind: kind.into(),
                name: id.into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
    }

    fn seed_ontology_class(svc: &SekaiServiceImpl, name: &str, kind: &str) {
        let mut class = ontology::OntologyClass {
            name: name.into(),
            description: String::new(),
            superclasses: vec![],
            equivalent_classes: vec![],
            disjoint_classes: vec![],
            properties: vec![],
            is_builtin: false,
            mapped_kind: kind.into(),
        };
        if kind.is_empty() {
            class.mapped_kind.clear();
        }
        svc.db.upsert_ontology_class(&class).unwrap();
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

    fn assign_color_action() -> ActionTypeDef {
        ActionTypeDef {
            name: "assign_color".into(),
            description: "Assign a widget color".into(),
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
                relation: "".into(),
            }],
            target_kind: "widget".into(),
            created: 0,
            required_purpose: String::new(),
        }
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
    async fn execute_action_denies_when_purpose_not_allow_listed() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let mut action = assign_color_action();
        action.required_purpose = "incident-response".into();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(action),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "widget-purpose",
                HashMap::from([("name".into(), "w".into())]),
            )),
        }))
        .await
        .unwrap();
        grant_object_role(&svc, "widget-purpose", "tester", security::Role::Editor);

        let err = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "assign_color".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-purpose".into()),
                        ("color".into(), "red".into()),
                    ]),
                    actor: "tester".into(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("purpose"));
    }

    #[tokio::test]
    async fn execute_action_allows_when_purpose_is_allow_listed() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let mut action = assign_color_action();
        action.name = "assign_color_purpose".into();
        action.required_purpose = "incident-response".into();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(action),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "widget-purpose-ok",
                HashMap::from([("name".into(), "w".into())]),
            )),
        }))
        .await
        .unwrap();
        grant_object_role(&svc, "widget-purpose-ok", "tester", security::Role::Editor);
        svc.db
            .create_object(&domain::Object {
                id: "principal-tester".into(),
                kind: markings::PRINCIPAL_PROFILE_KIND.into(),
                name: "tester".into(),
                namespace: "".into(),
                external_id: markings::principal_profile_external_id("tester"),
                properties: HashMap::from([
                    (
                        markings::PRINCIPAL_ALLOWED_PURPOSES_PROPERTY.into(),
                        "incident-response".into(),
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
        grant_object_role(&svc, "principal-tester", "root", security::Role::Admin);

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "assign_color_purpose".into(),
                params: HashMap::from([
                    ("id".into(), "widget-purpose-ok".into()),
                    ("color".into(), "blue".into()),
                ]),
                actor: "tester".into(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        let obj = svc.db.get_object("widget-purpose-ok").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "blue");
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("purpose.execute".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(decisions.iter().any(|d| d.outcome == "allowed"));
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
    async fn verify_audit_ledger_reports_clean_chain() {
        let svc = service();
        for i in 0..3 {
            svc.record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: format!("d{i}"),
                    timestamp: 0,
                    actor: "tester".into(),
                    action: "act".into(),
                    reason: String::new(),
                    evidence: HashMap::new(),
                    target_id: String::new(),
                    outcome: "done".into(),
                }),
            }))
            .await
            .unwrap();
        }
        let report = svc
            .verify_audit_ledger(with_principal(VerifyAuditLedgerRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(report.ok, "{}", report.error);
        assert_eq!(report.entries_checked, 3);
        assert_eq!(report.head_seq, 3);
        assert!(!report.head_hash.is_empty());
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
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("expected float"));
    }

    #[tokio::test]
    async fn object_responses_redact_restricted_schema_properties() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
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
        let create_err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-denied",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("secret_note".into(), "launch code".into()),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(create_err.code(), tonic::Code::PermissionDenied);

        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(widget_object(
                    "widget-secret",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("secret_note".into(), "launch code".into()),
                    ]),
                )),
            },
            "root",
        ))
        .await
        .unwrap();
        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "widget-secret".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(got.properties["name"], "spinner");
        assert_eq!(got.properties["secret_note"], "[redacted]");

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "list_widgets".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![PipelineStep {
                    op: "filter".into(),
                    kind: "widget".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                }],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        let function_result = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "list_widgets".into(),
                params: HashMap::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(
            function_result.objects[0].properties["secret_note"],
            "[redacted]"
        );

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "filter_secret_widgets".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![PipelineStep {
                    op: "filter".into(),
                    kind: "widget".into(),
                    property: "secret_note".into(),
                    value: "launch code".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                }],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        let function_err = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "filter_secret_widgets".into(),
                params: HashMap::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(function_err.code(), tonic::Code::PermissionDenied);

        let lineage = svc
            .get_lineage(with_principal(GetLineageRequest {
                object_id: "widget-secret".into(),
                max_nodes: 10,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(
            lineage.nodes[0].object.as_ref().unwrap().properties["secret_note"],
            "[redacted]"
        );

        let find_err = svc
            .find_by_property(with_principal(FindByPropertyRequest {
                kind: "widget".into(),
                key: "secret_note".into(),
                value: "launch code".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(find_err.code(), tonic::Code::PermissionDenied);

        let list_err = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "widget".into(),
                    property_filters: vec![PropertyFilter {
                        key: "secret_note".into(),
                        op: "eq".into(),
                        value: "launch code".into(),
                    }],
                    limit: 10,
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(list_err.code(), tonic::Code::PermissionDenied);

        let object_set_err = svc
            .create_object_set(with_principal(CreateObjectSetRequest {
                object_set: Some(ObjectSet {
                    id: "secret-set".into(),
                    name: "secret set".into(),
                    description: String::new(),
                    filter: Some(ListFilter {
                        kind: "widget".into(),
                        property_filters: vec![PropertyFilter {
                            key: "secret_note".into(),
                            op: "eq".into(),
                            value: "launch code".into(),
                        }],
                        limit: 10,
                        ..Default::default()
                    }),
                    owner_principal: String::new(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(object_set_err.code(), tonic::Code::PermissionDenied);

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
        assert_eq!(listed.objects[0].properties["secret_note"], "[redacted]");

        let mut update = got;
        update.name = "renamed".into();
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(update),
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-secret").unwrap().unwrap();
        assert_eq!(stored.name, "renamed");
        assert_eq!(stored.properties["secret_note"], "launch code");

        let mut attempted_overwrite = stored.clone();
        attempted_overwrite
            .properties
            .insert("secret_note".into(), "attacker code".into());
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(to_proto_obj(&attempted_overwrite)),
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-secret").unwrap().unwrap();
        assert_eq!(stored.properties["secret_note"], "launch code");

        let mut changed_secret = stored.clone();
        changed_secret
            .properties
            .insert("secret_note".into(), "rotated code".into());
        svc.db
            .update_object_with_audit(&changed_secret, "root")
            .unwrap();
        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "widget-secret".into(),
                limit: 20,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;
        let secret_change = changes
            .iter()
            .find(|change| change.field == "properties.secret_note")
            .unwrap();
        assert_eq!(secret_change.old_value, "[redacted]");
        assert_eq!(secret_change.new_value, "[redacted]");

        grant_object_role(&svc, "widget-secret", "tester", security::Role::Admin);
        let admin_view = svc
            .get_object(with_principal(GetObjectRequest {
                id: "widget-secret".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(admin_view.properties["secret_note"], "rotated code");

        grant_object_role(&svc, "widget-secret", "reader", security::Role::Viewer);
        svc.delete_object(with_principal(DeleteObjectRequest {
            id: "widget-secret".into(),
        }))
        .await
        .unwrap();
        let deleted_changes = svc
            .list_object_changes(with_named_principal(
                ListObjectChangesRequest {
                    object_id: "widget-secret".into(),
                    limit: 20,
                    offset: 0,
                },
                "reader",
            ))
            .await
            .unwrap()
            .into_inner()
            .changes;
        let deleted_secret_change = deleted_changes
            .iter()
            .find(|change| change.field == "properties.secret_note")
            .unwrap();
        assert_eq!(deleted_secret_change.old_value, "[redacted]");
        assert_eq!(deleted_secret_change.new_value, "[redacted]");
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
    async fn user_defined_action_type_round_trip_and_execute() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let created = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(assign_color_action()),
            }))
            .await
            .unwrap()
            .into_inner()
            .action_type
            .unwrap();
        assert_eq!(created.name, "assign_color");
        assert!(created.created > 0);

        let listed = svc
            .list_action_types(with_principal(ListActionTypesRequest {}))
            .await
            .unwrap()
            .into_inner()
            .action_types;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "assign_color");

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
        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "assign_color".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("color".into(), "blue".into()),
                    ]),
                    actor: "ignored".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "blue");
        let changes = svc.db.list_object_changes("widget-1", 10, 0).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "properties.color");
        assert_eq!(changes[0].changed_by, "alice");
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("assign_color".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "alice");
        assert_eq!(decisions[0].target_id, "widget-1");

        svc.delete_action_type(with_principal(DeleteActionTypeRequest {
            name: "assign_color".into(),
        }))
        .await
        .unwrap();
        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "red".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("unknown action"));
    }

    #[tokio::test]
    async fn user_defined_action_redacts_password_fixed_property_params() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "password".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "set_password".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "value".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "set_property".into(),
                    property: "password".into(),
                    value_from: "value".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
                required_purpose: String::new(),
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_password".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("value".into(), "secret-value".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_password".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].evidence["value"], "[redacted]");
    }

    #[tokio::test]
    async fn user_defined_action_validates_params_and_authorization() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(assign_color_action()),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let missing = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([("id".into(), "widget-1".into())]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::InvalidArgument);
        assert!(missing.message().contains("missing required param: color"));

        let bad_enum = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "green".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(bad_enum.code(), tonic::Code::InvalidArgument);
        assert!(bad_enum.message().contains("not in"));

        let denied = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert!(
            !svc.db
                .get_object("widget-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("color")
        );
    }

    #[tokio::test]
    async fn user_defined_action_rejects_undeclared_property_at_definition() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let mut action_type = assign_color_action();
        action_type.ops[0].property = "undeclared".into();

        let err = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(action_type),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
    }

    #[tokio::test]
    async fn user_defined_action_revalidates_against_current_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(assign_color_action()),
        }))
        .await
        .unwrap();
        let mut changed_schema = widget_schema_type();
        changed_schema
            .properties
            .retain(|property| property.name != "color");
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(changed_schema),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
        assert!(
            !svc.db
                .get_object("widget-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("color")
        );
    }

    #[tokio::test]
    async fn user_defined_action_rejects_undeclared_create_object_kind() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();

        let err = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(ActionTypeDef {
                    name: "spawn_typo".into(),
                    description: "".into(),
                    params: vec![ActionParamDef {
                        name: "child_name".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    }],
                    ops: vec![ActionOp {
                        op: "create_object".into(),
                        property: "widgte".into(),
                        value_from: "child_name".into(),
                        relation: "".into(),
                    }],
                    target_kind: "widget".into(),
                    created: 0,
                    required_purpose: String::new(),
                }),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
    }

    #[tokio::test]
    async fn user_defined_action_rolls_back_when_later_op_fails_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "size".into(),
            r#type: "enum".into(),
            required: false,
            description: "".into(),
            enum_values: vec!["small".into(), "large".into()],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        let mut action_type = assign_color_action();
        action_type.name = "assign_color_and_size".into();
        action_type.params.push(ActionParamDef {
            name: "size".into(),
            r#type: "string".into(),
            required: true,
            enum_values: vec![],
        });
        action_type.ops.push(ActionOp {
            op: "set_property".into(),
            property: "size".into(),
            value_from: "size".into(),
            relation: "".into(),
        });
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(action_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "red".into()),
                    ("size".into(), "small".into()),
                ]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color_and_size".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                            ("size".into(), "medium".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "red");
        assert_eq!(obj.properties["size"], "small");
        assert!(
            svc.db
                .list_object_changes("widget-1", 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn user_defined_action_creates_object_and_link_transactionally() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let action_type = ActionTypeDef {
            name: "spawn_child".into(),
            description: "Create a child widget and link target to sibling".into(),
            params: vec![
                ActionParamDef {
                    name: "child_name".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                },
                ActionParamDef {
                    name: "to_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                },
            ],
            ops: vec![
                ActionOp {
                    op: "create_object".into(),
                    property: "widget".into(),
                    value_from: "child_name".into(),
                    relation: "".into(),
                },
                ActionOp {
                    op: "create_link".into(),
                    property: "to_id".into(),
                    value_from: "".into(),
                    relation: "relates_to".into(),
                },
            ],
            target_kind: "widget".into(),
            created: 0,
            required_purpose: String::new(),
        };
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(action_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "parent".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "sibling".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "spawn_child".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("child_name".into(), "child".into()),
                        ("to_id".into(), "widget-2".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let children = svc.db.find_by_property("widget", "name", "child").unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].namespace, "");
        assert!(svc.db.get_link("widget-1->widget-2").unwrap().is_some());
        assert_eq!(
            svc.db.list_object_changes(&children[0].id, 10, 0).unwrap()[0].changed_by,
            "alice"
        );
    }

    #[tokio::test]
    async fn user_defined_action_create_link_requires_write_on_endpoint() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "link_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "to_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "create_link".into(),
                    property: "to_id".into(),
                    value_from: "".into(),
                    relation: "relates_to".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
                required_purpose: String::new(),
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "one".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "two".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "link_widget".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("to_id".into(), "widget-2".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("widget-1->widget-2").unwrap().is_none());
    }

    #[tokio::test]
    async fn user_defined_action_deletes_link_only_when_authorized_for_both_endpoints() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "unlink_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "link_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "delete_link".into(),
                    property: "".into(),
                    value_from: "link_id".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
                required_purpose: String::new(),
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "one".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "two".into())]),
            )))
            .unwrap();
        svc.db
            .create_link(&domain::Link {
                id: "link-1".into(),
                from_id: "widget-1".into(),
                to_id: "widget-2".into(),
                relation: "relates_to".into(),
                created: 0,
            })
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "unlink_widget".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("link_id".into(), "link-1".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        assert!(svc.db.get_link("link-1").unwrap().is_none());
    }

    #[tokio::test]
    async fn user_defined_action_delete_link_hides_unknown_link() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "unlink_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "link_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "delete_link".into(),
                    property: "".into(),
                    value_from: "link_id".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
                required_purpose: String::new(),
            }),
        }))
        .await
        .unwrap();

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "unlink_widget".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("link_id".into(), "missing-link".into()),
                        ]),
                        actor: "".into(),
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
    async fn user_defined_action_rolls_back_created_object_when_later_link_fails() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "spawn_then_link_missing".into(),
                description: "".into(),
                params: vec![
                    ActionParamDef {
                        name: "child_name".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    },
                    ActionParamDef {
                        name: "to_id".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    },
                ],
                ops: vec![
                    ActionOp {
                        op: "create_object".into(),
                        property: "widget".into(),
                        value_from: "child_name".into(),
                        relation: "".into(),
                    },
                    ActionOp {
                        op: "create_link".into(),
                        property: "to_id".into(),
                        value_from: "".into(),
                        relation: "relates_to".into(),
                    },
                ],
                target_kind: "widget".into(),
                created: 0,
                required_purpose: String::new(),
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "parent".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "missing", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "spawn_then_link_missing".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("child_name".into(), "child".into()),
                            ("to_id".into(), "missing".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("object not found"));
        assert!(
            svc.db
                .find_by_property("widget", "name", "child")
                .unwrap()
                .is_empty()
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
    async fn function_rpc_round_trip() {
        let svc = service();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "c1".into(),
                kind: "component".into(),
                name: "comp".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([
                    ("language".into(), "rust".into()),
                    ("task_total".into(), "5".into()),
                ]),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "sum_tasks".into(),
                description: "".into(),
                params: vec![FuncParam {
                    name: "lang".into(),
                    r#type: "string".into(),
                    required: true,
                }],
                pipeline: vec![
                    PipelineStep {
                        op: "filter".into(),
                        kind: "component".into(),
                        property: "language".into(),
                        value: "$lang".into(),
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
                        func: "sum".into(),
                        field: "task_total".into(),
                        r#as: "total".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();

        let executed = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "sum_tasks".into(),
                params: HashMap::from([("lang".into(), "rust".into())]),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(executed.result.unwrap().aggregates["total"], "5");
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
            },
            "alice",
        ))
        .await
        .unwrap();

        svc.delete_object(with_named_principal(
            DeleteObjectRequest {
                id: "audit-1".into(),
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
        }))
        .await
        .unwrap();

        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(object),
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
    async fn list_schema_types_requires_principal() {
        let svc = service();
        let err = svc
            .list_schema_types(Request::new(ListSchemaTypesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn delete_schema_type_rejects_builtin() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .delete_schema_type(with_principal(DeleteSchemaTypeRequest {
                kind: "namespace".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("builtin"));
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
    async fn interface_rpcs_enforce_auth_and_admin() {
        let svc = service();
        let err = svc
            .list_interfaces(Request::new(ListInterfacesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let interface = InterfaceDef {
            name: "Trackable".into(),
            description: "Trackable object".into(),
            properties: vec![],
            is_builtin: false,
        };
        let err = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface.clone()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        grant_object_role(&svc, "schema:Trackable", "tester", security::Role::Admin);
        let err = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface.clone()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        grant_object_role(&svc, "interface:Trackable", "tester", security::Role::Admin);
        let created = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface),
            }))
            .await
            .unwrap()
            .into_inner()
            .interface
            .unwrap();
        assert_eq!(created.name, "Trackable");

        let listed = svc
            .list_interfaces(with_principal(ListInterfacesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(
            listed
                .interfaces
                .iter()
                .any(|interface| interface.name == "Trackable" && !interface.is_builtin)
        );

        svc.delete_interface(with_principal(DeleteInterfaceRequest {
            name: "Trackable".into(),
        }))
        .await
        .unwrap();
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
    async fn mapped_relations_enforce_effective_endpoint_classes_and_report_legacy_violations() {
        let svc = service();
        seed_ontology_class(&svc, "Person", "");
        seed_ontology_class(&svc, "Human", "");
        seed_ontology_class(&svc, "Engineer", "component");
        seed_ontology_class(&svc, "Company", "model");
        seed_ontology_class(&svc, "Project", "project");

        let mut person = svc.db.get_ontology_class("Person").unwrap().unwrap();
        person.equivalent_classes = vec!["Human".into()];
        svc.db.upsert_ontology_class(&person).unwrap();
        let mut engineer = svc.db.get_ontology_class("Engineer").unwrap().unwrap();
        engineer.superclasses = vec!["Human".into()];
        svc.db.upsert_ontology_class(&engineer).unwrap();

        seed_object_kind(&svc, "engineer", "component");
        seed_object_kind(&svc, "company", "model");
        seed_object_kind(&svc, "project", "project");
        seed_object_kind(&svc, "bad-target", "project");

        // Unconstrained graph relations retain their existing permissive behavior.
        svc.create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "legacy".into(),
                from_id: "project".into(),
                to_id: "company".into(),
                relation: "works_for".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "legacy-both".into(),
                from_id: "project".into(),
                to_id: "bad-target".into(),
                relation: "works_for".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();

        svc.db
            .upsert_ontology_relation(&ontology::OntologyRelation {
                name: "employment".into(),
                description: String::new(),
                domain: "Person".into(),
                range: "Company".into(),
                cardinality: ontology::Cardinality::default(),
                inverse: String::new(),
                transitive: false,
                is_builtin: false,
                mapped_relation: "works_for".into(),
            })
            .unwrap();

        // Engineer reaches Person through inheritance and symmetric equivalence.
        svc.create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "valid".into(),
                from_id: "engineer".into(),
                to_id: "company".into(),
                relation: "works_for".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "legacy".into(),
                from_id: "project".into(),
                to_id: "company".into(),
                relation: "works_for".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();

        let incompatible = svc
            .create_link(with_principal(CreateLinkRequest {
                fail_if_exists: false,
                link: Some(Link {
                    id: "invalid".into(),
                    from_id: "project".into(),
                    to_id: "company".into(),
                    relation: "works_for".into(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(incompatible.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            incompatible.message(),
            "link endpoints violate ontology constraint"
        );
        assert_eq!(
            svc.db
                .create_link(&domain::Link {
                    id: "invalid-internal".into(),
                    from_id: "project".into(),
                    to_id: "company".into(),
                    relation: "works_for".into(),
                    created: 0,
                })
                .unwrap_err(),
            "link endpoints violate ontology constraint"
        );
        svc.create_link(with_principal(CreateLinkRequest {
            fail_if_exists: false,
            link: Some(Link {
                id: "empty-relation".into(),
                from_id: "project".into(),
                to_id: "company".into(),
                relation: String::new(),
                created: 0,
            }),
        }))
        .await
        .unwrap();

        let report = svc
            .report_ontology_link_violations(with_principal(ReportOntologyLinkViolationsRequest {
                ontology_relation: "employment".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(report.violations.len(), 2);
        assert_eq!(report.violations[0].link_id, "legacy");
        assert!(report.violations[0].domain_violation);
        assert!(!report.violations[0].range_violation);

        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(Object {
                id: "project".into(),
                kind: "project".into(),
                name: "renamed legacy project".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 1,
            }),
        }))
        .await
        .unwrap();
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(Object {
                id: "project".into(),
                kind: "component".into(),
                name: "renamed legacy project".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 2,
            }),
        }))
        .await
        .unwrap();

        let update = svc
            .update_object(with_principal(UpdateObjectRequest {
                object: Some(Object {
                    id: "engineer".into(),
                    kind: "project".into(),
                    name: "engineer".into(),
                    namespace: String::new(),
                    external_id: String::new(),
                    properties: HashMap::new(),
                    created: 0,
                    updated: 1,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(update.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            update.message(),
            "link endpoints violate ontology constraint"
        );
        let mut internal_update = svc.db.get_object("engineer").unwrap().unwrap();
        internal_update.kind = "project".into();
        assert_eq!(
            svc.db.update_object(&internal_update).unwrap_err(),
            "link endpoints violate ontology constraint"
        );
    }

    #[tokio::test]
    async fn ontology_constraint_checks_do_not_bypass_endpoint_authorization() {
        let svc = service();
        seed_ontology_class(&svc, "Person", "component");
        seed_ontology_class(&svc, "Company", "model");
        seed_object_kind(&svc, "person", "project");
        seed_object_kind(&svc, "hidden", "project");
        grant_object_role(&svc, "hidden", "other", security::Role::Admin);
        svc.db
            .create_link(&domain::Link {
                id: "existing-hidden-link".into(),
                from_id: "person".into(),
                to_id: "hidden".into(),
                relation: "works_for".into(),
                created: 0,
            })
            .unwrap();
        svc.db
            .upsert_ontology_relation(&ontology::OntologyRelation {
                name: "employment".into(),
                description: String::new(),
                domain: "Person".into(),
                range: "Company".into(),
                cardinality: ontology::Cardinality::default(),
                inverse: String::new(),
                transitive: false,
                is_builtin: false,
                mapped_relation: "works_for".into(),
            })
            .unwrap();

        let report = svc
            .report_ontology_link_violations(with_principal(ReportOntologyLinkViolationsRequest {
                ontology_relation: "employment".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(report.violations.is_empty());

        let error = svc
            .create_link(with_principal(CreateLinkRequest {
                fail_if_exists: false,
                link: Some(Link {
                    id: "hidden-link".into(),
                    from_id: "person".into(),
                    to_id: "hidden".into(),
                    relation: "works_for".into(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert_ne!(
            error.message(),
            "link endpoints violate ontology constraint"
        );

        let update = svc
            .update_object(with_principal(UpdateObjectRequest {
                object: Some(Object {
                    id: "person".into(),
                    kind: "component".into(),
                    name: "person".into(),
                    namespace: String::new(),
                    external_id: String::new(),
                    properties: HashMap::new(),
                    created: 0,
                    updated: 1,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(update.code(), tonic::Code::PermissionDenied);

        seed_object_kind(&svc, "unconstrained", "project");
        svc.db
            .create_link(&domain::Link {
                id: "unconstrained-hidden-link".into(),
                from_id: "unconstrained".into(),
                to_id: "hidden".into(),
                relation: "unmapped".into(),
                created: 0,
            })
            .unwrap();
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(Object {
                id: "unconstrained".into(),
                kind: "component".into(),
                name: "unconstrained".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 1,
            }),
        }))
        .await
        .unwrap();
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
    async fn project_schema_to_ontology_via_rpc() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();

        // A schema admin may project (schema governs the object model).
        let projected = svc
            .project_schema_to_ontology(with_principal(ProjectSchemaToOntologyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(projected.classes.iter().any(|class| class.name == "widget"));

        let widget = svc
            .get_ontology_class(with_principal(GetOntologyClassRequest {
                name: "widget".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .class
            .unwrap();
        assert_eq!(widget.mapped_kind, "widget");
        assert!(widget.properties.iter().any(|prop| prop.name == "name"));
    }

    #[tokio::test]
    async fn schema_projection_preserves_source_acl() {
        let svc = service();
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            },
            "local",
        ))
        .await
        .unwrap();
        grant_object_role(
            &svc,
            "schema:widget",
            "schema-reader",
            security::Role::Viewer,
        );
        grant_object_role(&svc, "schema:widget", "local", security::Role::Viewer);

        let projected = svc
            .project_schema_to_ontology(with_named_principal(
                ProjectSchemaToOntologyRequest {},
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(projected.classes.iter().any(|class| class.name == "widget"));

        let hidden = svc
            .get_ontology_class(with_named_principal(
                GetOntologyClassRequest {
                    name: "widget".into(),
                },
                "other-reader",
            ))
            .await
            .unwrap_err();
        assert_eq!(hidden.code(), tonic::Code::PermissionDenied);

        let visible = svc
            .get_ontology_class(with_named_principal(
                GetOntologyClassRequest {
                    name: "widget".into(),
                },
                "schema-reader",
            ))
            .await
            .unwrap()
            .into_inner()
            .class
            .unwrap();
        assert_eq!(visible.name, "widget");
    }

    #[tokio::test]
    async fn schema_projection_preflights_all_source_access_before_writing() {
        let svc = service();
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            },
            "local",
        ))
        .await
        .unwrap();
        grant_ontology_admin(&svc);
        grant_object_role(
            &svc,
            "schema:widget",
            "other-reader",
            security::Role::Viewer,
        );

        let denied = svc
            .project_schema_to_ontology(with_principal(ProjectSchemaToOntologyRequest {}))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.list_ontology_classes().unwrap().is_empty());
    }

    #[tokio::test]
    async fn schema_projection_rejects_type_interface_name_collision() {
        let svc = service();
        svc.create_interface(with_named_principal(
            CreateInterfaceRequest {
                interface: Some(InterfaceDef {
                    name: "Collision".into(),
                    description: String::new(),
                    properties: vec![],
                    is_builtin: false,
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        let mut object_type = widget_schema_type();
        object_type.kind = "Collision".into();
        object_type.implements = vec!["Collision".into()];
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(object_type),
            },
            "local",
        ))
        .await
        .unwrap();

        let invalid = svc
            .project_schema_to_ontology(with_named_principal(
                ProjectSchemaToOntologyRequest {},
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
        assert!(invalid.message().contains("share ontology class name"));
        assert!(svc.db.list_ontology_classes().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_interface_rejects_builtin() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .delete_interface(with_principal(DeleteInterfaceRequest {
                name: "RiskScored".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("builtin"));
    }

    #[tokio::test]
    async fn schema_type_implements_interface_and_list_filters_by_interface() {
        let svc = service();
        grant_schema_admin(&svc);
        let interface = InterfaceDef {
            name: "Trackable".into(),
            description: "Trackable object".into(),
            properties: vec![PropertyDef {
                name: "tracking_id".into(),
                r#type: "string".into(),
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
        svc.create_interface(with_principal(CreateInterfaceRequest {
            interface: Some(interface),
        }))
        .await
        .unwrap();

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

        let incompatible_update = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(InterfaceDef {
                    name: "Trackable".into(),
                    description: "Trackable object".into(),
                    properties: vec![
                        PropertyDef {
                            name: "tracking_id".into(),
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
                            name: "second_tracking_id".into(),
                            r#type: "string".into(),
                            required: true,
                            description: "".into(),
                            enum_values: vec![],
                            link_kind: "".into(),
                            compute_expr: "".into(),
                            classification: "public".into(),
                            struct_fields: vec![],
                        },
                    ],
                    is_builtin: false,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(incompatible_update.code(), tonic::Code::InvalidArgument);
        assert!(incompatible_update.message().contains("second_tracking_id"));

        let delete_referenced = svc
            .delete_interface(with_principal(DeleteInterfaceRequest {
                name: "Trackable".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(delete_referenced.code(), tonic::Code::FailedPrecondition);

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "tracked",
                HashMap::from([
                    ("name".into(), "tracked".into()),
                    ("tracking_id".into(), "trk-1".into()),
                ]),
            )),
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
    async fn delete_schema_type_removes_enforcement() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.delete_schema_type(with_principal(DeleteSchemaTypeRequest {
            kind: "widget".into(),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object("w1", HashMap::new())),
        }))
        .await
        .unwrap();
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
                DeleteObjectRequest { id: adopted.id },
                "local",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[tokio::test]
    async fn team_namespace_roles_scope_generic_object_access() {
        let svc = service();
        for (principal, role) in [("alice", "viewer"), ("bob", "editor")] {
            svc.ensure_team_namespace(with_named_principal(
                EnsureTeamNamespaceRequest {
                    namespace: "acme".into(),
                    principal: principal.into(),
                    role: role.into(),
                },
                "local",
            ))
            .await
            .unwrap();
        }
        svc.ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "beta".into(),
                principal: "carol".into(),
                role: "editor".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        for (id, namespace) in [("acme-object", "acme"), ("beta-object", "beta")] {
            svc.create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(Object {
                        id: id.into(),
                        kind: "note".into(),
                        name: id.into(),
                        namespace: namespace.into(),
                        external_id: String::new(),
                        properties: HashMap::new(),
                        created: 1,
                        updated: 1,
                    }),
                },
                "local",
            ))
            .await
            .unwrap();
        }

        svc.get_object(with_named_principal(
            GetObjectRequest {
                id: "acme-object".into(),
            },
            "alice",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.get_object(with_named_principal(
                GetObjectRequest {
                    id: "acme-object".into(),
                },
                "unmanaged-principal",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        let unmanaged_list = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        namespace: "acme".into(),
                        ..Default::default()
                    }),
                },
                "unmanaged-principal",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(unmanaged_list.objects.is_empty());
        assert_eq!(unmanaged_list.total, 0);
        assert_eq!(
            svc.get_object(with_named_principal(
                GetObjectRequest {
                    id: "beta-object".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            svc.create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(Object {
                        id: "viewer-write".into(),
                        kind: "note".into(),
                        name: "denied".into(),
                        namespace: "acme".into(),
                        external_id: String::new(),
                        properties: HashMap::new(),
                        created: 1,
                        updated: 1,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    id: "editor-write".into(),
                    kind: "note".into(),
                    name: "allowed".into(),
                    namespace: "acme".into(),
                    external_id: String::new(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                }),
            },
            "bob",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.list_objects(with_named_principal(
                ListObjectsRequest { filter: None },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        let listed = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        namespace: "acme".into(),
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(
            listed
                .objects
                .iter()
                .all(|object| object.namespace == "acme")
        );

        let unscoped_set = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        name: "unscoped".into(),
                        filter: Some(ListFilter::default()),
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(unscoped_set.code(), tonic::Code::PermissionDenied);

        svc.create_link(with_named_principal(
            CreateLinkRequest {
                fail_if_exists: false,
                link: Some(Link {
                    id: "cross-namespace-link".into(),
                    from_id: "acme-object".into(),
                    to_id: "beta-object".into(),
                    relation: "depends_on".into(),
                    created: 1,
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        let linked = svc
            .get_linked_objects(with_named_principal(
                GetLinkedObjectsRequest {
                    object_id: "acme-object".into(),
                    relation: "depends_on".into(),
                    direction: "outgoing".into(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(linked.objects.is_empty());
        let viewer_link = svc
            .create_link(with_named_principal(
                CreateLinkRequest {
                    fail_if_exists: false,
                    link: Some(Link {
                        id: "viewer-link".into(),
                        from_id: "acme-object".into(),
                        to_id: "editor-write".into(),
                        relation: "depends_on".into(),
                        created: 1,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(viewer_link.code(), tonic::Code::PermissionDenied);

        let lineage = svc
            .get_lineage(with_named_principal(
                GetLineageRequest {
                    object_id: "acme-object".into(),
                    max_nodes: 10,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(lineage.nodes.len(), 1);
        assert!(lineage.edges.is_empty());

        svc.create_function(with_named_principal(
            CreateFunctionRequest {
                function: Some(Function {
                    name: "all-notes".into(),
                    pipeline: vec![PipelineStep {
                        op: "filter".into(),
                        kind: "note".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.create_function(with_named_principal(
                CreateFunctionRequest {
                    function: Some(Function::default()),
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        let function_result = svc
            .execute_function(with_named_principal(
                ExecuteFunctionRequest {
                    name: "all-notes".into(),
                    params: HashMap::new(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(
            function_result
                .objects
                .iter()
                .all(|object| object.namespace == "acme")
        );

        for (id, object_id) in [("beta-dataset", "beta-object"), ("global-dataset", "")] {
            svc.create_dataset(with_named_principal(
                CreateDatasetRequest {
                    dataset: Some(Dataset {
                        id: id.into(),
                        name: id.into(),
                        object_id: object_id.into(),
                        ..Default::default()
                    }),
                },
                "local",
            ))
            .await
            .unwrap();
            assert_eq!(
                svc.query_rows(with_named_principal(
                    QueryRowsRequest {
                        dataset_id: id.into(),
                        query: None,
                    },
                    "alice",
                ))
                .await
                .unwrap_err()
                .code(),
                tonic::Code::PermissionDenied
            );
        }

        for (principal, target) in [("alice", "acme-object"), ("bob", "beta-object")] {
            let denied = svc
                .execute_action(with_named_principal(
                    ExecuteActionRequest {
                        request: Some(ActionRequest {
                            action: "set_property".into(),
                            params: HashMap::from([
                                ("id".into(), target.into()),
                                ("key".into(), "compromised".into()),
                                ("value".into(), "true".into()),
                            ]),
                            actor: principal.into(),
                        }),
                        dry_run: false,
                    },
                    principal,
                ))
                .await
                .unwrap_err();
            assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        }
        for params in [
            HashMap::from([
                ("id".into(), "namespace:acme-duplicate".into()),
                ("kind".into(), "namespace".into()),
                ("name".into(), "duplicate".into()),
                ("namespace".into(), "acme".into()),
                ("external_id".into(), "namespace:acme".into()),
            ]),
            HashMap::from([
                ("id".into(), "unscoped-action-object".into()),
                ("kind".into(), "note".into()),
                ("name".into(), "unscoped".into()),
            ]),
        ] {
            assert_eq!(
                svc.execute_action(with_named_principal(
                    ExecuteActionRequest {
                        request: Some(ActionRequest {
                            action: "create_object".into(),
                            params,
                            actor: "bob".into(),
                        }),
                        dry_run: false,
                    },
                    "bob",
                ))
                .await
                .unwrap_err()
                .code(),
                tonic::Code::PermissionDenied
            );
        }

        let acl_escalation = svc
            .create_grant(with_named_principal(
                CreateGrantRequest {
                    grant: Some(Grant {
                        id: "viewer-escalation".into(),
                        object_id: "acme-object".into(),
                        principal: "alice".into(),
                        role: "admin".into(),
                        created: 1,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(acl_escalation.code(), tonic::Code::PermissionDenied);
        let editor_acl_escalation = svc
            .create_grant(with_named_principal(
                CreateGrantRequest {
                    grant: Some(Grant {
                        id: "editor-escalation".into(),
                        object_id: "acme-object".into(),
                        principal: "bob".into(),
                        role: "admin".into(),
                        created: 1,
                    }),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(editor_acl_escalation.code(), tonic::Code::PermissionDenied);

        assert_eq!(
            svc.check_access(with_named_principal(
                CheckAccessRequest {
                    object_id: "beta-object".into(),
                    principals: vec!["carol".into()],
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );

        for (id, target_id) in [
            ("acme-decision", "acme-object"),
            ("beta-decision", "beta-object"),
        ] {
            svc.db
                .record_decision(&audit::Decision {
                    id: id.into(),
                    timestamp: 1,
                    actor: "local".into(),
                    action: "test".into(),
                    reason: "namespace isolation".into(),
                    evidence: HashMap::new(),
                    target_id: target_id.into(),
                    outcome: "recorded".into(),
                })
                .unwrap();
        }
        let decisions = svc
            .list_decisions(with_named_principal(
                ListDecisionsRequest {
                    limit: 10,
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            decisions
                .decisions
                .iter()
                .map(|decision| decision.id.as_str())
                .collect::<Vec<_>>(),
            vec!["acme-decision"]
        );

        let forged_decision = svc
            .record_decision(with_named_principal(
                RecordDecisionRequest {
                    decision: Some(Decision {
                        actor: "root".into(),
                        target_id: "beta-object".into(),
                        action: "forged".into(),
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(forged_decision.code(), tonic::Code::PermissionDenied);
        let recorded = svc
            .record_decision(with_named_principal(
                RecordDecisionRequest {
                    decision: Some(Decision {
                        actor: "root".into(),
                        target_id: "acme-object".into(),
                        action: "editor-note".into(),
                        ..Default::default()
                    }),
                },
                "bob",
            ))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        assert_eq!(recorded.actor, "bob");

        svc.create_contention_scope(with_named_principal(
            CreateContentionScopeRequest {
                request_id: "alice-scope".into(),
                scope: Some(ContentionScope {
                    id: "alice-scope".into(),
                    name: "alice".into(),
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
        assert_eq!(
            svc.create_work_unit(with_named_principal(
                CreateWorkUnitRequest {
                    request_id: "cross-team-work".into(),
                    work_unit: Some(WorkUnit {
                        id: "cross-team-work".into(),
                        kind: "analysis".into(),
                        actor: "alice".into(),
                        target_object_id: "beta-object".into(),
                        requested_spec: "read beta".into(),
                        scope_id: "alice-scope".into(),
                        timeout_seconds: 60,
                        heartbeat_ttl_seconds: 30,
                        idempotency_key: "cross-team-work".into(),
                        created_at: 1,
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );

        svc.create_contention_scope(with_named_principal(
            CreateContentionScopeRequest {
                request_id: "team-scope".into(),
                scope: Some(ContentionScope {
                    id: "team-scope".into(),
                    name: "team".into(),
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
                request_id: "beta-work".into(),
                work_unit: Some(WorkUnit {
                    id: "beta-work".into(),
                    kind: "analysis".into(),
                    actor: "local".into(),
                    target_object_id: "beta-object".into(),
                    requested_spec: "private beta work".into(),
                    scope_id: "team-scope".into(),
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    idempotency_key: "beta-work".into(),
                    created_at: 1,
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.get_work_unit(with_named_principal(
                GetWorkUnitRequest {
                    id: "beta-work".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            svc.get_provenance_report(with_named_principal(
                GetProvenanceReportRequest {
                    work_unit_id: "beta-work".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );

        svc.delete_object(with_named_principal(
            DeleteObjectRequest {
                id: "beta-object".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.list_object_changes(with_named_principal(
                ListObjectChangesRequest {
                    object_id: "beta-object".into(),
                    limit: 10,
                    offset: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        let beta_changes = svc
            .list_object_changes(with_named_principal(
                ListObjectChangesRequest {
                    object_id: "beta-object".into(),
                    limit: 10,
                    offset: 0,
                },
                "carol",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(
            beta_changes
                .changes
                .iter()
                .any(|change| change.field == "_deleted")
        );

        svc.delete_grant(with_named_principal(
            DeleteGrantRequest {
                id: "team:acme:alice".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.get_object(with_named_principal(
                GetObjectRequest {
                    id: "acme-object".into(),
                },
                "alice",
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
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
    async fn coordination_hierarchy_blocks_siblings_and_snapshot_reports_contention() {
        let svc = service();
        for scope in [
            ContentionScope {
                id: "root".into(),
                name: "gradle".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 100,
                updated: 100,
            },
            ContentionScope {
                id: "child-a".into(),
                name: "gradle/a".into(),
                parent_scope_id: "root".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 101,
                updated: 101,
            },
            ContentionScope {
                id: "child-b".into(),
                name: "gradle/b".into(),
                parent_scope_id: "root".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 102,
                updated: 102,
            },
        ] {
            svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: format!("req-scope-{}", scope.id),
                scope: Some(scope),
            }))
            .await
            .unwrap();
        }
        for (id, scope_id, created_at) in [("wu-a", "child-a", 200), ("wu-b", "child-b", 201)] {
            svc.create_work_unit(with_principal(CreateWorkUnitRequest {
                work_unit: Some(WorkUnit {
                    id: id.into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: format!("run {}", id),
                    scope_id: scope_id.into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: format!("idem-{}", id),
                    updated_at: created_at,
                }),
                request_id: format!("req-{}", id),
            }))
            .await
            .unwrap();
        }

        let admitted = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-a".into(),
                request_id: "req-admit-wu-a".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted);

        let blocked = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-b".into(),
                request_id: "req-admit-wu-b".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!blocked.admitted);
        assert!(blocked.reason.contains("saturated"));

        let snapshot = svc
            .get_coordination_snapshot(with_principal(GetCoordinationSnapshotRequest {}))
            .await
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap();
        assert_eq!(snapshot.pending_count, 1);
        assert_eq!(snapshot.running_count, 1);
        assert!(!snapshot.blocked_scopes.is_empty());
    }

    #[tokio::test]
    async fn managed_team_principals_cannot_read_global_coordination_snapshots() {
        let svc = service();
        svc.db
            .ensure_team_namespace("acme", "alice", security::Role::Viewer, "local")
            .unwrap();
        let error = svc
            .get_coordination_snapshot(with_named_principal(
                GetCoordinationSnapshotRequest {},
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        let error = svc
            .create_contention_scope(with_named_principal(
                CreateContentionScopeRequest {
                    request_id: "team-global-scope".into(),
                    scope: Some(ContentionScope {
                        id: "team-global-scope".into(),
                        name: "forbidden".into(),
                        max_concurrency: 1,
                        admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                        heartbeat_ttl_seconds: 30,
                        timeout_seconds: 60,
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
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
    async fn object_sets_resolve_like_inline_filter_and_owner_only_access() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "owner-visible".into(),
                kind: "query-demo".into(),
                name: "owner-visible".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "alpha".into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        grant_object_role(&svc, "owner-visible", "alice", security::Role::Viewer);

        svc.db
            .create_object(&domain::Object {
                id: "other-visible".into(),
                kind: "query-demo".into(),
                name: "other-visible".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "alpha".into())]),
                created: 2,
                updated: 2,
            })
            .unwrap();
        grant_object_role(&svc, "other-visible", "bob", security::Role::Viewer);

        let inline = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team".into(),
                            op: "eq".into(),
                            value: "alpha".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        let created_set = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "alpha-set".into(),
                        description: "only alpha objects".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            property_filters: vec![PropertyFilter {
                                key: "team".into(),
                                op: "eq".into(),
                                value: "alpha".into(),
                            }],
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        let set_id = created_set.object_set.unwrap().id;

        let resolved_by_owner = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: set_id.clone(),
                    limit: 10,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        let resolved_owner_ids = resolved_by_owner
            .objects
            .iter()
            .map(|obj| obj.id.clone())
            .collect::<Vec<_>>();

        assert_eq!(inline.total, 1);
        assert_eq!(resolved_by_owner.total, inline.total);
        assert_eq!(resolved_owner_ids, vec!["owner-visible"]);

        let err = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: set_id,
                    limit: 10,
                    offset: Some(0),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn delete_object_set_prevents_future_resolve() {
        let svc = service();
        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "temp".into(),
                        description: "temp set".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        svc.delete_object_set(with_named_principal(
            DeleteObjectSetRequest {
                id: created.id.clone(),
            },
            "alice",
        ))
        .await
        .unwrap();

        let err = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 10,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn create_object_set_rejects_duplicate_name_for_same_owner() {
        let svc = service();
        let payload = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: String::new(),
                name: "dup-name".into(),
                description: "first".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };

        svc.create_object_set(with_named_principal(payload.clone(), "alice"))
            .await
            .unwrap();

        let err = svc
            .create_object_set(with_named_principal(payload, "alice"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn create_object_set_rejects_duplicate_id_for_same_owner() {
        let svc = service();
        let first = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: "fixed-id".into(),
                name: "first-id".into(),
                description: "first".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };
        svc.create_object_set(with_named_principal(first.clone(), "alice"))
            .await
            .unwrap();

        let second = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: "fixed-id".into(),
                name: "second-id".into(),
                description: "second".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };

        let err = svc
            .create_object_set(with_named_principal(second, "alice"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn create_object_set_rejects_blank_name() {
        let svc = service();
        let err = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "  ".into(),
                        description: "blank".into(),
                        filter: Some(ListFilter::default()),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_object_set_rejects_invalid_property_key() {
        let svc = service();
        let err = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "invalid-key".into(),
                        description: "invalid filter".into(),
                        filter: Some(ListFilter {
                            property_filters: vec![PropertyFilter {
                                key: "team.name".into(),
                                op: "eq".into(),
                                value: "backend".into(),
                            }],
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn resolve_object_set_offset_zero_overrides_stored_offset() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "first".into(),
                kind: "query-demo".into(),
                name: "first".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "second".into(),
                kind: "query-demo".into(),
                name: "second".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 2,
                updated: 2,
            })
            .unwrap();

        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "offset-set".into(),
                        description: "offset override".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            order_by: "name".into(),
                            limit: 1,
                            offset: 1,
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        let response = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 1,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "first");
    }

    #[tokio::test]
    async fn resolve_object_set_omitted_offset_uses_stored_offset() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "first".into(),
                kind: "query-demo".into(),
                name: "first".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "second".into(),
                kind: "query-demo".into(),
                name: "second".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 2,
                updated: 2,
            })
            .unwrap();

        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "stored-offset-set".into(),
                        description: "stored offset".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            order_by: "name".into(),
                            limit: 1,
                            offset: 1,
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        let response = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 1,
                    offset: None,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "second");
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

        let export = svc
            .export_assurance(with_principal(ExportAssuranceRequest {
                action: "delete_link".into(),
                policy_scope: "agent:tester".into(),
                after: 0,
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(export.records.len(), 1);
        assert_eq!(
            export.records[0].decision.as_ref().unwrap().action,
            "delete_link"
        );
        assert_eq!(
            export.records[0].attestation.as_ref().unwrap().policy_scope,
            "agent:tester"
        );
        assert!(export.records[0].verification.as_ref().unwrap().ok);
        assert!(export.ledger.as_ref().unwrap().ok);
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
    async fn object_sets_cannot_read_or_target_reserved_governance_kinds() {
        let svc = service();
        // A held approval object carrying a secret param.
        let approval = action_approval::ActionApproval::pending(
            "tester",
            "rotate_key",
            HashMap::from([
                ("id".to_string(), "obj-1".to_string()),
                ("api_key".to_string(), "super-secret".to_string()),
            ]),
            "wu-1",
            "agent:tester",
            "destructive",
            "obj-1",
            0,
        );
        svc.db.create_action_approval(&approval).unwrap();

        // CreateObjectSet must reject a saved filter targeting a reserved kind.
        let err = svc
            .create_object_set(with_principal(CreateObjectSetRequest {
                object_set: Some(ObjectSet {
                    id: "leaky-set".into(),
                    name: "leaky".into(),
                    description: String::new(),
                    filter: Some(ListFilter {
                        kind: "action_approval".into(),
                        ..Default::default()
                    }),
                    owner_principal: "tester".into(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // Even a set persisted out-of-band (e.g. legacy) resolves to nothing,
        // because the visibility query now excludes reserved kinds.
        svc.db
            .create_object_set(&domain::ObjectSet {
                id: "legacy-leaky-set".into(),
                name: "legacy".into(),
                description: String::new(),
                filter: domain::ListFilter {
                    kind: Some("action_approval".into()),
                    ..Default::default()
                },
                owner_principal: "tester".into(),
                created: 0,
            })
            .unwrap();
        let resolved = svc
            .resolve_object_set(with_principal(ResolveObjectSetRequest {
                id: "legacy-leaky-set".into(),
                limit: 10,
                offset: Some(0),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resolved.objects.len(), 0);
        assert_eq!(resolved.total, 0);
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
            response.candidates[0].object.as_ref().unwrap().properties["secret_note"],
            REDACTED_VALUE
        );
        assert_eq!(response.denied_objects, 2);
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
        assert_eq!(denied_root.denied_objects, 1);
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

    #[tokio::test]
    #[cfg(any())]
    async fn tenant_rpcs_enforce_admin_lifecycle_and_idempotency() {
        let svc = service();
        let denied = svc
            .create_tenant(with_named_principal(
                CreateTenantRequest {
                    idempotency_key: "tenant-create-denied".into(),
                },
                "member",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let create = || {
            with_named_principal(
                CreateTenantRequest {
                    idempotency_key: "tenant-create-1".into(),
                },
                "root",
            )
        };
        let created = svc
            .create_tenant(create())
            .await
            .unwrap()
            .into_inner()
            .tenant
            .unwrap();
        let replayed = svc
            .create_tenant(create())
            .await
            .unwrap()
            .into_inner()
            .tenant
            .unwrap();
        assert_eq!(created, replayed);
        assert_eq!(
            created.contract_version,
            crate::sekai::tenant::TENANT_CONTRACT_VERSION
        );
        assert_eq!(created.state(), TenantLifecycleState::Active);

        let suspended = svc
            .suspend_tenant(with_named_principal(
                SuspendTenantRequest {
                    tenant_id: created.id.clone(),
                    idempotency_key: "tenant-suspend-1".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner()
            .tenant
            .unwrap();
        assert_eq!(suspended.state(), TenantLifecycleState::Suspended);
        assert!(matches!(
            svc.db.require_tenant_admission(&created.id),
            Err(crate::sekai::tenant::TenantError::AdmissionBlocked(_))
        ));

        let invalid = svc
            .suspend_tenant(with_named_principal(
                SuspendTenantRequest {
                    tenant_id: created.id.clone(),
                    idempotency_key: "tenant-suspend-2".into(),
                },
                "root",
            ))
            .await
            .unwrap_err();
        assert_eq!(invalid.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            svc.get_tenant(with_named_principal(
                GetTenantRequest {
                    tenant_id: created.id
                },
                "root"
            ))
            .await
            .unwrap()
            .into_inner()
            .tenant
            .unwrap()
            .state(),
            TenantLifecycleState::Suspended
        );
    }

    #[tokio::test]
    #[cfg(any())]
    async fn tenant_context_fails_closed_while_local_mode_skips_tenant_state() {
        let svc = service();
        let tenant_a = svc
            .db
            .create_tenant("root", "namespace-tenant-a", 1)
            .unwrap();
        let tenant_b = svc
            .db
            .create_tenant("root", "namespace-tenant-b", 2)
            .unwrap();
        svc.create_tenant_namespace(with_tenant_context(
            CreateTenantNamespaceRequest {
                namespace: "alpha".into(),
                tenant_id: tenant_a.id.clone(),
                migrated_from_namespace: String::new(),
            },
            "root",
            &tenant_a.id,
        ))
        .await
        .unwrap();

        let object = Object {
            id: "tenant-object".into(),
            kind: "note".into(),
            name: "tenant object".into(),
            namespace: "alpha".into(),
            ..Default::default()
        };
        svc.create_object(with_tenant_context(
            CreateObjectRequest {
                object: Some(object.clone()),
            },
            "root",
            &tenant_a.id,
        ))
        .await
        .unwrap();

        let missing = svc
            .get_object({
                let mut req = with_named_principal(
                    GetObjectRequest {
                        id: object.id.clone(),
                    },
                    "root",
                );
                req.metadata_mut()
                    .insert("x-sekai-auth-source", MetadataValue::from_static("token"));
                req
            })
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::PermissionDenied);

        let mismatched = svc
            .get_object(with_tenant_context(
                GetObjectRequest {
                    id: object.id.clone(),
                },
                "root",
                &tenant_b.id,
            ))
            .await
            .unwrap_err();
        assert_eq!(mismatched.code(), tonic::Code::NotFound);
        let absent = svc
            .get_object(with_tenant_context(
                GetObjectRequest {
                    id: "does-not-exist".into(),
                },
                "root",
                &tenant_b.id,
            ))
            .await
            .unwrap_err();
        assert_eq!(absent.code(), mismatched.code());

        svc.get_object(with_named_principal(
            GetObjectRequest { id: object.id },
            "local",
        ))
        .await
        .unwrap();
        assert!(svc.db.get_tenant("local").unwrap().is_none());
    }

    #[tokio::test]
    #[cfg(any())]
    async fn tenant_membership_rpcs_filter_scope_and_recheck_live_roles() {
        let svc = service();
        let tenant_a = svc.db.create_tenant("root", "membership-a", 1).unwrap();
        let tenant_b = svc.db.create_tenant("root", "membership-b", 2).unwrap();
        let owner = "owner".to_string();
        let owner_principal = format!("{}.owner", tenant_a.id);

        svc.create_tenant_membership(with_tenant_context(
            CreateTenantMembershipRequest {
                tenant_id: tenant_a.id.clone(),
                subject_id: owner.clone(),
                role: TenantMembershipRole::Owner as i32,
            },
            "root",
            &tenant_a.id,
        ))
        .await
        .unwrap();

        let visible = svc
            .list_tenant_memberships(with_tenant_context(
                ListTenantMembershipsRequest {
                    tenant_id: tenant_a.id.clone(),
                },
                &owner_principal,
                &tenant_a.id,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(visible.memberships.len(), 1);

        let cross_tenant = svc
            .list_tenant_memberships(with_tenant_context(
                ListTenantMembershipsRequest {
                    tenant_id: tenant_b.id.clone(),
                },
                &owner_principal,
                &tenant_a.id,
            ))
            .await
            .unwrap_err();
        assert_eq!(cross_tenant.code(), tonic::Code::PermissionDenied);

        let last_owner = svc
            .revoke_tenant_membership(with_tenant_context(
                RevokeTenantMembershipRequest {
                    tenant_id: tenant_a.id.clone(),
                    subject_id: owner.clone(),
                },
                &owner_principal,
                &tenant_a.id,
            ))
            .await
            .unwrap_err();
        assert_eq!(last_owner.code(), tonic::Code::FailedPrecondition);

        let second_owner = "owner-2".to_string();
        svc.create_tenant_membership(with_tenant_context(
            CreateTenantMembershipRequest {
                tenant_id: tenant_a.id.clone(),
                subject_id: second_owner,
                role: TenantMembershipRole::Owner as i32,
            },
            &owner_principal,
            &tenant_a.id,
        ))
        .await
        .unwrap();
        svc.revoke_tenant_membership(with_tenant_context(
            RevokeTenantMembershipRequest {
                tenant_id: tenant_a.id.clone(),
                subject_id: owner.clone(),
            },
            &owner_principal,
            &tenant_a.id,
        ))
        .await
        .unwrap();

        let revoked = svc
            .list_tenant_memberships(with_tenant_context(
                ListTenantMembershipsRequest {
                    tenant_id: tenant_a.id.clone(),
                },
                &owner_principal,
                &tenant_a.id,
            ))
            .await
            .unwrap_err();
        assert_eq!(revoked.code(), tonic::Code::PermissionDenied);
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
    #[cfg(any())]
    async fn tenant_credentials_are_scoped_and_require_live_admin_membership() {
        let svc = service();
        let tenant = svc
            .db
            .create_tenant("root", "credential-tenant", 1)
            .unwrap();
        svc.db
            .create_tenant_membership(
                &tenant.id,
                "owner",
                crate::sekai::tenant::TenantRole::Owner,
                "root",
                true,
                2,
            )
            .unwrap();
        svc.db
            .create_tenant_membership(
                &tenant.id,
                "member",
                crate::sekai::tenant::TenantRole::Member,
                "owner",
                false,
                3,
            )
            .unwrap();

        let created = svc
            .create_credential(with_tenant_context(
                CreateCredentialRequest {
                    principal: "worker".into(),
                    managed_team_principal: false,
                    tenant_id: tenant.id.clone(),
                },
                "owner",
                &tenant.id,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.credential.unwrap().tenant_id, tenant.id);

        let denied = svc
            .create_credential(with_tenant_context(
                CreateCredentialRequest {
                    principal: "other-worker".into(),
                    managed_team_principal: false,
                    tenant_id: tenant.id.clone(),
                },
                "member",
                &tenant.id,
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        svc.db
            .create_tenant_membership(
                &tenant.id,
                "owner-2",
                crate::sekai::tenant::TenantRole::Owner,
                "owner",
                false,
                4,
            )
            .unwrap();
        svc.db
            .change_tenant_membership_role(
                &tenant.id,
                "owner",
                crate::sekai::tenant::TenantRole::Member,
                "root",
                true,
                5,
            )
            .unwrap();
        let revoked_authority = svc
            .list_credentials(with_tenant_context(
                ListCredentialsRequest {
                    tenant_id: tenant.id.clone(),
                },
                "owner",
                &tenant.id,
            ))
            .await
            .unwrap_err();
        assert_eq!(revoked_authority.code(), tonic::Code::PermissionDenied);

        let platform_visible = svc
            .list_credentials(with_named_principal(
                ListCredentialsRequest {
                    tenant_id: tenant.id.clone(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(platform_visible.credentials.len(), 1);

        let non_canonical = svc
            .list_credentials(with_named_principal(
                ListCredentialsRequest {
                    tenant_id: format!(" {} ", platform_visible.credentials[0].tenant_id),
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(non_canonical.code(), tonic::Code::InvalidArgument);

        svc.db
            .suspend_tenant(&tenant.id, "root", "suspend-credential-tenant", 6)
            .unwrap();
        svc.revoke_credential(with_named_principal(
            RevokeCredentialRequest {
                principal: "worker".into(),
                tenant_id: tenant.id.clone(),
            },
            "local",
        ))
        .await
        .unwrap();
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
        svc.register_evidence_producer(with_named_principal(
            RegisterEvidenceProducerRequest {
                capability: Some(EvidenceProducerCapability {
                    producer_identity: "producer:checks".into(),
                    config_version: 1,
                    source_types: vec!["verification_system".into()],
                    source_instances: vec!["checks-primary".into()],
                    namespaces: vec!["acme".into()],
                    evidence_types: vec!["verification.result".into()],
                    target_kinds: vec!["service".into()],
                    classification_ceiling: "confidential".into(),
                    allowed_intents: vec!["upsert".into(), "retract".into(), "mark_stale".into()],
                    allow_operation_attachment: false,
                    replay_window_ms: 60_000,
                    max_clock_skew_ms: 1_000,
                    max_payload_bytes: 4_096,
                    max_relationships: 8,
                    rate_limit_per_minute: 100,
                    max_retained_submissions: 100_000,
                    revoked: false,
                }),
            },
            "local",
        ))
        .await
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

    #[tokio::test]
    async fn authorized_consumer_reads_retained_evidence_content() {
        let svc = configured_evidence_service(true).await;
        let grant = security::Grant {
            id: "grant-service-consumer".into(),
            object_id: "service-1".into(),
            principal: "consumer:onmyoji".into(),
            role: security::Role::Viewer,
            created: now_millis(),
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);

        let mut envelope = proto_evidence("run-content", 1);
        envelope
            .provenance
            .insert("run_url".into(), "https://ci.example/runs/42".into());
        let submitted = svc
            .submit_evidence(with_named_principal(
                SubmitEvidenceRequest {
                    envelope: Some(envelope.clone()),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        let submission_id = submitted.submission.unwrap().id;

        let content = svc
            .get_evidence_submission_content(with_named_principal(
                GetEvidenceSubmissionContentRequest {
                    submission_id: submission_id.clone(),
                },
                "consumer:onmyoji",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(content.submission_id, submission_id);
        assert_eq!(content.lifecycle_state, "available");
        let returned = content.envelope.unwrap();
        assert_eq!(returned.content_json, envelope.content_json);
        assert_eq!(returned.content_digest, envelope.content_digest);
        assert_eq!(returned.provenance, envelope.provenance);

        let evidence_object_id = svc
            .db
            .get_evidence_projection_object_id(&submission_id)
            .unwrap()
            .unwrap();
        let links = svc
            .db
            .list_links_by_relation(domain::REL_EVIDENCE_FOR)
            .unwrap();
        assert!(
            links
                .iter()
                .any(|link| { link.from_id == evidence_object_id && link.to_id == "service-1" })
        );

        let denied = svc
            .get_evidence_submission_content(with_named_principal(
                GetEvidenceSubmissionContentRequest {
                    submission_id: submission_id.clone(),
                },
                "consumer:other",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::NotFound);

        let replayed = svc
            .submit_evidence(with_named_principal(
                SubmitEvidenceRequest {
                    envelope: Some(envelope),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(replayed.deduplicated);
        assert_eq!(replayed.submission.unwrap().id, submission_id);
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

    #[tokio::test]
    async fn evidence_batch_is_bounded_before_mutation() {
        let svc = configured_evidence_service(true).await;
        let error = svc
            .submit_evidence_batch(with_named_principal(
                SubmitEvidenceBatchRequest {
                    envelopes: (0..101)
                        .map(|sequence| proto_evidence("batch", sequence))
                        .collect(),
                },
                "producer:checks",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            svc.db
                .list_evidence_submissions(&EvidenceSubmissionFilter::default())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn evidence_replay_and_retraction_preserve_lifecycle_history() {
        let svc = configured_evidence_service(false).await;
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
        let submission_id = submitted.submission.unwrap().id;
        assert!(!submitted.projected);
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
        let replayed = svc
            .replay_evidence_submission(with_named_principal(
                ReplayEvidenceSubmissionRequest {
                    submission_id: submission_id.clone(),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(replayed.projected);
        assert_eq!(replayed.submission.unwrap().lifecycle_state, "available");

        let retracted = svc
            .retract_evidence(with_named_principal(
                RetractEvidenceRequest {
                    submission_id: submission_id.clone(),
                    source_version: "v2".into(),
                    source_sequence: 2,
                    idempotency_key: "retract-run-1".into(),
                    observed_at_ms: now_millis(),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(retracted.projected);
        assert_eq!(
            svc.db
                .get_evidence_submission(&submission_id)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            evidence_domain::EvidenceLifecycleState::Retracted
        );
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
    async fn catalog_invocation_rechecks_live_policy_and_records_receipts() {
        let svc = service();
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.create_action_type(with_named_principal(
            CreateActionTypeRequest {
                action_type: Some(assign_color_action()),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    namespace: "acme".into(),
                    ..widget_object(
                        "widget-1",
                        HashMap::from([
                            ("name".into(), "one".into()),
                            ("color".into(), "red".into()),
                        ]),
                    )
                }),
            },
            "local",
        ))
        .await
        .unwrap();

        let mut read = with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: "acme".into(),
                    kind: "widget".into(),
                    ..Default::default()
                }),
            },
            "local",
        );
        read.metadata_mut().insert(
            "x-sekai-capability",
            "sekai.objects.query.widget".parse().unwrap(),
        );
        read.metadata_mut()
            .insert("x-sekai-operation-id", "catalog-read-1".parse().unwrap());
        read.metadata_mut().insert(
            "x-sekai-catalog-version",
            "sha256:observed-catalog".parse().unwrap(),
        );
        let read_response = svc.list_objects(read).await.unwrap();
        assert_eq!(
            read_response
                .metadata()
                .get("x-sekai-operation-id")
                .unwrap(),
            "catalog-read-1"
        );
        let read_receipt = svc
            .db
            .get_operation_receipt("catalog-read-1")
            .unwrap()
            .unwrap();
        assert!(read_receipt.completeness().complete);
        assert_eq!(read_receipt.operation_class, "catalog_invocation");
        assert_eq!(
            read_receipt.events[0].attributes["reported_catalog_version"],
            "sha256:observed-catalog"
        );

        let mut collision = with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: "acme".into(),
                    kind: "widget".into(),
                    ..Default::default()
                }),
            },
            "intruder",
        );
        collision.metadata_mut().insert(
            "x-sekai-capability",
            "sekai.objects.query.widget".parse().unwrap(),
        );
        collision
            .metadata_mut()
            .insert("x-sekai-operation-id", "catalog-read-1".parse().unwrap());
        assert_eq!(
            svc.list_objects(collision).await.unwrap_err().code(),
            tonic::Code::AlreadyExists
        );
        assert_eq!(
            svc.db
                .get_operation_receipt("catalog-read-1")
                .unwrap()
                .unwrap()
                .initiating_actor,
            "local"
        );

        let discovered = svc
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
        assert!(
            discovered
                .capabilities
                .iter()
                .any(|entry| entry.name == "sekai.actions.assign_color")
        );
        let mut invalid = with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "assign_color".into(),
                    params: HashMap::from([("id".into(), "widget-1".into())]),
                    actor: String::new(),
                }),
                dry_run: false,
            },
            "local",
        );
        invalid.metadata_mut().insert(
            "x-sekai-capability",
            "sekai.actions.assign_color".parse().unwrap(),
        );
        invalid
            .metadata_mut()
            .insert("x-sekai-namespace", "acme".parse().unwrap());
        invalid.metadata_mut().insert(
            "x-sekai-operation-id",
            "catalog-write-invalid-1".parse().unwrap(),
        );
        assert_eq!(
            svc.execute_action(invalid).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let invalid_receipt = svc
            .db
            .get_operation_receipt("catalog-write-invalid-1")
            .unwrap()
            .unwrap();
        assert!(!invalid_receipt.completeness().complete);
        assert!(
            serde_json::to_string(&invalid_receipt)
                .unwrap()
                .contains("invocation_failed")
        );
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "acme".into(),
                default_decision: ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let mut held = with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "assign_color".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("color".into(), "blue".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            },
            "local",
        );
        for (key, value) in [
            ("x-sekai-capability", "sekai.actions.assign_color"),
            ("x-sekai-namespace", "acme"),
            ("x-sekai-operation-id", "catalog-write-approved-1"),
            ("x-chisei-work-unit", "catalog-write-approved-1"),
            (
                "x-sekai-catalog-version",
                discovered.catalog_version.as_str(),
            ),
        ] {
            held.metadata_mut().insert(
                key,
                value.parse().expect("test metadata must be valid ASCII"),
            );
        }
        let approval_id = svc
            .execute_action(held)
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap()
            .approval_id;
        svc.approve_action(with_named_principal(
            ApproveActionRequest { approval_id },
            "local",
        ))
        .await
        .unwrap();
        let approved_receipt = svc
            .db
            .get_operation_receipt("catalog-write-approved-1")
            .unwrap()
            .unwrap();
        assert!(approved_receipt.completeness().complete);
        assert!(
            approved_receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::ApprovalDecided)
        );
        assert!(
            approved_receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::ActionPerformed)
        );
        assert_eq!(
            svc.db.get_object("widget-1").unwrap().unwrap().properties["color"],
            "blue"
        );
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "acme".into(),
                default_decision: ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let mut write = with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "assign_color".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("color".into(), "blue".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            },
            "local",
        );
        write.metadata_mut().insert(
            "x-sekai-capability",
            "sekai.actions.assign_color".parse().unwrap(),
        );
        write
            .metadata_mut()
            .insert("x-sekai-namespace", "acme".parse().unwrap());
        write.metadata_mut().insert(
            "x-sekai-operation-id",
            "catalog-write-denied-1".parse().unwrap(),
        );
        let denied = svc.execute_action(write).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::FailedPrecondition);
        let denied_receipt = svc
            .db
            .get_operation_receipt("catalog-write-denied-1")
            .unwrap()
            .unwrap();
        assert!(!denied_receipt.completeness().complete);
        assert!(
            serde_json::to_string(&denied_receipt)
                .unwrap()
                .contains("capability_unavailable")
        );
        assert_eq!(
            svc.db.get_object("widget-1").unwrap().unwrap().properties["color"],
            "blue"
        );
    }

    #[tokio::test]
    async fn capability_discovery_is_deterministic_pageable_and_reuses_schemas() {
        let svc = service();
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.create_action_type(with_named_principal(
            CreateActionTypeRequest {
                action_type: Some(assign_color_action()),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "acme".into(),
                default_decision: ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: Some(7),
                max_deletes_per_work_unit: Some(2),
            })
            .unwrap();

        let full = svc
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
        assert_eq!(full.contract_version, capability::CONTRACT_VERSION);
        assert_eq!(full.cache_scope, "authorization_context");
        assert_eq!(full.total_size as usize, full.capabilities.len());
        let widget_query = full
            .capabilities
            .iter()
            .find(|entry| entry.name == "sekai.objects.query.widget")
            .unwrap();
        assert_eq!(widget_query.object_type.as_ref().unwrap().kind, "widget");
        assert_eq!(widget_query.input_type, "sekai.ListObjectsRequest");
        let custom_action = full
            .capabilities
            .iter()
            .find(|entry| entry.name == "sekai.actions.assign_color")
            .unwrap();
        let custom_action_type = custom_action.action_type.as_ref().unwrap();
        assert_eq!(custom_action_type.name, "assign_color");
        assert_eq!(custom_action_type.params, assign_color_action().params);
        assert_eq!(custom_action_type.ops, assign_color_action().ops);
        assert_eq!(custom_action.approval_behavior, "required");
        assert!(
            custom_action
                .limits
                .iter()
                .any(|limit| { limit.name == "max_mutations_per_work_unit" && limit.value == 7 })
        );
        assert!(
            custom_action
                .limits
                .iter()
                .any(|limit| { limit.name == "max_deletes_per_work_unit" && limit.value == 2 })
        );
        assert!(
            full.capabilities
                .iter()
                .all(|entry| entry.name != "sekai.actions.create_object")
        );
        let create_widget = full
            .capabilities
            .iter()
            .find(|entry| entry.name == "sekai.actions.create_object.widget")
            .unwrap();
        let create_params = &create_widget.action_type.as_ref().unwrap().params;
        assert!(create_params.iter().any(|param| {
            param.name == "kind" && param.r#type == "enum" && param.enum_values == ["widget"]
        }));
        assert!(create_params.iter().any(|param| {
            param.name == "color" && param.r#type == "enum" && param.enum_values == ["red", "blue"]
        }));
        assert_eq!(create_widget.object_type.as_ref().unwrap().kind, "widget");
        let record_learning = full
            .capabilities
            .iter()
            .find(|entry| entry.name == "sekai.actions.record_learning")
            .unwrap();
        let learning_params = &record_learning.action_type.as_ref().unwrap().params;
        assert!(
            learning_params
                .iter()
                .any(|param| param.name == "score" && param.r#type == "int")
        );
        assert!(
            learning_params
                .iter()
                .any(|param| param.name == "passed" && param.r#type == "bool")
        );
        assert!(learning_params.iter().any(|param| {
            param.name == "status"
                && param.r#type == "enum"
                && param.enum_values == ["candidate", "active", "superseded", "rejected"]
        }));
        assert!(
            record_learning
                .limits
                .iter()
                .any(|limit| { limit.name == "max_mutations_per_invocation" && limit.value == 2 })
        );
        assert!(
            record_learning
                .limits
                .iter()
                .any(|limit| limit.name == "score_max" && limit.value == 100)
        );

        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "acme".into(),
                default_decision: ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: Some(8),
                max_deletes_per_work_unit: Some(2),
            })
            .unwrap();
        let policy_changed = svc
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
        assert_ne!(policy_changed.catalog_version, full.catalog_version);

        let first = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    page_size: 2,
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        let repeat = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    page_size: 2,
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first.catalog_version, repeat.catalog_version);
        assert_eq!(first.capabilities, repeat.capabilities);
        assert!(!first.next_page_token.is_empty());

        let second = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    catalog_version: first.catalog_version.clone(),
                    page_size: 2,
                    page_token: first.next_page_token,
                    ..Default::default()
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second.catalog_version, first.catalog_version);
        assert!(first.capabilities.iter().all(|left| {
            second
                .capabilities
                .iter()
                .all(|right| left.name != right.name)
        }));
    }

    #[tokio::test]
    async fn capability_discovery_filters_namespace_schema_action_and_policy_metadata() {
        let svc = service();
        svc.ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "acme".into(),
                principal: "alice".into(),
                role: "editor".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.ensure_team_namespace(with_named_principal(
            EnsureTeamNamespaceRequest {
                namespace: "beta".into(),
                principal: "bob".into(),
                role: "viewer".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.create_action_type(with_named_principal(
            CreateActionTypeRequest {
                action_type: Some(assign_color_action()),
            },
            "local",
        ))
        .await
        .unwrap();
        let mut secret_schema = widget_schema_type();
        secret_schema.kind = "secret_widget".into();
        secret_schema.description = "hidden schema description".into();
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(secret_schema),
            },
            "local",
        ))
        .await
        .unwrap();
        let mut secret_action = assign_color_action();
        secret_action.name = "secret_action".into();
        secret_action.description = "hidden action description".into();
        secret_action.target_kind = "secret_widget".into();
        svc.create_action_type(with_named_principal(
            CreateActionTypeRequest {
                action_type: Some(secret_action),
            },
            "local",
        ))
        .await
        .unwrap();
        grant_object_role(
            &svc,
            &schema_object_id("secret_widget"),
            "bob",
            security::Role::Viewer,
        );
        grant_object_role(
            &svc,
            &action_object_id("secret_action"),
            "bob",
            security::Role::Viewer,
        );
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "acme".into(),
                default_decision: ActionDecision::Allow,
                action_overrides: HashMap::from([("assign_color".into(), ActionDecision::Deny)]),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let before = svc
            .db
            .list_decisions(&audit::DecisionFilter::default())
            .unwrap()
            .len();
        let catalog = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "acme".into(),
                    page_size: 200,
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(catalog.capabilities.iter().all(|entry| {
            !entry.name.contains("secret_widget")
                && !entry.name.contains("secret_action")
                && !entry.name.contains("assign_color")
                && entry
                    .object_type
                    .as_ref()
                    .is_none_or(|object_type| object_type.kind != "secret_widget")
                && entry
                    .action_type
                    .as_ref()
                    .is_none_or(|action_type| action_type.name != "secret_action")
        }));
        assert!(
            catalog
                .capabilities
                .iter()
                .any(|entry| entry.name == "sekai.objects.query.widget")
        );
        let after = svc
            .db
            .list_decisions(&audit::DecisionFilter::default())
            .unwrap()
            .len();
        assert_eq!(
            before, after,
            "discovery must not emit hidden audit metadata"
        );

        let denied = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "beta".into(),
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert_eq!(denied.message(), "capability discovery denied");
        assert!(!denied.message().contains("secret_widget"));
        assert!(!denied.message().contains("secret_action"));

        let viewer_catalog = svc
            .discover_capabilities(with_named_principal(
                DiscoverCapabilitiesRequest {
                    namespace: "beta".into(),
                    page_size: 200,
                    ..Default::default()
                },
                "bob",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(
            viewer_catalog
                .capabilities
                .iter()
                .all(|entry| entry.kind != "action")
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

    #[tokio::test]
    async fn planner_worker_reviewer_handoff_rechecks_versions_and_hides_cross_principal_state() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "artifact:plan".into(),
                kind: "artifact".into(),
                name: "plan".into(),
                namespace: "delivery".into(),
                external_id: "artifact:plan".into(),
                properties: HashMap::new(),
                created: 5,
                updated: 7,
            })
            .unwrap();
        add_object_grant(&svc, "artifact:plan", "planner", security::Role::Editor);
        add_object_grant(&svc, "artifact:plan", "reviewer", security::Role::Viewer);
        svc.db
            .create_work_unit(&coordination::WorkUnit {
                id: "work-unit:worker".into(),
                kind: "implementation".into(),
                actor: "worker".into(),
                target_object_id: "artifact:plan".into(),
                status: coordination::WORK_UNIT_STATUS_COMPLETED.into(),
                requested_spec: "produce reviewable output".into(),
                scope_id: "delivery".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: 5,
                admitted_at: 6,
                started_at: 6,
                finished_at: 9,
                last_heartbeat_at: 8,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: "planner".into(),
                creator_principal: "planner".into(),
                idempotency_key: "worker-unit-1".into(),
                updated_at: 9,
            })
            .unwrap();
        let object_version =
            reference_content_digest(&svc.db.get_object("artifact:plan").unwrap().unwrap())
                .unwrap();
        let work_unit_version =
            reference_content_digest(&svc.db.get_work_unit("work-unit:worker").unwrap().unwrap())
                .unwrap();
        let now = now_millis();
        let request = CreateHandoffRequest {
            manifest: Some(HandoffManifest {
                id: "handoff:planner-reviewer".into(),
                namespace: "delivery".into(),
                parent_operation_id: "operation:plan".into(),
                parent_attempt_id: "attempt:1".into(),
                parent_work_unit_id: "work-unit:worker".into(),
                references: vec![
                    HandoffReference {
                        kind: "object".into(),
                        id: "artifact:plan".into(),
                        version: object_version,
                        omitted: false,
                        omission_reason: String::new(),
                    },
                    HandoffReference {
                        kind: "work_unit".into(),
                        id: "work-unit:worker".into(),
                        version: work_unit_version,
                        omitted: false,
                        omission_reason: String::new(),
                    },
                    HandoffReference {
                        kind: "evidence_submission".into(),
                        id: "evidence:retained-away".into(),
                        version: String::new(),
                        omitted: true,
                        omission_reason: "retention".into(),
                    },
                ],
                creator_principal: "forged".into(),
                intended_principal: "reviewer".into(),
                intended_scope: "delivery".into(),
                purpose: "review the worker output".into(),
                created_at_ms: now,
                expires_at_ms: now + 60_000,
                digest: String::new(),
                supersedes_manifest_id: String::new(),
                revoked: false,
            }),
            request_id: "handoff-request-1".into(),
        };
        let created = svc
            .create_handoff(with_named_principal(request.clone(), "planner"))
            .await
            .unwrap()
            .into_inner()
            .manifest
            .unwrap();
        assert_eq!(created.creator_principal, "planner");
        assert!(created.digest.starts_with("sha256:"));
        let replay = svc
            .create_handoff(with_named_principal(request.clone(), "planner"))
            .await
            .unwrap()
            .into_inner()
            .manifest
            .unwrap();
        assert_eq!(replay.digest, created.digest);

        let resolved = svc
            .resolve_handoff(with_named_principal(
                ResolveHandoffRequest {
                    manifest_id: created.id.clone(),
                },
                "reviewer",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resolved.available_references.len(), 2);
        assert_eq!(resolved.omissions[0].omission_reason, "retention");
        let hidden = svc
            .resolve_handoff(with_named_principal(
                ResolveHandoffRequest {
                    manifest_id: created.id.clone(),
                },
                "intruder",
            ))
            .await
            .unwrap_err();
        assert_eq!(hidden.code(), tonic::Code::NotFound);

        let mut artifact = svc.db.get_object("artifact:plan").unwrap().unwrap();
        artifact.updated = 8;
        svc.db.update_object(&artifact).unwrap();
        let stale = svc
            .resolve_handoff(with_named_principal(
                ResolveHandoffRequest {
                    manifest_id: created.id.clone(),
                },
                "reviewer",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stale.available_references.len(), 1);
        assert!(
            stale
                .omissions
                .iter()
                .any(|reference| reference.id.is_empty()
                    && reference.version.is_empty()
                    && reference.omission_reason == "unavailable")
        );
        let replay_after_change = svc
            .create_handoff(with_named_principal(request, "planner"))
            .await
            .unwrap()
            .into_inner()
            .manifest
            .unwrap();
        assert_eq!(replay_after_change.digest, created.digest);

        let revoked_manifest = svc
            .revoke_handoff(with_named_principal(
                RevokeHandoffRequest {
                    manifest_id: created.id.clone(),
                    reason: "planner withdrew context".into(),
                    request_id: "revoke-1".into(),
                },
                "planner",
            ))
            .await
            .unwrap()
            .into_inner()
            .manifest
            .unwrap();
        assert!(revoked_manifest.revoked);
        let revoked_domain = svc.db.get_handoff(&revoked_manifest.id).unwrap().unwrap();
        assert_eq!(
            revoked_domain.digest,
            revoked_domain.canonical_digest().unwrap()
        );
        let revoked = svc
            .resolve_handoff(with_named_principal(
                ResolveHandoffRequest {
                    manifest_id: created.id,
                },
                "reviewer",
            ))
            .await
            .unwrap_err();
        assert_eq!(revoked.code(), tonic::Code::NotFound);
    }
}

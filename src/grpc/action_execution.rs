//! Admission for legacy governed Action execution.
//!
//! The gRPC adapter authenticates the caller, resolves catalog correlation,
//! and maps protocol responses. This deep module owns the live target,
//! classification, purpose, namespace, schema, and policy admission ordering
//! that every direct Action execution must cross before an effect can run.

use super::catalog_invocation::CatalogInvocation;
use super::{
    ERASED_NAMESPACE, RequestEnterpriseContext, SekaiServiceImpl, action_policy_namespace,
    check_team_namespace, check_write, enforce_namespace_tenant_context,
    enforce_object_marking_access, ensure_action_schema_kinds_allowed, is_managed_team_principal,
    map_schema_definition_lifecycle_error, now_millis, record_marking_or_purpose_decision,
    redact_action_evidence, redact_action_outcome, resolve_principal_authority,
    schema_restricted_action_property,
};
use crate::grpc::pb::sekai::{ActionRequest, ActionResult};
use crate::sekai::action_lifecycle::{ActionAudit, ActionLimitExceeded, GovernedActionContext};
use crate::sekai::action_policy::ActionDecision;
use crate::sekai::{action_lifecycle, markings, security};
use std::collections::{HashMap, HashSet};
use std::sync::RwLockReadGuard;
use tonic::Status;

pub(super) struct AdmittedAction<'a> {
    pub target_ids: Vec<String>,
    pub sensitive_params: HashSet<String>,
    pub schema_kinds: Vec<String>,
    pub actor: String,
    pub lifecycle: GovernedActionContext,
    pub actions: RwLockReadGuard<'a, crate::sekai::action::ActionExecutor>,
}

pub(super) struct ActionExecution<'a> {
    service: &'a SekaiServiceImpl,
}

impl<'a> ActionExecution<'a> {
    pub(super) fn new(service: &'a SekaiServiceImpl) -> Self {
        Self { service }
    }

    pub(super) fn admit(
        &self,
        request: &ActionRequest,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        work_unit: &str,
        catalog_namespace: Option<&str>,
    ) -> Result<AdmittedAction<'a>, Status> {
        let actions = self
            .service
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let mask_missing_link = actions.masks_missing_link(&request.action);
        let sensitive_params = actions.sensitive_param_names(&request.action);
        let target_ids = actions
            .target_ids(&self.service.db, &request.action, &request.params)
            .map_err(|error| {
                if mask_missing_link && error == "link not found" {
                    Status::permission_denied("write denied")
                } else {
                    Status::invalid_argument(error)
                }
            })?;

        if let Some(namespace) = catalog_namespace {
            for target_id in &target_ids {
                if let Some(target) = self
                    .service
                    .db
                    .get_object(target_id)
                    .map_err(Status::internal)?
                    && target.namespace != namespace
                {
                    return Err(Status::failed_precondition(
                        "capability namespace does not match action target",
                    ));
                }
            }
            if request
                .params
                .get("namespace")
                .is_some_and(|target_namespace| target_namespace != namespace)
            {
                return Err(Status::failed_precondition(
                    "capability namespace does not match action target",
                ));
            }
        }

        if actions.creates_namespace(&request.action, &request.params) {
            return Err(Status::permission_denied(
                "namespace objects must be managed through EnsureTeamNamespace",
            ));
        }
        for target_id in &target_ids {
            if let Some(target) = self
                .service
                .db
                .get_object(target_id)
                .map_err(Status::internal)?
            {
                if target.kind == markings::PRINCIPAL_PROFILE_KIND {
                    return Err(Status::permission_denied(
                        "principal_profile objects require credential-admin CRUD paths",
                    ));
                }
                enforce_namespace_tenant_context(
                    &self.service.db,
                    tenant_context,
                    &target.namespace,
                    true,
                )?;
                check_team_namespace(&self.service.db, principals, &target.namespace, true)?;
                let _ = enforce_object_marking_access(
                    &self.service.db,
                    &target,
                    principals,
                    &format!("execute_action:{}:{}", request.action, target_id),
                )?;
            }
            check_write(&self.service.security, target_id, principals)?;
        }

        self.validate_classification(request, &actions)?;
        self.check_purpose(request, principals, &target_ids, &actions)?;

        if let Some(namespace) = request.params.get("namespace") {
            enforce_namespace_tenant_context(&self.service.db, tenant_context, namespace, true)?;
            check_team_namespace(&self.service.db, principals, namespace, true)?;
        } else if request.action == "create_object"
            && (tenant_context.is_some()
                || is_managed_team_principal(&self.service.db, principals)?)
        {
            return Err(Status::permission_denied(
                "team object creation requires a canonical namespace",
            ));
        }

        let schema_kinds = actions
            .schema_kinds(&self.service.db, &request.action, &request.params)
            .map_err(Status::invalid_argument)?;
        ensure_action_schema_kinds_allowed(&schema_kinds)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let policy_namespace =
            action_policy_namespace(&self.service.db, &target_ids, &request.params);
        let (op_mutations, op_deletes) = actions.action_op_counts(&request.action, &request.params);
        let lifecycle = GovernedActionContext::resolve(
            &self.service.db,
            &actor,
            &policy_namespace,
            &request.action,
            actions.action_risk_class(&request.action),
            work_unit,
            op_mutations,
            op_deletes,
            ERASED_NAMESPACE,
        )
        .map_err(Status::internal)?;

        Ok(AdmittedAction {
            target_ids,
            sensitive_params,
            schema_kinds,
            actor,
            lifecycle,
            actions,
        })
    }

    /// Execute one admitted Action through every policy outcome.
    ///
    /// The transport adapter has already authenticated the caller and checked
    /// live catalog visibility. This interface owns dry-run, approval, denial,
    /// limits, schema validation, effect execution, audit, metering, and
    /// catalog receipt completion in their required order.
    pub(super) fn execute(
        &self,
        request: ActionRequest,
        dry_run: bool,
        admitted: AdmittedAction<'a>,
        mut receipt: Option<&mut CatalogInvocation<'_>>,
    ) -> Result<ActionResult, Status> {
        let AdmittedAction {
            target_ids,
            sensitive_params,
            schema_kinds,
            actor,
            lifecycle,
            actions,
        } = admitted;
        let decision = lifecycle.decision;
        if let Some(receipt) = receipt.as_deref_mut() {
            receipt.mark_policy_decided(decision.as_str());
        }

        if dry_run {
            let planned_ops = actions
                .planned_ops(&request.action, &request.params)
                .map_err(Status::invalid_argument)?;
            let mut evidence = redact_action_evidence(&request.params, &sensitive_params, None);
            evidence.insert("dry_run".into(), "true".into());
            lifecycle
                .record_outcome(
                    &self.service.db,
                    self.service.budget.as_deref(),
                    audit(&actor, &request, &target_ids, evidence),
                    "execute_action_dry_run",
                    format!(
                        "dry-run: {} planned op(s), decision={}",
                        planned_ops.len(),
                        decision.as_str()
                    ),
                    false,
                )
                .map_err(Status::internal)?;
            finalize_receipt(receipt, decision, "dry_run")?;
            return Ok(ActionResult {
                action: request.action,
                message: format!("dry run: {} planned op(s)", planned_ops.len()),
                dry_run: true,
                planned_ops,
                decision: decision.as_str().into(),
                approval_id: String::new(),
            });
        }

        if decision == ActionDecision::RequireApproval {
            let approval = action_lifecycle::hold_action(
                &self.service.db,
                &lifecycle,
                &actor,
                &request.action,
                request.params.clone(),
                target_ids.first().map(String::as_str).unwrap_or_default(),
                redact_action_evidence(&request.params, &sensitive_params, None),
                now_millis(),
            )
            .map_err(Status::internal)?;
            finalize_receipt(
                receipt,
                decision,
                &format!("approval_required:{}", approval.id),
            )?;
            return Ok(ActionResult {
                action: request.action,
                message: format!("action held for approval: {}", approval.id),
                dry_run: false,
                planned_ops: Vec::new(),
                decision: decision.as_str().into(),
                approval_id: approval.id,
            });
        }

        if decision == ActionDecision::Deny {
            finalize_receipt(receipt, decision, "denied")?;
            lifecycle
                .record_outcome(
                    &self.service.db,
                    self.service.budget.as_deref(),
                    audit(
                        &actor,
                        &request,
                        &target_ids,
                        redact_action_evidence(&request.params, &sensitive_params, None),
                    ),
                    "action_policy_denied",
                    format!(
                        "{} by action policy {}",
                        decision.as_str(),
                        lifecycle.policy_scope
                    ),
                    false,
                )
                .map_err(Status::internal)?;
            return Err(Status::permission_denied(format!(
                "action {} denied by policy",
                request.action
            )));
        }

        if let Err(limit) = lifecycle.check_limits_and_record(
            &self.service.db,
            self.service.budget.as_deref(),
            audit(
                &actor,
                &request,
                &target_ids,
                redact_action_evidence(&request.params, &sensitive_params, None),
            ),
        ) {
            return Err(match limit {
                ActionLimitExceeded::Internal(error) => Status::internal(error),
                ActionLimitExceeded::BlastRadius { work_unit, .. } => Status::resource_exhausted(
                    format!("blast-radius cap exceeded for work unit {work_unit}"),
                ),
                ActionLimitExceeded::Budget { subject, .. } => {
                    if let Some(receipt) = receipt.as_deref_mut() {
                        receipt.mark_budget_decided("budget_exceeded");
                    }
                    Status::resource_exhausted(format!("action budget exhausted for {subject}"))
                }
            });
        }
        if let Some(receipt) = receipt.as_deref_mut() {
            receipt.mark_budget_decided(if self.service.budget.is_some() {
                "allow"
            } else {
                "not_configured"
            });
        }

        for kind in schema_kinds {
            self.service.require_schema_kind_loaded(&kind)?;
        }
        let schema = self
            .service
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        actions
            .validate_action_schema(&request.action, &schema)
            .map_err(Status::invalid_argument)?;
        let restricted_property =
            schema_restricted_action_property(&self.service.db, &schema, &request.params);
        let provisional_grant = (request.action == crate::sekai::learning::RECORD_LEARNING_ACTION)
            .then(|| security::Grant {
                id: String::new(),
                object_id: request.params.get("id").cloned().unwrap_or_default(),
                principal: actor.clone(),
                role: security::Role::Admin,
                created: now_millis(),
            })
            .filter(|grant| !grant.object_id.is_empty());
        if let Some(grant) = &provisional_grant {
            self.service.security.add_grant(grant);
        }
        let message = match actions.execute(
            &self.service.db,
            &schema,
            &request.action,
            &request.params,
            &actor,
        ) {
            Ok(message) => message,
            Err(error) => {
                if let Some(grant) = &provisional_grant {
                    self.service
                        .security
                        .remove_grant(&grant.object_id, &grant.principal);
                }
                return Err(Status::invalid_argument(error));
            }
        };
        drop(actions);
        drop(schema);
        self.service
            .refresh_security_after_action(&request.action, &request.params, &actor)?;
        lifecycle
            .record_outcome(
                &self.service.db,
                self.service.budget.as_deref(),
                audit(
                    &actor,
                    &request,
                    &target_ids,
                    redact_action_evidence(&request.params, &sensitive_params, restricted_property),
                ),
                "execute_action",
                redact_action_outcome(
                    &request.action,
                    &request.params,
                    &message,
                    restricted_property,
                ),
                true,
            )
            .map_err(Status::internal)?;
        finalize_receipt(receipt, decision, "succeeded")?;
        Ok(ActionResult {
            action: request.action,
            message,
            dry_run: false,
            planned_ops: Vec::new(),
            decision: decision.as_str().into(),
            approval_id: String::new(),
        })
    }

    fn validate_classification(
        &self,
        request: &ActionRequest,
        actions: &crate::sekai::action::ActionExecutor,
    ) -> Result<(), Status> {
        if request
            .params
            .get("key")
            .is_some_and(|key| key == markings::OBJECT_CLASSIFICATION_PROPERTY)
            && let Some(value) = request.params.get("value")
        {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        if let Some(value) = request.params.get(markings::OBJECT_CLASSIFICATION_PROPERTY) {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        if let Some(action_type) = actions.get_action_type(&request.action) {
            for operation in &action_type.ops {
                if operation.op == "set_property"
                    && operation.property == markings::OBJECT_CLASSIFICATION_PROPERTY
                {
                    let value = if operation.value_from.is_empty() {
                        request.params.get("value")
                    } else {
                        request.params.get(&operation.value_from)
                    };
                    if let Some(value) = value {
                        markings::parse_optional_classification(value)
                            .map_err(Status::invalid_argument)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn check_purpose(
        &self,
        request: &ActionRequest,
        principals: &[String],
        target_ids: &[String],
        actions: &crate::sekai::action::ActionExecutor,
    ) -> Result<(), Status> {
        let required_purpose = actions
            .get_action_type(&request.action)
            .map(|action_type| action_type.required_purpose.clone())
            .unwrap_or_default();
        if required_purpose.trim().is_empty() {
            return Ok(());
        }
        let authority = resolve_principal_authority(&self.service.db, principals)?;
        let purpose = markings::evaluate_purpose_access(
            &format!("execute_action:{}", request.action),
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
                &self.service.db,
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
                &self.service.db,
                &actor,
                "purpose.execute",
                target_ids.first().map(String::as_str).unwrap_or(""),
                &purpose.decision_id,
                "allowed",
                evidence,
            )?;
        }
        Ok(())
    }
}

fn audit(
    actor: &str,
    request: &ActionRequest,
    target_ids: &[String],
    evidence: HashMap<String, String>,
) -> ActionAudit {
    ActionAudit {
        actor: actor.to_string(),
        attestation_actor: actor.to_string(),
        action: request.action.clone(),
        target_id: target_ids.first().cloned().unwrap_or_default(),
        evidence,
        timestamp: now_millis(),
    }
}

fn finalize_receipt(
    receipt: Option<&mut CatalogInvocation<'_>>,
    decision: ActionDecision,
    outcome: &str,
) -> Result<(), Status> {
    receipt
        .map(|receipt| receipt.finalize(decision.as_str(), outcome))
        .transpose()
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::domain;
    use crate::sekai::action_policy::ActionDecision;
    use crate::sekai::security::{Grant, Role};
    use std::sync::Arc;

    fn admitted_service() -> SekaiServiceImpl {
        let service = SekaiServiceImpl::new(Arc::new(RuntimeDb::memory()));
        service
            .db
            .create_object(&domain::Object {
                id: "target-1".into(),
                kind: "object".into(),
                name: "target".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        let grant = Grant {
            id: "grant-1".into(),
            object_id: "target-1".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 0,
        };
        service.db.create_grant(&grant).unwrap();
        service.security.add_grant(&grant);
        service
    }

    fn set_property_request(value: &str) -> ActionRequest {
        ActionRequest {
            action: "set_property".into(),
            params: HashMap::from([
                ("id".into(), "target-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), value.into()),
            ]),
            actor: "ignored-protocol-actor".into(),
        }
    }

    #[test]
    fn interface_admits_authorized_target_and_binds_authenticated_actor() {
        let service = admitted_service();
        let admitted = ActionExecution::new(&service)
            .admit(
                &set_property_request("ready"),
                &["alice".into()],
                None,
                "work-1",
                None,
            )
            .unwrap();

        assert_eq!(admitted.target_ids, ["target-1"]);
        assert_eq!(admitted.actor, "alice");
        assert_eq!(admitted.lifecycle.decision, ActionDecision::Allow);
        assert_eq!(admitted.lifecycle.work_unit, "work-1");
    }

    #[test]
    fn interface_rejects_ungranted_target_before_policy_resolution() {
        let service = admitted_service();
        let error = match ActionExecution::new(&service).admit(
            &set_property_request("ready"),
            &["mallory".into()],
            None,
            "work-1",
            None,
        ) {
            Ok(_) => panic!("ungranted target must be denied"),
            Err(error) => error,
        };

        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn interface_executes_admitted_action_and_returns_result() {
        let service = admitted_service();
        let request = set_property_request("ready");
        let execution = ActionExecution::new(&service);
        let admitted = execution
            .admit(&request, &["alice".into()], None, "work-1", None)
            .unwrap();

        let result = execution.execute(request, false, admitted, None).unwrap();

        assert_eq!(result.action, "set_property");
        assert_eq!(result.decision, "allow");
        assert_eq!(
            service
                .db
                .get_object("target-1")
                .unwrap()
                .unwrap()
                .properties
                .get("status")
                .map(String::as_str),
            Some("ready")
        );
    }
}

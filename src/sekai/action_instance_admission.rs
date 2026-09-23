//! Governed `ActionInstance` admission behind one transport-neutral interface.
//!
//! Transport adapters authenticate the caller and enforce tenant context. This
//! module owns request validation, idempotent replay, type/policy/budget
//! decisions, receipt and audit creation, effect planning, and post-admission
//! metering so their ordering is exercised through the same interface callers
//! use.

use crate::chisei::budget::BudgetTracker;
use crate::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action::RiskClass;
use crate::sekai::action_instance::{
    ActionInstance, DECISION_DENY, DECISION_GRANT, STATUS_ADMITTED, STATUS_DENIED, STATUS_PARKED,
    SUBMIT_POLICY_ACTION, compute_request_digest_with_envelope, submit_budget_subject,
    validate_parameters_json,
};
use crate::sekai::action_object_mutation::{
    ActionObjectMutationError, AppliedObjectMutation, plan as plan_object_mutation,
};
use crate::sekai::action_type_criteria::{
    CRITERION_UNAVAILABLE, CriterionDecision, evaluate_submission_criteria, invoker_context,
};
use crate::sekai::object_security::PrincipalPolicyContext;
use crate::sekai::{action_effect, action_object_mutation, action_policy, audit, object_log};
use std::collections::{BTreeMap, HashMap};

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_RECORD_ADMISSION: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fail_next_record_admission() {
    FAIL_NEXT_RECORD_ADMISSION.with(|flag| flag.set(true));
}

#[derive(Debug, Clone)]
pub(crate) struct ActionInstanceAdmissionRequest {
    pub namespace: String,
    pub type_id: String,
    pub version: String,
    pub parameters_json: String,
    pub idempotency_key: String,
    pub evidence_submission_ids: Vec<String>,
    pub request_id: String,
    pub ontology_digest: String,
    pub autonomous_envelope_id: String,
    pub policy_context: PrincipalPolicyContext,
    pub budget_already_reserved: bool,
}

/// Grant or deny of a parked instance (#1084). The transport adapter
/// authenticates the decider and states which principals they present and
/// whether they administer the instance namespace.
#[derive(Debug, Clone)]
pub(crate) struct ActionInstanceDecisionRequest {
    pub instance_id: String,
    pub decision: String,
    pub reason: String,
    pub decider_principals: Vec<String>,
    pub decider_is_namespace_admin: bool,
}

/// One bounded answer for every refused or unknown decision target, so a
/// caller learns nothing about instances or types it may not decide.
pub(crate) const DECISION_ACCESS_DENIED: &str = "access denied";

#[derive(Debug, Clone)]
pub(crate) struct ActionInstanceAdmissionOutcome {
    pub instance: ActionInstance,
    pub replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActionInstanceAdmissionError {
    InvalidArgument(String),
    FailedPrecondition(String),
    AlreadyExists(String),
    PermissionDenied(String),
    Internal(String),
}

/// Recorded on the parked instance's receipt when an approver decides.
struct ApprovalRecord<'r> {
    decider: &'r str,
    decision: &'r str,
    reason: &'r str,
}

pub(crate) struct ActionInstanceAdmission<'a> {
    db: &'a RuntimeDb,
    budget: Option<&'a BudgetTracker>,
}

impl<'a> ActionInstanceAdmission<'a> {
    pub(crate) fn new(db: &'a RuntimeDb, budget: Option<&'a BudgetTracker>) -> Self {
        Self { db, budget }
    }

    pub(crate) fn admit(
        &self,
        request: ActionInstanceAdmissionRequest,
        actor: &str,
        now: i64,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let budget_already_reserved = request.budget_already_reserved;
        let namespace = request.namespace.trim().to_string();
        require_value("namespace", &namespace)?;
        require_value("type_id", request.type_id.trim())?;
        require_value("version", request.version.trim())?;
        require_value("idempotency_key", request.idempotency_key.trim())?;
        if request.idempotency_key.chars().any(char::is_whitespace) {
            return Err(ActionInstanceAdmissionError::InvalidArgument(
                "idempotency_key must not contain whitespace".into(),
            ));
        }
        validate_parameters_json(&request.parameters_json)
            .map_err(ActionInstanceAdmissionError::InvalidArgument)?;

        let mut evidence_ids = request.evidence_submission_ids.clone();
        evidence_ids.sort();
        evidence_ids.dedup();
        if evidence_ids.iter().any(|id| id.trim().is_empty()) {
            return Err(ActionInstanceAdmissionError::InvalidArgument(
                "evidence_submission_ids must not contain empty ids".into(),
            ));
        }
        let envelope_id = autonomous_envelope_id(&request)?;
        let request_digest = compute_request_digest_with_envelope(
            &namespace,
            &request.type_id,
            &request.version,
            &request.parameters_json,
            &evidence_ids,
            &envelope_id,
        )
        .map_err(ActionInstanceAdmissionError::InvalidArgument)?;

        let ontology_digest = parse_ontology_digest(&request.ontology_digest)?;

        if let Some(existing) = self
            .db
            .get_action_instance_by_idempotency(&namespace, &request.idempotency_key)
            .map_err(ActionInstanceAdmissionError::Internal)?
        {
            if existing.request_digest != request_digest {
                return Err(ActionInstanceAdmissionError::AlreadyExists(
                    "idempotency key conflict: same key with different request digest".into(),
                ));
            }
            return self.completed_replay(existing);
        }

        // New admissions consume a live signed envelope. Replay of an already
        // admitted request stays idempotent after stop, rollback, lease loss,
        // or receipt invalidation. The envelope is not a runtime grant.
        if request.type_id.starts_with("autonomous.") || !envelope_id.is_empty() {
            crate::sekai::autonomous_envelope::require_live_envelope(
                self.db,
                actor,
                &namespace,
                &envelope_id,
            )
            .map_err(ActionInstanceAdmissionError::FailedPrecondition)?;
        }

        let type_def = self
            .db
            .require_enabled_governed_action_type(&namespace, &request.type_id, &request.version)
            .map_err(|error| {
                if error.contains("unknown") || error.contains("disabled") {
                    ActionInstanceAdmissionError::FailedPrecondition(error)
                } else {
                    ActionInstanceAdmissionError::Internal(error)
                }
            })?;
        crate::chisei::evaluation_plan::validate_parameter_schema(&type_def.parameter_schema_json)
            .map_err(|error| {
                ActionInstanceAdmissionError::FailedPrecondition(format!(
                    "governed action type parameter schema invalid: {error}"
                ))
            })?;
        crate::chisei::evaluation_plan::validate_parameters(
            &type_def.parameter_schema_json,
            &request.parameters_json,
        )
        .map_err(|error| {
            ActionInstanceAdmissionError::InvalidArgument(format!(
                "action parameters invalid: {error}"
            ))
        })?;

        let criterion_object =
            load_criterion_object(self.db, &namespace, &type_def, &request.parameters_json)?;
        let criterion_policy = match &criterion_object {
            Some(object) => self
                .db
                .active_object_policy(&object.namespace, &object.kind)
                .map_err(|_| {
                    ActionInstanceAdmissionError::FailedPrecondition(
                        "object action unavailable".into(),
                    )
                })?,
            None => None,
        };
        let invoker = invoker_context(actor, Some(&request.policy_context));
        let criterion_decision = evaluate_submission_criteria(
            &type_def.submission_criteria,
            criterion_object.as_ref(),
            criterion_policy.as_ref(),
            &invoker,
        );

        let policy_project = if type_def.policy_scope.trim().is_empty() {
            namespace.clone()
        } else {
            type_def.policy_scope.clone()
        };
        let resolved_policy = self
            .db
            .resolve_action_policy(actor, &namespace, &policy_project)
            .map_err(ActionInstanceAdmissionError::Internal)?;
        let (policy_decision, policy_scope_label) = match &resolved_policy {
            Some(policy) => (
                policy.decide(SUBMIT_POLICY_ACTION, RiskClass::Write),
                policy.scope.clone(),
            ),
            None => (action_policy::ActionDecision::Allow, String::new()),
        };

        let instance_id = format!("gai-{}", uuid::Uuid::new_v4().simple());
        let operation_id = resolve_operation_id(&request.request_id)?;
        if let Some(existing) = self
            .db
            .get_action_instance_by_operation_id(&operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
        {
            return Err(ActionInstanceAdmissionError::AlreadyExists(format!(
                "operation_id {} is already bound to action instance {}",
                existing.operation_id, existing.instance_id
            )));
        }
        let mut status = STATUS_ADMITTED.to_string();
        let mut deny_reason = String::new();
        let mut policy_decision_text = policy_decision.as_str().to_string();
        let mut budget_decision = if self.budget.is_some() {
            "allow".to_string()
        } else {
            "not_configured".to_string()
        };
        match criterion_decision {
            CriterionDecision::Pass => {}
            CriterionDecision::Fail { criterion_id } => {
                status = STATUS_DENIED.into();
                deny_reason = criterion_id;
            }
            CriterionDecision::Unavailable => {
                status = STATUS_DENIED.into();
                deny_reason = CRITERION_UNAVAILABLE.into();
            }
        }
        if status == STATUS_ADMITTED && policy_decision == action_policy::ActionDecision::Deny {
            status = STATUS_DENIED.into();
            deny_reason = if policy_scope_label.is_empty() {
                "action policy denied submit_action_instance".into()
            } else {
                format!("action policy denied submit_action_instance ({policy_scope_label})")
            };
        } else if status == STATUS_ADMITTED
            && policy_decision == action_policy::ActionDecision::RequireApproval
        {
            // Parked, not denied: an approver decides later, and a grant
            // resumes this same instance against the state it finds then.
            status = STATUS_PARKED.into();
            policy_decision_text = "require_approval".into();
            budget_decision = "deferred".into();
        }

        let budget_subject = submit_budget_subject(&namespace, actor, &type_def.budget_scope);
        if status == STATUS_ADMITTED
            && let Some(budget) = self.budget
            && !budget_already_reserved
            && budget.check(&budget_subject, 1).is_err()
        {
            status = STATUS_DENIED.into();
            deny_reason = format!("action budget exhausted for {budget_subject}");
            budget_decision = "budget_exceeded".into();
        }

        let system_one_fill_json = crate::chisei::system_one_action::fill_provenance_json(
            &type_def,
            &request.parameters_json,
        )
        .map_err(ActionInstanceAdmissionError::InvalidArgument)?;
        let parked_object_digest = if status == STATUS_PARKED {
            target_object_digest(self.db, &request.parameters_json)?
        } else {
            String::new()
        };
        let instance = ActionInstance {
            instance_id: instance_id.clone(),
            namespace: namespace.clone(),
            type_id: request.type_id,
            version: request.version,
            principal: actor.to_string(),
            parameters_json: request.parameters_json,
            request_digest,
            idempotency_key: request.idempotency_key,
            operation_id: operation_id.clone(),
            status: status.clone(),
            deny_reason,
            evidence_submission_ids: evidence_ids.clone(),
            policy_decision: policy_decision_text,
            budget_decision,
            created_at_ms: now,
            decided_at_ms: now,
            system_one_fill_json,
            parked_object_digest,
            decided_by: String::new(),
            approval_decision: String::new(),
            autonomous_envelope_id: envelope_id.clone(),
        };
        let planned_effects = if status == STATUS_ADMITTED {
            let force_notify_fail =
                serde_json::from_str::<serde_json::Value>(&instance.parameters_json)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("notify_delivery")
                            .and_then(|delivery| delivery.as_str())
                            .map(|delivery| delivery == "fail")
                    })
                    .unwrap_or(false);
            Some(
                action_effect::plan_effects_for_admit(
                    &instance.instance_id,
                    &instance.namespace,
                    &instance.operation_id,
                    type_def.effect_kinds_to_materialize(),
                    &instance.parameters_json,
                    now,
                    force_notify_fail,
                )
                .map_err(ActionInstanceAdmissionError::InvalidArgument)?,
            )
        } else {
            None
        };

        // Reserve the instance before mutating so concurrent same-key submits
        // replay at the idempotency insert instead of racing the object write.
        let stored = self.db.put_action_instance(&instance).map_err(|error| {
            if error.contains("conflict") {
                ActionInstanceAdmissionError::AlreadyExists(error)
            } else if error.contains("required") || error.contains("must") {
                ActionInstanceAdmissionError::InvalidArgument(error)
            } else {
                ActionInstanceAdmissionError::Internal(error)
            }
        })?;
        let replay = stored.instance_id != instance_id;
        if replay {
            return self.completed_replay(stored);
        }

        // Same-key replay already returned above. Plan only a fresh admit so a
        // prior create cannot block retry or a durable deny. Submit policy on
        // the type is the write authority; this path does not re-check
        // CreateObject/UpdateObject grants.
        let applied_object = if status == STATUS_ADMITTED {
            match plan_object_mutation(
                self.db,
                &type_def,
                &stored.namespace,
                &stored.parameters_json,
            ) {
                Ok(None) => None,
                Ok(Some(planned)) => {
                    match action_object_mutation::apply(self.db, planned, actor, now) {
                        Ok(applied) => Some(applied),
                        Err(error) => {
                            let _ = self.db.delete_action_instance(&stored.instance_id);
                            return Err(map_object_mutation_error(error));
                        }
                    }
                }
                Err(error) => {
                    let _ = self.db.delete_action_instance(&stored.instance_id);
                    return Err(map_object_mutation_error(error));
                }
            }
        } else {
            None
        };
        if let Err(error) = self.record_admission(
            &stored,
            actor,
            &policy_scope_label,
            &budget_subject,
            &evidence_ids,
            planned_effects.as_deref(),
            applied_object.as_ref(),
            ontology_digest,
            budget_already_reserved,
            None,
            now,
        ) {
            let receipt_exists = self
                .db
                .get_operation_receipt(&stored.operation_id)
                .ok()
                .flatten()
                .is_some();
            if !receipt_exists {
                if let Some(applied) = &applied_object {
                    action_object_mutation::compensate(self.db, applied, actor);
                }
                let _ = self.db.delete_action_instance(&stored.instance_id);
            }
            return Err(error);
        }
        Ok(ActionInstanceAdmissionOutcome {
            instance: stored,
            replay,
        })
    }

    /// Grants or denies a parked instance (#1084). Authorization comes first
    /// and answers every refusal the same way. A repeated decision replays;
    /// a conflicting one fails. A grant resumes admission against current
    /// state; anything that changed since the park denies the instance
    /// terminally instead of writing part of it.
    pub(crate) fn decide(
        &self,
        request: ActionInstanceDecisionRequest,
        decider: &str,
        now: i64,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let decision = request.decision.trim();
        if decision != DECISION_GRANT && decision != DECISION_DENY {
            return Err(ActionInstanceAdmissionError::InvalidArgument(
                "decision must be grant or deny".into(),
            ));
        }
        require_value("instance_id", request.instance_id.trim())?;
        let access_denied =
            || ActionInstanceAdmissionError::PermissionDenied(DECISION_ACCESS_DENIED.into());
        let instance = self
            .db
            .get_action_instance(request.instance_id.trim())
            .map_err(ActionInstanceAdmissionError::Internal)?
            .ok_or_else(access_denied)?;
        let type_def = self
            .db
            .get_governed_action_type(&instance.namespace, &instance.type_id, &instance.version)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .ok_or_else(access_denied)?;
        let is_submitter = decider == instance.principal
            || request
                .decider_principals
                .iter()
                .any(|principal| principal == &instance.principal);
        let entitled = if type_def.approvers.is_empty() {
            request.decider_is_namespace_admin
        } else {
            request
                .decider_principals
                .iter()
                .chain(std::iter::once(&decider.to_string()))
                .any(|principal| type_def.approvers.contains(principal))
        };
        if is_submitter || !entitled {
            return Err(access_denied());
        }

        if instance.status != STATUS_PARKED {
            if instance.approval_decision == decision {
                return Ok(ActionInstanceAdmissionOutcome {
                    instance,
                    replay: true,
                });
            }
            return Err(ActionInstanceAdmissionError::FailedPrecondition(
                "action instance is not awaiting a decision".into(),
            ));
        }
        let approval = ApprovalRecord {
            decider,
            decision,
            reason: &request.reason,
        };
        if decision == DECISION_DENY {
            return self.finish_denied(instance, "denied_by_approver", &approval, now);
        }

        if !type_def.enabled {
            return self.finish_denied(instance, "type_unavailable_on_resume", &approval, now);
        }
        // The same autonomy fence as submit: a stopped or rolled-back
        // envelope cannot be resumed by an approval.
        if (instance.type_id.starts_with("autonomous.")
            || !instance.autonomous_envelope_id.is_empty())
            && crate::sekai::autonomous_envelope::require_live_envelope(
                self.db,
                &instance.principal,
                &instance.namespace,
                &instance.autonomous_envelope_id,
            )
            .is_err()
        {
            return self.finish_denied(instance, "envelope_not_live_on_resume", &approval, now);
        }
        if target_object_digest(self.db, &instance.parameters_json)?
            != instance.parked_object_digest
        {
            return self.finish_denied(instance, "stale_on_resume", &approval, now);
        }
        if crate::chisei::evaluation_plan::validate_parameters(
            &type_def.parameter_schema_json,
            &instance.parameters_json,
        )
        .is_err()
        {
            return self.finish_denied(instance, "parameters_invalid_on_resume", &approval, now);
        }
        let criterion_object = load_criterion_object(
            self.db,
            &instance.namespace,
            &type_def,
            &instance.parameters_json,
        )?;
        let criterion_policy = match &criterion_object {
            Some(object) => self
                .db
                .active_object_policy(&object.namespace, &object.kind)
                .map_err(|_| {
                    ActionInstanceAdmissionError::FailedPrecondition(
                        "object action unavailable".into(),
                    )
                })?,
            None => None,
        };
        match evaluate_submission_criteria(
            &type_def.submission_criteria,
            criterion_object.as_ref(),
            criterion_policy.as_ref(),
            &invoker_context(&instance.principal, None),
        ) {
            CriterionDecision::Pass => {}
            CriterionDecision::Fail { criterion_id } => {
                return self.finish_denied(instance, &criterion_id, &approval, now);
            }
            CriterionDecision::Unavailable => {
                return self.finish_denied(instance, CRITERION_UNAVAILABLE, &approval, now);
            }
        }
        let policy_project = if type_def.policy_scope.trim().is_empty() {
            instance.namespace.clone()
        } else {
            type_def.policy_scope.clone()
        };
        let resolved_policy = self
            .db
            .resolve_action_policy(&instance.principal, &instance.namespace, &policy_project)
            .map_err(ActionInstanceAdmissionError::Internal)?;
        let policy_scope_label = resolved_policy
            .as_ref()
            .map(|policy| policy.scope.clone())
            .unwrap_or_default();
        // The approval satisfies only `require_approval`; a policy that now
        // denies still denies.
        if resolved_policy.as_ref().is_some_and(|policy| {
            policy.decide(SUBMIT_POLICY_ACTION, RiskClass::Write)
                == action_policy::ActionDecision::Deny
        }) {
            return self.finish_denied(instance, "policy_denied_on_resume", &approval, now);
        }
        let budget_subject = submit_budget_subject(
            &instance.namespace,
            &instance.principal,
            &type_def.budget_scope,
        );
        // A decision never charges budget: the submit already accounted for
        // this instance (Combined Split reserves one unit at submit).

        let force_notify_fail =
            serde_json::from_str::<serde_json::Value>(&instance.parameters_json)
                .ok()
                .and_then(|value| {
                    value
                        .get("notify_delivery")
                        .and_then(|delivery| delivery.as_str())
                        .map(|delivery| delivery == "fail")
                })
                .unwrap_or(false);
        let planned_effects = action_effect::plan_effects_for_admit(
            &instance.instance_id,
            &instance.namespace,
            &instance.operation_id,
            type_def.effect_kinds_to_materialize(),
            &instance.parameters_json,
            now,
            force_notify_fail,
        )
        .map_err(ActionInstanceAdmissionError::InvalidArgument)?;
        let planned_object = plan_object_mutation(
            self.db,
            &type_def,
            &instance.namespace,
            &instance.parameters_json,
        )
        .map_err(map_object_mutation_error)?;
        let mut granted = instance.clone();
        granted.status = STATUS_ADMITTED.into();
        granted.deny_reason.clear();
        granted.policy_decision = "require_approval:granted".into();
        granted.budget_decision = if self.budget.is_some() {
            "allow".into()
        } else {
            "not_configured".into()
        };
        granted.decided_at_ms = now;
        granted.decided_by = decider.to_string();
        granted.approval_decision = DECISION_GRANT.into();
        // The object write and the parked-to-admitted transition commit
        // together, with the target re-digested under the same lock (#1139).
        let applied_object = match action_object_mutation::grant_parked(
            self.db,
            planned_object,
            &granted,
            &target_object_id(&instance.parameters_json),
            &instance.parked_object_digest,
            &instance.principal,
            now,
        )
        .map_err(map_object_mutation_error)?
        {
            action_object_mutation::ParkedGrant::Granted(applied) => {
                applied.map(|applied| *applied)
            }
            action_object_mutation::ParkedGrant::NotParked => {
                return self.replay_decided(&instance.instance_id, decision);
            }
            action_object_mutation::ParkedGrant::Stale => {
                return self.finish_denied(instance, "stale_on_resume", &approval, now);
            }
        };
        let ontology_digest = self
            .db
            .get_operation_receipt(&instance.operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .and_then(|receipt| receipt.ontology_digest);
        if let Err(error) = self.record_admission(
            &granted,
            &instance.principal,
            &policy_scope_label,
            &budget_subject,
            &granted.evidence_submission_ids,
            Some(&planned_effects),
            applied_object.as_ref(),
            ontology_digest,
            false,
            Some(&approval),
            now,
        ) {
            // Mirror admission: once the receipt records the approval the
            // grant stands; before that, undo the object write and park the
            // instance again so the decision can be retried.
            let recorded = self
                .db
                .get_operation_receipt(&instance.operation_id)
                .ok()
                .flatten()
                .is_some_and(|receipt| {
                    receipt
                        .events
                        .iter()
                        .any(|event| event.kind == ReceiptEventKind::ApprovalDecided)
                });
            if !recorded {
                if let Some(applied) = &applied_object {
                    action_object_mutation::compensate(self.db, applied, &instance.principal);
                }
                let _ = self.db.repark_action_instance(&instance);
            }
            return Err(error);
        }
        Ok(ActionInstanceAdmissionOutcome {
            instance: granted,
            replay: false,
        })
    }

    fn finish_denied(
        &self,
        instance: ActionInstance,
        reason: &str,
        approval: &ApprovalRecord<'_>,
        now: i64,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let mut denied = instance;
        denied.status = STATUS_DENIED.into();
        denied.deny_reason = reason.into();
        denied.decided_at_ms = now;
        denied.decided_by = approval.decider.to_string();
        denied.approval_decision = approval.decision.to_string();
        if denied.budget_decision == "deferred" {
            denied.budget_decision = "not_applicable".into();
        }
        if !self
            .db
            .decide_parked_action_instance(&denied)
            .map_err(ActionInstanceAdmissionError::Internal)?
        {
            return self.replay_decided(&denied.instance_id, approval.decision);
        }
        let ontology_digest = self
            .db
            .get_operation_receipt(&denied.operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .and_then(|receipt| receipt.ontology_digest);
        let budget_subject = submit_budget_subject(&denied.namespace, &denied.principal, "");
        self.record_admission(
            &denied,
            &denied.principal,
            "",
            &budget_subject,
            &denied.evidence_submission_ids,
            None,
            None,
            ontology_digest,
            false,
            Some(approval),
            now,
        )?;
        Ok(ActionInstanceAdmissionOutcome {
            instance: denied,
            replay: false,
        })
    }

    fn replay_decided(
        &self,
        instance_id: &str,
        decision: &str,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let current = self
            .db
            .get_action_instance(instance_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .ok_or_else(|| {
                ActionInstanceAdmissionError::Internal("decided instance vanished".into())
            })?;
        if current.approval_decision == decision {
            Ok(ActionInstanceAdmissionOutcome {
                instance: current,
                replay: true,
            })
        } else {
            Err(ActionInstanceAdmissionError::FailedPrecondition(
                "action instance is not awaiting a decision".into(),
            ))
        }
    }

    fn completed_replay(
        &self,
        existing: ActionInstance,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        if self
            .db
            .get_operation_receipt(&existing.operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .is_none()
        {
            return Err(ActionInstanceAdmissionError::FailedPrecondition(
                "action instance admission is still in progress".into(),
            ));
        }
        if existing.status == STATUS_ADMITTED
            && let Some(object) = object_for_admitted_instance(self.db, &existing)?
        {
            // Clerk admission is already durable. Log catch-up is best-effort so
            // a transient object-log error cannot fail an idempotent replay.
            catch_up_object_log(&existing.operation_id, &object.id, &object.kind, &object);
        }
        Ok(ActionInstanceAdmissionOutcome {
            instance: existing,
            replay: true,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn record_admission(
        &self,
        stored: &ActionInstance,
        actor: &str,
        policy_scope: &str,
        budget_subject: &str,
        evidence_ids: &[String],
        planned_effects: Option<&[action_effect::ActionEffect]>,
        applied_object: Option<&AppliedObjectMutation>,
        ontology_digest: Option<String>,
        budget_already_reserved: bool,
        approval: Option<&ApprovalRecord<'_>>,
        now: i64,
    ) -> Result<(), ActionInstanceAdmissionError> {
        #[cfg(test)]
        if FAIL_NEXT_RECORD_ADMISSION.with(|flag| flag.replace(false)) {
            return Err(ActionInstanceAdmissionError::Internal(
                "injected record_admission failure".into(),
            ));
        }
        let operation_id = &stored.operation_id;
        let mut intent_attributes = BTreeMap::from([
            ("instance_id".into(), stored.instance_id.clone()),
            ("type_id".into(), stored.type_id.clone()),
            ("version".into(), stored.version.clone()),
            ("request_digest".into(), stored.request_digest.clone()),
            ("idempotency_key".into(), stored.idempotency_key.clone()),
        ]);
        if !evidence_ids.is_empty() {
            intent_attributes.insert("evidence_submission_ids".into(), evidence_ids.join(","));
        }
        if let Some(applied) = applied_object {
            intent_attributes.insert("object_id".into(), applied.object_id.clone());
            intent_attributes.insert("object_kind".into(), applied.object_kind.clone());
            intent_attributes.insert("object_mutation".into(), applied.mutation.clone());
        }
        let event =
            |suffix: &str,
             parent: Option<String>,
             kind: ReceiptEventKind,
             attributes: BTreeMap<String, String>| OperationReceiptEvent {
                event_id: format!("{operation_id}:{suffix}"),
                operation_id: operation_id.clone(),
                parent_event_id: parent,
                timestamp_ms: now,
                surface: kind.surface(),
                kind,
                actor: actor.to_string(),
                references: Vec::new(),
                attributes,
            };
        let mut outcome_attributes = BTreeMap::from([("outcome".into(), stored.status.clone())]);
        if !stored.deny_reason.is_empty() {
            outcome_attributes.insert("deny_reason".into(), stored.deny_reason.clone());
        }
        // Denied admits never plan effects. Gate on admitted status so a
        // terminal denial cannot stay incomplete if a planner later passes
        // leftover pending dispatch.
        // A parked instance awaits its approver: the receipt stays open until
        // the decision completes it.
        let await_runtime_dispatch = stored.status == STATUS_PARKED
            || (stored.status == STATUS_ADMITTED && has_pending_runtime_dispatch(planned_effects));
        let mut events = vec![
            event(
                "intent",
                None,
                ReceiptEventKind::IntentRecorded,
                intent_attributes,
            ),
            event(
                "policy",
                Some(format!("{operation_id}:intent")),
                ReceiptEventKind::PolicyDecided,
                BTreeMap::from([
                    ("decision".into(), stored.policy_decision.clone()),
                    ("action".into(), SUBMIT_POLICY_ACTION.into()),
                ]),
            ),
            event(
                "routing",
                Some(format!("{operation_id}:policy")),
                ReceiptEventKind::RouteSelected,
                BTreeMap::from([
                    ("route".into(), "not_applicable".into()),
                    (
                        "reason".into(),
                        "routing not applicable to action instance admission".into(),
                    ),
                ]),
            ),
            event(
                "budget",
                Some(format!("{operation_id}:routing")),
                ReceiptEventKind::BudgetDecided,
                BTreeMap::from([
                    ("decision".into(), stored.budget_decision.clone()),
                    ("subject".into(), budget_subject.into()),
                ]),
            ),
        ];
        let mut outcome_parent = format!("{operation_id}:budget");
        if let Some(approval) = approval {
            let mut attributes = BTreeMap::from([
                ("decision".into(), approval.decision.to_string()),
                ("approver".into(), approval.decider.to_string()),
            ]);
            if !approval.reason.trim().is_empty() {
                attributes.insert("reason".into(), approval.reason.trim().to_string());
            }
            let mut decided = event(
                "approval",
                Some(outcome_parent.clone()),
                ReceiptEventKind::ApprovalDecided,
                attributes,
            );
            decided.actor = approval.decider.to_string();
            events.push(decided);
            outcome_parent = format!("{operation_id}:approval");
        }
        let completed_at_ms = if await_runtime_dispatch {
            None
        } else {
            events.push(event(
                "outcome",
                Some(outcome_parent),
                ReceiptEventKind::OutcomeRecorded,
                outcome_attributes,
            ));
            Some(now)
        };
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.clone(),
            parent_operation_id: None,
            namespace: stored.namespace.clone(),
            operation_class: "governed_action_instance".into(),
            initiating_actor: actor.to_string(),
            schema_version: "action-instance/v1".into(),
            policy_version: if policy_scope.is_empty() {
                "implicit-allow".into()
            } else {
                policy_scope.into()
            },
            // The submit time: a decision completes the receipt but does not
            // restart it. Equal to `now` on a fresh admit.
            started_at_ms: stored.created_at_ms,
            completed_at_ms,
            events,
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest,
            artifact: None,
        };
        self.db
            .put_operation_receipt(&receipt)
            .map_err(ActionInstanceAdmissionError::Internal)?;

        let mut evidence = HashMap::from([
            ("instance_id".into(), stored.instance_id.clone()),
            ("type_id".into(), stored.type_id.clone()),
            ("version".into(), stored.version.clone()),
            ("request_digest".into(), stored.request_digest.clone()),
            ("idempotency_key".into(), stored.idempotency_key.clone()),
            ("operation_id".into(), stored.operation_id.clone()),
            ("status".into(), stored.status.clone()),
            ("policy_decision".into(), stored.policy_decision.clone()),
            ("budget_decision".into(), stored.budget_decision.clone()),
            ("parameters_untrusted".into(), "true".into()),
        ]);
        if let Some(applied) = applied_object {
            evidence.insert("object_id".into(), applied.object_id.clone());
            evidence.insert("object_kind".into(), applied.object_kind.clone());
            evidence.insert("object_mutation".into(), applied.mutation.clone());
        }
        if !stored.deny_reason.is_empty() {
            evidence.insert("deny_reason".into(), stored.deny_reason.clone());
        }
        if let Some(approval) = approval {
            evidence.insert("approver".into(), approval.decider.to_string());
            evidence.insert("approval_decision".into(), approval.decision.to_string());
        }
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                actor: approval
                    .map_or(actor, |approval| approval.decider)
                    .to_string(),
                action: if approval.is_some() {
                    "decide_action_instance".into()
                } else {
                    "submit_action_instance".into()
                },
                reason: if stored.status == STATUS_PARKED {
                    "action_instance_parked".into()
                } else if stored.status == STATUS_ADMITTED {
                    "action_instance_admitted".into()
                } else if approval.is_some_and(|approval| approval.decision == DECISION_DENY) {
                    "action_instance_approver_denied".into()
                } else if stored.budget_decision == "budget_exceeded" {
                    "action_instance_budget_denied".into()
                } else {
                    "action_instance_policy_denied".into()
                },
                evidence,
                target_id: stored.instance_id.clone(),
                outcome: stored.status.clone(),
            })
            .map_err(ActionInstanceAdmissionError::Internal)?;

        if stored.status == STATUS_ADMITTED {
            if let Some(budget) = self.budget
                && !budget_already_reserved
            {
                budget.record(budget_subject, 1);
            }
            let effects = planned_effects.ok_or_else(|| {
                ActionInstanceAdmissionError::Internal("admitted instance effects missing".into())
            })?;
            self.db
                .put_action_effects(effects)
                .map_err(ActionInstanceAdmissionError::Internal)?;
            if let Some(applied) = applied_object {
                // #1115: the operation receipt above is already durable, so a
                // transient object-log failure here must not fail this
                // already-succeeded admission back to the caller — that was
                // the bug: this path used `?` while the replay catch-up path
                // (completed_replay) already treated the identical failure as
                // best-effort. Both now go through the same helper.
                catch_up_object_log(
                    operation_id,
                    &applied.object_id,
                    &applied.object_kind,
                    &applied.object,
                );
            }
        }
        Ok(())
    }
}

/// #1115: post-receipt object-log ingest is best-effort by design (ADR
/// 0081) — once the operation receipt is durable, a transient ingest
/// failure must never fail an already-succeeded admission back to the
/// caller. It must not go silent either: an operator or a dual-read
/// consumer has no other signal that this identity is missing from the
/// configured log until catch-up succeeds, so log one structured,
/// greppable event instead of swallowing the error outright.
fn catch_up_object_log(
    operation_id: &str,
    object_id: &str,
    object_kind: &str,
    object: &crate::domain::Object,
) {
    if let Err(error) = object_log::ensure_admitted_object_in_configured_log(object) {
        tracing::error!(
            operation_id = %operation_id,
            object_id = %object_id,
            object_kind = %object_kind,
            error = %error,
            "post-receipt object-log ingest failed; admission is durable but the \
             configured object log is missing this identity until catch-up succeeds"
        );
    }
}

fn object_for_admitted_instance(
    db: &RuntimeDb,
    instance: &ActionInstance,
) -> Result<Option<crate::domain::Object>, ActionInstanceAdmissionError> {
    let object_id = serde_json::from_str::<serde_json::Value>(&instance.parameters_json)
        .ok()
        .and_then(|value| {
            value
                .get("object_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    if object_id.trim().is_empty() {
        return Ok(None);
    }
    db.get_object(&object_id)
        .map_err(ActionInstanceAdmissionError::Internal)
}

/// Digest of the object named by `object_id` in the parameters, taken when an
/// instance parks. Any change to that object before a grant denies the
/// instance instead of applying against state the submitter never saw.
/// The `object_id` parameter an instance targets, or empty when it has none.
fn target_object_id(parameters_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()
        .and_then(|value| {
            value
                .get("object_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .filter(|object_id| !object_id.trim().is_empty())
        .unwrap_or_default()
}

fn target_object_digest(
    db: &RuntimeDb,
    parameters_json: &str,
) -> Result<String, ActionInstanceAdmissionError> {
    let object_id = target_object_id(parameters_json);
    if object_id.is_empty() {
        return Ok(String::new());
    }
    let object = db
        .get_object(&object_id)
        .map_err(ActionInstanceAdmissionError::Internal)?;
    crate::sekai::action_instance::object_state_digest(object.as_ref())
        .map_err(ActionInstanceAdmissionError::Internal)
}

fn load_criterion_object(
    db: &RuntimeDb,
    namespace: &str,
    type_def: &crate::sekai::governed_action_type::GovernedActionType,
    parameters_json: &str,
) -> Result<Option<crate::domain::Object>, ActionInstanceAdmissionError> {
    let needs_object = type_def
        .submission_criteria
        .iter()
        .any(|criterion| criterion.requires_object().unwrap_or(true));
    if !needs_object {
        return Ok(None);
    }
    let object_id = serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()
        .and_then(|value| {
            value
                .get("object_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    if object_id.trim().is_empty() {
        return Ok(None);
    }
    match db
        .get_object(&object_id)
        .map_err(ActionInstanceAdmissionError::Internal)?
    {
        Some(object) if object.namespace == namespace && object.kind == type_def.object_kind => {
            Ok(Some(object))
        }
        _ => Ok(None),
    }
}

fn map_object_mutation_error(error: ActionObjectMutationError) -> ActionInstanceAdmissionError {
    match error {
        ActionObjectMutationError::InvalidArgument(message) => {
            ActionInstanceAdmissionError::InvalidArgument(message)
        }
        ActionObjectMutationError::FailedPrecondition(message) => {
            ActionInstanceAdmissionError::FailedPrecondition(message)
        }
        ActionObjectMutationError::Internal(message) => {
            ActionInstanceAdmissionError::Internal(message)
        }
    }
}

fn require_value(name: &str, value: &str) -> Result<(), ActionInstanceAdmissionError> {
    if value.is_empty() {
        Err(ActionInstanceAdmissionError::InvalidArgument(format!(
            "{name} required"
        )))
    } else {
        Ok(())
    }
}

fn resolve_operation_id(request_id: &str) -> Result<String, ActionInstanceAdmissionError> {
    let request_id = request_id.trim();
    if request_id.is_empty() {
        return Ok(format!("op-gai-{}", uuid::Uuid::new_v4().simple()));
    }
    if request_id.chars().any(char::is_whitespace) {
        return Err(ActionInstanceAdmissionError::InvalidArgument(
            "request_id must not contain whitespace".into(),
        ));
    }
    Ok(request_id.to_string())
}

fn has_pending_runtime_dispatch(effects: Option<&[action_effect::ActionEffect]>) -> bool {
    effects.unwrap_or(&[]).iter().any(|effect| {
        effect.kind == crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH
            && effect.status == action_effect::EFFECT_STATUS_PENDING
    })
}

fn autonomous_envelope_id(
    request: &ActionInstanceAdmissionRequest,
) -> Result<String, ActionInstanceAdmissionError> {
    let explicit = request.autonomous_envelope_id.trim();
    let from_parameters = match serde_json::from_str::<serde_json::Value>(&request.parameters_json)
    {
        Ok(serde_json::Value::Object(map)) => map
            .get("autonomous_envelope_id")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string(),
        _ => String::new(),
    };
    if !explicit.is_empty() && !from_parameters.is_empty() && explicit != from_parameters {
        return Err(ActionInstanceAdmissionError::InvalidArgument(
            "autonomous_envelope_id conflict".into(),
        ));
    }
    Ok(if !explicit.is_empty() {
        explicit.to_string()
    } else {
        from_parameters
    })
}

fn parse_ontology_digest(raw: &str) -> Result<Option<String>, ActionInstanceAdmissionError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let Some(hex) = raw.strip_prefix("sha256:") else {
        return Err(ActionInstanceAdmissionError::InvalidArgument(
            "ontology_digest must be sha256:<64 lowercase hex chars>".into(),
        ));
    };
    if hex.len() != 64
        || hex.chars().any(|character| !character.is_ascii_hexdigit())
        || hex != hex.to_ascii_lowercase()
    {
        return Err(ActionInstanceAdmissionError::InvalidArgument(
            "ontology_digest must be sha256:<64 lowercase hex chars>".into(),
        ));
    }
    Ok(Some(raw.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::governed_action_type::{
        EFFECT_KIND_NOTIFY, EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType,
    };

    fn setup() -> RuntimeDb {
        let db = RuntimeDb::memory();
        db.put_governed_action_type(
            GovernedActionType {
                namespace: "acme".into(),
                type_id: "dispatch".into(),
                version: "1".into(),
                description: "dispatch work".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                object_kind: String::new(),
                object_mutation: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        db
    }

    const ONTOLOGY_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn request(parameters_json: &str) -> ActionInstanceAdmissionRequest {
        ActionInstanceAdmissionRequest {
            namespace: "acme".into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            parameters_json: parameters_json.into(),
            idempotency_key: "idem-1".into(),
            evidence_submission_ids: vec!["evidence-2".into(), "evidence-1".into()],
            request_id: String::new(),
            ontology_digest: String::new(),
            autonomous_envelope_id: String::new(),
            policy_context: PrincipalPolicyContext::default(),
            budget_already_reserved: false,
        }
    }

    #[test]
    fn admit_stamps_fill_provenance_for_a_bound_type() {
        let db = setup();
        let type_def = GovernedActionType {
            namespace: "acme".into(),
            type_id: "dispatch.bound".into(),
            version: "1".into(),
            description: "bound dispatch".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string","enum":["shikigami"]}},"required":["runtime"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
            system_one: Some(sekai_provider::system_one::SystemOneBind {
                model: "jev-1.13.0".into(),
                questions: vec![sekai_provider::system_one::SystemOneQuestionBind {
                    parameter: "runtime".into(),
                    question_type: "choice".into(),
                    instructions: "Which runtime".into(),
                    criteria: serde_json::json!({"shikigami": null}),
                }],
            }),
            enabled: true,
            ..Default::default()
        };
        db.put_governed_action_type(type_def.clone(), "operator", 2)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut bound_request = request(r#"{"runtime":"shikigami"}"#);
        bound_request.type_id = "dispatch.bound".into();
        bound_request.idempotency_key = "idem-bound".into();
        let admitted = admission.admit(bound_request, "alice", 10).unwrap();
        let expected = crate::chisei::system_one_action::fill_provenance_json(
            &type_def,
            r#"{"runtime":"shikigami"}"#,
        )
        .unwrap();
        assert_eq!(admitted.instance.system_one_fill_json, expected);
        assert!(!expected.is_empty());
        let stored = db
            .get_action_instance(&admitted.instance.instance_id)
            .unwrap()
            .expect("stored");
        assert_eq!(stored.system_one_fill_json, expected);
    }

    #[test]
    fn caller_request_id_and_ontology_digest_bind_the_receipt() {
        let db = setup();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut first = request(r#"{"runtime":"shikigami"}"#);
        first.request_id = "operation-delivery-exception".into();
        first.ontology_digest = ONTOLOGY_DIGEST.into();
        let admitted = admission.admit(first, "alice", 10).unwrap();
        assert_eq!(
            admitted.instance.operation_id,
            "operation-delivery-exception"
        );
        let receipt = db
            .get_operation_receipt("operation-delivery-exception")
            .unwrap()
            .expect("receipt");
        assert_eq!(receipt.ontology_digest.as_deref(), Some(ONTOLOGY_DIGEST));
        let completeness = receipt.completeness();
        assert!(
            !completeness.complete,
            "pending runtime_dispatch must leave the receipt open: {completeness:?}"
        );
        assert_eq!(receipt.completed_at_ms, None);
        assert!(receipt.uncovered_surfaces.is_empty());
        assert!(
            receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::RouteSelected)
        );
        assert!(
            !receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        );

        let mut replay = request(r#"{"runtime":"shikigami"}"#);
        replay.request_id = "operation-other".into();
        replay.ontology_digest = ONTOLOGY_DIGEST.into();
        let replayed = admission.admit(replay, "alice", 20).unwrap();
        assert!(replayed.replay);
        assert_eq!(
            replayed.instance.operation_id,
            "operation-delivery-exception"
        );

        let mut conflict = request(r#"{"runtime":"shikigami"}"#);
        conflict.idempotency_key = "idem-2".into();
        conflict.request_id = "operation-delivery-exception".into();
        let error = admission.admit(conflict, "alice", 30).unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::AlreadyExists(_)
        ));
    }

    #[test]
    fn autonomous_action_requires_a_live_envelope() {
        use crate::sekai::autonomous_envelope::{
            AutonomousEnvelope, AutonomousPins, ENVELOPE_CONTRACT, PROFILE_SIMULATE,
            PROFILE_VERSION, RECEIPT_CURRENT, STATUS_LIVE, admit_envelope, envelope_digest_for,
            stop_envelope,
        };
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};

        let db = setup();
        db.put_governed_action_type(
            GovernedActionType {
                namespace: "acme".into(),
                type_id: "autonomous.simulate".into(),
                version: "1".into(),
                description: "bounded autonomous simulate".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"},"autonomous_envelope_id":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                object_kind: String::new(),
                object_mutation: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut missing = request(r#"{"runtime":"shikigami"}"#);
        missing.type_id = "autonomous.simulate".into();
        missing.idempotency_key = "auto-missing".into();
        assert!(matches!(
            admission.admit(missing, "alice", 10),
            Err(ActionInstanceAdmissionError::FailedPrecondition(_))
        ));

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let digest = |tag: u8| format!("sha256:{tag:02x}{}", "ab".repeat(31));
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let mut envelope = AutonomousEnvelope {
            contract_version: ENVELOPE_CONTRACT.into(),
            envelope_id: "auto:sim".into(),
            namespace: "acme".into(),
            owner: "alice".into(),
            adapter_id: PROFILE_SIMULATE.into(),
            adapter_version: PROFILE_VERSION.into(),
            pins: AutonomousPins {
                state_digest: digest(1),
                policy_digest: digest(2),
                model_digest: digest(3),
                prompt_digest: digest(4),
                evidence_digest: digest(5),
                simulation_digest: digest(6),
                budget_digest: digest(7),
                lease_digest: digest(8),
            },
            signer_id: "signer:ops".into(),
            signer_digest: format!("sha256:{:x}", Sha256::digest(public_key)),
            public_key_hex: hex(&public_key),
            signature_hex: String::new(),
            envelope_digest: String::new(),
            receipt_digest: String::new(),
            receipt_status: RECEIPT_CURRENT.into(),
            status: STATUS_LIVE.into(),
            predecessor_id: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        };
        envelope.envelope_digest = envelope_digest_for(&envelope).unwrap();
        envelope.signature_hex = hex(&signing_key
            .sign(envelope.envelope_digest.as_bytes())
            .to_bytes());
        admit_envelope(&db, "alice", &envelope, 1_000).unwrap();

        let mut live = request(r#"{"runtime":"shikigami"}"#);
        live.type_id = "autonomous.simulate".into();
        live.idempotency_key = "auto-live".into();
        live.autonomous_envelope_id = "auto:sim".into();
        admission.admit(live.clone(), "alice", 20).unwrap();

        let mut other = live.clone();
        other.autonomous_envelope_id = "auto:other".into();
        assert!(matches!(
            admission.admit(other, "alice", 25),
            Err(ActionInstanceAdmissionError::AlreadyExists(_))
        ));

        // An approval-gated submit parks while the envelope is live...
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let mut gated = live.clone();
        gated.idempotency_key = "auto-gated".into();
        let parked = admission.admit(gated, "alice", 26).unwrap().instance;
        assert_eq!(parked.status, STATUS_PARKED);
        assert_eq!(parked.autonomous_envelope_id, "auto:sim");

        stop_envelope(&db, "alice", "acme", "auto:sim", 30).unwrap();
        let replayed = admission.admit(live, "alice", 40).unwrap();
        assert!(replayed.replay);

        // ...and an approval after the envelope stopped cannot resume it.
        let resumed = admission
            .decide(
                ActionInstanceDecisionRequest {
                    instance_id: parked.instance_id.clone(),
                    decision: DECISION_GRANT.into(),
                    reason: String::new(),
                    decider_principals: vec!["ops-admin".into()],
                    decider_is_namespace_admin: true,
                },
                "ops-admin",
                45,
            )
            .unwrap()
            .instance;
        assert_eq!(resumed.status, STATUS_DENIED);
        assert_eq!(resumed.deny_reason, "envelope_not_live_on_resume");

        let mut stopped = request(r#"{"runtime":"shikigami"}"#);
        stopped.type_id = "autonomous.simulate".into();
        stopped.idempotency_key = "auto-stopped".into();
        stopped.autonomous_envelope_id = "auto:sim".into();
        assert!(matches!(
            admission.admit(stopped, "alice", 50),
            Err(ActionInstanceAdmissionError::FailedPrecondition(_))
        ));
    }

    #[test]
    fn notify_only_admission_completes_the_receipt() {
        let db = setup();
        db.put_governed_action_type(
            GovernedActionType {
                namespace: "acme".into(),
                type_id: "notify".into(),
                version: "1".into(),
                description: "notify only".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"definition_digest":{"type":"string"}},"required":["definition_digest"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                object_kind: String::new(),
                object_mutation: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let admitted = admission
            .admit(
                ActionInstanceAdmissionRequest {
                    namespace: "acme".into(),
                    type_id: "notify".into(),
                    version: "1".into(),
                    parameters_json: r#"{"definition_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.into(),
                    idempotency_key: "notify-1".into(),
                    evidence_submission_ids: Vec::new(),
                    request_id: "operation-notify".into(),
                    ontology_digest: ONTOLOGY_DIGEST.into(),
                    autonomous_envelope_id: String::new(),
                    policy_context: PrincipalPolicyContext::default(),
                    budget_already_reserved: false,
                },
                "alice",
                10,
            )
            .unwrap();
        let receipt = db
            .get_operation_receipt(&admitted.instance.operation_id)
            .unwrap()
            .expect("receipt");
        let completeness = receipt.completeness();
        assert!(
            completeness.complete,
            "notify-only admission must complete: {completeness:?}"
        );
        assert_eq!(receipt.completed_at_ms, Some(10));
        assert!(
            receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        );
    }

    #[test]
    fn denied_dispatch_admission_completes_the_receipt() {
        let db = setup();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::Deny;
        db.upsert_action_policy(&policy).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut denied = request(r#"{"runtime":"shikigami"}"#);
        denied.request_id = "operation-denied".into();
        denied.ontology_digest = ONTOLOGY_DIGEST.into();
        let outcome = admission.admit(denied, "alice", 10).unwrap();
        assert_eq!(outcome.instance.status, STATUS_DENIED);
        let receipt = db
            .get_operation_receipt(&outcome.instance.operation_id)
            .unwrap()
            .expect("receipt");
        let completeness = receipt.completeness();
        assert!(
            completeness.complete,
            "denied dispatch admission must complete: {completeness:?}"
        );
        assert_eq!(receipt.completed_at_ms, Some(10));
        assert!(
            receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        );
    }

    #[test]
    fn invalid_ontology_digest_is_rejected_before_admit() {
        let db = setup();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut invalid = request(r#"{"runtime":"shikigami"}"#);
        invalid.ontology_digest = "sha256:ontology".into();
        let error = admission.admit(invalid, "alice", 10).unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::InvalidArgument(_)
        ));
        assert!(
            db.list_action_instances("acme", None, None, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn interface_owns_admission_receipt_audit_effects_and_replay() {
        let db = setup();
        let admission = ActionInstanceAdmission::new(&db, None);
        let first = admission
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 10)
            .unwrap();
        assert!(!first.replay);
        assert_eq!(first.instance.status, STATUS_ADMITTED);
        assert!(
            db.get_operation_receipt(&first.instance.operation_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            db.list_action_effects_for_instance(&first.instance.instance_id)
                .unwrap()
                .len(),
            1
        );
        let replay = admission
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 20)
            .unwrap();
        assert!(replay.replay);
        assert_eq!(replay.instance.instance_id, first.instance.instance_id);
    }

    #[test]
    fn interface_rejects_conflicting_replay_before_new_side_effects() {
        let db = setup();
        let admission = ActionInstanceAdmission::new(&db, None);
        admission
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 10)
            .unwrap();
        let error = admission
            .admit(request(r#"{"runtime":"other"}"#), "alice", 20)
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::AlreadyExists(_)
        ));
        assert_eq!(
            db.list_action_instances("acme", None, None, 10)
                .unwrap()
                .len(),
            1
        );
    }

    fn record_schema() -> &'static str {
        r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"title":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#
    }

    fn ensure_record_kind(db: &RuntimeDb) {
        db.upsert_object_type(&crate::sekai::schema::ObjectType {
            kind: "customer_record".into(),
            description: "Fixture customer record kind".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
    }

    fn record_type(mutation: &str) -> GovernedActionType {
        GovernedActionType {
            namespace: "acme".into(),
            type_id: format!("customer.record.{mutation}"),
            version: "1".into(),
            description: "create or update one customer record".into(),
            parameter_schema_json: record_schema().into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: "customer_record".into(),
            object_mutation: mutation.into(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            ..Default::default()
        }
    }

    fn record_request(type_id: &str, parameters_json: &str) -> ActionInstanceAdmissionRequest {
        ActionInstanceAdmissionRequest {
            namespace: "acme".into(),
            type_id: type_id.into(),
            version: "1".into(),
            parameters_json: parameters_json.into(),
            idempotency_key: "record-1".into(),
            evidence_submission_ids: Vec::new(),
            request_id: "operation-record".into(),
            ontology_digest: ONTOLOGY_DIGEST.into(),
            autonomous_envelope_id: String::new(),
            policy_context: PrincipalPolicyContext::default(),
            budget_already_reserved: false,
        }
    }

    #[test]
    fn submit_creates_one_admitted_record_and_binds_the_receipt() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let admitted = admission
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-1","name":"Acme","title":"first"}"#,
                ),
                "alice",
                10,
            )
            .unwrap();
        assert_eq!(admitted.instance.status, STATUS_ADMITTED);
        let stored = db.get_object("rec-1").unwrap().expect("created record");
        assert_eq!(stored.kind, "customer_record");
        assert_eq!(stored.namespace, "acme");
        assert_eq!(stored.name, "Acme");
        assert_eq!(
            stored.properties.get("title").map(String::as_str),
            Some("first")
        );
        let receipt = db
            .get_operation_receipt("operation-record")
            .unwrap()
            .expect("receipt");
        assert_eq!(receipt.ontology_digest.as_deref(), Some(ONTOLOGY_DIGEST));
        let intent = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .expect("intent");
        assert_eq!(
            intent.attributes.get("object_id").map(String::as_str),
            Some("rec-1")
        );
        assert_eq!(
            intent.attributes.get("object_kind").map(String::as_str),
            Some("customer_record")
        );
        assert!(!intent.attributes.values().any(|value| value == "first"));

        let replay = admission
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-1","name":"Acme","title":"first"}"#,
                ),
                "alice",
                20,
            )
            .unwrap();
        assert!(replay.replay);
        assert_eq!(replay.instance.instance_id, admitted.instance.instance_id);
        assert_eq!(db.get_object("rec-1").unwrap().unwrap().name, "Acme");
    }

    #[test]
    fn admitted_object_apply_ingests_and_denied_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        crate::sekai::object_log::with_test_log_path(&log, || {
            let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
            policy.default_decision = crate::sekai::action_policy::ActionDecision::Deny;
            db.upsert_action_policy(&policy).unwrap();
            let mut denied = record_request(
                "customer.record.create",
                r#"{"object_id":"rec-log","name":"Denied"}"#,
            );
            denied.idempotency_key = "record-denied-log".into();
            denied.request_id = "operation-denied-log".into();
            let denied = admission.admit(denied, "alice", 10).unwrap();
            assert_eq!(denied.instance.status, STATUS_DENIED);
            assert!(db.get_object("rec-log").unwrap().is_none());
            assert!(!log.exists(), "denied admit must not create an object log");

            policy.default_decision = crate::sekai::action_policy::ActionDecision::Allow;
            db.upsert_action_policy(&policy).unwrap();
            let mut admitted = record_request(
                "customer.record.create",
                r#"{"object_id":"rec-log","name":"Admitted","title":"live"}"#,
            );
            admitted.idempotency_key = "record-admitted-log".into();
            admitted.request_id = "operation-admitted-log".into();
            let admitted = admission.admit(admitted, "alice", 20).unwrap();
            assert_eq!(admitted.instance.status, STATUS_ADMITTED);
            assert!(db.get_object("rec-log").unwrap().is_some());
            let receipt = db
                .get_operation_receipt("operation-admitted-log")
                .unwrap()
                .expect("clerk receipt stays out of the object log");
            assert_eq!(receipt.ontology_digest.as_deref(), Some(ONTOLOGY_DIGEST));
            let store = mikura::Store::open(&log).unwrap();
            assert_eq!(
                crate::sekai::object_log::identity_generation(&store, "customer_record", "rec-log")
                    .unwrap(),
                1
            );
        });
    }

    #[test]
    fn failed_record_admission_does_not_ingest_so_retry_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        crate::sekai::object_log::with_test_log_path(&log, || {
            fail_next_record_admission();
            let mut request = record_request(
                "customer.record.create",
                r#"{"object_id":"rec-retry","name":"Retry"}"#,
            );
            request.idempotency_key = "record-retry-log".into();
            request.request_id = "operation-retry-log".into();
            assert!(admission.admit(request.clone(), "alice", 10).is_err());
            assert!(db.get_object("rec-retry").unwrap().is_none());
            assert!(
                db.get_operation_receipt("operation-retry-log")
                    .unwrap()
                    .is_none()
            );
            assert!(
                !log.exists(),
                "object-log ingest must wait for a durable admission receipt"
            );

            let admitted = admission.admit(request, "alice", 20).unwrap();
            assert_eq!(admitted.instance.status, STATUS_ADMITTED);
            assert!(db.get_object("rec-retry").unwrap().is_some());
            let store = mikura::Store::open(&log).unwrap();
            assert_eq!(
                crate::sekai::object_log::identity_generation(
                    &store,
                    "customer_record",
                    "rec-retry"
                )
                .unwrap(),
                1
            );
        });
    }

    #[test]
    fn ingest_failure_after_receipt_never_fails_the_admission_and_is_caught_up_on_replay() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        crate::sekai::object_log::with_test_log_path(&log, || {
            crate::sekai::object_log::fail_next_ingest();
            let mut request = record_request(
                "customer.record.create",
                r#"{"object_id":"rec-catchup","name":"Catchup"}"#,
            );
            request.idempotency_key = "record-catchup-log".into();
            request.request_id = "operation-catchup-log".into();
            // #1115: the receipt, object mutation, and effects are already
            // durable by the time ingest runs, so a transient ingest
            // failure must not fail this first, already-succeeded
            // admission back to the caller.
            let first = admission.admit(request.clone(), "alice", 10).unwrap();
            assert!(!first.replay);
            assert!(db.get_object("rec-catchup").unwrap().is_some());
            assert!(
                db.get_operation_receipt("operation-catchup-log")
                    .unwrap()
                    .is_some()
            );
            assert!(!log.exists());

            let replay = admission.admit(request, "alice", 20).unwrap();
            assert!(replay.replay);
            let store = mikura::Store::open(&log).unwrap();
            assert_eq!(
                crate::sekai::object_log::identity_generation(
                    &store,
                    "customer_record",
                    "rec-catchup"
                )
                .unwrap(),
                1
            );
        });
    }

    #[test]
    fn ingest_failure_after_receipt_logs_a_structured_catch_up_signal() {
        // #1115: swallowing the ingest error must not make the gap silent.
        // An operator or a dual-read consumer needs some other signal that
        // this identity is missing from the configured log until catch-up
        // succeeds; assert the structured log line actually fires with the
        // operation and object identity attached.
        use std::io::{self, Write};
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.0.lock().expect("log buffer").write(data)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);

        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();

        crate::sekai::object_log::with_test_log_path(&log, || {
            crate::sekai::object_log::fail_next_ingest();
            let mut request = record_request(
                "customer.record.create",
                r#"{"object_id":"rec-signal","name":"Signal"}"#,
            );
            request.idempotency_key = "record-signal-log".into();
            request.request_id = "operation-signal-log".into();
            tracing::subscriber::with_default(subscriber, || {
                admission.admit(request, "alice", 10).unwrap();
            });
        });

        let logs = String::from_utf8(buf.0.lock().expect("log buffer").clone()).expect("utf8 logs");
        assert!(
            logs.contains("post-receipt object-log ingest failed"),
            "{logs}"
        );
        assert!(logs.contains("operation-signal-log"), "{logs}");
        assert!(logs.contains("rec-signal"), "{logs}");
    }

    #[test]
    fn submit_updates_one_admitted_record() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        db.put_governed_action_type(record_type("update"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        admission
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-2","title":"first"}"#,
                ),
                "alice",
                10,
            )
            .unwrap();
        let mut update = record_request(
            "customer.record.update",
            r#"{"object_id":"rec-2","title":"second"}"#,
        );
        update.idempotency_key = "record-2".into();
        update.request_id = "operation-record-update".into();
        admission.admit(update, "alice", 20).unwrap();
        let stored = db.get_object("rec-2").unwrap().expect("updated record");
        assert_eq!(
            stored.properties.get("title").map(String::as_str),
            Some("second")
        );
        assert_eq!(stored.name, "rec-2");
    }

    #[test]
    fn missing_kind_fails_closed_before_a_success_receipt() {
        let db = setup();
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let error = admission
            .admit(
                record_request("customer.record.create", r#"{"object_id":"rec-3"}"#),
                "alice",
                10,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert!(db.get_object("rec-3").unwrap().is_none());
        assert!(
            db.get_operation_receipt("operation-record")
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_action_instances("acme", None, None, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn distinct_key_cannot_create_the_same_record_twice() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        admission
            .admit(
                record_request("customer.record.create", r#"{"object_id":"rec-5"}"#),
                "alice",
                10,
            )
            .unwrap();
        let mut second = record_request("customer.record.create", r#"{"object_id":"rec-5"}"#);
        second.idempotency_key = "record-5b".into();
        second.request_id = "operation-record-5b".into();
        let error = admission.admit(second, "alice", 20).unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert_eq!(
            db.list_action_instances("acme", None, None, 10)
                .unwrap()
                .len(),
            1
        );
    }

    fn approval_setup(mutation: &str, approvers: &[&str]) -> RuntimeDb {
        let db = setup();
        ensure_record_kind(&db);
        let mut type_def = record_type(mutation);
        type_def.approvers = approvers
            .iter()
            .map(|approver| approver.to_string())
            .collect();
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        db
    }

    fn decision(
        instance_id: &str,
        decision: &str,
        principal: &str,
    ) -> ActionInstanceDecisionRequest {
        ActionInstanceDecisionRequest {
            instance_id: instance_id.into(),
            decision: decision.into(),
            reason: "reviewed".into(),
            decider_principals: vec![principal.into()],
            decider_is_namespace_admin: false,
        }
    }

    #[test]
    fn require_approval_parks_and_an_approver_grant_resumes_the_same_instance() {
        let db = approval_setup("create", &["bob"]);
        let admission = ActionInstanceAdmission::new(&db, None);
        let request = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-9","title":"t"}"#,
        );
        let parked = admission
            .admit(request.clone(), "alice", 10)
            .unwrap()
            .instance;
        assert_eq!(parked.status, STATUS_PARKED);
        assert!(parked.deny_reason.is_empty());
        assert!(db.get_object("rec-9").unwrap().is_none());
        let open = db
            .get_operation_receipt("operation-record")
            .unwrap()
            .unwrap();
        assert_eq!(open.completed_at_ms, None, "a parked receipt stays open");

        // Replaying the submit returns the parked instance, never a second one.
        let replayed = admission.admit(request.clone(), "alice", 11).unwrap();
        assert!(replayed.replay);
        assert_eq!(replayed.instance.instance_id, parked.instance_id);

        let granted = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap();
        assert!(!granted.replay);
        assert_eq!(granted.instance.instance_id, parked.instance_id);
        assert_eq!(granted.instance.status, STATUS_ADMITTED);
        assert_eq!(granted.instance.decided_by, "bob");
        assert!(db.get_object("rec-9").unwrap().is_some());
        let receipt = db
            .get_operation_receipt("operation-record")
            .unwrap()
            .unwrap();
        assert!(receipt.completed_at_ms.is_some());
        assert!(receipt.events.iter().any(|event| {
            event.kind == ReceiptEventKind::ApprovalDecided && event.actor == "bob"
        }));
        assert!(
            receipt.completeness().complete,
            "{:?}",
            receipt.completeness()
        );

        // The same decision replays; a conflicting one fails.
        let again = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                30,
            )
            .unwrap();
        assert!(again.replay);
        assert!(matches!(
            admission.decide(
                decision(&parked.instance_id, DECISION_DENY, "bob"),
                "bob",
                31
            ),
            Err(ActionInstanceAdmissionError::FailedPrecondition(_))
        ));
        assert_eq!(
            db.list_action_instances("acme", None, None, 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn the_submitter_and_foreign_principals_cannot_decide() {
        let db = approval_setup("create", &["bob"]);
        let admission = ActionInstanceAdmission::new(&db, None);
        let parked = admission
            .admit(
                record_request("customer.record.create", r#"{"object_id":"rec-10"}"#),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        for (principal, instance_id) in [
            ("alice", parked.instance_id.as_str()),
            ("carol", parked.instance_id.as_str()),
            ("bob", "gai-unknown"),
        ] {
            let error = admission
                .decide(
                    decision(instance_id, DECISION_GRANT, principal),
                    principal,
                    20,
                )
                .unwrap_err();
            assert_eq!(
                error,
                ActionInstanceAdmissionError::PermissionDenied(DECISION_ACCESS_DENIED.into())
            );
        }
        // Even a namespace administrator cannot approve their own submit.
        let mut self_approval = decision(&parked.instance_id, DECISION_GRANT, "bob");
        self_approval.decider_principals = vec!["alice".into()];
        self_approval.decider_is_namespace_admin = true;
        assert!(matches!(
            admission.decide(self_approval, "alice", 21),
            Err(ActionInstanceAdmissionError::PermissionDenied(_))
        ));
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );
        assert!(db.get_object("rec-10").unwrap().is_none());
    }

    #[test]
    fn without_declared_approvers_only_a_namespace_admin_decides() {
        let db = approval_setup("create", &[]);
        let admission = ActionInstanceAdmission::new(&db, None);
        let parked = admission
            .admit(
                record_request("customer.record.create", r#"{"object_id":"rec-11"}"#),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        assert!(matches!(
            admission.decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20
            ),
            Err(ActionInstanceAdmissionError::PermissionDenied(_))
        ));
        let mut admin = decision(&parked.instance_id, DECISION_GRANT, "bob");
        admin.decider_is_namespace_admin = true;
        assert_eq!(
            admission.decide(admin, "bob", 21).unwrap().instance.status,
            STATUS_ADMITTED
        );
    }

    #[test]
    fn deny_is_terminal_and_a_replayed_submit_does_not_mint_a_second_instance() {
        let db = approval_setup("create", &["bob"]);
        let admission = ActionInstanceAdmission::new(&db, None);
        let request = record_request("customer.record.create", r#"{"object_id":"rec-12"}"#);
        let parked = admission
            .admit(request.clone(), "alice", 10)
            .unwrap()
            .instance;
        let denied = admission
            .decide(
                decision(&parked.instance_id, DECISION_DENY, "bob"),
                "bob",
                20,
            )
            .unwrap()
            .instance;
        assert_eq!(denied.status, STATUS_DENIED);
        assert_eq!(denied.deny_reason, "denied_by_approver");
        assert!(db.get_object("rec-12").unwrap().is_none());
        let replayed = admission.admit(request, "alice", 30).unwrap();
        assert!(replayed.replay);
        assert_eq!(replayed.instance.status, STATUS_DENIED);
        assert!(matches!(
            admission.decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                31
            ),
            Err(ActionInstanceAdmissionError::FailedPrecondition(_))
        ));
        assert_eq!(
            db.list_action_instances("acme", None, None, 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn an_unchanged_object_with_many_properties_grants_without_a_stale_denial() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        db.create_object(&crate::domain::Object {
            id: "rec-14".into(),
            kind: "customer_record".into(),
            name: "rec-14".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: ["title", "owner", "tier", "region", "segment", "note"]
                .into_iter()
                .map(|key| (key.to_string(), format!("{key}-value")))
                .collect(),
            created: 5,
            updated: 5,
        })
        .unwrap();
        let mut update_type = record_type("update");
        update_type.approvers = vec!["bob".into()];
        db.put_governed_action_type(update_type, "operator", 6)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let mut update = record_request(
            "customer.record.update",
            r#"{"object_id":"rec-14","title":"t2"}"#,
        );
        update.idempotency_key = "record-14-update".into();
        update.request_id = "operation-record-14-update".into();
        let parked = admission.admit(update, "alice", 10).unwrap().instance;
        for _ in 0..8 {
            assert_eq!(
                target_object_digest(&db, &parked.parameters_json).unwrap(),
                parked.parked_object_digest
            );
        }
        let granted = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap()
            .instance;
        assert_eq!(granted.status, STATUS_ADMITTED, "{}", granted.deny_reason);
    }

    /// Parks an update of `object_id` that bob may grant.
    fn parked_update(db: &RuntimeDb, object_id: &str) -> ActionInstance {
        ensure_record_kind(db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(db, None);
        admission
            .admit(
                record_request(
                    "customer.record.create",
                    &format!(r#"{{"object_id":"{object_id}","title":"v1"}}"#),
                ),
                "alice",
                5,
            )
            .unwrap();
        let mut update_type = record_type("update");
        update_type.approvers = vec!["bob".into(), "carol".into()];
        db.put_governed_action_type(update_type, "operator", 6)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let mut update = record_request(
            "customer.record.update",
            &format!(r#"{{"object_id":"{object_id}","title":"v2"}}"#),
        );
        update.idempotency_key = format!("{object_id}-update");
        update.request_id = format!("operation-{object_id}-update");
        let parked = admission.admit(update, "alice", 10).unwrap().instance;
        assert_eq!(parked.status, STATUS_PARKED);
        parked
    }

    fn change_count(db: &RuntimeDb, object_id: &str) -> usize {
        db.list_object_changes(object_id, 1000, 0).unwrap().len()
    }

    #[test]
    fn the_grant_transaction_writes_nothing_unless_the_transition_commits() {
        // #1139: the staleness check, object write, and parked-to-admitted
        // transition share one transaction.
        use crate::sekai::action_instance::{ParkedGrantOutcome, ParkedGrantWrite};
        let db = setup();
        let parked = parked_update(&db, "rec-21");
        let mut granted = parked.clone();
        granted.status = STATUS_ADMITTED.into();
        let mut planned = db.get_object("rec-21").unwrap().unwrap();
        planned.properties.insert("title".into(), "v2".into());
        planned.updated = 30;
        let write = ParkedGrantWrite::Update(planned);

        // Changed after the pre-check: the transaction re-digests and refuses.
        let mut changed = db.get_object("rec-21").unwrap().unwrap();
        changed
            .properties
            .insert("title".into(), "elsewhere".into());
        db.update_object(&changed).unwrap();
        assert!(matches!(
            db.grant_parked_action_instance(
                &granted,
                "rec-21",
                &parked.parked_object_digest,
                Some(&write),
                "alice",
            )
            .unwrap(),
            ParkedGrantOutcome::Stale
        ));
        let object = db.get_object("rec-21").unwrap().unwrap();
        assert_eq!(object.properties["title"], "elsewhere");
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );

        // Already decided elsewhere: no write lands.
        let current_digest =
            crate::sekai::action_instance::object_state_digest(Some(&object)).unwrap();
        let mut denied = parked.clone();
        denied.status = STATUS_DENIED.into();
        assert!(db.decide_parked_action_instance(&denied).unwrap());
        assert!(matches!(
            db.grant_parked_action_instance(
                &granted,
                "rec-21",
                &current_digest,
                Some(&write),
                "alice",
            )
            .unwrap(),
            ParkedGrantOutcome::NotParked
        ));
        assert_eq!(
            db.get_object("rec-21").unwrap().unwrap().properties["title"],
            "elsewhere"
        );
    }

    #[test]
    fn concurrent_grants_apply_the_object_write_exactly_once() {
        // Baseline: the audit rows one uncontended grant writes.
        let sequential = setup();
        let alone = parked_update(&sequential, "rec-22");
        let unchanged = change_count(&sequential, "rec-22");
        ActionInstanceAdmission::new(&sequential, None)
            .decide(
                decision(&alone.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap();
        let one_grant = change_count(&sequential, "rec-22") - unchanged;

        let db = std::sync::Arc::new(setup());
        let parked = parked_update(&db, "rec-22");
        let before = change_count(&db, "rec-22");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = ["bob", "carol"].map(|approver| {
            let db = db.clone();
            let barrier = barrier.clone();
            let instance_id = parked.instance_id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                ActionInstanceAdmission::new(&db, None)
                    .decide(
                        decision(&instance_id, DECISION_GRANT, approver),
                        approver,
                        20,
                    )
                    .unwrap()
            })
        });
        let outcomes = handles.map(|handle| handle.join().unwrap());
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.instance.status == STATUS_ADMITTED)
        );
        assert_eq!(outcomes.iter().filter(|outcome| !outcome.replay).count(), 1);
        // One write, and no compensating restore from a losing grant.
        assert_eq!(change_count(&db, "rec-22"), before + one_grant);
        assert_eq!(
            db.get_object("rec-22").unwrap().unwrap().properties["title"],
            "v2"
        );
    }

    #[test]
    fn a_grant_after_the_object_changed_fails_closed_without_writing() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        admission
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-13","title":"v1"}"#,
                ),
                "alice",
                5,
            )
            .unwrap();
        let mut update_type = record_type("update");
        update_type.approvers = vec!["bob".into()];
        db.put_governed_action_type(update_type, "operator", 6)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let mut update = record_request(
            "customer.record.update",
            r#"{"object_id":"rec-13","title":"v2"}"#,
        );
        update.idempotency_key = "record-13-update".into();
        update.request_id = "operation-record-13-update".into();
        let parked = admission.admit(update, "alice", 10).unwrap().instance;
        assert_eq!(parked.status, STATUS_PARKED);

        let mut changed = db.get_object("rec-13").unwrap().unwrap();
        changed
            .properties
            .insert("title".into(), "changed elsewhere".into());
        db.update_object(&changed).unwrap();

        let outcome = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap()
            .instance;
        assert_eq!(outcome.status, STATUS_DENIED);
        assert_eq!(outcome.deny_reason, "stale_on_resume");
        assert_eq!(
            db.get_object("rec-13")
                .unwrap()
                .unwrap()
                .properties
                .get("title")
                .map(String::as_str),
            Some("changed elsewhere")
        );
    }

    #[test]
    fn policy_deny_does_not_write_the_record() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::Deny;
        db.upsert_action_policy(&policy).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let outcome = admission
            .admit(
                record_request("customer.record.create", r#"{"object_id":"rec-4"}"#),
                "alice",
                10,
            )
            .unwrap();
        assert_eq!(outcome.instance.status, STATUS_DENIED);
        assert!(db.get_object("rec-4").unwrap().is_none());
        assert!(
            db.get_operation_receipt("operation-record")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn policy_deny_still_persists_when_the_record_already_exists() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        admission
            .admit(
                record_request("customer.record.create", r#"{"object_id":"rec-6"}"#),
                "alice",
                10,
            )
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::Deny;
        db.upsert_action_policy(&policy).unwrap();
        let mut denied = record_request("customer.record.create", r#"{"object_id":"rec-6"}"#);
        denied.idempotency_key = "record-6-deny".into();
        denied.request_id = "operation-record-6-deny".into();
        let outcome = admission.admit(denied, "alice", 20).unwrap();
        assert_eq!(outcome.instance.status, STATUS_DENIED);
        assert_eq!(
            db.get_object("rec-6").unwrap().unwrap().kind,
            "customer_record"
        );
    }

    #[test]
    fn incomplete_reservation_is_not_replayed_as_success() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let reserved = crate::sekai::action_instance::ActionInstance {
            autonomous_envelope_id: String::new(),
            parked_object_digest: String::new(),
            decided_by: String::new(),
            approval_decision: String::new(),
            instance_id: "gai-incomplete".into(),
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            principal: "alice".into(),
            parameters_json: r#"{"object_id":"rec-7"}"#.into(),
            request_digest: crate::sekai::action_instance::compute_request_digest(
                "acme",
                "customer.record.create",
                "1",
                r#"{"object_id":"rec-7"}"#,
                &[],
            )
            .unwrap(),
            idempotency_key: "record-7".into(),
            operation_id: "operation-record-7".into(),
            status: STATUS_ADMITTED.into(),
            deny_reason: String::new(),
            evidence_submission_ids: vec![],
            policy_decision: "allow".into(),
            budget_decision: "not_configured".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
            system_one_fill_json: String::new(),
        };
        db.put_action_instance(&reserved).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut retry = record_request("customer.record.create", r#"{"object_id":"rec-7"}"#);
        retry.idempotency_key = "record-7".into();
        retry.request_id = "operation-record-7".into();
        let error = admission.admit(retry, "alice", 20).unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert!(db.get_object("rec-7").unwrap().is_none());
    }

    #[test]
    fn submit_refuses_a_failing_criterion_with_the_preview_code() {
        let db = setup();
        ensure_record_kind(&db);
        let mut object = crate::domain::Object {
            id: "rec-8".into(),
            kind: "customer_record".into(),
            name: "Draft".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([("state".into(), "draft".into())]),
            created: 1,
            updated: 1,
        };
        db.create_object(&object).unwrap();
        let mut type_def = record_type("update");
        type_def.submission_criteria = vec![
            crate::sekai::action_type_criteria::ActionSubmissionCriterion {
                criterion_id: "ready_for_review".into(),
                kind: crate::sekai::action_type_criteria::CRITERION_KIND_PROPERTY_EQUALS.into(),
                property: "state".into(),
                value: "ready".into(),
            },
        ];
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let denied = admission
            .admit(
                record_request(
                    "customer.record.update",
                    r#"{"object_id":"rec-8","title":"still draft"}"#,
                ),
                "alice",
                10,
            )
            .unwrap();
        assert_eq!(denied.instance.status, STATUS_DENIED);
        assert_eq!(denied.instance.deny_reason, "ready_for_review");
        object.properties.insert("state".into(), "ready".into());
        db.update_object(&object).unwrap();
        let mut admitted = record_request(
            "customer.record.update",
            r#"{"object_id":"rec-8","title":"ready now"}"#,
        );
        admitted.idempotency_key = "record-8-ready".into();
        admitted.request_id = "operation-record-8-ready".into();
        let admitted = admission.admit(admitted, "alice", 20).unwrap();
        assert_eq!(admitted.instance.status, STATUS_ADMITTED);
    }
}

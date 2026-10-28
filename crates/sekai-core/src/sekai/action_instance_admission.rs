//! Governed `ActionInstance` admission behind one transport-neutral interface.
//!
//! Transport adapters authenticate the caller and enforce tenant context. This
//! module owns request validation, idempotent replay, type/policy/budget
//! decisions, receipt and audit creation, effect planning, and post-admission
//! metering so their ordering is exercised through the same interface callers
//! use.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action::RiskClass;
use crate::sekai::action_instance::{
    ActionInstance, ApprovalRequirement, DECISION_DENY, DECISION_GRANT, RULE_AGENT_PROPOSE_ONLY,
    STATUS_ADMITTED, STATUS_DENIED, STATUS_PARKED, SUBMIT_POLICY_ACTION,
    compute_request_digest_with_envelope, submit_budget_subject, validate_parameters_json,
};
use crate::sekai::action_object_mutation::{
    ActionObjectMutationError, AppliedObjectMutation, plan as plan_object_mutation,
};
use crate::sekai::action_ports::{ActionBudgetPort, ActionProposalPort};
use crate::sekai::action_type_criteria::{
    ActionSubmissionCriterion, CRITERION_UNAVAILABLE, CriterionDecision, SharingAnswer,
    evaluate_submission_criteria, invoker_context,
};
use crate::sekai::object_security::PrincipalPolicyContext;
use crate::sekai::{action_effect, action_object_mutation, action_policy, audit, object_log};
use sekai_domain::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[cfg(test)]
use std::cell::Cell;

/// Where a test simulates a crash: admission stops there with no cleanup,
/// as if the process died (#1931).
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    None,
    AfterReservation,
    AfterObjectWrite,
    /// After the receipt commits, before its follow-ups (#1943).
    AfterReceipt,
}

#[cfg(test)]
thread_local! {
    static CRASH_NEXT_ADMISSION: Cell<CrashPoint> = const { Cell::new(CrashPoint::None) };
    static FAIL_NEXT_RECORD_ADMISSION: Cell<bool> = const { Cell::new(false) };
    static TAKE_OVER_BEFORE_NEXT_RECEIPT: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub fn crash_next_admission(point: CrashPoint) {
    CRASH_NEXT_ADMISSION.with(|crash| crash.set(point));
}

#[cfg(test)]
fn crashes_at(point: CrashPoint) -> bool {
    CRASH_NEXT_ADMISSION.with(|crash| {
        let hit = crash.get() == point;
        if hit {
            crash.set(CrashPoint::None);
        }
        hit
    })
}

#[cfg(test)]
pub fn fail_next_record_admission() {
    FAIL_NEXT_RECORD_ADMISSION.with(|flag| flag.set(true));
}

/// Simulates a takeover between the next admission's object write and its
/// receipt: the reservation moves to a newer generation (#1930).
#[cfg(test)]
pub fn take_over_before_next_receipt() {
    TAKE_OVER_BEFORE_NEXT_RECEIPT.with(|flag| flag.set(true));
}

/// Receipt attribute naming the marking reading the receipt needs (#1706):
/// a governed Action's intent, and the Chisei receipts that project it.
pub const RECEIPT_MARKING_ATTRIBUTE: &str = "access_marking";

#[derive(Debug, Clone)]
pub struct ActionInstanceAdmissionRequest {
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
    pub delegating_actor: Option<String>,
    pub budget_already_reserved: bool,
    /// Shared-space owner tenant for freeze matching. Empty when the write
    /// is not through a named space.
    pub resource_tenant: String,
    /// Markings of the binding that submits (#1706); joined with the bound
    /// object's marking into the instance's. Empty for direct submits.
    pub binding_markings: Vec<String>,
    /// The object a binding submitted for, when its parameters need not
    /// name it; admission reads its marking (#1706). Empty otherwise.
    pub source_object_id: String,
    /// Whether the submitter is cleared for the instance's marking; the
    /// transport adapter supplies it, since it owns principal resolution.
    pub marking_gate: MarkingGate,
    /// What the device saw when it prepared this Action offline (#1580).
    /// The transport adapter fills the device id from the device-bound
    /// assertion after checking the device's proof.
    pub offline: Option<crate::sekai::offline_action::OfflineSubmission>,
    /// The target object's revision the caller checked (an executed plan
    /// step, #1679). Admission refuses unless the object it writes or parks
    /// against still has it, in the same read the write applies against.
    /// Empty checks nothing.
    pub expected_object_revision: String,
}

/// Clearance check admission runs against the marking it derives (#1706).
/// The default admits every marking, for internal admissions that act for
/// no caller (synthetic apply, workflows).
#[derive(Clone, Default)]
pub struct MarkingGate(Option<Arc<MarkingCheck>>);

type MarkingCheck = dyn Fn(&str) -> Result<bool, String> + Send + Sync;

impl MarkingGate {
    pub fn new(check: impl Fn(&str) -> Result<bool, String> + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(check)))
    }

    fn allows(&self, marking: &str) -> Result<bool, String> {
        match &self.0 {
            Some(check) if !marking.trim().is_empty() => check(marking),
            _ => Ok(true),
        }
    }
}

impl std::fmt::Debug for MarkingGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("MarkingGate")
            .field(&self.0.is_some())
            .finish()
    }
}

/// Grant or deny of a parked instance (#1084). The transport adapter
/// authenticates the decider and states which principals they present and
/// whether they administer the instance namespace.
#[derive(Debug, Clone)]
pub struct ActionInstanceDecisionRequest {
    pub instance_id: String,
    pub decision: String,
    pub reason: String,
    pub decider_principals: Vec<String>,
    pub decider_is_namespace_admin: bool,
    pub delegating_actor: Option<String>,
    /// Set when a plan execution grants its own step (#1679).
    pub execution_claim: Option<crate::sekai::action_instance::ExecutionClaim>,
}

/// One bounded answer for every refused or unknown decision target, so a
/// caller learns nothing about instances or types it may not decide.
pub const DECISION_ACCESS_DENIED: &str = "access denied";

/// A plan step's grant whose execution claim is gone; the run that took
/// over (or none, for a stopped plan) decides the step.
pub const PLAN_EXECUTION_CLAIM_LOST: &str = "plan execution claim lost";

#[derive(Debug, Clone)]
pub struct ActionInstanceAdmissionOutcome {
    pub instance: ActionInstance,
    pub replay: bool,
    /// The revision of the object this admission wrote; none on a replay or
    /// when nothing was written.
    pub object_revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionInstanceAdmissionError {
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

pub struct ActionInstanceAdmission<'a> {
    db: &'a RuntimeDb,
    budget: Option<&'a dyn ActionBudgetPort>,
    proposal: Option<&'a dyn ActionProposalPort>,
    tenant: &'a str,
    machine_credential: bool,
    budget_refused: bool,
}

impl<'a> ActionInstanceAdmission<'a> {
    pub fn new(db: &'a RuntimeDb, budget: Option<&'a dyn ActionBudgetPort>) -> Self {
        Self {
            db,
            budget,
            proposal: None,
            tenant: "",
            machine_credential: false,
            budget_refused: false,
        }
    }

    /// The budget was already refused, by a split-store reservation: record
    /// this admission as a budget denial, never admitted or parked, and charge
    /// nothing (#1871).
    pub fn with_budget_refused(mut self, budget_refused: bool) -> Self {
        self.budget_refused = budget_refused;
        self
    }

    pub fn with_proposal(mut self, proposal: Option<&'a dyn ActionProposalPort>) -> Self {
        self.proposal = proposal;
        self
    }

    pub fn with_tenant(mut self, tenant: &'a str) -> Self {
        self.tenant = tenant;
        self
    }

    pub fn with_machine_credential(mut self, machine_credential: bool) -> Self {
        self.machine_credential = machine_credential;
        self
    }

    /// The refusals [`Self::admit`] makes before it writes anything: missing
    /// or malformed request fields, an unknown or disabled type, and
    /// parameters its schema rejects. Reads only, so a caller that charges a
    /// budget before admitting runs this first and never charges a request
    /// that is refused anyway (#1864). Keep it in step with the start of
    /// `admit`.
    pub fn check_request(
        &self,
        request: &ActionInstanceAdmissionRequest,
    ) -> Result<(), ActionInstanceAdmissionError> {
        let namespace = request.namespace.trim();
        require_value("namespace", namespace)?;
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
        if request
            .evidence_submission_ids
            .iter()
            .any(|id| id.trim().is_empty())
        {
            return Err(ActionInstanceAdmissionError::InvalidArgument(
                "evidence_submission_ids must not contain empty ids".into(),
            ));
        }
        let type_def = self
            .db
            .require_enabled_governed_action_type(namespace, &request.type_id, &request.version)
            .map_err(|error| {
                if error.contains("unknown") || error.contains("disabled") {
                    ActionInstanceAdmissionError::FailedPrecondition(error)
                } else {
                    ActionInstanceAdmissionError::Internal(error)
                }
            })?;
        crate::sekai::parameter_schema::validate_parameter_schema(&type_def.parameter_schema_json)
            .map_err(|error| {
                ActionInstanceAdmissionError::FailedPrecondition(format!(
                    "governed action type parameter schema invalid: {error}"
                ))
            })?;
        crate::sekai::parameter_schema::validate_parameters(
            &type_def.parameter_schema_json,
            &request.parameters_json,
        )
        .map_err(|error| {
            ActionInstanceAdmissionError::InvalidArgument(format!(
                "action parameters invalid: {error}"
            ))
        })
    }

    pub fn admit(
        &self,
        request: ActionInstanceAdmissionRequest,
        actor: &str,
        now: i64,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let budget_already_reserved = request.budget_already_reserved;
        let expected_object_revision = request.expected_object_revision.clone();
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
        // An offline submission is part of what a retry must repeat exactly.
        let request_digest = match &request.offline {
            Some(offline) => offline_request_digest(&request_digest, offline)?,
            None => request_digest,
        };

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
            // An abandoned reservation (expired lease, no receipt) is taken
            // over before any gate: a landed write is finished as the original
            // submitter, and an empty one is released for a fresh, gated
            // admission (#1931).
            match self.take_over_abandoned(&existing)? {
                Abandoned::Live => return self.completed_replay(existing, now),
                Abandoned::Landed {
                    instance,
                    applied,
                    type_def,
                } => {
                    return self.repair_landed(*instance, *applied, &type_def, now);
                }
                Abandoned::Released => {}
            }
        }

        // The marking the instance will carry (#1706), derived here, the one
        // place it is authoritative, and the submitter must be cleared for
        // it before anything is reserved, charged or written.
        let marking = derive_instance_marking(
            self.db,
            &namespace,
            &request.parameters_json,
            &request.source_object_id,
            &request.binding_markings,
        )?;
        if !request
            .marking_gate
            .allows(&marking)
            .map_err(ActionInstanceAdmissionError::Internal)?
        {
            return Err(ActionInstanceAdmissionError::PermissionDenied(
                "access denied".into(),
            ));
        }

        let agent_action = crate::sekai::write_freeze::actor_is_agent(
            self.db,
            actor,
            request.delegating_actor.as_deref(),
            self.machine_credential,
        )
        .map_err(ActionInstanceAdmissionError::Internal)?;
        let tenant =
            crate::sekai::write_freeze::acting_or_registered_tenant(self.db, self.tenant, actor)
                .map_err(ActionInstanceAdmissionError::Internal)?;
        refuse_frozen(
            self.db,
            &crate::sekai::write_freeze::write_checks_for_actors(
                &namespace,
                tenant.as_ref(),
                actor,
                request.delegating_actor.as_deref(),
                request.type_id.trim(),
                agent_action,
            ),
        )?;
        if !request.resource_tenant.is_empty() && request.resource_tenant != tenant.as_ref() {
            refuse_frozen(
                self.db,
                &crate::sekai::write_freeze::write_checks_for_actors(
                    &namespace,
                    &request.resource_tenant,
                    actor,
                    request.delegating_actor.as_deref(),
                    request.type_id.trim(),
                    agent_action,
                ),
            )?;
        }

        // Propose-only keys off the actor principal. Freeze's agent_action also
        // matches machine credentials and delegating actors; those humans keep
        // Allow until the principal itself is an agent.
        let autonomy = if crate::sekai::agent_autonomy::actor_is_agent(self.db, actor) {
            Some(
                crate::sekai::agent_autonomy::evaluate_admission(
                    self.db,
                    actor,
                    &namespace,
                    &request.type_id,
                    &envelope_id,
                    now,
                )
                .map_err(ActionInstanceAdmissionError::Internal)?,
            )
        } else {
            None
        };
        let auto_apply_envelope = match &autonomy {
            Some(crate::sekai::agent_autonomy::AdmissionAutonomy::AutoApply { envelope_id }) => {
                envelope_id.clone()
            }
            _ => String::new(),
        };
        let consume_envelope = if envelope_id.is_empty() {
            auto_apply_envelope.as_str()
        } else {
            envelope_id.as_str()
        };
        // New admissions consume a live signed envelope. Replay of an already
        // admitted request stays idempotent after stop, rollback, lease loss,
        // or receipt invalidation. The envelope is not a runtime grant. An
        // auto-apply grant may supply the envelope for autonomous.* submits.
        if request.type_id.starts_with("autonomous.") || !consume_envelope.is_empty() {
            crate::sekai::autonomous_envelope::require_live_envelope(
                self.db,
                actor,
                &namespace,
                consume_envelope,
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
        crate::sekai::parameter_schema::validate_parameter_schema(&type_def.parameter_schema_json)
            .map_err(|error| {
                ActionInstanceAdmissionError::FailedPrecondition(format!(
                    "governed action type parameter schema invalid: {error}"
                ))
            })?;
        crate::sekai::parameter_schema::validate_parameters(
            &type_def.parameter_schema_json,
            &request.parameters_json,
        )
        .map_err(|error| {
            ActionInstanceAdmissionError::InvalidArgument(format!(
                "action parameters invalid: {error}"
            ))
        })?;
        let offline_touched = match &request.offline {
            Some(offline) => Some(validate_offline(
                &type_def,
                offline,
                &request.parameters_json,
                now,
            )?),
            None => None,
        };

        let criterion_object =
            load_criterion_object(self.db, &namespace, &type_def, &request.parameters_json)?;
        let criterion_policy = match &criterion_object {
            Some(object) => self
                .db
                .active_object_policy(&object.namespace, &object.kind)
                // A store failure, retryable; not a refused precondition.
                .map_err(|_| {
                    ActionInstanceAdmissionError::Internal("object policy unavailable".into())
                })?,
            None => None,
        };
        let invoker = invoker_context(actor, Some(&request.policy_context));
        let sharing_audit = SharingAudit {
            actor,
            namespace: &namespace,
            type_id: &type_def.type_id,
            now,
        };
        let criterion_decision = evaluate_submission_criteria(
            &type_def.submission_criteria,
            criterion_object.as_ref(),
            criterion_policy.as_ref(),
            &invoker,
            &|criterion| {
                resolve_sharing(
                    self.db,
                    tenant.as_ref(),
                    &request.parameters_json,
                    criterion,
                    Some(&sharing_audit),
                )
            },
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
        let (policy_decision, policy_rule, policy_scope_label) = match &resolved_policy {
            Some(policy) => {
                let (decision, rule) =
                    policy.decide_with_rule(SUBMIT_POLICY_ACTION, RiskClass::Write);
                (decision, rule.to_string(), policy.scope.clone())
            }
            None => (
                action_policy::ActionDecision::Allow,
                String::new(),
                String::new(),
            ),
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
        // A frozen site agent instance admits no new Action on its behalf
        // (#1934). The denial is recorded like any other, so it is audited.
        if status != STATUS_DENIED
            && let Some(instance_id) =
                crate::sekai::site_agent_instance::frozen_instance_for(self.db, &namespace, actor)
                    .map_err(ActionInstanceAdmissionError::Internal)?
        {
            status = STATUS_DENIED.into();
            deny_reason = format!("site agent instance {instance_id} is frozen");
        }

        let (budget_subject, budget_amount) = type_def
            .budget_charge(&namespace, actor, &request.parameters_json)
            .map_err(ActionInstanceAdmissionError::InvalidArgument)?;
        if status == STATUS_ADMITTED
            && let Some(budget) = self.budget
            && !budget_already_reserved
            && budget.check(&budget_subject, budget_amount).is_err()
        {
            status = STATUS_DENIED.into();
            deny_reason = format!("action budget exhausted for {budget_subject}");
            budget_decision = "budget_exceeded".into();
        }
        let mut parked_by_autonomy = false;
        match &autonomy {
            Some(crate::sekai::agent_autonomy::AdmissionAutonomy::AutoApply { .. })
                if status != STATUS_DENIED =>
            {
                if status == STATUS_PARKED {
                    status = STATUS_ADMITTED.into();
                    policy_decision_text = "auto_apply".into();
                    budget_decision = if self.budget.is_some() {
                        "allow".into()
                    } else {
                        "not_configured".into()
                    };
                } else if status == STATUS_ADMITTED {
                    policy_decision_text = "auto_apply".into();
                }
            }
            Some(crate::sekai::agent_autonomy::AdmissionAutonomy::ProposeOnly)
                if status == STATUS_ADMITTED =>
            {
                status = STATUS_PARKED.into();
                parked_by_autonomy = true;
                policy_decision_text = "require_approval".into();
                if !budget_already_reserved {
                    budget_decision = if self.budget.is_some() {
                        "allow".into()
                    } else {
                        "deferred".into()
                    };
                }
            }
            _ => {}
        }
        if status == STATUS_ADMITTED
            && let Some(budget) = self.budget
            && !budget_already_reserved
            && budget.check(&budget_subject, budget_amount).is_err()
        {
            status = STATUS_DENIED.into();
            deny_reason = format!("action budget exhausted for {budget_subject}");
            budget_decision = "budget_exceeded".into();
        }
        // Parking would let an approver grant work whose budget is gone.
        if self.budget_refused && status != STATUS_DENIED {
            status = STATUS_DENIED.into();
            parked_by_autonomy = false;
            deny_reason = format!("action budget exhausted for {budget_subject}");
            budget_decision = "budget_exceeded".into();
        }

        // Policy above was decided now, at arrival. An offline base that the
        // object has moved past is then judged by the type's conflict rule.
        let mut conflict = None;
        let mut offline_checked: Option<crate::domain::Object> = None;
        if let (Some(offline), Some(touched)) = (&request.offline, &offline_touched)
            && status != STATUS_DENIED
        {
            let current = load_offline_object(
                self.db,
                &namespace,
                &type_def.object_kind,
                &request.parameters_json,
            )?;
            conflict = offline.conflict(
                &type_def.offline_conflict,
                &type_def.last_writer_wins_properties,
                &current,
                touched,
            );
            if conflict.is_some() {
                status = STATUS_DENIED.into();
                deny_reason = crate::sekai::offline_action::CONFLICT_REASON.into();
            } else {
                offline_checked = Some(current);
            }
        }

        let system_one_fill_json = match self.proposal {
            Some(proposal) => proposal
                .fill_provenance_json(&type_def, &request.parameters_json)
                .map_err(ActionInstanceAdmissionError::InvalidArgument)?,
            None => String::new(),
        };
        let parked_object_digest = if status == STATUS_PARKED {
            match &offline_checked {
                // A parked offline Action is bound to the object version its
                // conflict check passed, not to a later read.
                Some(checked) => crate::sekai::action_instance::object_state_digest(Some(checked))
                    .map_err(ActionInstanceAdmissionError::Internal)?,
                None if !request.expected_object_revision.is_empty() => {
                    // The revision check and the parked digest read one object.
                    let object = target_object(self.db, &request.parameters_json)?;
                    if object
                        .as_ref()
                        .map(crate::sekai::action_describe_preview::object_revision)
                        != Some(request.expected_object_revision.clone())
                    {
                        return Err(object_changed());
                    }
                    crate::sekai::action_instance::object_state_digest(object.as_ref())
                        .map_err(ActionInstanceAdmissionError::Internal)?
                }
                None => target_object_digest(self.db, &request.parameters_json)?,
            }
        } else {
            String::new()
        };
        // This attempt's hold on the reservation: its object write, receipt,
        // and compensation are fenced on it (#1930).
        let lease = crate::sekai::action_instance::AdmissionLease::first();
        let instance = ActionInstance {
            instance_id: instance_id.clone(),
            namespace: namespace.clone(),
            type_id: request.type_id,
            version: request.version,
            principal: actor.to_string(),
            delegating_actor: request.delegating_actor,
            parameters_json: request.parameters_json.clone(),
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
            autonomous_envelope_id: if envelope_id.is_empty() {
                auto_apply_envelope
            } else {
                envelope_id.clone()
            },
            review: if status == STATUS_PARKED {
                crate::sekai::review_queue::place(
                    &type_def.review_queue,
                    &request.parameters_json,
                    now,
                    actor,
                    &type_def.approvers,
                )
            } else {
                Default::default()
            },
            agent_action,
            admission_tenant: tenant.as_ref().to_string(),
            resource_tenant: request.resource_tenant.clone(),
            marking,
            offline: request.offline.clone(),
            conflict,
            approval: (status == STATUS_PARKED).then(|| {
                if parked_by_autonomy {
                    ApprovalRequirement::new(
                        "",
                        RULE_AGENT_PROPOSE_ONLY.into(),
                        &type_def.approvers,
                    )
                } else {
                    ApprovalRequirement::new(&policy_scope_label, policy_rule, &type_def.approvers)
                }
            }),
            admission_lease: Some(lease.clone()),
            admission_ontology_digest: ontology_digest.clone(),
            admission_budget_already_reserved: budget_already_reserved,
        };
        let planned_effects = plan_admission_effects(&type_def, &instance, now)?;

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
            return self.completed_replay(stored, now);
        }

        #[cfg(test)]
        if crashes_at(CrashPoint::AfterReservation) {
            return Err(ActionInstanceAdmissionError::Internal(
                "injected crash".into(),
            ));
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
                Some(&stored.principal),
                Some(&stored.marking),
                now,
            ) {
                // The caller checked a revision: the write applies only over
                // the snapshot it is planned from, so compare that one.
                Ok(planned)
                    if !expected_object_revision.is_empty()
                        && !matches!(
                            &planned,
                            Some(action_object_mutation::PlannedObjectMutation::Update(_, snapshot))
                                if crate::sekai::action_describe_preview::object_revision(snapshot)
                                    == expected_object_revision
                        ) =>
                {
                    let _ = self
                        .db
                        .delete_action_instance_fenced(&stored.instance_id, &lease);
                    return Err(object_changed());
                }
                Ok(None) => None,
                // The conflict check passed against one version; a write
                // that landed since is judged afresh by a new submit.
                Ok(Some(action_object_mutation::PlannedObjectMutation::Update(_, snapshot)))
                    if offline_checked
                        .as_ref()
                        .is_some_and(|checked| !snapshot.persisted_state_matches(checked)) =>
                {
                    let _ = self
                        .db
                        .delete_action_instance_fenced(&stored.instance_id, &lease);
                    return Err(ActionInstanceAdmissionError::FailedPrecondition(
                        "the object changed while the offline Action was admitted; submit it again"
                            .into(),
                    ));
                }
                Ok(Some(planned)) => {
                    match action_object_mutation::apply(
                        self.db,
                        planned,
                        actor,
                        &crate::sekai::audit::ChangeAttribution::action(
                            &stored.instance_id,
                            &stored.operation_id,
                        ),
                        &stored.instance_id,
                        &lease,
                        now,
                    ) {
                        Ok(applied) => {
                            #[cfg(test)]
                            if crashes_at(CrashPoint::AfterObjectWrite) {
                                return Err(ActionInstanceAdmissionError::Internal(
                                    "injected crash".into(),
                                ));
                            }
                            Some(applied)
                        }
                        Err(error) => {
                            let _ = self
                                .db
                                .delete_action_instance_fenced(&stored.instance_id, &lease);
                            return Err(map_object_mutation_error(error));
                        }
                    }
                }
                Err(error) => {
                    let _ = self
                        .db
                        .delete_action_instance_fenced(&stored.instance_id, &lease);
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
            budget_amount,
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
            // Undo the object write and release the reservation in one fenced
            // transaction: only an owner that still holds it undoes, and a
            // crash leaves both or neither.
            if !receipt_exists {
                let undo = applied_object.as_ref().map_or(
                    crate::sekai::action_instance::AdmissionUndo::None,
                    action_object_mutation::admission_undo,
                );
                let _ = self
                    .db
                    .release_admission(&stored.instance_id, &lease, &undo, actor);
            }
            return Err(error);
        }
        if let Some(applied) = &applied_object {
            action_object_mutation::complete_object_write(self.db, &applied.object, actor, now);
        }
        Ok(ActionInstanceAdmissionOutcome {
            object_revision: applied_object.as_ref().map(|applied| {
                crate::sekai::action_describe_preview::object_revision(&applied.object)
            }),
            instance: stored,
            replay,
        })
    }

    /// Grants or denies a parked instance (#1084). Authorization comes first
    /// and answers every refusal the same way. A repeated decision replays;
    /// a conflicting one fails. A grant resumes admission against current
    /// state; anything that changed since the park denies the instance
    /// terminally instead of writing part of it.
    pub fn decide(
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
        let loaded = self
            .db
            .get_action_instance(request.instance_id.trim())
            .map_err(ActionInstanceAdmissionError::Internal)?
            .ok_or_else(access_denied)?;
        let _ = self.escalate_due(&loaded.namespace, now)?;
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
        if !may_decide(
            &type_def,
            &instance,
            decider,
            &request.decider_principals,
            request.decider_is_namespace_admin,
        ) {
            return Err(access_denied());
        }
        let latest = self
            .db
            .get_action_instance(&instance.instance_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .ok_or_else(access_denied)?;
        if latest.review.assignee != instance.review.assignee
            || latest.review.queue_id != instance.review.queue_id
        {
            return Err(access_denied());
        }
        let mut instance = self.finish_parked_submit(instance)?;
        instance.review = crate::sekai::review_queue::mark_decision(
            &type_def.review_queue,
            &instance.review,
            decider,
        );

        if instance.status != STATUS_PARKED {
            // A repeated decision replays and finishes any post-write
            // completion an interrupted grant skipped.
            return self.replay_decided(&instance.instance_id, decision, now);
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
        if crate::sekai::parameter_schema::validate_parameters(
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
                // A store failure, retryable; not a refused precondition.
                .map_err(|_| {
                    ActionInstanceAdmissionError::Internal("object policy unavailable".into())
                })?,
            None => None,
        };
        // Sharing is asked for the submitter's tenant, not the decider's.
        let sharing_audit = SharingAudit {
            actor: decider,
            namespace: &instance.namespace,
            type_id: &instance.type_id,
            now,
        };
        match evaluate_submission_criteria(
            &type_def.submission_criteria,
            criterion_object.as_ref(),
            criterion_policy.as_ref(),
            &invoker_context(&instance.principal, None),
            &|criterion| {
                resolve_sharing(
                    self.db,
                    &instance.admission_tenant,
                    &instance.parameters_json,
                    criterion,
                    Some(&sharing_audit),
                )
            },
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
        let submitter_tenant = crate::sekai::write_freeze::acting_or_registered_tenant(
            self.db,
            self.tenant,
            &instance.principal,
        )
        .map_err(ActionInstanceAdmissionError::Internal)?;
        let submitter_agent = instance.agent_action
            || crate::sekai::write_freeze::actor_is_agent(
                self.db,
                &instance.principal,
                instance.delegating_actor.as_deref(),
                false,
            )
            .map_err(ActionInstanceAdmissionError::Internal)?;
        let mut submitter_checks = crate::sekai::write_freeze::write_checks_for_actors(
            &instance.namespace,
            submitter_tenant.as_ref(),
            &instance.principal,
            instance.delegating_actor.as_deref(),
            instance.type_id.trim(),
            submitter_agent,
        );
        if !instance.admission_tenant.is_empty()
            && instance.admission_tenant != submitter_tenant.as_ref()
        {
            submitter_checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                &instance.namespace,
                &instance.admission_tenant,
                &instance.principal,
                instance.delegating_actor.as_deref(),
                instance.type_id.trim(),
                submitter_agent,
            ));
        }
        if !instance.resource_tenant.is_empty()
            && instance.resource_tenant != submitter_tenant.as_ref()
            && instance.resource_tenant != instance.admission_tenant
        {
            submitter_checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                &instance.namespace,
                &instance.resource_tenant,
                &instance.principal,
                instance.delegating_actor.as_deref(),
                instance.type_id.trim(),
                submitter_agent,
            ));
        }
        refuse_frozen(self.db, &submitter_checks)?;
        let decider_tenant =
            crate::sekai::write_freeze::acting_or_registered_tenant(self.db, self.tenant, decider)
                .map_err(ActionInstanceAdmissionError::Internal)?;
        let decider_agent = crate::sekai::write_freeze::actor_is_agent(
            self.db,
            decider,
            request.delegating_actor.as_deref(),
            self.machine_credential,
        )
        .map_err(ActionInstanceAdmissionError::Internal)?;
        let mut decider_checks = crate::sekai::write_freeze::write_checks_for_actors(
            &instance.namespace,
            decider_tenant.as_ref(),
            decider,
            request.delegating_actor.as_deref(),
            instance.type_id.trim(),
            decider_agent,
        );
        if !instance.resource_tenant.is_empty()
            && instance.resource_tenant != decider_tenant.as_ref()
        {
            decider_checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                &instance.namespace,
                &instance.resource_tenant,
                decider,
                request.delegating_actor.as_deref(),
                instance.type_id.trim(),
                decider_agent,
            ));
        }
        refuse_frozen(self.db, &decider_checks)?;
        let (budget_subject, budget_amount) = type_def
            .budget_charge(
                &instance.namespace,
                &instance.principal,
                &instance.parameters_json,
            )
            .map_err(ActionInstanceAdmissionError::InvalidArgument)?;

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
            Some(&instance.principal),
            Some(&instance.marking),
            now,
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
        expect_decision_follow_ups(&mut granted, instance.budget_decision != "deferred");
        // Do not re-check deferred budget here. Combined Split already reserved
        // before admit; production decide passes no budget port. A second check
        // would double-charge or deny reserved RequireApproval parks.
        // The object write and the parked-to-admitted transition commit
        // together, with the target re-digested under the same lock (#1139).
        let applied_object = match action_object_mutation::grant_parked(
            self.db,
            planned_object,
            &granted,
            &target_object_id(&instance.parameters_json),
            &instance.parked_object_digest,
            &instance.principal,
            request.execution_claim.as_ref(),
            now,
        )
        .map_err(map_object_mutation_error)?
        {
            action_object_mutation::ParkedGrant::Granted(applied) => {
                applied.map(|applied| *applied)
            }
            action_object_mutation::ParkedGrant::NotParked => {
                return self.replay_decided(&instance.instance_id, decision, now);
            }
            action_object_mutation::ParkedGrant::Stale => {
                return self.finish_denied(instance, "stale_on_resume", &approval, now);
            }
            action_object_mutation::ParkedGrant::ClaimLost => {
                return Err(ActionInstanceAdmissionError::FailedPrecondition(
                    PLAN_EXECUTION_CLAIM_LOST.into(),
                ));
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
            budget_amount,
            &granted.evidence_submission_ids,
            Some(&planned_effects),
            applied_object.as_ref(),
            ontology_digest,
            instance.budget_decision != "deferred",
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
        self.remember_decision(&granted, approval.reason)?;
        if let Some(applied) = &applied_object {
            action_object_mutation::complete_object_write(
                self.db,
                &applied.object,
                &instance.principal,
                now,
            );
        }
        Ok(ActionInstanceAdmissionOutcome {
            object_revision: applied_object.as_ref().map(|applied| {
                crate::sekai::action_describe_preview::object_revision(&applied.object)
            }),
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
        expect_decision_follow_ups(&mut denied, true);
        if !self
            .db
            .decide_parked_action_instance(&denied)
            .map_err(ActionInstanceAdmissionError::Internal)?
        {
            return self.replay_decided(&denied.instance_id, approval.decision, now);
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
            // A denial charges nothing.
            0,
            &denied.evidence_submission_ids,
            None,
            None,
            ontology_digest,
            false,
            Some(approval),
            now,
        )?;
        self.remember_decision(&denied, approval.reason)?;
        Ok(ActionInstanceAdmissionOutcome {
            object_revision: None,
            instance: denied,
            replay: false,
        })
    }

    fn remember_decision(
        &self,
        instance: &ActionInstance,
        reason: &str,
    ) -> Result<(), ActionInstanceAdmissionError> {
        let denied = instance.status == STATUS_DENIED;
        let memory = crate::sekai::decision_memory::DecisionMemory {
            memory_id: instance.instance_id.clone(),
            namespace: instance.namespace.clone(),
            type_id: instance.type_id.clone(),
            version: instance.version.clone(),
            instance_id: instance.instance_id.clone(),
            outcome: if denied {
                DECISION_DENY.into()
            } else {
                DECISION_GRANT.into()
            },
            reason: if denied && instance.deny_reason != "denied_by_approver" {
                instance.deny_reason.clone()
            } else {
                reason.to_string()
            },
            conditions_json: String::new(),
            facts_json: instance.parameters_json.clone(),
            decided_by: instance.decided_by.clone(),
            decided_at_ms: instance.decided_at_ms,
            superseded: false,
            parameters_json: instance.parameters_json.clone(),
        };
        self.db
            .put_decision_memory(&memory)
            .map_err(ActionInstanceAdmissionError::Internal)
    }

    /// Applies due review-queue SLA actions: reassign or auto-deny (#1455).
    pub fn escalate_due(
        &self,
        namespace: &str,
        now: i64,
    ) -> Result<(usize, usize), ActionInstanceAdmissionError> {
        let mut reassigned = 0;
        let mut denied = 0;
        loop {
            let mut progressed = false;
            let mut offset = 0;
            loop {
                let parked = self
                    .db
                    .list_action_instances_page(namespace, None, Some(STATUS_PARKED), 100, offset)
                    .map_err(ActionInstanceAdmissionError::Internal)?;
                let exhausted = parked.len() < 100;
                offset += parked.len();
                for instance in parked {
                    // An instance whose submit cannot finish yet is left
                    // parked; the next sweep or a decision retries it.
                    let Ok(instance) = self.finish_parked_submit(instance) else {
                        continue;
                    };
                    let Some(type_def) = self
                        .db
                        .get_governed_action_type(
                            &instance.namespace,
                            &instance.type_id,
                            &instance.version,
                        )
                        .map_err(ActionInstanceAdmissionError::Internal)?
                    else {
                        continue;
                    };
                    match crate::sekai::review_queue::escalate(
                        &type_def.review_queue,
                        &instance.review,
                        now,
                    ) {
                        crate::sekai::review_queue::Escalation::None => {}
                        crate::sekai::review_queue::Escalation::Reassign { assignee } => {
                            if assignee == instance.principal {
                                let mut next = instance;
                                next.review.escalated = true;
                                let approval = ApprovalRecord {
                                    decider: "review.queue",
                                    decision: DECISION_DENY,
                                    reason: "sla",
                                };
                                self.finish_denied(next, "review_sla_expired", &approval, now)?;
                                denied += 1;
                                progressed = true;
                                continue;
                            }
                            let expected_assignee = instance.review.assignee.clone();
                            let mut next = instance;
                            next.review =
                                crate::sekai::review_queue::apply_reassign(&next.review, &assignee);
                            if self
                                .db
                                .update_parked_action_instance(&next, &expected_assignee)
                                .map_err(ActionInstanceAdmissionError::Internal)?
                            {
                                reassigned += 1;
                                progressed = true;
                            }
                        }
                        crate::sekai::review_queue::Escalation::AutoDeny => {
                            let mut next = instance;
                            next.review.escalated = true;
                            let approval = ApprovalRecord {
                                decider: "review.queue",
                                decision: DECISION_DENY,
                                reason: "sla",
                            };
                            self.finish_denied(next, "review_sla_expired", &approval, now)?;
                            denied += 1;
                            progressed = true;
                        }
                    }
                }
                if exhausted {
                    break;
                }
            }
            if !progressed {
                break;
            }
        }
        Ok((reassigned, denied))
    }

    fn replay_decided(
        &self,
        instance_id: &str,
        decision: &str,
        now: i64,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let current = self
            .db
            .get_action_instance(instance_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .ok_or_else(|| {
                ActionInstanceAdmissionError::Internal("decided instance vanished".into())
            })?;
        if current.approval_decision == decision {
            self.resume_decision_follow_ups(&current)?;
            if current.status == STATUS_ADMITTED
                && let Some(object) = object_for_admitted_instance(self.db, &current)?
            {
                action_object_mutation::complete_object_write(
                    self.db,
                    &object,
                    &current.principal,
                    now,
                );
            }
            let remembered = self
                .db
                .get_decision_memory(&current.instance_id)
                .map_err(ActionInstanceAdmissionError::Internal)?;
            if remembered.is_none() {
                let reason = self
                    .db
                    .get_operation_receipt(&current.operation_id)
                    .map_err(ActionInstanceAdmissionError::Internal)?
                    .and_then(|receipt| {
                        receipt.events.iter().rev().find_map(|event| {
                            (event.kind == ReceiptEventKind::ApprovalDecided)
                                .then(|| event.attributes.get("reason").cloned())
                                .flatten()
                        })
                    })
                    .unwrap_or_default();
                self.remember_decision(&current, &reason)?;
            }
            if current.status == STATUS_DENIED {
                crate::sekai::agent_autonomy::revoke_if_granted(
                    self.db,
                    &current.decided_by,
                    &current.namespace,
                    &current.principal,
                    &current.type_id,
                    now,
                )
                .map_err(ActionInstanceAdmissionError::Internal)?;
            }
            Ok(ActionInstanceAdmissionOutcome {
                object_revision: None,
                instance: current,
                replay: true,
            })
        } else {
            Err(ActionInstanceAdmissionError::FailedPrecondition(
                "action instance is not awaiting a decision".into(),
            ))
        }
    }

    /// Takes over a reservation whose admission was abandoned (#1931): no
    /// receipt and an expired lease. A live admission, a legacy row without a
    /// lease, or a lost takeover race stays [`Abandoned::Live`]. After a
    /// takeover, a write the abandoned admission landed is reported for
    /// repair; otherwise the reservation is released.
    fn take_over_abandoned(
        &self,
        stored: &ActionInstance,
    ) -> Result<Abandoned, ActionInstanceAdmissionError> {
        let internal = ActionInstanceAdmissionError::Internal;
        // A lease without markers was written by an older binary: its writes
        // left no evidence, so it is never taken over.
        let Some(expired) = stored.admission_lease.as_ref().filter(|lease| {
            lease.expired() && lease.write_committed.is_some() && lease.receipt_recorded.is_some()
        }) else {
            return Ok(Abandoned::Live);
        };
        if self
            .db
            .get_operation_receipt(&stored.operation_id)
            .map_err(internal)?
            .is_some()
        {
            return Ok(Abandoned::Live);
        }
        let next = expired.succeeding();
        if !self
            .db
            .take_over_admission(stored, expired, &next)
            .map_err(internal)?
        {
            return Ok(Abandoned::Live);
        }
        let mut taken = stored.clone();
        taken.admission_lease = Some(next.clone());
        // The marker the fenced write set with the object write tells
        // whether it committed, whatever happened to the object since.
        if expired.write_committed == Some(true) {
            // The type as it was bound, enabled or not: finishing a landed
            // write authorizes nothing new.
            let type_def = self
                .db
                .get_governed_action_type(&stored.namespace, &stored.type_id, &stored.version)
                .map_err(internal)?
                .ok_or_else(|| internal("action type of an abandoned admission is gone".into()))?;
            // The current object is the committed write only while it keeps
            // that write's kind and revision; a later edit or a replacement
            // under the same id is not attributed to this admission.
            let applied = match object_for_admitted_instance(self.db, stored)? {
                Some(object)
                    if object.kind == type_def.object_kind
                        && expired.written_object_digest.as_deref()
                            == crate::sekai::action_instance::object_state_digest(Some(
                                &object,
                            ))
                            .ok()
                            .as_deref() =>
                {
                    AppliedObjectMutation::recovered(object, &type_def.object_mutation)
                }
                _ => AppliedObjectMutation::recovered_deleted(
                    &admitted_object_id(stored),
                    &type_def.object_kind,
                    &type_def.object_mutation,
                ),
            };
            return Ok(Abandoned::Landed {
                applied: Box::new(applied),
                instance: Box::new(taken),
                type_def: Box::new(type_def),
            });
        }
        if self
            .db
            .release_admission(
                &stored.instance_id,
                &next,
                &crate::sekai::action_instance::AdmissionUndo::None,
                &stored.principal,
            )
            .map_err(internal)?
        {
            Ok(Abandoned::Released)
        } else {
            Ok(Abandoned::Live)
        }
    }

    /// Records the receipt of an abandoned admission whose write landed, as
    /// its original submitter: policy scope and budget are the stored
    /// instance's, as on an approver's decision. The write is not repeated. A
    /// failure keeps the reservation for the next takeover.
    fn repair_landed(
        &self,
        instance: ActionInstance,
        applied: AppliedObjectMutation,
        type_def: &crate::sekai::governed_action_type::GovernedActionType,
        now: i64,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let policy_project = if type_def.policy_scope.trim().is_empty() {
            instance.namespace.clone()
        } else {
            type_def.policy_scope.clone()
        };
        let policy_scope_label = self
            .db
            .resolve_action_policy(&instance.principal, &instance.namespace, &policy_project)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .map(|policy| policy.scope)
            .unwrap_or_default();
        let (budget_subject, budget_amount) = type_def
            .budget_charge(
                &instance.namespace,
                &instance.principal,
                &instance.parameters_json,
            )
            .map_err(ActionInstanceAdmissionError::InvalidArgument)?;
        let effects = plan_admission_effects(type_def, &instance, now)?;
        self.record_admission(
            &instance,
            &instance.principal,
            &policy_scope_label,
            &budget_subject,
            budget_amount,
            &instance.evidence_submission_ids,
            effects.as_deref(),
            Some(&applied),
            instance.admission_ontology_digest.clone(),
            instance.admission_budget_already_reserved,
            None,
            now,
        )?;
        if applied.object_present {
            action_object_mutation::complete_object_write(
                self.db,
                &applied.object,
                &instance.principal,
                now,
            );
        }
        Ok(ActionInstanceAdmissionOutcome {
            object_revision: applied
                .object_present
                .then(|| crate::sekai::action_describe_preview::object_revision(&applied.object)),
            instance,
            replay: true,
        })
    }

    fn completed_replay(
        &self,
        existing: ActionInstance,
        now: i64,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let Some(receipt) = self
            .db
            .get_operation_receipt(&existing.operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
        else {
            return Err(ActionInstanceAdmissionError::FailedPrecondition(
                "action instance admission is still in progress".into(),
            ));
        };
        if existing
            .admission_lease
            .as_ref()
            .is_some_and(|lease| lease.follow_ups_recorded == Some(false))
        {
            self.resume_follow_ups(&existing, &receipt)?;
        }
        self.resume_decision_follow_ups(&existing)?;
        if existing.status == STATUS_ADMITTED
            && let Some(object) = object_for_admitted_instance(self.db, &existing)?
        {
            // Clerk admission is already durable. Log catch-up is best-effort so
            // a transient object-log error cannot fail an idempotent replay.
            catch_up_object_log(&existing.operation_id, &object.id, &object.kind, &object);
            action_object_mutation::complete_object_write(
                self.db,
                &object,
                &existing.principal,
                now,
            );
        }
        Ok(ActionInstanceAdmissionOutcome {
            object_revision: None,
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
        budget_amount: i32,
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
        if let Some(actor) = stored.delegating_actor.as_ref() {
            intent_attributes.insert("act".into(), actor.clone());
        }
        if !evidence_ids.is_empty() {
            intent_attributes.insert("evidence_submission_ids".into(), evidence_ids.join(","));
        }
        // The receipt carries the instance's marking, so reading it needs the
        // same clearance as reading the instance (#1706).
        if !stored.marking.is_empty() {
            intent_attributes.insert(RECEIPT_MARKING_ATTRIBUTE.into(), stored.marking.clone());
        }
        // Offline provenance (#1580): when and on which device it was
        // prepared, under which lease, and any conflict it met.
        if let Some(offline) = &stored.offline {
            intent_attributes.insert("offline".into(), "true".into());
            intent_attributes.insert(
                "offline_prepared_at_ms".into(),
                offline.prepared_at_ms.to_string(),
            );
            intent_attributes.insert(
                "offline_base_updated_ms".into(),
                offline.base_updated_ms.to_string(),
            );
            intent_attributes.insert("offline_device_id".into(), offline.device_id.clone());
            if !offline.lease_id.is_empty() {
                intent_attributes.insert("offline_lease_id".into(), offline.lease_id.clone());
            }
        }
        if let Some(conflict) = &stored.conflict {
            intent_attributes.insert(
                "offline_conflict_current_updated_ms".into(),
                conflict.current_updated_ms.to_string(),
            );
            intent_attributes.insert(
                "offline_conflict_properties".into(),
                conflict.properties.join(","),
            );
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
        let mut policy_attributes = BTreeMap::from([
            ("decision".into(), stored.policy_decision.clone()),
            ("action".into(), SUBMIT_POLICY_ACTION.into()),
        ]);
        // A parked instance names what parked it and who may decide (#1867).
        if let Some(approval) = &stored.approval {
            for (key, value) in approval_attributes(approval) {
                policy_attributes.insert(key.into(), value);
            }
        }
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
                policy_attributes,
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
            if !stored.review.queue_id.is_empty() {
                attributes.insert("queue_id".into(), stored.review.queue_id.clone());
            }
            if stored.review.agent_decision {
                attributes.insert("agent_decision".into(), "true".into());
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
        #[cfg(test)]
        if TAKE_OVER_BEFORE_NEXT_RECEIPT.with(|flag| flag.replace(false))
            && let Some(mut taken) = self
                .db
                .get_action_instance(&stored.instance_id)
                .map_err(ActionInstanceAdmissionError::Internal)?
            && let Some(lease) = taken.admission_lease.as_mut()
        {
            lease.owner = "recovering-owner".into();
            lease.generation += 1;
            self.db
                .delete_action_instance(&stored.instance_id)
                .and_then(|()| self.db.put_action_instance(&taken).map(|_| ()))
                .map_err(ActionInstanceAdmissionError::Internal)?;
        }
        // The admission receipt is fenced on the reservation's lease; a
        // decision on a parked instance records its receipt unfenced.
        match (approval, stored.admission_lease.as_ref()) {
            (None, Some(lease)) => {
                if !self
                    .db
                    .put_admission_receipt(&stored.instance_id, lease, &receipt)
                    .map_err(ActionInstanceAdmissionError::Internal)?
                {
                    return Err(ActionInstanceAdmissionError::FailedPrecondition(
                        crate::sekai::action_instance::ADMISSION_FENCE_LOST.into(),
                    ));
                }
            }
            _ => self
                .db
                .put_operation_receipt(&receipt)
                .map_err(ActionInstanceAdmissionError::Internal)?,
        }

        #[cfg(test)]
        if crashes_at(CrashPoint::AfterReceipt) {
            return Err(ActionInstanceAdmissionError::Internal(
                "injected crash after the receipt".into(),
            ));
        }
        let decision = admission_decision(
            stored,
            actor,
            applied_object.map(|applied| AdmittedObject {
                id: &applied.object_id,
                kind: &applied.object_kind,
                mutation: &applied.mutation,
            }),
            approval,
            now,
        );
        self.finish_admission(
            stored,
            &decision,
            budget_subject,
            budget_amount,
            budget_already_reserved,
            planned_effects,
            approval.is_some(),
        )?;
        if stored.status == STATUS_ADMITTED
            && let Some(applied) = applied_object.filter(|applied| applied.object_present)
        {
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
        Ok(())
    }

    /// Records what follows a receipt: the decision record, the budget
    /// charge, the planned effects, and for a denied submit the autonomy
    /// grant's revocation (#1943). Each step is idempotent: the
    /// decision and effect ids and the budget key derive from the operation.
    /// So a replay that finds the receipt can finish them, and a concurrent
    /// finisher changes nothing. Once an admission's follow-ups are all
    /// recorded, its lease says so.
    #[allow(clippy::too_many_arguments)]
    fn finish_admission(
        &self,
        stored: &ActionInstance,
        decision: &audit::Decision,
        budget_subject: &str,
        budget_amount: i32,
        budget_already_reserved: bool,
        planned_effects: Option<&[action_effect::ActionEffect]>,
        approver_decision: bool,
    ) -> Result<(), ActionInstanceAdmissionError> {
        let internal = ActionInstanceAdmissionError::Internal;
        if let Err(error) = self
            .db
            .record_decisions_idempotently(std::slice::from_ref(decision))
        {
            // A concurrent finisher may have inserted the same record first.
            if self
                .db
                .get_decision(&decision.id)
                .map_err(internal)?
                .as_ref()
                != Some(decision)
            {
                return Err(internal(error));
            }
        }
        // A charge is owed when the admission's budget decision allowed it.
        // Without the port that allowed it, the charge stays outstanding.
        if !budget_already_reserved
            && stored.budget_decision == "allow"
            && (stored.status == STATUS_ADMITTED || stored.status == STATUS_PARKED)
        {
            let step = if approver_decision {
                "decide"
            } else {
                "submit"
            };
            let charged = self
                .budget
                .ok_or_else(|| {
                    "the budget port that allowed this admission is not configured".to_string()
                })
                .and_then(|budget| {
                    budget.record_once(
                        budget_subject,
                        budget_amount,
                        &format!("{}:budget:{step}", stored.operation_id),
                        decision.timestamp,
                    )
                });
            // The charge stays outstanding for the resume (#1943, #1948). A
            // decision on a legacy reservation is never resumed, so it keeps
            // its earlier behaviour: the grant stands and the failure is
            // logged.
            let resumable = !approver_decision
                || stored
                    .admission_lease
                    .as_ref()
                    .is_some_and(|lease| lease.decision_follow_ups_recorded.is_some());
            match charged {
                Ok(()) => {}
                Err(error) if resumable => return Err(internal(error)),
                Err(error) => tracing::error!(
                    operation_id = %stored.operation_id,
                    error = %error,
                    "approval budget charge failed; the grant stands without it"
                ),
            }
        }
        if stored.status == STATUS_ADMITTED {
            let effects = planned_effects
                .ok_or_else(|| internal("admitted instance effects missing".into()))?;
            self.db
                .put_missing_action_effects(effects)
                .map_err(internal)?;
        }
        // A denial withdraws the principal's autonomy grant, as it stood
        // when denied.
        if stored.status == STATUS_DENIED {
            crate::sekai::agent_autonomy::revoke_if_granted_before(
                self.db,
                &decision.actor,
                &stored.namespace,
                &stored.principal,
                &stored.type_id,
                decision.timestamp,
                decision.timestamp,
            )
            .map_err(internal)?;
        }
        if approver_decision {
            self.db
                .mark_decision_follow_ups_recorded(&stored.instance_id)
        } else {
            self.db
                .mark_admission_follow_ups_recorded(&stored.instance_id)
        }
        .map_err(internal)
    }

    /// Finishes a parked submit's outstanding follow-ups before anything
    /// changes the instance or its receipt, which they are rebuilt from
    /// (#1943). Answers the instance with its marker set, so writing it back
    /// keeps the marker.
    fn finish_parked_submit(
        &self,
        mut instance: ActionInstance,
    ) -> Result<ActionInstance, ActionInstanceAdmissionError> {
        let Some(lease) = instance
            .admission_lease
            .as_mut()
            .filter(|lease| lease.follow_ups_recorded == Some(false))
        else {
            return Ok(instance);
        };
        lease.follow_ups_recorded = Some(true);
        let receipt = self
            .db
            .get_operation_receipt(&instance.operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .ok_or_else(|| {
                ActionInstanceAdmissionError::FailedPrecondition(
                    "action instance admission is still in progress".into(),
                )
            })?;
        self.resume_follow_ups(&instance, &receipt)?;
        Ok(instance)
    }

    /// Finishes the follow-ups of an admission whose receipt is recorded but
    /// whose lease does not say they are (#1943): a crash or failure after
    /// the receipt. It rebuilds them from the stored instance and its
    /// receipt, at the receipt's time, as the receipt's actor.
    fn resume_follow_ups(
        &self,
        stored: &ActionInstance,
        receipt: &OperationReceipt,
    ) -> Result<(), ActionInstanceAdmissionError> {
        let internal = ActionInstanceAdmissionError::Internal;
        let intent = receipt
            .events
            .first()
            .ok_or_else(|| internal("admission receipt has no intent".into()))?;
        let now = intent.timestamp_ms;
        // The type as it was bound, enabled or not: finishing an admission
        // authorizes nothing new.
        let type_def = self
            .db
            .get_governed_action_type(&stored.namespace, &stored.type_id, &stored.version)
            .map_err(internal)?
            .ok_or_else(|| internal("action type of an admission is gone".into()))?;
        let (budget_subject, budget_amount) = type_def
            .budget_charge(
                &stored.namespace,
                &stored.principal,
                &stored.parameters_json,
            )
            .map_err(ActionInstanceAdmissionError::InvalidArgument)?;
        let attribute = |key: &str| intent.attributes.get(key).map(String::as_str);
        let admitted = match (
            attribute("object_id"),
            attribute("object_kind"),
            attribute("object_mutation"),
        ) {
            (Some(id), Some(kind), Some(mutation)) => Some(AdmittedObject { id, kind, mutation }),
            _ => None,
        };
        let decision = admission_decision(stored, &receipt.initiating_actor, admitted, None, now);
        let effects = plan_admission_effects(&type_def, stored, now)?;
        self.finish_admission(
            stored,
            &decision,
            &budget_subject,
            budget_amount,
            stored.admission_budget_already_reserved,
            effects.as_deref(),
            false,
        )
    }
}

impl ActionInstanceAdmission<'_> {
    /// Finishes an approver decision's follow-ups when its lease says they
    /// are outstanding (#1948): a crash or failure after the decision's
    /// receipt. They are rebuilt from the decided instance and the receipt's
    /// approval event, at that event's time and as its decider.
    fn resume_decision_follow_ups(
        &self,
        stored: &ActionInstance,
    ) -> Result<(), ActionInstanceAdmissionError> {
        let internal = ActionInstanceAdmissionError::Internal;
        let Some(lease) = stored
            .admission_lease
            .as_ref()
            .filter(|lease| lease.decision_follow_ups_recorded == Some(false))
        else {
            return Ok(());
        };
        let Some(receipt) = self
            .db
            .get_operation_receipt(&stored.operation_id)
            .map_err(internal)?
        else {
            return Ok(());
        };
        // The decision's receipt is not recorded yet: nothing to finish.
        let Some(approved) = receipt
            .events
            .iter()
            .rev()
            .find(|event| event.kind == ReceiptEventKind::ApprovalDecided)
        else {
            return Ok(());
        };
        let intent = receipt
            .events
            .first()
            .ok_or_else(|| internal("decision receipt has no intent".into()))?;
        let attribute = |key: &str| intent.attributes.get(key).map(String::as_str);
        let admitted = match (
            attribute("object_id"),
            attribute("object_kind"),
            attribute("object_mutation"),
        ) {
            (Some(id), Some(kind), Some(mutation)) => Some(AdmittedObject { id, kind, mutation }),
            _ => None,
        };
        let decision_value = approved
            .attributes
            .get("decision")
            .map(String::as_str)
            .unwrap_or(&stored.approval_decision);
        let approval = ApprovalRecord {
            decider: &approved.actor,
            decision: decision_value,
            reason: approved
                .attributes
                .get("reason")
                .map(String::as_str)
                .unwrap_or_default(),
        };
        let now = approved.timestamp_ms;
        let decision = admission_decision(stored, &approved.actor, admitted, Some(&approval), now);
        let type_def = self
            .db
            .get_governed_action_type(&stored.namespace, &stored.type_id, &stored.version)
            .map_err(internal)?
            .ok_or_else(|| internal("action type of a decided instance is gone".into()))?;
        let (budget_subject, budget_amount) = if stored.status == STATUS_ADMITTED {
            type_def
                .budget_charge(
                    &stored.namespace,
                    &stored.principal,
                    &stored.parameters_json,
                )
                .map_err(ActionInstanceAdmissionError::InvalidArgument)?
        } else {
            (String::new(), 0)
        };
        let effects = plan_admission_effects(&type_def, stored, now)?;
        self.finish_admission(
            stored,
            &decision,
            &budget_subject,
            budget_amount,
            lease.decision_budget_reserved.unwrap_or(true),
            effects.as_deref(),
            true,
        )
    }
}

/// Marks a decided instance's follow-ups outstanding until recorded
/// (#1948). A lease from an older binary, or none, is left as it is: its
/// decision is not resumed.
fn expect_decision_follow_ups(decided: &mut ActionInstance, budget_reserved: bool) {
    if let Some(lease) = decided
        .admission_lease
        .as_mut()
        .filter(|lease| lease.follow_ups_recorded.is_some())
    {
        lease.decision_follow_ups_recorded = Some(false);
        lease.decision_budget_reserved = Some(budget_reserved);
    }
}

/// The object an admission wrote, as its receipt and decision name it.
#[derive(Clone, Copy)]
struct AdmittedObject<'a> {
    id: &'a str,
    kind: &'a str,
    mutation: &'a str,
}

/// The decision record of an admission, or of an approver's decision on a
/// parked one. Its id derives from the operation, so recording it again is a
/// no-op (#1943).
fn admission_decision(
    stored: &ActionInstance,
    actor: &str,
    admitted: Option<AdmittedObject<'_>>,
    approval: Option<&ApprovalRecord<'_>>,
    now: i64,
) -> audit::Decision {
    let mut evidence: HashMap<String, String> = stored
        .approval
        .as_ref()
        .map(|requirement| {
            approval_attributes(requirement)
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect()
        })
        .unwrap_or_default();
    evidence.extend([
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
    if let Some(actor) = stored.delegating_actor.as_ref() {
        evidence.insert("act".into(), actor.clone());
    }
    if let Some(admitted) = admitted {
        evidence.insert("object_id".into(), admitted.id.into());
        evidence.insert("object_kind".into(), admitted.kind.into());
        evidence.insert("object_mutation".into(), admitted.mutation.into());
    }
    if !stored.deny_reason.is_empty() {
        evidence.insert("deny_reason".into(), stored.deny_reason.clone());
    }
    if let Some(approval) = approval {
        evidence.insert("approver".into(), approval.decider.to_string());
        evidence.insert("approval_decision".into(), approval.decision.to_string());
    }
    let step = if approval.is_some() {
        "decide"
    } else {
        "submit"
    };
    audit::Decision {
        id: format!("{}:{step}", stored.operation_id),
        timestamp: now,
        actor: approval
            .map_or(actor, |approval| approval.decider)
            .to_string(),
        action: format!("{step}_action_instance"),
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
    }
}

/// Receipt and decision-record attributes for a parked instance's approval
/// requirement. Empty values are left out; approvers join with commas.
fn approval_attributes(approval: &ApprovalRequirement) -> Vec<(&'static str, String)> {
    [
        ("approval_policy_scope", approval.policy_scope.clone()),
        ("approval_rule", approval.rule.clone()),
        ("approvers", approval.approvers.join(",")),
        ("approver_role", approval.approver_role.clone()),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .collect()
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

/// What a takeover found for an abandoned reservation.
enum Abandoned {
    /// Not abandoned (receipt recorded, lease live, legacy row, or another
    /// taker won): answer as a replay.
    Live,
    /// The abandoned admission's object write landed.
    Landed {
        instance: Box<ActionInstance>,
        applied: Box<AppliedObjectMutation>,
        type_def: Box<crate::sekai::governed_action_type::GovernedActionType>,
    },
    /// Nothing landed; the reservation is gone.
    Released,
}

/// The effects an admitted instance materializes when its receipt records
/// them; none for any other status.
fn plan_admission_effects(
    type_def: &crate::sekai::governed_action_type::GovernedActionType,
    instance: &ActionInstance,
    now: i64,
) -> Result<Option<Vec<action_effect::ActionEffect>>, ActionInstanceAdmissionError> {
    if instance.status != STATUS_ADMITTED {
        return Ok(None);
    }
    let force_notify_fail = serde_json::from_str::<serde_json::Value>(&instance.parameters_json)
        .ok()
        .and_then(|value| {
            value
                .get("notify_delivery")
                .and_then(|delivery| delivery.as_str())
                .map(|delivery| delivery == "fail")
        })
        .unwrap_or(false);
    action_effect::plan_effects_for_admit(
        &instance.instance_id,
        &instance.namespace,
        &instance.operation_id,
        type_def.effect_kinds_to_materialize(),
        &instance.parameters_json,
        now,
        force_notify_fail,
    )
    .map(Some)
    .map_err(ActionInstanceAdmissionError::InvalidArgument)
}

/// The `object_id` parameter of `instance`, empty when it names none.
fn admitted_object_id(instance: &ActionInstance) -> String {
    serde_json::from_str::<serde_json::Value>(&instance.parameters_json)
        .ok()
        .and_then(|value| {
            value
                .get("object_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn object_for_admitted_instance(
    db: &RuntimeDb,
    instance: &ActionInstance,
) -> Result<Option<crate::domain::Object>, ActionInstanceAdmissionError> {
    let object_id = admitted_object_id(instance);
    if object_id.trim().is_empty() {
        return Ok(None);
    }
    db.get_object(&object_id)
        .map_err(ActionInstanceAdmissionError::Internal)
}

/// The instance's marking (#1706): the least upper bound of the markings of
/// the object its parameters name, the object a binding submitted for, and
/// the binding's own, under the namespace lattice, all read here at
/// admission, together with any marking the parameters set on the object
/// they write. A binding's source object that no longer exists (a delete
/// event) can no longer show its marking, so it counts as the lattice's top
/// rather than as unmarked. Unknown or incomparable tokens refuse the
/// admission rather than drop a marking.
pub fn derive_instance_marking(
    db: &RuntimeDb,
    namespace: &str,
    parameters_json: &str,
    source_object_id: &str,
    binding_markings: &[String],
) -> Result<String, ActionInstanceAdmissionError> {
    let lattice = db
        .get_classification_lattice(namespace)
        .map_err(ActionInstanceAdmissionError::Internal)?;
    let mut tokens = Vec::new();
    for (object_id, is_source) in [
        (target_object_id(parameters_json), false),
        (source_object_id.to_string(), true),
    ] {
        if object_id.trim().is_empty() {
            continue;
        }
        match db
            .get_object(&object_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
        {
            Some(object) => {
                if let Some(token) = crate::sekai::markings::object_marking_token(&object) {
                    tokens.push(token.to_string());
                }
            }
            None if is_source => tokens.push(top_marking(lattice.as_ref())?),
            None => {}
        }
    }
    // A marking the parameters set on the object they write (document
    // extraction carries the document's) is part of what the Action holds.
    if let Some(token) = serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()
        .as_ref()
        .and_then(|value| value.get(crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY))
        // As the object write stores it: numbers and booleans as text.
        .and_then(|value| match value {
            serde_json::Value::String(text) => Some(text.trim().to_string()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            serde_json::Value::Bool(flag) => Some(flag.to_string()),
            _ => None,
        })
        .filter(|token| !token.is_empty())
    {
        tokens.push(token);
    }
    tokens.extend(binding_markings.iter().cloned());
    if tokens.is_empty() {
        return Ok(String::new());
    }
    let (_, joined) = crate::sekai::classification_lattice::union_input_marking_tokens(
        lattice.as_ref(),
        tokens.iter().map(|token| Some(token.as_str())),
    )
    .map_err(|error| {
        ActionInstanceAdmissionError::FailedPrecondition(format!("action marking: {error}"))
    })?;
    Ok(joined.unwrap_or_default())
}

/// The highest marking of the namespace: the join of every lattice token, or
/// `restricted` without a lattice. Refuses when the tokens have no single
/// upper bound.
fn top_marking(
    lattice: Option<&crate::sekai::classification_lattice::ClassificationLattice>,
) -> Result<String, ActionInstanceAdmissionError> {
    let unknown = || {
        ActionInstanceAdmissionError::FailedPrecondition(
            "action marking: the deleted source's marking is unknown".into(),
        )
    };
    let Some(lattice) = lattice else {
        return Ok("restricted".into());
    };
    let (_, top) = crate::sekai::classification_lattice::union_input_marking_tokens(
        Some(lattice),
        lattice.tokens.iter().map(|token| Some(token.as_str())),
    )
    .map_err(|_| unknown())?;
    top.ok_or_else(unknown)
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

/// Whether `decider`, presenting `principals`, may decide `instance` of
/// `type_def`: not its submitter, entitled (a named approver, else a
/// namespace administrator), and allowed by its review-queue placement. The
/// one rule a decision applies and an approver inbox lists by (#1771).
pub fn may_decide(
    type_def: &crate::sekai::governed_action_type::GovernedActionType,
    instance: &ActionInstance,
    decider: &str,
    principals: &[String],
    decider_is_namespace_admin: bool,
) -> bool {
    let is_submitter = decider == instance.principal
        || principals
            .iter()
            .any(|principal| principal == &instance.principal);
    let entitled = if type_def.approvers.is_empty() {
        decider_is_namespace_admin
    } else {
        principals
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(decider))
            .any(|principal| {
                type_def
                    .approvers
                    .iter()
                    .any(|approver| approver == principal)
            })
    };
    !is_submitter
        && entitled
        && crate::sekai::review_queue::reviewer_may_decide(
            &type_def.review_queue,
            &instance.review,
            decider,
        )
}

fn object_changed() -> ActionInstanceAdmissionError {
    ActionInstanceAdmissionError::FailedPrecondition(
        "the object changed since the revision the caller checked".into(),
    )
}

fn target_object(
    db: &RuntimeDb,
    parameters_json: &str,
) -> Result<Option<crate::domain::Object>, ActionInstanceAdmissionError> {
    let object_id = target_object_id(parameters_json);
    if object_id.is_empty() {
        return Ok(None);
    }
    db.get_object(&object_id)
        .map_err(ActionInstanceAdmissionError::Internal)
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

/// Audit action for a cross-tenant sharing criterion check (#1860).
pub const SHARING_CRITERION_DECISION: &str = "action_criterion_sharing";

/// Who asks a sharing criterion, for its audit decision.
pub(crate) struct SharingAudit<'a> {
    pub actor: &'a str,
    pub namespace: &'a str,
    pub type_id: &'a str,
    pub now: i64,
}

/// Answers a sharing criterion (#1860, ADR 0077 amendment). Loads the target
/// object the criterion's parameter names, in any namespace, and asks the
/// identity extension whether `acting_tenant` shares an approved space with
/// its owner. Nothing about the target reaches the caller. No extension
/// means unshared; a missing target, a missing tenant under an extension,
/// or an extension error is unavailable. With `audit`, records the decision
/// and the owning tenant.
pub(crate) fn resolve_sharing(
    db: &RuntimeDb,
    acting_tenant: &str,
    parameters_json: &str,
    criterion: &ActionSubmissionCriterion,
    audit: Option<&SharingAudit<'_>>,
) -> SharingAnswer {
    let target = serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()
        .and_then(|parameters| {
            parameters
                .get(criterion.property.trim())
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .filter(|id| !id.is_empty())
        .and_then(|id| db.get_object(&id).ok().flatten());
    let (answer, owner_tenant) = match (&target, db.enterprise_extension()) {
        (None, _) => (SharingAnswer::Unavailable, String::new()),
        (Some(_), None) => (SharingAnswer::NotShared, String::new()),
        (Some(_), Some(_)) if acting_tenant.trim().is_empty() => {
            (SharingAnswer::Unavailable, String::new())
        }
        (Some(target), Some(extension)) => {
            match extension.tenants_share_space(acting_tenant, &target.namespace) {
                Ok(sharing) if sharing.shared => (SharingAnswer::Shared, sharing.owner_tenant),
                Ok(sharing) => (SharingAnswer::NotShared, sharing.owner_tenant),
                Err(_) => (SharingAnswer::Unavailable, String::new()),
            }
        }
    };
    if let Some(audit) = audit {
        let mut evidence = std::collections::HashMap::from([
            ("criterion_id".to_string(), criterion.criterion_id.clone()),
            ("namespace".to_string(), audit.namespace.to_string()),
            ("type_id".to_string(), audit.type_id.to_string()),
            ("acting_tenant".to_string(), acting_tenant.to_string()),
            ("owner_tenant".to_string(), owner_tenant),
        ]);
        if let Some(target) = &target {
            evidence.insert("target_namespace".into(), target.namespace.clone());
        }
        let (reason, outcome) = match answer {
            SharingAnswer::NotShared => ("no_shared_space", "allow"),
            SharingAnswer::Shared => ("shared_space", "deny"),
            SharingAnswer::Unavailable => (CRITERION_UNAVAILABLE, "deny"),
        };
        let _ = db.record_decision(&audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: audit.now,
            actor: audit.actor.to_string(),
            action: SHARING_CRITERION_DECISION.into(),
            reason: reason.into(),
            evidence,
            target_id: target.map(|target| target.id).unwrap_or_default(),
            outcome: outcome.into(),
        });
    }
    answer
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

fn refuse_frozen(
    db: &RuntimeDb,
    checks: &[crate::sekai::write_freeze::WriteFreezeCheck<'_>],
) -> Result<(), ActionInstanceAdmissionError> {
    match crate::sekai::write_freeze::freeze_reason_any(db, checks) {
        Ok(Some(reason)) => Err(ActionInstanceAdmissionError::FailedPrecondition(reason)),
        Ok(None) => Ok(()),
        Err(error) => Err(ActionInstanceAdmissionError::Internal(error)),
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

/// The request digest of an offline submission: the online digest and the
/// submission, so a retry must repeat both.
fn offline_request_digest(
    online: &str,
    offline: &crate::sekai::offline_action::OfflineSubmission,
) -> Result<String, ActionInstanceAdmissionError> {
    use sha2::Digest as _;
    let body = serde_json::to_string(&serde_json::json!({
        "request_digest": online,
        "offline": offline,
    }))
    .map_err(|error| ActionInstanceAdmissionError::Internal(error.to_string()))?;
    Ok(format!("{:x}", sha2::Sha256::digest(body.as_bytes())))
}

/// Check an offline submission against its type, and return the
/// properties the Action writes.
fn validate_offline(
    type_def: &crate::sekai::governed_action_type::GovernedActionType,
    offline: &crate::sekai::offline_action::OfflineSubmission,
    parameters_json: &str,
    now: i64,
) -> Result<std::collections::BTreeSet<String>, ActionInstanceAdmissionError> {
    if type_def.object_mutation.trim() != crate::sekai::governed_action_type::OBJECT_MUTATION_UPDATE
    {
        return Err(ActionInstanceAdmissionError::InvalidArgument(
            "an offline Action needs a type that updates an object".into(),
        ));
    }
    if offline.device_id.trim().is_empty() {
        return Err(ActionInstanceAdmissionError::PermissionDenied(
            "an offline Action needs a device-bound credential".into(),
        ));
    }
    let parameters: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|error| ActionInstanceAdmissionError::InvalidArgument(error.to_string()))?;
    let mut touched: std::collections::BTreeSet<String> =
        action_object_mutation::object_properties(&parameters)
            .map_err(map_object_mutation_error)?
            .into_keys()
            .collect();
    // A rename writes the object's name, which is compared like a property.
    if parameters.get("name").is_some() {
        touched.insert(crate::sekai::offline_action::NAME_FIELD.into());
    }
    offline
        .validate(&touched, now)
        .map_err(ActionInstanceAdmissionError::InvalidArgument)?;
    Ok(touched)
}

/// The object an offline Action updates, as it is now.
/// One outside the submission's namespace or of another kind is not found,
/// so a conflict never reports on it.
fn load_offline_object(
    db: &RuntimeDb,
    namespace: &str,
    object_kind: &str,
    parameters_json: &str,
) -> Result<crate::domain::Object, ActionInstanceAdmissionError> {
    let object_id = serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()
        .and_then(|value| value.get("object_id")?.as_str().map(str::to_string))
        .ok_or_else(|| {
            ActionInstanceAdmissionError::InvalidArgument("object_id parameter required".into())
        })?;
    db.get_object(&object_id)
        .map_err(ActionInstanceAdmissionError::Internal)?
        .filter(|object| object.namespace == namespace && object.kind == object_kind.trim())
        .ok_or_else(|| {
            ActionInstanceAdmissionError::FailedPrecondition(format!(
                "object {object_id} not found"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::governed_action_type::{
        EFFECT_KIND_NOTIFY, EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType,
    };

    fn setup() -> RuntimeDb {
        let db = RuntimeDb::memory();
        db.put_governed_action_type(dispatch_type("acme"), "operator", 1)
            .unwrap();
        db
    }

    /// The runtime-dispatch type the plain admission tests submit.
    fn dispatch_type(namespace: &str) -> GovernedActionType {
        GovernedActionType {
                namespace: namespace.into(),
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
            }
    }

    fn postgres_runtime() -> RuntimeDb {
        use crate::db::postgres::PostgresDb;
        use std::sync::Arc;

        let database_url = std::env::var("SEKAI_TEST_POSTGRES_URL").unwrap_or_else(|_| {
            panic!("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database")
        });
        let db = if let Ok(ca_certificate_path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            let ca_certificate = std::fs::read(&ca_certificate_path).unwrap_or_else(|error| {
                panic!("read PostgreSQL test CA certificate {ca_certificate_path}: {error}")
            });
            PostgresDb::connect_with_ca_certificate(&database_url, 4, &ca_certificate).unwrap()
        } else {
            PostgresDb::connect(&database_url, 4).unwrap()
        };
        RuntimeDb::Postgres(Arc::new(db))
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
            delegating_actor: Some("origin-user".into()),
            budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
            expected_object_revision: String::new(),
            offline: None,
        }
    }

    struct StampProposal(&'static str);

    impl ActionProposalPort for StampProposal {
        fn fill_provenance_json(
            &self,
            _type_def: &GovernedActionType,
            _parameters_json: &str,
        ) -> Result<String, String> {
            Ok(self.0.into())
        }
    }

    struct CountingBudget {
        remaining: std::sync::atomic::AtomicI32,
        recorded: std::sync::atomic::AtomicI32,
        keys: std::sync::Mutex<std::collections::BTreeSet<String>>,
    }

    impl ActionBudgetPort for CountingBudget {
        fn check(&self, _subject: &str, amount: i32) -> Result<(), String> {
            if self.remaining.load(std::sync::atomic::Ordering::SeqCst) < amount {
                Err("exhausted".into())
            } else {
                Ok(())
            }
        }

        fn record(&self, _subject: &str, amount: i32) {
            self.remaining
                .fetch_sub(amount, std::sync::atomic::Ordering::SeqCst);
            self.recorded
                .fetch_add(amount, std::sync::atomic::Ordering::SeqCst);
        }

        fn record_once(
            &self,
            subject: &str,
            amount: i32,
            key: &str,
            _at_ms: i64,
        ) -> Result<(), String> {
            if self.keys.lock().unwrap().insert(key.into()) {
                self.record(subject, amount);
            }
            Ok(())
        }
    }

    #[test]
    fn admit_without_proposal_port_leaves_fill_empty() {
        let db = setup();
        let admission = ActionInstanceAdmission::new(&db, None);
        let admitted = admission
            .admit(request(r#"{"runtime":"shikigami"}"#), "service-a", 10)
            .unwrap();
        assert!(admitted.instance.system_one_fill_json.is_empty());
        let receipt = db
            .get_operation_receipt(&admitted.instance.operation_id)
            .unwrap()
            .unwrap();
        let intent = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .unwrap();
        assert_eq!(intent.actor, "service-a");
        assert_eq!(
            intent.attributes.get("act").map(String::as_str),
            Some("origin-user")
        );
        let audit = db
            .list_decisions(&audit::DecisionFilter {
                actor: Some("service-a".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(audit.iter().any(
            |decision| decision.evidence.get("act").map(String::as_str) == Some("origin-user")
        ));
        assert_eq!(admitted.instance.budget_decision, "not_configured");
    }

    #[test]
    fn tenant_freeze_blocks_admit_when_tenant_is_supplied() {
        let db = setup();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
            scope_value: "acme-tenant".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionInstanceAdmission::new(&db, None)
            .with_tenant("acme-tenant")
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 10)
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze"))
        );
        ActionInstanceAdmission::new(&db, None)
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 10)
            .unwrap();
    }

    #[test]
    fn resource_tenant_freeze_blocks_admit() {
        let db = setup();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
            scope_value: "tenant-test".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let mut request = request(r#"{"runtime":"shikigami"}"#);
        request.delegating_actor = None;
        request.resource_tenant = "tenant-test".into();
        let blocked = ActionInstanceAdmission::new(&db, None)
            .admit(request, "alice", 10)
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze") && reason.contains("tenant/tenant-test"))
        );
    }

    #[test]
    fn persisted_resource_tenant_blocks_later_grant_without_tenant() {
        let db = approval_setup("create", &["bob"]);
        let mut parked_request = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-resource-tenant","title":"t"}"#,
        );
        parked_request.resource_tenant = "tenant-test".into();
        let parked = ActionInstanceAdmission::new(&db, None)
            .admit(parked_request, "alice", 10)
            .unwrap()
            .instance;
        assert_eq!(parked.resource_tenant, "tenant-test");
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
            scope_value: "tenant-test".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionInstanceAdmission::new(&db, None)
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze") && reason.contains("tenant/tenant-test"))
        );
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );
    }

    #[test]
    fn persisted_admission_tenant_blocks_later_grant_without_tenant() {
        let db = approval_setup("create", &["bob"]);
        let parked = ActionInstanceAdmission::new(&db, None)
            .with_tenant("acme-tenant")
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-stored-tenant","title":"t"}"#,
                ),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        assert_eq!(parked.admission_tenant, "acme-tenant");
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
            scope_value: "acme-tenant".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionInstanceAdmission::new(&db, None)
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze") && reason.contains("tenant/acme-tenant"))
        );
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );
    }

    #[test]
    fn principal_freeze_on_delegating_actor_blocks_admit() {
        let db = setup();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_PRINCIPAL.into(),
            scope_value: "alice".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let mut delegated = request(r#"{"runtime":"shikigami"}"#);
        delegated.delegating_actor = Some("alice".into());
        let blocked = ActionInstanceAdmission::new(&db, None)
            .admit(delegated, "agent:bot", 10)
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze") && reason.contains("principal/alice"))
        );
        let mut other = request(r#"{"runtime":"shikigami"}"#);
        other.delegating_actor = Some("bob".into());
        other.idempotency_key = "idem-2".into();
        ActionInstanceAdmission::new(&db, None)
            .admit(other, "agent:bot", 10)
            .unwrap();
    }

    #[test]
    fn registered_principal_tenant_freeze_blocks_admit_without_with_tenant() {
        let db = setup();
        db.put_service_principal(
            &crate::sekai::service_principal::ServicePrincipalRegistration {
                principal: "worker-a".into(),
                tenant_id: "acme-tenant".into(),
                namespaces: vec!["acme".into()],
                action_types: vec!["dispatch".into()],
                registered_by: "local".into(),
                created_at_ms: 1,
                updated_at_ms: 1,
            },
        )
        .unwrap();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
            scope_value: "acme-tenant".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let mut request = request(r#"{"runtime":"shikigami"}"#);
        request.delegating_actor = None;
        let blocked = ActionInstanceAdmission::new(&db, None)
            .admit(request, "worker-a", 10)
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze") && reason.contains("tenant/acme-tenant"))
        );
    }

    #[test]
    fn freeze_blocks_parked_grant() {
        let db = approval_setup("create", &["bob"]);
        let admission = ActionInstanceAdmission::new(&db, None);
        let parked = admission
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-freeze","title":"t"}"#,
                ),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        assert_eq!(parked.status, STATUS_PARKED);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "acme".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze"))
        );
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );
        assert!(db.get_object("rec-freeze").unwrap().is_none());
    }

    #[test]
    fn machine_credential_blocks_agent_action_admit() {
        let db = setup();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "acme".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_AGENT_ACTIONS.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let mut human = request(r#"{"runtime":"shikigami"}"#);
        human.delegating_actor = None;
        ActionInstanceAdmission::new(&db, None)
            .admit(human.clone(), "alice", 10)
            .unwrap();
        human.idempotency_key = "idem-2".into();
        let blocked = ActionInstanceAdmission::new(&db, None)
            .with_machine_credential(true)
            .admit(human, "alice", 10)
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze"))
        );
    }

    #[test]
    fn machine_credential_blocks_parked_grant() {
        let db = approval_setup("create", &["bob"]);
        let parked = ActionInstanceAdmission::new(&db, None)
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-machine","title":"t"}"#,
                ),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        assert_eq!(parked.status, STATUS_PARKED);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "acme".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_AGENT_ACTIONS.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionInstanceAdmission::new(&db, None)
            .with_machine_credential(true)
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze"))
        );
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );
        ActionInstanceAdmission::new(&db, None)
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                30,
            )
            .unwrap();
    }

    #[test]
    fn principal_agent_freeze_on_human_submitter_does_not_block_machine_grant() {
        let db = approval_setup("create", &["bob"]);
        let parked = ActionInstanceAdmission::new(&db, None)
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-human-submitter-machine-grant","title":"t"}"#,
                ),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        assert!(!parked.agent_action);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_PRINCIPAL.into(),
            scope_value: "alice".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_AGENT_ACTIONS.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let granted = ActionInstanceAdmission::new(&db, None)
            .with_machine_credential(true)
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap();
        assert_eq!(granted.instance.status, STATUS_ADMITTED);
    }

    #[test]
    fn persisted_agent_action_blocks_human_grant() {
        let db = approval_setup("create", &["bob"]);
        let parked = ActionInstanceAdmission::new(&db, None)
            .with_machine_credential(true)
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-persisted-agent","title":"t"}"#,
                ),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        assert!(parked.agent_action);
        assert_eq!(parked.status, STATUS_PARKED);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "acme".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_AGENT_ACTIONS.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionInstanceAdmission::new(&db, None)
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze"))
        );
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );
    }

    #[test]
    fn principal_freeze_on_approver_blocks_grant() {
        let db = approval_setup("create", &["bob"]);
        let parked = ActionInstanceAdmission::new(&db, None)
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-approver-freeze","title":"t"}"#,
                ),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_PRINCIPAL.into(),
            scope_value: "bob".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionInstanceAdmission::new(&db, None)
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze"))
        );
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );
        assert!(db.get_object("rec-approver-freeze").unwrap().is_none());
    }

    #[test]
    fn principal_freeze_on_approver_delegating_actor_blocks_grant() {
        let db = approval_setup("create", &["bob"]);
        let parked = ActionInstanceAdmission::new(&db, None)
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"rec-approver-act-freeze","title":"t"}"#,
                ),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_PRINCIPAL.into(),
            scope_value: "carol".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let mut grant = decision(&parked.instance_id, DECISION_GRANT, "bob");
        grant.delegating_actor = Some("carol".into());
        let blocked = ActionInstanceAdmission::new(&db, None)
            .decide(grant, "bob", 20)
            .unwrap_err();
        assert!(
            matches!(blocked, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze") && reason.contains("principal/carol"))
        );
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PARKED
        );
        assert!(db.get_object("rec-approver-act-freeze").unwrap().is_none());
    }

    #[test]
    fn admit_stamps_fill_provenance_from_the_proposal_port() {
        let db = setup();
        let proposal = StampProposal(r#"{"model":"test"}"#);
        let admission = ActionInstanceAdmission::new(&db, None).with_proposal(Some(&proposal));
        let admitted = admission
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 10)
            .unwrap();
        assert_eq!(admitted.instance.system_one_fill_json, proposal.0);
        let stored = db
            .get_action_instance(&admitted.instance.instance_id)
            .unwrap()
            .expect("stored");
        assert_eq!(stored.system_one_fill_json, proposal.0);
    }

    #[test]
    fn admit_records_budget_when_the_port_allows() {
        let db = setup();
        let budget = CountingBudget {
            remaining: std::sync::atomic::AtomicI32::new(1),
            recorded: std::sync::atomic::AtomicI32::new(0),
            keys: Default::default(),
        };
        let admitted = ActionInstanceAdmission::new(&db, Some(&budget))
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 10)
            .unwrap();
        assert_eq!(admitted.instance.status, STATUS_ADMITTED);
        assert_eq!(admitted.instance.budget_decision, "allow");
        assert_eq!(budget.recorded.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn admit_denies_when_the_budget_port_is_exhausted() {
        let db = setup();
        let budget = CountingBudget {
            remaining: std::sync::atomic::AtomicI32::new(0),
            recorded: std::sync::atomic::AtomicI32::new(0),
            keys: Default::default(),
        };
        let denied = ActionInstanceAdmission::new(&db, Some(&budget))
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 10)
            .unwrap();
        assert_eq!(denied.instance.status, STATUS_DENIED);
        assert_eq!(denied.instance.budget_decision, "budget_exceeded");
        assert_eq!(budget.recorded.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn agent_propose_only_denies_when_budget_is_exhausted() {
        let db = setup();
        let budget = CountingBudget {
            remaining: std::sync::atomic::AtomicI32::new(0),
            recorded: std::sync::atomic::AtomicI32::new(0),
            keys: Default::default(),
        };
        let denied = ActionInstanceAdmission::new(&db, Some(&budget))
            .admit(request(r#"{"runtime":"shikigami"}"#), "agent:bot", 10)
            .unwrap();
        assert_eq!(denied.instance.status, STATUS_DENIED);
        assert_eq!(denied.instance.budget_decision, "budget_exceeded");
        assert_eq!(budget.recorded.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn agent_parked_grant_rechecks_deferred_budget() {
        let db = setup();
        let budget = CountingBudget {
            remaining: std::sync::atomic::AtomicI32::new(1),
            recorded: std::sync::atomic::AtomicI32::new(0),
            keys: Default::default(),
        };
        let admission = ActionInstanceAdmission::new(&db, Some(&budget));
        let mut first = request(r#"{"runtime":"shikigami"}"#);
        first.idempotency_key = "agent-a".into();
        let parked_a = admission.admit(first, "agent:bot", 10).unwrap().instance;
        assert_eq!(parked_a.status, STATUS_PARKED);
        assert_eq!(parked_a.budget_decision, "allow");
        assert_eq!(budget.recorded.load(std::sync::atomic::Ordering::SeqCst), 1);
        let mut second = request(r#"{"runtime":"shikigami"}"#);
        second.idempotency_key = "agent-b".into();
        let denied = admission.admit(second, "agent:bot", 11).unwrap().instance;
        assert_eq!(denied.status, STATUS_DENIED);
        assert_eq!(denied.budget_decision, "budget_exceeded");
        assert_eq!(budget.recorded.load(std::sync::atomic::Ordering::SeqCst), 1);
        let granted = admission
            .decide(
                ActionInstanceDecisionRequest {
                    instance_id: parked_a.instance_id.clone(),
                    decision: DECISION_GRANT.into(),
                    reason: "reviewed".into(),
                    decider_principals: vec!["ops".into()],
                    decider_is_namespace_admin: true,
                    delegating_actor: None,
                    execution_claim: None,
                },
                "ops",
                20,
            )
            .unwrap()
            .instance;
        assert_eq!(granted.status, STATUS_ADMITTED);
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
                    delegating_actor: None,
                    execution_claim: None,
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
                    delegating_actor: None,
                    budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
                    expected_object_revision: String::new(),
                    offline: None,
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
            delegating_actor: None,
            budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
            expected_object_revision: String::new(),
            offline: None,
        }
    }

    /// An offline submission from device-7, prepared at 5 against `base`.
    fn offline_request(
        type_id: &str,
        version: &str,
        key: &str,
        parameters_json: &str,
        base_updated_ms: i64,
        base_properties: &[(&str, &str)],
    ) -> ActionInstanceAdmissionRequest {
        let mut request = record_request(type_id, parameters_json);
        request.version = version.into();
        request.idempotency_key = key.into();
        request.request_id = format!("operation-{key}");
        request.offline = Some(crate::sekai::offline_action::OfflineSubmission {
            prepared_at_ms: 5,
            base_updated_ms,
            base_properties: base_properties
                .iter()
                .map(|(key, value)| (key.to_string(), Some(value.to_string())))
                .collect(),
            lease_id: "lease-1".into(),
            device_id: "device-7".into(),
        });
        request
    }

    #[test]
    fn offline_actions_meet_conflict_rules_policy_at_arrival_and_replay() {
        use crate::sekai::offline_action::{CONFLICT_REASON, CONFLICT_REJECT_TOUCHED};
        let db = setup();
        ensure_record_kind(&db);
        // Records with two written properties, title and note.
        let with_note = |mutation: &str| {
            GovernedActionType {
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"title":{"type":"string"},"note":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            ..record_type(mutation)
        }
        };
        db.put_governed_action_type(with_note("create"), "operator", 1)
            .unwrap();
        db.put_governed_action_type(with_note("update"), "operator", 1)
            .unwrap();
        db.put_governed_action_type(
            GovernedActionType {
                version: "2".into(),
                offline_conflict: CONFLICT_REJECT_TOUCHED.into(),
                ..with_note("update")
            },
            "operator",
            1,
        )
        .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut create = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-1","name":"Acme","title":"draft","note":"a"}"#,
        );
        create.idempotency_key = "create-1".into();
        create.request_id = "operation-create-1".into();
        admission.admit(create, "alice", 10).unwrap();
        let base = db.get_object("rec-1").unwrap().unwrap().updated;
        // Someone changes another property online after the device read it.
        let mut online = record_request(
            "customer.record.update",
            r#"{"object_id":"rec-1","note":"b"}"#,
        );
        online.idempotency_key = "online-1".into();
        online.request_id = "operation-online-1".into();
        admission.admit(online, "bob", 20).unwrap();
        let current = db.get_object("rec-1").unwrap().unwrap().updated;
        assert_ne!(current, base);

        // Strict rule: any change since the base is a conflict, stored with
        // both versions, and a retry returns the same outcome.
        let strict = offline_request(
            "customer.record.update",
            "1",
            "offline-strict",
            r#"{"object_id":"rec-1","title":"final"}"#,
            base,
            &[("title", "draft")],
        );
        let conflict = admission.admit(strict.clone(), "alice", 30).unwrap();
        assert_eq!(conflict.instance.status, STATUS_DENIED);
        assert_eq!(conflict.instance.deny_reason, CONFLICT_REASON);
        let detail = conflict.instance.conflict.clone().unwrap();
        assert_eq!(
            (detail.base_updated_ms, detail.current_updated_ms),
            (base, current)
        );
        let again = admission.admit(strict, "alice", 40).unwrap();
        assert!(again.replay);
        assert_eq!(again.instance.instance_id, conflict.instance.instance_id);
        assert_eq!(again.instance.conflict, conflict.instance.conflict);
        assert_eq!(
            db.get_object("rec-1").unwrap().unwrap().properties["title"],
            "draft"
        );

        // Touched-properties rule: the change was to another property, so
        // it applies; the receipt records the offline provenance.
        let touched = offline_request(
            "customer.record.update",
            "2",
            "offline-touched",
            r#"{"object_id":"rec-1","title":"final"}"#,
            base,
            &[("title", "draft")],
        );
        let applied = admission.admit(touched, "alice", 50).unwrap();
        assert_eq!(
            applied.instance.status, STATUS_ADMITTED,
            "{:?}",
            applied.instance
        );
        assert_eq!(
            db.get_object("rec-1").unwrap().unwrap().properties["title"],
            "final"
        );
        let receipt = db
            .get_operation_receipt("operation-offline-touched")
            .unwrap()
            .unwrap();
        let intent = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .unwrap();
        for (key, value) in [
            ("offline", "true"),
            ("offline_prepared_at_ms", "5"),
            ("offline_device_id", "device-7"),
            ("offline_lease_id", "lease-1"),
        ] {
            assert_eq!(
                intent.attributes.get(key).map(String::as_str),
                Some(value),
                "{key}"
            );
        }
        // Under the same rule, a changed written property conflicts.
        let stale = offline_request(
            "customer.record.update",
            "2",
            "offline-touched-stale",
            r#"{"object_id":"rec-1","title":"other"}"#,
            base,
            &[("title", "draft")],
        );
        let refused = admission.admit(stale, "alice", 60).unwrap();
        assert_eq!(refused.instance.conflict.unwrap().properties, ["title"]);

        // Policy is decided at arrival: a deny set after the device prepared
        // the Action refuses it, though its base is current.
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::Deny;
        db.upsert_action_policy(&policy).unwrap();
        let fresh = db.get_object("rec-1").unwrap().unwrap();
        let late = offline_request(
            "customer.record.update",
            "1",
            "offline-policy",
            r#"{"object_id":"rec-1","title":"late"}"#,
            fresh.updated,
            &[("title", "final")],
        );
        let denied = admission.admit(late, "alice", 70).unwrap();
        assert_eq!(denied.instance.status, STATUS_DENIED);
        assert_ne!(denied.instance.deny_reason, CONFLICT_REASON);
        assert!(denied.instance.conflict.is_none());
    }

    #[test]
    fn an_offline_action_needs_a_device_and_an_update_type() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let create = offline_request(
            "customer.record.create",
            "1",
            "offline-create",
            r#"{"object_id":"rec-2","name":"x"}"#,
            1,
            &[],
        );
        assert!(matches!(
            admission.admit(create.clone(), "alice", 10),
            Err(ActionInstanceAdmissionError::InvalidArgument(_))
        ));
        let mut deviceless = create;
        deviceless.offline.as_mut().unwrap().device_id.clear();
        deviceless.type_id = "customer.record.update".into();
        db.put_governed_action_type(record_type("update"), "operator", 1)
            .unwrap();
        assert!(matches!(
            admission.admit(deviceless, "alice", 10),
            Err(ActionInstanceAdmissionError::PermissionDenied(_))
        ));

        // An object in another namespace is not found, so no conflict
        // reports on it.
        let mut foreign = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-foreign","name":"x"}"#,
        );
        foreign.namespace = "other".into();
        foreign.idempotency_key = "foreign-create".into();
        foreign.request_id = "operation-foreign-create".into();
        db.put_governed_action_type(
            GovernedActionType {
                namespace: "other".into(),
                ..record_type("create")
            },
            "operator",
            1,
        )
        .unwrap();
        admission.admit(foreign, "alice", 10).unwrap();
        let probe = offline_request(
            "customer.record.update",
            "1",
            "offline-foreign",
            r#"{"object_id":"rec-foreign","title":"x"}"#,
            1,
            &[("title", "x")],
        );
        let refused = admission.admit(probe, "alice", 20).unwrap_err();
        assert!(
            matches!(&refused, ActionInstanceAdmissionError::FailedPrecondition(message) if message.contains("not found")),
            "{refused:?}"
        );
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
                crate::sekai::object_log::identity_generation(
                    &store,
                    "acme",
                    "customer_record",
                    "rec-log"
                )
                .unwrap(),
                1
            );
            assert!(
                db.object_type_index_status("acme", "customer_record", 20)
                    .unwrap()
                    .is_none(),
                "Action apply must not write object_type_index as identity"
            );
        });
    }

    /// A takeover between the object write and the receipt leaves the first
    /// owner stale: its receipt is refused, and it neither undoes the write
    /// nor removes the newer owner's reservation (#1930).
    #[test]
    fn a_stale_owner_neither_records_nor_compensates() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        take_over_before_next_receipt();
        let mut request = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-taken","name":"Taken"}"#,
        );
        request.idempotency_key = "record-taken".into();
        request.request_id = "operation-taken".into();
        let error = ActionInstanceAdmission::new(&db, None)
            .admit(request, "alice", 10)
            .unwrap_err();
        assert!(
            matches!(
                &error,
                ActionInstanceAdmissionError::FailedPrecondition(message)
                    if message == crate::sekai::action_instance::ADMISSION_FENCE_LOST
            ),
            "{error:?}"
        );
        assert!(
            db.get_operation_receipt("operation-taken")
                .unwrap()
                .is_none()
        );
        assert!(db.get_object("rec-taken").unwrap().is_some());
        let reservation = db
            .get_action_instance_by_idempotency("acme", "record-taken")
            .unwrap()
            .expect("the newer owner's reservation stays");
        assert_eq!(reservation.admission_lease.unwrap().generation, 2);
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
                    "acme",
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
                    "acme",
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
        use std::sync::{Arc, Mutex, OnceLock};

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

        // #1200: callsite interest is process-wide. A thread-local
        // `with_default` subscriber loses the race when a sibling test
        // rebuilds the cache from a dispatcher that is uninterested.
        // Pin a process-wide ERROR subscriber so rebuilds keep this
        // event enabled. Unique request/object ids keep concurrent
        // ERROR lines from other tests out of the assertion.
        static CAPTURE: OnceLock<Buf> = OnceLock::new();
        let buf = CAPTURE.get_or_init(|| {
            let buf = Buf(Arc::new(Mutex::new(Vec::new())));
            let writer = buf.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::ERROR)
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            tracing::callsite::rebuild_interest_cache();
            buf
        });
        buf.0.lock().expect("log buffer").clear();

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
                r#"{"object_id":"rec-signal","name":"Signal"}"#,
            );
            request.idempotency_key = "record-signal-log".into();
            request.request_id = "operation-signal-log".into();
            tracing::callsite::rebuild_interest_cache();
            admission.admit(request, "alice", 10).unwrap();
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
            delegating_actor: None,
            execution_claim: None,
        }
    }

    #[test]
    fn review_queue_routes_over_threshold_and_refuses_outsiders() {
        let db = setup();
        ensure_record_kind(&db);
        let mut type_def = record_type("create");
        type_def.approvers = vec!["bob".into(), "carol".into()];
        type_def.review_queue = crate::sekai::review_queue::ReviewQueueSpec {
            queue_id: "spend".into(),
            sla_ms: 1_000,
            escalate: crate::sekai::review_queue::ESCALATE_AUTO_DENY.into(),
            threshold_param: String::new(),
            threshold: 0,
            pool: vec!["bob".into()],
            agent_reviewers: vec![],
            escalate_to: String::new(),
        };
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let parked = admission
            .admit(
                record_request("customer.record.create", r#"{"object_id":"rec-q"}"#),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        assert_eq!(parked.status, STATUS_PARKED);
        assert_eq!(parked.review.queue_id, "spend");
        assert_eq!(parked.review.assignee, "bob");
        let denied = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "carol"),
                "carol",
                20,
            )
            .unwrap_err();
        assert!(matches!(
            denied,
            ActionInstanceAdmissionError::PermissionDenied(_)
        ));
        let granted = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap()
            .instance;
        assert_eq!(granted.status, STATUS_ADMITTED);
        let receipt = db
            .get_operation_receipt(&granted.operation_id)
            .unwrap()
            .unwrap();
        let approval = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::ApprovalDecided)
            .expect("approval receipt");
        assert_eq!(
            approval.attributes.get("queue_id").map(String::as_str),
            Some("spend")
        );
        assert_eq!(
            approval.attributes.get("approver").map(String::as_str),
            Some("bob")
        );
        assert_eq!(
            approval.attributes.get("reason").map(String::as_str),
            Some("reviewed")
        );
    }

    #[test]
    fn decision_memory_surfaces_similar_readable_precedents() {
        let db = setup();
        ensure_record_kind(&db);
        let mut type_def = record_type("create");
        type_def.approvers = vec!["bob".into()];
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let submit = |key: &str, object_id: &str, now: i64| {
            let mut request = record_request(
                "customer.record.create",
                &format!(r#"{{"object_id":"{object_id}"}}"#),
            );
            request.idempotency_key = key.into();
            request.request_id = format!("op-{key}");
            admission.admit(request, "alice", now).unwrap().instance
        };
        let first = submit("mem-1", "rec-1", 10);
        admission
            .decide(
                decision(&first.instance_id, DECISION_DENY, "bob"),
                "bob",
                20,
            )
            .unwrap();
        let second = submit("mem-2", "rec-1", 30);
        admission
            .decide(
                decision(&second.instance_id, DECISION_GRANT, "bob"),
                "bob",
                40,
            )
            .unwrap();
        let unrelated = submit("mem-9", "rec-9", 50);
        admission
            .decide(
                decision(&unrelated.instance_id, DECISION_DENY, "bob"),
                "bob",
                60,
            )
            .unwrap();
        let third = submit("mem-3", "rec-1", 70);
        let memories = db
            .list_decision_memory(&third.namespace, &third.type_id)
            .unwrap();
        let shown = crate::sekai::decision_memory::precedents_for(
            &memories,
            &third.namespace,
            &third.type_id,
            &third.parameters_json,
            &[first.instance_id.clone(), second.instance_id.clone()],
        );
        assert_eq!(shown.len(), 2);
        assert!(shown.iter().any(|row| row.instance_id == first.instance_id));
        assert!(
            shown
                .iter()
                .any(|row| row.instance_id == second.instance_id)
        );
        assert!(
            !shown
                .iter()
                .any(|row| row.instance_id == unrelated.instance_id)
        );
        db.mark_decision_memory_superseded(&first.instance_id)
            .unwrap();
        let labelled = db
            .list_decision_memory(&third.namespace, &third.type_id)
            .unwrap();
        assert!(
            labelled
                .iter()
                .any(|row| row.instance_id == first.instance_id && row.superseded)
        );
    }

    #[test]
    fn review_queue_auto_denies_past_sla() {
        let db = setup();
        ensure_record_kind(&db);
        let mut type_def = record_type("create");
        type_def.approvers = vec!["bob".into()];
        type_def.review_queue = crate::sekai::review_queue::ReviewQueueSpec {
            queue_id: "spend".into(),
            sla_ms: 5,
            escalate: crate::sekai::review_queue::ESCALATE_AUTO_DENY.into(),
            threshold_param: String::new(),
            threshold: 0,
            pool: vec!["bob".into()],
            agent_reviewers: vec![],
            escalate_to: String::new(),
        };
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        // A crash after the receipt leaves the submit's follow-ups for the
        // sweep, which finishes them before it denies (#1943).
        crash_next_admission(CrashPoint::AfterReceipt);
        assert!(
            admission
                .admit(
                    record_request("customer.record.create", r#"{"object_id":"rec-sla"}"#),
                    "alice",
                    10,
                )
                .is_err()
        );
        let parked = db
            .list_action_instances("acme", None, Some(STATUS_PARKED), 10)
            .unwrap()
            .remove(0);
        let (reassigned, denied) = admission.escalate_due("acme", 16).unwrap();
        let submit = db
            .get_decision(&format!("{}:submit", parked.operation_id))
            .unwrap()
            .expect("submit record");
        assert_eq!(submit.outcome, STATUS_PARKED);
        assert_eq!(reassigned, 0);
        assert_eq!(denied, 1);
        let stored = db
            .get_action_instance(&parked.instance_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, STATUS_DENIED);
        assert_eq!(stored.deny_reason, "review_sla_expired");
        let late = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap_err();
        assert!(matches!(
            late,
            ActionInstanceAdmissionError::FailedPrecondition(_)
                | ActionInstanceAdmissionError::PermissionDenied(_)
        ));
    }

    /// A budget already refused upstream is recorded as a budget denial even
    /// where policy would park the Action: a parked instance would let an
    /// approver grant work with no budget behind it (#1871).
    #[test]
    fn a_refused_budget_denies_instead_of_parking() {
        let db = approval_setup("create", &["bob"]);
        let mut request = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-9","title":"t"}"#,
        );
        request.budget_already_reserved = true;
        let denied = ActionInstanceAdmission::new(&db, None)
            .with_budget_refused(true)
            .admit(request, "alice", 10)
            .unwrap()
            .instance;
        assert_eq!(denied.status, STATUS_DENIED);
        assert_eq!(denied.budget_decision, "budget_exceeded");
        assert!(
            denied.deny_reason.contains("action budget exhausted"),
            "{denied:?}"
        );
        assert!(
            db.list_action_instances("acme", None, Some(STATUS_PARKED), 10)
                .unwrap()
                .is_empty()
        );
        assert!(db.get_object("rec-9").unwrap().is_none());
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
        let inbox = db
            .list_action_instances("acme", None, Some(STATUS_PARKED), 10)
            .unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].instance_id, parked.instance_id);
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

    /// A parked submit whose follow-ups a crash left outstanding finishes
    /// them before an approver's decision changes the instance (#1943).
    #[test]
    fn a_decision_first_finishes_the_parked_submit_follow_ups() {
        let db = approval_setup("create", &["bob"]);
        let admission = ActionInstanceAdmission::new(&db, None);
        let request = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-11","title":"t"}"#,
        );
        crash_next_admission(CrashPoint::AfterReceipt);
        assert!(admission.admit(request, "alice", 10).is_err());
        let parked = db
            .list_action_instances("acme", None, Some(STATUS_PARKED), 10)
            .unwrap()
            .remove(0);
        let submitted = format!("{}:submit", parked.operation_id);
        assert!(db.get_decision(&submitted).unwrap().is_none());

        let granted = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap();
        assert_eq!(granted.instance.status, STATUS_ADMITTED);
        let submit = db.get_decision(&submitted).unwrap().expect("submit record");
        assert_eq!(submit.outcome, STATUS_PARKED);
        assert_eq!((submit.actor.as_str(), submit.timestamp), ("alice", 10));
        assert!(
            db.get_decision(&format!("{}:decide", parked.operation_id))
                .unwrap()
                .is_some()
        );
        // The decision keeps the marker, so replays never rebuild the submit
        // from the granted instance.
        assert_eq!(
            db.get_action_instance(&parked.instance_id)
                .unwrap()
                .unwrap()
                .admission_lease
                .unwrap()
                .follow_ups_recorded,
            Some(true)
        );
        let replay = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-11","title":"t"}"#,
        );
        assert!(admission.admit(replay, "alice", 30).unwrap().replay);
        assert!(
            admission
                .decide(
                    decision(&parked.instance_id, DECISION_GRANT, "bob"),
                    "bob",
                    31,
                )
                .unwrap()
                .replay
        );
    }

    #[test]
    fn a_parked_instance_names_its_rule_and_approvers_in_the_audit_record() {
        let db = approval_setup("create", &["bob", "carol"]);
        let mut policy = db.get_action_policy("acme").unwrap().unwrap();
        policy.action_overrides.insert(
            SUBMIT_POLICY_ACTION.into(),
            crate::sekai::action_policy::ActionDecision::RequireApproval,
        );
        db.upsert_action_policy(&policy).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let parked = admission
            .admit(
                record_request("customer.record.create", r#"{"object_id":"rec-13"}"#),
                "alice",
                10,
            )
            .unwrap()
            .instance;
        let expected = ApprovalRequirement {
            policy_scope: "acme".into(),
            rule: "action_override:submit_action_instance".into(),
            approvers: vec!["bob".into(), "carol".into()],
            approver_role: String::new(),
        };
        assert_eq!(parked.approval.as_ref(), Some(&expected));
        let stored = db
            .get_action_instance(&parked.instance_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.approval.as_ref(), Some(&expected));

        let receipt = db
            .get_operation_receipt("operation-record")
            .unwrap()
            .unwrap();
        let policy_event = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::PolicyDecided)
            .unwrap();
        let parked_record = db
            .list_decisions(&audit::DecisionFilter {
                target_id: Some(parked.instance_id.clone()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|decision| decision.reason == "action_instance_parked")
            .unwrap();
        let policy_attributes: HashMap<String, String> =
            policy_event.attributes.clone().into_iter().collect();
        for attributes in [&policy_attributes, &parked_record.evidence] {
            assert_eq!(attributes["approval_policy_scope"], "acme");
            assert_eq!(
                attributes["approval_rule"],
                "action_override:submit_action_instance"
            );
            assert_eq!(attributes["approvers"], "bob,carol");
            assert!(!attributes.contains_key("approver_role"));
        }

        // The decision keeps what required it.
        let granted = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                20,
            )
            .unwrap()
            .instance;
        assert_eq!(granted.status, STATUS_ADMITTED);
        assert_eq!(granted.approval, Some(expected));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_require_approval_parks_lists_and_a_named_approver_grants() {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let namespace = format!("ns-1314-{suffix}");
        let object_id = format!("rec-1314-{suffix}");
        let type_id = format!("customer.record.create.{suffix}");
        let db = postgres_runtime();
        ensure_record_kind(&db);
        let mut type_def = record_type("create");
        type_def.namespace = namespace.clone();
        type_def.type_id = type_id.clone();
        type_def.approvers = vec!["bob".into()];
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all(&namespace);
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut request = record_request(
            &type_id,
            &format!(r#"{{"object_id":"{object_id}","title":"t"}}"#),
        );
        request.namespace = namespace.clone();
        request.idempotency_key = format!("record-1314-{suffix}");
        request.request_id = format!("operation-1314-{suffix}");
        let parked = admission
            .admit(request.clone(), "alice", 10)
            .unwrap()
            .instance;
        assert_eq!(parked.status, STATUS_PARKED);
        let inbox = db
            .list_action_instances(&namespace, None, Some(STATUS_PARKED), 10)
            .unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].instance_id, parked.instance_id);
        assert_eq!(inbox[0].approval, parked.approval);
        assert_eq!(
            parked
                .approval
                .as_ref()
                .map(|approval| approval.rule.as_str()),
            Some("default_decision")
        );
        for principal in ["alice", "carol"] {
            let error = admission
                .decide(
                    decision(&parked.instance_id, DECISION_GRANT, principal),
                    principal,
                    20,
                )
                .unwrap_err();
            assert_eq!(
                error,
                ActionInstanceAdmissionError::PermissionDenied(DECISION_ACCESS_DENIED.into())
            );
        }
        let granted = admission
            .decide(
                decision(&parked.instance_id, DECISION_GRANT, "bob"),
                "bob",
                30,
            )
            .unwrap();
        assert!(!granted.replay);
        assert_eq!(granted.instance.status, STATUS_ADMITTED);
        assert_eq!(granted.instance.decided_by, "bob");
        assert!(db.get_object(&object_id).unwrap().is_some());
        let receipt = db
            .get_operation_receipt(&request.request_id)
            .unwrap()
            .unwrap();
        assert!(receipt.completed_at_ms.is_some());
        assert!(receipt.events.iter().any(|event| {
            event.kind == ReceiptEventKind::ApprovalDecided && event.actor == "bob"
        }));
        assert!(
            db.list_action_instances(&namespace, None, Some(STATUS_PARKED), 10)
                .unwrap()
                .is_empty()
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
        let approval = parked.approval.as_ref().unwrap();
        assert!(approval.approvers.is_empty());
        assert_eq!(
            approval.approver_role,
            crate::sekai::action_instance::APPROVER_ROLE_NAMESPACE_ADMIN
        );
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
                None,
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
                None,
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
            review: Default::default(),
            instance_id: "gai-incomplete".into(),
            namespace: "acme".into(),
            type_id: "customer.record.create".into(),
            version: "1".into(),
            delegating_actor: None,
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
            agent_action: false,
            admission_tenant: String::new(),
            resource_tenant: String::new(),
            marking: String::new(),
            conflict: None,
            approval: None,
            offline: None,
            admission_lease: None,
            admission_ontology_digest: None,
            admission_budget_already_reserved: false,
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

    /// Red and blue tenants with one alliance space whose approval a test
    /// can withdraw. Blue owns the `blue` namespace.
    struct AllianceExtension {
        allied: std::sync::Mutex<bool>,
    }

    impl crate::enterprise::EnterpriseExtension for AllianceExtension {
        fn authenticate_bearer(
            &self,
            _: &str,
        ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError>
        {
            Err(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn authenticate_context(
            &self,
            _: &str,
        ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError>
        {
            Err(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn tenant_context(
            &self,
            _: &crate::enterprise::AuthenticatedPrincipal,
        ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::Unauthenticated)
        }

        fn authorize_namespace(
            &self,
            _: &crate::enterprise::TenantContext,
            _: &str,
            _: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            Ok(())
        }

        fn authorize_unscoped_namespace(
            &self,
            _: &crate::enterprise::AuthenticatedPrincipal,
            _: &str,
            _: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::PermissionDenied)
        }

        fn tenants_share_space(
            &self,
            acting_tenant: &str,
            target_namespace: &str,
        ) -> Result<crate::enterprise::TenantSharing, crate::enterprise::ExtensionError> {
            let owner_tenant = if target_namespace == "blue" {
                "blue"
            } else {
                "red"
            };
            Ok(crate::enterprise::TenantSharing {
                owner_tenant: owner_tenant.into(),
                shared: acting_tenant == "red"
                    && owner_tenant == "blue"
                    && *self.allied.lock().unwrap(),
            })
        }
    }

    /// An extension that implements only the required methods.
    struct NoSharingLookup;

    impl crate::enterprise::EnterpriseExtension for NoSharingLookup {
        fn authenticate_bearer(
            &self,
            _: &str,
        ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError>
        {
            Err(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn authenticate_context(
            &self,
            _: &str,
        ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError>
        {
            Err(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn tenant_context(
            &self,
            _: &crate::enterprise::AuthenticatedPrincipal,
        ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::Unauthenticated)
        }

        fn authorize_namespace(
            &self,
            _: &crate::enterprise::TenantContext,
            _: &str,
            _: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            Ok(())
        }

        fn authorize_unscoped_namespace(
            &self,
            _: &crate::enterprise::AuthenticatedPrincipal,
            _: &str,
            _: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::PermissionDenied)
        }
    }

    /// An installed extension that has not implemented the sharing lookup
    /// fails closed instead of reporting unshared (#1860).
    #[test]
    fn an_extension_without_the_sharing_lookup_fails_closed() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(
            crate::db::sekai::SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(std::sync::Arc::new(NoSharingLookup)),
            )
            .unwrap(),
        ));
        ensure_record_kind(&db);
        db.create_object(&crate::domain::Object {
            id: "planet-blue".into(),
            kind: "customer_record".into(),
            name: "Blue planet".into(),
            namespace: "blue".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let mut type_def = record_type("create");
        type_def.parameter_schema_json = r#"{"type":"object","properties":{"object_id":{"type":"string"},"target_id":{"type":"string"}},"required":["object_id","target_id"],"additionalProperties":false}"#.into();
        type_def.submission_criteria = vec![
            crate::sekai::action_type_criteria::ActionSubmissionCriterion {
                criterion_id: "not_allied".into(),
                kind: crate::sekai::action_type_criteria::CRITERION_KIND_SHARES_NO_SPACE.into(),
                property: "target_id".into(),
                value: String::new(),
            },
        ];
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let refused = ActionInstanceAdmission::new(&db, None)
            .with_tenant("red")
            .admit(
                record_request(
                    "customer.record.create",
                    r#"{"object_id":"attack-1","target_id":"planet-blue"}"#,
                ),
                "alice",
                10,
            )
            .unwrap();
        assert_eq!(refused.instance.status, STATUS_DENIED);
        assert_eq!(refused.instance.deny_reason, CRITERION_UNAVAILABLE);
    }

    /// An Action against an allied tenant's object is denied while the
    /// tenants share an approved space, and admitted after the space is
    /// withdrawn, with no property sync on the target (#1860).
    #[test]
    fn sharing_criterion_follows_the_live_alliance() {
        let extension = std::sync::Arc::new(AllianceExtension {
            allied: std::sync::Mutex::new(true),
        });
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(
            crate::db::sekai::SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(extension.clone()),
            )
            .unwrap(),
        ));
        ensure_record_kind(&db);
        db.create_object(&crate::domain::Object {
            id: "planet-blue".into(),
            kind: "customer_record".into(),
            name: "Blue planet".into(),
            namespace: "blue".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let mut type_def = record_type("create");
        type_def.parameter_schema_json = r#"{"type":"object","properties":{"object_id":{"type":"string"},"target_id":{"type":"string"}},"required":["object_id","target_id"],"additionalProperties":false}"#.into();
        type_def.submission_criteria = vec![
            crate::sekai::action_type_criteria::ActionSubmissionCriterion {
                criterion_id: "not_allied".into(),
                kind: crate::sekai::action_type_criteria::CRITERION_KIND_SHARES_NO_SPACE.into(),
                property: "target_id".into(),
                value: String::new(),
            },
        ];
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None).with_tenant("red");
        let attack = |object_id: &str, key: &str| {
            let mut request = record_request(
                "customer.record.create",
                &format!(r#"{{"object_id":"{object_id}","target_id":"planet-blue"}}"#),
            );
            request.idempotency_key = key.into();
            request.request_id = format!("operation-{key}");
            request
        };
        let denied = admission
            .admit(attack("attack-1", "attack-1"), "alice", 10)
            .unwrap();
        assert_eq!(denied.instance.status, STATUS_DENIED);
        assert_eq!(denied.instance.deny_reason, "not_allied");
        assert!(db.get_object("attack-1").unwrap().is_none());

        *extension.allied.lock().unwrap() = false;
        let admitted = admission
            .admit(attack("attack-2", "attack-2"), "alice", 20)
            .unwrap();
        assert_eq!(admitted.instance.status, STATUS_ADMITTED);
        assert!(db.get_object("attack-2").unwrap().is_some());
        let planet = db.get_object("planet-blue").unwrap().unwrap();
        assert!(
            planet.properties.is_empty(),
            "no property sync on the target"
        );

        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some(SHARING_CRITERION_DECISION.into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 2);
        assert!(decisions.iter().all(|decision| {
            decision.evidence.get("owner_tenant").map(String::as_str) == Some("blue")
                && decision.target_id == "planet-blue"
        }));

        // A target that does not exist fails closed.
        let mut missing = attack("attack-3", "attack-3");
        missing.parameters_json = r#"{"object_id":"attack-3","target_id":"nowhere"}"#.into();
        let refused = admission.admit(missing, "alice", 30).unwrap();
        assert_eq!(refused.instance.deny_reason, CRITERION_UNAVAILABLE);
    }

    /// Backdates the reservation's lease for `key`, as if its admission had
    /// stalled past the lease (#1931).
    fn expire_reservation(db: &RuntimeDb, key: &str) {
        let mut stored = db
            .get_action_instance_by_idempotency("acme", key)
            .unwrap()
            .expect("reservation");
        let lease = stored.admission_lease.as_mut().expect("leased reservation");
        lease.expires_at_ms = crate::sekai::action_instance::lease_clock_ms() - 1;
        db.delete_action_instance(&stored.instance_id).unwrap();
        db.put_action_instance(&stored).unwrap();
    }

    /// The Action instances that wrote `object_id`, from its change rows.
    fn writers(db: &RuntimeDb, object_id: &str) -> std::collections::BTreeSet<String> {
        db.list_object_changes(object_id, 1_000, 0)
            .unwrap()
            .into_iter()
            .filter(|change| change.writer_kind == crate::sekai::audit::WRITER_ACTION_INSTANCE)
            .map(|change| change.writer_ref)
            .collect()
    }

    /// A process that dies after the reservation, or after the object write,
    /// leaves a key a resubmit recovers once its lease expires: exactly one
    /// applied write and one receipt. A live admission is left alone (#1931).
    fn abandoned_admissions_recover_exactly_once(db: &RuntimeDb) {
        ensure_record_kind(db);
        let _ = db.put_governed_action_type(record_type("create"), "operator", 1);
        let admission = ActionInstanceAdmission::new(db, None);
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let request = |object_id: &str, key: &str| {
            let mut request = record_request(
                "customer.record.create",
                &format!(r#"{{"object_id":"{object_id}","name":"Recovered"}}"#),
            );
            request.idempotency_key = key.into();
            request.request_id = format!("operation-{key}");
            request
        };

        // Crash after the reservation: nothing landed.
        let (object, key) = (format!("rec-res-{suffix}"), format!("res-{suffix}"));
        crash_next_admission(CrashPoint::AfterReservation);
        assert!(
            admission
                .admit(request(&object, &key), "alice", 10)
                .is_err()
        );
        let live = admission
            .admit(request(&object, &key), "alice", 11)
            .unwrap_err();
        assert!(
            matches!(&live, ActionInstanceAdmissionError::FailedPrecondition(message)
                if message.contains("still in progress")),
            "a live reservation is left alone: {live:?}"
        );
        expire_reservation(db, &key);
        let recovered = admission
            .admit(request(&object, &key), "alice", 12)
            .unwrap();
        assert_eq!(recovered.instance.status, STATUS_ADMITTED);
        assert!(db.get_object(&object).unwrap().is_some());
        assert!(
            db.get_operation_receipt(&recovered.instance.operation_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(writers(db, &object).len(), 1);

        // Crash after the object write: the receipt is repaired, not the
        // write repeated.
        let (object, key) = (format!("rec-obj-{suffix}"), format!("obj-{suffix}"));
        crash_next_admission(CrashPoint::AfterObjectWrite);
        assert!(
            admission
                .admit(request(&object, &key), "alice", 20)
                .is_err()
        );
        let abandoned = db
            .get_action_instance_by_idempotency("acme", &key)
            .unwrap()
            .expect("reservation");
        assert!(db.get_object(&object).unwrap().is_some());
        assert!(
            db.get_operation_receipt(&abandoned.operation_id)
                .unwrap()
                .is_none()
        );
        expire_reservation(db, &key);
        let repaired = admission
            .admit(request(&object, &key), "alice", 21)
            .unwrap();
        assert_eq!(repaired.instance.instance_id, abandoned.instance_id);
        assert_eq!(repaired.instance.admission_lease.unwrap().generation, 2);
        assert!(
            db.get_operation_receipt(&abandoned.operation_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            writers(db, &object),
            std::collections::BTreeSet::from([abandoned.instance_id.clone()])
        );
        // A later resubmit is a plain replay.
        let replay = admission
            .admit(request(&object, &key), "alice", 22)
            .unwrap();
        assert!(replay.replay);
        assert_eq!(writers(db, &object).len(), 1);

        // Crash after the object write, then the object is deleted: the
        // receipt is still repaired and the object is not created again.
        let (object, key) = (format!("rec-del-{suffix}"), format!("del-{suffix}"));
        crash_next_admission(CrashPoint::AfterObjectWrite);
        assert!(
            admission
                .admit(request(&object, &key), "alice", 30)
                .is_err()
        );
        let abandoned = db
            .get_action_instance_by_idempotency("acme", &key)
            .unwrap()
            .expect("reservation");
        db.delete_object_with_audit(&object, "operator").unwrap();
        expire_reservation(db, &key);
        let repaired = admission
            .admit(request(&object, &key), "alice", 31)
            .unwrap();
        assert_eq!(repaired.instance.instance_id, abandoned.instance_id);
        assert!(
            db.get_operation_receipt(&abandoned.operation_id)
                .unwrap()
                .is_some()
        );
        assert!(db.get_object(&object).unwrap().is_none(), "not resurrected");
    }

    /// A crash after the receipt leaves its follow-ups to the resubmit,
    /// which records the decision, the budget charge and the effects
    /// exactly once (#1943).
    fn follow_ups_after_the_receipt_are_finished_exactly_once(db: &RuntimeDb) {
        let budget = CountingBudget {
            remaining: std::sync::atomic::AtomicI32::new(10),
            recorded: std::sync::atomic::AtomicI32::new(0),
            keys: Default::default(),
        };
        let admission = ActionInstanceAdmission::new(db, Some(&budget));
        // A namespace of its own: the PostgreSQL test database is shared.
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let namespace = format!("after-receipt-{suffix}");
        db.put_governed_action_type(dispatch_type(&namespace), "operator", 1)
            .unwrap();
        let key = format!("after-receipt-{suffix}");
        let submit = || {
            let mut submit = request(r#"{"runtime":"shikigami"}"#);
            submit.namespace = namespace.clone();
            submit.idempotency_key = key.clone();
            submit
        };
        let decisions = |instance_id: &str| {
            db.list_decisions(&crate::sekai::audit::DecisionFilter {
                target_id: Some(instance_id.into()),
                limit: 50,
                ..Default::default()
            })
            .unwrap()
        };
        let recorded = || budget.recorded.load(std::sync::atomic::Ordering::SeqCst);

        crash_next_admission(CrashPoint::AfterReceipt);
        assert!(admission.admit(submit(), "alice", 10).is_err());
        let stored = db
            .get_action_instance_by_idempotency(&namespace, &key)
            .unwrap()
            .expect("instance");
        assert!(
            db.get_operation_receipt(&stored.operation_id)
                .unwrap()
                .is_some()
        );
        assert!(decisions(&stored.instance_id).is_empty());
        assert!(
            db.list_action_effects_for_instance(&stored.instance_id)
                .unwrap()
                .is_empty()
        );
        assert_eq!(recorded(), 0);
        assert_eq!(
            stored.admission_lease.as_ref().unwrap().follow_ups_recorded,
            Some(false)
        );

        // A replay without the budget port that allowed the charge leaves
        // the follow-ups outstanding rather than dropping the charge.
        assert!(
            ActionInstanceAdmission::new(db, None)
                .admit(submit(), "bob", 15)
                .is_err()
        );
        assert_eq!(recorded(), 0);
        assert_eq!(
            db.get_action_instance(&stored.instance_id)
                .unwrap()
                .unwrap()
                .admission_lease
                .unwrap()
                .follow_ups_recorded,
            Some(false)
        );

        for now in [20, 30] {
            let replayed = admission.admit(submit(), "bob", now).unwrap();
            assert!(replayed.replay);
            let recorded_decisions = decisions(&stored.instance_id);
            assert_eq!(recorded_decisions.len(), 1);
            let decision = &recorded_decisions[0];
            assert_eq!(decision.id, format!("{}:submit", stored.operation_id));
            assert_eq!((decision.actor.as_str(), decision.timestamp), ("alice", 10));
            assert_eq!(
                db.list_action_effects_for_instance(&stored.instance_id)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(recorded(), 1);
        }
        let finished = db
            .get_action_instance(&stored.instance_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            finished.admission_lease.unwrap().follow_ups_recorded,
            Some(true)
        );
    }

    /// A crash after an approver's decision receipt leaves its follow-ups
    /// to the replayed decision, which records the decide record, the
    /// effects and the charge exactly once (#1948).
    fn decision_follow_ups_are_finished_exactly_once(db: &RuntimeDb) {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let namespace = format!("decided-{suffix}");
        let mut type_def = dispatch_type(&namespace);
        type_def.approvers = vec!["bob".into()];
        db.put_governed_action_type(type_def, "operator", 1)
            .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all(&namespace);
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        db.upsert_action_policy(&policy).unwrap();
        let mut submit = request(r#"{"runtime":"shikigami"}"#);
        submit.namespace = namespace.clone();
        submit.idempotency_key = format!("decided-{suffix}");
        // Parked without a budget port: the charge is deferred to the grant.
        let parked = ActionInstanceAdmission::new(db, None)
            .admit(submit, "alice", 10)
            .unwrap()
            .instance;
        assert_eq!(parked.status, STATUS_PARKED);

        let budget = CountingBudget {
            remaining: std::sync::atomic::AtomicI32::new(10),
            recorded: std::sync::atomic::AtomicI32::new(0),
            keys: Default::default(),
        };
        let admission = ActionInstanceAdmission::new(db, Some(&budget));
        let decide_id = format!("{}:decide", parked.operation_id);
        let recorded = || budget.recorded.load(std::sync::atomic::Ordering::SeqCst);
        let effects = || {
            db.list_action_effects_for_instance(&parked.instance_id)
                .unwrap()
                .len()
        };
        crash_next_admission(CrashPoint::AfterReceipt);
        assert!(
            admission
                .decide(
                    decision(&parked.instance_id, DECISION_GRANT, "bob"),
                    "bob",
                    20
                )
                .is_err()
        );
        let decided = db
            .get_action_instance(&parked.instance_id)
            .unwrap()
            .unwrap();
        assert_eq!(decided.status, STATUS_ADMITTED);
        assert_eq!(
            decided
                .admission_lease
                .as_ref()
                .unwrap()
                .decision_follow_ups_recorded,
            Some(false)
        );
        assert!(db.get_decision(&decide_id).unwrap().is_none());
        assert_eq!((effects(), recorded()), (0, 0));

        for now in [30, 40] {
            let replayed = admission
                .decide(
                    decision(&parked.instance_id, DECISION_GRANT, "bob"),
                    "bob",
                    now,
                )
                .unwrap();
            assert!(replayed.replay);
            let record = db.get_decision(&decide_id).unwrap().expect("decide record");
            assert_eq!((record.actor.as_str(), record.timestamp), ("bob", 20));
            assert_eq!((effects(), recorded()), (1, 1));
        }
        let finished = db
            .get_action_instance(&parked.instance_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            finished
                .admission_lease
                .unwrap()
                .decision_follow_ups_recorded,
            Some(true)
        );
    }

    #[test]
    fn sqlite_decision_follow_ups_are_finished_exactly_once() {
        decision_follow_ups_are_finished_exactly_once(&setup());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL test database"]
    fn postgres_decision_follow_ups_are_finished_exactly_once() {
        decision_follow_ups_are_finished_exactly_once(&postgres_runtime());
    }

    #[test]
    fn sqlite_follow_ups_after_the_receipt_are_finished_exactly_once() {
        follow_ups_after_the_receipt_are_finished_exactly_once(&setup());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL test database"]
    fn postgres_follow_ups_after_the_receipt_are_finished_exactly_once() {
        follow_ups_after_the_receipt_are_finished_exactly_once(&postgres_runtime());
    }

    /// An admission that finished in one pass needs no resume: its lease
    /// says its follow-ups are recorded (#1943).
    #[test]
    fn a_finished_admission_marks_its_follow_ups_recorded() {
        let db = setup();
        let admitted = ActionInstanceAdmission::new(&db, None)
            .admit(request(r#"{"runtime":"shikigami"}"#), "alice", 10)
            .unwrap();
        let stored = db
            .get_action_instance(&admitted.instance.instance_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.admission_lease.unwrap().follow_ups_recorded,
            Some(true)
        );
    }

    #[test]
    fn sqlite_abandoned_admissions_recover_exactly_once() {
        abandoned_admissions_recover_exactly_once(&setup());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL test database"]
    fn postgres_abandoned_admissions_recover_exactly_once() {
        abandoned_admissions_recover_exactly_once(&postgres_runtime());
    }

    /// A landed write is finished even after the type was disabled, and the
    /// repaired receipt names the original submitter, not the retrying actor
    /// (#1931).
    #[test]
    fn a_landed_write_is_finished_as_its_submitter_after_the_type_is_disabled() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut request = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-disabled","name":"Recovered"}"#,
        );
        request.idempotency_key = "disabled-key".into();
        request.request_id = "operation-disabled-key".into();
        crash_next_admission(CrashPoint::AfterObjectWrite);
        assert!(admission.admit(request.clone(), "alice", 10).is_err());
        db.set_governed_action_type_enabled("acme", "customer.record.create", "1", false, 11)
            .unwrap();
        expire_reservation(&db, "disabled-key");
        // The retry names another ontology; the receipt keeps the original.
        request.ontology_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        let repaired = admission.admit(request, "bob", 12).unwrap();
        assert_eq!(repaired.instance.principal, "alice");
        let receipt = db
            .get_operation_receipt("operation-disabled-key")
            .unwrap()
            .expect("repaired receipt");
        assert_eq!(receipt.initiating_actor, "alice");
        assert_eq!(receipt.ontology_digest.as_deref(), Some(ONTOLOGY_DIGEST));
        assert_eq!(writers(&db, "rec-disabled").len(), 1);
    }

    /// An update that changes no field still commits: the commit marker, not
    /// a change row, tells the takeover to repair its receipt instead of
    /// admitting it again (#1931).
    #[test]
    fn a_no_change_update_is_recovered_without_reapplying() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("update"), "operator", 1)
            .unwrap();
        db.create_object(&crate::domain::Object {
            id: "rec-same".into(),
            kind: "customer_record".into(),
            name: "Same".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut request = record_request(
            "customer.record.update",
            r#"{"object_id":"rec-same","name":"Same"}"#,
        );
        request.idempotency_key = "same-key".into();
        request.request_id = "operation-same-key".into();
        crash_next_admission(CrashPoint::AfterObjectWrite);
        assert!(admission.admit(request.clone(), "alice", 10).is_err());
        let abandoned = db
            .get_action_instance_by_idempotency("acme", "same-key")
            .unwrap()
            .expect("reservation");
        assert_eq!(
            abandoned.admission_lease.as_ref().unwrap().write_committed,
            Some(true)
        );
        expire_reservation(&db, "same-key");
        let repaired = admission.admit(request, "alice", 11).unwrap();
        assert!(repaired.replay);
        assert_eq!(repaired.instance.instance_id, abandoned.instance_id);
        assert!(
            db.get_operation_receipt("operation-same-key")
                .unwrap()
                .is_some()
        );
    }

    /// A lease an older binary wrote carries no markers: after expiry it is
    /// still not taken over, since nothing records whether its write
    /// committed (#1931).
    #[test]
    fn a_lease_without_markers_is_never_taken_over() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut request = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-legacy","name":"Legacy"}"#,
        );
        request.idempotency_key = "legacy-key".into();
        request.request_id = "operation-legacy-key".into();
        crash_next_admission(CrashPoint::AfterObjectWrite);
        assert!(admission.admit(request.clone(), "alice", 10).is_err());
        let mut stored = db
            .get_action_instance_by_idempotency("acme", "legacy-key")
            .unwrap()
            .unwrap();
        let lease = stored.admission_lease.as_mut().unwrap();
        lease.write_committed = None;
        lease.receipt_recorded = None;
        lease.expires_at_ms = crate::sekai::action_instance::lease_clock_ms() - 1;
        db.delete_action_instance(&stored.instance_id).unwrap();
        db.put_action_instance(&stored).unwrap();
        let refused = admission.admit(request, "alice", 11).unwrap_err();
        assert!(
            matches!(&refused, ActionInstanceAdmissionError::FailedPrecondition(message)
                if message.contains("still in progress")),
            "{refused:?}"
        );
        assert!(db.get_object("rec-legacy").unwrap().is_some());
    }

    /// A later edit by another writer is not the committed write: the
    /// receipt is repaired, but the edited state is not attributed to it or
    /// written again (#1931). (An audited delete never frees an id for a
    /// replacement: the store refuses to reuse it.)
    #[test]
    fn a_later_edit_is_not_attributed_to_the_recovery() {
        let db = setup();
        ensure_record_kind(&db);
        db.put_governed_action_type(record_type("create"), "operator", 1)
            .unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let mut request = record_request(
            "customer.record.create",
            r#"{"object_id":"rec-edited","name":"Original"}"#,
        );
        request.idempotency_key = "edited-key".into();
        request.request_id = "operation-edited-key".into();
        crash_next_admission(CrashPoint::AfterObjectWrite);
        assert!(admission.admit(request.clone(), "alice", 10).is_err());
        let abandoned = db
            .get_action_instance_by_idempotency("acme", "edited-key")
            .unwrap()
            .unwrap();
        let mut edited = db.get_object("rec-edited").unwrap().unwrap();
        // The edit keeps the same `updated`: only the state digest tells it
        // apart from the committed write.
        edited.name = "Edited".into();
        db.update_object(&edited).unwrap();
        expire_reservation(&db, "edited-key");
        let repaired = admission.admit(request, "alice", 60).unwrap();
        assert_eq!(repaired.instance.instance_id, abandoned.instance_id);
        assert!(
            repaired.object_revision.is_none(),
            "the edit is not the write"
        );
        assert!(
            db.get_operation_receipt("operation-edited-key")
                .unwrap()
                .is_some()
        );
        assert_eq!(db.get_object("rec-edited").unwrap().unwrap().name, "Edited");
    }
}

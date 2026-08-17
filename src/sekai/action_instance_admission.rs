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
    ActionInstance, STATUS_ADMITTED, STATUS_DENIED, SUBMIT_POLICY_ACTION, compute_request_digest,
    submit_budget_subject, validate_parameters_json,
};
use crate::sekai::{action_effect, action_policy, audit};
use std::collections::{BTreeMap, HashMap};

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
}

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
    Internal(String),
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

        let mut evidence_ids = request.evidence_submission_ids;
        evidence_ids.sort();
        evidence_ids.dedup();
        if evidence_ids.iter().any(|id| id.trim().is_empty()) {
            return Err(ActionInstanceAdmissionError::InvalidArgument(
                "evidence_submission_ids must not contain empty ids".into(),
            ));
        }
        let request_digest = compute_request_digest(
            &namespace,
            &request.type_id,
            &request.version,
            &request.parameters_json,
            &evidence_ids,
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
            return Ok(ActionInstanceAdmissionOutcome {
                instance: existing,
                replay: true,
            });
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
        if policy_decision == action_policy::ActionDecision::Deny {
            status = STATUS_DENIED.into();
            deny_reason = if policy_scope_label.is_empty() {
                "action policy denied submit_action_instance".into()
            } else {
                format!("action policy denied submit_action_instance ({policy_scope_label})")
            };
        } else if policy_decision == action_policy::ActionDecision::RequireApproval {
            status = STATUS_DENIED.into();
            deny_reason = "submit_action_instance requires approval (not yet supported)".into();
            policy_decision_text = "require_approval".into();
        }

        let budget_subject = submit_budget_subject(&namespace, actor, &type_def.budget_scope);
        if status == STATUS_ADMITTED
            && let Some(budget) = self.budget
            && budget.check(&budget_subject, 1).is_err()
        {
            status = STATUS_DENIED.into();
            deny_reason = format!("action budget exhausted for {budget_subject}");
            budget_decision = "budget_exceeded".into();
        }

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
                    &type_def.allowed_effect_kinds,
                    &instance.parameters_json,
                    now,
                    force_notify_fail,
                )
                .map_err(ActionInstanceAdmissionError::InvalidArgument)?,
            )
        } else {
            None
        };

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
        if !replay {
            self.record_admission(
                &stored,
                actor,
                &policy_scope_label,
                &budget_subject,
                &evidence_ids,
                planned_effects.as_deref(),
                ontology_digest,
                now,
            )?;
        }
        Ok(ActionInstanceAdmissionOutcome {
            instance: stored,
            replay,
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
        ontology_digest: Option<String>,
        now: i64,
    ) -> Result<(), ActionInstanceAdmissionError> {
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
        let mut outcome_attributes = BTreeMap::from([(
            "outcome".into(),
            if stored.status == STATUS_ADMITTED {
                "admitted".into()
            } else {
                "denied".into()
            },
        )]);
        if !stored.deny_reason.is_empty() {
            outcome_attributes.insert("deny_reason".into(), stored.deny_reason.clone());
        }
        // Denied admits never plan effects. Gate on admitted status so a
        // terminal denial cannot stay incomplete if a planner later passes
        // leftover pending dispatch.
        let await_runtime_dispatch = stored.status == STATUS_ADMITTED
            && has_pending_runtime_dispatch(planned_effects);
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
        let completed_at_ms = if await_runtime_dispatch {
            None
        } else {
            events.push(event(
                "outcome",
                Some(format!("{operation_id}:budget")),
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
            started_at_ms: now,
            completed_at_ms,
            events,
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest,
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
        if !stored.deny_reason.is_empty() {
            evidence.insert("deny_reason".into(), stored.deny_reason.clone());
        }
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                actor: actor.to_string(),
                action: "submit_action_instance".into(),
                reason: if stored.status == STATUS_ADMITTED {
                    "action_instance_admitted".into()
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
            if let Some(budget) = self.budget {
                budget.record(budget_subject, 1);
            }
            let effects = planned_effects.ok_or_else(|| {
                ActionInstanceAdmissionError::Internal("admitted instance effects missing".into())
            })?;
            self.db
                .put_action_effects(effects)
                .map_err(ActionInstanceAdmissionError::Internal)?;
        }
        Ok(())
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
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
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
        }
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
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
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
}

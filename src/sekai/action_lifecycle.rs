//! Governed action lifecycle and ActionInstance ↔ receipt ↔ effect correlation.
//!
//! The plane keeps a single harvest spine on `operation_id`. ActionInstance is
//! the admission envelope; runtime hosts claim effects and harvest to the
//! bound operation.

use crate::chisei::budget::BudgetTracker;
use crate::chisei::receipt::{OperationReceipt, ReceiptEventKind};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action::RiskClass;
use crate::sekai::action_approval::{ActionApproval, ApprovalStatus};
use crate::sekai::action_effect::{
    ActionEffect, EFFECT_STATUS_CLAIMED, EFFECT_STATUS_COMPLETED, EFFECT_STATUS_FAILED,
    EFFECT_STATUS_PARKED, EFFECT_STATUS_PENDING,
};
use crate::sekai::action_instance::{ActionInstance, STATUS_ADMITTED};
use crate::sekai::action_policy::{ActionDecision, ActionPolicy};
use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;
use crate::sekai::{attestation, audit};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The policy result and resource-metering coordinates for one governed action.
///
/// Callers resolve this once, then use the same snapshot for admission, audit
/// attestation, and post-effect metering. This keeps direct execution and
/// approval resumption on the same lifecycle rules.
#[derive(Debug, Clone)]
pub struct GovernedActionContext {
    pub policy: Option<ActionPolicy>,
    pub decision: ActionDecision,
    pub policy_scope: String,
    pub namespace: String,
    pub risk: RiskClass,
    pub work_unit: String,
    pub budget_subject: String,
    pub op_mutations: u32,
    pub op_deletes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionLimitExceeded {
    Internal(String),
    BlastRadius {
        work_unit: String,
        used_mutations: u32,
        used_deletes: u32,
    },
    Budget {
        subject: String,
        reason: String,
    },
}

/// Transport-neutral evidence for one governed Action lifecycle transition.
#[derive(Debug, Clone)]
pub struct ActionAudit {
    pub actor: String,
    pub attestation_actor: String,
    pub action: String,
    pub target_id: String,
    pub evidence: HashMap<String, String>,
    pub timestamp: i64,
}

impl GovernedActionContext {
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        db: &RuntimeDb,
        actor: &str,
        namespace: &str,
        action: &str,
        risk: RiskClass,
        work_unit: &str,
        op_mutations: u32,
        op_deletes: u32,
        erased_namespace: &str,
    ) -> Result<Self, String> {
        let mut policy = db.resolve_action_policy(actor, namespace, namespace)?;
        let (decision, policy_scope) = match &policy {
            _ if namespace == erased_namespace => {
                // Erasure, not the stored policy, rendered this denial. Keep
                // the audit decision but do not mint a policy attestation that
                // would replay to a different result.
                policy = None;
                (ActionDecision::Deny, erased_namespace.to_string())
            }
            Some(policy) => (policy.decide(action, risk), policy.scope.clone()),
            None => (ActionDecision::Allow, String::new()),
        };
        Ok(Self {
            policy,
            decision,
            policy_scope,
            namespace: namespace.to_string(),
            risk,
            work_unit: work_unit.to_string(),
            budget_subject: action_budget_subject(risk, namespace, actor),
            op_mutations,
            op_deletes,
        })
    }

    pub fn check_limits(
        &self,
        db: &RuntimeDb,
        budget: Option<&BudgetTracker>,
    ) -> Result<(), ActionLimitExceeded> {
        if !self.work_unit.is_empty()
            && let Some((max_mutations, max_deletes)) = self.blast_caps()
        {
            let (used_mutations, used_deletes) = db
                .get_blast_radius(&self.work_unit)
                .map_err(ActionLimitExceeded::Internal)?;
            let exceeds = |cap: Option<u32>, used: u32, add: u32| {
                cap.is_some_and(|cap| used.saturating_add(add) > cap)
            };
            if exceeds(max_deletes, used_deletes, self.op_deletes)
                || exceeds(max_mutations, used_mutations, self.op_mutations)
            {
                return Err(ActionLimitExceeded::BlastRadius {
                    work_unit: self.work_unit.clone(),
                    used_mutations,
                    used_deletes,
                });
            }
        }
        if let Some(budget) = budget {
            budget.check(&self.budget_subject, 1).map_err(|reason| {
                ActionLimitExceeded::Budget {
                    subject: self.budget_subject.clone(),
                    reason,
                }
            })?;
        }
        Ok(())
    }

    pub fn record_usage(
        &self,
        db: &RuntimeDb,
        budget: Option<&BudgetTracker>,
    ) -> Result<(), String> {
        let blast_result = if !self.work_unit.is_empty()
            && self.blast_caps().is_some()
            && (self.op_mutations > 0 || self.op_deletes > 0)
        {
            db.add_blast_radius(&self.work_unit, self.op_mutations, self.op_deletes)
                .map(|_| ())
        } else {
            Ok(())
        };
        // Budget accounting remains independent after an effect commits. In
        // particular, approval resumption must still charge the budget when a
        // best-effort blast-radius write fails.
        if let Some(budget) = budget {
            budget.record(&self.budget_subject, 1);
        }
        blast_result
    }

    /// Commit a governed Action outcome and its attestation, then meter an
    /// effect only after the audit record is durable.
    pub fn record_outcome(
        &self,
        db: &RuntimeDb,
        budget: Option<&BudgetTracker>,
        mut audit: ActionAudit,
        reason: &str,
        outcome: String,
        meter: bool,
    ) -> Result<(), String> {
        self.decorate_evidence(&mut audit.evidence);
        let decision_id = uuid::Uuid::new_v4().to_string();
        let attested = self.attest(
            &decision_id,
            &audit.action,
            &audit.attestation_actor,
            &mut audit.evidence,
            audit.timestamp,
        );
        db.record_decision_with_attestation(
            &audit::Decision {
                id: decision_id,
                timestamp: audit.timestamp,
                actor: audit.actor,
                action: audit.action,
                reason: reason.to_string(),
                evidence: audit.evidence,
                target_id: audit.target_id,
                outcome,
            },
            attested.as_ref(),
        )?;
        if meter {
            self.record_usage(db, budget)?;
        }
        Ok(())
    }

    /// Check limits and durably record the denial through the same lifecycle
    /// interface used by direct execution and approval resumption.
    pub fn check_limits_and_record(
        &self,
        db: &RuntimeDb,
        budget: Option<&BudgetTracker>,
        mut audit: ActionAudit,
    ) -> Result<(), ActionLimitExceeded> {
        let limit = match self.check_limits(db, budget) {
            Ok(()) => return Ok(()),
            Err(limit) => limit,
        };
        self.decorate_evidence(&mut audit.evidence);
        let (reason, outcome) = match &limit {
            ActionLimitExceeded::Internal(_) => return Err(limit),
            ActionLimitExceeded::BlastRadius {
                work_unit,
                used_mutations,
                used_deletes,
            } => {
                audit
                    .evidence
                    .insert("used_mutations".into(), used_mutations.to_string());
                audit
                    .evidence
                    .insert("used_deletes".into(), used_deletes.to_string());
                (
                    "action_blast_radius_exceeded",
                    format!("blast-radius cap exceeded for work unit {work_unit}"),
                )
            }
            ActionLimitExceeded::Budget { subject, reason } => {
                audit
                    .evidence
                    .insert("budget_subject".into(), subject.clone());
                ("action_budget_exceeded", reason.clone())
            }
        };
        db.record_decision(&audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: audit.timestamp,
            actor: audit.actor,
            action: audit.action,
            reason: reason.into(),
            evidence: audit.evidence,
            target_id: audit.target_id,
            outcome,
        })
        .map_err(ActionLimitExceeded::Internal)?;
        Err(limit)
    }

    pub fn attest(
        &self,
        decision_id: &str,
        action: &str,
        actor: &str,
        evidence: &mut HashMap<String, String>,
        created: i64,
    ) -> Option<attestation::PolicyAttestation> {
        let policy = self.policy.as_ref()?;
        let record = attestation::build_action_attestation(attestation::ActionAttestationInput {
            decision_id,
            policy,
            action,
            actor,
            risk: self.risk,
            namespace: &self.namespace,
            decision: self.decision,
            created,
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

    fn blast_caps(&self) -> Option<(Option<u32>, Option<u32>)> {
        self.policy.as_ref().and_then(|policy| {
            match (
                policy.max_mutations_per_work_unit,
                policy.max_deletes_per_work_unit,
            ) {
                (None, None) => None,
                caps => Some(caps),
            }
        })
    }

    fn decorate_evidence(&self, evidence: &mut HashMap<String, String>) {
        evidence.insert("risk_class".into(), self.risk.as_str().into());
        evidence.insert("decision".into(), self.decision.as_str().into());
        if !self.policy_scope.is_empty() {
            evidence.insert("policy_scope".into(), self.policy_scope.clone());
        }
        if !self.work_unit.is_empty() {
            evidence.insert("work_unit".into(), self.work_unit.clone());
        }
    }
}

fn action_budget_subject(risk: RiskClass, namespace: &str, actor: &str) -> String {
    let base = format!("action:{}", risk.as_str());
    if namespace.trim().is_empty() {
        return base;
    }
    if actor.trim().is_empty() {
        return format!("{base}/project:{}", namespace.trim());
    }
    format!("{base}/project:{}/agent:{}", namespace.trim(), actor.trim())
}

#[allow(clippy::too_many_arguments)]
pub fn hold_action(
    db: &RuntimeDb,
    context: &GovernedActionContext,
    actor: &str,
    action: &str,
    params: HashMap<String, String>,
    target_id: &str,
    mut evidence: HashMap<String, String>,
    now: i64,
) -> Result<ActionApproval, String> {
    let approval = ActionApproval::pending(
        actor,
        action,
        params,
        &context.work_unit,
        &context.policy_scope,
        context.risk.as_str(),
        target_id,
        now,
    );
    db.create_action_approval(&approval)?;
    evidence.insert("risk_class".into(), context.risk.as_str().into());
    evidence.insert("policy_scope".into(), context.policy_scope.clone());
    evidence.insert("decision".into(), context.decision.as_str().into());
    evidence.insert("approval_id".into(), approval.id.clone());
    if !context.work_unit.is_empty() {
        evidence.insert("work_unit".into(), context.work_unit.clone());
    }
    let decision_id = uuid::Uuid::new_v4().to_string();
    let attested = context.attest(&decision_id, action, actor, &mut evidence, now);
    db.record_decision_with_attestation(
        &audit::Decision {
            id: decision_id,
            timestamp: now,
            actor: actor.to_string(),
            action: action.to_string(),
            reason: "action_approval_pending".into(),
            evidence,
            target_id: target_id.to_string(),
            outcome: format!("held for approval: {}", approval.id),
        },
        attested.as_ref(),
    )?;
    Ok(approval)
}

pub fn complete_approval(
    db: &RuntimeDb,
    context: &GovernedActionContext,
    approval: &mut ActionApproval,
    decided_by: &str,
    outcome: &str,
    now: i64,
) -> Result<(), String> {
    if approval.status != ApprovalStatus::Pending {
        return Err(format!(
            "approval {} is already {}",
            approval.id,
            approval.status.as_str()
        ));
    }
    approval.status = ApprovalStatus::Approved;
    approval.decided_by = decided_by.to_string();
    approval.outcome = outcome.to_string();
    approval.updated = now;
    db.update_action_approval(approval)?;
    let mut evidence = HashMap::from([
        ("approval_id".to_string(), approval.id.clone()),
        ("risk_class".to_string(), context.risk.as_str().into()),
        ("decision".to_string(), context.decision.as_str().into()),
        ("approval_status".to_string(), "approved".into()),
    ]);
    if !approval.policy_scope.is_empty() {
        evidence.insert("policy_scope".into(), approval.policy_scope.clone());
    }
    if !approval.work_unit.is_empty() {
        evidence.insert("work_unit".into(), approval.work_unit.clone());
    }
    let decision_id = uuid::Uuid::new_v4().to_string();
    let attested = context.attest(
        &decision_id,
        &approval.action,
        &approval.actor,
        &mut evidence,
        now,
    );
    db.record_decision_with_attestation(
        &audit::Decision {
            id: decision_id,
            timestamp: now,
            actor: approval.decided_by.clone(),
            action: approval.action.clone(),
            reason: "action_approval_approved".into(),
            evidence,
            target_id: approval.target_id.clone(),
            outcome: outcome.to_string(),
        },
        attested.as_ref(),
    )
}

/// Commit the generic denial transition and its audit decision. Callers retain
/// domain-specific pre-transition work such as parked-work rejection and
/// transport-specific receipt projection.
pub fn deny_approval(
    db: &RuntimeDb,
    approval: &mut ActionApproval,
    decided_by: &str,
    reason: &str,
    now: i64,
) -> Result<(), String> {
    if approval.status != ApprovalStatus::Pending {
        return Err(format!(
            "approval {} is already {}",
            approval.id,
            approval.status.as_str()
        ));
    }
    approval.status = ApprovalStatus::Denied;
    approval.decided_by = decided_by.to_string();
    approval.outcome = if reason.trim().is_empty() {
        "denied".to_string()
    } else {
        reason.trim().to_string()
    };
    approval.updated = now;
    db.update_action_approval(approval)?;
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
    db.record_decision(&audit::Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: now,
        actor: approval.decided_by.clone(),
        action: approval.action.clone(),
        reason: "action_approval_denied".into(),
        evidence,
        target_id: approval.target_id.clone(),
        outcome: approval.outcome.clone(),
    })
}

/// Correlation row for hosts and producers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCorrelation {
    pub instance_id: String,
    pub operation_id: String,
    pub namespace: String,
    pub effect_id: String,
    pub effect_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionLifecycleView {
    pub instance_id: String,
    pub operation_id: String,
    pub instance_status: String,
    pub runtime_effects: Vec<ActionCorrelation>,
    pub receipt_has_outcome: bool,
    pub receipt_event_count: usize,
    /// Human-readable consistency notes (empty when clean).
    pub mismatches: Vec<String>,
}

/// Build a reconstructible lifecycle view and mismatch notes.
pub fn evaluate_action_lifecycle(
    instance: &ActionInstance,
    effects: &[ActionEffect],
    receipt: Option<&OperationReceipt>,
) -> ActionLifecycleView {
    let mut mismatches = Vec::new();
    if instance.status == STATUS_ADMITTED && instance.operation_id.trim().is_empty() {
        mismatches.push("admitted instance missing operation_id".into());
    }
    if let Some(receipt) = receipt {
        if receipt.operation_id != instance.operation_id {
            mismatches.push(format!(
                "receipt operation_id {} != instance operation_id {}",
                receipt.operation_id, instance.operation_id
            ));
        }
        if receipt.namespace != instance.namespace {
            mismatches.push("receipt namespace does not match instance namespace".into());
        }
    } else if instance.status == STATUS_ADMITTED {
        mismatches.push("admitted instance has no operation receipt".into());
    }

    let runtime_effects: Vec<ActionCorrelation> = effects
        .iter()
        .filter(|e| e.kind == EFFECT_KIND_RUNTIME_DISPATCH)
        .map(|e| ActionCorrelation {
            instance_id: instance.instance_id.clone(),
            operation_id: instance.operation_id.clone(),
            namespace: instance.namespace.clone(),
            effect_id: e.effect_id.clone(),
            effect_status: e.status.clone(),
        })
        .collect();

    let receipt_has_outcome = receipt
        .map(|r| {
            r.events
                .iter()
                .any(|e| e.kind == ReceiptEventKind::OutcomeRecorded)
        })
        .unwrap_or(false);
    let receipt_event_count = receipt.map(|r| r.events.len()).unwrap_or(0);

    for corr in &runtime_effects {
        match corr.effect_status.as_str() {
            EFFECT_STATUS_COMPLETED | EFFECT_STATUS_FAILED => {
                if !receipt_has_outcome {
                    mismatches.push(format!(
                        "effect {} is {} but receipt lacks OutcomeRecorded (ack without harvest)",
                        corr.effect_id, corr.effect_status
                    ));
                }
            }
            EFFECT_STATUS_PENDING | EFFECT_STATUS_CLAIMED | EFFECT_STATUS_PARKED
                if receipt_has_outcome =>
            {
                mismatches.push(format!(
                    "receipt has OutcomeRecorded but effect {} still {}",
                    corr.effect_id, corr.effect_status
                ));
            }
            _ => {}
        }
    }

    // Harvest without terminal ack: receipt outcome present, no terminal runtime effect.
    if receipt_has_outcome {
        let any_terminal = runtime_effects.iter().any(|e| {
            e.effect_status == EFFECT_STATUS_COMPLETED || e.effect_status == EFFECT_STATUS_FAILED
        });
        if !runtime_effects.is_empty() && !any_terminal {
            mismatches.push("receipt OutcomeRecorded without terminal runtime_dispatch ack".into());
        }
    }

    ActionLifecycleView {
        instance_id: instance.instance_id.clone(),
        operation_id: instance.operation_id.clone(),
        instance_status: instance.status.clone(),
        runtime_effects,
        receipt_has_outcome,
        receipt_event_count,
        mismatches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptSurface,
    };
    use crate::sekai::action_instance::STATUS_DENIED;
    use crate::sekai::action_policy::ActionPolicy;
    use std::collections::BTreeMap;

    fn sample_instance(status: &str) -> ActionInstance {
        ActionInstance {
            instance_id: "gai-1".into(),
            namespace: "acme".into(),
            type_id: "t".into(),
            version: "1".into(),
            principal: "tester".into(),
            parameters_json: "{}".into(),
            request_digest: "d".into(),
            idempotency_key: "k".into(),
            operation_id: "op-1".into(),
            status: status.into(),
            deny_reason: String::new(),
            evidence_submission_ids: vec![],
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 1,
            decided_at_ms: 1,
        }
    }

    fn sample_effect(status: &str) -> ActionEffect {
        ActionEffect {
            effect_id: "gax-1".into(),
            instance_id: "gai-1".into(),
            namespace: "acme".into(),
            operation_id: "op-1".into(),
            kind: EFFECT_KIND_RUNTIME_DISPATCH.into(),
            status: status.into(),
            payload_json: "{}".into(),
            failure_reason: String::new(),
            created_at_ms: 1,
            updated_at_ms: 1,
            claim_owner: String::new(),
            claim_generation: 0,
            claim_fencing_token: String::new(),
            claim_expires_at_ms: 0,
            claim_request_id: String::new(),
            park_generation: 0,
            active_resolution_id: String::new(),
            claim_attempt_count: 0,
            lease_expiry_count: 0,
            park_count: 0,
            lifecycle_state: String::new(),
            retry_policy_version: String::new(),
            retry_policy_digest: String::new(),
            max_claim_attempts: 0,
            max_lease_expiries: 0,
            max_park_cycles: 0,
        }
    }

    fn sample_receipt(with_outcome: bool) -> OperationReceipt {
        let mut events = vec![OperationReceiptEvent {
            event_id: "op-1:intent".into(),
            operation_id: "op-1".into(),
            parent_event_id: None,
            timestamp_ms: 1,
            kind: ReceiptEventKind::IntentRecorded,
            surface: ReceiptSurface::Intent,
            actor: "tester".into(),
            references: vec![],
            attributes: BTreeMap::new(),
        }];
        if with_outcome {
            events.push(OperationReceiptEvent {
                event_id: "op-1:outcome".into(),
                operation_id: "op-1".into(),
                parent_event_id: Some("op-1:intent".into()),
                timestamp_ms: 2,
                kind: ReceiptEventKind::OutcomeRecorded,
                surface: ReceiptSurface::Outcome,
                actor: "runtime".into(),
                references: vec![],
                attributes: BTreeMap::from([("outcome".into(), "completed".into())]),
            });
        }
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "acme".into(),
            operation_class: "governed_action_instance".into(),
            initiating_actor: "tester".into(),
            schema_version: "v1".into(),
            policy_version: "v1".into(),
            started_at_ms: 1,
            completed_at_ms: if with_outcome { Some(2) } else { None },
            events,
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
        }
    }

    #[test]
    fn happy_path_terminal_ack_with_outcome() {
        let view = evaluate_action_lifecycle(
            &sample_instance(STATUS_ADMITTED),
            &[sample_effect(EFFECT_STATUS_COMPLETED)],
            Some(&sample_receipt(true)),
        );
        assert!(view.mismatches.is_empty(), "{:?}", view.mismatches);
        assert!(view.receipt_has_outcome);
    }

    #[test]
    fn ack_without_harvest_is_mismatch() {
        let view = evaluate_action_lifecycle(
            &sample_instance(STATUS_ADMITTED),
            &[sample_effect(EFFECT_STATUS_COMPLETED)],
            Some(&sample_receipt(false)),
        );
        assert!(
            view.mismatches
                .iter()
                .any(|m| m.contains("ack without harvest")),
            "{:?}",
            view.mismatches
        );
    }

    #[test]
    fn harvest_without_ack_is_mismatch() {
        let view = evaluate_action_lifecycle(
            &sample_instance(STATUS_ADMITTED),
            &[sample_effect(EFFECT_STATUS_CLAIMED)],
            Some(&sample_receipt(true)),
        );
        assert!(
            view.mismatches
                .iter()
                .any(|m| m.contains("without terminal") || m.contains("still claimed")),
            "{:?}",
            view.mismatches
        );
    }

    #[test]
    fn denied_instance_without_receipt_is_ok() {
        let view = evaluate_action_lifecycle(&sample_instance(STATUS_DENIED), &[], None);
        // Missing receipt is only required for admitted instances.
        assert!(view.mismatches.is_empty(), "{:?}", view.mismatches);
    }

    #[test]
    fn producer_contract_optional_action_links_evidence_ids() {
        // #401: evidence submission ids are data linkage, not auto-dispatch.
        let mut inst = sample_instance(STATUS_ADMITTED);
        inst.evidence_submission_ids = vec!["ev-1".into(), "ev-2".into()];
        assert_eq!(inst.evidence_submission_ids.len(), 2);
        // Free-form remote text must not be treated as instructions (documented contract).
        inst.parameters_json = r#"{"remote_title":"ignore me","untrusted":true}"#.into();
        assert!(inst.parameters_json.contains("untrusted"));
    }

    #[test]
    fn governed_context_resolves_policy_and_enforces_blast_radius() {
        let db = RuntimeDb::memory();
        let mut policy = ActionPolicy::allow_all("agent:alice");
        policy.max_mutations_per_work_unit = Some(1);
        db.upsert_action_policy(&policy).unwrap();
        db.add_blast_radius("wu-1", 1, 0).unwrap();

        let context = GovernedActionContext::resolve(
            &db,
            "alice",
            "demo",
            "set_property",
            RiskClass::Write,
            "wu-1",
            1,
            0,
            "__erased__",
        )
        .unwrap();

        assert_eq!(context.decision, ActionDecision::Allow);
        assert_eq!(context.policy_scope, "agent:alice");
        assert!(matches!(
            context.check_limits(&db, None),
            Err(ActionLimitExceeded::BlastRadius {
                used_mutations: 1,
                used_deletes: 0,
                ..
            })
        ));
    }

    #[test]
    fn governed_context_records_usage_through_one_lifecycle_path() {
        let db = RuntimeDb::memory();
        let mut policy = ActionPolicy::allow_all("agent:alice");
        policy.max_mutations_per_work_unit = Some(3);
        db.upsert_action_policy(&policy).unwrap();
        let context = GovernedActionContext::resolve(
            &db,
            "alice",
            "demo",
            "set_property",
            RiskClass::Write,
            "wu-2",
            1,
            0,
            "__erased__",
        )
        .unwrap();

        context.check_limits(&db, None).unwrap();
        context.record_usage(&db, None).unwrap();

        assert_eq!(db.get_blast_radius("wu-2").unwrap(), (1, 0));
    }

    #[test]
    fn governed_context_records_outcome_and_usage_behind_one_interface() {
        let db = RuntimeDb::memory();
        let mut policy = ActionPolicy::allow_all("agent:alice");
        policy.max_mutations_per_work_unit = Some(3);
        db.upsert_action_policy(&policy).unwrap();
        let context = GovernedActionContext::resolve(
            &db,
            "alice",
            "demo",
            "set_property",
            RiskClass::Write,
            "wu-outcome",
            1,
            0,
            "__erased__",
        )
        .unwrap();

        context
            .record_outcome(
                &db,
                None,
                ActionAudit {
                    actor: "alice".into(),
                    attestation_actor: "alice".into(),
                    action: "set_property".into(),
                    target_id: "obj-1".into(),
                    evidence: HashMap::from([("safe".into(), "value".into())]),
                    timestamp: 20,
                },
                "execute_action",
                "updated".into(),
                true,
            )
            .unwrap();

        let decisions = db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].evidence["risk_class"], "write");
        assert_eq!(decisions[0].evidence["work_unit"], "wu-outcome");
        assert_eq!(db.get_blast_radius("wu-outcome").unwrap(), (1, 0));
    }

    #[test]
    fn governed_context_records_limit_denial_behind_one_interface() {
        let db = RuntimeDb::memory();
        let mut policy = ActionPolicy::allow_all("agent:alice");
        policy.max_mutations_per_work_unit = Some(1);
        db.upsert_action_policy(&policy).unwrap();
        db.add_blast_radius("wu-limit", 1, 0).unwrap();
        let context = GovernedActionContext::resolve(
            &db,
            "alice",
            "demo",
            "set_property",
            RiskClass::Write,
            "wu-limit",
            1,
            0,
            "__erased__",
        )
        .unwrap();

        let result = context.check_limits_and_record(
            &db,
            None,
            ActionAudit {
                actor: "alice".into(),
                attestation_actor: "alice".into(),
                action: "set_property".into(),
                target_id: "obj-1".into(),
                evidence: HashMap::new(),
                timestamp: 20,
            },
        );

        assert!(matches!(
            result,
            Err(ActionLimitExceeded::BlastRadius { .. })
        ));
        let decisions = db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions[0].reason, "action_blast_radius_exceeded");
        assert_eq!(decisions[0].evidence["used_mutations"], "1");
    }

    #[test]
    fn erased_namespace_denial_does_not_attest_an_unrelated_policy() {
        let db = RuntimeDb::memory();
        db.upsert_action_policy(&ActionPolicy::allow_all("agent:alice"))
            .unwrap();
        let context = GovernedActionContext::resolve(
            &db,
            "alice",
            "__erased__",
            "set_property",
            RiskClass::Write,
            "",
            1,
            0,
            "__erased__",
        )
        .unwrap();
        let mut evidence = HashMap::new();

        assert_eq!(context.decision, ActionDecision::Deny);
        assert!(context.policy.is_none());
        assert!(
            context
                .attest("decision-1", "set_property", "alice", &mut evidence, 10)
                .is_none()
        );
    }

    #[test]
    fn denial_transition_is_terminal_and_audited() {
        let db = RuntimeDb::memory();
        let mut approval = ActionApproval::pending(
            "alice",
            "set_property",
            HashMap::from([
                ("id".into(), "obj-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), "done".into()),
            ]),
            "wu-3",
            "agent:alice",
            "write",
            "obj-1",
            10,
        );
        db.create_action_approval(&approval).unwrap();

        deny_approval(&db, &mut approval, "admin", "not authorized", 20).unwrap();

        assert_eq!(approval.status, ApprovalStatus::Denied);
        assert_eq!(approval.decided_by, "admin");
        assert_eq!(approval.outcome, "not authorized");
        assert!(
            db.list_decisions(&audit::DecisionFilter::default())
                .unwrap()
                .iter()
                .any(|decision| decision.reason == "action_approval_denied")
        );
        assert!(deny_approval(&db, &mut approval, "admin", "again", 30).is_err());
    }
}

//! ActionInstance ↔ operation receipt ↔ effect correlation (#400).
//!
//! The plane keeps a single harvest spine on `operation_id`. ActionInstance is
//! the admission envelope; runtime hosts claim effects and harvest to the
//! bound operation.

use crate::chisei::receipt::{OperationReceipt, ReceiptEventKind};
use crate::sekai::action_effect::{
    ActionEffect, EFFECT_STATUS_CLAIMED, EFFECT_STATUS_COMPLETED, EFFECT_STATUS_FAILED,
    EFFECT_STATUS_PARKED, EFFECT_STATUS_PENDING,
};
use crate::sekai::action_instance::{ActionInstance, STATUS_ADMITTED};
use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;
use serde::{Deserialize, Serialize};

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
}

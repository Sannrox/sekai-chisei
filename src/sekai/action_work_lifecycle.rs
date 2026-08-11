//! Runtime Action Work claim and acknowledgement lifecycle.
//!
//! Transport adapters authenticate callers and enforce namespace access before
//! crossing this seam. This module owns persistence calls, retry/park event
//! ordering, receipt harvest, audit records, active continuation lookup, and
//! storage-error classification behind one interface.

use crate::chisei::receipt::{OperationReceiptEvent, ReceiptEventKind};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_effect::{
    ACK_OUTCOME_PARKED, ActionEffect, EFFECT_STATUS_COMPLETED, EFFECT_STATUS_FAILED,
};
use crate::sekai::audit;
use crate::sekai::parked_work::{ActionWorkContinuation, ActionWorkPark};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActionWorkLifecycleError {
    InvalidArgument(String),
    FailedPrecondition(String),
    AlreadyExists(String),
    NotFound(String),
    Internal(String),
}

#[derive(Debug, Clone)]
pub(crate) struct ClaimActionWork<'a> {
    pub effect_id: &'a str,
    pub runtime_id: &'a str,
    pub request_id: &'a str,
    pub ttl_ms: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct HeartbeatActionClaim<'a> {
    pub effect_id: &'a str,
    pub runtime_id: &'a str,
    pub claim_generation: u64,
    pub fencing_token: &'a str,
    pub ttl_ms: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct AckActionWork<'a> {
    pub effect_id: &'a str,
    pub runtime_id: &'a str,
    pub claim_generation: u64,
    pub fencing_token: &'a str,
    pub outcome: &'a str,
    pub reason: &'a str,
    pub request_id: &'a str,
    pub checkpoint_store_id: &'a str,
    pub checkpoint_ref: &'a str,
    pub checkpoint_digest: &'a str,
}

#[derive(Debug, Clone)]
pub(crate) struct ReportActionClaimEvent<'a> {
    pub effect_id: &'a str,
    pub runtime_id: &'a str,
    pub claim_generation: u64,
    pub fencing_token: &'a str,
    pub kind: &'a str,
    pub checkpoint_digest: &'a str,
    pub reason_code: &'a str,
    pub request_id: &'a str,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaimedActionWork {
    pub effect: ActionEffect,
    pub continuation: Option<ActionWorkContinuation>,
    pub park: Option<ActionWorkPark>,
}

#[derive(Debug, Clone)]
pub(crate) struct AckedActionWork {
    pub effect: ActionEffect,
    pub park: Option<ActionWorkPark>,
    pub replay: bool,
}

pub(crate) struct ActionWorkLifecycle<'a> {
    db: &'a RuntimeDb,
}

impl<'a> ActionWorkLifecycle<'a> {
    pub(crate) fn new(db: &'a RuntimeDb) -> Self {
        Self { db }
    }

    pub(crate) fn list_claimable(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<ActionEffect>, ActionWorkLifecycleError> {
        self.db
            .list_claimable_action_work(namespace, runtime_id, now_ms, limit)
            .map_err(ActionWorkLifecycleError::Internal)
    }

    pub(crate) fn claim(
        &self,
        command: ClaimActionWork<'_>,
        actor: &str,
        now_ms: i64,
    ) -> Result<ClaimedActionWork, ActionWorkLifecycleError> {
        let stored = self
            .db
            .claim_action_work(
                command.effect_id,
                command.runtime_id,
                command.request_id,
                command.ttl_ms,
                now_ms,
            )
            .map_err(classify_claim_error)?;
        self.record_claim_audit(&stored, actor, now_ms);
        let active = self
            .db
            .get_active_continuation(&stored)
            .map_err(ActionWorkLifecycleError::Internal)?;
        Ok(ClaimedActionWork {
            effect: stored,
            continuation: active
                .as_ref()
                .map(|(continuation, _)| continuation.clone()),
            park: active.as_ref().map(|(_, park)| park.clone()),
        })
    }

    pub(crate) fn heartbeat(
        &self,
        command: HeartbeatActionClaim<'_>,
        _actor: &str,
        now_ms: i64,
    ) -> Result<ActionEffect, ActionWorkLifecycleError> {
        self.db
            .heartbeat_action_claim(
                command.effect_id,
                command.runtime_id,
                command.claim_generation,
                command.fencing_token,
                command.ttl_ms,
                now_ms,
            )
            .map_err(classify_heartbeat_error)
    }

    pub(crate) fn ack(
        &self,
        command: AckActionWork<'_>,
        actor: &str,
        now_ms: i64,
    ) -> Result<AckedActionWork, ActionWorkLifecycleError> {
        if command.outcome == ACK_OUTCOME_PARKED {
            let result = self
                .db
                .park_action_work(
                    command.effect_id,
                    command.runtime_id,
                    command.claim_generation,
                    command.fencing_token,
                    command.reason,
                    command.request_id,
                    command.checkpoint_store_id,
                    command.checkpoint_ref,
                    command.checkpoint_digest,
                    actor,
                    now_ms,
                )
                .map_err(classify_park_error)?;
            self.record_park_audit(&result.effect, &result.park, actor, now_ms);
            return Ok(AckedActionWork {
                effect: result.effect,
                park: Some(result.park),
                replay: result.replay,
            });
        }

        let stored = self
            .db
            .ack_action_work(
                command.effect_id,
                command.runtime_id,
                command.claim_generation,
                command.fencing_token,
                command.outcome,
                command.reason,
                now_ms,
            )
            .map_err(classify_ack_error)?;
        self.harvest_ack_receipt(&stored, command.runtime_id, now_ms)?;
        self.record_ack_audit(&stored, actor, command.runtime_id, now_ms);
        Ok(AckedActionWork {
            effect: stored,
            park: None,
            replay: false,
        })
    }

    pub(crate) fn report_event(
        &self,
        command: ReportActionClaimEvent<'_>,
        _actor: &str,
        now_ms: i64,
    ) -> Result<bool, ActionWorkLifecycleError> {
        self.db
            .report_action_claim_event(
                command.effect_id,
                command.runtime_id,
                command.claim_generation,
                command.fencing_token,
                command.kind,
                command.checkpoint_digest,
                command.reason_code,
                command.request_id,
                now_ms,
            )
            .map_err(classify_report_error)
    }

    fn harvest_ack_receipt(
        &self,
        effect: &ActionEffect,
        runtime_id: &str,
        now_ms: i64,
    ) -> Result<(), ActionWorkLifecycleError> {
        if !matches!(
            effect.status.as_str(),
            EFFECT_STATUS_COMPLETED | EFFECT_STATUS_FAILED
        ) {
            return Ok(());
        }
        let Some(mut receipt) = self
            .db
            .get_operation_receipt(&effect.operation_id)
            .map_err(ActionWorkLifecycleError::Internal)?
        else {
            return Ok(());
        };
        let has_outcome = receipt
            .events
            .iter()
            .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded);
        if has_outcome {
            return Ok(());
        }
        let parent = receipt
            .events
            .last()
            .map(|event| event.event_id.clone())
            .unwrap_or_else(|| format!("{}:intent", effect.operation_id));
        receipt.events.push(OperationReceiptEvent {
            event_id: format!("{}:action-ack", effect.operation_id),
            operation_id: effect.operation_id.clone(),
            parent_event_id: Some(parent),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::ActionPerformed,
            surface: ReceiptEventKind::ActionPerformed.surface(),
            actor: runtime_id.to_string(),
            references: Vec::new(),
            attributes: BTreeMap::from([
                ("effect_id".into(), effect.effect_id.clone()),
                ("instance_id".into(), effect.instance_id.clone()),
                ("source".into(), "ack_action_work".into()),
            ]),
        });
        receipt.events.push(OperationReceiptEvent {
            event_id: format!("{}:outcome", effect.operation_id),
            operation_id: effect.operation_id.clone(),
            parent_event_id: Some(format!("{}:action-ack", effect.operation_id)),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::OutcomeRecorded,
            surface: ReceiptEventKind::OutcomeRecorded.surface(),
            actor: runtime_id.to_string(),
            references: Vec::new(),
            attributes: BTreeMap::from([
                ("outcome".into(), effect.status.clone()),
                ("effect_id".into(), effect.effect_id.clone()),
            ]),
        });
        receipt.completed_at_ms = Some(now_ms);
        self.db
            .put_operation_receipt(&receipt)
            .map_err(ActionWorkLifecycleError::Internal)
    }

    fn record_claim_audit(&self, effect: &ActionEffect, actor: &str, now_ms: i64) {
        let _ = self.db.record_decision(&audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now_ms,
            actor: actor.to_string(),
            action: "claim_action_work".into(),
            reason: "action_effect_claimed".into(),
            evidence: HashMap::from([
                ("effect_id".into(), effect.effect_id.clone()),
                ("runtime_id".into(), effect.claim_owner.clone()),
                ("generation".into(), effect.claim_generation.to_string()),
                ("instance_id".into(), effect.instance_id.clone()),
                ("operation_id".into(), effect.operation_id.clone()),
            ]),
            target_id: effect.effect_id.clone(),
            outcome: effect.status.clone(),
        });
    }

    fn record_park_audit(
        &self,
        effect: &ActionEffect,
        park: &ActionWorkPark,
        actor: &str,
        now_ms: i64,
    ) {
        let _ = self.db.record_decision(&audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now_ms,
            actor: actor.to_string(),
            action: "ack_action_work".into(),
            reason: "action_effect_parked".into(),
            evidence: HashMap::from([
                ("effect_id".into(), effect.effect_id.clone()),
                ("operation_id".into(), effect.operation_id.clone()),
                ("park_id".into(), park.park_id.clone()),
                ("park_generation".into(), park.park_generation.to_string()),
                ("request_digest".into(), park.request_digest.clone()),
            ]),
            target_id: effect.effect_id.clone(),
            outcome: "awaiting_continuation".into(),
        });
    }

    fn record_ack_audit(&self, effect: &ActionEffect, actor: &str, runtime_id: &str, now_ms: i64) {
        let _ = self.db.record_decision(&audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now_ms,
            actor: actor.to_string(),
            action: "ack_action_work".into(),
            reason: format!("action_effect_{}", effect.status),
            evidence: HashMap::from([
                ("effect_id".into(), effect.effect_id.clone()),
                ("runtime_id".into(), runtime_id.to_string()),
                ("outcome".into(), effect.status.clone()),
                ("instance_id".into(), effect.instance_id.clone()),
                ("operation_id".into(), effect.operation_id.clone()),
            ]),
            target_id: effect.effect_id.clone(),
            outcome: effect.status.clone(),
        });
    }
}

fn classify_claim_error(error: String) -> ActionWorkLifecycleError {
    if error.contains("already claimed")
        || error.contains("not claimable")
        || error.contains("retry limit exceeded")
        || error.contains("dead-lettered")
    {
        ActionWorkLifecycleError::FailedPrecondition(error)
    } else if error.contains("required") || error.contains("ttl") || error.contains("NUL") {
        ActionWorkLifecycleError::InvalidArgument(error)
    } else if error.contains("not found") {
        ActionWorkLifecycleError::NotFound(error)
    } else {
        ActionWorkLifecycleError::Internal(error)
    }
}

fn classify_heartbeat_error(error: String) -> ActionWorkLifecycleError {
    if error.contains("fencing") || error.contains("expired") || error.contains("not claimed") {
        ActionWorkLifecycleError::FailedPrecondition(error)
    } else if error.contains("not found") {
        ActionWorkLifecycleError::NotFound(error)
    } else {
        ActionWorkLifecycleError::InvalidArgument(error)
    }
}

fn classify_ack_error(error: String) -> ActionWorkLifecycleError {
    if error.contains("fencing") || error.contains("expired") || error.contains("not claimed") {
        ActionWorkLifecycleError::FailedPrecondition(error)
    } else if error.contains("invalid") || error.contains("NUL") {
        ActionWorkLifecycleError::InvalidArgument(error)
    } else if error.contains("not found") {
        ActionWorkLifecycleError::NotFound(error)
    } else {
        ActionWorkLifecycleError::Internal(error)
    }
}

fn classify_park_error(error: String) -> ActionWorkLifecycleError {
    if error.contains("fencing")
        || error.contains("expired")
        || error.contains("not claimed")
        || error.contains("retry limit")
    {
        ActionWorkLifecycleError::FailedPrecondition(error)
    } else if error.contains("required")
        || error.contains("checkpoint")
        || error.contains("bounds")
        || error.contains("NUL")
    {
        ActionWorkLifecycleError::InvalidArgument(error)
    } else if error.contains("conflict") {
        ActionWorkLifecycleError::AlreadyExists(error)
    } else {
        ActionWorkLifecycleError::Internal(error)
    }
}

fn classify_report_error(error: String) -> ActionWorkLifecycleError {
    if error.contains("fence") {
        ActionWorkLifecycleError::FailedPrecondition(error)
    } else if error.contains("conflict") {
        ActionWorkLifecycleError::AlreadyExists(error)
    } else {
        ActionWorkLifecycleError::InvalidArgument(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceipt, ReceiptSurface, UncoveredSurface,
    };
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::action_effect::{ACK_OUTCOME_COMPLETED, plan_effects_for_admit};
    use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;

    fn seed_effect(db: &RuntimeDb) -> ActionEffect {
        let effect = plan_effects_for_admit(
            "ai-1",
            "acme",
            "op-1",
            &[EFFECT_KIND_RUNTIME_DISPATCH.into()],
            r#"{"runtime":"shikigami"}"#,
            10,
            false,
        )
        .unwrap()
        .remove(0);
        db.put_action_effects(std::slice::from_ref(&effect))
            .unwrap();
        effect
    }

    #[test]
    fn claim_returns_active_continuation_shape() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        let claimed = ActionWorkLifecycle::new(&db)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    request_id: "claim-1",
                    ttl_ms: 60_000,
                },
                "operator",
                100,
            )
            .unwrap();

        assert_eq!(claimed.effect.status, "claimed");
        assert!(claimed.continuation.is_none());
        assert!(claimed.park.is_none());
    }

    #[test]
    fn ack_harvests_missing_receipt_outcome() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        db.put_operation_receipt(&OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: effect.operation_id.clone(),
            parent_operation_id: None,
            namespace: effect.namespace.clone(),
            operation_class: "action_work".into(),
            initiating_actor: "operator".into(),
            schema_version: "action-work-lifecycle-test/v1".into(),
            policy_version: "not_applicable".into(),
            started_at_ms: 1,
            completed_at_ms: None,
            events: Vec::new(),
            uncovered_surfaces: vec![UncoveredSurface {
                surface: ReceiptSurface::Routing,
                reason: "not applicable".into(),
            }],
            reporter_grants: Vec::new(),
        })
        .unwrap();
        let claimed = ActionWorkLifecycle::new(&db)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    request_id: "claim-1",
                    ttl_ms: 60_000,
                },
                "operator",
                100,
            )
            .unwrap();

        ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.effect.claim_generation,
                    fencing_token: &claimed.effect.claim_fencing_token,
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                },
                "operator",
                200,
            )
            .unwrap();

        let receipt = db
            .get_operation_receipt(&effect.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.completed_at_ms, Some(200));
        assert!(
            receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        );
    }

    #[test]
    fn classifies_claim_conflicts_at_lifecycle_seam() {
        assert!(matches!(
            classify_claim_error("effect already claimed by runtime".into()),
            ActionWorkLifecycleError::FailedPrecondition(_)
        ));
        assert!(matches!(
            classify_claim_error("action effect not found".into()),
            ActionWorkLifecycleError::NotFound(_)
        ));
    }
}

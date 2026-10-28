//! Runtime Action Work claim and acknowledgement lifecycle.
//!
//! Transport adapters authenticate callers and enforce namespace access before
//! crossing this seam. This module owns persistence calls, retry/park event
//! ordering, receipt harvest, audit records, active continuation lookup, and
//! storage-error classification behind one interface.

use crate::db::runtime_db::RuntimeDb;
use crate::enterprise::{DelegatorApplyRefusal, NamespaceAction, revalidate_agent_ceiling};
use crate::sekai::action_effect::{
    ACK_OUTCOME_COMPLETED, ACK_OUTCOME_FAILED, ACK_OUTCOME_PARKED, ActionEffect,
    EFFECT_STATUS_COMPLETED, EFFECT_STATUS_FAILED,
};
use crate::sekai::audit;
use crate::sekai::delegating_principal::{
    DelegatorApplyError, current_delegating_principal_state, revalidate_delegator_at_apply,
};
use crate::sekai::governed_action_type::GovernedActionType;
use crate::sekai::parked_work::{ActionWorkContinuation, ActionWorkPark};
use sekai_domain::receipt::{
    OperationReceipt, OperationReceiptEvent, ReceiptArtifact, ReceiptEventKind,
};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionWorkLifecycleError {
    InvalidArgument(String),
    FailedPrecondition(String),
    AlreadyExists(String),
    NotFound(String),
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct ClaimActionWork<'a> {
    pub effect_id: &'a str,
    pub runtime_id: &'a str,
    pub request_id: &'a str,
    pub ttl_ms: i64,
}

#[derive(Debug, Clone)]
pub struct HeartbeatActionClaim<'a> {
    pub effect_id: &'a str,
    pub runtime_id: &'a str,
    pub claim_generation: u64,
    pub fencing_token: &'a str,
    pub ttl_ms: i64,
}

#[derive(Debug, Clone)]
pub struct AckActionWork<'a> {
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
    pub artifact_json: &'a str,
}

#[derive(Debug, Clone)]
pub struct ReportActionClaimEvent<'a> {
    pub effect_id: &'a str,
    pub runtime_id: &'a str,
    pub claim_generation: u64,
    pub fencing_token: &'a str,
    pub kind: &'a str,
    pub checkpoint_digest: &'a str,
    pub reason_code: &'a str,
    pub request_id: &'a str,
}

/// An Action Work claim cited by a model call (#1910).
#[derive(Debug, Clone, Copy)]
pub struct CitedActionClaim<'a> {
    pub effect_id: &'a str,
    pub claim_generation: u64,
    pub fencing_token: &'a str,
}

/// What a cited claim resolves to. Only `Live` carries an Action type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CitedClaimResolution {
    /// Live, held by the caller, in the call's namespace.
    Live(Box<GovernedActionType>),
    /// No such effect in the call's namespace, or its instance or type is gone.
    NotFound,
    /// Not claimed, lease expired, or a stale generation or token.
    NotLive,
    /// Live, but taken by another principal.
    Foreign,
}

#[derive(Debug, Clone)]
pub struct ClaimedActionWork {
    pub effect: ActionEffect,
    pub continuation: Option<ActionWorkContinuation>,
    pub park: Option<ActionWorkPark>,
}

#[derive(Debug, Clone)]
pub struct AckedActionWork {
    pub effect: ActionEffect,
    pub park: Option<ActionWorkPark>,
    pub replay: bool,
}

pub struct ActionWorkLifecycle<'a> {
    db: &'a RuntimeDb,
    enforce_agent_ceiling: bool,
}

impl<'a> ActionWorkLifecycle<'a> {
    pub fn new(db: &'a RuntimeDb) -> Self {
        Self {
            db,
            enforce_agent_ceiling: false,
        }
    }

    pub fn with_agent_ceiling(mut self, enforce: bool) -> Self {
        self.enforce_agent_ceiling = enforce;
        self
    }

    pub fn claim(
        &self,
        command: ClaimActionWork<'_>,
        actor: &str,
        now_ms: i64,
    ) -> Result<ClaimedActionWork, ActionWorkLifecycleError> {
        // Re-validate `act` before returning a fence so a disabled or removed
        // delegator cannot reach the side effect. Missing records stay the
        // persist seam's problem (NotFound / not claimable), matching the
        // #1423 apply-time follow-up rather than changing claim taxonomy.
        if let Some(reason) = self.delegator_apply_refusal(command.effect_id)?
            && reason != DelegatorApplyRefusal::RecordMissing
        {
            return self.fail_closed_delegator_claim(command, actor, now_ms, reason);
        }
        let stored = self
            .db
            .claim_action_work(
                command.effect_id,
                command.runtime_id,
                command.request_id,
                actor,
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

    pub fn heartbeat(
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

    pub fn ack(
        &self,
        command: AckActionWork<'_>,
        actor: &str,
        now_ms: i64,
    ) -> Result<AckedActionWork, ActionWorkLifecycleError> {
        let artifact = parse_ack_artifact(command.artifact_json)?;
        if let Some(stored) = self
            .db
            .get_action_effect(command.effect_id)
            .map_err(ActionWorkLifecycleError::Internal)?
            && stored.status != EFFECT_STATUS_COMPLETED
            && stored.status != EFFECT_STATUS_FAILED
        {
            let instance = self
                .db
                .get_action_instance(&stored.instance_id)
                .map_err(ActionWorkLifecycleError::Internal)?;
            let action_type = instance
                .as_ref()
                .map(|instance| instance.type_id.as_str())
                .unwrap_or("");
            let origin = instance
                .as_ref()
                .map(|instance| instance.principal.as_str())
                .unwrap_or("");
            let delegating = instance
                .as_ref()
                .and_then(|instance| instance.delegating_actor.as_deref());
            let stored_agent = instance
                .as_ref()
                .is_some_and(|instance| instance.agent_action);
            let actor_agent =
                crate::sekai::write_freeze::actor_is_agent(self.db, actor, None, false)
                    .map_err(ActionWorkLifecycleError::Internal)?;
            let origin_agent = stored_agent
                || crate::sekai::write_freeze::actor_is_agent(self.db, origin, delegating, false)
                    .map_err(ActionWorkLifecycleError::Internal)?;
            let actor_tenant =
                crate::sekai::write_freeze::acting_or_registered_tenant(self.db, "", actor)
                    .map_err(ActionWorkLifecycleError::Internal)?;
            let origin_tenant =
                crate::sekai::write_freeze::acting_or_registered_tenant(self.db, "", origin)
                    .map_err(ActionWorkLifecycleError::Internal)?;
            let mut checks = crate::sekai::write_freeze::write_checks_for_actors(
                &stored.namespace,
                actor_tenant.as_ref(),
                actor,
                None,
                action_type,
                actor_agent,
            );
            checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                &stored.namespace,
                origin_tenant.as_ref(),
                origin,
                delegating,
                action_type,
                origin_agent,
            ));
            let stored_tenant = instance
                .as_ref()
                .map(|instance| instance.admission_tenant.as_str())
                .unwrap_or("");
            if !stored_tenant.is_empty() {
                checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                    &stored.namespace,
                    stored_tenant,
                    origin,
                    delegating,
                    action_type,
                    origin_agent,
                ));
            }
            let resource_tenant = instance
                .as_ref()
                .map(|instance| instance.resource_tenant.as_str())
                .unwrap_or("");
            if !resource_tenant.is_empty() && resource_tenant != stored_tenant {
                checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                    &stored.namespace,
                    resource_tenant,
                    origin,
                    delegating,
                    action_type,
                    origin_agent,
                ));
            }
            match crate::sekai::write_freeze::freeze_reason_any(self.db, &checks) {
                Ok(Some(reason)) => {
                    return Err(ActionWorkLifecycleError::FailedPrecondition(reason));
                }
                Ok(None) => {}
                Err(error) => return Err(ActionWorkLifecycleError::Internal(error)),
            }
        }
        if command.outcome == ACK_OUTCOME_PARKED {
            if artifact.is_some() {
                return Err(ActionWorkLifecycleError::InvalidArgument(
                    "invalid artifact: parked acknowledgements cannot attach an artifact".into(),
                ));
            }
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
        if command.outcome == ACK_OUTCOME_FAILED && artifact.is_some() {
            return Err(ActionWorkLifecycleError::InvalidArgument(
                "invalid artifact: failed acknowledgements cannot attach an artifact".into(),
            ));
        }
        if command.outcome == ACK_OUTCOME_COMPLETED {
            let stored_effect = self
                .db
                .get_action_effect(command.effect_id)
                .map_err(ActionWorkLifecycleError::Internal)?;
            let already_completed = stored_effect
                .as_ref()
                .is_some_and(|effect| effect.status == EFFECT_STATUS_COMPLETED);
            if !already_completed
                && let Some(reason) = self.delegator_apply_refusal(command.effect_id)?
            {
                if stored_effect.is_none() {
                    return Err(ActionWorkLifecycleError::FailedPrecondition(
                        reason.as_str().into(),
                    ));
                }
                let stored = self
                    .db
                    .ack_action_work(
                        command.effect_id,
                        command.runtime_id,
                        command.claim_generation,
                        command.fencing_token,
                        ACK_OUTCOME_FAILED,
                        reason.as_str(),
                        now_ms,
                    )
                    .map_err(classify_ack_error)?;
                self.record_delegator_refusal_receipt(&stored, command.runtime_id, reason, now_ms)?;
                self.record_ack_audit(&stored, actor, command.runtime_id, now_ms);
                return Err(ActionWorkLifecycleError::FailedPrecondition(
                    reason.as_str().into(),
                ));
            }
        }
        // Fail closed before releasing the claim when a different artifact is
        // already bound. The locked harvest re-checks before writing.
        if let Some(incoming) = artifact.as_ref()
            && let Some(effect) = self
                .db
                .get_action_effect(command.effect_id)
                .map_err(ActionWorkLifecycleError::Internal)?
            && let Some(receipt) = self
                .db
                .get_operation_receipt(&effect.operation_id)
                .map_err(ActionWorkLifecycleError::Internal)?
            && let Some(existing) = receipt.artifact.as_ref()
            && existing != incoming
        {
            return Err(ActionWorkLifecycleError::InvalidArgument(
                "invalid artifact: receipt already has a different artifact".into(),
            ));
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
        // Terminal same-outcome replay skips claim fencing. Bind a new artifact
        // only when this request still presents the live claim fence.
        let allow_artifact_bind = stored.fence_matches(
            command.runtime_id,
            command.claim_generation,
            command.fencing_token,
        );
        self.harvest_ack_receipt(
            &stored,
            command.runtime_id,
            artifact,
            allow_artifact_bind,
            now_ms,
        )?;
        self.record_ack_audit(&stored, actor, command.runtime_id, now_ms);
        Ok(AckedActionWork {
            effect: stored,
            park: None,
            replay: false,
        })
    }

    /// Resolve a claim cited by a model call to the claimed Action type.
    /// Read-only. The claim must pass the same live fence as heartbeat and
    /// ack (against the stored owner), have been taken by `caller`, and
    /// belong to `namespace`; an effect in another namespace reads as not
    /// found so its existence is not disclosed.
    pub fn resolve_cited_claim(
        &self,
        claim: CitedActionClaim<'_>,
        caller: &str,
        namespace: &str,
        now_ms: i64,
    ) -> Result<CitedClaimResolution, String> {
        let Some(effect) = self.db.get_action_effect(claim.effect_id)? else {
            return Ok(CitedClaimResolution::NotFound);
        };
        if effect.namespace != namespace {
            return Ok(CitedClaimResolution::NotFound);
        }
        if effect
            .require_live_fence(
                &effect.claim_owner,
                claim.claim_generation,
                claim.fencing_token,
                now_ms,
            )
            .is_err()
        {
            return Ok(CitedClaimResolution::NotLive);
        }
        if effect.claim_principal.is_empty() || effect.claim_principal != caller {
            return Ok(CitedClaimResolution::Foreign);
        }
        let Some(instance) = self.db.get_action_instance(&effect.instance_id)? else {
            return Ok(CitedClaimResolution::NotFound);
        };
        Ok(self
            .db
            .get_governed_action_type(&instance.namespace, &instance.type_id, &instance.version)?
            .map_or(CitedClaimResolution::NotFound, |action_type| {
                CitedClaimResolution::Live(Box::new(action_type))
            }))
    }

    pub fn report_event(
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

    fn fail_closed_delegator_claim(
        &self,
        command: ClaimActionWork<'_>,
        actor: &str,
        now_ms: i64,
        reason: DelegatorApplyRefusal,
    ) -> Result<ClaimedActionWork, ActionWorkLifecycleError> {
        // Take the fence only to fail-ack. The caller never receives Claimed,
        // so the side effect does not run, and the item leaves the claimable
        // queue so later valid work is not stuck behind it.
        let stored = self
            .db
            .claim_action_work(
                command.effect_id,
                command.runtime_id,
                command.request_id,
                actor,
                command.ttl_ms,
                now_ms,
            )
            .map_err(classify_claim_error)?;
        let failed = self
            .db
            .ack_action_work(
                command.effect_id,
                command.runtime_id,
                stored.claim_generation,
                &stored.claim_fencing_token,
                ACK_OUTCOME_FAILED,
                reason.as_str(),
                now_ms,
            )
            .map_err(classify_ack_error)?;
        self.record_delegator_refusal_receipt(&failed, command.runtime_id, reason, now_ms)?;
        self.record_ack_audit(&failed, actor, command.runtime_id, now_ms);
        Err(ActionWorkLifecycleError::FailedPrecondition(
            reason.as_str().into(),
        ))
    }

    fn delegator_apply_refusal(
        &self,
        effect_id: &str,
    ) -> Result<Option<DelegatorApplyRefusal>, ActionWorkLifecycleError> {
        let Some(effect) = self
            .db
            .get_action_effect(effect_id)
            .map_err(ActionWorkLifecycleError::Internal)?
        else {
            return Ok(Some(DelegatorApplyRefusal::RecordMissing));
        };
        let Some(instance) = self
            .db
            .get_action_instance(&effect.instance_id)
            .map_err(ActionWorkLifecycleError::Internal)?
        else {
            return Ok(Some(DelegatorApplyRefusal::RecordMissing));
        };
        match revalidate_delegator_at_apply(
            self.db,
            instance.delegating_actor.as_deref(),
            &instance.namespace,
        ) {
            Ok(()) => {}
            Err(DelegatorApplyError::Refused(reason)) => return Ok(Some(reason)),
            Err(DelegatorApplyError::Internal(error)) => {
                return Err(ActionWorkLifecycleError::Internal(error));
            }
        }
        if !self.enforce_agent_ceiling {
            return Ok(None);
        }
        let agent = instance.principal.trim();
        let Some(user) = instance
            .delegating_actor
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        if agent.is_empty() || agent == user {
            return Ok(None);
        }
        // Grant ceiling only. Human credential liveness is already checked
        // on `delegating_actor`; an agent may hold a namespace grant without
        // its own login credential.
        let state = current_delegating_principal_state(
            self.db,
            agent,
            &instance.namespace,
            NamespaceAction::Write,
        )
        .map_err(ActionWorkLifecycleError::Internal)?;
        match revalidate_agent_ceiling(Some(agent), state.holds_needed_grant) {
            Ok(()) => Ok(None),
            Err(reason) => Ok(Some(reason)),
        }
    }

    fn record_delegator_refusal_receipt(
        &self,
        effect: &ActionEffect,
        runtime_id: &str,
        reason: DelegatorApplyRefusal,
        now_ms: i64,
    ) -> Result<(), ActionWorkLifecycleError> {
        match self
            .db
            .update_operation_receipt(&effect.operation_id, |receipt| {
                if receipt
                    .events
                    .iter()
                    .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
                {
                    return Ok(());
                }
                let parent = receipt
                    .events
                    .last()
                    .map(|event| event.event_id.clone())
                    .unwrap_or_else(|| format!("{}:intent", effect.operation_id));
                receipt.events.push(OperationReceiptEvent {
                    event_id: format!("{}:outcome", effect.operation_id),
                    operation_id: effect.operation_id.clone(),
                    parent_event_id: Some(parent),
                    timestamp_ms: now_ms,
                    kind: ReceiptEventKind::OutcomeRecorded,
                    surface: ReceiptEventKind::OutcomeRecorded.surface(),
                    actor: runtime_id.to_string(),
                    references: Vec::new(),
                    attributes: BTreeMap::from([
                        ("outcome".into(), "denied".into()),
                        ("reason".into(), reason.as_str().into()),
                        ("effect_id".into(), effect.effect_id.clone()),
                        ("instance_id".into(), effect.instance_id.clone()),
                    ]),
                });
                receipt.completed_at_ms = Some(now_ms);
                receipt.uncovered_surfaces.clear();
                Ok(())
            }) {
            Ok(_) => Ok(()),
            Err(error) if error.contains("operation receipt") && error.contains("not found") => {
                Ok(())
            }
            Err(error) => Err(ActionWorkLifecycleError::Internal(error)),
        }
    }

    fn harvest_ack_receipt(
        &self,
        effect: &ActionEffect,
        runtime_id: &str,
        artifact: Option<ReceiptArtifact>,
        allow_artifact_bind: bool,
        now_ms: i64,
    ) -> Result<(), ActionWorkLifecycleError> {
        if !matches!(
            effect.status.as_str(),
            EFFECT_STATUS_COMPLETED | EFFECT_STATUS_FAILED
        ) {
            return Ok(());
        }
        // Hold the reporter lock across read-modify-write so a late artifact
        // attach cannot clobber concurrently appended harvest events.
        match self
            .db
            .update_operation_receipt(&effect.operation_id, |receipt| {
                apply_ack_harvest(
                    receipt,
                    effect,
                    runtime_id,
                    artifact.as_ref(),
                    allow_artifact_bind,
                    now_ms,
                )
                .map_err(|error| match error {
                    ActionWorkLifecycleError::InvalidArgument(message)
                    | ActionWorkLifecycleError::Internal(message) => message,
                    other => format!("{other:?}"),
                })
                .map(|_| ())
            }) {
            Ok(_) => Ok(()),
            Err(error) if error.contains("operation receipt") && error.contains("not found") => {
                Ok(())
            }
            Err(error) if error.starts_with("invalid artifact:") => {
                Err(ActionWorkLifecycleError::InvalidArgument(error))
            }
            Err(error) => Err(ActionWorkLifecycleError::Internal(error)),
        }
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

fn apply_ack_harvest(
    receipt: &mut OperationReceipt,
    effect: &ActionEffect,
    runtime_id: &str,
    artifact: Option<&ReceiptArtifact>,
    allow_artifact_bind: bool,
    now_ms: i64,
) -> Result<bool, ActionWorkLifecycleError> {
    let mut changed = false;
    if let Some(incoming) = artifact {
        match &receipt.artifact {
            Some(existing) if existing != incoming => {
                return Err(ActionWorkLifecycleError::InvalidArgument(
                    "invalid artifact: receipt already has a different artifact".into(),
                ));
            }
            Some(_) => {}
            None if allow_artifact_bind => {
                receipt.artifact = Some(incoming.clone());
                changed = true;
            }
            None => {
                return Err(ActionWorkLifecycleError::InvalidArgument(
                    "invalid artifact: completed work cannot bind an artifact after the claim is released".into(),
                ));
            }
        }
    }
    let has_outcome = receipt
        .events
        .iter()
        .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded);
    let has_artifact_event = receipt
        .events
        .iter()
        .any(|event| event.kind == ReceiptEventKind::ArtifactProduced);
    if !has_outcome {
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
        let mut outcome_parent = format!("{}:action-ack", effect.operation_id);
        if receipt.artifact.is_some() && !has_artifact_event {
            receipt.events.push(OperationReceiptEvent {
                event_id: format!("{}:artifact", effect.operation_id),
                operation_id: effect.operation_id.clone(),
                parent_event_id: Some(outcome_parent.clone()),
                timestamp_ms: now_ms,
                kind: ReceiptEventKind::ArtifactProduced,
                surface: ReceiptEventKind::ArtifactProduced.surface(),
                actor: runtime_id.to_string(),
                references: Vec::new(),
                attributes: BTreeMap::from([
                    ("effect_id".into(), effect.effect_id.clone()),
                    ("source".into(), "ack_action_work".into()),
                ]),
            });
            outcome_parent = format!("{}:artifact", effect.operation_id);
        }
        receipt.events.push(OperationReceiptEvent {
            event_id: format!("{}:outcome", effect.operation_id),
            operation_id: effect.operation_id.clone(),
            parent_event_id: Some(outcome_parent),
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
        changed = true;
    } else if receipt.artifact.is_some() && !has_artifact_event {
        let parent = receipt
            .events
            .last()
            .map(|event| event.event_id.clone())
            .unwrap_or_else(|| format!("{}:intent", effect.operation_id));
        receipt.events.push(OperationReceiptEvent {
            event_id: format!("{}:artifact", effect.operation_id),
            operation_id: effect.operation_id.clone(),
            parent_event_id: Some(parent),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::ArtifactProduced,
            surface: ReceiptEventKind::ArtifactProduced.surface(),
            actor: runtime_id.to_string(),
            references: Vec::new(),
            attributes: BTreeMap::from([
                ("effect_id".into(), effect.effect_id.clone()),
                ("source".into(), "ack_action_work".into()),
            ]),
        });
        changed = true;
    }
    Ok(changed)
}

const ACK_ARTIFACT_JSON_MAX_BYTES: usize = 64 * 1024;
const FORBIDDEN_ARTIFACT_KEYS: &[&str] = &[
    "content",
    "content_base64",
    "bytes",
    "file_bytes",
    "payload_base64",
];

fn parse_ack_artifact(
    artifact_json: &str,
) -> Result<Option<ReceiptArtifact>, ActionWorkLifecycleError> {
    let trimmed = artifact_json.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > ACK_ARTIFACT_JSON_MAX_BYTES {
        return Err(ActionWorkLifecycleError::InvalidArgument(
            "invalid artifact: artifact_json exceeds 65536 bytes".into(),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(trimmed).map_err(|_| {
        ActionWorkLifecycleError::InvalidArgument(
            "invalid artifact: artifact_json is not JSON".into(),
        )
    })?;
    validate_ack_artifact(&value)?;
    serde_json::from_value(value).map(Some).map_err(|_| {
        ActionWorkLifecycleError::InvalidArgument(
            "invalid artifact: artifact_json is not a retained-artifact manifest".into(),
        )
    })
}

fn validate_ack_artifact(value: &serde_json::Value) -> Result<(), ActionWorkLifecycleError> {
    let Some(object) = value.as_object() else {
        return Err(ActionWorkLifecycleError::InvalidArgument(
            "invalid artifact: artifact_json must be a JSON object".into(),
        ));
    };
    reject_forbidden_artifact_keys(value)?;
    reject_unknown_artifact_keys(
        object,
        &["artifact_id", "digest", "tree_digest", "files"],
        "artifact",
    )?;
    for field in ["artifact_id", "digest", "tree_digest"] {
        let Some(raw) = object.get(field).and_then(serde_json::Value::as_str) else {
            return Err(ActionWorkLifecycleError::InvalidArgument(format!(
                "invalid artifact: {field} is required"
            )));
        };
        if raw.trim().is_empty() {
            return Err(ActionWorkLifecycleError::InvalidArgument(format!(
                "invalid artifact: {field} is required"
            )));
        }
        if field != "artifact_id" {
            require_content_digest(field, raw)?;
        }
    }
    if let Some(files) = object.get("files") {
        let Some(files) = files.as_array() else {
            return Err(ActionWorkLifecycleError::InvalidArgument(
                "invalid artifact: files must be an array".into(),
            ));
        };
        for (index, file) in files.iter().enumerate() {
            let Some(file) = file.as_object() else {
                return Err(ActionWorkLifecycleError::InvalidArgument(format!(
                    "invalid artifact: files[{index}] must be an object"
                )));
            };
            reject_unknown_artifact_keys(
                file,
                &["path", "kind", "digest", "mode", "immutable"],
                &format!("files[{index}]"),
            )?;
            for field in ["path", "kind", "digest"] {
                let Some(raw) = file.get(field).and_then(serde_json::Value::as_str) else {
                    return Err(ActionWorkLifecycleError::InvalidArgument(format!(
                        "invalid artifact: files[{index}].{field} is required"
                    )));
                };
                if raw.trim().is_empty() {
                    return Err(ActionWorkLifecycleError::InvalidArgument(format!(
                        "invalid artifact: files[{index}].{field} is required"
                    )));
                }
                if field == "digest" {
                    require_content_digest(&format!("files[{index}].digest"), raw)?;
                }
            }
        }
    }
    Ok(())
}

fn reject_unknown_artifact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), ActionWorkLifecycleError> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(ActionWorkLifecycleError::InvalidArgument(format!(
            "invalid artifact: {label} has unknown field {key}"
        )));
    }
    Ok(())
}

fn reject_forbidden_artifact_keys(
    value: &serde_json::Value,
) -> Result<(), ActionWorkLifecycleError> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(key) = map
                .keys()
                .find(|key| FORBIDDEN_ARTIFACT_KEYS.contains(&key.as_str()))
            {
                return Err(ActionWorkLifecycleError::InvalidArgument(format!(
                    "invalid artifact: {key} is not allowed on a retained-artifact manifest"
                )));
            }
            for nested in map.values() {
                reject_forbidden_artifact_keys(nested)?;
            }
        }
        serde_json::Value::Array(items) => {
            for nested in items {
                reject_forbidden_artifact_keys(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn require_content_digest(field: &str, raw: &str) -> Result<(), ActionWorkLifecycleError> {
    let Some(hex) = raw.strip_prefix("sha256:") else {
        return Err(ActionWorkLifecycleError::InvalidArgument(format!(
            "invalid artifact: {field} must be sha256:<64 lowercase hex chars>"
        )));
    };
    if hex.len() != 64
        || hex.chars().any(|character| !character.is_ascii_hexdigit())
        || hex != hex.to_ascii_lowercase()
    {
        return Err(ActionWorkLifecycleError::InvalidArgument(format!(
            "invalid artifact: {field} must be sha256:<64 lowercase hex chars>"
        )));
    }
    Ok(())
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
    use crate::db::runtime_db::RuntimeDb;
    use crate::enterprise::{
        AGENT_CEILING_GRANT_MISSING, DELEGATOR_DISABLED, DELEGATOR_GRANT_MISSING,
        DELEGATOR_NOT_MEMBER, DELEGATOR_RECORD_MISSING,
    };
    use crate::sekai::action_effect::{
        ACK_OUTCOME_COMPLETED, ACK_OUTCOME_FAILED, plan_effects_for_admit,
    };
    use crate::sekai::action_instance::{ActionInstance, STATUS_ADMITTED};
    use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;
    use crate::sekai::security::{Grant, Role};
    use sekai_domain::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptArtifact,
        ReceiptSurface, UncoveredSurface,
    };

    fn seed_admitted_instance(
        db: &RuntimeDb,
        effect: &ActionEffect,
        delegating_actor: Option<&str>,
    ) {
        db.put_action_instance(&ActionInstance {
            instance_id: effect.instance_id.clone(),
            namespace: effect.namespace.clone(),
            type_id: "dispatch".into(),
            version: "1".into(),
            principal: "runtime".into(),
            delegating_actor: delegating_actor.map(str::to_string),
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            request_digest: "digest-1".into(),
            idempotency_key: format!("idem-{}", effect.effect_id),
            operation_id: effect.operation_id.clone(),
            status: STATUS_ADMITTED.into(),
            deny_reason: String::new(),
            evidence_submission_ids: Vec::new(),
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
            system_one_fill_json: String::new(),
            parked_object_digest: String::new(),
            decided_by: String::new(),
            approval_decision: String::new(),
            autonomous_envelope_id: String::new(),
            review: Default::default(),
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
        })
        .unwrap();
    }

    fn seed_effect_row(db: &RuntimeDb) -> ActionEffect {
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

    fn seed_effect(db: &RuntimeDb) -> ActionEffect {
        let effect = seed_effect_row(db);
        seed_admitted_instance(db, &effect, None);
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
    fn freeze_blocks_in_flight_agent_ack() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        let claimed = ActionWorkLifecycle::new(&db)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    request_id: "claim-freeze",
                    ttl_ms: 60_000,
                },
                "operator",
                100,
            )
            .unwrap();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "acme".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_AGENT_ACTIONS.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let ack = AckActionWork {
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
            artifact_json: "",
        };
        let blocked = ActionWorkLifecycle::new(&db)
            .ack(ack.clone(), "agent:bot", 200)
            .unwrap_err();
        match blocked {
            ActionWorkLifecycleError::FailedPrecondition(reason) => {
                assert!(reason.contains("write freeze"));
            }
            other => panic!("expected freeze, got {other:?}"),
        }
        ActionWorkLifecycle::new(&db)
            .ack(ack.clone(), "operator", 200)
            .unwrap();
        ActionWorkLifecycle::new(&db)
            .ack(ack, "agent:bot", 300)
            .unwrap();
    }

    #[test]
    fn freeze_blocks_persisted_agent_ack() {
        let db = RuntimeDb::memory();
        let effect = seed_effect_row(&db);
        db.put_action_instance(&ActionInstance {
            instance_id: effect.instance_id.clone(),
            namespace: effect.namespace.clone(),
            type_id: "dispatch".into(),
            version: "1".into(),
            principal: "runtime".into(),
            delegating_actor: None,
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            request_digest: "digest-1".into(),
            idempotency_key: format!("idem-{}", effect.effect_id),
            operation_id: effect.operation_id.clone(),
            status: STATUS_ADMITTED.into(),
            deny_reason: String::new(),
            evidence_submission_ids: Vec::new(),
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
            system_one_fill_json: String::new(),
            parked_object_digest: String::new(),
            decided_by: String::new(),
            approval_decision: String::new(),
            autonomous_envelope_id: String::new(),
            review: Default::default(),
            agent_action: true,
            admission_tenant: String::new(),
            resource_tenant: String::new(),
            marking: String::new(),
            conflict: None,
            approval: None,
            offline: None,
            admission_lease: None,
            admission_ontology_digest: None,
            admission_budget_already_reserved: false,
        })
        .unwrap();
        let claimed = ActionWorkLifecycle::new(&db)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    request_id: "claim-persisted-agent",
                    ttl_ms: 60_000,
                },
                "operator",
                100,
            )
            .unwrap();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "acme".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_AGENT_ACTIONS.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionWorkLifecycle::new(&db)
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
                    artifact_json: "",
                },
                "operator",
                200,
            )
            .unwrap_err();
        match blocked {
            ActionWorkLifecycleError::FailedPrecondition(reason) => {
                assert!(reason.contains("write freeze"));
            }
            other => panic!("expected freeze, got {other:?}"),
        }
    }

    #[test]
    fn principal_agent_freeze_on_human_origin_does_not_block_machine_ack() {
        let db = RuntimeDb::memory();
        let effect = seed_effect_row(&db);
        db.put_action_instance(&ActionInstance {
            instance_id: effect.instance_id.clone(),
            namespace: effect.namespace.clone(),
            type_id: "dispatch".into(),
            version: "1".into(),
            principal: "alice".into(),
            delegating_actor: None,
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            request_digest: "digest-1".into(),
            idempotency_key: format!("idem-{}", effect.effect_id),
            operation_id: effect.operation_id.clone(),
            status: STATUS_ADMITTED.into(),
            deny_reason: String::new(),
            evidence_submission_ids: Vec::new(),
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
            system_one_fill_json: String::new(),
            parked_object_digest: String::new(),
            decided_by: String::new(),
            approval_decision: String::new(),
            autonomous_envelope_id: String::new(),
            review: Default::default(),
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
        })
        .unwrap();
        let claimed = claim_effect(&db, &effect);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_PRINCIPAL.into(),
            scope_value: "alice".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_AGENT_ACTIONS.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let result = ActionWorkLifecycle::new(&db).ack(
            ack_completed(&effect.effect_id, &claimed, ""),
            "agent:bot",
            200,
        );
        if let Err(ActionWorkLifecycleError::FailedPrecondition(reason)) = result {
            assert!(
                !reason.contains("write freeze"),
                "machine ack must not inherit the human origin's agent freeze: {reason}"
            );
        }
    }

    #[test]
    fn freeze_blocks_origin_principal_ack() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        let claimed = ActionWorkLifecycle::new(&db)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    request_id: "claim-origin-freeze",
                    ttl_ms: 60_000,
                },
                "operator",
                100,
            )
            .unwrap();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_PRINCIPAL.into(),
            scope_value: "runtime".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionWorkLifecycle::new(&db)
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
                    artifact_json: "",
                },
                "operator",
                200,
            )
            .unwrap_err();
        match blocked {
            ActionWorkLifecycleError::FailedPrecondition(reason) => {
                assert!(reason.contains("write freeze"));
            }
            other => panic!("expected freeze, got {other:?}"),
        }
    }

    #[test]
    fn freeze_blocks_delegating_principal_ack() {
        let (db, effect, _) = seed_delegated_apply_path();
        let claimed = claim_effect(&db, &effect);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_PRINCIPAL.into(),
            scope_value: DELEGATOR.into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionWorkLifecycle::new(&db)
            .ack(
                ack_completed(&effect.effect_id, &claimed, ""),
                "operator",
                200,
            )
            .unwrap_err();
        match blocked {
            ActionWorkLifecycleError::FailedPrecondition(reason) => {
                assert!(reason.contains("write freeze"));
                assert!(reason.contains("principal/origin-user"));
            }
            other => panic!("expected freeze, got {other:?}"),
        }
    }

    #[test]
    fn freeze_blocks_persisted_resource_tenant_ack() {
        let db = RuntimeDb::memory();
        let effect = seed_effect_row(&db);
        db.put_action_instance(&ActionInstance {
            instance_id: effect.instance_id.clone(),
            namespace: effect.namespace.clone(),
            type_id: "dispatch".into(),
            version: "1".into(),
            principal: "runtime".into(),
            delegating_actor: None,
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            request_digest: "digest-1".into(),
            idempotency_key: format!("idem-{}", effect.effect_id),
            operation_id: effect.operation_id.clone(),
            status: STATUS_ADMITTED.into(),
            deny_reason: String::new(),
            evidence_submission_ids: Vec::new(),
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
            system_one_fill_json: String::new(),
            parked_object_digest: String::new(),
            decided_by: String::new(),
            approval_decision: String::new(),
            autonomous_envelope_id: String::new(),
            review: Default::default(),
            agent_action: false,
            admission_tenant: String::new(),
            resource_tenant: "tenant-test".into(),
            marking: String::new(),
            conflict: None,
            approval: None,
            offline: None,
            admission_lease: None,
            admission_ontology_digest: None,
            admission_budget_already_reserved: false,
        })
        .unwrap();
        let claimed = claim_effect(&db, &effect);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
            scope_value: "tenant-test".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionWorkLifecycle::new(&db)
            .ack(
                ack_completed(&effect.effect_id, &claimed, ""),
                "operator",
                200,
            )
            .unwrap_err();
        match blocked {
            ActionWorkLifecycleError::FailedPrecondition(reason) => {
                assert!(reason.contains("write freeze"));
                assert!(reason.contains("tenant/tenant-test"));
            }
            other => panic!("expected freeze, got {other:?}"),
        }
    }

    #[test]
    fn freeze_blocks_persisted_admission_tenant_ack() {
        let db = RuntimeDb::memory();
        let effect = seed_effect_row(&db);
        db.put_action_instance(&ActionInstance {
            instance_id: effect.instance_id.clone(),
            namespace: effect.namespace.clone(),
            type_id: "dispatch".into(),
            version: "1".into(),
            principal: "runtime".into(),
            delegating_actor: None,
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            request_digest: "digest-1".into(),
            idempotency_key: format!("idem-{}", effect.effect_id),
            operation_id: effect.operation_id.clone(),
            status: STATUS_ADMITTED.into(),
            deny_reason: String::new(),
            evidence_submission_ids: Vec::new(),
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
            system_one_fill_json: String::new(),
            parked_object_digest: String::new(),
            decided_by: String::new(),
            approval_decision: String::new(),
            autonomous_envelope_id: String::new(),
            review: Default::default(),
            agent_action: false,
            admission_tenant: "acme-tenant".into(),
            resource_tenant: String::new(),
            marking: String::new(),
            conflict: None,
            approval: None,
            offline: None,
            admission_lease: None,
            admission_ontology_digest: None,
            admission_budget_already_reserved: false,
        })
        .unwrap();
        let claimed = claim_effect(&db, &effect);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
            scope_value: "acme-tenant".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionWorkLifecycle::new(&db)
            .ack(
                ack_completed(&effect.effect_id, &claimed, ""),
                "operator",
                200,
            )
            .unwrap_err();
        match blocked {
            ActionWorkLifecycleError::FailedPrecondition(reason) => {
                assert!(reason.contains("write freeze"));
                assert!(reason.contains("tenant/acme-tenant"));
            }
            other => panic!("expected freeze, got {other:?}"),
        }
    }

    #[test]
    fn freeze_blocks_registered_tenant_ack() {
        let db = RuntimeDb::memory();
        let effect = seed_effect_row(&db);
        seed_admitted_instance(&db, &effect, None);
        db.put_service_principal(
            &crate::sekai::service_principal::ServicePrincipalRegistration {
                principal: "runtime".into(),
                tenant_id: "acme-tenant".into(),
                namespaces: vec!["acme".into()],
                action_types: vec!["dispatch".into()],
                registered_by: "local".into(),
                created_at_ms: 1,
                updated_at_ms: 1,
            },
        )
        .unwrap();
        let claimed = claim_effect(&db, &effect);
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_TENANT.into(),
            scope_value: "acme-tenant".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let blocked = ActionWorkLifecycle::new(&db)
            .ack(
                ack_completed(&effect.effect_id, &claimed, ""),
                "operator",
                200,
            )
            .unwrap_err();
        match blocked {
            ActionWorkLifecycleError::FailedPrecondition(reason) => {
                assert!(reason.contains("write freeze"));
                assert!(reason.contains("tenant/acme-tenant"));
            }
            other => panic!("expected freeze, got {other:?}"),
        }
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
            ontology_digest: None,
            artifact: None,
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
                    artifact_json: "",
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
        assert!(receipt.artifact.is_none());
        assert!(
            receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        );
    }

    fn sample_artifact_json() -> String {
        serde_json::json!({
            "artifact_id": "art-1",
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tree_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "files": [{
                "path": "app/main.rs",
                "kind": "application",
                "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "mode": "0644",
                "immutable": true
            }]
        })
        .to_string()
    }

    fn seed_open_receipt(db: &RuntimeDb, effect: &ActionEffect) {
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
            ontology_digest: None,
            artifact: None,
        })
        .unwrap();
    }

    fn claim_effect(db: &RuntimeDb, effect: &ActionEffect) -> ActionEffect {
        ActionWorkLifecycle::new(db)
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
            .unwrap()
            .effect
    }

    #[test]
    fn completed_ack_persists_credential_free_artifact() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        seed_open_receipt(&db, &effect);
        let claimed = claim_effect(&db, &effect);
        let artifact_json = sample_artifact_json();

        ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.claim_generation,
                    fencing_token: &claimed.claim_fencing_token,
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: &artifact_json,
                },
                "operator",
                200,
            )
            .unwrap();

        let receipt = db
            .get_operation_receipt(&effect.operation_id)
            .unwrap()
            .unwrap();
        let artifact = receipt.artifact.expect("artifact");
        assert_eq!(artifact.artifact_id, "art-1");
        assert_eq!(artifact.files.len(), 1);
        assert_eq!(artifact.files[0].kind, "application");
        assert!(
            receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::ArtifactProduced)
        );
        assert!(
            receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        );
    }

    #[test]
    fn completed_ack_attaches_artifact_when_outcome_already_exists() {
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
            completed_at_ms: Some(50),
            events: vec![OperationReceiptEvent {
                event_id: format!("{}:outcome", effect.operation_id),
                operation_id: effect.operation_id.clone(),
                parent_event_id: None,
                timestamp_ms: 50,
                kind: ReceiptEventKind::OutcomeRecorded,
                surface: ReceiptEventKind::OutcomeRecorded.surface(),
                actor: "operator".into(),
                references: Vec::new(),
                attributes: BTreeMap::new(),
            }],
            uncovered_surfaces: vec![UncoveredSurface {
                surface: ReceiptSurface::Routing,
                reason: "not applicable".into(),
            }],
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        })
        .unwrap();
        let claimed = claim_effect(&db, &effect);
        let artifact_json = sample_artifact_json();

        ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.claim_generation,
                    fencing_token: &claimed.claim_fencing_token,
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: &artifact_json,
                },
                "operator",
                200,
            )
            .unwrap();

        let receipt = db
            .get_operation_receipt(&effect.operation_id)
            .unwrap()
            .unwrap();
        assert!(receipt.artifact.is_some());
        assert_eq!(
            receipt
                .events
                .iter()
                .filter(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
                .count(),
            1
        );
        assert!(
            receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::ArtifactProduced)
        );
        assert_eq!(receipt.completed_at_ms, Some(50));
    }

    #[test]
    fn failed_ack_rejects_artifact() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        seed_open_receipt(&db, &effect);
        let claimed = claim_effect(&db, &effect);
        let artifact_json = sample_artifact_json();

        let error = ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.claim_generation,
                    fencing_token: &claimed.claim_fencing_token,
                    outcome: ACK_OUTCOME_FAILED,
                    reason: "boom",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: &artifact_json,
                },
                "operator",
                200,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionWorkLifecycleError::InvalidArgument(message) if message.contains("failed")
        ));
        assert_eq!(
            db.get_action_effect(&effect.effect_id)
                .unwrap()
                .unwrap()
                .status,
            "claimed"
        );
    }

    #[test]
    fn replay_ack_cannot_bind_a_missing_artifact() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        seed_open_receipt(&db, &effect);
        let claimed = claim_effect(&db, &effect);

        ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.claim_generation,
                    fencing_token: &claimed.claim_fencing_token,
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: "",
                },
                "operator",
                200,
            )
            .unwrap();

        let artifact_json = sample_artifact_json();
        let error = ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "other-runtime",
                    claim_generation: 0,
                    fencing_token: "forged",
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: &artifact_json,
                },
                "operator",
                300,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionWorkLifecycleError::InvalidArgument(message)
                if message.contains("after the claim is released")
        ));
        assert!(
            db.get_operation_receipt(&effect.operation_id)
                .unwrap()
                .unwrap()
                .artifact
                .is_none()
        );
    }

    #[test]
    fn fenced_retry_can_bind_a_missing_artifact() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        seed_open_receipt(&db, &effect);
        let claimed = claim_effect(&db, &effect);

        ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.claim_generation,
                    fencing_token: &claimed.claim_fencing_token,
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: "",
                },
                "operator",
                200,
            )
            .unwrap();

        let artifact_json = sample_artifact_json();
        ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.claim_generation,
                    fencing_token: &claimed.claim_fencing_token,
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: &artifact_json,
                },
                "operator",
                300,
            )
            .unwrap();

        assert!(
            db.get_operation_receipt(&effect.operation_id)
                .unwrap()
                .unwrap()
                .artifact
                .is_some()
        );
    }

    #[test]
    fn artifact_json_rejects_unknown_fields() {
        assert!(matches!(
            parse_ack_artifact(r#"{"artifact_id":"art-1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tree_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","token":"secret"}"#),
            Err(ActionWorkLifecycleError::InvalidArgument(message)) if message.contains("unknown field token")
        ));
    }

    #[test]
    fn artifact_json_rejects_file_bytes() {
        assert!(matches!(
            parse_ack_artifact(r#"{"artifact_id":"art-1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tree_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","content_base64":"QQ=="}"#),
            Err(ActionWorkLifecycleError::InvalidArgument(message)) if message.contains("content_base64")
        ));
    }

    #[test]
    fn artifact_json_rejects_oversized_payload() {
        let oversized = format!(
            "{{\"artifact_id\":\"{}\"}}",
            "a".repeat(ACK_ARTIFACT_JSON_MAX_BYTES)
        );
        assert!(matches!(
            parse_ack_artifact(&oversized),
            Err(ActionWorkLifecycleError::InvalidArgument(message)) if message.contains("65536")
        ));
    }

    #[test]
    fn matching_artifact_is_accepted_when_already_bound() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        let artifact: ReceiptArtifact = serde_json::from_str(&sample_artifact_json()).unwrap();
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
            ontology_digest: None,
            artifact: Some(artifact),
        })
        .unwrap();
        let claimed = claim_effect(&db, &effect);
        let artifact_json = sample_artifact_json();

        ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.claim_generation,
                    fencing_token: &claimed.claim_fencing_token,
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: &artifact_json,
                },
                "operator",
                200,
            )
            .unwrap();
    }

    #[test]
    fn mismatched_artifact_is_rejected() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        let mut artifact: ReceiptArtifact = serde_json::from_str(&sample_artifact_json()).unwrap();
        artifact.artifact_id = "other".into();
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
            ontology_digest: None,
            artifact: Some(artifact),
        })
        .unwrap();
        let claimed = claim_effect(&db, &effect);
        let artifact_json = sample_artifact_json();

        let error = ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    claim_generation: claimed.claim_generation,
                    fencing_token: &claimed.claim_fencing_token,
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: &artifact_json,
                },
                "operator",
                200,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionWorkLifecycleError::InvalidArgument(message) if message.contains("different artifact")
        ));
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

    fn receipt_updated_at(db: &RuntimeDb, operation_id: &str) -> i64 {
        db.with_sqlite_conn(|conn| {
            conn.query_row(
                "SELECT updated_at FROM chisei_operation_receipts WHERE operation_id=?1",
                [operation_id],
                |row| row.get(0),
            )
            .unwrap()
        })
        .unwrap()
    }

    fn set_receipt_updated_at(db: &RuntimeDb, operation_id: &str, updated_at: i64) {
        db.with_sqlite_conn(|conn| {
            conn.execute(
                "UPDATE chisei_operation_receipts SET updated_at=?1 WHERE operation_id=?2",
                rusqlite::params![updated_at, operation_id],
            )
            .unwrap()
        })
        .unwrap();
    }

    fn ack_completed<'a>(
        effect_id: &'a str,
        claimed: &'a ActionEffect,
        artifact_json: &'a str,
    ) -> AckActionWork<'a> {
        AckActionWork {
            effect_id,
            runtime_id: "shikigami",
            claim_generation: claimed.claim_generation,
            fencing_token: &claimed.claim_fencing_token,
            outcome: ACK_OUTCOME_COMPLETED,
            reason: "done",
            request_id: "",
            checkpoint_store_id: "",
            checkpoint_ref: "",
            checkpoint_digest: "",
            artifact_json,
        }
    }

    #[test]
    fn first_artifact_bind_writes_and_same_outcome_replay_does_not() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        seed_open_receipt(&db, &effect);
        let claimed = claim_effect(&db, &effect);
        let artifact_json = sample_artifact_json();

        ActionWorkLifecycle::new(&db)
            .ack(
                ack_completed(&effect.effect_id, &claimed, &artifact_json),
                "operator",
                200,
            )
            .unwrap();
        set_receipt_updated_at(&db, &effect.operation_id, 1);
        assert_eq!(receipt_updated_at(&db, &effect.operation_id), 1);
        let bound = db
            .get_operation_receipt(&effect.operation_id)
            .unwrap()
            .unwrap();
        assert!(bound.artifact.is_some());
        assert_eq!(bound.completed_at_ms, Some(200));

        ActionWorkLifecycle::new(&db)
            .ack(
                ack_completed(&effect.effect_id, &claimed, &artifact_json),
                "operator",
                300,
            )
            .unwrap();
        assert_eq!(receipt_updated_at(&db, &effect.operation_id), 1);
        let replayed = db
            .get_operation_receipt(&effect.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(replayed, bound);
    }

    #[test]
    fn apply_ack_harvest_is_noop_when_outcome_and_artifact_already_match() {
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
        let artifact: ReceiptArtifact = serde_json::from_str(&sample_artifact_json()).unwrap();
        let mut receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: effect.operation_id.clone(),
            parent_operation_id: None,
            namespace: effect.namespace.clone(),
            operation_class: "action_work".into(),
            initiating_actor: "operator".into(),
            schema_version: "action-work-lifecycle-test/v1".into(),
            policy_version: "not_applicable".into(),
            started_at_ms: 1,
            completed_at_ms: Some(50),
            events: vec![
                OperationReceiptEvent {
                    event_id: format!("{}:outcome", effect.operation_id),
                    operation_id: effect.operation_id.clone(),
                    parent_event_id: None,
                    timestamp_ms: 50,
                    kind: ReceiptEventKind::OutcomeRecorded,
                    surface: ReceiptEventKind::OutcomeRecorded.surface(),
                    actor: "operator".into(),
                    references: Vec::new(),
                    attributes: BTreeMap::new(),
                },
                OperationReceiptEvent {
                    event_id: format!("{}:artifact", effect.operation_id),
                    operation_id: effect.operation_id.clone(),
                    parent_event_id: None,
                    timestamp_ms: 50,
                    kind: ReceiptEventKind::ArtifactProduced,
                    surface: ReceiptEventKind::ArtifactProduced.surface(),
                    actor: "operator".into(),
                    references: Vec::new(),
                    attributes: BTreeMap::new(),
                },
            ],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: Some(artifact.clone()),
        };
        let before = receipt.clone();
        let mut completed = effect.clone();
        completed.status = EFFECT_STATUS_COMPLETED.into();
        assert!(
            !apply_ack_harvest(
                &mut receipt,
                &completed,
                "shikigami",
                Some(&artifact),
                true,
                300,
            )
            .unwrap()
        );
        assert_eq!(receipt, before);
    }

    #[test]
    fn recent_open_receipt_stays_listable_until_ack() {
        let db = RuntimeDb::memory();
        let effect = seed_effect(&db);
        seed_open_receipt(&db, &effect);
        let listed = db
            .list_operation_receipts_in_window(&effect.namespace, 0, 50, 16)
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].completed_at_ms, None);

        let claimed = claim_effect(&db, &effect);
        ActionWorkLifecycle::new(&db)
            .ack(
                ack_completed(&effect.effect_id, &claimed, ""),
                "operator",
                200,
            )
            .unwrap();
        let completed = db
            .get_operation_receipt(&effect.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(completed.completed_at_ms, Some(200));
        assert!(
            completed
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        );
    }

    const DELEGATOR: &str = "origin-user";

    fn seed_delegated_apply_path() -> (RuntimeDb, ActionEffect, Grant) {
        let db = RuntimeDb::memory();
        let effect = seed_effect_row(&db);
        seed_admitted_instance(&db, &effect, Some(DELEGATOR));
        seed_open_receipt(&db, &effect);
        db.create_principal_credential(
            DELEGATOR,
            &sekai_domain::gateway_keys::hash_gateway_key("delegator-secret"),
            1,
        )
        .unwrap();
        let (_, grants) = db
            .ensure_team_namespace("acme", DELEGATOR, Role::Editor, "local")
            .unwrap();
        let grant = grants
            .into_iter()
            .find(|grant| grant.principal == DELEGATOR)
            .expect("namespace grant");
        (db, effect, grant)
    }

    fn receipt_reason(db: &RuntimeDb, operation_id: &str) -> Option<String> {
        db.get_operation_receipt(operation_id)
            .unwrap()
            .unwrap()
            .events
            .into_iter()
            .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
            .and_then(|event| event.attributes.get("reason").cloned())
    }

    fn apply_completed(
        db: &RuntimeDb,
        effect: &ActionEffect,
        claimed: &ActionEffect,
    ) -> Result<AckedActionWork, ActionWorkLifecycleError> {
        ActionWorkLifecycle::new(db).ack(
            ack_completed(&effect.effect_id, claimed, ""),
            "operator",
            200,
        )
    }

    #[test]
    fn apply_succeeds_when_delegator_is_still_authorized() {
        let (db, effect, _) = seed_delegated_apply_path();
        let claimed = claim_effect(&db, &effect);
        let acked = apply_completed(&db, &effect, &claimed).unwrap();
        assert_eq!(acked.effect.status, EFFECT_STATUS_COMPLETED);
    }

    #[test]
    fn completed_ack_replays_after_delegator_is_disabled() {
        let (db, effect, _) = seed_delegated_apply_path();
        let claimed = claim_effect(&db, &effect);
        apply_completed(&db, &effect, &claimed).unwrap();
        db.revoke_principal_credential(DELEGATOR).unwrap();
        let replayed = apply_completed(&db, &effect, &claimed).unwrap();
        assert_eq!(replayed.effect.status, EFFECT_STATUS_COMPLETED);
    }

    fn claim_refused_with(
        db: &RuntimeDb,
        effect: &ActionEffect,
        enforce_agent_ceiling: bool,
    ) -> ActionWorkLifecycleError {
        ActionWorkLifecycle::new(db)
            .with_agent_ceiling(enforce_agent_ceiling)
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
            .expect_err("delegator refusal must fail closed at claim")
    }

    fn claim_refused(db: &RuntimeDb, effect: &ActionEffect) -> ActionWorkLifecycleError {
        claim_refused_with(db, effect, false)
    }

    #[test]
    fn claim_is_refused_after_delegator_is_disabled() {
        let (db, effect, _) = seed_delegated_apply_path();
        db.revoke_principal_credential(DELEGATOR).unwrap();
        let error = claim_refused(&db, &effect);
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_DISABLED.into())
        );
        let stored = db.get_action_effect(&effect.effect_id).unwrap().unwrap();
        assert_eq!(stored.status, EFFECT_STATUS_FAILED);
        assert_eq!(stored.failure_reason, DELEGATOR_DISABLED);
        assert_eq!(
            receipt_reason(&db, &effect.operation_id).as_deref(),
            Some(DELEGATOR_DISABLED)
        );
    }

    #[test]
    fn claim_is_refused_when_delegator_is_not_a_member() {
        let (db, effect, grant) = seed_delegated_apply_path();
        db.delete_grant(&grant.id).unwrap();
        let error = claim_refused(&db, &effect);
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_NOT_MEMBER.into())
        );
        let stored = db.get_action_effect(&effect.effect_id).unwrap().unwrap();
        assert_eq!(stored.status, EFFECT_STATUS_FAILED);
    }

    #[test]
    fn claim_is_refused_when_delegator_grant_is_missing() {
        let (db, effect, grant) = seed_delegated_apply_path();
        db.create_grant(&Grant {
            id: grant.id,
            object_id: grant.object_id,
            principal: grant.principal,
            role: Role::Viewer,
            created: grant.created,
            ..Default::default()
        })
        .unwrap();
        let error = claim_refused(&db, &effect);
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_GRANT_MISSING.into())
        );
        let stored = db.get_action_effect(&effect.effect_id).unwrap().unwrap();
        assert_eq!(stored.status, EFFECT_STATUS_FAILED);
    }

    #[test]
    fn claim_is_refused_when_agent_ceiling_lacks_the_grant() {
        let (db, effect, _) = seed_delegated_apply_path();
        let error = claim_refused_with(&db, &effect, true);
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(AGENT_CEILING_GRANT_MISSING.into())
        );
        let stored = db.get_action_effect(&effect.effect_id).unwrap().unwrap();
        assert_eq!(stored.status, EFFECT_STATUS_FAILED);
        assert_eq!(stored.failure_reason, AGENT_CEILING_GRANT_MISSING);
        assert_eq!(
            receipt_reason(&db, &effect.operation_id).as_deref(),
            Some(AGENT_CEILING_GRANT_MISSING)
        );
    }

    #[test]
    fn claim_succeeds_when_user_and_agent_both_hold_the_grant() {
        let (db, effect, _) = seed_delegated_apply_path();
        db.create_principal_credential(
            "runtime",
            &sekai_domain::gateway_keys::hash_gateway_key("runtime-secret"),
            1,
        )
        .unwrap();
        db.ensure_team_namespace("acme", "runtime", Role::Editor, "local")
            .unwrap();
        ActionWorkLifecycle::new(&db)
            .with_agent_ceiling(true)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: "shikigami",
                    request_id: "claim-ok",
                    ttl_ms: 60_000,
                },
                "operator",
                100,
            )
            .unwrap();
    }

    #[test]
    fn apply_is_refused_when_agent_ceiling_lacks_the_grant() {
        let (db, effect, _) = seed_delegated_apply_path();
        let claimed = claim_effect(&db, &effect);
        let error = ActionWorkLifecycle::new(&db)
            .with_agent_ceiling(true)
            .ack(
                ack_completed(&effect.effect_id, &claimed, ""),
                "operator",
                200,
            )
            .expect_err("agent ceiling must fail closed at apply");
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(AGENT_CEILING_GRANT_MISSING.into())
        );
    }

    #[test]
    fn refused_delegator_claim_drains_so_later_work_remains_claimable() {
        let (db, blocked, _) = seed_delegated_apply_path();
        db.revoke_principal_credential(DELEGATOR).unwrap();
        let _ = claim_refused(&db, &blocked);
        let later = plan_effects_for_admit(
            "ai-2",
            "acme",
            "op-2",
            &[EFFECT_KIND_RUNTIME_DISPATCH.into()],
            r#"{"runtime":"shikigami"}"#,
            20,
            false,
        )
        .unwrap()
        .remove(0);
        db.put_action_effects(std::slice::from_ref(&later)).unwrap();
        seed_admitted_instance(&db, &later, None);
        let claimed = claim_effect(&db, &later);
        assert_eq!(claimed.status, "claimed");
        let blocked_stored = db.get_action_effect(&blocked.effect_id).unwrap().unwrap();
        assert_eq!(blocked_stored.status, EFFECT_STATUS_FAILED);
    }

    #[test]
    fn scheduled_claim_does_not_run_after_delegator_credentials_are_removed() {
        let (db, effect, _) = seed_delegated_apply_path();
        for credential in db.list_credentials(Some(DELEGATOR), None).unwrap() {
            db.revoke_principal_credential(&credential.principal)
                .unwrap();
        }
        let remaining = db.list_credentials(Some(DELEGATOR), None).unwrap();
        assert!(
            remaining
                .iter()
                .all(|credential| credential.status != "active"),
            "removed scheduled owner must not remain enabled"
        );
        let error = claim_refused(&db, &effect);
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_DISABLED.into())
        );
    }

    #[test]
    fn claim_is_refused_when_delegator_has_no_credential_rows() {
        let db = RuntimeDb::memory();
        let effect = seed_effect_row(&db);
        seed_admitted_instance(&db, &effect, Some(DELEGATOR));
        seed_open_receipt(&db, &effect);
        let (_, grants) = db
            .ensure_team_namespace("acme", DELEGATOR, Role::Editor, "local")
            .unwrap();
        assert!(
            grants.iter().any(|grant| grant.principal == DELEGATOR),
            "membership without credentials still exists"
        );
        let error = claim_refused(&db, &effect);
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_DISABLED.into())
        );
    }

    #[test]
    fn apply_refuses_when_delegator_is_disabled() {
        let (db, effect, _) = seed_delegated_apply_path();
        let claimed = claim_effect(&db, &effect);
        db.revoke_principal_credential(DELEGATOR).unwrap();
        let error = apply_completed(&db, &effect, &claimed).unwrap_err();
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_DISABLED.into())
        );
        assert_eq!(
            receipt_reason(&db, &effect.operation_id).as_deref(),
            Some(DELEGATOR_DISABLED)
        );
        let stored = db.get_action_effect(&effect.effect_id).unwrap().unwrap();
        assert_eq!(stored.status, EFFECT_STATUS_FAILED);
    }

    #[test]
    fn apply_refuses_when_delegator_is_not_a_member() {
        let (db, effect, grant) = seed_delegated_apply_path();
        let claimed = claim_effect(&db, &effect);
        db.delete_grant(&grant.id).unwrap();
        let error = apply_completed(&db, &effect, &claimed).unwrap_err();
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_NOT_MEMBER.into())
        );
        assert_eq!(
            receipt_reason(&db, &effect.operation_id).as_deref(),
            Some(DELEGATOR_NOT_MEMBER)
        );
    }

    #[test]
    fn apply_refuses_when_delegator_grant_is_missing() {
        let (db, effect, grant) = seed_delegated_apply_path();
        let claimed = claim_effect(&db, &effect);
        db.create_grant(&Grant {
            id: grant.id,
            object_id: grant.object_id,
            principal: grant.principal,
            role: Role::Viewer,
            created: grant.created,
            ..Default::default()
        })
        .unwrap();
        let error = apply_completed(&db, &effect, &claimed).unwrap_err();
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_GRANT_MISSING.into())
        );
        assert_eq!(
            receipt_reason(&db, &effect.operation_id).as_deref(),
            Some(DELEGATOR_GRANT_MISSING)
        );
    }

    #[test]
    fn apply_refuses_when_action_instance_is_missing() {
        let (db, effect, _) = seed_delegated_apply_path();
        let claimed = claim_effect(&db, &effect);
        db.delete_action_instance(&effect.instance_id).unwrap();
        let error = apply_completed(&db, &effect, &claimed).unwrap_err();
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_RECORD_MISSING.into())
        );
        assert_eq!(
            receipt_reason(&db, &effect.operation_id).as_deref(),
            Some(DELEGATOR_RECORD_MISSING)
        );
        let stored = db.get_action_effect(&effect.effect_id).unwrap().unwrap();
        assert_eq!(stored.status, EFFECT_STATUS_FAILED);
    }

    #[test]
    fn apply_refuses_when_action_effect_is_missing() {
        let db = RuntimeDb::memory();
        let error = ActionWorkLifecycle::new(&db)
            .ack(
                AckActionWork {
                    effect_id: "missing-effect",
                    runtime_id: "shikigami",
                    claim_generation: 1,
                    fencing_token: "fence",
                    outcome: ACK_OUTCOME_COMPLETED,
                    reason: "done",
                    request_id: "",
                    checkpoint_store_id: "",
                    checkpoint_ref: "",
                    checkpoint_digest: "",
                    artifact_json: "",
                },
                "operator",
                200,
            )
            .unwrap_err();
        assert_eq!(
            error,
            ActionWorkLifecycleError::FailedPrecondition(DELEGATOR_RECORD_MISSING.into())
        );
        assert!(db.get_action_effect("missing-effect").unwrap().is_none());
    }
}

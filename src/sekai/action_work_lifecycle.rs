//! Runtime Action Work claim and acknowledgement lifecycle.
//!
//! Transport adapters authenticate callers and enforce namespace access before
//! crossing this seam. This module owns persistence calls, retry/park event
//! ordering, receipt harvest, audit records, active continuation lookup, and
//! storage-error classification behind one interface.

use crate::chisei::receipt::{
    OperationReceipt, OperationReceiptEvent, ReceiptArtifact, ReceiptEventKind,
};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_effect::{
    ACK_OUTCOME_FAILED, ACK_OUTCOME_PARKED, ActionEffect, EFFECT_STATUS_COMPLETED,
    EFFECT_STATUS_FAILED,
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
    pub artifact_json: &'a str,
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
        let artifact = parse_ack_artifact(command.artifact_json)?;
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
        // Fail closed before releasing the claim when a different artifact is
        // already bound. The locked harvest re-checks before writing.
        if let Some(incoming) = artifact.as_ref() {
            if let Some(effect) = self
                .db
                .get_action_effect(command.effect_id)
                .map_err(ActionWorkLifecycleError::Internal)?
            {
                if let Some(receipt) = self
                    .db
                    .get_operation_receipt(&effect.operation_id)
                    .map_err(ActionWorkLifecycleError::Internal)?
                {
                    if let Some(existing) = receipt.artifact.as_ref() {
                        if existing != incoming {
                            return Err(ActionWorkLifecycleError::InvalidArgument(
                                "invalid artifact: receipt already has a different artifact".into(),
                            ));
                        }
                    }
                }
            }
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
) -> Result<(), ActionWorkLifecycleError> {
    if let Some(incoming) = artifact {
        match &receipt.artifact {
            Some(existing) if existing != incoming => {
                return Err(ActionWorkLifecycleError::InvalidArgument(
                    "invalid artifact: receipt already has a different artifact".into(),
                ));
            }
            Some(_) => {}
            None if allow_artifact_bind => receipt.artifact = Some(incoming.clone()),
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
    }
    Ok(())
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
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptArtifact,
        ReceiptSurface, UncoveredSurface,
    };
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::action_effect::{
        ACK_OUTCOME_COMPLETED, ACK_OUTCOME_FAILED, plan_effects_for_admit,
    };
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
}

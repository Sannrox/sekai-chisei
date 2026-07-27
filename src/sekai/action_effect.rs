//! Typed ActionInstance effects (#398 / research #395).
//!
//! Durable children of an admitted ActionInstance. Not silent log lines.
//! Claim for `runtime_dispatch` is #399; external_mutate stays on the permit path.

use crate::db::sekai::SekaiDb;
use crate::sekai::governed_action_type::{
    EFFECT_KIND_EXTERNAL_MUTATE, EFFECT_KIND_NOTIFY, EFFECT_KIND_RUNTIME_DISPATCH,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

pub const EFFECT_STATUS_PENDING: &str = "pending";
pub const EFFECT_STATUS_CLAIMED: &str = "claimed";
pub const EFFECT_STATUS_SENT: &str = "sent";
pub const EFFECT_STATUS_FAILED: &str = "failed";
pub const EFFECT_STATUS_SKIPPED: &str = "skipped";
pub const EFFECT_STATUS_COMPLETED: &str = "completed";
pub const EFFECT_STATUS_PARKED: &str = "parked";

pub const ACK_OUTCOME_COMPLETED: &str = "completed";
pub const ACK_OUTCOME_FAILED: &str = "failed";
pub const ACK_OUTCOME_PARKED: &str = "parked";

const MAX_CLAIM_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const DEFAULT_CLAIM_TTL_MS: i64 = 60_000;

/// Effect kinds that #398 materializes on admit.
pub const MATERIALIZED_EFFECT_KINDS: &[&str] = &[EFFECT_KIND_RUNTIME_DISPATCH, EFFECT_KIND_NOTIFY];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionEffect {
    pub effect_id: String,
    pub instance_id: String,
    pub namespace: String,
    pub operation_id: String,
    /// runtime_dispatch | notify | external_mutate
    pub kind: String,
    /// pending | claimed | sent | failed | skipped | completed | parked
    pub status: String,
    /// Kind-specific bounded JSON object (refs and correlation, not free-form authority).
    pub payload_json: String,
    pub failure_reason: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// Runtime id that holds the claim (empty when unclaimed).
    #[serde(default)]
    pub claim_owner: String,
    #[serde(default)]
    pub claim_generation: u64,
    #[serde(default)]
    pub claim_fencing_token: String,
    #[serde(default)]
    pub claim_expires_at_ms: i64,
    /// Idempotency key for the last successful claim request.
    #[serde(default)]
    pub claim_request_id: String,
}

impl ActionEffect {
    pub fn validate(&self) -> Result<(), String> {
        if self.effect_id.trim().is_empty() {
            return Err("effect_id required".into());
        }
        if self.instance_id.trim().is_empty() {
            return Err("instance_id required".into());
        }
        if self.namespace.trim().is_empty() {
            return Err("namespace required".into());
        }
        if self.operation_id.trim().is_empty() {
            return Err("operation_id required".into());
        }
        match self.kind.as_str() {
            EFFECT_KIND_RUNTIME_DISPATCH | EFFECT_KIND_NOTIFY | EFFECT_KIND_EXTERNAL_MUTATE => {}
            other => return Err(format!("unknown effect kind {other:?}")),
        }
        match self.status.as_str() {
            EFFECT_STATUS_PENDING
            | EFFECT_STATUS_CLAIMED
            | EFFECT_STATUS_SENT
            | EFFECT_STATUS_FAILED
            | EFFECT_STATUS_SKIPPED
            | EFFECT_STATUS_COMPLETED
            | EFFECT_STATUS_PARKED => {}
            other => return Err(format!("invalid effect status {other:?}")),
        }
        let payload: serde_json::Value = serde_json::from_str(&self.payload_json)
            .map_err(|e| format!("payload_json must be JSON: {e}"))?;
        if !payload.is_object() {
            return Err("payload_json must be a JSON object".into());
        }
        Ok(())
    }

    pub fn is_claimable_at(&self, now_ms: i64) -> bool {
        if self.kind != EFFECT_KIND_RUNTIME_DISPATCH {
            return false;
        }
        match self.status.as_str() {
            EFFECT_STATUS_PENDING | EFFECT_STATUS_PARKED => true,
            EFFECT_STATUS_CLAIMED => {
                self.claim_expires_at_ms > 0 && self.claim_expires_at_ms <= now_ms
            }
            _ => false,
        }
    }

    pub fn fence_matches(&self, owner: &str, generation: u64, fencing_token: &str) -> bool {
        self.claim_owner == owner
            && self.claim_generation == generation
            && self.claim_fencing_token == fencing_token
            && !self.claim_fencing_token.is_empty()
    }
}

fn fencing_token(effect_id: &str, generation: u64, owner: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(effect_id.as_bytes());
    hasher.update(b":");
    hasher.update(generation.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(owner.as_bytes());
    format!("fx-{:x}", hasher.finalize())
}

fn normalize_ttl_ms(ttl_ms: i64) -> Result<i64, String> {
    let ttl = if ttl_ms <= 0 {
        DEFAULT_CLAIM_TTL_MS
    } else {
        ttl_ms
    };
    if ttl > MAX_CLAIM_TTL_MS {
        return Err(format!("ttl_ms exceeds max {MAX_CLAIM_TTL_MS}"));
    }
    Ok(ttl)
}

/// Build initial effect records for an admitted instance from the type's allowed kinds.
pub fn plan_effects_for_admit(
    instance_id: &str,
    namespace: &str,
    operation_id: &str,
    allowed_effect_kinds: &[String],
    parameters_json: &str,
    now_ms: i64,
    force_notify_fail: bool,
) -> Result<Vec<ActionEffect>, String> {
    let params: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|e| format!("parameters_json must be JSON: {e}"))?;
    if !params.is_object() {
        return Err("parameters_json must be a JSON object".into());
    }

    let mut effects = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for kind in allowed_effect_kinds {
        if !seen.insert(kind.as_str()) {
            return Err(format!("duplicate effect kind {kind:?}"));
        }
        match kind.as_str() {
            EFFECT_KIND_RUNTIME_DISPATCH => {
                let runtime = params
                    .get("runtime")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default")
                    .to_string();
                let payload = serde_json::json!({
                    "runtime": runtime,
                    "instance_id": instance_id,
                    "operation_id": operation_id,
                    "parameters_digest": sha256_hex(parameters_json.as_bytes()),
                });
                effects.push(ActionEffect {
                    effect_id: format!("gax-{}", uuid::Uuid::new_v4().simple()),
                    instance_id: instance_id.into(),
                    namespace: namespace.into(),
                    operation_id: operation_id.into(),
                    kind: EFFECT_KIND_RUNTIME_DISPATCH.into(),
                    status: EFFECT_STATUS_PENDING.into(),
                    payload_json: payload.to_string(),
                    failure_reason: String::new(),
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                    claim_owner: String::new(),
                    claim_generation: 0,
                    claim_fencing_token: String::new(),
                    claim_expires_at_ms: 0,
                    claim_request_id: String::new(),
                });
            }
            EFFECT_KIND_NOTIFY => {
                let channel = params
                    .get("notify_channel")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default")
                    .to_string();
                let target = params
                    .get("notify_target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let (status, failure_reason, payload) = if force_notify_fail {
                    (
                        EFFECT_STATUS_FAILED,
                        "notify delivery failed (best-effort; admission retained)".to_string(),
                        serde_json::json!({
                            "channel": channel,
                            "target": target,
                            "instance_id": instance_id,
                            "operation_id": operation_id,
                            "delivery": "failed",
                        }),
                    )
                } else {
                    (
                        EFFECT_STATUS_SENT,
                        String::new(),
                        serde_json::json!({
                            "channel": channel,
                            "target": target,
                            "instance_id": instance_id,
                            "operation_id": operation_id,
                            "delivery": "recorded",
                        }),
                    )
                };
                effects.push(ActionEffect {
                    effect_id: format!("gax-{}", uuid::Uuid::new_v4().simple()),
                    instance_id: instance_id.into(),
                    namespace: namespace.into(),
                    operation_id: operation_id.into(),
                    kind: EFFECT_KIND_NOTIFY.into(),
                    status: status.into(),
                    payload_json: payload.to_string(),
                    failure_reason,
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                    claim_owner: String::new(),
                    claim_generation: 0,
                    claim_fencing_token: String::new(),
                    claim_expires_at_ms: 0,
                    claim_request_id: String::new(),
                });
            }
            EFFECT_KIND_EXTERNAL_MUTATE => {
                effects.push(ActionEffect {
                    effect_id: format!("gax-{}", uuid::Uuid::new_v4().simple()),
                    instance_id: instance_id.into(),
                    namespace: namespace.into(),
                    operation_id: operation_id.into(),
                    kind: EFFECT_KIND_EXTERNAL_MUTATE.into(),
                    status: EFFECT_STATUS_SKIPPED.into(),
                    payload_json: serde_json::json!({
                        "reason": "external_mutate uses permit path; not claimable here",
                        "instance_id": instance_id,
                        "operation_id": operation_id,
                    })
                    .to_string(),
                    failure_reason: String::new(),
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                    claim_owner: String::new(),
                    claim_generation: 0,
                    claim_fencing_token: String::new(),
                    claim_expires_at_ms: 0,
                    claim_request_id: String::new(),
                });
            }
            other => {
                return Err(format!("unknown effect kind {other:?}"));
            }
        }
    }
    Ok(effects)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

impl SekaiDb {
    pub fn migrate_action_effects(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_action_effects (
                effect_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL,
                namespace TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                failure_reason TEXT NOT NULL DEFAULT '',
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_action_effects_instance
                ON sekai_action_effects(instance_id, created_at_ms);
            CREATE INDEX IF NOT EXISTS idx_action_effects_kind_status
                ON sekai_action_effects(kind, status);
            CREATE INDEX IF NOT EXISTS idx_action_effects_ns
                ON sekai_action_effects(namespace, created_at_ms DESC);",
        )
        .map_err(|e| e.to_string())
    }

    pub fn put_action_effect(&self, effect: &ActionEffect) -> Result<ActionEffect, String> {
        self.migrate_action_effects()?;
        effect.validate()?;
        let body_json = serde_json::to_string(effect).map_err(|e| e.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_action_effects
             (effect_id, instance_id, namespace, operation_id, kind, status,
              payload_json, failure_reason, created_at_ms, updated_at_ms, body_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                effect.effect_id,
                effect.instance_id,
                effect.namespace,
                effect.operation_id,
                effect.kind,
                effect.status,
                effect.payload_json,
                effect.failure_reason,
                effect.created_at_ms,
                effect.updated_at_ms,
                body_json,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(effect.clone())
    }

    pub fn put_action_effects(
        &self,
        effects: &[ActionEffect],
    ) -> Result<Vec<ActionEffect>, String> {
        let mut out = Vec::with_capacity(effects.len());
        for effect in effects {
            out.push(self.put_action_effect(effect)?);
        }
        Ok(out)
    }

    pub fn get_action_effect(&self, effect_id: &str) -> Result<Option<ActionEffect>, String> {
        self.migrate_action_effects()?;
        let conn = self.conn();
        conn.query_row(
            "SELECT body_json FROM sekai_action_effects WHERE effect_id = ?1",
            params![effect_id],
            |row| {
                let body: String = row.get(0)?;
                Ok(body)
            },
        )
        .optional()
        .map_err(|e| e.to_string())?
        .map(|body| {
            serde_json::from_str(&body).map_err(|e| format!("corrupt action effect body: {e}"))
        })
        .transpose()
    }

    pub fn list_action_effects_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<ActionEffect>, String> {
        self.migrate_action_effects()?;
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT body_json FROM sekai_action_effects
                 WHERE instance_id = ?1
                 ORDER BY created_at_ms, effect_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![instance_id], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body = row.map_err(|e| e.to_string())?;
            out.push(
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action effect body: {e}"))?,
            );
        }
        Ok(out)
    }

    pub fn list_pending_runtime_dispatch_effects(
        &self,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<ActionEffect>, String> {
        self.migrate_action_effects()?;
        let limit = limit.clamp(1, 500) as i64;
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT body_json FROM sekai_action_effects
                 WHERE namespace = ?1 AND kind = ?2 AND status = ?3
                 ORDER BY created_at_ms
                 LIMIT ?4",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![
                    namespace,
                    EFFECT_KIND_RUNTIME_DISPATCH,
                    EFFECT_STATUS_PENDING,
                    limit
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body = row.map_err(|e| e.to_string())?;
            out.push(
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action effect body: {e}"))?,
            );
        }
        Ok(out)
    }

    pub fn update_action_effect(&self, effect: &ActionEffect) -> Result<ActionEffect, String> {
        self.migrate_action_effects()?;
        effect.validate()?;
        let body_json = serde_json::to_string(effect).map_err(|e| e.to_string())?;
        let conn = self.conn();
        let updated = conn
            .execute(
                "UPDATE sekai_action_effects
                 SET status = ?1, payload_json = ?2, failure_reason = ?3,
                     updated_at_ms = ?4, body_json = ?5
                 WHERE effect_id = ?6",
                params![
                    effect.status,
                    effect.payload_json,
                    effect.failure_reason,
                    effect.updated_at_ms,
                    body_json,
                    effect.effect_id,
                ],
            )
            .map_err(|e| e.to_string())?;
        if updated == 0 {
            return Err("action effect not found".into());
        }
        Ok(effect.clone())
    }

    /// Claimable runtime_dispatch: pending/parked, or claimed with expired lease.
    /// Optional runtime filter matches payload.runtime when provided.
    pub fn list_claimable_action_work(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<ActionEffect>, String> {
        self.migrate_action_effects()?;
        let limit = limit.clamp(1, 500);
        // Load candidates then filter claimable (lease expiry is time-dependent).
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT body_json FROM sekai_action_effects
                 WHERE namespace = ?1 AND kind = ?2
                 ORDER BY created_at_ms
                 LIMIT 2000",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![namespace, EFFECT_KIND_RUNTIME_DISPATCH], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body = row.map_err(|e| e.to_string())?;
            let effect: ActionEffect = serde_json::from_str(&body)
                .map_err(|e| format!("corrupt action effect body: {e}"))?;
            if !effect.is_claimable_at(now_ms) {
                continue;
            }
            if let Some(runtime_id) = runtime_id.filter(|r| !r.trim().is_empty()) {
                let payload: serde_json::Value =
                    serde_json::from_str(&effect.payload_json).unwrap_or(serde_json::json!({}));
                let runtime = payload
                    .get("runtime")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                if runtime != runtime_id {
                    continue;
                }
            }
            out.push(effect);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn claim_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        request_id: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<ActionEffect, String> {
        if runtime_id.trim().is_empty() {
            return Err("runtime_id required".into());
        }
        if request_id.trim().is_empty() {
            return Err("request_id required".into());
        }
        if request_id.chars().any(char::is_whitespace) {
            return Err("request_id must not contain whitespace".into());
        }
        let ttl = normalize_ttl_ms(ttl_ms)?;
        // Single-writer style: read, decide, write (same as other SQLite SoR paths).
        let mut effect = self
            .get_action_effect(effect_id)?
            .ok_or_else(|| "action effect not found".to_string())?;
        if effect.kind != EFFECT_KIND_RUNTIME_DISPATCH {
            return Err("only runtime_dispatch effects are claimable".into());
        }
        // Idempotent claim replay for same owner + request_id.
        if effect.status == EFFECT_STATUS_CLAIMED
            && effect.claim_owner == runtime_id
            && effect.claim_request_id == request_id
            && effect.claim_expires_at_ms > now_ms
        {
            return Ok(effect);
        }
        if !effect.is_claimable_at(now_ms) {
            if effect.status == EFFECT_STATUS_CLAIMED && effect.claim_expires_at_ms > now_ms {
                return Err(format!("effect already claimed by {}", effect.claim_owner));
            }
            return Err(format!("effect not claimable in status {}", effect.status));
        }
        let generation = effect.claim_generation.saturating_add(1).max(1);
        effect.status = EFFECT_STATUS_CLAIMED.into();
        effect.claim_owner = runtime_id.into();
        effect.claim_generation = generation;
        effect.claim_fencing_token = fencing_token(effect_id, generation, runtime_id);
        effect.claim_expires_at_ms = now_ms.saturating_add(ttl);
        effect.claim_request_id = request_id.into();
        effect.updated_at_ms = now_ms;
        effect.failure_reason.clear();
        self.update_action_effect(&effect)
    }

    pub fn heartbeat_action_claim(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token_in: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<ActionEffect, String> {
        let ttl = normalize_ttl_ms(ttl_ms)?;
        let mut effect = self
            .get_action_effect(effect_id)?
            .ok_or_else(|| "action effect not found".to_string())?;
        if effect.status != EFFECT_STATUS_CLAIMED {
            return Err(format!("effect not claimed (status={})", effect.status));
        }
        if effect.claim_expires_at_ms <= now_ms {
            return Err("claim lease expired".into());
        }
        if !effect.fence_matches(runtime_id, generation, fencing_token_in) {
            return Err("fencing token or generation mismatch".into());
        }
        effect.claim_expires_at_ms = now_ms.saturating_add(ttl);
        effect.updated_at_ms = now_ms;
        self.update_action_effect(&effect)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ack_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token_in: &str,
        outcome: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<ActionEffect, String> {
        let status = match outcome {
            ACK_OUTCOME_COMPLETED => EFFECT_STATUS_COMPLETED,
            ACK_OUTCOME_FAILED => EFFECT_STATUS_FAILED,
            ACK_OUTCOME_PARKED => EFFECT_STATUS_PARKED,
            other => {
                return Err(format!(
                    "invalid ack outcome {other:?}; expected completed|failed|parked"
                ));
            }
        };
        let mut effect = self
            .get_action_effect(effect_id)?
            .ok_or_else(|| "action effect not found".to_string())?;
        if effect.kind != EFFECT_KIND_RUNTIME_DISPATCH {
            return Err("only runtime_dispatch effects support ack".into());
        }
        // Terminal already with same outcome: idempotent.
        if effect.status == status {
            return Ok(effect);
        }
        if effect.status != EFFECT_STATUS_CLAIMED {
            return Err(format!("effect not claimed (status={})", effect.status));
        }
        if effect.claim_expires_at_ms <= now_ms {
            return Err("claim lease expired".into());
        }
        if !effect.fence_matches(runtime_id, generation, fencing_token_in) {
            return Err("fencing token or generation mismatch".into());
        }
        effect.status = status.into();
        effect.failure_reason = reason.to_string();
        effect.updated_at_ms = now_ms;
        if status == EFFECT_STATUS_PARKED {
            // Return to reclaimable pool without holding a live lease.
            effect.claim_expires_at_ms = 0;
        }
        self.update_action_effect(&effect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_materializes_dispatch_and_notify() {
        let effects = plan_effects_for_admit(
            "ai-1",
            "acme",
            "op-1",
            &["runtime_dispatch".into(), "notify".into()],
            r#"{"runtime":"shikigami","notify_channel":"slack"}"#,
            10,
            false,
        )
        .unwrap();
        assert_eq!(effects.len(), 2);
        assert_eq!(effects[0].kind, EFFECT_KIND_RUNTIME_DISPATCH);
        assert_eq!(effects[0].status, EFFECT_STATUS_PENDING);
        assert_eq!(effects[1].kind, EFFECT_KIND_NOTIFY);
        assert_eq!(effects[1].status, EFFECT_STATUS_SENT);
    }

    #[test]
    fn notify_failure_is_local_to_effect() {
        let effects = plan_effects_for_admit(
            "ai-1",
            "acme",
            "op-1",
            &["notify".into()],
            r#"{}"#,
            10,
            true,
        )
        .unwrap();
        assert_eq!(effects[0].status, EFFECT_STATUS_FAILED);
        assert!(effects[0].failure_reason.contains("best-effort"));
    }

    #[test]
    fn rejects_unknown_kind() {
        let err = plan_effects_for_admit(
            "ai-1",
            "acme",
            "op-1",
            &["shell_exec".into()],
            r#"{}"#,
            10,
            false,
        )
        .unwrap_err();
        assert!(err.contains("unknown"), "{err}");
    }

    #[test]
    fn put_get_list_pending_dispatch() {
        let db = SekaiDb::new(":memory:").unwrap();
        let effects = plan_effects_for_admit(
            "ai-1",
            "acme",
            "op-1",
            &["runtime_dispatch".into(), "notify".into()],
            r#"{"runtime":"shikigami"}"#,
            10,
            false,
        )
        .unwrap();
        db.put_action_effects(&effects).unwrap();
        let listed = db.list_action_effects_for_instance("ai-1").unwrap();
        assert_eq!(listed.len(), 2);
        let pending = db
            .list_pending_runtime_dispatch_effects("acme", 10)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, EFFECT_KIND_RUNTIME_DISPATCH);
        let got = db
            .get_action_effect(&effects[0].effect_id)
            .unwrap()
            .unwrap();
        assert_eq!(got.effect_id, effects[0].effect_id);
    }

    #[test]
    fn claim_exclusivity_fence_expiry_and_ack() {
        let db = SekaiDb::new(":memory:").unwrap();
        let effects = plan_effects_for_admit(
            "ai-1",
            "acme",
            "op-1",
            &["runtime_dispatch".into()],
            r#"{"runtime":"shikigami"}"#,
            10,
            false,
        )
        .unwrap();
        db.put_action_effects(&effects).unwrap();
        let effect_id = effects[0].effect_id.clone();

        let claimable = db
            .list_claimable_action_work("acme", Some("shikigami"), 100, 10)
            .unwrap();
        assert_eq!(claimable.len(), 1);

        let claimed = db
            .claim_action_work(&effect_id, "shikigami", "req-1", 1000, 100)
            .unwrap();
        assert_eq!(claimed.status, EFFECT_STATUS_CLAIMED);
        assert_eq!(claimed.claim_generation, 1);
        assert!(!claimed.claim_fencing_token.is_empty());

        // Double claim by other runtime fails
        let err = db
            .claim_action_work(&effect_id, "other", "req-2", 1000, 150)
            .unwrap_err();
        assert!(
            err.contains("already claimed") || err.contains("not claimable"),
            "{err}"
        );

        // Idempotent same request
        let replay = db
            .claim_action_work(&effect_id, "shikigami", "req-1", 1000, 160)
            .unwrap();
        assert_eq!(replay.claim_generation, 1);

        // Heartbeat
        let hb = db
            .heartbeat_action_claim(
                &effect_id,
                "shikigami",
                1,
                &claimed.claim_fencing_token,
                2000,
                200,
            )
            .unwrap();
        assert!(hb.claim_expires_at_ms >= 2200);

        // Bad fence
        let bad = db
            .heartbeat_action_claim(&effect_id, "shikigami", 1, "wrong", 1000, 250)
            .unwrap_err();
        assert!(bad.contains("fencing"), "{bad}");

        // Expiry reclaim
        let reclaimed = db
            .claim_action_work(&effect_id, "other", "req-3", 1000, 10_000)
            .unwrap();
        assert_eq!(reclaimed.claim_owner, "other");
        assert_eq!(reclaimed.claim_generation, 2);

        let done = db
            .ack_action_work(
                &effect_id,
                "other",
                2,
                &reclaimed.claim_fencing_token,
                ACK_OUTCOME_COMPLETED,
                "",
                10_100,
            )
            .unwrap();
        assert_eq!(done.status, EFFECT_STATUS_COMPLETED);
    }
}

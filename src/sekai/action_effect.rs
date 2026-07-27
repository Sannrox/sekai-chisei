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
    /// pending | claimed | sent | failed | skipped
    pub status: String,
    /// Kind-specific bounded JSON object (refs and correlation, not free-form authority).
    pub payload_json: String,
    pub failure_reason: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
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
            | EFFECT_STATUS_SKIPPED => {}
            other => return Err(format!("invalid effect status {other:?}")),
        }
        let payload: serde_json::Value = serde_json::from_str(&self.payload_json)
            .map_err(|e| format!("payload_json must be JSON: {e}"))?;
        if !payload.is_object() {
            return Err("payload_json must be a JSON object".into());
        }
        Ok(())
    }
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
}

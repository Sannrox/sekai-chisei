//! Typed ActionInstance effects (#398 / research #395).
//!
//! Durable children of an admitted ActionInstance. Not silent log lines.
//! Claim for `runtime_dispatch` is #399; external_mutate stays on the permit path.

use crate::db::sekai::SekaiDb;
use crate::sekai::governed_action_type::{
    EFFECT_KIND_EXTERNAL_MUTATE, EFFECT_KIND_NOTIFY, EFFECT_KIND_RUNTIME_DISPATCH,
};
use crate::sekai::parked_work::{
    ActionWorkContinuation, ActionWorkPark, ParkResult, ParkedWorkResolutionAction,
    ParkedWorkResolutionInput, ResolutionResult, canonical_json, sha256_digest,
    validate_checkpoint_tuple, validate_reason, validate_request_id,
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
pub const EFFECT_STATUS_DEAD_LETTERED: &str = "dead_lettered";
pub const EFFECT_STATUS_SUPERSEDED: &str = "superseded";

pub const EFFECT_LIFECYCLE_READY: &str = "ready";
pub const EFFECT_LIFECYCLE_CLAIMED: &str = "claimed";
pub const EFFECT_LIFECYCLE_AWAITING_CONTINUATION: &str = "awaiting_continuation";
pub const EFFECT_LIFECYCLE_COMPLETED: &str = "completed";
pub const EFFECT_LIFECYCLE_FAILED: &str = "failed";
pub const EFFECT_LIFECYCLE_DEAD_LETTERED: &str = "dead_lettered";
pub const EFFECT_LIFECYCLE_SUPERSEDED: &str = "superseded";

pub const RETRY_POLICY_VERSION_V1: &str = "runtime_dispatch_retry/v1";
pub const DEFAULT_MAX_CLAIM_ATTEMPTS: u32 = 8;
pub const DEFAULT_MAX_LEASE_EXPIRIES: u32 = 3;
pub const DEFAULT_MAX_PARK_CYCLES: u32 = 3;

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
    #[serde(default)]
    pub park_generation: u64,
    #[serde(default)]
    pub active_resolution_id: String,
    #[serde(default)]
    pub claim_attempt_count: u32,
    #[serde(default)]
    pub lease_expiry_count: u32,
    #[serde(default)]
    pub park_count: u32,
    #[serde(default)]
    pub lifecycle_state: String,
    #[serde(default)]
    pub retry_policy_version: String,
    #[serde(default)]
    pub retry_policy_digest: String,
    #[serde(default)]
    pub max_claim_attempts: u32,
    #[serde(default)]
    pub max_lease_expiries: u32,
    #[serde(default)]
    pub max_park_cycles: u32,
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
            | EFFECT_STATUS_PARKED
            | EFFECT_STATUS_DEAD_LETTERED
            | EFFECT_STATUS_SUPERSEDED => {}
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
        match self.effective_lifecycle_state() {
            EFFECT_LIFECYCLE_READY => true,
            EFFECT_LIFECYCLE_CLAIMED => {
                self.claim_expires_at_ms > 0 && self.claim_expires_at_ms <= now_ms
            }
            _ => false,
        }
    }

    pub fn effective_lifecycle_state(&self) -> &str {
        if !self.lifecycle_state.is_empty() {
            return &self.lifecycle_state;
        }
        match self.status.as_str() {
            EFFECT_STATUS_PENDING => EFFECT_LIFECYCLE_READY,
            EFFECT_STATUS_CLAIMED => EFFECT_LIFECYCLE_CLAIMED,
            EFFECT_STATUS_PARKED => EFFECT_LIFECYCLE_AWAITING_CONTINUATION,
            EFFECT_STATUS_COMPLETED => EFFECT_LIFECYCLE_COMPLETED,
            EFFECT_STATUS_FAILED => EFFECT_LIFECYCLE_FAILED,
            EFFECT_STATUS_DEAD_LETTERED => EFFECT_LIFECYCLE_DEAD_LETTERED,
            EFFECT_STATUS_SUPERSEDED => EFFECT_LIFECYCLE_SUPERSEDED,
            other => other,
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
                    park_generation: 0,
                    active_resolution_id: String::new(),
                    claim_attempt_count: 0,
                    lease_expiry_count: 0,
                    park_count: 0,
                    lifecycle_state: EFFECT_LIFECYCLE_READY.into(),
                    retry_policy_version: RETRY_POLICY_VERSION_V1.into(),
                    retry_policy_digest: retry_policy_digest(),
                    max_claim_attempts: DEFAULT_MAX_CLAIM_ATTEMPTS,
                    max_lease_expiries: DEFAULT_MAX_LEASE_EXPIRIES,
                    max_park_cycles: DEFAULT_MAX_PARK_CYCLES,
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
                    park_generation: 0,
                    active_resolution_id: String::new(),
                    claim_attempt_count: 0,
                    lease_expiry_count: 0,
                    park_count: 0,
                    lifecycle_state: status.into(),
                    retry_policy_version: String::new(),
                    retry_policy_digest: String::new(),
                    max_claim_attempts: 0,
                    max_lease_expiries: 0,
                    max_park_cycles: 0,
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
                    park_generation: 0,
                    active_resolution_id: String::new(),
                    claim_attempt_count: 0,
                    lease_expiry_count: 0,
                    park_count: 0,
                    lifecycle_state: EFFECT_STATUS_SKIPPED.into(),
                    retry_policy_version: String::new(),
                    retry_policy_digest: String::new(),
                    max_claim_attempts: 0,
                    max_lease_expiries: 0,
                    max_park_cycles: 0,
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

fn retry_policy_digest() -> String {
    sha256_hex(
        format!(
            "{RETRY_POLICY_VERSION_V1}:{DEFAULT_MAX_CLAIM_ATTEMPTS}:{DEFAULT_MAX_LEASE_EXPIRIES}:{DEFAULT_MAX_PARK_CYCLES}"
        )
        .as_bytes(),
    )
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
                ON sekai_action_effects(namespace, created_at_ms DESC);
            CREATE TABLE IF NOT EXISTS sekai_action_work_parks (
                park_id TEXT PRIMARY KEY,
                effect_id TEXT NOT NULL,
                park_generation INTEGER NOT NULL,
                request_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                body_json TEXT NOT NULL,
                UNIQUE(effect_id, park_generation),
                UNIQUE(effect_id, request_id)
            );
            CREATE TABLE IF NOT EXISTS sekai_parked_resolution_inputs (
                resolution_input_id TEXT PRIMARY KEY,
                effect_id TEXT NOT NULL,
                park_generation INTEGER NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sekai_parked_resolution_actions (
                resolution_action_id TEXT PRIMARY KEY,
                effect_id TEXT NOT NULL,
                park_generation INTEGER NOT NULL,
                request_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                body_json TEXT NOT NULL,
                UNIQUE(effect_id, request_id)
            );
            CREATE TABLE IF NOT EXISTS sekai_action_work_continuations (
                resolution_id TEXT PRIMARY KEY,
                effect_id TEXT NOT NULL,
                park_generation INTEGER NOT NULL,
                body_json TEXT NOT NULL,
                UNIQUE(effect_id, park_generation)
            );
            CREATE TABLE IF NOT EXISTS sekai_action_claim_events (
                effect_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                body_json TEXT NOT NULL,
                PRIMARY KEY(effect_id, request_id)
            );",
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
        if effect.status == EFFECT_STATUS_CLAIMED && effect.claim_expires_at_ms <= now_ms {
            effect.lease_expiry_count = effect.lease_expiry_count.saturating_add(1);
            if effect.max_lease_expiries > 0
                && effect.lease_expiry_count >= effect.max_lease_expiries
            {
                effect.status = EFFECT_STATUS_DEAD_LETTERED.into();
                effect.lifecycle_state = EFFECT_LIFECYCLE_DEAD_LETTERED.into();
                effect.failure_reason = "lease_expiry_limit_exceeded".into();
                effect.updated_at_ms = now_ms;
                self.update_action_effect(&effect)?;
                return Err("lease expiry retry limit exceeded; effect dead-lettered".into());
            }
        }
        if effect.max_claim_attempts > 0 && effect.claim_attempt_count >= effect.max_claim_attempts
        {
            effect.status = EFFECT_STATUS_DEAD_LETTERED.into();
            effect.lifecycle_state = EFFECT_LIFECYCLE_DEAD_LETTERED.into();
            effect.failure_reason = "claim_attempt_limit_exceeded".into();
            effect.updated_at_ms = now_ms;
            self.update_action_effect(&effect)?;
            return Err("claim retry limit exceeded; effect dead-lettered".into());
        }
        let generation = effect.claim_generation.saturating_add(1).max(1);
        effect.status = EFFECT_STATUS_CLAIMED.into();
        effect.lifecycle_state = EFFECT_LIFECYCLE_CLAIMED.into();
        effect.claim_attempt_count = effect.claim_attempt_count.saturating_add(1);
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
            other => {
                return Err(format!(
                    "invalid ack outcome {other:?}; parked requires park_action_work"
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
        effect.lifecycle_state = match status {
            EFFECT_STATUS_COMPLETED => EFFECT_LIFECYCLE_COMPLETED,
            EFFECT_STATUS_FAILED => EFFECT_LIFECYCLE_FAILED,
            EFFECT_STATUS_PARKED => EFFECT_LIFECYCLE_AWAITING_CONTINUATION,
            _ => status,
        }
        .into();
        effect.failure_reason = reason.to_string();
        effect.updated_at_ms = now_ms;
        self.update_action_effect(&effect)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn park_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token_in: &str,
        reason: &str,
        request_id: &str,
        checkpoint_store_id: &str,
        checkpoint_ref: &str,
        checkpoint_digest: &str,
        parked_by: &str,
        now_ms: i64,
    ) -> Result<ParkResult, String> {
        validate_request_id(request_id)?;
        validate_reason(reason)?;
        validate_checkpoint_tuple(checkpoint_store_id, checkpoint_ref, checkpoint_digest)?;
        if !checkpoint_store_id.is_empty() && !checkpoint_store_allowed(checkpoint_store_id) {
            return Err("checkpoint store is not allowlisted".into());
        }
        let request_digest = sha256_digest(
            &serde_json::json!({
                "effect_id": effect_id,
                "runtime_id": runtime_id,
                "claim_generation": generation,
                "fencing_token_digest": sha256_digest(fencing_token_in),
                "outcome": ACK_OUTCOME_PARKED,
                "reason": reason,
                "checkpoint_store_id": checkpoint_store_id,
                "checkpoint_ref": checkpoint_ref,
                "checkpoint_digest": checkpoint_digest,
            })
            .to_string(),
        );
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let replay: Option<(String, String)> = tx
            .query_row(
                "SELECT request_digest, body_json FROM sekai_action_work_parks
                 WHERE effect_id=?1 AND request_id=?2",
                params![effect_id, request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((stored_digest, body)) = replay {
            if stored_digest != request_digest {
                return Err("park acknowledgement idempotency conflict".into());
            }
            let park: ActionWorkPark = serde_json::from_str(&body)
                .map_err(|error| format!("corrupt park record: {error}"))?;
            let effect = load_effect_tx(&tx, effect_id)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(ParkResult {
                effect,
                park,
                replay: true,
            });
        }
        let mut effect = load_effect_tx(&tx, effect_id)?;
        if effect.kind != EFFECT_KIND_RUNTIME_DISPATCH {
            return Err("only runtime_dispatch effects support park".into());
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
        if effect.max_park_cycles > 0 && effect.park_count >= effect.max_park_cycles {
            effect.status = EFFECT_STATUS_DEAD_LETTERED.into();
            effect.lifecycle_state = EFFECT_LIFECYCLE_DEAD_LETTERED.into();
            effect.failure_reason = "park_cycle_limit_exceeded".into();
            effect.updated_at_ms = now_ms;
            update_effect_tx(&tx, &effect)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Err("park retry limit exceeded; effect dead-lettered".into());
        }
        effect.park_generation = effect.park_generation.saturating_add(1);
        effect.park_count = effect.park_count.saturating_add(1);
        effect.status = EFFECT_STATUS_PARKED.into();
        effect.lifecycle_state = EFFECT_LIFECYCLE_AWAITING_CONTINUATION.into();
        effect.failure_reason = reason.into();
        effect.active_resolution_id.clear();
        effect.claim_expires_at_ms = 0;
        effect.updated_at_ms = now_ms;
        let park = ActionWorkPark {
            park_id: format!("park-{}", uuid::Uuid::new_v4().simple()),
            effect_id: effect.effect_id.clone(),
            namespace: effect.namespace.clone(),
            operation_id: effect.operation_id.clone(),
            park_generation: effect.park_generation,
            claim_generation: generation,
            checkpoint_ref: checkpoint_ref.into(),
            checkpoint_digest: checkpoint_digest.into(),
            reason: reason.into(),
            parked_by: parked_by.into(),
            parked_at_ms: now_ms,
            request_id: request_id.into(),
            request_digest,
            checkpoint_store_id: checkpoint_store_id.into(),
        };
        let park_body = serde_json::to_string(&park).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_action_work_parks
             (park_id,effect_id,park_generation,request_id,request_digest,body_json)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                park.park_id,
                park.effect_id,
                park.park_generation as i64,
                park.request_id,
                park.request_digest,
                park_body
            ],
        )
        .map_err(|error| error.to_string())?;
        update_effect_tx(&tx, &effect)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ParkResult {
            effect,
            park,
            replay: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_parked_resolution(
        &self,
        effect_id: &str,
        expected_park_generation: u64,
        input_json: &str,
        reason: &str,
        request_id: &str,
        submitted_by: &str,
        policy_version: &str,
        status: &str,
        approval_id: &str,
        now_ms: i64,
    ) -> Result<ResolutionResult, String> {
        validate_request_id(request_id)?;
        validate_reason(reason)?;
        let input_json = canonical_json(input_json)?;
        if !matches!(
            status,
            "denied" | "pending_execution" | "pending_approval" | "invoked"
        ) {
            return Err("invalid initial resolution action status".into());
        }
        let request_digest = sha256_digest(
            &serde_json::json!({
                "effect_id": effect_id,
                "expected_park_generation": expected_park_generation,
                "input_json": input_json,
                "reason": reason,
                "submitted_by": submitted_by,
            })
            .to_string(),
        );
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some((stored_digest, body)) = tx
            .query_row(
                "SELECT request_digest, body_json FROM sekai_parked_resolution_actions
                 WHERE effect_id=?1 AND request_id=?2",
                params![effect_id, request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
        {
            if stored_digest != request_digest {
                return Err("resolution action idempotency conflict".into());
            }
            let action: ParkedWorkResolutionAction = serde_json::from_str(&body)
                .map_err(|error| format!("corrupt resolution action: {error}"))?;
            let effect = load_effect_tx(&tx, effect_id)?;
            let park = load_park_tx(&tx, effect_id, action.expected_park_generation)?;
            let continuation =
                load_continuation_tx(&tx, effect_id, action.expected_park_generation)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(ResolutionResult {
                effect,
                action,
                continuation,
                park,
                replay: true,
            });
        }
        let mut effect = load_effect_tx(&tx, effect_id)?;
        if effect.effective_lifecycle_state() != EFFECT_LIFECYCLE_AWAITING_CONTINUATION {
            return Err(format!(
                "effect is not awaiting continuation ({})",
                effect.status
            ));
        }
        if effect.park_generation != expected_park_generation {
            return Err("stale park generation".into());
        }
        let park = load_park_tx(&tx, effect_id, expected_park_generation)?;
        let input_digest = sha256_digest(&input_json);
        let input = ParkedWorkResolutionInput {
            resolution_input_id: format!("pri-{}", uuid::Uuid::new_v4().simple()),
            effect_id: effect_id.into(),
            park_generation: expected_park_generation,
            input_json: input_json.clone(),
            input_digest: input_digest.clone(),
            reason: reason.into(),
            submitted_by: submitted_by.into(),
            submitted_at_ms: now_ms,
        };
        let mut action = ParkedWorkResolutionAction {
            resolution_action_id: format!("pra-{}", uuid::Uuid::new_v4().simple()),
            effect_id: effect_id.into(),
            namespace: effect.namespace.clone(),
            expected_park_generation,
            status: status.into(),
            policy_version: policy_version.into(),
            approval_id: approval_id.into(),
            decided_by: submitted_by.into(),
            created_at_ms: now_ms,
            invoked_at_ms: 0,
            resolution_input_id: input.resolution_input_id.clone(),
            request_id: request_id.into(),
            request_digest: request_digest.clone(),
        };
        tx.execute(
            "INSERT INTO sekai_parked_resolution_inputs
             (resolution_input_id,effect_id,park_generation,body_json) VALUES (?1,?2,?3,?4)",
            params![
                input.resolution_input_id,
                input.effect_id,
                input.park_generation as i64,
                serde_json::to_string(&input).map_err(|error| error.to_string())?
            ],
        )
        .map_err(|error| error.to_string())?;
        let continuation = if status == "invoked" {
            stale_competing_resolutions_tx(
                &tx,
                effect_id,
                expected_park_generation,
                &action.resolution_action_id,
                submitted_by,
                now_ms,
            )?;
            action.invoked_at_ms = now_ms;
            let continuation =
                materialize_continuation(&effect, &park, &input, &action, submitted_by, now_ms);
            insert_continuation_tx(&tx, &continuation)?;
            effect.status = EFFECT_STATUS_PENDING.into();
            effect.lifecycle_state = EFFECT_LIFECYCLE_READY.into();
            effect.active_resolution_id = continuation.resolution_id.clone();
            effect.updated_at_ms = now_ms;
            update_effect_tx(&tx, &effect)?;
            Some(continuation)
        } else {
            None
        };
        tx.execute(
            "INSERT INTO sekai_parked_resolution_actions
             (resolution_action_id,effect_id,park_generation,request_id,request_digest,status,body_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                action.resolution_action_id,
                action.effect_id,
                action.expected_park_generation as i64,
                action.request_id,
                action.request_digest,
                action.status,
                serde_json::to_string(&action).map_err(|error| error.to_string())?
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ResolutionResult {
            effect,
            action,
            continuation,
            park,
            replay: false,
        })
    }

    pub fn invoke_parked_resolution(
        &self,
        resolution_action_id: &str,
        effect_id: &str,
        park_generation: u64,
        actor: &str,
        now_ms: i64,
    ) -> Result<ActionWorkContinuation, String> {
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let (mut action, input) =
            load_resolution_tx(&tx, resolution_action_id, effect_id, park_generation)?;
        if action.status == "invoked" {
            let continuation = load_continuation_tx(&tx, effect_id, park_generation)?
                .ok_or_else(|| "invoked resolution is missing its continuation".to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(continuation);
        }
        if !matches!(
            action.status.as_str(),
            "pending_execution" | "execution_accounted"
        ) {
            return Err("resolution action is not invokable".into());
        }
        let mut effect = load_effect_tx(&tx, effect_id)?;
        if effect.effective_lifecycle_state() != EFFECT_LIFECYCLE_AWAITING_CONTINUATION
            || effect.park_generation != park_generation
        {
            return Err("resolution action is stale".into());
        }
        let park = load_park_tx(&tx, effect_id, park_generation)?;
        let continuation = materialize_continuation(&effect, &park, &input, &action, actor, now_ms);
        insert_continuation_tx(&tx, &continuation)?;
        stale_competing_resolutions_tx(
            &tx,
            effect_id,
            park_generation,
            &action.resolution_action_id,
            actor,
            now_ms,
        )?;
        action.status = "invoked".into();
        action.decided_by = actor.into();
        action.invoked_at_ms = now_ms;
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='invoked',body_json=?1
             WHERE resolution_action_id=?2
               AND status IN ('pending_execution','execution_accounted')",
            params![
                serde_json::to_string(&action).map_err(|error| error.to_string())?,
                action.resolution_action_id
            ],
        )
        .map_err(|error| error.to_string())?;
        effect.status = EFFECT_STATUS_PENDING.into();
        effect.lifecycle_state = EFFECT_LIFECYCLE_READY.into();
        effect.active_resolution_id = continuation.resolution_id.clone();
        effect.updated_at_ms = now_ms;
        update_effect_tx(&tx, &effect)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(continuation)
    }

    pub fn authorize_parked_resolution_approval(
        &self,
        resolution_action_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let body: String = tx
            .query_row(
                "SELECT body_json FROM sekai_parked_resolution_actions
                 WHERE resolution_action_id=?1",
                params![resolution_action_id],
                |row| row.get(0),
            )
            .map_err(|_| "resolution action not found".to_string())?;
        let mut action: ParkedWorkResolutionAction = serde_json::from_str(&body)
            .map_err(|error| format!("corrupt resolution action: {error}"))?;
        if action.approval_id != approval_id {
            return Err("resolution approval binding mismatch".into());
        }
        if action.status == "execution_accounted" {
            return Ok(());
        }
        if action.status != "pending_approval" {
            return Err("resolution action is not awaiting approval".into());
        }
        action.status = "execution_accounted".into();
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='execution_accounted',body_json=?1
             WHERE resolution_action_id=?2 AND status='pending_approval'",
            params![
                serde_json::to_string(&action).map_err(|error| error.to_string())?,
                resolution_action_id
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn bind_parked_resolution_approval(
        &self,
        resolution_action_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let body: String = tx
            .query_row(
                "SELECT body_json FROM sekai_parked_resolution_actions
                 WHERE resolution_action_id=?1",
                params![resolution_action_id],
                |row| row.get(0),
            )
            .map_err(|_| "resolution action not found".to_string())?;
        let mut action: ParkedWorkResolutionAction =
            serde_json::from_str(&body).map_err(|error| error.to_string())?;
        if action.status == "pending_approval" && action.approval_id == approval_id {
            return Ok(());
        }
        if action.status != "pending_execution" {
            return Err("resolution action is not pending execution".into());
        }
        action.status = "pending_approval".into();
        action.approval_id = approval_id.into();
        tx.execute(
            "UPDATE sekai_parked_resolution_actions
             SET status='pending_approval',body_json=?1
             WHERE resolution_action_id=?2 AND status='pending_execution'",
            params![
                serde_json::to_string(&action).map_err(|error| error.to_string())?,
                resolution_action_id
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn mark_parked_resolution_accounted(
        &self,
        resolution_action_id: &str,
    ) -> Result<(), String> {
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let body: String = tx
            .query_row(
                "SELECT body_json FROM sekai_parked_resolution_actions
                 WHERE resolution_action_id=?1",
                params![resolution_action_id],
                |row| row.get(0),
            )
            .map_err(|_| "resolution action not found".to_string())?;
        let mut action: ParkedWorkResolutionAction = serde_json::from_str(&body)
            .map_err(|error| format!("corrupt resolution action: {error}"))?;
        if action.status == "execution_accounted" {
            return Ok(());
        }
        if action.status != "execution_reserved" {
            return Err("resolution action is not reserved for execution".into());
        }
        action.status = "execution_accounted".into();
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='execution_accounted',body_json=?1
             WHERE resolution_action_id=?2 AND status='execution_reserved'",
            params![
                serde_json::to_string(&action).map_err(|error| error.to_string())?,
                resolution_action_id
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn reserve_parked_resolution_execution(
        &self,
        resolution_action_id: &str,
        effect_id: &str,
        park_generation: u64,
    ) -> Result<(), String> {
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let effect = load_effect_tx(&tx, effect_id)?;
        if effect.effective_lifecycle_state() != EFFECT_LIFECYCLE_AWAITING_CONTINUATION
            || effect.park_generation != park_generation
        {
            return Err("resolution action is stale".into());
        }
        let (mut action, _) =
            load_resolution_tx(&tx, resolution_action_id, effect_id, park_generation)?;
        if matches!(
            action.status.as_str(),
            "execution_reserved" | "execution_accounted"
        ) {
            return Ok(());
        }
        if action.status != "pending_execution" {
            return Err("resolution action is not pending execution".into());
        }
        let winner: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sekai_parked_resolution_actions
                 WHERE effect_id=?1 AND park_generation=?2
                   AND status IN ('execution_reserved','execution_accounted')
                   AND resolution_action_id<>?3",
                params![effect_id, park_generation as i64, resolution_action_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if winner > 0 {
            return Err("another resolution action already reserved execution".into());
        }
        action.status = "execution_reserved".into();
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='execution_reserved',body_json=?1
             WHERE resolution_action_id=?2 AND status='pending_execution'",
            params![
                serde_json::to_string(&action).map_err(|error| error.to_string())?,
                resolution_action_id
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn reject_parked_resolution(
        &self,
        approval_id: &str,
        status: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        if !matches!(status, "rejected" | "cancelled" | "stale") {
            return Err("invalid resolution rejection status".into());
        }
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut statement = tx
            .prepare("SELECT body_json FROM sekai_parked_resolution_actions")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut action = None;
        for row in rows {
            let candidate: ParkedWorkResolutionAction =
                serde_json::from_str(&row.map_err(|error| error.to_string())?)
                    .map_err(|error| format!("corrupt resolution action: {error}"))?;
            if candidate.approval_id == approval_id {
                action = Some(candidate);
                break;
            }
        }
        drop(statement);
        let mut action = action.ok_or_else(|| "pending resolution action not found".to_string())?;
        if action.status == status {
            return Ok(());
        }
        if action.status != "pending_approval" {
            return Err("resolution action is already terminal".into());
        }
        action.status = status.into();
        action.decided_by = actor.into();
        action.invoked_at_ms = now_ms;
        let updated = tx
            .execute(
                "UPDATE sekai_parked_resolution_actions SET status=?1,body_json=?2
                 WHERE resolution_action_id=?3 AND status='pending_approval'",
                params![
                    status,
                    serde_json::to_string(&action).map_err(|error| error.to_string())?,
                    action.resolution_action_id
                ],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("pending resolution action not found".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn get_active_continuation(
        &self,
        effect: &ActionEffect,
    ) -> Result<Option<(ActionWorkContinuation, ActionWorkPark)>, String> {
        if effect.active_resolution_id.is_empty() {
            return Ok(None);
        }
        self.migrate_action_effects()?;
        let conn = self.conn();
        let continuation: Option<ActionWorkContinuation> = conn
            .query_row(
                "SELECT body_json FROM sekai_action_work_continuations WHERE resolution_id=?1",
                params![effect.active_resolution_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|body| serde_json::from_str(&body).map_err(|error| error.to_string()))
            .transpose()?;
        let Some(continuation) = continuation else {
            return Err("active continuation missing".into());
        };
        let park = conn
            .query_row(
                "SELECT body_json FROM sekai_action_work_parks WHERE park_id=?1",
                params![continuation.park_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())
            .and_then(|body| serde_json::from_str(&body).map_err(|error| error.to_string()))?;
        Ok(Some((continuation, park)))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn report_action_claim_event(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        kind: &str,
        checkpoint_digest: &str,
        reason_code: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        validate_request_id(request_id)?;
        if !matches!(
            kind,
            "resume_started"
                | "resume_succeeded"
                | "checkpoint_unavailable"
                | "replacement_started"
        ) {
            return Err("invalid claim event kind".into());
        }
        if reason_code.len() > 128 || checkpoint_digest.len() > 71 {
            return Err("claim event metadata exceeds bounds".into());
        }
        let digest = sha256_digest(
            &serde_json::json!({
                "effect_id": effect_id,
                "runtime_id": runtime_id,
                "generation": generation,
                "kind": kind,
                "checkpoint_digest": checkpoint_digest,
                "reason_code": reason_code,
            })
            .to_string(),
        );
        self.migrate_action_effects()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some(stored) = tx
            .query_row(
                "SELECT request_digest FROM sekai_action_claim_events
                 WHERE effect_id=?1 AND request_id=?2",
                params![effect_id, request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
        {
            if stored != digest {
                return Err("claim event idempotency conflict".into());
            }
            return Ok(true);
        }
        let effect = load_effect_tx(&tx, effect_id)?;
        if effect.status != EFFECT_STATUS_CLAIMED
            || effect.claim_expires_at_ms <= now_ms
            || !effect.fence_matches(runtime_id, generation, fencing_token)
        {
            return Err("claim event has no live matching fence".into());
        }
        let body = serde_json::json!({
            "effect_id": effect_id,
            "operation_id": effect.operation_id,
            "park_generation": effect.park_generation,
            "resolution_id": effect.active_resolution_id,
            "claim_generation": generation,
            "runtime_id": runtime_id,
            "kind": kind,
            "checkpoint_digest": checkpoint_digest,
            "reason_code": reason_code,
            "recorded_at_ms": now_ms,
        })
        .to_string();
        tx.execute(
            "INSERT INTO sekai_action_claim_events
             (effect_id,request_id,request_digest,body_json) VALUES (?1,?2,?3,?4)",
            params![effect_id, request_id, digest, body],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(false)
    }
}

fn checkpoint_store_allowed(store_id: &str) -> bool {
    std::env::var("SEKAI_CHECKPOINT_STORES")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|configured| configured == store_id)
        })
        .unwrap_or(false)
}

fn load_effect_tx(tx: &rusqlite::Transaction<'_>, effect_id: &str) -> Result<ActionEffect, String> {
    let body: String = tx
        .query_row(
            "SELECT body_json FROM sekai_action_effects WHERE effect_id=?1",
            params![effect_id],
            |row| row.get(0),
        )
        .map_err(|error| {
            if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                "action effect not found".into()
            } else {
                error.to_string()
            }
        })?;
    serde_json::from_str(&body).map_err(|error| format!("corrupt action effect body: {error}"))
}

fn update_effect_tx(tx: &rusqlite::Transaction<'_>, effect: &ActionEffect) -> Result<(), String> {
    effect.validate()?;
    let body = serde_json::to_string(effect).map_err(|error| error.to_string())?;
    let updated = tx
        .execute(
            "UPDATE sekai_action_effects SET status=?1,payload_json=?2,failure_reason=?3,
             updated_at_ms=?4,body_json=?5 WHERE effect_id=?6",
            params![
                effect.status,
                effect.payload_json,
                effect.failure_reason,
                effect.updated_at_ms,
                body,
                effect.effect_id
            ],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("action effect not found".into());
    }
    Ok(())
}

fn load_park_tx(
    tx: &rusqlite::Transaction<'_>,
    effect_id: &str,
    park_generation: u64,
) -> Result<ActionWorkPark, String> {
    let body: String = tx
        .query_row(
            "SELECT body_json FROM sekai_action_work_parks
             WHERE effect_id=?1 AND park_generation=?2",
            params![effect_id, park_generation as i64],
            |row| row.get(0),
        )
        .map_err(|_| "park record not found".to_string())?;
    serde_json::from_str(&body).map_err(|error| format!("corrupt park record: {error}"))
}

fn load_continuation_tx(
    tx: &rusqlite::Transaction<'_>,
    effect_id: &str,
    park_generation: u64,
) -> Result<Option<ActionWorkContinuation>, String> {
    tx.query_row(
        "SELECT body_json FROM sekai_action_work_continuations
         WHERE effect_id=?1 AND park_generation=?2",
        params![effect_id, park_generation as i64],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|error| error.to_string())?
    .map(|body| serde_json::from_str(&body).map_err(|error| error.to_string()))
    .transpose()
}

fn load_resolution_tx(
    tx: &rusqlite::Transaction<'_>,
    resolution_action_id: &str,
    effect_id: &str,
    park_generation: u64,
) -> Result<(ParkedWorkResolutionAction, ParkedWorkResolutionInput), String> {
    let action_body: String = tx
        .query_row(
            "SELECT body_json FROM sekai_parked_resolution_actions
             WHERE resolution_action_id=?1 AND effect_id=?2 AND park_generation=?3",
            params![resolution_action_id, effect_id, park_generation as i64],
            |row| row.get(0),
        )
        .map_err(|_| "resolution action not found".to_string())?;
    let action: ParkedWorkResolutionAction = serde_json::from_str(&action_body)
        .map_err(|error| format!("corrupt resolution action: {error}"))?;
    let input_body: String = tx
        .query_row(
            "SELECT body_json FROM sekai_parked_resolution_inputs WHERE resolution_input_id=?1",
            params![action.resolution_input_id],
            |row| row.get(0),
        )
        .map_err(|_| "resolution input not found".to_string())?;
    let input = serde_json::from_str(&input_body)
        .map_err(|error| format!("corrupt resolution input: {error}"))?;
    Ok((action, input))
}

fn stale_competing_resolutions_tx(
    tx: &rusqlite::Transaction<'_>,
    effect_id: &str,
    park_generation: u64,
    winning_action_id: &str,
    actor: &str,
    now_ms: i64,
) -> Result<(), String> {
    let mut statement = tx
        .prepare(
            "SELECT body_json FROM sekai_parked_resolution_actions
             WHERE effect_id=?1 AND park_generation=?2
               AND status IN ('pending_execution','execution_reserved','execution_accounted','pending_approval')
               AND resolution_action_id<>?3",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(
            params![effect_id, park_generation as i64, winning_action_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| error.to_string())?;
    let mut actions = Vec::new();
    for row in rows {
        let mut action: ParkedWorkResolutionAction =
            serde_json::from_str(&row.map_err(|error| error.to_string())?)
                .map_err(|error| format!("corrupt resolution action: {error}"))?;
        action.status = "stale".into();
        action.decided_by = actor.into();
        action.invoked_at_ms = now_ms;
        actions.push(action);
    }
    drop(statement);
    for action in actions {
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='stale',body_json=?1
             WHERE resolution_action_id=?2
               AND status IN ('pending_execution','execution_reserved','execution_accounted','pending_approval')",
            params![
                serde_json::to_string(&action).map_err(|error| error.to_string())?,
                action.resolution_action_id
            ],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn materialize_continuation(
    effect: &ActionEffect,
    park: &ActionWorkPark,
    input: &ParkedWorkResolutionInput,
    action: &ParkedWorkResolutionAction,
    actor: &str,
    now_ms: i64,
) -> ActionWorkContinuation {
    ActionWorkContinuation {
        resolution_id: format!("res-{}", uuid::Uuid::new_v4().simple()),
        effect_id: effect.effect_id.clone(),
        namespace: effect.namespace.clone(),
        operation_id: effect.operation_id.clone(),
        park_generation: park.park_generation,
        input_json: input.input_json.clone(),
        input_digest: input.input_digest.clone(),
        park_id: park.park_id.clone(),
        resolution_action_id: action.resolution_action_id.clone(),
        resolution_input_id: input.resolution_input_id.clone(),
        reason: input.reason.clone(),
        decided_by: actor.into(),
        decided_at_ms: now_ms,
        request_id: action.request_id.clone(),
    }
}

fn insert_continuation_tx(
    tx: &rusqlite::Transaction<'_>,
    continuation: &ActionWorkContinuation,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_action_work_continuations
         (resolution_id,effect_id,park_generation,body_json) VALUES (?1,?2,?3,?4)",
        params![
            continuation.resolution_id,
            continuation.effect_id,
            continuation.park_generation as i64,
            serde_json::to_string(continuation).map_err(|error| error.to_string())?
        ],
    )
    .map_err(|error| {
        if error.to_string().contains("UNIQUE") {
            "park generation already resolved".into()
        } else {
            error.to_string()
        }
    })?;
    Ok(())
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

    #[test]
    fn parked_work_requires_governed_resolution_before_reclaim() {
        let db = SekaiDb::new(":memory:").unwrap();
        let effect = plan_effects_for_admit(
            "ai-1",
            "acme",
            "op-1",
            &["runtime_dispatch".into()],
            r#"{"runtime":"shikigami"}"#,
            10,
            false,
        )
        .unwrap()
        .remove(0);
        db.put_action_effect(&effect).unwrap();
        let claimed = db
            .claim_action_work(&effect.effect_id, "shikigami", "claim-1", 60_000, 100)
            .unwrap();
        let parked = db
            .park_action_work(
                &effect.effect_id,
                "shikigami",
                claimed.claim_generation,
                &claimed.claim_fencing_token,
                "needs operator input",
                "park-req-1",
                "",
                "",
                "",
                "agent:tester",
                200,
            )
            .unwrap();
        assert_eq!(parked.effect.status, EFFECT_STATUS_PARKED);
        assert_eq!(
            parked.effect.effective_lifecycle_state(),
            EFFECT_LIFECYCLE_AWAITING_CONTINUATION
        );
        assert_eq!(parked.park.park_generation, 1);
        assert!(
            db.list_claimable_action_work("acme", None, 300, 10)
                .unwrap()
                .is_empty()
        );

        let replay = db
            .park_action_work(
                &effect.effect_id,
                "shikigami",
                claimed.claim_generation,
                &claimed.claim_fencing_token,
                "needs operator input",
                "park-req-1",
                "",
                "",
                "",
                "agent:tester",
                300,
            )
            .unwrap();
        assert!(replay.replay);
        assert_eq!(replay.park.park_id, parked.park.park_id);

        let resolved = db
            .submit_parked_resolution(
                &effect.effect_id,
                1,
                r#"{"answer":"continue"}"#,
                "operator answered",
                "resolve-req-1",
                "agent:tester",
                "default-allow",
                "invoked",
                "",
                400,
            )
            .unwrap();
        assert_eq!(resolved.effect.status, EFFECT_STATUS_PENDING);
        assert_eq!(
            resolved.effect.effective_lifecycle_state(),
            EFFECT_LIFECYCLE_READY
        );
        let continuation = resolved.continuation.unwrap();
        assert_eq!(continuation.operation_id, "op-1");
        assert_eq!(continuation.park_generation, 1);

        let reclaimed = db
            .claim_action_work(&effect.effect_id, "shikigami", "claim-2", 60_000, 500)
            .unwrap();
        assert_eq!(reclaimed.claim_generation, 2);
        let active = db.get_active_continuation(&reclaimed).unwrap().unwrap();
        assert_eq!(active.0.resolution_id, continuation.resolution_id);
        assert_eq!(active.1.park_id, parked.park.park_id);
    }

    #[test]
    fn pending_resolution_invokes_once_and_stale_generation_fails() {
        let db = SekaiDb::new(":memory:").unwrap();
        let effect = plan_effects_for_admit(
            "ai-1",
            "acme",
            "op-1",
            &["runtime_dispatch".into()],
            r#"{}"#,
            10,
            false,
        )
        .unwrap()
        .remove(0);
        db.put_action_effect(&effect).unwrap();
        let claimed = db
            .claim_action_work(&effect.effect_id, "runtime", "claim", 1_000, 10)
            .unwrap();
        db.park_action_work(
            &effect.effect_id,
            "runtime",
            1,
            &claimed.claim_fencing_token,
            "",
            "park",
            "",
            "",
            "",
            "runtime",
            20,
        )
        .unwrap();
        let pending = db
            .submit_parked_resolution(
                &effect.effect_id,
                1,
                r#"{"answer":"yes"}"#,
                "",
                "resolve",
                "operator",
                "namespace:acme",
                "pending_approval",
                "approval-1",
                30,
            )
            .unwrap();
        assert_eq!(pending.action.status, "pending_approval");
        assert!(pending.continuation.is_none());
        let competing = db
            .submit_parked_resolution(
                &effect.effect_id,
                1,
                r#"{"answer":"no"}"#,
                "",
                "resolve-competing",
                "operator",
                "namespace:acme",
                "pending_approval",
                "approval-2",
                31,
            )
            .unwrap();
        db.authorize_parked_resolution_approval(
            &pending.action.resolution_action_id,
            &pending.action.approval_id,
        )
        .unwrap();
        let continuation = db
            .invoke_parked_resolution(
                &pending.action.resolution_action_id,
                &effect.effect_id,
                1,
                "approver",
                40,
            )
            .unwrap();
        assert_eq!(continuation.decided_by, "approver");
        assert_eq!(continuation.input_json, r#"{"answer":"yes"}"#);
        assert_ne!(
            continuation.resolution_action_id,
            competing.action.resolution_action_id
        );
        let replay = db
            .invoke_parked_resolution(
                &pending.action.resolution_action_id,
                &effect.effect_id,
                1,
                "approver",
                50,
            )
            .unwrap();
        assert_eq!(replay.resolution_id, continuation.resolution_id);
        assert!(
            db.submit_parked_resolution(
                &effect.effect_id,
                2,
                r#"{"answer":"late"}"#,
                "",
                "late",
                "operator",
                "default",
                "invoked",
                "",
                60,
            )
            .unwrap_err()
            .contains("not awaiting")
        );
    }

    #[test]
    fn legacy_parked_rows_upgrade_to_unclaimable_awaiting_continuation() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.migrate_action_effects().unwrap();
        let mut effect = plan_effects_for_admit(
            "legacy-instance",
            "acme",
            "legacy-operation",
            &["runtime_dispatch".into()],
            r#"{}"#,
            10,
            false,
        )
        .unwrap()
        .remove(0);
        effect.status = EFFECT_STATUS_PARKED.into();
        let mut legacy = serde_json::to_value(&effect).unwrap();
        for field in [
            "park_generation",
            "active_resolution_id",
            "claim_attempt_count",
            "lease_expiry_count",
            "park_count",
            "lifecycle_state",
            "retry_policy_version",
            "retry_policy_digest",
            "max_claim_attempts",
            "max_lease_expiries",
            "max_park_cycles",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let body = serde_json::to_string(&legacy).unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_action_effects
                 (effect_id,instance_id,namespace,operation_id,kind,status,payload_json,
                  failure_reason,created_at_ms,updated_at_ms,body_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,'',10,10,?8)",
                params![
                    effect.effect_id,
                    effect.instance_id,
                    effect.namespace,
                    effect.operation_id,
                    effect.kind,
                    effect.status,
                    effect.payload_json,
                    body
                ],
            )
            .unwrap();
        let upgraded = db.get_action_effect(&effect.effect_id).unwrap().unwrap();
        assert_eq!(
            upgraded.effective_lifecycle_state(),
            EFFECT_LIFECYCLE_AWAITING_CONTINUATION
        );
        assert!(!upgraded.is_claimable_at(100));
    }
}

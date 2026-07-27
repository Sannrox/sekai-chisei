//! PostgreSQL ActionEffect store (#398).

use crate::db::postgres::PostgresDb;
use crate::sekai::action_effect::{ActionEffect, EFFECT_STATUS_PENDING};
use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;

impl PostgresDb {
    pub fn put_action_effect(&self, effect: &ActionEffect) -> Result<ActionEffect, String> {
        effect.validate()?;
        let body_json = serde_json::to_string(effect).map_err(|e| e.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_action_effects
                 (effect_id, instance_id, namespace, operation_id, kind, status,
                  payload_json, failure_reason, created_at_ms, updated_at_ms, body_json)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                &[
                    &effect.effect_id,
                    &effect.instance_id,
                    &effect.namespace,
                    &effect.operation_id,
                    &effect.kind,
                    &effect.status,
                    &effect.payload_json,
                    &effect.failure_reason,
                    &effect.created_at_ms,
                    &effect.updated_at_ms,
                    &body_json,
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
        self.connection()?
            .query_opt(
                "SELECT body_json FROM sekai_action_effects WHERE effect_id = $1",
                &[&effect_id],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                serde_json::from_str(&body).map_err(|e| format!("corrupt action effect body: {e}"))
            })
            .transpose()
    }

    pub fn list_action_effects_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<ActionEffect>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT body_json FROM sekai_action_effects
                 WHERE instance_id = $1
                 ORDER BY created_at_ms, effect_id",
                &[&instance_id],
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body: String = row.get(0);
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
        let limit = limit.clamp(1, 500) as i64;
        let kind = EFFECT_KIND_RUNTIME_DISPATCH;
        let status = EFFECT_STATUS_PENDING;
        let rows = self
            .connection()?
            .query(
                "SELECT body_json FROM sekai_action_effects
                 WHERE namespace = $1 AND kind = $2 AND status = $3
                 ORDER BY created_at_ms
                 LIMIT $4",
                &[&namespace, &kind, &status, &limit],
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body: String = row.get(0);
            out.push(
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action effect body: {e}"))?,
            );
        }
        Ok(out)
    }

    pub fn update_action_effect(
        &self,
        effect: &crate::sekai::action_effect::ActionEffect,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        effect.validate()?;
        let body_json = serde_json::to_string(effect).map_err(|e| e.to_string())?;
        let updated = self
            .connection()?
            .execute(
                "UPDATE sekai_action_effects
                 SET status = $1, payload_json = $2, failure_reason = $3,
                     updated_at_ms = $4, body_json = $5
                 WHERE effect_id = $6",
                &[
                    &effect.status,
                    &effect.payload_json,
                    &effect.failure_reason,
                    &effect.updated_at_ms,
                    &body_json,
                    &effect.effect_id,
                ],
            )
            .map_err(|e| e.to_string())?;
        if updated == 0 {
            return Err("action effect not found".into());
        }
        Ok(effect.clone())
    }

    pub fn list_claimable_action_work(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<ActionEffect>, String> {
        let limit = limit.clamp(1, 500);
        let kind = EFFECT_KIND_RUNTIME_DISPATCH;
        let rows = self
            .connection()?
            .query(
                "SELECT body_json FROM sekai_action_effects
                 WHERE namespace = $1 AND kind = $2
                 ORDER BY created_at_ms
                 LIMIT 2000",
                &[&namespace, &kind],
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body: String = row.get(0);
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
        // Delegate to shared domain logic via temporary load/update pattern
        // Mirror SQLite implementation by calling domain helpers after get.
        use crate::sekai::action_effect::EFFECT_STATUS_CLAIMED;
        use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;
        if runtime_id.trim().is_empty() {
            return Err("runtime_id required".into());
        }
        if request_id.trim().is_empty() {
            return Err("request_id required".into());
        }
        // Reuse SQLite path semantics by importing free functions via a thin reimplementation:
        // Call through RuntimeDb is preferred; here mirror the sqlite logic inline by
        // constructing via sekai module - actually simplest: copy the same decision tree.
        // To avoid duplication drift, load effect and apply same rules as sqlite by
        // temporarily using the sqlite file's code is not possible. Keep parity manually.
        let mut effect = self
            .get_action_effect(effect_id)?
            .ok_or_else(|| "action effect not found".to_string())?;
        if effect.kind != EFFECT_KIND_RUNTIME_DISPATCH {
            return Err("only runtime_dispatch effects are claimable".into());
        }
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
        let ttl = if ttl_ms <= 0 { 60_000 } else { ttl_ms };
        if ttl > 24 * 60 * 60 * 1_000 {
            return Err("ttl_ms exceeds max".into());
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(effect_id.as_bytes());
        hasher.update(b":");
        hasher.update(generation.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(runtime_id.as_bytes());
        let token = format!("fx-{:x}", hasher.finalize());
        effect.status = EFFECT_STATUS_CLAIMED.into();
        effect.claim_owner = runtime_id.into();
        effect.claim_generation = generation;
        effect.claim_fencing_token = token;
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
        use crate::sekai::action_effect::EFFECT_STATUS_CLAIMED;
        let ttl = if ttl_ms <= 0 { 60_000 } else { ttl_ms };
        if ttl > 24 * 60 * 60 * 1_000 {
            return Err("ttl_ms exceeds max".into());
        }
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
        use crate::sekai::action_effect::{
            ACK_OUTCOME_COMPLETED, ACK_OUTCOME_FAILED, ACK_OUTCOME_PARKED, EFFECT_STATUS_CLAIMED,
            EFFECT_STATUS_COMPLETED, EFFECT_STATUS_FAILED, EFFECT_STATUS_PARKED,
        };
        use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;
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
            effect.claim_expires_at_ms = 0;
        }
        self.update_action_effect(&effect)
    }
}

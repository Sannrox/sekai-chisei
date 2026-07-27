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
}

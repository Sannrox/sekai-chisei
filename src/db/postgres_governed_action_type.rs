//! PostgreSQL governed Action type registry (#396).

use crate::db::postgres::PostgresDb;
use crate::sekai::governed_action_type::GovernedActionType;

fn body_fingerprint(t: &GovernedActionType) -> Result<String, String> {
    let body = serde_json::json!({
        "description": t.description,
        "parameter_schema_json": t.parameter_schema_json,
        "allowed_effect_kinds": t.allowed_effect_kinds,
        "policy_scope": t.policy_scope,
        "budget_scope": t.budget_scope,
        "object_kind": t.object_kind,
        "object_mutation": t.object_mutation,
    });
    serde_json::to_string(&body).map_err(|e| e.to_string())
}

impl PostgresDb {
    pub fn put_governed_action_type(
        &self,
        mut type_def: GovernedActionType,
        actor: &str,
        now_ms: i64,
    ) -> Result<GovernedActionType, String> {
        let fingerprint = body_fingerprint(&type_def)?;
        if let Some(existing) = self.get_governed_action_type(
            &type_def.namespace,
            &type_def.type_id,
            &type_def.version,
        )? {
            let existing_fp = body_fingerprint(&existing)?;
            if existing_fp != fingerprint {
                return Err(
                    "governed action type version is immutable; register a new version".into(),
                );
            }
            return Ok(existing);
        }
        // Match SQLite: exact re-put is idempotent, while new rows must use
        // the closed schema contract with no legacy admission fallback.
        type_def.validate()?;
        if type_def.created_by.is_empty() {
            type_def.created_by = actor.to_string();
        }
        type_def.created_at_ms = now_ms;
        type_def.updated_at_ms = now_ms;
        type_def.disabled_at_ms = if type_def.enabled { 0 } else { now_ms };
        let body_json = serde_json::to_string(&type_def).map_err(|e| e.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_governed_action_types
                 (namespace, type_id, version, body_json, enabled, created_by, created_at_ms, updated_at_ms, disabled_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &type_def.namespace,
                    &type_def.type_id,
                    &type_def.version,
                    &body_json,
                    &type_def.enabled,
                    &type_def.created_by,
                    &type_def.created_at_ms,
                    &type_def.updated_at_ms,
                    &type_def.disabled_at_ms,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(type_def)
    }

    pub fn get_governed_action_type(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
    ) -> Result<Option<GovernedActionType>, String> {
        self.connection()?
            .query_opt(
                "SELECT body_json FROM sekai_governed_action_types
                 WHERE namespace = $1 AND type_id = $2 AND version = $3",
                &[&namespace, &type_id, &version],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt governed action type body: {e}"))
            })
            .transpose()
    }

    pub fn list_governed_action_types(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        enabled_only: bool,
    ) -> Result<Vec<GovernedActionType>, String> {
        let rows = if let Some(type_id) = type_id {
            self.connection()?.query(
                "SELECT body_json, enabled FROM sekai_governed_action_types
                 WHERE namespace = $1 AND type_id = $2
                 ORDER BY version",
                &[&namespace, &type_id],
            )
        } else {
            self.connection()?.query(
                "SELECT body_json, enabled FROM sekai_governed_action_types
                 WHERE namespace = $1
                 ORDER BY type_id, version",
                &[&namespace],
            )
        }
        .map_err(|e| e.to_string())?;
        let mut types = Vec::new();
        for row in rows {
            let body: String = row.get(0);
            let enabled: bool = row.get(1);
            if enabled_only && !enabled {
                continue;
            }
            types.push(
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt governed action type body: {e}"))?,
            );
        }
        Ok(types)
    }

    pub fn set_governed_action_type_enabled(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
        enabled: bool,
        now_ms: i64,
    ) -> Result<GovernedActionType, String> {
        let mut stored = self
            .get_governed_action_type(namespace, type_id, version)?
            .ok_or_else(|| "governed action type not found".to_string())?;
        stored.enabled = enabled;
        stored.updated_at_ms = now_ms;
        stored.disabled_at_ms = if enabled { 0 } else { now_ms };
        let body_json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let updated = self
            .connection()?
            .execute(
                "UPDATE sekai_governed_action_types
                 SET body_json = $1, enabled = $2, updated_at_ms = $3, disabled_at_ms = $4
                 WHERE namespace = $5 AND type_id = $6 AND version = $7",
                &[
                    &body_json,
                    &enabled,
                    &now_ms,
                    &stored.disabled_at_ms,
                    &namespace,
                    &type_id,
                    &version,
                ],
            )
            .map_err(|e| e.to_string())?;
        if updated == 0 {
            return Err("governed action type not found".into());
        }
        Ok(stored)
    }

    pub fn require_enabled_governed_action_type(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
    ) -> Result<GovernedActionType, String> {
        let Some(stored) = self.get_governed_action_type(namespace, type_id, version)? else {
            return Err(format!(
                "unknown governed action type {namespace}/{type_id}@{version}"
            ));
        };
        if !stored.enabled {
            return Err(format!(
                "governed action type {namespace}/{type_id}@{version} is disabled"
            ));
        }
        Ok(stored)
    }
}

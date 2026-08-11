//! Namespace-scoped governed Action type registry (#396 / research #395).
//!
//! Defines host-executed governed operations and their evidence contract.
//! Types define which decision kinds may be admitted; instances and effects are
//! later Issues (#397–#399).

use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

/// Known effect kinds allowed on governed action types at registry time.
pub const EFFECT_KIND_RUNTIME_DISPATCH: &str = "runtime_dispatch";
pub const EFFECT_KIND_NOTIFY: &str = "notify";
pub const EFFECT_KIND_EXTERNAL_MUTATE: &str = "external_mutate";

const KNOWN_EFFECT_KINDS: &[&str] = &[
    EFFECT_KIND_RUNTIME_DISPATCH,
    EFFECT_KIND_NOTIFY,
    EFFECT_KIND_EXTERNAL_MUTATE,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedActionType {
    pub namespace: String,
    pub type_id: String,
    pub version: String,
    pub description: String,
    /// JSON object describing parameters using the closed v1 subset.
    pub parameter_schema_json: String,
    pub allowed_effect_kinds: Vec<String>,
    /// Empty means use namespace policy defaults.
    pub policy_scope: String,
    /// Empty means use namespace budget defaults.
    pub budget_scope: String,
    pub enabled: bool,
    pub created_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub disabled_at_ms: i64,
}

impl GovernedActionType {
    pub fn validate(&self) -> Result<(), String> {
        if self.namespace.trim().is_empty() {
            return Err("namespace required".into());
        }
        if self.type_id.trim().is_empty() {
            return Err("type_id required".into());
        }
        if self.version.trim().is_empty() {
            return Err("version required".into());
        }
        if self.type_id.chars().any(char::is_whitespace) {
            return Err("type_id must not contain whitespace".into());
        }
        if self.version.chars().any(char::is_whitespace) {
            return Err("version must not contain whitespace".into());
        }
        let schema: serde_json::Value = serde_json::from_str(&self.parameter_schema_json)
            .map_err(|e| format!("parameter_schema_json must be JSON: {e}"))?;
        if !schema.is_object() {
            return Err("parameter_schema_json must be a JSON object".into());
        }
        crate::chisei::evaluation_plan::validate_parameter_schema(&self.parameter_schema_json)
            .map_err(|error| {
                format!("parameter_schema_json must use the closed v1 subset: {error}")
            })?;
        if self.allowed_effect_kinds.is_empty() {
            return Err("allowed_effect_kinds required".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for kind in &self.allowed_effect_kinds {
            if !KNOWN_EFFECT_KINDS.contains(&kind.as_str()) {
                return Err(format!(
                    "unknown effect kind {kind:?}; allowed: {}",
                    KNOWN_EFFECT_KINDS.join(", ")
                ));
            }
            if !seen.insert(kind.clone()) {
                return Err(format!("duplicate effect kind {kind:?}"));
            }
        }
        Ok(())
    }
}

fn body_fingerprint(t: &GovernedActionType) -> Result<String, String> {
    // Version immutability: identity is (namespace, type_id, version); body
    // fields other than enabled/disabled timestamps must match on re-put.
    let body = serde_json::json!({
        "description": t.description,
        "parameter_schema_json": t.parameter_schema_json,
        "allowed_effect_kinds": t.allowed_effect_kinds,
        "policy_scope": t.policy_scope,
        "budget_scope": t.budget_scope,
    });
    serde_json::to_string(&body).map_err(|e| e.to_string())
}

impl SekaiDb {
    pub fn migrate_governed_action_types(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_governed_action_types (
                namespace TEXT NOT NULL,
                type_id TEXT NOT NULL,
                version TEXT NOT NULL,
                body_json TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                created_by TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                disabled_at_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (namespace, type_id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_governed_action_types_ns
                ON sekai_governed_action_types(namespace);
            CREATE INDEX IF NOT EXISTS idx_governed_action_types_enabled
                ON sekai_governed_action_types(namespace, type_id, enabled);",
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn put_governed_action_type(
        &self,
        mut type_def: GovernedActionType,
        actor: &str,
        now_ms: i64,
    ) -> Result<GovernedActionType, String> {
        self.migrate_governed_action_types()?;
        let fingerprint = body_fingerprint(&type_def)?;
        // Must not hold a pool connection across get_*: in-memory pools are
        // single-connection and re-acquire would deadlock.
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
            // Idempotent put: return stored row (enabled state may differ).
            return Ok(existing);
        }
        // Exact re-put remains idempotent, but legacy object-only rows never
        // regain admission compatibility; only new rows are validated here.
        type_def.validate()?;
        if type_def.created_by.is_empty() {
            type_def.created_by = actor.to_string();
        }
        type_def.created_at_ms = now_ms;
        type_def.updated_at_ms = now_ms;
        if !type_def.enabled {
            type_def.disabled_at_ms = now_ms;
        } else {
            type_def.disabled_at_ms = 0;
        }
        let body_json = serde_json::to_string(&type_def).map_err(|e| e.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_governed_action_types
             (namespace, type_id, version, body_json, enabled, created_by,
              created_at_ms, updated_at_ms, disabled_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                type_def.namespace,
                type_def.type_id,
                type_def.version,
                body_json,
                type_def.enabled as i32,
                type_def.created_by,
                type_def.created_at_ms,
                type_def.updated_at_ms,
                type_def.disabled_at_ms,
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
        self.migrate_governed_action_types()?;
        let conn = self.conn();
        conn.query_row(
            "SELECT body_json FROM sekai_governed_action_types
             WHERE namespace = ?1 AND type_id = ?2 AND version = ?3",
            params![namespace, type_id, version],
            |row| {
                let body: String = row.get(0)?;
                Ok(body)
            },
        )
        .optional()
        .map_err(|e| e.to_string())?
        .map(|body| {
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
        self.migrate_governed_action_types()?;
        let conn = self.conn();
        let mut types = Vec::new();
        if let Some(type_id) = type_id {
            let mut stmt = conn
                .prepare(
                    "SELECT body_json, enabled FROM sekai_governed_action_types
                     WHERE namespace = ?1 AND type_id = ?2
                     ORDER BY version",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![namespace, type_id], |row| {
                    let body: String = row.get(0)?;
                    let enabled: i32 = row.get(1)?;
                    Ok((body, enabled))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (body, enabled) = row.map_err(|e| e.to_string())?;
                if enabled_only && enabled == 0 {
                    continue;
                }
                types.push(
                    serde_json::from_str(&body)
                        .map_err(|e| format!("corrupt governed action type body: {e}"))?,
                );
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT body_json, enabled FROM sekai_governed_action_types
                     WHERE namespace = ?1
                     ORDER BY type_id, version",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![namespace], |row| {
                    let body: String = row.get(0)?;
                    let enabled: i32 = row.get(1)?;
                    Ok((body, enabled))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (body, enabled) = row.map_err(|e| e.to_string())?;
                if enabled_only && enabled == 0 {
                    continue;
                }
                types.push(
                    serde_json::from_str(&body)
                        .map_err(|e| format!("corrupt governed action type body: {e}"))?,
                );
            }
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
        self.migrate_governed_action_types()?;
        let mut stored = self
            .get_governed_action_type(namespace, type_id, version)?
            .ok_or_else(|| "governed action type not found".to_string())?;
        stored.enabled = enabled;
        stored.updated_at_ms = now_ms;
        stored.disabled_at_ms = if enabled { 0 } else { now_ms };
        let body_json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let conn = self.conn();
        let updated = conn
            .execute(
                "UPDATE sekai_governed_action_types
                 SET body_json = ?1, enabled = ?2, updated_at_ms = ?3, disabled_at_ms = ?4
                 WHERE namespace = ?5 AND type_id = ?6 AND version = ?7",
                params![
                    body_json,
                    enabled as i32,
                    now_ms,
                    stored.disabled_at_ms,
                    namespace,
                    type_id,
                    version,
                ],
            )
            .map_err(|e| e.to_string())?;
        if updated == 0 {
            return Err("governed action type not found".into());
        }
        Ok(stored)
    }

    /// Fail-closed gate for ActionInstance submit (#397): unknown or disabled.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(enabled: bool) -> GovernedActionType {
        GovernedActionType {
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            description: "Admit a review decision".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![
                EFFECT_KIND_RUNTIME_DISPATCH.into(),
                EFFECT_KIND_NOTIFY.into(),
            ],
            policy_scope: String::new(),
            budget_scope: String::new(),
            enabled,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        }
    }

    #[test]
    fn put_get_list_and_version_immutability() {
        let db = SekaiDb::new(":memory:").unwrap();
        let put = db
            .put_governed_action_type(sample(true), "operator", 10)
            .unwrap();
        assert!(put.enabled);
        assert_eq!(put.created_by, "operator");
        let got = db
            .get_governed_action_type("acme", "review.intake", "1.0.0")
            .unwrap()
            .unwrap();
        assert_eq!(got.type_id, "review.intake");

        // Idempotent put
        db.put_governed_action_type(sample(true), "operator", 20)
            .unwrap();

        // Immutable body
        let mut changed = sample(true);
        changed.description = "different".into();
        let err = db
            .put_governed_action_type(changed, "operator", 30)
            .unwrap_err();
        assert!(err.contains("immutable"), "{err}");

        // New version ok
        let mut v2 = sample(true);
        v2.version = "1.1.0".into();
        db.put_governed_action_type(v2, "operator", 40).unwrap();
        let list = db
            .list_governed_action_types("acme", Some("review.intake"), false)
            .unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn disable_rejects_require_enabled() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.put_governed_action_type(sample(true), "operator", 10)
            .unwrap();
        db.require_enabled_governed_action_type("acme", "review.intake", "1.0.0")
            .unwrap();
        db.set_governed_action_type_enabled("acme", "review.intake", "1.0.0", false, 20)
            .unwrap();
        let err = db
            .require_enabled_governed_action_type("acme", "review.intake", "1.0.0")
            .unwrap_err();
        assert!(err.contains("disabled"), "{err}");
        let unknown = db
            .require_enabled_governed_action_type("acme", "missing", "1.0.0")
            .unwrap_err();
        assert!(unknown.contains("unknown"), "{unknown}");
    }

    #[test]
    fn rejects_unknown_effect_kind() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut bad = sample(true);
        bad.allowed_effect_kinds = vec!["shell_exec".into()];
        assert!(db.put_governed_action_type(bad, "op", 1).is_err());
    }

    #[test]
    fn rejects_parameter_schema_outside_closed_subset() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut bad = sample(true);
        bad.parameter_schema_json = r#"{"type":"object"}"#.into();
        let error = db.put_governed_action_type(bad, "op", 1).unwrap_err();
        assert!(error.contains("closed v1 subset"), "{error}");
    }
}

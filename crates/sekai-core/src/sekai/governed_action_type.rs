//! Namespace-scoped governed Action type registry (#396 / research #395).
//!
//! Defines host-executed governed operations and their evidence contract.
//! Types define which decision kinds may be admitted; instances and effects
//! live in `action_instance` and `action_effect`.

use crate::db::sekai::SekaiDb;
use crate::sekai::action_type_criteria::{ActionSubmissionCriterion, validate_submission_criteria};
use rusqlite::{OptionalExtension, params};
use sekai_types::impact_class::ImpactClass;
use serde::{Deserialize, Serialize};

/// Known effect kinds allowed on governed action types at registry time.
pub const EFFECT_KIND_RUNTIME_DISPATCH: &str = "runtime_dispatch";
pub const EFFECT_KIND_NOTIFY: &str = "notify";
pub const EFFECT_KIND_EXTERNAL_MUTATE: &str = "external_mutate";
pub const OBJECT_MUTATION_CREATE: &str = "create";
pub const OBJECT_MUTATION_UPDATE: &str = "update";

const KNOWN_EFFECT_KINDS: &[&str] = &[
    EFFECT_KIND_RUNTIME_DISPATCH,
    EFFECT_KIND_NOTIFY,
    EFFECT_KIND_EXTERNAL_MUTATE,
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Admitted object kind this type may create or update. Empty means admit-only.
    #[serde(default)]
    pub object_kind: String,
    /// `create` or `update` when `object_kind` is set. Empty means admit-only.
    #[serde(default)]
    pub object_mutation: String,
    /// Closed object-security v1 predicates over the bound object and invoker.
    #[serde(default)]
    pub submission_criteria: Vec<ActionSubmissionCriterion>,
    /// Subset of `allowed_effect_kinds` materialized on admit. Empty means all allowed.
    #[serde(default)]
    pub declared_effect_kinds: Vec<String>,
    /// Optional System One Function bind. Empty means preview does not fill.
    #[serde(default)]
    pub system_one: Option<sekai_types::system_one_bind::SystemOneBind>,
    /// Principals who may grant or deny a parked instance of this type.
    /// Empty means namespace administrators decide. A submitter never
    /// decides their own instance (#1084).
    #[serde(default)]
    pub approvers: Vec<String>,
    /// Optional review queue for parked instances (#1455).
    #[serde(default)]
    pub review_queue: crate::sekai::review_queue::ReviewQueueSpec,
    /// How an Action prepared offline meets a changed object (#1580):
    /// `reject_any` (empty), `reject_touched` or `last_writer_wins`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub offline_conflict: String,
    /// The properties `last_writer_wins` may overwrite.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub last_writer_wins_properties: Vec<String>,
    /// `routine` or `high_impact` (#1910). Empty means unclassified.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub impact_class: String,
    /// A required string or integer parameter whose value segments the
    /// action budget, such as a turn (#1859): each value is its own
    /// `work_unit:` scope under the submitter's. Empty: no segment.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub budget_work_unit_parameter: String,
    /// A required integer parameter with `minimum` of at least 0 whose value
    /// an admission charges, such as the amount spent (#1859). Empty: one
    /// unit per admission.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub budget_amount_parameter: String,
    pub enabled: bool,
    pub created_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub disabled_at_ms: i64,
}

impl GovernedActionType {
    pub fn validate(&self) -> Result<(), String> {
        crate::sekai::offline_action::validate_rule(
            &self.offline_conflict,
            &self.last_writer_wins_properties,
        )?;
        if !self.impact_class.is_empty() && self.impact().is_none() {
            return Err(format!(
                "impact_class must be empty or one of: {}",
                ImpactClass::ALL.map(ImpactClass::as_str).join(", ")
            ));
        }
        if self.namespace.trim().is_empty() {
            return Err("namespace required".into());
        }
        if self.type_id.trim().is_empty() {
            return Err("type_id required".into());
        }
        if self
            .approvers
            .iter()
            .any(|approver| approver.trim().is_empty() || approver.chars().any(char::is_whitespace))
        {
            return Err("approvers must be non-empty principals without whitespace".into());
        }
        self.review_queue.validate_with_approvers(&self.approvers)?;
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
        crate::sekai::parameter_schema::validate_parameter_schema(&self.parameter_schema_json)
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
        let mut declared_seen = std::collections::BTreeSet::new();
        for kind in &self.declared_effect_kinds {
            if !self
                .allowed_effect_kinds
                .iter()
                .any(|allowed| allowed == kind)
            {
                return Err(format!(
                    "undeclared effect kind {kind:?}; must be a subset of allowed_effect_kinds"
                ));
            }
            if !declared_seen.insert(kind.clone()) {
                return Err(format!("duplicate declared effect kind {kind:?}"));
            }
        }
        validate_object_binding(
            &self.object_kind,
            &self.object_mutation,
            &self.parameter_schema_json,
        )?;
        validate_submission_criteria(
            &self.submission_criteria,
            &self.object_kind,
            &self.object_mutation,
        )?;
        if let Some(bind) = self.system_one.as_ref().filter(|bind| !bind.is_empty()) {
            sekai_types::system_one_bind::validate_bind_against_schema(
                bind,
                &self.parameter_schema_json,
            )?;
        }
        validate_budget_parameters(
            &self.budget_work_unit_parameter,
            &self.budget_amount_parameter,
            &schema,
        )?;
        Ok(())
    }

    /// The declared impact class. Empty, or a value this build does not
    /// know, is unclassified.
    pub fn impact(&self) -> Option<ImpactClass> {
        ImpactClass::parse(&self.impact_class)
    }

    /// The budget subject and amount an admission with these (already
    /// validated) parameters charges: the submitter's subject, segmented by
    /// the work-unit parameter's value, and the amount parameter's value or
    /// one unit.
    pub fn budget_charge(
        &self,
        namespace: &str,
        actor: &str,
        parameters_json: &str,
    ) -> Result<(String, i32), String> {
        let subject = crate::sekai::action_instance::submit_budget_subject(
            namespace,
            actor,
            &self.budget_scope,
        );
        if self.budget_work_unit_parameter.is_empty() && self.budget_amount_parameter.is_empty() {
            return Ok((subject, 1));
        }
        let parameters: serde_json::Value = serde_json::from_str(parameters_json)
            .map_err(|error| format!("parameters_json must be JSON: {error}"))?;
        let subject = match self.budget_work_unit_parameter.as_str() {
            "" => subject,
            name => {
                let unit = match parameters.get(name) {
                    Some(serde_json::Value::String(unit)) => unit.clone(),
                    Some(serde_json::Value::Number(unit)) if unit.is_i64() => unit.to_string(),
                    _ => return Err(format!("budget work unit parameter {name:?} is missing")),
                };
                if unit.is_empty()
                    || unit.len() > 128
                    || unit
                        .chars()
                        .any(|c| c == '/' || c.is_whitespace() || c.is_control())
                {
                    return Err(format!(
                        "budget work unit parameter {name:?} must be 1 to 128 characters without '/' or whitespace"
                    ));
                }
                format!("{subject}/work_unit:{unit}")
            }
        };
        let amount = match self.budget_amount_parameter.as_str() {
            "" => 1,
            name => parameters
                .get(name)
                .and_then(serde_json::Value::as_i64)
                .and_then(|amount| i32::try_from(amount).ok())
                .filter(|amount| *amount >= 0)
                .ok_or_else(|| {
                    format!(
                        "budget amount parameter {name:?} must be an integer from 0 to {}",
                        i32::MAX
                    )
                })?,
        };
        Ok((subject, amount))
    }

    pub fn effect_kinds_to_materialize(&self) -> &[String] {
        if self.declared_effect_kinds.is_empty() {
            &self.allowed_effect_kinds
        } else {
            &self.declared_effect_kinds
        }
    }
}

/// Each budget parameter, when named, is a required parameter of a type that
/// always yields a usable value: the work unit a string or an integer, the
/// amount an integer that cannot be negative.
fn validate_budget_parameters(
    work_unit: &str,
    amount: &str,
    schema: &serde_json::Value,
) -> Result<(), String> {
    let required = |name: &str| {
        schema
            .get("required")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|required| required.iter().any(|value| value.as_str() == Some(name)))
    };
    let property = |name: &str| {
        schema
            .get("properties")
            .and_then(|properties| properties.get(name))
    };
    if !work_unit.is_empty() {
        let kind = property(work_unit)
            .and_then(|property| property.get("type"))
            .and_then(serde_json::Value::as_str);
        if !matches!(kind, Some("string" | "integer")) || !required(work_unit) {
            return Err(format!(
                "budget_work_unit_parameter {work_unit:?} must be a required string or integer parameter"
            ));
        }
    }
    if !amount.is_empty() {
        let property = property(amount);
        let integer = property
            .and_then(|property| property.get("type"))
            .and_then(serde_json::Value::as_str)
            == Some("integer");
        let non_negative = property
            .and_then(|property| property.get("minimum"))
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|minimum| minimum >= 0);
        if !integer || !non_negative || !required(amount) {
            return Err(format!(
                "budget_amount_parameter {amount:?} must be a required integer parameter with a minimum of at least 0"
            ));
        }
    }
    if !work_unit.is_empty() && work_unit == amount {
        return Err("budget_work_unit_parameter and budget_amount_parameter must differ".into());
    }
    Ok(())
}

fn validate_object_binding(
    object_kind: &str,
    object_mutation: &str,
    parameter_schema_json: &str,
) -> Result<(), String> {
    let object_kind = object_kind.trim();
    let object_mutation = object_mutation.trim();
    if object_kind.is_empty() && object_mutation.is_empty() {
        return Ok(());
    }
    if object_kind.is_empty() || object_mutation.is_empty() {
        return Err("object_kind and object_mutation must be set together".into());
    }
    if object_kind.chars().any(char::is_whitespace) {
        return Err("object_kind must not contain whitespace".into());
    }
    if object_mutation != OBJECT_MUTATION_CREATE && object_mutation != OBJECT_MUTATION_UPDATE {
        return Err(format!(
            "object_mutation must be {OBJECT_MUTATION_CREATE} or {OBJECT_MUTATION_UPDATE}"
        ));
    }
    let schema: serde_json::Value = serde_json::from_str(parameter_schema_json)
        .map_err(|error| format!("parameter_schema_json must be JSON: {error}"))?;
    let object_id = schema
        .get("properties")
        .and_then(|properties| properties.get("object_id"))
        .ok_or_else(|| "object binding requires parameter object_id".to_string())?;
    if object_id.get("type").and_then(|value| value.as_str()) != Some("string") {
        return Err("object_id parameter must be a string".into());
    }
    let required = schema
        .get("required")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "object_id must be a required parameter".to_string())?;
    if !required
        .iter()
        .any(|value| value.as_str() == Some("object_id"))
    {
        return Err("object_id must be a required parameter".into());
    }
    if schema
        .get("properties")
        .and_then(|properties| properties.get("notify_delivery"))
        .is_some()
    {
        return Err(
            "notify_delivery is an action-effect control and cannot be an object property".into(),
        );
    }
    Ok(())
}

pub fn body_fingerprint(t: &GovernedActionType) -> Result<String, String> {
    // Version immutability: identity is (namespace, type_id, version); body
    // fields other than enabled/disabled timestamps must match on re-put.
    let body = serde_json::json!({
        "description": t.description,
        "parameter_schema_json": t.parameter_schema_json,
        "allowed_effect_kinds": t.allowed_effect_kinds,
        "policy_scope": t.policy_scope,
        "budget_scope": t.budget_scope,
        "object_kind": t.object_kind,
        "object_mutation": t.object_mutation,
        "submission_criteria": t.submission_criteria,
        "declared_effect_kinds": t.declared_effect_kinds,
        "system_one": t.system_one,
        "review_queue": t.review_queue,
    });
    // Added after types were stored: only a set offline rule or impact
    // class enters the fingerprint, so every stored type keeps its
    // fingerprint.
    let mut body = body;
    if !t.offline_conflict.is_empty() || !t.last_writer_wins_properties.is_empty() {
        let object = body.as_object_mut().expect("fingerprint body is an object");
        object.insert("offline_conflict".into(), t.offline_conflict.clone().into());
        object.insert(
            "last_writer_wins_properties".into(),
            t.last_writer_wins_properties.clone().into(),
        );
    }
    if !t.impact_class.is_empty() {
        let object = body.as_object_mut().expect("fingerprint body is an object");
        object.insert("impact_class".into(), t.impact_class.clone().into());
    }
    if !t.budget_work_unit_parameter.is_empty() || !t.budget_amount_parameter.is_empty() {
        let object = body.as_object_mut().expect("fingerprint body is an object");
        object.insert(
            "budget_work_unit_parameter".into(),
            t.budget_work_unit_parameter.clone().into(),
        );
        object.insert(
            "budget_amount_parameter".into(),
            t.budget_amount_parameter.clone().into(),
        );
    }
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
            object_kind: String::new(),
            object_mutation: String::new(),
            enabled,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
            ..Default::default()
        }
    }

    /// Budget parameters must always yield a usable value: required, the
    /// work unit a string or integer, the amount a non-negative integer.
    /// Admission then charges the segmented subject and the amount (#1859).
    #[test]
    fn budget_parameters_segment_the_subject_and_set_the_amount() {
        let spend = |work_unit: &str, amount: &str, amount_schema: &str| GovernedActionType {
            parameter_schema_json: format!(
                r#"{{"type":"object","properties":{{"turn":{{"type":"string"}},"note":{{"type":"string"}},"amount":{amount_schema}}},"required":["turn","amount"],"additionalProperties":false}}"#
            ),
            budget_work_unit_parameter: work_unit.into(),
            budget_amount_parameter: amount.into(),
            ..sample(true)
        };
        let counted = r#"{"type":"integer","minimum":0}"#;
        let valid = spend("turn", "amount", counted);
        valid.validate().unwrap();
        for invalid in [
            spend("note", "amount", counted),
            spend("missing", "amount", counted),
            spend("turn", "turn", counted),
            spend("turn", "amount", r#"{"type":"integer"}"#),
            spend("turn", "amount", r#"{"type":"integer","minimum":-5}"#),
            spend("turn", "amount", r#"{"type":"number","minimum":0}"#),
        ] {
            assert!(invalid.validate().is_err(), "{invalid:?}");
        }
        assert_eq!(
            valid
                .budget_charge("acme", "alice", r#"{"turn":"turn-3","amount":40}"#)
                .unwrap(),
            (
                "action:governed/project:acme/agent:alice/work_unit:turn-3".into(),
                40
            )
        );
        assert!(
            valid
                .budget_charge("acme", "alice", r#"{"turn":"a/b","amount":1}"#)
                .is_err()
        );
        assert!(
            valid
                .budget_charge("acme", "alice", r#"{"turn":"t","amount":3000000000}"#)
                .is_err()
        );
        assert_eq!(
            sample(true)
                .budget_charge("acme", "alice", r#"{"summary":"x"}"#)
                .unwrap(),
            ("action:governed/project:acme/agent:alice".into(), 1)
        );
        // Stored types without budget parameters keep their fingerprint and
        // stored body, and bodies written before these fields still load.
        assert!(
            !body_fingerprint(&sample(true))
                .unwrap()
                .contains("budget_amount")
        );
        let stored = serde_json::to_string(&sample(true)).unwrap();
        assert!(!stored.contains("budget_work_unit") && !stored.contains("budget_amount"));
        assert_eq!(
            serde_json::from_str::<GovernedActionType>(&stored).unwrap(),
            sample(true)
        );
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

    /// #1910: an unclassified type keeps the fingerprint it had before
    /// `impact_class` existed, so stored versions stay idempotent on re-put.
    #[test]
    fn unclassified_fingerprint_is_unchanged_and_a_class_is_part_of_the_version() {
        assert_eq!(
            body_fingerprint(&sample(true)).unwrap(),
            concat!(
                r#"{"allowed_effect_kinds":["runtime_dispatch","notify"],"budget_scope":"","#,
                r#""declared_effect_kinds":[],"description":"Admit a review decision","#,
                r#""object_kind":"","object_mutation":"","parameter_schema_json":"#,
                r#""{\"type\":\"object\",\"properties\":{\"summary\":{\"type\":\"string\"}},"#,
                r#"\"required\":[\"summary\"],\"additionalProperties\":false}","policy_scope":"","#,
                r#""review_queue":{"agent_reviewers":[],"escalate":"","escalate_to":"","pool":[],"#,
                r#""queue_id":"","sla_ms":0,"threshold":0,"threshold_param":""},"#,
                r#""submission_criteria":[],"system_one":null}"#,
            )
        );
        let db = SekaiDb::new(":memory:").unwrap();
        // A row written before the field existed has no `impact_class` key.
        let legacy = serde_json::to_string(&sample(true)).unwrap();
        assert!(!legacy.contains("impact_class"));
        db.migrate_governed_action_types().unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_governed_action_types
                 (namespace, type_id, version, body_json, enabled, created_by,
                  created_at_ms, updated_at_ms, disabled_at_ms)
                 VALUES ('acme', 'review.intake', '1.0.0', ?1, 1, 'operator', 1, 1, 0)",
                params![legacy],
            )
            .unwrap();
        db.put_governed_action_type(sample(true), "operator", 2)
            .unwrap();

        let mut classified = sample(true);
        classified.impact_class = "high_impact".into();
        let err = db
            .put_governed_action_type(classified.clone(), "operator", 3)
            .unwrap_err();
        assert!(err.contains("immutable"), "{err}");
        classified.version = "2.0.0".into();
        db.put_governed_action_type(classified, "operator", 4)
            .unwrap();
        let stored = db
            .get_governed_action_type("acme", "review.intake", "2.0.0")
            .unwrap()
            .unwrap();
        assert_eq!(stored.impact(), Some(ImpactClass::HighImpact));
    }

    #[test]
    fn impact_class_is_a_closed_set() {
        for class in ImpactClass::ALL {
            let mut type_def = sample(true);
            type_def.impact_class = class.as_str().into();
            type_def.validate().unwrap();
        }
        let mut type_def = sample(true);
        type_def.impact_class = "critical".into();
        let err = type_def.validate().unwrap_err();
        assert!(err.contains("impact_class"), "{err}");
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

    #[test]
    fn object_binding_requires_object_id_and_known_mutation() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut missing = sample(true);
        missing.object_kind = "customer_record".into();
        missing.object_mutation = OBJECT_MUTATION_CREATE.into();
        let error = db.put_governed_action_type(missing, "op", 1).unwrap_err();
        assert!(error.contains("object_id"), "{error}");

        let mut bound = sample(true);
        bound.parameter_schema_json = r#"{"type":"object","properties":{"object_id":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into();
        bound.object_kind = "customer_record".into();
        bound.object_mutation = OBJECT_MUTATION_CREATE.into();
        db.put_governed_action_type(bound, "op", 1).unwrap();

        let mut notify = sample(true);
        notify.type_id = "review.notify".into();
        notify.parameter_schema_json = r#"{"type":"object","properties":{"object_id":{"type":"string"},"notify_delivery":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into();
        notify.object_kind = "customer_record".into();
        notify.object_mutation = OBJECT_MUTATION_CREATE.into();
        let error = db.put_governed_action_type(notify, "op", 1).unwrap_err();
        assert!(error.contains("notify_delivery"), "{error}");
    }

    #[test]
    fn rejects_undeclared_effect_kind() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut bad = sample(true);
        bad.declared_effect_kinds = vec![EFFECT_KIND_EXTERNAL_MUTATE.into()];
        let error = db.put_governed_action_type(bad, "op", 1).unwrap_err();
        assert!(error.contains("undeclared effect kind"), "{error}");
    }

    #[test]
    fn system_one_bind_must_be_pinned_and_schema_aligned() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut type_def = sample(true);
        type_def.parameter_schema_json = r#"{"type":"object","properties":{"object_id":{"type":"string"},"department":{"type":"string","enum":["billing","technical"]}},"required":["object_id","department"],"additionalProperties":false}"#.into();
        type_def.object_kind = "customer_record".into();
        type_def.object_mutation = OBJECT_MUTATION_UPDATE.into();
        type_def.system_one = Some(sekai_types::system_one_bind::SystemOneBind {
            model: "jev-latest".into(),
            questions: vec![sekai_types::system_one_bind::SystemOneQuestionBind {
                parameter: "department".into(),
                question_type: "choice".into(),
                instructions: "Which team".into(),
                criteria: serde_json::json!({"billing": null, "technical": null}),
            }],
        });
        let error = db
            .put_governed_action_type(type_def.clone(), "op", 1)
            .unwrap_err();
        assert!(error.contains("pinned"), "{error}");

        type_def.system_one.as_mut().unwrap().model = "jev-1.13.0".into();
        db.put_governed_action_type(type_def.clone(), "op", 1)
            .unwrap();
        type_def.system_one.as_mut().unwrap().model = "jev-1.14.0".into();
        let error = db.put_governed_action_type(type_def, "op", 2).unwrap_err();
        assert!(error.contains("immutable"), "{error}");
    }
}

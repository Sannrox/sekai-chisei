use crate::db::sekai::SekaiDb;
use crate::domain::{Link, Object};
use crate::sekai::schema::{PropertyType, SchemaRegistry};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

type ExecuteFn = Box<
    dyn Fn(&SekaiDb, &SchemaRegistry, &HashMap<String, String>, &str) -> Result<String, String>
        + Send
        + Sync,
>;
type TargetIdsFn =
    Box<dyn Fn(&SekaiDb, &HashMap<String, String>) -> Result<Vec<String>, String> + Send + Sync>;

pub struct ActionDef {
    pub name: String,
    pub required: Vec<String>,
    pub target_ids: TargetIdsFn,
    pub execute: ExecuteFn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionParamDef {
    pub name: String,
    pub param_type: PropertyType,
    pub required: bool,
    pub enum_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionOp {
    pub op: String,
    pub property: String,
    pub value_from: String,
    pub relation: String,
}

/// Risk classification for an action or op, ordered least to most dangerous.
/// The ordering is meaningful: an action type's class is the maximum over its
/// ops, and policy can gate by class (e.g. deny everything at or above `Write`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskClass {
    Read,
    Write,
    Destructive,
}

impl RiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskClass::Read => "read",
            RiskClass::Write => "write",
            RiskClass::Destructive => "destructive",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "read" => Some(RiskClass::Read),
            "write" => Some(RiskClass::Write),
            "destructive" => Some(RiskClass::Destructive),
            _ => None,
        }
    }
}

/// Risk class for a single graph op. Unknown ops are treated as `Destructive`
/// so newly added effectful ops fail safe under a restrictive policy until they
/// are explicitly classified.
pub fn op_risk_class(op: &str) -> RiskClass {
    match op {
        "delete_link" | "delete_object" => RiskClass::Destructive,
        "create_object" | "set_property" | "create_link" => RiskClass::Write,
        _ => RiskClass::Destructive,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionTypeDef {
    pub name: String,
    pub description: String,
    pub params: Vec<ActionParamDef>,
    pub ops: Vec<ActionOp>,
    pub target_kind: String,
    pub created: i64,
}

pub struct ActionExecutor {
    registry: HashMap<String, ActionDef>,
    action_types: HashMap<String, ActionTypeDef>,
}

impl Default for ActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionExecutor {
    pub fn new() -> Self {
        let mut e = Self {
            registry: HashMap::new(),
            action_types: HashMap::new(),
        };
        e.register_builtins();
        e
    }

    pub fn from_action_types(action_types: Vec<ActionTypeDef>) -> Result<Self, String> {
        let mut executor = Self::new();
        for action_type in action_types {
            executor.register_action_type(action_type)?;
        }
        Ok(executor)
    }

    pub fn has_action(&self, name: &str) -> bool {
        self.registry.contains_key(name) || self.action_types.contains_key(name)
    }

    pub fn list_action_types(&self) -> Vec<ActionTypeDef> {
        let mut action_types: Vec<_> = self.action_types.values().cloned().collect();
        action_types.sort_by(|a, b| a.name.cmp(&b.name));
        action_types
    }

    /// Risk class of an action by name. Builtin action names are op names, so
    /// they map directly; user-defined action types take the maximum class over
    /// their ops. Unknown actions are treated as `Destructive` (fail safe).
    pub fn action_risk_class(&self, action: &str) -> RiskClass {
        if self.registry.contains_key(action) {
            return op_risk_class(action);
        }
        if let Some(action_type) = self.action_types.get(action) {
            return action_type
                .ops
                .iter()
                .map(|op| op_risk_class(&op.op))
                .max()
                .unwrap_or(RiskClass::Write);
        }
        RiskClass::Destructive
    }

    /// Human-readable description of the ops an action would perform, in order.
    /// Used by dry-run; describes op shape without leaking property values.
    pub fn planned_ops(
        &self,
        action: &str,
        params: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let get = |key: &str| params.get(key).cloned().unwrap_or_default();
        if self.registry.contains_key(action) {
            let describe = match action {
                "create_object" => {
                    format!("create_object kind={} id={}", get("kind"), get("id"))
                }
                "set_property" => format!("set_property {}.{}", get("id"), get("key")),
                "create_link" => format!(
                    "create_link {}->{} ({})",
                    get("from_id"),
                    get("to_id"),
                    get("relation")
                ),
                "delete_link" => format!("delete_link {}", get("id")),
                other => other.to_string(),
            };
            return Ok(vec![describe]);
        }
        let action_type = self
            .action_types
            .get(action)
            .ok_or_else(|| format!("unknown action: {}", action))?;
        Ok(action_type
            .ops
            .iter()
            .map(|op| match op.op.as_str() {
                "set_property" => {
                    format!("set_property {} <- param {}", op.property, op.value_from)
                }
                "create_object" => {
                    format!(
                        "create_object kind={} name <- param {}",
                        op.property, op.value_from
                    )
                }
                "create_link" => {
                    format!(
                        "create_link relation={} to <- param {}",
                        op.relation, op.property
                    )
                }
                "delete_link" => format!("delete_link <- param {}", op.value_from),
                other => other.to_string(),
            })
            .collect())
    }

    /// Count the graph effects an action would contribute, as
    /// `(mutations, deletes)`. Mutations are object/link writes
    /// (create_object/set_property/create_link); deletes are link removals.
    /// Used for per-work-unit blast-radius caps.
    pub fn action_op_counts(&self, action: &str, _params: &HashMap<String, String>) -> (u32, u32) {
        let count_op = |op: &str| -> (u32, u32) {
            match op {
                "delete_link" | "delete_object" => (0, 1),
                "create_object" | "set_property" | "create_link" => (1, 0),
                _ => (1, 0),
            }
        };
        if self.registry.contains_key(action) {
            return count_op(action);
        }
        match self.action_types.get(action) {
            Some(action_type) => action_type.ops.iter().fold((0, 0), |(m, d), op| {
                let (om, od) = count_op(&op.op);
                (m + om, d + od)
            }),
            // Unknown action: treat as a single mutation (fail safe toward counting).
            None => (1, 0),
        }
    }

    pub fn masks_missing_link(&self, action: &str) -> bool {
        action == "delete_link"
            || self
                .action_types
                .get(action)
                .map(|action_type| action_type.ops.iter().any(|op| op.op == "delete_link"))
                .unwrap_or(false)
    }

    pub fn sensitive_param_names(&self, action: &str) -> HashSet<String> {
        self.action_types
            .get(action)
            .map(|action_type| {
                action_type
                    .ops
                    .iter()
                    .filter(|op| op.op == "set_property" && is_sensitive_name(&op.property))
                    .map(|op| op.value_from.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn register_action_type(&mut self, action_type: ActionTypeDef) -> Result<(), String> {
        validate_action_type_definition(&action_type, self.has_builtin(&action_type.name))?;
        self.action_types
            .insert(action_type.name.clone(), action_type);
        Ok(())
    }

    pub fn remove_action_type(&mut self, name: &str) {
        self.action_types.remove(name);
    }

    pub fn execute(
        &self,
        db: &SekaiDb,
        schema: &SchemaRegistry,
        action: &str,
        params: &HashMap<String, String>,
        actor: &str,
    ) -> Result<String, String> {
        if let Some(def) = self.registry.get(action) {
            Self::validate_required(def, params)?;
            return (def.execute)(db, schema, params, actor);
        }
        let action_type = self
            .action_types
            .get(action)
            .ok_or_else(|| format!("unknown action: {}", action))?;
        db.execute_action_type(action_type, params, schema, actor)
    }

    pub fn target_ids(
        &self,
        db: &SekaiDb,
        action: &str,
        params: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        if let Some(def) = self.registry.get(action) {
            Self::validate_required(def, params)?;
            return (def.target_ids)(db, params);
        }
        let action_type = self
            .action_types
            .get(action)
            .ok_or_else(|| format!("unknown action: {}", action))?;
        validate_action_params(action_type, params)?;
        db.action_type_target_ids(action_type, params)
    }

    pub fn schema_kinds(
        &self,
        db: &SekaiDb,
        action: &str,
        params: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        if action == "create_object" {
            return Ok(params.get("kind").cloned().into_iter().collect());
        }
        if action == "set_property" {
            let Some(id) = params.get("id") else {
                return Ok(Vec::new());
            };
            return Ok(db
                .get_object(id)?
                .map(|object| vec![object.kind])
                .unwrap_or_default());
        }
        let Some(action_type) = self.action_types.get(action) else {
            return Ok(Vec::new());
        };
        let mut kinds = vec![action_type.target_kind.clone()];
        kinds.extend(
            action_type
                .ops
                .iter()
                .filter(|op| op.op == "create_object")
                .map(|op| op.property.clone()),
        );
        kinds.sort();
        kinds.dedup();
        Ok(kinds)
    }

    pub fn validate_action_schema(
        &self,
        action: &str,
        schema: &SchemaRegistry,
    ) -> Result<(), String> {
        if let Some(action_type) = self.action_types.get(action) {
            validate_action_type_against_schema(action_type, schema)?;
        }
        Ok(())
    }

    fn validate_required(def: &ActionDef, params: &HashMap<String, String>) -> Result<(), String> {
        for r in &def.required {
            if !params.contains_key(r) {
                return Err(format!("missing required param: {}", r));
            }
        }
        Ok(())
    }

    fn has_builtin(&self, name: &str) -> bool {
        self.registry.contains_key(name)
    }

    fn register_builtins(&mut self) {
        self.registry.insert(
            "create_object".into(),
            ActionDef {
                name: "create_object".into(),
                required: vec!["id".into(), "kind".into(), "name".into()],
                target_ids: Box::new(|_, p| Ok(vec![p["id"].clone()])),
                execute: Box::new(|db, schema, p, actor| {
                    let now = chrono::Utc::now().timestamp();
                    let mut properties = HashMap::from([("name".into(), p["name"].clone())]);
                    for (key, value) in p {
                        if !matches!(
                            key.as_str(),
                            "id" | "kind" | "name" | "namespace" | "external_id"
                        ) {
                            properties.insert(key.clone(), value.clone());
                        }
                    }
                    let obj = Object {
                        id: p["id"].clone(),
                        kind: p["kind"].clone(),
                        name: p["name"].clone(),
                        namespace: p.get("namespace").cloned().unwrap_or_default(),
                        external_id: p.get("external_id").cloned().unwrap_or_default(),
                        properties,
                        created: now,
                        updated: now,
                    };
                    schema.validate(&obj)?;
                    db.create_object_with_audit(&obj, actor)?;
                    Ok(format!("created object {}", obj.id))
                }),
            },
        );
        self.registry.insert(
            "set_property".into(),
            ActionDef {
                name: "set_property".into(),
                required: vec!["id".into(), "key".into(), "value".into()],
                target_ids: Box::new(|_, p| Ok(vec![p["id"].clone()])),
                execute: Box::new(|db, schema, p, actor| {
                    let mut obj = db.get_object(&p["id"])?.ok_or("object not found")?;
                    obj.properties.insert(p["key"].clone(), p["value"].clone());
                    obj.updated = chrono::Utc::now().timestamp();
                    schema.validate(&obj)?;
                    db.update_object_with_audit(&obj, actor)?
                        .ok_or("object not found")?;
                    Ok(format!("set {}.{} = {}", obj.id, p["key"], p["value"]))
                }),
            },
        );
        self.registry.insert(
            "create_link".into(),
            ActionDef {
                name: "create_link".into(),
                required: vec!["from_id".into(), "to_id".into(), "relation".into()],
                target_ids: Box::new(|_, p| Ok(vec![p["from_id"].clone(), p["to_id"].clone()])),
                execute: Box::new(|db, _, p, _actor| {
                    let id = format!("{}->{}", p["from_id"], p["to_id"]);
                    let link = Link {
                        id: id.clone(),
                        from_id: p["from_id"].clone(),
                        to_id: p["to_id"].clone(),
                        relation: p["relation"].clone(),
                        created: chrono::Utc::now().timestamp(),
                    };
                    db.create_link(&link)?;
                    Ok(format!("created link {}", id))
                }),
            },
        );
        self.registry.insert(
            "delete_link".into(),
            ActionDef {
                name: "delete_link".into(),
                required: vec!["id".into()],
                target_ids: Box::new(|db, p| {
                    let link = db.get_link(&p["id"])?.ok_or("link not found")?;
                    Ok(vec![link.from_id, link.to_id])
                }),
                execute: Box::new(|db, _, p, _actor| {
                    db.delete_link(&p["id"])?;
                    Ok(format!("deleted link {}", p["id"]))
                }),
            },
        );
    }
}

pub fn validate_action_type_definition(
    action_type: &ActionTypeDef,
    builtin_collision: bool,
) -> Result<(), String> {
    if action_type.name.trim().is_empty() {
        return Err("action name required".into());
    }
    if builtin_collision {
        return Err("action name collides with builtin".into());
    }
    if action_type.target_kind.trim().is_empty() {
        return Err("target_kind required".into());
    }
    if action_type.ops.is_empty() {
        return Err("at least one op required".into());
    }

    let mut names = HashSet::from(["id".to_string()]);
    for param in &action_type.params {
        if param.name.trim().is_empty() {
            return Err("param name required".into());
        }
        if !names.insert(param.name.clone()) {
            return Err(format!("duplicate param: {}", param.name));
        }
        if param.param_type == PropertyType::Enum && param.enum_values.is_empty() {
            return Err(format!("enum param {} requires values", param.name));
        }
    }

    let params = action_type
        .params
        .iter()
        .map(|param| param.name.as_str())
        .collect::<HashSet<_>>();
    let param_names = action_type
        .params
        .iter()
        .map(|param| param.name.as_str())
        .collect::<HashSet<_>>();
    for op in &action_type.ops {
        match op.op.as_str() {
            "set_property" => {
                if op.property.trim().is_empty() {
                    return Err("set_property op requires property".into());
                }
                if op.value_from.trim().is_empty() {
                    return Err("set_property op requires value_from".into());
                }
                if !params.contains(op.value_from.as_str()) {
                    return Err(format!(
                        "set_property op references unknown param: {}",
                        op.value_from
                    ));
                }
            }
            "create_object" => {
                if op.property.trim().is_empty() {
                    return Err("create_object op requires property kind".into());
                }
                if op.value_from.trim().is_empty() {
                    return Err("create_object op requires value_from name param".into());
                }
                if !param_names.contains(op.value_from.as_str()) {
                    return Err(format!(
                        "create_object op references unknown param: {}",
                        op.value_from
                    ));
                }
            }
            "create_link" => {
                if op.property.trim().is_empty() {
                    return Err("create_link op requires property endpoint param".into());
                }
                if !param_names.contains(op.property.as_str()) {
                    return Err(format!(
                        "create_link op references unknown endpoint param: {}",
                        op.property
                    ));
                }
                if op.relation.trim().is_empty() {
                    return Err("create_link op requires relation".into());
                }
            }
            "delete_link" => {
                if op.value_from.trim().is_empty() {
                    return Err("delete_link op requires value_from link id param".into());
                }
                if !param_names.contains(op.value_from.as_str()) {
                    return Err(format!(
                        "delete_link op references unknown param: {}",
                        op.value_from
                    ));
                }
            }
            other => return Err(format!("unsupported action op: {other}")),
        }
    }
    Ok(())
}

pub fn validate_action_type_against_schema(
    action_type: &ActionTypeDef,
    schema: &SchemaRegistry,
) -> Result<(), String> {
    let target = schema
        .get(&action_type.target_kind)
        .ok_or_else(|| "target_kind schema type required".to_string())?;
    let allowed = target
        .properties
        .iter()
        .map(|property| property.name.as_str())
        .collect::<HashSet<_>>();
    for op in &action_type.ops {
        match op.op.as_str() {
            "set_property" if !allowed.contains(op.property.as_str()) => {
                return Err(format!(
                    "property {} is not declared on target_kind {}",
                    op.property, action_type.target_kind
                ));
            }
            "create_object" if schema.get(&op.property).is_none() => {
                return Err(format!(
                    "create_object kind {} is not declared",
                    op.property
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_action_params(
    action_type: &ActionTypeDef,
    params: &HashMap<String, String>,
) -> Result<(), String> {
    if !params.contains_key("id") {
        return Err("missing required param: id".into());
    }
    for param in &action_type.params {
        let Some(value) = params.get(&param.name) else {
            if param.required {
                return Err(format!("missing required param: {}", param.name));
            }
            continue;
        };
        validate_param_value(param, value)?;
    }
    Ok(())
}

fn validate_param_value(param: &ActionParamDef, value: &str) -> Result<(), String> {
    match param.param_type {
        PropertyType::Enum => {
            if !param.enum_values.iter().any(|allowed| allowed == value) {
                return Err(format!(
                    "param {}: value {:?} not in {:?}",
                    param.name, value, param.enum_values
                ));
            }
        }
        PropertyType::Bool => {
            if value != "true" && value != "false" {
                return Err(format!(
                    "param {}: expected bool, got {:?}",
                    param.name, value
                ));
            }
        }
        PropertyType::Int if !value.chars().all(|c| c.is_ascii_digit()) => {
            return Err(format!(
                "param {}: expected int, got {:?}",
                param.name, value
            ));
        }
        PropertyType::Float => match value.parse::<f64>() {
            Ok(parsed) if parsed.is_finite() => {}
            _ => {
                return Err(format!(
                    "param {}: expected float, got {:?}",
                    param.name, value
                ));
            }
        },
        PropertyType::Timestamp
            if value.parse::<i64>().is_err()
                && chrono::DateTime::parse_from_rfc3339(value).is_err() =>
        {
            return Err(format!(
                "param {}: expected timestamp, got {:?}",
                param.name, value
            ));
        }
        PropertyType::Struct => {
            let parsed: serde_json::Value = serde_json::from_str(value)
                .map_err(|_| format!("param {}: expected struct JSON object", param.name))?;
            if !parsed.is_object() {
                return Err(format!("param {}: expected struct JSON object", param.name));
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_sensitive_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains("password")
        || lower.contains("passphrase")
        || lower.contains("passwd")
        || lower.contains("credential")
}

impl SekaiDb {
    pub fn migrate_action_types(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_action_types (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                target_kind TEXT NOT NULL DEFAULT '',
                body_json TEXT NOT NULL,
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL
            );",
        )
        .map_err(|error| error.to_string())
    }

    pub fn upsert_action_type(&self, action_type: &ActionTypeDef) -> Result<ActionTypeDef, String> {
        self.migrate_action_types()?;
        let mut stored = action_type.clone();
        if stored.created <= 0 {
            stored.created = chrono::Utc::now().timestamp_millis();
        }
        let updated = chrono::Utc::now().timestamp_millis();
        let body_json = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_action_types (name, description, target_kind, body_json, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET
                description = excluded.description,
                target_kind = excluded.target_kind,
                body_json = excluded.body_json,
                updated = excluded.updated",
            params![
                stored.name,
                stored.description,
                stored.target_kind,
                body_json,
                stored.created,
                updated,
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(stored)
    }

    pub fn delete_action_type(&self, name: &str) -> Result<bool, String> {
        self.migrate_action_types()?;
        let conn = self.conn();
        let deleted = conn
            .execute(
                "DELETE FROM sekai_action_types WHERE name = ?1",
                params![name],
            )
            .map_err(|error| error.to_string())?;
        Ok(deleted > 0)
    }

    pub fn list_action_types(&self) -> Result<Vec<ActionTypeDef>, String> {
        self.migrate_action_types()?;
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT body_json FROM sekai_action_types ORDER BY name")
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let body_json: String = row.get(0)?;
                serde_json::from_str(&body_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| error.to_string())?;
        let parsed: Result<Vec<_>, rusqlite::Error> = rows.collect();
        parsed.map_err(|error| error.to_string())
    }

    pub fn execute_action_type(
        &self,
        action_type: &ActionTypeDef,
        params: &HashMap<String, String>,
        schema: &SchemaRegistry,
        actor: &str,
    ) -> Result<String, String> {
        validate_action_params(action_type, params)?;
        let id = params.get("id").cloned().unwrap_or_default();
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut target_object = tx
            .query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
                params![id],
                crate::db::sekai::row_to_object,
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "object not found".to_string())?;
        if target_object.kind != action_type.target_kind {
            return Err(format!(
                "target kind mismatch: expected {}, got {}",
                action_type.target_kind, target_object.kind
            ));
        }
        let before_target = target_object.clone();
        let mut object_changes = Vec::new();
        for op in &action_type.ops {
            match op.op.as_str() {
                "set_property" => {
                    let value = params
                        .get(&op.value_from)
                        .cloned()
                        .ok_or_else(|| format!("missing required param: {}", op.value_from))?;
                    target_object.properties.insert(op.property.clone(), value);
                }
                "create_object" => {
                    let name = params
                        .get(&op.value_from)
                        .cloned()
                        .ok_or_else(|| format!("missing required param: {}", op.value_from))?;
                    let now = chrono::Utc::now().timestamp();
                    let created = Object {
                        id: format!("{}:{}", action_type.name, uuid::Uuid::new_v4()),
                        kind: op.property.clone(),
                        name,
                        namespace: target_object.namespace.clone(),
                        external_id: String::new(),
                        properties: HashMap::new(),
                        created: now,
                        updated: now,
                    };
                    let mut created = created;
                    created
                        .properties
                        .insert("name".into(), created.name.clone());
                    schema.validate(&created)?;
                    let props =
                        serde_json::to_string(&created.properties).map_err(|e| e.to_string())?;
                    tx.execute(
                        "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                        params![
                            created.id,
                            created.kind,
                            created.name,
                            created.namespace,
                            created.external_id,
                            props,
                            created.created,
                            created.updated,
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                    object_changes.extend(crate::sekai::audit::object_diff_changes(
                        actor,
                        None,
                        Some(&created),
                        chrono::Utc::now().timestamp_millis(),
                    ));
                }
                "create_link" => {
                    let to_id = params
                        .get(&op.property)
                        .cloned()
                        .ok_or_else(|| format!("missing required param: {}", op.property))?;
                    ensure_object_exists(&tx, &to_id)?;
                    let link_id = format!("{}->{}", target_object.id, to_id);
                    tx.execute(
                        "INSERT OR IGNORE INTO sekai_links (id, from_id, to_id, relation, created) VALUES (?1,?2,?3,?4,?5)",
                        params![
                            link_id,
                            target_object.id,
                            to_id,
                            op.relation,
                            chrono::Utc::now().timestamp(),
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                }
                "delete_link" => {
                    let link_id = params
                        .get(&op.value_from)
                        .cloned()
                        .ok_or_else(|| format!("missing required param: {}", op.value_from))?;
                    let link =
                        get_link_tx(&tx, &link_id)?.ok_or_else(|| "link not found".to_string())?;
                    if link.from_id != target_object.id && link.to_id != target_object.id {
                        return Err("link does not target action object".into());
                    }
                    tx.execute("DELETE FROM sekai_links WHERE id = ?1", params![link_id])
                        .map_err(|error| error.to_string())?;
                }
                other => return Err(format!("unsupported action op: {other}")),
            }
        }
        target_object.updated = chrono::Utc::now().timestamp();
        schema.validate(&target_object)?;
        let props = serde_json::to_string(&target_object.properties).map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE sekai_objects SET kind=?2, name=?3, namespace=?4, external_id=?5, properties=?6, updated=?7 WHERE id=?1",
            params![
                target_object.id,
                target_object.kind,
                target_object.name,
                target_object.namespace,
                target_object.external_id,
                props,
                target_object.updated,
            ],
        )
        .map_err(|error| error.to_string())?;
        object_changes.extend(crate::sekai::audit::object_diff_changes(
            actor,
            Some(&before_target),
            Some(&target_object),
            chrono::Utc::now().timestamp_millis(),
        ));
        crate::sekai::audit::insert_object_changes(&tx, &object_changes)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(format!("executed action {}", action_type.name))
    }

    pub fn action_type_target_ids(
        &self,
        action_type: &ActionTypeDef,
        params: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let mut target_ids = vec![
            params
                .get("id")
                .cloned()
                .ok_or_else(|| "missing required param: id".to_string())?,
        ];
        for op in &action_type.ops {
            match op.op.as_str() {
                "create_link" => target_ids.push(
                    params
                        .get(&op.property)
                        .cloned()
                        .ok_or_else(|| format!("missing required param: {}", op.property))?,
                ),
                "delete_link" => {
                    let link_id = params
                        .get(&op.value_from)
                        .ok_or_else(|| format!("missing required param: {}", op.value_from))?;
                    let link = self
                        .get_link(link_id)?
                        .ok_or_else(|| "link not found".to_string())?;
                    target_ids.push(link.from_id);
                    target_ids.push(link.to_id);
                }
                _ => {}
            }
        }
        target_ids.sort();
        target_ids.dedup();
        Ok(target_ids)
    }
}

fn ensure_object_exists(conn: &rusqlite::Connection, id: &str) -> Result<(), String> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sekai_objects WHERE id = ?1",
            params![id],
            |_| Ok(()),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(format!("object not found: {id}"))
    }
}

fn get_link_tx(conn: &rusqlite::Connection, id: &str) -> Result<Option<Link>, String> {
    conn.query_row(
        "SELECT id, from_id, to_id, relation, created FROM sekai_links WHERE id = ?1",
        params![id],
        |row| {
            Ok(Link {
                id: row.get(0)?,
                from_id: row.get(1)?,
                to_id: row.get(2)?,
                relation: row.get(3)?,
                created: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_object_action() {
        let db = SekaiDb::new(":memory:").unwrap();
        let exec = ActionExecutor::new();
        let params = HashMap::from([
            ("id".into(), "o1".into()),
            ("kind".into(), "namespace".into()),
            ("name".into(), "test".into()),
        ]);
        assert_eq!(
            exec.target_ids(&db, "create_object", &params).unwrap(),
            vec!["o1".to_string()]
        );
        let schema = SchemaRegistry::new();
        let msg = exec
            .execute(&db, &schema, "create_object", &params, "user")
            .unwrap();
        assert!(msg.contains("o1"));
        assert!(db.get_object("o1").unwrap().is_some());
        let changes = db.list_object_changes("o1", 10, 0).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "_created");
        assert_eq!(changes[0].changed_by, "user");
    }

    #[test]
    fn test_set_property_action() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "o1".into(),
            kind: "namespace".into(),
            name: "r".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let exec = ActionExecutor::new();
        let params = HashMap::from([
            ("id".into(), "o1".into()),
            ("key".into(), "language".into()),
            ("value".into(), "rust".into()),
        ]);
        let schema = SchemaRegistry::new();
        exec.execute(&db, &schema, "set_property", &params, "user")
            .unwrap();
        let obj = db.get_object("o1").unwrap().unwrap();
        assert_eq!(obj.properties["language"], "rust");
        let changes = db.list_object_changes("o1", 10, 0).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "properties.language");
        assert_eq!(changes[0].new_value, "rust");
        assert_eq!(changes[0].changed_by, "user");
    }

    #[test]
    fn test_missing_param() {
        let db = SekaiDb::new(":memory:").unwrap();
        let exec = ActionExecutor::new();
        let params = HashMap::from([("id".into(), "o1".into())]);
        let schema = SchemaRegistry::new();
        assert!(
            exec.execute(&db, &schema, "create_object", &params, "user")
                .is_err()
        );
    }

    #[test]
    fn test_op_risk_class_mapping() {
        assert_eq!(op_risk_class("delete_link"), RiskClass::Destructive);
        assert_eq!(op_risk_class("delete_object"), RiskClass::Destructive);
        assert_eq!(op_risk_class("set_property"), RiskClass::Write);
        assert_eq!(op_risk_class("create_object"), RiskClass::Write);
        assert_eq!(op_risk_class("create_link"), RiskClass::Write);
        // Unknown ops fail safe as Destructive.
        assert_eq!(op_risk_class("teleport"), RiskClass::Destructive);
    }

    #[test]
    fn test_risk_class_ordering_and_parse() {
        assert!(RiskClass::Read < RiskClass::Write);
        assert!(RiskClass::Write < RiskClass::Destructive);
        assert_eq!(RiskClass::parse("READ"), Some(RiskClass::Read));
        assert_eq!(
            RiskClass::parse(" destructive "),
            Some(RiskClass::Destructive)
        );
        assert_eq!(RiskClass::parse("nonsense"), None);
        assert_eq!(RiskClass::Destructive.as_str(), "destructive");
    }

    #[test]
    fn test_builtin_action_risk_class() {
        let exec = ActionExecutor::new();
        assert_eq!(
            exec.action_risk_class("delete_link"),
            RiskClass::Destructive
        );
        assert_eq!(exec.action_risk_class("set_property"), RiskClass::Write);
        assert_eq!(exec.action_risk_class("create_object"), RiskClass::Write);
        assert_eq!(exec.action_risk_class("create_link"), RiskClass::Write);
        // Unknown action names fail safe as Destructive.
        assert_eq!(exec.action_risk_class("mystery"), RiskClass::Destructive);
    }

    #[test]
    fn test_action_type_risk_class_is_max_over_ops() {
        let write_only = ActionTypeDef {
            name: "recolor".into(),
            description: String::new(),
            params: vec![ActionParamDef {
                name: "color".into(),
                param_type: PropertyType::String,
                required: true,
                enum_values: vec![],
            }],
            ops: vec![ActionOp {
                op: "set_property".into(),
                property: "color".into(),
                value_from: "color".into(),
                relation: String::new(),
            }],
            target_kind: "widget".into(),
            created: 0,
        };
        let destructive = ActionTypeDef {
            name: "detach".into(),
            description: String::new(),
            params: vec![ActionParamDef {
                name: "link".into(),
                param_type: PropertyType::String,
                required: true,
                enum_values: vec![],
            }],
            ops: vec![
                ActionOp {
                    op: "set_property".into(),
                    property: "color".into(),
                    value_from: "link".into(),
                    relation: String::new(),
                },
                ActionOp {
                    op: "delete_link".into(),
                    property: String::new(),
                    value_from: "link".into(),
                    relation: String::new(),
                },
            ],
            target_kind: "widget".into(),
            created: 0,
        };
        let mut exec = ActionExecutor::new();
        exec.action_types
            .insert(write_only.name.clone(), write_only);
        exec.action_types
            .insert(destructive.name.clone(), destructive);
        assert_eq!(exec.action_risk_class("recolor"), RiskClass::Write);
        assert_eq!(exec.action_risk_class("detach"), RiskClass::Destructive);
    }
}

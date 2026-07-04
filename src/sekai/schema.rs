use crate::db::sekai::SekaiDb;
use crate::domain::{Object, ObjectKind};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PropertyType {
    String,
    Int,
    Float,
    Bool,
    Enum,
    Timestamp,
    Link,
    Computed,
}

impl PropertyType {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "string" => Some(Self::String),
            "int" => Some(Self::Int),
            "float" => Some(Self::Float),
            "bool" => Some(Self::Bool),
            "enum" => Some(Self::Enum),
            "timestamp" => Some(Self::Timestamp),
            "link" => Some(Self::Link),
            "computed" => Some(Self::Computed),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Enum => "enum",
            Self::Timestamp => "timestamp",
            Self::Link => "link",
            Self::Computed => "computed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyDef {
    pub name: String,
    pub prop_type: PropertyType,
    pub required: bool,
    pub description: String,
    pub enum_values: Vec<String>,
    pub link_kind: String,
    pub compute_expr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectType {
    pub kind: ObjectKind,
    pub description: String,
    pub properties: Vec<PropertyDef>,
    pub is_builtin: bool,
}

pub struct SchemaRegistry {
    types: HashMap<ObjectKind, ObjectType>,
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            types: HashMap::new(),
        };
        for object_type in builtin_object_types() {
            registry.register(object_type);
        }
        registry
    }

    pub fn register(&mut self, ot: ObjectType) {
        self.types.insert(ot.kind.clone(), ot);
    }

    pub fn remove(&mut self, kind: &str) {
        self.types.remove(kind);
    }

    pub fn get(&self, kind: &str) -> Option<&ObjectType> {
        self.types.get(kind)
    }

    pub fn all(&self) -> Vec<ObjectType> {
        let mut types: Vec<_> = self.types.values().cloned().collect();
        types.sort_by(|a, b| a.kind.cmp(&b.kind));
        types
    }

    pub fn from_types(types: Vec<ObjectType>) -> Self {
        let mut registry = Self::new();
        for object_type in types {
            registry.register(object_type);
        }
        registry
    }

    pub fn validate(&self, obj: &Object) -> Result<(), String> {
        let ot = match self.types.get(&obj.kind) {
            Some(t) => t,
            None => return Ok(()), // untyped kinds pass
        };
        let mut errs = Vec::new();
        for pd in &ot.properties {
            if pd.prop_type == PropertyType::Computed {
                continue;
            }
            let val = obj.properties.get(&pd.name);
            let empty = val.map(|v| v.is_empty()).unwrap_or(true);
            if pd.required && empty {
                errs.push(format!("missing required property: {}", pd.name));
                continue;
            }
            if empty {
                continue;
            }
            let v = val.unwrap();
            match &pd.prop_type {
                PropertyType::Enum => {
                    if !pd.enum_values.contains(v) {
                        errs.push(format!(
                            "property {}: value {:?} not in {:?}",
                            pd.name, v, pd.enum_values
                        ));
                    }
                }
                PropertyType::Bool => {
                    if v != "true" && v != "false" {
                        errs.push(format!("property {}: expected bool, got {:?}", pd.name, v));
                    }
                }
                PropertyType::Int if !v.chars().all(|c| c.is_ascii_digit()) => {
                    errs.push(format!("property {}: expected int, got {:?}", pd.name, v));
                }
                PropertyType::Float => match v.parse::<f64>() {
                    Ok(parsed) if parsed.is_finite() => {}
                    _ => errs.push(format!("property {}: expected float, got {:?}", pd.name, v)),
                },
                PropertyType::Timestamp if !is_valid_timestamp(v) => {
                    errs.push(format!(
                        "property {}: expected timestamp, got {:?}",
                        pd.name, v
                    ));
                }
                _ => {}
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

fn is_valid_timestamp(value: &str) -> bool {
    value.parse::<i64>().is_ok() || chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

fn builtin_object_types() -> Vec<ObjectType> {
    [
        ("agent", "Built-in agent object"),
        ("asset", "Built-in asset object"),
        ("budget", "Built-in budget object"),
        ("component", "Built-in component object"),
        ("gateway_key", "Built-in gateway key object"),
        ("namespace", "Built-in namespace object"),
        ("policy", "Built-in policy object"),
        ("project", "Built-in project object"),
        ("ticker", "Built-in ticker object"),
    ]
    .into_iter()
    .map(|(kind, description)| ObjectType {
        kind: kind.to_string(),
        description: description.to_string(),
        properties: Vec::new(),
        is_builtin: true,
    })
    .collect()
}

pub fn validate_object_type_definition(
    object_type: &ObjectType,
    existing: Option<&ObjectType>,
) -> Result<(), String> {
    if object_type.kind.trim().is_empty() {
        return Err("kind required".into());
    }
    if object_type.is_builtin {
        return Err("builtin schema types are code-owned".into());
    }
    if existing
        .map(|existing| existing.is_builtin)
        .unwrap_or(false)
    {
        return Err("cannot replace builtin schema type".into());
    }

    let mut seen = HashSet::new();
    for property in &object_type.properties {
        if property.name.trim().is_empty() {
            return Err("property name required".into());
        }
        if !seen.insert(property.name.clone()) {
            return Err(format!("duplicate property: {}", property.name));
        }
        if property.prop_type == PropertyType::Enum && property.enum_values.is_empty() {
            return Err(format!("enum property {} requires values", property.name));
        }
    }
    Ok(())
}

impl SekaiDb {
    pub(crate) fn migrate_schema_types(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_object_types (
                kind TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                properties_json TEXT NOT NULL DEFAULT '[]',
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL
            );",
        )
        .map_err(|error| error.to_string())
    }

    pub fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let properties_json =
            serde_json::to_string(&object_type.properties).map_err(|error| error.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(kind) DO UPDATE SET
                description = excluded.description,
                properties_json = excluded.properties_json,
                updated = excluded.updated",
            params![
                object_type.kind,
                object_type.description,
                properties_json,
                now
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn delete_object_type(&self, kind: &str) -> Result<bool, String> {
        let conn = self.conn();
        let deleted = conn
            .execute(
                "DELETE FROM sekai_object_types WHERE kind = ?1",
                params![kind],
            )
            .map_err(|error| error.to_string())?;
        Ok(deleted > 0)
    }

    pub fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT kind, description, properties_json FROM sekai_object_types WHERE kind = ?1",
            params![kind],
            row_to_object_type,
        )
        .optional()
        .map_err(|error| error.to_string())
    }

    pub fn list_object_types(&self) -> Result<Vec<ObjectType>, String> {
        let (types, errors) = self.list_object_types_with_errors()?;
        if !errors.is_empty() {
            let details = errors
                .iter()
                .map(|(kind, error)| format!("{kind}: {error}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("invalid schema type rows: {details}"));
        }
        Ok(types)
    }

    pub fn list_object_types_with_errors(
        &self,
    ) -> Result<(Vec<ObjectType>, HashMap<String, String>), String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT kind, description, properties_json FROM sekai_object_types ORDER BY kind",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt.query([]).map_err(|error| error.to_string())?;
        let mut types = Vec::new();
        let mut errors = HashMap::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let kind: String = row.get(0).map_err(|error| error.to_string())?;
            let description: String = row.get(1).map_err(|error| error.to_string())?;
            let properties_json: String = row.get(2).map_err(|error| error.to_string())?;
            match serde_json::from_str(&properties_json) {
                Ok(properties) => types.push(ObjectType {
                    kind,
                    description,
                    properties,
                    is_builtin: false,
                }),
                Err(error) => {
                    errors.insert(kind, error.to_string());
                }
            }
        }
        Ok((types, errors))
    }
}

fn row_to_object_type(row: &rusqlite::Row) -> Result<ObjectType, rusqlite::Error> {
    let properties_json: String = row.get(2)?;
    let properties = serde_json::from_str(&properties_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ObjectType {
        kind: row.get(0)?,
        description: row.get(1)?,
        properties,
        is_builtin: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn prop(name: &str, t: PropertyType, required: bool) -> PropertyDef {
        PropertyDef {
            name: name.into(),
            prop_type: t,
            required,
            description: String::new(),
            enum_values: vec![],
            link_kind: String::new(),
            compute_expr: String::new(),
        }
    }

    fn prop_enum(name: &str, values: &[&str], required: bool) -> PropertyDef {
        PropertyDef {
            name: name.into(),
            prop_type: PropertyType::Enum,
            required,
            description: String::new(),
            enum_values: values.iter().map(|s| s.to_string()).collect(),
            link_kind: String::new(),
            compute_expr: String::new(),
        }
    }

    fn widget_registry() -> SchemaRegistry {
        let mut r = SchemaRegistry::new();
        r.register(ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            is_builtin: false,
            properties: vec![
                prop_enum("color", &["red", "blue"], false),
                prop("name", PropertyType::String, true),
            ],
        });
        r
    }

    #[test]
    fn test_validate_passes_for_valid_object() {
        let reg = widget_registry();
        let obj = Object {
            id: "w1".into(),
            kind: "widget".into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("color".to_string(), "red".to_string()),
                ("name".to_string(), "foo".to_string()),
            ]),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).is_ok());
    }

    #[test]
    fn test_validate_rejects_bad_enum() {
        let reg = widget_registry();
        let obj = Object {
            id: "w1".into(),
            kind: "widget".into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("color".to_string(), "green".to_string()),
                ("name".to_string(), "foo".to_string()),
            ]),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).is_err());
    }

    #[test]
    fn test_validate_rejects_missing_required() {
        let reg = widget_registry();
        let obj = Object {
            id: "w1".into(),
            kind: "widget".into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        let err = reg.validate(&obj).unwrap_err();
        assert!(err.contains("name"));
    }

    #[test]
    fn test_validate_passes_untyped_kind() {
        let reg = SchemaRegistry::new();
        let obj = Object {
            id: "x".into(),
            kind: "anything".into(),
            name: "x".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).is_ok());
    }

    #[test]
    fn test_validate_rejects_non_finite_float() {
        let mut reg = SchemaRegistry::new();
        reg.register(ObjectType {
            kind: "measurement".into(),
            description: String::new(),
            is_builtin: false,
            properties: vec![prop("score", PropertyType::Float, true)],
        });
        let obj = Object {
            id: "m1".into(),
            kind: "measurement".into(),
            name: "m".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("score".to_string(), "nan".to_string())]),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).unwrap_err().contains("score"));
    }

    #[test]
    fn test_validate_timestamp_accepts_epoch_or_rfc3339() {
        let mut reg = SchemaRegistry::new();
        reg.register(ObjectType {
            kind: "event".into(),
            description: String::new(),
            is_builtin: false,
            properties: vec![prop("at", PropertyType::Timestamp, true)],
        });
        let mut obj = Object {
            id: "e1".into(),
            kind: "event".into(),
            name: "e".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("at".to_string(), "2026-07-03T19:20:00Z".to_string())]),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).is_ok());

        obj.properties.insert("at".into(), "1783106400000".into());
        assert!(reg.validate(&obj).is_ok());

        obj.properties.insert("at".into(), "tomorrow".into());
        assert!(reg.validate(&obj).unwrap_err().contains("at"));
    }

    #[test]
    fn test_object_type_persistence_round_trip() {
        let db = SekaiDb::new(":memory:").unwrap();
        let object_type = ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            is_builtin: false,
            properties: vec![
                prop("name", PropertyType::String, true),
                prop_enum("color", &["red", "blue"], false),
            ],
        };

        db.upsert_object_type(&object_type).unwrap();
        let listed = db.list_object_types().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, "widget");
        assert_eq!(listed[0].properties.len(), 2);

        let registry = SchemaRegistry::from_types(listed);
        assert!(registry.get("widget").is_some());

        assert!(db.delete_object_type("widget").unwrap());
        assert!(db.list_object_types().unwrap().is_empty());
    }
}

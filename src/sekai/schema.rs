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
    #[serde(default = "default_property_classification")]
    pub classification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectType {
    pub kind: ObjectKind,
    pub description: String,
    pub properties: Vec<PropertyDef>,
    pub is_builtin: bool,
    pub implements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDef {
    pub name: String,
    pub description: String,
    pub properties: Vec<PropertyDef>,
    pub is_builtin: bool,
}

#[derive(Clone)]
pub struct SchemaRegistry {
    types: HashMap<ObjectKind, ObjectType>,
    interfaces: HashMap<String, InterfaceDef>,
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
            interfaces: HashMap::new(),
        };
        for object_type in builtin_object_types() {
            registry.register(object_type);
        }
        for interface in builtin_interfaces() {
            registry.register_interface(interface);
        }
        registry
    }

    pub fn register(&mut self, ot: ObjectType) {
        self.types.insert(ot.kind.clone(), ot);
    }

    pub fn register_interface(&mut self, interface: InterfaceDef) {
        self.interfaces.insert(interface.name.clone(), interface);
    }

    pub fn remove(&mut self, kind: &str) {
        self.types.remove(kind);
    }

    pub fn remove_interface(&mut self, name: &str) {
        self.interfaces.remove(name);
    }

    pub fn get(&self, kind: &str) -> Option<&ObjectType> {
        self.types.get(kind)
    }

    pub fn get_interface(&self, name: &str) -> Option<&InterfaceDef> {
        self.interfaces.get(name)
    }

    pub fn all(&self) -> Vec<ObjectType> {
        let mut types: Vec<_> = self.types.values().cloned().collect();
        types.sort_by(|a, b| a.kind.cmp(&b.kind));
        types
    }

    pub fn all_interfaces(&self) -> Vec<InterfaceDef> {
        let mut interfaces: Vec<_> = self.interfaces.values().cloned().collect();
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        interfaces
    }

    pub fn from_types(types: Vec<ObjectType>) -> Self {
        Self::from_types_and_interfaces(types, Vec::new())
    }

    pub fn from_types_and_interfaces(
        types: Vec<ObjectType>,
        interfaces: Vec<InterfaceDef>,
    ) -> Self {
        let mut registry = Self::new();
        for interface in interfaces {
            registry.register_interface(interface);
        }
        for object_type in types {
            registry.register(object_type);
        }
        registry
    }

    pub fn kind_implements_all(&self, kind: &str, required: &[String]) -> bool {
        if required.is_empty() {
            return true;
        }
        let Some(object_type) = self.types.get(kind) else {
            return false;
        };
        required.iter().all(|name| {
            object_type
                .implements
                .iter()
                .any(|implemented| implemented == name)
        })
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

pub fn default_property_classification() -> String {
    "public".to_string()
}

pub fn normalize_property_classification(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "public"
    } else {
        trimmed
    }
}

pub fn is_restricted_property_classification(value: &str) -> bool {
    matches!(
        normalize_property_classification(value),
        "internal" | "sensitive"
    )
}

fn is_valid_property_classification(value: &str) -> bool {
    matches!(
        normalize_property_classification(value),
        "public" | "internal" | "sensitive"
    )
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
        implements: Vec::new(),
    })
    .collect()
}

fn builtin_interfaces() -> Vec<InterfaceDef> {
    [
        (
            "Auditable",
            "Object participates in audited control-plane activity.",
            Vec::new(),
        ),
        (
            "Budgeted",
            "Object can be associated with budget accounting or cost control.",
            vec![
                prop_def("cost_center", PropertyType::String, false),
                prop_def("budget_ref", PropertyType::String, false),
            ],
        ),
        (
            "Evaluable",
            "Object can carry evaluation and baseline state.",
            vec![
                prop_def("last_eval", PropertyType::Timestamp, false),
                prop_def("baseline", PropertyType::String, false),
            ],
        ),
        (
            "Governed",
            "Object is governed by owner, policy, and status metadata.",
            vec![
                prop_def("owner", PropertyType::String, false),
                prop_def("policy", PropertyType::String, false),
                prop_def("status", PropertyType::String, false),
            ],
        ),
        (
            "RiskScored",
            "Object exposes risk score context for policy and routing decisions.",
            vec![
                prop_def("risk_score", PropertyType::Float, false),
                prop_def("risk_reason", PropertyType::String, false),
                prop_def("risk_updated_at", PropertyType::Timestamp, false),
            ],
        ),
    ]
    .into_iter()
    .map(|(name, description, properties)| InterfaceDef {
        name: name.to_string(),
        description: description.to_string(),
        properties,
        is_builtin: true,
    })
    .collect()
}

fn prop_def(name: &str, prop_type: PropertyType, required: bool) -> PropertyDef {
    PropertyDef {
        name: name.to_string(),
        prop_type,
        required,
        description: String::new(),
        enum_values: Vec::new(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: default_property_classification(),
    }
}

pub fn validate_object_type_definition(
    object_type: &ObjectType,
    existing: Option<&ObjectType>,
    registry: &SchemaRegistry,
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
        if !is_valid_property_classification(&property.classification) {
            return Err(format!(
                "property {} has invalid classification: {}",
                property.name, property.classification
            ));
        }
    }
    let mut implemented = HashSet::new();
    let property_by_name: HashMap<&str, &PropertyDef> = object_type
        .properties
        .iter()
        .map(|property| (property.name.as_str(), property))
        .collect();
    for interface_name in &object_type.implements {
        if interface_name.trim().is_empty() {
            return Err("interface name required".into());
        }
        if !implemented.insert(interface_name.clone()) {
            return Err(format!("duplicate interface: {interface_name}"));
        }
        let interface = registry
            .get_interface(interface_name)
            .ok_or_else(|| format!("unknown interface: {interface_name}"))?;
        for interface_property in &interface.properties {
            let Some(implemented_property) = property_by_name.get(interface_property.name.as_str())
            else {
                if !interface_property.required {
                    continue;
                }
                return Err(format!(
                    "interface {interface_name} requires property {}",
                    interface_property.name
                ));
            };
            if implemented_property.prop_type != interface_property.prop_type {
                return Err(format!(
                    "interface {interface_name} property {} expects type {}, got {}",
                    interface_property.name,
                    interface_property.prop_type.as_str(),
                    implemented_property.prop_type.as_str()
                ));
            }
            if interface_property.required && !implemented_property.required {
                return Err(format!(
                    "interface {interface_name} property {} must be required",
                    interface_property.name
                ));
            }
        }
    }
    Ok(())
}

pub fn validate_interface_definition(
    interface: &InterfaceDef,
    existing: Option<&InterfaceDef>,
) -> Result<(), String> {
    if interface.name.trim().is_empty() {
        return Err("interface name required".into());
    }
    if interface.is_builtin {
        return Err("builtin interfaces are code-owned".into());
    }
    if existing
        .map(|existing| existing.is_builtin)
        .unwrap_or(false)
    {
        return Err("cannot replace builtin interface".into());
    }
    let mut seen = HashSet::new();
    for property in &interface.properties {
        if property.name.trim().is_empty() {
            return Err("property name required".into());
        }
        if !seen.insert(property.name.clone()) {
            return Err(format!("duplicate property: {}", property.name));
        }
        if property.prop_type == PropertyType::Enum && property.enum_values.is_empty() {
            return Err(format!("enum property {} requires values", property.name));
        }
        if !is_valid_property_classification(&property.classification) {
            return Err(format!(
                "property {} has invalid classification: {}",
                property.name, property.classification
            ));
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
                implements_json TEXT NOT NULL DEFAULT '[]',
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sekai_interfaces (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                properties_json TEXT NOT NULL DEFAULT '[]',
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL
            );",
        )
        .map_err(|error| error.to_string())?;
        conn.execute(
            "ALTER TABLE sekai_object_types ADD COLUMN implements_json TEXT NOT NULL DEFAULT '[]'",
            [],
        )
        .or_else(|error| {
            if error.to_string().contains("duplicate column name") {
                Ok(0)
            } else {
                Err(error)
            }
        })
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let properties_json =
            serde_json::to_string(&object_type.properties).map_err(|error| error.to_string())?;
        let implements_json =
            serde_json::to_string(&object_type.implements).map_err(|error| error.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_object_types (kind, description, properties_json, implements_json, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(kind) DO UPDATE SET
                description = excluded.description,
                properties_json = excluded.properties_json,
                implements_json = excluded.implements_json,
                updated = excluded.updated",
            params![
                object_type.kind,
                object_type.description,
                properties_json,
                implements_json,
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
            "SELECT kind, description, properties_json, implements_json FROM sekai_object_types WHERE kind = ?1",
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
                "SELECT kind, description, properties_json, implements_json FROM sekai_object_types ORDER BY kind",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt.query([]).map_err(|error| error.to_string())?;
        let mut types = Vec::new();
        let mut errors = HashMap::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let kind: String = row.get(0).map_err(|error| error.to_string())?;
            let description: String = row.get(1).map_err(|error| error.to_string())?;
            let properties_json: String = row.get(2).map_err(|error| error.to_string())?;
            let implements_json: String = row.get(3).map_err(|error| error.to_string())?;
            match (
                serde_json::from_str(&properties_json),
                serde_json::from_str(&implements_json),
            ) {
                (Ok(properties), Ok(implements)) => types.push(ObjectType {
                    kind,
                    description,
                    properties,
                    is_builtin: false,
                    implements,
                }),
                (Err(error), _) | (_, Err(error)) => {
                    errors.insert(kind, error.to_string());
                }
            }
        }
        Ok((types, errors))
    }

    pub fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let properties_json =
            serde_json::to_string(&interface.properties).map_err(|error| error.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_interfaces (name, description, properties_json, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(name) DO UPDATE SET
                description = excluded.description,
                properties_json = excluded.properties_json,
                updated = excluded.updated",
            params![interface.name, interface.description, properties_json, now],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn delete_interface(&self, name: &str) -> Result<bool, String> {
        let conn = self.conn();
        let deleted = conn
            .execute(
                "DELETE FROM sekai_interfaces WHERE name = ?1",
                params![name],
            )
            .map_err(|error| error.to_string())?;
        Ok(deleted > 0)
    }

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT name, description, properties_json FROM sekai_interfaces ORDER BY name",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map([], row_to_interface)
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }
}

fn row_to_object_type(row: &rusqlite::Row) -> Result<ObjectType, rusqlite::Error> {
    let properties_json: String = row.get(2)?;
    let implements_json: String = row.get(3)?;
    let properties = serde_json::from_str(&properties_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let implements = serde_json::from_str(&implements_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ObjectType {
        kind: row.get(0)?,
        description: row.get(1)?,
        properties,
        is_builtin: false,
        implements,
    })
}

fn row_to_interface(row: &rusqlite::Row) -> Result<InterfaceDef, rusqlite::Error> {
    let properties_json: String = row.get(2)?;
    let properties = serde_json::from_str(&properties_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(InterfaceDef {
        name: row.get(0)?,
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
            classification: default_property_classification(),
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
            classification: default_property_classification(),
        }
    }

    fn widget_registry() -> SchemaRegistry {
        let mut r = SchemaRegistry::new();
        r.register(ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            is_builtin: false,
            implements: vec![],
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
            implements: vec![],
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
            implements: vec![],
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
            implements: vec!["Trackable".into()],
            properties: vec![prop("name", PropertyType::String, true), {
                let mut property = prop_enum("color", &["red", "blue"], false);
                property.classification = "internal".into();
                property
            }],
        };

        db.upsert_interface(&InterfaceDef {
            name: "Trackable".into(),
            description: "Trackable object".into(),
            properties: vec![],
            is_builtin: false,
        })
        .unwrap();
        db.upsert_object_type(&object_type).unwrap();
        let listed = db.list_object_types().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, "widget");
        assert_eq!(listed[0].properties.len(), 2);
        assert_eq!(listed[0].properties[1].classification, "internal");
        assert_eq!(listed[0].implements, vec!["Trackable"]);

        let interfaces = db.list_interfaces().unwrap();
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "Trackable");

        let registry = SchemaRegistry::from_types_and_interfaces(listed, interfaces);
        assert!(registry.get("widget").is_some());
        assert!(registry.kind_implements_all("widget", &["Trackable".into()]));

        assert!(db.delete_object_type("widget").unwrap());
        assert!(db.list_object_types().unwrap().is_empty());
    }

    #[test]
    fn test_validate_object_type_rejects_unknown_interface() {
        let registry = SchemaRegistry::new();
        let object_type = ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            is_builtin: false,
            implements: vec!["Unknown".into()],
            properties: vec![],
        };
        let err = validate_object_type_definition(&object_type, registry.get("widget"), &registry)
            .unwrap_err();
        assert!(err.contains("unknown interface"));
    }

    #[test]
    fn test_validate_object_type_rejects_invalid_property_classification() {
        let registry = SchemaRegistry::new();
        let mut object_type = ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            is_builtin: false,
            implements: vec![],
            properties: vec![prop("secret", PropertyType::String, false)],
        };
        object_type.properties[0].classification = "private".into();

        let err = validate_object_type_definition(&object_type, registry.get("widget"), &registry)
            .unwrap_err();
        assert!(err.contains("invalid classification"));
    }

    #[test]
    fn test_validate_object_type_enforces_interface_properties() {
        let mut registry = SchemaRegistry::new();
        registry.register_interface(InterfaceDef {
            name: "Risky".into(),
            description: "Risk scored".into(),
            is_builtin: false,
            properties: vec![
                prop("risk_score", PropertyType::Float, true),
                prop("note", PropertyType::String, false),
            ],
        });
        let missing = ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            is_builtin: false,
            implements: vec!["Risky".into()],
            properties: vec![],
        };
        let err = validate_object_type_definition(&missing, None, &registry).unwrap_err();
        assert!(err.contains("risk_score"));

        let wrong_type = ObjectType {
            properties: vec![prop("risk_score", PropertyType::String, false)],
            ..missing
        };
        let err = validate_object_type_definition(&wrong_type, None, &registry).unwrap_err();
        assert!(err.contains("expects type float"));

        let optional_required_property = ObjectType {
            properties: vec![prop("risk_score", PropertyType::Float, false)],
            ..wrong_type
        };
        let err = validate_object_type_definition(&optional_required_property, None, &registry)
            .unwrap_err();
        assert!(err.contains("must be required"));

        let valid = ObjectType {
            properties: vec![prop("risk_score", PropertyType::Float, true)],
            ..optional_required_property
        };
        assert!(validate_object_type_definition(&valid, None, &registry).is_ok());
    }

    #[test]
    fn test_builtin_interfaces_are_code_owned() {
        let registry = SchemaRegistry::new();
        let builtin = registry.get_interface("RiskScored").unwrap().clone();
        let err = validate_interface_definition(
            &InterfaceDef {
                is_builtin: false,
                ..builtin
            },
            registry.get_interface("RiskScored"),
        )
        .unwrap_err();
        assert!(err.contains("cannot replace builtin interface"));
    }

    #[test]
    fn test_legacy_object_type_rows_default_empty_implements() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            conn.execute_batch(
                "DROP TABLE sekai_object_types;
                 CREATE TABLE sekai_object_types (
                    kind TEXT PRIMARY KEY,
                    description TEXT NOT NULL DEFAULT '',
                    properties_json TEXT NOT NULL DEFAULT '[]',
                    created INTEGER NOT NULL,
                    updated INTEGER NOT NULL
                 );
                 INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
                 VALUES ('legacy', 'Legacy type', '[]', 1, 1);",
            )
            .unwrap();
        }
        db.migrate_schema_types().unwrap();
        let listed = db.list_object_types().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].implements.is_empty());
    }
}

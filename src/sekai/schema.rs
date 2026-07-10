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
    Struct,
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
            "struct" => Some(Self::Struct),
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
            Self::Struct => "struct",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructFieldDef {
    pub name: String,
    pub prop_type: PropertyType,
    pub required: bool,
    pub description: String,
    pub enum_values: Vec<String>,
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
    #[serde(default)]
    pub struct_fields: Vec<StructFieldDef>,
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
            if registry
                .get_interface(&interface.name)
                .is_some_and(|existing| existing.is_builtin)
            {
                continue;
            }
            registry.register_interface(interface);
        }
        for object_type in types {
            if registry
                .get(&object_type.kind)
                .is_some_and(|existing| existing.is_builtin)
            {
                continue;
            }
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
                PropertyType::Struct => {
                    if let Err(error) =
                        validate_struct_property_value(&pd.name, &pd.struct_fields, v)
                    {
                        errs.push(error);
                    }
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

fn validate_struct_property_value(
    property_name: &str,
    fields: &[StructFieldDef],
    value: &str,
) -> Result<(), String> {
    let parsed: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| format!("property {property_name}: expected struct JSON object"))?;
    let Some(object) = parsed.as_object() else {
        return Err(format!(
            "property {property_name}: expected struct JSON object"
        ));
    };
    let mut errors = Vec::new();
    for field in fields {
        let field_value = object.get(&field.name);
        let empty = field_value
            .map(|value| value.is_null() || value.as_str().is_some_and(str::is_empty))
            .unwrap_or(true);
        if field.required && empty {
            errors.push(format!(
                "property {property_name}.{}: missing required field",
                field.name
            ));
            continue;
        }
        let Some(field_value) = field_value else {
            continue;
        };
        if empty {
            continue;
        }
        if let Err(error) = validate_struct_field_value(property_name, field, field_value) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn validate_struct_field_value(
    property_name: &str,
    field: &StructFieldDef,
    value: &serde_json::Value,
) -> Result<(), String> {
    let field_name = format!("{property_name}.{}", field.name);
    match field.prop_type {
        PropertyType::String => {
            if !value.is_string() {
                return Err(format!("property {field_name}: expected string"));
            }
        }
        PropertyType::Enum => {
            let Some(raw) = value.as_str() else {
                return Err(format!("property {field_name}: expected enum string"));
            };
            if !field.enum_values.iter().any(|allowed| allowed == raw) {
                return Err(format!(
                    "property {field_name}: value {:?} not in {:?}",
                    raw, field.enum_values
                ));
            }
        }
        PropertyType::Bool => {
            if !value.is_boolean() {
                return Err(format!("property {field_name}: expected bool"));
            }
        }
        PropertyType::Int => {
            if value.as_i64().is_none() {
                return Err(format!("property {field_name}: expected int"));
            }
        }
        PropertyType::Float => {
            if !value.as_f64().is_some_and(f64::is_finite) {
                return Err(format!("property {field_name}: expected float"));
            }
        }
        PropertyType::Timestamp => {
            let valid = value
                .as_i64()
                .map(|_| true)
                .or_else(|| value.as_str().map(is_valid_timestamp))
                .unwrap_or(false);
            if !valid {
                return Err(format!("property {field_name}: expected timestamp"));
            }
        }
        PropertyType::Link | PropertyType::Computed | PropertyType::Struct => {
            return Err(format!(
                "property {field_name}: unsupported struct field type"
            ));
        }
    }
    Ok(())
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
    let mut types = [
        (
            "agent",
            "Actor identity for a human, service, or automation that performs control-plane work.",
        ),
        (
            "asset",
            "Generic resource or artifact tracked by the graph when a more specific schema kind is not available.",
        ),
        (
            "budget",
            "Cost-control record used to account for spending limits, pressure, or allocation scope.",
        ),
        (
            "component",
            "Runnable or observable unit within a namespace, such as a service, model endpoint, or workflow step.",
        ),
        (
            "gateway_key",
            "Credential record for gateway access, routing policy, and usage attribution.",
        ),
        (
            "namespace",
            "Control-plane boundary for policies, budgets, routing hints, and related operational objects.",
        ),
        (
            "policy",
            "Policy record that configures routing, privacy, budget, or governance behavior for a scope.",
        ),
        (
            "project",
            "Work organization scope used for planning and attribution; namespaces remain the runtime boundary.",
        ),
        (
            "ticker",
            "Market symbol or tracked financial instrument used as object context.",
        ),
    ]
    .into_iter()
    .map(|(kind, description)| ObjectType {
        kind: kind.to_string(),
        description: description.to_string(),
        properties: Vec::new(),
        is_builtin: true,
        implements: Vec::new(),
    })
    .collect::<Vec<_>>();
    types.push(ObjectType {
        kind: crate::domain::KIND_LEARNING.to_string(),
        description:
            "Governed memory derived from an evaluated task outcome and linked to its graph target."
                .to_string(),
        properties: vec![
            classified_prop_def(
                "title",
                PropertyType::String,
                true,
                "Concise description of the learning.",
                "sensitive",
                &[],
            ),
            classified_prop_def(
                "prevention",
                PropertyType::String,
                true,
                "Concise guidance that prevents the observed failure or preserves the successful pattern.",
                "sensitive",
                &[],
            ),
            classified_prop_def(
                "reasoning",
                PropertyType::String,
                false,
                "Evaluation rationale supporting the learning.",
                "sensitive",
                &[],
            ),
            classified_prop_def(
                "source_request_id",
                PropertyType::String,
                false,
                "Request identifier from which the learning was derived.",
                "sensitive",
                &[],
            ),
            classified_prop_def(
                "score",
                PropertyType::Int,
                false,
                "Evaluation score from zero through one hundred.",
                "internal",
                &[],
            ),
            classified_prop_def(
                "passed",
                PropertyType::Bool,
                false,
                "Whether the evaluated task outcome passed its gate.",
                "internal",
                &[],
            ),
            classified_prop_def(
                "task_class",
                PropertyType::String,
                false,
                "Routing or workload class of the source task.",
                "internal",
                &[],
            ),
            classified_prop_def(
                "model",
                PropertyType::String,
                false,
                "Model that produced the evaluated outcome.",
                "internal",
                &[],
            ),
            classified_prop_def(
                "producer",
                PropertyType::String,
                false,
                "Principal or subsystem that produced the learning.",
                "internal",
                &[],
            ),
            classified_prop_def(
                "status",
                PropertyType::Enum,
                false,
                "Lifecycle state used by retrieval and promotion gates.",
                "internal",
                &["candidate", "active", "superseded", "rejected"],
            ),
        ],
        is_builtin: true,
        implements: vec!["Auditable".to_string()],
    });
    types
}

fn builtin_interfaces() -> Vec<InterfaceDef> {
    [
        (
            "Auditable",
            "Capability marker for objects that participate in audited control-plane activity.",
            Vec::new(),
        ),
        (
            "Budgeted",
            "Capability for objects associated with budget accounting or cost control.",
            vec![
                prop_def_desc(
                    "cost_center",
                    PropertyType::String,
                    false,
                    "Accounting label or organizational cost center for budget attribution.",
                ),
                prop_def_desc(
                    "budget_ref",
                    PropertyType::String,
                    false,
                    "Reference to the budget object or external budget system governing this object.",
                ),
            ],
        ),
        (
            "Evaluable",
            "Capability for objects that carry evaluation and baseline state.",
            vec![
                prop_def_desc(
                    "last_eval",
                    PropertyType::Timestamp,
                    false,
                    "Time when the most recent evaluation was recorded.",
                ),
                prop_def_desc(
                    "baseline",
                    PropertyType::String,
                    false,
                    "Named or serialized baseline used when comparing evaluation results.",
                ),
            ],
        ),
        (
            "Governed",
            "Capability for objects governed by owner, policy, and lifecycle status metadata.",
            vec![
                prop_def_desc(
                    "owner",
                    PropertyType::String,
                    false,
                    "Responsible principal, team, or service for governance decisions.",
                ),
                prop_def_desc(
                    "policy",
                    PropertyType::String,
                    false,
                    "Policy identifier or scope that governs this object.",
                ),
                prop_def_desc(
                    "status",
                    PropertyType::String,
                    false,
                    "Lifecycle or governance state, such as active, deprecated, or blocked.",
                ),
            ],
        ),
        (
            "RiskScored",
            "Capability for objects that expose risk context for policy and routing decisions.",
            vec![
                prop_def_desc(
                    "risk_score",
                    PropertyType::Float,
                    false,
                    "Numeric risk score used by policy or routing logic.",
                ),
                prop_def_desc(
                    "risk_reason",
                    PropertyType::String,
                    false,
                    "Human-readable explanation for the current risk score.",
                ),
                prop_def_desc(
                    "risk_updated_at",
                    PropertyType::Timestamp,
                    false,
                    "Time when risk metadata was last refreshed.",
                ),
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

fn prop_def_desc(
    name: &str,
    prop_type: PropertyType,
    required: bool,
    description: &str,
) -> PropertyDef {
    PropertyDef {
        name: name.to_string(),
        prop_type,
        required,
        description: description.to_string(),
        enum_values: Vec::new(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: default_property_classification(),
        struct_fields: Vec::new(),
    }
}

fn classified_prop_def(
    name: &str,
    prop_type: PropertyType,
    required: bool,
    description: &str,
    classification: &str,
    enum_values: &[&str],
) -> PropertyDef {
    PropertyDef {
        name: name.to_string(),
        prop_type,
        required,
        description: description.to_string(),
        enum_values: enum_values
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: classification.to_string(),
        struct_fields: Vec::new(),
    }
}

fn validate_property_definition(property: &PropertyDef) -> Result<(), String> {
    if property.name.trim().is_empty() {
        return Err("property name required".into());
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
    if property.prop_type == PropertyType::Struct {
        validate_struct_fields(&property.name, &property.struct_fields)?;
    } else if !property.struct_fields.is_empty() {
        return Err(format!(
            "property {} declares struct_fields but is not struct",
            property.name
        ));
    }
    Ok(())
}

fn validate_struct_fields(property_name: &str, fields: &[StructFieldDef]) -> Result<(), String> {
    if fields.is_empty() {
        return Err(format!("struct property {property_name} requires fields"));
    }
    let mut seen = HashSet::new();
    for field in fields {
        if field.name.trim().is_empty() {
            return Err(format!(
                "struct property {property_name} field name required"
            ));
        }
        if !seen.insert(field.name.clone()) {
            return Err(format!(
                "struct property {property_name} has duplicate field: {}",
                field.name
            ));
        }
        match field.prop_type {
            PropertyType::Enum if field.enum_values.is_empty() => {
                return Err(format!(
                    "struct property {property_name}.{} enum requires values",
                    field.name
                ));
            }
            PropertyType::Link | PropertyType::Computed | PropertyType::Struct => {
                return Err(format!(
                    "struct property {property_name}.{} has unsupported field type: {}",
                    field.name,
                    field.prop_type.as_str()
                ));
            }
            _ => {}
        }
    }
    Ok(())
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
        validate_property_definition(property)?;
        if !seen.insert(property.name.clone()) {
            return Err(format!("duplicate property: {}", property.name));
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
            if interface_property.prop_type == PropertyType::Struct {
                validate_struct_property_compatibility(
                    interface_name,
                    interface_property,
                    implemented_property,
                )?;
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
        validate_property_definition(property)?;
        if !seen.insert(property.name.clone()) {
            return Err(format!("duplicate property: {}", property.name));
        }
    }
    Ok(())
}

fn validate_struct_property_compatibility(
    interface_name: &str,
    interface_property: &PropertyDef,
    implemented_property: &PropertyDef,
) -> Result<(), String> {
    let implemented_fields = implemented_property
        .struct_fields
        .iter()
        .map(|field| (field.name.as_str(), field))
        .collect::<HashMap<_, _>>();
    for interface_field in &interface_property.struct_fields {
        let Some(implemented_field) = implemented_fields.get(interface_field.name.as_str()) else {
            if !interface_field.required {
                continue;
            }
            return Err(format!(
                "interface {interface_name} property {} requires struct field {}",
                interface_property.name, interface_field.name
            ));
        };
        if implemented_field.prop_type != interface_field.prop_type {
            return Err(format!(
                "interface {interface_name} property {}.{} expects type {}, got {}",
                interface_property.name,
                interface_field.name,
                interface_field.prop_type.as_str(),
                implemented_field.prop_type.as_str()
            ));
        }
        if interface_field.required && !implemented_field.required {
            return Err(format!(
                "interface {interface_name} property {}.{} must be required",
                interface_property.name, interface_field.name
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
            struct_fields: vec![],
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
            struct_fields: vec![],
        }
    }

    fn struct_field(name: &str, prop_type: PropertyType, required: bool) -> StructFieldDef {
        StructFieldDef {
            name: name.into(),
            prop_type,
            required,
            description: String::new(),
            enum_values: vec![],
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
    fn test_validate_struct_property_accepts_declared_fields() {
        let mut reg = SchemaRegistry::new();
        let mut generated = prop("generated", PropertyType::Struct, true);
        generated.struct_fields = vec![
            struct_field("value", PropertyType::String, true),
            struct_field("confidence", PropertyType::Float, true),
            struct_field("generated_at", PropertyType::Timestamp, false),
        ];
        reg.register(ObjectType {
            kind: "insight".into(),
            description: String::new(),
            is_builtin: false,
            implements: vec![],
            properties: vec![generated],
        });
        let obj = Object {
            id: "i1".into(),
            kind: "insight".into(),
            name: "insight".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([(
                "generated".into(),
                r#"{"value":"approve","confidence":0.92,"generated_at":"2026-07-06T12:00:00Z","extra":true}"#
                    .into(),
            )]),
            created: 0,
            updated: 0,
        };

        assert!(reg.validate(&obj).is_ok());
    }

    #[test]
    fn test_validate_struct_property_rejects_invalid_json_missing_fields_and_type_mismatch() {
        let mut reg = SchemaRegistry::new();
        let mut generated = prop("generated", PropertyType::Struct, true);
        generated.struct_fields = vec![
            struct_field("value", PropertyType::String, true),
            struct_field("confidence", PropertyType::Float, true),
        ];
        reg.register(ObjectType {
            kind: "insight".into(),
            description: String::new(),
            is_builtin: false,
            implements: vec![],
            properties: vec![generated],
        });
        let mut obj = Object {
            id: "i1".into(),
            kind: "insight".into(),
            name: "insight".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("generated".into(), "not-json".into())]),
            created: 0,
            updated: 0,
        };
        assert!(reg.validate(&obj).unwrap_err().contains("expected struct"));

        obj.properties
            .insert("generated".into(), r#"{"value":"approve"}"#.into());
        assert!(reg.validate(&obj).unwrap_err().contains("confidence"));

        obj.properties.insert(
            "generated".into(),
            r#"{"value":"approve","confidence":"high"}"#.into(),
        );
        assert!(reg.validate(&obj).unwrap_err().contains("expected float"));
    }

    #[test]
    fn test_object_type_persistence_round_trip() {
        let db = SekaiDb::new(":memory:").unwrap();
        let object_type = ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            is_builtin: false,
            implements: vec!["Trackable".into()],
            properties: vec![
                prop("name", PropertyType::String, true),
                {
                    let mut property = prop_enum("color", &["red", "blue"], false);
                    property.classification = "internal".into();
                    property
                },
                {
                    let mut property = prop("generated", PropertyType::Struct, false);
                    property.struct_fields = vec![
                        struct_field("value", PropertyType::String, true),
                        struct_field("confidence", PropertyType::Float, false),
                    ];
                    property
                },
            ],
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
        assert_eq!(listed[0].properties.len(), 3);
        assert_eq!(listed[0].properties[1].classification, "internal");
        assert_eq!(listed[0].properties[2].prop_type, PropertyType::Struct);
        assert_eq!(listed[0].properties[2].struct_fields.len(), 2);
        assert_eq!(listed[0].properties[2].struct_fields[0].name, "value");
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
                ..builtin.clone()
            },
            registry.get_interface("RiskScored"),
        )
        .unwrap_err();
        assert!(err.contains("cannot replace builtin interface"));

        let reloaded = SchemaRegistry::from_types_and_interfaces(
            Vec::new(),
            vec![InterfaceDef {
                description: "persisted override".into(),
                is_builtin: false,
                ..builtin
            }],
        );
        let restored = reloaded.get_interface("RiskScored").unwrap();
        assert!(restored.is_builtin);
        assert_ne!(restored.description, "persisted override");
    }

    #[test]
    fn test_builtin_object_type_descriptions_explain_semantics() {
        let registry = SchemaRegistry::new();
        for object_type in registry.all().into_iter().filter(|t| t.is_builtin) {
            assert!(
                !object_type.description.trim().is_empty(),
                "{} description is empty",
                object_type.kind
            );
            assert!(
                !object_type.description.starts_with("Built-in "),
                "{} description is still placeholder-like",
                object_type.kind
            );
        }

        let asset = registry.get("asset").unwrap().description.as_str();
        let namespace = registry.get("namespace").unwrap().description.as_str();
        let project = registry.get("project").unwrap().description.as_str();
        let component = registry.get("component").unwrap().description.as_str();
        assert!(asset.contains("Generic resource"));
        assert!(namespace.contains("Control-plane boundary"));
        assert!(project.contains("namespaces remain the runtime boundary"));
        assert!(component.contains("Runnable or observable unit"));
    }

    #[test]
    fn test_builtin_learning_schema_is_typed_and_conservatively_classified() {
        let registry = SchemaRegistry::from_types(vec![ObjectType {
            kind: crate::domain::KIND_LEARNING.into(),
            description: "persisted override".into(),
            properties: Vec::new(),
            is_builtin: false,
            implements: Vec::new(),
        }]);
        let learning = registry.get(crate::domain::KIND_LEARNING).unwrap();
        assert!(learning.is_builtin);
        assert_ne!(learning.description, "persisted override");
        assert_eq!(learning.implements, vec!["Auditable"]);

        let properties = learning
            .properties
            .iter()
            .map(|property| (property.name.as_str(), property))
            .collect::<HashMap<_, _>>();
        assert_eq!(properties.len(), 10);
        for name in ["title", "prevention", "reasoning", "source_request_id"] {
            assert_eq!(properties[name].classification, "sensitive");
        }
        for name in [
            "score",
            "passed",
            "task_class",
            "model",
            "producer",
            "status",
        ] {
            assert_eq!(properties[name].classification, "internal");
        }
        assert_eq!(properties["score"].prop_type, PropertyType::Int);
        assert_eq!(properties["passed"].prop_type, PropertyType::Bool);
        assert_eq!(properties["status"].prop_type, PropertyType::Enum);
        assert_eq!(
            properties["status"].enum_values,
            vec!["candidate", "active", "superseded", "rejected"]
        );

        let object = Object {
            id: "learning-1".into(),
            kind: crate::domain::KIND_LEARNING.into(),
            name: "Validate retries".into(),
            namespace: "payments".into(),
            external_id: "learning-1".into(),
            properties: HashMap::from([
                ("title".into(), "Validate retries".into()),
                ("prevention".into(), "Check the prior record".into()),
                ("reasoning".into(), "A side effect repeated".into()),
                ("source_request_id".into(), "request-1".into()),
                ("score".into(), "72".into()),
                ("passed".into(), "false".into()),
                ("task_class".into(), "reasoning".into()),
                ("model".into(), "judge-model".into()),
                ("producer".into(), "scoring-job".into()),
                ("status".into(), "candidate".into()),
            ]),
            created: 1,
            updated: 1,
        };
        assert!(registry.validate(&object).is_ok());
    }

    #[test]
    fn test_builtin_learning_schema_accepts_legacy_learning_properties() {
        let registry = SchemaRegistry::new();
        let legacy = Object {
            id: "learning-legacy".into(),
            kind: crate::domain::KIND_LEARNING.into(),
            name: "Legacy learning".into(),
            namespace: "payments".into(),
            external_id: "learning-legacy".into(),
            properties: HashMap::from([
                ("title".into(), "Legacy learning".into()),
                ("prevention".into(), "Check prior records".into()),
            ]),
            created: 1,
            updated: 1,
        };
        assert!(registry.validate(&legacy).is_ok());
    }

    #[test]
    fn test_builtin_interface_properties_have_descriptions() {
        let registry = SchemaRegistry::new();
        for interface in registry
            .all_interfaces()
            .into_iter()
            .filter(|i| i.is_builtin)
        {
            assert!(
                !interface.description.trim().is_empty(),
                "{} description is empty",
                interface.name
            );
            for property in &interface.properties {
                assert!(
                    !property.description.trim().is_empty(),
                    "{}.{} description is empty",
                    interface.name,
                    property.name
                );
            }
        }
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

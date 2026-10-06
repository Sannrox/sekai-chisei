//! Object type and property schema vocabulary.
//!
//! Chisei redacts context and fills System One parameters against it; the
//! Sekai schema registry re-exports it (ADR 0092 rule 3).

use serde::{Deserialize, Serialize};

use crate::domain::ObjectKind;

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

pub fn is_valid_property_classification(value: &str) -> bool {
    matches!(
        normalize_property_classification(value),
        "public" | "internal" | "sensitive"
    )
}

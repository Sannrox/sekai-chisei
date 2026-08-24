use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Object Kinds ---

pub type ObjectKind = String;

// Kinds the chisei routing logic matches on. Not a closed taxonomy — objects
// may use any kind; these just name the strings the code uses, in one
// place. `model`/`component` drive model selection in chisei::affinity (live
// as an internal routing affinity signal). `learning` is matched only in the learning/pipeline
// graph helpers, which are not yet wired to an RPC.
pub const KIND_MODEL: &str = "model";
pub const KIND_COMPONENT: &str = "component";
pub const KIND_LEARNING: &str = "learning";
pub const KIND_CAPABILITY: &str = "capability";
pub const KIND_EXTERNAL_EVIDENCE: &str = "external_evidence";

pub const DEFAULT_LIST_LIMIT: i32 = 100;
pub const MAX_LIST_LIMIT: i32 = 1000;

pub fn is_valid_property_key(key: &str) -> bool {
    !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Quote internal kind constants for a static SQL exclusion. Unknown characters
/// fail closed so a malformed kind cannot reopen a reserved-kind read surface.
pub fn excluded_kinds_sql(column: &str, excluded_kinds: &[&str]) -> Result<String, String> {
    if excluded_kinds.is_empty() {
        return Ok(String::new());
    }
    for kind in excluded_kinds {
        if kind.is_empty() || !kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!(
                "unsafe excluded kind {kind:?}: only ASCII alphanumeric and '_' allowed"
            ));
        }
    }
    let quoted = excluded_kinds
        .iter()
        .map(|kind| format!("'{kind}'"))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(" AND {column} NOT IN ({quoted})"))
}

pub fn storage_properties_json(properties: &HashMap<String, String>) -> Result<String, String> {
    for (key, value) in properties {
        if key.contains('\0') {
            return Err("object property key must not contain NUL".into());
        }
        if value.contains('\0') {
            return Err("object property value must not contain NUL".into());
        }
    }
    serde_json::to_string(properties).map_err(|error| error.to_string())
}

// --- Relations ---

pub type Relation = String;

pub const REL_CONTAINS: &str = "contains";
pub const REL_OWNS: &str = "owns";
pub const REL_TOUCHES: &str = "touches";
pub const REL_PRODUCES: &str = "produces";
pub const REL_DEPLOYS_TO: &str = "deploys_to";
pub const REL_ASSIGNED_TO: &str = "assigned_to";
pub const REL_DEPENDS_ON: &str = "depends_on";
pub const REL_TARGETS: &str = "targets";
pub const REL_EXECUTED: &str = "executed";
pub const REL_USED_FOR: &str = "used_for";
pub const REL_RELATION_SOURCE: &str = "relation_source";
pub const REL_RELATION_TARGET: &str = "relation_target";
pub const REL_EVIDENCE_FOR: &str = "evidence_for";
pub const REL_DERIVED_FROM: &str = "derived_from";

pub fn valid_relation(r: &str) -> bool {
    matches!(
        r,
        REL_CONTAINS
            | REL_OWNS
            | REL_TOUCHES
            | REL_PRODUCES
            | REL_DEPLOYS_TO
            | REL_ASSIGNED_TO
            | REL_DEPENDS_ON
            | REL_TARGETS
            | REL_EXECUTED
            | REL_USED_FOR
            | REL_RELATION_SOURCE
            | REL_RELATION_TARGET
            | REL_EVIDENCE_FOR
            | REL_DERIVED_FROM
    )
}

// --- Direction ---

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    #[default]
    Outgoing,
    Incoming,
}

// --- Object ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    pub id: String,
    pub kind: ObjectKind,
    pub name: String,
    pub namespace: String,
    pub external_id: String,
    pub properties: HashMap<String, String>,
    pub created: i64,
    pub updated: i64,
}

// --- Link ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub id: String,
    pub from_id: String,
    pub to_id: String,
    pub relation: Relation,
    pub created: i64,
}

// --- List Filter ---

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PropertyFilter {
    pub key: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ListFilter {
    pub kind: Option<String>,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub property_filters: Vec<PropertyFilter>,
    pub interface_filter: Vec<String>,
    pub limit: i32,
    pub offset: i32,
    pub order_by: String,
    pub descending: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_serde() {
        let obj = Object {
            id: "obj-1".into(),
            kind: "namespace".into(),
            name: "test-namespace".into(),
            namespace: "default".into(),
            external_id: "namespace:test-namespace".into(),
            properties: HashMap::from([("language".into(), "rust".into())]),
            created: 1000,
            updated: 1000,
        };
        let json = serde_json::to_string(&obj).unwrap();
        let parsed: Object = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "obj-1");
        assert_eq!(parsed.properties["language"], "rust");
    }

    #[test]
    fn excluded_kinds_sql_quotes_safe_kinds_and_rejects_unsafe_ones() {
        assert_eq!(excluded_kinds_sql("kind", &[]).unwrap(), "");
        assert_eq!(
            excluded_kinds_sql("o.kind", &["capability", "action_policy"]).unwrap(),
            " AND o.kind NOT IN ('capability','action_policy')"
        );
        assert!(
            excluded_kinds_sql("kind", &["bad-kind"])
                .unwrap_err()
                .contains("unsafe")
        );
    }

    #[test]
    fn storage_properties_json_rejects_nul() {
        let valid = HashMap::from([("owner".into(), "alice".into())]);
        assert!(storage_properties_json(&valid).unwrap().contains("alice"));
        let poisoned = HashMap::from([("owner".into(), "alice\0".into())]);
        assert!(
            storage_properties_json(&poisoned)
                .unwrap_err()
                .contains("NUL")
        );
    }

    #[test]
    fn test_link_serde() {
        let link = Link {
            id: "l-1".into(),
            from_id: "a".into(),
            to_id: "b".into(),
            relation: REL_CONTAINS.into(),
            created: 1000,
        };
        let json = serde_json::to_string(&link).unwrap();
        let parsed: Link = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.relation, REL_CONTAINS);
    }

    #[test]
    fn test_valid_relations() {
        assert!(valid_relation(REL_CONTAINS));
        assert!(valid_relation(REL_EXECUTED));
        assert!(valid_relation(REL_RELATION_SOURCE));
        assert!(valid_relation(REL_RELATION_TARGET));
        assert!(!valid_relation("invalid"));
    }
}

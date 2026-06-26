use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Object Kinds ---

pub type ObjectKind = String;

// Kinds the chisei routing logic matches on. Not a closed taxonomy — objects
// may use any kind; these just name the strings the code branches on, in one
// place. `model`/`component` drive model selection in chisei::affinity (live
// via the GetAffinity RPC). `learning` is matched only in the learning/pipeline
// graph helpers, which are not yet wired to an RPC.
pub const KIND_MODEL: &str = "model";
pub const KIND_COMPONENT: &str = "component";
pub const KIND_LEARNING: &str = "learning";

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

#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub kind: Option<String>,
    pub name: Option<String>,
    pub namespace: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_serde() {
        let obj = Object {
            id: "obj-1".into(),
            kind: "repo".into(),
            name: "test-repo".into(),
            namespace: "default".into(),
            external_id: "repo:test-repo".into(),
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
        assert!(!valid_relation("invalid"));
    }
}

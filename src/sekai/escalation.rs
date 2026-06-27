use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, REL_CONTAINS};

const DEFAULT_THRESHOLD: i32 = 3;

#[derive(Debug, Clone)]
pub struct EscalationResult {
    pub component: String,
    pub failures: i32,
    pub goal_spec: String,
}

pub fn check_escalation(
    db: &SekaiDb,
    namespace: &str,
    threshold: Option<i32>,
) -> Option<EscalationResult> {
    let thresh = threshold.unwrap_or(DEFAULT_THRESHOLD);
    let namespace_obj = db.find_by_external_id(&format!("namespace:{}", namespace)).ok()??;
    let components = db
        .get_linked_objects(&namespace_obj.id, REL_CONTAINS, &Direction::Outgoing)
        .ok()?;
    for comp in &components {
        if comp.kind != KIND_COMPONENT {
            continue;
        }
        let failures: i32 = comp
            .properties
            .get("consecutive_failures")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if failures >= thresh {
            return Some(EscalationResult {
                component: comp.name.clone(),
                failures,
                goal_spec: format!(
                    "Component '{}' in namespace '{}' has {} consecutive failures. Create a goal to investigate root cause.",
                    comp.name, namespace, failures
                ),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Link, Object};
    use std::collections::HashMap;

    #[test]
    fn test_escalation_triggers() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "namespace".into(),
            namespace: "".into(),
            external_id: "namespace:namespace".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "broken".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("consecutive_failures".into(), "5".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: REL_CONTAINS.into(),
            created: 0,
        })
        .unwrap();

        let result = check_escalation(&db, "namespace", None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().failures, 5);
    }

    #[test]
    fn test_no_escalation_below_threshold() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "namespace".into(),
            namespace: "".into(),
            external_id: "namespace:namespace".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "ok".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("consecutive_failures".into(), "1".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: REL_CONTAINS.into(),
            created: 0,
        })
        .unwrap();

        assert!(check_escalation(&db, "namespace", None).is_none());
    }
}

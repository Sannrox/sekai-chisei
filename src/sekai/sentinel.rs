use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, REL_CONTAINS};

const SUCCESS_RATE_THRESHOLD: i32 = 50;
const MIN_TASKS: i32 = 5;

#[derive(Debug, Clone)]
pub struct ProposedTask {
    pub namespace: String,
    pub spec: String,
    pub priority: i32,
}

pub fn scan(db: &SekaiDb) -> Vec<ProposedTask> {
    let namespaces = db
        .list_objects(&crate::domain::ListFilter {
            kind: Some("namespace".into()),
            ..Default::default()
        })
        .unwrap_or_default();
    let mut proposals = Vec::new();
    for namespace in &namespaces {
        let components = db
            .get_linked_objects(&namespace.id, REL_CONTAINS, &Direction::Outgoing)
            .unwrap_or_default();
        for comp in &components {
            if comp.kind != KIND_COMPONENT {
                continue;
            }
            let total: i32 = comp
                .properties
                .get("task_total")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if total < MIN_TASKS {
                continue;
            }
            let rate: i32 = comp
                .properties
                .get("success_rate")
                .and_then(|v| v.parse().ok())
                .unwrap_or(100);
            if rate < SUCCESS_RATE_THRESHOLD {
                proposals.push(ProposedTask {
                    namespace: namespace.name.clone(),
                    spec: format!("Component '{}' in namespace '{}' has success rate {}% (threshold {}%). Investigate and fix.", comp.name, namespace.name, rate, SUCCESS_RATE_THRESHOLD),
                    priority: 2,
                });
            }
        }
        if proposals.len() >= 5 {
            break;
        }
    }
    proposals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Link, Object};
    use std::collections::HashMap;

    #[test]
    fn test_sentinel_detects_degraded() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "my-namespace".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "bad-comp".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("task_total".into(), "10".into()),
                ("success_rate".into(), "30".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c2".into(),
            kind: KIND_COMPONENT.into(),
            name: "good-comp".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("task_total".into(), "10".into()),
                ("success_rate".into(), "90".into()),
            ]),
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
        db.create_link(&Link {
            id: "l2".into(),
            from_id: "r1".into(),
            to_id: "c2".into(),
            relation: REL_CONTAINS.into(),
            created: 0,
        })
        .unwrap();

        let proposals = scan(&db);
        assert_eq!(proposals.len(), 1);
        assert!(proposals[0].spec.contains("bad-comp"));
    }

    #[test]
    fn test_sentinel_ignores_low_volume() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "namespace".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "comp".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("task_total".into(), "2".into()),
                ("success_rate".into(), "0".into()),
            ]),
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

        let proposals = scan(&db);
        assert_eq!(proposals.len(), 0); // below min_tasks threshold
    }
}

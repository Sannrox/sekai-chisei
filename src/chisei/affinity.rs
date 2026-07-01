use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, KIND_MODEL, REL_CONTAINS, REL_TOUCHES};

pub struct AffinityResult {
    pub namespaces: Vec<String>,
    pub best_model: String,
    pub low_success: bool,
}

fn namespace_object(db: &SekaiDb, namespace: &str) -> Option<crate::domain::Object> {
    if namespace.is_empty() {
        return None;
    }

    db.find_by_external_id(&format!("namespace:{namespace}"))
        .ok()
        .flatten()
}

pub fn get_affinity(db: &SekaiDb, namespace: &str) -> AffinityResult {
    let best_model = model_for_namespace(db, namespace);
    let low_success = low_success_namespace(db, namespace);
    AffinityResult {
        namespaces: Vec::new(),
        best_model,
        low_success,
    }
}

fn model_for_namespace(db: &SekaiDb, namespace: &str) -> String {
    let Some(namespace_obj) = namespace_object(db, namespace) else {
        return String::new();
    };
    let comps = db
        .get_linked_objects(&namespace_obj.id, REL_CONTAINS, &Direction::Outgoing)
        .unwrap_or_default();
    let mut best = String::new();
    let mut best_score = 0.0f64;
    for comp in &comps {
        if comp.kind != KIND_COMPONENT {
            continue;
        }
        let models = db
            .get_linked_objects(&comp.id, REL_TOUCHES, &Direction::Incoming)
            .unwrap_or_default();
        for m in &models {
            if m.kind != KIND_MODEL {
                continue;
            }
            let s: f64 = m
                .properties
                .get(&format!("success:{}", comp.id))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            let f: f64 = m
                .properties
                .get(&format!("failure:{}", comp.id))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            let total = s + f;
            if total < 3.0 {
                continue;
            }
            let rate = s / total;
            if rate < 0.6 {
                continue;
            }
            if rate > best_score {
                best_score = rate;
                best = m.name.clone();
            }
        }
    }
    best
}

fn low_success_namespace(db: &SekaiDb, namespace: &str) -> bool {
    let Some(namespace_obj) = namespace_object(db, namespace) else {
        return false;
    };
    let comps = db
        .get_linked_objects(&namespace_obj.id, REL_CONTAINS, &Direction::Outgoing)
        .unwrap_or_default();
    comps.iter().any(|c| {
        if c.kind != KIND_COMPONENT {
            return false;
        }
        let total: i32 = c
            .properties
            .get("task_total")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let rate: i32 = c
            .properties
            .get("success_rate")
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        total >= 3 && rate < 50
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Link, Object};
    use std::collections::HashMap;

    #[test]
    fn test_low_success_namespace() {
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
            name: "c".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("task_total".into(), "5".into()),
                ("success_rate".into(), "20".into()),
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
        assert!(low_success_namespace(&db, "namespace"));
    }
}

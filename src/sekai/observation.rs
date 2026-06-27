use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, KIND_MODEL, Object, REL_CONTAINS};
use std::collections::HashMap;

pub struct TaskCompletion {
    pub request_id: String,
    pub namespace: String,
    pub model: String,
    pub status: String,
    pub packages: Vec<String>,
}

pub fn on_task_completed(db: &SekaiDb, event: &TaskCompletion) {
    let now = chrono::Utc::now().timestamp();
    let succeeded = event.status == "done";

    // Find or skip namespace
    let namespace_obj = match db
        .find_by_external_id(&format!("namespace:{}", event.namespace))
        .ok()
        .flatten()
    {
        Some(o) => o,
        None => return,
    };

    // Update component stats
    let components = db
        .get_linked_objects(&namespace_obj.id, REL_CONTAINS, &Direction::Outgoing)
        .unwrap_or_default();
    for mut comp in components {
        if comp.kind != KIND_COMPONENT {
            continue;
        }
        let total: i32 = comp
            .properties
            .get("task_total")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
            + 1;
        let succ: i32 = comp
            .properties
            .get("task_succeeded")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
            + if succeeded { 1 } else { 0 };
        let rate = if total > 0 { succ * 100 / total } else { 0 };
        let consec: i32 = if succeeded {
            0
        } else {
            comp.properties
                .get("consecutive_failures")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
                + 1
        };
        comp.properties
            .insert("task_total".into(), total.to_string());
        comp.properties
            .insert("task_succeeded".into(), succ.to_string());
        comp.properties
            .insert("success_rate".into(), rate.to_string());
        comp.properties
            .insert("consecutive_failures".into(), consec.to_string());
        comp.updated = now;
        db.update_object(&comp).ok();
    }

    // Ensure model object
    if !event.model.is_empty() {
        let model_ext = format!("model:{}", event.model);
        if db.find_by_external_id(&model_ext).ok().flatten().is_none() {
            let obj = Object {
                id: uuid::Uuid::new_v4().to_string(),
                kind: KIND_MODEL.into(),
                name: event.model.clone(),
                namespace: "".into(),
                external_id: model_ext,
                properties: HashMap::new(),
                created: now,
                updated: now,
            };
            db.create_object(&obj).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Link;

    fn setup() -> SekaiDb {
        let db = SekaiDb::new(":memory:").unwrap();
        let now = 0i64;
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "my-namespace".into(),
            namespace: "".into(),
            external_id: "namespace:my-namespace".into(),
            properties: HashMap::new(),
            created: now,
            updated: now,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "comp".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: now,
            updated: now,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: REL_CONTAINS.into(),
            created: now,
        })
        .unwrap();
        db
    }

    #[test]
    fn test_observation_updates_stats() {
        let db = setup();
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t1".into(),
                namespace: "my-namespace".into(),
                model: "claude".into(),
                status: "done".into(),
                packages: vec![],
            },
        );
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t2".into(),
                namespace: "my-namespace".into(),
                model: "claude".into(),
                status: "failed".into(),
                packages: vec![],
            },
        );

        let comp = db.get_object("c1").unwrap().unwrap();
        assert_eq!(comp.properties["task_total"], "2");
        assert_eq!(comp.properties["task_succeeded"], "1");
        assert_eq!(comp.properties["success_rate"], "50");
        assert_eq!(comp.properties["consecutive_failures"], "1");
    }

    #[test]
    fn test_observation_creates_model() {
        let db = setup();
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t1".into(),
                namespace: "my-namespace".into(),
                model: "claude-sonnet".into(),
                status: "done".into(),
                packages: vec![],
            },
        );
        assert!(
            db.find_by_external_id("model:claude-sonnet")
                .unwrap()
                .is_some()
        );
    }
}

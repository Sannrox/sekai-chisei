use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, REL_DEPENDS_ON};

#[derive(Debug, Clone)]
pub struct PropagationTask {
    pub namespace: String,
    pub spec: String,
    pub priority: i32,
}

/// When a shared-library namespace is updated, find downstream namespaces that depend on it.
pub fn on_namespace_task_done(
    db: &SekaiDb,
    namespace: &str,
    version: &str,
) -> Vec<PropagationTask> {
    let namespace_obj = match db
        .find_by_external_id(&format!("namespace:{}", namespace))
        .ok()
        .flatten()
    {
        Some(o) => o,
        None => return vec![],
    };
    // Find namespaces that depend on this namespace (incoming depends_on links).
    let dependents = db
        .get_linked_objects(&namespace_obj.id, REL_DEPENDS_ON, &Direction::Incoming)
        .unwrap_or_default();
    dependents.iter()
        .filter(|o| o.kind == "namespace")
        .map(|dep| PropagationTask {
            namespace: dep.name.clone(),
            spec: format!("Upstream dependency '{}' released version {}. Update dependency and verify compatibility.", namespace, version),
            priority: 1,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Link, Object};
    use std::collections::HashMap;

    #[test]
    fn test_propagation() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "lib".into(),
            kind: "namespace".into(),
            name: "shared-lib".into(),
            namespace: "".into(),
            external_id: "namespace:shared-lib".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "app".into(),
            kind: "namespace".into(),
            name: "my-app".into(),
            namespace: "".into(),
            external_id: "namespace:my-app".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "app".into(),
            to_id: "lib".into(),
            relation: REL_DEPENDS_ON.into(),
            created: 0,
        })
        .unwrap();

        let tasks = on_namespace_task_done(&db, "shared-lib", "v1.2.0");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].namespace, "my-app");
        assert!(tasks[0].spec.contains("v1.2.0"));
    }
}

use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, REL_DEPENDS_ON};

#[derive(Debug, Clone)]
pub struct PropagationTask {
    pub repo: String,
    pub spec: String,
    pub priority: i32,
}

/// When a shared-library repo is updated, find downstream repos that depend on it.
pub fn on_repo_task_done(db: &SekaiDb, repo: &str, version: &str) -> Vec<PropagationTask> {
    let repo_obj = match db
        .find_by_external_id(&format!("repo:{}", repo))
        .ok()
        .flatten()
    {
        Some(o) => o,
        None => return vec![],
    };
    // Find repos that depend_on this repo (incoming depends_on links)
    let dependents = db
        .get_linked_objects(&repo_obj.id, REL_DEPENDS_ON, &Direction::Incoming)
        .unwrap_or_default();
    dependents.iter()
        .filter(|o| o.kind == "repo")
        .map(|dep| PropagationTask {
            repo: dep.name.clone(),
            spec: format!("Upstream dependency '{}' released version {}. Update dependency and verify compatibility.", repo, version),
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
            kind: "repo".into(),
            name: "shared-lib".into(),
            namespace: "".into(),
            external_id: "repo:shared-lib".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "app".into(),
            kind: "repo".into(),
            name: "my-app".into(),
            namespace: "".into(),
            external_id: "repo:my-app".into(),
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

        let tasks = on_repo_task_done(&db, "shared-lib", "v1.2.0");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].repo, "my-app");
        assert!(tasks[0].spec.contains("v1.2.0"));
    }
}

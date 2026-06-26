use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_LEARNING, Link, Object, REL_TOUCHES};
use std::collections::HashMap;

/// Create a deduped KindLearning object linked to a repo. Returns true if created.
pub fn produce_learning(db: &SekaiDb, repo: &str, title: &str, prevention: &str) -> bool {
    if repo.is_empty() || title.is_empty() || prevention.is_empty() {
        return false;
    }
    let repo_obj = match db
        .find_by_external_id(&format!("repo:{}", repo))
        .ok()
        .flatten()
    {
        Some(o) => o,
        None => return false,
    };
    // Dedup: check if learning with same title already exists on this repo
    let existing = db
        .get_linked_objects(&repo_obj.id, REL_TOUCHES, &Direction::Incoming)
        .unwrap_or_default();
    for obj in &existing {
        if obj.kind == KIND_LEARNING
            && obj
                .properties
                .get("title")
                .map(|t| t == title)
                .unwrap_or(false)
        {
            return false;
        }
    }
    let now = chrono::Utc::now().timestamp();
    let id = format!("learning:{:x}", md5_hash(&format!("{}:{}", repo, title)));
    let obj = Object {
        id: id.clone(),
        kind: KIND_LEARNING.into(),
        name: title.to_string(),
        namespace: "".into(),
        external_id: id.clone(),
        properties: HashMap::from([
            ("title".into(), title.into()),
            ("prevention".into(), prevention.into()),
        ]),
        created: now,
        updated: now,
    };
    if db.create_object(&obj).is_err() {
        return false;
    }
    let link = Link {
        id: format!("{}->{}", id, repo_obj.id),
        from_id: id,
        to_id: repo_obj.id,
        relation: REL_TOUCHES.into(),
        created: now,
    };
    db.create_link(&link).ok();
    true
}

fn md5_hash(s: &str) -> u64 {
    // Simple hash for deterministic ID (not cryptographic)
    let mut h: u64 = 0;
    for b in s.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u64);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_produce_learning_dedup() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "r1".into(),
            kind: "repo".into(),
            name: "my-repo".into(),
            namespace: "".into(),
            external_id: "repo:my-repo".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();

        assert!(produce_learning(
            &db,
            "my-repo",
            "always validate input",
            "add input validation"
        ));
        assert!(!produce_learning(
            &db,
            "my-repo",
            "always validate input",
            "add input validation"
        )); // dedup
    }

    #[test]
    fn test_produce_learning_empty_inputs() {
        let db = SekaiDb::new(":memory:").unwrap();
        assert!(!produce_learning(&db, "", "title", "prev"));
        assert!(!produce_learning(&db, "repo", "", "prev"));
    }
}

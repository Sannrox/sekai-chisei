use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_LEARNING, Link, Object, REL_TOUCHES};
use std::collections::HashMap;

/// Create a deduped KindLearning object linked to a namespace. Returns true if created.
pub fn produce_learning(db: &SekaiDb, namespace: &str, title: &str, prevention: &str) -> bool {
    if namespace.is_empty() || title.is_empty() || prevention.is_empty() {
        return false;
    }
    let namespace_obj = match db
        .find_by_external_id(&format!("namespace:{}", namespace))
        .ok()
        .flatten()
    {
        Some(o) => o,
        None => return false,
    };
    // Dedup: check if learning with same title already exists on this namespace
    let existing = db
        .get_linked_objects(&namespace_obj.id, REL_TOUCHES, &Direction::Incoming)
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
    let id = format!(
        "learning:{:x}",
        md5_hash(&format!("{}:{}", namespace, title))
    );
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
        id: format!("{}->{}", id, namespace_obj.id),
        from_id: id,
        to_id: namespace_obj.id,
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
            kind: "namespace".into(),
            name: "my-namespace".into(),
            namespace: "".into(),
            external_id: "namespace:my-namespace".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();

        assert!(produce_learning(
            &db,
            "my-namespace",
            "always validate input",
            "add input validation"
        ));
        assert!(!produce_learning(
            &db,
            "my-namespace",
            "always validate input",
            "add input validation"
        )); // dedup
    }

    #[test]
    fn test_produce_learning_empty_inputs() {
        let db = SekaiDb::new(":memory:").unwrap();
        assert!(!produce_learning(&db, "", "title", "prev"));
        assert!(!produce_learning(&db, "namespace", "", "prev"));
    }
}

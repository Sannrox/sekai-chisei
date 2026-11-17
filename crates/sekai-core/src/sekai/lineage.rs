use crate::db::sekai::SekaiDb;
use crate::sekai::object_security::PrincipalPolicyContext;

pub use sekai_types::lineage::*;

pub fn get_lineage(
    db: &SekaiDb,
    object_id: &str,
    max_nodes: usize,
) -> Result<LineageResult, String> {
    walk_store(db, object_id, max_nodes, None)
}

pub fn get_lineage_with_policy_context(
    db: &SekaiDb,
    object_id: &str,
    max_nodes: usize,
    context: &PrincipalPolicyContext,
) -> Result<LineageResult, String> {
    walk_store(db, object_id, max_nodes, Some(context))
}

fn walk_store(
    db: &SekaiDb,
    object_id: &str,
    max_nodes: usize,
    context: Option<&PrincipalPolicyContext>,
) -> Result<LineageResult, String> {
    let object = |id: &str| match context {
        Some(context) => db.get_object_with_policy_context(id, context),
        None => db.get_object(id),
    };
    let start = object(object_id)?.ok_or("object not found")?;
    walk_lineage(
        start,
        max_nodes,
        |id, direction| match context {
            Some(context) => db.get_links_with_policy_context(id, "", direction, context),
            None => db.get_links(id, "", direction),
        },
        object,
        |_| Ok(true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Link, Object};
    use std::collections::HashMap;

    #[test]
    fn test_lineage_chain() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mk = |id: &str, kind: &str| Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        db.create_object(&mk("r1", "namespace")).unwrap();
        db.create_object(&mk("cm1", "commit")).unwrap();
        db.create_object(&mk("pr1", "pull_request")).unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "cm1".into(),
            relation: "produces".into(),
            created: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l2".into(),
            from_id: "cm1".into(),
            to_id: "pr1".into(),
            relation: "produces".into(),
            created: 0,
        })
        .unwrap();

        let res = get_lineage(&db, "r1", 0).unwrap();
        assert_eq!(res.nodes.len(), 3);
        assert_eq!(res.edges.len(), 2);
        assert_eq!(res.nodes[0].role, "namespace");
        assert!(!res.truncated);
    }

    #[test]
    fn test_lineage_truncation() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mk = |id: &str| Object {
            id: id.into(),
            kind: "commit".into(),
            name: id.into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        db.create_object(&mk("t0")).unwrap();
        for i in 1..10 {
            let id = format!("t{}", i);
            db.create_object(&mk(&id)).unwrap();
            db.create_link(&Link {
                id: format!("l{}", i),
                from_id: format!("t{}", i - 1),
                to_id: id,
                relation: "contains".into(),
                created: 0,
            })
            .unwrap();
        }
        let res = get_lineage(&db, "t0", 5).unwrap();
        assert!(res.truncated);
        assert!(res.nodes.len() <= 5);
    }
}

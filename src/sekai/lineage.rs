use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Object};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct LineageNode {
    pub object: Object,
    pub role: String,
    pub ephemeral: bool,
}

#[derive(Debug, Clone)]
pub struct LineageEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

#[derive(Debug, Clone, Default)]
pub struct LineageResult {
    pub nodes: Vec<LineageNode>,
    pub edges: Vec<LineageEdge>,
    pub truncated: bool,
}

const DEFAULT_MAX: usize = 200;

pub fn get_lineage(
    db: &SekaiDb,
    object_id: &str,
    max_nodes: usize,
) -> Result<LineageResult, String> {
    let max = if max_nodes == 0 {
        DEFAULT_MAX
    } else {
        max_nodes.min(500)
    };
    let mut result = LineageResult::default();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    let start = db.get_object(object_id)?.ok_or("object not found")?;
    visited.insert(start.id.clone());
    queue.push_back(start.clone());
    result.nodes.push(LineageNode {
        role: role_for(&start.kind),
        ephemeral: false,
        object: start,
    });

    while let Some(node) = queue.pop_front() {
        if result.nodes.len() >= max {
            result.truncated = true;
            break;
        }
        // Traverse both directions for lineage relations
        for dir in [Direction::Outgoing, Direction::Incoming] {
            let links = db.get_links(&node.id, "", &dir)?;
            for link in &links {
                if !is_lineage_relation(&link.relation) {
                    continue;
                }
                let target_id = match dir {
                    Direction::Outgoing => &link.to_id,
                    Direction::Incoming => &link.from_id,
                };
                if visited.contains(target_id) {
                    continue;
                }
                visited.insert(target_id.clone());

                if let Some(obj) = db.get_object(target_id)? {
                    result.edges.push(LineageEdge {
                        from: link.from_id.clone(),
                        to: link.to_id.clone(),
                        relation: link.relation.clone(),
                    });
                    result.nodes.push(LineageNode {
                        role: role_for(&obj.kind),
                        ephemeral: false,
                        object: obj.clone(),
                    });
                    queue.push_back(obj);
                }
                if result.nodes.len() >= max {
                    result.truncated = true;
                    break;
                }
            }
        }
    }
    Ok(result)
}

fn role_for(kind: &str) -> String {
    match kind {
        "repo" => "repo",
        "commit" => "commit",
        "pull_request" => "pr",
        _ => "other",
    }
    .into()
}

fn is_lineage_relation(rel: &str) -> bool {
    matches!(
        rel,
        "contains" | "produces" | "targets" | "executed" | "depends_on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Link;
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
        db.create_object(&mk("r1", "repo")).unwrap();
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
        assert_eq!(res.nodes[0].role, "repo");
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

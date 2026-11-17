//! Graph lineage walk results.
//!
//! Walk hosts stay in the plane so they can name `SekaiDb`.

use sekai_domain::domain::{Direction, Link, Object};
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

pub const DEFAULT_MAX_LINEAGE_NODES: usize = 200;

pub fn role_for(kind: &str) -> String {
    match kind {
        "namespace" => "namespace",
        "commit" => "commit",
        "pull_request" => "pr",
        _ => "other",
    }
    .into()
}

pub fn is_lineage_relation(rel: &str) -> bool {
    matches!(
        rel,
        "contains"
            | "produces"
            | "targets"
            | "executed"
            | "depends_on"
            | "evidence_for"
            | "derived_from"
    )
}

/// Breadth-first lineage walk from `start`, shared by every backend.
///
/// `admit` decides whether the caller may see a node. A node that is not
/// admitted is left out, is not walked past, and does not count against the
/// budget, so `truncated` is true only when an admitted node was left out.
/// `max_nodes` of 0 means `DEFAULT_MAX_LINEAGE_NODES`; it is capped at 500.
pub fn walk_lineage<E>(
    start: Object,
    max_nodes: usize,
    mut links: impl FnMut(&str, &Direction) -> Result<Vec<Link>, E>,
    mut object: impl FnMut(&str) -> Result<Option<Object>, E>,
    mut admit: impl FnMut(&Object) -> Result<bool, E>,
) -> Result<LineageResult, E> {
    let max = if max_nodes == 0 {
        DEFAULT_MAX_LINEAGE_NODES
    } else {
        max_nodes.min(500)
    };
    let mut result = LineageResult::default();
    let mut visited = HashSet::from([start.id.clone()]);
    let mut queue = VecDeque::from([start.clone()]);
    result.nodes.push(LineageNode {
        role: role_for(&start.kind),
        ephemeral: false,
        object: start,
    });
    while let Some(node) = queue.pop_front() {
        for direction in [Direction::Outgoing, Direction::Incoming] {
            for link in links(&node.id, &direction)? {
                if !is_lineage_relation(&link.relation) {
                    continue;
                }
                let target = match direction {
                    Direction::Outgoing => &link.to_id,
                    Direction::Incoming => &link.from_id,
                };
                if !visited.insert(target.clone()) {
                    continue;
                }
                let Some(found) = object(target)? else {
                    continue;
                };
                if !admit(&found)? {
                    continue;
                }
                if result.nodes.len() >= max {
                    result.truncated = true;
                    return Ok(result);
                }
                result.edges.push(LineageEdge {
                    from: link.from_id,
                    to: link.to_id,
                    relation: link.relation,
                });
                result.nodes.push(LineageNode {
                    role: role_for(&found.kind),
                    ephemeral: false,
                    object: found.clone(),
                });
                queue.push_back(found);
            }
        }
    }
    Ok(result)
}

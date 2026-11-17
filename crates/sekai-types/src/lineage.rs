//! Graph lineage walk results.
//!
//! Walk hosts stay in the plane so they can name `SekaiDb`.

use sekai_domain::domain::{Direction, Link, Object};
use std::collections::{HashMap, HashSet, VecDeque};

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

/// Identity of a visited node: ephemeral ids live beside object ids.
type NodeKey = (bool, String, String);

fn node_key(object: &Object, ephemeral: bool) -> NodeKey {
    let kind = if ephemeral {
        object.kind.clone()
    } else {
        String::new()
    };
    (ephemeral, kind, object.id.clone())
}

fn object_key(id: &str) -> NodeKey {
    (false, String::new(), id.to_string())
}

/// An edge between two admitted nodes, by node identity.
type EdgeKey = (NodeKey, NodeKey, String);

/// Walk state: what was decided per node, the answer, and the frontier.
struct Walk {
    max: usize,
    /// Every node decided so far, admitted or not.
    visited: HashSet<NodeKey>,
    admitted: HashSet<NodeKey>,
    nodes: Vec<(NodeKey, LineageNode)>,
    edges: Vec<EdgeKey>,
    edge_set: HashSet<EdgeKey>,
    queue: VecDeque<(Object, bool)>,
    truncated: bool,
}

impl Walk {
    /// Records `edge` once; both of its ends are admitted nodes.
    fn edge(&mut self, edge: EdgeKey) {
        if self.edge_set.insert(edge.clone()) {
            self.edges.push(edge);
        }
    }

    /// Decides one newly reached node. Returns false once the budget is
    /// spent on an admitted node, which ends the walk as truncated.
    fn reach<E>(
        &mut self,
        target: Object,
        ephemeral: bool,
        edge: EdgeKey,
        admit: &mut impl FnMut(&Object, bool) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let key = node_key(&target, ephemeral);
        if self.admitted.contains(&key) {
            self.edge(edge);
            return Ok(true);
        }
        if !self.visited.insert(key.clone()) || !admit(&target, ephemeral)? {
            return Ok(true);
        }
        if self.nodes.len() >= self.max {
            self.truncated = true;
            return Ok(false);
        }
        self.admitted.insert(key.clone());
        self.edge(edge);
        let node = LineageNode {
            role: if ephemeral {
                target.kind.clone()
            } else {
                role_for(&target.kind)
            },
            ephemeral,
            object: target.clone(),
        };
        self.nodes.push((key, node));
        self.queue.push_back((target, ephemeral));
        Ok(true)
    }

    /// The answer. Objects keep their ids; an ephemeral node whose id another
    /// node of the answer already holds takes the first free `<id>#<n>`, so
    /// every id in the answer, and every edge end, names one node.
    fn finish(self) -> LineageResult {
        let mut used = self
            .nodes
            .iter()
            .filter(|(_, node)| !node.ephemeral)
            .map(|(_, node)| node.object.id.clone())
            .collect::<HashSet<_>>();
        let mut ids = HashMap::new();
        let mut nodes = Vec::with_capacity(self.nodes.len());
        for (key, mut node) in self.nodes {
            if node.ephemeral {
                let base = node.object.id.clone();
                let mut id = base.clone();
                let mut n = 1;
                while used.contains(&id) {
                    id = format!("{base}#{n}");
                    n += 1;
                }
                used.insert(id.clone());
                node.object.id = id;
            }
            ids.insert(key, node.object.id.clone());
            nodes.push(node);
        }
        let edges = self
            .edges
            .into_iter()
            .filter_map(|(from, to, relation)| {
                Some(LineageEdge {
                    from: ids.get(&from)?.clone(),
                    to: ids.get(&to)?.clone(),
                    relation,
                })
            })
            .collect();
        LineageResult {
            nodes,
            edges,
            truncated: self.truncated,
        }
    }
}

/// Breadth-first lineage walk from `start`, shared by every backend.
///
/// `links` and `object` follow lineage links between objects. `upstream`
/// names the non-object nodes (`ephemeral`) a node came from, such as the
/// dataset behind a dataset-backed object; the walk records a `derived_from`
/// edge from the node to each of them. Ephemeral nodes are walked through
/// `upstream` only. An edge between two nodes already in the answer is kept.
///
/// `admit` decides whether the caller may see a node. A node that is not
/// admitted is left out, is not walked past, and does not count against the
/// budget, so `truncated` is true only when an admitted node was left out.
/// Nodes are loaded one at a time, so the walk stops reading at the budget.
/// `max_nodes` of 0 means `DEFAULT_MAX_LINEAGE_NODES`; it is capped at 500.
pub fn walk_lineage<E>(
    start: Object,
    max_nodes: usize,
    mut links: impl FnMut(&str, &Direction) -> Result<Vec<Link>, E>,
    mut object: impl FnMut(&str) -> Result<Option<Object>, E>,
    mut upstream: impl FnMut(&Object, bool) -> Result<Vec<Object>, E>,
    mut admit: impl FnMut(&Object, bool) -> Result<bool, E>,
) -> Result<LineageResult, E> {
    let start_key = node_key(&start, false);
    let mut walk = Walk {
        max: if max_nodes == 0 {
            DEFAULT_MAX_LINEAGE_NODES
        } else {
            max_nodes.min(500)
        },
        visited: HashSet::from([start_key.clone()]),
        admitted: HashSet::from([start_key.clone()]),
        nodes: vec![(
            start_key,
            LineageNode {
                role: role_for(&start.kind),
                ephemeral: false,
                object: start.clone(),
            },
        )],
        edges: Vec::new(),
        edge_set: HashSet::new(),
        queue: VecDeque::from([(start, false)]),
        truncated: false,
    };
    while let Some((node, node_ephemeral)) = walk.queue.pop_front() {
        if !node_ephemeral {
            for direction in [Direction::Outgoing, Direction::Incoming] {
                for link in links(&node.id, &direction)? {
                    if !is_lineage_relation(&link.relation) {
                        continue;
                    }
                    let target_id = match direction {
                        Direction::Outgoing => &link.to_id,
                        Direction::Incoming => &link.from_id,
                    };
                    let key = object_key(target_id);
                    let edge = (
                        object_key(&link.from_id),
                        object_key(&link.to_id),
                        link.relation,
                    );
                    if walk.admitted.contains(&key) {
                        walk.edge(edge);
                        continue;
                    }
                    if walk.visited.contains(&key) {
                        continue;
                    }
                    let Some(target) = object(&key.2)? else {
                        walk.visited.insert(key);
                        continue;
                    };
                    if !walk.reach(target, false, edge, &mut admit)? {
                        return Ok(walk.finish());
                    }
                }
            }
        }
        let from = node_key(&node, node_ephemeral);
        for target in upstream(&node, node_ephemeral)? {
            let edge = (from.clone(), node_key(&target, true), "derived_from".into());
            if !walk.reach(target, true, edge, &mut admit)? {
                return Ok(walk.finish());
            }
        }
    }
    Ok(walk.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn object(id: &str, kind: &str) -> Object {
        Object {
            id: id.into(),
            kind: kind.into(),
            name: String::new(),
            namespace: "ns".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 0,
            updated: 0,
        }
    }

    #[test]
    fn an_ephemeral_node_never_takes_an_object_id_of_the_answer() {
        // The object's own id spells the id of the dataset behind it.
        let result = walk_lineage::<Infallible>(
            object("dataset:ns/ds", "Order"),
            0,
            |_, _| Ok(Vec::new()),
            |_| Ok(None),
            |_, ephemeral| {
                Ok(if ephemeral {
                    Vec::new()
                } else {
                    vec![object("dataset:ns/ds", "dataset")]
                })
            },
            |_, _| Ok(true),
        )
        .unwrap();
        let ids = result
            .nodes
            .iter()
            .map(|node| node.object.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["dataset:ns/ds", "dataset:ns/ds#1"]);
        let edge = &result.edges[0];
        assert_eq!(
            (edge.from.as_str(), edge.to.as_str()),
            ("dataset:ns/ds", "dataset:ns/ds#1")
        );
    }
}

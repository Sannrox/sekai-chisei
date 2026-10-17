//! Graph lineage walk results.
//!
//! Walk hosts stay in the plane so they can name `SekaiDb`.

use sekai_domain::domain::Object;

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

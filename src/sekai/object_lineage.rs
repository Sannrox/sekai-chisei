//! Dataset-backed object lineage for inbound sync and write-back.
//!
//! Records the chain source → dataset → object → action → external mutate
//! without inventing a second object identity.

use serde::{Deserialize, Serialize};

pub const LINEAGE_KIND_SOURCE: &str = "source_record";
pub const LINEAGE_KIND_DATASET: &str = "dataset";
pub const LINEAGE_KIND_OBJECT: &str = "object";
pub const LINEAGE_KIND_ACTION: &str = "action_instance";
pub const LINEAGE_KIND_WRITEBACK: &str = "external_mutate";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageNode {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLineage {
    pub type_digest: String,
    pub source_id: String,
    pub dataset_id: String,
    pub object_id: String,
    pub action_instance_id: String,
    pub writeback_effect_id: String,
    pub nodes: Vec<LineageNode>,
}

pub fn dataset_id_for(type_digest: &str, type_name: &str) -> String {
    format!("dataset:{type_digest}:{type_name}")
}

pub fn bind_sync_lineage(
    type_digest: &str,
    source_id: &str,
    type_name: &str,
    object_id: &str,
) -> Result<ObjectLineage, String> {
    if type_digest.trim().is_empty() || object_id.trim().is_empty() || source_id.trim().is_empty() {
        return Err("type_digest, source_id, and object_id are required".into());
    }
    let dataset_id = dataset_id_for(type_digest, type_name);
    Ok(ObjectLineage {
        type_digest: type_digest.into(),
        source_id: source_id.into(),
        dataset_id: dataset_id.clone(),
        object_id: object_id.into(),
        action_instance_id: String::new(),
        writeback_effect_id: String::new(),
        nodes: vec![
            LineageNode {
                kind: LINEAGE_KIND_SOURCE.into(),
                id: source_id.into(),
            },
            LineageNode {
                kind: LINEAGE_KIND_DATASET.into(),
                id: dataset_id,
            },
            LineageNode {
                kind: LINEAGE_KIND_OBJECT.into(),
                id: object_id.into(),
            },
        ],
    })
}

pub fn bind_writeback(
    lineage: ObjectLineage,
    action_instance_id: &str,
    writeback_effect_id: &str,
) -> Result<ObjectLineage, String> {
    if action_instance_id.trim().is_empty() || writeback_effect_id.trim().is_empty() {
        return Err("action instance and write-back effect ids are required".into());
    }
    if lineage.object_id.trim().is_empty() {
        return Err("write-back cannot invent an object identity".into());
    }
    let mut bound = lineage;
    bound.action_instance_id = action_instance_id.into();
    bound.writeback_effect_id = writeback_effect_id.into();
    bound.nodes.push(LineageNode {
        kind: LINEAGE_KIND_ACTION.into(),
        id: action_instance_id.into(),
    });
    bound.nodes.push(LineageNode {
        kind: LINEAGE_KIND_WRITEBACK.into(),
        id: writeback_effect_id.into(),
    });
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_lineage_does_not_invent_object_id() {
        let lineage = bind_sync_lineage("sha256:types", "github:acme/ops#12", "Issue", "sync-1")
            .expect("lineage");
        assert_eq!(lineage.object_id, "sync-1");
        assert_eq!(lineage.dataset_id, "dataset:sha256:types:Issue");
        assert_eq!(lineage.nodes.len(), 3);
    }

    #[test]
    fn writeback_appends_action_and_effect() {
        let lineage = bind_sync_lineage("sha256:types", "github:acme/ops#12", "Issue", "sync-1")
            .expect("lineage");
        let bound = bind_writeback(lineage, "ai-1", "gax-1").expect("writeback");
        assert_eq!(bound.action_instance_id, "ai-1");
        assert_eq!(bound.writeback_effect_id, "gax-1");
        assert_eq!(
            bound.nodes.last().map(|node| node.kind.as_str()),
            Some(LINEAGE_KIND_WRITEBACK)
        );
    }

    #[test]
    fn empty_ids_fail_closed() {
        assert!(bind_sync_lineage("", "src", "Issue", "obj").is_err());
        let lineage = bind_sync_lineage("t", "s", "Issue", "o").unwrap();
        assert!(bind_writeback(lineage, "", "fx").is_err());
    }
}

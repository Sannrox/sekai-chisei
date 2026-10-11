//! Dataset-backed object lineage for inbound sync and write-back.
//!
//! Records the chain source → dataset → object → action → external mutate
//! without inventing a second object identity. Types live in `sekai-source-sdk`.

pub use sekai_source_sdk::{
    LINEAGE_KIND_ACTION, LINEAGE_KIND_DATASET, LINEAGE_KIND_OBJECT, LINEAGE_KIND_SOURCE,
    LINEAGE_KIND_WRITEBACK, LineageNode, ObjectLineage, bind_sync_lineage, bind_writeback,
    dataset_id_for,
};

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

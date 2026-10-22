//! Typed durable-store handle for Chisei decision state (the two-store split).
//!
//! Chisei constructors never take `RuntimeDb`; wrong-plane access has to name
//! a constructor. The handle does not `Deref`, `From`, or `AsRef` to
//! [`RuntimeDb`]. Domain code under `crate::chisei` reaches persistence only
//! through this handle and the per-family ports in `super::ports`.

use std::sync::Arc;

use crate::db::runtime_db::RuntimeDb;
use crate::db::store::SekaiStore;

/// Chisei-owned decision state. Sekai constructors must not take this.
///
/// Combined Split keeps Chisei families on `inner` and records
/// `RecordDecision` rows on `decisions` (the Sekai dest, ADR 0083 rule 1).
#[derive(Clone, Debug)]
pub struct ChiseiStore {
    pub(super) inner: Arc<RuntimeDb>,
    pub(super) decisions: Arc<RuntimeDb>,
}

/// Transitional combined-mode facade: both planes share one physical store.
pub fn split_shared_runtime(db: Arc<RuntimeDb>) -> (SekaiStore, ChiseiStore) {
    (
        SekaiStore::from_shared_runtime(db.clone()),
        ChiseiStore::from_shared_runtime(db),
    )
}

/// In-process fixture: one physical store behind both typed handles.
#[cfg(test)]
pub fn paired_memory() -> (SekaiStore, ChiseiStore) {
    split_shared_runtime(Arc::new(RuntimeDb::memory()))
}

impl ChiseiStore {
    pub fn from_shared_runtime(db: Arc<RuntimeDb>) -> Self {
        Self {
            inner: db.clone(),
            decisions: db,
        }
    }

    /// Combined Split: Chisei families on `chisei`, decision-ledger rows on `sekai`.
    pub fn from_split_runtimes(chisei: Arc<RuntimeDb>, sekai: Arc<RuntimeDb>) -> Self {
        Self {
            inner: chisei,
            decisions: sekai,
        }
    }

    pub fn memory() -> Self {
        Self::from_shared_runtime(Arc::new(RuntimeDb::memory()))
    }

    pub fn open_sqlite(path: &str) -> Self {
        Self::from_shared_runtime(Arc::new(RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new_for_plane(
                path,
                crate::db::schema_plane::SchemaPlane::Chisei,
            )
            .expect("open sqlite store"),
        ))))
    }

    /// True when this Chisei store and `sekai` share one physical store
    /// (the combined-mode compatibility facade).
    pub fn shares_physical_store_with(&self, sekai: &SekaiStore) -> bool {
        std::ptr::eq(self.inner.as_ref(), sekai.runtime())
    }

    pub(crate) fn runtime(&self) -> &RuntimeDb {
        &self.inner
    }

    pub(crate) fn runtime_arc(&self) -> Arc<RuntimeDb> {
        self.inner.clone()
    }

    pub(crate) fn decision_runtime(&self) -> &RuntimeDb {
        &self.decisions
    }

    /// Graph facts Chisei persists (namespace policy objects). Combined Split
    /// keeps those on the Sekai dest; Owned points at the same store as
    /// [`Self::runtime`].
    pub(crate) fn fact_runtime(&self) -> &RuntimeDb {
        &self.decisions
    }

    /// True when Kioku memories and graph facts live on one physical store,
    /// so promotion can authorize evidence inside the memory transaction.
    pub(crate) fn shares_graph_with_memory(&self) -> bool {
        Arc::ptr_eq(&self.inner, &self.decisions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_shared_runtime_is_one_physical_store() {
        let db = Arc::new(RuntimeDb::memory());
        let (sekai, chisei) = split_shared_runtime(db);
        assert_eq!(
            sekai.runtime().backend_name(),
            chisei.runtime().backend_name()
        );
        assert_eq!(sekai.runtime().backend_name(), "sqlite");
    }

    #[test]
    fn shares_physical_store_only_for_the_shared_facade() {
        let (sekai, chisei) = split_shared_runtime(Arc::new(RuntimeDb::memory()));
        assert!(chisei.shares_physical_store_with(&sekai));
        assert!(chisei.shares_graph_with_memory());
        assert!(!ChiseiStore::memory().shares_physical_store_with(&SekaiStore::memory()));
        let split = ChiseiStore::from_split_runtimes(
            Arc::new(RuntimeDb::memory()),
            Arc::new(RuntimeDb::memory()),
        );
        assert!(!split.shares_graph_with_memory());
    }

    #[test]
    fn chisei_memory_does_not_require_naming_runtime_db_at_callers() {
        let store = ChiseiStore::memory();
        store.runtime().ping().expect("memory store pings");
    }

    #[test]
    fn split_store_kioku_graph_auth_reads_sekai_dest() {
        use crate::chisei::kioku::MemoryRetrievalRequest;
        use crate::chisei_store::ChiseiKiokuStore;
        use crate::domain::Object;
        use crate::sekai::evidence::EvidenceClassification;
        use std::collections::HashMap;

        let sekai = SekaiStore::memory();
        let chisei = ChiseiStore::from_split_runtimes(
            ChiseiStore::memory().runtime_arc(),
            sekai.runtime_arc(),
        );
        sekai
            .create_object(&Object {
                id: "namespace-payments".into(),
                kind: "namespace".into(),
                name: "payments".into(),
                namespace: "payments".into(),
                external_id: "namespace:payments".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        assert_eq!(
            chisei
                .kioku_authorized_classification_ceiling("payments", "agent:planner")
                .unwrap(),
            EvidenceClassification::Public
        );
        assert!(
            chisei
                .runtime()
                .kioku_authorized_classification_ceiling("payments", "agent:planner")
                .unwrap_err()
                .contains("not an authorized graph scope")
        );
        let retrieved = chisei
            .retrieve_kioku_memories(&MemoryRetrievalRequest {
                namespace: "payments".into(),
                operation_class: "schema_change".into(),
                context_object_ids: vec![],
                classification_ceiling: EvidenceClassification::Public,
                min_confidence_bps: 0,
                max_results: 10,
                actor: "agent:planner".into(),
                now_ms: 150,
            })
            .unwrap();
        assert!(retrieved.is_empty());
    }

    #[test]
    fn split_runtimes_record_decisions_on_the_sekai_handle() {
        use crate::chisei_store::ChiseiDecisionStore;

        let sekai = SekaiStore::memory();
        let chisei = ChiseiStore::from_split_runtimes(
            ChiseiStore::memory().runtime_arc(),
            sekai.runtime_arc(),
        );
        chisei
            .record_decision(&crate::sekai::audit::Decision {
                id: "owned-by-sekai".into(),
                timestamp: 1,
                actor: "chisei.test".into(),
                action: "policy".into(),
                reason: "adr-0083".into(),
                evidence: Default::default(),
                target_id: "ns".into(),
                outcome: "allow".into(),
            })
            .unwrap();
        assert_eq!(
            sekai
                .runtime()
                .list_decisions(&crate::sekai::audit::DecisionFilter::default())
                .unwrap()
                .len(),
            1
        );
        assert!(
            chisei
                .runtime()
                .list_decisions(&crate::sekai::audit::DecisionFilter::default())
                .unwrap()
                .is_empty()
        );
        assert!(sekai.runtime().verify_ledger().unwrap().ok);
    }

    #[test]
    fn typed_handles_do_not_coerce_to_runtime_db() {
        let production = include_str!("handle.rs")
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .expect("production handle module");
        assert!(
            !production.contains("impl std::ops::Deref"),
            "typed handles must not Deref to RuntimeDb"
        );
        let chisei_impl = production
            .split("impl ChiseiStore {")
            .nth(1)
            .expect("ChiseiStore impl");
        assert!(
            !chisei_impl.contains("pub fn runtime("),
            "ChiseiStore must not expose RuntimeDb on its public surface"
        );
        assert!(
            !chisei_impl.contains("pub fn runtime_arc("),
            "ChiseiStore must not expose RuntimeDb on its public surface"
        );
        assert!(
            !production.contains("impl From<"),
            "typed handles must not From RuntimeDb"
        );
        assert!(
            !production.contains("impl AsRef<RuntimeDb>"),
            "typed handles must not AsRef RuntimeDb"
        );
        let sekai_service = include_str!("../grpc/sekai_service.rs");
        assert!(
            !sekai_service.contains("BudgetTracker"),
            "Sekai service must not hold a Chisei BudgetTracker"
        );
        let budget = include_str!("../chisei/budget.rs");
        assert!(
            budget.contains("pub fn new(db: ChiseiStore)"),
            "BudgetTracker::new must take ChiseiStore only"
        );
    }

    #[test]
    fn chisei_sources_do_not_name_runtime_db() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chisei");
        let mut hits = Vec::new();
        for entry in walkdir_chisei(&root) {
            let text = std::fs::read_to_string(&entry).expect("read chisei source");
            if text.contains("RuntimeDb") {
                hits.push(entry.display().to_string());
            }
        }
        assert!(
            hits.is_empty(),
            "Chisei modules must not name RuntimeDb: {hits:?}"
        );
    }

    fn walkdir_chisei(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read chisei dir") {
                let entry = entry.expect("dirent").path();
                if entry.is_dir() {
                    stack.push(entry);
                } else if entry.extension().is_some_and(|ext| ext == "rs") {
                    files.push(entry);
                }
            }
        }
        files
    }
}

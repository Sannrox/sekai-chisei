//! Typed durable-store handle for Chisei decision state (the two-store split).
//!
//! Chisei constructors never take `RuntimeDb`; wrong-plane access has to name
//! a constructor. The handle does not `Deref`, `From`, or `AsRef` to
//! [`RuntimeDb`]. Domain code under `crate::chisei` reaches persistence only
//! through this handle and the per-family ports in `super::ports`.

use std::sync::Arc;

use sekai_core::db::runtime_db::RuntimeDb;
use sekai_core::db::store::SekaiStore;

use super::ChiseiSqliteSchema;
use super::postgres_migrations;

/// Apply Chisei family DDL to an already-open runtime. `ChiseiStore` open
/// calls this; relocate dest init and conformance helpers that still hold a
/// bare `RuntimeDb` do too. PostgreSQL work runs off the Tokio runtime so
/// request-path wraps (quota gate, console) do not panic.
pub fn try_apply_chisei_schema(inner: &RuntimeDb) -> Result<(), String> {
    match inner {
        RuntimeDb::Sqlite(db) => db.migrate_chisei_families(),
        RuntimeDb::Postgres(db) => postgres_migrations::apply_chisei_postgres_schema(db),
    }
}

/// Apply Chisei family DDL, panicking when the dest cannot take schema.
pub fn apply_chisei_schema(inner: &RuntimeDb) {
    try_apply_chisei_schema(inner).expect("apply Chisei schema");
}

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
        apply_chisei_schema(&db);
        Self {
            inner: db.clone(),
            decisions: db,
        }
    }

    /// Combined Split: Chisei families on `chisei`, decision-ledger rows on `sekai`.
    pub fn from_split_runtimes(chisei: Arc<RuntimeDb>, sekai: Arc<RuntimeDb>) -> Self {
        apply_chisei_schema(&chisei);
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
            sekai_core::db::sekai::SekaiDb::new_for_plane(
                path,
                sekai_core::db::schema_plane::SchemaPlane::Chisei,
            )
            .expect("open sqlite store"),
        ))))
    }

    /// True when this Chisei store and `sekai` share one physical store
    /// (the combined-mode compatibility facade).
    pub fn shares_physical_store_with(&self, sekai: &SekaiStore) -> bool {
        std::ptr::eq(self.inner.as_ref(), sekai.runtime())
    }

    pub fn runtime(&self) -> &RuntimeDb {
        &self.inner
    }

    pub fn runtime_arc(&self) -> Arc<RuntimeDb> {
        self.inner.clone()
    }

    pub fn decision_runtime(&self) -> &RuntimeDb {
        &self.decisions
    }

    /// Graph facts Chisei persists (namespace policy objects). Combined Split
    /// keeps those on the Sekai dest; Owned points at the same store as
    /// [`Self::runtime`].
    pub fn fact_runtime(&self) -> &RuntimeDb {
        &self.decisions
    }

    /// True when Kioku memories and graph facts live on one physical store,
    /// so promotion can authorize evidence inside the memory transaction.
    pub fn shares_graph_with_memory(&self) -> bool {
        Arc::ptr_eq(&self.inner, &self.decisions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei_store::ChiseiRuntimeDb;

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
    fn chisei_memory_applies_chisei_family_schema() {
        let store = ChiseiStore::memory();
        let RuntimeDb::Sqlite(db) = store.runtime() else {
            panic!("memory store is sqlite");
        };
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='chisei_eval_suites'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn sekai_memory_omits_chisei_family_schema() {
        let store = SekaiStore::memory();
        let RuntimeDb::Sqlite(db) = store.runtime() else {
            panic!("memory store is sqlite");
        };
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='chisei_eval_suites'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn wrapping_the_same_runtime_applies_chisei_schema_once() {
        let db = Arc::new(RuntimeDb::memory());
        let first = ChiseiStore::from_shared_runtime(db.clone());
        let RuntimeDb::Sqlite(inner) = first.runtime() else {
            panic!("memory store is sqlite");
        };
        assert!(inner.chisei_schema_applied());
        let _second = ChiseiStore::from_shared_runtime(db);
    }

    #[test]
    fn wrapping_a_sekai_plane_sqlite_does_not_install_chisei_families() {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            sekai_core::db::sekai::SekaiDb::new_for_plane(
                ":memory:",
                sekai_core::db::schema_plane::SchemaPlane::Sekai,
            )
            .expect("sekai-plane sqlite"),
        )));
        let store = ChiseiStore::from_shared_runtime(db);
        let RuntimeDb::Sqlite(inner) = store.runtime() else {
            panic!("memory store is sqlite");
        };
        let count: i64 = inner
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='chisei_eval_suites'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn split_store_kioku_graph_auth_reads_sekai_dest() {
        use crate::chisei::kioku::MemoryRetrievalRequest;
        use crate::chisei_store::ChiseiKiokuStore;
        use sekai_core::domain::Object;
        use sekai_core::sekai::evidence::EvidenceClassification;
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
            .record_decision(&sekai_core::sekai::audit::Decision {
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
                .list_decisions(&sekai_core::sekai::audit::DecisionFilter::default())
                .unwrap()
                .len(),
            1
        );
        assert!(
            chisei
                .runtime()
                .list_decisions(&sekai_core::sekai::audit::DecisionFilter::default())
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
            chisei_impl.contains("pub fn runtime("),
            "composition reaches the Chisei RuntimeDb through ChiseiStore::runtime"
        );
        assert!(
            chisei_impl.contains("pub fn runtime_arc("),
            "composition reaches the Chisei RuntimeDb through ChiseiStore::runtime_arc"
        );
        assert!(
            !production.contains("impl From<"),
            "typed handles must not From RuntimeDb"
        );
        assert!(
            !production.contains("impl AsRef<RuntimeDb>"),
            "typed handles must not AsRef RuntimeDb"
        );
        let sekai_service = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../src/grpc/sekai_service.rs"
        ));
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

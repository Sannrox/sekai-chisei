//! Typed durable-store handles for the accepted two-store split.
//!
//! Combined mode always opens two physical stores. One [`RuntimeDb`] behind
//! both handles remains an explicit facade (`from_shared_runtime` /
//! `split_shared_runtime`) for a single-plane process's own store and for
//! in-process fixtures. Handles do
//! not `Deref`, `From`, or `AsRef` to [`RuntimeDb`]: wrong-plane access
//! has to name that constructor. Chisei constructors never take
//! `RuntimeDb` and Sekai constructors never take a Chisei handle.

use std::sync::Arc;

use super::runtime_db::RuntimeDb;

mod chisei_ports;

pub use chisei_ports::{
    ChiseiBudgetStore, ChiseiDataQualityStore, ChiseiDecisionStore, ChiseiEvalStore,
    ChiseiEvaluationStore, ChiseiEvolveStore, ChiseiExternalActionStore, ChiseiGatewayStore,
    ChiseiGovernedSubjectStore, ChiseiGunshiStore, ChiseiKiokuStore, ChiseiLearningChangeStore,
    ChiseiObservationStore, ChiseiPermitStore, ChiseiPortfolioStore, ChiseiReceiptStore,
    ChiseiRoutingProfileStore,
};

/// Sekai-owned facts and commits. Chisei code must not construct or hold this.
#[derive(Clone, Debug)]
pub struct SekaiStore {
    inner: Arc<RuntimeDb>,
}

/// Chisei-owned decision state. Sekai constructors must not take this.
///
/// Combined Split keeps Chisei families on `inner` and records
/// `RecordDecision` rows on `decisions` (the Sekai dest, ADR 0083 rule 1).
#[derive(Clone, Debug)]
pub struct ChiseiStore {
    inner: Arc<RuntimeDb>,
    decisions: Arc<RuntimeDb>,
}

/// Transitional combined-mode facade: both planes share one physical store.
pub fn split_shared_runtime(db: Arc<RuntimeDb>) -> (SekaiStore, ChiseiStore) {
    (
        SekaiStore { inner: db.clone() },
        ChiseiStore::from_shared_runtime(db),
    )
}

impl SekaiStore {
    pub fn from_shared_runtime(db: Arc<RuntimeDb>) -> Self {
        Self { inner: db }
    }

    pub fn memory() -> Self {
        Self::from_shared_runtime(Arc::new(RuntimeDb::memory()))
    }

    pub fn open_sqlite(path: &str) -> Self {
        Self::from_shared_runtime(Arc::new(RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new(path).expect("open sqlite store"),
        ))))
    }

    pub fn runtime(&self) -> &RuntimeDb {
        &self.inner
    }

    pub fn runtime_arc(&self) -> Arc<RuntimeDb> {
        self.inner.clone()
    }

    pub fn get_object(&self, id: &str) -> Result<Option<crate::domain::Object>, String> {
        self.inner.get_object(id)
    }

    pub fn update_object(&self, object: &crate::domain::Object) -> Result<(), String> {
        self.inner.update_object(object)
    }

    pub fn create_object(&self, object: &crate::domain::Object) -> Result<(), String> {
        self.inner.create_object(object)
    }

    pub fn create_link(&self, link: &crate::domain::Link) -> Result<(), String> {
        self.inner.create_link(link)
    }

    pub fn find_by_external_id(
        &self,
        external_id: &str,
    ) -> Result<Option<crate::domain::Object>, String> {
        self.inner.find_by_external_id(external_id)
    }

    pub fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        direction: &crate::domain::Direction,
    ) -> Result<Vec<crate::domain::Object>, String> {
        self.inner
            .get_linked_objects(object_id, relation, direction)
    }

    pub fn list_objects(
        &self,
        filter: &crate::domain::ListFilter,
    ) -> Result<Vec<crate::domain::Object>, String> {
        self.inner.list_all_objects(filter)
    }

    #[cfg(test)]
    pub fn create_principal_grant(
        &self,
        grant_id: &str,
        object_id: &str,
        grant: &crate::chisei::principal::PrincipalGrant,
        created: i64,
    ) -> Result<(), String> {
        self.inner
            .create_principal_grant(grant_id, object_id, grant, created)
    }

    #[cfg(test)]
    pub fn delete_grant(&self, grant_id: &str) -> Result<(), String> {
        self.inner.delete_grant(grant_id).map(|_| ())
    }

    pub fn list_usable_evidence_for_targets(
        &self,
        target_object_ids: &[String],
        allowed_evidence_classes: &[(String, String)],
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::sekai::evidence_store::UsableEvidenceContext>, String> {
        self.inner.list_usable_evidence_for_targets(
            target_object_ids,
            allowed_evidence_classes,
            now_ms,
            limit,
        )
    }

    pub fn list_usable_evidence_classes_for_targets(
        &self,
        target_object_ids: &[String],
        now_ms: i64,
    ) -> Result<Vec<(String, String)>, String> {
        self.inner
            .list_usable_evidence_classes_for_targets(target_object_ids, now_ms)
    }
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
            crate::db::sekai::SekaiDb::new(path).expect("open sqlite store"),
        ))))
    }

    /// True when this Chisei store and `sekai` share one physical store
    /// (the combined-mode compatibility facade).
    pub fn shares_physical_store_with(&self, sekai: &SekaiStore) -> bool {
        Arc::ptr_eq(&self.inner, &sekai.inner)
    }

    pub(crate) fn runtime(&self) -> &RuntimeDb {
        &self.inner
    }

    #[cfg(test)]
    pub(crate) fn runtime_arc(&self) -> Arc<RuntimeDb> {
        self.inner.clone()
    }

    pub(crate) fn decision_runtime(&self) -> &RuntimeDb {
        &self.decisions
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
        assert!(!ChiseiStore::memory().shares_physical_store_with(&SekaiStore::memory()));
    }

    #[test]
    fn chisei_memory_does_not_require_naming_runtime_db_at_callers() {
        let store = ChiseiStore::memory();
        store.runtime().ping().expect("memory store pings");
    }

    #[test]
    fn split_runtimes_record_decisions_on_the_sekai_handle() {
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
        let production = include_str!("store.rs")
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

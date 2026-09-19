//! Typed durable-store handles for the accepted two-store split.
//!
//! Combined mode opens two physical stores when destination variables are
//! set. One [`RuntimeDb`] behind both handles remains an explicit
//! compatibility facade (`from_shared_runtime` / `split_shared_runtime`)
//! for a single `DB_PATH` / `DATABASE_URL` until relocation. Handles do
//! not `Deref`, `From`, or `AsRef` to [`RuntimeDb`]: wrong-plane access
//! has to name that constructor. Chisei constructors never take
//! `RuntimeDb` and Sekai constructors never take a Chisei handle.

use std::sync::Arc;

use super::runtime_db::RuntimeDb;

/// Sekai-owned facts and commits. Chisei code must not construct or hold this.
#[derive(Clone, Debug)]
pub struct SekaiStore {
    inner: Arc<RuntimeDb>,
}

/// Chisei-owned decision state. Sekai constructors must not take this.
#[derive(Clone, Debug)]
pub struct ChiseiStore {
    inner: Arc<RuntimeDb>,
}

/// Transitional combined-mode facade: both planes share one physical store.
pub fn split_shared_runtime(db: Arc<RuntimeDb>) -> (SekaiStore, ChiseiStore) {
    (SekaiStore { inner: db.clone() }, ChiseiStore { inner: db })
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
}

impl ChiseiStore {
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
    fn chisei_memory_does_not_require_naming_runtime_db_at_callers() {
        let store = ChiseiStore::memory();
        store.runtime().ping().expect("memory store pings");
    }

    #[test]
    fn typed_handles_do_not_coerce_to_runtime_db() {
        let production = include_str!("store.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production handle module");
        assert!(
            !production.contains("impl std::ops::Deref"),
            "typed handles must not Deref to RuntimeDb"
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

//! Typed durable-store handles for the accepted two-store split.
//!
//! Combined mode opens two physical stores when destination variables are
//! set. One [`RuntimeDb`] behind both handles remains an explicit
//! compatibility facade (`split_shared_runtime`) for a single `DB_PATH` /
//! `DATABASE_URL` until relocation. Chisei constructors never take
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

    #[allow(dead_code)]
    pub(crate) fn runtime(&self) -> &RuntimeDb {
        &self.inner
    }

    pub(crate) fn runtime_arc(&self) -> Arc<RuntimeDb> {
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

    #[allow(dead_code)]
    pub(crate) fn runtime(&self) -> &RuntimeDb {
        &self.inner
    }

    #[allow(dead_code)]
    pub(crate) fn runtime_arc(&self) -> Arc<RuntimeDb> {
        self.inner.clone()
    }
}

impl From<Arc<RuntimeDb>> for SekaiStore {
    fn from(db: Arc<RuntimeDb>) -> Self {
        Self::from_shared_runtime(db)
    }
}

impl From<Arc<RuntimeDb>> for ChiseiStore {
    fn from(db: Arc<RuntimeDb>) -> Self {
        Self::from_shared_runtime(db)
    }
}

impl From<RuntimeDb> for SekaiStore {
    fn from(db: RuntimeDb) -> Self {
        Self::from_shared_runtime(Arc::new(db))
    }
}

impl From<RuntimeDb> for ChiseiStore {
    fn from(db: RuntimeDb) -> Self {
        Self::from_shared_runtime(Arc::new(db))
    }
}

impl From<&RuntimeDb> for ChiseiStore {
    fn from(db: &RuntimeDb) -> Self {
        Self::from(db.clone())
    }
}

impl std::ops::Deref for SekaiStore {
    type Target = RuntimeDb;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::Deref for ChiseiStore {
    type Target = RuntimeDb;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<RuntimeDb> for SekaiStore {
    fn as_ref(&self) -> &RuntimeDb {
        &self.inner
    }
}

impl AsRef<RuntimeDb> for ChiseiStore {
    fn as_ref(&self) -> &RuntimeDb {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_shared_runtime_is_one_physical_store() {
        let db = Arc::new(RuntimeDb::memory());
        let (sekai, chisei) = split_shared_runtime(db);
        assert_eq!(sekai.backend_name(), chisei.backend_name());
        assert_eq!(sekai.backend_name(), "sqlite");
    }

    #[test]
    fn chisei_memory_does_not_require_naming_runtime_db_at_callers() {
        let store = ChiseiStore::memory();
        store.ping().expect("memory store pings");
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

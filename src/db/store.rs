//! Typed durable-store handle for Sekai facts and commits.
//!
//! Combined mode always opens two physical stores. One [`RuntimeDb`] behind
//! both handles remains an explicit facade (`from_shared_runtime`) for a
//! single-plane process's own store and for in-process fixtures. The handle
//! does not `Deref`, `From`, or `AsRef` to [`RuntimeDb`]. The Chisei handle
//! lives in the Chisei store module and Sekai constructors never take it.

use std::sync::Arc;

use super::runtime_db::RuntimeDb;

/// Sekai-owned facts and commits. Chisei code must not construct or hold this.
#[derive(Clone, Debug)]
pub struct SekaiStore {
    inner: Arc<RuntimeDb>,
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
            crate::db::sekai::SekaiDb::new_for_plane(
                path,
                crate::db::schema_plane::SchemaPlane::Sekai,
            )
            .expect("open sqlite store"),
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
        grant: &sekai_types::principal::PrincipalGrant,
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

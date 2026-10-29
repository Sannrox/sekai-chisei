//! Dual-backend community-store dispatch for documents.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    /// Atomic first-writer-wins insert; see `SekaiDb::insert_governed_document`.
    pub fn insert_governed_document(
        &self,
        document: &crate::sekai::document::GovernedDocument,
    ) -> Result<Option<crate::sekai::document::GovernedDocument>, String> {
        match self {
            Self::Sqlite(db) => db.insert_governed_document(document),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.insert_governed_document(document))
            }
        }
    }

    pub fn get_governed_document(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Option<crate::sekai::document::GovernedDocument>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_document(namespace, document_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_governed_document(namespace, document_id)
            }),
        }
    }

    pub fn put_governed_rendition(
        &self,
        rendition: &crate::sekai::document::DocumentRendition,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_rendition(rendition),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_governed_rendition(rendition))
            }
        }
    }

    pub fn list_governed_renditions(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Vec<crate::sekai::document::DocumentRendition>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_renditions(namespace, document_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_renditions(namespace, document_id)
            }),
        }
    }

    pub fn update_governed_document(
        &self,
        namespace: &str,
        document_id: &str,
        update: impl FnOnce(
            crate::sekai::document::GovernedDocument,
        ) -> Result<crate::sekai::document::GovernedDocument, String>,
    ) -> Result<crate::sekai::document::GovernedDocument, String> {
        match self {
            Self::Sqlite(db) => db.update_governed_document(namespace, document_id, update),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.update_governed_document(namespace, document_id, update)
            }),
        }
    }
}

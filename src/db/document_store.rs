//! SQLite persistence for governed documents and renditions (#688).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::document::{DOCUMENT_UNAVAILABLE, DocumentRendition, GovernedDocument};

impl SekaiDb {
    pub fn put_governed_document(&self, document: &GovernedDocument) -> Result<(), String> {
        let json = serde_json::to_string(document)
            .map_err(|error| format!("encode governed document: {error}"))?;
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_governed_documents
                    (namespace, document_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, document_id) DO UPDATE SET
                    record_json = excluded.record_json
                 WHERE sekai_governed_documents.owner = excluded.owner",
                params![
                    document.namespace,
                    document.document_id,
                    document.owner,
                    json
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        Ok(())
    }

    /// Read-modify-write of one document in a single write transaction, so a check made
    /// by `update` (hold, deletion, expiry) still holds when its result is stored.
    /// Writing a deleted document also drops its renditions in the same transaction.
    pub fn update_governed_document(
        &self,
        namespace: &str,
        document_id: &str,
        update: impl FnOnce(GovernedDocument) -> Result<GovernedDocument, String>,
    ) -> Result<GovernedDocument, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current: String = tx
            .query_row(
                "SELECT record_json FROM sekai_governed_documents
                 WHERE namespace = ?1 AND document_id = ?2",
                params![namespace, document_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or(DOCUMENT_UNAVAILABLE)?;
        let current: GovernedDocument = serde_json::from_str(&current)
            .map_err(|error| format!("decode governed document: {error}"))?;
        let owner = current.owner.clone();
        let next = update(current)?;
        if next.namespace != namespace || next.document_id != document_id || next.owner != owner {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        let json = serde_json::to_string(&next)
            .map_err(|error| format!("encode governed document: {error}"))?;
        tx.execute(
            "UPDATE sekai_governed_documents SET record_json = ?3
             WHERE namespace = ?1 AND document_id = ?2",
            params![namespace, document_id, json],
        )
        .map_err(|error| error.to_string())?;
        if next.deleted_at_ms != 0 {
            tx.execute(
                "DELETE FROM sekai_governed_renditions
                 WHERE namespace = ?1 AND document_id = ?2",
                params![namespace, document_id],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(next)
    }

    pub fn get_governed_document(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Option<GovernedDocument>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_governed_documents
                 WHERE namespace = ?1 AND document_id = ?2",
                params![namespace, document_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode governed document: {error}"))
        })
        .transpose()
    }

    pub fn put_governed_rendition(&self, rendition: &DocumentRendition) -> Result<(), String> {
        let json = serde_json::to_string(rendition)
            .map_err(|error| format!("encode governed rendition: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let parent = tx
            .query_row(
                "SELECT record_json FROM sekai_governed_documents
                 WHERE namespace = ?1 AND document_id = ?2",
                params![rendition.namespace, rendition.document_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !parent.as_deref().is_some_and(live_parent) {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_renditions
                    (namespace, document_id, rendition_id, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, document_id, rendition_id) DO UPDATE SET
                    record_json = excluded.record_json
                 WHERE sekai_governed_renditions.namespace = excluded.namespace
                   AND sekai_governed_renditions.document_id = excluded.document_id",
                params![
                    rendition.namespace,
                    rendition.document_id,
                    rendition.rendition_id,
                    json
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn list_governed_renditions(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Vec<DocumentRendition>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_governed_renditions
                 WHERE namespace = ?1 AND document_id = ?2
                 ORDER BY rendition_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, document_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        let mut renditions = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            renditions.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode governed rendition: {error}"))?,
            );
        }
        Ok(renditions)
    }
}

/// A rendition may only attach to a stored document that has not been deleted.
pub(crate) fn live_parent(record_json: &str) -> bool {
    serde_json::from_str::<GovernedDocument>(record_json)
        .is_ok_and(|document| document.deleted_at_ms == 0)
}

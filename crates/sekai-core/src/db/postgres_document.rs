//! PostgreSQL persistence for governed documents and renditions (#1325).

use postgres::Row;

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::sekai::document::{
    DOCUMENT_UNAVAILABLE, DocumentRendition, GovernedDocument, RENDITIONS_OVERSIZED,
};

impl PostgresDb {
    /// Insert `document` unless its id is taken, under the document's advisory
    /// lock. Returns `None` when this call stored it, or the record that
    /// already holds the id, untouched (#1776).
    pub fn insert_governed_document(
        &self,
        document: &GovernedDocument,
    ) -> Result<Option<GovernedDocument>, String> {
        let json = serde_json::to_string(document)
            .map_err(|error| format!("encode governed document: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = advisory_lock_key(&[
            "governed_document",
            &document.namespace,
            &document.document_id,
        ]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let inserted = tx
            .execute(
                "INSERT INTO sekai_governed_documents
                    (namespace, document_id, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, document_id) DO NOTHING",
                &[
                    &document.namespace,
                    &document.document_id,
                    &document.owner,
                    &json,
                ],
            )
            .map_err(|error| error.to_string())?;
        let existing = if inserted == 0 {
            let row = tx
                .query_one(
                    "SELECT record_json FROM sekai_governed_documents
                     WHERE namespace = $1 AND document_id = $2",
                    &[&document.namespace, &document.document_id],
                )
                .map_err(|error| error.to_string())?;
            let current: String = row.get(0);
            Some(
                serde_json::from_str(&current)
                    .map_err(|error| format!("decode governed document: {error}"))?,
            )
        } else {
            None
        };
        tx.commit().map_err(|error| error.to_string())?;
        Ok(existing)
    }

    /// Read-modify-write of one document under its advisory lock, so a check made by
    /// `update` (hold, deletion, expiry) still holds when its result is stored.
    /// Writing a deleted document also drops its renditions in the same transaction.
    pub fn update_governed_document(
        &self,
        namespace: &str,
        document_id: &str,
        update: impl FnOnce(GovernedDocument) -> Result<GovernedDocument, String>,
    ) -> Result<GovernedDocument, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = advisory_lock_key(&["governed_document", namespace, document_id]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let current: String = tx
            .query_opt(
                "SELECT record_json FROM sekai_governed_documents
                 WHERE namespace = $1 AND document_id = $2",
                &[&namespace, &document_id],
            )
            .map_err(|error| error.to_string())?
            .ok_or(DOCUMENT_UNAVAILABLE)?
            .get(0);
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
            "UPDATE sekai_governed_documents SET record_json = $3
             WHERE namespace = $1 AND document_id = $2",
            &[&namespace, &document_id, &json],
        )
        .map_err(|error| error.to_string())?;
        if next.deleted_at_ms != 0 {
            tx.execute(
                "DELETE FROM sekai_governed_renditions
                 WHERE namespace = $1 AND document_id = $2",
                &[&namespace, &document_id],
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
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_governed_documents
                 WHERE namespace = $1 AND document_id = $2",
                &[&namespace, &document_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row: Row| {
                let json: String = row.get(0);
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode governed document: {error}"))
            })
            .transpose()
    }

    /// Insert `rendition` unless its id is taken on the document, under the
    /// document's advisory lock with the live-parent check and the `max`
    /// rendition bound. Returns `None` when this call stored it, or the
    /// rendition that already holds the id, untouched (#2266).
    pub fn insert_governed_rendition(
        &self,
        rendition: &DocumentRendition,
        max: usize,
    ) -> Result<Option<DocumentRendition>, String> {
        let json = serde_json::to_string(rendition)
            .map_err(|error| format!("encode governed rendition: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = advisory_lock_key(&[
            "governed_document",
            &rendition.namespace,
            &rendition.document_id,
        ]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let parent = tx
            .query_opt(
                "SELECT record_json FROM sekai_governed_documents
                 WHERE namespace = $1 AND document_id = $2",
                &[&rendition.namespace, &rendition.document_id],
            )
            .map_err(|error| error.to_string())?;
        if !parent
            .is_some_and(|row| crate::db::document_store::live_parent(&row.get::<_, String>(0)))
        {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        let existing = tx
            .query_opt(
                "SELECT record_json FROM sekai_governed_renditions
                 WHERE namespace = $1 AND document_id = $2 AND rendition_id = $3",
                &[
                    &rendition.namespace,
                    &rendition.document_id,
                    &rendition.rendition_id,
                ],
            )
            .map_err(|error| error.to_string())?;
        if let Some(existing) = existing {
            return serde_json::from_str(&existing.get::<_, String>(0))
                .map(Some)
                .map_err(|error| format!("decode governed rendition: {error}"));
        }
        let count: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM sekai_governed_renditions
                 WHERE namespace = $1 AND document_id = $2",
                &[&rendition.namespace, &rendition.document_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if count >= max as i64 {
            return Err(RENDITIONS_OVERSIZED.into());
        }
        tx.execute(
            "INSERT INTO sekai_governed_renditions
                (namespace, document_id, rendition_id, record_json)
             VALUES ($1, $2, $3, $4)",
            &[
                &rendition.namespace,
                &rendition.document_id,
                &rendition.rendition_id,
                &json,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(None)
    }

    pub fn list_governed_renditions(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Vec<DocumentRendition>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT record_json FROM sekai_governed_renditions
                 WHERE namespace = $1 AND document_id = $2
                 ORDER BY rendition_id",
                &[&namespace, &document_id],
            )
            .map_err(|error| error.to_string())?;
        let mut renditions = Vec::new();
        for row in rows {
            let json: String = row.get(0);
            renditions.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode governed rendition: {error}"))?,
            );
        }
        Ok(renditions)
    }
}

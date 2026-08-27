//! SQLite persistence for governed documents and renditions (#688).

use rusqlite::{OptionalExtension, params};

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
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let parent = tx
            .query_row(
                "SELECT record_json FROM sekai_governed_documents
                 WHERE namespace = ?1 AND document_id = ?2",
                params![rendition.namespace, rendition.document_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if parent.is_none() {
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

    pub fn delete_governed_renditions(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "DELETE FROM sekai_governed_renditions
                 WHERE namespace = ?1 AND document_id = ?2",
                params![namespace, document_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

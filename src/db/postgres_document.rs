//! PostgreSQL persistence for governed documents and renditions (#1325).

use postgres::Row;

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::sekai::document::{DOCUMENT_UNAVAILABLE, DocumentRendition, GovernedDocument};

impl PostgresDb {
    pub fn put_governed_document(&self, document: &GovernedDocument) -> Result<(), String> {
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
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_documents
                    (namespace, document_id, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, document_id) DO UPDATE SET
                    record_json = EXCLUDED.record_json
                 WHERE sekai_governed_documents.owner = EXCLUDED.owner",
                &[
                    &document.namespace,
                    &document.document_id,
                    &document.owner,
                    &json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
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

    pub fn put_governed_rendition(&self, rendition: &DocumentRendition) -> Result<(), String> {
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
        if parent.is_none() {
            return Err(DOCUMENT_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_renditions
                    (namespace, document_id, rendition_id, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, document_id, rendition_id) DO UPDATE SET
                    record_json = EXCLUDED.record_json
                 WHERE sekai_governed_renditions.namespace = EXCLUDED.namespace
                   AND sekai_governed_renditions.document_id = EXCLUDED.document_id",
                &[
                    &rendition.namespace,
                    &rendition.document_id,
                    &rendition.rendition_id,
                    &json,
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

    pub fn delete_governed_renditions(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_governed_renditions
                 WHERE namespace = $1 AND document_id = $2",
                &[&namespace, &document_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

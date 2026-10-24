//! SQLite persistence for registered source-type descriptors (#818).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::source_type_descriptor::{DESCRIPTOR_UNAVAILABLE, StoredSourceTypeDescriptor};

impl SekaiDb {
    pub fn get_source_type_descriptor(
        &self,
        namespace: &str,
        digest: &str,
    ) -> Result<Option<StoredSourceTypeDescriptor>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_source_type_descriptors
                 WHERE namespace = ?1 AND digest = ?2",
                params![namespace, digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode source-type descriptor: {error}"))
        })
        .transpose()
    }

    pub fn put_source_type_descriptor(
        &self,
        descriptor: &StoredSourceTypeDescriptor,
    ) -> Result<(), String> {
        let json = serde_json::to_string(descriptor)
            .map_err(|error| format!("encode source-type descriptor: {error}"))?;
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_source_type_descriptors
                    (namespace, digest, source, record_kind, schema_revision, status, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(namespace, digest) DO NOTHING",
                params![
                    descriptor.namespace,
                    descriptor.digest,
                    descriptor.source,
                    descriptor.record_kind,
                    descriptor.schema_revision,
                    descriptor.status,
                    descriptor.admitted_by,
                    json
                ],
            )
            .map_err(constraint_unavailable)?;
        if changed == 0 {
            return Err(DESCRIPTOR_UNAVAILABLE.into());
        }
        Ok(())
    }

    pub fn cas_source_type_descriptor(
        &self,
        expected: &StoredSourceTypeDescriptor,
        next: &StoredSourceTypeDescriptor,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.digest != next.digest
            || expected.admitted_by != next.admitted_by
            || expected.source != next.source
            || expected.record_kind != next.record_kind
            || expected.schema_revision != next.schema_revision
        {
            return Err(DESCRIPTOR_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode source-type descriptor: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT record_json FROM sekai_source_type_descriptors
                 WHERE namespace = ?1 AND digest = ?2",
                params![expected.namespace, expected.digest],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current: StoredSourceTypeDescriptor =
            serde_json::from_str(&current.ok_or(DESCRIPTOR_UNAVAILABLE)?)
                .map_err(|error| format!("decode source-type descriptor: {error}"))?;
        if current != *expected {
            return Err(DESCRIPTOR_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_source_type_descriptors
                 SET status = ?1, owner = ?2, record_json = ?3
                 WHERE namespace = ?4 AND digest = ?5 AND status = ?6 AND owner = ?7",
                params![
                    next.status,
                    next.admitted_by,
                    next_json,
                    next.namespace,
                    next.digest,
                    expected.status,
                    expected.admitted_by
                ],
            )
            .map_err(constraint_unavailable)?;
        if changed == 0 {
            return Err(DESCRIPTOR_UNAVAILABLE.into());
        }
        tx.commit().map_err(constraint_unavailable)?;
        Ok(())
    }
}

fn constraint_unavailable(error: rusqlite::Error) -> String {
    let text = error.to_string();
    if text.to_ascii_lowercase().contains("unique") {
        DESCRIPTOR_UNAVAILABLE.into()
    } else {
        text
    }
}

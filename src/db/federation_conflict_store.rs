//! SQLite persistence for governed federation conflicts (#699).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::federation_conflict::FederationConflict;

impl SekaiDb {
    pub fn put_federation_conflict(&self, record: &FederationConflict) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode federation conflict: {error}"))?;
        self.conn()
            .execute(
                "INSERT INTO sekai_federation_conflicts
                    (conflict_id, namespace, object_id, status, record_json, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(conflict_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    object_id = excluded.object_id,
                    status = excluded.status,
                    record_json = excluded.record_json,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    record.conflict_id,
                    record.namespace,
                    record.object_id,
                    record.status,
                    json,
                    record.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_federation_conflict(
        &self,
        conflict_id: &str,
    ) -> Result<Option<FederationConflict>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_federation_conflicts WHERE conflict_id = ?1",
                params![conflict_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode federation conflict: {error}"))
        })
        .transpose()
    }

    pub fn list_federation_conflicts(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<FederationConflict>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_federation_conflicts
                 WHERE (?1 IS NULL OR namespace = ?1)
                 ORDER BY updated_at_ms ASC, object_id ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut records = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            records.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode federation conflict: {error}"))?,
            );
        }
        Ok(records)
    }
}

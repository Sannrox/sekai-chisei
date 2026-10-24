//! SQLite persistence for registered Iceberg and Parquet snapshots (#682).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::open_table::{
    OpenTableSnapshot, OpenTableSource, QUERY_UNAVAILABLE, SNAPSHOT_UNAVAILABLE,
};

impl SekaiDb {
    pub fn put_open_table_source(&self, source: &OpenTableSource) -> Result<(), String> {
        let json = serde_json::to_string(source)
            .map_err(|error| format!("encode open table source: {error}"))?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let previous = load_source(&tx, &source.source_id)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_open_table_sources
                    (source_id, namespace, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(source_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    record_json = excluded.record_json
                 WHERE sekai_open_table_sources.owner = excluded.owner",
                params![source.source_id, source.namespace, source.owner, json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(QUERY_UNAVAILABLE.into());
        }
        if previous.is_some_and(|existing| {
            existing.schema_digest != source.schema_digest
                || existing.snapshot_digest != source.snapshot_digest
        }) {
            tx.execute(
                "DELETE FROM sekai_open_table_snapshots WHERE source_id = ?1",
                params![source.source_id],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_open_table_source(
        &self,
        source_id: &str,
    ) -> Result<Option<OpenTableSource>, String> {
        load_source(&self.conn(), source_id)
    }

    pub fn put_open_table_snapshot(&self, snapshot: &OpenTableSnapshot) -> Result<(), String> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| format!("encode open table snapshot: {error}"))?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let source = load_source(&tx, &snapshot.source_id)?.ok_or(QUERY_UNAVAILABLE)?;
        if source.snapshot_digest != snapshot.snapshot_digest {
            return Err(SNAPSHOT_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "INSERT INTO sekai_open_table_snapshots
                    (source_id, snapshot_digest, record_json)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(source_id) DO UPDATE SET
                    snapshot_digest = excluded.snapshot_digest,
                    record_json = excluded.record_json
                 WHERE EXISTS (
                    SELECT 1 FROM sekai_open_table_sources
                    WHERE source_id = excluded.source_id
                      AND json_extract(record_json, '$.snapshot_digest') = excluded.snapshot_digest
                 )",
                params![snapshot.source_id, snapshot.snapshot_digest, json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(SNAPSHOT_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_open_table_snapshot(
        &self,
        source_id: &str,
    ) -> Result<Option<OpenTableSnapshot>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_open_table_snapshots WHERE source_id = ?1",
                params![source_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode open table snapshot: {error}"))
        })
        .transpose()
    }
}

fn load_source(
    conn: &rusqlite::Connection,
    source_id: &str,
) -> Result<Option<OpenTableSource>, String> {
    let json: Option<String> = conn
        .query_row(
            "SELECT record_json FROM sekai_open_table_sources WHERE source_id = ?1",
            params![source_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    json.map(|value| {
        serde_json::from_str(&value).map_err(|error| format!("decode open table source: {error}"))
    })
    .transpose()
}

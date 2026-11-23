//! SQLite persistence for governed federation conflicts (#699).

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::de::DeserializeOwned;

use super::sekai::SekaiDb;
use crate::sekai::federation_conflict::{FederationConflict, STALE_CONFLICT};

impl SekaiDb {
    /// Stores `record` only while the stored conflict still equals `expected`
    /// (`None`: no row yet), so a writer that read an older version gets
    /// [`STALE_CONFLICT`] instead of rolling back a newer status.
    pub fn put_federation_conflict(
        &self,
        expected: Option<&FederationConflict>,
        record: &FederationConflict,
    ) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("begin federation conflict write: {error}"))?;
        write_federation_conflict(&tx, expected, record)?;
        tx.commit()
            .map_err(|error| format!("commit federation conflict write: {error}"))
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

/// Compare-and-set conflict write inside the caller's write transaction.
pub(super) fn write_federation_conflict(
    conn: &Connection,
    expected: Option<&FederationConflict>,
    record: &FederationConflict,
) -> Result<(), String> {
    require_stored(
        conn,
        "SELECT record_json FROM sekai_federation_conflicts WHERE conflict_id = ?1",
        &record.conflict_id,
        expected,
        STALE_CONFLICT,
    )?;
    let json = serde_json::to_string(record)
        .map_err(|error| format!("encode federation conflict: {error}"))?;
    conn.execute(
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

/// Fails with `stale` unless the row `select_sql` reads for `id` decodes to
/// `expected` (`None`: no row). Compares decoded records, not JSON text, so a
/// field-order or encoding change does not read as a concurrent write.
pub(super) fn require_stored<T: DeserializeOwned + PartialEq>(
    conn: &Connection,
    select_sql: &str,
    id: &str,
    expected: Option<&T>,
    stale: &str,
) -> Result<(), String> {
    let json: Option<String> = conn
        .query_row(select_sql, params![id], |row| row.get(0))
        .optional()
        .map_err(|error| error.to_string())?;
    let stored = json
        .map(|value| serde_json::from_str::<T>(&value).map_err(|error| error.to_string()))
        .transpose()?;
    if stored.as_ref() == expected {
        Ok(())
    } else {
        Err(stale.into())
    }
}

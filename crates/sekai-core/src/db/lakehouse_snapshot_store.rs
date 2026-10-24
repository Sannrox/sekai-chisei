//! SQLite persistence for lakehouse snapshots (#712).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::lakehouse_snapshot::{LAKEHOUSE_UNAVAILABLE, LakehouseSnapshot};

impl SekaiDb {
    pub fn get_lakehouse_snapshot(
        &self,
        namespace: &str,
        snapshot_id: &str,
    ) -> Result<Option<LakehouseSnapshot>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_lakehouse_snapshots
                 WHERE namespace = ?1 AND snapshot_id = ?2",
                params![namespace, snapshot_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode lakehouse snapshot: {error}"))
        })
        .transpose()
    }

    pub fn put_lakehouse_snapshot(&self, snapshot: &LakehouseSnapshot) -> Result<(), String> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| format!("encode lakehouse snapshot: {error}"))?;
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_lakehouse_snapshots
                    (namespace, snapshot_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, snapshot_id) DO NOTHING",
                params![
                    snapshot.namespace,
                    snapshot.snapshot_id,
                    snapshot.owner,
                    json
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        Ok(())
    }

    pub fn cas_lakehouse_snapshot(
        &self,
        expected: &LakehouseSnapshot,
        next: &LakehouseSnapshot,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.snapshot_id != next.snapshot_id
            || expected.owner != next.owner
        {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode lakehouse snapshot: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT record_json FROM sekai_lakehouse_snapshots
                 WHERE namespace = ?1 AND snapshot_id = ?2",
                params![expected.namespace, expected.snapshot_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current: LakehouseSnapshot =
            serde_json::from_str(&current.ok_or(LAKEHOUSE_UNAVAILABLE)?)
                .map_err(|error| format!("decode lakehouse snapshot: {error}"))?;
        if current != *expected {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_lakehouse_snapshots
                 SET record_json = ?1
                 WHERE namespace = ?2 AND snapshot_id = ?3 AND owner = ?4",
                params![next_json, next.namespace, next.snapshot_id, next.owner],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(LAKEHOUSE_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

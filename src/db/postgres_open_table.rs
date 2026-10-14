//! PostgreSQL persistence for registered Iceberg/Parquet open-table projections (#1479).

use postgres::GenericClient;

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::sekai::open_table::{
    OpenTableSnapshot, OpenTableSource, QUERY_UNAVAILABLE, SNAPSHOT_UNAVAILABLE,
};

impl PostgresDb {
    pub fn put_open_table_source(&self, source: &OpenTableSource) -> Result<(), String> {
        let json = serde_json::to_string(source)
            .map_err(|error| format!("encode open table source: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // Serialize registration against snapshot admission on the same source_id.
        // SQLite's connection lock hid this; PostgreSQL must lock before the
        // previous-digest read so a concurrent v2 admit cannot leave a v2
        // snapshot under a v1 source.
        lock_source(&mut tx, &source.source_id)?;
        let previous = load_source(&mut tx, &source.source_id)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_open_table_sources
                    (source_id, namespace, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (source_id) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    record_json = EXCLUDED.record_json
                 WHERE sekai_open_table_sources.owner = EXCLUDED.owner",
                &[&source.source_id, &source.namespace, &source.owner, &json],
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
                "DELETE FROM sekai_open_table_snapshots WHERE source_id = $1",
                &[&source.source_id],
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
        load_source(&mut *self.connection()?, source_id)
    }

    pub fn put_open_table_snapshot(&self, snapshot: &OpenTableSnapshot) -> Result<(), String> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| format!("encode open table snapshot: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_source(&mut tx, &snapshot.source_id)?;
        let source = load_source(&mut tx, &snapshot.source_id)?.ok_or(QUERY_UNAVAILABLE)?;
        if source.snapshot_digest != snapshot.snapshot_digest {
            return Err(SNAPSHOT_UNAVAILABLE.into());
        }
        // INSERT...SELECT WHERE EXISTS also guards the first-row path:
        // ON CONFLICT's WHERE only applies to the update branch.
        let changed = tx
            .execute(
                "INSERT INTO sekai_open_table_snapshots
                    (source_id, snapshot_digest, record_json)
                 SELECT $1, $2, $3
                 WHERE EXISTS (
                    SELECT 1 FROM sekai_open_table_sources
                    WHERE source_id = $1
                      AND (record_json::jsonb) ->> 'snapshot_digest' = $2
                 )
                 ON CONFLICT (source_id) DO UPDATE SET
                    snapshot_digest = EXCLUDED.snapshot_digest,
                    record_json = EXCLUDED.record_json
                 WHERE EXISTS (
                    SELECT 1 FROM sekai_open_table_sources
                    WHERE source_id = EXCLUDED.source_id
                      AND (record_json::jsonb) ->> 'snapshot_digest' = EXCLUDED.snapshot_digest
                 )",
                &[&snapshot.source_id, &snapshot.snapshot_digest, &json],
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
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_open_table_snapshots WHERE source_id = $1",
                &[&source_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_snapshot(&row.get::<_, String>(0)))
            .transpose()
    }
}

fn lock_source(client: &mut impl GenericClient, source_id: &str) -> Result<(), String> {
    let lock_key = advisory_lock_key(&["open_table", source_id]);
    client
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 1479))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn load_source(
    client: &mut impl GenericClient,
    source_id: &str,
) -> Result<Option<OpenTableSource>, String> {
    client
        .query_opt(
            "SELECT record_json FROM sekai_open_table_sources WHERE source_id = $1",
            &[&source_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| decode_source(&row.get::<_, String>(0)))
        .transpose()
}

fn decode_source(json: &str) -> Result<OpenTableSource, String> {
    serde_json::from_str(json).map_err(|error| format!("decode open table source: {error}"))
}

fn decode_snapshot(json: &str) -> Result<OpenTableSnapshot, String> {
    serde_json::from_str(json).map_err(|error| format!("decode open table snapshot: {error}"))
}

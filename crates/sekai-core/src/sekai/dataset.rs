use crate::db::sekai::SekaiDb;
use crate::sekai::dataset_version::{self, DatasetRollback, DatasetVersion};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::HashMap;

pub use sekai_types::dataset::*;

pub fn parse_columns(value: &str) -> Result<Vec<ColumnDef>, String> {
    if let Ok(columns) = serde_json::from_str::<Vec<(String, String, String)>>(value) {
        return Ok(columns
            .into_iter()
            .map(|(name, col_type, classification)| ColumnDef {
                name,
                col_type,
                classification,
            })
            .collect());
    }
    match serde_json::from_str::<Vec<(String, String)>>(value) {
        Ok(columns) => Ok(columns
            .into_iter()
            .map(|(name, col_type)| ColumnDef {
                name,
                col_type,
                classification: crate::sekai::schema::default_property_classification(),
            })
            .collect()),
        Err(error) => Err(format!("corrupt dataset columns: {error}")),
    }
}

pub(crate) fn encode_dataset_columns(columns: &[ColumnDef]) -> Result<String, String> {
    serde_json::to_string(
        &columns
            .iter()
            .map(|column| {
                (
                    &column.name,
                    &column.col_type,
                    crate::sekai::schema::normalize_property_classification(&column.classification),
                )
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|error| error.to_string())
}

fn validate_dataset_columns(columns: &[ColumnDef]) -> Result<(), String> {
    for column in columns {
        if !crate::sekai::schema::is_valid_property_classification(&column.classification) {
            return Err(format!(
                "column {} has invalid classification: {}",
                column.name, column.classification
            ));
        }
    }
    Ok(())
}

/// Create a dataset using an already-open connection or transaction.
pub fn create_dataset_tx(conn: &Connection, dataset: &Dataset) -> Result<(), String> {
    validate_dataset_columns(&dataset.columns)?;
    let cols = encode_dataset_columns(&dataset.columns)?;
    conn.execute(
        "INSERT INTO sekai_datasets (id,name,columns,object_id,created,partition_keys)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            dataset.id,
            dataset.name,
            cols,
            dataset.object_id,
            dataset.created,
            encode_partition_keys(&dataset.partition_keys)?
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

/// Append missing column definitions using an already-open transaction.
pub fn add_dataset_columns_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    columns: &[ColumnDef],
) -> Result<(), String> {
    validate_dataset_columns(columns)?;
    let json: String = tx
        .query_row(
            "SELECT columns FROM sekai_datasets WHERE id=?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("dataset {dataset_id:?} not found"))?;
    let mut current = parse_columns(&json)?;
    let before = current.len();
    for column in columns {
        if !current.iter().any(|defined| defined.name == column.name) {
            current.push(column.clone());
        }
    }
    if current.len() == before {
        return Ok(());
    }
    let encoded = encode_dataset_columns(&current)?;
    tx.execute(
        "UPDATE sekai_datasets SET columns=?2 WHERE id=?1",
        params![dataset_id, encoded],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

/// Append rows and snapshot a dataset version using an already-open transaction.
/// Returns the inclusive `(first_id, last_id)` range of inserted rows, or `(0, 0)`
/// when `rows` is empty.
pub fn append_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    rows: &[HashMap<String, String>],
) -> Result<(i64, i64), String> {
    if rows.is_empty() {
        return Ok((0, 0));
    }
    // Row ids come from one table-wide sequence, so the range starts after the
    // table's highest id. SQLite has one writer, so every id above it is ours.
    let before: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(id), 0) FROM sekai_dataset_rows",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let keys_json: String = tx
        .query_row(
            "SELECT partition_keys FROM sekai_datasets WHERE id = ?1",
            params![dataset_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| "[]".into());
    let keys = parse_partition_keys(&keys_json)?;
    if keys.is_empty() {
        let payloads: Vec<String> = rows
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<_, _>>()
            .map_err(|error| error.to_string())?;
        let json = serde_json::to_string(&payloads).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_dataset_rows (dataset_id, data)
             SELECT ?1, value FROM json_each(?2)",
            params![dataset_id, json],
        )
        .map_err(|error| error.to_string())?;
    } else {
        for row in rows {
            let data = serde_json::to_string(row).map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data, partition_key)
                 VALUES (?1, ?2, ?3)",
                params![
                    dataset_id,
                    data,
                    crate::sekai::governed_transform::partition_value(&keys, row)
                ],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    snapshot_dataset_version_tx(tx, dataset_id, "", "", "", "", dataset_version::now_ms())?;
    let after: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(id), 0) FROM sekai_dataset_rows WHERE dataset_id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    Ok((before + 1, after))
}

pub fn reindex_dataset_partition_keys(
    tx: &Transaction<'_>,
    dataset_id: &str,
    keys: &[String],
) -> Result<(), String> {
    let rows: Vec<(i64, String)> = {
        let mut stmt = tx
            .prepare("SELECT id, data FROM sekai_dataset_rows WHERE dataset_id = ?1")
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(params![dataset_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    for (id, data) in rows {
        let partition_key = partition_key_for_row_json(keys, &data)?;
        tx.execute(
            "UPDATE sekai_dataset_rows SET partition_key = ?1 WHERE id = ?2",
            params![partition_key, id],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Newest live row of one source key; `LIKE 'srcds:%'` matches the partial
/// index `idx_dataset_rows_source_key`.
pub(crate) const LATEST_SOURCE_ROW_SQL: &str = "SELECT data FROM sekai_dataset_rows
     WHERE dataset_id LIKE 'srcds:%' AND dataset_id = ?1
       AND json_extract(data, '$.source_id') = ?2
     ORDER BY id DESC LIMIT 1";
/// Newest row of one source key in one retained version. A version has one
/// layout, so at most one branch answers: a `copy` version seeks
/// `idx_dataset_version_rows_source_key`, a `span` version seeks
/// `idx_dataset_row_spans_source_key` and keeps the spans live at its seq
/// (the unary `+` keeps the planner off the seq-range index).
pub(crate) const LATEST_SOURCE_VERSION_ROW_SQL: &str = "SELECT data FROM (
       SELECT data FROM sekai_dataset_version_rows
       WHERE dataset_id LIKE 'srcds:%' AND dataset_id = ?1 AND version_id = ?2
         AND json_extract(data, '$.source_id') = ?3
       ORDER BY row_id DESC LIMIT 1)
     UNION ALL
     SELECT data FROM (
       SELECT s.data FROM sekai_dataset_versions v
       JOIN sekai_dataset_row_spans s
         ON s.dataset_id = v.dataset_id
        AND +s.from_seq <= v.seq AND (s.to_seq IS NULL OR s.to_seq > v.seq)
       WHERE v.dataset_id = ?1 AND v.version_id = ?2
         AND v.layout = 'span' AND v.purged = 0
         AND s.dataset_id LIKE 'srcds:%' AND s.dataset_id = ?1
         AND json_extract(s.data, '$.source_id') = ?3
       ORDER BY s.row_id DESC LIMIT 1)
     LIMIT 1";

/// Dataset versions record changes (ADR 0172, #3475). A `copy` version, as
/// releases before #3509 wrote them, keeps its full row copy in
/// `sekai_dataset_version_rows`; a `span` version's content is every span
/// live at its seq. Both layouts are read; only `span` is written. Readers of
/// a version's rows go through `sekai_dataset_version_content`.
fn migrate_dataset_row_spans(conn: &rusqlite::Connection) -> Result<(), String> {
    crate::db::add_sqlite_column(
        conn,
        "ALTER TABLE sekai_dataset_versions ADD COLUMN kind TEXT NOT NULL DEFAULT 'snapshot'",
    )?;
    crate::db::add_sqlite_column(
        conn,
        "ALTER TABLE sekai_dataset_versions ADD COLUMN layout TEXT NOT NULL DEFAULT 'copy'",
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sekai_dataset_row_spans (
             dataset_id TEXT NOT NULL,
             row_id INTEGER NOT NULL,
             from_seq INTEGER NOT NULL,
             to_seq INTEGER,
             data TEXT NOT NULL,
             partition_key TEXT NOT NULL DEFAULT '',
             PRIMARY KEY (dataset_id, row_id, from_seq)
         );
         CREATE INDEX IF NOT EXISTS idx_dataset_row_spans_from
             ON sekai_dataset_row_spans(dataset_id, from_seq);
         CREATE INDEX IF NOT EXISTS idx_dataset_row_spans_source_key
             ON sekai_dataset_row_spans(dataset_id, json_extract(data, '$.source_id'), row_id)
             WHERE dataset_id LIKE 'srcds:%';
         CREATE VIEW IF NOT EXISTS sekai_dataset_version_content AS
         SELECT dataset_id, version_id, row_id, data, partition_key
         FROM sekai_dataset_version_rows
         UNION ALL
         SELECT v.dataset_id, v.version_id, s.row_id, s.data, s.partition_key
         FROM sekai_dataset_versions v
         JOIN sekai_dataset_row_spans s
           ON s.dataset_id = v.dataset_id
          AND s.from_seq <= v.seq
          AND (s.to_seq IS NULL OR s.to_seq > v.seq)
         WHERE v.layout = 'span' AND v.purged = 0;",
    )
    .map_err(|error| error.to_string())
}

impl SekaiDb {
    pub fn migrate_datasets(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_datasets (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, columns TEXT NOT NULL,
                object_id TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sekai_dataset_rows (
                id INTEGER PRIMARY KEY AUTOINCREMENT, dataset_id TEXT NOT NULL,
                data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dataset_rows ON sekai_dataset_rows(dataset_id);
            CREATE INDEX IF NOT EXISTS idx_dataset_rows_id ON sekai_dataset_rows(dataset_id, id);
            CREATE TABLE IF NOT EXISTS sekai_virtual_tables (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, dataset_id TEXT NOT NULL,
                filters TEXT NOT NULL DEFAULT '[]', columns TEXT NOT NULL DEFAULT '[]',
                created INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sekai_dataset_versions (
                dataset_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                tenant TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                restored_from_version_id TEXT NOT NULL DEFAULT '',
                row_count INTEGER NOT NULL,
                purged INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (dataset_id, version_id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_dataset_versions_seq
                ON sekai_dataset_versions(dataset_id, seq);
            CREATE TABLE IF NOT EXISTS sekai_dataset_version_rows (
                dataset_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                row_id INTEGER NOT NULL,
                data TEXT NOT NULL,
                partition_key TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (dataset_id, version_id, row_id)
            );
            CREATE TABLE IF NOT EXISTS sekai_dataset_version_policy (
                dataset_id TEXT PRIMARY KEY,
                retain_count INTEGER NOT NULL DEFAULT 0
            );",
        )
        .map_err(|e| e.to_string())?;
        crate::sekai::dataset_health::migrate_dataset_health(&conn)?;
        crate::sekai::consumer_violation::migrate_consumer_violations(&conn)?;
        crate::db::dataset_branch::migrate_dataset_branches(&conn)?;
        conn.execute_batch(crate::db::dataset_rollback_proposal::SQLITE_SCHEMA)
            .map_err(|error| error.to_string())?;
        crate::db::add_sqlite_column(
            &conn,
            "ALTER TABLE sekai_datasets ADD COLUMN partition_keys TEXT NOT NULL DEFAULT '[]'",
        )?;
        crate::db::add_sqlite_column(
            &conn,
            "ALTER TABLE sekai_dataset_rows ADD COLUMN partition_key TEXT NOT NULL DEFAULT ''",
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dataset_rows_partition
             ON sekai_dataset_rows(dataset_id, partition_key)",
            [],
        )
        .map_err(|e| e.to_string())?;
        // Keyed newest-first lookup of a source batch row (#3259). Partial, so
        // only `srcds:` rows pay for the expression.
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_dataset_rows_source_key
                 ON sekai_dataset_rows(dataset_id, json_extract(data, '$.source_id'), id)
                 WHERE dataset_id LIKE 'srcds:%';
             CREATE INDEX IF NOT EXISTS idx_dataset_version_rows_source_key
                 ON sekai_dataset_version_rows(
                     dataset_id, version_id, json_extract(data, '$.source_id'), row_id
                 )
                 WHERE dataset_id LIKE 'srcds:%';",
        )
        .map_err(|e| e.to_string())?;
        // One series of a samples dataset by time (#3472, ADR 0171). Partial,
        // so only rows with a series id pay for the entry, and guarded, so a
        // malformed row never fails its insert; the series read repeats each
        // expression and the predicate exactly.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dataset_rows_series
                 ON sekai_dataset_rows(
                     dataset_id,
                     json_extract(data, '$.series_id'),
                     CAST(json_extract(data, '$.timestamp') AS INTEGER)
                 )
                 WHERE json_valid(data) AND json_extract(data, '$.series_id') IS NOT NULL",
            [],
        )
        .map_err(|e| e.to_string())?;
        migrate_dataset_row_spans(&conn)?;
        let stored: Option<String> = conn
            .query_row(
                "SELECT columns FROM sekai_datasets WHERE id='llm_calls'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(stored) = stored {
            let mut columns = parse_columns(&stored)?;
            if !columns.iter().any(|column| column.name == "data_class") {
                let insert_at = columns
                    .iter()
                    .position(|column| column.name == "project")
                    .map_or(columns.len(), |index| index + 1);
                columns.insert(
                    insert_at,
                    ColumnDef {
                        name: "data_class".into(),
                        col_type: "string".into(),
                        classification: llm_call_column_classification("data_class").into(),
                    },
                );
            }
            for column in &mut columns {
                column.classification = llm_call_column_classification(&column.name).into();
            }
            let columns = serde_json::to_string(
                &columns
                    .iter()
                    .map(|column| (&column.name, &column.col_type, &column.classification))
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "UPDATE sekai_datasets SET columns=?1 WHERE id='llm_calls'",
                params![columns],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn create_dataset(&self, d: &Dataset) -> Result<(), String> {
        let conn = self.conn();
        create_dataset_tx(&conn, d)
    }

    /// Append the column definitions the dataset lacks, against the
    /// definitions read in this transaction: a concurrent change to an
    /// existing column is never overwritten (#1693).
    pub fn add_dataset_columns(
        &self,
        dataset_id: &str,
        columns: &[ColumnDef],
    ) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        add_dataset_columns_tx(&tx, dataset_id, columns)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn update_dataset(&self, d: &Dataset) -> Result<(), String> {
        for column in &d.columns {
            if !crate::sekai::schema::is_valid_property_classification(&column.classification) {
                return Err(format!(
                    "column {} has invalid classification: {}",
                    column.name, column.classification
                ));
            }
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let previous_json: String = tx
            .query_row(
                "SELECT partition_keys FROM sekai_datasets WHERE id=?1",
                params![d.id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("dataset {:?} not found", d.id))?;
        let previous = parse_partition_keys(&previous_json)?;
        let cols = serde_json::to_string(
            &d.columns
                .iter()
                .map(|c| {
                    (
                        &c.name,
                        &c.col_type,
                        crate::sekai::schema::normalize_property_classification(&c.classification),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|error| error.to_string())?;
        let changed = tx
            .execute(
                "UPDATE sekai_datasets SET name=?2, columns=?3, partition_keys=?4 WHERE id=?1",
                params![
                    d.id,
                    d.name,
                    cols,
                    encode_partition_keys(&d.partition_keys)?
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err(format!("dataset {:?} not found", d.id));
        }
        if previous != d.partition_keys {
            reindex_dataset_partition_keys(&tx, &d.id, &d.partition_keys)?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT id,name,columns,object_id,created,partition_keys FROM sekai_datasets WHERE id=?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5).unwrap_or_else(|_| "[]".into()),
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;
        row.map(|(id, name, cols_str, object_id, created, keys)| {
            Ok(Dataset {
                id,
                name,
                columns: parse_columns(&cols_str)?,
                object_id,
                created,
                partition_keys: parse_partition_keys(&keys)?,
            })
        })
        .transpose()
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id,name,columns,object_id,created,partition_keys FROM sekai_datasets")
            .map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let cols_str: String = row.get(2).map_err(|e| e.to_string())?;
            let keys: String = row.get(5).unwrap_or_else(|_| "[]".into());
            results.push(Dataset {
                id: row.get(0).map_err(|e| e.to_string())?,
                name: row.get(1).map_err(|e| e.to_string())?,
                columns: parse_columns(&cols_str)?,
                object_id: row.get(3).map_err(|e| e.to_string())?,
                created: row.get(4).map_err(|e| e.to_string())?,
                partition_keys: parse_partition_keys(&keys)?,
            });
        }
        Ok(results)
    }

    pub fn append_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn();
        // Immediate: the append reads before it writes, and a deferred read
        // snapshot that another writer commits past fails without waiting
        // (#3361). Taking the write lock first waits within the busy timeout.
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        append_rows_tx(&tx, dataset_id, rows)?;
        tx.commit().map_err(|error| error.to_string())?;
        i32::try_from(rows.len()).map_err(|_| "too many dataset rows".into())
    }

    pub fn list_dataset_versions(&self, dataset_id: &str) -> Result<Vec<DatasetVersion>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                        restored_from_version_id, row_count, purged
                 FROM sekai_dataset_versions WHERE dataset_id = ?1 ORDER BY seq",
            )
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(params![dataset_id], map_dataset_version_row)
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    pub fn dataset_version_retention(&self, dataset_id: &str) -> Result<i32, String> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT retain_count FROM sekai_dataset_version_policy WHERE dataset_id = ?1",
                params![dataset_id],
                |row| row.get::<_, i32>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .unwrap_or(0))
    }

    pub fn set_dataset_version_retention(
        &self,
        dataset_id: &str,
        retain_count: i32,
    ) -> Result<(), String> {
        if retain_count < 0 {
            return Err("version_retention_count must be >= 0".into());
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM sekai_datasets WHERE id = ?1",
                params![dataset_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if exists.is_none() {
            return Err(dataset_version::DATASET_NOT_FOUND.into());
        }
        tx.execute(
            "INSERT INTO sekai_dataset_version_policy (dataset_id, retain_count)
             VALUES (?1, ?2)
             ON CONFLICT(dataset_id) DO UPDATE SET retain_count = excluded.retain_count",
            params![dataset_id, retain_count],
        )
        .map_err(|error| error.to_string())?;
        prune_dataset_versions_tx(&tx, dataset_id)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<DatasetVersion, String> {
        let conn = self.conn();
        let row = if !version_id.is_empty() {
            conn.query_row(
                "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                        restored_from_version_id, row_count, purged
                 FROM sekai_dataset_versions WHERE dataset_id = ?1 AND version_id = ?2",
                params![dataset_id, version_id],
                map_dataset_version_row,
            )
            .optional()
            .map_err(|error| error.to_string())?
        } else if as_of_ms > 0 {
            conn.query_row(
                "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                        restored_from_version_id, row_count, purged
                 FROM sekai_dataset_versions
                 WHERE dataset_id = ?1 AND created_at_ms <= ?2
                 ORDER BY seq DESC LIMIT 1",
                params![dataset_id, as_of_ms],
                map_dataset_version_row,
            )
            .optional()
            .map_err(|error| error.to_string())?
        } else {
            conn.query_row(
                "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                        restored_from_version_id, row_count, purged
                 FROM sekai_dataset_versions WHERE dataset_id = ?1
                 ORDER BY seq DESC LIMIT 1",
                params![dataset_id],
                map_dataset_version_row,
            )
            .optional()
            .map_err(|error| error.to_string())?
        };
        let version = row.ok_or_else(|| dataset_version::DATASET_VERSION_NOT_FOUND.to_string())?;
        if version.purged {
            return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
        }
        Ok(version)
    }

    pub fn query_dataset_version_rows(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        Ok(self
            .load_dataset_version(dataset_id, version_id, as_of_ms)?
            .1)
    }

    pub fn load_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<(DatasetVersion, Vec<HashMap<String, String>>), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let version = get_dataset_version_tx(&tx, dataset_id, version_id, as_of_ms)?;
        if version.purged {
            return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
        }
        let rows = query_dataset_version_rows_tx(&tx, dataset_id, &version.version_id)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok((version, rows))
    }

    /// One page of a version's rows in `row_id` order: up to `limit + 1` rows
    /// after `after_row_id`, so the caller can tell whether more follow. A
    /// row keeps its `row_id` when another row of the version is erased.
    pub fn load_dataset_version_page(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
        after_row_id: Option<i64>,
        limit: usize,
    ) -> Result<DatasetVersionPage, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let version = get_dataset_version_tx(&tx, dataset_id, version_id, as_of_ms)?;
        if version.purged {
            return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
        }
        let rows = {
            let mut stmt = tx
                .prepare(
                    "SELECT row_id, data FROM sekai_dataset_version_content
                     WHERE dataset_id = ?1 AND version_id = ?2 AND row_id > ?3
                     ORDER BY row_id LIMIT ?4",
                )
                .map_err(|error| error.to_string())?;
            let mapped = stmt
                .query_map(
                    params![
                        dataset_id,
                        version.version_id,
                        after_row_id.unwrap_or(i64::MIN),
                        i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
                    ],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(|error| error.to_string())?;
            let mut rows = Vec::new();
            for row in mapped {
                let (row_id, data) = row.map_err(|error| error.to_string())?;
                rows.push((
                    row_id,
                    serde_json::from_str(&data).map_err(|error| error.to_string())?,
                ));
            }
            rows
        };
        tx.commit().map_err(|error| error.to_string())?;
        Ok((version, rows))
    }

    pub fn rollback_dataset(&self, request: &DatasetRollback) -> Result<DatasetVersion, String> {
        if request.restore_from_version_id.trim().is_empty() {
            return Err(dataset_version::DATASET_ROLLBACK_REQUIRES_RESTORE.into());
        }
        let mut conn = self.conn();
        // Immediate: the write lock is held before the object type index
        // check, so a registration on another connection cannot commit
        // between the check and the rollback (#2415).
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let version = rollback_dataset_tx(&tx, request)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(version)
    }

    pub fn list_dataset_row_records(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<DatasetRowRecord>, String> {
        self.list_dataset_row_records_after(dataset_id, 0)
    }

    pub fn list_dataset_row_records_after(
        &self,
        dataset_id: &str,
        after_id: i64,
    ) -> Result<Vec<DatasetRowRecord>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, data FROM sekai_dataset_rows
                 WHERE dataset_id = ?1 AND id > ?2
                 ORDER BY id",
            )
            .map_err(|e| e.to_string())?;
        let mut rows_iter = stmt
            .query(params![dataset_id, after_id])
            .map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        while let Some(row) = rows_iter.next().map_err(|e| e.to_string())? {
            let id: i64 = row.get(0).map_err(|e| e.to_string())?;
            let data: String = row.get(1).map_err(|e| e.to_string())?;
            let map: HashMap<String, String> = serde_json::from_str(&data)
                .map_err(|error| format!("corrupt dataset row for {dataset_id:?}: {error}"))?;
            results.push((id, map));
        }
        Ok(results)
    }

    pub fn query_rows(
        &self,
        dataset_id: &str,
        q: &RowQuery,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let state = crate::sekai::dataset_health::load_state_conn(&tx, dataset_id)?;
        let mut stmt = if state.quarantined && !state.last_healthy_version_id.is_empty() {
            tx.prepare(
                "SELECT data FROM sekai_dataset_version_content
                 WHERE dataset_id = ?1 AND version_id = ?2 ORDER BY row_id",
            )
            .map_err(|e| e.to_string())?
        } else if state.quarantined {
            return Ok(Vec::new());
        } else {
            tx.prepare("SELECT data FROM sekai_dataset_rows WHERE dataset_id = ?1 ORDER BY id")
                .map_err(|e| e.to_string())?
        };
        let mut rows_iter = if state.quarantined && !state.last_healthy_version_id.is_empty() {
            stmt.query(params![dataset_id, state.last_healthy_version_id])
                .map_err(|e| e.to_string())?
        } else {
            stmt.query(params![dataset_id]).map_err(|e| e.to_string())?
        };
        let mut results = Vec::new();
        let mut skipped = 0;
        while let Some(row) = rows_iter.next().map_err(|e| e.to_string())? {
            let data: String = row.get(0).map_err(|e| e.to_string())?;
            let map: HashMap<String, String> = serde_json::from_str(&data)
                .map_err(|error| format!("corrupt dataset row for {dataset_id:?}: {error}"))?;
            if !matches_row_filters(&map, &q.filters) {
                continue;
            }
            if skipped < q.offset {
                skipped += 1;
                continue;
            }
            let projected = if q.columns.is_empty() {
                map
            } else {
                map.into_iter()
                    .filter(|(k, _)| q.columns.contains(k))
                    .collect()
            };
            results.push(projected);
            if q.limit > 0 && results.len() >= q.limit as usize {
                break;
            }
        }
        Ok(results)
    }

    /// The newest row whose `source_id` is `source_id` in source batch
    /// dataset `dataset_id`, under the same health rules as [`Self::query_rows`]:
    /// a quarantined dataset serves its last healthy version, or nothing. One
    /// index seek over `idx_dataset_rows_source_key` (#3259); the literal
    /// `srcds:` predicate lets the partial index apply.
    pub fn latest_source_batch_row(
        &self,
        dataset_id: &str,
        source_id: &str,
    ) -> Result<Option<HashMap<String, String>>, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let state = crate::sekai::dataset_health::load_state_conn(&tx, dataset_id)?;
        let data: Option<String> = if state.quarantined && !state.last_healthy_version_id.is_empty()
        {
            tx.query_row(
                LATEST_SOURCE_VERSION_ROW_SQL,
                params![dataset_id, state.last_healthy_version_id, source_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
        } else if state.quarantined {
            None
        } else {
            tx.query_row(
                LATEST_SOURCE_ROW_SQL,
                params![dataset_id, source_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
        };
        data.map(|data| {
            serde_json::from_str(&data)
                .map_err(|error| format!("corrupt dataset row for {dataset_id:?}: {error}"))
        })
        .transpose()
    }

    pub fn redact_dataset_fields(
        &self,
        dataset_id: &str,
        classification: &str,
        filters: &[RowFilter],
    ) -> Result<DatasetRedaction, String> {
        if !crate::sekai::schema::is_restricted_property_classification(classification) {
            return Err("classification must be internal or sensitive".into());
        }
        let classification =
            crate::sekai::schema::normalize_property_classification(classification);
        let mut conn = self.conn();
        // Columns are read under the write lock, so a classification change
        // committed before this call starts redacting is honored (#2821).
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let (columns_json, keys_json): (String, String) = tx
            .query_row(
                "SELECT columns, partition_keys FROM sekai_datasets WHERE id=?1",
                params![dataset_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "dataset not found".to_string())?;
        let columns = parse_columns(&columns_json)?;
        let fields = redaction_fields(&columns, classification, filters)?;
        if fields.is_empty() {
            return Ok(DatasetRedaction::default());
        }
        let keys = parse_partition_keys(&keys_json)?;
        let rows = {
            let mut stmt = tx
                .prepare("SELECT id,data FROM sekai_dataset_rows WHERE dataset_id=?1 ORDER BY id")
                .map_err(|e| e.to_string())?;
            stmt.query_map(params![dataset_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        let mut result = DatasetRedaction::default();
        for (id, data) in rows {
            let mut values: HashMap<String, String> =
                serde_json::from_str(&data).map_err(|e| e.to_string())?;
            if !matches_row_filters(&values, filters) {
                continue;
            }
            let mut changed = 0;
            for field in &fields {
                if let Some(value) = values.get_mut(*field)
                    && value != "[redacted]"
                {
                    *value = "[redacted]".into();
                    changed += 1;
                }
            }
            if changed == 0 {
                continue;
            }
            let data = serde_json::to_string(&values).map_err(|e| e.to_string())?;
            let partition_key = crate::sekai::governed_transform::partition_value(&keys, &values);
            tx.execute(
                "UPDATE sekai_dataset_rows SET data=?1, partition_key=?2 WHERE id=?3 AND dataset_id=?4",
                params![data, partition_key, id, dataset_id],
            )
            .map_err(|e| e.to_string())?;
            result.rows_updated += 1;
            result.fields_redacted += changed;
        }
        redact_dataset_version_rows_tx(&tx, dataset_id, filters, &fields, &keys)?;
        crate::db::dataset_branch::edit_branch_rows_tx(&tx, dataset_id, &|row| {
            redact_branch_row(row, filters, &fields)
        })?;
        if result.rows_updated > 0 {
            snapshot_dataset_version_tx(
                &tx,
                dataset_id,
                "",
                "",
                "redaction",
                "",
                dataset_version::now_ms(),
            )?;
        }
        crate::db::governed_transform::redact_transform_partition_receipts(
            &tx,
            dataset_id,
            keys.is_empty() || keys.iter().any(|key| fields.contains(&key.as_str())),
        )?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(result)
    }

    pub fn create_virtual_table(&self, vt: &VirtualTable) -> Result<(), String> {
        let conn = self.conn();
        let filters = serde_json::to_string(
            &vt.filters
                .iter()
                .map(|f| (&f.column, &f.op, &f.value))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let cols = serde_json::to_string(&vt.columns).unwrap();
        conn.execute("INSERT INTO sekai_virtual_tables (id,name,dataset_id,filters,columns,created) VALUES (?1,?2,?3,?4,?5,?6)",
            params![vt.id, vt.name, vt.dataset_id, filters, cols, vt.created]).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_virtual_tables(&self) -> Result<Vec<VirtualTable>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id,name,dataset_id,filters,columns,created FROM sekai_virtual_tables")
            .map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let filters_str: String = row.get(3).map_err(|e| e.to_string())?;
            let filters: Vec<(String, String, String)> = serde_json::from_str(&filters_str)
                .map_err(|error| format!("corrupt virtual table filters: {error}"))?;
            let cols_str: String = row.get(4).map_err(|e| e.to_string())?;
            let columns: Vec<String> = serde_json::from_str(&cols_str)
                .map_err(|error| format!("corrupt virtual table columns: {error}"))?;
            results.push(VirtualTable {
                id: row.get(0).map_err(|e| e.to_string())?,
                name: row.get(1).map_err(|e| e.to_string())?,
                dataset_id: row.get(2).map_err(|e| e.to_string())?,
                filters: filters
                    .into_iter()
                    .map(|(c, o, v)| RowFilter {
                        column: c,
                        op: o,
                        value: v,
                    })
                    .collect(),
                columns,
                created: row.get(5).map_err(|e| e.to_string())?,
            });
        }
        Ok(results)
    }

    pub fn query_virtual_table(
        &self,
        vt: &VirtualTable,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        let q = RowQuery {
            filters: vt.filters.clone(),
            columns: vt.columns.clone(),
            ..Default::default()
        };
        self.query_rows(&vt.dataset_id, &q)
    }
}

/// Stored rows of one dataset in a layout table: `(key, row_id, data)`, where
/// `key` is the copy row's `version_id` or the span's `from_seq`.
fn stored_rows<K: rusqlite::types::FromSql>(
    tx: &Transaction<'_>,
    sql: &str,
    dataset_id: &str,
) -> Result<Vec<(K, i64, String)>, String> {
    let mut stmt = tx.prepare(sql).map_err(|error| error.to_string())?;
    let mapped = stmt
        .query_map(params![dataset_id], |row| {
            Ok((row.get::<_, K>(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| error.to_string())?;
    mapped
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

/// Deletes the closed spans of a dataset that no retained `span` version
/// covers. Open spans are the live content and always stay.
pub(crate) const PURGE_UNCOVERED_SPANS_SQLITE: &str = "DELETE FROM sekai_dataset_row_spans
     WHERE dataset_id = ?1 AND to_seq IS NOT NULL
       AND NOT EXISTS (
         SELECT 1 FROM sekai_dataset_versions v
         WHERE v.dataset_id = ?1 AND v.layout = 'span' AND v.purged = 0
           AND v.seq >= sekai_dataset_row_spans.from_seq
           AND v.seq < sekai_dataset_row_spans.to_seq
       )";

const COPY_ROWS_SQL: &str =
    "SELECT version_id, row_id, data FROM sekai_dataset_version_rows WHERE dataset_id = ?1";
const SPAN_ROWS_SQL: &str =
    "SELECT from_seq, row_id, data FROM sekai_dataset_row_spans WHERE dataset_id = ?1";

/// Redacts matching rows of every version, in both layouts. A shared span is
/// rewritten once and every version that covers it sees the result.
fn redact_dataset_version_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    filters: &[RowFilter],
    fields: &[&str],
    keys: &[String],
) -> Result<(), String> {
    let redact = |data: &str| -> Result<Option<(String, String)>, String> {
        let mut values: HashMap<String, String> =
            serde_json::from_str(data).map_err(|error| error.to_string())?;
        if !matches_row_filters(&values, filters) {
            return Ok(None);
        }
        let mut changed = false;
        for field in fields {
            if let Some(value) = values.get_mut(*field)
                && value != "[redacted]"
            {
                *value = "[redacted]".into();
                changed = true;
            }
        }
        if !changed {
            return Ok(None);
        }
        let data = serde_json::to_string(&values).map_err(|error| error.to_string())?;
        let partition_key = crate::sekai::governed_transform::partition_value(keys, &values);
        Ok(Some((data, partition_key)))
    };
    for (version_id, row_id, data) in stored_rows::<String>(tx, COPY_ROWS_SQL, dataset_id)? {
        if let Some((data, partition_key)) = redact(&data)? {
            tx.execute(
                "UPDATE sekai_dataset_version_rows SET data = ?1, partition_key = ?2
                 WHERE dataset_id = ?3 AND version_id = ?4 AND row_id = ?5",
                params![data, partition_key, dataset_id, version_id, row_id],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    for (from_seq, row_id, data) in stored_rows::<i64>(tx, SPAN_ROWS_SQL, dataset_id)? {
        if let Some((data, partition_key)) = redact(&data)? {
            tx.execute(
                "UPDATE sekai_dataset_row_spans SET data = ?1, partition_key = ?2
                 WHERE dataset_id = ?3 AND row_id = ?4 AND from_seq = ?5",
                params![data, partition_key, dataset_id, row_id, from_seq],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn map_dataset_version_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DatasetVersion> {
    Ok(DatasetVersion {
        dataset_id: row.get(0)?,
        version_id: row.get(1)?,
        seq: row.get(2)?,
        created_at_ms: row.get(3)?,
        actor: row.get(4)?,
        tenant: row.get(5)?,
        reason: row.get(6)?,
        restored_from_version_id: row.get(7)?,
        row_count: row.get(8)?,
        purged: row.get::<_, i64>(9)? != 0,
    })
}

/// A dataset version and one page of its rows, each with its stable `row_id`.
pub type DatasetVersionPage = (DatasetVersion, Vec<(i64, HashMap<String, String>)>);

pub fn query_dataset_version_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    version_id: &str,
) -> Result<Vec<HashMap<String, String>>, String> {
    let mut stmt = tx
        .prepare(
            "SELECT data FROM sekai_dataset_version_content
             WHERE dataset_id = ?1 AND version_id = ?2 ORDER BY row_id",
        )
        .map_err(|error| error.to_string())?;
    let mapped = stmt
        .query_map(params![dataset_id, version_id], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|error| error.to_string())?;
    let mut rows = Vec::new();
    for data in mapped {
        let data = data.map_err(|error| error.to_string())?;
        rows.push(serde_json::from_str(&data).map_err(|error| error.to_string())?);
    }
    Ok(rows)
}

/// Check `filters` against `columns` and pick the columns that carry
/// `classification` (already normalized). Both stores call this on columns
/// read inside their redaction write transaction.
pub(crate) fn redaction_fields<'a>(
    columns: &'a [ColumnDef],
    classification: &str,
    filters: &[RowFilter],
) -> Result<Vec<&'a str>, String> {
    for filter in filters {
        if !columns.iter().any(|column| column.name == filter.column) {
            return Err(format!("unknown filter column: {}", filter.column));
        }
        if !matches!(
            filter.op.as_str(),
            "eq" | "neq" | "gt" | "lt" | "gte" | "lte"
        ) {
            return Err(format!("unsupported filter operator: {}", filter.op));
        }
    }
    Ok(columns
        .iter()
        .filter(|column| {
            crate::sekai::schema::normalize_property_classification(&column.classification)
                == classification
        })
        .map(|column| column.name.as_str())
        .collect())
}

/// The redaction of one branch working-copy row: matching rows get the
/// fields replaced, and a row that no longer decodes is dropped.
pub fn redact_branch_row(
    row: Option<HashMap<String, String>>,
    filters: &[RowFilter],
    fields: &[&str],
) -> crate::sekai::dataset_branch::BranchRowEdit {
    use crate::sekai::dataset_branch::BranchRowEdit;
    let Some(mut values) = row else {
        return BranchRowEdit::Delete;
    };
    if !matches_row_filters(&values, filters) {
        return BranchRowEdit::Keep;
    }
    let mut changed = false;
    for field in fields {
        if let Some(value) = values.get_mut(*field)
            && value != "[redacted]"
        {
            *value = "[redacted]".into();
            changed = true;
        }
    }
    if changed {
        BranchRowEdit::Replace(values)
    } else {
        BranchRowEdit::Keep
    }
}

pub fn erase_matching_dataset_version_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    matches: &dyn Fn(&HashMap<String, String>) -> bool,
) -> Result<(), String> {
    let table: Option<String> = tx
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sekai_dataset_version_rows'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if table.is_none() {
        return Ok(());
    }
    crate::db::dataset_branch::edit_branch_rows_tx(tx, dataset_id, &|row| match row {
        Some(values) if !matches(&values) => crate::sekai::dataset_branch::BranchRowEdit::Keep,
        _ => crate::sekai::dataset_branch::BranchRowEdit::Delete,
    })?;
    // A row that does not parse is erased too: it cannot be shown to be clear.
    let erase = |data: &str| {
        serde_json::from_str::<HashMap<String, String>>(data)
            .map_or(true, |values| matches(&values))
    };
    for (version_id, row_id, data) in stored_rows::<String>(tx, COPY_ROWS_SQL, dataset_id)? {
        if erase(&data) {
            tx.execute(
                "DELETE FROM sekai_dataset_version_rows
                 WHERE dataset_id = ?1 AND version_id = ?2 AND row_id = ?3",
                params![dataset_id, version_id, row_id],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    for (from_seq, row_id, data) in stored_rows::<i64>(tx, SPAN_ROWS_SQL, dataset_id)? {
        if erase(&data) {
            tx.execute(
                "DELETE FROM sekai_dataset_row_spans
                 WHERE dataset_id = ?1 AND row_id = ?2 AND from_seq = ?3",
                params![dataset_id, row_id, from_seq],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    tx.execute(
        "UPDATE sekai_dataset_versions SET row_count = (
            SELECT COUNT(*) FROM sekai_dataset_version_content
            WHERE dataset_id = sekai_dataset_versions.dataset_id
              AND version_id = sekai_dataset_versions.version_id
         ) WHERE dataset_id = ?1",
        params![dataset_id],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn get_dataset_version_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    version_id: &str,
    as_of_ms: i64,
) -> Result<DatasetVersion, String> {
    let row = if !version_id.is_empty() {
        tx.query_row(
            "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                    restored_from_version_id, row_count, purged
             FROM sekai_dataset_versions WHERE dataset_id = ?1 AND version_id = ?2",
            params![dataset_id, version_id],
            map_dataset_version_row,
        )
        .optional()
        .map_err(|error| error.to_string())?
    } else if as_of_ms > 0 {
        tx.query_row(
            "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                    restored_from_version_id, row_count, purged
             FROM sekai_dataset_versions
             WHERE dataset_id = ?1 AND created_at_ms <= ?2
             ORDER BY seq DESC LIMIT 1",
            params![dataset_id, as_of_ms],
            map_dataset_version_row,
        )
        .optional()
        .map_err(|error| error.to_string())?
    } else {
        tx.query_row(
            "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                    restored_from_version_id, row_count, purged
             FROM sekai_dataset_versions WHERE dataset_id = ?1
             ORDER BY seq DESC LIMIT 1",
            params![dataset_id],
            map_dataset_version_row,
        )
        .optional()
        .map_err(|error| error.to_string())?
    };
    row.ok_or_else(|| dataset_version::DATASET_VERSION_NOT_FOUND.to_string())
}

/// Writes a `snapshot` version of the dataset's live rows (ADR 0172): it
/// closes every open span and opens one span per live row, so its cost is the
/// dataset's size. Every writer uses it except source batch landing, which
/// writes the change alone through [`land_source_rows_tx`].
pub fn snapshot_dataset_version_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    actor: &str,
    tenant: &str,
    reason: &str,
    restored_from_version_id: &str,
    created_at_ms: i64,
) -> Result<DatasetVersion, String> {
    let exists: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM sekai_datasets WHERE id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if exists.is_none() {
        return Err(dataset_version::DATASET_NOT_FOUND.into());
    }
    let next = next_version_tx(tx, dataset_id, created_at_ms)?;
    let jsons: Vec<String> = {
        let mut stmt = tx
            .prepare("SELECT data FROM sekai_dataset_rows WHERE dataset_id = ?1 ORDER BY id")
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(params![dataset_id], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    tx.execute(
        "UPDATE sekai_dataset_row_spans SET to_seq = ?2 WHERE dataset_id = ?1 AND to_seq IS NULL",
        params![dataset_id, next.seq],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(OPEN_LIVE_SPANS_SQLITE, params![dataset_id, next.seq])
        .map_err(|error| error.to_string())?;
    let row_count = i64::try_from(jsons.len()).map_err(|_| "too many dataset rows".to_string())?;
    insert_span_version_tx(
        tx,
        dataset_id,
        &next,
        VersionChange {
            kind: "snapshot",
            changed: &jsons,
            row_count,
        },
        VersionMeta {
            actor,
            tenant,
            reason,
            restored_from_version_id,
        },
    )
}

/// Lands source records into a source dataset as one span version (ADR
/// 0172): an `append` when every external id (`source_id`) is new, otherwise
/// an `update` that closes and removes the earlier row of each external id it
/// replaces, so the live rows stay equal to the latest version. A batch that
/// names one id twice lands its last row. The cost follows the batch, except
/// that the first span version of a dataset opens spans for the rows it
/// already holds, once. Returns the inclusive range of inserted row ids, or
/// `(0, 0)` when `rows` is empty.
pub fn land_source_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    rows: &[HashMap<String, String>],
) -> Result<(i64, i64), String> {
    if rows.is_empty() {
        return Ok((0, 0));
    }
    let rows = crate::db::source_batch_dataset::last_row_per_key(rows);
    let keys_json: String = tx
        .query_row(
            "SELECT partition_keys FROM sekai_datasets WHERE id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| dataset_version::DATASET_NOT_FOUND.to_string())?;
    let keys = parse_partition_keys(&keys_json)?;
    let next = next_version_tx(tx, dataset_id, dataset_version::now_ms())?;
    let mut replaced = Vec::new();
    {
        // Seeks `idx_dataset_rows_source_key`.
        let mut find = tx
            .prepare_cached(
                "SELECT id FROM sekai_dataset_rows
                 WHERE dataset_id LIKE 'srcds:%' AND dataset_id = ?1
                   AND json_extract(data, '$.source_id') = ?2",
            )
            .map_err(|error| error.to_string())?;
        for key in rows
            .iter()
            .filter_map(|row| row.get(crate::db::source_batch_dataset::KEY_COLUMN))
        {
            let ids = find
                .query_map(params![dataset_id, key], |row| row.get::<_, i64>(0))
                .map_err(|error| error.to_string())?;
            for id in ids {
                replaced.push(id.map_err(|error| error.to_string())?);
            }
        }
    }
    replaced.sort_unstable();
    for id in &replaced {
        if next.on_spans {
            tx.execute(
                "UPDATE sekai_dataset_row_spans SET to_seq = ?3
                 WHERE dataset_id = ?1 AND row_id = ?2 AND to_seq IS NULL",
                params![dataset_id, id, next.seq],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute("DELETE FROM sekai_dataset_rows WHERE id = ?1", params![id])
            .map_err(|error| error.to_string())?;
    }
    if !next.on_spans {
        tx.execute(OPEN_LIVE_SPANS_SQLITE, params![dataset_id, next.seq])
            .map_err(|error| error.to_string())?;
    }
    let mut changed: Vec<String> = replaced.iter().map(|id| format!("-{id}")).collect();
    let (mut first, mut last) = (0, 0);
    for row in &rows {
        let data = serde_json::to_string(row).map_err(|error| error.to_string())?;
        let partition_key = crate::sekai::governed_transform::partition_value(&keys, row);
        tx.execute(
            "INSERT INTO sekai_dataset_rows (dataset_id, data, partition_key) VALUES (?1, ?2, ?3)",
            params![dataset_id, data, partition_key],
        )
        .map_err(|error| error.to_string())?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO sekai_dataset_row_spans (dataset_id, row_id, from_seq, data, partition_key)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![dataset_id, id, next.seq, data, partition_key],
        )
        .map_err(|error| error.to_string())?;
        if first == 0 {
            first = id;
        }
        last = id;
        changed.push(data);
    }
    let row_count = if next.on_spans {
        i64::from(next.previous_row_count) + rows.len() as i64 - replaced.len() as i64
    } else {
        tx.query_row(
            "SELECT COUNT(*) FROM sekai_dataset_rows WHERE dataset_id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?
    };
    insert_span_version_tx(
        tx,
        dataset_id,
        &next,
        VersionChange {
            kind: if replaced.is_empty() {
                "append"
            } else {
                "update"
            },
            changed: &changed,
            row_count,
        },
        VersionMeta::default(),
    )?;
    Ok((first, last))
}

/// Opens a span at seq `?2` for every live row of dataset `?1`.
const OPEN_LIVE_SPANS_SQLITE: &str =
    "INSERT INTO sekai_dataset_row_spans (dataset_id, row_id, from_seq, data, partition_key)
     SELECT dataset_id, id, ?2, data, COALESCE(partition_key, '')
     FROM sekai_dataset_rows WHERE dataset_id = ?1";

/// Where the next version of a dataset goes, read from its latest version.
struct NextVersion {
    seq: i64,
    created_at_ms: i64,
    /// Empty for a dataset's first version.
    previous_version_id: String,
    /// The latest version is a `span` version, so the open spans hold its
    /// content and a change can build on them. A `copy` latest version (or
    /// none) means the change first opens spans for the live rows.
    on_spans: bool,
    previous_row_count: i32,
}

fn next_version_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    created_at_ms: i64,
) -> Result<NextVersion, String> {
    let latest = tx
        .query_row(
            "SELECT seq, created_at_ms, version_id, layout = 'span', row_count
             FROM sekai_dataset_versions WHERE dataset_id = ?1
             ORDER BY seq DESC LIMIT 1",
            params![dataset_id],
            |row| {
                Ok(NextVersion {
                    seq: row.get::<_, i64>(0)? + 1,
                    created_at_ms: created_at_ms.max(row.get::<_, i64>(1)?.saturating_add(1)),
                    previous_version_id: row.get(2)?,
                    on_spans: row.get(3)?,
                    previous_row_count: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    Ok(latest.unwrap_or(NextVersion {
        seq: 1,
        created_at_ms,
        previous_version_id: String::new(),
        on_spans: false,
        previous_row_count: 0,
    }))
}

/// What a new version changed: its kind, the rows its id hashes (see
/// [`dataset_version::span_version_id`]), and its content's row count.
struct VersionChange<'a> {
    kind: &'a str,
    changed: &'a [String],
    row_count: i64,
}

/// Who wrote a version and why; empty for a landed batch.
#[derive(Clone, Copy, Default)]
struct VersionMeta<'a> {
    actor: &'a str,
    tenant: &'a str,
    reason: &'a str,
    restored_from_version_id: &'a str,
}

/// Records a `span` version whose spans are already written, then judges its
/// health and prunes past retention.
fn insert_span_version_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    next: &NextVersion,
    change: VersionChange<'_>,
    meta: VersionMeta<'_>,
) -> Result<DatasetVersion, String> {
    let row_count =
        i32::try_from(change.row_count).map_err(|_| "too many dataset rows".to_string())?;
    let version_id = dataset_version::span_version_id(
        dataset_id,
        next.seq,
        next.created_at_ms,
        change.kind,
        &next.previous_version_id,
        change.changed,
    );
    tx.execute(
        "INSERT INTO sekai_dataset_versions
         (dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
          restored_from_version_id, row_count, purged, kind, layout)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,'span')",
        params![
            dataset_id,
            version_id,
            next.seq,
            next.created_at_ms,
            meta.actor,
            meta.tenant,
            meta.reason,
            meta.restored_from_version_id,
            row_count,
            change.kind
        ],
    )
    .map_err(|error| error.to_string())?;
    let version = DatasetVersion {
        dataset_id: dataset_id.into(),
        version_id,
        seq: next.seq,
        created_at_ms: next.created_at_ms,
        actor: meta.actor.into(),
        tenant: meta.tenant.into(),
        reason: meta.reason.into(),
        restored_from_version_id: meta.restored_from_version_id.into(),
        row_count,
        purged: false,
    };
    crate::sekai::dataset_health::judge_after_write_sqlite(
        tx,
        dataset_id,
        &version,
        next.created_at_ms,
    )?;
    prune_dataset_versions_tx(tx, dataset_id)?;
    Ok(version)
}

fn prune_dataset_versions_tx(tx: &Transaction<'_>, dataset_id: &str) -> Result<(), String> {
    let retain: i32 = tx
        .query_row(
            "SELECT retain_count FROM sekai_dataset_version_policy WHERE dataset_id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .unwrap_or(0);
    if retain <= 0 {
        return Ok(());
    }
    let max_seq: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM sekai_dataset_versions WHERE dataset_id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let cutoff = max_seq - i64::from(retain);
    if cutoff < 1 {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM sekai_dataset_version_rows
         WHERE dataset_id = ?1 AND version_id IN (
            SELECT version_id FROM sekai_dataset_versions
            WHERE dataset_id = ?1 AND seq <= ?2
              AND version_id != COALESCE((
                SELECT last_healthy_version_id FROM sekai_dataset_health_state
                WHERE dataset_id = ?1
              ), '')
              AND version_id NOT IN (
                SELECT base_version_id FROM sekai_dataset_branches WHERE dataset_id = ?1
              )
         )",
        params![dataset_id, cutoff],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "UPDATE sekai_dataset_versions SET purged = 1
         WHERE dataset_id = ?1 AND seq <= ?2
           AND version_id != COALESCE((
             SELECT last_healthy_version_id FROM sekai_dataset_health_state
             WHERE dataset_id = ?1
           ), '')
           AND version_id NOT IN (
             SELECT base_version_id FROM sekai_dataset_branches WHERE dataset_id = ?1
           )",
        params![dataset_id, cutoff],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(PURGE_UNCOVERED_SPANS_SQLITE, params![dataset_id])
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn mark_consuming_transform_outputs_stale_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    cause_ref: &str,
    now_ms: i64,
) -> Result<(), String> {
    let table: Option<String> = tx
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sekai_governed_transform'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if table.is_none() {
        return Ok(());
    }
    let definitions: Vec<String> = {
        let mut stmt = tx
            .prepare("SELECT definition_json FROM sekai_governed_transform")
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    for json in definitions {
        let transform: crate::sekai::governed_transform::GovernedTransform =
            serde_json::from_str(&json).map_err(|error| error.to_string())?;
        if !transform.consumes_dataset(dataset_id) && transform.output_dataset_id != dataset_id {
            continue;
        }
        tx.execute(
            "INSERT INTO sekai_transform_output_state
             (namespace, dataset_id, freshness, upstream_version, blocked_run_id, updated_at_ms)
             VALUES (?1, ?2, 'stale', ?3, '', ?4)
             ON CONFLICT(namespace, dataset_id) DO UPDATE SET
                freshness = 'stale',
                upstream_version = excluded.upstream_version,
                blocked_run_id = '',
                updated_at_ms = excluded.updated_at_ms",
            params![
                transform.namespace,
                transform.output_dataset_id,
                cause_ref,
                now_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_governed_transform_checkpoint
             WHERE namespace = ?1 AND transform_id = ?2",
            params![transform.namespace, transform.transform_id],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// The rollback of [`SekaiDb::rollback_dataset`] inside the caller's
/// immediate transaction, so it commits together with other writes. The
/// caller commits on success and rolls back on any error.
pub(crate) fn rollback_dataset_tx(
    tx: &rusqlite::Transaction<'_>,
    request: &DatasetRollback,
) -> Result<DatasetVersion, String> {
    let restored =
        get_dataset_version_tx(tx, &request.dataset_id, &request.restore_from_version_id, 0)?;
    if restored.purged {
        return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
    }
    // Checked inside the rollback transaction, so it holds for the write.
    let backing_index: Option<(String, String)> = tx
        .query_row(
            "SELECT namespace, kind FROM sekai_object_type_datasource
             WHERE dataset_id = ?1 AND edits_only = 0
             ORDER BY namespace, kind LIMIT 1",
            params![request.dataset_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if let Some((namespace, kind)) = backing_index {
        return Err(dataset_version::rollback_backs_index_error(
            &namespace, &kind,
        ));
    }
    tx.execute(
        "DELETE FROM sekai_dataset_rows WHERE dataset_id = ?1",
        params![request.dataset_id],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_dataset_rows (dataset_id, data, partition_key)
         SELECT dataset_id, data, partition_key FROM sekai_dataset_version_content
         WHERE dataset_id = ?1 AND version_id = ?2
         ORDER BY row_id",
        params![request.dataset_id, restored.version_id],
    )
    .map_err(|error| error.to_string())?;
    let keys_json: String = tx
        .query_row(
            "SELECT partition_keys FROM sekai_datasets WHERE id = ?1",
            params![request.dataset_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    reindex_dataset_partition_keys(tx, &request.dataset_id, &parse_partition_keys(&keys_json)?)?;
    mark_consuming_transform_outputs_stale_tx(
        tx,
        &request.dataset_id,
        &restored.version_id,
        dataset_version::now_ms(),
    )?;
    let version = snapshot_dataset_version_tx(
        tx,
        &request.dataset_id,
        &request.actor,
        &request.tenant,
        &request.reason,
        &restored.version_id,
        dataset_version::now_ms(),
    )?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    /// #3361: an append that overlaps another connection's write waits for
    /// it within the busy timeout instead of failing with "database is
    /// locked" when its read snapshot goes stale.
    #[test]
    fn an_append_waits_for_another_connections_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append-wait.db");
        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        db.create_dataset(&Dataset {
            id: "a".into(),
            name: "a".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        let writer = rusqlite::Connection::open(&path).unwrap();
        writer
            .execute_batch("BEGIN IMMEDIATE; CREATE TABLE other_write (id INTEGER);")
            .unwrap();
        // The writer commits while the append is waiting on its lock, which
        // leaves a deferred transaction's read snapshot stale.
        let committer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            writer.execute_batch("COMMIT").unwrap();
        });
        let rows = vec![HashMap::from([("v".to_string(), "1".to_string())])];
        let appended = db.append_rows("a", &rows);
        committer.join().unwrap();
        assert_eq!(appended, Ok(1));
    }

    #[test]
    fn interleaved_appends_return_only_their_own_row_ids() {
        let db = setup();
        for id in ["a", "b"] {
            db.create_dataset(&Dataset {
                id: id.into(),
                name: id.into(),
                columns: Vec::new(),
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        }
        let rows = |n: usize| vec![HashMap::from([("v".to_string(), "1".to_string())]); n];
        let append = |dataset: &str, n: usize| {
            let mut conn = db.conn();
            let tx = conn.transaction().unwrap();
            let range = append_rows_tx(&tx, dataset, &rows(n)).unwrap();
            tx.commit().unwrap();
            range
        };
        let ids_in = |dataset: &str, (from, to): (i64, i64)| -> Vec<String> {
            db.conn()
                .prepare("SELECT dataset_id FROM sekai_dataset_rows WHERE id BETWEEN ?1 AND ?2")
                .unwrap()
                .query_map(params![from, to], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .filter(|owner: &String| owner != dataset)
                .collect()
        };

        let first_a = append("a", 2);
        let first_b = append("b", 3);
        let second_a = append("a", 2);

        assert_eq!(first_a, (1, 2));
        assert_eq!(first_b, (3, 5));
        assert_eq!(second_a, (6, 7));
        for (dataset, range) in [("a", first_a), ("b", first_b), ("a", second_a)] {
            assert!(ids_in(dataset, range).is_empty(), "{dataset} {range:?}");
        }
    }

    #[test]
    fn test_dataset_crud_and_rows() {
        let db = setup();
        let ds = Dataset {
            id: "ds1".into(),
            name: "metrics".into(),
            columns: vec![
                ColumnDef {
                    name: "ts".into(),
                    col_type: "int".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "val".into(),
                    col_type: "float".into(),
                    classification: "public".into(),
                },
            ],
            object_id: "".into(),
            created: 100,
            partition_keys: Vec::new(),
        };
        db.create_dataset(&ds).unwrap();

        let got = db.get_dataset("ds1").unwrap().unwrap();
        assert_eq!(got.name, "metrics");
        assert_eq!(got.columns.len(), 2);

        let rows = vec![
            HashMap::from([("ts".into(), "1".into()), ("val".into(), "10.5".into())]),
            HashMap::from([("ts".into(), "2".into()), ("val".into(), "20.0".into())]),
            HashMap::from([("ts".into(), "3".into()), ("val".into(), "5.0".into())]),
        ];
        db.append_rows("ds1", &rows).unwrap();

        let records = db.list_dataset_row_records("ds1").unwrap();
        assert_eq!(records.len(), 3);
        let after_first = db
            .list_dataset_row_records_after("ds1", records[0].0)
            .unwrap();
        assert_eq!(
            after_first.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![records[1].0, records[2].0]
        );

        let all = db.query_rows("ds1", &RowQuery::default()).unwrap();
        assert_eq!(all.len(), 3);

        let filtered = db
            .query_rows(
                "ds1",
                &RowQuery {
                    filters: vec![RowFilter {
                        column: "val".into(),
                        op: "gt".into(),
                        value: "8".into(),
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(filtered.len(), 2);

        let projected = db
            .query_rows(
                "ds1",
                &RowQuery {
                    columns: vec!["val".into()],
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(projected[0].contains_key("val") && !projected[0].contains_key("ts"));
    }

    #[test]
    fn update_dataset_reindexes_row_partition_keys() {
        let db = setup();
        let mut dataset = Dataset {
            id: "ds1".into(),
            name: "metrics".into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "region".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        };
        db.create_dataset(&dataset).unwrap();
        db.append_rows(
            "ds1",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("region".into(), "east".into()),
            ])],
        )
        .unwrap();
        dataset.partition_keys = vec!["region".into()];
        db.update_dataset(&dataset).unwrap();
        let key: String = db
            .conn()
            .query_row(
                "SELECT partition_key FROM sekai_dataset_rows WHERE dataset_id = 'ds1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(key, "east");
    }

    #[test]
    fn redact_dataset_fields_rewrites_partition_key() {
        let db = setup();
        db.create_dataset(&Dataset {
            id: "ds1".into(),
            name: "metrics".into(),
            columns: vec![ColumnDef {
                name: "region".into(),
                col_type: "string".into(),
                classification: "sensitive".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: vec!["region".into()],
        })
        .unwrap();
        db.append_rows("ds1", &[HashMap::from([("region".into(), "east".into())])])
            .unwrap();
        assert_eq!(db.list_dataset_versions("ds1").unwrap().len(), 1);
        db.redact_dataset_fields("ds1", "sensitive", &[]).unwrap();
        let versions = db.list_dataset_versions("ds1").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[1].reason, "redaction");
        let key: String = db
            .conn()
            .query_row(
                "SELECT partition_key FROM sekai_dataset_rows WHERE dataset_id = 'ds1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(key, "[redacted]");
        let version_key: String = db
            .conn()
            .query_row(
                "SELECT partition_key FROM sekai_dataset_version_content WHERE dataset_id = 'ds1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version_key, "[redacted]");
    }

    const SPANS: &str = "srcds:spans";

    fn row(key: &str, kind: &str) -> HashMap<String, String> {
        HashMap::from([
            ("source_id".into(), key.into()),
            ("kind".into(), kind.into()),
        ])
    }

    /// A source dataset as release N left it: live rows {a, b} and two
    /// `copy` versions, {a} then {a, b}.
    fn copy_dataset(db: &SekaiDb) {
        db.create_dataset(&Dataset {
            id: SPANS.into(),
            name: "spans".into(),
            columns: vec![ColumnDef {
                name: "kind".into(),
                col_type: "string".into(),
                classification: "sensitive".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        let conn = db.conn();
        for (seq, key) in [(1i64, "a"), (2, "b")] {
            let data = serde_json::to_string(&row(key, key)).unwrap();
            conn.execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data) VALUES (?1, ?2)",
                params![SPANS, data],
            )
            .unwrap();
            let version_id = format!("copy-{seq}");
            conn.execute(
                "INSERT INTO sekai_dataset_versions
                 (dataset_id, version_id, seq, created_at_ms, row_count)
                 VALUES (?1, ?2, ?3, ?3, ?3)",
                params![SPANS, version_id, seq],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sekai_dataset_version_rows (dataset_id, version_id, row_id, data)
                 SELECT dataset_id, ?2, id, data FROM sekai_dataset_rows WHERE dataset_id = ?1",
                params![SPANS, version_id],
            )
            .unwrap();
        }
    }

    fn land(db: &SekaiDb, rows: &[HashMap<String, String>]) -> DatasetVersion {
        {
            let mut conn = db.conn();
            let tx = conn.transaction().unwrap();
            land_source_rows_tx(&tx, SPANS, rows).unwrap();
            tx.commit().unwrap();
        }
        db.list_dataset_versions(SPANS).unwrap().pop().unwrap()
    }

    fn kinds(db: &SekaiDb, version_id: &str) -> Vec<String> {
        db.load_dataset_version(SPANS, version_id, 0)
            .unwrap()
            .1
            .into_iter()
            .map(|row| row["kind"].clone())
            .collect()
    }

    fn version_kind(db: &SekaiDb, version_id: &str) -> (String, String) {
        db.conn()
            .query_row(
                "SELECT kind, layout FROM sekai_dataset_versions
                 WHERE dataset_id = ?1 AND version_id = ?2",
                params![SPANS, version_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    /// Lands two batches after the upgrade: 3 appends c, 4 replaces b with
    /// b2. Returns the latest `copy` version and both `span` versions.
    fn span_versions(db: &SekaiDb) -> (String, String, String) {
        copy_dataset(db);
        let appended = land(db, &[row("c", "c")]).version_id;
        // One batch naming b twice lands its last row.
        let updated = land(db, &[row("b", "b1"), row("b", "b2")]).version_id;
        ("copy-2".into(), appended, updated)
    }

    #[test]
    fn span_versions_read_their_computed_content_through_every_reader() {
        let db = setup();
        let (copy, appended, updated) = span_versions(&db);
        assert_eq!(kinds(&db, &copy), ["a", "b"]);
        assert_eq!(kinds(&db, "copy-1"), ["a"]);
        assert_eq!(kinds(&db, &appended), ["a", "b", "c"]);
        assert_eq!(kinds(&db, &updated), ["a", "c", "b2"]);
        assert_eq!(
            version_kind(&db, &appended),
            ("append".into(), "span".into())
        );
        assert_eq!(
            version_kind(&db, &updated),
            ("update".into(), "span".into())
        );
        // The replaced row leaves the live rows too, so they equal the latest
        // version.
        let live: Vec<String> = db
            .list_dataset_row_records(SPANS)
            .unwrap()
            .into_iter()
            .map(|(_, row)| row["kind"].clone())
            .collect();
        assert_eq!(live, kinds(&db, &updated));
        let version = db.get_dataset_version(SPANS, &updated, 0).unwrap();
        assert_eq!(version.row_count, 3);
        // Paging keeps row ids in order across shared spans.
        let page = db
            .load_dataset_version_page(SPANS, &updated, 0, None, 1)
            .unwrap()
            .1;
        let next = db
            .load_dataset_version_page(SPANS, &updated, 0, Some(page[0].0), 10)
            .unwrap()
            .1;
        assert_eq!(page.len() + next.len(), 4);
        // Rollback to a span version restores its content as live rows.
        let restored = db
            .rollback_dataset(&DatasetRollback {
                dataset_id: SPANS.into(),
                restore_from_version_id: appended.clone(),
                reason: "restore".into(),
                actor: "tester".into(),
                tenant: String::new(),
            })
            .unwrap();
        assert_eq!(kinds(&db, &restored.version_id), ["a", "b", "c"]);
        // A pinned replay of the older span version still reads its rows.
        assert_eq!(kinds(&db, &appended), ["a", "b", "c"]);
    }

    #[test]
    fn erasure_and_redaction_rewrite_a_shared_span_once() {
        let db = setup();
        let (copy, appended, updated) = span_versions(&db);
        {
            let mut conn = db.conn();
            let tx = conn.transaction().unwrap();
            erase_matching_dataset_version_rows_tx(&tx, SPANS, &|row| row["kind"] == "c").unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(kinds(&db, &appended), ["a", "b"]);
        assert_eq!(kinds(&db, &updated), ["a", "b2"]);
        assert_eq!(
            db.get_dataset_version(SPANS, &updated, 0)
                .unwrap()
                .row_count,
            2
        );

        db.redact_dataset_fields(SPANS, "sensitive", &[]).unwrap();
        for version_id in [&copy, &appended, &updated] {
            assert!(
                kinds(&db, version_id)
                    .iter()
                    .all(|kind| kind == "[redacted]"),
                "{version_id}"
            );
        }
        let spans: (i64, i64) = db
            .conn()
            .query_row(
                "SELECT SUM(from_seq <= 4), SUM(from_seq > 4) FROM sekai_dataset_row_spans
                 WHERE dataset_id = 'srcds:spans'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            spans,
            (3, 3),
            "a, b (closed), b2 are rewritten, never copied; the redaction version \
             opens the live a, c, b2"
        );
    }

    #[test]
    fn purge_keeps_spans_a_retained_version_covers() {
        let db = setup();
        let (_, appended, updated) = span_versions(&db);
        // Keep only the newest version: b's closed span (3..4) is covered
        // by no retained version, and goes. Open spans stay.
        db.set_dataset_version_retention(SPANS, 1).unwrap();
        let error = db.get_dataset_version(SPANS, &appended, 0).unwrap_err();
        assert!(error.contains("past retention"), "{error}");
        assert_eq!(kinds(&db, &updated), ["a", "c", "b2"]);
        let closed: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_dataset_row_spans
                 WHERE dataset_id = 'srcds:spans' AND to_seq IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(closed, 0);
    }

    #[test]
    fn source_key_lookup_reads_the_spans_live_at_a_span_version() {
        let db = setup();
        let conn = db.conn();
        // Key k: row 1 live in 1..2, its replacement row 2 from 2; row 3 is
        // another key. Version 1 sees row 1, version 2 sees row 2.
        conn.execute_batch(
            "INSERT INTO sekai_dataset_row_spans (dataset_id, row_id, from_seq, to_seq, data) VALUES
               ('srcds:t', 1, 1, 2, '{\"source_id\":\"k\",\"v\":\"old\"}'),
               ('srcds:t', 2, 2, NULL, '{\"source_id\":\"k\",\"v\":\"new\"}'),
               ('srcds:t', 3, 1, NULL, '{\"source_id\":\"other\"}');
             INSERT INTO sekai_dataset_versions
               (dataset_id, version_id, seq, created_at_ms, row_count, kind, layout) VALUES
               ('srcds:t', 'v1', 1, 1, 2, 'snapshot', 'span'),
               ('srcds:t', 'v2', 2, 2, 2, 'update', 'span');",
        )
        .unwrap();
        let lookup = |version: &str| -> Option<String> {
            conn.query_row(
                LATEST_SOURCE_VERSION_ROW_SQL,
                params!["srcds:t", version, "k"],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
        };
        assert!(lookup("v1").unwrap().contains("old"));
        assert!(lookup("v2").unwrap().contains("new"));
        assert_eq!(lookup("missing"), None);
    }

    #[test]
    fn set_version_retention_prunes_immediately() {
        let db = setup();
        db.create_dataset(&Dataset {
            id: "retain".into(),
            name: "retain".into(),
            columns: vec![ColumnDef {
                name: "kind".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        for kind in ["v1", "v2", "v3"] {
            db.append_rows("retain", &[HashMap::from([("kind".into(), kind.into())])])
                .unwrap();
        }
        let first = db.list_dataset_versions("retain").unwrap()[0].clone();
        db.set_dataset_version_retention("retain", 2).unwrap();
        let error = db
            .get_dataset_version("retain", &first.version_id, 0)
            .unwrap_err();
        assert!(error.contains("past retention"), "{error}");
    }

    #[test]
    fn query_rows_rejects_corrupt_stored_json() {
        let db = setup();
        db.create_dataset(&Dataset {
            id: "corrupt".into(),
            name: "corrupt".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data) VALUES (?1, ?2)",
                rusqlite::params!["corrupt", "not-json"],
            )
            .unwrap();

        let error = db.query_rows("corrupt", &RowQuery::default()).unwrap_err();

        assert!(error.contains("corrupt dataset row for \"corrupt\""));
    }

    #[test]
    fn get_dataset_rejects_corrupt_column_metadata() {
        let db = setup();
        db.conn()
            .execute(
                "INSERT INTO sekai_datasets (id,name,columns,object_id,created)
                 VALUES ('bad-cols','bad','not-json','',1)",
                [],
            )
            .unwrap();

        let error = db.get_dataset("bad-cols").unwrap_err();
        assert!(error.contains("corrupt dataset columns"), "{error}");
        let list_error = db.list_datasets().unwrap_err();
        assert!(
            list_error.contains("corrupt dataset columns"),
            "{list_error}"
        );
    }

    #[test]
    fn numeric_filters_do_not_treat_non_numeric_as_zero() {
        let db = setup();
        db.create_dataset(&Dataset {
            id: "nums".into(),
            name: "nums".into(),
            columns: vec![ColumnDef {
                name: "val".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        db.append_rows("nums", &[HashMap::from([("val".into(), "N/A".into())])])
            .unwrap();

        let matched = db
            .query_rows(
                "nums",
                &RowQuery {
                    filters: vec![RowFilter {
                        column: "val".into(),
                        op: "lt".into(),
                        value: "10".into(),
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            matched.is_empty(),
            "non-numeric cells must not match lt via 0.0"
        );
    }

    #[test]
    fn list_virtual_tables_rejects_corrupt_filters() {
        let db = setup();
        db.conn()
            .execute(
                "INSERT INTO sekai_virtual_tables (id,name,dataset_id,filters,columns,created)
                 VALUES ('vt1','vt1','ds1','not-json','[]',1)",
                [],
            )
            .unwrap();

        let error = db.list_virtual_tables().unwrap_err();
        assert!(error.contains("corrupt virtual table filters"), "{error}");
    }

    #[test]
    fn update_dataset_preserves_rows_and_creation_time() {
        let db = setup();
        let mut dataset = Dataset {
            id: "ds1".into(),
            name: "old name".into(),
            columns: vec![ColumnDef {
                name: "old_column".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: "object-a".into(),
            created: 100,
            partition_keys: Vec::new(),
        };
        db.create_dataset(&dataset).unwrap();
        db.append_rows(
            "ds1",
            &[HashMap::from([("old_column".into(), "value".into())])],
        )
        .unwrap();

        dataset.name = "new name".into();
        dataset.columns.push(ColumnDef {
            name: "new_column".into(),
            col_type: "string".into(),
            classification: "public".into(),
        });
        dataset.object_id = "object-b".into();
        dataset.created = 999;
        db.update_dataset(&dataset).unwrap();

        let updated = db.get_dataset("ds1").unwrap().unwrap();
        assert_eq!(updated.name, "new name");
        assert_eq!(updated.columns.len(), 2);
        assert_eq!(updated.object_id, "object-a");
        assert_eq!(updated.created, 100);
        assert_eq!(
            db.query_rows("ds1", &RowQuery::default()).unwrap(),
            vec![HashMap::from([("old_column".into(), "value".into())])]
        );
    }

    #[test]
    fn loads_legacy_dataset_columns_as_public() {
        let db = setup();
        db.conn()
            .execute(
                "INSERT INTO sekai_datasets (id,name,columns,object_id,created)
                 VALUES ('legacy','legacy','[[\"value\",\"string\"]]','',1)",
                [],
            )
            .unwrap();

        let dataset = db.get_dataset("legacy").unwrap().unwrap();
        assert_eq!(dataset.columns[0].classification, "public");
    }

    #[test]
    fn migrates_legacy_llm_call_column_classifications() {
        let db = setup();
        db.conn()
            .execute(
                "INSERT INTO sekai_datasets (id,name,columns,object_id,created)
                 VALUES ('llm_calls','calls','[[\"user_id\",\"string\"],[\"status\",\"string\"]]','',1)",
                [],
            )
            .unwrap();
        db.migrate_datasets().unwrap();

        let dataset = db.get_dataset("llm_calls").unwrap().unwrap();
        assert_eq!(dataset.columns[0].classification, "sensitive");
        assert_eq!(dataset.columns[1].classification, "public");
        let data_class = dataset
            .columns
            .iter()
            .find(|column| column.name == "data_class")
            .unwrap();
        assert_eq!(data_class.col_type, "string");
        assert_eq!(data_class.classification, "public");
    }

    #[test]
    fn migrate_datasets_can_run_twice_on_an_upgraded_database() {
        let db = setup();
        db.migrate_datasets().unwrap();
        db.migrate_datasets().unwrap();
        let datasets_sql: String = db
            .conn()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sekai_datasets'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let rows_sql: String = db
            .conn()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sekai_dataset_rows'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(datasets_sql.contains("partition_keys"), "{datasets_sql}");
        assert!(rows_sql.contains("partition_key"), "{rows_sql}");
        let index: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name = 'idx_dataset_rows_partition'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index, 1);
    }

    #[test]
    fn migrate_datasets_returns_partition_index_errors() {
        let db = setup();
        db.conn()
            .execute_batch(
                "DROP INDEX idx_dataset_rows_partition;
                 CREATE TABLE idx_dataset_rows_partition (x TEXT);",
            )
            .unwrap();
        let error = db.migrate_datasets().unwrap_err();
        assert!(
            error.contains("there is already a table named idx_dataset_rows_partition"),
            "{error}"
        );
    }

    /// Redaction reads columns under the dataset write lock (#2821). A
    /// writer holding that lock reclassifies `identity` as sensitive and
    /// drops `note`; the redaction that waited on it redacts `identity` and
    /// refuses a filter on `note`.
    fn redaction_reads_columns_under_the_lock(
        db: &crate::db::runtime_db::RuntimeDb,
        dataset_id: &str,
        hold: impl Fn(&str) -> Box<dyn FnOnce() + Send>,
    ) {
        use crate::db::runtime_db::RuntimeDb;
        let column = |name: &str, classification: &str| ColumnDef {
            name: name.into(),
            col_type: "string".into(),
            classification: classification.into(),
        };
        db.create_dataset(&Dataset {
            id: dataset_id.into(),
            name: dataset_id.into(),
            columns: vec![
                column("namespace", "public"),
                column("identity", "public"),
                column("note", "public"),
            ],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        db.append_rows(
            dataset_id,
            &[HashMap::from([
                ("namespace".into(), "ops".into()),
                ("identity".into(), "alice".into()),
                ("note".into(), "n".into()),
            ])],
        )
        .unwrap();
        let reclassified = r#"[["namespace","string","public"],["identity","string","sensitive"]]"#;
        let filter = |column: &str| RowFilter {
            column: column.into(),
            op: "eq".into(),
            value: "ops".into(),
        };
        for (filters, expect_refused) in [
            (vec![filter("note")], true),
            (vec![filter("namespace")], false),
        ] {
            let release = hold(reclassified);
            let result = std::thread::scope(|scope| {
                let redaction = scope.spawn(|| match db {
                    RuntimeDb::Sqlite(sqlite) => {
                        sqlite.redact_dataset_fields(dataset_id, "sensitive", &filters)
                    }
                    RuntimeDb::Postgres(postgres) => {
                        postgres.redact_dataset_fields(dataset_id, "sensitive", &filters)
                    }
                });
                std::thread::sleep(std::time::Duration::from_millis(300));
                assert!(!redaction.is_finished(), "the redaction waits for the lock");
                release();
                redaction.join().unwrap()
            });
            if expect_refused {
                let error = result.unwrap_err();
                assert!(error.contains("unknown filter column: note"), "{error}");
            } else {
                assert_eq!(result.unwrap().fields_redacted, 1);
                let rows = db.query_rows(dataset_id, &Default::default()).unwrap();
                assert_eq!(rows[0]["identity"], "[redacted]");
            }
        }
    }

    #[test]
    fn sqlite_redaction_reads_columns_under_the_lock() {
        let path = std::env::temp_dir().join(format!(
            "sekai-redaction-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let path = path.to_str().unwrap().to_string();
        let db = crate::db::runtime_db::RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(&path).unwrap(),
        ));
        redaction_reads_columns_under_the_lock(&db, "reclassified", |columns| {
            let writer = rusqlite::Connection::open(&path).unwrap();
            writer.execute_batch("BEGIN IMMEDIATE").unwrap();
            writer
                .execute(
                    "UPDATE sekai_datasets SET columns=?1 WHERE id='reclassified'",
                    params![columns],
                )
                .unwrap();
            Box::new(move || writer.execute_batch("COMMIT").unwrap())
        });
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_redaction_reads_columns_under_the_lock() {
        let db = crate::sekai::work_claim_conformance::postgres();
        let crate::db::runtime_db::RuntimeDb::Postgres(postgres) = &db else {
            unreachable!()
        };
        let dataset_id = format!("reclassified-{}", uuid::Uuid::new_v4().simple());
        redaction_reads_columns_under_the_lock(&db, &dataset_id, |columns| {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let postgres = postgres.clone();
            let dataset_id = dataset_id.clone();
            let columns = columns.to_string();
            let holder = std::thread::spawn(move || {
                let mut connection = postgres.connection().unwrap();
                let mut tx = connection.transaction().unwrap();
                crate::db::postgres::lock_dataset_rows(&mut tx, &dataset_id).unwrap();
                tx.execute(
                    "UPDATE sekai_datasets SET columns=$1 WHERE id=$2",
                    &[&columns, &dataset_id],
                )
                .unwrap();
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                tx.commit().unwrap();
            });
            ready_rx.recv().unwrap();
            Box::new(move || {
                release_tx.send(()).unwrap();
                holder.join().unwrap();
            })
        });
    }

    #[test]
    fn redacts_only_matching_classified_dataset_fields() {
        let db = setup();
        db.create_dataset(&Dataset {
            id: "classified".into(),
            name: "classified".into(),
            columns: vec![
                ColumnDef {
                    name: "namespace".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "identity".into(),
                    col_type: "string".into(),
                    classification: "sensitive".into(),
                },
                ColumnDef {
                    name: "metric".into(),
                    col_type: "int".into(),
                    classification: "public".into(),
                },
            ],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        db.append_rows(
            "classified",
            &[
                HashMap::from([
                    ("namespace".into(), "redact".into()),
                    ("identity".into(), "alice".into()),
                    ("metric".into(), "1".into()),
                ]),
                HashMap::from([
                    ("namespace".into(), "keep".into()),
                    ("identity".into(), "bob".into()),
                    ("metric".into(), "2".into()),
                ]),
            ],
        )
        .unwrap();

        let error = db
            .redact_dataset_fields(
                "classified",
                "sensitive",
                &[RowFilter {
                    column: "namespace".into(),
                    op: "contains".into(),
                    value: "redact".into(),
                }],
            )
            .unwrap_err();
        assert!(error.contains("unsupported filter operator"));

        let result = db
            .redact_dataset_fields(
                "classified",
                "sensitive",
                &[RowFilter {
                    column: "namespace".into(),
                    op: "eq".into(),
                    value: "redact".into(),
                }],
            )
            .unwrap();
        assert_eq!(result.rows_updated, 1);
        assert_eq!(result.fields_redacted, 1);
        let rows = db.query_rows("classified", &RowQuery::default()).unwrap();
        assert_eq!(rows[0]["identity"], "[redacted]");
        assert_eq!(rows[0]["metric"], "1");
        assert_eq!(rows[1]["identity"], "bob");
        assert_eq!(
            db.redact_dataset_fields("classified", "sensitive", &[])
                .unwrap()
                .rows_updated,
            1
        );
    }

    #[test]
    fn test_virtual_table() {
        let db = setup();
        let ds = Dataset {
            id: "ds1".into(),
            name: "t".into(),
            columns: vec![ColumnDef {
                name: "x".into(),
                col_type: "int".into(),
                classification: "public".into(),
            }],
            object_id: "".into(),
            created: 0,
            partition_keys: Vec::new(),
        };
        db.create_dataset(&ds).unwrap();
        db.append_rows(
            "ds1",
            &[
                HashMap::from([("x".into(), "1".into())]),
                HashMap::from([("x".into(), "5".into())]),
                HashMap::from([("x".into(), "10".into())]),
            ],
        )
        .unwrap();

        let vt = VirtualTable {
            id: "vt1".into(),
            name: "high_x".into(),
            dataset_id: "ds1".into(),
            filters: vec![RowFilter {
                column: "x".into(),
                op: "gte".into(),
                value: "5".into(),
            }],
            columns: vec![],
            created: 0,
        };
        db.create_virtual_table(&vt).unwrap();

        let vts = db.list_virtual_tables().unwrap();
        assert_eq!(vts.len(), 1);

        let rows = db.query_virtual_table(&vts[0]).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn row_value_matches_eq_and_numeric_ops() {
        assert!(row_value_matches("3", "gte", "2"));
        assert!(!row_value_matches("1", "gte", "2"));
        assert!(row_value_matches("eu", "eq", "eu"));
        assert!(!row_value_matches("eu", "gt", "ap"));
        assert!(!row_value_matches("3", "contains", "3"));
    }
}

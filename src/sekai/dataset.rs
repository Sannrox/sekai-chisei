use crate::db::sekai::SekaiDb;
use crate::sekai::dataset_version::{self, DatasetRollback, DatasetVersion};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDef {
    pub name: String,
    pub col_type: String,
    pub classification: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatasetRedaction {
    pub rows_updated: i32,
    pub fields_redacted: i32,
}

pub fn llm_call_column_classification(name: &str) -> &'static str {
    if matches!(
        name,
        "request_id" | "agent" | "user_id" | "key_id" | "work_unit_id" | "refusal_reason"
    ) {
        "sensitive"
    } else if matches!(
        name,
        "project" | "route_bias" | "policy_scope" | "policy_version"
    ) {
        "internal"
    } else {
        "public"
    }
}

pub type DatasetRowRecord = (i64, HashMap<String, String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    pub id: String,
    pub name: String,
    pub columns: Vec<ColumnDef>,
    pub object_id: String,
    pub created: i64,
    pub partition_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowFilter {
    pub column: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RowQuery {
    pub filters: Vec<RowFilter>,
    pub columns: Vec<String>,
    pub limit: i32,
    pub offset: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualTable {
    pub id: String,
    pub name: String,
    pub dataset_id: String,
    pub filters: Vec<RowFilter>,
    pub columns: Vec<String>,
    pub created: i64,
}

fn parse_columns(value: &str) -> Result<Vec<ColumnDef>, String> {
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

pub(crate) fn encode_partition_keys(keys: &[String]) -> Result<String, String> {
    serde_json::to_string(keys).map_err(|error| error.to_string())
}

pub(crate) fn parse_partition_keys(value: &str) -> Result<Vec<String>, String> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(value).map_err(|error| format!("corrupt dataset partition_keys: {error}"))
}

pub(crate) fn partition_key_for_row_json(keys: &[String], data: &str) -> Result<String, String> {
    let row: HashMap<String, String> =
        serde_json::from_str(data).map_err(|error| format!("corrupt dataset row: {error}"))?;
    Ok(crate::sekai::governed_transform::partition_value(
        keys, &row,
    ))
}

fn reindex_dataset_partition_keys(
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

fn compare_numeric(left: &str, right: &str, op: &str) -> bool {
    let (Ok(left), Ok(right)) = (left.parse::<f64>(), right.parse::<f64>()) else {
        return false;
    };
    match op {
        "gt" => left > right,
        "lt" => left < right,
        "gte" => left >= right,
        "lte" => left <= right,
        _ => false,
    }
}

/// Shared property compare for dataset rows and object-type index reads.
/// Unknown operators and non-numeric inequalities fail closed (no match).
pub(crate) fn row_value_matches(actual: &str, op: &str, expected: &str) -> bool {
    match op {
        "eq" | "" => actual == expected,
        "neq" => actual != expected,
        "gt" | "lt" | "gte" | "lte" => compare_numeric(actual, expected, op),
        _ => false,
    }
}

impl SekaiDb {
    pub(crate) fn migrate_datasets(&self) -> Result<(), String> {
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
        let _ = conn.execute(
            "ALTER TABLE sekai_datasets ADD COLUMN partition_keys TEXT NOT NULL DEFAULT '[]'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE sekai_dataset_rows ADD COLUMN partition_key TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dataset_rows_partition
             ON sekai_dataset_rows(dataset_id, partition_key)",
            [],
        );
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
        for column in &d.columns {
            if !crate::sekai::schema::is_valid_property_classification(&column.classification) {
                return Err(format!(
                    "column {} has invalid classification: {}",
                    column.name, column.classification
                ));
            }
        }
        let conn = self.conn();
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
        .unwrap();
        conn.execute("INSERT INTO sekai_datasets (id,name,columns,object_id,created,partition_keys) VALUES (?1,?2,?3,?4,?5,?6)",
            params![d.id, d.name, cols, d.object_id, d.created, encode_partition_keys(&d.partition_keys)?]).map_err(|e| e.to_string())?;
        Ok(())
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
        let tx = conn.transaction().map_err(|error| error.to_string())?;
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
        snapshot_dataset_version_tx(&tx, dataset_id, "", "", "", "", dataset_version::now_ms())?;
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

    pub fn rollback_dataset(&self, request: &DatasetRollback) -> Result<DatasetVersion, String> {
        if request.restore_from_version_id.trim().is_empty() {
            return Err(dataset_version::DATASET_ROLLBACK_REQUIRES_RESTORE.into());
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let restored = get_dataset_version_tx(
            &tx,
            &request.dataset_id,
            &request.restore_from_version_id,
            0,
        )?;
        if restored.purged {
            return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
        }
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE dataset_id = ?1",
            params![request.dataset_id],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_dataset_rows (dataset_id, data, partition_key)
             SELECT dataset_id, data, partition_key FROM sekai_dataset_version_rows
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
        reindex_dataset_partition_keys(
            &tx,
            &request.dataset_id,
            &parse_partition_keys(&keys_json)?,
        )?;
        mark_consuming_transform_outputs_stale_tx(
            &tx,
            &request.dataset_id,
            &restored.version_id,
            dataset_version::now_ms(),
        )?;
        let version = snapshot_dataset_version_tx(
            &tx,
            &request.dataset_id,
            &request.actor,
            &request.tenant,
            &request.reason,
            &restored.version_id,
            dataset_version::now_ms(),
        )?;
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
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT data FROM sekai_dataset_rows WHERE dataset_id = ?1")
            .map_err(|e| e.to_string())?;
        let mut rows_iter = stmt.query(params![dataset_id]).map_err(|e| e.to_string())?;
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
        let dataset = self
            .get_dataset(dataset_id)?
            .ok_or_else(|| "dataset not found".to_string())?;
        for filter in filters {
            if !dataset
                .columns
                .iter()
                .any(|column| column.name == filter.column)
            {
                return Err(format!("unknown filter column: {}", filter.column));
            }
            if !matches!(
                filter.op.as_str(),
                "eq" | "neq" | "gt" | "lt" | "gte" | "lte"
            ) {
                return Err(format!("unsupported filter operator: {}", filter.op));
            }
        }
        let fields: Vec<&str> = dataset
            .columns
            .iter()
            .filter(|column| {
                crate::sekai::schema::normalize_property_classification(&column.classification)
                    == classification
            })
            .map(|column| column.name.as_str())
            .collect();
        if fields.is_empty() {
            return Ok(DatasetRedaction::default());
        }

        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let keys_json: String = tx
            .query_row(
                "SELECT partition_keys FROM sekai_datasets WHERE id=?1",
                params![dataset_id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
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

fn matches_row_filters(row: &HashMap<String, String>, filters: &[RowFilter]) -> bool {
    for f in filters {
        let val = match row.get(&f.column) {
            Some(v) => v,
            None => return false,
        };
        let ok = row_value_matches(val, &f.op, &f.value);
        if !ok {
            return false;
        }
    }
    true
}

fn redact_dataset_version_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    filters: &[RowFilter],
    fields: &[&str],
    keys: &[String],
) -> Result<(), String> {
    let rows: Vec<(String, i64, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT version_id, row_id, data FROM sekai_dataset_version_rows
                 WHERE dataset_id = ?1",
            )
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(params![dataset_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    for (version_id, row_id, data) in rows {
        let mut values: HashMap<String, String> =
            serde_json::from_str(&data).map_err(|error| error.to_string())?;
        if !matches_row_filters(&values, filters) {
            continue;
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
            continue;
        }
        let data = serde_json::to_string(&values).map_err(|error| error.to_string())?;
        let partition_key = crate::sekai::governed_transform::partition_value(keys, &values);
        tx.execute(
            "UPDATE sekai_dataset_version_rows SET data = ?1, partition_key = ?2
             WHERE dataset_id = ?3 AND version_id = ?4 AND row_id = ?5",
            params![data, partition_key, dataset_id, version_id, row_id],
        )
        .map_err(|error| error.to_string())?;
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

fn query_dataset_version_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    version_id: &str,
) -> Result<Vec<HashMap<String, String>>, String> {
    let mut stmt = tx
        .prepare(
            "SELECT data FROM sekai_dataset_version_rows
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

pub(crate) fn erase_matching_dataset_version_rows_tx(
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
    let rows: Vec<(String, i64, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT version_id, row_id, data FROM sekai_dataset_version_rows
                 WHERE dataset_id = ?1",
            )
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(params![dataset_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    for (version_id, row_id, data) in rows {
        let values = match serde_json::from_str::<HashMap<String, String>>(&data) {
            Ok(values) => values,
            Err(_) => {
                tx.execute(
                    "DELETE FROM sekai_dataset_version_rows
                     WHERE dataset_id = ?1 AND version_id = ?2 AND row_id = ?3",
                    params![dataset_id, version_id, row_id],
                )
                .map_err(|error| error.to_string())?;
                continue;
            }
        };
        if !matches(&values) {
            continue;
        }
        tx.execute(
            "DELETE FROM sekai_dataset_version_rows
             WHERE dataset_id = ?1 AND version_id = ?2 AND row_id = ?3",
            params![dataset_id, version_id, row_id],
        )
        .map_err(|error| error.to_string())?;
    }
    tx.execute(
        "UPDATE sekai_dataset_versions SET row_count = (
            SELECT COUNT(*) FROM sekai_dataset_version_rows
            WHERE dataset_id = sekai_dataset_versions.dataset_id
              AND version_id = sekai_dataset_versions.version_id
         ) WHERE dataset_id = ?1",
        params![dataset_id],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn get_dataset_version_tx(
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

pub(crate) fn snapshot_dataset_version_tx(
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
    let seq: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM sekai_dataset_versions WHERE dataset_id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let prev_ms: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(created_at_ms), 0) FROM sekai_dataset_versions WHERE dataset_id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let created_at_ms = created_at_ms.max(prev_ms.saturating_add(1));
    let row_jsons: Vec<(i64, String, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT id, data, COALESCE(partition_key, '') FROM sekai_dataset_rows
                 WHERE dataset_id = ?1 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(params![dataset_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    let jsons: Vec<String> = row_jsons.iter().map(|(_, data, _)| data.clone()).collect();
    let version_id = dataset_version::version_id(dataset_id, seq, created_at_ms, &jsons);
    let row_count =
        i32::try_from(row_jsons.len()).map_err(|_| "too many dataset rows".to_string())?;
    tx.execute(
        "INSERT INTO sekai_dataset_versions
         (dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
          restored_from_version_id, row_count, purged)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
        params![
            dataset_id,
            version_id,
            seq,
            created_at_ms,
            actor,
            tenant,
            reason,
            restored_from_version_id,
            row_count
        ],
    )
    .map_err(|error| error.to_string())?;
    for (row_id, data, partition_key) in &row_jsons {
        tx.execute(
            "INSERT INTO sekai_dataset_version_rows
             (dataset_id, version_id, row_id, data, partition_key)
             VALUES (?1,?2,?3,?4,?5)",
            params![dataset_id, version_id, row_id, data, partition_key],
        )
        .map_err(|error| error.to_string())?;
    }
    prune_dataset_versions_tx(tx, dataset_id)?;
    Ok(DatasetVersion {
        dataset_id: dataset_id.into(),
        version_id,
        seq,
        created_at_ms,
        actor: actor.into(),
        tenant: tenant.into(),
        reason: reason.into(),
        restored_from_version_id: restored_from_version_id.into(),
        row_count,
        purged: false,
    })
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
         )",
        params![dataset_id, cutoff],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "UPDATE sekai_dataset_versions SET purged = 1
         WHERE dataset_id = ?1 AND seq <= ?2",
        params![dataset_id, cutoff],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn mark_consuming_transform_outputs_stale_tx(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
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
                "SELECT partition_key FROM sekai_dataset_version_rows WHERE dataset_id = 'ds1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version_key, "[redacted]");
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

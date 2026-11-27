use crate::db::postgres::{PostgresDb, lock_dataset_rows};
use crate::sekai::dataset::{
    ColumnDef, Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable,
};
use crate::sekai::dataset_version::{self, DatasetRollback, DatasetVersion};
use postgres::IsolationLevel;
use std::collections::HashMap;

/// Newest live row of one source key; `LIKE 'srcds:%'` matches the partial
/// index `idx_dataset_rows_source_key` (migration 0176).
pub(crate) const LATEST_SOURCE_ROW_SQL: &str = "SELECT data FROM sekai_dataset_rows
     WHERE dataset_id LIKE 'srcds:%' AND dataset_id=$1
       AND (data::jsonb)->>'source_id' = $2
     ORDER BY id DESC LIMIT 1";
/// Newest row of one source key in one retained version. A version has one
/// layout, so at most one branch answers: a `copy` version seeks
/// `idx_dataset_version_rows_source_key`, a `span` version seeks
/// `idx_dataset_row_spans_source_key` and keeps the spans live at its seq.
pub(crate) const LATEST_SOURCE_VERSION_ROW_SQL: &str =
    "(SELECT data FROM sekai_dataset_version_rows
       WHERE dataset_id LIKE 'srcds:%' AND dataset_id=$1 AND version_id=$2
         AND (data::jsonb)->>'source_id' = $3
       ORDER BY row_id DESC LIMIT 1)
     UNION ALL
     (SELECT s.data FROM sekai_dataset_versions v
       JOIN sekai_dataset_row_spans s
         ON s.dataset_id = v.dataset_id
        AND s.from_seq <= v.seq AND (s.to_seq IS NULL OR s.to_seq > v.seq)
       WHERE v.dataset_id=$1 AND v.version_id=$2
         AND v.layout = 'span' AND v.purged = 0
         AND s.dataset_id LIKE 'srcds:%' AND s.dataset_id=$1
         AND (s.data::jsonb)->>'source_id' = $3
       ORDER BY s.row_id DESC LIMIT 1)
     LIMIT 1";

impl PostgresDb {
    pub fn create_dataset(&self, dataset: &Dataset) -> Result<(), String> {
        validate_columns(&dataset.columns)?;
        let columns = encode_columns(&dataset.columns)?;
        let partition_keys = crate::sekai::dataset::encode_partition_keys(&dataset.partition_keys)?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_datasets (id,name,columns,object_id,created,partition_keys)
                 VALUES ($1,$2,$3,$4,$5,$6)",
                &[
                    &dataset.id,
                    &dataset.name,
                    &columns,
                    &dataset.object_id,
                    &dataset.created,
                    &partition_keys,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Append the column definitions the dataset lacks, against the
    /// definitions read under the dataset rows lock: a concurrent change to
    /// an existing column is never overwritten (#1693).
    pub fn add_dataset_columns(
        &self,
        dataset_id: &str,
        columns: &[ColumnDef],
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_dataset_rows(&mut tx, dataset_id)?;
        let json: String = tx
            .query_opt(
                "SELECT columns FROM sekai_datasets WHERE id=$1",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0))
            .ok_or_else(|| format!("dataset {dataset_id:?} not found"))?;
        let mut current = crate::sekai::dataset::parse_columns(&json)?;
        let before = current.len();
        for column in columns {
            if !current.iter().any(|defined| defined.name == column.name) {
                current.push(column.clone());
            }
        }
        if current.len() == before {
            return Ok(());
        }
        tx.execute(
            "UPDATE sekai_datasets SET columns=$2 WHERE id=$1",
            &[&dataset_id, &encode_columns(&current)?],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn update_dataset(&self, dataset: &Dataset) -> Result<(), String> {
        validate_columns(&dataset.columns)?;
        let columns = encode_columns(&dataset.columns)?;
        let partition_keys = crate::sekai::dataset::encode_partition_keys(&dataset.partition_keys)?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_dataset_rows(&mut tx, &dataset.id)?;
        let previous_json: Option<String> = tx
            .query_opt(
                "SELECT partition_keys FROM sekai_datasets WHERE id=$1",
                &[&dataset.id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        let Some(previous_json) = previous_json else {
            return Err(format!("dataset {:?} not found", dataset.id));
        };
        let previous = crate::sekai::dataset::parse_partition_keys(&previous_json)?;
        let changed = tx
            .execute(
                "UPDATE sekai_datasets SET name=$2, columns=$3, partition_keys=$4 WHERE id=$1",
                &[&dataset.id, &dataset.name, &columns, &partition_keys],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err(format!("dataset {:?} not found", dataset.id));
        }
        if previous != dataset.partition_keys {
            let rows = tx
                .query(
                    "SELECT id, data FROM sekai_dataset_rows WHERE dataset_id=$1",
                    &[&dataset.id],
                )
                .map_err(|error| error.to_string())?;
            for row in rows {
                let id: i64 = row.get(0);
                let data: String = row.get(1);
                let partition_key = crate::sekai::dataset::partition_key_for_row_json(
                    &dataset.partition_keys,
                    &data,
                )?;
                tx.execute(
                    "UPDATE sekai_dataset_rows SET partition_key=$1 WHERE id=$2",
                    &[&partition_key, &id],
                )
                .map_err(|error| error.to_string())?;
            }
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        self.connection()?
            .query_opt(
                "SELECT id,name,columns,object_id,created,partition_keys FROM sekai_datasets WHERE id=$1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_dataset)
            .transpose()
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        self.connection()?
            .query(
                "SELECT id,name,columns,object_id,created,partition_keys FROM sekai_datasets ORDER BY id",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_dataset)
            .collect()
    }

    pub fn append_dataset_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String> {
        // Nothing appended is no new version, as on SQLite.
        if rows.is_empty() {
            return Ok(0);
        }
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        append_dataset_rows_tx(&mut transaction, dataset_id, rows)?;
        transaction.commit().map_err(|error| error.to_string())?;
        i32::try_from(rows.len()).map_err(|_| "too many dataset rows".into())
    }

    pub fn list_dataset_row_records(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<crate::sekai::dataset::DatasetRowRecord>, String> {
        self.list_dataset_row_records_after(dataset_id, 0)
    }

    pub fn list_dataset_row_records_after(
        &self,
        dataset_id: &str,
        after_id: i64,
    ) -> Result<Vec<crate::sekai::dataset::DatasetRowRecord>, String> {
        self.connection()?
            .query(
                "SELECT id, data FROM sekai_dataset_rows WHERE dataset_id=$1 AND id>$2 ORDER BY id",
                &[&dataset_id, &after_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let id: i64 = row.get(0);
                let data: String = row.get(1);
                let values: HashMap<String, String> = serde_json::from_str(&data)
                    .map_err(|error| format!("corrupt dataset row for {dataset_id:?}: {error}"))?;
                Ok((id, values))
            })
            .collect()
    }

    pub fn query_dataset_rows(
        &self,
        dataset_id: &str,
        query: &RowQuery,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(|error| error.to_string())?;
        let state = crate::db::postgres_dataset_health::load_state_pg(&mut tx, dataset_id)?;
        let rows = if state.quarantined && !state.last_healthy_version_id.is_empty() {
            tx.query(
                "SELECT data FROM sekai_dataset_version_content
                 WHERE dataset_id=$1 AND version_id=$2 ORDER BY row_id",
                &[&dataset_id, &state.last_healthy_version_id],
            )
            .map_err(|error| error.to_string())?
        } else if state.quarantined {
            Vec::new()
        } else {
            tx.query(
                "SELECT data FROM sekai_dataset_rows WHERE dataset_id=$1 ORDER BY id",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
        };
        let mut result = Vec::new();
        let mut skipped = 0;
        for row in rows {
            let data: String = row.get(0);
            let mut values: HashMap<String, String> = serde_json::from_str(&data)
                .map_err(|error| format!("corrupt dataset row for {dataset_id:?}: {error}"))?;
            if !matches_filters(&values, &query.filters) {
                continue;
            }
            if skipped < query.offset.max(0) {
                skipped += 1;
                continue;
            }
            if !query.columns.is_empty() {
                values.retain(|key, _| query.columns.contains(key));
            }
            result.push(values);
            if query.limit > 0 && result.len() >= query.limit as usize {
                break;
            }
        }
        Ok(result)
    }

    /// PostgreSQL twin of the SQLite `latest_source_batch_row`: one seek over
    /// `idx_dataset_rows_source_key` (migration 0176, #3259).
    pub fn latest_source_batch_row(
        &self,
        dataset_id: &str,
        source_id: &str,
    ) -> Result<Option<HashMap<String, String>>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(|error| error.to_string())?;
        let state = crate::db::postgres_dataset_health::load_state_pg(&mut tx, dataset_id)?;
        let row = if state.quarantined && !state.last_healthy_version_id.is_empty() {
            tx.query_opt(
                LATEST_SOURCE_VERSION_ROW_SQL,
                &[&dataset_id, &state.last_healthy_version_id, &source_id],
            )
            .map_err(|error| error.to_string())?
        } else if state.quarantined {
            None
        } else {
            tx.query_opt(LATEST_SOURCE_ROW_SQL, &[&dataset_id, &source_id])
                .map_err(|error| error.to_string())?
        };
        row.map(|row| {
            let data: String = row.get(0);
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
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_dataset_rows(&mut transaction, dataset_id)?;
        // Columns are read under the dataset lock, so a classification change
        // committed before this call takes the lock is honored (#2821).
        let (columns_json, keys_json): (String, String) = transaction
            .query_opt(
                "SELECT columns, partition_keys FROM sekai_datasets WHERE id=$1",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| (row.get(0), row.get(1)))
            .ok_or_else(|| "dataset not found".to_string())?;
        let columns = crate::sekai::dataset::parse_columns(&columns_json)?;
        let fields = crate::sekai::dataset::redaction_fields(&columns, classification, filters)?;
        let keys = crate::sekai::dataset::parse_partition_keys(&keys_json)?;
        let rows = transaction
            .query(
                "SELECT id,data FROM sekai_dataset_rows WHERE dataset_id=$1 ORDER BY id FOR UPDATE",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?;
        let mut result = DatasetRedaction::default();
        for row in rows {
            let id: i64 = row.get(0);
            let data: String = row.get(1);
            let mut values: HashMap<String, String> =
                serde_json::from_str(&data).map_err(|error| error.to_string())?;
            if !matches_filters(&values, filters) {
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
            let data = serde_json::to_string(&values).map_err(|error| error.to_string())?;
            let partition_key = crate::sekai::governed_transform::partition_value(&keys, &values);
            transaction
                .execute(
                    "UPDATE sekai_dataset_rows SET data=$1, partition_key=$2 WHERE id=$3 AND dataset_id=$4",
                    &[&data, &partition_key, &id, &dataset_id],
                )
                .map_err(|error| error.to_string())?;
            result.rows_updated += 1;
            result.fields_redacted += changed;
        }
        redact_dataset_version_rows_pg(&mut transaction, dataset_id, filters, &fields, &keys)?;
        crate::db::postgres_dataset_branch::edit_branch_rows_pg(
            &mut transaction,
            dataset_id,
            &|row| crate::sekai::dataset::redact_branch_row(row, filters, &fields),
        )?;
        if result.rows_updated > 0 {
            snapshot_dataset_version_pg(
                &mut transaction,
                dataset_id,
                "",
                "",
                "redaction",
                "",
                crate::sekai::dataset_version::now_ms(),
            )?;
        }
        crate::db::postgres_governed_transform::redact_transform_partition_receipts_pg(
            &mut transaction,
            dataset_id,
            keys.is_empty()
                || keys
                    .iter()
                    .any(|key| fields.iter().any(|field| field == key)),
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn create_virtual_table(&self, table: &VirtualTable) -> Result<(), String> {
        let filters = serde_json::to_string(
            &table
                .filters
                .iter()
                .map(|filter| (&filter.column, &filter.op, &filter.value))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| error.to_string())?;
        let columns = serde_json::to_string(&table.columns).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_virtual_tables (id,name,dataset_id,filters,columns,created)
                 VALUES ($1,$2,$3,$4,$5,$6)",
                &[
                    &table.id,
                    &table.name,
                    &table.dataset_id,
                    &filters,
                    &columns,
                    &table.created,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_virtual_tables(&self) -> Result<Vec<VirtualTable>, String> {
        self.connection()?
            .query(
                "SELECT id,name,dataset_id,filters,columns,created
                 FROM sekai_virtual_tables ORDER BY id",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let filters: String = row.get(3);
                let filters: Vec<(String, String, String)> =
                    serde_json::from_str(&filters).map_err(|error| error.to_string())?;
                let columns: String = row.get(4);
                Ok(VirtualTable {
                    id: row.get(0),
                    name: row.get(1),
                    dataset_id: row.get(2),
                    filters: filters
                        .into_iter()
                        .map(|(column, op, value)| RowFilter { column, op, value })
                        .collect(),
                    columns: serde_json::from_str(&columns).map_err(|error| error.to_string())?,
                    created: row.get(5),
                })
            })
            .collect()
    }
    pub fn list_dataset_versions(&self, dataset_id: &str) -> Result<Vec<DatasetVersion>, String> {
        self.connection()?
            .query(
                "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                        restored_from_version_id, row_count, purged
                 FROM sekai_dataset_versions WHERE dataset_id = $1 ORDER BY seq",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_dataset_version)
            .collect()
    }

    pub fn dataset_version_retention(&self, dataset_id: &str) -> Result<i32, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT retain_count FROM sekai_dataset_version_policy WHERE dataset_id = $1",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0))
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        crate::db::postgres::lock_dataset_rows(&mut tx, dataset_id)?;
        let found: Option<i32> = tx
            .query_opt("SELECT 1 FROM sekai_datasets WHERE id = $1", &[&dataset_id])
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if found.is_none() {
            return Err(dataset_version::DATASET_NOT_FOUND.into());
        }
        tx.execute(
            "INSERT INTO sekai_dataset_version_policy (dataset_id, retain_count)
             VALUES ($1, $2)
             ON CONFLICT (dataset_id) DO UPDATE SET retain_count = EXCLUDED.retain_count",
            &[&dataset_id, &retain_count],
        )
        .map_err(|error| error.to_string())?;
        prune_dataset_versions_pg(&mut tx, dataset_id)?;
        tx.commit().map(|_| ()).map_err(|error| error.to_string())
    }

    pub fn get_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<DatasetVersion, String> {
        let mut connection = self.connection()?;
        let row = if !version_id.is_empty() {
            connection.query_opt(
                "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                        restored_from_version_id, row_count, purged
                 FROM sekai_dataset_versions WHERE dataset_id = $1 AND version_id = $2",
                &[&dataset_id, &version_id],
            )
        } else if as_of_ms > 0 {
            connection.query_opt(
                "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                        restored_from_version_id, row_count, purged
                 FROM sekai_dataset_versions
                 WHERE dataset_id = $1 AND created_at_ms <= $2
                 ORDER BY seq DESC LIMIT 1",
                &[&dataset_id, &as_of_ms],
            )
        } else {
            connection.query_opt(
                "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                        restored_from_version_id, row_count, purged
                 FROM sekai_dataset_versions WHERE dataset_id = $1
                 ORDER BY seq DESC LIMIT 1",
                &[&dataset_id],
            )
        }
        .map_err(|error| error.to_string())?;
        let version = row
            .map(row_to_dataset_version)
            .transpose()?
            .ok_or_else(|| dataset_version::DATASET_VERSION_NOT_FOUND.to_string())?;
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        crate::db::postgres::lock_dataset_rows(&mut tx, dataset_id)?;
        let version = get_dataset_version_pg(&mut tx, dataset_id, version_id, as_of_ms)?;
        if version.purged {
            return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
        }
        let rows = tx
            .query(
                "SELECT data FROM sekai_dataset_version_content
                 WHERE dataset_id = $1 AND version_id = $2 ORDER BY row_id",
                &[&dataset_id, &version.version_id],
            )
            .map_err(|error| error.to_string())?;
        let rows = rows
            .into_iter()
            .map(|row| {
                let data: String = row.get(0);
                serde_json::from_str(&data).map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok((version, rows))
    }

    /// One page of a version's rows in `row_id` order; see the SQLite
    /// `load_dataset_version_page`.
    pub fn load_dataset_version_page(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
        after_row_id: Option<i64>,
        limit: usize,
    ) -> Result<crate::sekai::dataset::DatasetVersionPage, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        crate::db::postgres::lock_dataset_rows(&mut tx, dataset_id)?;
        let version = get_dataset_version_pg(&mut tx, dataset_id, version_id, as_of_ms)?;
        if version.purged {
            return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
        }
        let rows = tx
            .query(
                "SELECT row_id, data FROM sekai_dataset_version_content
                 WHERE dataset_id = $1 AND version_id = $2 AND row_id > $3
                 ORDER BY row_id LIMIT $4",
                &[
                    &dataset_id,
                    &version.version_id,
                    &after_row_id.unwrap_or(i64::MIN),
                    &i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| error.to_string())?;
        let rows = rows
            .into_iter()
            .map(|row| {
                let row_id: i64 = row.get(0);
                let data: String = row.get(1);
                serde_json::from_str(&data)
                    .map(|values| (row_id, values))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok((version, rows))
    }

    pub fn rollback_dataset(&self, request: &DatasetRollback) -> Result<DatasetVersion, String> {
        if request.restore_from_version_id.trim().is_empty() {
            return Err(dataset_version::DATASET_ROLLBACK_REQUIRES_RESTORE.into());
        }
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        crate::db::postgres::lock_dataset_rows(&mut tx, &request.dataset_id)?;
        let version = rollback_dataset_pg(&mut tx, request)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(version)
    }
}

/// The rollback of [`PostgresDb::rollback_dataset`] inside the caller's
/// transaction, which must already hold
/// [`crate::db::postgres::lock_dataset_rows`] for the dataset. The caller
/// commits on success and rolls back on any error.
pub(crate) fn rollback_dataset_pg(
    tx: &mut postgres::Transaction<'_>,
    request: &DatasetRollback,
) -> Result<DatasetVersion, String> {
    let restored =
        get_dataset_version_pg(tx, &request.dataset_id, &request.restore_from_version_id, 0)?;
    if restored.purged {
        return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
    }
    // Checked inside the rollback transaction, as on SQLite.
    if let Some(row) = tx
        .query_opt(
            "SELECT namespace, kind FROM sekai_object_type_datasource
             WHERE dataset_id = $1 AND NOT edits_only
             ORDER BY namespace, kind LIMIT 1",
            &[&request.dataset_id],
        )
        .map_err(|error| error.to_string())?
    {
        return Err(dataset_version::rollback_backs_index_error(
            &row.get::<_, String>(0),
            &row.get::<_, String>(1),
        ));
    }
    tx.execute(
        "DELETE FROM sekai_dataset_rows WHERE dataset_id = $1",
        &[&request.dataset_id],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_dataset_rows (dataset_id, data)
         SELECT dataset_id, data FROM sekai_dataset_version_content
         WHERE dataset_id = $1 AND version_id = $2
         ORDER BY row_id",
        &[&request.dataset_id, &restored.version_id],
    )
    .map_err(|error| error.to_string())?;
    let keys_json: String = tx
        .query_one(
            "SELECT partition_keys FROM sekai_datasets WHERE id = $1",
            &[&request.dataset_id],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    let keys = crate::sekai::dataset::parse_partition_keys(&keys_json)?;
    let live = tx
        .query(
            "SELECT id, data FROM sekai_dataset_rows WHERE dataset_id = $1",
            &[&request.dataset_id],
        )
        .map_err(|error| error.to_string())?;
    for row in live {
        let id: i64 = row.get(0);
        let data: String = row.get(1);
        let partition_key = crate::sekai::dataset::partition_key_for_row_json(&keys, &data)?;
        tx.execute(
            "UPDATE sekai_dataset_rows SET partition_key = $1 WHERE id = $2",
            &[&partition_key, &id],
        )
        .map_err(|error| error.to_string())?;
    }
    mark_consuming_transform_outputs_stale_pg(
        tx,
        &request.dataset_id,
        &restored.version_id,
        dataset_version::now_ms(),
    )?;
    let version = snapshot_dataset_version_pg(
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

fn validate_columns(columns: &[ColumnDef]) -> Result<(), String> {
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

pub(crate) fn create_dataset_tx(
    tx: &mut postgres::Transaction<'_>,
    dataset: &Dataset,
) -> Result<(), String> {
    validate_columns(&dataset.columns)?;
    let columns = encode_columns(&dataset.columns)?;
    let partition_keys = crate::sekai::dataset::encode_partition_keys(&dataset.partition_keys)?;
    tx.execute(
        "INSERT INTO sekai_datasets (id,name,columns,object_id,created,partition_keys)
         VALUES ($1,$2,$3,$4,$5,$6)",
        &[
            &dataset.id,
            &dataset.name,
            &columns,
            &dataset.object_id,
            &dataset.created,
            &partition_keys,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

pub(crate) fn add_dataset_columns_tx(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    columns: &[ColumnDef],
) -> Result<(), String> {
    validate_columns(columns)?;
    lock_dataset_rows(tx, dataset_id)?;
    let json: String = tx
        .query_opt(
            "SELECT columns FROM sekai_datasets WHERE id=$1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .ok_or_else(|| format!("dataset {dataset_id:?} not found"))?;
    let mut current = crate::sekai::dataset::parse_columns(&json)?;
    let before = current.len();
    for column in columns {
        if !current.iter().any(|defined| defined.name == column.name) {
            current.push(column.clone());
        }
    }
    if current.len() == before {
        return Ok(());
    }
    tx.execute(
        "UPDATE sekai_datasets SET columns=$2 WHERE id=$1",
        &[&dataset_id, &encode_columns(&current)?],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn append_dataset_rows_tx(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    rows: &[HashMap<String, String>],
) -> Result<(i64, i64), String> {
    if rows.is_empty() {
        return Ok((0, 0));
    }
    lock_dataset_rows(tx, dataset_id)?;
    let keys_json: Option<String> = tx
        .query_opt(
            "SELECT partition_keys FROM sekai_datasets WHERE id=$1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    let Some(keys_json) = keys_json else {
        return Err("dataset not found".into());
    };
    let keys = crate::sekai::dataset::parse_partition_keys(&keys_json)?;
    // The range is the first and last id these inserts took from the
    // table-wide identity, not this dataset's previous maximum, which other
    // datasets' rows may have passed since. The lock is per dataset, so an
    // append to another dataset running at the same moment can still take ids
    // inside this range.
    let (mut first, mut last) = (i64::MAX, 0i64);
    for row in rows {
        let data = serde_json::to_string(row).map_err(|error| error.to_string())?;
        let partition_key = crate::sekai::governed_transform::partition_value(&keys, row);
        let id: i64 = tx
            .query_one(
                "INSERT INTO sekai_dataset_rows (dataset_id,data,partition_key) VALUES ($1,$2,$3) RETURNING id",
                &[&dataset_id, &data, &partition_key],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        first = first.min(id);
        last = last.max(id);
    }
    snapshot_dataset_version_pg(tx, dataset_id, "", "", "", "", dataset_version::now_ms())?;
    Ok((first, last))
}

fn encode_columns(columns: &[ColumnDef]) -> Result<String, String> {
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

fn row_to_dataset(row: postgres::Row) -> Result<Dataset, String> {
    let columns: String = row.get(2);
    let columns = serde_json::from_str::<Vec<(String, String, String)>>(&columns)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|(name, col_type, classification)| ColumnDef {
            name,
            col_type,
            classification,
        })
        .collect();
    let keys: String = row.try_get(5).unwrap_or_else(|_| "[]".into());
    Ok(Dataset {
        id: row.get(0),
        name: row.get(1),
        columns,
        object_id: row.get(3),
        created: row.get(4),
        partition_keys: crate::sekai::dataset::parse_partition_keys(&keys)?,
    })
}

/// The shared row filter, so both backends answer a query alike.
fn matches_filters(row: &HashMap<String, String>, filters: &[RowFilter]) -> bool {
    crate::sekai::dataset::matches_row_filters(row, filters)
}

fn row_to_dataset_version(row: postgres::Row) -> Result<DatasetVersion, String> {
    let purged: i32 = row.get(9);
    Ok(DatasetVersion {
        dataset_id: row.get(0),
        version_id: row.get(1),
        seq: row.get(2),
        created_at_ms: row.get(3),
        actor: row.get(4),
        tenant: row.get(5),
        reason: row.get(6),
        restored_from_version_id: row.get(7),
        row_count: row.get(8),
        purged: purged != 0,
    })
}

pub(crate) fn get_dataset_version_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    version_id: &str,
    as_of_ms: i64,
) -> Result<DatasetVersion, String> {
    let row = if !version_id.is_empty() {
        tx.query_opt(
            "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                    restored_from_version_id, row_count, purged
             FROM sekai_dataset_versions WHERE dataset_id = $1 AND version_id = $2",
            &[&dataset_id, &version_id],
        )
    } else if as_of_ms > 0 {
        tx.query_opt(
            "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                    restored_from_version_id, row_count, purged
             FROM sekai_dataset_versions
             WHERE dataset_id = $1 AND created_at_ms <= $2
             ORDER BY seq DESC LIMIT 1",
            &[&dataset_id, &as_of_ms],
        )
    } else {
        tx.query_opt(
            "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                    restored_from_version_id, row_count, purged
             FROM sekai_dataset_versions WHERE dataset_id = $1
             ORDER BY seq DESC LIMIT 1",
            &[&dataset_id],
        )
    }
    .map_err(|error| error.to_string())?;
    row.map(row_to_dataset_version)
        .transpose()?
        .ok_or_else(|| dataset_version::DATASET_VERSION_NOT_FOUND.to_string())
}

/// Writes a `snapshot` version of the dataset's live rows (ADR 0172), as
/// `crate::sekai::dataset::snapshot_dataset_version_tx` does on SQLite.
pub fn snapshot_dataset_version_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    actor: &str,
    tenant: &str,
    reason: &str,
    restored_from_version_id: &str,
    created_at_ms: i64,
) -> Result<DatasetVersion, String> {
    let exists: Option<i32> = tx
        .query_opt("SELECT 1 FROM sekai_datasets WHERE id = $1", &[&dataset_id])
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    if exists.is_none() {
        return Err(dataset_version::DATASET_NOT_FOUND.into());
    }
    let next = next_version_pg(tx, dataset_id, created_at_ms)?;
    let jsons: Vec<String> = tx
        .query(
            "SELECT data FROM sekai_dataset_rows WHERE dataset_id = $1 ORDER BY id",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    tx.execute(
        "UPDATE sekai_dataset_row_spans SET to_seq = $2 WHERE dataset_id = $1 AND to_seq IS NULL",
        &[&dataset_id, &next.seq],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(OPEN_LIVE_SPANS_PG, &[&dataset_id, &next.seq])
        .map_err(|error| error.to_string())?;
    let row_count = i64::try_from(jsons.len()).map_err(|_| "too many dataset rows".to_string())?;
    insert_span_version_pg(
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

/// Lands source records into a source dataset as one span version, as
/// `crate::sekai::dataset::land_source_rows_tx` does on SQLite, under the
/// dataset rows lock.
pub(crate) fn land_source_rows_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    rows: &[HashMap<String, String>],
) -> Result<(i64, i64), String> {
    if rows.is_empty() {
        return Ok((0, 0));
    }
    lock_dataset_rows(tx, dataset_id)?;
    let rows = crate::db::source_batch_dataset::last_row_per_key(rows);
    let keys_json: String = tx
        .query_opt(
            "SELECT partition_keys FROM sekai_datasets WHERE id=$1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .ok_or_else(|| dataset_version::DATASET_NOT_FOUND.to_string())?;
    let keys = crate::sekai::dataset::parse_partition_keys(&keys_json)?;
    let next = next_version_pg(tx, dataset_id, dataset_version::now_ms())?;
    let source_ids: Vec<&str> = rows
        .iter()
        .filter_map(|row| row.get(crate::db::source_batch_dataset::KEY_COLUMN))
        .map(String::as_str)
        .collect();
    let replaced: Vec<i64> = tx
        .query(
            "SELECT id FROM sekai_dataset_rows
             WHERE dataset_id LIKE 'srcds:%' AND dataset_id = $1
               AND (data::jsonb)->>'source_id' = ANY($2)
             ORDER BY id",
            &[&dataset_id, &source_ids],
        )
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    if !replaced.is_empty() {
        if next.on_spans {
            tx.execute(
                "UPDATE sekai_dataset_row_spans SET to_seq = $3
                 WHERE dataset_id = $1 AND row_id = ANY($2) AND to_seq IS NULL",
                &[&dataset_id, &replaced, &next.seq],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE id = ANY($1)",
            &[&replaced],
        )
        .map_err(|error| error.to_string())?;
    }
    if !next.on_spans {
        tx.execute(OPEN_LIVE_SPANS_PG, &[&dataset_id, &next.seq])
            .map_err(|error| error.to_string())?;
    }
    let mut changed: Vec<String> = replaced.iter().map(|id| format!("-{id}")).collect();
    let (mut first, mut last) = (0i64, 0i64);
    for row in &rows {
        let data = serde_json::to_string(row).map_err(|error| error.to_string())?;
        let partition_key = crate::sekai::governed_transform::partition_value(&keys, row);
        let id: i64 = tx
            .query_one(
                "INSERT INTO sekai_dataset_rows (dataset_id,data,partition_key) VALUES ($1,$2,$3) RETURNING id",
                &[&dataset_id, &data, &partition_key],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        tx.execute(
            "INSERT INTO sekai_dataset_row_spans (dataset_id, row_id, from_seq, data, partition_key)
             VALUES ($1,$2,$3,$4,$5)",
            &[&dataset_id, &id, &next.seq, &data, &partition_key],
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
        tx.query_one(
            "SELECT COUNT(*) FROM sekai_dataset_rows WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .get(0)
    };
    insert_span_version_pg(
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

/// Opens a span at seq `$2` for every live row of dataset `$1`.
const OPEN_LIVE_SPANS_PG: &str =
    "INSERT INTO sekai_dataset_row_spans (dataset_id, row_id, from_seq, data, partition_key)
     SELECT dataset_id, id, $2, data, COALESCE(partition_key, '')
     FROM sekai_dataset_rows WHERE dataset_id = $1";

/// Where the next version of a dataset goes; see the SQLite `NextVersion`.
struct NextVersion {
    seq: i64,
    created_at_ms: i64,
    previous_version_id: String,
    on_spans: bool,
    previous_row_count: i32,
}

fn next_version_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    created_at_ms: i64,
) -> Result<NextVersion, String> {
    let latest = tx
        .query_opt(
            "SELECT seq, created_at_ms, version_id, layout = 'span', row_count
             FROM sekai_dataset_versions WHERE dataset_id = $1
             ORDER BY seq DESC LIMIT 1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?;
    Ok(match latest {
        Some(row) => NextVersion {
            seq: row.get::<_, i64>(0) + 1,
            created_at_ms: created_at_ms.max(row.get::<_, i64>(1).saturating_add(1)),
            previous_version_id: row.get(2),
            on_spans: row.get(3),
            previous_row_count: row.get(4),
        },
        None => NextVersion {
            seq: 1,
            created_at_ms,
            previous_version_id: String::new(),
            on_spans: false,
            previous_row_count: 0,
        },
    })
}

struct VersionChange<'a> {
    kind: &'a str,
    changed: &'a [String],
    row_count: i64,
}

#[derive(Clone, Copy, Default)]
struct VersionMeta<'a> {
    actor: &'a str,
    tenant: &'a str,
    reason: &'a str,
    restored_from_version_id: &'a str,
}

/// Records a `span` version whose spans are already written, then judges its
/// health and prunes past retention.
fn insert_span_version_pg(
    tx: &mut postgres::Transaction<'_>,
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
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0,$10,'span')",
        &[
            &dataset_id,
            &version_id,
            &next.seq,
            &next.created_at_ms,
            &meta.actor,
            &meta.tenant,
            &meta.reason,
            &meta.restored_from_version_id,
            &row_count,
            &change.kind,
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
    crate::db::postgres_dataset_health::judge_after_write_pg(
        tx,
        dataset_id,
        &version,
        next.created_at_ms,
    )?;
    prune_dataset_versions_pg(tx, dataset_id)?;
    Ok(version)
}

fn prune_dataset_versions_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
) -> Result<(), String> {
    let retain: i32 = tx
        .query_opt(
            "SELECT retain_count FROM sekai_dataset_version_policy WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .unwrap_or(0);
    if retain <= 0 {
        return Ok(());
    }
    let max_seq: i64 = tx
        .query_one(
            "SELECT COALESCE(MAX(seq), 0) FROM sekai_dataset_versions WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    let cutoff = max_seq - i64::from(retain);
    if cutoff < 1 {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM sekai_dataset_version_rows
         WHERE dataset_id = $1 AND version_id IN (
            SELECT version_id FROM sekai_dataset_versions
            WHERE dataset_id = $1 AND seq <= $2
              AND version_id != COALESCE((
                SELECT last_healthy_version_id FROM sekai_dataset_health_state
                WHERE dataset_id = $1
              ), '')
              AND version_id NOT IN (
                SELECT base_version_id FROM sekai_dataset_branches WHERE dataset_id = $1
              )
         )",
        &[&dataset_id, &cutoff],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "UPDATE sekai_dataset_versions SET purged = 1
         WHERE dataset_id = $1 AND seq <= $2
           AND version_id != COALESCE((
             SELECT last_healthy_version_id FROM sekai_dataset_health_state
             WHERE dataset_id = $1
           ), '')
           AND version_id NOT IN (
             SELECT base_version_id FROM sekai_dataset_branches WHERE dataset_id = $1
           )",
        &[&dataset_id, &cutoff],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(PURGE_UNCOVERED_SPANS_PG, &[&dataset_id])
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Deletes the closed spans of a dataset that no retained `span` version
/// covers (ADR 0172). Open spans are the live content and always stay.
const PURGE_UNCOVERED_SPANS_PG: &str = "DELETE FROM sekai_dataset_row_spans s
     WHERE s.dataset_id = $1 AND s.to_seq IS NOT NULL
       AND NOT EXISTS (
         SELECT 1 FROM sekai_dataset_versions v
         WHERE v.dataset_id = $1 AND v.layout = 'span' AND v.purged = 0
           AND v.seq >= s.from_seq AND v.seq < s.to_seq
       )";

pub fn mark_consuming_transform_outputs_stale_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    cause_ref: &str,
    now_ms: i64,
) -> Result<(), String> {
    let rows = tx
        .query("SELECT definition_json FROM sekai_governed_transform", &[])
        .map_err(|error| error.to_string())?;
    for row in rows {
        let json: String = row.get(0);
        let transform: crate::sekai::governed_transform::GovernedTransform =
            serde_json::from_str(&json).map_err(|error| error.to_string())?;
        if !transform.consumes_dataset(dataset_id) && transform.output_dataset_id != dataset_id {
            continue;
        }
        tx.execute(
            "INSERT INTO sekai_transform_output_state
             (namespace, dataset_id, freshness, upstream_version, blocked_run_id, updated_at_ms)
             VALUES ($1, $2, 'stale', $3, '', $4)
             ON CONFLICT (namespace, dataset_id) DO UPDATE SET
                freshness = 'stale',
                upstream_version = EXCLUDED.upstream_version,
                blocked_run_id = '',
                updated_at_ms = EXCLUDED.updated_at_ms",
            &[
                &transform.namespace,
                &transform.output_dataset_id,
                &cause_ref,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_governed_transform_checkpoint
             WHERE namespace = $1 AND transform_id = $2",
            &[&transform.namespace, &transform.transform_id],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Redacts matching rows of every version, in both layouts. A shared span is
/// rewritten once and every version that covers it sees the result.
fn redact_dataset_version_rows_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    filters: &[RowFilter],
    fields: &[&str],
    keys: &[String],
) -> Result<(), String> {
    let redact = |data: &str| -> Result<Option<(String, String)>, String> {
        let mut values: HashMap<String, String> =
            serde_json::from_str(data).map_err(|error| error.to_string())?;
        if !matches_filters(&values, filters) {
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
    let copies = tx
        .query(
            "SELECT version_id, row_id, data FROM sekai_dataset_version_rows WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?;
    for row in copies {
        let (version_id, row_id): (String, i64) = (row.get(0), row.get(1));
        if let Some((data, partition_key)) = redact(row.get(2))? {
            tx.execute(
                "UPDATE sekai_dataset_version_rows SET data = $1, partition_key = $2
                 WHERE dataset_id = $3 AND version_id = $4 AND row_id = $5",
                &[&data, &partition_key, &dataset_id, &version_id, &row_id],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    let spans = tx
        .query(
            "SELECT from_seq, row_id, data FROM sekai_dataset_row_spans WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?;
    for row in spans {
        let (from_seq, row_id): (i64, i64) = (row.get(0), row.get(1));
        if let Some((data, partition_key)) = redact(row.get(2))? {
            tx.execute(
                "UPDATE sekai_dataset_row_spans SET data = $1, partition_key = $2
                 WHERE dataset_id = $3 AND row_id = $4 AND from_seq = $5",
                &[&data, &partition_key, &dataset_id, &row_id, &from_seq],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::postgres::ScratchDatabase;

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_interleaved_appends_return_only_their_own_row_ids() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
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
            let mut connection = db.connection().unwrap();
            let mut tx = connection.transaction().unwrap();
            let range = append_dataset_rows_tx(&mut tx, dataset, &rows(n)).unwrap();
            tx.commit().unwrap();
            range
        };
        let owners_in = |(from, to): (i64, i64)| -> Vec<String> {
            db.connection()
                .unwrap()
                .query(
                    "SELECT DISTINCT dataset_id FROM sekai_dataset_rows WHERE id BETWEEN $1 AND $2",
                    &[&from, &to],
                )
                .unwrap()
                .iter()
                .map(|row| row.get(0))
                .collect()
        };

        let first_a = append("a", 2);
        let first_b = append("b", 3);
        let second_a = append("a", 2);

        for (dataset, range, len) in [("a", first_a, 2), ("b", first_b, 3), ("a", second_a, 2)] {
            assert_eq!(range.1 - range.0 + 1, len, "{dataset} {range:?}");
            assert_eq!(
                owners_in(range),
                vec![dataset.to_string()],
                "{dataset} {range:?}"
            );
        }
    }

    /// ADR 0172 on PostgreSQL: after `copy` versions from the release before,
    /// a landed batch writes an `append`, then an `update` that replaces a
    /// row by its external id; every version reads its own rows, the live
    /// rows equal the latest version, and rollback and retention keep each
    /// retained version's content.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_landed_batches_write_span_versions_after_copy_versions() {
        const ID: &str = "srcds:spans";
        let row = |key: &str, kind: &str| {
            HashMap::from([
                ("source_id".to_string(), key.to_string()),
                ("kind".to_string(), kind.to_string()),
            ])
        };
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&Dataset {
            id: ID.into(),
            name: "spans".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        {
            let mut connection = db.connection().unwrap();
            for (seq, key) in [(1i64, "a"), (2, "b")] {
                let data = serde_json::to_string(&row(key, key)).unwrap();
                connection
                    .execute(
                        "INSERT INTO sekai_dataset_rows (dataset_id, data) VALUES ($1, $2)",
                        &[&ID, &data],
                    )
                    .unwrap();
                let version_id = format!("copy-{seq}");
                connection
                    .execute(
                        "INSERT INTO sekai_dataset_versions
                         (dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                          restored_from_version_id, row_count, purged)
                         VALUES ($1, $2, $3, $3, '', '', '', '', $4, 0)",
                        &[&ID, &version_id, &seq, &(seq as i32)],
                    )
                    .unwrap();
                connection
                    .execute(
                        "INSERT INTO sekai_dataset_version_rows
                         (dataset_id, version_id, row_id, data, partition_key)
                         SELECT dataset_id, $2, id, data, '' FROM sekai_dataset_rows
                         WHERE dataset_id = $1",
                        &[&ID, &version_id],
                    )
                    .unwrap();
            }
        }
        let land = |rows: &[HashMap<String, String>]| {
            let mut connection = db.connection().unwrap();
            let mut tx = connection.transaction().unwrap();
            land_source_rows_pg(&mut tx, ID, rows).unwrap();
            tx.commit().unwrap();
            db.list_dataset_versions(ID).unwrap().pop().unwrap()
        };
        let kinds = |version_id: &str| -> Vec<String> {
            db.load_dataset_version(ID, version_id, 0)
                .unwrap()
                .1
                .into_iter()
                .map(|row| row["kind"].clone())
                .collect()
        };
        let appended = land(&[row("c", "c")]);
        // One batch naming b twice lands its last row.
        let updated = land(&[row("b", "b1"), row("b", "b2")]);
        assert_eq!(kinds("copy-1"), ["a"]);
        assert_eq!(kinds("copy-2"), ["a", "b"]);
        assert_eq!(kinds(&appended.version_id), ["a", "b", "c"]);
        assert_eq!(kinds(&updated.version_id), ["a", "c", "b2"]);
        assert_eq!((appended.row_count, updated.row_count), (3, 3));
        let mut connection = db.connection().unwrap();
        let shape: Vec<(String, String)> = connection
            .query(
                "SELECT kind, layout FROM sekai_dataset_versions
                 WHERE dataset_id = $1 ORDER BY seq",
                &[&ID],
            )
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();
        let shape: Vec<(&str, &str)> = shape
            .iter()
            .map(|(kind, layout)| (kind.as_str(), layout.as_str()))
            .collect();
        assert_eq!(
            shape,
            [
                ("snapshot", "copy"),
                ("snapshot", "copy"),
                ("append", "span"),
                ("update", "span"),
            ]
        );
        let live: Vec<String> = connection
            .query(
                "SELECT data FROM sekai_dataset_rows WHERE dataset_id = $1 ORDER BY id",
                &[&ID],
            )
            .unwrap()
            .iter()
            .map(|row| {
                serde_json::from_str::<HashMap<String, String>>(&row.get::<_, String>(0))
                    .unwrap()["kind"]
                    .clone()
            })
            .collect();
        assert_eq!(live, kinds(&updated.version_id));

        let restored = db
            .rollback_dataset(&DatasetRollback {
                dataset_id: ID.into(),
                restore_from_version_id: appended.version_id.clone(),
                reason: "restore".into(),
                actor: "tester".into(),
                tenant: String::new(),
            })
            .unwrap();
        assert_eq!(kinds(&restored.version_id), ["a", "b", "c"]);
        assert_eq!(kinds(&updated.version_id), ["a", "c", "b2"]);

        db.set_dataset_version_retention(ID, 1).unwrap();
        assert!(db.load_dataset_version(ID, &updated.version_id, 0).is_err());
        assert_eq!(kinds(&restored.version_id), ["a", "b", "c"]);
        let closed: i64 = connection
            .query_one(
                "SELECT COUNT(*) FROM sekai_dataset_row_spans
                 WHERE dataset_id = $1 AND to_seq IS NOT NULL",
                &[&ID],
            )
            .unwrap()
            .get(0);
        assert_eq!(closed, 0, "no retained version covers a closed span");
    }
}

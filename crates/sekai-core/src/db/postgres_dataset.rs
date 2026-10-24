use crate::db::postgres::{PostgresDb, lock_dataset_rows};
use crate::sekai::dataset::{
    ColumnDef, Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable,
};
use crate::sekai::dataset_version::{self, DatasetRollback, DatasetVersion};
use postgres::IsolationLevel;
use std::collections::HashMap;

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
        crate::db::postgres::lock_dataset_rows(&mut transaction, dataset_id)?;
        let keys_json: Option<String> = transaction
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
        for row in rows {
            let data = serde_json::to_string(row).map_err(|error| error.to_string())?;
            let partition_key = crate::sekai::governed_transform::partition_value(&keys, row);
            transaction
                .execute(
                    "INSERT INTO sekai_dataset_rows (dataset_id,data,partition_key) VALUES ($1,$2,$3)",
                    &[&dataset_id, &data, &partition_key],
                )
                .map_err(|error| error.to_string())?;
        }
        snapshot_dataset_version_pg(
            &mut transaction,
            dataset_id,
            "",
            "",
            "",
            "",
            dataset_version::now_ms(),
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        i32::try_from(rows.len()).map_err(|_| "too many dataset rows".into())
    }

    pub fn list_dataset_row_records(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<crate::sekai::dataset::DatasetRowRecord>, String> {
        self.connection()?
            .query(
                "SELECT id, data FROM sekai_dataset_rows WHERE dataset_id=$1 ORDER BY id",
                &[&dataset_id],
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
                "SELECT data FROM sekai_dataset_version_rows
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

    pub fn redact_dataset_fields(
        &self,
        dataset_id: &str,
        classification: &str,
        filters: &[RowFilter],
    ) -> Result<DatasetRedaction, String> {
        if !crate::sekai::schema::is_restricted_property_classification(classification) {
            return Err("classification must be internal or sensitive".into());
        }
        let dataset = self
            .get_dataset(dataset_id)?
            .ok_or_else(|| "dataset not found".to_string())?;
        validate_filters(&dataset, filters)?;
        let classification =
            crate::sekai::schema::normalize_property_classification(classification);
        let fields = dataset
            .columns
            .iter()
            .filter(|column| {
                crate::sekai::schema::normalize_property_classification(&column.classification)
                    == classification
            })
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>();
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_dataset_rows(&mut transaction, dataset_id)?;
        let keys_json: String = transaction
            .query_one(
                "SELECT partition_keys FROM sekai_datasets WHERE id=$1",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
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
                "SELECT data FROM sekai_dataset_version_rows
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

    pub fn rollback_dataset(&self, request: &DatasetRollback) -> Result<DatasetVersion, String> {
        if request.restore_from_version_id.trim().is_empty() {
            return Err(dataset_version::DATASET_ROLLBACK_REQUIRES_RESTORE.into());
        }
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        crate::db::postgres::lock_dataset_rows(&mut tx, &request.dataset_id)?;
        let restored = get_dataset_version_pg(
            &mut tx,
            &request.dataset_id,
            &request.restore_from_version_id,
            0,
        )?;
        if restored.purged {
            return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
        }
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE dataset_id = $1",
            &[&request.dataset_id],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_dataset_rows (dataset_id, data)
             SELECT dataset_id, data FROM sekai_dataset_version_rows
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
            &mut tx,
            &request.dataset_id,
            &restored.version_id,
            dataset_version::now_ms(),
        )?;
        let version = snapshot_dataset_version_pg(
            &mut tx,
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

fn validate_filters(dataset: &Dataset, filters: &[RowFilter]) -> Result<(), String> {
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
    Ok(())
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

fn get_dataset_version_pg(
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
    let seq: i64 = tx
        .query_one(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM sekai_dataset_versions WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    let prev_ms: i64 = tx
        .query_one(
            "SELECT COALESCE(MAX(created_at_ms), 0) FROM sekai_dataset_versions WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    let created_at_ms = created_at_ms.max(prev_ms.saturating_add(1));
    let live = tx
        .query(
            "SELECT id, data, COALESCE(partition_key, '') FROM sekai_dataset_rows
             WHERE dataset_id = $1 ORDER BY id",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?;
    let row_jsons: Vec<(i64, String, String)> = live
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let jsons: Vec<String> = row_jsons.iter().map(|(_, data, _)| data.clone()).collect();
    let version_id = dataset_version::version_id(dataset_id, seq, created_at_ms, &jsons);
    let row_count =
        i32::try_from(row_jsons.len()).map_err(|_| "too many dataset rows".to_string())?;
    tx.execute(
        "INSERT INTO sekai_dataset_versions
         (dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
          restored_from_version_id, row_count, purged)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0)",
        &[
            &dataset_id,
            &version_id,
            &seq,
            &created_at_ms,
            &actor,
            &tenant,
            &reason,
            &restored_from_version_id,
            &row_count,
        ],
    )
    .map_err(|error| error.to_string())?;
    for (row_id, data, partition_key) in &row_jsons {
        tx.execute(
            "INSERT INTO sekai_dataset_version_rows
             (dataset_id, version_id, row_id, data, partition_key)
             VALUES ($1,$2,$3,$4,$5)",
            &[&dataset_id, &version_id, row_id, data, partition_key],
        )
        .map_err(|error| error.to_string())?;
    }
    let version = DatasetVersion {
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
    };
    crate::db::postgres_dataset_health::judge_after_write_pg(
        tx,
        dataset_id,
        &version,
        created_at_ms,
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
    .map(|_| ())
    .map_err(|error| error.to_string())
}

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

fn redact_dataset_version_rows_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    filters: &[RowFilter],
    fields: &[&str],
    keys: &[String],
) -> Result<(), String> {
    let rows = tx
        .query(
            "SELECT version_id, row_id, data FROM sekai_dataset_version_rows WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?;
    for row in rows {
        let version_id: String = row.get(0);
        let row_id: i64 = row.get(1);
        let data: String = row.get(2);
        let mut values: HashMap<String, String> =
            serde_json::from_str(&data).map_err(|error| error.to_string())?;
        if !matches_filters(&values, filters) {
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
            "UPDATE sekai_dataset_version_rows SET data = $1, partition_key = $2
             WHERE dataset_id = $3 AND version_id = $4 AND row_id = $5",
            &[&data, &partition_key, &dataset_id, &version_id, &row_id],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

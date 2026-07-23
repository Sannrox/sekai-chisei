use crate::db::postgres::PostgresDb;
use crate::sekai::dataset::{
    ColumnDef, Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable,
};
use std::collections::HashMap;

impl PostgresDb {
    pub fn create_dataset(&self, dataset: &Dataset) -> Result<(), String> {
        validate_columns(&dataset.columns)?;
        let columns = encode_columns(&dataset.columns)?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_datasets (id,name,columns,object_id,created)
                 VALUES ($1,$2,$3,$4,$5)",
                &[
                    &dataset.id,
                    &dataset.name,
                    &columns,
                    &dataset.object_id,
                    &dataset.created,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn update_dataset(&self, dataset: &Dataset) -> Result<(), String> {
        validate_columns(&dataset.columns)?;
        let columns = encode_columns(&dataset.columns)?;
        let changed = self
            .connection()?
            .execute(
                "UPDATE sekai_datasets SET name=$2, columns=$3 WHERE id=$1",
                &[&dataset.id, &dataset.name, &columns],
            )
            .map_err(|error| error.to_string())?;
        (changed == 1)
            .then_some(())
            .ok_or_else(|| format!("dataset {:?} not found", dataset.id))
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        self.connection()?
            .query_opt(
                "SELECT id,name,columns,object_id,created FROM sekai_datasets WHERE id=$1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_dataset)
            .transpose()
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        self.connection()?
            .query(
                "SELECT id,name,columns,object_id,created FROM sekai_datasets ORDER BY id",
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
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if transaction
            .query_opt("SELECT 1 FROM sekai_datasets WHERE id=$1", &[&dataset_id])
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Err("dataset not found".into());
        }
        for row in rows {
            let data = serde_json::to_string(row).map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO sekai_dataset_rows (dataset_id,data) VALUES ($1,$2)",
                    &[&dataset_id, &data],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        i32::try_from(rows.len()).map_err(|_| "too many dataset rows".into())
    }

    pub fn query_dataset_rows(
        &self,
        dataset_id: &str,
        query: &RowQuery,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT data FROM sekai_dataset_rows WHERE dataset_id=$1 ORDER BY id",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?;
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
            transaction
                .execute(
                    "UPDATE sekai_dataset_rows SET data=$1 WHERE id=$2 AND dataset_id=$3",
                    &[&data, &id, &dataset_id],
                )
                .map_err(|error| error.to_string())?;
            result.rows_updated += 1;
            result.fields_redacted += changed;
        }
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
    Ok(Dataset {
        id: row.get(0),
        name: row.get(1),
        columns,
        object_id: row.get(3),
        created: row.get(4),
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

fn matches_filters(row: &HashMap<String, String>, filters: &[RowFilter]) -> bool {
    filters.iter().all(|filter| {
        let Some(value) = row.get(&filter.column) else {
            return false;
        };
        match filter.op.as_str() {
            "eq" => value == &filter.value,
            "neq" => value != &filter.value,
            "gt" => numeric(value) > numeric(&filter.value),
            "lt" => numeric(value) < numeric(&filter.value),
            "gte" => numeric(value) >= numeric(&filter.value),
            "lte" => numeric(value) <= numeric(&filter.value),
            _ => false,
        }
    })
}

fn numeric(value: &str) -> f64 {
    value.parse().unwrap_or(0.0)
}

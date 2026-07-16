use crate::db::sekai::SekaiDb;
use rusqlite::params;
use std::collections::HashMap;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct Dataset {
    pub id: String,
    pub name: String,
    pub columns: Vec<ColumnDef>,
    pub object_id: String,
    pub created: i64,
}

#[derive(Debug, Clone)]
pub struct RowFilter {
    pub column: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct RowQuery {
    pub filters: Vec<RowFilter>,
    pub columns: Vec<String>,
    pub limit: i32,
    pub offset: i32,
}

#[derive(Debug, Clone)]
pub struct VirtualTable {
    pub id: String,
    pub name: String,
    pub dataset_id: String,
    pub filters: Vec<RowFilter>,
    pub columns: Vec<String>,
    pub created: i64,
}

fn parse_columns(value: &str) -> Vec<ColumnDef> {
    if let Ok(columns) = serde_json::from_str::<Vec<(String, String, String)>>(value) {
        return columns
            .into_iter()
            .map(|(name, col_type, classification)| ColumnDef {
                name,
                col_type,
                classification,
            })
            .collect();
    }
    serde_json::from_str::<Vec<(String, String)>>(value)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, col_type)| ColumnDef {
            name,
            col_type,
            classification: crate::sekai::schema::default_property_classification(),
        })
        .collect()
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
            CREATE TABLE IF NOT EXISTS sekai_virtual_tables (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, dataset_id TEXT NOT NULL,
                filters TEXT NOT NULL DEFAULT '[]', columns TEXT NOT NULL DEFAULT '[]',
                created INTEGER NOT NULL
            );",
        )
        .map_err(|e| e.to_string())?;
        let stored: Option<String> = conn
            .query_row(
                "SELECT columns FROM sekai_datasets WHERE id='llm_calls'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(stored) = stored {
            let mut columns = parse_columns(&stored);
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
        conn.execute("INSERT INTO sekai_datasets (id,name,columns,object_id,created) VALUES (?1,?2,?3,?4,?5)",
            params![d.id, d.name, cols, d.object_id, d.created]).map_err(|e| e.to_string())?;
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
        .map_err(|error| error.to_string())?;
        let changed = conn
            .execute(
                "UPDATE sekai_datasets SET name=?2, columns=?3 WHERE id=?1",
                params![d.id, d.name, cols],
            )
            .map_err(|error| error.to_string())?;
        (changed == 1)
            .then_some(())
            .ok_or_else(|| format!("dataset {:?} not found", d.id))
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id,name,columns,object_id,created FROM sekai_datasets WHERE id=?1",
            params![id],
            |row| {
                let cols_str: String = row.get(2)?;
                Ok(Dataset {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    columns: parse_columns(&cols_str),
                    object_id: row.get(3)?,
                    created: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id,name,columns,object_id,created FROM sekai_datasets")
            .map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let cols_str: String = row.get(2).map_err(|e| e.to_string())?;
            results.push(Dataset {
                id: row.get(0).map_err(|e| e.to_string())?,
                name: row.get(1).map_err(|e| e.to_string())?,
                columns: parse_columns(&cols_str),
                object_id: row.get(3).map_err(|e| e.to_string())?,
                created: row.get(4).map_err(|e| e.to_string())?,
            });
        }
        Ok(results)
    }

    pub fn append_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String> {
        let conn = self.conn();
        let mut count = 0;
        for row in rows {
            let data = serde_json::to_string(row).unwrap();
            conn.execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data) VALUES (?1, ?2)",
                params![dataset_id, data],
            )
            .map_err(|e| e.to_string())?;
            count += 1;
        }
        Ok(count)
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
            let map: HashMap<String, String> = serde_json::from_str(&data).unwrap_or_default();
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
            tx.execute(
                "UPDATE sekai_dataset_rows SET data=?1 WHERE id=?2 AND dataset_id=?3",
                params![data, id, dataset_id],
            )
            .map_err(|e| e.to_string())?;
            result.rows_updated += 1;
            result.fields_redacted += changed;
        }
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
            let filters: Vec<(String, String, String)> =
                serde_json::from_str(&filters_str).unwrap_or_default();
            let cols_str: String = row.get(4).map_err(|e| e.to_string())?;
            let columns: Vec<String> = serde_json::from_str(&cols_str).unwrap_or_default();
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
        let ok = match f.op.as_str() {
            "eq" => val == &f.value,
            "neq" => val != &f.value,
            "gt" => val.parse::<f64>().unwrap_or(0.0) > f.value.parse::<f64>().unwrap_or(0.0),
            "lt" => val.parse::<f64>().unwrap_or(0.0) < f.value.parse::<f64>().unwrap_or(0.0),
            "gte" => val.parse::<f64>().unwrap_or(0.0) >= f.value.parse::<f64>().unwrap_or(0.0),
            "lte" => val.parse::<f64>().unwrap_or(0.0) <= f.value.parse::<f64>().unwrap_or(0.0),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

use rusqlite::OptionalExtension;

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
}

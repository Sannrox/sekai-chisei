use crate::db::sekai::SekaiDb;
use rusqlite::params;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub name: String,
    pub col_type: String,
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

impl SekaiDb {
    pub fn migrate_datasets(&self) {
        let conn = self.conn.lock().unwrap();
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
        .unwrap();
    }

    pub fn create_dataset(&self, d: &Dataset) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let cols = serde_json::to_string(
            &d.columns
                .iter()
                .map(|c| (&c.name, &c.col_type))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        conn.execute("INSERT INTO sekai_datasets (id,name,columns,object_id,created) VALUES (?1,?2,?3,?4,?5)",
            params![d.id, d.name, cols, d.object_id, d.created]).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id,name,columns,object_id,created FROM sekai_datasets WHERE id=?1",
            params![id],
            |row| {
                let cols_str: String = row.get(2)?;
                let cols: Vec<(String, String)> =
                    serde_json::from_str(&cols_str).unwrap_or_default();
                Ok(Dataset {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    columns: cols
                        .into_iter()
                        .map(|(n, t)| ColumnDef {
                            name: n,
                            col_type: t,
                        })
                        .collect(),
                    object_id: row.get(3)?,
                    created: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id,name,columns,object_id,created FROM sekai_datasets")
            .map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let cols_str: String = row.get(2).unwrap_or_default();
            let cols: Vec<(String, String)> = serde_json::from_str(&cols_str).unwrap_or_default();
            results.push(Dataset {
                id: row.get(0).unwrap(),
                name: row.get(1).unwrap(),
                columns: cols
                    .into_iter()
                    .map(|(n, t)| ColumnDef {
                        name: n,
                        col_type: t,
                    })
                    .collect(),
                object_id: row.get(3).unwrap_or_default(),
                created: row.get(4).unwrap(),
            });
        }
        Ok(results)
    }

    pub fn append_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT data FROM sekai_dataset_rows WHERE dataset_id = ?1")
            .map_err(|e| e.to_string())?;
        let mut rows_iter = stmt.query(params![dataset_id]).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut skipped = 0;
        while let Some(row) = rows_iter.next().map_err(|e| e.to_string())? {
            let data: String = row.get(0).unwrap();
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

    pub fn create_virtual_table(&self, vt: &VirtualTable) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id,name,dataset_id,filters,columns,created FROM sekai_virtual_tables")
            .map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let filters_str: String = row.get(3).unwrap_or_default();
            let filters: Vec<(String, String, String)> =
                serde_json::from_str(&filters_str).unwrap_or_default();
            let cols_str: String = row.get(4).unwrap_or_default();
            let columns: Vec<String> = serde_json::from_str(&cols_str).unwrap_or_default();
            results.push(VirtualTable {
                id: row.get(0).unwrap(),
                name: row.get(1).unwrap(),
                dataset_id: row.get(2).unwrap(),
                filters: filters
                    .into_iter()
                    .map(|(c, o, v)| RowFilter {
                        column: c,
                        op: o,
                        value: v,
                    })
                    .collect(),
                columns,
                created: row.get(5).unwrap(),
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
            _ => true,
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
        let db = SekaiDb::new(":memory:").unwrap();
        db.migrate_datasets();
        db
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
                },
                ColumnDef {
                    name: "val".into(),
                    col_type: "float".into(),
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
    fn test_virtual_table() {
        let db = setup();
        let ds = Dataset {
            id: "ds1".into(),
            name: "t".into(),
            columns: vec![ColumnDef {
                name: "x".into(),
                col_type: "int".into(),
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

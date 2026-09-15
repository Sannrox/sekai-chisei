use crate::db::sekai::SekaiDb;
use crate::sekai::governed_transform::{
    GovernedTransform, TransformRun, apply_steps, evaluate_quality, rows_digest,
};
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;
use uuid::Uuid;

impl SekaiDb {
    pub(crate) fn migrate_governed_transforms(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS sekai_governed_transform (
                    namespace TEXT NOT NULL,
                    transform_id TEXT NOT NULL,
                    definition_json TEXT NOT NULL,
                    definition_digest TEXT NOT NULL,
                    input_dataset_id TEXT NOT NULL,
                    output_dataset_id TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (namespace, transform_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_governed_transform_run (
                    run_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    transform_id TEXT NOT NULL,
                    definition_digest TEXT NOT NULL,
                    input_digest TEXT NOT NULL,
                    output_digest TEXT NOT NULL,
                    last_input_row_id INTEGER NOT NULL,
                    incremental INTEGER NOT NULL,
                    quarantined INTEGER NOT NULL,
                    quality_rule TEXT NOT NULL,
                    rows_in INTEGER NOT NULL,
                    rows_out INTEGER NOT NULL,
                    lineage_parent TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sekai_governed_transform_checkpoint (
                    namespace TEXT NOT NULL,
                    transform_id TEXT NOT NULL,
                    last_input_row_id INTEGER NOT NULL,
                    live_run_id TEXT NOT NULL,
                    live_output_digest TEXT NOT NULL,
                    PRIMARY KEY (namespace, transform_id)
                );
                ",
            )
            .map_err(|error| error.to_string())
    }

    pub fn put_governed_transform(
        &self,
        transform: &GovernedTransform,
        created_at_ms: i64,
    ) -> Result<(), String> {
        let json = serde_json::to_string(transform).map_err(|error| error.to_string())?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_governed_transform
                 (namespace, transform_id, definition_json, definition_digest, input_dataset_id, output_dataset_id, created_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    transform.namespace,
                    transform.transform_id,
                    json,
                    transform.definition_digest,
                    transform.input_dataset_id,
                    transform.output_dataset_id,
                    created_at_ms
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<GovernedTransform>, String> {
        self.conn()
            .query_row(
                "SELECT definition_json FROM sekai_governed_transform
                 WHERE namespace = ?1 AND transform_id = ?2",
                params![namespace, transform_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn run_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        incremental: bool,
        now_ms: i64,
    ) -> Result<TransformRun, String> {
        let transform = self
            .get_governed_transform(namespace, transform_id)?
            .ok_or("governed transform not found")?;
        let checkpoint = self.transform_checkpoint(namespace, transform_id)?;
        let after_id = if incremental {
            checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.0)
                .unwrap_or(0)
        } else {
            0
        };
        let records = self.list_dataset_row_records(&transform.input_dataset_id)?;
        let selected: Vec<(i64, HashMap<String, String>)> = records
            .into_iter()
            .filter(|(id, _)| *id > after_id)
            .collect();
        let last_input_row_id = selected.iter().map(|(id, _)| *id).max().unwrap_or(after_id);
        let input_rows: Vec<HashMap<String, String>> =
            selected.iter().map(|(_, row)| row.clone()).collect();
        let output_rows = apply_steps(&input_rows, &transform.steps);
        if let Err(error) = evaluate_quality(&output_rows, &transform.quality_rule) {
            let run = TransformRun {
                run_id: Uuid::new_v4().to_string(),
                namespace: namespace.into(),
                transform_id: transform_id.into(),
                definition_digest: transform.definition_digest,
                input_digest: rows_digest(&input_rows),
                output_digest: checkpoint
                    .as_ref()
                    .map(|checkpoint| checkpoint.2.clone())
                    .unwrap_or_default(),
                last_input_row_id: after_id,
                incremental,
                quarantined: true,
                quality_rule: error.message(),
                rows_in: input_rows.len() as i32,
                rows_out: 0,
                lineage_parent: checkpoint
                    .as_ref()
                    .map(|checkpoint| checkpoint.1.clone())
                    .unwrap_or_default(),
                created_at_ms: now_ms,
            };
            self.insert_transform_run(&run)?;
            return Ok(run);
        }
        if !incremental {
            self.clear_dataset_rows(&transform.output_dataset_id)?;
        }
        if !output_rows.is_empty() {
            self.append_rows(&transform.output_dataset_id, &output_rows)?;
        }
        let live_rows = self.list_dataset_row_records(&transform.output_dataset_id)?;
        let live: Vec<HashMap<String, String>> =
            live_rows.into_iter().map(|(_, row)| row).collect();
        let run = TransformRun {
            run_id: Uuid::new_v4().to_string(),
            namespace: namespace.into(),
            transform_id: transform_id.into(),
            definition_digest: transform.definition_digest.clone(),
            input_digest: rows_digest(&input_rows),
            output_digest: rows_digest(&live),
            last_input_row_id,
            incremental,
            quarantined: false,
            quality_rule: transform.quality_rule.clone(),
            rows_in: input_rows.len() as i32,
            rows_out: output_rows.len() as i32,
            lineage_parent: checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.1.clone())
                .unwrap_or_default(),
            created_at_ms: now_ms,
        };
        self.insert_transform_run(&run)?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_governed_transform_checkpoint
                 (namespace, transform_id, last_input_row_id, live_run_id, live_output_digest)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    namespace,
                    transform_id,
                    last_input_row_id,
                    run.run_id,
                    run.output_digest
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(run)
    }

    pub fn get_governed_transform_run(&self, run_id: &str) -> Result<Option<TransformRun>, String> {
        self.conn()
            .query_row(
                "SELECT run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
                        last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
                        lineage_parent, created_at_ms
                 FROM sekai_governed_transform_run WHERE run_id = ?1",
                params![run_id],
                |row| {
                    Ok(TransformRun {
                        run_id: row.get(0)?,
                        namespace: row.get(1)?,
                        transform_id: row.get(2)?,
                        definition_digest: row.get(3)?,
                        input_digest: row.get(4)?,
                        output_digest: row.get(5)?,
                        last_input_row_id: row.get(6)?,
                        incremental: row.get::<_, i64>(7)? != 0,
                        quarantined: row.get::<_, i64>(8)? != 0,
                        quality_rule: row.get(9)?,
                        rows_in: row.get(10)?,
                        rows_out: row.get(11)?,
                        lineage_parent: row.get(12)?,
                        created_at_ms: row.get(13)?,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn transform_checkpoint(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<(i64, String, String)>, String> {
        self.conn()
            .query_row(
                "SELECT last_input_row_id, live_run_id, live_output_digest
                 FROM sekai_governed_transform_checkpoint
                 WHERE namespace = ?1 AND transform_id = ?2",
                params![namespace, transform_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn insert_transform_run(&self, run: &TransformRun) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_governed_transform_run
                 (run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
                  last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
                  lineage_parent, created_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    run.run_id,
                    run.namespace,
                    run.transform_id,
                    run.definition_digest,
                    run.input_digest,
                    run.output_digest,
                    run.last_input_row_id,
                    i64::from(run.incremental),
                    i64::from(run.quarantined),
                    run.quality_rule,
                    run.rows_in,
                    run.rows_out,
                    run.lineage_parent,
                    run.created_at_ms
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn clear_dataset_rows(&self, dataset_id: &str) -> Result<(), String> {
        self.conn()
            .execute(
                "DELETE FROM sekai_dataset_rows WHERE dataset_id = ?1",
                params![dataset_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform, TransformStep};

    fn db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn dataset(id: &str) -> Dataset {
        Dataset {
            id: id.into(),
            name: id.into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "keep".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: String::new(),
            created: 1,
        }
    }

    fn step_filter() -> TransformStep {
        TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }
    }

    #[test]
    fn incremental_run_processes_only_new_rows() {
        let db = db();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        let mut rows = Vec::new();
        for i in 0..100 {
            rows.push(HashMap::from([
                ("id".into(), i.to_string()),
                ("keep".into(), "yes".into()),
            ]));
        }
        db.append_rows("in", &rows).unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![step_filter()],
            quality_rule: String::new(),
            definition_digest: String::new(),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let first = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert_eq!(first.rows_in, 100);
        assert!(!first.quarantined);
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "new".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        let second = db.run_governed_transform("ops", "t1", true, 30).unwrap();
        assert_eq!(second.rows_in, 1);
        assert_eq!(second.lineage_parent, first.run_id);
        assert_ne!(second.output_digest, first.output_digest);
        assert_eq!(
            db.query_rows("out", &Default::default()).unwrap().len(),
            101
        );
    }

    #[test]
    fn quality_failure_quarantines_and_keeps_previous_output() {
        let db = db();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![TransformStep {
                kind: "project".into(),
                column: String::new(),
                op: String::new(),
                value: String::new(),
                columns: vec!["id".into(), "keep".into()],
            }],
            quality_rule: "required:keep".into(),
            definition_digest: String::new(),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        db.run_governed_transform("ops", "t1", false, 20).unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "2".into()),
                ("keep".into(), String::new()),
            ])],
        )
        .unwrap();
        let failed = db.run_governed_transform("ops", "t1", true, 30).unwrap();
        assert!(failed.quarantined);
        assert!(failed.quality_rule.contains("required:keep"));
        assert_eq!(db.query_rows("out", &Default::default()).unwrap().len(), 1);
    }

    #[test]
    fn five_transform_pipeline_is_incremental() {
        let db = db();
        for i in 0..6 {
            db.create_dataset(&dataset(&format!("d{i}"))).unwrap();
        }
        db.append_rows(
            "d0",
            &(0..200)
                .map(|i| {
                    HashMap::from([("id".into(), i.to_string()), ("keep".into(), "yes".into())])
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        for i in 0..5 {
            let transform = GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: format!("t{i}"),
                input_dataset_id: format!("d{i}"),
                output_dataset_id: format!("d{}", i + 1),
                steps: vec![step_filter()],
                quality_rule: String::new(),
                definition_digest: String::new(),
            }
            .prepare()
            .unwrap();
            db.put_governed_transform(&transform, 10).unwrap();
            db.run_governed_transform("ops", &format!("t{i}"), false, 20)
                .unwrap();
        }
        db.append_rows(
            "d0",
            &(200..202)
                .map(|i| {
                    HashMap::from([("id".into(), i.to_string()), ("keep".into(), "yes".into())])
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let t0 = db.run_governed_transform("ops", "t0", true, 30).unwrap();
        assert_eq!(t0.rows_in, 2);
        for i in 1..5 {
            db.run_governed_transform("ops", &format!("t{i}"), true, 30)
                .unwrap();
        }
        assert_eq!(db.query_rows("d5", &Default::default()).unwrap().len(), 202);
    }
}

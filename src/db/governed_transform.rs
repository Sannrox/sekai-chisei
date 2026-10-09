use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::DatasetRowRecord;
use crate::sekai::governed_transform::{
    GovernedTransform, TransformRun, bind_checkpoint, checkpoint_after_id, compute_run,
    fold_output_digest, rows_digest,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
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
                    definition_digest TEXT NOT NULL DEFAULT '',
                    last_input_row_id INTEGER NOT NULL,
                    live_run_id TEXT NOT NULL,
                    live_output_digest TEXT NOT NULL,
                    PRIMARY KEY (namespace, transform_id)
                );
                ",
            )
            .map_err(|error| error.to_string())?;
        let _ = self.conn().execute(
            "ALTER TABLE sekai_governed_transform_checkpoint
             ADD COLUMN definition_digest TEXT NOT NULL DEFAULT ''",
            [],
        );
        Ok(())
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

    /// Reference-platform analog: governed dataset writes are one transaction. SQLite
    /// `BEGIN IMMEDIATE` serializes writers on the file the way PostgreSQL
    /// uses `pg_advisory_xact_lock` plus a transaction.
    pub fn run_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        incremental: bool,
        now_ms: i64,
    ) -> Result<TransformRun, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let run = run_governed_transform_tx(&tx, namespace, transform_id, incremental, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
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

    pub fn list_governed_transforms(
        &self,
        namespace: &str,
    ) -> Result<Vec<GovernedTransform>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT definition_json FROM sekai_governed_transform
                 WHERE namespace = ?1 ORDER BY transform_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let json = row.map_err(|error| error.to_string())?;
            serde_json::from_str(&json).map_err(|error| error.to_string())
        })
        .collect()
    }

    pub fn list_governed_transform_runs(
        &self,
        namespace: &str,
        limit: i64,
    ) -> Result<Vec<TransformRun>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
                        last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
                        lineage_parent, created_at_ms
                 FROM sekai_governed_transform_run
                 WHERE namespace = ?1
                 ORDER BY created_at_ms DESC, run_id DESC
                 LIMIT ?2",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, limit], |row| {
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
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }
}

fn run_governed_transform_tx(
    tx: &Transaction<'_>,
    namespace: &str,
    transform_id: &str,
    incremental: bool,
    now_ms: i64,
) -> Result<TransformRun, String> {
    let transform =
        load_transform(tx, namespace, transform_id)?.ok_or("governed transform not found")?;
    if !dataset_exists(tx, &transform.input_dataset_id)?
        || !dataset_exists(tx, &transform.output_dataset_id)?
    {
        return Err("dataset not found".into());
    }
    let stored = load_checkpoint(tx, namespace, transform_id)?;
    let (incremental, checkpoint) =
        bind_checkpoint(incremental, stored, &transform.definition_digest);
    let after_id = checkpoint_after_id(incremental, checkpoint.as_ref());
    let records = list_row_records_after(tx, &transform.input_dataset_id, after_id)?;
    let (mut run, output_rows) = compute_run(
        &transform,
        checkpoint.as_ref(),
        &records,
        incremental,
        now_ms,
        Uuid::new_v4().to_string(),
    );
    if run.quarantined {
        if !incremental {
            run.output_digest = live_output_digest(tx, &transform.output_dataset_id)?;
        }
        insert_transform_run(tx, &run)?;
        return Ok(run);
    }
    if !incremental {
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE dataset_id = ?1",
            params![transform.output_dataset_id],
        )
        .map_err(|error| error.to_string())?;
    }
    append_output_rows(tx, &transform.output_dataset_id, &output_rows)?;
    run.output_digest = if incremental {
        checkpoint
            .as_ref()
            .and_then(|checkpoint| fold_output_digest(&checkpoint.2, &output_rows))
            .ok_or_else(|| "checkpoint digest encoding is not current".to_string())?
    } else {
        rows_digest(&output_rows)
    };
    insert_transform_run(tx, &run)?;
    tx.execute(
        "INSERT OR REPLACE INTO sekai_governed_transform_checkpoint
         (namespace, transform_id, definition_digest, last_input_row_id, live_run_id, live_output_digest)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            namespace,
            transform_id,
            transform.definition_digest,
            run.last_input_row_id,
            run.run_id,
            run.output_digest
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(run)
}

fn load_transform(
    tx: &Transaction<'_>,
    namespace: &str,
    transform_id: &str,
) -> Result<Option<GovernedTransform>, String> {
    tx.query_row(
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

fn dataset_exists(tx: &Transaction<'_>, dataset_id: &str) -> Result<bool, String> {
    tx.query_row(
        "SELECT 1 FROM sekai_datasets WHERE id = ?1",
        params![dataset_id],
        |_| Ok(()),
    )
    .optional()
    .map(|row| row.is_some())
    .map_err(|error| error.to_string())
}

fn load_checkpoint(
    tx: &Transaction<'_>,
    namespace: &str,
    transform_id: &str,
) -> Result<
    Option<(
        crate::sekai::governed_transform::TransformCheckpoint,
        String,
    )>,
    String,
> {
    tx.query_row(
        "SELECT last_input_row_id, live_run_id, live_output_digest, definition_digest
         FROM sekai_governed_transform_checkpoint
         WHERE namespace = ?1 AND transform_id = ?2",
        params![namespace, transform_id],
        |row| Ok(((row.get(0)?, row.get(1)?, row.get(2)?), row.get(3)?)),
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn list_row_records_after(
    tx: &Transaction<'_>,
    dataset_id: &str,
    after_id: i64,
) -> Result<Vec<DatasetRowRecord>, String> {
    let mut stmt = tx
        .prepare(
            "SELECT id, data FROM sekai_dataset_rows
             WHERE dataset_id = ?1 AND id > ?2
             ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let mut rows_iter = stmt
        .query(params![dataset_id, after_id])
        .map_err(|error| error.to_string())?;
    let mut results = Vec::new();
    while let Some(row) = rows_iter.next().map_err(|error| error.to_string())? {
        let id: i64 = row.get(0).map_err(|error| error.to_string())?;
        let data: String = row.get(1).map_err(|error| error.to_string())?;
        let map: HashMap<String, String> = serde_json::from_str(&data)
            .map_err(|error| format!("corrupt dataset row for {dataset_id:?}: {error}"))?;
        results.push((id, map));
    }
    Ok(results)
}

fn live_output_digest(tx: &Transaction<'_>, dataset_id: &str) -> Result<String, String> {
    let live: Vec<HashMap<String, String>> = list_row_records_after(tx, dataset_id, 0)?
        .into_iter()
        .map(|(_, row)| row)
        .collect();
    Ok(rows_digest(&live))
}

fn append_output_rows(
    tx: &Transaction<'_>,
    dataset_id: &str,
    rows: &[HashMap<String, String>],
) -> Result<(), String> {
    if rows.is_empty() {
        return Ok(());
    }
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
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn insert_transform_run(tx: &Transaction<'_>, run: &TransformRun) -> Result<(), String> {
    tx.execute(
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
        let listed = db.list_governed_transform_runs("ops", 10).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].run_id, second.run_id);
        assert_ne!(second.output_digest, first.output_digest);
        let live = db.query_rows("out", &Default::default()).unwrap();
        assert_eq!(live.len(), 101);
        assert_eq!(second.output_digest, rows_digest(&live));
        let after_first = db
            .list_dataset_row_records_after("in", first.last_input_row_id)
            .unwrap();
        assert_eq!(after_first.len(), 1);
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

    #[test]
    fn missing_output_dataset_fails_closed() {
        let db = db();
        db.create_dataset(&dataset("in")).unwrap();
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
            output_dataset_id: "missing".into(),
            steps: vec![step_filter()],
            quality_rule: String::new(),
            definition_digest: String::new(),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let error = db
            .run_governed_transform("ops", "t1", false, 20)
            .unwrap_err();
        assert_eq!(error, "dataset not found");
        assert!(
            db.list_governed_transform_runs("ops", 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn missing_input_dataset_fails_closed() {
        let db = db();
        db.create_dataset(&dataset("out")).unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "missing".into(),
            output_dataset_id: "out".into(),
            steps: vec![step_filter()],
            quality_rule: String::new(),
            definition_digest: String::new(),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let error = db
            .run_governed_transform("ops", "t1", false, 20)
            .unwrap_err();
        assert_eq!(error, "dataset not found");
        assert!(
            db.list_governed_transform_runs("ops", 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            db.query_rows("out", &Default::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn replaced_definition_rebuilds_instead_of_incremental() {
        let db = db();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.create_dataset(&dataset("out2")).unwrap();
        db.append_rows(
            "in",
            &[
                HashMap::from([("id".into(), "1".into()), ("keep".into(), "yes".into())]),
                HashMap::from([("id".into(), "2".into()), ("keep".into(), "yes".into())]),
            ],
        )
        .unwrap();
        let first = GovernedTransform {
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
        db.put_governed_transform(&first, 10).unwrap();
        let run = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert_eq!(run.rows_in, 2);
        let replaced = GovernedTransform {
            output_dataset_id: "out2".into(),
            definition_digest: String::new(),
            ..first
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&replaced, 30).unwrap();
        let rebuilt = db.run_governed_transform("ops", "t1", true, 40).unwrap();
        assert!(!rebuilt.incremental);
        assert_eq!(rebuilt.rows_in, 2);
        assert_eq!(rebuilt.lineage_parent, run.run_id);
        assert_eq!(db.query_rows("out2", &Default::default()).unwrap().len(), 2);
    }

    #[test]
    fn old_format_checkpoint_digest_forces_full_rebuild() {
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
            steps: vec![step_filter()],
            quality_rule: String::new(),
            definition_digest: String::new(),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let first = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert!(!first.incremental);
        db.conn()
            .execute(
                "UPDATE sekai_governed_transform_checkpoint
                 SET live_output_digest = ?1
                 WHERE namespace = 'ops' AND transform_id = 't1'",
                params![format!("sha256:{}", "ab".repeat(32))],
            )
            .unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "2".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        let rebuilt = db.run_governed_transform("ops", "t1", true, 30).unwrap();
        assert!(!rebuilt.incremental);
        assert_eq!(rebuilt.rows_in, 2);
        let live = db.query_rows("out", &Default::default()).unwrap();
        assert_eq!(live.len(), 2);
        assert_eq!(rebuilt.output_digest, rows_digest(&live));
        assert!(
            rebuilt
                .output_digest
                .starts_with(crate::sekai::governed_transform::OUTPUT_DIGEST_PREFIX)
        );
    }

    #[test]
    fn quarantined_replacement_receipt_uses_the_current_output() {
        let db = db();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.create_dataset(&dataset("out2")).unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        let first = GovernedTransform {
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
        db.put_governed_transform(&first, 10).unwrap();
        let run = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        let replaced = GovernedTransform {
            output_dataset_id: "out2".into(),
            quality_rule: "min_rows:1".into(),
            definition_digest: String::new(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: "no".into(),
                columns: Vec::new(),
            }],
            ..first
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&replaced, 30).unwrap();
        let failed = db.run_governed_transform("ops", "t1", true, 40).unwrap();
        assert!(failed.quarantined);
        assert_eq!(failed.lineage_parent, run.run_id);
        assert_eq!(failed.output_digest, rows_digest(&[]));
        assert_ne!(failed.output_digest, run.output_digest);
        assert_eq!(db.query_rows("out", &Default::default()).unwrap().len(), 1);
        assert!(
            db.query_rows("out2", &Default::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn full_run_append_failure_keeps_previous_output() {
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
            steps: vec![step_filter()],
            quality_rule: String::new(),
            definition_digest: String::new(),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let first = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        db.conn()
            .execute_batch(
                "CREATE TRIGGER fail_out_append BEFORE INSERT ON sekai_dataset_rows
                 WHEN NEW.dataset_id = 'out'
                 BEGIN
                   SELECT RAISE(ABORT, 'injected append failure');
                 END;",
            )
            .unwrap();
        let error = db
            .run_governed_transform("ops", "t1", false, 30)
            .unwrap_err();
        assert!(error.contains("injected append failure"), "{error}");
        let live = db.query_rows("out", &Default::default()).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0]["id"], "1");
        let listed = db.list_governed_transform_runs("ops", 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].run_id, first.run_id);
        assert_eq!(listed[0].output_digest, rows_digest(&live));
    }

    fn persistent_transform_db() -> (tempfile::TempDir, SekaiDb, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transform.db");
        let path = path.to_str().unwrap().to_string();
        let db = SekaiDb::new(&path).unwrap();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows(
            "in",
            &[
                HashMap::from([("id".into(), "1".into()), ("keep".into(), "yes".into())]),
                HashMap::from([("id".into(), "2".into()), ("keep".into(), "yes".into())]),
            ],
        )
        .unwrap();
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
        (dir, db, path)
    }

    #[test]
    fn concurrent_incremental_runs_do_not_duplicate_output() {
        let (_dir, db, path) = persistent_transform_db();
        db.run_governed_transform("ops", "t1", false, 20).unwrap();
        db.append_rows(
            "in",
            &[
                HashMap::from([("id".into(), "3".into()), ("keep".into(), "yes".into())]),
                HashMap::from([("id".into(), "4".into()), ("keep".into(), "yes".into())]),
            ],
        )
        .unwrap();
        drop(db);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let joins: Vec<_> = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    let db = SekaiDb::new(&path).unwrap();
                    barrier.wait();
                    db.run_governed_transform("ops", "t1", true, 30)
                })
            })
            .collect();
        for join in joins {
            join.join().unwrap().unwrap();
        }
        let db = SekaiDb::new(&path).unwrap();
        let live = db.query_rows("out", &Default::default()).unwrap();
        let mut ids: Vec<_> = live.iter().map(|row| row["id"].clone()).collect();
        ids.sort();
        assert_eq!(ids, ["1", "2", "3", "4"]);
        let latest = db.list_governed_transform_runs("ops", 1).unwrap();
        assert_eq!(latest[0].output_digest, rows_digest(&live));
    }

    #[test]
    fn concurrent_full_runs_do_not_duplicate_output() {
        let (_dir, db, path) = persistent_transform_db();
        db.run_governed_transform("ops", "t1", false, 20).unwrap();
        drop(db);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let joins: Vec<_> = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    let db = SekaiDb::new(&path).unwrap();
                    barrier.wait();
                    db.run_governed_transform("ops", "t1", false, 30)
                })
            })
            .collect();
        for join in joins {
            join.join().unwrap().unwrap();
        }
        let db = SekaiDb::new(&path).unwrap();
        let live = db.query_rows("out", &Default::default()).unwrap();
        let mut ids: Vec<_> = live.iter().map(|row| row["id"].clone()).collect();
        ids.sort();
        assert_eq!(ids, ["1", "2"]);
        let latest = db.list_governed_transform_runs("ops", 1).unwrap();
        assert_eq!(latest[0].output_digest, rows_digest(&live));
    }
}

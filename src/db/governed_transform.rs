use crate::db::sekai::SekaiDb;
use crate::sekai::classification_lattice::ClassificationLattice;
use crate::sekai::dataset::DatasetRowRecord;
use crate::sekai::governed_transform::{
    GovernedTransform, InputLoadBudget, TransformInputRows, TransformRun, bind_checkpoint,
    budget_quarantined_run, checkpoint_after_id, compute_run_tables_until,
    derive_transform_markings, fold_output_digest, require_bound_output_for_markings, rows_digest,
};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
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
                    created_at_ms INTEGER NOT NULL,
                    markings_in TEXT NOT NULL DEFAULT '',
                    markings_out TEXT NOT NULL DEFAULT ''
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
        let _ = self.conn().execute(
            "ALTER TABLE sekai_governed_transform_run
             ADD COLUMN markings_in TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = self.conn().execute(
            "ALTER TABLE sekai_governed_transform_run
             ADD COLUMN markings_out TEXT NOT NULL DEFAULT ''",
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
                        lineage_parent, created_at_ms, markings_in, markings_out
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
                        markings_in: row.get(14).unwrap_or_default(),
                        markings_out: row.get(15).unwrap_or_default(),
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
                        lineage_parent, created_at_ms, markings_in, markings_out
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
                    markings_in: row.get(14).unwrap_or_default(),
                    markings_out: row.get(15).unwrap_or_default(),
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
    let bindings = transform.input_bindings();
    for (_, dataset_id) in &bindings {
        if !dataset_exists(tx, dataset_id)? {
            return Err("dataset not found".into());
        }
    }
    if !dataset_exists(tx, &transform.output_dataset_id)? {
        return Err("dataset not found".into());
    }
    let stored = load_checkpoint(tx, namespace, transform_id)?;
    let (mut incremental, checkpoint) =
        bind_checkpoint(incremental, stored, &transform.definition_digest);
    if !transform.allows_incremental() {
        incremental = false;
    }
    let after_id = checkpoint_after_id(incremental, checkpoint.as_ref());
    let mut load_budget = InputLoadBudget::for_transform(&transform);
    let mut loaded: Vec<(String, Vec<String>, Vec<DatasetRowRecord>)> = Vec::new();
    let mut input_object_tokens: Vec<Option<String>> = Vec::new();
    for (alias, dataset_id) in &bindings {
        loaded.push((
            alias.clone(),
            load_dataset_column_names(tx, dataset_id)?,
            list_row_records_after(tx, dataset_id, after_id, load_budget.as_mut())?,
        ));
        let object_id = load_dataset_object_id(tx, dataset_id)?;
        input_object_tokens.push(load_object_marking_token(tx, &object_id)?);
        if load_budget
            .as_ref()
            .is_some_and(|budget| budget.exceeded.is_some())
        {
            break;
        }
    }
    if let Some(budget) = load_budget.as_mut() {
        budget.expire_if_past();
    }
    let lattice = load_lattice(tx, namespace)?;
    let output_object_id = load_dataset_object_id(tx, &transform.output_dataset_id)?;
    let prior_token = load_object_marking_token(tx, &output_object_id)?;
    let marking_rows: Vec<&HashMap<String, String>> = loaded
        .iter()
        .flat_map(|(_, _, records)| records.iter().map(|(_, row)| row))
        .collect();
    let (markings_in, markings_out) = derive_transform_markings(
        lattice.as_ref(),
        input_object_tokens.iter().map(|token| token.as_deref()),
        prior_token.as_deref(),
        marking_rows,
    )?;
    if let Some(budget) = load_budget.as_mut() {
        budget.expire_if_past();
    }
    let tables: Vec<TransformInputRows<'_>> = loaded
        .iter()
        .map(|(alias, columns, records)| TransformInputRows {
            alias,
            records,
            columns,
        })
        .collect();
    let deadline = load_budget.as_ref().map(|budget| budget.deadline());
    let (mut run, output_rows) =
        if let Some(reason) = load_budget.and_then(|budget| budget.exceeded) {
            (
                budget_quarantined_run(
                    &transform,
                    checkpoint.as_ref(),
                    incremental,
                    now_ms,
                    Uuid::new_v4().to_string(),
                    loaded
                        .iter()
                        .map(|(_, _, records)| records.len() as i32)
                        .sum(),
                    reason,
                ),
                Vec::new(),
            )
        } else {
            compute_run_tables_until(
                &transform,
                checkpoint.as_ref(),
                &tables,
                incremental,
                now_ms,
                Uuid::new_v4().to_string(),
                deadline,
            )
        };
    run.markings_in = markings_in;
    run.markings_out = markings_out;
    if run.quarantined {
        if !incremental {
            run.output_digest = live_output_digest(tx, &transform.output_dataset_id)?;
        }
        insert_transform_run(tx, &run)?;
        return Ok(run);
    }
    require_bound_output_for_markings(&output_object_id, &run.markings_out)?;
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
    stamp_object_marking(tx, &output_object_id, &run.markings_out, now_ms)?;
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
    mut budget: Option<&mut InputLoadBudget>,
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
        let data = match row.get_ref(1).map_err(|error| error.to_string())? {
            rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes) => {
                bytes
            }
            rusqlite::types::ValueRef::Null => b"{}",
            other => {
                return Err(format!("corrupt dataset row for {dataset_id:?}: {other:?}"));
            }
        };
        if let Some(budget) = budget.as_mut()
            && !budget.allow_encoded(data.len() as u64)
        {
            break;
        }
        let map: HashMap<String, String> = serde_json::from_slice(data)
            .map_err(|error| format!("corrupt dataset row for {dataset_id:?}: {error}"))?;
        if let Some(budget) = budget.as_mut()
            && !budget.charge(&map)
        {
            break;
        }
        results.push((id, map));
    }
    Ok(results)
}

fn live_output_digest(tx: &Transaction<'_>, dataset_id: &str) -> Result<String, String> {
    let live: Vec<HashMap<String, String>> = list_row_records_after(tx, dataset_id, 0, None)?
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
          lineage_parent, created_at_ms, markings_in, markings_out)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
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
            run.created_at_ms,
            run.markings_in,
            run.markings_out
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn load_lattice(
    tx: &Transaction<'_>,
    namespace: &str,
) -> Result<Option<ClassificationLattice>, String> {
    match tx.query_row(
        "SELECT lattice_json FROM sekai_classification_lattices WHERE namespace = ?1",
        params![namespace],
        |row| row.get::<_, String>(0),
    ) {
        Ok(json) => {
            let lattice: ClassificationLattice =
                serde_json::from_str(&json).map_err(|error| error.to_string())?;
            lattice.prepare().map(Some)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => {
            let message = error.to_string();
            if message.contains("no such table") {
                Ok(None)
            } else {
                Err(message)
            }
        }
    }
}

fn load_dataset_column_names(
    tx: &Transaction<'_>,
    dataset_id: &str,
) -> Result<Vec<String>, String> {
    let json: String = tx
        .query_row(
            "SELECT columns FROM sekai_datasets WHERE id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "dataset not found".to_string())?;
    dataset_column_names(&json)
}

pub(crate) fn dataset_column_names(json: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|error| format!("corrupt dataset columns: {error}"))?;
    let Some(items) = value.as_array() else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for item in items {
        if let Some(name) = item.get(0).and_then(serde_json::Value::as_str) {
            names.push(name.to_string());
        } else if let Some(name) = item
            .as_array()
            .and_then(|pair| pair.first())
            .and_then(|value| value.as_str())
        {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

fn load_dataset_object_id(tx: &Transaction<'_>, dataset_id: &str) -> Result<String, String> {
    tx.query_row(
        "SELECT object_id FROM sekai_datasets WHERE id = ?1",
        params![dataset_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "dataset not found".into())
}

fn load_object_marking_token(
    tx: &Transaction<'_>,
    object_id: &str,
) -> Result<Option<String>, String> {
    if object_id.trim().is_empty() {
        return Ok(None);
    }
    let properties = tx
        .query_row(
            "SELECT properties FROM sekai_objects WHERE id = ?1",
            params![object_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("input markings unresolvable: object {object_id} not found"))?;
    let map: HashMap<String, String> =
        serde_json::from_str(&properties).map_err(|error| error.to_string())?;
    Ok(map
        .get(OBJECT_CLASSIFICATION_PROPERTY)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn stamp_object_marking(
    tx: &Transaction<'_>,
    object_id: &str,
    token: &str,
    now_ms: i64,
) -> Result<(), String> {
    if object_id.trim().is_empty() {
        return Ok(());
    }
    let properties = tx
        .query_row(
            "SELECT properties FROM sekai_objects WHERE id = ?1",
            params![object_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("output markings unresolvable: object {object_id} not found"))?;
    let mut map: HashMap<String, String> =
        serde_json::from_str(&properties).map_err(|error| error.to_string())?;
    if token.trim().is_empty() {
        map.remove(OBJECT_CLASSIFICATION_PROPERTY);
    } else {
        map.insert(
            OBJECT_CLASSIFICATION_PROPERTY.to_string(),
            token.to_string(),
        );
    }
    let json = serde_json::to_string(&map).map_err(|error| error.to_string())?;
    let changed = tx
        .execute(
            "UPDATE sekai_objects SET properties = ?1, updated = ?2 WHERE id = ?3",
            params![json, now_ms, object_id],
        )
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err(format!(
            "output markings unresolvable: object {object_id} not found"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        AnalyticalSpec, CONTRACT_VERSION, GovernedTransform, TransformInput, TransformStep,
    };

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
            analytical: None,
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
            analytical: None,
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
                analytical: None,
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
            analytical: None,
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
            analytical: None,
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
            analytical: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&first, 10).unwrap();
        let run = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert_eq!(run.rows_in, 2);
        let replaced = GovernedTransform {
            output_dataset_id: "out2".into(),
            definition_digest: String::new(),
            analytical: None,
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
            analytical: None,
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
            analytical: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&first, 10).unwrap();
        let run = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        let replaced = GovernedTransform {
            output_dataset_id: "out2".into(),
            quality_rule: "min_rows:1".into(),
            definition_digest: String::new(),
            analytical: None,
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
            analytical: None,
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
            analytical: None,
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

    fn object(id: &str, marking: Option<&str>) -> crate::domain::Object {
        let mut properties = HashMap::new();
        if let Some(marking) = marking {
            properties.insert(OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into());
        }
        crate::domain::Object {
            id: id.into(),
            kind: "artifact".into(),
            name: id.into(),
            namespace: "ops".into(),
            external_id: format!("artifact:{id}"),
            properties,
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn transform_unions_input_markings_onto_output_and_receipt() {
        let db = db();
        let mut input = dataset("in");
        input.object_id = "in-obj".into();
        let mut output = dataset("out");
        output.object_id = "out-obj".into();
        db.create_object(&object("in-obj", Some("internal")))
            .unwrap();
        db.create_object(&object("out-obj", None)).unwrap();
        db.create_dataset(&input).unwrap();
        db.create_dataset(&output).unwrap();
        db.append_rows(
            "in",
            &[
                HashMap::from([
                    ("id".into(), "1".into()),
                    ("keep".into(), "yes".into()),
                    (OBJECT_CLASSIFICATION_PROPERTY.into(), "internal".into()),
                ]),
                HashMap::from([
                    ("id".into(), "2".into()),
                    ("keep".into(), "yes".into()),
                    (OBJECT_CLASSIFICATION_PROPERTY.into(), "confidential".into()),
                ]),
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
            analytical: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let run = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert!(run.markings_in.contains("internal"));
        assert!(run.markings_in.contains("confidential"));
        assert_eq!(run.markings_out, "confidential");
        let stored = db.get_governed_transform_run(&run.run_id).unwrap().unwrap();
        assert_eq!(stored.markings_out, "confidential");
        let output_object = db.get_object("out-obj").unwrap().unwrap();
        assert_eq!(
            output_object.properties.get(OBJECT_CLASSIFICATION_PROPERTY),
            Some(&"confidential".to_string())
        );
    }

    #[test]
    fn full_rebuild_folds_live_output_marking() {
        let db = db();
        let mut input = dataset("in");
        input.object_id = "in-obj".into();
        let mut output = dataset("out");
        output.object_id = "out-obj".into();
        db.create_object(&object("in-obj", Some("public"))).unwrap();
        db.create_object(&object("out-obj", Some("confidential")))
            .unwrap();
        db.create_dataset(&input).unwrap();
        db.create_dataset(&output).unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
                (OBJECT_CLASSIFICATION_PROPERTY.into(), "public".into()),
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
            analytical: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let run = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert_eq!(run.markings_in, "public");
        assert_eq!(run.markings_out, "confidential");
        let output_object = db.get_object("out-obj").unwrap().unwrap();
        assert_eq!(
            output_object.properties.get(OBJECT_CLASSIFICATION_PROPERTY),
            Some(&"confidential".to_string())
        );
    }

    #[test]
    fn marked_run_without_output_object_fails_closed_without_writing() {
        let db = db();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
                (OBJECT_CLASSIFICATION_PROPERTY.into(), "confidential".into()),
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
            analytical: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let error = db
            .run_governed_transform("ops", "t1", false, 20)
            .unwrap_err();
        assert!(error.contains("output markings unresolvable"), "{error}");
        assert!(
            db.query_rows("out", &Default::default())
                .unwrap()
                .is_empty()
        );
        assert!(
            db.list_governed_transform_runs("ops", 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn unknown_input_marking_fails_closed_without_writing_output() {
        let db = db();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
                (OBJECT_CLASSIFICATION_PROPERTY.into(), "secret-sauce".into()),
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
            analytical: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let error = db
            .run_governed_transform("ops", "t1", false, 20)
            .unwrap_err();
        assert!(error.contains("unknown classification marking"), "{error}");
        assert!(
            db.query_rows("out", &Default::default())
                .unwrap()
                .is_empty()
        );
        assert!(
            db.list_governed_transform_runs("ops", 10)
                .unwrap()
                .is_empty()
        );
    }

    fn analytical_filter() -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![step_filter()],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec::default()),
        }
        .prepare()
        .unwrap()
    }

    #[test]
    fn incremental_run_processes_only_new_rows_on_analytical_profile() {
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
        db.put_governed_transform(&analytical_filter(), 10).unwrap();
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
        let live = db.query_rows("out", &Default::default()).unwrap();
        assert_eq!(live.len(), 101);
        assert_eq!(second.output_digest, rows_digest(&live));
    }

    #[test]
    fn quality_failure_quarantines_and_keeps_previous_output_on_analytical_profile() {
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
            analytical: Some(AnalyticalSpec::default()),
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
    fn five_transform_pipeline_is_incremental_on_analytical_profile() {
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
                analytical: Some(AnalyticalSpec::default()),
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
    fn analytical_join_aggregate_writes_receipt() {
        let db = db();
        let customers = Dataset {
            id: "customers".into(),
            name: "customers".into(),
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
        };
        let orders = Dataset {
            id: "orders".into(),
            name: "orders".into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "customer_id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "amount".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: String::new(),
            created: 1,
        };
        db.create_dataset(&customers).unwrap();
        db.create_dataset(&orders).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows(
            "customers",
            &[
                HashMap::from([("id".into(), "c1".into()), ("region".into(), "east".into())]),
                HashMap::from([("id".into(), "c2".into()), ("region".into(), "west".into())]),
            ],
        )
        .unwrap();
        db.append_rows(
            "orders",
            &[
                HashMap::from([
                    ("id".into(), "o1".into()),
                    ("customer_id".into(), "c1".into()),
                    ("amount".into(), "10".into()),
                ]),
                HashMap::from([
                    ("id".into(), "o2".into()),
                    ("customer_id".into(), "c1".into()),
                    ("amount".into(), "5".into()),
                ]),
            ],
        )
        .unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "join1".into(),
            input_dataset_id: "customers".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec {
                inputs: vec![
                    TransformInput {
                        alias: "customers".into(),
                        dataset_id: "customers".into(),
                    },
                    TransformInput {
                        alias: "orders".into(),
                        dataset_id: "orders".into(),
                    },
                ],
                sql: "SELECT c.region AS region, COUNT(*) AS orders, SUM(o.amount) AS total FROM orders o JOIN customers c ON o.customer_id = c.id GROUP BY c.region".into(),
                memory_limit_bytes: 0,
                time_limit_ms: 0,
            }),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let run = db
            .run_governed_transform("ops", "join1", false, 20)
            .unwrap();
        assert!(!run.quarantined);
        assert_eq!(run.rows_out, 1);
        assert!(run.definition_digest.starts_with("sha256:"));
        assert!(!run.input_digest.is_empty());
        let live = db.query_rows("out", &Default::default()).unwrap();
        assert_eq!(live[0].get("region").map(String::as_str), Some("east"));
        assert_eq!(live[0].get("orders").map(String::as_str), Some("2"));
    }

    #[test]
    fn over_budget_analytical_query_keeps_previous_output() {
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
        db.put_governed_transform(&analytical_filter(), 10).unwrap();
        db.run_governed_transform("ops", "t1", false, 20).unwrap();
        let hog = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec {
                inputs: vec![TransformInput {
                    alias: "input".into(),
                    dataset_id: "in".into(),
                }],
                sql: "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t) SELECT n FROM t"
                    .into(),
                memory_limit_bytes: 0,
                time_limit_ms: 1,
            }),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&hog, 40).unwrap();
        let failed = db.run_governed_transform("ops", "t1", false, 50).unwrap();
        assert!(failed.quarantined);
        assert_eq!(
            failed.quality_rule,
            crate::sekai::transform_engine::BUDGET_TIME
        );
        assert_eq!(db.query_rows("out", &Default::default()).unwrap().len(), 1);
    }

    #[test]
    fn over_budget_input_load_keeps_previous_output() {
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
        db.put_governed_transform(&analytical_filter(), 10).unwrap();
        db.run_governed_transform("ops", "t1", false, 20).unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "2".into()),
                ("keep".into(), "x".repeat(400)),
            ])],
        )
        .unwrap();
        let hog = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec {
                inputs: vec![TransformInput {
                    alias: "input".into(),
                    dataset_id: "in".into(),
                }],
                sql: "SELECT * FROM input".into(),
                memory_limit_bytes: 80,
                time_limit_ms: 5_000,
            }),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&hog, 40).unwrap();
        let failed = db.run_governed_transform("ops", "t1", false, 50).unwrap();
        assert!(failed.quarantined);
        assert_eq!(
            failed.quality_rule,
            crate::sekai::transform_engine::BUDGET_MEMORY
        );
        assert_eq!(db.query_rows("out", &Default::default()).unwrap().len(), 1);
    }

    #[test]
    fn incremental_analytical_join_rebuilds_from_all_rows() {
        let db = db();
        let customers = Dataset {
            id: "customers".into(),
            name: "customers".into(),
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
        };
        let orders = Dataset {
            id: "orders".into(),
            name: "orders".into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "customer_id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "amount".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: String::new(),
            created: 1,
        };
        db.create_dataset(&customers).unwrap();
        db.create_dataset(&orders).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows(
            "customers",
            &[
                HashMap::from([("id".into(), "c1".into()), ("region".into(), "east".into())]),
                HashMap::from([("id".into(), "c2".into()), ("region".into(), "west".into())]),
            ],
        )
        .unwrap();
        db.append_rows(
            "orders",
            &[HashMap::from([
                ("id".into(), "o1".into()),
                ("customer_id".into(), "c1".into()),
                ("amount".into(), "10".into()),
            ])],
        )
        .unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "join1".into(),
            input_dataset_id: "customers".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec {
                inputs: vec![
                    TransformInput {
                        alias: "customers".into(),
                        dataset_id: "customers".into(),
                    },
                    TransformInput {
                        alias: "orders".into(),
                        dataset_id: "orders".into(),
                    },
                ],
                sql: "SELECT c.region AS region, COUNT(*) AS orders FROM orders o JOIN customers c ON o.customer_id = c.id GROUP BY c.region".into(),
                memory_limit_bytes: 0,
                time_limit_ms: 0,
            }),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        db.run_governed_transform("ops", "join1", false, 20)
            .unwrap();
        db.append_rows(
            "orders",
            &[HashMap::from([
                ("id".into(), "o2".into()),
                ("customer_id".into(), "c2".into()),
                ("amount".into(), "4".into()),
            ])],
        )
        .unwrap();
        let second = db.run_governed_transform("ops", "join1", true, 30).unwrap();
        assert!(!second.incremental);
        assert_eq!(second.rows_out, 2);
        let live = db.query_rows("out", &Default::default()).unwrap();
        assert_eq!(live.len(), 2);
    }

    #[test]
    fn analytical_join_unions_secondary_input_object_marking() {
        let db = db();
        let mut customers = Dataset {
            id: "customers".into(),
            name: "customers".into(),
            columns: vec![ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: "cust-obj".into(),
            created: 1,
        };
        customers.columns.push(ColumnDef {
            name: "region".into(),
            col_type: "string".into(),
            classification: "public".into(),
        });
        let orders = Dataset {
            id: "orders".into(),
            name: "orders".into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "customer_id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: "ord-obj".into(),
            created: 1,
        };
        let mut output = dataset("out");
        output.object_id = "out-obj".into();
        db.create_object(&object("cust-obj", Some("public")))
            .unwrap();
        db.create_object(&object("ord-obj", Some("confidential")))
            .unwrap();
        db.create_object(&object("out-obj", None)).unwrap();
        db.create_dataset(&customers).unwrap();
        db.create_dataset(&orders).unwrap();
        db.create_dataset(&output).unwrap();
        db.append_rows(
            "customers",
            &[HashMap::from([
                ("id".into(), "c1".into()),
                ("region".into(), "east".into()),
            ])],
        )
        .unwrap();
        db.append_rows(
            "orders",
            &[HashMap::from([
                ("id".into(), "o1".into()),
                ("customer_id".into(), "c1".into()),
            ])],
        )
        .unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "join1".into(),
            input_dataset_id: "customers".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec {
                inputs: vec![
                    TransformInput {
                        alias: "customers".into(),
                        dataset_id: "customers".into(),
                    },
                    TransformInput {
                        alias: "orders".into(),
                        dataset_id: "orders".into(),
                    },
                ],
                sql: "SELECT c.region AS region, COUNT(*) AS orders FROM orders o JOIN customers c ON o.customer_id = c.id GROUP BY c.region".into(),
                memory_limit_bytes: 0,
                time_limit_ms: 0,
            }),
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let run = db
            .run_governed_transform("ops", "join1", false, 20)
            .unwrap();
        assert!(run.markings_in.contains("confidential"));
        assert_eq!(run.markings_out, "confidential");
    }
}

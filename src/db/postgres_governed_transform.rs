//! PostgreSQL persistence for plane-owned governed transforms (#1287).

use postgres::Row;
use std::collections::HashMap;
use uuid::Uuid;

use crate::db::postgres::{PostgresDb, advisory_lock_key, lock_dataset_rows};
use crate::db::postgres_audit::lock_object_lifecycle;
use crate::domain::storage_properties_json;
use crate::sekai::dataset::DatasetRowRecord;
use crate::sekai::governed_transform::{
    GovernedTransform, TransformRun, bind_checkpoint, checkpoint_after_id, compute_run,
    derive_transform_markings, fold_output_digest, require_bound_output_for_markings, rows_digest,
};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;

impl PostgresDb {
    pub fn put_governed_transform(
        &self,
        transform: &GovernedTransform,
        created_at_ms: i64,
    ) -> Result<(), String> {
        let json = serde_json::to_string(transform).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_governed_transform
                 (namespace, transform_id, definition_json, definition_digest,
                  input_dataset_id, output_dataset_id, created_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)
                 ON CONFLICT (namespace, transform_id) DO UPDATE SET
                    definition_json = EXCLUDED.definition_json,
                    definition_digest = EXCLUDED.definition_digest,
                    input_dataset_id = EXCLUDED.input_dataset_id,
                    output_dataset_id = EXCLUDED.output_dataset_id,
                    created_at_ms = EXCLUDED.created_at_ms",
                &[
                    &transform.namespace,
                    &transform.transform_id,
                    &json,
                    &transform.definition_digest,
                    &transform.input_dataset_id,
                    &transform.output_dataset_id,
                    &created_at_ms,
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
        self.connection()?
            .query_opt(
                "SELECT definition_json FROM sekai_governed_transform
                 WHERE namespace = $1 AND transform_id = $2",
                &[&namespace, &transform_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .transpose()
    }

    pub fn run_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        incremental: bool,
        now_ms: i64,
    ) -> Result<TransformRun, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = advisory_lock_key(&["governed_transform", namespace, transform_id]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let transform = load_transform(&mut tx, namespace, transform_id)?
            .ok_or_else(|| "governed transform not found".to_string())?;
        lock_transform_datasets(
            &mut tx,
            &transform.input_dataset_id,
            &transform.output_dataset_id,
        )?;
        let stored = load_checkpoint(&mut tx, namespace, transform_id)?;
        let (incremental, checkpoint) =
            bind_checkpoint(incremental, stored, &transform.definition_digest);
        let after_id = checkpoint_after_id(incremental, checkpoint.as_ref());
        let records = load_row_records(&mut tx, &transform.input_dataset_id, after_id)?;
        let input_object_id = load_dataset_object_id(&mut tx, &transform.input_dataset_id)?;
        let input_token = load_object_marking_token(&mut tx, &input_object_id)?;
        let output_object_id = load_dataset_object_id(&mut tx, &transform.output_dataset_id)?;
        if !output_object_id.trim().is_empty() {
            lock_object_lifecycle(&mut tx, &output_object_id)?;
        }
        let prior_token = load_object_marking_token(&mut tx, &output_object_id)?;
        let (markings_in, markings_out) = derive_transform_markings(
            None,
            input_token.as_deref(),
            prior_token.as_deref(),
            records.iter().map(|(_, row)| row),
        )?;
        let (mut run, output_rows) = compute_run(
            &transform,
            checkpoint.as_ref(),
            &records,
            incremental,
            now_ms,
            Uuid::new_v4().to_string(),
        );
        run.markings_in = markings_in;
        run.markings_out = markings_out;
        if run.quarantined {
            if !incremental {
                let live: Vec<HashMap<String, String>> =
                    load_row_records(&mut tx, &transform.output_dataset_id, 0)?
                        .into_iter()
                        .map(|(_, row)| row)
                        .collect();
                run.output_digest = rows_digest(&live);
            }
            insert_transform_run(&mut tx, &run)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(run);
        }
        require_bound_output_for_markings(&output_object_id, &run.markings_out)?;
        if !incremental {
            tx.execute(
                "DELETE FROM sekai_dataset_rows WHERE dataset_id = $1",
                &[&transform.output_dataset_id],
            )
            .map_err(|error| error.to_string())?;
        }
        insert_output_rows(&mut tx, &transform.output_dataset_id, &output_rows)?;
        run.output_digest = if incremental {
            checkpoint
                .as_ref()
                .and_then(|checkpoint| fold_output_digest(&checkpoint.2, &output_rows))
                .ok_or_else(|| "checkpoint digest encoding is not current".to_string())?
        } else {
            rows_digest(&output_rows)
        };
        stamp_object_marking(&mut tx, &output_object_id, &run.markings_out, now_ms)?;
        insert_transform_run(&mut tx, &run)?;
        tx.execute(
            "INSERT INTO sekai_governed_transform_checkpoint
             (namespace, transform_id, definition_digest, last_input_row_id, live_run_id, live_output_digest)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (namespace, transform_id) DO UPDATE SET
                definition_digest = EXCLUDED.definition_digest,
                last_input_row_id = EXCLUDED.last_input_row_id,
                live_run_id = EXCLUDED.live_run_id,
                live_output_digest = EXCLUDED.live_output_digest",
            &[
                &namespace,
                &transform_id,
                &transform.definition_digest,
                &run.last_input_row_id,
                &run.run_id,
                &run.output_digest,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(run)
    }

    pub fn get_governed_transform_run(&self, run_id: &str) -> Result<Option<TransformRun>, String> {
        self.connection()?
            .query_opt(
                "SELECT run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
                        last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
                        lineage_parent, created_at_ms, markings_in, markings_out
                 FROM sekai_governed_transform_run WHERE run_id = $1",
                &[&run_id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_run)
            .transpose()
    }

    pub fn list_governed_transforms(
        &self,
        namespace: &str,
    ) -> Result<Vec<GovernedTransform>, String> {
        self.connection()?
            .query(
                "SELECT definition_json FROM sekai_governed_transform
                 WHERE namespace = $1 ORDER BY transform_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .collect()
    }

    pub fn list_governed_transform_runs(
        &self,
        namespace: &str,
        limit: i64,
    ) -> Result<Vec<TransformRun>, String> {
        self.connection()?
            .query(
                "SELECT run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
                        last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
                        lineage_parent, created_at_ms, markings_in, markings_out
                 FROM sekai_governed_transform_run
                 WHERE namespace = $1
                 ORDER BY created_at_ms DESC, run_id DESC
                 LIMIT $2",
                &[&namespace, &limit],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_run)
            .collect()
    }
}

fn lock_transform_datasets(
    tx: &mut postgres::Transaction<'_>,
    input_dataset_id: &str,
    output_dataset_id: &str,
) -> Result<(), String> {
    let mut ids = [input_dataset_id, output_dataset_id];
    ids.sort_unstable();
    let mut last = "";
    for dataset_id in ids {
        if dataset_id == last {
            continue;
        }
        last = dataset_id;
        lock_dataset_rows(tx, dataset_id)?;
        if tx
            .query_opt("SELECT 1 FROM sekai_datasets WHERE id=$1", &[&dataset_id])
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Err("dataset not found".into());
        }
    }
    Ok(())
}

fn load_transform(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    transform_id: &str,
) -> Result<Option<GovernedTransform>, String> {
    tx.query_opt(
        "SELECT definition_json FROM sekai_governed_transform
         WHERE namespace = $1 AND transform_id = $2",
        &[&namespace, &transform_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| {
        let json: String = row.get(0);
        serde_json::from_str(&json).map_err(|error| error.to_string())
    })
    .transpose()
}

fn load_checkpoint(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    transform_id: &str,
) -> Result<
    Option<(
        crate::sekai::governed_transform::TransformCheckpoint,
        String,
    )>,
    String,
> {
    Ok(tx
        .query_opt(
            "SELECT last_input_row_id, live_run_id, live_output_digest, definition_digest
             FROM sekai_governed_transform_checkpoint
             WHERE namespace = $1 AND transform_id = $2",
            &[&namespace, &transform_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| ((row.get(0), row.get(1), row.get(2)), row.get(3))))
}

fn insert_output_rows(
    tx: &mut postgres::Transaction<'_>,
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
    tx.execute(
        "INSERT INTO sekai_dataset_rows (dataset_id, data)
         SELECT $1, unnest($2::text[])",
        &[&dataset_id, &payloads],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn load_row_records(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    after_id: i64,
) -> Result<Vec<DatasetRowRecord>, String> {
    tx.query(
        "SELECT id, data FROM sekai_dataset_rows
         WHERE dataset_id=$1 AND id > $2
         ORDER BY id",
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

fn insert_transform_run(
    tx: &mut postgres::Transaction<'_>,
    run: &TransformRun,
) -> Result<(), String> {
    let incremental: i16 = i16::from(run.incremental);
    let quarantined: i16 = i16::from(run.quarantined);
    tx.execute(
        "INSERT INTO sekai_governed_transform_run
         (run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
          last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
          lineage_parent, created_at_ms, markings_in, markings_out)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        &[
            &run.run_id,
            &run.namespace,
            &run.transform_id,
            &run.definition_digest,
            &run.input_digest,
            &run.output_digest,
            &run.last_input_row_id,
            &incremental,
            &quarantined,
            &run.quality_rule,
            &run.rows_in,
            &run.rows_out,
            &run.lineage_parent,
            &run.created_at_ms,
            &run.markings_in,
            &run.markings_out,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn row_to_run(row: Row) -> Result<TransformRun, String> {
    let incremental: i16 = row.get(7);
    let quarantined: i16 = row.get(8);
    Ok(TransformRun {
        run_id: row.get(0),
        namespace: row.get(1),
        transform_id: row.get(2),
        definition_digest: row.get(3),
        input_digest: row.get(4),
        output_digest: row.get(5),
        last_input_row_id: row.get(6),
        incremental: incremental != 0,
        quarantined: quarantined != 0,
        quality_rule: row.get(9),
        rows_in: row.get(10),
        rows_out: row.get(11),
        lineage_parent: row.get(12),
        created_at_ms: row.get(13),
        markings_in: row.get(14),
        markings_out: row.get(15),
    })
}

fn load_dataset_object_id(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
) -> Result<String, String> {
    tx.query_opt(
        "SELECT object_id FROM sekai_datasets WHERE id = $1",
        &[&dataset_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| row.get(0))
    .ok_or_else(|| "dataset not found".into())
}

fn load_object_marking_token(
    tx: &mut postgres::Transaction<'_>,
    object_id: &str,
) -> Result<Option<String>, String> {
    if object_id.trim().is_empty() {
        return Ok(None);
    }
    let properties: String = tx
        .query_opt(
            "SELECT properties FROM sekai_objects WHERE id = $1",
            &[&object_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .ok_or_else(|| format!("input markings unresolvable: object {object_id} not found"))?;
    let map: HashMap<String, String> =
        serde_json::from_str(&properties).map_err(|error| error.to_string())?;
    Ok(map
        .get(OBJECT_CLASSIFICATION_PROPERTY)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn stamp_object_marking(
    tx: &mut postgres::Transaction<'_>,
    object_id: &str,
    token: &str,
    now_ms: i64,
) -> Result<(), String> {
    if object_id.trim().is_empty() {
        return Ok(());
    }
    let properties: String = tx
        .query_opt(
            "SELECT properties FROM sekai_objects WHERE id = $1 FOR UPDATE",
            &[&object_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
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
    let json = storage_properties_json(&map)?;
    let changed = tx
        .execute(
            "UPDATE sekai_objects SET properties = $1, updated = $2 WHERE id = $3",
            &[&json, &now_ms, &object_id],
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
    use crate::db::postgres::ScratchDatabase;
    use crate::sekai::dataset::{ColumnDef, Dataset, RowQuery};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, TransformStep};

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
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_incremental_run_matches_sqlite_envelope() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        let mut rows = Vec::new();
        for i in 0..100 {
            rows.push(HashMap::from([
                ("id".into(), i.to_string()),
                ("keep".into(), "yes".into()),
            ]));
        }
        db.append_dataset_rows("in", &rows).unwrap();
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
        db.append_dataset_rows(
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
        let live = db.query_dataset_rows("out", &RowQuery::default()).unwrap();
        assert_eq!(live.len(), 101);
        assert_eq!(second.output_digest, rows_digest(&live));
        let listed = db.list_governed_transform_runs("ops", 10).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].run_id, second.run_id);
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
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_transform_unions_input_markings_onto_output_and_receipt() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        let mut input = dataset("in");
        input.object_id = "in-obj".into();
        let mut output = dataset("out");
        output.object_id = "out-obj".into();
        db.create_object(&object("in-obj", Some("internal")))
            .unwrap();
        db.create_object(&object("out-obj", None)).unwrap();
        db.create_dataset(&input).unwrap();
        db.create_dataset(&output).unwrap();
        db.append_dataset_rows(
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
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_full_rebuild_folds_live_output_marking() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        let mut input = dataset("in");
        input.object_id = "in-obj".into();
        let mut output = dataset("out");
        output.object_id = "out-obj".into();
        db.create_object(&object("in-obj", Some("public"))).unwrap();
        db.create_object(&object("out-obj", Some("confidential")))
            .unwrap();
        db.create_dataset(&input).unwrap();
        db.create_dataset(&output).unwrap();
        db.append_dataset_rows(
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
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_marked_run_without_output_object_fails_closed_without_writing() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
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
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let error = db
            .run_governed_transform("ops", "t1", false, 20)
            .unwrap_err();
        assert!(error.contains("output markings unresolvable"), "{error}");
        assert!(
            db.query_dataset_rows("out", &RowQuery::default())
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
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_unknown_input_marking_fails_closed_without_writing_output() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
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
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let error = db
            .run_governed_transform("ops", "t1", false, 20)
            .unwrap_err();
        assert!(error.contains("unknown classification marking"), "{error}");
        assert!(
            db.query_dataset_rows("out", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
        assert!(
            db.list_governed_transform_runs("ops", 10)
                .unwrap()
                .is_empty()
        );
    }
}

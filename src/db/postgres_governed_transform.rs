//! PostgreSQL persistence for plane-owned governed transforms (#1287).

use postgres::Row;
use postgres::fallible_iterator::FallibleIterator;
use postgres::types::ToSql;
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

use crate::db::postgres::{PostgresDb, advisory_lock_key, lock_dataset_rows};
use crate::db::postgres_audit::lock_object_lifecycle;
use crate::domain::storage_properties_json;
use crate::sekai::dataset::DatasetRowRecord;
use crate::sekai::governed_transform::{
    DEFAULT_TRANSFORM_TENANT_CONCURRENCY, GovernedTransform, InputLoadBudget,
    MAX_TRANSFORM_LEASE_EXPIRIES, STALE_TRANSFORM_CLAIM, TRANSFORM_DEFINITION_CHANGED,
    TRANSFORM_DIGEST_MISMATCH, TRANSFORM_OUTPUT_BLOCKED, TRANSFORM_OUTPUT_FRESH,
    TRANSFORM_OUTPUT_STALE, TRANSFORM_TRIGGER_CANCELLED, TRANSFORM_TRIGGER_MANUAL,
    TRANSFORM_TRIGGER_SCHEDULE, TRANSFORM_TRIGGER_UPSTREAM, TRANSFORM_WORK_CANCELLED,
    TRANSFORM_WORK_CLAIMED, TRANSFORM_WORK_COMPLETED, TRANSFORM_WORK_FAILED,
    TRANSFORM_WORK_PENDING, TransformInputRows, TransformOutputState, TransformRun,
    TransformRunInputRow, TransformWork, WriteTransformRunCommand, admit_isolated_run,
    bind_checkpoint, bind_isolated_write_lineage, bind_receipts_to_dataset, budget_quarantined_run,
    checkpoint_after_id, compute_run_tables_until, dataset_digest, derive_transform_markings,
    evaluate_quality, fold_live_output_marking, fold_output_digest, input_partition_receipts,
    normalize_transform_claim_ttl_ms, partition_records, partition_value, prepare_partition_commit,
    receipts_for_touched_partitions, redact_run_partition_receipts, refuse_dependency_cycle,
    require_bound_output_for_markings, rows_digest, schedule_due_bucket,
    transform_claim_fence_matches, transform_work_is_claimable, trigger_is_due, trim_page_to_bytes,
};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;

impl PostgresDb {
    pub fn put_governed_transform(
        &self,
        transform: &GovernedTransform,
        created_at_ms: i64,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = advisory_lock_key(&["governed_transform", "graph", &transform.namespace]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let published = list_all_transforms_pg(&mut tx)?;
        refuse_dependency_cycle(&published, transform).map_err(|error| error.message())?;
        let json = serde_json::to_string(transform).map_err(|error| error.to_string())?;
        tx.execute(
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
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
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

    pub fn admitted_isolated_transform(
        &self,
        run_id: &str,
    ) -> Result<Option<GovernedTransform>, String> {
        self.connection()?
            .query_opt(
                "SELECT definition_json, definition_digest FROM sekai_transform_work
                 WHERE run_id = $1",
                &[&run_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let json: String = row.get(0);
                let digest: String = row.get(1);
                parse_admitted_definition(&json, &digest)
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
        if transform.is_isolated_process() {
            let mut run = admit_isolated_postgres(&mut tx, &transform, now_ms)?;
            run.stamp_trigger(TRANSFORM_TRIGGER_MANUAL, "");
            persist_transform_run_pg(&mut tx, &run)?;
            tx.execute(
                "DELETE FROM sekai_transform_trigger_pending
                 WHERE namespace = $1 AND transform_id = $2",
                &[&transform.namespace, &transform.transform_id],
            )
            .map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(run);
        }
        let bindings = transform.input_bindings();
        let mut lock_ids: Vec<&str> = bindings.iter().map(|(_, id)| id.as_str()).collect();
        lock_ids.push(transform.output_dataset_id.as_str());
        lock_transform_datasets(&mut tx, &lock_ids)?;
        let stored = load_checkpoint(&mut tx, namespace, transform_id)?;
        let output_keys = load_dataset_partition_keys_pg(&mut tx, &transform.output_dataset_id)?;
        let (mut incremental, checkpoint) = bind_checkpoint(
            incremental,
            stored,
            &transform.definition_digest,
            &output_keys,
        );
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
                load_dataset_column_names(&mut tx, dataset_id)?,
                load_row_records(&mut tx, dataset_id, after_id, load_budget.as_mut())?,
            ));
            let object_id = load_dataset_object_id(&mut tx, dataset_id)?;
            input_object_tokens.push(load_object_marking_token(&mut tx, &object_id)?);
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
        let output_object_id = load_dataset_object_id(&mut tx, &transform.output_dataset_id)?;
        if !output_object_id.trim().is_empty() {
            lock_object_lifecycle(&mut tx, &output_object_id)?;
        }
        let prior_token = load_object_marking_token(&mut tx, &output_object_id)?;
        let marking_rows: Vec<&std::collections::HashMap<String, String>> = loaded
            .iter()
            .flat_map(|(_, _, records)| records.iter().map(|(_, row)| row))
            .collect();
        let (markings_in, markings_out) = derive_transform_markings(
            None,
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
        run.stamp_trigger(TRANSFORM_TRIGGER_MANUAL, "");
        run.input_partitions = input_receipts_from_loaded_pg(&mut tx, &bindings, &loaded)?;
        if run.quarantined {
            if !incremental {
                let live = live_output_rows_pg(&mut tx, &transform.output_dataset_id)?;
                let keys = load_dataset_partition_keys_pg(&mut tx, &transform.output_dataset_id)?;
                run.output_digest = dataset_digest(&keys, &live);
            }
            insert_transform_run(&mut tx, &run)?;
            after_run_committed_pg(&mut tx, &transform, &run, now_ms)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(run);
        }
        require_bound_output_for_markings(&output_object_id, &run.markings_out)?;
        persist_computed_output_pg(
            &mut tx,
            &transform,
            &bindings,
            &loaded,
            incremental,
            checkpoint.as_ref(),
            &output_rows,
            &mut run,
        )?;
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
        after_run_committed_pg(&mut tx, &transform, &run, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(run)
    }

    pub fn tick_governed_transforms(&self, now_ms: i64) -> Result<Vec<TransformRun>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let runs = tick_governed_transforms_pg(&mut tx, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(runs)
    }

    pub fn get_transform_output_state(
        &self,
        namespace: &str,
        dataset_id: &str,
    ) -> Result<Option<TransformOutputState>, String> {
        self.connection()?
            .query_opt(
                "SELECT namespace, dataset_id, freshness, upstream_version, blocked_run_id, updated_at_ms
                 FROM sekai_transform_output_state
                 WHERE namespace = $1 AND dataset_id = $2",
                &[&namespace, &dataset_id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_output_state)
            .transpose()
    }

    pub fn set_transform_namespace_concurrency(
        &self,
        namespace: &str,
        max_concurrent: i64,
    ) -> Result<(), String> {
        if max_concurrent <= 0 {
            return Err("max_concurrent must be positive".into());
        }
        self.connection()?
            .execute(
                "INSERT INTO sekai_transform_namespace_limit (namespace, max_concurrent)
                 VALUES ($1,$2)
                 ON CONFLICT (namespace) DO UPDATE SET max_concurrent = EXCLUDED.max_concurrent",
                &[&namespace, &max_concurrent],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn note_source_change(
        &self,
        namespace: &str,
        object_or_dataset_ids: &[String],
        cause: &str,
        cause_ref: &str,
        now_ms: i64,
    ) -> Result<Vec<TransformRun>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let datasets = resolve_changed_datasets_pg(&mut tx, object_or_dataset_ids)?;
        let mut runs = Vec::new();
        for dataset_id in datasets {
            runs.extend(enqueue_change_triggers_pg(
                &mut tx,
                namespace,
                &dataset_id,
                cause,
                cause_ref,
                now_ms,
                false,
            )?);
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(runs)
    }

    pub fn cancel_governed_transform_run(
        &self,
        run_id: &str,
        now_ms: i64,
    ) -> Result<TransformRun, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let run = cancel_governed_transform_run_pg(&mut tx, run_id, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(run)
    }

    pub fn get_governed_transform_run(&self, run_id: &str) -> Result<Option<TransformRun>, String> {
        self.connection()?
            .query_opt(
                "SELECT run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
                        last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
                        lineage_parent, created_at_ms, markings_in, markings_out,
                        profile, engine, runtime_image, dispatch_status, trigger_cause, trigger_ref,
                        input_partitions, output_partitions
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
                        lineage_parent, created_at_ms, markings_in, markings_out,
                        profile, engine, runtime_image, dispatch_status, trigger_cause, trigger_ref,
                        input_partitions, output_partitions
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

    pub fn list_claimable_transform_work(
        &self,
        namespace: &str,
        now_ms: i64,
        limit: i64,
    ) -> Result<Vec<TransformWork>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT run_id, namespace, transform_id, definition_digest, engine, runtime_image,
                        status, claim_owner, claim_generation, fencing_token, claim_expires_at_ms,
                        lease_expiries, created_at_ms
                 FROM sekai_transform_work
                 WHERE namespace = $1
                 ORDER BY created_at_ms, run_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?;
        let cap = if limit <= 0 { 50 } else { limit.min(500) };
        let mut out = Vec::new();
        for row in rows {
            let work = row_to_work(row)?;
            if transform_work_is_claimable(&work, now_ms) {
                out.push(work);
                if out.len() as i64 >= cap {
                    break;
                }
            }
        }
        Ok(out)
    }

    pub fn claim_transform_work(
        &self,
        namespace: &str,
        runtime_id: &str,
        run_id: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<Option<(TransformWork, GovernedTransform)>, String> {
        if runtime_id.trim().is_empty() {
            return Err("runtime_id required".into());
        }
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_transform_work_namespace(&mut tx, namespace)?;
        let claimed =
            claim_transform_work_pg(&mut tx, namespace, runtime_id, run_id, ttl_ms, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(claimed)
    }

    pub fn heartbeat_transform_work(
        &self,
        run_id: &str,
        runtime_id: &str,
        claim_generation: i64,
        fencing_token: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<TransformWork, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let namespace = peek_transform_work_namespace(&mut tx, run_id)?;
        lock_transform_work_namespace(&mut tx, &namespace)?;
        // `now_ms` is the caller's transaction time, matching SQLite's
        // injected clock. Expiry is judged at that logical time after the
        // namespace lock serializes claim/heartbeat/write.
        let mut work =
            load_transform_work_pg(&mut tx, run_id)?.ok_or("transform work not found")?;
        if !transform_claim_fence_matches(
            &work,
            runtime_id,
            claim_generation,
            fencing_token,
            now_ms,
        ) {
            return Err(STALE_TRANSFORM_CLAIM.into());
        }
        work.claim_expires_at_ms = now_ms.saturating_add(normalize_transform_claim_ttl_ms(ttl_ms));
        persist_fenced_transform_work_pg(&mut tx, &work, claim_generation, fencing_token)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(work)
    }

    pub fn read_transform_run_input(
        &self,
        command: &WriteTransformRunCommand,
        alias: &str,
        after_alias: &str,
        after_row_id: i64,
        limit: i64,
        now_ms: i64,
    ) -> Result<Vec<TransformRunInputRow>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let namespace = peek_transform_work_namespace(&mut tx, &command.run_id)?;
        lock_transform_work_namespace(&mut tx, &namespace)?;
        let work =
            load_transform_work_pg(&mut tx, &command.run_id)?.ok_or("transform work not found")?;
        if !transform_claim_fence_matches(
            &work,
            &command.runtime_id,
            command.claim_generation,
            &command.fencing_token,
            now_ms,
        ) {
            return Err(STALE_TRANSFORM_CLAIM.into());
        }
        let _transform = load_admitted_transform_pg(&mut tx, &work)?;
        load_run_input_snapshot_pg(
            &mut tx,
            &command.run_id,
            alias,
            after_alias,
            after_row_id,
            limit,
            command.partition_key.as_deref(),
            command.max_bytes,
        )
    }

    pub fn write_transform_run(
        &self,
        command: WriteTransformRunCommand,
        now_ms: i64,
    ) -> Result<TransformRun, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let namespace = peek_transform_work_namespace(&mut tx, &command.run_id)?;
        lock_transform_work_namespace(&mut tx, &namespace)?;
        let run = write_transform_run_pg(&mut tx, &command, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(run)
    }
}

fn lock_transform_datasets(
    tx: &mut postgres::Transaction<'_>,
    dataset_ids: &[&str],
) -> Result<(), String> {
    let mut ids: Vec<&str> = dataset_ids.to_vec();
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

fn peek_transform_work_namespace(
    tx: &mut postgres::Transaction<'_>,
    run_id: &str,
) -> Result<String, String> {
    tx.query_opt(
        "SELECT namespace FROM sekai_transform_work WHERE run_id = $1",
        &[&run_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| row.get(0))
    .ok_or_else(|| "transform work not found".into())
}

fn lock_transform_work_namespace(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
) -> Result<(), String> {
    let lock_key = advisory_lock_key(&["transform_work", namespace]);
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
        &[&lock_key],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
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
    let keys = load_dataset_partition_keys_pg(tx, dataset_id)?;
    if keys.is_empty() {
        let payloads: Vec<String> = rows
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<_, _>>()
            .map_err(|error| error.to_string())?;
        return tx
            .execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data)
         SELECT $1, unnest($2::text[])",
                &[&dataset_id, &payloads],
            )
            .map(|_| ())
            .map_err(|error| error.to_string());
    }
    for row in rows {
        let data = serde_json::to_string(row).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_dataset_rows (dataset_id, data, partition_key)
             VALUES ($1, $2, $3)",
            &[&dataset_id, &data, &partition_value(&keys, row)],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn live_output_rows_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
) -> Result<Vec<HashMap<String, String>>, String> {
    Ok(load_row_records(tx, dataset_id, 0, None)?
        .into_iter()
        .map(|(_, row)| row)
        .collect())
}

fn persist_computed_output_pg(
    tx: &mut postgres::Transaction<'_>,
    transform: &GovernedTransform,
    bindings: &[(String, String)],
    loaded: &[(String, Vec<String>, Vec<DatasetRowRecord>)],
    incremental: bool,
    checkpoint: Option<&crate::sekai::governed_transform::TransformCheckpoint>,
    output_rows: &[HashMap<String, String>],
    run: &mut TransformRun,
) -> Result<(), String> {
    let keys = load_dataset_partition_keys_pg(tx, &transform.output_dataset_id)?;
    run.input_partitions = input_receipts_from_loaded_pg(tx, bindings, loaded)?;
    if keys.is_empty() {
        if !incremental {
            tx.execute(
                "DELETE FROM sekai_dataset_rows WHERE dataset_id = $1",
                &[&transform.output_dataset_id],
            )
            .map_err(|error| error.to_string())?;
        }
        insert_output_rows(tx, &transform.output_dataset_id, output_rows)?;
        run.output_digest = if incremental {
            checkpoint
                .and_then(|checkpoint| fold_output_digest(&checkpoint.2, output_rows))
                .ok_or_else(|| "checkpoint digest encoding is not current".to_string())?
        } else {
            rows_digest(output_rows)
        };
        return Ok(());
    }
    if incremental {
        insert_output_rows(tx, &transform.output_dataset_id, output_rows)?;
    } else {
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE dataset_id = $1",
            &[&transform.output_dataset_id],
        )
        .map_err(|error| error.to_string())?;
        insert_output_rows(tx, &transform.output_dataset_id, output_rows)?;
        run.output_partitions = partition_records(&keys, output_rows, &transform.output_dataset_id);
    }
    let live = live_output_rows_pg(tx, &transform.output_dataset_id)?;
    if incremental {
        run.output_partitions = receipts_for_touched_partitions(
            &keys,
            &live,
            output_rows,
            &transform.output_dataset_id,
        );
    }
    run.output_digest = dataset_digest(&keys, &live);
    Ok(())
}

fn input_receipts_from_loaded_pg(
    tx: &mut postgres::Transaction<'_>,
    bindings: &[(String, String)],
    loaded: &[(String, Vec<String>, Vec<DatasetRowRecord>)],
) -> Result<Vec<crate::sekai::governed_transform::TransformPartition>, String> {
    let mut inputs = Vec::new();
    for ((_, dataset_id), (_, _, records)) in bindings.iter().zip(loaded.iter()) {
        let keys = load_dataset_partition_keys_pg(tx, dataset_id)?;
        let rows = records.iter().map(|(_, row)| row.clone()).collect();
        inputs.push((dataset_id.clone(), keys, rows));
    }
    Ok(input_partition_receipts(inputs))
}

fn load_row_records(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    after_id: i64,
    mut budget: Option<&mut InputLoadBudget>,
) -> Result<Vec<DatasetRowRecord>, String> {
    let params: [&(dyn ToSql + Sync); 2] = [&dataset_id, &after_id];
    let mut rows = tx
        .query_raw(
            "SELECT id, data FROM sekai_dataset_rows
             WHERE dataset_id=$1 AND id > $2
             ORDER BY id",
            params,
        )
        .map_err(|error| error.to_string())?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let id: i64 = row.get(0);
        let data: &str = row.get(1);
        if let Some(budget) = budget.as_mut()
            && !budget.allow_encoded(data.len() as u64)
        {
            break;
        }
        let values: HashMap<String, String> = serde_json::from_str(data)
            .map_err(|error| format!("corrupt dataset row for {dataset_id:?}: {error}"))?;
        if let Some(budget) = budget.as_mut()
            && !budget.charge(&values)
        {
            break;
        }
        results.push((id, values));
    }
    Ok(results)
}

fn insert_transform_run(
    tx: &mut postgres::Transaction<'_>,
    run: &TransformRun,
) -> Result<(), String> {
    let incremental: i16 = i16::from(run.incremental);
    let quarantined: i16 = i16::from(run.quarantined);
    let input_partitions =
        serde_json::to_string(&run.input_partitions).map_err(|error| error.to_string())?;
    let output_partitions =
        serde_json::to_string(&run.output_partitions).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_governed_transform_run
         (run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
          last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
          lineage_parent, created_at_ms, markings_in, markings_out,
          profile, engine, runtime_image, dispatch_status, trigger_cause, trigger_ref, input_partitions, output_partitions)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)",
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
            &run.profile,
            &run.engine,
            &run.runtime_image,
            &run.dispatch_status,
            &run.trigger_cause,
            &run.trigger_ref,
            &input_partitions,
            &output_partitions,
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
        profile: row.try_get(16).unwrap_or_default(),
        engine: row.try_get(17).unwrap_or_default(),
        runtime_image: row.try_get(18).unwrap_or_default(),
        dispatch_status: row.try_get(19).unwrap_or_default(),
        trigger_cause: row.try_get(20).unwrap_or_default(),
        trigger_ref: row.try_get(21).unwrap_or_default(),
        input_partitions: serde_json::from_str(
            &row.try_get::<_, String>(22).unwrap_or_else(|_| "[]".into()),
        )
        .unwrap_or_default(),
        output_partitions: serde_json::from_str(
            &row.try_get::<_, String>(23).unwrap_or_else(|_| "[]".into()),
        )
        .unwrap_or_default(),
    })
}

fn load_dataset_column_names(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
) -> Result<Vec<String>, String> {
    let json: String = tx
        .query_opt(
            "SELECT columns FROM sekai_datasets WHERE id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .ok_or_else(|| "dataset not found".to_string())?;
    crate::db::governed_transform::dataset_column_names(&json)
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

fn admit_isolated_postgres(
    tx: &mut postgres::Transaction<'_>,
    transform: &GovernedTransform,
    now_ms: i64,
) -> Result<TransformRun, String> {
    let bindings = transform.input_bindings();
    let mut lock_ids: Vec<&str> = bindings.iter().map(|(_, id)| id.as_str()).collect();
    lock_ids.push(transform.output_dataset_id.as_str());
    lock_transform_datasets(tx, &lock_ids)?;
    let mut loaded: Vec<(String, Vec<String>, Vec<DatasetRowRecord>)> = Vec::new();
    let mut input_object_tokens: Vec<Option<String>> = Vec::new();
    for (alias, dataset_id) in &bindings {
        loaded.push((
            alias.clone(),
            load_dataset_column_names(tx, dataset_id)?,
            load_row_records(tx, dataset_id, 0, None)?,
        ));
        let object_id = load_dataset_object_id(tx, dataset_id)?;
        input_object_tokens.push(load_object_marking_token(tx, &object_id)?);
    }
    let output_object_id = load_dataset_object_id(tx, &transform.output_dataset_id)?;
    let prior_token = load_object_marking_token(tx, &output_object_id)?;
    let marking_rows: Vec<&HashMap<String, String>> = loaded
        .iter()
        .flat_map(|(_, _, records)| records.iter().map(|(_, row)| row))
        .collect();
    let (markings_in, markings_out) = derive_transform_markings(
        None,
        input_object_tokens.iter().map(|token| token.as_deref()),
        prior_token.as_deref(),
        marking_rows,
    )?;
    let tables: Vec<TransformInputRows<'_>> = loaded
        .iter()
        .map(|(alias, columns, records)| TransformInputRows {
            alias,
            records,
            columns,
        })
        .collect();
    let mut run = admit_isolated_run(transform, &tables, now_ms, Uuid::new_v4().to_string())
        .map_err(|error| error.message())?;
    run.markings_in = markings_in;
    run.markings_out = markings_out;
    run.input_partitions = input_receipts_from_loaded_pg(tx, &bindings, &loaded)?;
    insert_transform_run(tx, &run)?;
    persist_run_input_snapshot_pg(tx, &run.run_id, &bindings, &loaded)?;
    let spec = transform
        .isolated_process
        .as_ref()
        .ok_or("isolated_process profile required")?;
    persist_admitted_transform_work_pg(
        tx,
        &TransformWork {
            run_id: run.run_id.clone(),
            namespace: transform.namespace.clone(),
            transform_id: transform.transform_id.clone(),
            definition_digest: transform.definition_digest.clone(),
            engine: spec.engine.clone(),
            runtime_image: spec.runtime_image.clone(),
            status: TRANSFORM_WORK_PENDING.into(),
            claim_owner: String::new(),
            claim_generation: 0,
            fencing_token: String::new(),
            claim_expires_at_ms: 0,
            lease_expiries: 0,
            created_at_ms: now_ms,
        },
        transform,
    )?;
    Ok(run)
}

fn claim_transform_work_pg(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    runtime_id: &str,
    run_id: &str,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<Option<(TransformWork, GovernedTransform)>, String> {
    let rows = tx
        .query(
            "SELECT run_id, namespace, transform_id, definition_digest, engine, runtime_image,
                    status, claim_owner, claim_generation, fencing_token, claim_expires_at_ms,
                    lease_expiries, created_at_ms
             FROM sekai_transform_work
             WHERE namespace = $1
             ORDER BY created_at_ms, run_id",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    let wanted = run_id.trim();
    let mut chosen: Option<(TransformWork, GovernedTransform)> = None;
    for row in rows {
        let preview = row_to_work(row)?;
        if !wanted.is_empty() && preview.run_id != wanted {
            continue;
        }
        let Some(mut work) = load_transform_work_pg(tx, &preview.run_id)? else {
            continue;
        };
        if work.status == TRANSFORM_WORK_CLAIMED && work.claim_expires_at_ms <= now_ms {
            work.lease_expiries = work.lease_expiries.saturating_add(1);
            if work.lease_expiries >= MAX_TRANSFORM_LEASE_EXPIRIES {
                work.status = TRANSFORM_WORK_FAILED.into();
                persist_transform_work_pg(tx, &work)?;
                stamp_run_dispatch_pg(tx, &work.run_id, TRANSFORM_WORK_FAILED)?;
                delete_run_input_snapshot_pg(tx, &work.run_id)?;
                continue;
            }
            persist_transform_work_pg(tx, &work)?;
        }
        if !transform_work_is_claimable(&work, now_ms) {
            continue;
        }
        let transform = match load_admitted_transform_pg(tx, &work) {
            Ok(transform) => transform,
            Err(error) if error == TRANSFORM_DEFINITION_CHANGED => {
                work.status = TRANSFORM_WORK_FAILED.into();
                persist_transform_work_pg(tx, &work)?;
                stamp_run_dispatch_pg(tx, &work.run_id, TRANSFORM_WORK_FAILED)?;
                delete_run_input_snapshot_pg(tx, &work.run_id)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        chosen = Some((work, transform));
        break;
    }
    let (mut work, transform) = match chosen {
        Some(chosen) => chosen,
        None => return Ok(None),
    };
    work.status = TRANSFORM_WORK_CLAIMED.into();
    work.claim_owner = runtime_id.to_string();
    work.claim_generation = work.claim_generation.saturating_add(1);
    work.fencing_token = Uuid::new_v4().to_string();
    work.claim_expires_at_ms = now_ms.saturating_add(normalize_transform_claim_ttl_ms(ttl_ms));
    persist_transform_work_pg(tx, &work)?;
    stamp_run_dispatch_pg(tx, &work.run_id, TRANSFORM_WORK_CLAIMED)?;
    Ok(Some((work, transform)))
}

fn write_transform_run_pg(
    tx: &mut postgres::Transaction<'_>,
    command: &WriteTransformRunCommand,
    now_ms: i64,
) -> Result<TransformRun, String> {
    let work = load_transform_work_pg(tx, &command.run_id)?.ok_or("transform work not found")?;
    if !transform_claim_fence_matches(
        &work,
        &command.runtime_id,
        command.claim_generation,
        &command.fencing_token,
        now_ms,
    ) {
        return Err(STALE_TRANSFORM_CLAIM.into());
    }
    let transform = load_admitted_transform_pg(tx, &work)?;
    lock_transform_datasets(tx, &[transform.output_dataset_id.as_str()])?;
    let mut run = tx
        .query_opt(
            "SELECT run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
                    last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
                    lineage_parent, created_at_ms, markings_in, markings_out,
                    profile, engine, runtime_image, dispatch_status, trigger_cause, trigger_ref,
                        input_partitions, output_partitions
             FROM sekai_governed_transform_run WHERE run_id = $1",
            &[&command.run_id],
        )
        .map_err(|error| error.to_string())?
        .map(row_to_run)
        .transpose()?
        .ok_or("transform run not found")?;
    let keys = load_dataset_partition_keys_pg(tx, &transform.output_dataset_id)?;
    let partition_commit = if command.quarantined {
        None
    } else if command.replaced_partitions.is_empty() {
        if dataset_digest(&keys, &command.rows) != command.output_digest {
            return Err(TRANSFORM_DIGEST_MISMATCH.into());
        }
        None
    } else {
        let live_rows: Vec<HashMap<String, String>> =
            load_row_records(tx, &transform.output_dataset_id, 0, None)?
                .into_iter()
                .map(|(_, row)| row)
                .collect();
        Some(prepare_partition_commit(
            &keys,
            &live_rows,
            &command.replaced_partitions,
            &command.output_digest,
        )?)
    };
    let quality_rows = partition_commit
        .as_ref()
        .map(|commit| commit.merged_rows.as_slice())
        .unwrap_or(command.rows.as_slice());
    let quality_error = evaluate_quality(quality_rows, &transform.quality_rule)
        .err()
        .map(|error| error.message());
    let quarantined = command.quarantined || quality_error.is_some();
    let output_object_id = load_dataset_object_id(tx, &transform.output_dataset_id)?;
    if quarantined {
        run.quarantined = true;
        run.quality_rule = quality_error.unwrap_or_else(|| {
            if command.quality_rule.trim().is_empty() {
                transform.quality_rule.clone()
            } else {
                command.quality_rule.clone()
            }
        });
        run.rows_out = 0;
        let live: Vec<HashMap<String, String>> =
            load_row_records(tx, &transform.output_dataset_id, 0, None)?
                .into_iter()
                .map(|(_, row)| row)
                .collect();
        let keys = load_dataset_partition_keys_pg(tx, &transform.output_dataset_id)?;
        run.output_digest = dataset_digest(&keys, &live);
        if !output_object_id.trim().is_empty() {
            lock_object_lifecycle(tx, &output_object_id)?;
        }
        let live_output = load_object_marking_token(tx, &output_object_id)?;
        run.markings_out =
            fold_live_output_marking(None, &run.markings_out, live_output.as_deref())?;
        require_bound_output_for_markings(&output_object_id, &run.markings_out)?;
        run.dispatch_status = TRANSFORM_WORK_COMPLETED.into();
        run.engine = work.engine.clone();
        run.runtime_image = work.runtime_image.clone();
        persist_transform_run_pg(tx, &run)?;
        let mut done = work;
        done.status = TRANSFORM_WORK_COMPLETED.into();
        persist_fenced_transform_work_pg(
            tx,
            &done,
            command.claim_generation,
            &command.fencing_token,
        )?;
        delete_run_input_snapshot_pg(tx, &run.run_id)?;
        after_run_committed_pg(tx, &transform, &run, now_ms)?;
        return Ok(run);
    }
    let live = match load_checkpoint(tx, &transform.namespace, &transform.transform_id)? {
        Some(((_, live_run_id, _), _)) if !live_run_id.is_empty() => {
            load_transform_run_pg(tx, &live_run_id)?
        }
        _ => None,
    };
    bind_isolated_write_lineage(&mut run, live.as_ref())?;
    if !output_object_id.trim().is_empty() {
        lock_object_lifecycle(tx, &output_object_id)?;
    }
    let live_output = load_object_marking_token(tx, &output_object_id)?;
    run.markings_out = fold_live_output_marking(None, &run.markings_out, live_output.as_deref())?;
    require_bound_output_for_markings(&output_object_id, &run.markings_out)?;
    if let Some(commit) = partition_commit {
        replace_output_partitions_pg(tx, &transform.output_dataset_id, &commit.replacements)?;
        run.output_digest = commit.envelope_digest.clone();
        run.rows_out = commit.merged_rows.len() as i32;
        run.output_partitions = commit.written;
        bind_receipts_to_dataset(&mut run.output_partitions, &transform.output_dataset_id);
    } else {
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE dataset_id = $1",
            &[&transform.output_dataset_id],
        )
        .map_err(|error| error.to_string())?;
        insert_output_rows(tx, &transform.output_dataset_id, &command.rows)?;
        run.output_digest = dataset_digest(&keys, &command.rows);
        run.rows_out = command.rows.len() as i32;
        run.output_partitions = if keys.is_empty() {
            Vec::new()
        } else {
            partition_records(&keys, &command.rows, &transform.output_dataset_id)
        };
    }
    run.quarantined = false;
    run.dispatch_status = TRANSFORM_WORK_COMPLETED.into();
    run.engine = work.engine.clone();
    run.runtime_image = work.runtime_image.clone();
    stamp_object_marking(tx, &output_object_id, &run.markings_out, now_ms)?;
    persist_transform_run_pg(tx, &run)?;
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
            &transform.namespace,
            &transform.transform_id,
            &transform.definition_digest,
            &run.last_input_row_id,
            &run.run_id,
            &run.output_digest,
        ],
    )
    .map_err(|error| error.to_string())?;
    let mut done = work;
    done.status = TRANSFORM_WORK_COMPLETED.into();
    persist_fenced_transform_work_pg(tx, &done, command.claim_generation, &command.fencing_token)?;
    delete_run_input_snapshot_pg(tx, &run.run_id)?;
    after_run_committed_pg(tx, &transform, &run, now_ms)?;
    Ok(run)
}

fn row_to_work(row: Row) -> Result<TransformWork, String> {
    Ok(TransformWork {
        run_id: row.get(0),
        namespace: row.get(1),
        transform_id: row.get(2),
        definition_digest: row.get(3),
        engine: row.get(4),
        runtime_image: row.get(5),
        status: row.get(6),
        claim_owner: row.get(7),
        claim_generation: row.get(8),
        fencing_token: row.get(9),
        claim_expires_at_ms: row.get(10),
        lease_expiries: row.get(11),
        created_at_ms: row.get(12),
    })
}

fn load_transform_run_pg(
    tx: &mut postgres::Transaction<'_>,
    run_id: &str,
) -> Result<Option<TransformRun>, String> {
    tx.query_opt(
        "SELECT run_id, namespace, transform_id, definition_digest, input_digest, output_digest,
                last_input_row_id, incremental, quarantined, quality_rule, rows_in, rows_out,
                lineage_parent, created_at_ms, markings_in, markings_out,
                profile, engine, runtime_image, dispatch_status, trigger_cause, trigger_ref,
                        input_partitions, output_partitions
         FROM sekai_governed_transform_run WHERE run_id = $1",
        &[&run_id],
    )
    .map_err(|error| error.to_string())?
    .map(row_to_run)
    .transpose()
}

fn load_transform_work_pg(
    tx: &mut postgres::Transaction<'_>,
    run_id: &str,
) -> Result<Option<TransformWork>, String> {
    tx.query_opt(
        "SELECT run_id, namespace, transform_id, definition_digest, engine, runtime_image,
                status, claim_owner, claim_generation, fencing_token, claim_expires_at_ms,
                lease_expiries, created_at_ms
         FROM sekai_transform_work WHERE run_id = $1 FOR UPDATE",
        &[&run_id],
    )
    .map_err(|error| error.to_string())?
    .map(row_to_work)
    .transpose()
}

fn persist_admitted_transform_work_pg(
    tx: &mut postgres::Transaction<'_>,
    work: &TransformWork,
    transform: &GovernedTransform,
) -> Result<(), String> {
    let json = serde_json::to_string(transform).map_err(|error| error.to_string())?;
    upsert_transform_work_pg(tx, work, &json)
}

fn persist_transform_work_pg(
    tx: &mut postgres::Transaction<'_>,
    work: &TransformWork,
) -> Result<(), String> {
    upsert_transform_work_pg(tx, work, "")
}

fn upsert_transform_work_pg(
    tx: &mut postgres::Transaction<'_>,
    work: &TransformWork,
    definition_json: &str,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_transform_work
         (run_id, namespace, transform_id, definition_digest, definition_json, engine, runtime_image, status,
          claim_owner, claim_generation, fencing_token, claim_expires_at_ms, lease_expiries, created_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         ON CONFLICT (run_id) DO UPDATE SET
            status = EXCLUDED.status,
            claim_owner = EXCLUDED.claim_owner,
            claim_generation = EXCLUDED.claim_generation,
            fencing_token = EXCLUDED.fencing_token,
            claim_expires_at_ms = EXCLUDED.claim_expires_at_ms,
            lease_expiries = EXCLUDED.lease_expiries",
        &[
            &work.run_id,
            &work.namespace,
            &work.transform_id,
            &work.definition_digest,
            &definition_json,
            &work.engine,
            &work.runtime_image,
            &work.status,
            &work.claim_owner,
            &work.claim_generation,
            &work.fencing_token,
            &work.claim_expires_at_ms,
            &work.lease_expiries,
            &work.created_at_ms,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn persist_fenced_transform_work_pg(
    tx: &mut postgres::Transaction<'_>,
    work: &TransformWork,
    expected_generation: i64,
    expected_token: &str,
) -> Result<(), String> {
    let changed = tx
        .execute(
            "UPDATE sekai_transform_work SET
                status = $2,
                claim_owner = $3,
                claim_generation = $4,
                fencing_token = $5,
                claim_expires_at_ms = $6,
                lease_expiries = $7
             WHERE run_id = $1
               AND claim_generation = $8
               AND fencing_token = $9
               AND status = $10",
            &[
                &work.run_id,
                &work.status,
                &work.claim_owner,
                &work.claim_generation,
                &work.fencing_token,
                &work.claim_expires_at_ms,
                &work.lease_expiries,
                &expected_generation,
                &expected_token,
                &TRANSFORM_WORK_CLAIMED,
            ],
        )
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err(STALE_TRANSFORM_CLAIM.into());
    }
    Ok(())
}

fn persist_run_input_snapshot_pg(
    tx: &mut postgres::Transaction<'_>,
    run_id: &str,
    bindings: &[(String, String)],
    loaded: &[(String, Vec<String>, Vec<DatasetRowRecord>)],
) -> Result<(), String> {
    // Snapshot is the admitted pin: persist the full loaded set, not a stream.
    for ((alias, dataset_id), (_, _, records)) in bindings.iter().zip(loaded.iter()) {
        let keys = load_dataset_partition_keys_pg(tx, dataset_id)?;
        for (row_id, values) in records {
            let values_json = serde_json::to_string(values).map_err(|error| error.to_string())?;
            let partition_key = partition_value(&keys, values);
            tx.execute(
                "INSERT INTO sekai_transform_run_input
                 (run_id, alias, dataset_id, row_id, values_json, partition_key)
                 VALUES ($1,$2,$3,$4,$5,$6)",
                &[
                    &run_id,
                    alias,
                    dataset_id,
                    row_id,
                    &values_json,
                    &partition_key,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn load_admitted_transform_pg(
    tx: &mut postgres::Transaction<'_>,
    work: &TransformWork,
) -> Result<GovernedTransform, String> {
    let json: String = tx
        .query_opt(
            "SELECT definition_json FROM sekai_transform_work WHERE run_id = $1",
            &[&work.run_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .ok_or_else(|| "transform work not found".to_string())?;
    parse_admitted_definition(&json, &work.definition_digest)
}

fn parse_admitted_definition(
    json: &str,
    definition_digest: &str,
) -> Result<GovernedTransform, String> {
    if json.trim().is_empty() {
        return Err(TRANSFORM_DEFINITION_CHANGED.into());
    }
    let transform: GovernedTransform =
        serde_json::from_str(json).map_err(|_| TRANSFORM_DEFINITION_CHANGED.to_string())?;
    if transform.definition_digest != definition_digest {
        return Err(TRANSFORM_DEFINITION_CHANGED.into());
    }
    Ok(transform)
}

fn load_run_input_snapshot_pg(
    tx: &mut postgres::Transaction<'_>,
    run_id: &str,
    alias: &str,
    after_alias: &str,
    after_row_id: i64,
    limit: i64,
    partition_key: Option<&str>,
    max_bytes: i64,
) -> Result<Vec<TransformRunInputRow>, String> {
    let cap = if limit <= 0 { 1_000 } else { limit.min(5_000) };
    let wanted = alias.trim();
    let after = after_alias.trim();
    let (wanted_partition, has_selector) = match partition_key {
        Some(key) => (key, 1i32),
        None => ("", 0i32),
    };
    // Empty alias walks every input in (alias, row_id) order. Continue with
    // after_alias + after_row_id from the last row. Named alias stays per input.
    // Unset selector ($6 = 0) reads every partition; empty string is an identity.
    let rows = if wanted.is_empty() {
        tx.query(
            "SELECT alias, dataset_id, row_id, values_json, partition_key
             FROM sekai_transform_run_input
             WHERE run_id = $1
               AND ($6 = 0 OR partition_key = $5)
               AND (alias > $2 OR (alias = $2 AND row_id > $3))
             ORDER BY alias, row_id
             LIMIT $4",
            &[
                &run_id,
                &after,
                &after_row_id,
                &cap,
                &wanted_partition,
                &has_selector,
            ],
        )
        .map_err(|error| error.to_string())?
    } else {
        tx.query(
            "SELECT alias, dataset_id, row_id, values_json, partition_key
             FROM sekai_transform_run_input
             WHERE run_id = $1 AND alias = $2 AND row_id > $3
               AND ($6 = 0 OR partition_key = $5)
             ORDER BY row_id
             LIMIT $4",
            &[
                &run_id,
                &wanted,
                &after_row_id,
                &cap,
                &wanted_partition,
                &has_selector,
            ],
        )
        .map_err(|error| error.to_string())?
    };
    let mut out = Vec::new();
    for row in rows {
        let values_json: String = row.get(3);
        let values: HashMap<String, String> =
            serde_json::from_str(&values_json).map_err(|error| error.to_string())?;
        out.push(TransformRunInputRow {
            alias: row.get(0),
            dataset_id: row.get(1),
            row_id: row.get(2),
            values,
            partition_key: row.try_get(4).unwrap_or_default(),
        });
    }
    Ok(trim_page_to_bytes(out, max_bytes))
}

fn load_dataset_partition_keys_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
) -> Result<Vec<String>, String> {
    let json: String = tx
        .query_opt(
            "SELECT partition_keys FROM sekai_datasets WHERE id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.try_get(0).unwrap_or_else(|_| "[]".into()))
        .unwrap_or_else(|| "[]".into());
    crate::sekai::dataset::parse_partition_keys(&json)
}

fn replace_output_partitions_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    replacements: &[(String, Vec<HashMap<String, String>>)],
) -> Result<(), String> {
    for (partition_key, rows) in replacements {
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE dataset_id = $1 AND partition_key = $2",
            &[&dataset_id, partition_key],
        )
        .map_err(|error| error.to_string())?;
        for row in rows {
            let data = serde_json::to_string(row).map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data, partition_key)
                 VALUES ($1, $2, $3)",
                &[&dataset_id, &data, partition_key],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn delete_run_input_snapshot_pg(
    tx: &mut postgres::Transaction<'_>,
    run_id: &str,
) -> Result<(), String> {
    tx.execute(
        "DELETE FROM sekai_transform_run_input WHERE run_id = $1",
        &[&run_id],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

pub(crate) fn redact_transform_partition_receipts_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    redact_snapshots: bool,
) -> Result<(), String> {
    if redact_snapshots {
        tx.execute(
            "UPDATE sekai_transform_run_input SET partition_key = '[redacted]'
             WHERE dataset_id = $1 AND partition_key != '' AND partition_key != '[redacted]'",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?;
    }
    let rows = tx
        .query(
            "SELECT run_id, input_partitions, output_partitions
             FROM sekai_governed_transform_run
             FOR UPDATE",
            &[],
        )
        .map_err(|error| error.to_string())?;
    for row in rows {
        let run_id: String = row.get(0);
        let input_json: String = row.get(1);
        let output_json: String = row.get(2);
        let mut input_partitions: Vec<crate::sekai::governed_transform::TransformPartition> =
            serde_json::from_str(&input_json).unwrap_or_default();
        let mut output_partitions: Vec<crate::sekai::governed_transform::TransformPartition> =
            serde_json::from_str(&output_json).unwrap_or_default();
        if !redact_run_partition_receipts(dataset_id, &mut input_partitions, &mut output_partitions)
        {
            continue;
        }
        let input_json =
            serde_json::to_string(&input_partitions).map_err(|error| error.to_string())?;
        let output_json =
            serde_json::to_string(&output_partitions).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_governed_transform_run
             SET input_partitions = $1, output_partitions = $2
             WHERE run_id = $3",
            &[&input_json, &output_json, &run_id],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn persist_transform_run_pg(
    tx: &mut postgres::Transaction<'_>,
    run: &TransformRun,
) -> Result<(), String> {
    let incremental: i16 = i16::from(run.incremental);
    let quarantined: i16 = i16::from(run.quarantined);
    let output_partitions =
        serde_json::to_string(&run.output_partitions).map_err(|error| error.to_string())?;
    tx.execute(
        "UPDATE sekai_governed_transform_run SET
            output_digest = $2, last_input_row_id = $3, incremental = $4, quarantined = $5,
            quality_rule = $6, rows_in = $7, rows_out = $8, lineage_parent = $9,
            markings_in = $10, markings_out = $11, profile = $12, engine = $13,
            runtime_image = $14, dispatch_status = $15, trigger_cause = $16, trigger_ref = $17,
            output_partitions = $18
         WHERE run_id = $1",
        &[
            &run.run_id,
            &run.output_digest,
            &run.last_input_row_id,
            &incremental,
            &quarantined,
            &run.quality_rule,
            &run.rows_in,
            &run.rows_out,
            &run.lineage_parent,
            &run.markings_in,
            &run.markings_out,
            &run.profile,
            &run.engine,
            &run.runtime_image,
            &run.dispatch_status,
            &run.trigger_cause,
            &run.trigger_ref,
            &output_partitions,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn stamp_run_dispatch_pg(
    tx: &mut postgres::Transaction<'_>,
    run_id: &str,
    status: &str,
) -> Result<(), String> {
    tx.execute(
        "UPDATE sekai_governed_transform_run SET dispatch_status = $2 WHERE run_id = $1",
        &[&run_id, &status],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn list_all_transforms_pg(
    tx: &mut postgres::Transaction<'_>,
) -> Result<Vec<GovernedTransform>, String> {
    tx.query(
        "SELECT definition_json FROM sekai_governed_transform
         ORDER BY namespace, transform_id",
        &[],
    )
    .map_err(|error| error.to_string())?
    .into_iter()
    .map(|row| {
        let json: String = row.get(0);
        serde_json::from_str(&json).map_err(|error| error.to_string())
    })
    .collect()
}

fn row_to_output_state(row: Row) -> Result<TransformOutputState, String> {
    Ok(TransformOutputState {
        namespace: row.get(0),
        dataset_id: row.get(1),
        freshness: row.get(2),
        upstream_version: row.get(3),
        blocked_run_id: row.get(4),
        updated_at_ms: row.get(5),
    })
}

fn after_run_committed_pg(
    tx: &mut postgres::Transaction<'_>,
    transform: &GovernedTransform,
    run: &TransformRun,
    now_ms: i64,
) -> Result<Vec<TransformRun>, String> {
    tx.execute(
        "DELETE FROM sekai_transform_trigger_pending
         WHERE namespace = $1 AND transform_id = $2 AND first_seen_ms <= $3",
        &[
            &transform.namespace,
            &transform.transform_id,
            &run.created_at_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    if run.quarantined {
        upsert_output_state_pg(
            tx,
            &transform.namespace,
            &transform.output_dataset_id,
            TRANSFORM_OUTPUT_BLOCKED,
            &run.run_id,
            &run.run_id,
            now_ms,
        )?;
        for downstream in list_all_transforms_pg(tx)? {
            if downstream.namespace != transform.namespace
                || !downstream.consumes_dataset(&transform.output_dataset_id)
                || downstream.change_trigger().is_none()
            {
                continue;
            }
            upsert_output_state_pg(
                tx,
                &downstream.namespace,
                &downstream.output_dataset_id,
                TRANSFORM_OUTPUT_BLOCKED,
                &run.run_id,
                &run.run_id,
                now_ms,
            )?;
            tx.execute(
                "DELETE FROM sekai_transform_trigger_pending
                 WHERE namespace = $1 AND transform_id = $2",
                &[&downstream.namespace, &downstream.transform_id],
            )
            .map_err(|error| error.to_string())?;
        }
        return Ok(Vec::new());
    }
    let pending_ref = tx
        .query_opt(
            "SELECT cause_ref FROM sekai_transform_trigger_pending
             WHERE namespace = $1 AND transform_id = $2",
            &[&transform.namespace, &transform.transform_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get::<_, String>(0));
    if let Some(cause_ref) = pending_ref {
        upsert_output_state_pg(
            tx,
            &transform.namespace,
            &transform.output_dataset_id,
            TRANSFORM_OUTPUT_STALE,
            &cause_ref,
            "",
            now_ms,
        )?;
    } else {
        upsert_output_state_pg(
            tx,
            &transform.namespace,
            &transform.output_dataset_id,
            TRANSFORM_OUTPUT_FRESH,
            &run.output_digest,
            "",
            now_ms,
        )?;
    }
    enqueue_change_triggers_pg(
        tx,
        &transform.namespace,
        &transform.output_dataset_id,
        TRANSFORM_TRIGGER_UPSTREAM,
        &run.run_id,
        now_ms,
        true,
    )
}

fn upsert_output_state_pg(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    dataset_id: &str,
    freshness: &str,
    upstream_version: &str,
    blocked_run_id: &str,
    now_ms: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_transform_output_state
         (namespace, dataset_id, freshness, upstream_version, blocked_run_id, updated_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (namespace, dataset_id) DO UPDATE SET
            freshness = EXCLUDED.freshness,
            upstream_version = EXCLUDED.upstream_version,
            blocked_run_id = EXCLUDED.blocked_run_id,
            updated_at_ms = EXCLUDED.updated_at_ms",
        &[
            &namespace,
            &dataset_id,
            &freshness,
            &upstream_version,
            &blocked_run_id,
            &now_ms,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn enqueue_change_triggers_pg(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    dataset_id: &str,
    cause: &str,
    cause_ref: &str,
    now_ms: i64,
    admit_now: bool,
) -> Result<Vec<TransformRun>, String> {
    let mut admitted = Vec::new();
    for transform in list_all_transforms_pg(tx)? {
        if transform.namespace != namespace || !transform.consumes_dataset(dataset_id) {
            continue;
        }
        let Some(trigger) = transform.change_trigger() else {
            continue;
        };
        if cause == TRANSFORM_TRIGGER_UPSTREAM
            && remaining_blocked_inputs_pg(tx, &transform, dataset_id)?
        {
            continue;
        }
        if output_blocked_by_upstream_pg(tx, &transform)? && cause != TRANSFORM_TRIGGER_UPSTREAM {
            continue;
        }
        upsert_output_state_pg(
            tx,
            &transform.namespace,
            &transform.output_dataset_id,
            TRANSFORM_OUTPUT_STALE,
            cause_ref,
            "",
            now_ms,
        )?;
        let first_seen = tx
            .query_opt(
                "SELECT first_seen_ms FROM sekai_transform_trigger_pending
                 WHERE namespace = $1 AND transform_id = $2",
                &[&transform.namespace, &transform.transform_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, i64>(0))
            .unwrap_or(now_ms);
        tx.execute(
            "INSERT INTO sekai_transform_trigger_pending
             (namespace, transform_id, cause, cause_ref, first_seen_ms)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (namespace, transform_id) DO UPDATE SET
                cause = EXCLUDED.cause,
                cause_ref = EXCLUDED.cause_ref",
            &[
                &transform.namespace,
                &transform.transform_id,
                &cause,
                &cause_ref,
                &first_seen,
            ],
        )
        .map_err(|error| error.to_string())?;
        // Source-batch bursts pass admit_now=false and wait for debounce.
        // A committed upstream DAG hop admits in this transaction so the
        // pipeline advances without a later tick.
        if (admit_now || trigger_is_due(first_seen, trigger.debounce_ms, now_ms))
            && can_admit_namespace_pg(tx, &transform.namespace)?
            && let Some(run) = run_caused_pg(tx, &transform, false, cause, cause_ref, now_ms)?
        {
            admitted.push(run);
        }
    }
    Ok(admitted)
}

fn can_admit_namespace_pg(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
) -> Result<bool, String> {
    let lock_key = advisory_lock_key(&["governed_transform", "admit", namespace]);
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
        &[&lock_key],
    )
    .map_err(|error| error.to_string())?;
    let limit: i64 = tx
        .query_opt(
            "SELECT max_concurrent FROM sekai_transform_namespace_limit WHERE namespace = $1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .unwrap_or(DEFAULT_TRANSFORM_TENANT_CONCURRENCY)
        .max(1);
    let inflight: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM sekai_transform_work
             WHERE namespace = $1 AND status IN ($2, $3)",
            &[&namespace, &TRANSFORM_WORK_PENDING, &TRANSFORM_WORK_CLAIMED],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    Ok(inflight < limit)
}

fn remaining_blocked_inputs_pg(
    tx: &mut postgres::Transaction<'_>,
    transform: &GovernedTransform,
    recovered_dataset_id: &str,
) -> Result<bool, String> {
    for (_, dataset_id) in transform.input_bindings() {
        if dataset_id == recovered_dataset_id {
            continue;
        }
        let blocked = tx
            .query_opt(
                "SELECT freshness FROM sekai_transform_output_state
                 WHERE namespace = $1 AND dataset_id = $2",
                &[&transform.namespace, &dataset_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0))
            .is_some_and(|freshness| freshness == TRANSFORM_OUTPUT_BLOCKED);
        if blocked {
            return Ok(true);
        }
    }
    Ok(false)
}

fn output_blocked_by_upstream_pg(
    tx: &mut postgres::Transaction<'_>,
    transform: &GovernedTransform,
) -> Result<bool, String> {
    let Some(row) = tx
        .query_opt(
            "SELECT freshness, blocked_run_id FROM sekai_transform_output_state
             WHERE namespace = $1 AND dataset_id = $2",
            &[&transform.namespace, &transform.output_dataset_id],
        )
        .map_err(|error| error.to_string())?
    else {
        return Ok(false);
    };
    let freshness: String = row.get(0);
    let blocked_run_id: String = row.get(1);
    if freshness != TRANSFORM_OUTPUT_BLOCKED || blocked_run_id.is_empty() {
        return Ok(false);
    }
    Ok(
        load_transform_run_pg(tx, &blocked_run_id)?.is_some_and(|run| {
            run.namespace != transform.namespace || run.transform_id != transform.transform_id
        }),
    )
}

fn tick_governed_transforms_pg(
    tx: &mut postgres::Transaction<'_>,
    now_ms: i64,
) -> Result<Vec<TransformRun>, String> {
    let lock_key = advisory_lock_key(&["governed_transform", "tick"]);
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
        &[&lock_key],
    )
    .map_err(|error| error.to_string())?;
    let mut by_namespace: BTreeMap<String, Vec<(GovernedTransform, String, String)>> =
        BTreeMap::new();
    for transform in list_all_transforms_pg(tx)? {
        if let Some(schedule) = &transform.schedule
            && !output_blocked_by_upstream_pg(tx, &transform)?
        {
            let last = tx
                .query_opt(
                    "SELECT last_bucket FROM sekai_transform_schedule_cursor
                     WHERE namespace = $1 AND transform_id = $2",
                    &[&transform.namespace, &transform.transform_id],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, i64>(0));
            if let Some(bucket) = schedule_due_bucket(last, schedule.every_ms, now_ms) {
                by_namespace
                    .entry(transform.namespace.clone())
                    .or_default()
                    .push((
                        transform.clone(),
                        TRANSFORM_TRIGGER_SCHEDULE.into(),
                        bucket.to_string(),
                    ));
            }
        }
        if let Some(row) = tx
            .query_opt(
                "SELECT first_seen_ms, cause, cause_ref FROM sekai_transform_trigger_pending
                 WHERE namespace = $1 AND transform_id = $2",
                &[&transform.namespace, &transform.transform_id],
            )
            .map_err(|error| error.to_string())?
        {
            let first_seen: i64 = row.get(0);
            let cause: String = row.get(1);
            let cause_ref: String = row.get(2);
            let debounce = transform
                .change_trigger()
                .map(|trigger| trigger.debounce_ms)
                .unwrap_or(0);
            if trigger_is_due(first_seen, debounce, now_ms) {
                let items = by_namespace.entry(transform.namespace.clone()).or_default();
                if !items
                    .iter()
                    .any(|(queued, _, _)| queued.transform_id == transform.transform_id)
                {
                    items.push((transform, cause, cause_ref));
                }
            }
        }
    }
    let mut due: Vec<Vec<(GovernedTransform, String, String)>> =
        by_namespace.into_values().collect();
    let mut admitted = Vec::new();
    loop {
        let mut progress = false;
        for items in &mut due {
            while !items.is_empty() {
                let namespace = items[0].0.namespace.clone();
                if !can_admit_namespace_pg(tx, &namespace)? {
                    items.clear();
                    break;
                }
                let (transform, cause, cause_ref) = items.remove(0);
                if let Some(run) = run_caused_pg(tx, &transform, false, &cause, &cause_ref, now_ms)?
                {
                    if cause == TRANSFORM_TRIGGER_SCHEDULE
                        && let Ok(bucket) = cause_ref.parse::<i64>()
                    {
                        tx.execute(
                            "INSERT INTO sekai_transform_schedule_cursor
                             (namespace, transform_id, last_bucket) VALUES ($1,$2,$3)
                             ON CONFLICT (namespace, transform_id) DO UPDATE SET
                                last_bucket = EXCLUDED.last_bucket",
                            &[&transform.namespace, &transform.transform_id, &bucket],
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    admitted.push(run);
                    progress = true;
                    break;
                }
            }
        }
        if !progress {
            break;
        }
    }
    Ok(admitted)
}

fn run_caused_pg(
    tx: &mut postgres::Transaction<'_>,
    transform: &GovernedTransform,
    incremental: bool,
    cause: &str,
    cause_ref: &str,
    now_ms: i64,
) -> Result<Option<TransformRun>, String> {
    if transform.is_isolated_process() {
        let open: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM sekai_transform_work
                 WHERE namespace = $1 AND transform_id = $2 AND status IN ($3, $4)",
                &[
                    &transform.namespace,
                    &transform.transform_id,
                    &TRANSFORM_WORK_PENDING,
                    &TRANSFORM_WORK_CLAIMED,
                ],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if open > 0 {
            return Ok(None);
        }
        let mut run = admit_isolated_postgres(tx, transform, now_ms)?;
        run.stamp_trigger(cause, cause_ref);
        persist_transform_run_pg(tx, &run)?;
        tx.execute(
            "DELETE FROM sekai_transform_trigger_pending
             WHERE namespace = $1 AND transform_id = $2",
            &[&transform.namespace, &transform.transform_id],
        )
        .map_err(|error| error.to_string())?;
        return Ok(Some(run));
    }
    let mut run = run_in_process_pg(tx, transform, incremental, now_ms)?;
    run.stamp_trigger(cause, cause_ref);
    persist_transform_run_pg(tx, &run)?;
    after_run_committed_pg(tx, transform, &run, now_ms)?;
    Ok(Some(run))
}

fn run_in_process_pg(
    tx: &mut postgres::Transaction<'_>,
    transform: &GovernedTransform,
    incremental: bool,
    now_ms: i64,
) -> Result<TransformRun, String> {
    let bindings = transform.input_bindings();
    let mut lock_ids: Vec<&str> = bindings.iter().map(|(_, id)| id.as_str()).collect();
    lock_ids.push(transform.output_dataset_id.as_str());
    lock_transform_datasets(tx, &lock_ids)?;
    let stored = load_checkpoint(tx, &transform.namespace, &transform.transform_id)?;
    let output_keys = load_dataset_partition_keys_pg(tx, &transform.output_dataset_id)?;
    let (mut incremental, checkpoint) = bind_checkpoint(
        incremental,
        stored,
        &transform.definition_digest,
        &output_keys,
    );
    if !transform.allows_incremental() {
        incremental = false;
    }
    let after_id = checkpoint_after_id(incremental, checkpoint.as_ref());
    let mut load_budget = InputLoadBudget::for_transform(transform);
    let mut loaded: Vec<(String, Vec<String>, Vec<DatasetRowRecord>)> = Vec::new();
    let mut input_object_tokens: Vec<Option<String>> = Vec::new();
    for (alias, dataset_id) in &bindings {
        loaded.push((
            alias.clone(),
            load_dataset_column_names(tx, dataset_id)?,
            load_row_records(tx, dataset_id, after_id, load_budget.as_mut())?,
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
    let output_object_id = load_dataset_object_id(tx, &transform.output_dataset_id)?;
    if !output_object_id.trim().is_empty() {
        lock_object_lifecycle(tx, &output_object_id)?;
    }
    let prior_token = load_object_marking_token(tx, &output_object_id)?;
    let marking_rows: Vec<&HashMap<String, String>> = loaded
        .iter()
        .flat_map(|(_, _, records)| records.iter().map(|(_, row)| row))
        .collect();
    let (markings_in, markings_out) = derive_transform_markings(
        None,
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
                    transform,
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
                transform,
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
    run.input_partitions = input_receipts_from_loaded_pg(tx, &bindings, &loaded)?;
    if run.quarantined {
        if !incremental {
            let live = live_output_rows_pg(tx, &transform.output_dataset_id)?;
            let keys = load_dataset_partition_keys_pg(tx, &transform.output_dataset_id)?;
            run.output_digest = dataset_digest(&keys, &live);
        }
        insert_transform_run(tx, &run)?;
        return Ok(run);
    }
    require_bound_output_for_markings(&output_object_id, &run.markings_out)?;
    persist_computed_output_pg(
        tx,
        transform,
        &bindings,
        &loaded,
        incremental,
        checkpoint.as_ref(),
        &output_rows,
        &mut run,
    )?;
    stamp_object_marking(tx, &output_object_id, &run.markings_out, now_ms)?;
    insert_transform_run(tx, &run)?;
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
            &transform.namespace,
            &transform.transform_id,
            &transform.definition_digest,
            &run.last_input_row_id,
            &run.run_id,
            &run.output_digest,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(run)
}

fn resolve_changed_datasets_pg(
    tx: &mut postgres::Transaction<'_>,
    object_or_dataset_ids: &[String],
) -> Result<Vec<String>, String> {
    let mut datasets = Vec::new();
    for id in object_or_dataset_ids {
        if id.trim().is_empty() {
            continue;
        }
        let found = tx
            .query(
                "SELECT id FROM sekai_datasets WHERE id = $1 OR object_id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?;
        for row in found {
            let dataset_id: String = row.get(0);
            if !datasets.contains(&dataset_id) {
                datasets.push(dataset_id);
            }
        }
    }
    Ok(datasets)
}

fn cancel_governed_transform_run_pg(
    tx: &mut postgres::Transaction<'_>,
    run_id: &str,
    now_ms: i64,
) -> Result<TransformRun, String> {
    let mut run = load_transform_run_pg(tx, run_id)?.ok_or("governed transform run not found")?;
    if let Some(work) = load_transform_work_pg(tx, run_id)?
        && (work.status == TRANSFORM_WORK_PENDING || work.status == TRANSFORM_WORK_CLAIMED)
    {
        tx.execute(
            "UPDATE sekai_transform_work SET status = $2 WHERE run_id = $1",
            &[&run_id, &TRANSFORM_WORK_CANCELLED],
        )
        .map_err(|error| error.to_string())?;
        run.dispatch_status = TRANSFORM_WORK_CANCELLED.into();
        run.quarantined = true;
        run.quality_rule = TRANSFORM_TRIGGER_CANCELLED.into();
        run.stamp_trigger(TRANSFORM_TRIGGER_CANCELLED, run_id);
        persist_transform_run_pg(tx, &run)?;
        delete_run_input_snapshot_pg(tx, run_id)?;
    }
    if let Some(transform) = load_transform(tx, &run.namespace, &run.transform_id)? {
        for downstream in list_all_transforms_pg(tx)? {
            if downstream.namespace != transform.namespace
                || !downstream.consumes_dataset(&transform.output_dataset_id)
            {
                continue;
            }
            let pending_work: Option<String> = tx
                .query_opt(
                    "SELECT run_id FROM sekai_transform_work
                     WHERE namespace = $1 AND transform_id = $2 AND status = $3",
                    &[
                        &downstream.namespace,
                        &downstream.transform_id,
                        &TRANSFORM_WORK_PENDING,
                    ],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get(0));
            let had_trigger = tx
                .query_opt(
                    "SELECT 1 FROM sekai_transform_trigger_pending
                     WHERE namespace = $1 AND transform_id = $2",
                    &[&downstream.namespace, &downstream.transform_id],
                )
                .map_err(|error| error.to_string())?
                .is_some();
            if pending_work.is_none() && !had_trigger {
                continue;
            }
            tx.execute(
                "DELETE FROM sekai_transform_trigger_pending
                 WHERE namespace = $1 AND transform_id = $2",
                &[&downstream.namespace, &downstream.transform_id],
            )
            .map_err(|error| error.to_string())?;
            if let Some(work_run_id) = pending_work {
                if let Some(work) = load_transform_work_pg(tx, &work_run_id)?
                    && work.status == TRANSFORM_WORK_PENDING
                {
                    tx.execute(
                        "UPDATE sekai_transform_work SET status = $2 WHERE run_id = $1",
                        &[&work_run_id, &TRANSFORM_WORK_CANCELLED],
                    )
                    .map_err(|error| error.to_string())?;
                    if let Some(mut downstream_run) = load_transform_run_pg(tx, &work_run_id)? {
                        downstream_run.dispatch_status = TRANSFORM_WORK_CANCELLED.into();
                        downstream_run.quarantined = true;
                        downstream_run.quality_rule = TRANSFORM_TRIGGER_CANCELLED.into();
                        downstream_run.stamp_trigger(TRANSFORM_TRIGGER_CANCELLED, &run.run_id);
                        persist_transform_run_pg(tx, &downstream_run)?;
                    }
                    delete_run_input_snapshot_pg(tx, &work_run_id)?;
                }
                continue;
            }
            let skip = TransformRun {
                run_id: Uuid::new_v4().to_string(),
                namespace: downstream.namespace.clone(),
                transform_id: downstream.transform_id.clone(),
                definition_digest: downstream.definition_digest.clone(),
                input_digest: String::new(),
                output_digest: String::new(),
                last_input_row_id: 0,
                incremental: false,
                quarantined: true,
                quality_rule: TRANSFORM_TRIGGER_CANCELLED.into(),
                rows_in: 0,
                rows_out: 0,
                lineage_parent: run.run_id.clone(),
                created_at_ms: now_ms,
                markings_in: String::new(),
                markings_out: String::new(),
                profile: String::new(),
                engine: String::new(),
                runtime_image: String::new(),
                dispatch_status: TRANSFORM_WORK_CANCELLED.into(),
                trigger_cause: TRANSFORM_TRIGGER_CANCELLED.into(),
                trigger_ref: run.run_id.clone(),
                input_partitions: Vec::new(),
                output_partitions: Vec::new(),
            };
            insert_transform_run(tx, &skip)?;
        }
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::postgres::ScratchDatabase;
    use crate::sekai::dataset::{ColumnDef, Dataset, RowQuery};
    use crate::sekai::governed_transform::{
        AnalyticalSpec, CONTRACT_VERSION, ISOLATED_CLASS, IsolatedProcessSpec,
        PARTITIONED_DIGEST_PREFIX, TRANSFORM_DEPENDENCY_CYCLE, TRANSFORM_TRIGGER_MANUAL,
        TRANSFORM_TRIGGER_SCHEDULE, TRANSFORM_TRIGGER_UPSTREAM, TransformInput, TransformSchedule,
        TransformStep, TransformTrigger,
    };

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
            partition_keys: Vec::new(),
        }
    }

    fn partitioned_dataset(id: &str) -> Dataset {
        let mut dataset = dataset(id);
        dataset.columns.push(ColumnDef {
            name: "region".into(),
            col_type: "string".into(),
            classification: "public".into(),
        });
        dataset.partition_keys = vec!["region".into()];
        dataset
    }

    fn east_west_rows() -> (Vec<HashMap<String, String>>, Vec<HashMap<String, String>>) {
        (
            vec![HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
                ("region".into(), "east".into()),
            ])],
            vec![HashMap::from([
                ("id".into(), "2".into()),
                ("keep".into(), "yes".into()),
                ("region".into(), "west".into()),
            ])],
        )
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
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
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
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
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
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
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
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
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
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
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
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_incremental_run_on_analytical_profile() {
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
        db.put_governed_transform(&analytical_filter(), 10).unwrap();
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
        let live = db.query_dataset_rows("out", &RowQuery::default()).unwrap();
        assert_eq!(live.len(), 101);
        assert_eq!(second.output_digest, rows_digest(&live));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_analytical_join_aggregate_writes_receipt() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
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
            partition_keys: Vec::new(),
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
            partition_keys: Vec::new(),
        };
        db.create_dataset(&customers).unwrap();
        db.create_dataset(&orders).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
            "customers",
            &[
                HashMap::from([("id".into(), "c1".into()), ("region".into(), "east".into())]),
                HashMap::from([("id".into(), "c2".into()), ("region".into(), "west".into())]),
            ],
        )
        .unwrap();
        db.append_dataset_rows(
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
            isolated_process: None,
            schedule: None,
            trigger: None,
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
        let live = db.query_dataset_rows("out", &RowQuery::default()).unwrap();
        assert_eq!(live[0].get("region").map(String::as_str), Some("east"));
        assert_eq!(live[0].get("orders").map(String::as_str), Some("2"));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_over_budget_analytical_query_keeps_previous_output() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
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
            isolated_process: None,
            schedule: None,
            trigger: None,
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
        assert_eq!(
            db.query_dataset_rows("out", &RowQuery::default())
                .unwrap()
                .len(),
            1
        );
    }

    fn isolated_transform() -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "iso1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                inputs: Vec::new(),
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_run_claims_reads_and_commits_write_back() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        let admitted = db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        assert_eq!(admitted.profile, ISOLATED_CLASS);
        assert_eq!(admitted.dispatch_status, TRANSFORM_WORK_PENDING);
        assert!(
            db.query_dataset_rows("out", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        assert_eq!(work.run_id, admitted.run_id);
        assert_eq!(work.status, TRANSFORM_WORK_CLAIMED);
        let fence = WriteTransformRunCommand {
            run_id: work.run_id.clone(),
            runtime_id: work.claim_owner.clone(),
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token.clone(),
            ..WriteTransformRunCommand::default()
        };
        let inputs = db
            .read_transform_run_input(&fence, "", "", 0, 100, 40)
            .unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].values.get("id").map(String::as_str), Some("1"));
        let output = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("keep".into(), "yes".into()),
            ("derived".into(), "ok".into()),
        ])];
        let committed = db
            .write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id.clone(),
                    runtime_id: work.claim_owner.clone(),
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token.clone(),
                    rows: output.clone(),
                    output_digest: rows_digest(&output),
                    quarantined: false,
                    quality_rule: String::new(),
                    ..WriteTransformRunCommand::default()
                },
                50,
            )
            .unwrap();
        assert_eq!(committed.dispatch_status, TRANSFORM_WORK_COMPLETED);
        assert_eq!(committed.rows_out, 1);
        let live = db.query_dataset_rows("out", &RowQuery::default()).unwrap();
        assert_eq!(live, output);
        assert_eq!(committed.output_digest, rows_digest(&live));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_write_back_folds_live_output_marking() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        let mut input = dataset("in");
        input.object_id = "in-obj".into();
        let mut output = dataset("out");
        output.object_id = "out-obj".into();
        db.create_object(&object("in-obj", None)).unwrap();
        db.create_object(&object("out-obj", None)).unwrap();
        db.create_dataset(&input).unwrap();
        db.create_dataset(&output).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        let admitted = db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        assert!(admitted.markings_out.is_empty());
        let mut live_object = db.get_object("out-obj").unwrap().unwrap();
        live_object
            .properties
            .insert(OBJECT_CLASSIFICATION_PROPERTY.into(), "confidential".into());
        db.update_object(&live_object).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let output_rows = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("keep".into(), "yes".into()),
        ])];
        let committed = db
            .write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id,
                    runtime_id: work.claim_owner,
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token,
                    rows: output_rows.clone(),
                    output_digest: rows_digest(&output_rows),
                    quarantined: false,
                    quality_rule: String::new(),
                    ..WriteTransformRunCommand::default()
                },
                50,
            )
            .unwrap();
        assert_eq!(committed.markings_out, "confidential");
        let stamped = db.get_object("out-obj").unwrap().unwrap();
        assert_eq!(
            stamped.properties.get(OBJECT_CLASSIFICATION_PROPERTY),
            Some(&"confidential".to_string())
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_quarantined_write_back_folds_live_output_marking() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        let mut input = dataset("in");
        input.object_id = "in-obj".into();
        let mut output = dataset("out");
        output.object_id = "out-obj".into();
        db.create_object(&object("in-obj", None)).unwrap();
        db.create_object(&object("out-obj", None)).unwrap();
        db.create_dataset(&input).unwrap();
        db.create_dataset(&output).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let mut live_object = db.get_object("out-obj").unwrap().unwrap();
        live_object
            .properties
            .insert(OBJECT_CLASSIFICATION_PROPERTY.into(), "confidential".into());
        db.update_object(&live_object).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let committed = db
            .write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id,
                    runtime_id: work.claim_owner,
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token,
                    rows: vec![HashMap::from([("id".into(), "1".into())])],
                    output_digest: "ignored".into(),
                    quarantined: true,
                    quality_rule: "worker-failed".into(),
                    ..WriteTransformRunCommand::default()
                },
                50,
            )
            .unwrap();
        assert!(committed.quarantined);
        assert_eq!(committed.markings_out, "confidential");
        assert!(
            db.query_dataset_rows("out", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_stale_fence_write_back_commits_nothing() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        let admitted = db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let output = vec![HashMap::from([("id".into(), "x".into())])];
        let error = db
            .write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id,
                    runtime_id: work.claim_owner,
                    claim_generation: work.claim_generation,
                    fencing_token: "not-the-token".into(),
                    rows: output,
                    output_digest: "ignored".into(),
                    quarantined: false,
                    quality_rule: String::new(),
                    ..WriteTransformRunCommand::default()
                },
                40,
            )
            .unwrap_err();
        assert_eq!(error, STALE_TRANSFORM_CLAIM);
        assert!(
            db.query_dataset_rows("out", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
        let stored = db
            .get_governed_transform_run(&admitted.run_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.dispatch_status, TRANSFORM_WORK_CLAIMED);
        assert!(stored.output_digest.is_empty());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_expired_lease_returns_to_the_queue() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let (first, _) = db
            .claim_transform_work("ops", "runner-a", "", 5, 30)
            .unwrap()
            .expect("first claim");
        let (second, _) = db
            .claim_transform_work("ops", "runner-b", "", 5, first.claim_expires_at_ms + 1)
            .unwrap()
            .expect("expired lease returns to queue");
        assert_eq!(second.claim_owner, "runner-b");
        assert_eq!(second.claim_generation, first.claim_generation + 1);
        assert_eq!(second.lease_expiries, 1);
        assert_ne!(second.fencing_token, first.fencing_token);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_third_lease_expiry_fails_the_run() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        let admitted = db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let mut now_ms = 30;
        for attempt in 0..MAX_TRANSFORM_LEASE_EXPIRIES {
            let (work, _) = db
                .claim_transform_work("ops", &format!("runner-{attempt}"), "", 5, now_ms)
                .unwrap()
                .expect("claim before the expiry cap");
            now_ms = work.claim_expires_at_ms + 1;
        }
        assert!(
            db.claim_transform_work("ops", "runner-final", "", 5, now_ms)
                .unwrap()
                .is_none()
        );
        let stored = db
            .get_governed_transform_run(&admitted.run_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.dispatch_status, TRANSFORM_WORK_FAILED);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_reads_the_admitted_input_snapshot() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "2".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let inputs = db
            .read_transform_run_input(
                &WriteTransformRunCommand {
                    run_id: work.run_id,
                    runtime_id: work.claim_owner,
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token,
                    ..WriteTransformRunCommand::default()
                },
                "",
                "",
                0,
                100,
                40,
            )
            .unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].values.get("id").map(String::as_str), Some("1"));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_write_back_enforces_the_jobspec_quality_rule() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
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
            transform_id: "iso1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: "required:keep".into(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                inputs: Vec::new(),
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let admitted = db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let output = vec![HashMap::from([("id".into(), "1".into())])];
        let committed = db
            .write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id,
                    runtime_id: work.claim_owner,
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token,
                    rows: output.clone(),
                    output_digest: rows_digest(&output),
                    quarantined: false,
                    quality_rule: String::new(),
                    ..WriteTransformRunCommand::default()
                },
                40,
            )
            .unwrap();
        assert!(committed.quarantined);
        assert!(committed.quality_rule.contains("required:keep"));
        assert!(
            db.query_dataset_rows("out", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
        let stored = db
            .get_governed_transform_run(&admitted.run_id)
            .unwrap()
            .unwrap();
        assert!(stored.quarantined);
        assert_eq!(stored.output_digest, rows_digest(&[]));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_write_back_uses_the_admitted_jobspec() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.create_dataset(&dataset("other")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        let admitted = db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let mut updated = isolated_transform();
        updated.isolated_process.as_mut().unwrap().engine = "duckdb".into();
        updated.output_dataset_id = "other".into();
        updated.definition_digest.clear();
        let updated = updated.prepare().unwrap();
        db.put_governed_transform(&updated, 25).unwrap();
        let (work, transform) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("pinned admitted JobSpec");
        assert_eq!(work.run_id, admitted.run_id);
        assert_eq!(
            transform.isolated_process.as_ref().unwrap().engine,
            "python"
        );
        assert_eq!(transform.output_dataset_id, "out");
        let output = vec![HashMap::from([("id".into(), "1".into())])];
        db.write_transform_run(
            WriteTransformRunCommand {
                run_id: work.run_id,
                runtime_id: work.claim_owner,
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token,
                rows: output.clone(),
                output_digest: rows_digest(&output),
                quarantined: false,
                quality_rule: String::new(),
                ..WriteTransformRunCommand::default()
            },
            40,
        )
        .unwrap();
        assert_eq!(
            db.query_dataset_rows("out", &RowQuery::default()).unwrap(),
            output
        );
        assert!(
            db.query_dataset_rows("other", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_empty_alias_paginates_across_inputs() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("left")).unwrap();
        db.create_dataset(&dataset("right")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
            "left",
            &[
                HashMap::from([("id".into(), "1".into()), ("keep".into(), "yes".into())]),
                HashMap::from([("id".into(), "2".into()), ("keep".into(), "yes".into())]),
            ],
        )
        .unwrap();
        db.append_dataset_rows(
            "right",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "iso1".into(),
            input_dataset_id: "left".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                inputs: vec![
                    TransformInput {
                        alias: "left".into(),
                        dataset_id: "left".into(),
                    },
                    TransformInput {
                        alias: "right".into(),
                        dataset_id: "right".into(),
                    },
                ],
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let fence = WriteTransformRunCommand {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            ..WriteTransformRunCommand::default()
        };
        let mut seen = Vec::new();
        let mut after_alias = String::new();
        let mut after_row_id = 0;
        loop {
            let page = db
                .read_transform_run_input(&fence, "", &after_alias, after_row_id, 1, 40)
                .unwrap();
            if page.is_empty() {
                break;
            }
            after_alias = page[0].alias.clone();
            after_row_id = page[0].row_id;
            seen.push((page[0].alias.clone(), page[0].values.get("id").cloned()));
        }
        assert_eq!(
            seen,
            vec![
                ("left".into(), Some("1".into())),
                ("left".into(), Some("2".into())),
                ("right".into(), Some("1".into())),
            ]
        );
    }

    fn projection(id: &str, input: &str, output: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: id.into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: vec![step_filter()],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_put_refuses_a_dependency_cycle() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.put_governed_transform(&projection("a", "in", "out"), 10)
            .unwrap();
        let error = db
            .put_governed_transform(&projection("b", "out", "in"), 11)
            .unwrap_err();
        assert_eq!(error, TRANSFORM_DEPENDENCY_CYCLE);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_schedule_admits_one_run_per_tick_across_restarts() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        let mut transform = projection("t1", "in", "out");
        transform.schedule = Some(TransformSchedule { every_ms: 1_000 });
        transform.definition_digest.clear();
        let transform = transform.prepare().unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let first = db.tick_governed_transforms(1_500).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].trigger_cause, TRANSFORM_TRIGGER_SCHEDULE);
        assert_eq!(first[0].trigger_ref, "1");
        assert_eq!(db.tick_governed_transforms(1_800).unwrap().len(), 0);
        let second = db.tick_governed_transforms(2_000).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].trigger_ref, "2");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_schedule_partitioned_run_records_partition_digest() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&partitioned_dataset("in")).unwrap();
        db.create_dataset(&partitioned_dataset("out")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
                ("region".into(), "east".into()),
            ])],
        )
        .unwrap();
        let mut transform = projection("t1", "in", "out");
        transform.steps = vec![TransformStep {
            kind: "project".into(),
            column: String::new(),
            op: String::new(),
            value: String::new(),
            columns: vec!["id".into(), "keep".into(), "region".into()],
        }];
        transform.schedule = Some(TransformSchedule { every_ms: 1_000 });
        transform.definition_digest.clear();
        let transform = transform.prepare().unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let first = db.tick_governed_transforms(1_500).unwrap();
        assert_eq!(first.len(), 1);
        assert!(
            first[0]
                .output_digest
                .starts_with(PARTITIONED_DIGEST_PREFIX)
        );
        assert_eq!(first[0].input_partitions.len(), 1);
        assert_eq!(first[0].input_partitions[0].partition_key, "east");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_upstream_commit_triggers_downstream_once() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        for id in ["in", "mid", "out"] {
            db.create_dataset(&dataset(id)).unwrap();
        }
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&projection("up", "in", "mid"), 10)
            .unwrap();
        let mut down = projection("down", "mid", "out");
        down.trigger = Some(TransformTrigger {
            on_input_commit: true,
            debounce_ms: 0,
        });
        down.definition_digest.clear();
        let down = down.prepare().unwrap();
        db.put_governed_transform(&down, 11).unwrap();
        let up = db.run_governed_transform("ops", "up", false, 20).unwrap();
        assert_eq!(up.trigger_cause, TRANSFORM_TRIGGER_MANUAL);
        let runs = db.list_governed_transform_runs("ops", 10).unwrap();
        assert_eq!(runs.len(), 2);
        let down_run = runs.iter().find(|run| run.transform_id == "down").unwrap();
        assert_eq!(down_run.trigger_cause, TRANSFORM_TRIGGER_UPSTREAM);
        assert_eq!(down_run.trigger_ref, up.run_id);
        assert_eq!(db.tick_governed_transforms(30).unwrap().len(), 0);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_streamed_read_stays_inside_byte_bound() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&partitioned_dataset("in")).unwrap();
        db.create_dataset(&partitioned_dataset("out")).unwrap();
        let mut rows = Vec::new();
        for i in 0..20 {
            rows.push(HashMap::from([
                ("id".into(), i.to_string()),
                ("keep".into(), "yes".into()),
                ("region".into(), if i < 10 { "east" } else { "west" }.into()),
            ]));
        }
        db.append_dataset_rows("in", &rows).unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let mut fence = WriteTransformRunCommand {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            max_bytes: 40,
            ..WriteTransformRunCommand::default()
        };
        let mut seen = Vec::new();
        let mut after_alias = String::new();
        let mut after_row_id = 0;
        loop {
            let page = db
                .read_transform_run_input(&fence, "", &after_alias, after_row_id, 100, 40)
                .unwrap();
            if page.is_empty() {
                break;
            }
            let page_bytes: u64 = page
                .iter()
                .map(crate::sekai::governed_transform::row_stream_bytes)
                .sum();
            assert!(
                page_bytes <= 40 || page.len() == 1,
                "page exceeded bound: {page_bytes}"
            );
            after_alias = page.last().unwrap().alias.clone();
            after_row_id = page.last().unwrap().row_id;
            fence.partition_key = None;
            seen.extend(page);
        }
        assert_eq!(seen.len(), 20);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_partition_write_back_rewrites_one_partition() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&partitioned_dataset("in")).unwrap();
        db.create_dataset(&partitioned_dataset("out")).unwrap();
        let (east, west) = east_west_rows();
        db.append_dataset_rows("in", &[east[0].clone(), west[0].clone()])
            .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let first_output = vec![east[0].clone(), west[0].clone()];
        let keys = vec!["region".into()];
        let first_envelope = crate::sekai::governed_transform::partitioned_dataset_digest(
            &crate::sekai::governed_transform::group_rows_by_partition(&keys, &first_output)
                .into_iter()
                .map(|(key, rows)| (key, crate::sekai::governed_transform::rows_digest(&rows)))
                .collect(),
        );
        let committed = db
            .write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id.clone(),
                    runtime_id: work.claim_owner.clone(),
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token.clone(),
                    replaced_partitions: vec![
                        crate::sekai::governed_transform::TransformPartitionWrite {
                            partition_key: "east".into(),
                            rows: east.clone(),
                        },
                        crate::sekai::governed_transform::TransformPartitionWrite {
                            partition_key: "west".into(),
                            rows: west.clone(),
                        },
                    ],
                    output_digest: first_envelope,
                    ..WriteTransformRunCommand::default()
                },
                50,
            )
            .unwrap();
        assert_eq!(committed.output_partitions.len(), 2);
        let west_digest = committed
            .output_partitions
            .iter()
            .find(|partition| partition.partition_key == "west")
            .unwrap()
            .digest
            .clone();

        db.put_governed_transform(&isolated_transform(), 60)
            .unwrap();
        let admitted = db.run_governed_transform("ops", "iso1", false, 70).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", &admitted.run_id, 60_000, 80)
            .unwrap()
            .expect("claimable work");
        let mut new_east = east.clone();
        new_east[0].insert("keep".into(), "derived".into());
        let merged = vec![new_east[0].clone(), west[0].clone()];
        let envelope = crate::sekai::governed_transform::partitioned_dataset_digest(
            &crate::sekai::governed_transform::group_rows_by_partition(&keys, &merged)
                .into_iter()
                .map(|(key, rows)| (key, crate::sekai::governed_transform::rows_digest(&rows)))
                .collect(),
        );
        let second = db
            .write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id,
                    runtime_id: work.claim_owner,
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token,
                    replaced_partitions: vec![
                        crate::sekai::governed_transform::TransformPartitionWrite {
                            partition_key: "east".into(),
                            rows: new_east,
                        },
                    ],
                    output_digest: envelope,
                    ..WriteTransformRunCommand::default()
                },
                90,
            )
            .unwrap();
        assert_eq!(second.output_partitions.len(), 1);
        assert_eq!(second.output_partitions[0].partition_key, "east");
        let live = db.query_dataset_rows("out", &RowQuery::default()).unwrap();
        assert_eq!(live.len(), 2);
        let west_live = live
            .iter()
            .find(|row| row.get("region").map(String::as_str) == Some("west"))
            .unwrap();
        assert_eq!(west_live.get("id").map(String::as_str), Some("2"));
        assert_eq!(
            crate::sekai::governed_transform::rows_digest(&[west_live.clone()]),
            west_digest
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_isolated_process_failed_partition_write_keeps_previous_output() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&partitioned_dataset("in")).unwrap();
        db.create_dataset(&partitioned_dataset("out")).unwrap();
        let (east, west) = east_west_rows();
        db.append_dataset_rows("in", &[east[0].clone(), west[0].clone()])
            .unwrap();
        db.put_governed_transform(&isolated_transform(), 10)
            .unwrap();
        db.run_governed_transform("ops", "iso1", false, 20).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, 30)
            .unwrap()
            .expect("claimable work");
        let first_output = vec![east[0].clone(), west[0].clone()];
        let keys = vec!["region".into()];
        let first_envelope = crate::sekai::governed_transform::partitioned_dataset_digest(
            &crate::sekai::governed_transform::group_rows_by_partition(&keys, &first_output)
                .into_iter()
                .map(|(key, rows)| (key, crate::sekai::governed_transform::rows_digest(&rows)))
                .collect(),
        );
        db.write_transform_run(
            WriteTransformRunCommand {
                run_id: work.run_id,
                runtime_id: work.claim_owner,
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token,
                replaced_partitions: vec![
                    crate::sekai::governed_transform::TransformPartitionWrite {
                        partition_key: "east".into(),
                        rows: east.clone(),
                    },
                    crate::sekai::governed_transform::TransformPartitionWrite {
                        partition_key: "west".into(),
                        rows: west.clone(),
                    },
                ],
                output_digest: first_envelope,
                ..WriteTransformRunCommand::default()
            },
            50,
        )
        .unwrap();
        let before = db.query_dataset_rows("out", &RowQuery::default()).unwrap();
        db.put_governed_transform(&isolated_transform(), 60)
            .unwrap();
        let admitted = db.run_governed_transform("ops", "iso1", false, 70).unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", &admitted.run_id, 60_000, 80)
            .unwrap()
            .expect("claimable work");
        let error = db
            .write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id,
                    runtime_id: work.claim_owner,
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token,
                    replaced_partitions: vec![
                        crate::sekai::governed_transform::TransformPartitionWrite {
                            partition_key: "east".into(),
                            rows: east,
                        },
                    ],
                    output_digest: "sha256-sum-v1:not-the-envelope".into(),
                    ..WriteTransformRunCommand::default()
                },
                90,
            )
            .unwrap_err();
        assert!(error.contains("digest"));
        assert_eq!(
            db.query_dataset_rows("out", &RowQuery::default()).unwrap(),
            before
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_incremental_run_rewrites_only_changed_partition() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&partitioned_dataset("in")).unwrap();
        db.create_dataset(&partitioned_dataset("out")).unwrap();
        let (east, west) = east_west_rows();
        db.append_dataset_rows("in", &[east[0].clone(), west[0].clone()])
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
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let first = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert!(first.output_digest.starts_with("sha256-partitions-v1:"));
        assert_eq!(first.output_partitions.len(), 2);
        let before = db.list_dataset_row_records("out").unwrap();
        let west_ids: Vec<i64> = before
            .iter()
            .filter(|(_, row)| row.get("region").map(String::as_str) == Some("west"))
            .map(|(id, _)| *id)
            .collect();
        let east_ids: Vec<i64> = before
            .iter()
            .filter(|(_, row)| row.get("region").map(String::as_str) == Some("east"))
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(west_ids.len(), 1);
        assert_eq!(east_ids.len(), 1);
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "3".into()),
                ("keep".into(), "yes".into()),
                ("region".into(), "east".into()),
            ])],
        )
        .unwrap();
        let second = db.run_governed_transform("ops", "t1", true, 30).unwrap();
        assert_eq!(second.rows_in, 1);
        assert_eq!(second.output_partitions.len(), 1);
        assert_eq!(second.output_partitions[0].partition_key, "east");
        assert_ne!(second.output_digest, first.output_digest);
        let after = db.list_dataset_row_records("out").unwrap();
        let west_after: Vec<i64> = after
            .iter()
            .filter(|(_, row)| row.get("region").map(String::as_str) == Some("west"))
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(west_after, west_ids);
        let east_after: Vec<i64> = after
            .iter()
            .filter(|(_, row)| row.get("region").map(String::as_str) == Some("east"))
            .map(|(id, _)| *id)
            .collect();
        assert!(east_after.starts_with(&east_ids));
        assert_eq!(after.len(), 3);
        let live: Vec<_> = after.into_iter().map(|(_, row)| row).collect();
        assert_eq!(
            second.output_digest,
            crate::sekai::governed_transform::dataset_digest(&["region".into()], &live)
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_quality_failure_keeps_input_partition_receipts() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&partitioned_dataset("in")).unwrap();
        db.create_dataset(&partitioned_dataset("out")).unwrap();
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), String::new()),
                ("region".into(), "east".into()),
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
                columns: vec!["id".into(), "keep".into(), "region".into()],
            }],
            quality_rule: "required:keep".into(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let failed = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert!(failed.quarantined);
        assert_eq!(failed.input_partitions.len(), 1);
        assert_eq!(failed.input_partitions[0].partition_key, "east");
        assert_eq!(failed.input_partitions[0].rows, 1);
        assert!(
            db.query_dataset_rows("out", &RowQuery::default())
                .unwrap()
                .is_empty()
        );
    }

    fn sensitive_partitioned_dataset(id: &str) -> Dataset {
        let mut dataset = partitioned_dataset(id);
        for column in &mut dataset.columns {
            if column.name == "region" {
                column.classification = "sensitive".into();
            }
        }
        dataset
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_redact_dataset_fields_rewrites_transform_partition_receipts() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_dataset(&sensitive_partitioned_dataset("in"))
            .unwrap();
        db.create_dataset(&sensitive_partitioned_dataset("out"))
            .unwrap();
        let (east, west) = east_west_rows();
        db.append_dataset_rows("in", &[east[0].clone(), west[0].clone()])
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
                columns: vec!["id".into(), "keep".into(), "region".into()],
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        let run = db.run_governed_transform("ops", "t1", false, 20).unwrap();
        assert!(
            run.input_partitions
                .iter()
                .any(|partition| partition.partition_key == "east")
        );
        db.redact_dataset_fields("in", "sensitive", &[]).unwrap();
        let after_input = db.get_governed_transform_run(&run.run_id).unwrap().unwrap();
        assert!(
            after_input
                .input_partitions
                .iter()
                .all(|partition| partition.partition_key == "[redacted]")
        );
        assert!(
            after_input
                .output_partitions
                .iter()
                .any(|partition| partition.partition_key == "east")
        );
        db.redact_dataset_fields("out", "sensitive", &[]).unwrap();
        let after_output = db.get_governed_transform_run(&run.run_id).unwrap().unwrap();
        assert!(
            after_output
                .output_partitions
                .iter()
                .all(|partition| partition.partition_key == "[redacted]")
        );
    }
}

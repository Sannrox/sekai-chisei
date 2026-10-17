//! In-process execution for governed transforms.
//!
//! Types and SQL compile/validate live in `sekai-types`. This module keeps the
//! rusqlite host and re-exports the value types so existing `crate::sekai::governed_transform`
//! paths stay stable.

pub use sekai_types::governed_transform::*;

use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::sekai::transform_engine::{
    self, BUDGET_MEMORY, BUDGET_TIME, DEFAULT_MEMORY_LIMIT_BYTES, EngineTable, host_limit,
};

fn apply_profile(
    transform: &GovernedTransform,
    tables: &[EngineTable],
    deadline: Option<std::time::Instant>,
) -> Result<Vec<HashMap<String, String>>, TransformError> {
    if transform.isolated_process.is_some() {
        return Err(TransformError::InvalidArgument(
            "isolated_process runs cannot execute in-process".into(),
        ));
    }
    if let Some(spec) = &transform.analytical {
        transform_engine::execute_sql_until(
            &spec.sql,
            tables,
            spec.memory_limit_bytes,
            spec.time_limit_ms,
            deadline,
        )
    } else {
        Ok(apply_steps(
            tables
                .first()
                .map(|table| table.rows.as_slice())
                .unwrap_or(&[]),
            &transform.steps,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn quarantined_run(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    tables: &[EngineTable],
    after_id: i64,
    incremental: bool,
    now_ms: i64,
    run_id: String,
    rows_in: i32,
    reason: &str,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    (
        TransformRun {
            run_id,
            namespace: transform.namespace.clone(),
            transform_id: transform.transform_id.clone(),
            definition_digest: transform.definition_digest.clone(),
            input_digest: run_input_digest(transform, tables),
            output_digest: checkpoint
                .map(|checkpoint| checkpoint.2.clone())
                .unwrap_or_default(),
            last_input_row_id: after_id,
            incremental,
            quarantined: true,
            quality_rule: reason.into(),
            rows_in,
            rows_out: 0,
            lineage_parent: checkpoint
                .map(|checkpoint| checkpoint.1.clone())
                .unwrap_or_default(),
            created_at_ms: now_ms,
            markings_in: String::new(),
            markings_out: String::new(),
            profile: String::new(),
            engine: String::new(),
            runtime_image: String::new(),
            dispatch_status: String::new(),
            trigger_cause: String::new(),
            trigger_ref: String::new(),
            input_partitions: Vec::new(),
            output_partitions: Vec::new(),
        },
        Vec::new(),
    )
}

fn run_input_digest(transform: &GovernedTransform, tables: &[EngineTable]) -> String {
    if transform.is_analytical() || transform.is_isolated_process() {
        let mut hasher = Sha256::new();
        for table in tables {
            hash_field(&mut hasher, &table.alias);
            hash_field(&mut hasher, &rows_digest(&table.rows));
        }
        format!("sha256:{:x}", hasher.finalize())
    } else {
        rows_digest(
            tables
                .first()
                .map(|table| table.rows.as_slice())
                .unwrap_or(&[]),
        )
    }
}

/// Compute one run. The caller persists `output_rows` (unless quarantined),
/// then fills `run.output_digest` with `fold_output_digest` (incremental) or
/// `rows_digest(&output_rows)` (full rebuild) and writes the receipt.
/// Compute one run. The caller persists `output_rows` (unless quarantined),
/// then fills `run.output_digest` with `fold_output_digest` (incremental) or
/// `rows_digest(&output_rows)` (full rebuild) and writes the receipt.
pub fn compute_run(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    input_records: &[(i64, HashMap<String, String>)],
    incremental: bool,
    now_ms: i64,
    run_id: String,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    compute_run_tables(
        transform,
        checkpoint,
        &[TransformInputRows {
            alias: "input",
            records: input_records,
            columns: &[],
        }],
        incremental,
        now_ms,
        run_id,
    )
}

pub fn compute_run_tables(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    inputs: &[TransformInputRows<'_>],
    incremental: bool,
    now_ms: i64,
    run_id: String,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    compute_run_tables_until(
        transform,
        checkpoint,
        inputs,
        incremental,
        now_ms,
        run_id,
        None,
    )
}

pub fn compute_run_tables_until(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    inputs: &[TransformInputRows<'_>],
    incremental: bool,
    now_ms: i64,
    run_id: String,
    deadline: Option<std::time::Instant>,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    let after_id = checkpoint_after_id(incremental, checkpoint);
    let mut last_input_row_id = after_id;
    let mut tables: Vec<EngineTable> = Vec::new();
    let mut rows_in = 0i32;
    let mut used = 0u64;
    let memory_limit = transform
        .analytical
        .as_ref()
        .map(|spec| host_limit(spec.memory_limit_bytes, DEFAULT_MEMORY_LIMIT_BYTES));
    for input in inputs {
        let mut rows = Vec::new();
        for (id, row) in input.records {
            if *id <= after_id {
                continue;
            }
            last_input_row_id = last_input_row_id.max(*id);
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return quarantined_run(
                    transform,
                    checkpoint,
                    &tables,
                    after_id,
                    incremental,
                    now_ms,
                    run_id,
                    rows_in,
                    BUDGET_TIME,
                );
            }
            if let Some(limit) = memory_limit {
                used = used.saturating_add(row_payload_bytes(row));
                if used > limit {
                    return quarantined_run(
                        transform,
                        checkpoint,
                        &tables,
                        after_id,
                        incremental,
                        now_ms,
                        run_id,
                        rows_in,
                        BUDGET_MEMORY,
                    );
                }
            }
            rows.push(row.clone());
            rows_in += 1;
        }
        tables.push(EngineTable {
            alias: input.alias.to_string(),
            rows,
            columns: input.columns.to_vec(),
        });
    }
    let output_rows = match apply_profile(transform, &tables, deadline) {
        Ok(rows) => rows,
        Err(error) => {
            return quarantined_run(
                transform,
                checkpoint,
                &tables,
                after_id,
                incremental,
                now_ms,
                run_id,
                rows_in,
                &error.message(),
            );
        }
    };
    if let Err(error) = evaluate_quality(&output_rows, &transform.quality_rule) {
        return quarantined_run(
            transform,
            checkpoint,
            &tables,
            after_id,
            incremental,
            now_ms,
            run_id,
            rows_in,
            &error.message(),
        );
    }
    let run = TransformRun {
        run_id,
        namespace: transform.namespace.clone(),
        transform_id: transform.transform_id.clone(),
        definition_digest: transform.definition_digest.clone(),
        input_digest: run_input_digest(transform, &tables),
        output_digest: String::new(),
        last_input_row_id,
        incremental,
        quarantined: false,
        quality_rule: transform.quality_rule.clone(),
        rows_in,
        rows_out: output_rows.len() as i32,
        lineage_parent: checkpoint
            .map(|checkpoint| checkpoint.1.clone())
            .unwrap_or_default(),
        created_at_ms: now_ms,
        markings_in: String::new(),
        markings_out: String::new(),
        profile: String::new(),
        engine: String::new(),
        runtime_image: String::new(),
        dispatch_status: String::new(),
        trigger_cause: String::new(),
        trigger_ref: String::new(),
        input_partitions: Vec::new(),
        output_partitions: Vec::new(),
    };
    (run, output_rows)
}

/// Admit an isolated-process run as pending work. The plane does not compute
/// output rows; a claimed worker writes them back under a fence.
/// Admit an isolated-process run as pending work. The plane does not compute
/// output rows; a claimed worker writes them back under a fence.
pub fn admit_isolated_run(
    transform: &GovernedTransform,
    inputs: &[TransformInputRows<'_>],
    now_ms: i64,
    run_id: String,
) -> Result<TransformRun, TransformError> {
    let spec = transform.isolated_process.as_ref().ok_or_else(|| {
        TransformError::InvalidArgument("isolated_process profile required".into())
    })?;
    let mut last_input_row_id = 0i64;
    let mut tables: Vec<EngineTable> = Vec::new();
    let mut rows_in = 0i32;
    for input in inputs {
        let mut rows = Vec::new();
        for (id, row) in input.records {
            last_input_row_id = last_input_row_id.max(*id);
            rows.push(row.clone());
            rows_in += 1;
        }
        tables.push(EngineTable {
            alias: input.alias.to_string(),
            rows,
            columns: input.columns.to_vec(),
        });
    }
    Ok(TransformRun {
        run_id,
        namespace: transform.namespace.clone(),
        transform_id: transform.transform_id.clone(),
        definition_digest: transform.definition_digest.clone(),
        input_digest: run_input_digest(transform, &tables),
        output_digest: String::new(),
        last_input_row_id,
        incremental: false,
        quarantined: false,
        quality_rule: transform.quality_rule.clone(),
        rows_in,
        rows_out: 0,
        lineage_parent: String::new(),
        created_at_ms: now_ms,
        markings_in: String::new(),
        markings_out: String::new(),
        profile: ISOLATED_CLASS.into(),
        engine: spec.engine.clone(),
        runtime_image: spec.runtime_image.clone(),
        dispatch_status: TRANSFORM_WORK_PENDING.into(),
        trigger_cause: String::new(),
        trigger_ref: String::new(),
        input_partitions: Vec::new(),
        output_partitions: Vec::new(),
    })
}

/// Sampled in-process preview. Budget codes fail; other quarantine is `error`.
pub fn compute_preview_tables(
    transform: &GovernedTransform,
    inputs: &[TransformInputRows<'_>],
    now_ms: i64,
    preview_id: String,
) -> Result<(Vec<HashMap<String, String>>, String), String> {
    let deadline = transform.analytical.as_ref().and_then(|spec| {
        if spec.time_limit_ms == 0 {
            None
        } else {
            Some(std::time::Instant::now() + std::time::Duration::from_millis(spec.time_limit_ms))
        }
    });
    let (run, rows) =
        compute_run_tables_until(transform, None, inputs, false, now_ms, preview_id, deadline);
    if run.quarantined {
        let code = run.quality_rule;
        if code == BUDGET_TIME || code == BUDGET_MEMORY {
            return Err(code);
        }
        return Ok((rows, code));
    }
    Ok((rows, String::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn transform() -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: "yes".into(),
                columns: Vec::new(),
            }],
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
    fn projection_digest_ignores_absent_analytical_profile() {
        let first = transform();
        let mut second = first.clone();
        second.analytical = None;
        second.isolated_process = None;
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_eq!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn projection_digest_ignores_absent_isolated_process_profile() {
        let first = transform();
        let mut second = first.clone();
        second.isolated_process = None;
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_eq!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn projection_digest_ignores_absent_schedule_and_trigger() {
        let first = transform();
        let mut second = first.clone();
        second.schedule = None;
        second.trigger = None;
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_eq!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn schedule_participates_in_digest() {
        let first = transform();
        let mut second = first.clone();
        second.schedule = Some(TransformSchedule { every_ms: 60_000 });
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_ne!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn cycle_is_refused_from_published_definitions() {
        let upstream = transform();
        let mut downstream = transform();
        downstream.transform_id = "t2".into();
        downstream.input_dataset_id = "out".into();
        downstream.output_dataset_id = "mid".into();
        downstream.definition_digest.clear();
        let downstream = downstream.prepare().unwrap();
        refuse_dependency_cycle(std::slice::from_ref(&upstream), &downstream).unwrap();

        let mut back = transform();
        back.transform_id = "t3".into();
        back.input_dataset_id = "mid".into();
        back.output_dataset_id = "in".into();
        back.definition_digest.clear();
        let back = back.prepare().unwrap();
        let error = refuse_dependency_cycle(&[upstream, downstream], &back).unwrap_err();
        assert_eq!(error.message(), TRANSFORM_DEPENDENCY_CYCLE);
    }

    #[test]
    fn schedule_admits_each_bucket_once() {
        assert_eq!(schedule_due_bucket(None, 1_000, 1_500), Some(1));
        assert_eq!(schedule_due_bucket(Some(1), 1_000, 1_500), None);
        assert_eq!(schedule_due_bucket(Some(1), 1_000, 2_000), Some(2));
    }

    #[test]
    fn trigger_debounce_coalesces_until_the_window() {
        assert!(!trigger_is_due(10, 1_000, 500));
        assert!(trigger_is_due(10, 1_000, 1_010));
        assert!(trigger_is_due(10, 0, 10));
    }

    #[test]
    fn isolated_process_engine_participates_in_digest() {
        let first = isolated_transform("duckdb", "ghcr.io/sekai/runner:1");
        let second = isolated_transform("duckdb", "ghcr.io/sekai/runner:2");
        assert_ne!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn isolated_process_prepare_trims_input_aliases() {
        let mut transform = isolated_transform("python", "runner:1");
        transform.isolated_process.as_mut().unwrap().inputs = vec![TransformInput {
            alias: " left ".into(),
            dataset_id: " in ".into(),
        }];
        transform.input_dataset_id = " in ".into();
        transform.definition_digest.clear();
        let prepared = transform.prepare().unwrap();
        let spec = prepared.isolated_process.as_ref().unwrap();
        assert_eq!(spec.inputs[0].alias, "left");
        assert_eq!(spec.inputs[0].dataset_id, "in");
        assert_eq!(prepared.input_dataset_id, "in");
    }

    #[test]
    fn expired_claimed_work_returns_to_the_queue_until_the_lease_cap() {
        let work = TransformWork {
            status: TRANSFORM_WORK_CLAIMED.into(),
            claim_expires_at_ms: 10,
            lease_expiries: 0,
            ..TransformWork::default()
        };
        assert!(transform_work_is_claimable(&work, 11));
        let dead = TransformWork {
            lease_expiries: MAX_TRANSFORM_LEASE_EXPIRIES,
            ..work.clone()
        };
        assert!(!transform_work_is_claimable(&dead, 11));
        assert!(!transform_work_is_claimable(
            &TransformWork {
                status: TRANSFORM_WORK_COMPLETED.into(),
                ..work
            },
            11
        ));
    }

    #[test]
    fn write_back_fence_rejects_stale_generation_and_expired_lease() {
        let work = TransformWork {
            status: TRANSFORM_WORK_CLAIMED.into(),
            claim_owner: "runner-a".into(),
            claim_generation: 2,
            fencing_token: "fence".into(),
            claim_expires_at_ms: 50,
            ..TransformWork::default()
        };
        assert!(transform_claim_fence_matches(
            &work, "runner-a", 2, "fence", 40
        ));
        assert!(!transform_claim_fence_matches(
            &work, "runner-a", 1, "fence", 40
        ));
        assert!(!transform_claim_fence_matches(
            &work, "runner-a", 2, "other", 40
        ));
        assert!(!transform_claim_fence_matches(
            &work, "runner-a", 2, "fence", 50
        ));
        assert!(transform_claim_is_current(&work, "runner-a", 2, "fence"));
        let completed = TransformWork {
            status: TRANSFORM_WORK_COMPLETED.into(),
            claim_expires_at_ms: 10,
            ..work
        };
        assert!(transform_completed_write_matches(
            &completed, "runner-a", 2, "fence"
        ));
        assert!(!transform_completed_write_matches(
            &completed, "runner-b", 2, "fence"
        ));
        assert!(!transform_completed_write_matches(
            &completed, "runner-a", 1, "fence"
        ));
        assert!(!transform_completed_write_matches(
            &completed, "runner-a", 2, "other"
        ));
        assert!(!transform_completed_write_matches(
            &completed, "runner-a", 2, ""
        ));
        assert!(!transform_claim_is_current(
            &completed, "runner-a", 2, "fence"
        ));
    }

    fn isolated_transform(engine: &str, runtime_image: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "iso".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: engine.into(),
                runtime_image: runtime_image.into(),
                inputs: Vec::new(),
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    #[test]
    fn bind_checkpoint_drops_a_pin_from_a_different_digest() {
        let pin = (7, "run".into(), rows_digest(&[]));
        let (incremental, checkpoint) =
            bind_checkpoint(true, Some((pin.clone(), "old".into())), "new", &[]);
        assert!(!incremental);
        assert_eq!(checkpoint.as_ref(), Some(&pin));
        let (incremental, checkpoint) =
            bind_checkpoint(true, Some((pin.clone(), "same".into())), "same", &[]);
        assert!(incremental);
        assert_eq!(checkpoint.as_ref(), Some(&pin));
        let (incremental, checkpoint) =
            bind_checkpoint(false, Some((pin.clone(), "same".into())), "same", &[]);
        assert!(!incremental);
        assert_eq!(checkpoint, Some(pin));
    }

    #[test]
    fn bind_checkpoint_forces_rebuild_for_old_or_malformed_output_digest() {
        let definition = "same";
        let old = (7, "run".into(), format!("sha256:{}", "ab".repeat(32)));
        let (incremental, checkpoint) = bind_checkpoint(
            true,
            Some((old.clone(), definition.into())),
            definition,
            &[],
        );
        assert!(!incremental);
        assert_eq!(checkpoint.as_ref(), Some(&old));
        let empty = (7, "run".into(), String::new());
        let (incremental, _) =
            bind_checkpoint(true, Some((empty, definition.into())), definition, &[]);
        assert!(!incremental);
        let malformed = (7, "run".into(), "sha256-sum-v1:zzzz".into());
        let (incremental, _) =
            bind_checkpoint(true, Some((malformed, definition.into())), definition, &[]);
        assert!(!incremental);
        let partitioned = (
            7,
            "run".into(),
            partitioned_dataset_digest(&BTreeMap::new()),
        );
        let (incremental, _) = bind_checkpoint(
            true,
            Some((partitioned.clone(), definition.into())),
            definition,
            &[],
        );
        assert!(!incremental);
        let (incremental, _) = bind_checkpoint(
            true,
            Some((partitioned, definition.into())),
            definition,
            &["region".into()],
        );
        assert!(incremental);
    }

    #[test]
    fn changed_definition_gets_a_new_digest() {
        let first = transform();
        let mut second = first.clone();
        second.steps[0].value = "no".into();
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_ne!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn adjacent_dataset_ids_do_not_share_a_digest() {
        let mut left = transform();
        left.input_dataset_id = "a".into();
        left.output_dataset_id = "bc".into();
        left.definition_digest.clear();
        let left = left.prepare().unwrap();
        let mut right = transform();
        right.input_dataset_id = "ab".into();
        right.output_dataset_id = "c".into();
        right.definition_digest.clear();
        let right = right.prepare().unwrap();
        assert_ne!(left.definition_digest, right.definition_digest);
    }

    #[test]
    fn secrets_are_rejected_in_definitions() {
        let mut bad = transform();
        bad.steps[0].column = "api_key".into();
        bad.definition_digest.clear();
        let error = bad.prepare().unwrap_err();
        assert!(error.message().contains("credentials"));
    }

    #[test]
    fn quality_rule_names_the_failure() {
        let rows = vec![HashMap::from([("name".into(), String::new())])];
        let error = evaluate_quality(&rows, "required:name").unwrap_err();
        assert_eq!(error.message(), "quality rule required:name");
    }

    #[test]
    fn full_rebuild_quarantine_keeps_the_live_receipt() {
        let mut transform = transform();
        transform.quality_rule = "min_rows:1".into();
        transform.definition_digest.clear();
        let transform = transform.prepare().unwrap();
        let pin = (9, "live-run".into(), "live-out".into());
        let (run, rows) = compute_run(&transform, Some(&pin), &[], false, 40, "new-run".into());
        assert!(run.quarantined);
        assert!(rows.is_empty());
        assert_eq!(run.lineage_parent, "live-run");
        assert_eq!(run.output_digest, "live-out");
        assert!(!run.incremental);
    }

    #[test]
    fn incremental_output_digest_matches_full_recompute() {
        let first = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("keep".into(), "yes".into()),
        ])];
        let second = vec![HashMap::from([
            ("id".into(), "2".into()),
            ("keep".into(), "yes".into()),
        ])];
        let folded = fold_output_digest(&rows_digest(&first), &second).expect("current encoding");
        let mut combined = first.clone();
        combined.extend(second.clone());
        assert_eq!(folded, rows_digest(&combined));
        assert!(folded.starts_with(OUTPUT_DIGEST_PREFIX));
        assert!(fold_output_digest(&format!("sha256:{}", "ab".repeat(32)), &second).is_none());
        let swapped = vec![second[0].clone(), first[0].clone()];
        assert_eq!(rows_digest(&combined), rows_digest(&swapped));
    }

    #[test]
    fn output_digest_counts_duplicate_rows() {
        let row = HashMap::from([("id".into(), "1".into())]);
        let one = [row.clone()];
        let two = [row.clone(), row];
        assert_ne!(rows_digest(&one), rows_digest(&two));
    }

    #[test]
    fn checkpoint_after_id_is_exclusive() {
        let pin = (7, "run".into(), "out".into());
        assert_eq!(checkpoint_after_id(true, Some(&pin)), 7);
        assert_eq!(checkpoint_after_id(false, Some(&pin)), 0);
        assert_eq!(checkpoint_after_id(true, None), 0);
    }

    #[test]
    fn derived_markings_union_rows_and_fail_closed_on_unknown() {
        let rows = vec![
            HashMap::from([
                ("id".into(), "1".into()),
                (
                    crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "internal".into(),
                ),
            ]),
            HashMap::from([
                ("id".into(), "2".into()),
                (
                    crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "confidential".into(),
                ),
            ]),
        ];
        let (inputs, output) = derive_transform_markings(None, [None], None, &rows).unwrap();
        assert_eq!(inputs, "internal,confidential");
        assert_eq!(output, "confidential");
        let (inputs, output) =
            derive_transform_markings(None, [Some("public")], Some("internal"), &[]).unwrap();
        assert_eq!(inputs, "public");
        assert_eq!(output, "internal");
        let (inputs, output) = derive_transform_markings(
            None,
            [Some("public"), Some("confidential")],
            None,
            &[] as &[HashMap<String, String>],
        )
        .unwrap();
        assert!(inputs.contains("confidential"));
        assert_eq!(output, "confidential");
        assert!(
            derive_transform_markings(
                None,
                [None],
                None,
                &[HashMap::from([(
                    crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "secret-sauce".into()
                )])]
            )
            .unwrap_err()
            .contains("unknown classification marking")
        );
        assert_eq!(
            fold_live_output_marking(None, "", Some("confidential")).unwrap(),
            "confidential"
        );
        assert_eq!(
            fold_live_output_marking(None, "public", Some("confidential")).unwrap(),
            "confidential"
        );
        assert_eq!(
            fold_live_output_marking(None, "confidential", Some("public")).unwrap(),
            "confidential"
        );
        assert!(require_bound_output_for_markings("", "confidential").is_err());
        assert!(require_bound_output_for_markings("out-obj", "confidential").is_ok());
        assert!(require_bound_output_for_markings("", "").is_ok());
    }

    #[test]
    fn isolated_write_lineage_rejects_a_newer_live_receipt() {
        let older = sample_run("a", 10);
        let newer = sample_run("b", 20);
        let mut rejected = older.clone();
        assert_eq!(
            bind_isolated_write_lineage(&mut rejected, Some(&newer)).unwrap_err(),
            STALE_TRANSFORM_ADMISSION
        );
        let mut child = newer.clone();
        bind_isolated_write_lineage(&mut child, Some(&older)).unwrap();
        assert_eq!(child.lineage_parent, "a");
        let mut first = older.clone();
        bind_isolated_write_lineage(&mut first, None).unwrap();
        assert!(first.lineage_parent.is_empty());
    }

    fn sample_run(id: &str, created_at_ms: i64) -> TransformRun {
        TransformRun {
            run_id: id.into(),
            namespace: "ops".into(),
            transform_id: "t".into(),
            definition_digest: String::new(),
            input_digest: String::new(),
            output_digest: String::new(),
            last_input_row_id: 0,
            incremental: false,
            quarantined: false,
            quality_rule: String::new(),
            rows_in: 0,
            rows_out: 0,
            lineage_parent: String::new(),
            created_at_ms,
            markings_in: String::new(),
            markings_out: String::new(),
            profile: String::new(),
            engine: String::new(),
            runtime_image: String::new(),
            dispatch_status: String::new(),
            trigger_cause: String::new(),
            trigger_ref: String::new(),
            input_partitions: Vec::new(),
            output_partitions: Vec::new(),
        }
    }

    fn analytical_from_bindings(inputs: Vec<TransformInput>) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: String::new(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec {
                inputs,
                sql: String::new(),
                memory_limit_bytes: 0,
                time_limit_ms: 0,
            }),
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
    }

    #[test]
    fn analytical_aliases_are_unique_case_insensitively() {
        let mut transform = analytical_from_bindings(vec![
            TransformInput {
                alias: "Orders".into(),
                dataset_id: "a".into(),
            },
            TransformInput {
                alias: "orders".into(),
                dataset_id: "b".into(),
            },
        ]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM \"Orders\"".into();
        let error = transform.prepare().unwrap_err();
        assert!(error.message().contains("unique"), "{}", error.message());
    }

    #[test]
    fn analytical_prepare_fills_input_dataset_id_from_first_binding() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "customers".into(),
            dataset_id: "cust".into(),
        }]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM customers".into();
        let prepared = transform.prepare().unwrap();
        assert_eq!(prepared.input_dataset_id, "cust");
        assert_eq!(
            prepared.input_bindings(),
            vec![("customers".into(), "cust".into())]
        );
    }

    #[test]
    fn analytical_steps_compile_against_first_input_alias() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "customers".into(),
            dataset_id: "cust".into(),
        }]);
        transform.steps = vec![TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }];
        let prepared = transform.prepare().unwrap();
        assert_eq!(
            prepared.analytical.as_ref().unwrap().sql,
            "SELECT * FROM (SELECT * FROM \"customers\") WHERE \"keep\" = 'yes'"
        );
    }

    #[test]
    fn analytical_steps_rejected_with_multiple_inputs() {
        let mut transform = analytical_from_bindings(vec![
            TransformInput {
                alias: "customers".into(),
                dataset_id: "cust".into(),
            },
            TransformInput {
                alias: "orders".into(),
                dataset_id: "ord".into(),
            },
        ]);
        transform.steps = vec![TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }];
        let error = transform.prepare().unwrap_err();
        assert!(
            error.message().contains("explicit sql"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn compiled_analytical_steps_keep_incremental() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "customers".into(),
            dataset_id: "cust".into(),
        }]);
        transform.steps = vec![TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }];
        let prepared = transform.prepare().unwrap();
        assert!(prepared.allows_incremental());
    }

    #[test]
    fn explicit_order_by_sql_rebuilds() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "input".into(),
            dataset_id: "in".into(),
        }]);
        transform.analytical.as_mut().unwrap().sql =
            "SELECT * FROM input ORDER BY id LIMIT 1".into();
        let prepared = transform.prepare().unwrap();
        assert!(!prepared.allows_incremental());
    }

    #[test]
    fn secondary_analytical_input_cannot_be_the_output() {
        let mut transform = analytical_from_bindings(vec![
            TransformInput {
                alias: "source".into(),
                dataset_id: "in".into(),
            },
            TransformInput {
                alias: "prior".into(),
                dataset_id: "out".into(),
            },
        ]);
        transform.analytical.as_mut().unwrap().sql =
            "SELECT * FROM source UNION ALL SELECT * FROM prior".into();
        let error = transform.prepare().unwrap_err();
        assert!(
            error.message().contains("distinct dataset"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn analytical_limits_clamp_to_host_maxima() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "input".into(),
            dataset_id: "in".into(),
        }]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM input".into();
        transform.analytical.as_mut().unwrap().memory_limit_bytes = u64::MAX;
        transform.analytical.as_mut().unwrap().time_limit_ms = u64::MAX;
        let prepared = transform.prepare().unwrap();
        let spec = prepared.analytical.as_ref().unwrap();
        assert_eq!(
            spec.memory_limit_bytes,
            transform_engine::DEFAULT_MEMORY_LIMIT_BYTES
        );
        assert_eq!(spec.time_limit_ms, transform_engine::DEFAULT_TIME_LIMIT_MS);
    }

    #[test]
    fn analytical_input_digest_includes_alias_identity() {
        let mut transform = analytical_from_bindings(vec![
            TransformInput {
                alias: "left".into(),
                dataset_id: "a".into(),
            },
            TransformInput {
                alias: "right".into(),
                dataset_id: "b".into(),
            },
        ]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM left".into();
        let transform = transform.prepare().unwrap();
        let left = vec![(1, HashMap::from([("id".into(), "1".into())]))];
        let right = vec![(1, HashMap::from([("id".into(), "2".into())]))];
        let (first, _) = compute_run_tables(
            &transform,
            None,
            &[
                TransformInputRows {
                    alias: "left",
                    records: &left,
                    columns: &[],
                },
                TransformInputRows {
                    alias: "right",
                    records: &right,
                    columns: &[],
                },
            ],
            false,
            10,
            "r1".into(),
        );
        let (swapped, _) = compute_run_tables(
            &transform,
            None,
            &[
                TransformInputRows {
                    alias: "left",
                    records: &right,
                    columns: &[],
                },
                TransformInputRows {
                    alias: "right",
                    records: &left,
                    columns: &[],
                },
            ],
            false,
            10,
            "r2".into(),
        );
        assert_ne!(first.input_digest, swapped.input_digest);
    }

    #[test]
    fn analytical_input_copy_respects_memory_budget() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "input".into(),
            dataset_id: "in".into(),
        }]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM input".into();
        transform.analytical.as_mut().unwrap().memory_limit_bytes = 80;
        let transform = transform.prepare().unwrap();
        let records = vec![(1, HashMap::from([("blob".into(), "x".repeat(200))]))];
        let (run, rows) = compute_run_tables(
            &transform,
            None,
            &[TransformInputRows {
                alias: "input",
                records: &records,
                columns: &[],
            }],
            false,
            10,
            "r1".into(),
        );
        assert!(run.quarantined);
        assert_eq!(run.quality_rule, BUDGET_MEMORY);
        assert!(rows.is_empty());
    }

    #[test]
    fn input_partition_receipts_use_each_input_keys() {
        let left_keys = vec!["region".into()];
        let right_keys = vec!["customer_id".into()];
        let left = vec![HashMap::from([
            ("id".into(), "c1".into()),
            ("region".into(), "east".into()),
        ])];
        let right = vec![HashMap::from([
            ("id".into(), "o1".into()),
            ("customer_id".into(), "c1".into()),
        ])];
        let receipts = input_partition_receipts([
            ("customers".into(), left_keys, left),
            ("orders".into(), right_keys, right),
            (
                "plain".into(),
                Vec::new(),
                vec![HashMap::from([("id".into(), "x".into())])],
            ),
        ]);
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].partition_key, "east");
        assert_eq!(receipts[0].dataset_id, "customers");
        assert_eq!(receipts[1].partition_key, "c1");
        assert_eq!(receipts[1].dataset_id, "orders");
    }

    #[test]
    fn snapshot_receipts_keep_each_input_partition_separate() {
        let receipts = receipts_from_snapshot_rows([
            TransformRunInputRow {
                alias: "left".into(),
                dataset_id: "customers".into(),
                row_id: 1,
                values: HashMap::from([("region".into(), "east".into())]),
                partition_key: "east".into(),
            },
            TransformRunInputRow {
                alias: "right".into(),
                dataset_id: "orders".into(),
                row_id: 1,
                values: HashMap::from([("region".into(), "east".into())]),
                partition_key: "east".into(),
            },
            TransformRunInputRow {
                alias: "left".into(),
                dataset_id: "customers".into(),
                row_id: 2,
                values: HashMap::from([("region".into(), String::new())]),
                partition_key: String::new(),
            },
        ]);
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0].partition_key, "");
        assert_eq!(receipts[1].partition_key, "east");
        assert_eq!(receipts[2].partition_key, "east");
        assert_eq!(receipts[0].rows, 1);
        assert_eq!(receipts[1].rows, 1);
        assert_eq!(receipts[2].rows, 1);
    }

    #[test]
    fn trim_page_counts_partition_identity_bytes() {
        let row = |key: &str| TransformRunInputRow {
            alias: "in".into(),
            dataset_id: "ds".into(),
            row_id: 1,
            values: HashMap::from([("region".into(), key.into())]),
            partition_key: key.into(),
        };
        let big = "e".repeat(200);
        let first = row(&big);
        let cap = row_stream_bytes(&first) as i64 + 10;
        let page = trim_page_to_bytes(vec![first, row(&big)], cap);
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn rewritten_partitions_keeps_untouched_keys_off_the_list() {
        let keys = vec!["region".into()];
        let live = vec![
            HashMap::from([("id".into(), "1".into()), ("region".into(), "east".into())]),
            HashMap::from([("id".into(), "2".into()), ("region".into(), "west".into())]),
        ];
        let added = vec![HashMap::from([
            ("id".into(), "3".into()),
            ("region".into(), "east".into()),
        ])];
        let rewritten = rewritten_partitions(&keys, &live, &added);
        assert_eq!(rewritten.len(), 1);
        assert_eq!(rewritten[0].0, "east");
        assert_eq!(rewritten[0].1.len(), 2);
        assert!(dataset_digest(&keys, &live).starts_with(PARTITIONED_DIGEST_PREFIX));
    }

    #[test]
    fn partitioned_digest_does_not_fold_as_sum_v1() {
        let mut partitions = BTreeMap::new();
        partitions.insert(
            "east".into(),
            rows_digest(&[HashMap::from([("id".into(), "1".into())])]),
        );
        let digest = partitioned_dataset_digest(&partitions);
        assert!(digest.starts_with(PARTITIONED_DIGEST_PREFIX));
        assert!(parse_output_digest(&digest).is_none());
        assert!(parse_partitioned_digest(&digest).is_some());
        assert!(fold_output_digest(&digest, &[]).is_none());
    }

    #[test]
    fn prepare_partition_commit_keeps_untouched_rows() {
        let keys = vec!["region".into()];
        let live = vec![
            HashMap::from([("id".into(), "1".into()), ("region".into(), "east".into())]),
            HashMap::from([("id".into(), "2".into()), ("region".into(), "west".into())]),
        ];
        let west = vec![HashMap::from([
            ("id".into(), "2".into()),
            ("region".into(), "west".into()),
            ("keep".into(), "yes".into()),
        ])];
        let mut merged_groups = group_rows_by_partition(&keys, &live);
        merged_groups.insert("west".into(), west.clone());
        let envelope = partitioned_dataset_digest(
            &merged_groups
                .iter()
                .map(|(key, rows)| (key.clone(), rows_digest(rows)))
                .collect(),
        );
        let prepared = prepare_partition_commit(
            &keys,
            &live,
            &[TransformPartitionWrite {
                partition_key: "west".into(),
                rows: west,
            }],
            &envelope,
        )
        .unwrap();
        assert_eq!(prepared.written.len(), 1);
        assert_eq!(prepared.written[0].partition_key, "west");
        assert_eq!(prepared.merged_rows.len(), 2);
        assert!(
            prepare_partition_commit(
                &keys,
                &live,
                &[TransformPartitionWrite {
                    partition_key: "west".into(),
                    rows: vec![HashMap::from([
                        ("id".into(), "2".into()),
                        ("region".into(), "west".into())
                    ])],
                }],
                "sha256-sum-v1:deadbeef",
            )
            .is_err()
        );
    }

    #[test]
    fn prepare_partition_commit_drops_empty_partitions_from_envelope() {
        let keys = vec!["region".into()];
        let live = vec![
            HashMap::from([("id".into(), "1".into()), ("region".into(), "east".into())]),
            HashMap::from([("id".into(), "2".into()), ("region".into(), "west".into())]),
        ];
        let remaining = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("region".into(), "east".into()),
        ])];
        let envelope = dataset_digest(&keys, &remaining);
        let prepared = prepare_partition_commit(
            &keys,
            &live,
            &[TransformPartitionWrite {
                partition_key: "west".into(),
                rows: Vec::new(),
            }],
            &envelope,
        )
        .unwrap();
        assert_eq!(prepared.written[0].rows, 0);
        assert_eq!(prepared.envelope_digest, envelope);
        assert_eq!(prepared.merged_rows, remaining);
    }

    #[test]
    fn rewrite_partition_identities_replaces_matching_keys() {
        let mut receipts = vec![
            TransformPartition {
                partition_key: "east".into(),
                digest: "d1".into(),
                rows: 1,
                dataset_id: "in".into(),
            },
            TransformPartition {
                partition_key: "west".into(),
                digest: "d2".into(),
                rows: 1,
                dataset_id: "out".into(),
            },
        ];
        let replacements = HashMap::from([("east".into(), "[redacted]".into())]);
        assert!(rewrite_partition_identities(&mut receipts, &replacements));
        assert_eq!(receipts[0].partition_key, "[redacted]");
        assert_eq!(receipts[1].partition_key, "west");
        receipts[0].partition_key = "east".into();
        assert!(redact_run_partition_receipts("in", &mut receipts, &mut []));
        assert_eq!(receipts[0].partition_key, "[redacted]");
        assert_eq!(receipts[0].digest, "[redacted]");
        assert_eq!(receipts[1].partition_key, "west");
        assert_eq!(receipts[1].digest, "d2");
        let mut empty = [TransformPartition {
            partition_key: String::new(),
            digest: "d3".into(),
            rows: 1,
            dataset_id: "in".into(),
        }];
        assert!(redact_run_partition_receipts("in", &mut empty, &mut []));
        assert!(empty[0].partition_key.is_empty());
        assert_eq!(empty[0].digest, "[redacted]");
    }

    #[test]
    fn prepare_partition_commit_rejects_duplicate_partition_identity() {
        let keys = vec!["region".into()];
        let live = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("region".into(), "east".into()),
        ])];
        let first = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("region".into(), "east".into()),
            ("keep".into(), "first".into()),
        ])];
        let second = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("region".into(), "east".into()),
            ("keep".into(), "second".into()),
        ])];
        let envelope = dataset_digest(&keys, &second);
        let error = prepare_partition_commit(
            &keys,
            &live,
            &[
                TransformPartitionWrite {
                    partition_key: "east".into(),
                    rows: first,
                },
                TransformPartitionWrite {
                    partition_key: "east".into(),
                    rows: second,
                },
            ],
            &envelope,
        )
        .unwrap_err();
        assert!(error.contains("duplicate partition write"));
    }

    #[test]
    fn composite_partition_value_does_not_collide_on_embedded_separators() {
        let keys = vec!["left".into(), "right".into()];
        let first = HashMap::from([
            ("left".into(), "a\u{1f}b".into()),
            ("right".into(), "c".into()),
        ]);
        let second = HashMap::from([
            ("left".into(), "a".into()),
            ("right".into(), "b\u{1f}c".into()),
        ]);
        assert_ne!(
            partition_value(&keys, &first),
            partition_value(&keys, &second)
        );
        assert_eq!(
            partition_value(
                &["region".into()],
                &HashMap::from([("region".into(), "east".into())])
            ),
            "east"
        );
    }

    #[test]
    fn preview_id_is_not_a_run_id_prefix_collision() {
        let id = new_preview_id();
        assert!(is_preview_id(&id));
        assert!(!is_preview_id("run-1"));
        assert!(id.starts_with(PREVIEW_ID_PREFIX));
    }

    #[test]
    fn preview_row_cap_defaults_and_rejects_plane_maximum() {
        assert_eq!(resolve_preview_row_cap(0).unwrap(), DEFAULT_PREVIEW_ROW_CAP);
        assert_eq!(resolve_preview_row_cap(512).unwrap(), 512);
        assert_eq!(resolve_preview_row_cap(1024).unwrap(), 1024);
        assert_eq!(resolve_preview_row_cap(1025).unwrap_err(), PREVIEW_ROW_CAP);
    }

    #[test]
    fn preview_column_allowlist_drops_ungranted_keys() {
        let mut records = vec![(
            1,
            HashMap::from([
                ("keep".into(), "yes".into()),
                ("secret".into(), "no".into()),
            ]),
        )];
        apply_preview_column_allowlist(&mut records, Some(&["keep".into()]));
        assert_eq!(records[0].1, HashMap::from([("keep".into(), "yes".into())]));
    }
}

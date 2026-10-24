use crate::db::postgres::PostgresDb;
use crate::sekai::dataset::{ColumnDef, RowFilter, parse_columns};
use crate::sekai::dataset_health::{
    ALERT_FIRING, ALERT_KIND_JOB, ALERT_KIND_SCHEDULE, ALERT_REASON_FAILED, ALERT_REASON_LATE,
    ALERT_REASON_RETRIED, ALERT_RESOLVED, DatasetAlert, DatasetHealthCheck, DatasetHealthResult,
    DatasetHealthState, evaluate_health_check, validate_health_check,
};
use crate::sekai::dataset_version::{self, DatasetVersion};
use postgres::Transaction;
use std::collections::HashMap;

impl PostgresDb {
    pub fn put_dataset_health_check(&self, check: &DatasetHealthCheck) -> Result<(), String> {
        validate_health_check(check)?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let exists: Option<i32> = tx
            .query_opt(
                "SELECT 1 FROM sekai_datasets WHERE id = $1",
                &[&check.dataset_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if exists.is_none() {
            return Err(dataset_version::DATASET_NOT_FOUND.into());
        }
        upsert_check_pg(&mut tx, check)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn list_dataset_health_checks(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<DatasetHealthCheck>, String> {
        let mut connection = self.connection()?;
        list_checks_pg(&mut *connection, dataset_id)
    }

    pub fn list_dataset_health_results(
        &self,
        dataset_id: &str,
        version_id: &str,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        self.connection()?
            .query(
                "SELECT dataset_id, version_id, check_id, passed, detail, judged_at_ms, quarantined
                 FROM sekai_dataset_health_results
                 WHERE dataset_id = $1 AND ($2 = '' OR version_id = $2)
                 ORDER BY judged_at_ms, check_id",
                &[&dataset_id, &version_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_result)
            .collect()
    }

    pub fn dataset_health_state(&self, dataset_id: &str) -> Result<DatasetHealthState, String> {
        let mut connection = self.connection()?;
        load_state_pg(&mut *connection, dataset_id)
    }

    pub fn list_dataset_alerts(&self, dataset_id: &str) -> Result<Vec<DatasetAlert>, String> {
        self.connection()?
            .query(
                "SELECT kind, ref_id, dataset_id, tenant, space, reason, state, emitted_at_ms
                 FROM sekai_dataset_alerts WHERE dataset_id = $1 ORDER BY id",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                Ok(DatasetAlert {
                    kind: row.get(0),
                    ref_id: row.get(1),
                    dataset_id: row.get(2),
                    tenant: row.get(3),
                    space: row.get(4),
                    reason: row.get(5),
                    state: row.get(6),
                    emitted_at_ms: row.get(7),
                })
            })
            .collect()
    }

    pub fn run_dataset_health_checks(
        &self,
        dataset_id: &str,
        now_ms: i64,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        crate::db::postgres::lock_dataset_rows(&mut tx, dataset_id)?;
        let results = run_health_checks_pg(&mut tx, dataset_id, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(results)
    }
}

pub fn load_state_pg(
    client: &mut impl postgres::GenericClient,
    dataset_id: &str,
) -> Result<DatasetHealthState, String> {
    Ok(client
        .query_opt(
            "SELECT last_healthy_version_id, quarantined
             FROM sekai_dataset_health_state WHERE dataset_id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            let quarantined: i32 = row.get(1);
            DatasetHealthState {
                last_healthy_version_id: row.get(0),
                quarantined: quarantined != 0,
            }
        })
        .unwrap_or_default())
}

pub fn judge_after_write_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    version: &DatasetVersion,
    now_ms: i64,
) -> Result<Vec<DatasetHealthResult>, String> {
    judge_version_pg(tx, dataset_id, version, now_ms, None)
}

fn list_checks_pg(
    client: &mut impl postgres::GenericClient,
    dataset_id: &str,
) -> Result<Vec<DatasetHealthCheck>, String> {
    client
        .query(
            "SELECT dataset_id, check_id, kind, max_age_ms, min_rows, max_rows, columns,
                    predicate, blocking, every_ms, tenant, space, last_run_ms
             FROM sekai_dataset_health_checks WHERE dataset_id = $1 ORDER BY check_id",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(row_to_check)
        .collect()
}

fn row_to_check(row: postgres::Row) -> Result<DatasetHealthCheck, String> {
    let columns: String = row.get(6);
    let predicate: String = row.get(7);
    let blocking: i32 = row.get(8);
    Ok(DatasetHealthCheck {
        dataset_id: row.get(0),
        check_id: row.get(1),
        kind: row.get(2),
        max_age_ms: row.get(3),
        min_rows: row.get(4),
        max_rows: row.get(5),
        columns: serde_json::from_str(&columns).map_err(|error| error.to_string())?,
        predicate: serde_json::from_str::<Vec<RowFilter>>(&predicate)
            .map_err(|error| error.to_string())?,
        blocking: blocking != 0,
        every_ms: row.get(9),
        tenant: row.get(10),
        space: row.get(11),
        last_run_ms: row.get(12),
    })
}

fn row_to_result(row: postgres::Row) -> Result<DatasetHealthResult, String> {
    let passed: i32 = row.get(3);
    let quarantined: i32 = row.get(6);
    Ok(DatasetHealthResult {
        dataset_id: row.get(0),
        version_id: row.get(1),
        check_id: row.get(2),
        passed: passed != 0,
        detail: row.get(4),
        judged_at_ms: row.get(5),
        quarantined: quarantined != 0,
    })
}

fn upsert_check_pg(tx: &mut Transaction<'_>, check: &DatasetHealthCheck) -> Result<(), String> {
    let columns = serde_json::to_string(&check.columns).map_err(|error| error.to_string())?;
    let predicate = serde_json::to_string(&check.predicate).map_err(|error| error.to_string())?;
    let blocking: i32 = if check.blocking { 1 } else { 0 };
    tx.execute(
        "INSERT INTO sekai_dataset_health_checks
         (dataset_id, check_id, kind, max_age_ms, min_rows, max_rows, columns, predicate,
          blocking, every_ms, tenant, space, last_run_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         ON CONFLICT (dataset_id, check_id) DO UPDATE SET
           kind=EXCLUDED.kind, max_age_ms=EXCLUDED.max_age_ms, min_rows=EXCLUDED.min_rows,
           max_rows=EXCLUDED.max_rows, columns=EXCLUDED.columns, predicate=EXCLUDED.predicate,
           blocking=EXCLUDED.blocking, every_ms=EXCLUDED.every_ms, tenant=EXCLUDED.tenant,
           space=EXCLUDED.space",
        &[
            &check.dataset_id,
            &check.check_id,
            &check.kind,
            &check.max_age_ms,
            &check.min_rows,
            &check.max_rows,
            &columns,
            &predicate,
            &blocking,
            &check.every_ms,
            &check.tenant,
            &check.space,
            &check.last_run_ms,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

/// Apply due scheduled checks. Callers invoke `RunDatasetHealthChecks`
/// on the stored cadence; this crate does not start a background worker.
fn run_health_checks_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    now_ms: i64,
) -> Result<Vec<DatasetHealthResult>, String> {
    let checks = list_checks_pg(tx, dataset_id)?;
    let mut due_ids = Vec::new();
    let mut recover_ids = Vec::new();
    for check in &checks {
        if check.every_ms <= 0 {
            due_ids.push(check.check_id.clone());
            continue;
        }
        let due =
            check.last_run_ms == 0 || check.last_run_ms.saturating_add(check.every_ms) <= now_ms;
        let late =
            check.last_run_ms > 0 && check.last_run_ms.saturating_add(check.every_ms) < now_ms;
        if late {
            emit_alert_pg(
                tx,
                ALERT_KIND_SCHEDULE,
                &format!("{}/{}", check.dataset_id, check.check_id),
                dataset_id,
                &check.tenant,
                &check.space,
                ALERT_REASON_LATE,
                ALERT_FIRING,
                now_ms,
            )?;
        }
        if due {
            due_ids.push(check.check_id.clone());
            if !late {
                recover_ids.push(check.clone());
            }
        }
    }
    let version = latest_version_pg(tx, dataset_id)?;
    let Some(version) = version else {
        return Ok(Vec::new());
    };
    let results = if due_ids.is_empty() {
        Vec::new()
    } else {
        judge_version_pg(tx, dataset_id, &version, now_ms, Some(&due_ids))?
    };
    for check_id in &due_ids {
        tx.execute(
            "UPDATE sekai_dataset_health_checks SET last_run_ms = $1
             WHERE dataset_id = $2 AND check_id = $3",
            &[&now_ms, &dataset_id, check_id],
        )
        .map_err(|error| error.to_string())?;
    }
    for check in &recover_ids {
        emit_alert_pg(
            tx,
            ALERT_KIND_SCHEDULE,
            &format!("{}/{}", check.dataset_id, check.check_id),
            dataset_id,
            &check.tenant,
            &check.space,
            ALERT_REASON_LATE,
            ALERT_RESOLVED,
            now_ms,
        )?;
    }
    Ok(results)
}

fn latest_version_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
) -> Result<Option<DatasetVersion>, String> {
    Ok(tx
        .query_opt(
            "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                    restored_from_version_id, row_count, purged
             FROM sekai_dataset_versions
             WHERE dataset_id = $1 AND purged = 0
             ORDER BY seq DESC LIMIT 1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            let purged: i32 = row.get(9);
            DatasetVersion {
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
            }
        }))
}

fn judge_version_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    version: &DatasetVersion,
    now_ms: i64,
    due_check_ids: Option<&[String]>,
) -> Result<Vec<DatasetHealthResult>, String> {
    let all_checks = list_checks_pg(tx, dataset_id)?;
    let mut checks = all_checks.clone();
    if let Some(due) = due_check_ids {
        checks.retain(|check| due.iter().any(|id| id == &check.check_id));
        if checks.is_empty() {
            return Ok(Vec::new());
        }
    }
    if checks.is_empty() {
        persist_state_pg(
            tx,
            dataset_id,
            &DatasetHealthState {
                last_healthy_version_id: version.version_id.clone(),
                quarantined: false,
            },
        )?;
        return Ok(Vec::new());
    }
    let columns = load_columns_pg(tx, dataset_id)?;
    let rows = load_version_rows_pg(tx, dataset_id, &version.version_id)?;
    let prior_state = load_state_pg(tx, dataset_id)?;
    let mut results = Vec::new();
    let mut blocking_failed = false;
    for check in &checks {
        let (passed, detail) =
            evaluate_health_check(check, &rows, &columns, version.created_at_ms, now_ms);
        record_check_metric(check, passed);
        if check.blocking && !passed {
            blocking_failed = true;
        }
        let previous = previous_result_pg(tx, dataset_id, &check.check_id, &version.version_id)?;
        let ref_id = format!("{}/{}", check.dataset_id, check.check_id);
        if !passed {
            emit_alert_pg(
                tx,
                ALERT_KIND_JOB,
                &ref_id,
                dataset_id,
                &check.tenant,
                &check.space,
                ALERT_REASON_FAILED,
                ALERT_FIRING,
                now_ms,
            )?;
            if previous.as_ref().is_some_and(|result| !result.passed) {
                emit_alert_pg(
                    tx,
                    ALERT_KIND_JOB,
                    &ref_id,
                    dataset_id,
                    &check.tenant,
                    &check.space,
                    ALERT_REASON_RETRIED,
                    ALERT_FIRING,
                    now_ms,
                )?;
            }
        } else {
            emit_alert_pg(
                tx,
                ALERT_KIND_JOB,
                &ref_id,
                dataset_id,
                &check.tenant,
                &check.space,
                ALERT_REASON_FAILED,
                ALERT_RESOLVED,
                now_ms,
            )?;
            emit_alert_pg(
                tx,
                ALERT_KIND_JOB,
                &ref_id,
                dataset_id,
                &check.tenant,
                &check.space,
                ALERT_REASON_RETRIED,
                ALERT_RESOLVED,
                now_ms,
            )?;
        }
        results.push(DatasetHealthResult {
            dataset_id: dataset_id.into(),
            version_id: version.version_id.clone(),
            check_id: check.check_id.clone(),
            passed,
            detail,
            judged_at_ms: now_ms,
            quarantined: false,
        });
    }
    let mut state = prior_state;
    if blocking_failed {
        if state.last_healthy_version_id.is_empty()
            || state.last_healthy_version_id == version.version_id
        {
            state.last_healthy_version_id =
                last_healthy_fallback_pg(tx, dataset_id, version.seq)?.unwrap_or_default();
        }
        state.quarantined = true;
    } else if !crate::sekai::dataset_health::skipped_blocking_checks(
        due_check_ids,
        &checks,
        &all_checks,
    ) {
        state.last_healthy_version_id = version.version_id.clone();
        state.quarantined = false;
    }
    for result in &mut results {
        result.quarantined = state.quarantined;
        persist_result_pg(tx, result)?;
    }
    persist_state_pg(tx, dataset_id, &state)?;
    Ok(results)
}

fn load_columns_pg(tx: &mut Transaction<'_>, dataset_id: &str) -> Result<Vec<ColumnDef>, String> {
    let stored: String = tx
        .query_one(
            "SELECT columns FROM sekai_datasets WHERE id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    parse_columns(&stored)
}

fn load_version_rows_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    version_id: &str,
) -> Result<Vec<HashMap<String, String>>, String> {
    tx.query(
        "SELECT data FROM sekai_dataset_version_rows
         WHERE dataset_id = $1 AND version_id = $2 ORDER BY row_id",
        &[&dataset_id, &version_id],
    )
    .map_err(|error| error.to_string())?
    .into_iter()
    .map(|row| {
        let data: String = row.get(0);
        serde_json::from_str(&data).map_err(|error| error.to_string())
    })
    .collect()
}

fn previous_result_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    check_id: &str,
    version_id: &str,
) -> Result<Option<DatasetHealthResult>, String> {
    tx.query_opt(
        "SELECT dataset_id, version_id, check_id, passed, detail, judged_at_ms, quarantined
         FROM sekai_dataset_health_results
         WHERE dataset_id = $1 AND check_id = $2 AND version_id = $3
         ORDER BY judged_at_ms DESC LIMIT 1",
        &[&dataset_id, &check_id, &version_id],
    )
    .map_err(|error| error.to_string())?
    .map(row_to_result)
    .transpose()
}

fn last_healthy_fallback_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    seq: i64,
) -> Result<Option<String>, String> {
    Ok(tx
        .query_opt(
            "SELECT v.version_id FROM sekai_dataset_versions v
             WHERE v.dataset_id = $1 AND v.seq < $2 AND v.purged = 0
               AND NOT EXISTS (
                 SELECT 1 FROM sekai_dataset_health_results r
                 INNER JOIN sekai_dataset_health_checks c
                   ON c.dataset_id = r.dataset_id AND c.check_id = r.check_id
                 WHERE r.dataset_id = v.dataset_id
                   AND r.version_id = v.version_id
                   AND c.blocking != 0 AND r.passed = 0
               )
             ORDER BY v.seq DESC LIMIT 1",
            &[&dataset_id, &seq],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0)))
}

fn persist_result_pg(tx: &mut Transaction<'_>, result: &DatasetHealthResult) -> Result<(), String> {
    let passed: i32 = if result.passed { 1 } else { 0 };
    let quarantined: i32 = if result.quarantined { 1 } else { 0 };
    tx.execute(
        "INSERT INTO sekai_dataset_health_results
         (dataset_id, version_id, check_id, passed, detail, judged_at_ms, quarantined)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (dataset_id, version_id, check_id) DO UPDATE SET
           passed=EXCLUDED.passed, detail=EXCLUDED.detail, judged_at_ms=EXCLUDED.judged_at_ms,
           quarantined=EXCLUDED.quarantined",
        &[
            &result.dataset_id,
            &result.version_id,
            &result.check_id,
            &passed,
            &result.detail,
            &result.judged_at_ms,
            &quarantined,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn persist_state_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    state: &DatasetHealthState,
) -> Result<(), String> {
    let quarantined: i32 = if state.quarantined { 1 } else { 0 };
    tx.execute(
        "INSERT INTO sekai_dataset_health_state
         (dataset_id, last_healthy_version_id, quarantined)
         VALUES ($1,$2,$3)
         ON CONFLICT (dataset_id) DO UPDATE SET
           last_healthy_version_id=EXCLUDED.last_healthy_version_id,
           quarantined=EXCLUDED.quarantined",
        &[&dataset_id, &state.last_healthy_version_id, &quarantined],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn emit_alert_pg(
    tx: &mut Transaction<'_>,
    kind: &str,
    ref_id: &str,
    dataset_id: &str,
    tenant: &str,
    space: &str,
    reason: &str,
    state: &str,
    now_ms: i64,
) -> Result<(), String> {
    let alert_key = format!("{kind}:{ref_id}:{reason}");
    let latest: Option<String> = tx
        .query_opt(
            "SELECT state FROM sekai_dataset_alerts WHERE alert_key = $1 ORDER BY id DESC LIMIT 1",
            &[&alert_key],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    if latest.as_deref() == Some(state) {
        return Ok(());
    }
    if state == ALERT_RESOLVED && latest.as_deref() != Some(ALERT_FIRING) {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO sekai_dataset_alerts
         (alert_key, kind, ref_id, dataset_id, tenant, space, reason, state, emitted_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[
            &alert_key,
            &kind,
            &ref_id,
            &dataset_id,
            &tenant,
            &space,
            &reason,
            &state,
            &now_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    record_job_metric(
        tenant,
        space,
        if state == ALERT_RESOLVED {
            "resolved"
        } else {
            reason
        },
    );
    Ok(())
}

fn record_check_metric(check: &DatasetHealthCheck, passed: bool) {
    let outcome = if passed { "pass" } else { "fail" };
    metrics::counter!(
        "sekai_dataset_health_check_results_total",
        "tenant" => check.tenant.clone(),
        "space" => check.space.clone(),
        "outcome" => outcome
    )
    .increment(1);
}

fn record_job_metric(tenant: &str, space: &str, outcome: &str) {
    metrics::counter!(
        "sekai_dataset_job_outcomes_total",
        "tenant" => tenant.to_string(),
        "space" => space.to_string(),
        "outcome" => outcome.to_string()
    )
    .increment(1);
}

use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::{ColumnDef, RowFilter, row_value_matches};
use crate::sekai::dataset_version::{self, DatasetVersion};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const KIND_FRESHNESS: &str = "freshness";
pub const KIND_ROW_COUNT: &str = "row_count";
pub const KIND_SCHEMA: &str = "schema";
pub const KIND_NOT_NULL: &str = "not_null";
pub const KIND_UNIQUE: &str = "unique";
pub const KIND_PREDICATE: &str = "predicate";

pub const ALERT_KIND_JOB: &str = "job";
pub const ALERT_KIND_SCHEDULE: &str = "schedule";
pub const ALERT_REASON_LATE: &str = "late";
pub const ALERT_REASON_FAILED: &str = "failed";
pub const ALERT_REASON_RETRIED: &str = "retried";
pub const ALERT_FIRING: &str = "firing";
pub const ALERT_RESOLVED: &str = "resolved";

const SQLITE_HEALTH_SCHEMA: &str = "
            CREATE TABLE IF NOT EXISTS sekai_dataset_health_checks (
                dataset_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                max_age_ms INTEGER NOT NULL DEFAULT 0,
                min_rows INTEGER NOT NULL DEFAULT 0,
                max_rows INTEGER NOT NULL DEFAULT 0,
                columns TEXT NOT NULL DEFAULT '[]',
                predicate TEXT NOT NULL DEFAULT '[]',
                blocking INTEGER NOT NULL DEFAULT 0,
                every_ms INTEGER NOT NULL DEFAULT 0,
                tenant TEXT NOT NULL DEFAULT '',
                space TEXT NOT NULL DEFAULT '',
                last_run_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (dataset_id, check_id)
            );
            CREATE TABLE IF NOT EXISTS sekai_dataset_health_results (
                dataset_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                passed INTEGER NOT NULL,
                detail TEXT NOT NULL,
                judged_at_ms INTEGER NOT NULL,
                quarantined INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (dataset_id, version_id, check_id)
            );
            CREATE TABLE IF NOT EXISTS sekai_dataset_health_state (
                dataset_id TEXT PRIMARY KEY,
                last_healthy_version_id TEXT NOT NULL DEFAULT '',
                quarantined INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sekai_dataset_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                ref_id TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                tenant TEXT NOT NULL DEFAULT '',
                space TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL,
                state TEXT NOT NULL,
                emitted_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sekai_dataset_alerts_dataset
                ON sekai_dataset_alerts(dataset_id, emitted_at_ms);
";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetHealthCheck {
    pub dataset_id: String,
    pub check_id: String,
    pub kind: String,
    pub max_age_ms: i64,
    pub min_rows: i32,
    pub max_rows: i32,
    pub columns: Vec<String>,
    pub predicate: Vec<RowFilter>,
    pub blocking: bool,
    pub every_ms: i64,
    pub tenant: String,
    pub space: String,
    pub last_run_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetHealthResult {
    pub dataset_id: String,
    pub version_id: String,
    pub check_id: String,
    pub passed: bool,
    pub detail: String,
    pub judged_at_ms: i64,
    pub quarantined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DatasetHealthState {
    pub last_healthy_version_id: String,
    pub quarantined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetAlert {
    pub kind: String,
    pub ref_id: String,
    pub dataset_id: String,
    pub tenant: String,
    pub space: String,
    pub reason: String,
    pub state: String,
    pub emitted_at_ms: i64,
}

/// A scheduled run that did not evaluate every blocking check must not
/// clear an existing quarantine or promote the latest version as healthy.
pub fn skipped_blocking_checks(
    due_check_ids: Option<&[String]>,
    evaluated: &[DatasetHealthCheck],
    all_checks: &[DatasetHealthCheck],
) -> bool {
    due_check_ids.is_some()
        && all_checks.iter().any(|check| {
            check.blocking && !evaluated.iter().any(|seen| seen.check_id == check.check_id)
        })
}

pub fn validate_health_check(check: &DatasetHealthCheck) -> Result<(), String> {
    if check.dataset_id.trim().is_empty() {
        return Err("dataset_id required".into());
    }
    if check.check_id.trim().is_empty() {
        return Err("check_id required".into());
    }
    if check.every_ms < 0 {
        return Err("every_ms must be >= 0".into());
    }
    match check.kind.as_str() {
        KIND_FRESHNESS => {
            if check.max_age_ms <= 0 {
                return Err("freshness check requires max_age_ms > 0".into());
            }
        }
        KIND_ROW_COUNT => {
            if check.min_rows < 0 || check.max_rows < 0 {
                return Err("row_count bounds must be >= 0".into());
            }
            if check.max_rows > 0 && check.max_rows < check.min_rows {
                return Err("row_count max_rows must be >= min_rows".into());
            }
        }
        KIND_SCHEMA | KIND_NOT_NULL | KIND_UNIQUE => {
            if check.columns.is_empty() {
                return Err(format!("{} check requires columns", check.kind));
            }
        }
        KIND_PREDICATE => {
            if check.predicate.is_empty() {
                return Err("predicate check requires predicate".into());
            }
        }
        other => return Err(format!("unknown health check kind {other}")),
    }
    Ok(())
}

pub fn evaluate_health_check(
    check: &DatasetHealthCheck,
    rows: &[HashMap<String, String>],
    columns: &[ColumnDef],
    version_created_at_ms: i64,
    now_ms: i64,
) -> (bool, String) {
    match check.kind.as_str() {
        KIND_FRESHNESS => {
            let age = now_ms.saturating_sub(version_created_at_ms);
            if age <= check.max_age_ms {
                (true, format!("age_ms={age}"))
            } else {
                (
                    false,
                    format!("age_ms={age} exceeds max_age_ms={}", check.max_age_ms),
                )
            }
        }
        KIND_ROW_COUNT => {
            let count = i32::try_from(rows.len()).unwrap_or(i32::MAX);
            let min_ok = count >= check.min_rows;
            let max_ok = check.max_rows == 0 || count <= check.max_rows;
            if min_ok && max_ok {
                (true, format!("row_count={count}"))
            } else {
                (
                    false,
                    format!(
                        "row_count={count} outside [{}, {}]",
                        check.min_rows,
                        if check.max_rows == 0 {
                            "unbounded".into()
                        } else {
                            check.max_rows.to_string()
                        }
                    ),
                )
            }
        }
        KIND_SCHEMA => {
            let expected: std::collections::BTreeSet<_> = check.columns.iter().cloned().collect();
            let actual: std::collections::BTreeSet<_> =
                columns.iter().map(|column| column.name.clone()).collect();
            if expected == actual {
                (true, "schema matches".into())
            } else {
                (
                    false,
                    format!("schema mismatch expected={expected:?} actual={actual:?}"),
                )
            }
        }
        KIND_NOT_NULL => {
            for (index, row) in rows.iter().enumerate() {
                for column in &check.columns {
                    match row.get(column) {
                        Some(value) if !value.is_empty() => {}
                        _ => {
                            return (false, format!("null or missing {column} at row {index}"));
                        }
                    }
                }
            }
            (true, "no nulls".into())
        }
        KIND_UNIQUE => {
            let mut seen = std::collections::BTreeSet::new();
            for (index, row) in rows.iter().enumerate() {
                let key: Vec<String> = check
                    .columns
                    .iter()
                    .map(|column| row.get(column).cloned().unwrap_or_default())
                    .collect();
                if !seen.insert(key.clone()) {
                    return (
                        false,
                        format!("duplicate {:?} at row {index}", check.columns),
                    );
                }
            }
            (true, "unique".into())
        }
        KIND_PREDICATE => {
            for (index, row) in rows.iter().enumerate() {
                for filter in &check.predicate {
                    let Some(actual) = row.get(&filter.column) else {
                        return (
                            false,
                            format!("predicate missed {} at row {index}", filter.column),
                        );
                    };
                    if !row_value_matches(actual, &filter.op, &filter.value) {
                        return (
                            false,
                            format!(
                                "predicate {} {} {} failed at row {index}",
                                filter.column, filter.op, filter.value
                            ),
                        );
                    }
                }
            }
            (true, "predicate holds".into())
        }
        other => (false, format!("unknown kind {other}")),
    }
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

pub fn migrate_dataset_health(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(SQLITE_HEALTH_SCHEMA)
        .map_err(|error| error.to_string())
}

impl SekaiDb {
    pub fn put_dataset_health_check(&self, check: &DatasetHealthCheck) -> Result<(), String> {
        validate_health_check(check)?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM sekai_datasets WHERE id = ?1",
                params![check.dataset_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if exists.is_none() {
            return Err(dataset_version::DATASET_NOT_FOUND.into());
        }
        upsert_check_tx(&tx, check)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn list_dataset_health_checks(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<DatasetHealthCheck>, String> {
        let conn = self.conn();
        list_checks_conn(&conn, dataset_id)
    }

    pub fn list_dataset_health_results(
        &self,
        dataset_id: &str,
        version_id: &str,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        let conn = self.conn();
        list_results_conn(&conn, dataset_id, version_id)
    }

    pub fn dataset_health_state(&self, dataset_id: &str) -> Result<DatasetHealthState, String> {
        let conn = self.conn();
        load_state_conn(&conn, dataset_id)
    }

    pub fn list_dataset_alerts(&self, dataset_id: &str) -> Result<Vec<DatasetAlert>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT kind, ref_id, dataset_id, tenant, space, reason, state, emitted_at_ms
                 FROM sekai_dataset_alerts WHERE dataset_id = ?1 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let mapped = stmt
            .query_map(params![dataset_id], |row| {
                Ok(DatasetAlert {
                    kind: row.get(0)?,
                    ref_id: row.get(1)?,
                    dataset_id: row.get(2)?,
                    tenant: row.get(3)?,
                    space: row.get(4)?,
                    reason: row.get(5)?,
                    state: row.get(6)?,
                    emitted_at_ms: row.get(7)?,
                })
            })
            .map_err(|error| error.to_string())?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    pub fn run_dataset_health_checks(
        &self,
        dataset_id: &str,
        now_ms: i64,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let results = run_health_checks_tx(&tx, dataset_id, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(results)
    }
}

pub fn load_state_conn(
    conn: &rusqlite::Connection,
    dataset_id: &str,
) -> Result<DatasetHealthState, String> {
    conn.query_row(
        "SELECT last_healthy_version_id, quarantined
         FROM sekai_dataset_health_state WHERE dataset_id = ?1",
        params![dataset_id],
        |row| {
            let quarantined: i64 = row.get(1)?;
            Ok(DatasetHealthState {
                last_healthy_version_id: row.get(0)?,
                quarantined: quarantined != 0,
            })
        },
    )
    .optional()
    .map_err(|error| error.to_string())
    .map(|state| state.unwrap_or_default())
}

fn list_checks_conn(
    conn: &rusqlite::Connection,
    dataset_id: &str,
) -> Result<Vec<DatasetHealthCheck>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT dataset_id, check_id, kind, max_age_ms, min_rows, max_rows, columns,
                    predicate, blocking, every_ms, tenant, space, last_run_ms
             FROM sekai_dataset_health_checks WHERE dataset_id = ?1 ORDER BY check_id",
        )
        .map_err(|error| error.to_string())?;
    let mapped = stmt
        .query_map(params![dataset_id], row_to_check)
        .map_err(|error| error.to_string())?;
    mapped
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn list_results_conn(
    conn: &rusqlite::Connection,
    dataset_id: &str,
    version_id: &str,
) -> Result<Vec<DatasetHealthResult>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT dataset_id, version_id, check_id, passed, detail, judged_at_ms, quarantined
             FROM sekai_dataset_health_results
             WHERE dataset_id = ?1 AND (?2 = '' OR version_id = ?2)
             ORDER BY judged_at_ms, check_id",
        )
        .map_err(|error| error.to_string())?;
    let mapped = stmt
        .query_map(params![dataset_id, version_id], |row| {
            let passed: i64 = row.get(3)?;
            let quarantined: i64 = row.get(6)?;
            Ok(DatasetHealthResult {
                dataset_id: row.get(0)?,
                version_id: row.get(1)?,
                check_id: row.get(2)?,
                passed: passed != 0,
                detail: row.get(4)?,
                judged_at_ms: row.get(5)?,
                quarantined: quarantined != 0,
            })
        })
        .map_err(|error| error.to_string())?;
    mapped
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn row_to_check(row: &rusqlite::Row<'_>) -> rusqlite::Result<DatasetHealthCheck> {
    let columns: String = row.get(6)?;
    let predicate: String = row.get(7)?;
    let blocking: i64 = row.get(8)?;
    Ok(DatasetHealthCheck {
        dataset_id: row.get(0)?,
        check_id: row.get(1)?,
        kind: row.get(2)?,
        max_age_ms: row.get(3)?,
        min_rows: row.get(4)?,
        max_rows: row.get(5)?,
        columns: serde_json::from_str(&columns).unwrap_or_default(),
        predicate: serde_json::from_str(&predicate).unwrap_or_default(),
        blocking: blocking != 0,
        every_ms: row.get(9)?,
        tenant: row.get(10)?,
        space: row.get(11)?,
        last_run_ms: row.get(12)?,
    })
}

fn upsert_check_tx(tx: &Transaction<'_>, check: &DatasetHealthCheck) -> Result<(), String> {
    let columns = serde_json::to_string(&check.columns).map_err(|error| error.to_string())?;
    let predicate = serde_json::to_string(&check.predicate).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_dataset_health_checks
         (dataset_id, check_id, kind, max_age_ms, min_rows, max_rows, columns, predicate,
          blocking, every_ms, tenant, space, last_run_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(dataset_id, check_id) DO UPDATE SET
           kind=excluded.kind, max_age_ms=excluded.max_age_ms, min_rows=excluded.min_rows,
           max_rows=excluded.max_rows, columns=excluded.columns, predicate=excluded.predicate,
           blocking=excluded.blocking, every_ms=excluded.every_ms, tenant=excluded.tenant,
           space=excluded.space",
        params![
            check.dataset_id,
            check.check_id,
            check.kind,
            check.max_age_ms,
            check.min_rows,
            check.max_rows,
            columns,
            predicate,
            if check.blocking { 1 } else { 0 },
            check.every_ms,
            check.tenant,
            check.space,
            check.last_run_ms,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

pub fn judge_after_write_sqlite(
    tx: &Transaction<'_>,
    dataset_id: &str,
    version: &DatasetVersion,
    now_ms: i64,
) -> Result<Vec<DatasetHealthResult>, String> {
    judge_version_tx(tx, dataset_id, version, now_ms, None)
}

/// Apply due scheduled checks for one dataset.
///
/// `every_ms` records the cadence; a caller invokes `RunDatasetHealthChecks`
/// on that interval, the same way `TickGovernedTransforms` drives transform
/// schedules. This crate does not start a background worker.
fn run_health_checks_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    now_ms: i64,
) -> Result<Vec<DatasetHealthResult>, String> {
    let checks = list_checks_conn(tx, dataset_id)?;
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
            emit_alert_tx(
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
    let version = latest_version_tx(tx, dataset_id)?;
    let Some(version) = version else {
        return Ok(Vec::new());
    };
    let results = if due_ids.is_empty() {
        Vec::new()
    } else {
        judge_version_tx(tx, dataset_id, &version, now_ms, Some(&due_ids))?
    };
    for check_id in &due_ids {
        tx.execute(
            "UPDATE sekai_dataset_health_checks SET last_run_ms = ?1
             WHERE dataset_id = ?2 AND check_id = ?3",
            params![now_ms, dataset_id, check_id],
        )
        .map_err(|error| error.to_string())?;
    }
    for check in &recover_ids {
        emit_alert_tx(
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

fn latest_version_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
) -> Result<Option<DatasetVersion>, String> {
    tx.query_row(
        "SELECT dataset_id, version_id, seq, created_at_ms, actor, tenant, reason,
                restored_from_version_id, row_count, purged
         FROM sekai_dataset_versions
         WHERE dataset_id = ?1 AND purged = 0
         ORDER BY seq DESC LIMIT 1",
        params![dataset_id],
        |row| {
            let purged: i64 = row.get(9)?;
            Ok(DatasetVersion {
                dataset_id: row.get(0)?,
                version_id: row.get(1)?,
                seq: row.get(2)?,
                created_at_ms: row.get(3)?,
                actor: row.get(4)?,
                tenant: row.get(5)?,
                reason: row.get(6)?,
                restored_from_version_id: row.get(7)?,
                row_count: row.get(8)?,
                purged: purged != 0,
            })
        },
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn judge_version_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    version: &DatasetVersion,
    now_ms: i64,
    due_check_ids: Option<&[String]>,
) -> Result<Vec<DatasetHealthResult>, String> {
    let all_checks = list_checks_conn(tx, dataset_id)?;
    let mut checks = all_checks.clone();
    if let Some(due) = due_check_ids {
        checks.retain(|check| due.iter().any(|id| id == &check.check_id));
        if checks.is_empty() {
            return Ok(Vec::new());
        }
    }
    if checks.is_empty() {
        persist_state_tx(
            tx,
            dataset_id,
            &DatasetHealthState {
                last_healthy_version_id: version.version_id.clone(),
                quarantined: false,
            },
        )?;
        return Ok(Vec::new());
    }
    let columns = load_columns_tx(tx, dataset_id)?;
    let rows = load_version_rows_tx(tx, dataset_id, &version.version_id)?;
    let prior_state = load_state_conn(tx, dataset_id)?;
    let mut results = Vec::new();
    let mut blocking_failed = false;
    for check in &checks {
        let (passed, detail) =
            evaluate_health_check(check, &rows, &columns, version.created_at_ms, now_ms);
        record_check_metric(check, passed);
        if check.blocking && !passed {
            blocking_failed = true;
        }
        let previous = previous_result_tx(tx, dataset_id, &check.check_id, &version.version_id)?;
        let ref_id = format!("{}/{}", check.dataset_id, check.check_id);
        if !passed {
            emit_alert_tx(
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
                emit_alert_tx(
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
            emit_alert_tx(
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
            emit_alert_tx(
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
    let mut state = prior_state.clone();
    if blocking_failed {
        if state.last_healthy_version_id.is_empty()
            || state.last_healthy_version_id == version.version_id
        {
            state.last_healthy_version_id =
                last_healthy_fallback_tx(tx, dataset_id, version.seq)?.unwrap_or_default();
        }
        state.quarantined = true;
    } else if !skipped_blocking_checks(due_check_ids, &checks, &all_checks) {
        state.last_healthy_version_id = version.version_id.clone();
        state.quarantined = false;
    }
    for result in &mut results {
        result.quarantined = state.quarantined;
        persist_result_tx(tx, result)?;
    }
    persist_state_tx(tx, dataset_id, &state)?;
    Ok(results)
}

fn load_columns_tx(tx: &Transaction<'_>, dataset_id: &str) -> Result<Vec<ColumnDef>, String> {
    let stored: String = tx
        .query_row(
            "SELECT columns FROM sekai_datasets WHERE id = ?1",
            params![dataset_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    crate::sekai::dataset::parse_columns(&stored)
}

fn load_version_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    version_id: &str,
) -> Result<Vec<HashMap<String, String>>, String> {
    let mut stmt = tx
        .prepare(
            "SELECT data FROM sekai_dataset_version_rows
             WHERE dataset_id = ?1 AND version_id = ?2 ORDER BY row_id",
        )
        .map_err(|error| error.to_string())?;
    let mapped = stmt
        .query_map(params![dataset_id, version_id], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|error| error.to_string())?;
    let mut rows = Vec::new();
    for data in mapped {
        let data = data.map_err(|error| error.to_string())?;
        rows.push(serde_json::from_str(&data).map_err(|error| error.to_string())?);
    }
    Ok(rows)
}

fn previous_result_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    check_id: &str,
    version_id: &str,
) -> Result<Option<DatasetHealthResult>, String> {
    tx.query_row(
        "SELECT dataset_id, version_id, check_id, passed, detail, judged_at_ms, quarantined
         FROM sekai_dataset_health_results
         WHERE dataset_id = ?1 AND check_id = ?2 AND version_id = ?3
         ORDER BY judged_at_ms DESC LIMIT 1",
        params![dataset_id, check_id, version_id],
        |row| {
            let passed: i64 = row.get(3)?;
            let quarantined: i64 = row.get(6)?;
            Ok(DatasetHealthResult {
                dataset_id: row.get(0)?,
                version_id: row.get(1)?,
                check_id: row.get(2)?,
                passed: passed != 0,
                detail: row.get(4)?,
                judged_at_ms: row.get(5)?,
                quarantined: quarantined != 0,
            })
        },
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn last_healthy_fallback_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    seq: i64,
) -> Result<Option<String>, String> {
    tx.query_row(
        "SELECT v.version_id FROM sekai_dataset_versions v
         WHERE v.dataset_id = ?1 AND v.seq < ?2 AND v.purged = 0
           AND NOT EXISTS (
             SELECT 1 FROM sekai_dataset_health_results r
             INNER JOIN sekai_dataset_health_checks c
               ON c.dataset_id = r.dataset_id AND c.check_id = r.check_id
             WHERE r.dataset_id = v.dataset_id
               AND r.version_id = v.version_id
               AND c.blocking != 0 AND r.passed = 0
           )
         ORDER BY v.seq DESC LIMIT 1",
        params![dataset_id, seq],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn persist_result_tx(tx: &Transaction<'_>, result: &DatasetHealthResult) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_dataset_health_results
         (dataset_id, version_id, check_id, passed, detail, judged_at_ms, quarantined)
         VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(dataset_id, version_id, check_id) DO UPDATE SET
           passed=excluded.passed, detail=excluded.detail, judged_at_ms=excluded.judged_at_ms,
           quarantined=excluded.quarantined",
        params![
            result.dataset_id,
            result.version_id,
            result.check_id,
            if result.passed { 1 } else { 0 },
            result.detail,
            result.judged_at_ms,
            if result.quarantined { 1 } else { 0 },
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn persist_state_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    state: &DatasetHealthState,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_dataset_health_state
         (dataset_id, last_healthy_version_id, quarantined)
         VALUES (?1,?2,?3)
         ON CONFLICT(dataset_id) DO UPDATE SET
           last_healthy_version_id=excluded.last_healthy_version_id,
           quarantined=excluded.quarantined",
        params![
            dataset_id,
            state.last_healthy_version_id,
            if state.quarantined { 1 } else { 0 },
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn emit_alert_tx(
    tx: &Transaction<'_>,
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
        .query_row(
            "SELECT state FROM sekai_dataset_alerts WHERE alert_key = ?1 ORDER BY id DESC LIMIT 1",
            params![alert_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if latest.as_deref() == Some(state) {
        return Ok(());
    }
    if state == ALERT_RESOLVED && latest.as_deref() != Some(ALERT_FIRING) {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO sekai_dataset_alerts
         (alert_key, kind, ref_id, dataset_id, tenant, space, reason, state, emitted_at_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            alert_key, kind, ref_id, dataset_id, tenant, space, reason, state, now_ms
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::dataset::{ColumnDef, Dataset};

    fn db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn dataset(id: &str, columns: &[&str]) -> Dataset {
        Dataset {
            id: id.into(),
            name: id.into(),
            columns: columns
                .iter()
                .map(|name| ColumnDef {
                    name: (*name).into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                })
                .collect(),
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }
    }

    fn check(id: &str, dataset_id: &str, kind: &str) -> DatasetHealthCheck {
        DatasetHealthCheck {
            dataset_id: dataset_id.into(),
            check_id: id.into(),
            kind: kind.into(),
            max_age_ms: 0,
            min_rows: 0,
            max_rows: 0,
            columns: Vec::new(),
            predicate: Vec::new(),
            blocking: false,
            every_ms: 0,
            tenant: "acme".into(),
            space: "ops".into(),
            last_run_ms: 0,
        }
    }

    #[test]
    fn freshness_row_count_and_schema_pass_and_fail() {
        let rows = vec![HashMap::from([
            ("kind".into(), "build".into()),
            ("n".into(), "1".into()),
        ])];
        let columns = vec![
            ColumnDef {
                name: "kind".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
            ColumnDef {
                name: "n".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
        ];
        let mut freshness = check("fresh", "ds", KIND_FRESHNESS);
        freshness.max_age_ms = 1_000;
        assert!(evaluate_health_check(&freshness, &rows, &columns, 100, 200).0);
        assert!(!evaluate_health_check(&freshness, &rows, &columns, 100, 2_000).0);

        let mut counts = check("count", "ds", KIND_ROW_COUNT);
        counts.min_rows = 1;
        counts.max_rows = 1;
        assert!(evaluate_health_check(&counts, &rows, &columns, 0, 0).0);
        counts.max_rows = 0;
        counts.min_rows = 2;
        assert!(!evaluate_health_check(&counts, &rows, &columns, 0, 0).0);

        let mut schema = check("schema", "ds", KIND_SCHEMA);
        schema.columns = vec!["kind".into(), "n".into()];
        assert!(evaluate_health_check(&schema, &rows, &columns, 0, 0).0);
        schema.columns = vec!["kind".into()];
        assert!(!evaluate_health_check(&schema, &rows, &columns, 0, 0).0);
    }

    #[test]
    fn blocking_failure_keeps_readers_on_previous_version() {
        let db = db();
        db.create_dataset(&dataset("ds", &["kind"])).unwrap();
        let mut blocking = check("rows", "ds", KIND_ROW_COUNT);
        blocking.min_rows = 1;
        blocking.max_rows = 1;
        blocking.blocking = true;
        db.put_dataset_health_check(&blocking).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v1".into())])])
            .unwrap();
        let healthy = db
            .query_rows("ds", &crate::sekai::dataset::RowQuery::default())
            .unwrap();
        assert_eq!(healthy.len(), 1);
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v2".into())])])
            .unwrap();
        let state = db.dataset_health_state("ds").unwrap();
        assert!(state.quarantined);
        let live = db
            .query_rows("ds", &crate::sekai::dataset::RowQuery::default())
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0]["kind"], "v1");
        let versions = db.list_dataset_versions("ds").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(state.last_healthy_version_id, versions[0].version_id);
    }

    #[test]
    fn scheduled_check_does_not_clear_blocking_quarantine() {
        let db = db();
        db.create_dataset(&dataset("ds", &["kind"])).unwrap();
        let mut blocking = check("rows", "ds", KIND_ROW_COUNT);
        blocking.min_rows = 1;
        blocking.max_rows = 1;
        blocking.blocking = true;
        blocking.every_ms = 1_000_000;
        db.put_dataset_health_check(&blocking).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v1".into())])])
            .unwrap();
        db.run_dataset_health_checks("ds", 1_000).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v2".into())])])
            .unwrap();
        assert!(db.dataset_health_state("ds").unwrap().quarantined);
        let mut scheduled = check("fresh", "ds", KIND_FRESHNESS);
        scheduled.max_age_ms = 60_000;
        scheduled.every_ms = 1_000;
        db.put_dataset_health_check(&scheduled).unwrap();
        db.run_dataset_health_checks("ds", 5_000).unwrap();
        let state = db.dataset_health_state("ds").unwrap();
        assert!(
            state.quarantined,
            "scheduled freshness must not lift a blocking quarantine"
        );
        let live = db
            .query_rows("ds", &crate::sekai::dataset::RowQuery::default())
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0]["kind"], "v1");
    }

    #[test]
    fn late_schedule_emits_one_alert_and_recovery_resolves() {
        crate::obs::metrics::handle();
        let db = db();
        db.create_dataset(&dataset("ds", &["kind"])).unwrap();
        let mut scheduled = check("fresh", "ds", KIND_FRESHNESS);
        scheduled.max_age_ms = 10_000;
        scheduled.every_ms = 1_000;
        scheduled.tenant = "acme".into();
        scheduled.space = "ops".into();
        db.put_dataset_health_check(&scheduled).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v1".into())])])
            .unwrap();
        db.run_dataset_health_checks("ds", 5_000).unwrap();
        assert!(db.list_dataset_alerts("ds").unwrap().is_empty());
        db.run_dataset_health_checks("ds", 7_000).unwrap();
        let first = db.list_dataset_alerts("ds").unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].reason, ALERT_REASON_LATE);
        assert_eq!(first[0].state, ALERT_FIRING);
        assert_eq!(first[0].tenant, "acme");
        assert_eq!(first[0].space, "ops");
        db.run_dataset_health_checks("ds", 7_500).unwrap();
        let still = db.list_dataset_alerts("ds").unwrap();
        assert_eq!(still.len(), 1, "late schedule emits exactly one firing");
        db.run_dataset_health_checks("ds", 8_000).unwrap();
        let alerts = db.list_dataset_alerts("ds").unwrap();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[1].state, ALERT_RESOLVED);
        crate::obs::metrics::handle();
        let rendered = crate::obs::metrics::handle().render();
        assert!(
            rendered.contains("tenant=\"acme\""),
            "metrics missing tenant label: {rendered}"
        );
        assert!(
            rendered.contains("space=\"ops\""),
            "metrics missing space label: {rendered}"
        );
    }

    #[test]
    fn prune_keeps_the_last_healthy_snapshot() {
        let db = db();
        db.create_dataset(&dataset("ds", &["kind"])).unwrap();
        db.set_dataset_version_retention("ds", 1).unwrap();
        let mut blocking = check("rows", "ds", KIND_ROW_COUNT);
        blocking.min_rows = 1;
        blocking.max_rows = 1;
        blocking.blocking = true;
        db.put_dataset_health_check(&blocking).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v1".into())])])
            .unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v2".into())])])
            .unwrap();
        let live = db
            .query_rows("ds", &crate::sekai::dataset::RowQuery::default())
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0]["kind"], "v1");
        let versions = db.list_dataset_versions("ds").unwrap();
        let healthy = db.dataset_health_state("ds").unwrap();
        let pinned = versions
            .iter()
            .find(|version| version.version_id == healthy.last_healthy_version_id)
            .expect("healthy version remains listed");
        assert!(
            !pinned.purged,
            "healthy snapshot must survive retain_count=1"
        );
    }

    #[test]
    fn blocking_rejudge_skips_a_previously_failed_version() {
        let db = db();
        db.create_dataset(&dataset("ds", &["kind"])).unwrap();
        let mut counts = check("count", "ds", KIND_ROW_COUNT);
        counts.min_rows = 2;
        counts.blocking = true;
        db.put_dataset_health_check(&counts).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v1".into())])])
            .unwrap();
        assert!(
            db.dataset_health_state("ds")
                .unwrap()
                .last_healthy_version_id
                .is_empty()
        );
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v2".into())])])
            .unwrap();
        let healthy = db.dataset_health_state("ds").unwrap();
        assert!(!healthy.quarantined);
        let mut freshness = check("fresh", "ds", KIND_FRESHNESS);
        freshness.max_age_ms = 1;
        freshness.blocking = true;
        db.put_dataset_health_check(&freshness).unwrap();
        let created = db
            .list_dataset_versions("ds")
            .unwrap()
            .into_iter()
            .map(|version| version.created_at_ms)
            .max()
            .unwrap();
        db.run_dataset_health_checks("ds", created.saturating_add(10_000))
            .unwrap();
        let state = db.dataset_health_state("ds").unwrap();
        assert!(state.quarantined);
        assert!(state.last_healthy_version_id.is_empty());
        let live = db
            .query_rows("ds", &crate::sekai::dataset::RowQuery::default())
            .unwrap();
        assert!(live.is_empty());
    }

    #[test]
    fn job_alert_resolves_when_the_check_recovers() {
        let db = db();
        db.create_dataset(&dataset("ds", &["kind"])).unwrap();
        let mut counts = check("count", "ds", KIND_ROW_COUNT);
        counts.min_rows = 1;
        counts.max_rows = 1;
        db.put_dataset_health_check(&counts).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v1".into())])])
            .unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v2".into())])])
            .unwrap();
        let firing: Vec<_> = db
            .list_dataset_alerts("ds")
            .unwrap()
            .into_iter()
            .filter(|alert| alert.reason == ALERT_REASON_FAILED)
            .collect();
        assert_eq!(firing.len(), 1);
        assert_eq!(firing[0].state, ALERT_FIRING);
        counts.max_rows = 0;
        db.put_dataset_health_check(&counts).unwrap();
        db.run_dataset_health_checks("ds", 1).unwrap();
        let alerts: Vec<_> = db
            .list_dataset_alerts("ds")
            .unwrap()
            .into_iter()
            .filter(|alert| alert.reason == ALERT_REASON_FAILED)
            .collect();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[1].state, ALERT_RESOLVED);
    }

    #[test]
    fn first_blocking_failure_keeps_an_unjudged_prior_snapshot() {
        let db = db();
        db.create_dataset(&dataset("ds", &["kind"])).unwrap();
        db.set_dataset_version_retention("ds", 1).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v1".into())])])
            .unwrap();
        let mut blocking = check("rows", "ds", KIND_ROW_COUNT);
        blocking.min_rows = 1;
        blocking.max_rows = 1;
        blocking.blocking = true;
        db.put_dataset_health_check(&blocking).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v2".into())])])
            .unwrap();
        let state = db.dataset_health_state("ds").unwrap();
        assert!(state.quarantined);
        assert!(!state.last_healthy_version_id.is_empty());
        let live = db
            .query_rows("ds", &crate::sekai::dataset::RowQuery::default())
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0]["kind"], "v1");
    }

    #[test]
    fn repeated_failure_on_the_same_version_emits_retried() {
        let db = db();
        db.create_dataset(&dataset("ds", &["kind"])).unwrap();
        let mut freshness = check("fresh", "ds", KIND_FRESHNESS);
        freshness.max_age_ms = 1;
        db.put_dataset_health_check(&freshness).unwrap();
        db.append_rows("ds", &[HashMap::from([("kind".into(), "v1".into())])])
            .unwrap();
        let created = db.list_dataset_versions("ds").unwrap()[0].created_at_ms;
        db.run_dataset_health_checks("ds", created.saturating_add(10_000))
            .unwrap();
        db.run_dataset_health_checks("ds", created.saturating_add(20_000))
            .unwrap();
        let retried: Vec<_> = db
            .list_dataset_alerts("ds")
            .unwrap()
            .into_iter()
            .filter(|alert| alert.reason == ALERT_REASON_RETRIED)
            .collect();
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0].state, ALERT_FIRING);
    }
}

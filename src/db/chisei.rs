use std::collections::{BTreeSet, HashMap};

use rusqlite::{Connection, OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::chisei::{
    eval, evolve,
    receipt::{OperationReceipt, OperationReceiptEvent, OperationReporterGrant, ReceiptEventKind},
};

fn outcome_evidence(event: &OperationReceiptEvent) -> Result<Option<(&str, f64, bool)>, String> {
    if !matches!(
        event.kind,
        ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
    ) {
        return Ok(None);
    }
    let Some(metric) = event.attributes.get("outcome_metric") else {
        return Ok(None);
    };
    let Some(value) = event.attributes.get("outcome_value") else {
        return Ok(None);
    };
    let Some(passed) = event.attributes.get("passed") else {
        return Ok(None);
    };
    let metric = metric.trim();
    let value = value
        .parse::<f64>()
        .map_err(|_| "outcome evidence value must be finite".to_string())?;
    if metric.is_empty() || !value.is_finite() {
        return Err("outcome evidence metric and finite value are required".into());
    }
    let passed = passed
        .parse::<bool>()
        .map_err(|_| "outcome evidence passed flag must be boolean".to_string())?;
    Ok(Some((metric, value, passed)))
}

impl SekaiDb {
    pub(crate) fn migrate_chisei(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_eval_suites (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                cases_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chisei_eval_runs (
                id TEXT PRIMARY KEY,
                suite_id TEXT NOT NULL,
                config_ref TEXT NOT NULL,
                results_json TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_eval_runs_suite ON chisei_eval_runs(suite_id, timestamp);
            CREATE TABLE IF NOT EXISTS chisei_eval_iterations (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                suite_id TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT '',
                changed_file TEXT NOT NULL,
                diff_hash TEXT NOT NULL,
                parent_iteration_id TEXT NOT NULL,
                baseline_run_id TEXT NOT NULL,
                candidate_run_id TEXT NOT NULL,
                delta REAL NOT NULL,
                regressed INTEGER NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_eval_iterations_suite ON chisei_eval_iterations(suite_id, created);
            CREATE INDEX IF NOT EXISTS idx_chisei_eval_iterations_file ON chisei_eval_iterations(changed_file, created);
            CREATE TABLE IF NOT EXISTS chisei_evolve_tasks (
                id TEXT PRIMARY KEY,
                task_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chisei_evolve_enhancements (
                request_id TEXT PRIMARY KEY,
                original_spec TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chisei_sample_observations (
                request_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT '',
                spec TEXT NOT NULL DEFAULT '',
                resolved_model TEXT NOT NULL DEFAULT '',
                output_content TEXT NOT NULL DEFAULT '',
                sample_reason TEXT NOT NULL DEFAULT '',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                stop_reason TEXT NOT NULL DEFAULT '',
                timestamp INTEGER NOT NULL,
                scored INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                task_class TEXT NOT NULL DEFAULT '',
                cost_usd_micros INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_sample_observations_scored ON chisei_sample_observations(scored, timestamp);
            CREATE TABLE IF NOT EXISTS chisei_operation_receipts (
                operation_id TEXT PRIMARY KEY,
                request_id TEXT,
                lookup_request_id TEXT,
                initiating_actor TEXT,
                caller_scope TEXT,
                alias_retired INTEGER NOT NULL DEFAULT 0,
                namespace TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_operation_receipts_namespace
                ON chisei_operation_receipts(namespace, updated_at);
            CREATE TABLE IF NOT EXISTS chisei_gateway_request_aliases (
                caller_scope TEXT NOT NULL,
                request_alias TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                reserved_at INTEGER NOT NULL,
                dispatch_started INTEGER NOT NULL DEFAULT 0,
                dispatch_token TEXT,
                PRIMARY KEY(caller_scope, request_alias)
            );
            CREATE TABLE IF NOT EXISTS chisei_gunshi_allocation_state (
                namespace TEXT PRIMARY KEY,
                revision_id TEXT NOT NULL,
                changed_at_ms INTEGER NOT NULL,
                state_json TEXT NOT NULL
            );",
        )
        .map_err(|e| e.to_string())?;
        match conn.execute(
            "ALTER TABLE chisei_operation_receipts ADD COLUMN request_id TEXT",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }
        for statement in [
            "ALTER TABLE chisei_operation_receipts ADD COLUMN lookup_request_id TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN initiating_actor TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN caller_scope TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN alias_retired INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE chisei_gateway_request_aliases ADD COLUMN dispatch_started INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE chisei_gateway_request_aliases ADD COLUMN dispatch_token TEXT",
        ] {
            match conn.execute(statement, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                    if message.contains("duplicate column name") => {}
                Err(err) => return Err(err.to_string()),
            }
        }
        conn.execute_batch(
            r#"WITH candidates AS (
               SELECT receipts.operation_id,
                      json_extract(
                        CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                        '$.attributes.request_id'
                      ) AS request_id
               FROM chisei_operation_receipts AS receipts,
                    json_each(
                      CASE WHEN json_valid(receipts.receipt_json)
                           THEN receipts.receipt_json
                           ELSE '{"events":[]}' END,
                      '$.events'
                    ) AS events
               WHERE json_extract(
                       CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                       '$.kind'
                     )='intent_recorded'
                 AND json_type(
                       CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                       '$.attributes.request_id'
                     )='text'
             ), unique_candidates AS (
               SELECT operation_id, request_id
               FROM candidates
               WHERE request_id IS NOT NULL AND request_id != ''
                 AND request_id IN (
                   SELECT request_id FROM candidates GROUP BY request_id HAVING COUNT(*)=1
                 )
             )
             UPDATE chisei_operation_receipts
             SET request_id=(
               SELECT request_id FROM unique_candidates
               WHERE unique_candidates.operation_id=chisei_operation_receipts.operation_id
             )
             WHERE request_id IS NULL
               AND operation_id IN (SELECT operation_id FROM unique_candidates);
             DROP INDEX IF EXISTS idx_chisei_operation_receipts_lookup;
             WITH ranked_aliases AS (
               SELECT operation_id,
                      row_number() OVER (
                        PARTITION BY
                          COALESCE(
                            caller_scope,
                            substr(request_id, 8, instr(substr(request_id, 8), ':') - 1)
                          ),
                          lookup_request_id
                        ORDER BY (caller_scope IS NOT NULL) DESC,
                                 updated_at DESC,
                                 operation_id DESC
                      ) AS alias_rank
               FROM chisei_operation_receipts
               WHERE lookup_request_id IS NOT NULL
                 AND (
                   caller_scope IS NOT NULL
                   OR (request_id LIKE 'chisei:%:%' AND instr(substr(request_id, 8), ':') > 1)
                 )
             )
             UPDATE chisei_operation_receipts
             SET lookup_request_id=NULL, alias_retired=1
             WHERE operation_id IN (
               SELECT operation_id FROM ranked_aliases WHERE alias_rank > 1
             );
             UPDATE chisei_operation_receipts
             SET alias_retired=1
             WHERE lookup_request_id IS NULL
               AND alias_retired=0
               AND EXISTS (
                 SELECT 1
                 FROM json_each(
                   CASE WHEN json_valid(chisei_operation_receipts.receipt_json)
                        THEN chisei_operation_receipts.receipt_json
                        ELSE '{"events":[]}' END,
                   '$.events'
                 ) AS events
                 WHERE json_extract(
                         CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                         '$.kind'
                       )='intent_recorded'
                   AND json_type(
                         CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                         '$.attributes.lookup_request_id'
                       )='text'
                   AND COALESCE(
                         json_extract(
                           CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                           '$.attributes.lookup_request_id'
                         ),
                         ''
                       ) != ''
               );
             UPDATE chisei_operation_receipts
             SET caller_scope=substr(request_id, 8, instr(substr(request_id, 8), ':') - 1)
             WHERE caller_scope IS NULL
               AND lookup_request_id IS NOT NULL
               AND request_id LIKE 'chisei:%:%'
               AND instr(substr(request_id, 8), ':') > 1;
             CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_request
               ON chisei_operation_receipts(request_id) WHERE request_id IS NOT NULL;
             CREATE UNIQUE INDEX idx_chisei_operation_receipts_lookup
               ON chisei_operation_receipts(caller_scope, lookup_request_id)
               WHERE caller_scope IS NOT NULL AND lookup_request_id IS NOT NULL;
             INSERT OR IGNORE INTO chisei_gateway_request_aliases(
               caller_scope, request_alias, request_id, operation_id, reserved_at
             )
             SELECT caller_scope,
                    COALESCE(
                      lookup_request_id,
                      (SELECT json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id')
                       FROM json_each(CASE WHEN json_valid(receipt_json) THEN receipt_json ELSE '{"events":[]}' END, '$.events') AS events
                       WHERE json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.kind')='intent_recorded'
                         AND json_type(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id')='text'
                         AND json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id') != ''
                       LIMIT 1)
                    ),
                    COALESCE(request_id, operation_id), operation_id, updated_at
             FROM chisei_operation_receipts
             WHERE caller_scope IS NOT NULL
               AND COALESCE(
                     lookup_request_id,
                     (SELECT json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id')
                      FROM json_each(CASE WHEN json_valid(receipt_json) THEN receipt_json ELSE '{"events":[]}' END, '$.events') AS events
                      WHERE json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.kind')='intent_recorded'
                        AND json_type(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id')='text'
                        AND json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id') != ''
                      LIMIT 1)
                   ) IS NOT NULL;"#,
        )
        .map_err(|error| error.to_string())?;
        match conn.execute(
            "ALTER TABLE chisei_eval_iterations ADD COLUMN namespace TEXT NOT NULL DEFAULT ''",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }
        match conn.execute(
            "ALTER TABLE chisei_sample_observations ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }
        match conn.execute(
            "ALTER TABLE chisei_sample_observations ADD COLUMN task_class TEXT NOT NULL DEFAULT ''",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }
        match conn.execute(
            "ALTER TABLE chisei_sample_observations ADD COLUMN cost_usd_micros INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }

        if table_exists(&conn, "aipp_eval_suites")?
            && table_exists(&conn, "aipp_eval_runs")?
            && table_exists(&conn, "aipp_eval_iterations")?
            && table_exists(&conn, "aipp_evolve_tasks")?
            && table_exists(&conn, "aipp_evolve_enhancements")?
        {
            let aipp_namespace_projection =
                legacy_namespace_projection_column(&conn, "aipp_eval_iterations", true)?
                    .unwrap_or_else(|| "''".to_string());

            conn.execute(
                "INSERT OR IGNORE INTO chisei_eval_suites(id, name, description, cases_json)
                 SELECT id, name, description, cases_json FROM aipp_eval_suites",
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT OR IGNORE INTO chisei_eval_runs(id, suite_id, config_ref, results_json, timestamp)
                 SELECT id, suite_id, config_ref, results_json, timestamp FROM aipp_eval_runs",
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO chisei_eval_iterations(
                        id, run_id, suite_id, namespace, changed_file, diff_hash, parent_iteration_id,
                        baseline_run_id, candidate_run_id, delta, regressed, created
                     )
                     SELECT id, run_id, suite_id, {aipp_namespace_projection}, changed_file, diff_hash,
                            parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created
                     FROM aipp_eval_iterations"
                ),
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT OR IGNORE INTO chisei_evolve_tasks(id, task_json)
                 SELECT id, task_json FROM aipp_evolve_tasks",
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT OR IGNORE INTO chisei_evolve_enhancements(request_id, original_spec)
                 SELECT task_id, original_spec FROM aipp_evolve_enhancements",
                [],
            )
            .map_err(|e| e.to_string())?;
        }

        if let Some(legacy_namespace_column) =
            legacy_namespace_projection_column(&conn, "chisei_eval_iterations", false)?
        {
            let update_sql = format!(
                "UPDATE chisei_eval_iterations SET namespace = COALESCE(NULLIF(namespace, ''), {legacy_namespace_column})
                 WHERE namespace = '' AND COALESCE({legacy_namespace_column}, '') <> ''"
            );
            conn.execute(&update_sql, []).map_err(|e| e.to_string())?;
        }

        let legacy_rows = {
            let mut stmt = conn
                .prepare(
                    "SELECT i.id, i.changed_file, s.cases_json, r.results_json
                     FROM chisei_eval_iterations i
                     LEFT JOIN chisei_eval_suites s ON s.id = i.suite_id
                     LEFT JOIN chisei_eval_runs r ON r.id = i.run_id
                     WHERE i.namespace = ''",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        };
        for (id, changed_file, cases_json, results_json) in legacy_rows {
            let Some(namespace) = infer_legacy_iteration_namespace(
                &changed_file,
                cases_json.as_deref(),
                results_json.as_deref(),
            ) else {
                continue;
            };
            conn.execute(
                "UPDATE chisei_eval_iterations SET namespace = ?1 WHERE id = ?2 AND namespace = ''",
                params![namespace, id],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    #[cfg(feature = "gateway-test-support")]
    #[doc(hidden)]
    pub fn gateway_test_migrate_chisei(&self) -> Result<(), String> {
        self.migrate_chisei()
    }

    pub fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        let conn = self.conn();
        upsert_operation_receipt(&conn, receipt)
    }

    pub fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO chisei_operation_receipts(operation_id, initiating_actor, namespace, receipt_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                receipt.operation_id,
                receipt.initiating_actor,
                receipt.namespace,
                receipt_json,
                chrono::Utc::now().timestamp_millis(),
            ],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }
}

pub(crate) fn upsert_operation_receipt(
    conn: &Connection,
    receipt: &OperationReceipt,
) -> Result<(), String> {
    let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
    let request_id = receipt.events.iter().find_map(|event| {
        (event.kind == ReceiptEventKind::IntentRecorded)
            .then(|| event.attributes.get("request_id"))
            .flatten()
            .filter(|request_id| !request_id.is_empty())
    });
    let lookup_request_id = receipt.events.iter().find_map(|event| {
        (event.kind == ReceiptEventKind::IntentRecorded)
            .then(|| event.attributes.get("lookup_request_id"))
            .flatten()
            .filter(|request_id| !request_id.is_empty())
    });
    let caller_scope = receipt.events.iter().find_map(|event| {
        (event.kind == ReceiptEventKind::IntentRecorded)
            .then(|| event.attributes.get("caller_scope"))
            .flatten()
            .filter(|scope| !scope.is_empty())
    });
    conn.execute(
            "INSERT INTO chisei_operation_receipts(operation_id, request_id, lookup_request_id, initiating_actor, caller_scope, namespace, receipt_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(operation_id) DO UPDATE SET
                request_id=excluded.request_id,
                lookup_request_id=CASE
                  WHEN chisei_operation_receipts.alias_retired=1 THEN NULL
                  ELSE excluded.lookup_request_id
                END,
                initiating_actor=excluded.initiating_actor,
                caller_scope=COALESCE(excluded.caller_scope, chisei_operation_receipts.caller_scope),
                namespace=excluded.namespace,
                receipt_json=excluded.receipt_json,
                updated_at=excluded.updated_at",
            params![
                receipt.operation_id,
                request_id,
                lookup_request_id,
                receipt.initiating_actor,
                caller_scope,
                receipt.namespace,
                receipt_json,
                chrono::Utc::now().timestamp_millis()
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

impl SekaiDb {
    pub fn get_operation_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        let conn = self.conn();
        let receipt_json = conn
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id=?1",
                params![operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        receipt_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn list_operation_receipts_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<OperationReceipt>, String> {
        // Callers may pass max+1 to detect overflow; allow that sentinel.
        let limit = limit.min(5_001) as i64;
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE namespace=?1
                   AND CAST(json_extract(receipt_json, '$.started_at_ms') AS INTEGER) < ?3
                   AND (
                     json_extract(receipt_json, '$.completed_at_ms') IS NULL
                     OR CAST(json_extract(receipt_json, '$.completed_at_ms') AS INTEGER) > ?2
                   )
                 ORDER BY CAST(json_extract(receipt_json, '$.started_at_ms') AS INTEGER), operation_id
                 LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![namespace, start_timestamp_ms, end_timestamp_ms, limit],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?;
        let mut receipts = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            receipts.push(serde_json::from_str(&json).map_err(|error| error.to_string())?);
        }
        Ok(receipts)
    }

    pub fn reserve_gateway_request_alias(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let receipt_exists = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM chisei_operation_receipts
                   WHERE caller_scope=?1 AND lookup_request_id=?2
                 )",
                params![caller_scope, request_alias],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| error.to_string())?;
        if receipt_exists {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let existing_reservation = transaction
            .query_row(
                "SELECT request_id, operation_id, dispatch_started
                 FROM chisei_gateway_request_aliases
                 WHERE caller_scope=?1 AND request_alias=?2",
                params![caller_scope, request_alias],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((existing_request_id, existing_operation_id, dispatch_started)) =
            existing_reservation
        {
            let resumable = existing_request_id == request_id
                && existing_operation_id == operation_id
                && !dispatch_started;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(resumable);
        }
        let reserved = transaction.execute(
            "INSERT OR IGNORE INTO chisei_gateway_request_aliases(caller_scope, request_alias, request_id, operation_id, reserved_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                caller_scope,
                request_alias,
                request_id,
                operation_id,
                chrono::Utc::now().timestamp_millis()
            ],
        )
        .map_err(|error| error.to_string())? == 1;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(reserved)
    }

    pub fn claim_gateway_request_alias_dispatch(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
        dispatch_token: &str,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let claimed = transaction
            .execute(
                "UPDATE chisei_gateway_request_aliases
                 SET dispatch_started=1, dispatch_token=?1
                 WHERE caller_scope=?2 AND request_alias=?3 AND request_id=?4
                   AND operation_id=?5 AND dispatch_started=0",
                params![
                    dispatch_token,
                    caller_scope,
                    request_alias,
                    request_id,
                    operation_id,
                ],
            )
            .map_err(|error| error.to_string())?
            == 1;
        let same_claim = if claimed {
            true
        } else {
            transaction
                .query_row(
                    "SELECT dispatch_token=?1
                     FROM chisei_gateway_request_aliases
                     WHERE caller_scope=?2 AND request_alias=?3 AND request_id=?4
                       AND operation_id=?5 AND dispatch_started=1",
                    params![
                        dispatch_token,
                        caller_scope,
                        request_alias,
                        request_id,
                        operation_id,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .unwrap_or(false)
        };
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(same_claim)
    }

    pub fn find_gateway_receipt_by_logical_operation_id(
        &self,
        operation_id: &str,
        attempt: Option<u32>,
    ) -> Result<Option<OperationReceipt>, String> {
        let conn = self.conn();
        let attempt = attempt.map(|attempt| attempt.to_string());
        let mut statement = conn
            .prepare(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE instr(operation_id, ?1 || ':__attempt__:')=1
                   AND (?2 IS NULL OR operation_id LIKE '%:' || ?2)
                 ORDER BY updated_at DESC, operation_id DESC LIMIT 2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![operation_id, attempt], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if rows.len() > 1 {
            return Err("logical operation id matches multiple receipt attempts".into());
        }
        rows.into_iter()
            .next()
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        let conn = self.conn();
        let receipt_json = conn
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE request_id=?1",
                params![request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        receipt_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn find_operation_receipt_by_lookup_request_id(
        &self,
        request_id: &str,
        caller_scope: Option<&str>,
        initiating_actor: Option<&str>,
    ) -> Result<Option<OperationReceipt>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE lookup_request_id=?1
                   AND (?2 IS NULL OR caller_scope=?2)
                   AND (?3 IS NULL OR initiating_actor=?3)
                 ORDER BY operation_id LIMIT 2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![request_id, caller_scope, initiating_actor], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if rows.len() > 1 {
            return Err("request id matches multiple operation receipts".into());
        }
        rows.into_iter()
            .next()
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String> {
        if event.operation_id != operation_id {
            return Err("event operation id does not match receipt".into());
        }
        // `conn()` returns the database's sole `MutexGuard<Connection>` and
        // this guard remains live through the read, mutation, and update below.
        // Concurrent reporters therefore serialize across this whole JSON
        // read-modify-write sequence rather than overwriting one another.
        let conn = self.conn();
        let receipt_json = conn
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id=?1",
                params![operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        if let Some(existing) = receipt
            .events
            .iter()
            .find(|existing| existing.event_id == event.event_id)
        {
            let mut replay = event.clone();
            replay.timestamp_ms = existing.timestamp_ms;
            if existing == &replay {
                return Ok((receipt, false));
            }
            return Err(format!(
                "event {} already exists with different evidence",
                event.event_id
            ));
        }
        if let Some((metric, value, passed)) = outcome_evidence(&event)? {
            for existing in &receipt.events {
                let Some((existing_metric, existing_value, existing_passed)) =
                    outcome_evidence(existing)?
                else {
                    continue;
                };
                if existing_metric == metric
                    && (existing_value != value || existing_passed != passed)
                {
                    return Err(format!(
                        "outcome metric {metric} already exists with different evidence"
                    ));
                }
            }
        }
        let parent_id = event
            .parent_event_id
            .as_deref()
            .ok_or_else(|| "reported event requires a causal parent".to_string())?;
        if !receipt
            .events
            .iter()
            .any(|existing| existing.event_id == parent_id)
        {
            return Err(format!("causal parent {parent_id} not found"));
        }
        receipt
            .uncovered_surfaces
            .retain(|entry| entry.surface != event.surface);
        if event.kind == ReceiptEventKind::OutcomeRecorded {
            if receipt.completed_at_ms.is_some() {
                return Err("operation receipt already has a terminal outcome".into());
            }
            receipt.completed_at_ms = Some(event.timestamp_ms);
        }
        let produced_at_ms = event.timestamp_ms;
        receipt.events.push(event);
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        let durable_at_ms = chrono::Utc::now().timestamp_millis();
        conn.execute(
            "UPDATE chisei_operation_receipts SET receipt_json=?1, updated_at=?2 WHERE operation_id=?3",
            params![updated_json, durable_at_ms, operation_id],
        )
        .map_err(|error| error.to_string())?;
        record_durability_lag(
            crate::obs::labels::LagSurface::Receipt,
            produced_at_ms,
            durable_at_ms,
        );
        Ok((receipt, true))
    }

    pub(crate) fn update_operation_receipt<F>(
        &self,
        operation_id: &str,
        update: F,
    ) -> Result<OperationReceipt, String>
    where
        F: FnOnce(&mut OperationReceipt) -> Result<(), String>,
    {
        // Hold the same sole connection guard used by reporter appends across
        // this entire read-modify-write operation so completion cannot erase
        // evidence reported concurrently.
        let conn = self.conn();
        let receipt_json = conn
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id=?1",
                params![operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        update(&mut receipt)?;
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        conn.execute(
            "UPDATE chisei_operation_receipts SET receipt_json=?1, updated_at=?2 WHERE operation_id=?3",
            params![updated_json, chrono::Utc::now().timestamp_millis(), operation_id],
        )
        .map_err(|error| error.to_string())?;
        Ok(receipt)
    }

    pub fn authorize_operation_reporter(
        &self,
        operation_id: &str,
        principal: &str,
        event_kinds: Vec<ReceiptEventKind>,
    ) -> Result<bool, String> {
        let conn = self.conn();
        let receipt_json = conn
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id=?1",
                params![operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        let mut normalized = event_kinds;
        normalized.sort_by_key(|kind| kind.as_str());
        normalized.dedup();
        if let Some(grant) = receipt
            .reporter_grants
            .iter_mut()
            .find(|grant| grant.principal == principal)
        {
            let mut existing = grant.event_kinds.clone();
            existing.sort_by_key(|kind| kind.as_str());
            existing.dedup();
            if existing == normalized {
                return Ok(false);
            }
            grant.event_kinds = normalized;
        } else {
            receipt.reporter_grants.push(OperationReporterGrant {
                principal: principal.to_string(),
                event_kinds: normalized,
            });
        }
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        conn.execute(
            "UPDATE chisei_operation_receipts SET receipt_json=?1, updated_at=?2 WHERE operation_id=?3",
            params![updated_json, chrono::Utc::now().timestamp_millis(), operation_id],
        )
        .map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        let cases_json = serde_json::to_string(&suite.cases).map_err(|e| e.to_string())?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        transaction.execute(
            "INSERT INTO chisei_eval_suites (id, name, description, cases_json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, cases_json=excluded.cases_json
             WHERE substr(excluded.id, 1, 9) = 'sampling-'",
            params![suite.id, suite.name, suite.description, cases_json],
        )
        .map_err(|e| e.to_string())?;
        let stored: (String, String, String) = transaction
            .query_row(
                "SELECT name, description, cases_json FROM chisei_eval_suites WHERE id = ?1",
                params![suite.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| error.to_string())?;
        if stored == (suite.name.clone(), suite.description.clone(), cases_json) {
            transaction.commit().map_err(|error| error.to_string())
        } else {
            Err(format!("eval suite {:?} is immutable", suite.id))
        }
    }

    /// Create or append-only update a `feedback-` eval suite (idempotent by case id).
    pub fn append_feedback_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        if !suite.id.starts_with("feedback-") {
            return Err("append_feedback_eval_suite requires a feedback- suite id".into());
        }
        let cases_json = serde_json::to_string(&suite.cases).map_err(|e| e.to_string())?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT cases_json FROM chisei_eval_suites WHERE id = ?1",
                params![suite.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(existing_json) = existing {
            let existing_cases: Vec<eval::Case> =
                serde_json::from_str(&existing_json).map_err(|error| error.to_string())?;
            // Caller must only add cases; existing case bodies must match.
            for existing_case in &existing_cases {
                match suite.cases.iter().find(|case| case.id == existing_case.id) {
                    Some(case) if case == existing_case => {}
                    Some(_) => {
                        return Err(format!(
                            "feedback case {} already exists with different content",
                            existing_case.id
                        ));
                    }
                    None => {
                        return Err("feedback suite update cannot drop existing cases".into());
                    }
                }
            }
            transaction
                .execute(
                    "UPDATE chisei_eval_suites
                     SET name = ?2, description = ?3, cases_json = ?4
                     WHERE id = ?1",
                    params![suite.id, suite.name, suite.description, cases_json],
                )
                .map_err(|error| error.to_string())?;
        } else {
            transaction
                .execute(
                    "INSERT INTO chisei_eval_suites (id, name, description, cases_json)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![suite.id, suite.name, suite.description, cases_json],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id, name, description, cases_json FROM chisei_eval_suites WHERE id = ?1",
            params![id],
            |row| {
                let cases_json: String = row.get(3)?;
                let cases = serde_json::from_str(&cases_json).unwrap_or_default();
                Ok(eval::Suite {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    cases,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, name, description, cases_json FROM chisei_eval_suites ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let cases_json: String = row.get(3)?;
                let cases = serde_json::from_str(&cases_json).unwrap_or_default();
                Ok(eval::Suite {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    cases,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn put_eval_run(&self, run: &eval::Run) -> Result<(), String> {
        let results_json = serde_json::to_string(&run.results).map_err(|e| e.to_string())?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        transaction.execute(
            "INSERT OR IGNORE INTO chisei_eval_runs (id, suite_id, config_ref, results_json, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![run.id, run.suite_id, run.config_ref, results_json, run.timestamp],
        )
        .map_err(|e| e.to_string())?;
        let stored: (String, String, String, i64) = transaction
            .query_row(
                "SELECT suite_id, config_ref, results_json, timestamp FROM chisei_eval_runs WHERE id = ?1",
                params![run.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| error.to_string())?;
        if stored
            == (
                run.suite_id.clone(),
                run.config_ref.clone(),
                results_json,
                run.timestamp,
            )
        {
            transaction.commit().map_err(|error| error.to_string())
        } else {
            Err(format!("eval run {:?} is immutable", run.id))
        }
    }

    pub fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id, suite_id, config_ref, results_json, timestamp FROM chisei_eval_runs WHERE id = ?1",
            params![id],
            |row| {
                let results_json: String = row.get(3)?;
                let results = serde_json::from_str(&results_json).unwrap_or_default();
                Ok(eval::Run {
                    id: row.get(0)?,
                    suite_id: row.get(1)?,
                    config_ref: row.get(2)?,
                    results,
                    timestamp: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, suite_id, config_ref, results_json, timestamp FROM chisei_eval_runs WHERE suite_id = ?1 ORDER BY timestamp",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![suite_id], |row| {
                let results_json: String = row.get(3)?;
                let results = serde_json::from_str(&results_json).unwrap_or_default();
                Ok(eval::Run {
                    id: row.get(0)?,
                    suite_id: row.get(1)?,
                    config_ref: row.get(2)?,
                    results,
                    timestamp: row.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn list_all_eval_run_records(&self) -> Result<Vec<eval::Run>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, suite_id, config_ref, results_json, timestamp FROM chisei_eval_runs ORDER BY timestamp",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let results_json: String = row.get(3)?;
                let results = serde_json::from_str(&results_json).unwrap_or_default();
                Ok(eval::Run {
                    id: row.get(0)?,
                    suite_id: row.get(1)?,
                    config_ref: row.get(2)?,
                    results,
                    timestamp: row.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Keep only the newest `keep` runs for a suite (newest by timestamp), deleting the rest. Used
    /// to bound the rows the scoring job's continuous per-cycle run emission would otherwise grow
    /// without limit. Scoped to a single suite id, so user-authored suites are never touched.
    pub fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM chisei_eval_runs WHERE suite_id = ?1 AND id NOT IN (
                SELECT id FROM chisei_eval_runs WHERE suite_id = ?1 ORDER BY timestamp DESC, id DESC LIMIT ?2
            )",
            params![suite_id, keep],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Keep only the newest `keep` iterations for a suite (newest by `created`), deleting the rest.
    pub fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM chisei_eval_iterations WHERE suite_id = ?1 AND id NOT IN (
                SELECT id FROM chisei_eval_iterations WHERE suite_id = ?1 ORDER BY created DESC, id DESC LIMIT ?2
            )",
            params![suite_id, keep],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO chisei_eval_iterations (id, run_id, suite_id, namespace, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                iteration.id,
                iteration.run_id,
                iteration.suite_id,
                iteration.namespace,
                iteration.changed_file,
                iteration.diff_hash,
                iteration.parent_iteration_id,
                iteration.baseline_run_id,
                iteration.candidate_run_id,
                iteration.delta,
                iteration.regressed,
                iteration.created,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_eval_iteration_records(
        &self,
        suite_id: &str,
    ) -> Result<Vec<eval::Iteration>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, run_id, suite_id, namespace, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created FROM chisei_eval_iterations WHERE suite_id = ?1 ORDER BY created, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![suite_id], |row| {
                Ok(eval::Iteration {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    suite_id: row.get(2)?,
                    namespace: row.get(3)?,
                    changed_file: row.get(4)?,
                    diff_hash: row.get(5)?,
                    parent_iteration_id: row.get(6)?,
                    baseline_run_id: row.get(7)?,
                    candidate_run_id: row.get(8)?,
                    delta: row.get(9)?,
                    regressed: row.get(10)?,
                    created: row.get(11)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, run_id, suite_id, namespace, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created FROM chisei_eval_iterations ORDER BY created, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(eval::Iteration {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    suite_id: row.get(2)?,
                    namespace: row.get(3)?,
                    changed_file: row.get(4)?,
                    diff_hash: row.get(5)?,
                    parent_iteration_id: row.get(6)?,
                    baseline_run_id: row.get(7)?,
                    candidate_run_id: row.get(8)?,
                    delta: row.get(9)?,
                    regressed: row.get(10)?,
                    created: row.get(11)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn latest_eval_iteration_for_file(
        &self,
        changed_file: &str,
    ) -> Result<Option<eval::Iteration>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id, run_id, suite_id, namespace, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created FROM chisei_eval_iterations WHERE changed_file = ?1 ORDER BY created DESC, id DESC LIMIT 1",
            params![changed_file],
            |row| {
                Ok(eval::Iteration {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    suite_id: row.get(2)?,
                    namespace: row.get(3)?,
                    changed_file: row.get(4)?,
                    diff_hash: row.get(5)?,
                    parent_iteration_id: row.get(6)?,
                    baseline_run_id: row.get(7)?,
                    candidate_run_id: row.get(8)?,
                    delta: row.get(9)?,
                    regressed: row.get(10)?,
                    created: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn put_evolve_task(&self, task: &evolve::TaskRecord) -> Result<(), String> {
        let conn = self.conn();
        let task_json = serde_json::to_string(task).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO chisei_evolve_tasks (id, task_json) VALUES (?1, ?2)",
            params![task.id, task_json],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load durable Gunshi namespace allocation control state (JSON blob).
    pub fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT state_json FROM chisei_gunshi_allocation_state WHERE namespace = ?1",
            params![namespace],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Insert or CAS-update Gunshi allocation state.
    ///
    /// When `expected_revision` is `None`, the row must not exist yet (install).
    /// When `Some(rev)`, the existing `revision_id` must match for the update to apply.
    pub fn put_gunshi_allocation_state_cas(
        &self,
        namespace: &str,
        revision_id: &str,
        changed_at_ms: i64,
        state_json: &str,
        expected_revision: Option<&str>,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let current = tx
            .query_row(
                "SELECT revision_id FROM chisei_gunshi_allocation_state WHERE namespace = ?1",
                params![namespace],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        match (current.as_deref(), expected_revision) {
            (None, None) => {
                tx.execute(
                    "INSERT INTO chisei_gunshi_allocation_state
                        (namespace, revision_id, changed_at_ms, state_json)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![namespace, revision_id, changed_at_ms, state_json],
                )
                .map_err(|e| e.to_string())?;
            }
            (Some(existing), Some(expected)) if existing == expected => {
                let updated = tx
                    .execute(
                        "UPDATE chisei_gunshi_allocation_state
                         SET revision_id = ?2, changed_at_ms = ?3, state_json = ?4
                         WHERE namespace = ?1 AND revision_id = ?5",
                        params![namespace, revision_id, changed_at_ms, state_json, expected],
                    )
                    .map_err(|e| e.to_string())?;
                if updated != 1 {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn get_evolve_task_record(&self, id: &str) -> Result<Option<evolve::TaskRecord>, String> {
        let conn = self.conn();
        let task_json = conn
            .query_row(
                "SELECT task_json FROM chisei_evolve_tasks WHERE id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        task_json
            .map(|json| serde_json::from_str(&json).map_err(|e| e.to_string()))
            .transpose()
    }

    pub fn list_evolve_task_records(&self) -> Result<Vec<evolve::TaskRecord>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT task_json FROM chisei_evolve_tasks ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let task_jsons = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        task_jsons
            .into_iter()
            .map(|json| serde_json::from_str(&json).map_err(|e| e.to_string()))
            .collect()
    }

    pub fn put_evolve_enhancement(
        &self,
        request_id: &str,
        original_spec: &str,
    ) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO chisei_evolve_enhancements (request_id, original_spec) VALUES (?1, ?2)",
            params![request_id, original_spec],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persist a sampled execution observation captured at execute time. Idempotent on
    /// `request_id` (re-execution does not reset the `scored` flag).
    pub fn put_sample_observation(
        &self,
        obs: &crate::chisei::scoring::SampleObservation,
    ) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR IGNORE INTO chisei_sample_observations
                (request_id, namespace, spec, resolved_model, output_content, sample_reason, input_tokens, output_tokens, stop_reason, timestamp, scored, task_class, cost_usd_micros)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, ?12)",
            params![
                obs.request_id,
                obs.namespace,
                obs.spec,
                obs.resolved_model,
                obs.output_content,
                obs.sample_reason,
                obs.input_tokens,
                obs.output_tokens,
                obs.stop_reason,
                obs.timestamp,
                obs.task_class,
                obs.cost_usd_micros,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Oldest-first batch of observations the scoring job has not yet consumed.
    pub fn list_unscored_observations(
        &self,
        limit: i32,
    ) -> Result<Vec<crate::chisei::scoring::SampleObservation>, String> {
        let effective_limit = if limit > 0 { limit } else { 16 };
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT request_id, namespace, spec, resolved_model, output_content, sample_reason, input_tokens, output_tokens, stop_reason, timestamp, scored, task_class, cost_usd_micros
                 FROM chisei_sample_observations WHERE scored = 0 ORDER BY timestamp, request_id LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![effective_limit], |row| {
                Ok(crate::chisei::scoring::SampleObservation {
                    request_id: row.get(0)?,
                    namespace: row.get(1)?,
                    spec: row.get(2)?,
                    resolved_model: row.get(3)?,
                    output_content: row.get(4)?,
                    sample_reason: row.get(5)?,
                    input_tokens: row.get(6)?,
                    output_tokens: row.get(7)?,
                    stop_reason: row.get(8)?,
                    timestamp: row.get(9)?,
                    scored: row.get::<_, i64>(10)? != 0,
                    task_class: row.get(11)?,
                    cost_usd_micros: row.get(12)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Increment and return the judge-failure count for an observation, so the scoring job can
    /// retire records that fail deterministically instead of letting them occupy batch slots forever.
    pub fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
        let conn = self.conn();
        conn.execute(
            "UPDATE chisei_sample_observations SET attempts = attempts + 1 WHERE request_id = ?1",
            params![request_id],
        )
        .map_err(|e| e.to_string())?;
        conn.query_row(
            "SELECT attempts FROM chisei_sample_observations WHERE request_id = ?1",
            params![request_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| e.to_string())
    }

    /// Remove a consumed observation. The row is queue input only — the scored outcome is
    /// preserved durably in the eval run, iteration, and audit decision — so deleting it bounds
    /// table growth to the unscored backlog plus the in-flight batch.
    pub fn delete_observation(&self, request_id: &str) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM chisei_sample_observations WHERE request_id = ?1",
            params![request_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_evolve_enhancements(&self) -> Result<HashMap<String, String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT request_id, original_spec FROM chisei_evolve_enhancements")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }
}

fn infer_legacy_iteration_namespace(
    changed_file: &str,
    cases_json: Option<&str>,
    results_json: Option<&str>,
) -> Option<String> {
    let cases: Vec<serde_json::Value> = serde_json::from_str(cases_json?).ok()?;
    let results: Vec<eval::CaseResult> = serde_json::from_str(results_json?).ok()?;
    let case_namespaces: HashMap<_, _> = cases
        .into_iter()
        .filter_map(|case| {
            let id = case.get("id")?.as_str()?.to_string();
            legacy_case_namespace(&case).map(|namespace| (id, namespace))
        })
        .collect();
    let namespaces: BTreeSet<String> = results
        .iter()
        .filter_map(|result| case_namespaces.get(&result.case_id).cloned())
        .collect();
    if namespaces.len() == 1 {
        return namespaces.into_iter().next();
    }
    let matching: Vec<String> = namespaces
        .into_iter()
        .filter(|namespace| changed_file.contains(namespace))
        .collect();
    if matching.len() == 1 {
        Some(matching[0].clone())
    } else {
        None
    }
}

fn table_exists(conn: &rusqlite::Connection, table_name: &str) -> Result<bool, String> {
    let exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name = ?1",
            params![table_name],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(exists.is_some())
}

fn legacy_namespace_projection_column(
    conn: &rusqlite::Connection,
    table_name: &str,
    prefer_exact_namespace: bool,
) -> Result<Option<String>, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({})", table_name))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(1)?;
            let column_type: String = row.get(2)?;
            Ok((name, column_type))
        })
        .map_err(|e| e.to_string())?;
    let mut unknown_text_columns: Vec<String> = Vec::new();
    for row in rows {
        let (column_name, column_type) = row.map_err(|e| e.to_string())?;
        if column_name == "namespace" && prefer_exact_namespace {
            return Ok(Some("\"namespace\"".to_string()));
        }
        if !is_known_namespace_column(table_name, &column_name)
            && is_text_affinity_column(&column_type)
        {
            unknown_text_columns.push(format!("\"{}\"", column_name));
        }
    }
    if unknown_text_columns.len() == 1 {
        return Ok(unknown_text_columns.into_iter().next());
    }
    Ok(None)
}

fn is_known_namespace_column(table_name: &str, column_name: &str) -> bool {
    match table_name {
        "chisei_eval_iterations" => {
            matches!(
                column_name,
                "id" | "run_id"
                    | "suite_id"
                    | "namespace"
                    | "changed_file"
                    | "diff_hash"
                    | "parent_iteration_id"
                    | "baseline_run_id"
                    | "candidate_run_id"
                    | "delta"
                    | "regressed"
                    | "created"
            )
        }
        "aipp_eval_iterations" => {
            matches!(
                column_name,
                "id" | "run_id"
                    | "suite_id"
                    | "changed_file"
                    | "diff_hash"
                    | "parent_iteration_id"
                    | "baseline_run_id"
                    | "candidate_run_id"
                    | "delta"
                    | "regressed"
                    | "created"
            )
        }
        _ => false,
    }
}

fn is_text_affinity_column(column_type: &str) -> bool {
    let normalized = column_type.trim().to_uppercase();
    normalized.is_empty()
        || normalized.contains("CHAR")
        || normalized.contains("CLOB")
        || normalized.contains("TEXT")
}

fn legacy_case_namespace(case: &serde_json::Value) -> Option<String> {
    case.get("namespace")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .or_else(|| {
            case.as_object().and_then(|object| {
                let mut candidates: Vec<String> = object
                    .iter()
                    .filter_map(|(key, value)| {
                        if is_legacy_case_namespace_key(key) && value.is_string() {
                            value.as_str().map(|value| value.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                if candidates.len() == 1 {
                    candidates.pop()
                } else {
                    None
                }
            })
        })
}

fn is_legacy_case_namespace_key(key: &str) -> bool {
    !matches!(key, "id" | "name" | "assertions" | "spec")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_request_aliases_are_reserved_once_per_scope() {
        let db = SekaiDb::new(":memory:").unwrap();
        assert!(
            db.reserve_gateway_request_alias("scope-a", "opaque-1", "request-1", "operation-1")
                .unwrap()
        );
        assert!(
            db.reserve_gateway_request_alias("scope-a", "opaque-1", "request-1", "operation-1")
                .unwrap(),
            "a lost reservation response must resume while still pending"
        );
        assert!(
            db.claim_gateway_request_alias_dispatch(
                "scope-a",
                "opaque-1",
                "request-1",
                "operation-1",
                "dispatch-a"
            )
            .unwrap()
        );
        assert!(
            db.claim_gateway_request_alias_dispatch(
                "scope-a",
                "opaque-1",
                "request-1",
                "operation-1",
                "dispatch-a"
            )
            .unwrap(),
            "a lost claim response must be retryable by the same gateway invocation"
        );
        assert!(
            !db.claim_gateway_request_alias_dispatch(
                "scope-a",
                "opaque-1",
                "request-1",
                "operation-1",
                "dispatch-b"
            )
            .unwrap(),
            "a concurrent request must not claim an authorized dispatch"
        );
        assert!(
            !db.reserve_gateway_request_alias("scope-a", "opaque-1", "request-1", "operation-1")
                .unwrap(),
            "a dispatched alias must not be replayed"
        );
        assert!(
            !db.reserve_gateway_request_alias("scope-a", "opaque-1", "request-2", "operation-2")
                .unwrap()
        );
        assert!(
            db.reserve_gateway_request_alias("scope-b", "opaque-1", "request-3", "operation-3")
                .unwrap()
        );
        db.conn()
            .execute(
                "INSERT INTO chisei_operation_receipts(operation_id, request_id, lookup_request_id, initiating_actor, caller_scope, namespace, receipt_json, updated_at)
                 VALUES ('legacy-op', 'legacy-request', 'legacy-alias', 'gateway', 'scope-a', 'default', '{}', 1)",
                [],
            )
            .unwrap();
        assert!(
            !db.reserve_gateway_request_alias(
                "scope-a",
                "legacy-alias",
                "new-request",
                "new-operation"
            )
            .unwrap()
        );
    }
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn receipt_request_backfill_ignores_malformed_legacy_rows() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn()
            .execute(
                "INSERT INTO chisei_operation_receipts
                 (operation_id, request_id, namespace, receipt_json, updated_at)
                 VALUES ('damaged', NULL, 'test', '{invalid', 1)",
                [],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO chisei_operation_receipts
                 (operation_id, request_id, namespace, receipt_json, updated_at)
                 VALUES ('damaged-events', NULL, 'test', '{\"events\":[\"broken\"]}', 2)",
                [],
            )
            .unwrap();

        db.migrate_chisei().unwrap();
        assert!(
            db.find_operation_receipt_by_request_id("missing")
                .unwrap()
                .is_none()
        );

        db.conn()
            .execute_batch(
                "DROP INDEX idx_chisei_operation_receipts_lookup;
                 INSERT INTO chisei_operation_receipts
                   (operation_id, request_id, lookup_request_id, initiating_actor, caller_scope, namespace, receipt_json, updated_at)
                 VALUES
                   ('legacy-alias', 'chisei:scope-a:legacy', 'shared-alias', 'agent:test', NULL, 'test', '{}', 3),
                   ('current-alias', 'chisei:scope-a:current', 'shared-alias', 'agent:test', 'scope-a', 'test', '{}', 2);
                 CREATE UNIQUE INDEX idx_chisei_operation_receipts_lookup
                   ON chisei_operation_receipts(caller_scope, lookup_request_id)
                   WHERE caller_scope IS NOT NULL AND lookup_request_id IS NOT NULL;",
            )
            .unwrap();
        db.migrate_chisei().unwrap();
        let aliases: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM chisei_operation_receipts WHERE lookup_request_id='shared-alias'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(aliases, 1);
        let owner: String = db
            .conn()
            .query_row(
                "SELECT operation_id FROM chisei_operation_receipts WHERE lookup_request_id='shared-alias'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owner, "current-alias");
        let retired: i64 = db
            .conn()
            .query_row(
                "SELECT alias_retired FROM chisei_operation_receipts WHERE operation_id='legacy-alias'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retired, 1);

        db.conn()
            .execute(
                "INSERT INTO chisei_operation_receipts
                 (operation_id, request_id, lookup_request_id, initiating_actor, caller_scope, alias_retired, namespace, receipt_json, updated_at)
                 VALUES ('damaged-alias', 'chisei:scope-a:damaged', NULL, 'agent:test', 'scope-a', 0, 'test',
                         '{\"events\":[{\"kind\":\"intent_recorded\",\"attributes\":{\"lookup_request_id\":{}}}]}', 4)",
                [],
            )
            .unwrap();
        db.migrate_chisei().unwrap();
        let retired: i64 = db
            .conn()
            .query_row(
                "SELECT alias_retired FROM chisei_operation_receipts WHERE operation_id='damaged-alias'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retired, 0);

        db.conn()
            .execute(
                "UPDATE chisei_operation_receipts
                 SET alias_retired=0,
                     receipt_json='{\"events\":[{\"kind\":\"intent_recorded\",\"attributes\":{\"lookup_request_id\":\"shared-alias\"}}]}'
                 WHERE operation_id='legacy-alias'",
                [],
            )
            .unwrap();
        db.migrate_chisei().unwrap();
        let retired: i64 = db
            .conn()
            .query_row(
                "SELECT alias_retired FROM chisei_operation_receipts WHERE operation_id='legacy-alias'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retired, 1);
    }

    #[test]
    fn eval_writers_wait_for_active_transactions_and_preserve_outcomes() {
        let path =
            std::env::temp_dir().join(format!("sekai-eval-lock-{}.db", uuid::Uuid::new_v4()));
        let first = Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap());
        let second = Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap());
        let suite = eval::Suite {
            id: "sampling-live".into(),
            name: "initial".into(),
            description: String::new(),
            cases: Vec::new(),
        };
        first.put_eval_suite(&suite).unwrap();

        let mut connection = first.conn();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "UPDATE chisei_eval_suites SET name='held' WHERE id='sampling-live'",
                [],
            )
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut competing = suite.clone();
        competing.name = "competing".into();
        let writer = second.clone();
        let handle = std::thread::spawn(move || {
            tx.send(writer.put_eval_suite(&competing)).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        transaction.commit().unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
        handle.join().unwrap();
        assert_eq!(
            first
                .get_eval_suite_record("sampling-live")
                .unwrap()
                .unwrap()
                .name,
            "competing"
        );

        let run = eval::Run {
            id: "immutable-run".into(),
            suite_id: "promotion-suite".into(),
            config_ref: "v1".into(),
            results: Vec::new(),
            timestamp: 1,
        };
        let mut connection = first.conn();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO chisei_eval_runs (id, suite_id, config_ref, results_json, timestamp) VALUES (?1, ?2, ?3, '[]', ?4)",
                params![run.id, run.suite_id, run.config_ref, run.timestamp],
            )
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut competing = run.clone();
        competing.config_ref = "v2".into();
        let writer = second.clone();
        let handle = std::thread::spawn(move || {
            tx.send(writer.put_eval_run(&competing)).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        transaction.commit().unwrap();
        let error = rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert!(error.contains("immutable-run") && error.contains("immutable"));
        handle.join().unwrap();
        assert_eq!(
            first
                .get_eval_run_record("immutable-run")
                .unwrap()
                .unwrap()
                .config_ref,
            "v1"
        );

        drop((first, second));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
    }
}

/// Time between a record being produced and becoming durable.
///
/// Both timestamps are wall-clock milliseconds sampled at different points, so
/// a clock adjustment can make the difference negative. A negative lag is not
/// meaningful: `None` drops it rather than clamping to zero, because clamping
/// would report a real clock problem as a run of implausibly fast writes.
///
/// Kept pure so it can be tested without the process-global metrics recorder,
/// which other tests in this binary also write to.
fn durability_lag(produced_at_ms: i64, durable_at_ms: i64) -> Option<std::time::Duration> {
    let lag_ms = durable_at_ms.checked_sub(produced_at_ms)?;
    if lag_ms < 0 {
        return None;
    }
    Some(std::time::Duration::from_millis(lag_ms as u64))
}

fn record_durability_lag(
    surface: crate::obs::labels::LagSurface,
    produced_at_ms: i64,
    durable_at_ms: i64,
) {
    if let Some(lag) = durability_lag(produced_at_ms, durable_at_ms) {
        crate::obs::signals::record_durability_lag(surface, lag);
    }
}

#[cfg(test)]
mod durability_lag_tests {
    use super::durability_lag;
    use std::time::Duration;

    #[test]
    fn negative_lag_from_clock_skew_is_dropped_not_clamped() {
        // Produced at t=1000, "durable" at t=900 means the clock moved, not
        // that the write was instant. Reporting zero would hide a real clock
        // problem behind a run of implausibly fast writes.
        assert_eq!(durability_lag(1000, 900), None);
    }

    #[test]
    fn ordinary_lag_is_measured_in_milliseconds() {
        assert_eq!(durability_lag(1000, 1250), Some(Duration::from_millis(250)));
    }

    #[test]
    fn zero_lag_is_recorded_not_dropped() {
        assert_eq!(durability_lag(1000, 1000), Some(Duration::ZERO));
    }

    #[test]
    fn overflowing_timestamps_do_not_panic() {
        assert_eq!(durability_lag(i64::MIN, i64::MAX), None);
    }
}

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::chisei::{
    eval, evolve,
    receipt::{OperationReceipt, ReceiptEventKind},
};
#[cfg(any(test, feature = "gateway-test-support"))]
use crate::chisei_store::ChiseiSqliteSchema;
use crate::chisei_store::chisei_eval_backend::{
    EVAL_GATE_MAX_CASES, EVAL_GATE_MAX_RESULTS, decode_eval_gate_cases, decode_eval_gate_run,
};
use crate::chisei_store::ext::ReceiptChainSekaiDbExt;
use sekai_core::db::sekai::SekaiDb;

pub trait ChiseiSekaiDbExt {
    #[cfg(feature = "gateway-test-support")]
    #[doc(hidden)]
    fn gateway_test_migrate_chisei(&self) -> Result<(), String>;

    fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String>;
}

impl ChiseiSekaiDbExt for SekaiDb {
    #[cfg(feature = "gateway-test-support")]
    #[doc(hidden)]
    fn gateway_test_migrate_chisei(&self) -> Result<(), String> {
        self.migrate_chisei()
    }

    fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        let request_id = receipt_intent_attr(receipt, "request_id");
        let lookup_request_id = receipt_intent_attr(receipt, "lookup_request_id");
        let caller_scope = receipt_intent_attr(receipt, "caller_scope");
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO chisei_operation_receipts(
                operation_id, request_id, lookup_request_id, initiating_actor,
                caller_scope, namespace, receipt_json, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                receipt.operation_id,
                request_id,
                lookup_request_id,
                receipt.initiating_actor,
                caller_scope,
                receipt.namespace,
                receipt_json,
                chrono::Utc::now().timestamp_millis(),
            ],
        )
        .map_err(|error| error.to_string())?;
        self.append_operation_receipt_chain(&tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())
    }
}

pub(crate) fn upsert_operation_receipt(
    conn: &Connection,
    receipt: &OperationReceipt,
) -> Result<(), String> {
    let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
    let request_id = receipt_intent_attr(receipt, "request_id");
    let lookup_request_id = receipt_intent_attr(receipt, "lookup_request_id");
    let caller_scope = receipt_intent_attr(receipt, "caller_scope");
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

fn receipt_intent_attr<'a>(receipt: &'a OperationReceipt, name: &str) -> Option<&'a String> {
    receipt.events.iter().find_map(|event| {
        (event.kind == ReceiptEventKind::IntentRecorded)
            .then(|| event.attributes.get(name))
            .flatten()
            .filter(|value| !value.is_empty())
    })
}

pub trait ChiseiSekaiDbExt2 {
    fn count_active_kioku_promotions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
    ) -> Result<i64, String>;

    fn list_kioku_lifecycle_events_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::chisei::kioku::MemoryLifecycleEvent>, String>;

    fn list_kioku_outcomes_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::chisei::kioku::MemoryOutcomeObservation>, String>;

    fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String>;

    /// Create or append-only update a `feedback-` eval suite (idempotent by case id).
    fn append_feedback_eval_suite(&self, suite: &eval::Suite) -> Result<(), String>;

    fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String>;

    fn get_eval_suite_record_for_gate(&self, id: &str) -> Result<Option<eval::Suite>, String>;

    fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String>;

    fn put_eval_run(&self, run: &eval::Run) -> Result<(), String>;

    fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String>;

    fn get_latest_eval_run_record_for_gate(
        &self,
        suite_id: &str,
        config_ref: &str,
        max_timestamp_ms: i64,
    ) -> Result<Option<eval::Run>, String>;

    fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String>;

    fn list_all_eval_run_records(&self) -> Result<Vec<eval::Run>, String>;

    /// Keep only the newest `keep` runs for a suite (newest by timestamp), deleting the rest. Used
    /// to bound the rows the scoring job's continuous per-cycle run emission would otherwise grow
    /// without limit. Scoped to a single suite id, so user-authored suites are never touched.
    fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String>;

    /// Keep only the newest `keep` iterations for a suite (newest by `created`), deleting the rest.
    fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String>;

    fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String>;

    fn list_eval_iteration_records(&self, suite_id: &str) -> Result<Vec<eval::Iteration>, String>;

    fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String>;

    fn latest_eval_iteration_for_file(
        &self,
        changed_file: &str,
    ) -> Result<Option<eval::Iteration>, String>;

    fn put_evolve_task(&self, task: &evolve::TaskRecord) -> Result<(), String>;

    /// Load durable Gunshi namespace allocation control state (JSON blob).
    fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String>;

    /// Insert or CAS-update Gunshi allocation state.
    ///
    /// When `expected_revision` is `None`, the row must not exist yet (install).
    /// When `Some(rev)`, the existing `revision_id` must match for the update to apply.
    fn put_gunshi_allocation_state_cas(
        &self,
        namespace: &str,
        revision_id: &str,
        changed_at_ms: i64,
        state_json: &str,
        expected_revision: Option<&str>,
    ) -> Result<bool, String>;

    fn get_evolve_task_record(&self, id: &str) -> Result<Option<evolve::TaskRecord>, String>;

    fn list_evolve_task_records(&self) -> Result<Vec<evolve::TaskRecord>, String>;

    /// Persist a sampled execution observation captured at execute time. Idempotent on
    /// `request_id` (re-execution does not reset the `scored` flag).
    fn put_sample_observation(
        &self,
        obs: &crate::chisei::scoring::SampleObservation,
    ) -> Result<(), String>;

    /// Read one observation for an authorized, bounded telemetry projection.
    fn get_sample_observation(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String>;

    /// Read one observation only when its request identity and namespace match.
    fn get_sample_observation_in_namespace(
        &self,
        request_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String>;

    /// Oldest-first batch of observations the scoring job has not yet consumed.
    fn list_unscored_observations(
        &self,
        limit: i32,
    ) -> Result<Vec<crate::chisei::scoring::SampleObservation>, String>;

    /// Increment and return the judge-failure count for an observation, so the scoring job can
    /// retire records that fail deterministically instead of letting them occupy batch slots forever.
    fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String>;

    /// Remove a consumed observation. The row is queue input only — the scored outcome is
    /// preserved durably in the eval run, iteration, and audit decision — so deleting it bounds
    /// table growth to the unscored backlog plus the in-flight batch.
    fn delete_observation(&self, request_id: &str) -> Result<(), String>;
}

impl ChiseiSekaiDbExt2 for SekaiDb {
    fn count_active_kioku_promotions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
    ) -> Result<i64, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT COUNT(*)
             FROM chisei_kioku_lifecycle_events AS lifecycle
             JOIN chisei_kioku_memories AS memory
               ON memory.id=lifecycle.memory_id AND memory.version=lifecycle.memory_version
             WHERE memory.namespace=?1 AND memory.state='active'
               AND lifecycle.action='promoted'
               AND lifecycle.recorded_at_ms >= ?2
               AND lifecycle.recorded_at_ms < ?3",
            rusqlite::params![namespace, start_timestamp_ms, end_timestamp_ms],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())
    }

    fn list_kioku_lifecycle_events_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::chisei::kioku::MemoryLifecycleEvent>, String> {
        let limit = limit.min(5_001) as i64;
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT lifecycle.memory_id, lifecycle.memory_version, lifecycle.action,
                        lifecycle.from_state, lifecycle.to_state, lifecycle.actor,
                        lifecycle.reason, lifecycle.recorded_at_ms
                 FROM chisei_kioku_lifecycle_events AS lifecycle
                 JOIN chisei_kioku_memories AS memory
                   ON memory.id=lifecycle.memory_id AND memory.version=lifecycle.memory_version
                 WHERE memory.namespace=?1
                   AND lifecycle.recorded_at_ms >= ?2
                   AND lifecycle.recorded_at_ms < ?3
                 ORDER BY lifecycle.recorded_at_ms, lifecycle.id
                 LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![namespace, start_timestamp_ms, end_timestamp_ms, limit],
                |row| {
                    Ok(crate::chisei::kioku::MemoryLifecycleEvent {
                        memory_id: row.get(0)?,
                        memory_version: row.get(1)?,
                        action: row.get(2)?,
                        from_state: row.get(3)?,
                        to_state: row.get(4)?,
                        actor: row.get(5)?,
                        reason: row.get(6)?,
                        recorded_at_ms: row.get(7)?,
                    })
                },
            )
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    fn list_kioku_outcomes_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::chisei::kioku::MemoryOutcomeObservation>, String> {
        let limit = limit.min(5_001) as i64;
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT outcome.memory_id, outcome.memory_version, outcome.operation_id,
                        outcome.memory_applied, outcome.outcome_metric, outcome.outcome_value,
                        outcome.passed, outcome.recorded_at_ms
                 FROM chisei_kioku_outcomes AS outcome
                 JOIN chisei_kioku_memories AS memory
                   ON memory.id=outcome.memory_id AND memory.version=outcome.memory_version
                 WHERE memory.namespace=?1
                   AND outcome.recorded_at_ms >= ?2
                   AND outcome.recorded_at_ms < ?3
                 ORDER BY outcome.recorded_at_ms, outcome.operation_id
                 LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![namespace, start_timestamp_ms, end_timestamp_ms, limit],
                |row| {
                    Ok(crate::chisei::kioku::MemoryOutcomeObservation {
                        memory_id: row.get(0)?,
                        memory_version: row.get(1)?,
                        operation_id: row.get(2)?,
                        request_id: String::new(),
                        memory_applied: row.get(3)?,
                        outcome_metric: row.get(4)?,
                        outcome_value: row.get(5)?,
                        passed: row.get(6)?,
                        recorded_at_ms: row.get(7)?,
                    })
                },
            )
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
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
    fn append_feedback_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
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

    fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
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

    fn get_eval_suite_record_for_gate(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        let conn = self.conn();
        let row: Option<(String, String, String, String)> = conn
            .query_row(
                "SELECT id, name, description, cases_json FROM chisei_eval_suites WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        row.map(|(id, name, description, cases_json)| {
            let cases = decode_eval_gate_cases(&cases_json)?;
            if cases.len() > EVAL_GATE_MAX_CASES {
                return Err(format!(
                    "eval suite contains more than {EVAL_GATE_MAX_CASES} gate cases"
                ));
            }
            Ok(eval::Suite {
                id,
                name,
                description,
                cases,
            })
        })
        .transpose()
    }

    fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String> {
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

    fn put_eval_run(&self, run: &eval::Run) -> Result<(), String> {
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

    fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
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

    fn get_latest_eval_run_record_for_gate(
        &self,
        suite_id: &str,
        config_ref: &str,
        max_timestamp_ms: i64,
    ) -> Result<Option<eval::Run>, String> {
        let conn = self.conn();
        let row: Option<(String, String, String, String, i64)> = conn
            .query_row(
                "SELECT id, suite_id, config_ref, results_json, timestamp
                 FROM chisei_eval_runs
                 WHERE suite_id = ?1 AND config_ref = ?2
                   AND timestamp > 0 AND timestamp <= ?3
                 ORDER BY timestamp DESC, id DESC
                 LIMIT 1",
                params![suite_id, config_ref, max_timestamp_ms],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        row.map(|(id, suite_id, config_ref, results_json, timestamp)| {
            let run = decode_eval_gate_run(id, suite_id, config_ref, &results_json, timestamp)?;
            if run.results.len() > EVAL_GATE_MAX_RESULTS {
                return Err(format!(
                    "eval run contains more than {EVAL_GATE_MAX_RESULTS} gate results"
                ));
            }
            Ok(run)
        })
        .transpose()
    }

    fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String> {
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

    fn list_all_eval_run_records(&self) -> Result<Vec<eval::Run>, String> {
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
    fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
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
    fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
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

    fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String> {
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

    fn list_eval_iteration_records(&self, suite_id: &str) -> Result<Vec<eval::Iteration>, String> {
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

    fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String> {
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

    fn latest_eval_iteration_for_file(
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

    fn put_evolve_task(&self, task: &evolve::TaskRecord) -> Result<(), String> {
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
    fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String> {
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
    fn put_gunshi_allocation_state_cas(
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

    fn get_evolve_task_record(&self, id: &str) -> Result<Option<evolve::TaskRecord>, String> {
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

    fn list_evolve_task_records(&self) -> Result<Vec<evolve::TaskRecord>, String> {
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

    /// Persist a sampled execution observation captured at execute time. Idempotent on
    /// `request_id` (re-execution does not reset the `scored` flag).
    fn put_sample_observation(
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

    /// Read one observation for an authorized, bounded telemetry projection.
    fn get_sample_observation(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String> {
        if request_id.trim().is_empty() {
            return Err("request_id required".into());
        }
        let conn = self.conn();
        conn.query_row(
            "SELECT request_id, namespace, spec, resolved_model, output_content,
                    sample_reason, input_tokens, output_tokens, stop_reason,
                    timestamp, scored, task_class, cost_usd_micros
             FROM chisei_sample_observations WHERE request_id = ?1",
            params![request_id],
            |row| {
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
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Read one observation only when its request identity and namespace match.
    fn get_sample_observation_in_namespace(
        &self,
        request_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::chisei::scoring::SampleObservation>, String> {
        if request_id.trim().is_empty() || namespace.trim().is_empty() {
            return Err("request_id and namespace required".into());
        }
        let conn = self.conn();
        conn.query_row(
            "SELECT request_id, namespace, spec, resolved_model, output_content,
                    sample_reason, input_tokens, output_tokens, stop_reason,
                    timestamp, scored, task_class, cost_usd_micros
             FROM chisei_sample_observations
             WHERE request_id = ?1 AND namespace = ?2",
            params![request_id, namespace],
            |row| {
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
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Oldest-first batch of observations the scoring job has not yet consumed.
    fn list_unscored_observations(
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
    fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
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
    fn delete_observation(&self, request_id: &str) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM chisei_sample_observations WHERE request_id = ?1",
            params![request_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_request_aliases_are_reserved_once_per_scope() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
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
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
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

        db.conn().pragma_update(None, "user_version", 0).unwrap();
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
        db.conn().pragma_update(None, "user_version", 0).unwrap();
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
        db.conn().pragma_update(None, "user_version", 0).unwrap();
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
        db.conn().pragma_update(None, "user_version", 0).unwrap();
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

    fn window_receipt(
        operation_id: &str,
        started_at_ms: i64,
        completed_at_ms: Option<i64>,
    ) -> OperationReceipt {
        OperationReceipt {
            version: sekai_domain::receipt::OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.into(),
            parent_operation_id: None,
            namespace: "acme".into(),
            operation_class: "governed_action_instance".into(),
            initiating_actor: "alice".into(),
            schema_version: "action-instance/v1".into(),
            policy_version: "implicit-allow".into(),
            started_at_ms,
            completed_at_ms,
            events: Vec::new(),
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        }
    }

    fn receipt_updated_at(db: &SekaiDb, operation_id: &str) -> i64 {
        db.conn()
            .query_row(
                "SELECT updated_at FROM chisei_operation_receipts WHERE operation_id=?1",
                [operation_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn windowed_lists_keep_recent_opens_and_drop_stale_opens() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
        let ttl = sekai_core::db::chisei_receipt::OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS;
        let recent_started = ttl + 100;
        let later_start = recent_started + ttl + 10;
        db.put_operation_receipt(&window_receipt("open-recent", recent_started, None))
            .unwrap();
        db.put_operation_receipt(&window_receipt("open-stale", 1, None))
            .unwrap();
        db.put_operation_receipt(&window_receipt(
            "completed-in-later-window",
            later_start,
            Some(later_start + 50),
        ))
        .unwrap();

        let recent_ids = db
            .list_operation_receipts_in_window("acme", recent_started, recent_started + 100, 16)
            .unwrap()
            .into_iter()
            .map(|receipt| receipt.operation_id)
            .collect::<Vec<_>>();
        assert_eq!(recent_ids, vec!["open-recent".to_string()]);

        let later_ids = db
            .list_operation_receipts_in_window("acme", later_start, later_start + 100, 16)
            .unwrap()
            .into_iter()
            .map(|receipt| receipt.operation_id)
            .collect::<Vec<_>>();
        assert_eq!(later_ids, vec!["completed-in-later-window".to_string()]);
        assert!(
            db.get_operation_receipt("open-stale")
                .unwrap()
                .unwrap()
                .completed_at_ms
                .is_none(),
            "stale opens stay harvestable until ack"
        );
    }

    #[test]
    fn update_operation_receipt_skips_write_when_unchanged() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
        db.put_operation_receipt(&window_receipt("op-skip", 1, None))
            .unwrap();
        db.conn()
            .execute(
                "UPDATE chisei_operation_receipts SET updated_at=1 WHERE operation_id='op-skip'",
                [],
            )
            .unwrap();
        db.update_operation_receipt("op-skip", |_| Ok(())).unwrap();
        assert_eq!(receipt_updated_at(&db, "op-skip"), 1);

        db.update_operation_receipt("op-skip", |receipt| {
            receipt.completed_at_ms = Some(2);
            Ok(())
        })
        .unwrap();
        assert_ne!(receipt_updated_at(&db, "op-skip"), 1);
        assert_eq!(
            db.get_operation_receipt("op-skip")
                .unwrap()
                .unwrap()
                .completed_at_ms,
            Some(2)
        );
    }

    #[test]
    fn eval_writers_wait_for_active_transactions_and_preserve_outcomes() {
        let path =
            std::env::temp_dir().join(format!("sekai-eval-lock-{}.db", uuid::Uuid::new_v4()));
        let first = Arc::new(crate::chisei_store::open_sekai_with_chisei_schema(
            path.to_str().unwrap(),
        ));
        let second = Arc::new(crate::chisei_store::open_sekai_with_chisei_schema(
            path.to_str().unwrap(),
        ));
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

    #[test]
    fn gate_reads_fail_closed_on_malformed_suite_or_run_payloads() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
        let suite = eval::Suite {
            id: "gate-suite".into(),
            name: "gate".into(),
            description: String::new(),
            cases: vec![eval::Case {
                id: "case".into(),
                name: "case".into(),
                namespace: "namespace".into(),
                spec: "spec".into(),
                assertions: vec![],
            }],
        };
        db.put_eval_suite(&suite).unwrap();
        db.put_eval_run(&eval::Run {
            id: "run".into(),
            suite_id: suite.id.clone(),
            config_ref: "config".into(),
            results: vec![eval::CaseResult {
                case_id: "case".into(),
                passed: true,
                status: "passed".into(),
                result: String::new(),
                score: 1,
                reason: String::new(),
                elapsed: 1,
            }],
            timestamp: 100,
        })
        .unwrap();

        db.conn()
            .execute(
                "UPDATE chisei_eval_suites SET cases_json = '{malformed' WHERE id = 'gate-suite'",
                [],
            )
            .unwrap();
        assert!(db.get_eval_suite_record_for_gate("gate-suite").is_err());

        db.conn()
            .execute(
                "UPDATE chisei_eval_suites SET cases_json = '[]' WHERE id = 'gate-suite'",
                [],
            )
            .unwrap();
        db.conn()
            .execute(
                "UPDATE chisei_eval_runs SET results_json = '{malformed' WHERE id = 'run'",
                [],
            )
            .unwrap();
        assert!(
            db.get_latest_eval_run_record_for_gate("gate-suite", "config", 200)
                .is_err()
        );
    }
}

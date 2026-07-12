use std::collections::HashMap;

use crate::chisei::{eval, evolve};
use crate::db::postgres::PostgresDb;

const ITERATION_COLUMNS: &str = "id, run_id, suite_id, namespace, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created";
const SAMPLE_LEASE_MS: i64 = 30 * 60 * 1000;

impl PostgresDb {
    pub fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        let cases_json = serde_json::to_string(&suite.cases).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_eval_suites (id, name, description, cases_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    cases_json = excluded.cases_json",
                &[&suite.id, &suite.name, &suite.description, &cases_json],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        self.connection()?
            .query_opt(
                "SELECT id, name, description, cases_json FROM chisei_eval_suites WHERE id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_eval_suite)
            .transpose()
    }

    pub fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String> {
        self.connection()?
            .query(
                "SELECT id, name, description, cases_json FROM chisei_eval_suites ORDER BY id",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_eval_suite)
            .collect()
    }

    pub fn put_eval_run(&self, run: &eval::Run) -> Result<(), String> {
        let results_json =
            serde_json::to_string(&run.results).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_eval_runs (id, suite_id, config_ref, results_json, timestamp)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT(id) DO UPDATE SET
                    suite_id = excluded.suite_id,
                    config_ref = excluded.config_ref,
                    results_json = excluded.results_json,
                    timestamp = excluded.timestamp",
                &[
                    &run.id,
                    &run.suite_id,
                    &run.config_ref,
                    &results_json,
                    &run.timestamp,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
        self.connection()?
            .query_opt(
                "SELECT id, suite_id, config_ref, results_json, timestamp
                 FROM chisei_eval_runs WHERE id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_eval_run)
            .transpose()
    }

    pub fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String> {
        self.query_eval_runs(
            "SELECT id, suite_id, config_ref, results_json, timestamp
             FROM chisei_eval_runs WHERE suite_id = $1 ORDER BY timestamp",
            &[&suite_id],
        )
    }

    pub fn list_all_eval_run_records(&self) -> Result<Vec<eval::Run>, String> {
        self.query_eval_runs(
            "SELECT id, suite_id, config_ref, results_json, timestamp
             FROM chisei_eval_runs ORDER BY timestamp",
            &[],
        )
    }

    fn query_eval_runs(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<eval::Run>, String> {
        self.connection()?
            .query(sql, params)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_eval_run)
            .collect()
    }

    pub fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM chisei_eval_runs
                 WHERE suite_id = $1 AND id NOT IN (
                    SELECT id FROM chisei_eval_runs
                    WHERE suite_id = $1 ORDER BY timestamp DESC, id DESC LIMIT $2
                 )",
                &[&suite_id, &keep],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String> {
        let regressed = i64::from(iteration.regressed);
        self.connection()?
            .execute(
                "INSERT INTO chisei_eval_iterations
                    (id, run_id, suite_id, namespace, changed_file, diff_hash,
                     parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                 ON CONFLICT(id) DO UPDATE SET
                    run_id = excluded.run_id,
                    suite_id = excluded.suite_id,
                    namespace = excluded.namespace,
                    changed_file = excluded.changed_file,
                    diff_hash = excluded.diff_hash,
                    parent_iteration_id = excluded.parent_iteration_id,
                    baseline_run_id = excluded.baseline_run_id,
                    candidate_run_id = excluded.candidate_run_id,
                    delta = excluded.delta,
                    regressed = excluded.regressed,
                    created = excluded.created",
                &[
                    &iteration.id,
                    &iteration.run_id,
                    &iteration.suite_id,
                    &iteration.namespace,
                    &iteration.changed_file,
                    &iteration.diff_hash,
                    &iteration.parent_iteration_id,
                    &iteration.baseline_run_id,
                    &iteration.candidate_run_id,
                    &iteration.delta,
                    &regressed,
                    &iteration.created,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_eval_iteration_records(
        &self,
        suite_id: &str,
    ) -> Result<Vec<eval::Iteration>, String> {
        self.query_eval_iterations(
            &format!(
                "SELECT {ITERATION_COLUMNS} FROM chisei_eval_iterations
                 WHERE suite_id = $1 ORDER BY created, id"
            ),
            &[&suite_id],
        )
    }

    pub fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String> {
        self.query_eval_iterations(
            &format!("SELECT {ITERATION_COLUMNS} FROM chisei_eval_iterations ORDER BY created, id"),
            &[],
        )
    }

    pub fn latest_eval_iteration_for_file(
        &self,
        changed_file: &str,
    ) -> Result<Option<eval::Iteration>, String> {
        Ok(self
            .connection()?
            .query_opt(
                &format!(
                    "SELECT {ITERATION_COLUMNS} FROM chisei_eval_iterations
                     WHERE changed_file = $1 ORDER BY created DESC, id DESC LIMIT 1"
                ),
                &[&changed_file],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_eval_iteration))
    }

    pub fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM chisei_eval_iterations
                 WHERE suite_id = $1 AND id NOT IN (
                    SELECT id FROM chisei_eval_iterations
                    WHERE suite_id = $1 ORDER BY created DESC, id DESC LIMIT $2
                 )",
                &[&suite_id, &keep],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn query_eval_iterations(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<eval::Iteration>, String> {
        Ok(self
            .connection()?
            .query(sql, params)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_eval_iteration)
            .collect())
    }

    pub fn put_evolve_task(&self, task: &evolve::TaskRecord) -> Result<(), String> {
        let task_json = serde_json::to_string(task).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_evolve_tasks (id, task_json) VALUES ($1, $2)
                 ON CONFLICT(id) DO UPDATE SET task_json = excluded.task_json",
                &[&task.id, &task_json],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_evolve_task_record(&self, id: &str) -> Result<Option<evolve::TaskRecord>, String> {
        self.connection()?
            .query_opt(
                "SELECT task_json FROM chisei_evolve_tasks WHERE id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .transpose()
    }

    pub fn list_evolve_task_records(&self) -> Result<Vec<evolve::TaskRecord>, String> {
        self.connection()?
            .query("SELECT task_json FROM chisei_evolve_tasks ORDER BY id", &[])
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .collect()
    }

    pub fn put_evolve_enhancement(
        &self,
        request_id: &str,
        original_spec: &str,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO chisei_evolve_enhancements (request_id, original_spec)
                 VALUES ($1, $2)
                 ON CONFLICT(request_id) DO UPDATE SET original_spec = excluded.original_spec",
                &[&request_id, &original_spec],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_evolve_enhancements(&self) -> Result<HashMap<String, String>, String> {
        self.connection()?
            .query(
                "SELECT request_id, original_spec FROM chisei_evolve_enhancements",
                &[],
            )
            .map(|rows| {
                rows.into_iter()
                    .map(|row| (row.get(0), row.get(1)))
                    .collect()
            })
            .map_err(|error| error.to_string())
    }

    pub fn put_sample_observation(
        &self,
        observation: &crate::chisei::scoring::SampleObservation,
    ) -> Result<(), String> {
        let input_tokens = i64::from(observation.input_tokens);
        let output_tokens = i64::from(observation.output_tokens);
        self.connection()?
            .execute(
                "INSERT INTO chisei_sample_observations
                    (request_id, namespace, spec, resolved_model, output_content,
                     sample_reason, input_tokens, output_tokens, stop_reason, timestamp,
                     scored, task_class, cost_usd_micros)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, $11, $12)
                 ON CONFLICT(request_id) DO NOTHING",
                &[
                    &observation.request_id,
                    &observation.namespace,
                    &observation.spec,
                    &observation.resolved_model,
                    &observation.output_content,
                    &observation.sample_reason,
                    &input_tokens,
                    &output_tokens,
                    &observation.stop_reason,
                    &observation.timestamp,
                    &observation.task_class,
                    &observation.cost_usd_micros,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_unscored_observations(
        &self,
        limit: i32,
    ) -> Result<Vec<crate::chisei::scoring::SampleObservation>, String> {
        let effective_limit = i64::from(if limit > 0 { limit } else { 16 });
        let now = chrono::Utc::now().timestamp_millis();
        let lease_expires_at = now.saturating_add(SAMPLE_LEASE_MS);
        let lease_owner = format!("scorer-{}", uuid::Uuid::new_v4().simple());
        let mut connection = self.connection()?;
        let rows = connection
            .query(
                "WITH candidates AS (
                    SELECT request_id FROM chisei_sample_observations
                    WHERE scored = 0 AND lease_expires_at <= $2
                    ORDER BY timestamp, request_id
                    FOR UPDATE SKIP LOCKED LIMIT $1
                 )
                 UPDATE chisei_sample_observations AS observations
                 SET lease_owner = $3, lease_expires_at = $4
                 FROM candidates
                 WHERE observations.request_id = candidates.request_id
                 RETURNING observations.request_id, observations.namespace, observations.spec,
                           observations.resolved_model, observations.output_content,
                           observations.sample_reason, observations.input_tokens,
                           observations.output_tokens, observations.stop_reason,
                           observations.timestamp, observations.scored,
                           observations.task_class, observations.cost_usd_micros",
                &[&effective_limit, &now, &lease_owner, &lease_expires_at],
            )
            .map_err(|error| error.to_string())?;
        let mut observations = Vec::new();
        for row in rows {
            let request_id: String = row.get(0);
            match row_to_sample_observation(row) {
                Ok(observation) => observations.push(observation),
                Err(error) => {
                    match connection.execute(
                        "UPDATE chisei_sample_observations
                             SET scored = -1, lease_owner = '', lease_expires_at = 0
                             WHERE request_id = $1",
                        &[&request_id],
                    ) {
                        Ok(_) => {
                            tracing::error!(%error, request_id, "quarantined invalid PostgreSQL sample observation")
                        }
                        Err(quarantine_error) => {
                            tracing::error!(%error, %quarantine_error, request_id, "failed to quarantine invalid PostgreSQL sample observation")
                        }
                    }
                }
            }
        }
        observations.sort_by(|left, right| {
            left.timestamp
                .cmp(&right.timestamp)
                .then_with(|| left.request_id.cmp(&right.request_id))
        });
        Ok(observations)
    }

    pub fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
        self.connection()?
            .query_opt(
                "UPDATE chisei_sample_observations
                 SET attempts = attempts + 1, lease_owner = '', lease_expires_at = 0
                 WHERE request_id = $1
                 RETURNING attempts",
                &[&request_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0))
            .ok_or_else(|| format!("sample observation not found: {request_id}"))
    }

    pub fn delete_observation(&self, request_id: &str) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM chisei_sample_observations WHERE request_id = $1",
                &[&request_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn row_to_eval_suite(row: postgres::Row) -> Result<eval::Suite, String> {
    let id: String = row.get(0);
    let cases_json: String = row.get(3);
    Ok(eval::Suite {
        id: id.clone(),
        name: row.get(1),
        description: row.get(2),
        cases: decode_json_or_default(&cases_json, "suite", &id),
    })
}

fn row_to_eval_run(row: postgres::Row) -> Result<eval::Run, String> {
    let id: String = row.get(0);
    let results_json: String = row.get(3);
    Ok(eval::Run {
        id: id.clone(),
        suite_id: row.get(1),
        config_ref: row.get(2),
        results: decode_json_or_default(&results_json, "run", &id),
        timestamp: row.get(4),
    })
}

fn decode_json_or_default<T>(json: &str, record_kind: &str, record_id: &str) -> T
where
    T: serde::de::DeserializeOwned + Default,
{
    serde_json::from_str(json).unwrap_or_else(|error| {
        tracing::warn!(%error, record_kind, record_id, "malformed PostgreSQL eval payload; using empty value");
        T::default()
    })
}

fn row_to_eval_iteration(row: postgres::Row) -> eval::Iteration {
    let regressed: i64 = row.get(10);
    eval::Iteration {
        id: row.get(0),
        run_id: row.get(1),
        suite_id: row.get(2),
        namespace: row.get(3),
        changed_file: row.get(4),
        diff_hash: row.get(5),
        parent_iteration_id: row.get(6),
        baseline_run_id: row.get(7),
        candidate_run_id: row.get(8),
        delta: row.get(9),
        regressed: regressed != 0,
        created: row.get(11),
    }
}

fn row_to_sample_observation(
    row: postgres::Row,
) -> Result<crate::chisei::scoring::SampleObservation, String> {
    let request_id: String = row.get(0);
    let input_tokens = i32::try_from(row.get::<_, i64>(6))
        .map_err(|_| format!("input_tokens out of range for observation {request_id}"))?;
    let output_tokens = i32::try_from(row.get::<_, i64>(7))
        .map_err(|_| format!("output_tokens out of range for observation {request_id}"))?;
    let scored: i64 = row.get(10);
    Ok(crate::chisei::scoring::SampleObservation {
        request_id,
        namespace: row.get(1),
        spec: row.get(2),
        resolved_model: row.get(3),
        output_content: row.get(4),
        sample_reason: row.get(5),
        input_tokens,
        output_tokens,
        stop_reason: row.get(8),
        timestamp: row.get(9),
        scored: scored != 0,
        task_class: row.get(11),
        cost_usd_micros: row.get(12),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iteration_projection_matches_row_decoder() {
        assert_eq!(ITERATION_COLUMNS.split(',').count(), 12);
        assert!(ITERATION_COLUMNS.contains("regressed"));
    }

    #[test]
    fn malformed_eval_payloads_default_without_hiding_other_rows() {
        let decoded: Vec<eval::CaseResult> =
            decode_json_or_default("not-json", "run", "run-corrupt");
        assert!(decoded.is_empty());
    }
}

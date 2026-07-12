use crate::chisei::eval;
use crate::db::postgres::PostgresDb;

const ITERATION_COLUMNS: &str = "id, run_id, suite_id, namespace, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created";

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
}

fn row_to_eval_suite(row: postgres::Row) -> Result<eval::Suite, String> {
    let cases_json: String = row.get(3);
    Ok(eval::Suite {
        id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        cases: decode_json_or_default(&cases_json),
    })
}

fn row_to_eval_run(row: postgres::Row) -> Result<eval::Run, String> {
    let results_json: String = row.get(3);
    Ok(eval::Run {
        id: row.get(0),
        suite_id: row.get(1),
        config_ref: row.get(2),
        results: decode_json_or_default(&results_json),
        timestamp: row.get(4),
    })
}

fn decode_json_or_default<T>(json: &str) -> T
where
    T: serde::de::DeserializeOwned + Default,
{
    serde_json::from_str(json).unwrap_or_default()
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
        let decoded: Vec<eval::CaseResult> = decode_json_or_default("not-json");
        assert!(decoded.is_empty());
    }
}

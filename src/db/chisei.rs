use std::collections::{BTreeSet, HashMap};

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::chisei::{eval, evolve};

impl SekaiDb {
    pub fn migrate_chisei(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
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
                repo TEXT NOT NULL DEFAULT '',
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
                repo TEXT NOT NULL DEFAULT '',
                spec TEXT NOT NULL DEFAULT '',
                resolved_model TEXT NOT NULL DEFAULT '',
                output_content TEXT NOT NULL DEFAULT '',
                sample_reason TEXT NOT NULL DEFAULT '',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                stop_reason TEXT NOT NULL DEFAULT '',
                timestamp INTEGER NOT NULL,
                scored INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_sample_observations_scored ON chisei_sample_observations(scored, timestamp);",
        )
        .map_err(|e| e.to_string())?;
        match conn.execute(
            "ALTER TABLE chisei_eval_iterations ADD COLUMN repo TEXT NOT NULL DEFAULT ''",
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

        if table_exists(&conn, "aipp_eval_suites")?
            && table_exists(&conn, "aipp_eval_runs")?
            && table_exists(&conn, "aipp_eval_iterations")?
            && table_exists(&conn, "aipp_evolve_tasks")?
            && table_exists(&conn, "aipp_evolve_enhancements")?
        {
            let legacy_iter_repo_projection =
                if column_exists(&conn, "aipp_eval_iterations", "repo")? {
                    "repo"
                } else {
                    "''"
                };

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
                        id, run_id, suite_id, repo, changed_file, diff_hash, parent_iteration_id,
                        baseline_run_id, candidate_run_id, delta, regressed, created
                     )
                     SELECT id, run_id, suite_id, {legacy_iter_repo_projection}, changed_file, diff_hash,
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

        let legacy_rows = {
            let mut stmt = conn
                .prepare(
                    "SELECT i.id, i.changed_file, s.cases_json, r.results_json
                     FROM chisei_eval_iterations i
                     LEFT JOIN chisei_eval_suites s ON s.id = i.suite_id
                     LEFT JOIN chisei_eval_runs r ON r.id = i.run_id
                     WHERE i.repo = ''",
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
            let Some(repo) = infer_legacy_iteration_repo(
                &changed_file,
                cases_json.as_deref(),
                results_json.as_deref(),
            ) else {
                continue;
            };
            conn.execute(
                "UPDATE chisei_eval_iterations SET repo = ?1 WHERE id = ?2 AND repo = ''",
                params![repo, id],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let cases_json = serde_json::to_string(&suite.cases).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO chisei_eval_suites (id, name, description, cases_json) VALUES (?1, ?2, ?3, ?4)",
            params![suite.id, suite.name, suite.description, cases_json],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let results_json = serde_json::to_string(&run.results).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO chisei_eval_runs (id, suite_id, config_ref, results_json, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![run.id, run.suite_id, run.config_ref, results_json, run.timestamp],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO chisei_eval_iterations (id, run_id, suite_id, repo, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                iteration.id,
                iteration.run_id,
                iteration.suite_id,
                iteration.repo,
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, run_id, suite_id, repo, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created FROM chisei_eval_iterations WHERE suite_id = ?1 ORDER BY created, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![suite_id], |row| {
                Ok(eval::Iteration {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    suite_id: row.get(2)?,
                    repo: row.get(3)?,
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, run_id, suite_id, repo, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created FROM chisei_eval_iterations ORDER BY created, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(eval::Iteration {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    suite_id: row.get(2)?,
                    repo: row.get(3)?,
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
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, run_id, suite_id, repo, changed_file, diff_hash, parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created FROM chisei_eval_iterations WHERE changed_file = ?1 ORDER BY created DESC, id DESC LIMIT 1",
            params![changed_file],
            |row| {
                Ok(eval::Iteration {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    suite_id: row.get(2)?,
                    repo: row.get(3)?,
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
        let conn = self.conn.lock().unwrap();
        let task_json = serde_json::to_string(task).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO chisei_evolve_tasks (id, task_json) VALUES (?1, ?2)",
            params![task.id, task_json],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_evolve_task_record(&self, id: &str) -> Result<Option<evolve::TaskRecord>, String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO chisei_sample_observations
                (request_id, repo, spec, resolved_model, output_content, sample_reason, input_tokens, output_tokens, stop_reason, timestamp, scored)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0)",
            params![
                obs.request_id,
                obs.repo,
                obs.spec,
                obs.resolved_model,
                obs.output_content,
                obs.sample_reason,
                obs.input_tokens,
                obs.output_tokens,
                obs.stop_reason,
                obs.timestamp,
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT request_id, repo, spec, resolved_model, output_content, sample_reason, input_tokens, output_tokens, stop_reason, timestamp, scored
                 FROM chisei_sample_observations WHERE scored = 0 ORDER BY timestamp, request_id LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![effective_limit], |row| {
                Ok(crate::chisei::scoring::SampleObservation {
                    request_id: row.get(0)?,
                    repo: row.get(1)?,
                    spec: row.get(2)?,
                    resolved_model: row.get(3)?,
                    output_content: row.get(4)?,
                    sample_reason: row.get(5)?,
                    input_tokens: row.get(6)?,
                    output_tokens: row.get(7)?,
                    stop_reason: row.get(8)?,
                    timestamp: row.get(9)?,
                    scored: row.get::<_, i64>(10)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Increment and return the judge-failure count for an observation, so the scoring job can
    /// retire records that fail deterministically instead of letting them occupy batch slots forever.
    pub fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM chisei_sample_observations WHERE request_id = ?1",
            params![request_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_evolve_enhancements(&self) -> Result<HashMap<String, String>, String> {
        let conn = self.conn.lock().unwrap();
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

fn infer_legacy_iteration_repo(
    changed_file: &str,
    cases_json: Option<&str>,
    results_json: Option<&str>,
) -> Option<String> {
    let cases: Vec<eval::Case> = serde_json::from_str(cases_json?).ok()?;
    let results: Vec<eval::CaseResult> = serde_json::from_str(results_json?).ok()?;
    let case_repos: HashMap<_, _> = cases.into_iter().map(|case| (case.id, case.repo)).collect();
    let repos: BTreeSet<String> = results
        .iter()
        .filter_map(|result| case_repos.get(&result.case_id).cloned())
        .collect();
    if repos.len() == 1 {
        return repos.into_iter().next();
    }
    let matching: Vec<String> = repos
        .into_iter()
        .filter(|repo| changed_file.contains(repo))
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

fn column_exists(
    conn: &rusqlite::Connection,
    table_name: &str,
    column_name: &str,
) -> Result<bool, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({})", table_name))
        .map_err(|e| e.to_string())?;
    let mut rows = stmt
        .query_map([], |row| {
            let name: String = row.get(1)?;
            Ok(name)
        })
        .map_err(|e| e.to_string())?;
    while let Some(row) = rows.next().transpose().map_err(|e| e.to_string())? {
        if row == column_name {
            return Ok(true);
        }
    }
    Ok(false)
}

//! Eval run state (#1674) on both community backends: one row per run with
//! its spec, its lease and the spend reserved for cases not yet recorded,
//! and one row per (run, case) result. A case is reserved and recorded only
//! while its start holds the run's lease, and the first result per case
//! wins, so a restarted, overlapping or lapsed start never records a case
//! twice and never loses track of what a crashed one may have spent.

use crate::chisei::eval_run::{EvalCaseResult, EvalRunSpec};
use sekai_core::db::postgres::PostgresDb;
use sekai_core::db::sekai::SekaiDb;

/// The lease-held predicate over `chisei_dataset_runs`, with the holder and
/// the time as the given parameters.
fn held(holder: &str, now: &str) -> String {
    format!("lease_holder = {holder} AND lease_until_ms >= {now}")
}

fn spec_from(json: &str) -> Result<EvalRunSpec, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt eval run: {error}"))
}

fn result_from(json: &str) -> Result<EvalCaseResult, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt eval case result: {error}"))
}

pub trait EvalRunSekaiDbExt {
    fn put_dataset_run(&self, spec: &EvalRunSpec, now_ms: i64) -> Result<EvalRunSpec, String>;

    fn lease_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String>;

    fn release_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
    ) -> Result<(), String>;

    fn reserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String>;

    fn record_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        result: &EvalCaseResult,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<Option<EvalCaseResult>, String>;

    fn unreserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<(), String>;

    fn dataset_run_uncertain_micros(&self, namespace: &str, run_id: &str) -> Result<i64, String>;

    fn list_dataset_run_cases(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Vec<EvalCaseResult>, String>;

    /// Records the run bound to the released artifact it evaluates, in one
    /// transaction: a new run is created with its binding, and an existing
    /// run keeps whatever binding it was created with (none, if it was
    /// started without one). Returns the stored spec and binding (#1677).
    /// The binding is kept apart from the spec so readers of the spec format
    /// are unchanged.
    fn put_bound_dataset_run(
        &self,
        spec: &EvalRunSpec,
        artifact_digest: &str,
        now_ms: i64,
    ) -> Result<(EvalRunSpec, Option<String>), String>;

    fn dataset_run_artifact(&self, namespace: &str, run_id: &str)
    -> Result<Option<String>, String>;

    /// Every run of `namespace` with when it was first started, oldest
    /// first (#1677).
    fn list_dataset_runs(&self, namespace: &str) -> Result<Vec<(EvalRunSpec, i64)>, String>;
}

impl EvalRunSekaiDbExt for SekaiDb {
    fn put_dataset_run(&self, spec: &EvalRunSpec, now_ms: i64) -> Result<EvalRunSpec, String> {
        let json = serde_json::to_string(spec).map_err(|error| error.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO chisei_dataset_runs (namespace, run_id, spec_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            rusqlite::params![spec.namespace, spec.run_id, json, now_ms],
        )
        .map_err(|error| error.to_string())?;
        let stored: String = conn
            .query_row(
                "SELECT spec_json FROM chisei_dataset_runs WHERE namespace = ?1 AND run_id = ?2",
                rusqlite::params![spec.namespace, spec.run_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        spec_from(&stored)
    }

    fn lease_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        let condition = if renew {
            held("?3", "?4")
        } else {
            "(lease_holder = '' OR lease_until_ms < ?4)".to_string()
        };
        self.conn()
            .execute(
                &format!(
                    "UPDATE chisei_dataset_runs SET lease_holder = ?3, lease_until_ms = ?5
                     WHERE namespace = ?1 AND run_id = ?2 AND {condition}"
                ),
                rusqlite::params![namespace, run_id, holder, now_ms, until_ms],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    fn release_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE chisei_dataset_runs SET lease_holder = '', lease_until_ms = 0
                 WHERE namespace = ?1 AND run_id = ?2 AND lease_holder = ?3",
                rusqlite::params![namespace, run_id, holder],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn reserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                &format!(
                    "UPDATE chisei_dataset_runs
                     SET lease_until_ms = ?5, uncertain_micros = uncertain_micros + ?6
                     WHERE namespace = ?1 AND run_id = ?2 AND {}",
                    held("?3", "?4")
                ),
                rusqlite::params![namespace, run_id, holder, now_ms, until_ms, reserve_micros],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    fn record_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        result: &EvalCaseResult,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<Option<EvalCaseResult>, String> {
        let json = serde_json::to_string(result).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let released = tx
            .execute(
                &format!(
                    "UPDATE chisei_dataset_runs
                     SET uncertain_micros = MAX(uncertain_micros - ?5, 0)
                     WHERE namespace = ?1 AND run_id = ?2 AND {}",
                    held("?3", "?4")
                ),
                rusqlite::params![namespace, run_id, holder, now_ms, reserve_micros],
            )
            .map_err(|error| error.to_string())?;
        if released != 1 {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO chisei_dataset_run_cases
                (namespace, run_id, case_id, result_json, cost_micros, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
            rusqlite::params![
                namespace,
                run_id,
                result.case_id,
                json,
                result.outcome.cost_micros,
                result.recorded_at_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        let stored: String = tx
            .query_row(
                "SELECT result_json FROM chisei_dataset_run_cases
                 WHERE namespace = ?1 AND run_id = ?2 AND case_id = ?3",
                rusqlite::params![namespace, run_id, result.case_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        result_from(&stored).map(Some)
    }

    fn unreserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                &format!(
                    "UPDATE chisei_dataset_runs
                     SET uncertain_micros = MAX(uncertain_micros - ?5, 0)
                     WHERE namespace = ?1 AND run_id = ?2 AND {}",
                    held("?3", "?4")
                ),
                rusqlite::params![namespace, run_id, holder, now_ms, reserve_micros],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn dataset_run_uncertain_micros(&self, namespace: &str, run_id: &str) -> Result<i64, String> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()
            .query_row(
                "SELECT uncertain_micros FROM chisei_dataset_runs
                 WHERE namespace = ?1 AND run_id = ?2",
                rusqlite::params![namespace, run_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .unwrap_or(0))
    }

    fn list_dataset_run_cases(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Vec<EvalCaseResult>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT result_json FROM chisei_dataset_run_cases
                 WHERE namespace = ?1 AND run_id = ?2 ORDER BY case_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![namespace, run_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| result_from(&row.map_err(|error| error.to_string())?))
            .collect()
    }

    /// Records the run bound to the released artifact it evaluates, in one
    /// transaction: a new run is created with its binding, and an existing
    /// run keeps whatever binding it was created with (none, if it was
    /// started without one). Returns the stored spec and binding (#1677).
    /// The binding is kept apart from the spec so readers of the spec format
    /// are unchanged.
    fn put_bound_dataset_run(
        &self,
        spec: &EvalRunSpec,
        artifact_digest: &str,
        now_ms: i64,
    ) -> Result<(EvalRunSpec, Option<String>), String> {
        use rusqlite::OptionalExtension;
        let json = serde_json::to_string(spec).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let created = tx
            .execute(
                "INSERT INTO chisei_dataset_runs (namespace, run_id, spec_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                rusqlite::params![spec.namespace, spec.run_id, json, now_ms],
            )
            .map_err(|error| error.to_string())?;
        if created == 1 {
            tx.execute(
                "INSERT INTO chisei_dataset_run_artifacts (namespace, run_id, artifact_digest)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![spec.namespace, spec.run_id, artifact_digest],
            )
            .map_err(|error| error.to_string())?;
        }
        let stored: String = tx
            .query_row(
                "SELECT spec_json FROM chisei_dataset_runs WHERE namespace = ?1 AND run_id = ?2",
                rusqlite::params![spec.namespace, spec.run_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let bound: Option<String> = tx
            .query_row(
                "SELECT artifact_digest FROM chisei_dataset_run_artifacts
                 WHERE namespace = ?1 AND run_id = ?2",
                rusqlite::params![spec.namespace, spec.run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok((spec_from(&stored)?, bound))
    }

    fn dataset_run_artifact(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT artifact_digest FROM chisei_dataset_run_artifacts
                 WHERE namespace = ?1 AND run_id = ?2",
                rusqlite::params![namespace, run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    /// Every run of `namespace` with when it was first started, oldest
    /// first (#1677).
    fn list_dataset_runs(&self, namespace: &str) -> Result<Vec<(EvalRunSpec, i64)>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT spec_json, created_at_ms FROM chisei_dataset_runs
                 WHERE namespace = ?1 ORDER BY created_at_ms, run_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![namespace], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (json, created) = row.map_err(|error| error.to_string())?;
            Ok((spec_from(&json)?, created))
        })
        .collect()
    }
}

pub trait EvalRunPostgresDbExt {
    fn put_dataset_run(&self, spec: &EvalRunSpec, now_ms: i64) -> Result<EvalRunSpec, String>;

    fn lease_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String>;

    fn release_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
    ) -> Result<(), String>;

    fn reserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String>;

    fn record_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        result: &EvalCaseResult,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<Option<EvalCaseResult>, String>;

    fn unreserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<(), String>;

    fn dataset_run_uncertain_micros(&self, namespace: &str, run_id: &str) -> Result<i64, String>;

    fn list_dataset_run_cases(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Vec<EvalCaseResult>, String>;

    fn put_bound_dataset_run(
        &self,
        spec: &EvalRunSpec,
        artifact_digest: &str,
        now_ms: i64,
    ) -> Result<(EvalRunSpec, Option<String>), String>;

    fn dataset_run_artifact(&self, namespace: &str, run_id: &str)
    -> Result<Option<String>, String>;

    fn list_dataset_runs(&self, namespace: &str) -> Result<Vec<(EvalRunSpec, i64)>, String>;
}

impl EvalRunPostgresDbExt for PostgresDb {
    fn put_dataset_run(&self, spec: &EvalRunSpec, now_ms: i64) -> Result<EvalRunSpec, String> {
        let json = serde_json::to_string(spec).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO chisei_dataset_runs (namespace, run_id, spec_json, created_at_ms)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[&spec.namespace, &spec.run_id, &json, &now_ms],
            )
            .map_err(|error| error.to_string())?;
        let row = connection
            .query_one(
                "SELECT spec_json FROM chisei_dataset_runs WHERE namespace = $1 AND run_id = $2",
                &[&spec.namespace, &spec.run_id],
            )
            .map_err(|error| error.to_string())?;
        spec_from(row.get(0))
    }

    fn lease_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        let condition = if renew {
            held("$3", "$4")
        } else {
            "(lease_holder = '' OR lease_until_ms < $4)".to_string()
        };
        let mut connection = self.connection()?;
        connection
            .execute(
                &format!(
                    "UPDATE chisei_dataset_runs SET lease_holder = $3, lease_until_ms = $5
                     WHERE namespace = $1 AND run_id = $2 AND {condition}"
                ),
                &[&namespace, &run_id, &holder, &now_ms, &until_ms],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    fn release_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "UPDATE chisei_dataset_runs SET lease_holder = '', lease_until_ms = 0
                 WHERE namespace = $1 AND run_id = $2 AND lease_holder = $3",
                &[&namespace, &run_id, &holder],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn reserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                &format!(
                    "UPDATE chisei_dataset_runs
                     SET lease_until_ms = $5, uncertain_micros = uncertain_micros + $6
                     WHERE namespace = $1 AND run_id = $2 AND {}",
                    held("$3", "$4")
                ),
                &[
                    &namespace,
                    &run_id,
                    &holder,
                    &now_ms,
                    &until_ms,
                    &reserve_micros,
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    fn record_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        result: &EvalCaseResult,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<Option<EvalCaseResult>, String> {
        let json = serde_json::to_string(result).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let released = tx
            .execute(
                &format!(
                    "UPDATE chisei_dataset_runs
                     SET uncertain_micros = GREATEST(uncertain_micros - $5, 0)
                     WHERE namespace = $1 AND run_id = $2 AND {}",
                    held("$3", "$4")
                ),
                &[&namespace, &run_id, &holder, &now_ms, &reserve_micros],
            )
            .map_err(|error| error.to_string())?;
        if released != 1 {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO chisei_dataset_run_cases
                (namespace, run_id, case_id, result_json, cost_micros, recorded_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            &[
                &namespace,
                &run_id,
                &result.case_id,
                &json,
                &result.outcome.cost_micros,
                &result.recorded_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        let row = tx
            .query_one(
                "SELECT result_json FROM chisei_dataset_run_cases
                 WHERE namespace = $1 AND run_id = $2 AND case_id = $3",
                &[&namespace, &run_id, &result.case_id],
            )
            .map_err(|error| error.to_string())?;
        let stored: String = row.get(0);
        tx.commit().map_err(|error| error.to_string())?;
        result_from(&stored).map(Some)
    }

    fn unreserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                &format!(
                    "UPDATE chisei_dataset_runs
                     SET uncertain_micros = GREATEST(uncertain_micros - $5, 0)
                     WHERE namespace = $1 AND run_id = $2 AND {}",
                    held("$3", "$4")
                ),
                &[&namespace, &run_id, &holder, &now_ms, &reserve_micros],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn dataset_run_uncertain_micros(&self, namespace: &str, run_id: &str) -> Result<i64, String> {
        let mut connection = self.connection()?;
        Ok(connection
            .query_opt(
                "SELECT uncertain_micros FROM chisei_dataset_runs
                 WHERE namespace = $1 AND run_id = $2",
                &[&namespace, &run_id],
            )
            .map_err(|error| error.to_string())?
            .map_or(0, |row| row.get::<_, i64>(0)))
    }

    fn list_dataset_run_cases(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Vec<EvalCaseResult>, String> {
        let mut connection = self.connection()?;
        connection
            .query(
                "SELECT result_json FROM chisei_dataset_run_cases
                 WHERE namespace = $1 AND run_id = $2 ORDER BY case_id",
                &[&namespace, &run_id],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| result_from(row.get(0)))
            .collect()
    }

    fn put_bound_dataset_run(
        &self,
        spec: &EvalRunSpec,
        artifact_digest: &str,
        now_ms: i64,
    ) -> Result<(EvalRunSpec, Option<String>), String> {
        let json = serde_json::to_string(spec).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let created = tx
            .execute(
                "INSERT INTO chisei_dataset_runs (namespace, run_id, spec_json, created_at_ms)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[&spec.namespace, &spec.run_id, &json, &now_ms],
            )
            .map_err(|error| error.to_string())?;
        if created == 1 {
            tx.execute(
                "INSERT INTO chisei_dataset_run_artifacts (namespace, run_id, artifact_digest)
                 VALUES ($1, $2, $3)",
                &[&spec.namespace, &spec.run_id, &artifact_digest],
            )
            .map_err(|error| error.to_string())?;
        }
        let stored: String = tx
            .query_one(
                "SELECT spec_json FROM chisei_dataset_runs WHERE namespace = $1 AND run_id = $2",
                &[&spec.namespace, &spec.run_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        let bound: Option<String> = tx
            .query_opt(
                "SELECT artifact_digest FROM chisei_dataset_run_artifacts
                 WHERE namespace = $1 AND run_id = $2",
                &[&spec.namespace, &spec.run_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        tx.commit().map_err(|error| error.to_string())?;
        Ok((spec_from(&stored)?, bound))
    }

    fn dataset_run_artifact(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Option<String>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT artifact_digest FROM chisei_dataset_run_artifacts
                 WHERE namespace = $1 AND run_id = $2",
                &[&namespace, &run_id],
            )
            .map(|row| row.map(|row| row.get(0)))
            .map_err(|error| error.to_string())
    }

    fn list_dataset_runs(&self, namespace: &str) -> Result<Vec<(EvalRunSpec, i64)>, String> {
        let mut connection = self.connection()?;
        connection
            .query(
                "SELECT spec_json, created_at_ms FROM chisei_dataset_runs
                 WHERE namespace = $1 ORDER BY created_at_ms, run_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| Ok((spec_from(row.get(0))?, row.get::<_, i64>(1))))
            .collect()
    }
}

pub trait EvalRunRuntimeDbExt {
    fn put_bound_dataset_run(
        &self,
        spec: &EvalRunSpec,
        artifact_digest: &str,
        now_ms: i64,
    ) -> Result<(EvalRunSpec, Option<String>), String>;
    fn dataset_run_artifact(&self, namespace: &str, run_id: &str)
    -> Result<Option<String>, String>;
    fn list_dataset_runs(&self, namespace: &str) -> Result<Vec<(EvalRunSpec, i64)>, String>;
}

impl EvalRunRuntimeDbExt for sekai_core::db::runtime_db::RuntimeDb {
    /// Records a run with its artifact binding in one write; see
    /// `SekaiDb::put_bound_dataset_run`.
    fn put_bound_dataset_run(
        &self,
        spec: &EvalRunSpec,
        artifact_digest: &str,
        now_ms: i64,
    ) -> Result<(EvalRunSpec, Option<String>), String> {
        match self {
            Self::Sqlite(db) => db.put_bound_dataset_run(spec, artifact_digest, now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.put_bound_dataset_run(spec, artifact_digest, now_ms)
            }),
        }
    }

    /// The artifact a run is bound to, if any.
    fn dataset_run_artifact(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.dataset_run_artifact(namespace, run_id),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.dataset_run_artifact(namespace, run_id))
            }
        }
    }

    /// Every eval run of `namespace` with when it was first started.
    fn list_dataset_runs(&self, namespace: &str) -> Result<Vec<(EvalRunSpec, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_runs(namespace),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.list_dataset_runs(namespace))
            }
        }
    }
}

/// Dispatches to the backend the plane runs on; PostgreSQL off the async
/// runtime.
macro_rules! dispatch {
    ($self:ident, $db:ident => $call:expr) => {
        match $self {
            Self::Sqlite($db) => $call,
            Self::Postgres($db) => sekai_core::db::postgres::off_runtime(|| $call),
        }
    };
}

/// The runner's store over whichever backend the plane runs on.
impl crate::chisei::eval_run::EvalRunStore for sekai_core::db::runtime_db::RuntimeDb {
    fn put_dataset_run(&self, spec: &EvalRunSpec, now_ms: i64) -> Result<EvalRunSpec, String> {
        dispatch!(self, db => db.put_dataset_run(spec, now_ms))
    }

    fn reserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        dispatch!(self, db => db.reserve_dataset_run_case(
            namespace, run_id, holder, reserve_micros, now_ms, until_ms
        ))
    }

    fn record_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        result: &EvalCaseResult,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<Option<EvalCaseResult>, String> {
        dispatch!(self, db => db.record_dataset_run_case(
            namespace, run_id, holder, result, reserve_micros, now_ms
        ))
    }

    fn unreserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        dispatch!(self, db => db.unreserve_dataset_run_case(
            namespace, run_id, holder, reserve_micros, now_ms
        ))
    }

    fn dataset_run_uncertain_micros(&self, namespace: &str, run_id: &str) -> Result<i64, String> {
        dispatch!(self, db => db.dataset_run_uncertain_micros(namespace, run_id))
    }

    fn list_dataset_run_cases(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Vec<EvalCaseResult>, String> {
        dispatch!(self, db => db.list_dataset_run_cases(namespace, run_id))
    }

    fn lease_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        dispatch!(self, db => db.lease_dataset_run(namespace, run_id, holder, renew, now_ms, until_ms))
    }

    fn release_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
    ) -> Result<(), String> {
        dispatch!(self, db => db.release_dataset_run(namespace, run_id, holder))
    }
}

#[cfg(test)]
mod tests {
    use crate::chisei::eval_run::tests::{dataset, spec};
    use crate::chisei::eval_run::{
        CaseOutcome, EvalCaseExecutor, EvalCaseResult, EvalRunSpec, EvalRunStore, RUN_CONFLICT,
        STATUS_COMPLETED, run,
    };
    use crate::chisei_store::eval_run::EvalRunRuntimeDbExt;
    use sekai_core::db::runtime_db::RuntimeDb;
    use std::sync::Arc;

    struct Flat;

    impl EvalCaseExecutor for Flat {
        fn run_case(
            &self,
            _spec: &EvalRunSpec,
            _dataset: &crate::chisei::eval_dataset::EvalDataset,
            _case: &crate::chisei::eval_dataset::EvalCase,
        ) -> Result<CaseOutcome, crate::chisei::eval_run::CaseError> {
            Ok(CaseOutcome {
                passed: true,
                reason: "fixture".into(),
                input_tokens: 3,
                output_tokens: 2,
                cost_micros: 5,
                receipts: Some(Default::default()),
                policy: None,
            })
        }
    }

    /// A run is bound to an artifact only as it is created; an existing run
    /// keeps its binding, or its lack of one (#1677).
    #[test]
    fn a_run_is_bound_to_an_artifact_only_when_created() {
        use crate::chisei::eval_run::tests::spec;
        let db = crate::chisei_store::ChiseiStore::memory().runtime_arc();
        let bound = EvalRunSpec {
            run_id: "bound".into(),
            ..spec(1, 1_000)
        };
        let digest = |tag: &str| format!("sha256:{}", tag.repeat(32));
        assert_eq!(
            db.put_bound_dataset_run(&bound, &digest("ab"), 1)
                .unwrap()
                .1,
            Some(digest("ab"))
        );
        assert_eq!(
            db.put_bound_dataset_run(&bound, &digest("cd"), 2)
                .unwrap()
                .1,
            Some(digest("ab"))
        );
        let unbound = EvalRunSpec {
            run_id: "unbound".into(),
            ..spec(1, 1_000)
        };
        crate::chisei::eval_run::EvalRunStore::put_dataset_run(db.as_ref(), &unbound, 3).unwrap();
        assert_eq!(
            db.put_bound_dataset_run(&unbound, &digest("ab"), 4)
                .unwrap()
                .1,
            None
        );
        assert_eq!(db.dataset_run_artifact("acme", "unbound").unwrap(), None);
    }

    /// The first spec wins, a case is reserved and recorded only under the
    /// lease, the first result wins, and a crashed start's reservation stays
    /// counted, on every backend.
    fn contract(db: &RuntimeDb, namespace: &str) {
        let mut first = spec(2, 1_000);
        first.namespace = namespace.into();
        let run_id = first.run_id.clone();
        assert_eq!(db.put_dataset_run(&first, 1).unwrap(), first);
        let mut other = first.clone();
        other.model = "openai/other".into();
        assert_eq!(db.put_dataset_run(&other, 2).unwrap(), first);
        // One start at a time: a held lease refuses another, a lapsed one is
        // taken over, and only the holder renews it.
        assert!(
            db.lease_dataset_run(namespace, &run_id, "a", false, 10, 100)
                .unwrap()
        );
        assert!(
            !db.lease_dataset_run(namespace, &run_id, "b", false, 20, 200)
                .unwrap()
        );
        assert!(
            !db.lease_dataset_run(namespace, &run_id, "b", true, 20, 200)
                .unwrap()
        );
        assert!(
            db.lease_dataset_run(namespace, &run_id, "a", true, 30, 300)
                .unwrap()
        );
        let result = |cost| EvalCaseResult {
            case_id: "case-0001".into(),
            outcome: CaseOutcome {
                passed: true,
                reason: "first".into(),
                input_tokens: 1,
                output_tokens: 1,
                cost_micros: cost,
                receipts: None,
                policy: None,
            },
            recorded_at_ms: 3,
        };
        // Reserved, then recorded: the reservation moves into the ledger.
        assert!(
            db.reserve_dataset_run_case(namespace, &run_id, "a", 100, 40, 300)
                .unwrap()
        );
        assert_eq!(
            db.dataset_run_uncertain_micros(namespace, &run_id).unwrap(),
            100
        );
        assert_eq!(
            db.record_dataset_run_case(namespace, &run_id, "a", &result(7), 100, 41)
                .unwrap(),
            Some(result(7))
        );
        assert_eq!(
            db.dataset_run_uncertain_micros(namespace, &run_id).unwrap(),
            0
        );
        // The first result wins; a holder that is not current records nothing.
        assert!(
            db.reserve_dataset_run_case(namespace, &run_id, "a", 100, 42, 300)
                .unwrap()
        );
        assert_eq!(
            db.record_dataset_run_case(namespace, &run_id, "a", &result(9), 100, 43)
                .unwrap(),
            Some(result(7))
        );
        assert!(
            !db.reserve_dataset_run_case(namespace, &run_id, "b", 100, 44, 300)
                .unwrap()
        );
        // A start that reserves and crashes leaves its reservation counted.
        assert!(
            db.reserve_dataset_run_case(namespace, &run_id, "a", 100, 45, 300)
                .unwrap()
        );
        assert!(
            db.lease_dataset_run(namespace, &run_id, "b", false, 301, 400)
                .unwrap()
        );
        assert_eq!(
            db.record_dataset_run_case(namespace, &run_id, "a", &result(9), 100, 302)
                .unwrap(),
            None
        );
        assert_eq!(
            db.dataset_run_uncertain_micros(namespace, &run_id).unwrap(),
            100
        );
        assert_eq!(
            db.list_dataset_run_cases(namespace, &run_id).unwrap(),
            [result(7)]
        );
        // A start that holds the lease keeps any other from running cases.
        assert_eq!(
            run(db, &Flat, &first, &dataset(4), || 350).unwrap_err(),
            crate::chisei::eval_run::RUN_IN_PROGRESS
        );
        db.release_dataset_run(namespace, &run_id, "b").unwrap();
        // The runner resumes past the recorded case, counting the crashed
        // reservation against the budget but not the ledger.
        let report = run(db, &Flat, &first, &dataset(4), || 500).unwrap();
        assert_eq!(report.status, STATUS_COMPLETED);
        assert_eq!(report.results.len(), 4);
        assert_eq!(report.spent_micros, 7 + 3 * 5);
        assert_eq!(report.uncertain_micros, 100);
        assert_eq!(
            run(db, &Flat, &other, &dataset(4), || 600).unwrap_err(),
            RUN_CONFLICT
        );
    }

    #[test]
    fn sqlite_eval_runs_keep_the_first_spec_and_result() {
        let db = crate::chisei_store::ChiseiStore::memory().runtime_arc();
        contract(db.as_ref(), "acme");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_eval_runs_keep_the_first_spec_and_result() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => sekai_core::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => sekai_core::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = crate::chisei_store::ChiseiStore::from_shared_runtime(Arc::new(
            RuntimeDb::Postgres(Arc::new(db.unwrap())),
        ))
        .runtime_arc();
        // A namespace of its own, so concurrent runs on one database do not
        // share a run.
        let namespace = format!("eval-run-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        contract(db.as_ref(), &namespace);
    }
}

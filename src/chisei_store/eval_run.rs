//! Eval run state (#1674) on both community backends: one row per run with
//! its spec, its lease and the spend reserved for cases not yet recorded,
//! and one row per (run, case) result. A case is reserved and recorded only
//! while its start holds the run's lease, and the first result per case
//! wins, so a restarted, overlapping or lapsed start never records a case
//! twice and never loses track of what a crashed one may have spent.

use crate::chisei::eval_run::{EvalCaseResult, EvalRunSpec};
use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS chisei_dataset_runs (
    namespace TEXT NOT NULL,
    run_id TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    lease_holder TEXT NOT NULL DEFAULT '',
    lease_until_ms INTEGER NOT NULL DEFAULT 0,
    uncertain_micros INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, run_id)
);
CREATE TABLE IF NOT EXISTS chisei_dataset_run_cases (
    namespace TEXT NOT NULL,
    run_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    cost_micros INTEGER NOT NULL,
    recorded_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, run_id, case_id)
);
";

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

impl SekaiDb {
    pub(crate) fn migrate_eval_runs(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    pub fn put_dataset_run(&self, spec: &EvalRunSpec, now_ms: i64) -> Result<EvalRunSpec, String> {
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

    pub fn lease_dataset_run(
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

    pub fn release_dataset_run(
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

    pub fn reserve_dataset_run_case(
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

    pub fn record_dataset_run_case(
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

    pub fn unreserve_dataset_run_case(
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

    pub fn dataset_run_uncertain_micros(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<i64, String> {
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

    pub fn list_dataset_run_cases(
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
}

impl PostgresDb {
    pub fn put_dataset_run(&self, spec: &EvalRunSpec, now_ms: i64) -> Result<EvalRunSpec, String> {
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

    pub fn lease_dataset_run(
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

    pub fn release_dataset_run(
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

    pub fn reserve_dataset_run_case(
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

    pub fn record_dataset_run_case(
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

    pub fn unreserve_dataset_run_case(
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

    pub fn dataset_run_uncertain_micros(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<i64, String> {
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

    pub fn list_dataset_run_cases(
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
}

/// Dispatches to the backend the plane runs on; PostgreSQL off the async
/// runtime.
macro_rules! dispatch {
    ($self:ident, $db:ident => $call:expr) => {
        match $self {
            Self::Sqlite($db) => $call,
            Self::Postgres($db) => crate::db::postgres::off_runtime(|| $call),
        }
    };
}

/// The runner's store over whichever backend the plane runs on.
impl crate::chisei::eval_run::EvalRunStore for crate::db::runtime_db::RuntimeDb {
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
    use crate::db::runtime_db::RuntimeDb;
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
        contract(&RuntimeDb::memory(), "acme");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_eval_runs_keep_the_first_spec_and_result() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(Arc::new(db.unwrap()));
        // A namespace of its own, so concurrent runs on one database do not
        // share a run.
        let namespace = format!("eval-run-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        contract(&db, &namespace);
    }
}

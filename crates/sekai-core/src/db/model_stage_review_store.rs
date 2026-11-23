//! SQLite and PostgreSQL persistence for model stage reviews (#3159).
//!
//! One row per (namespace, model, stage, version). A submission inserts a
//! pending row, and a decision moves it once from pending to approved or
//! rejected. Each write records its operation receipt in the same
//! transaction, and a write that changes nothing records none.

use rusqlite::{OptionalExtension, params};
use sekai_domain::receipt::OperationReceipt;

use super::postgres::PostgresDb;
use super::sekai::SekaiDb;
use crate::sekai::model_stage::{ModelStageReview, ReviewState};

pub(crate) const SQLITE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sekai_model_stage_reviews (
    namespace TEXT NOT NULL,
    model_name TEXT NOT NULL,
    stage TEXT NOT NULL,
    version_id TEXT NOT NULL,
    state TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    submitted_at_ms INTEGER NOT NULL,
    decided_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    decided_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, model_name, stage, version_id)
);";

const COLUMNS: &str = "namespace, model_name, stage, version_id, state, submitted_by, \
     submitted_at_ms, decided_by, reason, decided_at_ms";

/// The key of one review: namespace, model, stage and version.
pub struct ReviewKey<'a> {
    pub namespace: &'a str,
    pub model_name: &'a str,
    pub stage: &'a str,
    pub version_id: &'a str,
}

/// An unknown stored state reads as pending, so it never admits a promotion.
fn parse_state(value: &str) -> ReviewState {
    ReviewState::parse(value).unwrap_or(ReviewState::Pending)
}

fn review_from_sqlite(row: &rusqlite::Row<'_>) -> rusqlite::Result<ModelStageReview> {
    Ok(ModelStageReview {
        namespace: row.get(0)?,
        model_name: row.get(1)?,
        stage: row.get(2)?,
        version_id: row.get(3)?,
        state: parse_state(&row.get::<_, String>(4)?),
        submitted_by: row.get(5)?,
        submitted_at_ms: row.get(6)?,
        decided_by: row.get(7)?,
        reason: row.get(8)?,
        decided_at_ms: row.get(9)?,
    })
}

fn review_from_pg(row: &postgres::Row) -> ModelStageReview {
    ModelStageReview {
        namespace: row.get(0),
        model_name: row.get(1),
        stage: row.get(2),
        version_id: row.get(3),
        state: parse_state(row.get(4)),
        submitted_by: row.get(5),
        submitted_at_ms: row.get(6),
        decided_by: row.get(7),
        reason: row.get(8),
        decided_at_ms: row.get(9),
    }
}

impl SekaiDb {
    pub(crate) fn migrate_model_stage_reviews(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(SQLITE_SCHEMA)
            .map_err(|error| error.to_string())
    }

    pub fn get_model_stage_review(
        &self,
        key: &ReviewKey<'_>,
    ) -> Result<Option<ModelStageReview>, String> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_model_stage_reviews
                     WHERE namespace = ?1 AND model_name = ?2 AND stage = ?3 AND version_id = ?4"
                ),
                params![key.namespace, key.model_name, key.stage, key.version_id],
                review_from_sqlite,
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    /// Inserts the pending `review` and its `receipt`. Returns `false`,
    /// writing nothing, when a review of that version for that stage exists.
    pub fn submit_model_stage_review(
        &self,
        review: &ModelStageReview,
        receipt: &OperationReceipt,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let inserted = tx
            .execute(
                &format!(
                    "INSERT INTO sekai_model_stage_reviews ({COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, '', '', 0)
                     ON CONFLICT (namespace, model_name, stage, version_id) DO NOTHING"
                ),
                params![
                    review.namespace,
                    review.model_name,
                    review.stage,
                    review.version_id,
                    review.submitted_by,
                    review.submitted_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        if inserted != 1 {
            return Ok(false);
        }
        super::chisei_receipt_sqlite::upsert_operation_receipt(&tx, receipt)?;
        super::receipt_chain::append_operation_receipt_chain(&tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// Moves a pending review to `decided`'s state, decider, reason and time,
    /// recording `receipt`. Returns `false`, writing nothing, when the review
    /// is no longer pending or the decider is its submitter.
    pub fn decide_model_stage_review(
        &self,
        decided: &ModelStageReview,
        receipt: &OperationReceipt,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let moved = tx
            .execute(
                "UPDATE sekai_model_stage_reviews
                 SET state = ?1, decided_by = ?2, reason = ?3, decided_at_ms = ?4
                 WHERE namespace = ?5 AND model_name = ?6 AND stage = ?7 AND version_id = ?8
                   AND state = 'pending' AND submitted_by <> ?2",
                params![
                    decided.state.as_str(),
                    decided.decided_by,
                    decided.reason,
                    decided.decided_at_ms,
                    decided.namespace,
                    decided.model_name,
                    decided.stage,
                    decided.version_id
                ],
            )
            .map_err(|error| error.to_string())?;
        if moved != 1 {
            return Ok(false);
        }
        super::chisei_receipt_sqlite::upsert_operation_receipt(&tx, receipt)?;
        super::receipt_chain::append_operation_receipt_chain(&tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

impl PostgresDb {
    /// See [`SekaiDb::get_model_stage_review`].
    pub fn get_model_stage_review(
        &self,
        key: &ReviewKey<'_>,
    ) -> Result<Option<ModelStageReview>, String> {
        Ok(self
            .connection()?
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_model_stage_reviews
                     WHERE namespace = $1 AND model_name = $2 AND stage = $3 AND version_id = $4"
                ),
                &[&key.namespace, &key.model_name, &key.stage, &key.version_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| review_from_pg(&row)))
    }

    /// See [`SekaiDb::submit_model_stage_review`].
    pub fn submit_model_stage_review(
        &self,
        review: &ModelStageReview,
        receipt: &OperationReceipt,
    ) -> Result<bool, String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let inserted = tx
            .execute(
                &format!(
                    "INSERT INTO sekai_model_stage_reviews ({COLUMNS})
                     VALUES ($1, $2, $3, $4, 'pending', $5, $6, '', '', 0)
                     ON CONFLICT (namespace, model_name, stage, version_id) DO NOTHING"
                ),
                &[
                    &review.namespace,
                    &review.model_name,
                    &review.stage,
                    &review.version_id,
                    &review.submitted_by,
                    &review.submitted_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        if inserted != 1 {
            return Ok(false);
        }
        self.upsert_operation_receipt_on(&mut tx, receipt)?;
        super::postgres_receipt_chain::append_operation_receipt_chain(&mut tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// See [`SekaiDb::decide_model_stage_review`].
    pub fn decide_model_stage_review(
        &self,
        decided: &ModelStageReview,
        receipt: &OperationReceipt,
    ) -> Result<bool, String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let moved = tx
            .execute(
                "UPDATE sekai_model_stage_reviews
                 SET state = $1, decided_by = $2, reason = $3, decided_at_ms = $4
                 WHERE namespace = $5 AND model_name = $6 AND stage = $7 AND version_id = $8
                   AND state = 'pending' AND submitted_by <> $2",
                &[
                    &decided.state.as_str(),
                    &decided.decided_by,
                    &decided.reason,
                    &decided.decided_at_ms,
                    &decided.namespace,
                    &decided.model_name,
                    &decided.stage,
                    &decided.version_id,
                ],
            )
            .map_err(|error| error.to_string())?;
        if moved != 1 {
            return Ok(false);
        }
        self.upsert_operation_receipt_on(&mut tx, receipt)?;
        super::postgres_receipt_chain::append_operation_receipt_chain(&mut tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::ReviewKey;
    use crate::db::model_stage_store::store_tests::receipt;
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::model_stage::{ModelStageReview, ReviewState};

    fn pending(version_id: &str) -> ModelStageReview {
        ModelStageReview {
            namespace: "ml".into(),
            model_name: "churn".into(),
            stage: "production".into(),
            version_id: version_id.into(),
            state: ReviewState::Pending,
            submitted_by: "alice".into(),
            submitted_at_ms: 1,
            decided_by: String::new(),
            reason: String::new(),
            decided_at_ms: 0,
        }
    }

    /// A submission inserts once; a decision applies once, never by the
    /// submitter; each applied write records its receipt and a refused one
    /// records none.
    fn reviews_submit_and_decide_once(db: &RuntimeDb) {
        let key = ReviewKey {
            namespace: "ml",
            model_name: "churn",
            stage: "production",
            version_id: "mv_1",
        };
        assert!(db.get_model_stage_review(&key).unwrap().is_none());
        assert!(
            db.submit_model_stage_review(&pending("mv_1"), &receipt("sub-1"))
                .unwrap()
        );
        assert!(
            !db.submit_model_stage_review(&pending("mv_1"), &receipt("sub-2"))
                .unwrap()
        );
        assert!(db.get_operation_receipt("sub-2").unwrap().is_none());

        let decide = |by: &str, state| ModelStageReview {
            state,
            decided_by: by.into(),
            reason: "looks right".into(),
            decided_at_ms: 2,
            ..pending("mv_1")
        };
        assert!(
            !db.decide_model_stage_review(&decide("alice", ReviewState::Approved), &receipt("d-0"))
                .unwrap()
        );
        assert_eq!(
            db.get_model_stage_review(&key).unwrap().unwrap().state,
            ReviewState::Pending
        );
        assert!(
            db.decide_model_stage_review(&decide("bob", ReviewState::Approved), &receipt("d-1"))
                .unwrap()
        );
        assert!(db.get_operation_receipt("d-1").unwrap().is_some());
        // A decision is final.
        assert!(
            !db.decide_model_stage_review(&decide("carol", ReviewState::Rejected), &receipt("d-2"))
                .unwrap()
        );
        assert!(db.get_operation_receipt("d-2").unwrap().is_none());
        let stored = db.get_model_stage_review(&key).unwrap().unwrap();
        assert_eq!(stored, decide("bob", ReviewState::Approved));
    }

    #[test]
    fn sqlite_reviews_submit_and_decide_once() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        reviews_submit_and_decide_once(&db);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_reviews_submit_and_decide_once() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        reviews_submit_and_decide_once(&db);
    }
}

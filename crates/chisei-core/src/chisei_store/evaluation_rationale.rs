//! Retained judge rationale (#2630) on both community backends. One row per
//! (operation, node, trial slot), written once; expired rows are deleted by
//! the rationale sweep.

use crate::chisei::evaluation_rationale::{
    EvaluationRationale, EvaluationRationaleStore, RationaleKey,
};
use sekai_core::db::postgres::PostgresDb;
use sekai_core::db::runtime_db::RuntimeDb;
use sekai_core::db::sekai::SekaiDb;

pub(crate) const SQLITE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS chisei_evaluation_rationales (
    operation_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    trial_index INTEGER NOT NULL,
    namespace TEXT NOT NULL,
    rationale TEXT NOT NULL,
    rationale_digest TEXT NOT NULL,
    evidence_object_ids TEXT NOT NULL,
    classification TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY (operation_id, node_id, trial_index)
);
CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_rationales_expiry
    ON chisei_evaluation_rationales (expires_at_ms);
";

const COLUMNS: &str = "operation_id, node_id, trial_index, namespace, rationale, rationale_digest, \
     evidence_object_ids, classification, created_at_ms, expires_at_ms";

type Row = (
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
);

fn decode(row: Row) -> Result<EvaluationRationale, String> {
    let (
        operation_id,
        node_id,
        trial_index,
        namespace,
        rationale,
        rationale_digest,
        evidence_object_ids,
        classification,
        created_at_ms,
        expires_at_ms,
    ) = row;
    Ok(EvaluationRationale {
        operation_id,
        node_id,
        trial_index: u32::try_from(trial_index).map_err(|error| error.to_string())?,
        namespace,
        rationale,
        rationale_digest,
        evidence_object_ids: serde_json::from_str(&evidence_object_ids)
            .map_err(|error| format!("corrupt evaluation rationale evidence: {error}"))?,
        classification,
        created_at_ms,
        expires_at_ms,
    })
}

fn evidence_json(rationale: &EvaluationRationale) -> Result<String, String> {
    serde_json::to_string(&rationale.evidence_object_ids).map_err(|error| error.to_string())
}

fn sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn postgres_row(row: &postgres::Row) -> Row {
    (
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
        row.get(6),
        row.get(7),
        row.get(8),
        row.get(9),
    )
}

/// The key to page after; the empty key sorts before every stored one.
fn after_params(after: Option<&RationaleKey>) -> (String, String, i64) {
    after.map_or((String::new(), String::new(), -1), |(op, node, trial)| {
        (op.clone(), node.clone(), i64::from(*trial))
    })
}

impl EvaluationRationaleStore for SekaiDb {
    fn put_evaluation_rationales(&self, rationales: &[EvaluationRationale]) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        for rationale in rationales {
            tx.execute(
                &format!(
                    "INSERT INTO chisei_evaluation_rationales ({COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) ON CONFLICT DO NOTHING"
                ),
                rusqlite::params![
                    rationale.operation_id,
                    rationale.node_id,
                    i64::from(rationale.trial_index),
                    rationale.namespace,
                    rationale.rationale,
                    rationale.rationale_digest,
                    evidence_json(rationale)?,
                    rationale.classification,
                    rationale.created_at_ms,
                    rationale.expires_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    fn get_evaluation_rationale(
        &self,
        operation_id: &str,
        node_id: &str,
        trial_index: u32,
    ) -> Result<Option<EvaluationRationale>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM chisei_evaluation_rationales
                     WHERE operation_id = ?1 AND node_id = ?2 AND trial_index = ?3"
                ),
                rusqlite::params![operation_id, node_id, i64::from(trial_index)],
                sqlite_row,
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(decode)
            .transpose()
    }

    fn delete_evaluation_rationale(
        &self,
        operation_id: &str,
        node_id: &str,
        trial_index: u32,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "DELETE FROM chisei_evaluation_rationales
                 WHERE operation_id = ?1 AND node_id = ?2 AND trial_index = ?3",
                rusqlite::params![operation_id, node_id, i64::from(trial_index)],
            )
            .map(drop)
            .map_err(|error| error.to_string())
    }

    fn delete_expired_evaluation_rationales(&self, now_ms: i64) -> Result<u64, String> {
        self.conn()
            .execute(
                "DELETE FROM chisei_evaluation_rationales WHERE expires_at_ms <= ?1",
                [now_ms],
            )
            .map(|deleted| deleted as u64)
            .map_err(|error| error.to_string())
    }

    fn list_evaluation_rationales(
        &self,
        after: Option<&RationaleKey>,
        limit: usize,
    ) -> Result<Vec<EvaluationRationale>, String> {
        let (operation_id, node_id, trial_index) = after_params(after);
        let limit = i64::try_from(limit).map_err(|error| error.to_string())?;
        let conn = self.conn();
        let mut statement = conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM chisei_evaluation_rationales
                 WHERE (operation_id, node_id, trial_index) > (?1, ?2, ?3)
                 ORDER BY operation_id, node_id, trial_index LIMIT ?4"
            ))
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![operation_id, node_id, trial_index, limit],
                sqlite_row,
            )
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        rows.into_iter().map(decode).collect()
    }
}

impl EvaluationRationaleStore for PostgresDb {
    fn put_evaluation_rationales(&self, rationales: &[EvaluationRationale]) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for rationale in rationales {
            tx.execute(
                &format!(
                    "INSERT INTO chisei_evaluation_rationales ({COLUMNS})
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING"
                ),
                &[
                    &rationale.operation_id,
                    &rationale.node_id,
                    &i64::from(rationale.trial_index),
                    &rationale.namespace,
                    &rationale.rationale,
                    &rationale.rationale_digest,
                    &evidence_json(rationale)?,
                    &rationale.classification,
                    &rationale.created_at_ms,
                    &rationale.expires_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    fn get_evaluation_rationale(
        &self,
        operation_id: &str,
        node_id: &str,
        trial_index: u32,
    ) -> Result<Option<EvaluationRationale>, String> {
        self.connection()?
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM chisei_evaluation_rationales
                     WHERE operation_id = $1 AND node_id = $2 AND trial_index = $3"
                ),
                &[&operation_id, &node_id, &i64::from(trial_index)],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode(postgres_row(&row)))
            .transpose()
    }

    fn delete_evaluation_rationale(
        &self,
        operation_id: &str,
        node_id: &str,
        trial_index: u32,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM chisei_evaluation_rationales
                 WHERE operation_id = $1 AND node_id = $2 AND trial_index = $3",
                &[&operation_id, &node_id, &i64::from(trial_index)],
            )
            .map(drop)
            .map_err(|error| error.to_string())
    }

    fn delete_expired_evaluation_rationales(&self, now_ms: i64) -> Result<u64, String> {
        self.connection()?
            .execute(
                "DELETE FROM chisei_evaluation_rationales WHERE expires_at_ms <= $1",
                &[&now_ms],
            )
            .map_err(|error| error.to_string())
    }

    fn list_evaluation_rationales(
        &self,
        after: Option<&RationaleKey>,
        limit: usize,
    ) -> Result<Vec<EvaluationRationale>, String> {
        let (operation_id, node_id, trial_index) = after_params(after);
        let limit = i64::try_from(limit).map_err(|error| error.to_string())?;
        self.connection()?
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM chisei_evaluation_rationales
                     WHERE (operation_id, node_id, trial_index) > ($1, $2, $3)
                     ORDER BY operation_id, node_id, trial_index LIMIT $4"
                ),
                &[&operation_id, &node_id, &trial_index, &limit],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| decode(postgres_row(row)))
            .collect()
    }
}

/// Dispatches to the backend the plane runs on; PostgreSQL off the async
/// runtime.
impl EvaluationRationaleStore for RuntimeDb {
    fn put_evaluation_rationales(&self, rationales: &[EvaluationRationale]) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_evaluation_rationales(rationales),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.put_evaluation_rationales(rationales))
            }
        }
    }

    fn get_evaluation_rationale(
        &self,
        operation_id: &str,
        node_id: &str,
        trial_index: u32,
    ) -> Result<Option<EvaluationRationale>, String> {
        match self {
            Self::Sqlite(db) => db.get_evaluation_rationale(operation_id, node_id, trial_index),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_evaluation_rationale(operation_id, node_id, trial_index)
            }),
        }
    }

    fn delete_evaluation_rationale(
        &self,
        operation_id: &str,
        node_id: &str,
        trial_index: u32,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_evaluation_rationale(operation_id, node_id, trial_index),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.delete_evaluation_rationale(operation_id, node_id, trial_index)
            }),
        }
    }

    fn delete_expired_evaluation_rationales(&self, now_ms: i64) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.delete_expired_evaluation_rationales(now_ms),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.delete_expired_evaluation_rationales(now_ms)
            }),
        }
    }

    fn list_evaluation_rationales(
        &self,
        after: Option<&RationaleKey>,
        limit: usize,
    ) -> Result<Vec<EvaluationRationale>, String> {
        match self {
            Self::Sqlite(db) => db.list_evaluation_rationales(after, limit),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_evaluation_rationales(after, limit)
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::chisei::evaluation_rationale::{EvaluationRationale, EvaluationRationaleStore};
    use sekai_core::db::runtime_db::RuntimeDb;

    fn rationale(operation_id: &str, trial_index: u32, expires_at_ms: i64) -> EvaluationRationale {
        EvaluationRationale {
            operation_id: operation_id.into(),
            node_id: "judge".into(),
            trial_index,
            namespace: "ml".into(),
            rationale: format!("why {trial_index}"),
            rationale_digest: format!("sha256:{trial_index}"),
            evidence_object_ids: vec!["evidence-1".into()],
            classification: "internal".into(),
            created_at_ms: 1,
            expires_at_ms,
        }
    }

    /// A rationale is written once, pages in key order, and leaves at its TTL.
    /// Operation ids carry a unique prefix, so runs sharing a database do not
    /// see each other's rows.
    fn rationale_store_contract(db: &RuntimeDb) {
        let prefix = format!(
            "op-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let (a, b) = (format!("{prefix}-a"), format!("{prefix}-b"));
        let first = rationale(&a, 0, 100);
        db.put_evaluation_rationales(&[first.clone(), rationale(&a, 1, 200)])
            .unwrap();
        // A repeat of a stored key keeps the first write.
        let mut changed = first.clone();
        changed.rationale = "rewritten".into();
        db.put_evaluation_rationales(&[changed, rationale(&b, 0, 300)])
            .unwrap();
        assert_eq!(
            db.get_evaluation_rationale(&a, "judge", 0).unwrap(),
            Some(first.clone())
        );
        let mine = |after: Option<&crate::chisei::evaluation_rationale::RationaleKey>| -> Vec<_> {
            db.list_evaluation_rationales(after, 1_000)
                .unwrap()
                .into_iter()
                .filter(|row| row.operation_id.starts_with(&prefix))
                .map(|row| row.key())
                .collect()
        };
        let first_key = first.key();
        assert_eq!(
            mine(Some(&first_key)),
            [
                (a.clone(), "judge".to_string(), 1),
                (b.clone(), "judge".to_string(), 0)
            ]
        );
        assert_eq!(mine(None).len(), 3);

        assert!(db.delete_expired_evaluation_rationales(200).unwrap() >= 2);
        assert!(
            db.get_evaluation_rationale(&a, "judge", 1)
                .unwrap()
                .is_none()
        );
        db.delete_evaluation_rationale(&b, "judge", 0).unwrap();
        assert!(mine(None).is_empty());
    }

    #[test]
    fn sqlite_rationale_store_contract() {
        let db = crate::chisei_store::ChiseiStore::memory().runtime_arc();
        rationale_store_contract(db.as_ref());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_rationale_store_contract() {
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
        let store = crate::chisei_store::ChiseiStore::from_shared_runtime(Arc::new(
            RuntimeDb::Postgres(Arc::new(db.unwrap())),
        ))
        .runtime_arc();
        rationale_store_contract(store.as_ref());
    }
}

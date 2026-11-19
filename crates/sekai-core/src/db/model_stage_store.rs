//! SQLite and PostgreSQL persistence for model stages (#3023).
//!
//! A stage row names the version one model's consumers use. Promotion moves
//! it with a compare-and-set on the current version and writes its receipt in
//! the same transaction, so a stage never moves without a receipt and two
//! concurrent promotions cannot both apply.

use rusqlite::{OptionalExtension, params};
use sekai_domain::receipt::OperationReceipt;

use super::postgres::PostgresDb;
use super::sekai::SekaiDb;
use crate::sekai::model_stage::{MODEL_STAGE_NOT_FOUND, ModelStage};
use crate::sekai::model_version::ModelVersion;

pub(crate) const SQLITE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sekai_model_stages (
    namespace TEXT NOT NULL,
    model_name TEXT NOT NULL,
    stage TEXT NOT NULL,
    evaluation_suite_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, model_name, stage)
);";

const COLUMNS: &str =
    "namespace, model_name, stage, evaluation_suite_id, version_id, updated_at_ms";

fn stage_from_sqlite(row: &rusqlite::Row<'_>) -> rusqlite::Result<ModelStage> {
    Ok(ModelStage {
        namespace: row.get(0)?,
        model_name: row.get(1)?,
        stage: row.get(2)?,
        evaluation_suite_id: row.get(3)?,
        version_id: row.get(4)?,
        updated_at_ms: row.get(5)?,
    })
}

fn stage_from_pg(row: &postgres::Row) -> ModelStage {
    ModelStage {
        namespace: row.get(0),
        model_name: row.get(1),
        stage: row.get(2),
        evaluation_suite_id: row.get(3),
        version_id: row.get(4),
        updated_at_ms: row.get(5),
    }
}

/// The version a stage pin resolves to inside a run admission. A missing stage
/// or one with no version yet refuses the run.
pub(crate) fn stage_version_sqlite(
    conn: &rusqlite::Connection,
    namespace: &str,
    model_name: &str,
    stage: &str,
) -> Result<String, String> {
    conn.query_row(
        "SELECT version_id FROM sekai_model_stages
         WHERE namespace = ?1 AND model_name = ?2 AND stage = ?3",
        params![namespace, model_name, stage],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|error| error.to_string())?
    .filter(|version_id| !version_id.is_empty())
    .ok_or_else(|| MODEL_STAGE_NOT_FOUND.to_string())
}

/// See [`stage_version_sqlite`].
pub(crate) fn stage_version_pg(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    model_name: &str,
    stage: &str,
) -> Result<String, String> {
    tx.query_opt(
        "SELECT version_id FROM sekai_model_stages
         WHERE namespace = $1 AND model_name = $2 AND stage = $3",
        &[&namespace, &model_name, &stage],
    )
    .map_err(|error| error.to_string())?
    .map(|row| row.get::<_, String>(0))
    .filter(|version_id| !version_id.is_empty())
    .ok_or_else(|| MODEL_STAGE_NOT_FOUND.to_string())
}

const FOLLOW_SQLITE: &str = "UPDATE sekai_model_stages SET version_id = ?1, updated_at_ms = ?2
     WHERE namespace = ?3 AND model_name = ?4 AND evaluation_suite_id = ''";

/// Moves `version`'s gateless stages to it, in the registering transaction.
pub(crate) fn follow_gateless_stages_sqlite(
    tx: &rusqlite::Transaction<'_>,
    version: &ModelVersion,
) -> Result<(), String> {
    tx.execute(
        FOLLOW_SQLITE,
        params![
            version.version_id,
            version.created_at_ms,
            version.namespace,
            version.model_name
        ],
    )
    .map(drop)
    .map_err(|error| error.to_string())
}

/// See [`follow_gateless_stages_sqlite`].
pub(crate) fn follow_gateless_stages_pg(
    tx: &mut postgres::Transaction<'_>,
    version: &ModelVersion,
) -> Result<(), String> {
    tx.execute(
        "UPDATE sekai_model_stages SET version_id = $1, updated_at_ms = $2
         WHERE namespace = $3 AND model_name = $4 AND evaluation_suite_id = ''",
        &[
            &version.version_id,
            &version.created_at_ms,
            &version.namespace,
            &version.model_name,
        ],
    )
    .map(drop)
    .map_err(|error| error.to_string())
}

impl SekaiDb {
    pub(crate) fn migrate_model_stages(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(SQLITE_SCHEMA)
            .map_err(|error| error.to_string())
    }

    /// Creates a stage or changes its gate; a stage's current version is kept.
    pub fn put_model_stage(&self, stage: &ModelStage) -> Result<ModelStage, String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_model_stages (namespace, model_name, stage, evaluation_suite_id, version_id, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (namespace, model_name, stage) DO UPDATE
                 SET evaluation_suite_id = excluded.evaluation_suite_id,
                     updated_at_ms = excluded.updated_at_ms",
                params![
                    stage.namespace,
                    stage.model_name,
                    stage.stage,
                    stage.evaluation_suite_id,
                    stage.version_id,
                    stage.updated_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_model_stage(&stage.namespace, &stage.model_name, &stage.stage)?
            .ok_or_else(|| "model stage vanished after put".into())
    }

    pub fn get_model_stage(
        &self,
        namespace: &str,
        model_name: &str,
        stage: &str,
    ) -> Result<Option<ModelStage>, String> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_model_stages
                     WHERE namespace = ?1 AND model_name = ?2 AND stage = ?3"
                ),
                params![namespace, model_name, stage],
                stage_from_sqlite,
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    /// Stages in `namespace` ordered by model and stage; an empty `model_name`
    /// lists every model's stages.
    pub fn list_model_stages(
        &self,
        namespace: &str,
        model_name: &str,
    ) -> Result<Vec<ModelStage>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM sekai_model_stages
                 WHERE namespace = ?1 AND (?2 = '' OR model_name = ?2)
                 ORDER BY model_name, stage"
            ))
            .map_err(|error| error.to_string())?;
        statement
            .query_map(params![namespace, model_name], stage_from_sqlite)
            .map_err(|error| error.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|error| error.to_string())
    }

    /// Moves `stage` from `expected_version_id` to its new `version_id` and
    /// records `receipt` in one transaction. Returns `false`, writing nothing,
    /// when the stage no longer holds `expected_version_id`.
    pub fn promote_model_stage(
        &self,
        stage: &ModelStage,
        expected_version_id: &str,
        receipt: &OperationReceipt,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let moved = tx
            .execute(
                "UPDATE sekai_model_stages SET version_id = ?1, updated_at_ms = ?2
                 WHERE namespace = ?3 AND model_name = ?4 AND stage = ?5 AND version_id = ?6",
                params![
                    stage.version_id,
                    stage.updated_at_ms,
                    stage.namespace,
                    stage.model_name,
                    stage.stage,
                    expected_version_id
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
    /// See [`SekaiDb::put_model_stage`].
    pub fn put_model_stage(&self, stage: &ModelStage) -> Result<ModelStage, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_model_stages (namespace, model_name, stage, evaluation_suite_id, version_id, updated_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (namespace, model_name, stage) DO UPDATE
                 SET evaluation_suite_id = EXCLUDED.evaluation_suite_id,
                     updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &stage.namespace,
                    &stage.model_name,
                    &stage.stage,
                    &stage.evaluation_suite_id,
                    &stage.version_id,
                    &stage.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_model_stage(&stage.namespace, &stage.model_name, &stage.stage)?
            .ok_or_else(|| "model stage vanished after put".into())
    }

    pub fn get_model_stage(
        &self,
        namespace: &str,
        model_name: &str,
        stage: &str,
    ) -> Result<Option<ModelStage>, String> {
        Ok(self
            .connection()?
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_model_stages
                     WHERE namespace = $1 AND model_name = $2 AND stage = $3"
                ),
                &[&namespace, &model_name, &stage],
            )
            .map_err(|error| error.to_string())?
            .map(|row| stage_from_pg(&row)))
    }

    pub fn list_model_stages(
        &self,
        namespace: &str,
        model_name: &str,
    ) -> Result<Vec<ModelStage>, String> {
        Ok(self
            .connection()?
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_model_stages
                     WHERE namespace = $1 AND ($2 = '' OR model_name = $2)
                     ORDER BY model_name, stage"
                ),
                &[&namespace, &model_name],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(stage_from_pg)
            .collect())
    }

    /// See [`SekaiDb::promote_model_stage`].
    pub fn promote_model_stage(
        &self,
        stage: &ModelStage,
        expected_version_id: &str,
        receipt: &OperationReceipt,
    ) -> Result<bool, String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let moved = tx
            .execute(
                "UPDATE sekai_model_stages SET version_id = $1, updated_at_ms = $2
                 WHERE namespace = $3 AND model_name = $4 AND stage = $5 AND version_id = $6",
                &[
                    &stage.version_id,
                    &stage.updated_at_ms,
                    &stage.namespace,
                    &stage.model_name,
                    &stage.stage,
                    &expected_version_id,
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
pub(crate) mod store_tests {
    use std::collections::BTreeMap;

    use sekai_domain::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    };

    use crate::db::model_version_store::store_tests::version;
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::model_stage::ModelStage;

    pub(crate) fn stage(name: &str, suite: &str) -> ModelStage {
        ModelStage {
            namespace: "ml".into(),
            model_name: "churn".into(),
            stage: name.into(),
            evaluation_suite_id: suite.into(),
            version_id: String::new(),
            updated_at_ms: 1,
        }
    }

    pub(crate) fn receipt(operation_id: &str) -> OperationReceipt {
        let kind = ReceiptEventKind::PolicyDecided;
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.into(),
            parent_operation_id: None,
            namespace: "ml".into(),
            operation_class: crate::sekai::model_stage::PROMOTION_OPERATION_CLASS.into(),
            initiating_actor: "operator".into(),
            schema_version: "model_stage/v1".into(),
            policy_version: "model_stage/v1".into(),
            started_at_ms: 10,
            completed_at_ms: Some(10),
            events: vec![OperationReceiptEvent {
                event_id: format!("{operation_id}-policy"),
                operation_id: operation_id.into(),
                parent_event_id: None,
                timestamp_ms: 10,
                kind,
                surface: kind.surface(),
                actor: "operator".into(),
                references: Vec::new(),
                attributes: BTreeMap::new(),
            }],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        }
    }

    /// A gateless stage follows each registered version; a gated one moves
    /// only by a compare-and-set promotion that records its receipt, and a
    /// lost race writes neither the move nor the receipt.
    pub(crate) fn stages_follow_and_promote(db: &RuntimeDb) {
        db.put_model_stage(&stage("latest", "")).unwrap();
        db.put_model_stage(&stage("production", "suite-a")).unwrap();
        let first = db.insert_model_version(&version("sha256:a", 2)).unwrap();
        let get = |name: &str| db.get_model_stage("ml", "churn", name).unwrap().unwrap();
        assert_eq!(get("latest").version_id, first.version_id);
        assert_eq!(get("production").version_id, "");

        let promoted = ModelStage {
            version_id: first.version_id.clone(),
            updated_at_ms: 3,
            ..stage("production", "suite-a")
        };
        assert!(
            db.promote_model_stage(&promoted, "", &receipt("op-1"))
                .unwrap()
        );
        assert!(db.get_operation_receipt("op-1").unwrap().is_some());
        // A promotion that expected the old version lost the race.
        assert!(
            !db.promote_model_stage(&promoted, "", &receipt("op-2"))
                .unwrap()
        );
        assert!(db.get_operation_receipt("op-2").unwrap().is_none());

        let second = db.insert_model_version(&version("sha256:b", 4)).unwrap();
        assert_eq!(get("latest").version_id, second.version_id);
        assert_eq!(get("production").version_id, first.version_id);

        // Changing a gate keeps the stage's version.
        db.put_model_stage(&stage("production", "suite-b")).unwrap();
        let regated = get("production");
        assert_eq!(regated.evaluation_suite_id, "suite-b");
        assert_eq!(regated.version_id, first.version_id);
        let names: Vec<_> = db
            .list_model_stages("ml", "")
            .unwrap()
            .into_iter()
            .map(|stage| stage.stage)
            .collect();
        assert_eq!(names, ["latest", "production"]);
        assert!(db.list_model_stages("ml", "other").unwrap().is_empty());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;

    #[test]
    fn sqlite_stages_follow_and_promote() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        super::store_tests::stages_follow_and_promote(&db);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_stages_follow_and_promote() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        super::store_tests::stages_follow_and_promote(&db);
    }
}

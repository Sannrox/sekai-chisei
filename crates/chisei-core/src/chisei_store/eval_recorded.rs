//! Stored recorded eval dataset definitions (ADR 0153, #3513) on both
//! community backends: one row per (namespace, name, version), written once,
//! with the same "current version" rule as `eval_dataset.rs`. The row holds
//! case references only (instance id, request digest, decision, decided at).

use crate::chisei::eval_dataset::recorded::{
    RecordedEvalDatasetDefinition, RecordedEvalDatasetStore, StoredRecordedEvalDataset,
};
use sekai_core::db::postgres::PostgresDb;
use sekai_core::db::sekai::SekaiDb;

const COLUMNS: &str =
    "namespace, definition_json, version, digest, case_count, created_by, created_at_ms";

const CURRENT: &str = "NOT EXISTS (
    SELECT 1 FROM chisei_eval_recorded_datasets AS later
    WHERE later.namespace = d.namespace AND later.name = d.name
      AND (later.created_at_ms > d.created_at_ms
           OR (later.created_at_ms = d.created_at_ms AND later.version > d.version)))";

const INSERT_SQLITE: &str = "INSERT INTO chisei_eval_recorded_datasets
     (namespace, name, version, definition_json, digest, case_count, created_by, created_at_ms)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT DO NOTHING";
const INSERT_POSTGRES: &str = "INSERT INTO chisei_eval_recorded_datasets
     (namespace, name, version, definition_json, digest, case_count, created_by, created_at_ms)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING";

type Row = (String, String, String, String, i64, String, i64);

fn record_from(row: Row) -> Result<StoredRecordedEvalDataset, String> {
    let (namespace, json, version, digest, case_count, created_by, created_at_ms) = row;
    let definition: RecordedEvalDatasetDefinition = serde_json::from_str(&json)
        .map_err(|error| format!("corrupt recorded eval dataset definition: {error}"))?;
    Ok(StoredRecordedEvalDataset {
        namespace,
        definition,
        version,
        digest,
        case_count: u64::try_from(case_count).map_err(|error| error.to_string())?,
        created_by,
        created_at_ms,
    })
}

fn columns_of(record: &StoredRecordedEvalDataset) -> Result<(String, i64), String> {
    Ok((
        serde_json::to_string(&record.definition).map_err(|error| error.to_string())?,
        i64::try_from(record.case_count).map_err(|error| error.to_string())?,
    ))
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
    )
}

fn select_version(placeholder: [&str; 3]) -> String {
    let [namespace, name, version] = placeholder;
    format!(
        "SELECT {COLUMNS} FROM chisei_eval_recorded_datasets
         WHERE namespace = {namespace} AND name = {name} AND version = {version}"
    )
}

fn select_current(placeholder: [&str; 2]) -> String {
    let [namespace, name] = placeholder;
    format!(
        "SELECT {COLUMNS} FROM chisei_eval_recorded_datasets AS d
         WHERE namespace = {namespace} AND name = {name} AND {CURRENT}"
    )
}

fn select_page(placeholder: [&str; 3]) -> String {
    let [namespace, after, limit] = placeholder;
    format!(
        "SELECT {COLUMNS} FROM chisei_eval_recorded_datasets AS d
         WHERE namespace = {namespace} AND name > {after} AND {CURRENT}
         ORDER BY name LIMIT {limit}"
    )
}

impl RecordedEvalDatasetStore for SekaiDb {
    fn put_recorded_eval_dataset(
        &self,
        record: &StoredRecordedEvalDataset,
    ) -> Result<StoredRecordedEvalDataset, String> {
        let (json, case_count) = columns_of(record)?;
        let name = &record.definition.selection.name;
        let conn = self.conn();
        conn.execute(
            INSERT_SQLITE,
            rusqlite::params![
                record.namespace,
                name,
                record.version,
                json,
                record.digest,
                case_count,
                record.created_by,
                record.created_at_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        let row = conn
            .query_row(
                &select_version(["?1", "?2", "?3"]),
                rusqlite::params![record.namespace, name, record.version],
                sqlite_row,
            )
            .map_err(|error| error.to_string())?;
        record_from(row)
    }

    fn get_recorded_eval_dataset(
        &self,
        namespace: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<StoredRecordedEvalDataset>, String> {
        use rusqlite::OptionalExtension;
        let conn = self.conn();
        match version {
            Some(version) => conn
                .query_row(
                    &select_version(["?1", "?2", "?3"]),
                    rusqlite::params![namespace, name, version],
                    sqlite_row,
                )
                .optional(),
            None => conn
                .query_row(
                    &select_current(["?1", "?2"]),
                    rusqlite::params![namespace, name],
                    sqlite_row,
                )
                .optional(),
        }
        .map_err(|error| error.to_string())?
        .map(record_from)
        .transpose()
    }

    fn list_recorded_eval_datasets(
        &self,
        namespace: &str,
        after_name: &str,
        limit: usize,
    ) -> Result<Vec<StoredRecordedEvalDataset>, String> {
        let limit = i64::try_from(limit).map_err(|error| error.to_string())?;
        let conn = self.conn();
        let mut statement = conn
            .prepare(&select_page(["?1", "?2", "?3"]))
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![namespace, after_name, limit], sqlite_row)
            .map_err(|error| error.to_string())?;
        rows.map(|row| record_from(row.map_err(|error| error.to_string())?))
            .collect()
    }
}

impl RecordedEvalDatasetStore for PostgresDb {
    fn put_recorded_eval_dataset(
        &self,
        record: &StoredRecordedEvalDataset,
    ) -> Result<StoredRecordedEvalDataset, String> {
        let (json, case_count) = columns_of(record)?;
        let name = &record.definition.selection.name;
        let mut connection = self.connection()?;
        connection
            .execute(
                INSERT_POSTGRES,
                &[
                    &record.namespace,
                    name,
                    &record.version,
                    &json,
                    &record.digest,
                    &case_count,
                    &record.created_by,
                    &record.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        let row = connection
            .query_one(
                &select_version(["$1", "$2", "$3"]),
                &[&record.namespace, name, &record.version],
            )
            .map_err(|error| error.to_string())?;
        record_from(postgres_row(&row))
    }

    fn get_recorded_eval_dataset(
        &self,
        namespace: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<StoredRecordedEvalDataset>, String> {
        let mut connection = self.connection()?;
        match version {
            Some(version) => connection.query_opt(
                &select_version(["$1", "$2", "$3"]),
                &[&namespace, &name, &version],
            ),
            None => connection.query_opt(&select_current(["$1", "$2"]), &[&namespace, &name]),
        }
        .map_err(|error| error.to_string())?
        .map(|row| record_from(postgres_row(&row)))
        .transpose()
    }

    fn list_recorded_eval_datasets(
        &self,
        namespace: &str,
        after_name: &str,
        limit: usize,
    ) -> Result<Vec<StoredRecordedEvalDataset>, String> {
        let limit = i64::try_from(limit).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        connection
            .query(
                &select_page(["$1", "$2", "$3"]),
                &[&namespace, &after_name, &limit],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| record_from(postgres_row(row)))
            .collect()
    }
}

/// Dispatches to the backend the plane runs on; PostgreSQL off the async
/// runtime.
impl RecordedEvalDatasetStore for sekai_core::db::runtime_db::RuntimeDb {
    fn put_recorded_eval_dataset(
        &self,
        record: &StoredRecordedEvalDataset,
    ) -> Result<StoredRecordedEvalDataset, String> {
        match self {
            Self::Sqlite(db) => db.put_recorded_eval_dataset(record),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.put_recorded_eval_dataset(record))
            }
        }
    }

    fn get_recorded_eval_dataset(
        &self,
        namespace: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<StoredRecordedEvalDataset>, String> {
        match self {
            Self::Sqlite(db) => db.get_recorded_eval_dataset(namespace, name, version),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_recorded_eval_dataset(namespace, name, version)
            }),
        }
    }

    fn list_recorded_eval_datasets(
        &self,
        namespace: &str,
        after_name: &str,
        limit: usize,
    ) -> Result<Vec<StoredRecordedEvalDataset>, String> {
        match self {
            Self::Sqlite(db) => db.list_recorded_eval_datasets(namespace, after_name, limit),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_recorded_eval_datasets(namespace, after_name, limit)
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::eval_dataset::recorded::{
        DECISION_DENY, DECISION_GRANT, RECORDED_DATASET_DEFINITION_CONTRACT, RecordedCase,
        RecordedDatasetSelection,
    };
    use sekai_core::db::runtime_db::RuntimeDb;
    use std::sync::Arc;

    fn record(namespace: &str, cases: &[(&str, &str)], at: i64) -> StoredRecordedEvalDataset {
        let definition = RecordedEvalDatasetDefinition::freeze(
            RecordedDatasetSelection {
                contract_version: RECORDED_DATASET_DEFINITION_CONTRACT.into(),
                name: "refund-reviews".into(),
                action_type: "refund".into(),
                decided_from_ms: 0,
                decided_to_ms: 1_000,
                decision: None,
            },
            cases
                .iter()
                .map(|(id, decision)| RecordedCase {
                    instance_id: (*id).into(),
                    request_digest: format!("sha256:{id}"),
                    decision: (*decision).into(),
                    decided_at_ms: 10,
                })
                .collect(),
        )
        .unwrap();
        StoredRecordedEvalDataset::new(namespace, definition, "alice", at).unwrap()
    }

    /// The store contract both backends share.
    fn contract(db: &RuntimeDb, namespace: &str) {
        let first = record(namespace, &[("a", DECISION_GRANT), ("b", DECISION_DENY)], 1);
        assert_eq!(db.put_recorded_eval_dataset(&first).unwrap(), first);
        // Writing the same version again returns the stored row unchanged.
        let mut retried = first.clone();
        retried.created_at_ms = 99;
        assert_eq!(db.put_recorded_eval_dataset(&retried).unwrap(), first);
        let smaller = record(namespace, &[("a", DECISION_GRANT)], 2);
        db.put_recorded_eval_dataset(&smaller).unwrap();
        assert_eq!(
            db.get_recorded_eval_dataset(namespace, "refund-reviews", None)
                .unwrap(),
            Some(smaller.clone()),
            "the version first put most recently is current"
        );
        assert_eq!(
            db.get_recorded_eval_dataset(namespace, "refund-reviews", Some(&first.version))
                .unwrap(),
            Some(first),
            "earlier versions keep resolving"
        );
        assert_eq!(
            db.list_recorded_eval_datasets(namespace, "", 10).unwrap(),
            vec![smaller]
        );
        assert_eq!(
            db.get_recorded_eval_dataset("other", "refund-reviews", None)
                .unwrap(),
            None
        );
    }

    #[test]
    fn sqlite_recorded_eval_datasets_are_versioned_per_namespace() {
        let store = crate::chisei_store::ChiseiStore::memory();
        contract(store.runtime_arc().as_ref(), "acme");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_recorded_eval_datasets_are_versioned_per_namespace() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => {
                PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap())
            }
            Err(_) => PostgresDb::connect(&url, 4),
        };
        let store = crate::chisei_store::ChiseiStore::from_shared_runtime(Arc::new(
            RuntimeDb::Postgres(Arc::new(db.unwrap())),
        ));
        // A namespace of its own, so concurrent runs on one database do not
        // share definitions.
        let namespace = format!(
            "eval-recorded-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        contract(store.runtime_arc().as_ref(), &namespace);
    }
}

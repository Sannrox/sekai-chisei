//! Stored eval dataset definitions (#2306) on both community backends: one
//! row per (namespace, name, version), written once. The current version of
//! a name is the one first put most recently; ties fall to the higher
//! version so every instance reads the same one.

use crate::chisei::eval_dataset::{
    EvalDatasetDefinition, EvalDatasetDefinitionStore, StoredEvalDatasetDefinition,
};
use sekai_core::db::postgres::PostgresDb;
use sekai_core::db::sekai::SekaiDb;

const COLUMNS: &str =
    "namespace, definition_json, version, digest, case_count, created_by, created_at_ms";

/// Rows of `d` with no later version of the same name.
const CURRENT: &str = "NOT EXISTS (
    SELECT 1 FROM chisei_eval_dataset_definitions AS later
    WHERE later.namespace = d.namespace AND later.name = d.name
      AND (later.created_at_ms > d.created_at_ms
           OR (later.created_at_ms = d.created_at_ms AND later.version > d.version)))";

type Row = (String, String, String, String, i64, String, i64);

fn record_from(row: Row) -> Result<StoredEvalDatasetDefinition, String> {
    let (namespace, json, version, digest, case_count, created_by, created_at_ms) = row;
    let definition: EvalDatasetDefinition = serde_json::from_str(&json)
        .map_err(|error| format!("corrupt eval dataset definition: {error}"))?;
    Ok(StoredEvalDatasetDefinition {
        namespace,
        definition,
        version,
        digest,
        case_count: u64::try_from(case_count).map_err(|error| error.to_string())?,
        created_by,
        created_at_ms,
    })
}

fn json_of(record: &StoredEvalDatasetDefinition) -> Result<String, String> {
    serde_json::to_string(&record.definition).map_err(|error| error.to_string())
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

impl EvalDatasetDefinitionStore for SekaiDb {
    fn put_eval_dataset_definition(
        &self,
        record: &StoredEvalDatasetDefinition,
    ) -> Result<StoredEvalDatasetDefinition, String> {
        let json = json_of(record)?;
        let case_count = i64::try_from(record.case_count).map_err(|error| error.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO chisei_eval_dataset_definitions
             (namespace, name, version, definition_json, digest, case_count, created_by, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT DO NOTHING",
            rusqlite::params![
                record.namespace,
                record.definition.name,
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
                &format!(
                    "SELECT {COLUMNS} FROM chisei_eval_dataset_definitions
                     WHERE namespace = ?1 AND name = ?2 AND version = ?3"
                ),
                rusqlite::params![record.namespace, record.definition.name, record.version],
                sqlite_row,
            )
            .map_err(|error| error.to_string())?;
        record_from(row)
    }

    fn get_eval_dataset_definition(
        &self,
        namespace: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<StoredEvalDatasetDefinition>, String> {
        use rusqlite::OptionalExtension;
        let conn = self.conn();
        let row = match version {
            Some(version) => conn
                .query_row(
                    &format!(
                        "SELECT {COLUMNS} FROM chisei_eval_dataset_definitions
                         WHERE namespace = ?1 AND name = ?2 AND version = ?3"
                    ),
                    rusqlite::params![namespace, name, version],
                    sqlite_row,
                )
                .optional(),
            None => conn
                .query_row(
                    &format!(
                        "SELECT {COLUMNS} FROM chisei_eval_dataset_definitions AS d
                         WHERE namespace = ?1 AND name = ?2 AND {CURRENT}"
                    ),
                    rusqlite::params![namespace, name],
                    sqlite_row,
                )
                .optional(),
        }
        .map_err(|error| error.to_string())?;
        row.map(record_from).transpose()
    }

    fn list_eval_dataset_definitions(
        &self,
        namespace: &str,
        after_name: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvalDatasetDefinition>, String> {
        let limit = i64::try_from(limit).map_err(|error| error.to_string())?;
        let conn = self.conn();
        let mut statement = conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM chisei_eval_dataset_definitions AS d
                 WHERE namespace = ?1 AND name > ?2 AND {CURRENT}
                 ORDER BY name LIMIT ?3"
            ))
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![namespace, after_name, limit], sqlite_row)
            .map_err(|error| error.to_string())?;
        rows.map(|row| record_from(row.map_err(|error| error.to_string())?))
            .collect()
    }
}

impl EvalDatasetDefinitionStore for PostgresDb {
    fn put_eval_dataset_definition(
        &self,
        record: &StoredEvalDatasetDefinition,
    ) -> Result<StoredEvalDatasetDefinition, String> {
        let json = json_of(record)?;
        let case_count = i64::try_from(record.case_count).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO chisei_eval_dataset_definitions
                 (namespace, name, version, definition_json, digest, case_count, created_by, created_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
                &[
                    &record.namespace,
                    &record.definition.name,
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
                &format!(
                    "SELECT {COLUMNS} FROM chisei_eval_dataset_definitions
                     WHERE namespace = $1 AND name = $2 AND version = $3"
                ),
                &[&record.namespace, &record.definition.name, &record.version],
            )
            .map_err(|error| error.to_string())?;
        record_from(postgres_row(&row))
    }

    fn get_eval_dataset_definition(
        &self,
        namespace: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<StoredEvalDatasetDefinition>, String> {
        let mut connection = self.connection()?;
        let row = match version {
            Some(version) => connection.query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM chisei_eval_dataset_definitions
                     WHERE namespace = $1 AND name = $2 AND version = $3"
                ),
                &[&namespace, &name, &version],
            ),
            None => connection.query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM chisei_eval_dataset_definitions AS d
                     WHERE namespace = $1 AND name = $2 AND {CURRENT}"
                ),
                &[&namespace, &name],
            ),
        }
        .map_err(|error| error.to_string())?;
        row.map(|row| record_from(postgres_row(&row))).transpose()
    }

    fn list_eval_dataset_definitions(
        &self,
        namespace: &str,
        after_name: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvalDatasetDefinition>, String> {
        let limit = i64::try_from(limit).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        connection
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM chisei_eval_dataset_definitions AS d
                     WHERE namespace = $1 AND name > $2 AND {CURRENT}
                     ORDER BY name LIMIT $3"
                ),
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
impl EvalDatasetDefinitionStore for sekai_core::db::runtime_db::RuntimeDb {
    fn put_eval_dataset_definition(
        &self,
        record: &StoredEvalDatasetDefinition,
    ) -> Result<StoredEvalDatasetDefinition, String> {
        match self {
            Self::Sqlite(db) => db.put_eval_dataset_definition(record),
            Self::Postgres(db) => {
                sekai_core::db::postgres::off_runtime(|| db.put_eval_dataset_definition(record))
            }
        }
    }

    fn get_eval_dataset_definition(
        &self,
        namespace: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<StoredEvalDatasetDefinition>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_dataset_definition(namespace, name, version),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.get_eval_dataset_definition(namespace, name, version)
            }),
        }
    }

    fn list_eval_dataset_definitions(
        &self,
        namespace: &str,
        after_name: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvalDatasetDefinition>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_dataset_definitions(namespace, after_name, limit),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.list_eval_dataset_definitions(namespace, after_name, limit)
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::chisei::eval_dataset::{
        DatasetSources, EvalDatasetDefinition, EvalDatasetDefinitionStore,
        StoredEvalDatasetDefinition, is_not_found, resolve,
    };
    use sekai_core::db::runtime_db::RuntimeDb;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn directory() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/evaluation/datasets")
    }

    fn fixture_json() -> String {
        std::fs::read_to_string(directory().join("supply-chain-triage.json")).unwrap()
    }

    fn json_with(edit: impl FnOnce(&mut EvalDatasetDefinition)) -> String {
        let mut definition: EvalDatasetDefinition = serde_json::from_str(&fixture_json()).unwrap();
        edit(&mut definition);
        serde_json::to_string(&definition).unwrap()
    }

    fn put(
        db: &RuntimeDb,
        namespace: &str,
        json: &str,
        actor: &str,
        at: i64,
    ) -> StoredEvalDatasetDefinition {
        let record = StoredEvalDatasetDefinition::new(namespace, json, actor, at).unwrap();
        db.put_eval_dataset_definition(&record).unwrap()
    }

    /// Same content, same version as the directory; changed content adds a
    /// version and earlier ones keep resolving; reads stay in their
    /// namespace and list by name in pages, on every backend.
    fn contract(db: &RuntimeDb, namespace: &str) {
        let first = put(db, namespace, &fixture_json(), "alice", 10);
        let from_directory = resolve(&directory(), "supply-chain-triage", &first.version).unwrap();
        assert_eq!(first.digest, from_directory.digest);
        assert_eq!(first.case_count, from_directory.cases.len() as u64);
        // A repeat keeps the first put, whoever repeats it.
        assert_eq!(put(db, namespace, &fixture_json(), "bob", 20), first);

        let reseeded = put(db, namespace, &json_with(|d| d.seed = 1674), "alice", 30);
        assert_ne!(reseeded.version, first.version);
        let current = db
            .get_eval_dataset_definition(namespace, "supply-chain-triage", None)
            .unwrap()
            .unwrap();
        assert_eq!(current.version, reseeded.version);
        // Putting the first content again does not make it current.
        put(db, namespace, &fixture_json(), "alice", 40);
        assert_eq!(
            db.get_eval_dataset_definition(namespace, "supply-chain-triage", None)
                .unwrap()
                .unwrap()
                .version,
            reseeded.version
        );
        let sources = DatasetSources {
            directory: None,
            store: db,
            namespace,
        };
        for version in [&first.version, &reseeded.version] {
            assert_eq!(
                &sources
                    .resolve("supply-chain-triage", version)
                    .unwrap()
                    .version,
                version
            );
        }
        assert!(is_not_found(
            &sources
                .resolve("supply-chain-triage", "v0000000000000000")
                .unwrap_err()
        ));

        // Another namespace sees none of it.
        let elsewhere = format!("{namespace}-other");
        assert!(
            db.get_eval_dataset_definition(&elsewhere, "supply-chain-triage", Some(&first.version))
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_eval_dataset_definitions(&elsewhere, "", 10)
                .unwrap()
                .is_empty()
        );
        assert!(is_not_found(
            &DatasetSources {
                directory: None,
                store: db,
                namespace: &elsewhere
            }
            .resolve("supply-chain-triage", &first.version)
            .unwrap_err()
        ));

        // The current version of each name, by name, in pages.
        let other = put(
            db,
            namespace,
            &json_with(|d| d.name = "a-first".into()),
            "alice",
            50,
        );
        let page = db.list_eval_dataset_definitions(namespace, "", 1).unwrap();
        assert_eq!(page, [other]);
        let page = db
            .list_eval_dataset_definitions(namespace, "a-first", 10)
            .unwrap();
        assert_eq!(page, [reseeded]);
    }

    #[test]
    fn sqlite_eval_dataset_definitions_are_versioned_per_namespace() {
        let db = crate::chisei_store::ChiseiStore::memory().runtime_arc();
        contract(db.as_ref(), "acme");
    }

    /// Two instances over one database share definitions, and a database
    /// from before the table gains it on open.
    #[test]
    fn sqlite_eval_dataset_definitions_are_shared_and_upgrade_in_place() {
        let path = std::env::temp_dir().join(format!(
            "chisei-eval-datasets-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let path = path.to_string_lossy().into_owned();
        let open = || {
            RuntimeDb::Sqlite(Arc::new(
                crate::chisei_store::open_sekai_with_chisei_schema(&path),
            ))
        };
        let (one, two) = (open(), open());
        let stored = put(&one, "acme", &fixture_json(), "alice", 1);
        assert_eq!(
            two.get_eval_dataset_definition("acme", "supply-chain-triage", None)
                .unwrap(),
            Some(stored)
        );
        drop((one, two));
        let upgraded = open();
        let RuntimeDb::Sqlite(db) = &upgraded else {
            unreachable!()
        };
        db.conn()
            .execute_batch("DROP TABLE chisei_eval_dataset_definitions")
            .unwrap();
        drop(upgraded);
        let reopened = open();
        assert!(
            reopened
                .list_eval_dataset_definitions("acme", "", 10)
                .unwrap()
                .is_empty()
        );
        put(&reopened, "acme", &fixture_json(), "alice", 2);
        drop(reopened);
        std::fs::remove_file(path).ok();
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_eval_dataset_definitions_are_versioned_per_namespace() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let connect = || {
            let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
                Ok(path) => sekai_core::db::postgres::PostgresDb::connect_with_ca_certificate(
                    &url,
                    4,
                    &std::fs::read(path).unwrap(),
                ),
                Err(_) => sekai_core::db::postgres::PostgresDb::connect(&url, 4),
            };
            crate::chisei_store::ChiseiStore::from_shared_runtime(Arc::new(RuntimeDb::Postgres(
                Arc::new(db.unwrap()),
            )))
            .runtime_arc()
        };
        // A namespace of its own, so concurrent runs on one database do not
        // share definitions.
        let namespace = format!(
            "eval-dataset-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let db = connect();
        contract(db.as_ref(), &namespace);
        // A second instance reads what the first stored.
        assert!(
            connect()
                .get_eval_dataset_definition(&namespace, "a-first", None)
                .unwrap()
                .is_some()
        );
    }
}

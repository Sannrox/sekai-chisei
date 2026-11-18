//! SQLite and PostgreSQL persistence for model version references (#3020).
//!
//! A version id is derived from (namespace, model name, digest), so a repeat
//! registration conflicts on the primary key, writes nothing, and reads back
//! the stored record.

use rusqlite::{OptionalExtension, params};

use super::postgres::PostgresDb;
use super::sekai::SekaiDb;
use crate::sekai::model_version::ModelVersion;

fn encode(version: &ModelVersion) -> Result<String, String> {
    serde_json::to_string(version).map_err(|error| format!("encode model version: {error}"))
}

fn decode(json: &str) -> Result<ModelVersion, String> {
    serde_json::from_str(json).map_err(|error| format!("decode model version: {error}"))
}

impl SekaiDb {
    pub(crate) fn migrate_model_versions(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_model_versions (
                    version_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sekai_model_versions_name
                    ON sekai_model_versions (namespace, model_name, version_id);",
            )
            .map_err(|error| error.to_string())
    }

    /// Stores `version` unless its id is already held; returns the stored record.
    pub fn insert_model_version(&self, version: &ModelVersion) -> Result<ModelVersion, String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_model_versions (version_id, namespace, model_name, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (version_id) DO NOTHING",
                params![
                    version.version_id,
                    version.namespace,
                    version.model_name,
                    encode(version)?
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_model_version(&version.namespace, &version.version_id)?
            .ok_or_else(|| "model version vanished after insert".into())
    }

    pub fn get_model_version(
        &self,
        namespace: &str,
        version_id: &str,
    ) -> Result<Option<ModelVersion>, String> {
        self.conn()
            .query_row(
                "SELECT record_json FROM sekai_model_versions
                 WHERE namespace = ?1 AND version_id = ?2",
                params![namespace, version_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|json| decode(&json))
            .transpose()
    }

    /// Versions in `namespace` ordered by id; an empty `model_name` lists all.
    pub fn list_model_versions(
        &self,
        namespace: &str,
        model_name: &str,
    ) -> Result<Vec<ModelVersion>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT record_json FROM sekai_model_versions
                 WHERE namespace = ?1 AND (?2 = '' OR model_name = ?2)
                 ORDER BY version_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![namespace, model_name], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        rows.map(|json| decode(&json.map_err(|error| error.to_string())?))
            .collect()
    }
}

impl PostgresDb {
    /// See [`SekaiDb::insert_model_version`].
    pub fn insert_model_version(&self, version: &ModelVersion) -> Result<ModelVersion, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_model_versions (version_id, namespace, model_name, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (version_id) DO NOTHING",
                &[
                    &version.version_id,
                    &version.namespace,
                    &version.model_name,
                    &encode(version)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_model_version(&version.namespace, &version.version_id)?
            .ok_or_else(|| "model version vanished after insert".into())
    }

    pub fn get_model_version(
        &self,
        namespace: &str,
        version_id: &str,
    ) -> Result<Option<ModelVersion>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_model_versions
                 WHERE namespace = $1 AND version_id = $2",
                &[&namespace, &version_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode(row.get(0)))
            .transpose()
    }

    pub fn list_model_versions(
        &self,
        namespace: &str,
        model_name: &str,
    ) -> Result<Vec<ModelVersion>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_model_versions
                 WHERE namespace = $1 AND ($2 = '' OR model_name = $2)
                 ORDER BY version_id",
                &[&namespace, &model_name],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| decode(row.get(0)))
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod store_tests {
    use std::collections::BTreeMap;

    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::model_version::{
        AdapterContract, ModelColumn, ModelInput, ModelVersionRegistration,
    };

    pub(crate) fn registration(digest: &str, run_id: &str) -> ModelVersionRegistration {
        let column = |name: &str| ModelColumn {
            name: name.into(),
            col_type: "float".into(),
        };
        ModelVersionRegistration {
            namespace: "ml".into(),
            model_name: "churn".into(),
            digest: digest.into(),
            adapter_id: "tabular-classifier".into(),
            adapter_version: "1".into(),
            registry_locator: format!("churn/{digest}"),
            contract: AdapterContract {
                inputs: vec![ModelInput {
                    name: "features".into(),
                    columns: vec![column("tenure")],
                }],
                output: vec![column("score")],
            },
            run_id: run_id.into(),
            actor: "trainer".into(),
        }
    }

    pub(crate) fn version(
        digest: &str,
        created_at_ms: i64,
    ) -> crate::sekai::model_version::ModelVersion {
        let inputs = BTreeMap::from([("customers".to_string(), "v1".to_string())]);
        crate::sekai::model_version::ModelVersion::from_run(
            registration(digest, "run-1"),
            "ml",
            "secret",
            &inputs,
            created_at_ms,
        )
        .unwrap()
    }

    /// A repeat insert of one digest keeps the first record and writes no
    /// second row; another digest is a second version.
    pub(crate) fn repeat_insert_keeps_one_record(db: &RuntimeDb) {
        let first = db.insert_model_version(&version("sha256:a", 1)).unwrap();
        let again = db.insert_model_version(&version("sha256:a", 2)).unwrap();
        assert_eq!(again, first);
        db.insert_model_version(&version("sha256:b", 3)).unwrap();
        let listed = db.list_model_versions("ml", "churn").unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&first));
        assert!(db.list_model_versions("ml", "other").unwrap().is_empty());
        assert!(
            db.get_model_version("other", &first.version_id)
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::store_tests;
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;

    #[test]
    fn sqlite_repeat_insert_keeps_one_record() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        store_tests::repeat_insert_keeps_one_record(&db);
    }

    #[test]
    fn sqlite_version_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let path = path.to_str().unwrap();
        let stored = SekaiDb::new(path)
            .unwrap()
            .insert_model_version(&store_tests::version("sha256:a", 1))
            .unwrap();
        let reopened = SekaiDb::new(path).unwrap();
        assert_eq!(
            reopened
                .get_model_version("ml", &stored.version_id)
                .unwrap(),
            Some(stored)
        );
    }

    fn training_run(
        run_id: &str,
        dispatch_status: &str,
    ) -> crate::sekai::governed_transform::TransformRun {
        crate::sekai::governed_transform::TransformRun {
            run_id: run_id.into(),
            namespace: "ml".into(),
            transform_id: "train-churn".into(),
            definition_digest: String::new(),
            input_digest: String::new(),
            output_digest: String::new(),
            last_input_row_id: 0,
            incremental: false,
            quarantined: false,
            quality_rule: String::new(),
            rows_in: 0,
            rows_out: 0,
            lineage_parent: String::new(),
            created_at_ms: 1,
            markings_in: "internal,secret".into(),
            markings_out: "secret".into(),
            profile: String::new(),
            engine: String::new(),
            runtime_image: String::new(),
            dispatch_status: dispatch_status.into(),
            trigger_cause: String::new(),
            trigger_ref: String::new(),
            input_partitions: Vec::new(),
            output_partitions: Vec::new(),
            input_versions: [
                ("customers".to_string(), "v3".to_string()),
                ("events".to_string(), "v9".to_string()),
            ]
            .into(),
        }
    }

    #[test]
    fn registration_takes_lineage_and_marking_from_the_run_receipt() {
        let sqlite = Arc::new(SekaiDb::new(":memory:").unwrap());
        {
            let mut conn = sqlite.conn();
            let tx = conn.transaction().unwrap();
            for run in [training_run("run-1", ""), training_run("run-2", "failed")] {
                crate::db::governed_transform::insert_transform_run(&tx, &run).unwrap();
            }
            tx.commit().unwrap();
        }
        let db = RuntimeDb::Sqlite(sqlite);
        let version = db
            .register_model_version(store_tests::registration("sha256:a", "run-1"), 5)
            .unwrap();
        assert_eq!(version.run_id, "run-1");
        assert_eq!(version.marking, "secret");
        let inputs: Vec<_> = version
            .training_inputs
            .iter()
            .map(|input| (input.dataset_id.as_str(), input.version_id.as_str()))
            .collect();
        assert_eq!(inputs, [("customers", "v3"), ("events", "v9")]);
        let again = db
            .register_model_version(store_tests::registration("sha256:a", "run-1"), 6)
            .unwrap();
        assert_eq!(again, version);

        let failed = db
            .register_model_version(store_tests::registration("sha256:b", "run-2"), 7)
            .unwrap_err();
        assert!(failed.contains("did not complete"), "{failed}");
        let missing = db
            .register_model_version(store_tests::registration("sha256:c", "nope"), 8)
            .unwrap_err();
        assert!(missing.contains("not found"), "{missing}");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_repeat_insert_keeps_one_record() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        store_tests::repeat_insert_keeps_one_record(&db);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_version_survives_reconnect() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let stored = RuntimeDb::Postgres(Arc::new(scratch.connect()))
            .insert_model_version(&store_tests::version("sha256:a", 1))
            .unwrap();
        let reconnected = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        assert_eq!(
            reconnected
                .get_model_version("ml", &stored.version_id)
                .unwrap(),
            Some(stored)
        );
    }
}

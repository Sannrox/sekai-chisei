//! SQLite and PostgreSQL persistence for model version references (#3020).
//!
//! A version id is derived from (namespace, model name, digest), so a repeat
//! registration conflicts on the primary key, writes nothing, and reads back
//! the stored record.

use rusqlite::{OptionalExtension, params};

use super::postgres::PostgresDb;
use super::sekai::SekaiDb;
use std::collections::BTreeMap;

use super::model_stage_store::{stage_version_pg, stage_version_sqlite};
use crate::sekai::model_stage::parse_stage_pin;
use crate::sekai::model_version::ModelVersion;

fn encode(version: &ModelVersion) -> Result<String, String> {
    serde_json::to_string(version).map_err(|error| format!("encode model version: {error}"))
}

fn decode(json: &str) -> Result<ModelVersion, String> {
    serde_json::from_str(json).map_err(|error| format!("decode model version: {error}"))
}

/// The model inputs of `transform` as `(name, pinned value)`: a version id or
/// a [`stage pin`](crate::sekai::model_stage::parse_stage_pin).
fn pinned_model_inputs(
    transform: &crate::sekai::governed_transform::GovernedTransform,
) -> impl Iterator<Item = (&String, &String)> {
    transform
        .isolated_process
        .iter()
        .flat_map(|spec| spec.model_inputs.iter())
}

fn marking_token(version: ModelVersion) -> Option<String> {
    (!version.marking.is_empty()).then_some(version.marking)
}

/// What a run admission pins for its model inputs, read in the admitting
/// transaction.
pub(crate) struct ModelInputPins {
    /// The marking token of each pinned version, folded into the output marking.
    pub markings: Vec<Option<String>>,
    /// `model:<name>` to the version id the run uses, for `input_versions`.
    pub pins: BTreeMap<String, String>,
}

impl ModelInputPins {
    fn new() -> Self {
        Self {
            markings: Vec::new(),
            pins: BTreeMap::new(),
        }
    }

    fn push(&mut self, name: &str, version: ModelVersion) {
        self.pins.insert(
            format!(
                "{}{name}",
                crate::sekai::governed_transform::MODEL_PIN_PREFIX
            ),
            version.version_id.clone(),
        );
        self.markings.push(marking_token(version));
    }
}

/// Resolves each model input `transform` pins. A stage pin resolves to the
/// stage's current version (#3023); a stage with no version yet, or a pin
/// naming no version in the namespace, refuses the run.
pub(crate) fn resolve_model_input_pins(
    conn: &rusqlite::Connection,
    transform: &crate::sekai::governed_transform::GovernedTransform,
) -> Result<ModelInputPins, String> {
    let mut resolved = ModelInputPins::new();
    for (name, pinned) in pinned_model_inputs(transform) {
        let version_id = match parse_stage_pin(pinned) {
            Some((model_name, stage)) => {
                stage_version_sqlite(conn, &transform.namespace, model_name, stage)?
            }
            None => pinned.clone(),
        };
        let json = conn
            .query_row(
                "SELECT record_json FROM sekai_model_versions
                 WHERE namespace = ?1 AND version_id = ?2",
                params![transform.namespace, version_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| crate::sekai::model_version::MODEL_VERSION_NOT_FOUND.to_string())?;
        resolved.push(name, decode(&json)?);
    }
    Ok(resolved)
}

/// See [`resolve_model_input_pins`].
pub(crate) fn resolve_model_input_pins_pg(
    tx: &mut postgres::Transaction<'_>,
    transform: &crate::sekai::governed_transform::GovernedTransform,
) -> Result<ModelInputPins, String> {
    let mut resolved = ModelInputPins::new();
    for (name, pinned) in pinned_model_inputs(transform) {
        let version_id = match parse_stage_pin(pinned) {
            Some((model_name, stage)) => {
                stage_version_pg(tx, &transform.namespace, model_name, stage)?
            }
            None => pinned.clone(),
        };
        let row = tx
            .query_opt(
                "SELECT record_json FROM sekai_model_versions
                 WHERE namespace = $1 AND version_id = $2",
                &[&transform.namespace, &version_id],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| crate::sekai::model_version::MODEL_VERSION_NOT_FOUND.to_string())?;
        resolved.push(name, decode(row.get(0))?);
    }
    Ok(resolved)
}

/// Stores `version` in `tx` unless its id is already held. A newly stored
/// version moves the model's gateless stages to it (#3023); a repeat
/// registration moves nothing. Model registration and a training run's
/// write-back (#3021) share it.
pub(crate) fn insert_model_version_sqlite(
    tx: &rusqlite::Transaction<'_>,
    version: &ModelVersion,
) -> Result<(), String> {
    let inserted = tx
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
    if inserted == 1 {
        super::model_stage_store::follow_gateless_stages_sqlite(tx, version)?;
    }
    Ok(())
}

/// See [`insert_model_version_sqlite`].
pub(crate) fn insert_model_version_pg(
    tx: &mut postgres::Transaction<'_>,
    version: &ModelVersion,
) -> Result<(), String> {
    let inserted = tx
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
    if inserted == 1 {
        super::model_stage_store::follow_gateless_stages_pg(tx, version)?;
    }
    Ok(())
}

/// The versions a successful write-back of `run` publishes for the model
/// outputs `transform` declares (#3021); empty when it declares none.
pub(crate) fn run_model_outputs(
    transform: &crate::sekai::governed_transform::GovernedTransform,
    run: &crate::sekai::governed_transform::TransformRun,
    command: &crate::sekai::governed_transform::WriteTransformRunCommand,
    now_ms: i64,
) -> Result<Vec<ModelVersion>, String> {
    let declared = transform
        .isolated_process
        .as_ref()
        .map(|spec| &spec.model_outputs);
    let Some(declared) = declared.filter(|declared| !declared.is_empty()) else {
        if command.model_outputs.is_empty() {
            return Ok(Vec::new());
        }
        return Err("the transform declares no model outputs".into());
    };
    crate::sekai::model_version::RunModelOutputs {
        declared,
        writes: &command.model_outputs,
        namespace: &run.namespace,
        run_id: &run.run_id,
        actor: &command.runtime_id,
        run_marking: &run.markings_out,
        run_inputs: &run.input_versions,
        now_ms,
    }
    .versions()
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
    /// A newly stored version moves the model's gateless stages to it in the
    /// same transaction (#3023); a repeat registration moves nothing.
    pub fn insert_model_version(&self, version: &ModelVersion) -> Result<ModelVersion, String> {
        {
            let mut conn = self.conn();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            insert_model_version_sqlite(&tx, version)?;
            tx.commit().map_err(|error| error.to_string())?;
        }
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
        {
            let mut conn = self.connection()?;
            let mut tx = conn.transaction().map_err(|error| error.to_string())?;
            insert_model_version_pg(&mut tx, version)?;
            tx.commit().map_err(|error| error.to_string())?;
        }
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

    /// A training run publishes exactly one version per declared model
    /// output with its write-back (#3021): a killed host's stale claim
    /// publishes nothing, a write naming other models is refused whole, a
    /// retried write adds nothing, and a quarantined run publishes none.
    pub(crate) fn training_run_publishes_one_version(db: &RuntimeDb) {
        use crate::sekai::dataset::{ColumnDef, Dataset};
        use crate::sekai::governed_transform::{
            CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, WriteTransformRunCommand,
            rows_digest,
        };
        use crate::sekai::model_version::ModelOutputWrite;
        for id in ["in", "out"] {
            db.create_dataset(&Dataset {
                id: id.into(),
                name: id.into(),
                columns: vec![ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        }
        let rows = vec![std::collections::HashMap::from([(
            "id".to_string(),
            "1".to_string(),
        )])];
        db.append_rows("in", &rows).unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ml".into(),
            transform_id: "train".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: "python".into(),
                runtime_image: "trainer:1".into(),
                code: "fit()".into(),
                model_outputs: [" churn ".to_string()].into(),
                ..Default::default()
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        assert_eq!(
            transform.isolated_process.as_ref().unwrap().model_outputs,
            ["churn".to_string()].into()
        );
        db.put_governed_transform(&transform, 10).unwrap();
        let trained = |model_name: &str, digest: &str| {
            let registration = registration(digest, "");
            ModelOutputWrite {
                model_name: model_name.into(),
                digest: digest.into(),
                adapter_id: registration.adapter_id,
                adapter_version: registration.adapter_version,
                registry_locator: registration.registry_locator,
                contract: registration.contract,
            }
        };
        let write = |work: &crate::sekai::governed_transform::TransformWork,
                     quarantined: bool,
                     outputs: Vec<ModelOutputWrite>,
                     now_ms: i64| {
            db.write_transform_run(
                WriteTransformRunCommand {
                    run_id: work.run_id.clone(),
                    runtime_id: work.claim_owner.clone(),
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token.clone(),
                    rows: rows.clone(),
                    output_digest: rows_digest(&rows),
                    quarantined,
                    model_outputs: outputs,
                    ..WriteTransformRunCommand::default()
                },
                now_ms,
            )
        };
        let versions = || db.list_model_versions("ml", "churn").unwrap();

        let run = db.run_governed_transform("ml", "train", false, 20).unwrap();
        let (killed, _) = db
            .claim_transform_work("ml", "host-a", "", 1_000, 30)
            .unwrap()
            .expect("claimable work");
        // host-a dies mid-training; its lease lapses and host-b takes over.
        let (retry, _) = db
            .claim_transform_work("ml", "host-b", "", 60_000, 5_000)
            .unwrap()
            .expect("expired work is claimable again");
        assert_eq!(retry.run_id, run.run_id);
        assert!(write(&killed, false, vec![trained("churn", "sha256:a")], 5_100).is_err());
        assert!(versions().is_empty(), "a stale claim publishes nothing");

        for wrong in [
            Vec::new(),
            vec![trained("churn", "sha256:a"), trained("other", "sha256:o")],
            vec![trained("churn", "sha256:a"), trained("churn", "sha256:b")],
        ] {
            let refused = write(&retry, false, wrong, 5_200).unwrap_err();
            assert!(refused.contains("model output"), "{refused}");
        }
        assert!(versions().is_empty(), "a refused write publishes nothing");
        assert!(
            db.query_rows("out", &Default::default())
                .unwrap()
                .is_empty()
        );

        let committed = write(&retry, false, vec![trained("churn", "sha256:a")], 5_300).unwrap();
        let [version] = versions().try_into().expect("exactly one version");
        assert_eq!(version.run_id, run.run_id);
        assert_eq!(version.actor, "host-b");
        assert_eq!(version.marking, committed.markings_out);
        assert_eq!(
            version
                .training_inputs
                .iter()
                .map(|input| (input.dataset_id.as_str(), input.version_id.as_str()))
                .collect::<Vec<_>>(),
            committed
                .input_versions
                .iter()
                .map(|(dataset, version)| (dataset.as_str(), version.as_str()))
                .collect::<Vec<_>>()
        );
        assert_eq!(version.training_inputs[0].dataset_id, "in");
        // A repeated write-back of the committed run adds nothing.
        write(&retry, false, vec![trained("churn", "sha256:a")], 5_400).unwrap();
        assert_eq!(versions().len(), 1);

        db.run_governed_transform("ml", "train", false, 6_000)
            .unwrap();
        let (quarantined, _) = db
            .claim_transform_work("ml", "host-b", "", 60_000, 6_100)
            .unwrap()
            .expect("second run");
        let run = write(
            &quarantined,
            true,
            vec![trained("churn", "sha256:q")],
            6_200,
        )
        .unwrap();
        assert!(run.quarantined);
        assert_eq!(versions().len(), 1, "a quarantined run publishes nothing");
    }

    /// A run of a transform pinning a model version records the pin and
    /// carries the version's marking; a pin naming no version refuses the
    /// run (#3074).
    pub(crate) fn pinned_model_input_marks_and_pins_the_run(db: &RuntimeDb) {
        use crate::sekai::dataset::{ColumnDef, Dataset};
        use crate::sekai::governed_transform::{
            CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, MODEL_INPUT_LABEL,
        };
        for id in ["in", "out"] {
            db.create_dataset(&Dataset {
                id: id.into(),
                name: id.into(),
                columns: vec![ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        }
        db.append_rows(
            "in",
            &[std::collections::HashMap::from([("id".into(), "1".into())])],
        )
        .unwrap();
        let mut registration = registration("sha256:a", "run-1");
        registration.namespace = "ops".into();
        let pinned = db
            .insert_model_version(
                &crate::sekai::model_version::ModelVersion::from_run(
                    registration,
                    "ops",
                    "confidential",
                    &BTreeMap::new(),
                    1,
                )
                .unwrap(),
            )
            .unwrap();
        let transform = |transform_id: &str, version_id: &str| {
            GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: transform_id.into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: Vec::new(),
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: Some(IsolatedProcessSpec {
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    code: "score()".into(),
                    model_inputs: BTreeMap::from([("scorer".into(), version_id.into())]),
                    model_outputs: Default::default(),
                    ..Default::default()
                }),
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap()
        };
        let scoring = transform("score", &pinned.version_id);
        assert_eq!(
            scoring.isolated_process.as_ref().unwrap().requires[MODEL_INPUT_LABEL],
            "v1"
        );
        db.put_governed_transform(&scoring, 10).unwrap();
        let run = db
            .run_governed_transform("ops", "score", false, 20)
            .unwrap();
        assert_eq!(run.input_versions["model:scorer"], pinned.version_id);
        assert_eq!(run.markings_out, "confidential");

        db.put_governed_transform(&transform("dangling", "mv_missing"), 30)
            .unwrap();
        let refused = db
            .run_governed_transform("ops", "dangling", false, 40)
            .unwrap_err();
        assert!(refused.contains("model version not found"), "{refused}");

        // A stage pin (#3023) refuses until the stage has a version, then
        // resolves to whatever version the stage holds when each run is admitted.
        let mut gated =
            super::super::model_stage_store::store_tests::stage("production", "suite-a");
        gated.namespace = "ops".into();
        db.put_model_stage(&gated).unwrap();
        db.put_governed_transform(&transform("staged", "stage:churn/production"), 50)
            .unwrap();
        let unpromoted = db
            .run_governed_transform("ops", "staged", false, 60)
            .unwrap_err();
        assert!(unpromoted.contains("model stage not found"), "{unpromoted}");
        let promote = |version_id: &str, expected: &str, operation_id: &str| {
            let stage = crate::sekai::model_stage::ModelStage {
                version_id: version_id.into(),
                ..gated.clone()
            };
            let mut receipt = super::super::model_stage_store::store_tests::receipt(operation_id);
            receipt.namespace = "ops".into();
            assert!(db.promote_model_stage(&stage, expected, &receipt).unwrap());
        };
        promote(&pinned.version_id, "", "op-staged-1");
        let run = db
            .run_governed_transform("ops", "staged", false, 70)
            .unwrap();
        assert_eq!(run.input_versions["model:scorer"], pinned.version_id);
        let mut next = self::registration("sha256:b", "run-1");
        next.namespace = "ops".into();
        let next = db
            .insert_model_version(
                &crate::sekai::model_version::ModelVersion::from_run(
                    next,
                    "ops",
                    "",
                    &BTreeMap::new(),
                    2,
                )
                .unwrap(),
            )
            .unwrap();
        promote(&next.version_id, &pinned.version_id, "op-staged-2");
        let run = db
            .run_governed_transform("ops", "staged", false, 80)
            .unwrap();
        assert_eq!(run.input_versions["model:scorer"], next.version_id);

        // A dataset input may not shadow a model pin in the receipt.
        let mut shadowing = transform("shadow", &pinned.version_id);
        shadowing.definition_digest.clear();
        let spec = shadowing.isolated_process.as_mut().unwrap();
        spec.inputs = vec![crate::sekai::governed_transform::TransformInput {
            alias: "features".into(),
            dataset_id: "model:scorer".into(),
            ..Default::default()
        }];
        assert!(shadowing.prepare().is_err());
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
    fn sqlite_training_run_publishes_one_version() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        store_tests::training_run_publishes_one_version(&db);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_training_run_publishes_one_version() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        store_tests::training_run_publishes_one_version(&db);
    }

    #[test]
    fn sqlite_pinned_model_input_marks_and_pins_the_run() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        store_tests::pinned_model_input_marks_and_pins_the_run(&db);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_pinned_model_input_marks_and_pins_the_run() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        store_tests::pinned_model_input_marks_and_pins_the_run(&db);
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

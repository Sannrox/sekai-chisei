//! Replaying a governed transform at past input versions (#1585), on either
//! backend. The run itself is the branch run of ADR 0119 with every input
//! pinned to a version; this module resolves the pins, diffs the result
//! against a baseline version of the output, names the downstream impact
//! and keeps the record.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::dataset_branch::{self, DatasetBranchRun};
use crate::sekai::dataset_version;
use crate::sekai::governed_transform::GovernedTransform;
use crate::sekai::object_type_index::ObjectTypeDatasource;
use crate::sekai::transform_replay::{
    self, REPLAY_OUTPUT_MISMATCH, REPLAY_PIN_NOT_AN_INPUT, ReplayTransform, TransformReplay,
};
use std::collections::{BTreeMap, HashMap};

impl RuntimeDb {
    /// Replay `request`: run the transform (stored, or the candidate
    /// definition) over its inputs pinned to versions, on a fresh branch of
    /// its output, and record what it read, ran and changed; the branch and
    /// the record commit together. The output dataset itself is untouched;
    /// the branch is promoted by proposing and merging it, or discarded by
    /// deleting it.
    pub fn replay_governed_transform(
        &self,
        request: &ReplayTransform,
        now_ms: i64,
    ) -> Result<TransformReplay, String> {
        let stored = self
            .get_governed_transform(&request.namespace, &request.transform_id)?
            .ok_or("governed transform not found")?;
        if !request.expected_definition_digest.is_empty()
            && stored.definition_digest != request.expected_definition_digest
        {
            return Err(transform_replay::REPLAY_TRANSFORM_CHANGED.into());
        }
        let transform = candidate_or_stored(&stored, &request.definition_json)?;
        if transform.is_isolated_process() {
            return Err(dataset_branch::BRANCH_RUN_ISOLATED.into());
        }
        let bindings = transform.input_bindings();
        if let Some(stray) = request
            .input_versions
            .keys()
            .find(|pinned| !bindings.iter().any(|(_, dataset_id)| dataset_id == *pinned))
        {
            return Err(format!("{REPLAY_PIN_NOT_AN_INPUT}: {stray}"));
        }
        let mut pins = BTreeMap::new();
        for (_, dataset_id) in &bindings {
            // An empty pin is no pin: only a dataset with no version yet
            // reads as empty. A receipt's unversioned pin is that: no rows.
            let version = match request.input_versions.get(dataset_id) {
                Some(version) if version == crate::sekai::governed_transform::INPUT_UNVERSIONED => {
                    String::new()
                }
                Some(version) if !version.trim().is_empty() => version.clone(),
                _ => self.version_at(dataset_id, request.as_of_ms)?,
            };
            pins.insert(dataset_id.clone(), version);
        }
        let output = transform.output_dataset_id.clone();
        let baseline_version_id = if request.baseline_version_id.is_empty() {
            self.version_at(&output, request.as_of_ms)?
        } else {
            request.baseline_version_id.clone()
        };
        // Bounded before it is read: the run's budget does not cover it. The
        // rows are read inside the run's transaction.
        if !baseline_version_id.is_empty() {
            let version = self.get_dataset_version(&output, &baseline_version_id, 0)?;
            if version.purged {
                return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
            }
            if i64::from(version.row_count) > transform_replay::MAX_BASELINE_ROWS {
                return Err(transform_replay::REPLAY_BASELINE_TOO_LARGE.into());
            }
        }

        // Everything the record needs besides the run is read first, so the
        // record is made and kept inside the run's transaction.
        let datasources = self.list_object_type_datasources(&request.namespace)?;
        let key = transform_replay::diff_key(&request.key_column, &output, &datasources);
        let partition_keys = self
            .get_dataset(&output)?
            .map(|dataset| dataset.partition_keys)
            .unwrap_or_default();
        let downstream = transform_replay::downstream(
            &output,
            &self.list_governed_transforms(&request.namespace)?,
            &datasources,
        );
        let id = uuid::Uuid::new_v4().to_string();
        let branch = transform_replay::replay_branch(&id);
        let describe = |run: &DatasetBranchRun,
                        rows: &[HashMap<String, String>],
                        baseline: &[HashMap<String, String>]| {
            Ok(TransformReplay {
                id: id.clone(),
                namespace: request.namespace.clone(),
                transform_id: request.transform_id.clone(),
                output_dataset_id: output.clone(),
                branch: run.branch.clone(),
                inputs: run.inputs.clone(),
                definition_digest: transform.definition_digest.clone(),
                candidate: transform.definition_digest != stored.definition_digest,
                engine_version: env!("CARGO_PKG_VERSION").into(),
                as_of_ms: request.as_of_ms,
                baseline_version_id: baseline_version_id.clone(),
                non_deterministic: transform_replay::non_deterministic_steps(&transform),
                markings_out: run.markings_out.clone(),
                output_digest: crate::sekai::governed_transform::dataset_digest(
                    &partition_keys,
                    rows,
                ),
                baseline_output_digest: crate::sekai::governed_transform::dataset_digest(
                    &partition_keys,
                    baseline,
                ),
                diff: transform_replay::diff_replay(baseline, rows, &key),
                downstream: downstream.clone(),
                actor: request.actor.clone(),
                tenant: request.tenant.clone(),
                created_at_ms: now_ms,
            })
        };
        self.replay_transform_into_branch(
            &request.namespace,
            &transform,
            &branch,
            &pins,
            &request.actor,
            &request.tenant,
            now_ms,
            &baseline_version_id,
            // Checked again in the transaction, which a redefinition or
            // delete cannot interleave with.
            &stored.definition_digest,
            &describe,
        )
    }

    /// The version of `dataset_id` at `as_of_ms` (the latest when 0); empty
    /// when it had none yet, so the input reads as empty.
    fn version_at(&self, dataset_id: &str, as_of_ms: i64) -> Result<String, String> {
        match self.get_dataset_version(dataset_id, "", as_of_ms) {
            Ok(version) if version.purged => {
                Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into())
            }
            Ok(version) => Ok(version.version_id),
            Err(error) if error == dataset_version::DATASET_VERSION_NOT_FOUND => Ok(String::new()),
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn replay_transform_into_branch(
        &self,
        namespace: &str,
        transform: &GovernedTransform,
        branch: &str,
        pins: &BTreeMap<String, String>,
        actor: &str,
        tenant: &str,
        now_ms: i64,
        baseline_version_id: &str,
        definition_digest: &str,
        describe: &transform_replay::Describe<'_>,
    ) -> Result<TransformReplay, String> {
        match self {
            Self::Sqlite(db) => db.replay_transform_into_branch(
                namespace,
                transform,
                branch,
                pins,
                actor,
                tenant,
                now_ms,
                baseline_version_id,
                definition_digest,
                describe,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.replay_transform_into_branch(
                    namespace,
                    transform,
                    branch,
                    pins,
                    actor,
                    tenant,
                    now_ms,
                    baseline_version_id,
                    definition_digest,
                    describe,
                )
            }),
        }
    }

    pub fn get_transform_replay(&self, id: &str) -> Result<Option<TransformReplay>, String> {
        match self {
            Self::Sqlite(db) => db.get_transform_replay(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_transform_replay(id)),
        }
    }

    pub fn list_object_type_datasources(
        &self,
        namespace: &str,
    ) -> Result<Vec<ObjectTypeDatasource>, String> {
        match self {
            Self::Sqlite(db) => db.list_object_type_datasources(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_object_type_datasources(namespace))
            }
        }
    }
}

/// The transform a replay runs: the stored one, or a candidate definition
/// that keeps its namespace, id and output.
pub fn candidate_or_stored(
    stored: &GovernedTransform,
    definition_json: &str,
) -> Result<GovernedTransform, String> {
    if definition_json.trim().is_empty() {
        return Ok(stored.clone());
    }
    let candidate: GovernedTransform = serde_json::from_str(definition_json)
        .map_err(|error| format!("invalid candidate definition: {error}"))?;
    let candidate = candidate.prepare().map_err(|error| error.message())?;
    if candidate.namespace != stored.namespace
        || candidate.transform_id != stored.transform_id
        || candidate.output_dataset_id != stored.output_dataset_id
    {
        return Err(REPLAY_OUTPUT_MISMATCH.into());
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::dataset::DatasetBackend;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::dataset_branch::{MergeDatasetBranch, ProposeDatasetBranch};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, TransformStep};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn row(id: &str, keep: &str) -> HashMap<String, String> {
        HashMap::from([("id".into(), id.into()), ("keep".into(), keep.into())])
    }

    fn filter(namespace: &str, input: &str, output: &str, value: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            transform_id: "t1".into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: value.into(),
                columns: Vec::new(),
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    /// The #1585 acceptance on one backend: an unchanged replay reproduces
    /// the original output digest, a changed transform diffs correctly on a
    /// fixture, pinned versions are read as they were, the output stays
    /// untouched, and the result promotes through a branch merge.
    fn exercise(runtime: &RuntimeDb, data: &dyn DatasetBackend) {
        let suffix = uuid::Uuid::new_v4().as_simple().to_string();
        let (input, output, namespace) = (
            format!("in-{suffix}"),
            format!("out-{suffix}"),
            format!("ops-{suffix}"),
        );
        for id in [&input, &output] {
            data.create_dataset(&Dataset {
                id: id.clone(),
                name: id.clone(),
                columns: ["id", "keep"]
                    .map(|name| ColumnDef {
                        name: name.into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    })
                    .to_vec(),
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        }
        data.append_rows(&input, &[row("1", "yes"), row("2", "no"), row("3", "yes")])
            .unwrap();
        let first_input = data
            .list_dataset_versions(&input)
            .unwrap()
            .last()
            .unwrap()
            .version_id
            .clone();
        let transform = filter(&namespace, &input, &output, "yes");
        runtime.put_governed_transform(&transform, 10).unwrap();
        let original = runtime
            .run_governed_transform(&namespace, "t1", false, 20)
            .unwrap();
        // #1794: the receipt pins the version each input was read at, and a
        // run on unchanged inputs reads the same pins.
        assert_eq!(
            original.input_versions,
            BTreeMap::from([(input.clone(), first_input.clone())])
        );
        let stored = runtime
            .list_governed_transform_runs(&namespace, 10)
            .unwrap()
            .into_iter()
            .find(|run| run.run_id == original.run_id)
            .unwrap();
        assert_eq!(stored.input_versions, original.input_versions);
        let again = runtime
            .run_governed_transform(&namespace, "t1", false, 25)
            .unwrap();
        assert_eq!(again.input_versions, original.input_versions);
        assert_eq!(again.input_digest, original.input_digest);
        let output_versions = data.list_dataset_versions(&output).unwrap();
        let request = ReplayTransform {
            namespace: namespace.clone(),
            transform_id: "t1".into(),
            key_column: "id".into(),
            actor: "analyst".into(),
            tenant: "t1".into(),
            ..ReplayTransform::default()
        };

        // Unchanged inputs and transform reproduce the original output.
        let same = runtime.replay_governed_transform(&request, 30).unwrap();
        assert!(same.diff.reproduced(), "{:?}", same.diff);
        assert_eq!(same.output_digest, original.output_digest);
        assert_eq!(same.inputs.len(), 1);
        assert_eq!(same.inputs[0].version_id, first_input);
        assert_eq!(same.definition_digest, transform.definition_digest);
        assert!(!same.candidate && same.non_deterministic.is_empty());
        assert_eq!(same.downstream[0].dataset_id, output);
        assert_eq!(
            runtime.get_transform_replay(&same.id).unwrap().unwrap(),
            same.without_rows()
        );

        // A replay authorized against an older definition is refused.
        assert_eq!(
            runtime
                .replay_governed_transform(
                    &ReplayTransform {
                        expected_definition_digest: "sha256:older".into(),
                        ..request.clone()
                    },
                    35,
                )
                .unwrap_err(),
            transform_replay::REPLAY_TRANSFORM_CHANGED
        );

        // A changed transform diffs on the fixture: 1 and 3 leave, 2 joins.
        let changed = ReplayTransform {
            definition_json: serde_json::to_string(&filter(&namespace, &input, &output, "no"))
                .unwrap(),
            ..request.clone()
        };
        let replay = runtime.replay_governed_transform(&changed, 40).unwrap();
        assert!(replay.candidate);
        assert_eq!(
            (
                replay.diff.rows_added,
                replay.diff.rows_removed,
                replay.diff.rows_changed
            ),
            (1, 2, 0)
        );
        assert_eq!(replay.diff.changed_keys, ["1", "2", "3"]);

        // A pinned past version is read as it was, after the input moved on.
        data.append_rows(&input, &[row("4", "yes")]).unwrap();
        // #1794: the original receipt's own pins reproduce its output.
        let from_receipt = runtime
            .replay_governed_transform(
                &ReplayTransform {
                    input_versions: original.input_versions.clone(),
                    ..request.clone()
                },
                45,
            )
            .unwrap();
        assert_eq!(from_receipt.output_digest, original.output_digest);
        // An unversioned pin reads no rows, whatever the input holds now.
        let unversioned = runtime
            .replay_governed_transform(
                &ReplayTransform {
                    input_versions: BTreeMap::from([(
                        input.clone(),
                        crate::sekai::governed_transform::INPUT_UNVERSIONED.into(),
                    )]),
                    ..request.clone()
                },
                47,
            )
            .unwrap();
        assert_eq!(
            (
                unversioned.inputs[0].rows,
                unversioned.inputs[0].version_id.as_str()
            ),
            (0, "")
        );
        let pinned = runtime
            .replay_governed_transform(
                &ReplayTransform {
                    input_versions: BTreeMap::from([(input.clone(), first_input.clone())]),
                    ..request.clone()
                },
                50,
            )
            .unwrap();
        assert!(pinned.diff.reproduced());
        let latest = runtime.replay_governed_transform(&request, 60).unwrap();
        assert_eq!(latest.diff.changed_keys, ["4"]);

        // Pins must name inputs and versions that still hold rows.
        assert!(
            runtime
                .replay_governed_transform(
                    &ReplayTransform {
                        input_versions: BTreeMap::from([(output.clone(), first_input.clone())]),
                        ..request.clone()
                    },
                    70,
                )
                .unwrap_err()
                .starts_with(REPLAY_PIN_NOT_AN_INPUT)
        );
        assert_eq!(
            runtime
                .replay_governed_transform(
                    &ReplayTransform {
                        input_versions: BTreeMap::from([(input.clone(), "nope".into())]),
                        ..request.clone()
                    },
                    80,
                )
                .unwrap_err(),
            dataset_version::DATASET_VERSION_NOT_FOUND
        );

        // Replays leave the output alone; the result promotes by merge.
        assert_eq!(
            data.list_dataset_versions(&output).unwrap(),
            output_versions
        );
        let proposal = data
            .propose_dataset_branch(&ProposeDatasetBranch {
                expected_incarnation: None,
                dataset_id: output.clone(),
                branch: latest.branch.clone(),
                actor: "analyst".into(),
                tenant: "t1".into(),
            })
            .unwrap();
        data.merge_dataset_branch(&MergeDatasetBranch {
            dataset_id: output.clone(),
            proposal_id: proposal.id,
            actor: "reviewer".into(),
            tenant: "t1".into(),
            reason: "replay".into(),
        })
        .unwrap();
        assert_eq!(
            data.list_dataset_versions(&output).unwrap().len(),
            output_versions.len() + 1
        );
        // Discarding a replay is deleting its branch.
        data.delete_dataset_branch(&output, &replay.branch, "t1")
            .unwrap();
    }

    /// A dataset populated before versioning still has live rows and no
    /// `sekai_dataset_versions` row. The run snapshots those rows and pins
    /// the snapshot so replay matches after the live table moves on.
    fn exercise_legacy_populated_pins(
        runtime: &RuntimeDb,
        data: &dyn DatasetBackend,
        forget_versions: &dyn Fn(&str),
    ) {
        let suffix = uuid::Uuid::new_v4().as_simple().to_string();
        let (input, output, namespace) = (
            format!("legacy-in-{suffix}"),
            format!("legacy-out-{suffix}"),
            format!("legacy-ops-{suffix}"),
        );
        for id in [&input, &output] {
            data.create_dataset(&Dataset {
                id: id.clone(),
                name: id.clone(),
                columns: ["id", "keep"]
                    .map(|name| ColumnDef {
                        name: name.into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    })
                    .to_vec(),
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        }
        data.append_rows(&input, &[row("1", "yes"), row("2", "no")])
            .unwrap();
        forget_versions(&input);
        assert!(data.list_dataset_versions(&input).unwrap().is_empty());
        let transform = filter(&namespace, &input, &output, "yes");
        runtime.put_governed_transform(&transform, 10).unwrap();
        let original = runtime
            .run_governed_transform(&namespace, "t1", false, 20)
            .unwrap();
        let pin = original
            .input_versions
            .get(&input)
            .cloned()
            .expect("receipt pins the input");
        assert_ne!(pin, crate::sekai::governed_transform::INPUT_UNVERSIONED);
        assert_eq!(
            data.list_dataset_versions(&input)
                .unwrap()
                .last()
                .unwrap()
                .version_id,
            pin
        );
        data.append_rows(&input, &[row("3", "yes")]).unwrap();
        let replayed = runtime
            .replay_governed_transform(
                &ReplayTransform {
                    namespace: namespace.clone(),
                    transform_id: "t1".into(),
                    key_column: "id".into(),
                    actor: "analyst".into(),
                    tenant: "t1".into(),
                    input_versions: original.input_versions.clone(),
                    ..ReplayTransform::default()
                },
                30,
            )
            .unwrap();
        assert_eq!(replayed.output_digest, original.output_digest);
        assert_eq!(replayed.inputs[0].version_id, pin);
        assert_eq!(replayed.inputs[0].rows, 2);
    }

    #[test]
    fn sqlite_replays_reproduce_diff_and_promote() {
        let db = Arc::new(crate::db::sekai::SekaiDb::new(":memory:").unwrap());
        exercise(&RuntimeDb::Sqlite(db.clone()), db.as_ref());
    }

    #[test]
    fn sqlite_legacy_populated_input_is_snapshotted_and_replayable() {
        let db = Arc::new(crate::db::sekai::SekaiDb::new(":memory:").unwrap());
        exercise_legacy_populated_pins(
            &RuntimeDb::Sqlite(db.clone()),
            db.as_ref(),
            &|dataset_id| {
                let conn = db.conn();
                conn.execute(
                    "DELETE FROM sekai_dataset_version_rows WHERE dataset_id = ?1",
                    rusqlite::params![dataset_id],
                )
                .unwrap();
                conn.execute(
                    "DELETE FROM sekai_dataset_versions WHERE dataset_id = ?1",
                    rusqlite::params![dataset_id],
                )
                .unwrap();
            },
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_replays_reproduce_diff_and_promote() {
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
        let db = Arc::new(db.unwrap());
        exercise(&RuntimeDb::Postgres(db.clone()), db.as_ref());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_legacy_populated_input_is_snapshotted_and_replayable() {
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
        let db = Arc::new(db.unwrap());
        exercise_legacy_populated_pins(
            &RuntimeDb::Postgres(db.clone()),
            db.as_ref(),
            &|dataset_id| {
                let mut conn = db.connection().unwrap();
                conn.execute(
                    "DELETE FROM sekai_dataset_version_rows WHERE dataset_id = $1",
                    &[&dataset_id],
                )
                .unwrap();
                conn.execute(
                    "DELETE FROM sekai_dataset_versions WHERE dataset_id = $1",
                    &[&dataset_id],
                )
                .unwrap();
            },
        );
    }
}

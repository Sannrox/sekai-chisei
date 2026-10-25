//! Shadowing a candidate transform revision (#1795) on either backend: one
//! candidate replay per run of the active revision, pinned to that run's
//! receipt and diffed against the output version the run wrote.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::governed_transform::TransformRun;
use crate::sekai::transform_replay::{self, ReplayTransform};
use crate::sekai::transform_shadow::{
    self, DEFAULT_SHADOW_RUNS, MAX_SHADOW_RUNS, SHADOW_NEEDS_CANDIDATE, SHADOW_NO_RUNS,
    SHADOW_RUN_NOT_FOUND, ShadowRun, ShadowSample, ShadowTransform, TransformShadowReport,
};
use std::collections::BTreeSet;
use std::time::Instant;

impl RuntimeDb {
    /// Shadow `request`'s candidate against the active revision. Each
    /// replayed run leaves a replay record and a `replay-` branch, as a
    /// replay does; the output dataset, objects and run history are
    /// untouched. A run that cannot be compared, or whose replay fails, is
    /// reported skipped with the reason.
    pub fn shadow_governed_transform(
        &self,
        request: &ShadowTransform,
        now_ms: i64,
    ) -> Result<TransformShadowReport, String> {
        if request.definition_json.trim().is_empty() {
            return Err(SHADOW_NEEDS_CANDIDATE.into());
        }
        let stored = self
            .get_governed_transform(&request.namespace, &request.transform_id)?
            .ok_or("governed transform not found")?;
        if !request.expected_definition_digest.is_empty()
            && stored.definition_digest != request.expected_definition_digest
        {
            return Err(transform_replay::REPLAY_TRANSFORM_CHANGED.into());
        }
        let candidate =
            crate::db::transform_replay::candidate_or_stored(&stored, &request.definition_json)?;
        let runs = self.shadowed_runs(request, &stored.definition_digest)?;
        if runs.is_empty() {
            return Err(SHADOW_NO_RUNS.into());
        }
        let candidate_inputs: BTreeSet<String> = candidate
            .input_bindings()
            .into_iter()
            .map(|(_, dataset_id)| dataset_id)
            .collect();
        let mut shadowed = Vec::with_capacity(runs.len());
        let mut samples = Vec::new();
        for run in &runs {
            let (active_latency_ms, active_compute_ms) = self
                .transform_run_finish(&run.run_id)?
                .map_or((None, None), |(finished_at_ms, compute_ms)| {
                    (Some(finished_at_ms - run.created_at_ms), compute_ms)
                });
            let entry = ShadowRun {
                run_id: run.run_id.clone(),
                active_compute_ms,
                active_latency_ms,
                ..ShadowRun::default()
            };
            let skip = |reason: &str| ShadowRun {
                skipped: reason.into(),
                ..entry.clone()
            };
            if let Some(reason) = unshadowable(run, &stored.definition_digest) {
                shadowed.push(skip(reason));
                continue;
            }
            // Recorded in the run's transaction; runs from before #1795 have
            // none.
            let Some(baseline_version_id) = self.transform_run_output_version(&run.run_id)? else {
                shadowed.push(skip(transform_shadow::SKIP_NO_OUTPUT_VERSION));
                continue;
            };
            let started = Instant::now();
            let replay = self.replay_governed_transform(
                &ReplayTransform {
                    namespace: request.namespace.clone(),
                    transform_id: request.transform_id.clone(),
                    // The run's pins for the inputs the candidate keeps; an
                    // input it adds reads the version written before the run
                    // was admitted. A version from the same millisecond may
                    // be later than the run, so it does not count.
                    input_versions: run
                        .input_versions
                        .iter()
                        .filter(|(dataset_id, _)| candidate_inputs.contains(*dataset_id))
                        .map(|(dataset_id, version)| (dataset_id.clone(), version.clone()))
                        .collect(),
                    as_of_ms: run.created_at_ms - 1,
                    definition_json: request.definition_json.clone(),
                    baseline_version_id: baseline_version_id.clone(),
                    key_column: request.key_column.clone(),
                    expected_definition_digest: stored.definition_digest.clone(),
                    actor: request.actor.clone(),
                    tenant: request.tenant.clone(),
                },
                now_ms,
            );
            let entry = ShadowRun {
                baseline_version_id,
                shadow_ms: i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
                ..entry.clone()
            };
            // Earlier replays have committed their branches and records, so
            // a failure is this run's, reported in the report rather than
            // failing the shadow and undoing its quota charge.
            let replay = match replay {
                Ok(replay) => replay,
                Err(error) => {
                    shadowed.push(ShadowRun {
                        skipped: error,
                        ..entry
                    });
                    continue;
                }
            };
            let entry = entry.compared(&replay);
            if replay.baseline_output_digest != run.output_digest {
                shadowed.push(ShadowRun {
                    skipped: transform_shadow::SKIP_BASELINE_MOVED.into(),
                    ..entry
                });
                continue;
            }
            samples.extend(replay.diff.samples.into_iter().map(|change| ShadowSample {
                run_id: run.run_id.clone(),
                change,
            }));
            shadowed.push(entry);
        }
        Ok(transform_shadow::shadow_report(
            &request.namespace,
            &request.transform_id,
            &stored.definition_digest,
            &candidate.definition_digest,
            shadowed,
            samples,
        ))
    }

    /// The named runs of the transform, in the request's order; else its
    /// newest runs of the active revision that can be shadowed.
    fn shadowed_runs(
        &self,
        request: &ShadowTransform,
        active_digest: &str,
    ) -> Result<Vec<TransformRun>, String> {
        if !request.run_ids.is_empty() {
            if request.run_ids.len() > MAX_SHADOW_RUNS {
                return Err(format!("a shadow replays at most {MAX_SHADOW_RUNS} runs"));
            }
            return request
                .run_ids
                .iter()
                .map(|run_id| {
                    self.get_governed_transform_run(run_id)?
                        .filter(|run| {
                            run.namespace == request.namespace
                                && run.transform_id == request.transform_id
                        })
                        .ok_or_else(|| format!("{SHADOW_RUN_NOT_FOUND}: {run_id}"))
                })
                .collect();
        }
        let limit = match request.limit {
            0 => DEFAULT_SHADOW_RUNS,
            limit => limit.min(MAX_SHADOW_RUNS),
        };
        Ok(self
            .list_runs_of_governed_transform(
                &request.namespace,
                &request.transform_id,
                transform_shadow::SHADOW_RUN_SCAN,
            )?
            .into_iter()
            .filter(|run| unshadowable(run, active_digest).is_none())
            .take(limit)
            .collect())
    }
}

/// Why `run` has nothing to compare a candidate with.
fn unshadowable(run: &TransformRun, active_digest: &str) -> Option<&'static str> {
    if run.definition_digest != active_digest {
        Some(transform_shadow::SKIP_OTHER_REVISION)
    } else if run.input_versions.is_empty() {
        Some(transform_shadow::SKIP_NO_PINS)
    } else if run.quarantined || !matches!(run.dispatch_status.as_str(), "" | "completed") {
        Some(transform_shadow::SKIP_NO_OUTPUT)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::dataset::DatasetBackend;
    use crate::domain::ListFilter;
    use crate::sekai::dataset::{ColumnDef, Dataset, RowQuery};
    use crate::sekai::dataset_version;
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform, TransformStep};
    use crate::sekai::transform_shadow::SKIP_OTHER_REVISION;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn row(id: &str, keep: &str) -> HashMap<String, String> {
        HashMap::from([("id".into(), id.into()), ("keep".into(), keep.into())])
    }

    fn filter(namespace: &str, input: &str, output: &str, op: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            transform_id: "t1".into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: op.into(),
                value: if op == "eq" { "yes" } else { "no" }.into(),
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

    /// The #1795 acceptance on one backend: a candidate with one changed
    /// rule shadows each active run on that run's pinned inputs, the report
    /// names exactly the rows the rule changes, and nothing live is written.
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
        // Active keeps `yes`; the candidate's one changed rule keeps all
        // but `no`, so exactly the `maybe` rows differ.
        let active = filter(&namespace, &input, &output, "eq");
        let candidate = filter(&namespace, &input, &output, "neq");
        data.append_rows(
            &input,
            &[row("1", "yes"), row("2", "no"), row("3", "maybe")],
        )
        .unwrap();
        runtime.put_governed_transform(&active, 10).unwrap();
        // Runs at the wall clock, as the output versions they write are.
        let first = runtime
            .run_governed_transform(&namespace, "t1", false, dataset_version::now_ms())
            .unwrap();
        data.append_rows(&input, &[row("4", "maybe"), row("5", "yes")])
            .unwrap();
        // Admitted in the millisecond the first run's output version was
        // written: the shadow still diffs against the second run's own.
        let first_output_ms = data.list_dataset_versions(&output).unwrap()[0].created_at_ms;
        let second = runtime
            .run_governed_transform(&namespace, "t1", false, first_output_ms)
            .unwrap();
        // Each run records the output version it left.
        let output_versions = data.list_dataset_versions(&output).unwrap();
        assert_eq!(
            runtime
                .transform_run_output_version(&second.run_id)
                .unwrap(),
            Some(output_versions.last().unwrap().version_id.clone())
        );
        // Inputs move on after the runs; the shadow reads each run's pins.
        data.append_rows(&input, &[row("6", "maybe")]).unwrap();

        let live = |runtime: &RuntimeDb| {
            (
                data.query_rows(&output, &RowQuery::default()).unwrap(),
                data.list_dataset_versions(&output).unwrap(),
                runtime
                    .list_governed_transform_runs(&namespace, 50)
                    .unwrap(),
                runtime
                    .list_all_objects(&ListFilter::default())
                    .unwrap()
                    .len(),
            )
        };
        let before = live(runtime);
        let request = ShadowTransform {
            namespace: namespace.clone(),
            transform_id: "t1".into(),
            definition_json: serde_json::to_string(&candidate).unwrap(),
            key_column: "id".into(),
            expected_definition_digest: active.definition_digest.clone(),
            actor: "analyst".into(),
            tenant: "t1".into(),
            ..ShadowTransform::default()
        };
        let report = runtime.shadow_governed_transform(&request, 40).unwrap();
        assert_eq!(report.active_definition_digest, active.definition_digest);
        assert_eq!(
            report.candidate_definition_digest,
            candidate.definition_digest
        );
        // Each run with only the rows the rule changes. The two runs may
        // share an admission millisecond, so their order is not asserted.
        let runs: std::collections::BTreeMap<&str, &[String]> = report
            .runs
            .iter()
            .map(|run| (run.run_id.as_str(), run.changed_keys.as_slice()))
            .collect();
        assert_eq!(
            runs,
            std::collections::BTreeMap::from([
                (
                    second.run_id.as_str(),
                    &["3".to_string(), "4".to_string()][..]
                ),
                (first.run_id.as_str(), &["3".to_string()][..]),
            ])
        );
        assert!(report.runs.iter().all(|run| run.skipped.is_empty()));
        assert_eq!(
            (report.rows_added, report.rows_removed, report.rows_changed),
            (3, 0, 0)
        );
        assert_eq!((report.rows_compared, report.rows_matched), (6, 3));
        assert!((report.match_rate - 0.5).abs() < 1e-9);
        assert!(
            report
                .samples
                .iter()
                .all(|sample| sample.change.after["keep"] == "maybe")
        );
        assert_eq!(report.samples.len(), 3);
        assert!(
            report
                .runs
                .iter()
                .all(|run| run.active_latency_ms.is_some())
        );

        // Shadow runs write only their replay branches: the output's rows
        // and versions, run history and objects are untouched.
        assert_eq!(live(runtime), before);
        for run in &report.runs {
            let replay = runtime
                .get_transform_replay(&run.replay_id)
                .unwrap()
                .unwrap();
            assert!(replay.candidate);
            assert_eq!(replay.branch, run.branch);
        }

        // The active revision against itself matches every row.
        let same = runtime
            .shadow_governed_transform(
                &ShadowTransform {
                    definition_json: serde_json::to_string(&active).unwrap(),
                    run_ids: vec![first.run_id.clone()],
                    ..request.clone()
                },
                50,
            )
            .unwrap();
        assert_eq!((same.runs_compared, same.match_rate), (1, 1.0));

        // A candidate reading another input reads it as of the run, not as
        // it is now.
        let other = format!("other-{suffix}");
        data.create_dataset(&Dataset {
            id: other.clone(),
            name: other.clone(),
            ..data.get_dataset(&input).unwrap().unwrap()
        })
        .unwrap();
        data.append_rows(&other, &[row("1", "yes"), row("5", "yes")])
            .unwrap();
        // Versions and runs carry millisecond times; keep them apart.
        let tick = || std::thread::sleep(std::time::Duration::from_millis(2));
        tick();
        let elsewhere = runtime
            .run_governed_transform(&namespace, "t1", false, dataset_version::now_ms())
            .unwrap();
        tick();
        data.append_rows(&other, &[row("9", "yes")]).unwrap();
        let moved = runtime
            .shadow_governed_transform(
                &ShadowTransform {
                    definition_json: serde_json::to_string(&filter(
                        &namespace, &other, &output, "eq",
                    ))
                    .unwrap(),
                    run_ids: vec![elsewhere.run_id.clone()],
                    ..request.clone()
                },
                55,
            )
            .unwrap();
        assert_eq!(moved.runs[0].skipped, "");
        assert_eq!(moved.match_rate, 1.0, "{moved:?}");

        // A named run of an older revision is reported, not compared.
        runtime.put_governed_transform(&candidate, 60).unwrap();
        let after_change = runtime
            .shadow_governed_transform(
                &ShadowTransform {
                    run_ids: vec![first.run_id.clone()],
                    expected_definition_digest: candidate.definition_digest.clone(),
                    ..request.clone()
                },
                70,
            )
            .unwrap();
        assert_eq!(after_change.runs[0].skipped, SKIP_OTHER_REVISION);
        assert_eq!(after_change.runs_compared, 0);
        // A shadow authorized against the older revision is refused.
        assert_eq!(
            runtime.shadow_governed_transform(&request, 80).unwrap_err(),
            transform_replay::REPLAY_TRANSFORM_CHANGED
        );
        assert_eq!(
            runtime
                .shadow_governed_transform(
                    &ShadowTransform {
                        definition_json: String::new(),
                        ..request.clone()
                    },
                    90,
                )
                .unwrap_err(),
            SHADOW_NEEDS_CANDIDATE
        );
    }

    #[test]
    fn sqlite_shadow_reports_the_changed_rows_and_writes_nothing_live() {
        let db = Arc::new(crate::db::sekai::SekaiDb::new(":memory:").unwrap());
        exercise(&RuntimeDb::Sqlite(db.clone()), db.as_ref());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_shadow_reports_the_changed_rows_and_writes_nothing_live() {
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
}

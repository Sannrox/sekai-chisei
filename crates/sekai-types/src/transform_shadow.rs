//! Shadowing a candidate transform revision against the active one (#1795).
//!
//! A shadow replays the candidate (ADR 0120) once per recorded run of the
//! active revision, pinned to the input versions that run's receipt names,
//! on a fresh branch of the output. Each replay is diffed against the output
//! version that run wrote, so both sides read identical inputs. Nothing runs
//! on a schedule or trigger, and nothing writes the output dataset, objects
//! or Actions. The report sums the diffs with match rate, cost and latency.

use serde::{Deserialize, Serialize};

use crate::governed_transform::GovernedTransform;
use crate::transform_replay::{MAX_SAMPLES, ReplayRowChange, TransformReplay};

/// A namespace that requires shadows refuses to promote a transform
/// revision without a passing report for it (#1796).
pub const REFUSAL_TRANSFORM_SHADOW: &str = "transform_promotion_requires_shadow_report";
pub const SHADOW_NEEDS_CANDIDATE: &str = "a shadow needs a candidate definition";
pub const SHADOW_NO_RUNS: &str = "the active revision has no runs to shadow";
pub const SHADOW_RUN_NOT_FOUND: &str = "a named run is not a run of this transform";
/// Why a named run was not replayed.
pub const SKIP_OTHER_REVISION: &str = "run of another revision";
pub const SKIP_NO_PINS: &str = "run receipt pins no input versions";
pub const SKIP_NO_OUTPUT: &str = "run wrote no output";
pub const SKIP_NO_OUTPUT_VERSION: &str = "no output version is recorded for the run";
pub const SKIP_BASELINE_MOVED: &str = "the output version does not match the run's output digest";
/// Runs a shadow replays when the request names none.
pub const DEFAULT_SHADOW_RUNS: usize = 10;
/// Most runs one shadow replays.
pub const MAX_SHADOW_RUNS: usize = 25;
/// Newest runs of the transform searched for runs of the active revision.
pub const SHADOW_RUN_SCAN: i64 = 500;

/// What to shadow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ShadowTransform {
    pub namespace: String,
    pub transform_id: String,
    /// The candidate revision (JSON); it keeps the namespace, id and output.
    pub definition_json: String,
    /// Runs of the active revision to shadow; else its newest runs.
    pub run_ids: Vec<String>,
    /// How many newest runs when `run_ids` is empty; 0 is the default.
    pub limit: usize,
    /// The row key, as for a replay.
    pub key_column: String,
    /// As for a replay: refused if the stored definition changed since.
    pub expected_definition_digest: String,
    /// Also make the namespace require a passing report before promoting
    /// any transform revision. Once set, it stays.
    pub require_for_promotion: bool,
    pub actor: String,
    pub tenant: String,
}

/// One run of the active revision, and its candidate replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ShadowRun {
    pub run_id: String,
    /// Empty when the run was not replayed.
    pub replay_id: String,
    pub branch: String,
    /// The output version the active run wrote: the diff's baseline.
    pub baseline_version_id: String,
    /// Why the run is not in the totals; empty when it is.
    pub skipped: String,
    pub rows_compared: i64,
    pub rows_matched: i64,
    pub rows_added: i64,
    pub rows_removed: i64,
    pub rows_changed: i64,
    /// Up to the replay's bound of keys added, removed or changed.
    pub changed_keys: Vec<String>,
    /// The active run's measured compute; `None` when it has none.
    pub active_compute_ms: Option<i64>,
    /// From admission to finish of the active run.
    pub active_latency_ms: Option<i64>,
    /// The candidate replay, start to commit. In-process, so it is also its
    /// compute.
    pub shadow_ms: i64,
}

/// One changed row, with the run it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ShadowSample {
    pub run_id: String,
    pub change: ReplayRowChange,
}

/// A candidate revision against the active one over the shadowed runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TransformShadowReport {
    /// The stored report's id.
    pub id: String,
    pub namespace: String,
    pub transform_id: String,
    pub active_definition_digest: String,
    pub candidate_definition_digest: String,
    /// The candidate as a definition member carries it: without schedule or
    /// trigger, which stay local. Promotion checks reports by this digest.
    pub candidate_member_digest: String,
    /// At least one run was compared. A passing report is evidence for
    /// promotion; it does not judge the differences.
    pub passing: bool,
    pub runs: Vec<ShadowRun>,
    /// Totals over the runs that were not skipped.
    pub runs_compared: i64,
    pub rows_compared: i64,
    pub rows_matched: i64,
    pub rows_added: i64,
    pub rows_removed: i64,
    pub rows_changed: i64,
    /// `rows_matched / rows_compared`; 1 when nothing was compared.
    pub match_rate: f64,
    /// Up to [`MAX_SAMPLES`] changed rows across the runs.
    pub samples: Vec<ShadowSample>,
    /// Active compute over the compared runs that measured it.
    pub active_compute_ms: i64,
    pub shadow_compute_ms: i64,
    /// Mean latency per compared run on each side.
    pub active_latency_ms: i64,
    pub shadow_latency_ms: i64,
}

impl ShadowRun {
    /// The run, compared through `replay`: rows in either side by key (or
    /// whole row) and those equal on both.
    pub fn compared(mut self, replay: &TransformReplay) -> Self {
        let diff = &replay.diff;
        self.replay_id.clone_from(&replay.id);
        self.branch.clone_from(&replay.branch);
        self.rows_compared = diff.baseline_rows + diff.rows_added;
        self.rows_matched = diff.baseline_rows - diff.rows_removed - diff.rows_changed;
        self.rows_added = diff.rows_added;
        self.rows_removed = diff.rows_removed;
        self.rows_changed = diff.rows_changed;
        self.changed_keys.clone_from(&diff.changed_keys);
        self
    }
}

/// Sum `runs` into a report; `samples` come with their run ids in run order.
pub fn shadow_report(
    namespace: &str,
    transform_id: &str,
    active_definition_digest: &str,
    candidate_definition_digest: &str,
    runs: Vec<ShadowRun>,
    samples: Vec<ShadowSample>,
) -> TransformShadowReport {
    let compared: Vec<&ShadowRun> = runs.iter().filter(|run| run.skipped.is_empty()).collect();
    let sum = |field: fn(&ShadowRun) -> i64| compared.iter().map(|run| field(run)).sum::<i64>();
    let mean = |total: i64, count: usize| match count {
        0 => 0,
        count => total / count as i64,
    };
    let active_latencies: Vec<i64> = compared
        .iter()
        .filter_map(|run| run.active_latency_ms)
        .collect();
    let (rows_compared, rows_matched) = (sum(|run| run.rows_compared), sum(|run| run.rows_matched));
    let shadow_compute_ms = sum(|run| run.shadow_ms);
    TransformShadowReport {
        namespace: namespace.into(),
        transform_id: transform_id.into(),
        active_definition_digest: active_definition_digest.into(),
        candidate_definition_digest: candidate_definition_digest.into(),
        runs_compared: compared.len() as i64,
        rows_compared,
        rows_matched,
        rows_added: sum(|run| run.rows_added),
        rows_removed: sum(|run| run.rows_removed),
        rows_changed: sum(|run| run.rows_changed),
        match_rate: match rows_compared {
            0 => 1.0,
            total => rows_matched as f64 / total as f64,
        },
        samples: samples.into_iter().take(MAX_SAMPLES).collect(),
        active_compute_ms: sum(|run| run.active_compute_ms.unwrap_or(0)),
        shadow_compute_ms,
        active_latency_ms: mean(active_latencies.iter().sum(), active_latencies.len()),
        shadow_latency_ms: mean(shadow_compute_ms, compared.len()),
        passing: !compared.is_empty(),
        runs,
        ..TransformShadowReport::default()
    }
}

/// Whether a shadow can compare `candidate` with `active` at all: both run
/// in-process and write the same output. Promotion gates only changes a
/// shadow can compare; the rest have no report to require (#1796).
pub fn shadow_can_compare(active: &GovernedTransform, candidate: &GovernedTransform) -> bool {
    active.output_dataset_id == candidate.output_dataset_id
        && !active.is_isolated_process()
        && !candidate.is_isolated_process()
}

impl TransformShadowReport {
    /// The report as stored: counts and digests. Changed keys and sample rows
    /// are values of the data and are returned, not kept.
    pub fn without_rows(&self) -> Self {
        let mut stored = self.clone();
        stored.samples.clear();
        for run in &mut stored.runs {
            run.changed_keys.clear();
        }
        stored
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transform_replay::ReplayDiff;

    #[test]
    fn only_in_process_changes_to_the_same_output_can_be_compared() {
        let transform = GovernedTransform {
            contract_version: String::new(),
            namespace: String::new(),
            transform_id: String::new(),
            input_dataset_id: String::new(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        };
        assert!(shadow_can_compare(&transform, &transform));
        let moved = GovernedTransform {
            output_dataset_id: "elsewhere".into(),
            ..transform.clone()
        };
        assert!(!shadow_can_compare(&transform, &moved));
        let isolated = GovernedTransform {
            isolated_process: Some(Default::default()),
            ..transform.clone()
        };
        assert!(!shadow_can_compare(&transform, &isolated));
        assert!(!shadow_can_compare(&isolated, &transform));
    }

    fn replay(baseline_rows: i64, added: i64, removed: i64, changed: i64) -> TransformReplay {
        TransformReplay {
            id: "r".into(),
            branch: "replay-r".into(),
            diff: ReplayDiff {
                baseline_rows,
                rows_added: added,
                rows_removed: removed,
                rows_changed: changed,
                ..ReplayDiff::default()
            },
            ..TransformReplay::default()
        }
    }

    #[test]
    fn totals_match_rate_and_means_skip_skipped_runs() {
        let run = |id: &str, shadow_ms: i64, active: Option<i64>| ShadowRun {
            run_id: id.into(),
            shadow_ms,
            active_compute_ms: active,
            active_latency_ms: active,
            ..ShadowRun::default()
        };
        // 4 baseline rows: 1 changed, 1 removed, 1 added → 2 of 5 match.
        let first = run("a", 30, Some(10)).compared(&replay(4, 1, 1, 1));
        assert_eq!((first.rows_compared, first.rows_matched), (5, 2));
        let second = run("b", 10, None).compared(&replay(5, 0, 0, 0));
        let skipped = ShadowRun {
            skipped: SKIP_BASELINE_MOVED.into(),
            ..run("c", 99, Some(99)).compared(&replay(9, 9, 0, 0))
        };
        let report = shadow_report("ns", "t", "a", "b", vec![first, second, skipped], vec![]);
        assert_eq!(report.runs_compared, 2);
        assert_eq!((report.rows_compared, report.rows_matched), (10, 7));
        assert!((report.match_rate - 0.7).abs() < 1e-9);
        assert_eq!(
            (report.active_compute_ms, report.shadow_compute_ms),
            (10, 40)
        );
        assert_eq!(
            (report.active_latency_ms, report.shadow_latency_ms),
            (10, 20)
        );
        assert_eq!(report.runs.len(), 3);
        assert!(report.passing);
        let empty = shadow_report("ns", "t", "a", "b", vec![], vec![]);
        assert_eq!((empty.match_rate, empty.shadow_latency_ms), (1.0, 0));
        assert!(!empty.passing);
    }
}

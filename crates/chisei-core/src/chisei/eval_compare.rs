//! Baseline comparison of eval runs with significance gating (#1677).
//!
//! A candidate run is compared with a baseline run of the same dataset
//! version, case by case. Whether the candidate is significantly worse is an
//! exact McNemar test on the discordant pairs: `regressions` (the baseline
//! passed and the candidate failed) against `improvements`. Under no change
//! each discordant pair is a fair coin, so the one-sided p-value is
//! `P(X >= regressions)` for `X ~ Binomial(regressions + improvements, 1/2)`.
//! Policy violation counts (#1676) are compared separately, kind by kind,
//! and any increase is reported.
//!
//! The gate fails on a significant regression (`p_value < alpha`) and, when
//! configured, on any increase in policy violations. Both runs must cover
//! every case of the dataset; a partial run is refused, never compared.
//!
//! Both runs must be judged by the same evaluator definition at the same
//! digest, since outcomes of different evaluators are not comparable. A
//! stochastic evaluator pins the model it runs on, so comparing two models
//! needs an evaluator that does not run on the model under test.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::chisei::eval_dataset::EvalDataset;
use crate::chisei::eval_policy::{ViolationKind, score_run};
use crate::chisei::eval_run::{EvalCaseResult, EvalRunSpec};

pub const EVAL_COMPARISON_CONTRACT: &str = "chisei.eval-run-comparison/v1";
pub const VERDICT_PASS: &str = "pass";
pub const VERDICT_FAIL: &str = "fail";
pub const DEFAULT_ALPHA: f64 = 0.05;

/// When a comparison fails the gate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ComparisonGate {
    /// A regression with a p-value below this is significant; in (0, 1).
    pub alpha: f64,
    /// Whether any increase in a policy violation kind fails the gate.
    pub block_on_policy_increase: bool,
}

impl Default for ComparisonGate {
    fn default() -> Self {
        Self {
            alpha: DEFAULT_ALPHA,
            block_on_policy_increase: true,
        }
    }
}

/// One run as compared: its spec and its recorded results.
pub struct ComparedRun<'a> {
    pub spec: &'a EvalRunSpec,
    pub results: &'a [EvalCaseResult],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDelta {
    pub kind: String,
    pub baseline: u64,
    pub candidate: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunComparison {
    pub contract_version: String,
    pub namespace: String,
    pub dataset: String,
    pub dataset_version: String,
    pub baseline_run_id: String,
    pub candidate_run_id: String,
    pub cases: u64,
    pub both_passed: u64,
    pub both_failed: u64,
    /// The baseline passed, the candidate failed.
    pub regressions: u64,
    /// The baseline failed, the candidate passed.
    pub improvements: u64,
    /// Exact one-sided McNemar p-value that the candidate is worse.
    pub p_value: f64,
    pub alpha: f64,
    pub significant_regression: bool,
    /// Every policy kind with both counts.
    pub policy: Vec<PolicyDelta>,
    /// The kinds whose count rose.
    pub policy_increased: Vec<String>,
    pub verdict: String,
    pub reasons: Vec<String>,
}

/// Compares `candidate` with `baseline` over `dataset` and applies `gate`.
pub fn compare_runs(
    dataset: &EvalDataset,
    baseline: ComparedRun<'_>,
    candidate: ComparedRun<'_>,
    gate: ComparisonGate,
) -> Result<RunComparison, String> {
    if !(gate.alpha > 0.0 && gate.alpha < 1.0) {
        return Err("alpha must be between 0 and 1".into());
    }
    for run in [&baseline, &candidate] {
        if run.spec.namespace != baseline.spec.namespace
            || run.spec.dataset != dataset.name
            || run.spec.dataset_version != dataset.version
        {
            return Err(
                "both runs must be of the compared dataset version in one namespace".into(),
            );
        }
    }
    // Outcomes are comparable only through the same evaluator.
    if baseline.spec.evaluator_definition_id != candidate.spec.evaluator_definition_id
        || baseline.spec.evaluator_digest != candidate.spec.evaluator_digest
    {
        return Err("both runs must use the same evaluator definition and digest".into());
    }
    if baseline.spec.run_id == candidate.spec.run_id {
        return Err("a comparison needs two distinct runs".into());
    }
    let outcomes = |run: &ComparedRun<'_>| -> Result<HashMap<String, bool>, String> {
        let recorded: HashMap<String, bool> = run
            .results
            .iter()
            .map(|result| (result.case_id.clone(), result.outcome.passed))
            .collect();
        if dataset
            .cases
            .iter()
            .any(|case| !recorded.contains_key(&case.case_id))
        {
            return Err(format!(
                "run {} has cases without a result; compare complete runs only",
                run.spec.run_id
            ));
        }
        Ok(recorded)
    };
    let (before, after) = (outcomes(&baseline)?, outcomes(&candidate)?);
    let (mut both_passed, mut both_failed, mut regressions, mut improvements) = (0, 0, 0, 0);
    for case in &dataset.cases {
        match (before[&case.case_id], after[&case.case_id]) {
            (true, true) => both_passed += 1,
            (false, false) => both_failed += 1,
            (true, false) => regressions += 1,
            (false, true) => improvements += 1,
        }
    }
    let p_value = mcnemar_one_sided(regressions, improvements);
    let significant_regression = regressions > improvements && p_value < gate.alpha;

    let counts = |run: &ComparedRun<'_>| {
        score_run(
            run.results
                .iter()
                .map(|result| (result.case_id.as_str(), result.outcome.policy.as_ref())),
        )
        .counts
    };
    let (policy_before, policy_after): (BTreeMap<_, _>, BTreeMap<_, _>) =
        (counts(&baseline), counts(&candidate));
    let policy: Vec<PolicyDelta> = ViolationKind::ALL
        .iter()
        .map(|kind| PolicyDelta {
            kind: kind.as_str().into(),
            baseline: policy_before.get(kind).copied().unwrap_or(0),
            candidate: policy_after.get(kind).copied().unwrap_or(0),
        })
        .collect();
    let policy_increased: Vec<String> = policy
        .iter()
        .filter(|delta| delta.candidate > delta.baseline)
        .map(|delta| delta.kind.clone())
        .collect();

    let mut reasons = Vec::new();
    if significant_regression {
        reasons.push(format!(
            "{regressions} cases regressed against {improvements} improved (p = {p_value:.4} < {})",
            gate.alpha
        ));
    }
    if gate.block_on_policy_increase && !policy_increased.is_empty() {
        reasons.push(format!(
            "policy violations increased: {}",
            policy_increased.join(", ")
        ));
    }
    Ok(RunComparison {
        contract_version: EVAL_COMPARISON_CONTRACT.into(),
        namespace: baseline.spec.namespace.clone(),
        dataset: dataset.name.clone(),
        dataset_version: dataset.version.clone(),
        baseline_run_id: baseline.spec.run_id.clone(),
        candidate_run_id: candidate.spec.run_id.clone(),
        cases: dataset.cases.len() as u64,
        both_passed,
        both_failed,
        regressions,
        improvements,
        p_value,
        alpha: gate.alpha,
        significant_regression,
        policy,
        policy_increased,
        verdict: if reasons.is_empty() {
            VERDICT_PASS
        } else {
            VERDICT_FAIL
        }
        .into(),
        reasons,
    })
}

/// `P(X >= regressions)` for `X ~ Binomial(regressions + improvements, 1/2)`,
/// summed in log space so thousands of discordant pairs stay exact enough.
pub fn mcnemar_one_sided(regressions: u64, improvements: u64) -> f64 {
    let n = regressions + improvements;
    if n == 0 {
        return 1.0;
    }
    // ln(k!) for k in 0..=n.
    let mut ln_factorial = Vec::with_capacity(n as usize + 1);
    ln_factorial.push(0.0_f64);
    for k in 1..=n {
        ln_factorial.push(ln_factorial[k as usize - 1] + (k as f64).ln());
    }
    let ln_half_n = n as f64 * 0.5_f64.ln();
    let p: f64 = (regressions..=n)
        .map(|k| {
            (ln_factorial[n as usize] - ln_factorial[k as usize] - ln_factorial[(n - k) as usize]
                + ln_half_n)
                .exp()
        })
        .sum();
    p.min(1.0)
}

/// One run in a dataset's trend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunTrendPoint {
    pub run_id: String,
    pub agent: String,
    pub model: String,
    pub tool_version: String,
    pub dataset_version: String,
    pub started_at_ms: i64,
    pub cases_recorded: u64,
    pub cases_passed: u64,
    /// Policy violations by kind over the recorded cases.
    pub policy: BTreeMap<String, u64>,
}

/// A trend point for one run from its recorded results.
pub fn trend_point(
    spec: &EvalRunSpec,
    started_at_ms: i64,
    results: &[EvalCaseResult],
) -> RunTrendPoint {
    RunTrendPoint {
        run_id: spec.run_id.clone(),
        agent: spec.agent.clone(),
        model: spec.model.clone(),
        tool_version: spec.tool_version.clone(),
        dataset_version: spec.dataset_version.clone(),
        started_at_ms,
        cases_recorded: results.len() as u64,
        cases_passed: results
            .iter()
            .filter(|result| result.outcome.passed)
            .count() as u64,
        policy: score_run(
            results
                .iter()
                .map(|result| (result.case_id.as_str(), result.outcome.policy.as_ref())),
        )
        .counts
        .into_iter()
        .map(|(kind, count)| (kind.as_str().to_string(), count))
        .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::eval_policy::{CasePolicyOutcome, POLICY_SCORER_VERSION, Violation};
    use crate::chisei::eval_run::CaseOutcome;
    use crate::chisei::eval_run::tests::{dataset, spec};

    fn results(passed: impl Fn(usize) -> bool, leaks: usize) -> Vec<EvalCaseResult> {
        dataset(40)
            .cases
            .iter()
            .enumerate()
            .map(|(index, case)| EvalCaseResult {
                case_id: case.case_id.clone(),
                outcome: CaseOutcome {
                    passed: passed(index),
                    reason: "fixture".into(),
                    input_tokens: 1,
                    output_tokens: 1,
                    cost_micros: 1,
                    receipts: None,
                    policy: Some(CasePolicyOutcome {
                        scorer_version: POLICY_SCORER_VERSION.into(),
                        violations: (index < leaks)
                            .then(|| Violation {
                                kind: ViolationKind::MarkingLeak,
                                case_id: case.case_id.clone(),
                                receipt_id: format!("{}/answer", case.case_id),
                            })
                            .into_iter()
                            .collect(),
                    }),
                },
                recorded_at_ms: 1,
            })
            .collect()
    }

    fn run_spec(run_id: &str) -> EvalRunSpec {
        EvalRunSpec {
            run_id: run_id.into(),
            ..spec(4, 1_000)
        }
    }

    #[test]
    fn exact_mcnemar_matches_the_binomial_tail() {
        assert_eq!(mcnemar_one_sided(0, 0), 1.0);
        // P(X >= 5 | n = 5) = 1/32.
        assert!((mcnemar_one_sided(5, 0) - 1.0 / 32.0).abs() < 1e-12);
        // P(X >= 8 | n = 10) = (45 + 10 + 1) / 1024.
        assert!((mcnemar_one_sided(8, 2) - 56.0 / 1024.0).abs() < 1e-12);
        assert!(mcnemar_one_sided(500, 500) > 0.5);
    }

    #[test]
    fn a_seeded_regression_is_significant_and_fails_the_gate() {
        let dataset = dataset(40);
        let (baseline_spec, candidate_spec) = (run_spec("baseline"), run_spec("candidate"));
        let baseline = results(|_| true, 0);
        // Ten cases that passed now fail.
        let regressed = results(|index| index >= 10, 0);
        let comparison = compare_runs(
            &dataset,
            ComparedRun {
                spec: &baseline_spec,
                results: &baseline,
            },
            ComparedRun {
                spec: &candidate_spec,
                results: &regressed,
            },
            ComparisonGate::default(),
        )
        .unwrap();
        assert_eq!((comparison.regressions, comparison.improvements), (10, 0));
        assert!(comparison.significant_regression);
        assert_eq!(comparison.verdict, VERDICT_FAIL);

        // An unchanged candidate passes.
        let unchanged = compare_runs(
            &dataset,
            ComparedRun {
                spec: &baseline_spec,
                results: &baseline,
            },
            ComparedRun {
                spec: &candidate_spec,
                results: &baseline,
            },
            ComparisonGate::default(),
        )
        .unwrap();
        assert_eq!(unchanged.verdict, VERDICT_PASS);
        assert_eq!(unchanged.p_value, 1.0);
    }

    #[test]
    fn a_new_policy_violation_is_reported_and_gates_when_configured() {
        let dataset = dataset(40);
        let (baseline_spec, candidate_spec) = (run_spec("baseline"), run_spec("candidate"));
        let (baseline, leaking) = (results(|_| true, 0), results(|_| true, 2));
        let compare = |gate| {
            compare_runs(
                &dataset,
                ComparedRun {
                    spec: &baseline_spec,
                    results: &baseline,
                },
                ComparedRun {
                    spec: &candidate_spec,
                    results: &leaking,
                },
                gate,
            )
            .unwrap()
        };
        let blocked = compare(ComparisonGate::default());
        assert_eq!(blocked.policy_increased, ["marking_leak"]);
        assert_eq!(blocked.verdict, VERDICT_FAIL);
        let reported = compare(ComparisonGate {
            block_on_policy_increase: false,
            ..ComparisonGate::default()
        });
        assert_eq!(reported.policy_increased, ["marking_leak"]);
        assert_eq!(reported.verdict, VERDICT_PASS);
    }

    #[test]
    fn partial_runs_and_mismatched_datasets_are_refused() {
        let dataset = dataset(40);
        let (baseline_spec, candidate_spec) = (run_spec("baseline"), run_spec("candidate"));
        let baseline = results(|_| true, 0);
        let partial = &baseline[..30];
        assert!(
            compare_runs(
                &dataset,
                ComparedRun {
                    spec: &baseline_spec,
                    results: &baseline
                },
                ComparedRun {
                    spec: &candidate_spec,
                    results: partial
                },
                ComparisonGate::default(),
            )
            .is_err()
        );
        let other_version = EvalRunSpec {
            dataset_version: "v-other".into(),
            ..run_spec("candidate")
        };
        assert!(
            compare_runs(
                &dataset,
                ComparedRun {
                    spec: &baseline_spec,
                    results: &baseline
                },
                ComparedRun {
                    spec: &other_version,
                    results: &baseline
                },
                ComparisonGate::default(),
            )
            .is_err()
        );
        assert!(
            compare_runs(
                &dataset,
                ComparedRun {
                    spec: &baseline_spec,
                    results: &baseline
                },
                ComparedRun {
                    spec: &baseline_spec,
                    results: &baseline
                },
                ComparisonGate::default(),
            )
            .is_err()
        );
        let other_evaluator = EvalRunSpec {
            evaluator_digest: "sha256:another-evaluator".into(),
            ..run_spec("candidate")
        };
        assert!(
            compare_runs(
                &dataset,
                ComparedRun {
                    spec: &baseline_spec,
                    results: &baseline
                },
                ComparedRun {
                    spec: &other_evaluator,
                    results: &baseline
                },
                ComparisonGate::default(),
            )
            .is_err()
        );
    }
}

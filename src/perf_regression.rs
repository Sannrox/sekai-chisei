//! Statistical regression gating for control-plane performance reports.
//!
//! A single benchmark run cannot distinguish a real regression from measurement
//! noise. Repeated observation of the checked-in workloads on identical hardware
//! shows run-to-run spread reaching 60% on sub-microsecond workloads and 26% on
//! filesystem-bound startup, while most workloads stay within 12%. Gating on a
//! single sample against a fixed budget therefore produces false failures.
//!
//! This module gates on the median of repeated runs and refuses to gate at all
//! when a workload's measured dispersion, or its absolute latency, leaves it
//! below the resolution the harness can defend.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Minimum repetitions required before any gate decision is trustworthy.
pub const MIN_REPETITIONS: usize = 3;

/// Relative standard deviation at or above which a workload is not
/// gate-eligible. The comparison is inclusive: a workload sitting exactly on
/// the ceiling is excluded, because a false exclusion costs a missed regression
/// while a false inclusion costs a red CI run on unchanged code.
pub const NOISE_CEILING_RSD_PERCENT: f64 = 25.0;

/// Latency below which timer resolution dominates the measurement.
pub const MIN_GATEABLE_LATENCY_US: f64 = 1.0;

/// Multiple of observed dispersion a median must exceed before a budget breach
/// counts as significant rather than as sampling noise.
pub const SIGNIFICANCE_FACTOR: f64 = 1.5;

/// One workload measurement extracted from a `sekai.performance-report/v1` run.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkloadSample {
    pub id: String,
    pub p50_latency_us: f64,
    pub p95_latency_us: f64,
    pub p99_latency_us: f64,
    pub relative_standard_deviation_percent: f64,
}

/// Latency budget for a workload, mirroring the manifest `budgets` object.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct WorkloadBudget {
    pub p50_latency_us: f64,
    pub p95_latency_us: f64,
    pub p99_latency_us: f64,
}

/// Why a workload cannot carry a regression gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Ineligibility {
    /// Observed dispersion exceeds [`NOISE_CEILING_RSD_PERCENT`].
    NoiseDominated,
    /// Measured latency sits at or below timer resolution.
    BelowTimerResolution,
    /// Fewer than [`MIN_REPETITIONS`] samples were supplied.
    InsufficientSamples,
}

/// Outcome of gating a single workload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum GateOutcome {
    /// Median is within budget.
    WithinBudget,
    /// Median exceeds budget by more than the significance margin.
    SignificantRegression {
        observed_us: f64,
        budget_us: f64,
        exceeded_by_percent: f64,
    },
    /// Median exceeds budget, but not beyond measured dispersion.
    InconclusiveBreach {
        observed_us: f64,
        budget_us: f64,
        dispersion_percent: f64,
    },
    /// Workload is excluded from gating.
    NotGateable(Ineligibility),
}

impl GateOutcome {
    /// Whether this outcome should fail CI or release validation.
    pub fn fails_gate(&self) -> bool {
        matches!(self, GateOutcome::SignificantRegression { .. })
    }
}

/// Gate decision for one workload, including the evidence behind it.
#[derive(Debug, Clone, Serialize)]
pub struct WorkloadDecision {
    pub id: String,
    pub repetitions: usize,
    pub median_p95_us: f64,
    pub spread_percent: f64,
    pub outcome: GateOutcome,
}

/// Aggregate gate decision across every workload in a manifest.
#[derive(Debug, Clone, Serialize)]
pub struct GateReport {
    pub decisions: Vec<WorkloadDecision>,
}

impl GateReport {
    /// Workloads whose regression is significant enough to fail the gate.
    pub fn failures(&self) -> Vec<&WorkloadDecision> {
        self.decisions
            .iter()
            .filter(|decision| decision.outcome.fails_gate())
            .collect()
    }

    /// Workloads excluded from gating, which need harness work before they
    /// can defend a budget.
    pub fn ungateable(&self) -> Vec<&WorkloadDecision> {
        self.decisions
            .iter()
            .filter(|decision| matches!(decision.outcome, GateOutcome::NotGateable(_)))
            .collect()
    }

    pub fn passed(&self) -> bool {
        self.failures().is_empty()
    }
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|left, right| left.partial_cmp(right).expect("finite latency samples"));
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn spread_percent(values: &[f64], median_value: f64) -> f64 {
    if median_value <= 0.0 {
        return f64::INFINITY;
    }
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    (max - min) / median_value * 100.0
}

/// Gate one workload across repeated runs against its budget.
pub fn evaluate_workload(
    id: &str,
    samples: &[WorkloadSample],
    budget: &WorkloadBudget,
) -> WorkloadDecision {
    let repetitions = samples.len();
    let mut p95_values: Vec<f64> = samples.iter().map(|s| s.p95_latency_us).collect();

    if repetitions < MIN_REPETITIONS {
        let median_p95 = if p95_values.is_empty() {
            0.0
        } else {
            median(&mut p95_values)
        };
        return WorkloadDecision {
            id: id.to_string(),
            repetitions,
            median_p95_us: median_p95,
            spread_percent: 0.0,
            outcome: GateOutcome::NotGateable(Ineligibility::InsufficientSamples),
        };
    }

    let median_p95 = median(&mut p95_values);
    let spread = spread_percent(&p95_values, median_p95);
    let worst_rsd = samples
        .iter()
        .map(|s| s.relative_standard_deviation_percent)
        .fold(0.0_f64, f64::max);
    let dispersion = spread.max(worst_rsd);

    let outcome = if median_p95 < MIN_GATEABLE_LATENCY_US {
        GateOutcome::NotGateable(Ineligibility::BelowTimerResolution)
    } else if dispersion >= NOISE_CEILING_RSD_PERCENT {
        GateOutcome::NotGateable(Ineligibility::NoiseDominated)
    } else if median_p95 <= budget.p95_latency_us {
        GateOutcome::WithinBudget
    } else {
        let exceeded_by = (median_p95 - budget.p95_latency_us) / budget.p95_latency_us * 100.0;
        if exceeded_by > dispersion * SIGNIFICANCE_FACTOR {
            GateOutcome::SignificantRegression {
                observed_us: median_p95,
                budget_us: budget.p95_latency_us,
                exceeded_by_percent: exceeded_by,
            }
        } else {
            GateOutcome::InconclusiveBreach {
                observed_us: median_p95,
                budget_us: budget.p95_latency_us,
                dispersion_percent: dispersion,
            }
        }
    };

    WorkloadDecision {
        id: id.to_string(),
        repetitions,
        median_p95_us: median_p95,
        spread_percent: spread,
        outcome,
    }
}

/// Gate every workload that appears in both the repeated runs and the budgets.
pub fn evaluate(
    runs: &[Vec<WorkloadSample>],
    budgets: &BTreeMap<String, WorkloadBudget>,
) -> GateReport {
    let mut by_workload: BTreeMap<String, Vec<WorkloadSample>> = BTreeMap::new();
    for run in runs {
        for sample in run {
            by_workload
                .entry(sample.id.clone())
                .or_default()
                .push(sample.clone());
        }
    }

    let decisions = budgets
        .iter()
        .filter_map(|(id, budget)| {
            by_workload
                .get(id)
                .map(|samples| evaluate_workload(id, samples, budget))
        })
        .collect();

    GateReport { decisions }
}

// --- Baseline-relative comparison ---
//
// The budget gate above answers "is it fast enough". Detecting a regression
// asks a different question: "did it get slower". Those diverge sharply here,
// because the checked-in budgets carry between 1.6x and 119.6x headroom over
// observed values, so a budget gate only fires on a catastrophic slowdown while
// an ordinary regression passes silently.
//
// Comparing against a recorded baseline closes that gap, at the cost of
// requiring the baseline to describe the same hardware.

/// Relative change smaller than this is never called a regression, however
/// quiet the measurement. Below it the result is real but not worth a failure.
pub const MIN_DETECTABLE_REGRESSION_PERCENT: f64 = 5.0;

/// How a workload compares against its recorded baseline.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum BaselineVerdict {
    /// Within combined measurement noise.
    Unchanged,
    /// Measurably faster than baseline.
    Improved { delta_percent: f64 },
    /// Measurably slower than baseline, beyond noise and the detection floor.
    Regressed {
        delta_percent: f64,
        threshold_percent: f64,
    },
    /// Excluded for the same reasons the budget gate excludes a workload.
    NotComparable(Ineligibility),
    /// Present in the current runs but absent from the baseline.
    MissingFromBaseline,
}

impl BaselineVerdict {
    pub fn is_regression(&self) -> bool {
        matches!(self, BaselineVerdict::Regressed { .. })
    }
}

/// One workload's comparison against baseline.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineComparison {
    pub id: String,
    pub baseline_p95_us: f64,
    pub current_median_p95_us: f64,
    pub delta_percent: f64,
    pub combined_noise_percent: f64,
    pub verdict: BaselineVerdict,
}

/// Comparison across every workload shared by the runs and the baseline.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineReport {
    pub comparisons: Vec<BaselineComparison>,
}

impl BaselineReport {
    pub fn regressions(&self) -> Vec<&BaselineComparison> {
        self.comparisons
            .iter()
            .filter(|comparison| comparison.verdict.is_regression())
            .collect()
    }

    pub fn improvements(&self) -> Vec<&BaselineComparison> {
        self.comparisons
            .iter()
            .filter(|comparison| matches!(comparison.verdict, BaselineVerdict::Improved { .. }))
            .collect()
    }

    pub fn passed(&self) -> bool {
        self.regressions().is_empty()
    }
}

/// Combine two independent relative uncertainties.
///
/// Added in quadrature rather than summed: the baseline and the current runs
/// are separate measurements, so their variances add while their standard
/// deviations do not. Summing would overstate the noise and hide real
/// regressions behind an inflated threshold.
fn combine_noise(current_percent: f64, baseline_percent: f64) -> f64 {
    (current_percent.powi(2) + baseline_percent.powi(2)).sqrt()
}

/// Compare one workload's repeated runs against its baseline sample.
pub fn compare_workload(
    id: &str,
    samples: &[WorkloadSample],
    baseline: &WorkloadSample,
) -> BaselineComparison {
    let mut p95_values: Vec<f64> = samples.iter().map(|s| s.p95_latency_us).collect();
    let current_median = if p95_values.is_empty() {
        0.0
    } else {
        median(&mut p95_values)
    };

    let mut comparison = BaselineComparison {
        id: id.to_string(),
        baseline_p95_us: baseline.p95_latency_us,
        current_median_p95_us: current_median,
        delta_percent: 0.0,
        combined_noise_percent: 0.0,
        verdict: BaselineVerdict::Unchanged,
    };

    // The observed delta is always reported, even when the verdict is
    // NotComparable. Leaving it at zero made a row read as "no change" while
    // its baseline and current columns visibly disagreed; comparability is the
    // verdict's job, not the number's.
    if baseline.p95_latency_us > 0.0 {
        comparison.delta_percent =
            (current_median - baseline.p95_latency_us) / baseline.p95_latency_us * 100.0;
    }

    if samples.len() < MIN_REPETITIONS {
        comparison.verdict = BaselineVerdict::NotComparable(Ineligibility::InsufficientSamples);
        return comparison;
    }
    if current_median < MIN_GATEABLE_LATENCY_US || baseline.p95_latency_us < MIN_GATEABLE_LATENCY_US
    {
        comparison.verdict = BaselineVerdict::NotComparable(Ineligibility::BelowTimerResolution);
        return comparison;
    }

    let spread = spread_percent(&p95_values, current_median);
    let worst_current_rsd = samples
        .iter()
        .map(|s| s.relative_standard_deviation_percent)
        .fold(0.0_f64, f64::max);
    let current_dispersion = spread.max(worst_current_rsd);
    let noise = combine_noise(
        current_dispersion,
        baseline.relative_standard_deviation_percent,
    );
    comparison.combined_noise_percent = noise;

    if current_dispersion >= NOISE_CEILING_RSD_PERCENT {
        comparison.verdict = BaselineVerdict::NotComparable(Ineligibility::NoiseDominated);
        return comparison;
    }

    let delta = comparison.delta_percent;

    let threshold = (noise * SIGNIFICANCE_FACTOR).max(MIN_DETECTABLE_REGRESSION_PERCENT);
    comparison.verdict = if delta > threshold {
        BaselineVerdict::Regressed {
            delta_percent: delta,
            threshold_percent: threshold,
        }
    } else if -delta > threshold {
        BaselineVerdict::Improved {
            delta_percent: delta,
        }
    } else {
        BaselineVerdict::Unchanged
    };
    comparison
}

/// Compare repeated runs against a recorded baseline.
pub fn compare_to_baseline(
    runs: &[Vec<WorkloadSample>],
    baseline: &[WorkloadSample],
) -> BaselineReport {
    let mut by_workload: BTreeMap<String, Vec<WorkloadSample>> = BTreeMap::new();
    for run in runs {
        for sample in run {
            by_workload
                .entry(sample.id.clone())
                .or_default()
                .push(sample.clone());
        }
    }
    let baseline_by_id: BTreeMap<&str, &WorkloadSample> = baseline
        .iter()
        .map(|sample| (sample.id.as_str(), sample))
        .collect();

    let comparisons = by_workload
        .iter()
        .map(|(id, samples)| match baseline_by_id.get(id.as_str()) {
            Some(baseline_sample) => compare_workload(id, samples, baseline_sample),
            None => {
                let mut p95_values: Vec<f64> = samples.iter().map(|s| s.p95_latency_us).collect();
                let current_median = if p95_values.is_empty() {
                    0.0
                } else {
                    median(&mut p95_values)
                };
                BaselineComparison {
                    id: id.clone(),
                    baseline_p95_us: 0.0,
                    current_median_p95_us: current_median,
                    delta_percent: 0.0,
                    combined_noise_percent: 0.0,
                    verdict: BaselineVerdict::MissingFromBaseline,
                }
            }
        })
        .collect();

    BaselineReport { comparisons }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, p95: f64, rsd: f64) -> WorkloadSample {
        WorkloadSample {
            id: id.to_string(),
            p50_latency_us: p95 / 2.0,
            p95_latency_us: p95,
            p99_latency_us: p95 * 1.2,
            relative_standard_deviation_percent: rsd,
        }
    }

    fn budget(p95: f64) -> WorkloadBudget {
        WorkloadBudget {
            p50_latency_us: p95 / 2.0,
            p95_latency_us: p95,
            p99_latency_us: p95 * 1.5,
        }
    }

    #[test]
    fn stable_workload_within_budget_passes() {
        let samples = vec![
            sample("policy", 6.0, 5.0),
            sample("policy", 6.2, 6.0),
            sample("policy", 6.1, 5.5),
        ];
        let decision = evaluate_workload("policy", &samples, &budget(10.0));
        assert_eq!(decision.outcome, GateOutcome::WithinBudget);
        assert!(!decision.outcome.fails_gate());
    }

    #[test]
    fn large_stable_breach_is_significant() {
        let samples = vec![
            sample("egress", 50.0, 3.0),
            sample("egress", 51.0, 3.0),
            sample("egress", 50.5, 3.0),
        ];
        let decision = evaluate_workload("egress", &samples, &budget(30.0));
        assert!(decision.outcome.fails_gate());
        match decision.outcome {
            GateOutcome::SignificantRegression {
                exceeded_by_percent,
                ..
            } => assert!(exceeded_by_percent > 60.0),
            other => panic!("expected significant regression, got {other:?}"),
        }
    }

    #[test]
    fn marginal_breach_within_dispersion_is_inconclusive() {
        let samples = vec![
            sample("gunshi", 31.0, 12.0),
            sample("gunshi", 32.0, 12.0),
            sample("gunshi", 30.5, 12.0),
        ];
        let decision = evaluate_workload("gunshi", &samples, &budget(30.0));
        assert!(!decision.outcome.fails_gate());
        assert!(matches!(
            decision.outcome,
            GateOutcome::InconclusiveBreach { .. }
        ));
    }

    #[test]
    fn noise_dominated_workload_is_not_gateable() {
        // Mirrors the measured behaviour of startup_fresh_sqlite.
        let samples = vec![
            sample("startup", 23000.0, 20.8),
            sample("startup", 30000.0, 22.0),
            sample("startup", 28000.0, 19.0),
        ];
        let decision = evaluate_workload("startup", &samples, &budget(25000.0));
        assert_eq!(
            decision.outcome,
            GateOutcome::NotGateable(Ineligibility::NoiseDominated)
        );
        assert!(!decision.outcome.fails_gate());
    }

    #[test]
    fn dispersion_exactly_on_the_ceiling_is_excluded() {
        // median 28000, spread (30000-23000)/28000 == exactly 25.0%.
        let samples = vec![
            sample("startup", 23000.0, 1.0),
            sample("startup", 30000.0, 1.0),
            sample("startup", 28000.0, 1.0),
        ];
        let decision = evaluate_workload("startup", &samples, &budget(25000.0));
        assert_eq!(decision.spread_percent, NOISE_CEILING_RSD_PERCENT);
        assert_eq!(
            decision.outcome,
            GateOutcome::NotGateable(Ineligibility::NoiseDominated)
        );
    }

    #[test]
    fn sub_microsecond_workload_is_below_timer_resolution() {
        // Mirrors the measured behaviour of provider_failure_fallback.
        let samples = vec![
            sample("fallback", 0.4, 11.9),
            sample("fallback", 0.2, 10.0),
            sample("fallback", 0.3, 12.0),
        ];
        let decision = evaluate_workload("fallback", &samples, &budget(0.5));
        assert_eq!(
            decision.outcome,
            GateOutcome::NotGateable(Ineligibility::BelowTimerResolution)
        );
    }

    #[test]
    fn single_run_is_never_gateable() {
        let samples = vec![sample("policy", 6.0, 5.0)];
        let decision = evaluate_workload("policy", &samples, &budget(10.0));
        assert_eq!(
            decision.outcome,
            GateOutcome::NotGateable(Ineligibility::InsufficientSamples)
        );
    }

    // --- Baseline comparison ---

    #[test]
    fn quiet_slowdown_beyond_noise_is_a_regression() {
        let baseline = sample("egress", 30.0, 2.0);
        let samples = vec![
            sample("egress", 40.0, 2.0),
            sample("egress", 40.5, 2.0),
            sample("egress", 39.8, 2.0),
        ];
        let comparison = compare_workload("egress", &samples, &baseline);
        assert!(comparison.verdict.is_regression(), "{:?}", comparison);
        assert!((comparison.delta_percent - 33.3).abs() < 1.0);
    }

    #[test]
    fn slowdown_inside_combined_noise_is_unchanged() {
        // 10% slower, but both measurements are noisy enough that the
        // combined threshold exceeds the delta.
        let baseline = sample("egress", 30.0, 12.0);
        let samples = vec![
            sample("egress", 33.0, 12.0),
            sample("egress", 33.0, 12.0),
            sample("egress", 33.0, 12.0),
        ];
        let comparison = compare_workload("egress", &samples, &baseline);
        assert_eq!(comparison.verdict, BaselineVerdict::Unchanged);
    }

    #[test]
    fn small_delta_never_regresses_however_quiet() {
        // 3% slower with near-zero noise: real, but under the detection floor.
        let baseline = sample("egress", 100.0, 0.01);
        let samples = vec![
            sample("egress", 103.0, 0.01),
            sample("egress", 103.0, 0.01),
            sample("egress", 103.0, 0.01),
        ];
        let comparison = compare_workload("egress", &samples, &baseline);
        assert_eq!(comparison.verdict, BaselineVerdict::Unchanged);
        assert!(comparison.combined_noise_percent < MIN_DETECTABLE_REGRESSION_PERCENT);
    }

    #[test]
    fn measurable_speedup_is_reported_not_failed() {
        let baseline = sample("persist", 100.0, 2.0);
        let samples = vec![
            sample("persist", 80.0, 2.0),
            sample("persist", 81.0, 2.0),
            sample("persist", 79.0, 2.0),
        ];
        let comparison = compare_workload("persist", &samples, &baseline);
        assert!(matches!(
            comparison.verdict,
            BaselineVerdict::Improved { .. }
        ));
        assert!(!comparison.verdict.is_regression());
    }

    #[test]
    fn noise_dominated_workload_is_not_comparable() {
        let baseline = sample("startup", 20000.0, 2.0);
        let samples = vec![
            sample("startup", 30000.0, 30.0),
            sample("startup", 31000.0, 30.0),
            sample("startup", 29000.0, 30.0),
        ];
        let comparison = compare_workload("startup", &samples, &baseline);
        assert_eq!(
            comparison.verdict,
            BaselineVerdict::NotComparable(Ineligibility::NoiseDominated)
        );
        assert!(!comparison.verdict.is_regression());
    }

    #[test]
    fn sub_microsecond_workload_is_not_comparable() {
        let baseline = sample("fallback", 0.4, 5.0);
        let samples = vec![
            sample("fallback", 0.9, 5.0),
            sample("fallback", 0.9, 5.0),
            sample("fallback", 0.9, 5.0),
        ];
        let comparison = compare_workload("fallback", &samples, &baseline);
        assert_eq!(
            comparison.verdict,
            BaselineVerdict::NotComparable(Ineligibility::BelowTimerResolution)
        );
    }

    #[test]
    fn noise_combines_in_quadrature_not_by_sum() {
        // 3 and 4 combine to 5, not 7. Summing would inflate the threshold and
        // hide real regressions.
        let combined = combine_noise(3.0, 4.0);
        assert!((combined - 5.0).abs() < 1e-9, "got {combined}");
    }

    #[test]
    fn not_comparable_rows_still_report_their_observed_delta() {
        // A noise-dominated workload whose baseline and current differ by 42%
        // must not render as 0.0%: that reads as "no change" to anyone
        // scanning the delta column.
        let baseline = sample("attestation", 390.1, 2.0);
        let samples = vec![
            sample("attestation", 225.5, 30.0),
            sample("attestation", 226.0, 30.0),
            sample("attestation", 225.0, 30.0),
        ];
        let comparison = compare_workload("attestation", &samples, &baseline);
        assert_eq!(
            comparison.verdict,
            BaselineVerdict::NotComparable(Ineligibility::NoiseDominated)
        );
        assert!(
            comparison.delta_percent < -40.0,
            "delta not reported for a non-comparable row: {}",
            comparison.delta_percent
        );
    }

    #[test]
    fn workload_absent_from_baseline_is_flagged_not_silently_passed() {
        let runs = vec![
            vec![sample("brand_new", 10.0, 1.0)],
            vec![sample("brand_new", 10.0, 1.0)],
            vec![sample("brand_new", 10.0, 1.0)],
        ];
        let report = compare_to_baseline(&runs, &[sample("other", 5.0, 1.0)]);
        assert_eq!(report.comparisons.len(), 1);
        assert_eq!(
            report.comparisons[0].verdict,
            BaselineVerdict::MissingFromBaseline
        );
        assert!(report.passed());
    }

    #[test]
    fn baseline_report_separates_regressions_from_improvements() {
        let baseline = vec![sample("slow", 30.0, 2.0), sample("fast", 100.0, 2.0)];
        let runs: Vec<Vec<WorkloadSample>> = (0..3)
            .map(|_| vec![sample("slow", 45.0, 2.0), sample("fast", 70.0, 2.0)])
            .collect();
        let report = compare_to_baseline(&runs, &baseline);
        assert!(!report.passed());
        assert_eq!(report.regressions().len(), 1);
        assert_eq!(report.regressions()[0].id, "slow");
        assert_eq!(report.improvements().len(), 1);
        assert_eq!(report.improvements()[0].id, "fast");
    }

    #[test]
    fn report_separates_failures_from_exclusions() {
        let mut budgets = BTreeMap::new();
        budgets.insert("egress".to_string(), budget(30.0));
        budgets.insert("fallback".to_string(), budget(0.5));

        let runs = vec![
            vec![sample("egress", 50.0, 3.0), sample("fallback", 0.4, 11.0)],
            vec![sample("egress", 51.0, 3.0), sample("fallback", 0.2, 10.0)],
            vec![sample("egress", 50.5, 3.0), sample("fallback", 0.3, 12.0)],
        ];

        let report = evaluate(&runs, &budgets);
        assert!(!report.passed());
        assert_eq!(report.failures().len(), 1);
        assert_eq!(report.failures()[0].id, "egress");
        assert_eq!(report.ungateable().len(), 1);
        assert_eq!(report.ungateable()[0].id, "fallback");
    }
}

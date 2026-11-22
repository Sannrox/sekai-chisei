//! Evaluate repeated benchmark reports against the checked-in budgets.
//!
//! `perf_regression` gates on the median of repeated runs, so this driver takes
//! several `sekai.performance-report` files (v1 or v2) rather than one:
//!
//! ```text
//! perf-gate --manifest benchmarks/manifest-v1.json run1.json run2.json run3.json [--enforce]
//! ```
//!
//! Without `--enforce` the exit status is always zero and the run is a
//! measurement. `--enforce` makes a significant regression fail the process.
//! That split exists because absolute latency budgets are hardware-specific:
//! the checked-in budgets were calibrated on Apple M2 Pro, and enforcing them
//! unchanged on other hardware fails for reasons unrelated to a code change.
//!
//! v2 reports also carry plane signals per workload. Those are gated against
//! the manifest's `signal_budgets` and the baseline the same way; a baseline
//! without signals skips the signal comparison.

use sekai_chisei::perf_regression::{
    BaselineVerdict, GateOutcome, Ineligibility, MIN_DETECTABLE_REGRESSION_PERCENT,
    MIN_REPETITIONS, WorkloadBudget, WorkloadSample, compare_to_baseline_with_threshold, evaluate,
};
use sekai_chisei::perf_signals::{
    SignalOutcome, SignalVerdict, WorkloadSignals, compare_signals_to_baseline, evaluate_signals,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::process::ExitCode;

#[derive(Debug, Deserialize)]
struct Report {
    results: Vec<WorkloadSample>,
}

/// The same report read for its plane signals only.
#[derive(Debug, Deserialize)]
struct SignalReport {
    results: Vec<WorkloadSignals>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    workloads: Vec<ManifestWorkload>,
}

#[derive(Debug, Deserialize)]
struct ManifestWorkload {
    id: String,
    budgets: WorkloadBudget,
    #[serde(default)]
    signal_budgets: BTreeMap<String, f64>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("perf-gate: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut manifest_path = None;
    let mut baseline_path = None;
    let mut enforce = false;
    let mut regression_threshold_percent = MIN_DETECTABLE_REGRESSION_PERCENT;
    let mut report_paths = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => {
                manifest_path = Some(args.next().ok_or("--manifest requires a path")?);
            }
            "--baseline" => {
                baseline_path = Some(args.next().ok_or("--baseline requires a path")?);
            }
            "--regression-threshold-percent" => {
                let raw = args
                    .next()
                    .ok_or("--regression-threshold-percent requires a number")?;
                let parsed: f64 = raw
                    .parse()
                    .map_err(|_| format!("invalid --regression-threshold-percent {raw}"))?;
                if !parsed.is_finite() || parsed <= 0.0 {
                    return Err("--regression-threshold-percent must be a positive number".into());
                }
                regression_threshold_percent = parsed;
            }
            "--enforce" => enforce = true,
            other if other.starts_with("--") => {
                return Err(format!("unknown flag {other}"));
            }
            other => report_paths.push(other.to_string()),
        }
    }

    let manifest_path = manifest_path.unwrap_or_else(|| "benchmarks/manifest-v1.json".to_string());
    if report_paths.len() < MIN_REPETITIONS {
        return Err(format!(
            "need at least {MIN_REPETITIONS} reports to separate a regression from noise, got {}",
            report_paths.len()
        ));
    }

    let manifest_bytes =
        std::fs::read(&manifest_path).map_err(|e| format!("read {manifest_path}: {e}"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("parse {manifest_path}: {e}"))?;
    let mut budgets = BTreeMap::new();
    let mut signal_budgets = BTreeMap::new();
    for workload in manifest.workloads {
        // A later duplicate would silently replace the budget a reader sees first.
        if budgets
            .insert(workload.id.clone(), workload.budgets)
            .is_some()
        {
            return Err(format!(
                "{manifest_path}: duplicate workload id {:?}",
                workload.id
            ));
        }
        signal_budgets.insert(workload.id, workload.signal_budgets);
    }

    let mut runs = Vec::new();
    let mut signal_runs = Vec::new();
    for path in &report_paths {
        let (report, signals) = read_report(path)?;
        runs.push(report.results);
        signal_runs.push(signals.results);
    }

    let gate = evaluate(&runs, &budgets);

    println!(
        "{:<36}{:>12}{:>10}  outcome",
        "workload", "median p95", "spread"
    );
    println!("{}", "-".repeat(78));
    for decision in &gate.decisions {
        let outcome = match &decision.outcome {
            GateOutcome::WithinBudget => "within budget".to_string(),
            GateOutcome::SignificantRegression {
                exceeded_by_percent,
                budget_us,
                ..
            } => format!("REGRESSION +{exceeded_by_percent:.1}% over {budget_us:.1}us"),
            GateOutcome::InconclusiveBreach {
                dispersion_percent, ..
            } => format!("over budget, within noise ({dispersion_percent:.1}%)"),
            GateOutcome::NotGateable(reason) => match reason {
                Ineligibility::NoiseDominated => "not gateable: noise dominated".to_string(),
                Ineligibility::BelowTimerResolution => {
                    "not gateable: below timer resolution".to_string()
                }
                Ineligibility::InsufficientSamples => {
                    "not gateable: insufficient samples".to_string()
                }
            },
        };
        println!(
            "{:<36}{:>12.1}{:>9.0}%  {outcome}",
            decision.id, decision.median_p95_us, decision.spread_percent
        );
    }
    println!("{}", "-".repeat(78));

    let signal_gate = evaluate_signals(&signal_runs, &signal_budgets);
    let signal_failures = signal_gate
        .iter()
        .filter(|decision| decision.outcome.fails_gate())
        .count();
    if !signal_gate.is_empty() {
        println!();
        println!(
            "{:<36}{:<20}{:>12}{:>10}  outcome",
            "workload", "signal", "median", "spread"
        );
        println!("{}", "-".repeat(98));
        for decision in &signal_gate {
            let outcome = match &decision.outcome {
                SignalOutcome::WithinBudget => "within budget".to_string(),
                SignalOutcome::Regression { worse_by_percent } => format!(
                    "REGRESSION +{worse_by_percent:.1}% over {:.3}",
                    decision.budget
                ),
                SignalOutcome::InconclusiveBreach {
                    dispersion_percent, ..
                } => format!("over budget, within noise ({dispersion_percent:.1}%)"),
                SignalOutcome::NotGateable(reason) => {
                    format!("not gateable: {}", ineligibility(reason))
                }
                _ => "unknown outcome".to_string(),
            };
            println!(
                "{:<36}{:<20}{:>12.3}{:>9.0}%  {outcome}",
                decision.id, decision.signal, decision.median, decision.spread_percent
            );
        }
        println!("{}", "-".repeat(98));
    }

    let mut baseline_regressions = 0usize;
    if let Some(path) = &baseline_path {
        let (baseline, baseline_signals) = read_report(path)?;
        let comparison = compare_to_baseline_with_threshold(
            &runs,
            &baseline.results,
            regression_threshold_percent,
        );

        println!();
        println!(
            "{:<36}{:>12}{:>12}{:>9}  verdict",
            "workload", "baseline", "current", "delta"
        );
        println!("{}", "-".repeat(88));
        for row in &comparison.comparisons {
            let verdict = match &row.verdict {
                BaselineVerdict::Unchanged => "unchanged".to_string(),
                BaselineVerdict::Improved { delta_percent } => {
                    format!("improved {delta_percent:.1}%")
                }
                BaselineVerdict::Regressed {
                    delta_percent,
                    threshold_percent,
                } => {
                    format!("REGRESSED +{delta_percent:.1}% over {threshold_percent:.1}% threshold")
                }
                BaselineVerdict::NotComparable(reason) => match reason {
                    Ineligibility::NoiseDominated => "not comparable: noise dominated".to_string(),
                    Ineligibility::BelowTimerResolution => {
                        "not comparable: below timer resolution".to_string()
                    }
                    Ineligibility::InsufficientSamples => {
                        "not comparable: insufficient samples".to_string()
                    }
                },
                BaselineVerdict::MissingFromBaseline => "absent from baseline".to_string(),
                BaselineVerdict::MissingFromCurrent => "absent from the current runs".to_string(),
            };
            println!(
                "{:<36}{:>12.1}{:>12.1}{:>8.1}%  {verdict}",
                row.id, row.baseline_p95_us, row.current_median_p95_us, row.delta_percent
            );
        }
        println!("{}", "-".repeat(88));
        baseline_regressions = comparison
            .comparisons
            .iter()
            .filter(|row| row.verdict.fails_gate())
            .count();
        println!(
            "{} compared, {} regressions, {} improvements",
            comparison.comparisons.len(),
            baseline_regressions,
            comparison.improvements().len()
        );

        let signal_comparison = compare_signals_to_baseline(
            &signal_runs,
            &baseline_signals.results,
            regression_threshold_percent,
        );
        if !signal_comparison.is_empty() {
            println!();
            println!(
                "{:<36}{:<20}{:>12}{:>12}  verdict",
                "workload", "signal", "baseline", "current"
            );
            println!("{}", "-".repeat(98));
            for row in &signal_comparison {
                let verdict = match &row.verdict {
                    SignalVerdict::Unchanged => "unchanged".to_string(),
                    SignalVerdict::Improved { worse_by_percent } => {
                        format!("improved {:.1}%", -worse_by_percent)
                    }
                    SignalVerdict::Regressed {
                        worse_by_percent,
                        threshold_percent,
                    } => format!(
                        "REGRESSED +{worse_by_percent:.1}% over {threshold_percent:.1}% threshold"
                    ),
                    SignalVerdict::SkippedAbsentFromBaseline => {
                        "skipped: absent from baseline".to_string()
                    }
                    SignalVerdict::SkippedZeroBaseline => "skipped: zero baseline".to_string(),
                    SignalVerdict::NotComparable(reason) => {
                        format!("not comparable: {}", ineligibility(reason))
                    }
                    _ => "unknown verdict".to_string(),
                };
                let baseline = row
                    .baseline
                    .map_or_else(|| "-".to_string(), |value| format!("{value:.3}"));
                println!(
                    "{:<36}{:<20}{:>12}{:>12.3}  {verdict}",
                    row.id, row.signal, baseline, row.current_median
                );
            }
            println!("{}", "-".repeat(98));
            let signal_regressions = signal_comparison
                .iter()
                .filter(|row| row.verdict.is_regression())
                .count();
            baseline_regressions += signal_regressions;
            println!(
                "{} signals compared, {signal_regressions} regressions",
                signal_comparison.len()
            );
        }
    }

    let failures = gate.failures();
    let ungateable = gate.ungateable();
    println!(
        "{} workloads, {} regressions, {} not gateable, {} repetitions",
        gate.decisions.len(),
        failures.len(),
        ungateable.len(),
        report_paths.len()
    );

    let total = failures.len() + signal_failures + baseline_regressions;
    if total == 0 {
        return Ok(ExitCode::SUCCESS);
    }
    if enforce {
        eprintln!(
            "perf-gate: {} budget regressions, {baseline_regressions} baseline regressions",
            failures.len() + signal_failures
        );
        Ok(ExitCode::FAILURE)
    } else {
        println!("perf-gate: reporting only, rerun with --enforce to fail on regressions");
        Ok(ExitCode::SUCCESS)
    }
}

/// Reads one report for its latency samples and its plane signals.
fn read_report(path: &str) -> Result<(Report, SignalReport), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let report = serde_json::from_slice(&bytes).map_err(|e| format!("parse {path}: {e}"))?;
    let signals = serde_json::from_slice(&bytes).map_err(|e| format!("parse {path}: {e}"))?;
    Ok((report, signals))
}

fn ineligibility(reason: &Ineligibility) -> &'static str {
    match reason {
        Ineligibility::NoiseDominated => "noise dominated",
        Ineligibility::BelowTimerResolution => "below timer resolution",
        Ineligibility::InsufficientSamples => "insufficient samples",
    }
}

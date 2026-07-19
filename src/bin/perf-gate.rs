//! Evaluate repeated benchmark reports against the checked-in budgets.
//!
//! `perf_regression` gates on the median of repeated runs, so this driver takes
//! several `sekai.performance-report/v1` files rather than one:
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

use sekai_chisei::perf_regression::{
    BaselineVerdict, GateOutcome, Ineligibility, MIN_REPETITIONS, WorkloadBudget, WorkloadSample,
    compare_to_baseline, evaluate,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::process::ExitCode;

#[derive(Debug, Deserialize)]
struct Report {
    results: Vec<WorkloadSample>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    workloads: Vec<ManifestWorkload>,
}

#[derive(Debug, Deserialize)]
struct ManifestWorkload {
    id: String,
    budgets: WorkloadBudget,
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
    let budgets: BTreeMap<String, WorkloadBudget> = manifest
        .workloads
        .into_iter()
        .map(|workload| (workload.id, workload.budgets))
        .collect();

    let mut runs = Vec::new();
    for path in &report_paths {
        let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        let report: Report =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse {path}: {e}"))?;
        runs.push(report.results);
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

    let mut baseline_regressions = 0usize;
    if let Some(path) = &baseline_path {
        let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        let baseline: Report =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse {path}: {e}"))?;
        let comparison = compare_to_baseline(&runs, &baseline.results);

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
            };
            println!(
                "{:<36}{:>12.1}{:>12.1}{:>8.1}%  {verdict}",
                row.id, row.baseline_p95_us, row.current_median_p95_us, row.delta_percent
            );
        }
        println!("{}", "-".repeat(88));
        baseline_regressions = comparison.regressions().len();
        println!(
            "{} compared, {} regressions, {} improvements",
            comparison.comparisons.len(),
            baseline_regressions,
            comparison.improvements().len()
        );
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

    let total = failures.len() + baseline_regressions;
    if total == 0 {
        return Ok(ExitCode::SUCCESS);
    }
    if enforce {
        eprintln!(
            "perf-gate: {} budget regressions, {baseline_regressions} baseline regressions",
            failures.len()
        );
        Ok(ExitCode::FAILURE)
    } else {
        println!("perf-gate: reporting only, rerun with --enforce to fail on regressions");
        Ok(ExitCode::SUCCESS)
    }
}

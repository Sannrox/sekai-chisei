//! Driver-level checks for the `perf-gate` binary.
//!
//! The gating logic itself is unit-tested in `perf_regression`. These cover the
//! parts only the driver owns: argument handling, the repetition floor, and the
//! difference between reporting and enforcing.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    // The integration test binary lives in target/<profile>/deps.
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("perf-gate")
}

fn write_report(dir: &std::path::Path, name: &str, egress_p95: f64) -> PathBuf {
    let report = serde_json::json!({
        "results": [
            {
                "id": "context_egress_filtering",
                "p50_latency_us": egress_p95 / 2.0,
                "p95_latency_us": egress_p95,
                "p99_latency_us": egress_p95 * 1.1,
                "relative_standard_deviation_percent": 2.0
            }
        ]
    });
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(&report).expect("serialize")).expect("write report");
    path
}

fn write_manifest(dir: &std::path::Path, budget_p95: f64) -> PathBuf {
    let manifest = serde_json::json!({
        "workloads": [
            {
                "id": "context_egress_filtering",
                "budgets": {
                    "p50_latency_us": budget_p95 / 2.0,
                    "p95_latency_us": budget_p95,
                    "p99_latency_us": budget_p95 * 1.5
                }
            }
        ]
    });
    let path = dir.join("manifest.json");
    std::fs::write(&path, serde_json::to_vec(&manifest).expect("serialize")).expect("write");
    path
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("perf-gate-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn fewer_than_three_reports_is_refused() {
    let dir = temp_dir("few");
    let manifest = write_manifest(&dir, 500.0);
    let report = write_report(&dir, "one.json", 30.0);

    let output = Command::new(binary())
        .arg("--manifest")
        .arg(&manifest)
        .arg(&report)
        .output()
        .expect("run perf-gate");

    assert!(!output.status.success(), "single report was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at least 3 reports"),
        "unhelpful error: {stderr}"
    );
}

#[test]
fn regression_fails_only_under_enforce() {
    let dir = temp_dir("enforce");
    let manifest = write_manifest(&dir, 500.0);
    let reports: Vec<PathBuf> = (1..=3)
        .map(|n| write_report(&dir, &format!("run-{n}.json"), 700.0))
        .collect();

    let reporting = Command::new(binary())
        .arg("--manifest")
        .arg(&manifest)
        .args(&reports)
        .output()
        .expect("run perf-gate");
    assert!(
        reporting.status.success(),
        "reporting mode failed on a regression"
    );
    let stdout = String::from_utf8_lossy(&reporting.stdout);
    assert!(
        stdout.contains("REGRESSION"),
        "regression not reported: {stdout}"
    );

    let enforcing = Command::new(binary())
        .arg("--enforce")
        .arg("--manifest")
        .arg(&manifest)
        .args(&reports)
        .output()
        .expect("run perf-gate");
    assert!(
        !enforcing.status.success(),
        "enforce mode passed a significant regression"
    );
}

#[test]
fn within_budget_passes_under_enforce() {
    let dir = temp_dir("within");
    let manifest = write_manifest(&dir, 500.0);
    let reports: Vec<PathBuf> = (1..=3)
        .map(|n| write_report(&dir, &format!("ok-{n}.json"), 30.0))
        .collect();

    let output = Command::new(binary())
        .arg("--enforce")
        .arg("--manifest")
        .arg(&manifest)
        .args(&reports)
        .output()
        .expect("run perf-gate");

    assert!(
        output.status.success(),
        "in-budget run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unknown_flag_is_rejected() {
    let dir = temp_dir("flag");
    let manifest = write_manifest(&dir, 500.0);
    let reports: Vec<PathBuf> = (1..=3)
        .map(|n| write_report(&dir, &format!("f-{n}.json"), 30.0))
        .collect();

    let output = Command::new(binary())
        .arg("--nope")
        .arg("--manifest")
        .arg(&manifest)
        .args(&reports)
        .output()
        .expect("run perf-gate");

    assert!(!output.status.success(), "unknown flag was accepted");
}

#[test]
fn baseline_regression_fails_enforce_even_when_budget_passes() {
    // The point of baseline comparison: a slowdown well inside a loose budget
    // is invisible to the budget gate but must still fail.
    let dir = temp_dir("baseline");
    let manifest = write_manifest(&dir, 5000.0); // deliberately loose
    let baseline_path = write_report(&dir, "baseline.json", 30.0);
    let reports: Vec<PathBuf> = (1..=3)
        .map(|n| write_report(&dir, &format!("b-{n}.json"), 60.0))
        .collect();

    let budget_only = Command::new(binary())
        .arg("--enforce")
        .arg("--manifest")
        .arg(&manifest)
        .args(&reports)
        .output()
        .expect("run perf-gate");
    assert!(
        budget_only.status.success(),
        "a 2x slowdown inside a loose budget should pass the budget gate"
    );

    let with_baseline = Command::new(binary())
        .arg("--enforce")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--baseline")
        .arg(&baseline_path)
        .args(&reports)
        .output()
        .expect("run perf-gate");
    assert!(
        !with_baseline.status.success(),
        "baseline comparison missed a 2x slowdown: {}",
        String::from_utf8_lossy(&with_baseline.stdout)
    );
    assert!(
        String::from_utf8_lossy(&with_baseline.stdout).contains("REGRESSED"),
        "regression not shown in output"
    );
}

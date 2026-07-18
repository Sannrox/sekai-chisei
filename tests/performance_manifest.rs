use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MANIFEST: &str = include_str!("../benchmarks/manifest-v1.json");
const BASELINE: &str = include_str!("../benchmarks/baseline-apple-m2-pro.json");

#[test]
fn benchmark_manifest_is_versioned_bounded_and_complete() {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("valid benchmark manifest JSON");
    assert_eq!(
        manifest["contract_version"],
        "sekai.performance-manifest/v1"
    );
    assert_eq!(manifest["fixture_version"], "sekai.adoption-workloads/v1");
    let workloads = manifest["workloads"].as_array().expect("workload array");
    assert_eq!(workloads.len(), 13);
    let mut ids = BTreeSet::new();
    let mut categories = BTreeSet::new();
    for workload in workloads {
        assert!(ids.insert(workload["id"].as_str().expect("workload id")));
        categories.insert(workload["category"].as_str().expect("category"));
        assert!(workload["dataset_size"].as_u64().unwrap() > 0);
        assert!(workload["concurrency"].as_u64().unwrap() > 0);
        assert!(workload["operations_per_iteration"].as_u64().unwrap() > 0);
        assert!(workload["sample_iterations"].as_u64().unwrap() >= 10);
        assert!(!workload["observes"].as_array().unwrap().is_empty());
        let budgets = &workload["budgets"];
        let p50 = budgets["p50_latency_us"].as_f64().unwrap();
        let p95 = budgets["p95_latency_us"].as_f64().unwrap();
        let p99 = budgets["p99_latency_us"].as_f64().unwrap();
        assert!(p50 > 0.0 && p50 <= p95 && p95 <= p99);
    }
    for required in [
        "startup",
        "policy",
        "gateway",
        "context",
        "audit",
        "evidence",
        "memory",
        "advisory",
        "persistence",
        "provider",
        "reporting",
    ] {
        assert!(categories.contains(required), "missing {required} workload");
    }
}

#[test]
fn benchmark_fixtures_and_labels_are_sanitized() {
    let lowered = format!("{MANIFEST}\n{BASELINE}").to_ascii_lowercase();
    for forbidden in [
        "authorization: bearer",
        "openai_api_key",
        "anthropic_api_key",
        "private production",
        "customer payload",
    ] {
        assert!(
            !lowered.contains(forbidden),
            "manifest contains {forbidden}"
        );
    }
}

#[test]
fn checked_in_baseline_matches_the_manifest_contract() {
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    assert_eq!(baseline["contract_version"], "sekai.performance-report/v1");
    assert_eq!(baseline["manifest_version"], manifest["contract_version"]);
    assert_eq!(baseline["fixture_version"], manifest["fixture_version"]);
    assert_eq!(baseline["build_profile"], "release");
    assert!(
        !baseline["hardware"]["description"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    assert!(
        !baseline["hardware"]["operating_system"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        baseline["results"].as_array().unwrap().len(),
        manifest["workloads"].as_array().unwrap().len()
    );
    let manifest_contracts = manifest["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|workload| {
            (
                workload["id"].as_str().unwrap(),
                (
                    workload["operations_per_iteration"].as_u64().unwrap(),
                    workload["budgets"]["p50_latency_us"].as_f64().unwrap(),
                    workload["budgets"]["p95_latency_us"].as_f64().unwrap(),
                    workload["budgets"]["p99_latency_us"].as_f64().unwrap(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert!(
        baseline["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| {
                let id = result["id"].as_str().unwrap();
                let operations = result["operations_per_iteration"].as_u64().unwrap();
                let mean = result["mean_latency_us"].as_f64().unwrap();
                let throughput = result["throughput_operations_per_second"].as_f64().unwrap();
                let expected_throughput = 1_000_000.0 / mean * operations as f64;
                let (expected_operations, p50_budget, p95_budget, p99_budget) =
                    manifest_contracts[id];
                let budget_compliant = result["p50_latency_us"].as_f64().unwrap() <= p50_budget
                    && result["p95_latency_us"].as_f64().unwrap() <= p95_budget
                    && result["p99_latency_us"].as_f64().unwrap() <= p99_budget;
                budget_compliant
                    && result["within_budget"].as_bool() == Some(budget_compliant)
                    && expected_operations == operations
                    && (throughput - expected_throughput).abs() / expected_throughput < 0.01
                    && result["standard_deviation_us"].as_f64().is_some()
                    && result["relative_standard_deviation_percent"]
                        .as_f64()
                        .is_some()
            })
    );
}

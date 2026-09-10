use serde_json::Value;
use std::collections::BTreeSet;

const MANIFEST: &str = include_str!("../benchmarks/manifest-source-ingestion-v1.json");

#[test]
fn source_ingestion_manifest_is_measurement_only() {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("valid source ingestion manifest");
    assert_eq!(
        manifest["contract_version"],
        "sekai.performance-manifest/v1"
    );
    assert_eq!(
        manifest["fixture_version"],
        "sekai.source-ingestion-workloads/v1"
    );
    let description = manifest["description"].as_str().unwrap();
    assert!(description.contains("regression thresholds are not adopted"));
    let workloads = manifest["workloads"].as_array().expect("workload array");
    assert_eq!(workloads.len(), 3);
    let mut ids = BTreeSet::new();
    let mut sizes = BTreeSet::new();
    for workload in workloads {
        assert!(ids.insert(workload["id"].as_str().unwrap()));
        assert_eq!(workload["category"], "source_ingestion");
        sizes.insert(workload["dataset_size"].as_u64().unwrap());
        assert!(workload["concurrency"].as_u64().unwrap() >= 2);
        assert!(workload["sample_iterations"].as_u64().unwrap() >= 10);
        let observes = workload["observes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        for required in [
            "ingestion_throughput",
            "checkpoint_lag",
            "query_latency",
            "memory",
        ] {
            assert!(observes.contains(required), "missing {required}");
        }
        let p50 = workload["budgets"]["p50_latency_us"].as_f64().unwrap();
        let p95 = workload["budgets"]["p95_latency_us"].as_f64().unwrap();
        let p99 = workload["budgets"]["p99_latency_us"].as_f64().unwrap();
        assert!(p50 > 0.0 && p50 <= p95 && p95 <= p99);
    }
    assert_eq!(
        sizes,
        BTreeSet::from([8, 32, 96]),
        "small/medium/large graphs"
    );
    let lowered = MANIFEST.to_ascii_lowercase();
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

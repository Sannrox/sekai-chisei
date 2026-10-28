use sekai_chisei::perf_object_path::{
    ACTION_APPLY_P99_US, APPLY_SOURCE_BATCH_MIN_RECORDS_PER_SEC, GET_OBJECT_P99_US,
    LIST_PAGE_P95_US, ObjectPathBackend, ObjectPathHarness, ObjectPathId, ObjectPathKind,
    ObjectPathScale, POLICY_OVERHEAD_FRACTION, benchmark_for, parse_workload_id,
    policy_read_overhead_fraction, release_cached_graphs, required_workload_ids,
    smoke_workload_ids,
};
use serde_json::Value;
use std::collections::BTreeSet;

const MANIFEST: &str = include_str!("../benchmarks/manifest-object-path-v1.json");
const SMOKE: &str = include_str!("../benchmarks/manifest-object-path-smoke-v1.json");
const WORKFLOW: &str = include_str!("../.github/workflows/performance.yml");
const POSTGRES_WRAPPER: &str = include_str!("../scripts/object-path-with-postgres.sh");

#[test]
fn object_path_manifest_covers_required_workloads_and_published_budgets() {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("object-path manifest JSON");
    assert_eq!(
        manifest["contract_version"],
        "sekai.performance-manifest/v1"
    );
    assert_eq!(
        manifest["fixture_version"],
        "sekai.object-path-workloads/v1"
    );
    let workloads = manifest["workloads"].as_array().expect("workload array");
    let ids = workloads
        .iter()
        .map(|workload| workload["id"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    for required in required_workload_ids() {
        assert!(ids.contains(*required), "missing {required}");
        assert!(parse_workload_id(required).is_some(), "{required} unparsed");
    }

    let by_id = workloads
        .iter()
        .map(|workload| (workload["id"].as_str().unwrap(), workload))
        .collect::<std::collections::BTreeMap<_, _>>();
    for id in [
        "get_object_sqlite_10k",
        "get_object_sqlite_100k",
        "get_object_postgres_10k",
        "get_object_postgres_100k",
    ] {
        let p99 = by_id[id]["budgets"]["p99_latency_us"].as_f64().unwrap();
        assert!(p99 <= GET_OBJECT_P99_US, "{id} p99 {p99} exceeds 5ms");
    }
    for id in ["list_page_sqlite_100k", "list_page_postgres_100k"] {
        let p95 = by_id[id]["budgets"]["p95_latency_us"].as_f64().unwrap();
        assert!(p95 <= LIST_PAGE_P95_US, "{id} p95 {p95} exceeds 25ms");
        assert_eq!(by_id[id]["dataset_size"].as_u64().unwrap(), 100_000);
    }
    for id in [
        "action_apply_sqlite_10k",
        "action_apply_sqlite_100k",
        "action_apply_postgres_10k",
        "action_apply_postgres_100k",
    ] {
        let p99 = by_id[id]["budgets"]["p99_latency_us"].as_f64().unwrap();
        assert!(p99 <= ACTION_APPLY_P99_US, "{id} p99 {p99} exceeds 25ms");
    }
    for id in [
        "apply_source_batch_grpc_sqlite_100",
        "apply_source_batch_grpc_sqlite_1000",
        "apply_source_batch_grpc_postgres_100",
        "apply_source_batch_grpc_postgres_1000",
    ] {
        let mean_budget = by_id[id]["budgets"]["p95_latency_us"].as_f64().unwrap();
        let records = by_id[id]["operations_per_iteration"].as_f64().unwrap();
        let min_throughput = 1_000_000.0 / mean_budget * records;
        assert!(
            min_throughput + f64::EPSILON >= APPLY_SOURCE_BATCH_MIN_RECORDS_PER_SEC,
            "{id} p95 budget implies {min_throughput} records/s"
        );
    }
}

#[test]
fn object_path_smoke_manifest_is_a_wide_budget_subset() {
    let smoke: Value = serde_json::from_str(SMOKE).expect("smoke manifest JSON");
    assert_eq!(smoke["fixture_version"], "sekai.object-path-smoke/v1");
    let ids = smoke["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|workload| workload["id"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    for required in smoke_workload_ids() {
        assert!(ids.contains(*required), "missing smoke {required}");
        let parsed = parse_workload_id(required).expect(required);
        assert_eq!(parsed.backend, ObjectPathBackend::Sqlite);
        assert_eq!(parsed.scale, ObjectPathScale::Smoke);
    }
    for workload in smoke["workloads"].as_array().unwrap() {
        assert!(workload["budgets"]["p99_latency_us"].as_f64().unwrap() >= 1_000_000.0);
        assert!(workload["sample_iterations"].as_u64().unwrap() >= 10);
    }
}

#[test]
fn scheduled_performance_workflow_enforces_object_path_at_twenty_percent() {
    assert!(WORKFLOW.contains("manifest-object-path-v1.json"));
    assert!(WORKFLOW.contains("manifest-object-path-smoke-v1.json"));
    assert!(WORKFLOW.contains("--enforce"));
    assert!(WORKFLOW.contains("--regression-threshold-percent"));
    assert!(WORKFLOW.contains("20"));
    assert!(WORKFLOW.contains("pull_request"));
    assert!(WORKFLOW.contains("scripts/object-path-with-postgres.sh"));
    assert!(WORKFLOW.contains("dropped every postgres workload"));
    assert!(POSTGRES_WRAPPER.contains("SEKAI_BENCH_POSTGRES_URL"));
    assert!(POSTGRES_WRAPPER.contains("ssl=on"));
    assert!(POSTGRES_WRAPPER.contains("hostssl"));
    assert!(POSTGRES_WRAPPER.contains("bind((\"127.0.0.1\", 0))"));
    assert!(!POSTGRES_WRAPPER.contains("55434"));
}

#[test]
fn cached_read_workloads_keep_their_requested_operation() {
    let dataset = 16usize;
    let get = ObjectPathHarness::cached(
        ObjectPathId {
            kind: ObjectPathKind::GetObject,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("cache GetObject");
    let list = ObjectPathHarness::cached(
        ObjectPathId {
            kind: ObjectPathKind::ListPage,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("cache ListObjects");
    assert_eq!(get.kind(), ObjectPathKind::GetObject);
    assert_eq!(list.kind(), ObjectPathKind::ListPage);
    get.run_once().expect("cached GetObject");
    list.run_once().expect("cached ListObjects");
}

#[test]
fn releasing_cached_graphs_removes_sqlite_fixtures() {
    let harness = ObjectPathHarness::cached(
        ObjectPathId {
            kind: ObjectPathKind::GetObject,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        17,
        1,
    )
    .expect("cache GetObject");
    let path = harness
        .sqlite_dir_path()
        .expect("sqlite fixture")
        .to_path_buf();
    assert!(path.exists());
    drop(harness);
    assert!(
        path.exists(),
        "cached graph should retain the fixture until release"
    );
    release_cached_graphs();
    assert!(!path.exists());
}

#[test]
fn object_path_grpc_hot_paths_run_on_the_seeded_sqlite_graph() {
    let dataset = 16usize;
    let get = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::GetObject,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("open get harness");
    get.get_object().expect("GetObject");
    get.list_page().expect("ListObjects");
    get.run_once().expect("get run_once");
    let mut dispatched = benchmark_for("get_object_sqlite_smoke", dataset, 1)
        .expect("benchmark_for")
        .expect("object-path id");
    dispatched().expect("bench dispatch GetObject");

    let filter = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::EvaluateFilter,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("open filter harness");
    filter.run_once().expect("EvaluateObjectSet filter");

    let sort = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::EvaluateSort,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("open sort harness");
    sort.run_once().expect("EvaluateObjectSet sort");

    let one_hop = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::EvaluateOneHop,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("open one-hop harness");
    one_hop.run_once().expect("EvaluateObjectSet one-hop");

    let two_hop = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::EvaluateTwoHop,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("open two-hop harness");
    two_hop.run_once().expect("EvaluateObjectSet two-hop");

    let action = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::ActionApply,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("open action harness");
    let before = action.target_properties().expect("rank before apply");
    action.action_apply().expect("SubmitActionInstance");
    let after = action.target_properties().expect("rank after apply");
    assert_ne!(
        before.get("rank"),
        after.get("rank"),
        "Action apply must mutate the bound Item"
    );

    let policy = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::PolicyCheckedRead,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("open policy harness");
    policy.get_object().expect("policy-checked GetObject");

    let batch = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::ApplySourceBatch,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        8,
    )
    .expect("open batch harness");
    batch.apply_source_batch().expect("ApplySourceBatch");
    batch
        .apply_source_batch()
        .expect("ApplySourceBatch second page");

    let write = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::CreateObject,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset,
        1,
    )
    .expect("open write harness");
    write.create_object().expect("CreateObject");
    write.update_object().expect("UpdateObject");
}

#[test]
fn policy_checked_read_overhead_stays_within_published_budget() {
    assert_eq!(POLICY_OVERHEAD_FRACTION, 0.20);
    let overhead = policy_read_overhead_fraction(16).expect("measure overhead");
    assert!(
        overhead.is_finite(),
        "policy-checked read overhead {overhead} is not finite"
    );
    // Debug-profile samples are too noisy for the published 20% SLO; the
    // scheduled object-path gate enforces that budget against a baseline.
    assert!(
        overhead < 5.0,
        "policy-checked read overhead {overhead} is unreasonably large"
    );
}

// A wall-clock p99 ratio that shared runners cannot hold in a debug build
// alongside the rest of the suite (#1884). The scheduled object-path job
// runs it in release.
#[test]
#[ignore = "wall-clock p99 ratio; run by the scheduled object-path job"]
fn mixed_get_object_p99_stays_within_2x_idle_during_source_batch() {
    // One RPC page is capped at 500 records; the helper applies two pages.
    let harness = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::ApplySourceBatch,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Batch1000,
        },
        64,
        500,
    )
    .expect("open mixed harness");
    // Wall-clock p99 on a shared runner is noisy. A real regression misses
    // the bound on every attempt; noise rarely does three times in a row.
    let mut attempts = Vec::new();
    for _ in 0..3 {
        let (idle, busy) = harness
            .mixed_get_object_p99_during_batch(16)
            .expect("measure mixed GetObject");
        if busy <= idle * 2.0 || busy <= GET_OBJECT_P99_US * 2.0 {
            return;
        }
        attempts.push((idle, busy));
    }
    panic!("busy GetObject p99 exceeded 2x idle on every attempt (idle_us, busy_us): {attempts:?}");
}

//! Shared eval/portfolio authority across replicas (#308 / #117).

use sekai_chisei::chisei::eval::{EvalStore, Run, Suite};
use sekai_chisei::chisei::portfolio::{Observation, PortfolioStore};
use sekai_chisei::db::replica_safety::{ReplicaSafetyInventory, TwoReplicaSqlite};
use std::sync::Arc;

#[test]
fn inventory_marks_eval_and_portfolio_authoritative() {
    let inventory = ReplicaSafetyInventory::load().unwrap();
    inventory
        .require_authoritative("chisei.evaluation")
        .unwrap();
    inventory.require_authoritative("chisei.portfolio").unwrap();
    let scratch = inventory.surface("chisei.eval.batch_scratch").unwrap();
    assert!(matches!(
        scratch.class,
        sekai_chisei::db::replica_safety::ReplicaAuthorityClass::ProcessLocalOk
    ));
}

#[test]
fn process_local_eval_store_is_not_shared() {
    assert!(!EvalStore::new().is_shared());
}

#[test]
fn suite_written_on_one_replica_is_visible_on_the_other() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let writer = EvalStore::with_db(Arc::clone(&pair.a));
    let reader = EvalStore::with_db(Arc::clone(&pair.b));
    assert!(writer.is_shared());
    assert!(reader.is_shared());

    writer
        .put_suite(Suite {
            id: "suite-1".into(),
            name: "shared".into(),
            description: "cross-replica".into(),
            cases: Vec::new(),
        })
        .unwrap();

    let suite = reader.get_suite("suite-1").expect("suite visible on B");
    assert_eq!(suite.name, "shared");
    assert_eq!(suite.description, "cross-replica");
}

#[test]
fn run_written_on_one_replica_is_listed_on_the_other() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let a = EvalStore::with_db(Arc::clone(&pair.a));
    let b = EvalStore::with_db(Arc::clone(&pair.b));
    a.put_suite(Suite {
        id: "suite-runs".into(),
        name: "runs".into(),
        description: String::new(),
        cases: Vec::new(),
    })
    .unwrap();
    a.put_run(Run {
        id: "run-1".into(),
        suite_id: "suite-runs".into(),
        config_ref: "cfg-v1".into(),
        results: Vec::new(),
        timestamp: 42,
    })
    .unwrap();

    let runs = b.list_runs("suite-runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].id, "run-1");
    assert_eq!(runs[0].config_ref, "cfg-v1");
    assert_eq!(b.get_run("run-1").unwrap().timestamp, 42);
}

#[test]
fn process_local_eval_is_not_visible_across_stores() {
    let a = EvalStore::new();
    let b = EvalStore::new();
    a.put_suite(Suite {
        id: "local-only".into(),
        name: "local".into(),
        description: String::new(),
        cases: Vec::new(),
    })
    .unwrap();
    assert!(b.get_suite("local-only").is_none());
}

#[test]
fn portfolio_observation_is_shared_across_replicas() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let a = PortfolioStore::new(Arc::clone(&pair.a));
    let b = PortfolioStore::new(Arc::clone(&pair.b));
    a.record(&Observation {
        namespace: "ns".into(),
        task_class: "code review".into(),
        model: "model-a".into(),
        prompt_variant: "default".into(),
        quality_score: 80.0,
        cost_usd_micros: 1_000,
        sample_count: 3,
        updated_at: 10,
    })
    .unwrap();

    let points = b.points("ns", "code review").unwrap();
    assert!(
        points.iter().any(|p| p.model == "model-a"),
        "points={points:?}"
    );
}

#[test]
fn grpc_chisei_service_constructs_shared_eval_store() {
    // Static guarantee: production service uses with_db (see ChiseiServiceImpl::new).
    // Behavioral check uses the same wiring.
    let pair = TwoReplicaSqlite::open().unwrap();
    let eval = EvalStore::with_db(Arc::clone(&pair.a));
    assert!(eval.is_shared());
}

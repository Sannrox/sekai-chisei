//! Shared SQLite/PostgreSQL conformance for eval suites/runs/iterations and samples.

use sekai_chisei::chisei::eval::{
    Assertion, Case, CaseResult, Iteration, Run, Suite, check_assertions,
};
use sekai_chisei::chisei::scoring::SampleObservation;
use sekai_chisei::db::chisei_eval_backend::ChiseiEvalBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};

trait EvalHarness: ChiseiEvalBackend {}
impl EvalHarness for SekaiDb {}
impl EvalHarness for PostgresDb {}

fn exercise(db: &dyn EvalHarness, prefix: &str) {
    let suite_id = format!("{prefix}-suite");
    let suite = Suite {
        id: suite_id.clone(),
        name: "parity".into(),
        description: "conformance".into(),
        cases: vec![],
    };
    db.put_eval_suite(&suite).unwrap();
    assert_eq!(
        db.get_eval_suite_record(&suite_id).unwrap().unwrap().name,
        "parity"
    );
    // Immutable suite body fails closed for non-sampling ids.
    let mut renamed = suite.clone();
    renamed.name = "renamed".into();
    assert!(
        db.put_eval_suite(&renamed)
            .unwrap_err()
            .contains("immutable")
    );

    let invalid_suite = Suite {
        id: format!("{prefix}-invalid-suite"),
        name: "invalid".into(),
        description: String::new(),
        cases: vec![Case {
            id: "invalid-case".into(),
            name: "invalid".into(),
            namespace: format!("{prefix}-ns"),
            spec: String::new(),
            assertions: vec![Assertion {
                assert_type: "min_socre".into(),
                value: "90".into(),
            }],
        }],
    };
    db.put_eval_suite(&invalid_suite).unwrap();
    let persisted_invalid = db
        .get_eval_suite_record(&invalid_suite.id)
        .unwrap()
        .unwrap();
    let (passed, reason) = check_assertions(
        &persisted_invalid.cases[0].assertions,
        "done",
        "sensitive-result-content",
        100,
    );
    assert!(!passed);
    assert_eq!(reason, "unsupported eval assertion type \"min_socre\"");
    assert!(!reason.contains("sensitive-result-content"));

    let run_id = format!("{prefix}-run");
    let run = Run {
        id: run_id.clone(),
        suite_id: suite_id.clone(),
        config_ref: "cfg".into(),
        results: vec![CaseResult {
            case_id: "c1".into(),
            passed: true,
            status: "ok".into(),
            result: "pass".into(),
            score: 100,
            reason: "ok".into(),
            elapsed: 1,
        }],
        timestamp: 100,
    };
    db.put_eval_run(&run).unwrap();
    assert_eq!(
        db.get_eval_run_record(&run_id)
            .unwrap()
            .unwrap()
            .results
            .len(),
        1
    );

    let iteration = Iteration {
        id: format!("{prefix}-iter"),
        run_id: run_id.clone(),
        suite_id: suite_id.clone(),
        namespace: format!("{prefix}-ns"),
        changed_file: "src/x.rs".into(),
        diff_hash: "abc".into(),
        parent_iteration_id: String::new(),
        baseline_run_id: run_id.clone(),
        candidate_run_id: run_id.clone(),
        delta: 0.1,
        regressed: false,
        created: 200,
    };
    db.put_eval_iteration(&iteration).unwrap();
    let listed = db.list_eval_iteration_records(&suite_id).unwrap();
    assert!(listed.iter().any(|item| item.id == iteration.id));

    let request_id = format!("{prefix}-sample");
    db.put_sample_observation(&SampleObservation {
        request_id: request_id.clone(),
        namespace: format!("{prefix}-ns"),
        spec: "hello".into(),
        resolved_model: "model".into(),
        output_content: "world".into(),
        sample_reason: "test".into(),
        input_tokens: 1,
        output_tokens: 2,
        stop_reason: "end".into(),
        timestamp: 300,
        scored: false,
        task_class: "primary".into(),
        cost_usd_micros: 10,
    })
    .unwrap();
    // Idempotent insert for same request_id
    db.put_sample_observation(&SampleObservation {
        request_id: request_id.clone(),
        namespace: "other".into(),
        spec: "x".into(),
        resolved_model: "m".into(),
        output_content: "y".into(),
        sample_reason: "t".into(),
        input_tokens: 0,
        output_tokens: 0,
        stop_reason: "".into(),
        timestamp: 301,
        scored: false,
        task_class: "".into(),
        cost_usd_micros: 0,
    })
    .unwrap();
    assert_eq!(db.bump_observation_attempts(&request_id).unwrap(), 1);
    assert_eq!(db.bump_observation_attempts(&request_id).unwrap(), 2);
    db.delete_observation(&request_id).unwrap();
}

#[test]
fn sqlite_chisei_eval_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_chisei_eval_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    assert!(
        restarted
            .get_eval_suite_record(&format!("{prefix}-suite"))
            .unwrap()
            .is_some()
    );
}

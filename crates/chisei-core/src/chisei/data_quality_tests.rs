//! Tests of `chisei::data_quality` that break the decision-ledger write
//! through the store's connection (#2714).

use super::tests::{fixture, publish_pin, put_dataset};
use super::*;

fn fail_decision_writes(db: &ChiseiStore, fail: bool) {
    let sql = if fail {
        "CREATE TRIGGER fail_decision_write BEFORE INSERT ON sekai_decisions
         BEGIN SELECT RAISE(ABORT, 'injected decision write failure'); END;"
    } else {
        "DROP TRIGGER fail_decision_write;"
    };
    db.runtime().conn().execute_batch(sql).unwrap();
}

fn decisions(db: &ChiseiStore, action: &str, result_id: &str) -> usize {
    db.list_decisions(&sekai_core::sekai::audit::DecisionFilter {
        action: Some(action.into()),
        ..Default::default()
    })
    .unwrap()
    .into_iter()
    .filter(|decision| decision.target_id == result_id)
    .count()
}

#[test]
fn evaluate_retry_after_a_failed_audit_records_one_decision() {
    let (sekai, db, facts) = fixture();
    put_dataset(&sekai, "4", &[("owner", "alice")]);
    publish_pin(&sekai, &db);
    let evaluate = |now| {
        evaluate_rule(
            &db,
            facts.reader(),
            "analyst",
            "quality",
            "orders-pin",
            None,
            now,
        )
    };
    fail_decision_writes(&db, true);
    assert!(evaluate(20).is_err());
    fail_decision_writes(&db, false);
    let result = evaluate(21).unwrap();
    assert_eq!(result.status, STATUS_PASS);
    evaluate(22).unwrap();
    assert_eq!(
        decisions(&db, "data_quality.result_evaluate", &result.result_id),
        1
    );
}

#[test]
fn cancel_retry_after_a_failed_audit_records_one_decision() {
    let (sekai, db, facts) = fixture();
    put_dataset(&sekai, "4", &[("owner", "alice")]);
    publish_pin(&sekai, &db);
    let running = start_evaluation(
        &db,
        facts.reader(),
        "analyst",
        "quality",
        "orders-pin",
        None,
        20,
    )
    .unwrap();
    fail_decision_writes(&db, true);
    assert!(cancel_evaluation(&db, "analyst", &running.result_id, 21).is_err());
    fail_decision_writes(&db, false);
    let cancelled = cancel_evaluation(&db, "analyst", &running.result_id, 22).unwrap();
    assert_eq!(cancelled.status, STATUS_CANCELLED);
    assert_eq!(cancelled.evaluated_at_ms, 21);
    assert_eq!(
        decisions(&db, "data_quality.result_cancel", &running.result_id),
        1
    );
}

#[test]
fn restoring_an_earlier_rule_version_is_audited_again() {
    let (sekai, db, _) = fixture();
    put_dataset(&sekai, "4", &[("owner", "alice")]);
    let publish = |min_rows, now| {
        publish_rule(
            &db,
            "analyst",
            &PublishDataQualityRule {
                namespace: "quality".into(),
                rule_id: "orders-count".into(),
                dataset_id: "orders".into(),
                evaluator: EVALUATOR_ROW_COUNT.into(),
                expected_digest: None,
                required_fields: Vec::new(),
                min_rows: Some(min_rows),
                max_rows: None,
                baseline_digest: None,
            },
            now,
        )
    };
    let first = publish(1, 10).unwrap();
    publish(2, 11).unwrap();
    let restored = publish(1, 12).unwrap();
    assert_eq!(restored.rule_digest, first.rule_digest);
    assert_eq!(
        decisions(&db, "data_quality.rule_publish", &first.rule_digest),
        2
    );
}

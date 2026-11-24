use super::*;
use crate::chisei::receipt::OPERATION_RECEIPT_VERSION;
use crate::db::sekai::SekaiDb;

fn event(
    operation_id: &str,
    sequence: usize,
    timestamp_ms: i64,
    kind: ReceiptEventKind,
    attributes: &[(&str, &str)],
) -> OperationReceiptEvent {
    OperationReceiptEvent {
        event_id: format!("{operation_id}-{sequence}"),
        operation_id: operation_id.into(),
        parent_event_id: None,
        timestamp_ms,
        kind,
        surface: kind.surface(),
        actor: "test".into(),
        references: Vec::new(),
        attributes: attributes
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect(),
    }
}

fn memory_runtime() -> RuntimeDb {
    let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
    crate::chisei_store::apply_chisei_schema(&db);
    db
}

/// One completed operation with one model call per `(model, variant, cost,
/// latency)` entry, and a verification with `passed`.
fn put_operation(
    db: &RuntimeDb,
    namespace: &str,
    id: &str,
    class: &str,
    calls: &[(&str, &str, &str, &str)],
    passed: bool,
) {
    let mut events = vec![event(id, 0, 100, ReceiptEventKind::IntentRecorded, &[])];
    for (index, (model, variant, cost, latency)) in calls.iter().enumerate() {
        events.push(event(
            id,
            index + 1,
            110 + index as i64,
            ReceiptEventKind::ModelCalled,
            &[
                ("model", model),
                ("prompt_variant", variant),
                ("cost_usd_micros", cost),
                ("latency_ms", latency),
                ("input_tokens", "10"),
                ("output_tokens", "4"),
            ],
        ));
    }
    events.push(event(
        id,
        90,
        190,
        ReceiptEventKind::VerificationRecorded,
        &[
            ("status", if passed { "passed" } else { "failed" }),
            ("evaluator", "schema-check"),
        ],
    ));
    events.push(event(
        id,
        91,
        195,
        ReceiptEventKind::OutcomeRecorded,
        &[("status", if passed { "completed" } else { "failed" })],
    ));
    db.put_operation_receipt(&OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: id.into(),
        parent_operation_id: None,
        namespace: namespace.into(),
        operation_class: class.into(),
        initiating_actor: "test".into(),
        schema_version: "test/v1".into(),
        policy_version: "test/v1".into(),
        started_at_ms: 100,
        completed_at_ms: Some(200),
        events,
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    })
    .unwrap();
}

fn read(db: &RuntimeDb, group_by: TelemetryDimension) -> ExecutionTelemetry {
    query_execution_telemetry(db, &["alpha".into()], &[], 0, 1_000, group_by, |_| true).unwrap()
}

fn group<'a>(telemetry: &'a ExecutionTelemetry, key: &str) -> &'a TelemetryGroup {
    telemetry
        .groups
        .iter()
        .find(|group| group.key == key)
        .unwrap_or_else(|| panic!("no group {key}: {:?}", telemetry.groups))
}

fn seeded() -> RuntimeDb {
    let db = memory_runtime();
    put_operation(
        &db,
        "alpha",
        "op-1",
        "triage",
        &[
            ("model-a", "v1", "100", "40"),
            ("model-b", "v2", "300", "90"),
        ],
        true,
    );
    put_operation(
        &db,
        "alpha",
        "op-2",
        "triage",
        &[("model-a", "v1", "200", "60")],
        false,
    );
    // Another namespace never leaks into alpha's aggregates.
    put_operation(
        &db,
        "beta",
        "op-3",
        "triage",
        &[("model-a", "v1", "999", "5")],
        true,
    );
    db
}

#[test]
fn model_groups_attribute_each_call_to_its_own_model() {
    let telemetry = read(&seeded(), TelemetryDimension::Model);
    let model_a = group(&telemetry, "model-a");
    assert_eq!(
        (
            model_a.receipts,
            model_a.model_calls,
            model_a.spend_usd_micros
        ),
        (2, 2, 300)
    );
    assert_eq!((model_a.input_tokens, model_a.output_tokens), (20, 8));
    assert_eq!((model_a.latency_p50_ms, model_a.latency_p99_ms), (40, 60));
    assert_eq!(model_a.outcomes.get("verified"), Some(&1));
    assert_eq!(model_a.outcomes.get("failed"), Some(&1));
    assert_eq!(
        (model_a.verifications, model_a.verifications_passed),
        (2, 1)
    );
    let model_b = group(&telemetry, "model-b");
    assert_eq!((model_b.receipts, model_b.spend_usd_micros), (1, 300));
    assert_eq!(telemetry.receipts, 2);
    assert!(telemetry.gaps.is_empty(), "{:?}", telemetry.gaps);
}

#[test]
fn receipt_level_dimensions_count_each_receipt_once_per_value() {
    let db = seeded();
    let variants = read(&db, TelemetryDimension::PromptVariant);
    // op-1 used both variants, so it counts in each; its calls go to both.
    assert_eq!(group(&variants, "v1").receipts, 2);
    assert_eq!(group(&variants, "v2").receipts, 1);
    let tasks = read(&db, TelemetryDimension::TaskClass);
    assert_eq!(group(&tasks, "triage").spend_usd_micros, 600);
    let outcomes = read(&db, TelemetryDimension::OutcomeClass);
    assert_eq!(group(&outcomes, "failed").receipts, 1);
    let evaluators = read(&db, TelemetryDimension::Evaluator);
    assert_eq!(group(&evaluators, "schema-check").verifications_passed, 1);
}

#[test]
fn unrecorded_dimensions_and_missing_facts_are_reported_as_gaps() {
    let db = seeded();
    let tools = read(&db, TelemetryDimension::Tool);
    assert_eq!(tools.unrecorded_receipts, 2);
    assert_eq!(group(&tools, UNRECORDED_KEY).receipts, 2);
    assert!(tools.gaps.contains(&TelemetryGap {
        fact: "tool".into(),
        reason: "not_recorded".into(),
    }));
    let empty = query_execution_telemetry(
        &db,
        &["alpha".into()],
        &[],
        5_000,
        6_000,
        TelemetryDimension::Model,
        |_| true,
    )
    .unwrap();
    assert_eq!(empty.gaps[0].fact, RECORD_KIND_OPERATION_RECEIPT);
    assert!(empty.groups.is_empty());
}

#[test]
fn free_text_never_becomes_a_group_key() {
    let db = memory_runtime();
    put_operation(
        &db,
        "alpha",
        "op-1",
        "Summarize the customer's complaint about invoice 42",
        &[("model-a", "v1", "1", "1")],
        true,
    );
    let tasks = read(&db, TelemetryDimension::TaskClass);
    assert_eq!(tasks.groups.len(), 1);
    assert_eq!(tasks.groups[0].key, OTHER_KEY);
}

#[test]
fn same_closed_window_rereads_the_same_digest() {
    let db = seeded();
    let first = read(&db, TelemetryDimension::Model);
    assert!(first.digest.starts_with("sha256:"));
    assert_eq!(read(&db, TelemetryDimension::Model).digest, first.digest);
    assert_ne!(
        read(&db, TelemetryDimension::TaskClass).digest,
        first.digest
    );
    // A withheld namespace changes the reported scope, so the digest too.
    let withheld = query_execution_telemetry(
        &db,
        &["alpha".into()],
        &["beta".into()],
        0,
        1_000,
        TelemetryDimension::Model,
        |_| true,
    )
    .unwrap();
    assert_eq!(withheld.withheld_namespaces, vec!["beta".to_string()]);
    assert_eq!(withheld.receipts, first.receipts);
    assert_ne!(withheld.digest, first.digest);
}

#[test]
fn windows_past_the_bounds_are_refused_not_truncated() {
    let db = memory_runtime();
    let refused = query_execution_telemetry(
        &db,
        &["alpha".into()],
        &[],
        0,
        MAX_STATISTICS_WINDOW_MS + 1,
        TelemetryDimension::Model,
        |_| true,
    )
    .unwrap_err();
    assert!(matches!(refused, TelemetryError::NarrowWindow(_)));
    for index in 0..=MAX_STATISTICS_RECEIPTS {
        put_operation(&db, "alpha", &format!("op-{index}"), "triage", &[], true);
    }
    let refused = query_execution_telemetry(
        &db,
        &["alpha".into()],
        &[],
        0,
        1_000,
        TelemetryDimension::Model,
        |_| true,
    )
    .unwrap_err();
    assert!(
        matches!(refused, TelemetryError::NarrowWindow(_)),
        "{refused:?}"
    );
}

#[test]
fn nearest_rank_percentiles() {
    let samples = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    assert_eq!(nearest_rank(&samples, 50), 50);
    assert_eq!(nearest_rank(&samples, 90), 90);
    assert_eq!(nearest_rank(&samples, 99), 100);
    assert_eq!(nearest_rank(&[], 50), 0);
}

#[test]
fn receipts_the_caller_may_not_see_are_counted_as_withheld_only() {
    let telemetry = query_execution_telemetry(
        &seeded(),
        &["alpha".into()],
        &[],
        0,
        1_000,
        TelemetryDimension::Model,
        |receipt| receipt.operation_id != "op-1",
    )
    .unwrap();
    assert_eq!((telemetry.receipts, telemetry.withheld_receipts), (1, 1));
    assert_eq!(group(&telemetry, "model-a").spend_usd_micros, 200);
    assert!(telemetry.groups.iter().all(|group| group.key != "model-b"));
}

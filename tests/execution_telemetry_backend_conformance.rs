//! SQLite/PostgreSQL conformance for execution telemetry (ADR 0156): the
//! same receipts aggregate to the same groups, and the window is half-open.

use sekai_chisei::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
};
use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::execution_telemetry::{TelemetryDimension, query_execution_telemetry};
use std::sync::Arc;

fn put_receipt(db: &RuntimeDb, namespace: &str, id: &str, started_at_ms: i64, model: &str) {
    let event =
        |sequence: usize, offset: i64, kind: ReceiptEventKind, attributes: &[(&str, &str)]| {
            OperationReceiptEvent {
                event_id: format!("{id}-{sequence}"),
                operation_id: id.into(),
                parent_event_id: None,
                timestamp_ms: started_at_ms + offset,
                kind,
                surface: kind.surface(),
                actor: "conformance".into(),
                references: Vec::new(),
                attributes: attributes
                    .iter()
                    .map(|(key, value)| ((*key).into(), (*value).into()))
                    .collect(),
            }
        };
    db.put_operation_receipt(&OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: id.into(),
        parent_operation_id: None,
        namespace: namespace.into(),
        operation_class: "triage".into(),
        initiating_actor: "conformance".into(),
        schema_version: "test/v1".into(),
        policy_version: "test/v1".into(),
        started_at_ms,
        completed_at_ms: Some(started_at_ms + 50),
        events: vec![
            event(0, 0, ReceiptEventKind::IntentRecorded, &[]),
            event(
                1,
                10,
                ReceiptEventKind::ModelCalled,
                &[
                    ("model", model),
                    ("cost_usd_micros", "100"),
                    ("latency_ms", "20"),
                    ("input_tokens", "8"),
                    ("output_tokens", "2"),
                ],
            ),
            event(
                2,
                40,
                ReceiptEventKind::OutcomeRecorded,
                &[("status", "completed")],
            ),
        ],
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    })
    .unwrap();
}

fn exercise(db: &RuntimeDb, namespace: &str) {
    put_receipt(db, namespace, &format!("{namespace}-1"), 1_000, "model-a");
    put_receipt(db, namespace, &format!("{namespace}-2"), 1_100, "model-a");
    put_receipt(db, namespace, &format!("{namespace}-3"), 1_200, "model-b");
    // Starts at the exclusive end of the window, so it is outside.
    put_receipt(db, namespace, &format!("{namespace}-4"), 2_000, "model-b");
    let read = || {
        query_execution_telemetry(
            db,
            &[namespace.to_string()],
            &[],
            1_000,
            2_000,
            TelemetryDimension::Model,
            |_| true,
        )
        .unwrap()
    };
    let telemetry = read();
    assert_eq!(telemetry.receipts, 3);
    let summary: Vec<_> = telemetry
        .groups
        .iter()
        .map(|group| {
            (
                group.key.as_str(),
                group.receipts,
                group.spend_usd_micros,
                group.input_tokens,
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![("model-a", 2, 200, 16), ("model-b", 1, 100, 8)]
    );
    assert!(
        telemetry.gaps.iter().all(|gap| gap.fact == "verifications"),
        "{:?}",
        telemetry.gaps
    );
    assert_eq!(read().digest, telemetry.digest);
}

#[test]
fn sqlite_execution_telemetry_conformance() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    sekai_chisei::chisei_store::apply_chisei_schema(&db);
    exercise(&db, &format!("sqlite-{}", uuid::Uuid::new_v4().simple()));
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_execution_telemetry_conformance() {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    };
    let db = RuntimeDb::Postgres(Arc::new(db));
    sekai_chisei::chisei_store::apply_chisei_schema(&db);
    exercise(&db, &format!("pg-{}", uuid::Uuid::new_v4().simple()));
}

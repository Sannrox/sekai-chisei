//! Shared SQLite/PostgreSQL conformance for Chisei operation receipts and
//! gateway request-alias reservation.

use sekai_chisei::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    ReceiptSurface,
};
use sekai_chisei::db::chisei_receipt::ChiseiReceiptBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use std::collections::BTreeMap;

trait ReceiptHarness: ChiseiReceiptBackend {}
impl ReceiptHarness for SekaiDb {}
impl ReceiptHarness for PostgresDb {}

fn intent_receipt(
    operation_id: &str,
    namespace: &str,
    attrs: BTreeMap<String, String>,
) -> OperationReceipt {
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.into(),
        parent_operation_id: None,
        namespace: namespace.into(),
        operation_class: "triage".into(),
        initiating_actor: "human:alice".into(),
        schema_version: "chisei.execution/v1".into(),
        policy_version: "policy/v1".into(),
        started_at_ms: 1_000,
        completed_at_ms: None,
        events: vec![OperationReceiptEvent {
            event_id: format!("{operation_id}-intent"),
            operation_id: operation_id.into(),
            parent_event_id: None,
            timestamp_ms: 1_000,
            kind: ReceiptEventKind::IntentRecorded,
            surface: ReceiptSurface::Intent,
            actor: "human:alice".into(),
            references: vec![],
            attributes: attrs,
        }],
        uncovered_surfaces: vec![],
        reporter_grants: vec![],
        ontology_digest: None,
        artifact: None,
    }
}

fn exercise(db: &dyn ReceiptHarness, prefix: &str) {
    let operation_id = format!("{prefix}-op-1");
    let request_id = format!("{prefix}-req-1");
    let lookup = format!("{prefix}-alias");
    let mut attrs = BTreeMap::new();
    attrs.insert("request_id".into(), request_id.clone());
    attrs.insert("lookup_request_id".into(), lookup.clone());
    attrs.insert("caller_scope".into(), format!("{prefix}-scope"));
    let receipt = intent_receipt(&operation_id, &format!("{prefix}-ns"), attrs);

    db.put_operation_receipt(&receipt).unwrap();
    let loaded = db.get_operation_receipt(&operation_id).unwrap().unwrap();
    assert_eq!(loaded.operation_id, operation_id);
    assert_eq!(loaded.events.len(), 1);

    assert_eq!(
        db.find_operation_receipt_by_request_id(&request_id)
            .unwrap()
            .unwrap()
            .operation_id,
        operation_id
    );
    assert_eq!(
        db.find_operation_receipt_by_lookup_request_id(
            &lookup,
            Some(&format!("{prefix}-scope")),
            Some("human:alice"),
        )
        .unwrap()
        .unwrap()
        .operation_id,
        operation_id
    );

    assert!(
        db.authorize_operation_reporter(
            &operation_id,
            "agent:reporter",
            vec![ReceiptEventKind::OutcomeRecorded],
        )
        .unwrap()
    );
    assert!(
        !db.authorize_operation_reporter(
            &operation_id,
            "agent:reporter",
            vec![ReceiptEventKind::OutcomeRecorded],
        )
        .unwrap()
    );

    let outcome = OperationReceiptEvent {
        event_id: format!("{operation_id}-outcome"),
        operation_id: operation_id.clone(),
        parent_event_id: Some(format!("{operation_id}-intent")),
        timestamp_ms: 2_000,
        kind: ReceiptEventKind::OutcomeRecorded,
        surface: ReceiptSurface::Outcome,
        actor: "agent:reporter".into(),
        references: vec![],
        attributes: BTreeMap::from([
            ("outcome_metric".into(), "pass".into()),
            ("outcome_value".into(), "1.0".into()),
            ("passed".into(), "true".into()),
        ]),
    };
    let (updated, inserted) = db
        .append_operation_receipt_event(&operation_id, outcome.clone())
        .unwrap();
    assert!(inserted);
    assert_eq!(updated.events.len(), 2);
    assert_eq!(updated.completed_at_ms, Some(2_000));
    let (replay, inserted_again) = db
        .append_operation_receipt_event(&operation_id, outcome)
        .unwrap();
    assert!(!inserted_again);
    assert_eq!(replay.events.len(), 2);

    let alias_scope = format!("{prefix}-gateway");
    let alias = format!("{prefix}-opaque");
    let alias_request = format!("{prefix}-gateway-req");
    let alias_operation = format!("{prefix}-gateway-op");
    assert!(
        db.reserve_gateway_request_alias(&alias_scope, &alias, &alias_request, &alias_operation)
            .unwrap()
    );
    assert!(
        db.reserve_gateway_request_alias(&alias_scope, &alias, &alias_request, &alias_operation)
            .unwrap(),
        "lost reservation response must resume while pending"
    );
    assert!(
        !db.reserve_gateway_request_alias(
            &alias_scope,
            &alias,
            &format!("{prefix}-other-req"),
            &format!("{prefix}-other-op"),
        )
        .unwrap()
    );
    assert!(
        db.claim_gateway_request_alias_dispatch(
            &alias_scope,
            &alias,
            &alias_request,
            &alias_operation,
            "dispatch-a",
        )
        .unwrap()
    );
    assert!(
        db.claim_gateway_request_alias_dispatch(
            &alias_scope,
            &alias,
            &alias_request,
            &alias_operation,
            "dispatch-a",
        )
        .unwrap(),
        "same dispatch token is idempotent"
    );
    assert!(
        !db.claim_gateway_request_alias_dispatch(
            &alias_scope,
            &alias,
            &alias_request,
            &alias_operation,
            "dispatch-b",
        )
        .unwrap()
    );

    // Alias collision with an existing receipt lookup key fails closed.
    assert!(
        !db.reserve_gateway_request_alias(&format!("{prefix}-scope"), &lookup, "any", "any-op",)
            .unwrap()
    );
}

#[test]
fn sqlite_chisei_execution_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise(&db, "sqlite");
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
fn postgres_chisei_execution_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    let operation_id = format!("{prefix}-op-1");
    let loaded = restarted
        .get_operation_receipt(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.events.len(), 2);
    assert_eq!(loaded.completed_at_ms, Some(2_000));
}

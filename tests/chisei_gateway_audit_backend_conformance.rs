//! Shared SQLite/PostgreSQL conformance for gateway audit durable evidence:
//! decision log rows plus operation-receipt linkage.

use sekai_chisei::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    ReceiptSurface,
};
use sekai_chisei::db::chisei_receipt::ChiseiReceiptBackend;
use sekai_chisei::db::decision::DecisionBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::audit::{Decision, DecisionFilter};
use std::collections::{BTreeMap, HashMap};

trait GatewayAuditHarness: DecisionBackend + ChiseiReceiptBackend {}
impl GatewayAuditHarness for SekaiDb {}
impl GatewayAuditHarness for PostgresDb {}

fn exercise(db: &dyn GatewayAuditHarness, prefix: &str) {
    let operation_id = format!("{prefix}-op");
    let event_id = format!("{prefix}-gateway-event");
    db.put_operation_receipt(&OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.clone(),
        parent_operation_id: None,
        namespace: format!("{prefix}-ns"),
        operation_class: "gateway".into(),
        initiating_actor: "gateway:proxy".into(),
        schema_version: "chisei.gateway/v1".into(),
        policy_version: "policy/v1".into(),
        started_at_ms: 1_000,
        completed_at_ms: None,
        events: vec![OperationReceiptEvent {
            event_id: format!("{operation_id}-intent"),
            operation_id: operation_id.clone(),
            parent_event_id: None,
            timestamp_ms: 1_000,
            kind: ReceiptEventKind::IntentRecorded,
            surface: ReceiptSurface::Intent,
            actor: "gateway:proxy".into(),
            references: vec![],
            attributes: BTreeMap::from([
                ("request_id".into(), format!("{prefix}-req")),
                ("caller_scope".into(), format!("{prefix}-scope")),
            ]),
        }],
        uncovered_surfaces: vec![],
        reporter_grants: vec![],
        ontology_digest: None,
        artifact: None,
    })
    .unwrap();

    let decision = Decision {
        id: format!("{prefix}-decision"),
        timestamp: 1_100,
        actor: "gateway:proxy".into(),
        action: "gateway.audit".into(),
        reason: "gateway_request_audited".into(),
        evidence: HashMap::from([
            ("namespace".into(), format!("{prefix}-ns")),
            ("gateway_audit_event_id".into(), event_id.clone()),
            ("operation_id".into(), operation_id.clone()),
        ]),
        target_id: operation_id.clone(),
        outcome: "recorded".into(),
    };
    db.record_decision(&decision).unwrap();

    let loaded = db.get_decision(&decision.id).unwrap().unwrap();
    assert_eq!(
        loaded.evidence.get("gateway_audit_event_id").unwrap(),
        &event_id
    );
    assert!(db.get_operation_receipt(&operation_id).unwrap().is_some());
    let listed = db
        .list_decisions(&DecisionFilter {
            actor: Some("gateway:proxy".into()),
            action: Some("gateway.audit".into()),
            target_id: Some(operation_id),
            after: 0,
            limit: 10,
            offset: 0,
        })
        .unwrap();
    assert!(listed.iter().any(|item| item.id == decision.id));
}

#[test]
fn sqlite_chisei_gateway_audit_conformance() {
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
fn postgres_chisei_gateway_audit_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    assert!(
        restarted
            .get_decision(&format!("{prefix}-decision"))
            .unwrap()
            .is_some()
    );
}

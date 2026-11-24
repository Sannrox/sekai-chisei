//! Execution telemetry through gRPC (ADR 0156): readable namespaces are
//! aggregated, unreadable ones are named as withheld and never counted, and
//! bounds refuse rather than truncate.

use super::*;
use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, OperationReceiptEvent};

fn put_receipt(db: &RuntimeDb, namespace: &str, id: &str, marking: Option<&str>) {
    let event =
        |sequence: usize, timestamp_ms, kind: ReceiptEventKind, attributes: &[(&str, &str)]| {
            OperationReceiptEvent {
                event_id: format!("{id}-{sequence}"),
                operation_id: id.into(),
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
        };
    db.put_operation_receipt(&crate::chisei::receipt::OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: id.into(),
        parent_operation_id: None,
        namespace: namespace.into(),
        operation_class: "triage".into(),
        initiating_actor: "test".into(),
        schema_version: "test/v1".into(),
        policy_version: "test/v1".into(),
        started_at_ms: 100,
        completed_at_ms: Some(200),
        events: vec![
            event(
                0,
                100,
                ReceiptEventKind::IntentRecorded,
                &marking
                    .map(|marking| {
                        vec![(
                            crate::chisei::sekai_commit::RECEIPT_MARKING_ATTRIBUTE,
                            marking,
                        )]
                    })
                    .unwrap_or_default(),
            ),
            event(
                1,
                110,
                ReceiptEventKind::ModelCalled,
                &[
                    ("model", "model-a"),
                    ("cost_usd_micros", "250"),
                    ("latency_ms", "30"),
                ],
            ),
            event(
                2,
                190,
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

fn telemetry_request(
    namespaces: &[&str],
    until_ms: i64,
    group_by: &str,
) -> Request<GetExecutionTelemetryRequest> {
    let mut request = Request::new(GetExecutionTelemetryRequest {
        namespaces: namespaces
            .iter()
            .map(|namespace| (*namespace).into())
            .collect(),
        since_ms: 0,
        until_ms,
        group_by: group_by.into(),
    });
    request
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    request
}

#[tokio::test]
async fn unreadable_namespaces_are_withheld_and_never_counted() {
    let (svc, _sekai) = split_store_service();
    put_receipt(svc.db.runtime(), "acme", "op-acme", None);
    put_receipt(svc.db.runtime(), "secret", "op-secret", None);
    // Readable namespace, but alice holds no clearance for the marking.
    put_receipt(svc.db.runtime(), "acme", "op-marked", Some("confidential"));
    let response = svc
        .get_execution_telemetry(telemetry_request(&["secret", "acme"], 1_000, "model"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.namespaces, vec!["acme".to_string()]);
    assert_eq!(response.withheld_namespaces, vec!["secret".to_string()]);
    assert_eq!(response.receipts, 1);
    assert_eq!(response.withheld_receipts, 1);
    assert_eq!(response.groups.len(), 1);
    assert_eq!(response.groups[0].key, "model-a");
    assert_eq!(response.groups[0].spend_usd_micros, 250);
    assert_eq!(
        response.contract_version,
        crate::execution_telemetry::TELEMETRY_CONTRACT
    );
    assert!(response.digest.starts_with("sha256:"));
}

#[tokio::test]
async fn invalid_requests_and_oversized_windows_are_refused() {
    let (svc, _sekai) = split_store_service();
    let unknown_dimension = svc
        .get_execution_telemetry(telemetry_request(&["acme"], 1_000, "customer"))
        .await
        .unwrap_err();
    assert_eq!(unknown_dimension.code(), tonic::Code::InvalidArgument);
    let no_namespaces = svc
        .get_execution_telemetry(telemetry_request(&[], 1_000, "model"))
        .await
        .unwrap_err();
    assert_eq!(no_namespaces.code(), tonic::Code::InvalidArgument);
    let too_wide = svc
        .get_execution_telemetry(telemetry_request(
            &["acme"],
            crate::operation_statistics::MAX_STATISTICS_WINDOW_MS + 1,
            "model",
        ))
        .await
        .unwrap_err();
    assert_eq!(too_wide.code(), tonic::Code::ResourceExhausted);
    assert!(too_wide.message().starts_with("narrow the window"));
}

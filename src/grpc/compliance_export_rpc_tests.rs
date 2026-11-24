use super::*;
use crate::compliance_export::{
    ComplianceExportBundle, MAX_COMPLIANCE_RECEIPTS, sign_compliance_export,
    verify_compliance_export,
};
use crate::sekai::security::Role;
use futures_util::StreamExt;
use sekai_domain::receipt::{OPERATION_RECEIPT_VERSION, OperationReceipt};
use tonic::metadata::MetadataValue;

const NS: &str = "acme";

/// A split layout: receipts on the Chisei store, decisions on the Sekai
/// store, as the combined server opens them by default.
fn split() -> (SekaiServiceImpl, crate::chisei_store::ChiseiStore) {
    let sekai = Arc::new(RuntimeDb::memory());
    let chisei = Arc::new(RuntimeDb::Sqlite(Arc::new(
        crate::db::sekai::SekaiDb::new_for_plane(
            ":memory:",
            crate::db::schema_plane::SchemaPlane::Chisei,
        )
        .unwrap(),
    )));
    let chisei = crate::chisei_store::ChiseiStore::from_split_runtimes(chisei, sekai.clone());
    let sekai = crate::db::store::SekaiStore::from_shared_runtime(sekai);
    let clerk = crate::composition::cross_store_admission::CrossStoreAdmission::new(
        chisei.clone(),
        sekai.clone(),
        None,
    );
    let svc = SekaiServiceImpl::new(sekai).with_cross_store_admission(Arc::new(clerk));
    let (_, grants) = svc
        .db
        .runtime()
        .ensure_team_namespace(NS, "alice", Role::Admin, "local")
        .unwrap();
    for grant in grants {
        svc.security.add_grant(&grant);
    }
    (svc, chisei)
}

fn receipt(id: &str, started_at_ms: i64) -> OperationReceipt {
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: id.into(),
        parent_operation_id: None,
        namespace: NS.into(),
        operation_class: "chat".into(),
        initiating_actor: "operator".into(),
        schema_version: "schema-1".into(),
        policy_version: "policy-1".into(),
        started_at_ms,
        completed_at_ms: Some(started_at_ms + 10),
        events: Vec::new(),
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    }
}

fn request(request_id: &str) -> ExportComplianceBundleRequest {
    ExportComplianceBundleRequest {
        namespace: NS.into(),
        start_timestamp_ms: 100,
        end_timestamp_ms: 10_000,
        full: false,
        request_id: request_id.into(),
    }
}

/// The streamed bundle bytes and the last chunk.
async fn export(
    svc: &SekaiServiceImpl,
    principal: &str,
    request: ExportComplianceBundleRequest,
) -> Result<(Vec<u8>, ComplianceBundleChunk), tonic::Status> {
    let mut req = Request::new(request);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    let mut stream = svc.export_compliance_bundle_rpc(req)?.into_inner();
    let mut bytes = Vec::new();
    let mut last = None;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        bytes.extend_from_slice(&chunk.data);
        last = Some(chunk);
    }
    Ok((bytes, last.expect("at least one chunk")))
}

fn export_decisions(svc: &SekaiServiceImpl) -> Vec<crate::sekai::audit::Decision> {
    svc.db
        .runtime()
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            action: Some("compliance.export".into()),
            ..Default::default()
        })
        .unwrap()
}

#[tokio::test]
async fn a_namespace_admin_without_the_capability_is_refused() {
    let (svc, _) = split();
    let status = export(&svc, "alice", request("r1")).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(export_decisions(&svc).is_empty());
}

#[tokio::test]
async fn a_process_without_the_receipt_store_refuses() {
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
        RuntimeDb::memory(),
    )));
    let status = export(&svc, "root", request("r1")).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn the_bundle_matches_the_cli_bytes_and_verifies_once_signed() {
    let (svc, chisei) = split();
    let receipts = chisei.runtime();
    receipts
        .put_operation_receipt(&receipt("op-1", 150))
        .unwrap();
    receipts
        .put_operation_receipt(&receipt("op-2", 250))
        .unwrap();

    let (bytes, last) = export(&svc, "root", request("r1")).await.unwrap();
    assert!(last.done);
    // The CLI's bundle for the same request and export time, over the
    // same receipts and decisions.
    let cli = export_compliance_from_stores(
        receipts,
        svc.db.runtime(),
        &ComplianceExportRequest {
            namespace: NS.into(),
            start_timestamp_ms: 100,
            end_timestamp_ms: 10_000,
            redaction: RedactionMode::Redacted,
            actor: "root".into(),
            request_id: "r1".into(),
        },
        last.exported_at_ms,
    )
    .unwrap();
    assert_eq!(bytes, compliance_bundle_bytes(&cli).unwrap());
    assert_eq!(last.content_digest, cli.manifest.content_digest);

    let mut bundle: ComplianceExportBundle = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bundle.receipts.len(), 2);
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    sign_compliance_export(&mut bundle, &signing, "auditor", "k1", 1).unwrap();
    let public: String = signing
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(verify_compliance_export(&bundle, Some(&public)).ok);

    // A retried request records its export once, naming the caller.
    export(&svc, "root", request("r1")).await.unwrap();
    let decisions = export_decisions(&svc);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].actor, "root");
    // The same request id for another window is refused.
    let reused = ExportComplianceBundleRequest {
        end_timestamp_ms: 9_000,
        ..request("r1")
    };
    assert_eq!(
        export(&svc, "root", reused).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}

#[tokio::test]
async fn a_window_over_the_receipt_limit_is_refused_not_truncated() {
    let (svc, chisei) = split();
    for index in 0..=MAX_COMPLIANCE_RECEIPTS {
        chisei
            .runtime()
            .put_operation_receipt(&receipt(&format!("op-{index}"), 200))
            .unwrap();
    }
    let status = export(&svc, "root", request("r1")).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("narrow the time window"));
    assert!(export_decisions(&svc).is_empty());
}

//! Saved exports a Source delivers (ADR 0148): only a runtime that Source's
//! placement admits claims the artifacts, the deprecated list leaves them
//! to it, and every acknowledged delivery lands in the Source's health.

use super::*;
use crate::sekai::source::{self, PutSource, SourceSpec};
use sekai_source_sdk::{ConfigValue, SourceConfig};

fn put_source(svc: &SekaiServiceImpl, source_id: &str, tokens: (&str, &str), spec: SourceSpec) {
    source::put(
        svc.db.runtime(),
        &PutSource {
            namespace: "exp".into(),
            source_id: source_id.into(),
            source: tokens.0.into(),
            source_instance: tokens.1.into(),
            spec,
            expected_revision: 0,
            now_ms: 1,
        },
    )
    .unwrap();
}

/// A relational Source that delivers, placed in zone `eu`, and a GitHub
/// Source that does not deliver.
fn put_sources(svc: &SekaiServiceImpl) {
    let spec = |connector_type: &str, config: SourceConfig, egress: &str| SourceSpec {
        connector_type: connector_type.into(),
        connector_version: "1".into(),
        config,
        credential_ref: "exp/handle".into(),
        egress: vec![egress.into()],
        placement: [("zone".to_string(), "eu".to_string())].into(),
        every_ms: 0,
        owner: "team".into(),
        markings: Vec::new(),
        certification_id: String::new(),
    };
    let text = |value: &str| ConfigValue::Text(value.into());
    put_source(
        svc,
        "warehouse",
        ("warehouse", "exports"),
        spec(
            "relational",
            SourceConfig::from([
                ("endpoint".into(), text("db.internal:5432")),
                ("database".into(), text("exports")),
                ("user".into(), text("writer")),
            ]),
            "db.internal:5432",
        ),
    );
    put_source(
        svc,
        "repo",
        ("github", "acme/repo"),
        spec(
            "github",
            SourceConfig::from([("api_url".into(), text("https://api.github.com"))]),
            "api.github.com",
        ),
    );
}

fn register(svc: &SekaiServiceImpl, runtime_id: &str, zone: &str) {
    svc.db
        .runtime()
        .register_transform_runtime(
            "exp",
            runtime_id,
            &[("zone".to_string(), zone.to_string())].into(),
            "local",
            1,
        )
        .unwrap();
}

async fn listed_for(svc: &SekaiServiceImpl, runtime_id: &str) -> Vec<DeliverableExportArtifact> {
    svc.list_claimable_work(with_named_principal(
        ListClaimableWorkRequest {
            kind: WorkKind::ExportDelivery.into(),
            namespace: "exp".into(),
            runtime_id: runtime_id.into(),
            ..Default::default()
        },
        "tester",
    ))
    .await
    .unwrap()
    .into_inner()
    .work
    .into_iter()
    .filter_map(|work| match work.payload {
        Some(claimable_work::Payload::ExportDelivery(artifact)) => Some(artifact),
        _ => None,
    })
    .collect()
}

/// How many artifacts `runtime_id` lists when it asks only for Sources of
/// `types`.
async fn typed_listed_for(svc: &SekaiServiceImpl, runtime_id: &str, types: &[&str]) -> usize {
    svc.list_claimable_work(with_named_principal(
        ListClaimableWorkRequest {
            kind: WorkKind::ExportDelivery.into(),
            namespace: "exp".into(),
            runtime_id: runtime_id.into(),
            options: Some(list_claimable_work_request::Options::ExportDelivery(
                ExportDeliveryWorkOptions {
                    connector_types: types
                        .iter()
                        .map(|name| ConnectorTypeRef {
                            name: (*name).into(),
                            version: "1".into(),
                        })
                        .collect(),
                },
            )),
            ..Default::default()
        },
        "tester",
    ))
    .await
    .unwrap()
    .into_inner()
    .work
    .len()
}

async fn claim_as(
    svc: &SekaiServiceImpl,
    runtime_id: &str,
    receipt_id: &str,
) -> Result<ExportDeliveryWork, tonic::Status> {
    let request = ClaimWorkRequest {
        runtime_id: runtime_id.into(),
        ..claim_delivery(receipt_id)
    };
    match svc
        .claim_work(with_named_principal(request, "tester"))
        .await?
        .into_inner()
        .payload
    {
        Some(claim_work_response::Payload::ExportDelivery(work)) => Ok(work),
        _ => panic!("an export-delivery claim"),
    }
}

fn failed(work: &ExportDeliveryWork, reason: &str) -> AckWorkRequest {
    AckWorkRequest {
        outcome: "failed".into(),
        reason: reason.into(),
        options: None,
        ..ack_delivery(work, "")
    }
}

#[tokio::test]
async fn an_export_a_source_delivers_goes_only_to_that_sources_runtime() {
    let svc = service();
    put_sources(&svc);
    scheduled_export(&svc, "warehouse").await;

    // A definition names only an active Source of a type that delivers.
    let saved = svc
        .get_export_definition(with_named_principal(
            GetExportDefinitionRequest {
                namespace: "exp".into(),
                definition_id: "nightly".into(),
            },
            "tester",
        ))
        .await
        .unwrap()
        .into_inner()
        .definition
        .unwrap();
    assert_eq!(saved.delivery_source_id, "warehouse");
    for (source, message) in [
        ("missing", "delivery source not found"),
        ("repo", "delivery source type does not deliver exports"),
    ] {
        let refused = svc
            .put_export_definition(with_named_principal(
                PutExportDefinitionRequest {
                    definition: Some(ExportDefinition {
                        definition_id: "other".into(),
                        delivery_source_id: source.into(),
                        ..saved.clone()
                    }),
                },
                "tester",
            ))
            .await
            .unwrap_err();
        assert_eq!(
            (refused.code(), refused.message()),
            (tonic::Code::FailedPrecondition, message)
        );
    }

    // The deprecated list leaves the artifact to the Source's runtime, and
    // only a runtime the Source's placement admits sees or claims it.
    assert!(
        svc.list_deliverable_export_artifacts(with_named_principal(
            ListDeliverableExportArtifactsRequest {
                namespace: "exp".into(),
            },
            "tester",
        ))
        .await
        .unwrap()
        .into_inner()
        .artifacts
        .is_empty()
    );
    register(&svc, "runtime-us", "us");
    register(&svc, "runtime-eu", "eu");
    assert!(listed_for(&svc, "runtime-us").await.is_empty());
    let listed = listed_for(&svc, "runtime-eu").await;
    assert_eq!(listed.len(), 1);
    let artifact = &listed[0];
    assert_eq!(artifact.delivery_source_id, "warehouse");
    for (types, count) in [(vec![], 1), (vec!["github"], 0), (vec!["relational"], 1)] {
        assert_eq!(typed_listed_for(&svc, "runtime-eu", &types).await, count);
    }

    // Unfenced, the deprecated fetch and acknowledge refuse it too.
    assert_eq!(
        fetch_delivery(&svc, &artifact.receipt_id, None)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    assert_eq!(
        svc.acknowledge_export_delivery(with_named_principal(
            AcknowledgeExportDeliveryRequest {
                receipt_id: artifact.receipt_id.clone(),
                content_digest: artifact.content_digest.clone(),
                claim: None,
            },
            "tester",
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::NotFound
    );
    for receipt_id in ["", artifact.receipt_id.as_str()] {
        assert_eq!(
            claim_as(&svc, "runtime-us", receipt_id)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }
    let work = claim_as(&svc, "runtime-eu", "").await.unwrap();
    assert_eq!(
        work.artifact.as_ref().unwrap().delivery_source_id,
        "warehouse"
    );

    // A failure is recorded under the live fence and leaves the claim.
    for (request, code) in [
        (failed(&work, "lease_expired"), tonic::Code::InvalidArgument),
        (failed(&work, "nonsense"), tonic::Code::InvalidArgument),
        (
            AckWorkRequest {
                fencing_token: "stale".into(),
                ..failed(&work, "unreachable")
            },
            tonic::Code::FailedPrecondition,
        ),
    ] {
        assert_eq!(
            svc.ack_work(with_named_principal(request, "tester"))
                .await
                .unwrap_err()
                .code(),
            code
        );
    }
    svc.ack_work(with_named_principal(failed(&work, "unreachable"), "tester"))
        .await
        .unwrap();
    let delivery = |svc: &SekaiServiceImpl| {
        svc.db
            .runtime()
            .get_source("exp", "warehouse")
            .unwrap()
            .unwrap()
            .delivery
    };
    let after_failure = delivery(&svc);
    assert_eq!(
        (
            after_failure.last_failure.as_str(),
            after_failure.last_runtime.as_str(),
            after_failure.last_success_at_ms
        ),
        ("unreachable", "runtime-eu", 0)
    );
    assert!(after_failure.last_failure_at_ms > 0);

    // The same holder retries and delivers; the success is recorded.
    let fence = delivery_fence_of(&work);
    let bytes = fetch_delivery(&svc, &artifact.receipt_id, Some(fence))
        .await
        .unwrap();
    assert_eq!(
        format!("sha256:{:x}", sha2::Sha256::digest(&bytes)),
        artifact.content_digest
    );
    svc.ack_work(with_named_principal(
        ack_delivery(&work, &artifact.content_digest),
        "tester",
    ))
    .await
    .unwrap();
    assert!(delivery(&svc).last_success_at_ms > 0);
    assert_eq!(
        svc.get_source(with_named_principal(
            GetSourceRequest {
                namespace: "exp".into(),
                source_id: "warehouse".into(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .source
        .unwrap()
        .delivery
        .unwrap()
        .last_runtime,
        "runtime-eu"
    );
}

#[tokio::test]
async fn a_disabled_delivery_source_holds_its_artifacts() {
    let svc = service();
    put_sources(&svc);
    scheduled_export(&svc, "warehouse").await;
    register(&svc, "runtime-eu", "eu");
    assert_eq!(listed_for(&svc, "runtime-eu").await.len(), 1);
    let held = claim_as(&svc, "runtime-eu", "").await.unwrap();
    let receipt_id = held.artifact.clone().unwrap().receipt_id;

    source::disable(svc.db.runtime(), "exp", "warehouse", 2).unwrap();
    assert!(listed_for(&svc, "runtime-eu").await.is_empty());
    assert_eq!(
        claim_as(&svc, "runtime-eu", "").await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    // The claim taken before the disable neither renews nor reads the bytes.
    let heartbeat = svc
        .heartbeat_work_claim(with_named_principal(
            HeartbeatWorkClaimRequest {
                kind: WorkKind::ExportDelivery.into(),
                namespace: "exp".into(),
                work_id: receipt_id.clone(),
                runtime_id: held.claim_owner.clone(),
                claim_generation: held.claim_generation,
                fencing_token: held.fencing_token.clone(),
                ttl_ms: 60_000,
            },
            "tester",
        ))
        .await
        .unwrap_err();
    assert_eq!(heartbeat.code(), tonic::Code::FailedPrecondition);
    let fetch = svc
        .fetch_export_artifact(with_named_principal(
            FetchExportArtifactRequest {
                receipt_id,
                claim: Some(ExportDeliveryFence {
                    runtime_id: held.claim_owner,
                    claim_generation: held.claim_generation,
                    fencing_token: held.fencing_token,
                }),
            },
            "tester",
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(fetch.code(), tonic::Code::NotFound);
}

/// Delivered artifacts: receipt id and bytes.
type Deliveries = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

/// A relational delivery that fails while `failures_left` lasts, recording
/// every delivered artifact.
struct Recorded {
    delivered: Deliveries,
    failures_left: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl sekai_source_sdk::Connector for Recorded {
    fn deliver(
        &mut self,
        artifact: &sekai_source_sdk::ExportArtifact<'_>,
    ) -> Result<(), sekai_source_sdk::ConnectorFailure> {
        use std::sync::atomic::Ordering;
        if self
            .failures_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(sekai_source_sdk::ConnectorFailure::Unreachable);
        }
        self.delivered
            .lock()
            .unwrap()
            .push((artifact.receipt_id.into(), artifact.bytes.to_vec()));
        Ok(())
    }
}

/// Serves `svc` on an ephemeral port until the sender drops.
async fn serve(svc: &SekaiServiceImpl) -> (String, tokio::sync::oneshot::Sender<()>) {
    use tower::Layer;
    let service = crate::rpc_maturity::RpcMaturityLayer::new(true)
        .layer(crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer::new(svc.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            )
            .await
            .unwrap();
    });
    (endpoint, stop)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sources_runtime_delivers_retries_and_takes_over_a_crashed_delivery() {
    use sekai_connector_runtime::{Connectors, CredentialBindings, Ran, Runtime, RuntimeOptions};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    const LEASE: std::time::Duration = std::time::Duration::from_millis(300);

    let svc = service();
    put_sources(&svc);
    scheduled_export(&svc, "warehouse").await;
    let (endpoint, _stop) = serve(&svc).await;
    let dir = tempfile::tempdir().unwrap();
    let password = dir.path().join("password");
    std::fs::write(&password, "p").unwrap();
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let failures_left = Arc::new(AtomicUsize::new(1));
    let connectors = {
        let (delivered, failures_left) = (delivered.clone(), failures_left.clone());
        Connectors::default().with(&sekai_source_sdk::RELATIONAL_CONNECTOR, move |_| {
            Ok(Box::new(Recorded {
                delivered: delivered.clone(),
                failures_left: failures_left.clone(),
            }))
        })
    };
    let namespaces = ["exp".to_string()];
    let runtime = |id: &str| {
        let bindings: CredentialBindings = serde_json::from_value(serde_json::json!({
            "exp/handle": {
                "namespaces": ["exp"],
                "destinations": ["db.internal:5432"],
                "slots": { "password": { "file": password } }
            }
        }))
        .unwrap();
        Runtime::connect(
            sekai_client::ClientConfig::new(&endpoint, "local")
                .with_default_timeout(std::time::Duration::from_secs(5)),
            &namespaces,
            RuntimeOptions {
                runtime_id: id.into(),
                labels: [("zone".to_string(), "eu".to_string())].into(),
                lease: LEASE,
            },
            bindings,
            connectors.clone(),
        )
    };
    let (a, b) = (
        runtime("runtime-a").await.unwrap(),
        runtime("runtime-b").await.unwrap(),
    );
    a.register().await.unwrap();
    b.register().await.unwrap();

    // A claims and dies; B sees nothing while the lease lives.
    let (source, held) = a.claim_delivery(0).await.unwrap().unwrap();
    let receipt_id = held.artifact.as_ref().unwrap().receipt_id.clone();
    assert!(b.claim_delivery(0).await.unwrap().is_none());

    // After the lapse B takes over; its first try fails and is recorded
    // on the Source, and the claim it keeps holds the artifact a lease.
    tokio::time::sleep(LEASE * 2).await;
    assert_eq!(
        b.pass().await.unwrap(),
        [Ran::Delivered {
            receipt_id: receipt_id.clone(),
            outcome: Err(sekai_connector_runtime::SyncFailure::Unreachable),
        }]
    );
    let health = svc
        .db
        .runtime()
        .get_source("exp", "warehouse")
        .unwrap()
        .unwrap()
        .delivery;
    assert_eq!(
        (health.last_failure.as_str(), health.last_runtime.as_str()),
        ("unreachable", "runtime-b")
    );
    assert!(
        b.pass().await.unwrap().is_empty(),
        "no retry inside the lease"
    );

    // A lease later the artifact is delivered once, and A's stale fence
    // can neither fetch nor acknowledge it.
    tokio::time::sleep(LEASE * 2).await;
    assert_eq!(
        b.pass().await.unwrap(),
        [Ran::Delivered {
            receipt_id: receipt_id.clone(),
            outcome: Ok(()),
        }]
    );
    assert_eq!(
        a.deliver(0, source, held).await.unwrap(),
        Ran::DeliveryLost {
            receipt_id: receipt_id.clone()
        }
    );
    let delivered = delivered.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].0, receipt_id);
    let digest = format!("sha256:{:x}", sha2::Sha256::digest(&delivered[0].1));
    assert_eq!(
        crate::sekai::data_export::export_receipt(svc.db.runtime(), &receipt_id)
            .unwrap()
            .and_then(|receipt| crate::sekai::data_export::completed_digest(&receipt)),
        Some(digest)
    );
    let health = svc
        .db
        .runtime()
        .get_source("exp", "warehouse")
        .unwrap()
        .unwrap()
        .delivery;
    assert!(health.last_success_at_ms >= health.last_failure_at_ms);
    assert!(b.pass().await.unwrap().is_empty());
}

/// A definition saved before `delivery_source_id` existed still decodes,
/// delivered by no Source.
#[test]
fn a_definition_stored_before_delivery_sources_still_decodes() {
    let mut stored = serde_json::to_value(ExportDefinition {
        namespace: "exp".into(),
        definition_id: "nightly".into(),
        delivery_source_id: "warehouse".into(),
        ..Default::default()
    })
    .unwrap();
    stored
        .as_object_mut()
        .unwrap()
        .remove("deliverySourceId")
        .unwrap();
    let decoded = super::super::data_export_rpc::decode_definition(&stored.to_string()).unwrap();
    assert_eq!(decoded.definition_id, "nightly");
    assert!(decoded.delivery_source_id.is_empty());
}

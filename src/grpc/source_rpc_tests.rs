//! `sekai.source/v1` over gRPC: the admin RPCs, and Source sync through the
//! claimable-work family.

use super::*;
use crate::sekai::security::Role;
use tonic::metadata::MetadataValue;

const NS: &str = "src-rpc";

fn service() -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    crate::chisei_store::apply_chisei_schema(&db);
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db));
    for (principal, role) in [("root", Role::Admin), ("reader", Role::Viewer)] {
        let (_, grants) = svc
            .db
            .runtime()
            .ensure_team_namespace(NS, principal, role, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
    }
    svc
}

/// A request as the token interceptor leaves it: the principal, plus a
/// machine context with no tenant.
fn as_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    req.extensions_mut()
        .insert(crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: principal.into(),
                credential_id: format!("{principal}-credential"),
            },
        ));
    req
}

fn github_spec(every_ms: i64) -> ConnectorSourceSpec {
    ConnectorSourceSpec {
        connector_type: "github".into(),
        connector_version: "1".into(),
        config: [(
            "api_url".to_string(),
            SourceConfigValue {
                value: Some(source_config_value::Value::Text(
                    "https://api.github.com".into(),
                )),
            },
        )]
        .into(),
        credential_ref: "ops/github-bot".into(),
        egress: vec!["api.github.com".into()],
        placement: [("zone".to_string(), "eu".to_string())].into(),
        every_ms,
        owner: "team-integrations".into(),
        ..Default::default()
    }
}

fn put_request(spec: ConnectorSourceSpec, expected_revision: i64) -> PutSourceRequest {
    PutSourceRequest {
        namespace: NS.into(),
        source_id: "repo".into(),
        source: "github".into(),
        source_instance: "acme/repo".into(),
        spec: Some(spec),
        expected_revision,
    }
}

async fn put(svc: &SekaiServiceImpl, every_ms: i64) -> ConnectorSource {
    svc.put_source(as_principal(put_request(github_spec(every_ms), 0), "root"))
        .await
        .unwrap()
        .into_inner()
        .source
        .unwrap()
}

#[tokio::test]
async fn an_admin_puts_lists_and_disables_a_source_and_a_reader_reads_it() {
    let svc = service();
    let created = put(&svc, 0).await;
    assert_eq!((created.revision, created.status.as_str()), (1, "active"));
    assert_eq!(created.spec, Some(github_spec(0)));

    // Readers read; only administrators write.
    let read = svc
        .get_source(as_principal(
            GetSourceRequest {
                namespace: NS.into(),
                source_id: "repo".into(),
            },
            "reader",
        ))
        .await
        .unwrap()
        .into_inner()
        .source;
    assert_eq!(read, Some(created.clone()));
    let denied = svc
        .put_source(as_principal(put_request(github_spec(0), 1), "reader"))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    for stranger in ["anonymous", "stranger"] {
        assert!(
            svc.list_sources(as_principal(
                ListSourcesRequest {
                    namespace: NS.into(),
                    ..Default::default()
                },
                stranger,
            ))
            .await
            .is_err()
        );
    }

    // The store's refusals map to their codes.
    let codes = [
        (put_request(github_spec(0), 0), tonic::Code::Aborted),
        (put_request(github_spec(0), 7), tonic::Code::Aborted),
        (
            PutSourceRequest {
                source_id: "other".into(),
                ..put_request(github_spec(0), 0)
            },
            tonic::Code::AlreadyExists,
        ),
        (
            PutSourceRequest {
                spec: Some(ConnectorSourceSpec {
                    credential_ref: String::new(),
                    config: [(
                        "token".to_string(),
                        SourceConfigValue {
                            value: Some(source_config_value::Value::Text("ghp_x".into())),
                        },
                    )]
                    .into(),
                    ..github_spec(0)
                }),
                ..put_request(github_spec(0), 1)
            },
            tonic::Code::InvalidArgument,
        ),
        (
            PutSourceRequest {
                spec: None,
                ..put_request(github_spec(0), 1)
            },
            tonic::Code::InvalidArgument,
        ),
    ];
    for (request, code) in codes {
        let refused = svc
            .put_source(as_principal(request, "root"))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), code, "{refused:?}");
    }

    let disable = || {
        svc.disable_source(as_principal(
            DisableSourceRequest {
                namespace: NS.into(),
                source_id: "repo".into(),
            },
            "root",
        ))
    };
    let disabled = disable().await.unwrap().into_inner().source.unwrap();
    assert_eq!(
        (disabled.revision, disabled.status.as_str()),
        (2, "disabled")
    );
    assert_eq!(
        disable().await.unwrap().into_inner().source,
        Some(disabled),
        "a disable is idempotent"
    );

    let listed = svc
        .list_sources(as_principal(
            ListSourcesRequest {
                namespace: NS.into(),
                limit: 1,
                ..Default::default()
            },
            "reader",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.sources.len(), 1);
    assert_eq!(listed.next_page_token, "repo");
}

fn claim_request(work_id: &str) -> ClaimWorkRequest {
    ClaimWorkRequest {
        kind: WorkKind::SourceSync.into(),
        namespace: NS.into(),
        runtime_id: "connector-a".into(),
        work_id: work_id.into(),
        ttl_ms: 60_000,
        ..Default::default()
    }
}

fn ack_request(work: &SourceSyncWork, outcome: &str, reason: &str) -> AckWorkRequest {
    AckWorkRequest {
        kind: WorkKind::SourceSync.into(),
        namespace: NS.into(),
        work_id: "repo".into(),
        runtime_id: work.claim_owner.clone(),
        claim_generation: work.claim_generation,
        fencing_token: work.fencing_token.clone(),
        outcome: outcome.into(),
        reason: reason.into(),
        ..Default::default()
    }
}

async fn register(svc: &SekaiServiceImpl, runtime_id: &str, zone: &str) {
    svc.register_transform_runtime(as_principal(
        RegisterTransformRuntimeRequest {
            namespace: NS.into(),
            runtime_id: runtime_id.into(),
            labels: vec![TransformLabel {
                key: "zone".into(),
                value: zone.into(),
            }],
        },
        "root",
    ))
    .await
    .unwrap();
}

async fn claim(svc: &SekaiServiceImpl, work_id: &str) -> Result<SourceSyncWork, Status> {
    match svc
        .claim_work(as_principal(claim_request(work_id), "root"))
        .await?
        .into_inner()
        .payload
    {
        Some(claim_work_response::Payload::SourceSync(work)) => Ok(work),
        other => panic!("a source sync claim, not {other:?}"),
    }
}

#[tokio::test]
async fn a_placed_runtime_claims_heartbeats_and_fails_a_sync_once() {
    let svc = service();
    put(&svc, 60_000).await;
    svc.db
        .runtime()
        .tick_source_syncs(NS, now_millis())
        .unwrap();

    // Placement: an unregistered or misplaced runtime sees nothing.
    let list = || {
        svc.list_claimable_work(as_principal(
            ListClaimableWorkRequest {
                kind: WorkKind::SourceSync.into(),
                namespace: NS.into(),
                runtime_id: "connector-a".into(),
                ..Default::default()
            },
            "root",
        ))
    };
    assert!(list().await.unwrap().into_inner().work.is_empty());
    register(&svc, "connector-a", "us").await;
    assert_eq!(
        claim(&svc, "repo").await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        claim(&svc, "").await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    register(&svc, "connector-a", "eu").await;
    assert_eq!(list().await.unwrap().into_inner().work.len(), 1);

    // A reader may not run sync work.
    assert!(
        svc.claim_work(as_principal(claim_request(""), "reader"))
            .await
            .is_err()
    );

    let work = claim(&svc, "").await.unwrap();
    let source = work.source.as_ref().unwrap();
    assert_eq!(source.spec, Some(github_spec(60_000)));
    assert_eq!(source.sync.as_ref().unwrap().claim_owner, "connector-a");
    let heartbeat = svc
        .heartbeat_work_claim(as_principal(
            HeartbeatWorkClaimRequest {
                kind: WorkKind::SourceSync.into(),
                namespace: NS.into(),
                work_id: "repo".into(),
                runtime_id: work.claim_owner.clone(),
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token.clone(),
                ttl_ms: 60_000,
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .payload;
    assert!(matches!(
        heartbeat,
        Some(heartbeat_work_claim_response::Payload::SourceSync(_))
    ));

    // A failure names its class; lease_expired is the plane's own.
    for (outcome, reason) in [("failed", ""), ("failed", "lease_expired"), ("parked", "")] {
        let refused = svc
            .ack_work(as_principal(ack_request(&work, outcome, reason), "root"))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument, "{outcome}");
    }
    let ack = || {
        svc.ack_work(as_principal(
            ack_request(&work, "failed", "unavailable"),
            "root",
        ))
    };
    let Some(ack_work_response::Payload::SourceSync(acked)) =
        ack().await.unwrap().into_inner().payload
    else {
        panic!("a source sync ack");
    };
    let sync = acked.sync.unwrap();
    assert_eq!(
        (sync.last_failure.as_str(), sync.due),
        ("unavailable", false)
    );
    assert!(ack().await.is_ok(), "a retried ack replays");

    // No retry loop: the failed bucket is done until the next one.
    assert_eq!(
        claim(&svc, "").await.unwrap_err().code(),
        tonic::Code::NotFound
    );
}

#[tokio::test]
async fn a_disable_fences_the_live_sync_claim() {
    let svc = service();
    put(&svc, 60_000).await;
    register(&svc, "connector-a", "eu").await;
    svc.db
        .runtime()
        .tick_source_syncs(NS, now_millis())
        .unwrap();
    let work = claim(&svc, "repo").await.unwrap();
    svc.disable_source(as_principal(
        DisableSourceRequest {
            namespace: NS.into(),
            source_id: "repo".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let refused = svc
        .ack_work(as_principal(ack_request(&work, "completed", ""), "root"))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
}

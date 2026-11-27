//! `sekai.source/v1` over gRPC: the admin RPCs, and Source sync and
//! external effects through the claimable-work family.

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

/// #3552: an enterprise-scoped credential uses the user's live roles to
/// manage Sources and discovery in its tenant; another tenant is refused.
#[tokio::test]
async fn tenant_assertion_manages_sources_and_discovery_in_its_namespace() {
    let svc = enterprise_service();
    crate::chisei_store::apply_chisei_schema(svc.db.runtime());
    let ns = "allowed";
    let put_req = || PutSourceRequest {
        namespace: ns.into(),
        source_id: "repo".into(),
        source: "github".into(),
        source_instance: "acme/repo".into(),
        spec: Some(github_spec(0)),
        expected_revision: 0,
    };
    let get_req = || GetSourceRequest {
        namespace: ns.into(),
        source_id: "repo".into(),
    };
    let list_req = || ListSourcesRequest {
        namespace: ns.into(),
        ..Default::default()
    };
    let disable_req = || DisableSourceRequest {
        namespace: ns.into(),
        source_id: "repo".into(),
    };
    let request_disc = || RequestSourceDiscoveryRequest {
        namespace: ns.into(),
        source_id: "repo".into(),
    };

    assert_eq!(
        svc.put_source(with_tenant_write_context(put_req()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );

    grant_source_namespace(&svc, ns, "subject-a", Role::Viewer);
    let listed = svc
        .list_sources(with_tenant_context(list_req()))
        .await
        .unwrap()
        .into_inner();
    assert!(listed.sources.is_empty());
    assert_eq!(
        svc.get_source(with_tenant_context(get_req()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    for denied in [
        svc.put_source(with_tenant_write_context(put_req()))
            .await
            .unwrap_err()
            .code(),
        svc.disable_source(with_tenant_write_context(disable_req()))
            .await
            .unwrap_err()
            .code(),
        svc.request_source_discovery(with_tenant_write_context(request_disc()))
            .await
            .unwrap_err()
            .code(),
    ] {
        assert_eq!(denied, tonic::Code::PermissionDenied);
    }

    grant_source_namespace(&svc, ns, "subject-a", Role::Admin);
    let created = svc
        .put_source(with_tenant_write_context(put_req()))
        .await
        .unwrap()
        .into_inner()
        .source
        .unwrap();
    assert_eq!(created.source_id, "repo");
    assert_eq!(
        svc.get_source(with_tenant_context(get_req()))
            .await
            .unwrap()
            .into_inner()
            .source
            .unwrap()
            .source_id,
        "repo"
    );
    assert_eq!(
        svc.list_sources(with_tenant_context(list_req()))
            .await
            .unwrap()
            .into_inner()
            .sources
            .len(),
        1
    );
    let discovery = svc
        .request_source_discovery(with_tenant_write_context(request_disc()))
        .await
        .unwrap()
        .into_inner()
        .discovery
        .unwrap();
    assert!(!discovery.discovery_id.is_empty());
    let got = svc
        .get_source_discovery(with_tenant_write_context(GetSourceDiscoveryRequest {
            namespace: ns.into(),
            discovery_id: discovery.discovery_id,
        }))
        .await
        .unwrap()
        .into_inner()
        .discovery
        .unwrap();
    assert_eq!(got.source_id, "repo");
    let disabled = svc
        .disable_source(with_tenant_write_context(disable_req()))
        .await
        .unwrap()
        .into_inner()
        .source
        .unwrap();
    assert_eq!(disabled.status, "disabled");

    grant_source_namespace(&svc, "denied", "subject-a", Role::Admin);
    assert_eq!(
        svc.put_source(with_tenant_write_context(PutSourceRequest {
            namespace: "denied".into(),
            ..put_req()
        }))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::PermissionDenied
    );
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

/// Sync notes (ADR 0163) reach the Source and its health; a retried ack
/// keeps the first ones, and a malformed note is refused.
#[tokio::test]
async fn a_completed_sync_reports_its_notes_on_the_source_and_its_health() {
    let svc = service();
    put(&svc, 60_000).await;
    register(&svc, "connector-a", "eu").await;
    svc.db
        .runtime()
        .tick_source_syncs(NS, now_millis())
        .unwrap();
    let work = claim(&svc, "repo").await.unwrap();
    let skipped = |offset, reason: &str| SourceSyncNote {
        note: Some(source_sync_note::Note::SkippedRecord(
            source_sync_note::SkippedRecord {
                partition: 3,
                offset,
                reason: reason.into(),
            },
        )),
    };
    let notes = |notes, overflow_count| SourceSyncNotes {
        notes,
        overflow_count,
    };
    let ack = |notes| {
        svc.ack_work(as_principal(
            AckWorkRequest {
                options: Some(ack_work_request::Options::SourceSyncNotes(notes)),
                ..ack_request(&work, "completed", "")
            },
            "root",
        ))
    };
    let refused = ack(notes(vec![skipped(1, "too_long")], 0))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);

    let reported = notes(
        vec![
            SourceSyncNote {
                note: Some(source_sync_note::Note::OffsetGap(
                    source_sync_note::OffsetGap {
                        partition: 3,
                        from_offset: 0,
                        to_offset: 120,
                    },
                )),
            },
            skipped(121, "not_json"),
        ],
        5,
    );
    let Some(ack_work_response::Payload::SourceSync(acked)) =
        ack(reported.clone()).await.unwrap().into_inner().payload
    else {
        panic!("a source sync ack");
    };
    assert_eq!(acked.sync.unwrap().last_notes.as_ref(), Some(&reported));
    ack(notes(vec![skipped(9, "missing_id")], 0)).await.unwrap();

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
        .source
        .unwrap();
    assert_eq!(read.sync.unwrap().last_notes, Some(reported.clone()));
    let health = |principal| {
        svc.get_source_health(as_principal(
            GetSourceHealthRequest {
                namespace: NS.into(),
                source_instance: "acme/repo".into(),
                type_digest: source_sync_domain::GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
                delayed_after_ms: None,
            },
            principal,
        ))
    };
    let disclosed = health("root").await.unwrap().into_inner().health.unwrap();
    assert_eq!(disclosed.sync_notes, Some(reported));
    let hidden = health("stranger")
        .await
        .unwrap()
        .into_inner()
        .health
        .unwrap();
    assert_eq!(hidden.sync_notes, None);
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

/// Lands one `Issue` per `(external id, object key)` for the `repo` Source.
fn land(svc: &SekaiServiceImpl, from: &str, to: &str, records: &[(&str, Option<&str>)]) {
    use sekai_source_sdk::{SourceAdapterConfig, SourceRecord, build_source_batch};
    let adapter = SourceAdapterConfig {
        namespace: NS.into(),
        producer_identity: "connector-a".into(),
        source_instance: "acme/repo".into(),
        type_digest: source_sync_domain::GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
    };
    let records = records
        .iter()
        .map(|&(external_id, object_key)| SourceRecord {
            source: "github".into(),
            source_instance: "acme/repo".into(),
            external_id: external_id.into(),
            source_version: format!("etag-{external_id}"),
            type_name: "Issue".into(),
            display_name: external_id.into(),
            payload_digest: format!("sha256:{}", "b".repeat(64)),
            properties: Default::default(),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
            payload: None,
            object_key: object_key.map(Into::into),
        })
        .collect();
    let batch = build_source_batch(&adapter, from, to, 20, records).unwrap();
    let applied = svc
        .db
        .runtime()
        .apply_source_batch(&batch, "connector-a", now_millis())
        .unwrap();
    assert!(
        applied.checkpoint_advanced,
        "{}",
        applied.transaction.reason
    );
}

#[tokio::test]
async fn only_the_sync_claim_holder_reads_the_sources_record_versions() {
    let svc = service();
    put(&svc, 60_000).await;
    register(&svc, "connector-a", "eu").await;
    svc.db
        .runtime()
        .tick_source_syncs(NS, now_millis())
        .unwrap();
    let work = claim(&svc, "repo").await.unwrap();
    land(
        &svc,
        "",
        "cursor:1",
        &[("12", Some("b.csv")), ("13", Some("a.csv"))],
    );
    let read = |work: &SourceSyncWork, principal: &str| {
        svc.list_source_record_versions(as_principal(
            ListSourceRecordVersionsRequest {
                namespace: NS.into(),
                source_id: "repo".into(),
                runtime_id: work.claim_owner.clone(),
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token.clone(),
                ..Default::default()
            },
            principal,
        ))
    };
    let records = read(&work, "root").await.unwrap().into_inner().records;
    assert_eq!(
        records,
        vec![
            SourceRecordVersion {
                external_id: "13".into(),
                object_key: "a.csv".into(),
                source_version: "etag-13".into(),
            },
            SourceRecordVersion {
                external_id: "12".into(),
                object_key: "b.csv".into(),
                source_version: "etag-12".into(),
            },
        ]
    );
    assert_eq!(
        read(&work, "reader").await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let stale = SourceSyncWork {
        fencing_token: "stale".into(),
        ..work.clone()
    };
    assert_eq!(
        read(&stale, "root").await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );

    land(&svc, "cursor:1", "cursor:2", &[("14", None)]);
    let unkeyed = read(&work, "root").await.unwrap_err();
    assert_eq!(
        (unkeyed.code(), unkeyed.message()),
        (
            tonic::Code::FailedPrecondition,
            sekai_client::claim::SOURCE_RECORDS_UNKEYED
        )
    );
}

/// A pending `external_mutate` effect on a record of the `repo` Source.
fn admit_external_effect(svc: &SekaiServiceImpl) -> String {
    let effect = crate::sekai::action_effect::plan_effects_for_admit(
        "instance-1",
        NS,
        "operation-1",
        &["external_mutate".into()],
        r#"{"permit_id":"permit-1","source_id":"github:acme/repo#12"}"#,
        10,
        false,
    )
    .unwrap()
    .remove(0);
    svc.db
        .runtime()
        .put_action_effects(std::slice::from_ref(&effect))
        .unwrap();
    effect.effect_id
}

async fn claim_effect(
    svc: &SekaiServiceImpl,
    principal: &str,
) -> Result<ExternalEffectWork, Status> {
    match svc
        .claim_work(as_principal(
            ClaimWorkRequest {
                kind: WorkKind::ExternalEffect.into(),
                ..claim_request("")
            },
            principal,
        ))
        .await?
        .into_inner()
        .payload
    {
        Some(claim_work_response::Payload::ExternalEffect(work)) => Ok(work),
        other => panic!("an external effect claim, not {other:?}"),
    }
}

#[tokio::test]
async fn only_a_placed_runtime_claims_an_external_effect_and_outcome_unknown_is_final() {
    let svc = service();
    put(&svc, 0).await;
    let effect_id = admit_external_effect(&svc);

    // The record's Source places the work: a misplaced runtime or a reader
    // cannot take it.
    register(&svc, "connector-a", "us").await;
    assert_eq!(
        claim_effect(&svc, "root").await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    register(&svc, "connector-a", "eu").await;
    assert!(claim_effect(&svc, "reader").await.is_err());
    let work = claim_effect(&svc, "root").await.unwrap();
    let effect = work.effect.unwrap();
    assert_eq!(effect.effect_id, effect_id);
    assert_eq!(
        (effect.status.as_str(), effect.claim_generation),
        ("claimed", 1)
    );
    assert_eq!(work.source.unwrap().source_id, "repo");

    // The Action-work path stays closed to the effect.
    assert!(
        svc.claim_action_work(as_principal(
            ClaimActionWorkRequest {
                effect_id: effect_id.clone(),
                runtime_id: "connector-a".into(),
                request_id: "r1".into(),
                ttl_ms: 60_000,
            },
            "root",
        ))
        .await
        .is_err()
    );

    let ack = || AckWorkRequest {
        kind: WorkKind::ExternalEffect.into(),
        namespace: NS.into(),
        work_id: effect_id.clone(),
        runtime_id: effect.claim_owner.clone(),
        claim_generation: i64::try_from(effect.claim_generation).unwrap(),
        fencing_token: effect.claim_fencing_token.clone(),
        outcome: "outcome_unknown".into(),
        reason: "permit already redeemed".into(),
        ..Default::default()
    };
    for _ in 0..2 {
        let acked = svc
            .ack_work(as_principal(ack(), "root"))
            .await
            .unwrap()
            .into_inner()
            .payload;
        let Some(ack_work_response::Payload::ExternalEffect(acked)) = acked else {
            panic!("an external effect acknowledge, not {acked:?}");
        };
        assert_eq!(acked.status, "outcome_unknown");
    }
    assert_eq!(
        claim_effect(&svc, "root").await.unwrap_err().code(),
        tonic::Code::NotFound
    );
}

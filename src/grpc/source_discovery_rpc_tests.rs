//! Source discovery (#3091) over gRPC: an administrator requests it, a
//! placed runtime runs it through the claimable-work family, and only the
//! requester reads the result back once.

use super::*;
use crate::sekai::audit::DecisionFilter;
use crate::sekai::security::Role;
use crate::sekai::source::SOURCE_DISCOVERY_SAMPLE_ACTION;
use sekai_source_sdk::{
    DiscoveredColumn, DiscoveredRecordKind, SOURCE_DISCOVERY_VERSION, SourceDiscovery,
};
use tonic::metadata::MetadataValue;

const NS: &str = "discovery-rpc";
const SECRET_CELL: &str = "cell-value-never-audited";

fn service() -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    crate::chisei_store::apply_chisei_schema(&db);
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db));
    for (principal, role) in [
        ("root", Role::Admin),
        ("other-admin", Role::Admin),
        ("reader", Role::Viewer),
    ] {
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

async fn put_source(svc: &SekaiServiceImpl, markings: &[&str]) {
    svc.put_source(as_principal(
        PutSourceRequest {
            namespace: NS.into(),
            source_id: "orders".into(),
            source: "github".into(),
            source_instance: "acme/repo".into(),
            spec: Some(ConnectorSourceSpec {
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
                owner: "team-data".into(),
                markings: markings.iter().map(|m| m.to_string()).collect(),
                ..Default::default()
            }),
            expected_revision: 0,
        },
        "root",
    ))
    .await
    .unwrap();
}

async fn register(svc: &SekaiServiceImpl) {
    svc.register_transform_runtime(as_principal(
        RegisterTransformRuntimeRequest {
            namespace: NS.into(),
            runtime_id: "connector-a".into(),
            labels: vec![TransformLabel {
                key: "zone".into(),
                value: "eu".into(),
            }],
        },
        "root",
    ))
    .await
    .unwrap();
}

async fn request(svc: &SekaiServiceImpl, principal: &str) -> Result<SourceDiscoveryResult, Status> {
    Ok(svc
        .request_source_discovery(as_principal(
            RequestSourceDiscoveryRequest {
                namespace: NS.into(),
                source_id: "orders".into(),
            },
            principal,
        ))
        .await?
        .into_inner()
        .discovery
        .unwrap())
}

async fn get(
    svc: &SekaiServiceImpl,
    discovery_id: &str,
    principal: &str,
) -> Result<SourceDiscoveryResult, Status> {
    Ok(svc
        .get_source_discovery(as_principal(
            GetSourceDiscoveryRequest {
                namespace: NS.into(),
                discovery_id: discovery_id.into(),
            },
            principal,
        ))
        .await?
        .into_inner()
        .discovery
        .unwrap())
}

async fn claim(svc: &SekaiServiceImpl) -> SourceDiscoveryWork {
    let claimed = svc
        .claim_work(as_principal(
            ClaimWorkRequest {
                kind: WorkKind::SourceDiscovery.into(),
                namespace: NS.into(),
                runtime_id: "connector-a".into(),
                ttl_ms: 60_000,
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .payload;
    match claimed {
        Some(claim_work_response::Payload::SourceDiscovery(work)) => work,
        other => panic!("a source discovery claim, not {other:?}"),
    }
}

fn completed_ack(work: &SourceDiscoveryWork, fencing_token: &str) -> AckWorkRequest {
    let document = SourceDiscovery {
        contract_version: SOURCE_DISCOVERY_VERSION.into(),
        source: "postgres.table".into(),
        record_kinds: vec![DiscoveredRecordKind {
            record_kind: "orders".into(),
            schema_revision: "1".into(),
            columns: vec![DiscoveredColumn {
                name: "id".into(),
                data_type: "text".into(),
                nullable: false,
                profile: None,
            }],
            key_candidates: vec![vec!["id".into()]],
            references: Vec::new(),
            value_findings: Vec::new(),
        }],
    };
    AckWorkRequest {
        kind: WorkKind::SourceDiscovery.into(),
        namespace: NS.into(),
        work_id: work.discovery_id.clone(),
        runtime_id: work.claim_owner.clone(),
        claim_generation: work.claim_generation,
        fencing_token: fencing_token.into(),
        outcome: "completed".into(),
        options: Some(ack_work_request::Options::SourceDiscovery(
            SourceDiscoveryAckOptions {
                discovery_json: serde_json::to_string(&document).unwrap(),
                samples: vec![SourceDiscoverySample {
                    record_kind: "orders".into(),
                    unsupported: false,
                    rows: vec![SourceDiscoverySampleRow {
                        cells: [("id".to_string(), SECRET_CELL.to_string())].into(),
                    }],
                }],
            },
        )),
        ..Default::default()
    }
}

fn audited_samples(svc: &SekaiServiceImpl) -> Vec<crate::sekai::audit::Decision> {
    svc.db
        .runtime()
        .list_decisions(&DecisionFilter {
            action: Some(SOURCE_DISCOVERY_SAMPLE_ACTION.into()),
            ..Default::default()
        })
        .unwrap()
}

#[tokio::test]
async fn an_admin_requests_a_runtime_discovers_and_the_requester_reads_it_once() {
    let svc = service();
    put_source(&svc, &[]).await;
    register(&svc).await;

    // Only administrators request; a repeat returns the open request.
    assert_eq!(
        request(&svc, "reader").await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let requested = request(&svc, "root").await.unwrap();
    assert_eq!(
        (requested.status.as_str(), requested.requested_by.as_str()),
        ("pending", "root")
    );
    assert_eq!(
        request(&svc, "root").await.unwrap().discovery_id,
        requested.discovery_id
    );

    let work = claim(&svc).await;
    assert_eq!(work.discovery_id, requested.discovery_id);
    assert_eq!(
        work.source
            .as_ref()
            .unwrap()
            .spec
            .as_ref()
            .unwrap()
            .connector_type,
        "github"
    );

    // A stale fence writes nothing and audits nothing.
    let stale = svc
        .ack_work(as_principal(completed_ack(&work, "stale-token"), "root"))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    assert!(audited_samples(&svc).is_empty());

    svc.ack_work(as_principal(
        completed_ack(&work, &work.fencing_token),
        "root",
    ))
    .await
    .unwrap();

    // The sample is audited by row count under the requester, never its cells.
    let audited = audited_samples(&svc);
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].actor, "root");
    assert_eq!(
        audited[0].evidence.get("row_count").map(String::as_str),
        Some("1")
    );
    assert!(
        audited[0]
            .evidence
            .values()
            .all(|value| !value.contains(SECRET_CELL))
    );

    // Another administrator cannot read it; the requester reads it once.
    assert_eq!(
        get(&svc, &requested.discovery_id, "other-admin")
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    let result = get(&svc, &requested.discovery_id, "root").await.unwrap();
    assert_eq!(result.status, "completed");
    assert!(result.discovery_json.contains("\"orders\""));
    assert!(!result.discovery_json.contains(SECRET_CELL));
    assert_eq!(
        result.samples[0].rows[0]
            .cells
            .get("id")
            .map(String::as_str),
        Some(SECRET_CELL)
    );
    assert!(result.samples_withheld_reason.is_empty());
    assert_eq!(
        get(&svc, &requested.discovery_id, "root")
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
}

#[tokio::test]
async fn samples_are_withheld_from_a_caller_not_cleared_for_the_source_markings() {
    let svc = service();
    put_source(&svc, &["restricted"]).await;
    register(&svc).await;
    // A marked Source with no clearance configured denies all but trusted
    // service principals.
    let requested = request(&svc, "other-admin").await.unwrap();
    let work = claim(&svc).await;
    svc.ack_work(as_principal(
        completed_ack(&work, &work.fencing_token),
        "root",
    ))
    .await
    .unwrap();

    let result = get(&svc, &requested.discovery_id, "other-admin")
        .await
        .unwrap();
    assert_eq!(result.status, "completed");
    assert!(result.discovery_json.contains("\"orders\""));
    assert!(result.samples.is_empty());
    assert!(!result.samples_withheld_reason.is_empty());
}

#[tokio::test]
async fn a_request_no_runtime_takes_reads_as_unavailable() {
    let svc = service();
    put_source(&svc, &[]).await;
    let requested = request(&svc, "root").await.unwrap();
    assert_eq!(
        get(&svc, &requested.discovery_id, "root")
            .await
            .unwrap()
            .status,
        "pending"
    );
    let later = now_millis() + crate::sekai::source_discovery::DISCOVERY_DEADLINE_MS + 1;
    let settled = crate::sekai::source_discovery::take(
        svc.db.runtime(),
        NS,
        &requested.discovery_id,
        "root",
        later,
    )
    .unwrap();
    assert_eq!(
        (settled.status.as_str(), settled.failure.as_str()),
        ("failed", "unavailable")
    );
}

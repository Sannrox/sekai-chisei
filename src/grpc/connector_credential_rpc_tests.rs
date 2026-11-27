//! Issue, revoke, and claim of plane-held connector credential handles
//! (ADR 0175).

use super::*;
use crate::sekai::security::Role;
use sekai_connector_runtime::FleetKey;
use tonic::metadata::MetadataValue;

const NS: &str = "ops";

fn service() -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    crate::chisei_store::apply_chisei_schema(&db);
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db));
    for (principal, role) in [
        ("root", Role::Admin),
        ("ops-admin", Role::Admin),
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

fn github_spec(handle: &str) -> ConnectorSourceSpec {
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
        credential_ref: handle.into(),
        egress: vec!["api.github.com".into()],
        placement: [("zone".to_string(), "eu".to_string())].into(),
        every_ms: 60_000,
        owner: "team".into(),
        ..Default::default()
    }
}

async fn put_source(svc: &SekaiServiceImpl, handle: &str) {
    svc.put_source(as_principal(
        PutSourceRequest {
            namespace: NS.into(),
            source_id: "repo".into(),
            source: "github".into(),
            source_instance: "acme/repo".into(),
            spec: Some(github_spec(handle)),
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
            runtime_id: "runtime-a".into(),
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

async fn claim(svc: &SekaiServiceImpl) -> SourceSyncWork {
    svc.db
        .runtime()
        .tick_source_syncs(NS, now_millis())
        .unwrap();
    match svc
        .claim_work(as_principal(
            ClaimWorkRequest {
                kind: WorkKind::SourceSync.into(),
                namespace: NS.into(),
                runtime_id: "runtime-a".into(),
                work_id: "repo".into(),
                ttl_ms: 60_000,
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .payload
    {
        Some(claim_work_response::Payload::SourceSync(work)) => work,
        other => panic!("source sync, not {other:?}"),
    }
}

#[tokio::test]
async fn platform_admin_issues_and_revokes_a_sealed_handle() {
    let svc = service();
    let fleet = FleetKey::generate("fleet-1");
    let secret = b"plane-token";
    assert!(
        svc.register_runtime_fleet_key(as_principal(
            RegisterRuntimeFleetKeyRequest {
                key_id: "fleet-1".into(),
                public_key: fleet.public_bytes().to_vec(),
            },
            "ops-admin",
        ))
        .await
        .unwrap_err()
        .message()
        .contains("credential admin")
    );

    let registered = svc
        .register_runtime_fleet_key(as_principal(
            RegisterRuntimeFleetKeyRequest {
                key_id: "fleet-1".into(),
                public_key: fleet.public_bytes().to_vec(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();
    assert_eq!(registered.key_id, "fleet-1");
    assert_eq!(
        svc.register_runtime_fleet_key(as_principal(
            RegisterRuntimeFleetKeyRequest {
                key_id: "fleet-1".into(),
                public_key: fleet.public_bytes().to_vec(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap()
        .public_key,
        registered.public_key
    );

    let issued = svc
        .issue_credential_handle(as_principal(
            IssueCredentialHandleRequest {
                name: "ops/github-bot".into(),
                namespaces: vec![NS.into()],
                destinations: vec!["api.github.com".into()],
                slots: vec![SealedCredentialSlot {
                    name: "token".into(),
                    fleet_key_id: "fleet-1".into(),
                    ciphertext: fleet.seal(secret).unwrap(),
                }],
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(issued.name, "ops/github-bot");
    assert!(!issued.content_digest.is_empty());

    put_source(&svc, "ops/github-bot").await;
    let got = svc
        .get_source(as_principal(
            GetSourceRequest {
                namespace: NS.into(),
                source_id: "repo".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let got_debug = format!("{got:?}");
    assert!(!got_debug.contains("plane-token"));
    assert_eq!(
        got.source
            .as_ref()
            .and_then(|source| source.spec.as_ref())
            .map(|spec| spec.credential_ref.as_str()),
        Some("ops/github-bot")
    );
    register(&svc).await;
    let work = claim(&svc).await;
    let material = work.credential.expect("plane handle on the claim");
    assert!(!material.revoked);
    assert_eq!(material.slots.len(), 1);
    let ciphertext = String::from_utf8_lossy(&material.slots[0].ciphertext);
    assert!(!ciphertext.contains("plane-token"));

    svc.revoke_credential_handle(as_principal(
        RevokeCredentialHandleRequest {
            name: "ops/github-bot".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.db
        .runtime()
        .tick_source_syncs(NS, now_millis() + 1)
        .unwrap();
    // The previous claim still holds; disable-and-reclaim is not this test.
    let stored = crate::sekai::connector_credential::get_handle(svc.db.runtime(), "ops/github-bot")
        .unwrap()
        .unwrap();
    assert!(stored.revoked);
    assert!(stored.slots.is_empty());
    let row = format!("{stored:?}");
    assert!(!row.contains("plane-token"));
}

#[tokio::test]
async fn a_revoked_handle_is_carried_as_a_tombstone_on_the_next_claim() {
    let svc = service();
    let fleet = FleetKey::generate("fleet-1");
    svc.register_runtime_fleet_key(as_principal(
        RegisterRuntimeFleetKeyRequest {
            key_id: "fleet-1".into(),
            public_key: fleet.public_bytes().to_vec(),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.issue_credential_handle(as_principal(
        IssueCredentialHandleRequest {
            name: "ops/github-bot".into(),
            namespaces: vec![NS.into()],
            destinations: vec!["api.github.com".into()],
            slots: vec![SealedCredentialSlot {
                name: "token".into(),
                fleet_key_id: "fleet-1".into(),
                ciphertext: fleet.seal(b"plane-token").unwrap(),
            }],
        },
        "root",
    ))
    .await
    .unwrap();
    svc.revoke_credential_handle(as_principal(
        RevokeCredentialHandleRequest {
            name: "ops/github-bot".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    put_source(&svc, "ops/github-bot").await;
    register(&svc).await;
    let work = claim(&svc).await;
    let material = work.credential.expect("tombstone on the claim");
    assert!(material.revoked);
    assert!(material.slots.is_empty());
}

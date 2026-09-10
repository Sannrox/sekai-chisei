//! Register, inspect, and retire one admitted source-type descriptor (#818).

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    InspectSourceTypeDescriptorRequest, RegisterSourceTypeDescriptorRequest,
    RetireSourceTypeDescriptorRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::object_sync::GITHUB_OBJECT_SYNC_TYPE_DIGEST;
use sekai_chisei::sekai::security::Role;
use sekai_chisei::sekai::source_type_descriptor::{
    DESCRIPTOR_UNAVAILABLE, ProposedSourceTypeDescriptor, SOURCE_TYPE_DESCRIPTOR_CONTRACT,
    inspect_source_type_descriptor, register_source_type_descriptor, retire_source_type_descriptor,
    synthetic_pager_alert_v1,
};
use sekai_chisei::source_adapter_catalog::built_in_source_adapters;
use std::sync::Arc;
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

const FIXTURE: &str = include_str!("fixtures/source_type_descriptor/pager_alert_v1.json");

fn with_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    req
}

fn service() -> SekaiServiceImpl {
    SekaiServiceImpl::new(Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    ))))
}

#[test]
fn fixture_matches_prepared_pager_identity() {
    let fixture: ProposedSourceTypeDescriptor = serde_json::from_str(FIXTURE).unwrap();
    let prepared = synthetic_pager_alert_v1();
    assert_eq!(fixture, prepared);
    assert_eq!(fixture.contract_version, SOURCE_TYPE_DESCRIPTOR_CONTRACT);
    fixture.validate().unwrap();
}

#[test]
fn registered_descriptor_does_not_change_github_discovery() {
    let db = RuntimeDb::memory();
    let pager = synthetic_pager_alert_v1();
    register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
    let profiles = built_in_source_adapters();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].source, "github");
    assert_eq!(profiles[0].record_types, ["Issue", "PullRequest"]);
    assert_eq!(profiles[0].type_digest, GITHUB_OBJECT_SYNC_TYPE_DIGEST);
    assert_ne!(pager.digest, GITHUB_OBJECT_SYNC_TYPE_DIGEST);
}

#[tokio::test]
async fn grpc_register_inspect_and_retire_one_descriptor() {
    let svc = service();
    let pager = synthetic_pager_alert_v1();
    let registered = svc
        .register_source_type_descriptor(with_principal(
            RegisterSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                source: pager.source.clone(),
                record_kind: pager.record_kind.clone(),
                schema_revision: pager.schema_revision.clone(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .descriptor
        .unwrap();
    assert_eq!(registered.digest, pager.digest);
    assert_eq!(registered.status, "live");
    assert_eq!(registered.namespace, "ops");
    assert_eq!(registered.family, "source_control.object_sync");
    let inspected = svc
        .inspect_source_type_descriptor(with_principal(
            InspectSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                digest: registered.digest.clone(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .descriptor
        .unwrap();
    assert_eq!(inspected.source, "synthetic.pager");
    assert_eq!(inspected.record_kind, "Alert");
    assert_eq!(inspected.digest, pager.digest);
    assert!(
        inspected
            .contract_version
            .starts_with("sekai.source-type-descriptor/")
    );

    let denied = svc
        .inspect_source_type_descriptor(with_principal(
            InspectSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                digest: registered.digest.clone(),
            },
            "anonymous",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::Unauthenticated);

    let unknown = svc
        .inspect_source_type_descriptor(with_principal(
            InspectSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                digest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    .into(),
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(unknown.code(), Code::Unavailable);
    assert_eq!(unknown.message(), "source-type descriptor is unavailable");

    let retired = svc
        .retire_source_type_descriptor(with_principal(
            RetireSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                digest: registered.digest.clone(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .descriptor
        .unwrap();
    assert_eq!(retired.status, "retired");
    assert_eq!(
        retire_source_type_descriptor(&RuntimeDb::memory(), "local", "ops", &pager.digest, 11)
            .unwrap_err(),
        DESCRIPTOR_UNAVAILABLE
    );
}

#[tokio::test]
async fn grpc_rejects_github_profile_reuse_and_unauthenticated_register() {
    let svc = service();
    let github = svc
        .register_source_type_descriptor(with_principal(
            RegisterSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                source: "github".into(),
                record_kind: "Issue".into(),
                schema_revision: "v1".into(),
            },
            "local",
        ))
        .await
        .unwrap_err();
    assert_eq!(github.code(), Code::InvalidArgument);

    let unauthenticated = svc
        .register_source_type_descriptor(Request::new(RegisterSourceTypeDescriptorRequest {
            namespace: "ops".into(),
            source: "synthetic.pager".into(),
            record_kind: "Alert".into(),
            schema_revision: "v1".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(unauthenticated.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn grpc_allows_namespace_admin_and_rejects_editor() {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    db.ensure_team_namespace("ops", "alice", Role::Admin, "local")
        .unwrap();
    db.ensure_team_namespace("ops", "bob", Role::Editor, "local")
        .unwrap();
    let svc = SekaiServiceImpl::new(db);
    let pager = synthetic_pager_alert_v1();
    let registered = svc
        .register_source_type_descriptor(with_principal(
            RegisterSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                source: pager.source.clone(),
                record_kind: pager.record_kind.clone(),
                schema_revision: pager.schema_revision.clone(),
            },
            "alice",
        ))
        .await
        .unwrap()
        .into_inner()
        .descriptor
        .unwrap();
    assert_eq!(registered.digest, pager.digest);
    let editor = svc
        .register_source_type_descriptor(with_principal(
            RegisterSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                source: "synthetic.cmdb".into(),
                record_kind: "Service".into(),
                schema_revision: "v1".into(),
            },
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(editor.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_denies_unmanaged_namespace_without_global_admin() {
    let svc = service();
    let denied = svc
        .register_source_type_descriptor(with_principal(
            RegisterSourceTypeDescriptorRequest {
                namespace: "ops".into(),
                source: "synthetic.pager".into(),
                record_kind: "Alert".into(),
                schema_revision: "v1".into(),
            },
            "alice",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
}

#[test]
fn inspect_omits_owner_and_secret_like_fields() {
    let db = RuntimeDb::memory();
    let pager = synthetic_pager_alert_v1();
    let admitted = register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
    let inspected = inspect_source_type_descriptor(&db, "local", "ops", &admitted.digest).unwrap();
    let json = serde_json::to_string(&inspected).unwrap();
    for forbidden in [
        "admitted_by",
        "retired_by",
        "cursor",
        "payload",
        "secret",
        "token",
    ] {
        assert!(!json.contains(forbidden), "{forbidden} leaked in {json}");
    }
}

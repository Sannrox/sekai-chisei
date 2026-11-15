//! Datasource index RPCs (#2282): register, reindex, status, and typed
//! edits run the same lifecycle and the same refusals on SQLite and PostgreSQL.

use super::*;
use crate::grpc::pb::sekai::property_value::Kind;
use tonic::metadata::MetadataValue;

const NAMESPACE: &str = "sales";
const KIND: &str = "Customer";
const DATASET: &str = "ds-customers";

fn service_on(db: RuntimeDb) -> SekaiServiceImpl {
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
        db,
    )))
}

/// Run an index test on a scratch PostgreSQL database, on a multi-thread
/// runtime because the PostgreSQL store blocks in place. The store drops
/// after the runtime: closing its pool blocks.
fn on_postgres<F: std::future::Future<Output = ()>>(test: impl FnOnce(RuntimeDb) -> F) {
    let scratch = crate::db::ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test(db.clone()));
    drop(db);
}

fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    req
}

fn column(name: &str, col_type: &str) -> ColumnDef {
    ColumnDef {
        name: name.into(),
        r#type: col_type.into(),
        classification: "public".into(),
    }
}

fn property(name: &str, col_type: &str) -> PropertyDef {
    PropertyDef {
        name: name.into(),
        r#type: col_type.into(),
        classification: "public".into(),
        ..Default::default()
    }
}

fn datasource() -> ObjectTypeDatasource {
    ObjectTypeDatasource {
        contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
        namespace: NAMESPACE.into(),
        kind: KIND.into(),
        definition_digest: "sha256:customer-v1".into(),
        dataset_id: DATASET.into(),
        key_column: "customer_id".into(),
        property_mapping: HashMap::from([
            ("region".into(), "region".into()),
            ("quantity".into(), "quantity".into()),
        ]),
        hidden_column: "hidden".into(),
        ..Default::default()
    }
}

fn string_value(value: &str) -> PropertyValue {
    PropertyValue {
        kind: Some(Kind::StringValue(value.into())),
    }
}

fn int_value(value: i64) -> PropertyValue {
    PropertyValue {
        kind: Some(Kind::IntValue(value)),
    }
}

fn assert_status(label: &str, status: &Status, code: tonic::Code, message: &str) {
    assert_eq!(status.code(), code, "{label}: {status}");
    assert_eq!(status.message(), message, "{label}: {status}");
}

async fn seed_kind(svc: &SekaiServiceImpl) {
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: KIND.into(),
                properties: vec![property("region", "string"), property("quantity", "int")],
                ..Default::default()
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    svc.create_dataset(with_named_principal(
        CreateDatasetRequest {
            dataset: Some(Dataset {
                id: DATASET.into(),
                name: "customers".into(),
                columns: vec![
                    column("customer_id", "string"),
                    column("region", "string"),
                    column("quantity", "string"),
                    column("hidden", "string"),
                ],
                ..Default::default()
            }),
        },
        "local",
    ))
    .await
    .unwrap();
    svc.append_rows(with_named_principal(
        AppendRowsRequest {
            dataset_id: DATASET.into(),
            rows: vec![
                Row {
                    values: HashMap::from([
                        ("customer_id".into(), "c1".into()),
                        ("region".into(), "eu".into()),
                        ("quantity".into(), "2".into()),
                        ("hidden".into(), "0".into()),
                    ]),
                },
                Row {
                    values: HashMap::from([
                        ("customer_id".into(), "c-hidden".into()),
                        ("region".into(), "eu".into()),
                        ("quantity".into(), "9".into()),
                        ("hidden".into(), "true".into()),
                    ]),
                },
            ],
        },
        "local",
    ))
    .await
    .unwrap();
}

async fn register(svc: &SekaiServiceImpl, principal: &str) -> Result<ObjectTypeDatasource, Status> {
    svc.register_object_type_datasource(with_named_principal(
        RegisterObjectTypeDatasourceRequest {
            datasource: Some(datasource()),
            idempotency_key: "reg-1".into(),
        },
        principal,
    ))
    .await
    .map(|response| response.into_inner().datasource.unwrap())
}

async fn reindex(
    svc: &SekaiServiceImpl,
    principal: &str,
) -> Result<ReindexObjectTypeResponse, Status> {
    svc.reindex_object_type(with_named_principal(
        ReindexObjectTypeRequest {
            namespace: NAMESPACE.into(),
            kind: KIND.into(),
            full_rebuild: true,
        },
        principal,
    ))
    .await
    .map(|response| response.into_inner())
}

async fn status(svc: &SekaiServiceImpl, principal: &str) -> Result<ObjectTypeIndexStatus, Status> {
    svc.get_object_type_index_status(with_named_principal(
        GetObjectTypeIndexStatusRequest {
            namespace: NAMESPACE.into(),
            kind: KIND.into(),
        },
        principal,
    ))
    .await
    .map(|response| response.into_inner().status.unwrap())
}

async fn put_edit(
    svc: &SekaiServiceImpl,
    principal: &str,
    properties: HashMap<String, PropertyValue>,
) -> Result<(), Status> {
    svc.put_object_type_index_edit(with_named_principal(
        PutObjectTypeIndexEditRequest {
            namespace: NAMESPACE.into(),
            kind: KIND.into(),
            source_key: "c1".into(),
            properties,
            hidden: false,
            idempotency_key: "act-region".into(),
        },
        principal,
    ))
    .await
    .map(|_| ())
}

/// Register, reindex, read status, and put a typed edit: hidden source rows
/// stay out of the count, and an unfit PropertyValue is refused by name.
async fn exercise_index_rpc_lifecycle(db: RuntimeDb) {
    let svc = service_on(db);
    seed_kind(&svc).await;

    let missing = status(&svc, "local").await.unwrap_err();
    assert_status(
        "status before register",
        &missing,
        tonic::Code::NotFound,
        "not found",
    );

    let stored = register(&svc, "local").await.unwrap();
    assert_eq!(stored.dataset_id, DATASET);
    assert_eq!(stored.key_column, "customer_id");
    let report = reindex(&svc, "local").await.unwrap();
    assert!(!report.quarantined, "{report:?}");
    let indexed = status(&svc, "local").await.unwrap();
    assert_eq!(
        indexed.member_count, 1,
        "hidden source rows are not members"
    );
    assert_eq!(indexed.namespace, NAMESPACE);
    assert_eq!(indexed.kind, KIND);

    put_edit(
        &svc,
        "local",
        HashMap::from([
            ("region".into(), string_value("west")),
            ("quantity".into(), int_value(7)),
        ]),
    )
    .await
    .unwrap();
    let rebuilt = reindex(&svc, "local").await.unwrap();
    assert!(!rebuilt.quarantined, "{rebuilt:?}");
    assert_eq!(status(&svc, "local").await.unwrap().member_count, 1);

    let unfit = put_edit(
        &svc,
        "local",
        HashMap::from([("quantity".into(), string_value("nope"))]),
    )
    .await
    .unwrap_err();
    assert_eq!(unfit.code(), tonic::Code::InvalidArgument, "{unfit}");
    assert!(
        unfit.message().contains("quantity"),
        "typed edit names the unfit property: {unfit}"
    );
}

#[tokio::test]
async fn index_rpcs_run_the_lifecycle() {
    exercise_index_rpc_lifecycle(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_index_rpcs_run_the_lifecycle() {
    on_postgres(exercise_index_rpc_lifecycle);
}

/// Writes require the credential-admin principal. Status is a namespace
/// read: a non-member is refused, a granted viewer may read.
async fn exercise_index_rpc_refusals(db: RuntimeDb) {
    let svc = service_on(db);
    seed_kind(&svc).await;
    register(&svc, "local").await.unwrap();
    reindex(&svc, "local").await.unwrap();
    svc.ensure_team_namespace(with_named_principal(
        EnsureTeamNamespaceRequest {
            namespace: NAMESPACE.into(),
            principal: "alice".into(),
            role: "viewer".into(),
        },
        "local",
    ))
    .await
    .unwrap();

    let admin_denied = "credential admin required";
    for (label, result) in [
        ("register as alice", register(&svc, "alice").await.map(drop)),
        ("reindex as alice", reindex(&svc, "alice").await.map(drop)),
        (
            "put edit as alice",
            put_edit(
                &svc,
                "alice",
                HashMap::from([("region".into(), string_value("west"))]),
            )
            .await,
        ),
    ] {
        assert_status(
            label,
            &result.unwrap_err(),
            tonic::Code::PermissionDenied,
            admin_denied,
        );
    }

    let view = status(&svc, "alice").await.unwrap();
    assert_eq!(view.member_count, 1);

    let outsider = status(&svc, "bob").await.unwrap_err();
    assert_status(
        "status as outsider",
        &outsider,
        tonic::Code::PermissionDenied,
        "namespace access denied",
    );
}

#[tokio::test]
async fn index_rpcs_refuse_outside_admin_and_namespace() {
    exercise_index_rpc_refusals(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_index_rpcs_refuse_outside_admin_and_namespace() {
    on_postgres(exercise_index_rpc_refusals);
}

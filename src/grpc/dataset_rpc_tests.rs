//! Dataset version, rollback and health RPCs (#2415): the promoted family runs
//! the same lifecycle and the same refusals on SQLite and PostgreSQL.

use super::*;

const DATASET: &str = "ds-orders";

fn service_on(db: RuntimeDb) -> SekaiServiceImpl {
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
        db,
    )))
}

/// Run a dataset test on a scratch PostgreSQL database, on a multi-thread
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

fn local<T>(payload: T) -> Request<T> {
    with_named_principal(payload, "local")
}

/// A dataset with one row per version: three appends make versions 1 to 3.
async fn seed_versions(svc: &SekaiServiceImpl) {
    svc.create_dataset(local(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: DATASET.into(),
            name: "orders".into(),
            columns: ["order_id", "region"]
                .map(|name| ColumnDef {
                    name: name.into(),
                    r#type: "string".into(),
                    classification: "public".into(),
                })
                .to_vec(),
            ..Default::default()
        }),
    }))
    .await
    .unwrap();
    for order in ["o1", "o2", "o3"] {
        svc.append_rows(local(AppendRowsRequest {
            dataset_id: DATASET.into(),
            rows: vec![Row {
                values: HashMap::from([
                    ("order_id".into(), order.into()),
                    ("region".into(), "eu".into()),
                ]),
            }],
        }))
        .await
        .unwrap();
    }
}

async fn versions(svc: &SekaiServiceImpl) -> Vec<DatasetVersion> {
    svc.list_dataset_versions(local(ListDatasetVersionsRequest {
        dataset_id: DATASET.into(),
        ..Default::default()
    }))
    .await
    .unwrap()
    .into_inner()
    .versions
}

async fn live_orders(svc: &SekaiServiceImpl) -> Vec<String> {
    let mut orders: Vec<String> = svc
        .query_rows(local(QueryRowsRequest {
            dataset_id: DATASET.into(),
            query: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .rows
        .into_iter()
        .map(|row| row.values["order_id"].clone())
        .collect();
    orders.sort();
    orders
}

/// List, page, read a version, roll back, and run health checks.
async fn exercise_dataset_rpc_lifecycle(db: RuntimeDb) {
    let svc = service_on(db);
    seed_versions(&svc).await;

    let listed = svc
        .list_datasets(local(ListDatasetsRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert!(listed.datasets.iter().any(|dataset| dataset.id == DATASET));

    let first_page = svc
        .list_dataset_versions(local(ListDatasetVersionsRequest {
            dataset_id: DATASET.into(),
            page_size: 2,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first_page.versions.len(), 2);
    assert!(!first_page.next_page_token.is_empty());
    let all = versions(&svc).await;
    assert_eq!(
        all.iter().map(|version| version.seq).collect::<Vec<_>>(),
        [1, 2, 3]
    );

    let first = svc
        .get_dataset_version(local(GetDatasetVersionRequest {
            dataset_id: DATASET.into(),
            version_id: all[0].version_id.clone(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.rows.len(), 1);
    assert_eq!(first.rows[0].values["order_id"], "o1");

    let rolled = svc
        .rollback_dataset(local(RollbackDatasetRequest {
            dataset_id: DATASET.into(),
            restore_from_version_id: all[0].version_id.clone(),
            reason: "bad sync".into(),
            tenant: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    let restored = rolled.version.unwrap();
    assert_eq!(restored.seq, 4);
    assert_eq!(restored.restored_from_version_id, all[0].version_id);
    assert_eq!(live_orders(&svc).await, ["o1"]);

    svc.put_dataset_health_check(local(PutDatasetHealthCheckRequest {
        check: Some(DatasetHealthCheck {
            dataset_id: DATASET.into(),
            check_id: "enough-rows".into(),
            kind: crate::sekai::dataset_health::KIND_ROW_COUNT.into(),
            min_rows: 2,
            ..Default::default()
        }),
    }))
    .await
    .unwrap();
    let checks = svc
        .list_dataset_health_checks(local(ListDatasetHealthChecksRequest {
            dataset_id: DATASET.into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .checks;
    assert_eq!(checks.len(), 1);
    let judged = svc
        .run_dataset_health_checks(local(RunDatasetHealthChecksRequest {
            dataset_id: DATASET.into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .results;
    assert_eq!(judged.len(), 1);
    assert!(!judged[0].passed, "one live row is below min_rows");
    let results = svc
        .list_dataset_health_results(local(ListDatasetHealthResultsRequest {
            dataset_id: DATASET.into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].check_id, "enough-rows");
    svc.list_dataset_alerts(local(ListDatasetAlertsRequest {
        dataset_id: DATASET.into(),
        ..Default::default()
    }))
    .await
    .unwrap();
}

#[tokio::test]
async fn dataset_rpcs_run_the_lifecycle() {
    exercise_dataset_rpc_lifecycle(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_dataset_rpcs_run_the_lifecycle() {
    on_postgres(exercise_dataset_rpc_lifecycle);
}

/// A dataset that an object type index derives objects from refuses rollback
/// by name and keeps its rows, so derived objects never sit on rows the
/// dataset no longer holds.
async fn exercise_rollback_refuses_index_backed_dataset(db: RuntimeDb) {
    let svc = service_on(db);
    seed_versions(&svc).await;
    svc.create_schema_type(local(CreateSchemaTypeRequest {
        r#type: Some(ObjectType {
            kind: "Order".into(),
            properties: vec![PropertyDef {
                name: "region".into(),
                r#type: "string".into(),
                classification: "public".into(),
                ..Default::default()
            }],
            ..Default::default()
        }),
    }))
    .await
    .unwrap();
    svc.register_object_type_datasource(local(RegisterObjectTypeDatasourceRequest {
        datasource: Some(ObjectTypeDatasource {
            contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Order".into(),
            definition_digest: "sha256:order-v1".into(),
            dataset_id: DATASET.into(),
            key_column: "order_id".into(),
            property_mapping: HashMap::from([("region".into(), "region".into())]),
            ..Default::default()
        }),
        idempotency_key: "reg-orders".into(),
    }))
    .await
    .unwrap();

    let first = versions(&svc).await.remove(0);
    let refused = svc
        .rollback_dataset(local(RollbackDatasetRequest {
            dataset_id: DATASET.into(),
            restore_from_version_id: first.version_id,
            reason: "bad sync".into(),
            tenant: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition, "{refused}");
    assert!(
        refused
            .message()
            .contains("object type index (sales/Order)"),
        "{refused}"
    );
    assert_eq!(live_orders(&svc).await, ["o1", "o2", "o3"]);
    assert_eq!(
        versions(&svc).await.len(),
        3,
        "no restore version is written"
    );
}

#[tokio::test]
async fn rollback_refuses_an_index_backed_dataset() {
    exercise_rollback_refuses_index_backed_dataset(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_rollback_refuses_an_index_backed_dataset() {
    on_postgres(exercise_rollback_refuses_index_backed_dataset);
}

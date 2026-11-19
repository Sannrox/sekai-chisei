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

/// Registers `kind` in `sales` as an object type indexed from `dataset_id`,
/// and creates one object of it.
async fn seed_dataset_backed_object(svc: &SekaiServiceImpl, kind: &str, dataset_id: &str) {
    svc.create_schema_type(local(CreateSchemaTypeRequest {
        r#type: Some(ObjectType {
            kind: kind.into(),
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
            kind: kind.into(),
            definition_digest: format!("sha256:{kind}-v1"),
            dataset_id: dataset_id.into(),
            key_column: "order_id".into(),
            property_mapping: HashMap::from([("region".into(), "region".into())]),
            ..Default::default()
        }),
        idempotency_key: format!("reg-{kind}"),
    }))
    .await
    .unwrap();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: format!("{kind}-1"),
            kind: kind.into(),
            name: kind.into(),
            namespace: "sales".into(),
            external_id: format!("{kind}:1"),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
}

fn seed_dataset(svc: &SekaiServiceImpl, id: &str, object_id: &str) {
    svc.db
        .runtime()
        .create_dataset(&crate::sekai::dataset::Dataset {
            id: id.into(),
            name: id.into(),
            columns: Vec::new(),
            object_id: object_id.into(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
}

fn seed_transform(svc: &SekaiServiceImpl, id: &str, input: &str, output: &str) {
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform, TransformStep};
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "sales".into(),
        transform_id: id.into(),
        input_dataset_id: input.into(),
        output_dataset_id: output.into(),
        steps: vec![TransformStep {
            kind: "project".into(),
            column: String::new(),
            op: String::new(),
            value: String::new(),
            columns: vec!["order_id".into()],
        }],
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: None,
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    svc.db
        .runtime()
        .put_governed_transform(&transform, 10)
        .unwrap();
}

async fn lineage_of(svc: &SekaiServiceImpl, object_id: &str) -> LineageResult {
    svc.get_lineage(local(GetLineageRequest {
        object_id: object_id.into(),
        max_nodes: 0,
    }))
    .await
    .unwrap()
    .into_inner()
    .result
    .unwrap()
}

/// `(kind, id, ephemeral)` per node, and `from>to` per edge.
fn lineage_shape(result: &LineageResult) -> (Vec<(String, String, bool)>, Vec<String>) {
    (
        result
            .nodes
            .iter()
            .map(|node| {
                let object = node.object.as_ref().unwrap();
                (object.kind.clone(), object.id.clone(), node.ephemeral)
            })
            .collect(),
        result
            .edges
            .iter()
            .map(|edge| format!("{}>{}", edge.from, edge.to))
            .collect(),
    )
}

/// GetLineage on a dataset-backed object reaches its dataset, the transform
/// that writes it and that transform's input, or the source that lands a
/// source-owned dataset. A dataset the caller may not read is left out
/// without truncating the answer.
async fn exercise_lineage_reaches_datasets(db: RuntimeDb) {
    let svc = service_on(db);
    seed_dataset(&svc, "ds-raw", "");
    seed_dataset(&svc, "ds-orders", "");
    seed_transform(&svc, "tf-orders", "ds-raw", "ds-orders");
    seed_dataset_backed_object(&svc, "Order", "ds-orders").await;
    let result = lineage_of(&svc, "Order-1").await;
    let node = |kind: &str, id: &str, ephemeral| (kind.to_string(), id.to_string(), ephemeral);
    assert_eq!(
        lineage_shape(&result),
        (
            vec![
                node("Order", "Order-1", false),
                node("dataset", "dataset:sales/ds-orders", true),
                node("transform", "transform:sales/tf-orders", true),
                node("dataset", "dataset:sales/ds-raw", true),
            ],
            [
                "Order-1>dataset:sales/ds-orders",
                "dataset:sales/ds-orders>transform:sales/tf-orders",
                "transform:sales/tf-orders>dataset:sales/ds-raw",
            ]
            .map(String::from)
            .to_vec(),
        )
    );
    assert!(!result.truncated);

    // The input dataset is bound to an object that does not exist, so the
    // dataset read check refuses it.
    seed_dataset(&svc, "ds-hidden", "missing-binding-object");
    seed_dataset(&svc, "ds-returns", "");
    seed_transform(&svc, "tf-returns", "ds-hidden", "ds-returns");
    seed_dataset_backed_object(&svc, "Return", "ds-returns").await;
    let result = lineage_of(&svc, "Return-1").await;
    let (nodes, edges) = lineage_shape(&result);
    assert_eq!(
        nodes.last(),
        Some(&node("transform", "transform:sales/tf-returns", true)),
        "{nodes:?}"
    );
    assert!(edges.iter().all(|edge| !edge.contains("ds-hidden")));
    assert!(!result.truncated);

    let source_dataset = crate::db::source_batch_dataset::binding_dataset_id("bind-1", "Refund");
    seed_dataset(&svc, &source_dataset, "");
    seed_dataset_backed_object(&svc, "Refund", &source_dataset).await;
    let (nodes, _) = lineage_shape(&lineage_of(&svc, "Refund-1").await);
    assert_eq!(
        nodes.last(),
        Some(&node("source", "source:sales/bind-1", true)),
        "{nodes:?}"
    );

    // A second object backed by the same dataset keeps its own edge to it.
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "Order-2".into(),
            kind: "Order".into(),
            name: "Order".into(),
            namespace: "sales".into(),
            external_id: "Order:2".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .runtime()
        .create_link(&domain::Link {
            id: "order-1-from-2".into(),
            from_id: "Order-1".into(),
            to_id: "Order-2".into(),
            relation: "derived_from".into(),
            created: 0,
        })
        .unwrap();
    let (_, edges) = lineage_shape(&lineage_of(&svc, "Order-1").await);
    assert!(
        edges.contains(&"Order-2>dataset:sales/ds-orders".to_string()),
        "{edges:?}"
    );
}

/// A transform scoring with a pinned model version (#3074): lineage from its
/// output reaches the model version and, through it, the dataset the model
/// was trained on.
async fn exercise_lineage_reaches_pinned_model_version(db: RuntimeDb) {
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform};
    use crate::sekai::model_version as model;
    let svc = service_on(db);
    for id in ["ds-features", "ds-scores", "ds-train"] {
        seed_dataset(&svc, id, "");
    }
    let column = |name: &str| model::ModelColumn {
        name: name.into(),
        col_type: "string".into(),
    };
    let version = svc
        .db
        .runtime()
        .insert_model_version(
            &model::ModelVersion::from_run(
                model::ModelVersionRegistration {
                    namespace: "sales".into(),
                    model_name: "churn".into(),
                    digest: "sha256:a".into(),
                    adapter_id: "tabular".into(),
                    adapter_version: "1".into(),
                    registry_locator: "churn/a".into(),
                    contract: model::AdapterContract {
                        inputs: vec![model::ModelInput {
                            name: "features".into(),
                            columns: vec![column("order_id")],
                        }],
                        output: vec![column("score")],
                    },
                    run_id: "run-train".into(),
                    actor: "trainer".into(),
                },
                "sales",
                "",
                &std::collections::BTreeMap::from([("ds-train".into(), "v1".into())]),
                1,
            )
            .unwrap(),
        )
        .unwrap();
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "sales".into(),
        transform_id: "tf-score".into(),
        input_dataset_id: "ds-features".into(),
        output_dataset_id: "ds-scores".into(),
        steps: Vec::new(),
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: Some(crate::sekai::governed_transform::IsolatedProcessSpec {
            engine: "python".into(),
            runtime_image: "runner:1".into(),
            code: "score()".into(),
            model_inputs: std::collections::BTreeMap::from([(
                "scorer".into(),
                version.version_id.clone(),
            )]),
            ..Default::default()
        }),
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    svc.db
        .runtime()
        .put_governed_transform(&transform, 10)
        .unwrap();
    seed_dataset_backed_object(&svc, "Score", "ds-scores").await;
    let (_, edges) = lineage_shape(&lineage_of(&svc, "Score-1").await);
    let model_node = format!("model_version:sales/{}", version.version_id);
    for edge in [
        "transform:sales/tf-score>dataset:sales/ds-features".to_string(),
        format!("transform:sales/tf-score>{model_node}"),
        format!("{model_node}>dataset:sales/ds-train"),
    ] {
        assert!(edges.contains(&edge), "{edge} missing from {edges:?}");
    }
}

/// A model trained by a transform (#3021): the runner's write-back
/// publishes one version through `WriteTransformRunResult`, and lineage from
/// a transform scoring with it reaches the training transform and its
/// training dataset.
async fn exercise_trained_model_publishes_with_lineage(db: RuntimeDb) {
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform};
    let svc = service_on(db);
    for id in ["ds-train", "ds-fit", "ds-features", "ds-scores"] {
        seed_dataset(&svc, id, "");
    }
    let rows = vec![std::collections::HashMap::from([(
        "order_id".to_string(),
        "1".to_string(),
    )])];
    svc.db.runtime().append_rows("ds-train", &rows).unwrap();
    let isolated = |transform_id: &str, input: &str, output: &str, spec| {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            transform_id: transform_id.into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(spec),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    };
    let training = isolated(
        "tf-train",
        "ds-train",
        "ds-fit",
        crate::sekai::governed_transform::IsolatedProcessSpec {
            engine: "python".into(),
            runtime_image: "trainer:1".into(),
            code: "fit()".into(),
            model_outputs: ["churn".to_string()].into(),
            ..Default::default()
        },
    );
    svc.db
        .runtime()
        .put_governed_transform(&training, 10)
        .unwrap();
    // The definition's model outputs reach clients.
    let listed = svc
        .list_governed_transforms(with_named_principal(
            ListGovernedTransformsRequest {
                namespace: "sales".into(),
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.transforms[0].model_outputs, ["churn"]);
    let run = svc
        .db
        .runtime()
        .run_governed_transform("sales", "tf-train", false, 20)
        .unwrap();
    let (work, _) = svc
        .db
        .runtime()
        // The RPC write-back checks the lease at wall-clock time.
        .claim_transform_work(
            "sales",
            "trainer-1",
            "",
            60_000,
            chrono::Utc::now().timestamp_millis(),
        )
        .unwrap()
        .expect("claimable training run");
    let column = |name: &str| ColumnDef {
        name: name.into(),
        r#type: "string".into(),
        ..Default::default()
    };
    svc.write_transform_run_result(with_named_principal(
        WriteTransformRunResultRequest {
            run_id: work.run_id,
            runtime_id: work.claim_owner,
            claim_generation: work.claim_generation,
            fencing_token: work.fencing_token,
            rows: rows
                .iter()
                .map(|values| TransformRunInputRow {
                    values: values.clone(),
                    ..Default::default()
                })
                .collect(),
            output_digest: crate::sekai::governed_transform::rows_digest(&rows),
            model_outputs: vec![TransformModelOutput {
                model_name: "churn".into(),
                digest: "sha256:trained".into(),
                adapter_id: "tabular".into(),
                adapter_version: "1".into(),
                registry_locator: "churn/trained".into(),
                contract: Some(ModelAdapterContract {
                    inputs: vec![ModelInput {
                        name: "features".into(),
                        columns: vec![column("order_id")],
                    }],
                    output: vec![column("score")],
                }),
            }],
            ..Default::default()
        },
        "local",
    ))
    .await
    .unwrap();
    let [version] = svc
        .db
        .runtime()
        .list_model_versions("sales", "churn")
        .unwrap()
        .try_into()
        .expect("one published version");
    assert_eq!(version.run_id, run.run_id);

    let scoring = isolated(
        "tf-score",
        "ds-features",
        "ds-scores",
        crate::sekai::governed_transform::IsolatedProcessSpec {
            engine: "python".into(),
            runtime_image: "runner:1".into(),
            code: "score()".into(),
            model_inputs: [("scorer".to_string(), version.version_id.clone())].into(),
            ..Default::default()
        },
    );
    svc.db
        .runtime()
        .put_governed_transform(&scoring, 40)
        .unwrap();
    seed_dataset_backed_object(&svc, "Score", "ds-scores").await;
    let (_, edges) = lineage_shape(&lineage_of(&svc, "Score-1").await);
    let model_node = format!("model_version:sales/{}", version.version_id);
    for edge in [
        format!("transform:sales/tf-score>{model_node}"),
        format!("{model_node}>dataset:sales/ds-train"),
        format!("{model_node}>transform:sales/tf-train"),
    ] {
        assert!(edges.contains(&edge), "{edge} missing from {edges:?}");
    }
}

#[tokio::test]
async fn trained_model_publishes_with_lineage() {
    exercise_trained_model_publishes_with_lineage(RuntimeDb::memory()).await;
}

#[tokio::test]
async fn lineage_reaches_pinned_model_version() {
    exercise_lineage_reaches_pinned_model_version(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_lineage_reaches_pinned_model_version() {
    on_postgres(exercise_lineage_reaches_pinned_model_version);
}

#[tokio::test]
async fn lineage_reaches_datasets() {
    exercise_lineage_reaches_datasets(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_lineage_reaches_datasets() {
    on_postgres(exercise_lineage_reaches_datasets);
}

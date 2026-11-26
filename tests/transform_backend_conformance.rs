//! Promoted transform, schedule, and chain RPCs (#2414): each call is
//! invokable without the experimental gate on SQLite and PostgreSQL. Two
//! planes ticking a due bucket through `TickGovernedTransforms` admit one
//! run, and a crash before the cursor commit leaves the bucket due.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    CancelGovernedTransformRunRequest, GetGovernedTransformRunRequest, GetTransformChainRunRequest,
    GetTransformOutputStateRequest, GovernedTransform, ListGovernedTransformRunsRequest,
    ListGovernedTransformsRequest, PreviewGovernedTransformRequest, PutGovernedTransformRequest,
    PutTransformChainRequest, RunGovernedTransformRequest, RunTransformChainRequest,
    TickGovernedTransformsRequest, TransformChain, TransformChainStep, TransformStep,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::rpc_maturity::require_invokable;
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset};
use sekai_chisei::sekai::governed_transform::{CONTRACT_VERSION, ISOLATED_CLASS};
use sekai_chisei::sekai::transform_chain::CHAIN_CONTRACT;
use tonic::Code;
use tonic::metadata::MetadataValue;

use crate::postgres_scratch::ScratchDatabase;

const PROMOTED: &[&str] = &[
    "PutGovernedTransform",
    "ListGovernedTransforms",
    "PreviewGovernedTransform",
    "RunGovernedTransform",
    "GetGovernedTransformRun",
    "ListGovernedTransformRuns",
    "CancelGovernedTransformRun",
    "GetTransformOutputState",
    "TickGovernedTransforms",
    "PutTransformChain",
    "RunTransformChain",
    "GetTransformChainRun",
];

const STILL_EXPERIMENTAL: &[&str] = &[
    "RunAdHocGovernedTransform",
    "ListTransformChains",
    "GetTransformChain",
    "ListTransformChainRuns",
    "ShadowGovernedTransform",
    "ReplayGovernedTransform",
    "RunGovernedTransformOnBranch",
    "ApplyStreamingTransformBatch",
];

fn request<T>(payload: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(payload);
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static("local"));
    request
}

fn plane(db: Arc<RuntimeDb>) -> SekaiServiceImpl {
    sekai_chisei::chisei_store::apply_chisei_schema(&db);
    SekaiServiceImpl::new(SekaiStore::from_shared_runtime(db))
}

fn dataset(id: &str) -> Dataset {
    Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    }
}

fn projection(id: &str, input: &str, output: &str) -> GovernedTransform {
    GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: id.into(),
        input_dataset_id: input.into(),
        output_dataset_id: output.into(),
        steps: vec![TransformStep {
            kind: "project".into(),
            columns: vec!["id".into()],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn seed_pair(db: &RuntimeDb, input: &str, output: &str) {
    db.create_dataset(&dataset(input)).unwrap();
    db.create_dataset(&dataset(output)).unwrap();
    db.append_rows(input, &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
}

/// Runs on a multi-threaded runtime, as the server does, so a handler that
/// calls a blocking store on a runtime worker fails here too.
fn exercise(db: Arc<RuntimeDb>) {
    for rpc in PROMOTED {
        require_invokable(rpc, false).unwrap_or_else(|error| panic!("{rpc}: {error}"));
    }
    for rpc in STILL_EXPERIMENTAL {
        let error = require_invokable(rpc, false).expect_err(rpc);
        assert_eq!(error.code(), Code::FailedPrecondition, "{rpc}");
    }

    seed_pair(&db, "in", "out");
    let svc = plane(db.clone());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let transform = projection("hosted", "in", "out");
        svc.put_governed_transform(request(PutGovernedTransformRequest {
            transform: Some(transform.clone()),
        }))
        .await
        .unwrap();

        let preview = svc
            .preview_governed_transform(request(PreviewGovernedTransformRequest {
                transform: Some(transform),
                row_cap: 0,
                preview_id: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!preview.rows.is_empty(), "{preview:?}");

        let listed = svc
            .list_governed_transforms(request(ListGovernedTransformsRequest {
                namespace: "ops".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .transforms;
        assert!(
            listed.iter().any(|item| item.transform_id == "hosted"),
            "{listed:?}"
        );

        let run = svc
            .run_governed_transform(request(RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "hosted".into(),
                incremental: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        assert_eq!(run.transform_id, "hosted");
        assert!(!run.quarantined);

        let got = svc
            .get_governed_transform_run(request(GetGovernedTransformRunRequest {
                run_id: run.run_id.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        assert_eq!(got.run_id, run.run_id);

        let runs = svc
            .list_governed_transform_runs(request(ListGovernedTransformRunsRequest {
                namespace: "ops".into(),
                limit: 20,
            }))
            .await
            .unwrap()
            .into_inner()
            .runs;
        assert!(
            runs.iter().any(|item| item.run_id == run.run_id),
            "{runs:?}"
        );

        let state = svc
            .get_transform_output_state(request(GetTransformOutputStateRequest {
                namespace: "ops".into(),
                dataset_id: "out".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .state
            .expect("output state after a run");
        assert_eq!(state.dataset_id, "out");

        seed_pair(&db, "iso-in", "iso-out");
        svc.put_governed_transform(request(PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "isolated".into(),
                input_dataset_id: "iso-in".into(),
                output_dataset_id: "iso-out".into(),
                profile: ISOLATED_CLASS.into(),
                code: "SELECT * FROM input".into(),
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap();
        let pending = svc
            .run_governed_transform(request(RunGovernedTransformRequest {
                namespace: "ops".into(),
                transform_id: "isolated".into(),
                incremental: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        assert_eq!(pending.dispatch_status, "pending");
        let cancelled = svc
            .cancel_governed_transform_run(request(CancelGovernedTransformRunRequest {
                run_id: pending.run_id.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        assert_eq!(cancelled.run_id, pending.run_id);

        svc.put_transform_chain(request(PutTransformChainRequest {
            chain: Some(TransformChain {
                contract_version: CHAIN_CONTRACT.into(),
                namespace: "ops".into(),
                chain_id: "pipe".into(),
                steps: vec![TransformChainStep {
                    name: "a".into(),
                    transform_id: "hosted".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        }))
        .await
        .unwrap();
        let chain = svc
            .run_transform_chain(request(RunTransformChainRequest {
                namespace: "ops".into(),
                chain_id: "pipe".into(),
                idempotency_key: "pipe-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        assert_eq!(chain.chain_id, "pipe");
        let chain_got = svc
            .get_transform_chain_run(request(GetTransformChainRunRequest {
                run_id: chain.run_id.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        assert_eq!(chain_got.run_id, chain.run_id);

        seed_pair(&db, "tick-in", "tick-out");
        svc.put_governed_transform(request(PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                schedule_every_ms: 60_000,
                ..projection("hourly", "tick-in", "tick-out")
            }),
        }))
        .await
        .unwrap();
        let ticked = svc
            .tick_governed_transforms(request(TickGovernedTransformsRequest { now_ms: 90_000 }))
            .await
            .unwrap()
            .into_inner()
            .runs;
        assert_eq!(ticked.len(), 1, "{ticked:?}");
        assert_eq!(ticked[0].transform_id, "hourly");
    });
}

fn two_planes_tick_once(a: Arc<RuntimeDb>, b: Arc<RuntimeDb>) {
    seed_pair(&a, "share-in", "share-out");
    let a = Arc::new(plane(a));
    let b = Arc::new(plane(b));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        a.put_governed_transform(request(PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                schedule_every_ms: 60_000,
                ..projection("shared", "share-in", "share-out")
            }),
        }))
        .await
        .unwrap();
        let ticks = [a.clone(), b.clone()].map(|plane| {
            tokio::spawn(async move {
                plane
                    .tick_governed_transforms(request(TickGovernedTransformsRequest {
                        now_ms: 90_000,
                    }))
                    .await
                    .map(|response| response.into_inner().runs.len())
            })
        });
        let mut admitted = 0;
        for tick in ticks {
            admitted += tick.await.unwrap().unwrap();
        }
        assert_eq!(admitted, 1, "one plane admits the due run");
        let runs = a
            .list_governed_transform_runs(request(ListGovernedTransformRunsRequest {
                namespace: "ops".into(),
                limit: 20,
            }))
            .await
            .unwrap()
            .into_inner()
            .runs;
        assert_eq!(
            runs.iter()
                .filter(|run| run.transform_id == "shared")
                .count(),
            1,
            "{runs:?}"
        );
    });
}

fn uncommitted_cursor_leaves_bucket_due_sqlite(path: &Path) {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(path.to_str().unwrap()).unwrap(),
    )));
    seed_pair(&db, "crash-in", "crash-out");
    let svc = plane(db);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        svc.put_governed_transform(request(PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                schedule_every_ms: 60_000,
                ..projection("crash", "crash-in", "crash-out")
            }),
        }))
        .await
        .unwrap();
    });
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO sekai_transform_schedule_cursor
         (namespace, transform_id, last_bucket) VALUES (?1, ?2, ?3)",
        rusqlite::params!["ops", "crash", 1i64],
    )
    .unwrap();
    conn.execute_batch("ROLLBACK").unwrap();
    drop(conn);
    runtime.block_on(async {
        let ticked = svc
            .tick_governed_transforms(request(TickGovernedTransformsRequest { now_ms: 90_000 }))
            .await
            .unwrap()
            .into_inner()
            .runs;
        assert_eq!(ticked.len(), 1, "{ticked:?}");
        assert_eq!(ticked[0].transform_id, "crash");
    });
}

#[test]
fn sqlite_promoted_transform_rpcs_run_without_the_experimental_gate() {
    exercise(Arc::new(RuntimeDb::memory()));
}

#[test]
fn sqlite_two_planes_tick_a_due_bucket_once_through_tick() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!(
        "sekai-2414-{}-{}.db",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let open = || {
        Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(path.to_str().unwrap()).unwrap(),
        )))
    };
    two_planes_tick_once(open(), open());
}

#[test]
fn sqlite_uncommitted_schedule_cursor_leaves_the_bucket_due() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!(
        "sekai-2414-crash-{}-{}.db",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    uncommitted_cursor_leaves_bucket_due_sqlite(&path);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_promoted_transform_rpcs_run_without_the_experimental_gate() {
    let scratch = ScratchDatabase::create();
    exercise(Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect(8)))));
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_two_planes_tick_a_due_bucket_once_through_tick() {
    let scratch = ScratchDatabase::create();
    let a = Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect(8))));
    let b = Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect(8))));
    two_planes_tick_once(a, b);
}

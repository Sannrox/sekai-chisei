//! A row-wise model step of a governed transform (#3025): the connector
//! runtime runs the prompt over each row through a policy-mode gateway, the
//! plane commits only typed output, and the gateway's own policy decides
//! every call. The model is a fake upstream on an ephemeral port that
//! replies with the text after `Score `.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::routing::post;
use chisei_gateway::gateway::GatewayConfig;
use chisei_gateway::gateway::test_support::{self, TestRuntime};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
use sekai_chisei::grpc::pb::sekai::{
    GetGovernedTransformRunRequest, GovernedTransform, PreviewGovernedTransformRequest,
    PutGovernedTransformRequest, RunGovernedTransformRequest, TransformLlmStep,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::rpc_maturity::RpcMaturityLayer;
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset};
use sekai_chisei::sekai::security::Role;
use sekai_client::ClientConfig;
use sekai_client::claim::{ClaimAttempt, TransformFence, TransformWrite};
use sekai_client::protocol::sekai::TransformRunInputRow;
use sekai_connector_runtime::llm_rows::{GatewayRoute, NO_GATEWAY_ROUTE};
use sekai_connector_runtime::{Connectors, CredentialBindings, Ran, Runtime, RuntimeOptions};
use sekai_domain::gateway_keys::hash_gateway_key;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::Layer;

const NS: &str = "ops";
const PRINCIPAL: &str = "local";
const STEP_KEY: &str = "sk-transform-step";
const READER_KEY: &str = "sk-log-reader";
const MODEL: &str = "gpt-5.5";

/// The serving plane and its store.
struct Plane {
    db: Arc<RuntimeDb>,
    endpoint: String,
}

async fn plane() -> Plane {
    plane_over(RuntimeDb::memory()).await
}

async fn plane_over(db: RuntimeDb) -> Plane {
    let db = Arc::new(db);
    db.ensure_team_namespace(NS, PRINCIPAL, Role::Admin, PRINCIPAL)
        .unwrap();
    for id in ["reviews", "scores"] {
        db.create_dataset(&Dataset {
            id: id.into(),
            name: id.into(),
            columns: vec![ColumnDef {
                name: "text".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    }
    let service = RpcMaturityLayer::new(true).layer(SekaiServiceServer::new(
        SekaiServiceImpl::new(SekaiStore::from_shared_runtime(db.clone())),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    Plane { db, endpoint }
}

impl Plane {
    fn seed(&self, texts: &[&str]) {
        let rows: Vec<HashMap<String, String>> = texts
            .iter()
            .map(|text| HashMap::from([("text".to_string(), text.to_string())]))
            .collect();
        match self.db.as_ref() {
            RuntimeDb::Postgres(pg) => tokio::task::block_in_place(|| {
                pg.append_dataset_rows("reviews", &rows).unwrap();
            }),
            db => {
                db.append_rows("reviews", &rows).unwrap();
            }
        }
    }

    async fn sekai(&self) -> SekaiServiceClient<tonic::transport::Channel> {
        let mut client = SekaiServiceClient::connect(self.endpoint.clone())
            .await
            .unwrap();
        client = client.max_decoding_message_size(usize::MAX);
        client
    }

    async fn runtime(&self, labels: BTreeMap<String, String>) -> Runtime {
        Runtime::connect(
            ClientConfig::new(&self.endpoint, PRINCIPAL)
                .with_default_timeout(Duration::from_secs(5)),
            &[NS.to_string()],
            RuntimeOptions {
                runtime_id: "runner".into(),
                labels,
                lease: Duration::from_secs(30),
            },
            CredentialBindings::default(),
            Connectors::default(),
        )
        .await
        .unwrap()
    }
}

fn principal_request<T>(message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request
        .metadata_mut()
        .insert("x-principal", PRINCIPAL.parse().unwrap());
    request
}

fn definition(transform_id: &str) -> GovernedTransform {
    GovernedTransform {
        contract_version: "sekai.governed-transform/v1".into(),
        namespace: NS.into(),
        transform_id: transform_id.into(),
        input_dataset_id: "reviews".into(),
        output_dataset_id: "scores".into(),
        profile: "isolated_process".into(),
        engine: "llm-rows".into(),
        runtime_image: "connector-runtime".into(),
        code: "Score {text}".into(),
        llm_step: Some(TransformLlmStep {
            model: MODEL.into(),
            output_column: "score".into(),
            output_type: "integer".into(),
        }),
        ..Default::default()
    }
}

/// Replies to each chat completion with the text after `Score ` in its
/// last message, and counts the requests it receives.
async fn fake_model() -> (String, Arc<Mutex<usize>>) {
    let calls = Arc::new(Mutex::new(0));
    let counted = calls.clone();
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        post(move |Json(body): Json<Value>| {
            let counted = counted.clone();
            async move {
                *counted.lock().unwrap() += 1;
                let prompt = body["messages"][0]["content"].as_str().unwrap_or_default();
                let reply = prompt.strip_prefix("Score ").unwrap_or(prompt);
                Json(json!({
                    "id": "chatcmpl-step",
                    "object": "chat.completion",
                    "model": MODEL,
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
                }))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, calls)
}

/// A policy-mode gateway in front of `upstream`. The `transforms` principal
/// may reach `models`; the `chisei` principal reads the egress log.
async fn gateway(upstream: String, models: &[&str], dir: &std::path::Path) -> String {
    let policy_path = dir.join("policy.json");
    let policy = json!({
        "format": test_support::POLICY_FORMAT,
        "generation": 1,
        "principals": [
            {
                "name": "transforms",
                "key_sha256": [hash_gateway_key(STEP_KEY)],
                "routes": [{"provider": "openai", "models": models}],
            },
            {
                "name": "chisei",
                "key_sha256": [hash_gateway_key(READER_KEY)],
                "routes": [{"provider": "openai", "models": [MODEL]}],
                "log_reader": true,
            }
        ],
        "egress": [{"provider": "openai", "data_classes": ["unknown"]}],
    });
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let config = GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream,
        openai_api_key: Some("real-openai-key".into()),
        anthropic_base_url: "http://127.0.0.1:9/v1".into(),
        anthropic_api_key: None,
        ollama_base_url: "http://127.0.0.1:9/v1".into(),
        native_base_url: None,
        chisei_grpc_target: None,
        default_project: "default".into(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    };
    let runtime = TestRuntime::new(test_support::DEFAULT_KEY_CACHE_TTL)
        .with_recovery_spool_path(dir.join("recovery.jsonl"))
        .with_policy(policy_path, &dir.join("log"))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, test_support::app(config, runtime))
            .await
            .unwrap()
    });
    base
}

/// The gateway's admission records, by the operation id each names.
async fn admissions(gateway: &str) -> Vec<Value> {
    let page: Value = reqwest::Client::new()
        .get(format!("{gateway}/_chisei/log?after=0"))
        .bearer_auth(READER_KEY)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    page["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["kind"] == "admission")
        .cloned()
        .collect()
}

fn route(gateway: &str) -> GatewayRoute {
    GatewayRoute {
        base_url: format!("{gateway}/v1"),
        key: STEP_KEY.into(),
    }
}

async fn run_once(plane: &Plane, transform_id: &str) -> String {
    let mut sekai = plane.sekai().await;
    sekai
        .put_governed_transform(principal_request(PutGovernedTransformRequest {
            transform: Some(definition(transform_id)),
        }))
        .await
        .unwrap();
    sekai
        .run_governed_transform(principal_request(RunGovernedTransformRequest {
            namespace: NS.into(),
            transform_id: transform_id.into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap()
        .run_id
}

async fn stored_run(plane: &Plane, run_id: &str) -> sekai_chisei::grpc::pb::sekai::TransformRun {
    plane
        .sekai()
        .await
        .get_governed_transform_run(principal_request(GetGovernedTransformRunRequest {
            run_id: run_id.into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .run
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_preview_scores_sample_rows_through_the_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let plane = plane().await;
    plane.seed(&["3", "5"]);
    let (upstream, calls) = fake_model().await;
    let gateway = gateway(upstream, &[MODEL], dir.path()).await;
    let runtime = plane
        .runtime(BTreeMap::new())
        .await
        .with_gateway(route(&gateway));
    runtime.register().await.unwrap();

    let mut sekai = plane.sekai().await;
    let preview = |preview_id: String| PreviewGovernedTransformRequest {
        transform: Some(definition("score-preview")),
        preview_id,
        ..Default::default()
    };
    let started = sekai
        .preview_governed_transform(principal_request(preview(String::new())))
        .await
        .unwrap()
        .into_inner();
    let ran = runtime.pass().await.unwrap();
    assert!(
        matches!(
            &ran[..],
            [Ran::Transformed {
                outcome: Ok(()),
                ..
            }]
        ),
        "{ran:?}"
    );
    let done = sekai
        .preview_governed_transform(principal_request(preview(started.preview_id.clone())))
        .await
        .unwrap()
        .into_inner();
    assert!(done.error.is_empty(), "{done:?}");
    let mut scores: Vec<&str> = done
        .rows
        .iter()
        .map(|row| row.values["score"].as_str())
        .collect();
    scores.sort_unstable();
    assert_eq!(scores, ["3", "5"]);

    // Every call left through the gateway, with its own admission record
    // naming the transforms principal and the preview it ran for.
    assert_eq!(*calls.lock().unwrap(), 2);
    let admitted = admissions(&gateway).await;
    assert_eq!(admitted.len(), 2, "{admitted:?}");
    for record in &admitted {
        assert_eq!(record["principal"], "transforms");
        // The gateway scopes the supplied operation id to its principal.
        let operation = record["operation_id"].as_str().unwrap();
        assert!(operation.ends_with(&started.preview_id), "{operation}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reply_that_is_not_the_declared_type_quarantines_the_run_naming_the_row() {
    quarantines_a_reply_of_the_wrong_type(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_a_reply_that_is_not_the_declared_type_quarantines_the_run_naming_the_row() {
    on_postgres(quarantines_a_reply_of_the_wrong_type);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_plane_quarantines_written_rows_that_are_not_the_declared_type() {
    quarantines_written_rows_of_the_wrong_type(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_the_plane_quarantines_written_rows_that_are_not_the_declared_type() {
    on_postgres(quarantines_written_rows_of_the_wrong_type);
}

/// Runs `exercise` against a scratch PostgreSQL database of its own.
fn on_postgres<F: std::future::Future<Output = ()>>(exercise: impl FnOnce(RuntimeDb) -> F) {
    let scratch = crate::postgres_scratch::ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(4)));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(exercise(db.clone()));
    // The plane task holds a handle; the last one must drop outside the
    // runtime, since the blocking driver cannot shut down on a worker.
    drop(runtime);
    drop(db);
}

async fn quarantines_a_reply_of_the_wrong_type(db: RuntimeDb) {
    let dir = tempfile::tempdir().unwrap();
    let plane = plane_over(db).await;
    plane.seed(&["3", "seven"]);
    let (upstream, _) = fake_model().await;
    let gateway = gateway(upstream, &[MODEL], dir.path()).await;
    let runtime = plane
        .runtime(BTreeMap::new())
        .await
        .with_gateway(route(&gateway));
    runtime.register().await.unwrap();

    let run_id = run_once(&plane, "score-strict").await;
    runtime.pass().await.unwrap();
    let run = stored_run(&plane, &run_id).await;
    assert!(run.quarantined, "{run:?}");
    assert_eq!(run.rows_out, 0);
    assert_eq!(
        run.quality_rule,
        "llm_output_type: row 2: score is not integer"
    );
}

async fn quarantines_written_rows_of_the_wrong_type(db: RuntimeDb) {
    let plane = plane_over(db).await;
    plane.seed(&["3"]);
    let run_id = run_once(&plane, "score-checked").await;
    let client = sekai_client::CoreLoopClient::connect(
        ClientConfig::new(&plane.endpoint, PRINCIPAL)
            .with_namespace(NS)
            .with_default_timeout(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    let claims = client.runtime_claim();
    claims
        .register_transform_runtime("writer", [("sekai.step.llm", "v1")])
        .await
        .unwrap();
    let ClaimAttempt::Claimed(claimed) = claims
        .claim_transform_work("writer", &run_id, Duration::from_secs(30))
        .await
        .unwrap()
    else {
        panic!("expected the run to be claimable");
    };
    let fence = TransformFence::from_work(&claimed.work.unwrap(), "writer");
    let rows = vec![HashMap::from([
        ("text".to_string(), "3".to_string()),
        ("score".to_string(), "three".to_string()),
    ])];
    claims
        .write_transform_result(
            &fence,
            TransformWrite {
                output_digest: sekai_chisei::sekai::governed_transform::rows_digest(&rows),
                rows: rows
                    .into_iter()
                    .map(|values| TransformRunInputRow {
                        values,
                        ..Default::default()
                    })
                    .collect(),
                quarantined: false,
                quality_rule: String::new(),
                partitions: Vec::new(),
                model_outputs: Vec::new(),
            },
        )
        .await
        .unwrap();
    let run = stored_run(&plane, &run_id).await;
    assert!(run.quarantined, "{run:?}");
    assert_eq!(
        run.quality_rule,
        "llm_output_type: output row 0: score is not integer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runtime_with_no_gateway_route_refuses_the_step_before_any_call() {
    let plane = plane().await;
    plane.seed(&["3"]);
    let (_, calls) = fake_model().await;
    // Labelled for model steps by hand, but given no route.
    let runtime = plane
        .runtime(BTreeMap::from([("sekai.step.llm".into(), "v1".into())]))
        .await;
    runtime.register().await.unwrap();

    let run_id = run_once(&plane, "score-unrouted").await;
    let ran = runtime.pass().await.unwrap();
    assert!(
        matches!(&ran[..], [Ran::Transformed { outcome: Err(code), .. }] if code == NO_GATEWAY_ROUTE),
        "{ran:?}"
    );
    assert_eq!(*calls.lock().unwrap(), 0);
    let run = stored_run(&plane, &run_id).await;
    assert_eq!(run.rows_out, 0, "{run:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_policy_decides_the_steps_calls() {
    let dir = tempfile::tempdir().unwrap();
    let plane = plane().await;
    plane.seed(&["3"]);
    let (upstream, calls) = fake_model().await;
    // The transforms principal may reach another model only.
    let gateway = gateway(upstream, &["gpt-5.5-mini"], dir.path()).await;
    let runtime = plane
        .runtime(BTreeMap::new())
        .await
        .with_gateway(route(&gateway));
    runtime.register().await.unwrap();

    run_once(&plane, "score-denied").await;
    let ran = runtime.pass().await.unwrap();
    assert!(
        matches!(&ran[..], [Ran::Transformed { outcome: Err(code), .. }] if code == "gateway_refused"),
        "{ran:?}"
    );
    assert_eq!(*calls.lock().unwrap(), 0, "the provider is never reached");
}

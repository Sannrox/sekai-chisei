//! Gateway proxy tests that need a running in-process control plane.
//!
//! Only the root crate builds the Sekai and Chisei gRPC services, so these
//! tests live here; the gateway's own unit tests stay in
//! `crates/chisei-gateway` and no longer rebuild on root edits (#2590).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::header::{ACCEPT_ENCODING, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, Request, Response, StatusCode, Uri};
use axum::routing::any;
use chisei_gateway::gateway::test_support::{
    DEFAULT_GATEWAY_TIER, DEFAULT_KEY_CACHE_TTL, DEFAULT_MAX_REQUEST_BYTES, TestRuntime, X_API_KEY,
    X_CHISEI_AGENT, X_CHISEI_DATA_CLASS, X_CHISEI_OPERATION_ID, X_CHISEI_PROJECT,
    X_CHISEI_RETRY_SAFETY,
};
use chisei_gateway::gateway::{GatewayConfig, GatewayIdentity, ModelPricing};
use chisei_gateway::llm::HttpTimeouts;
use chisei_gateway::provider_profile::CAPABILITY_MATRIX_VERSION;
use sekai_admin_client::client::connect_sekai;
use sekai_chisei::chisei::eval::{
    Case as InternalEvalCase, CaseResult as InternalCaseResult, EvalStore, Run as InternalEvalRun,
    Suite as InternalEvalSuite,
};
use sekai_chisei::chisei_store::ChiseiRuntimeDb;
use sekai_chisei::config::Config;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::dataset::RowQuery;
use sekai_domain::gateway_keys::hash_gateway_key;
use sekai_proto::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_proto::chisei::chisei_service_server::ChiseiServiceServer;
use sekai_proto::chisei::{
    DecideGatewayExecutionRequest, GetEffectivePolicySummaryRequest, SetBudgetLimitRequest,
    SetNamespacePolicyRequest,
};
use sekai_proto::sekai::sekai_service_server::SekaiServiceServer;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request as GrpcRequest;
use tonic::transport::Server;

const DEFAULT_CONTEXT_ADMISSION_POLICY_JSON: &str = r#"{"contract_version":"chisei.context-admission/v1","default_action":"include","unknown_action":"hold_out","rules":[]}"#;

fn routing_config() -> GatewayConfig {
    GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "https://openai.example/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: "https://anthropic.example".to_string(),
        anthropic_api_key: None,
        ollama_base_url: "http://localhost:11434/v1".to_string(),
        native_base_url: Some("http://localhost:9999/v1".to_string()),
        chisei_grpc_target: None,
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    }
}

#[tokio::test]
async fn gateway_health_and_readiness_reflect_governance_availability() {
    let (upstream_base, _) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let mut unavailable_config = routing_config();
    unavailable_config.openai_base_url = upstream_base.clone();
    unavailable_config.chisei_grpc_target = None;
    let gateway_base = spawn_gateway_with_config(unavailable_config).await;
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("{gateway_base}/healthz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{gateway_base}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let (target, _) = spawn_control_plane().await;
    let mut config = routing_config();
    config.openai_base_url = upstream_base;
    config.chisei_grpc_target = Some(target);
    let ready_gateway = spawn_gateway_with_config(config).await;
    assert_eq!(
        client
            .get(format!("{ready_gateway}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[derive(Debug, Clone)]
struct RecordedRequest {
    path: String,
    query: Option<String>,
    authorization: Option<String>,
    x_api_key: Option<String>,
    chisei_agent: Option<String>,
    accept_encoding: Option<String>,
    body: String,
}

#[derive(Clone)]
struct FakeUpstreamState {
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    response_body: &'static str,
    content_type: &'static str,
    status: StatusCode,
    delay: Option<Duration>,
}

async fn fake_upstream(
    State(state): State<FakeUpstreamState>,
    uri: Uri,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response<Body> {
    let body = to_bytes(request.into_body(), DEFAULT_MAX_REQUEST_BYTES)
        .await
        .unwrap();
    state.requests.lock().unwrap().push(RecordedRequest {
        path: uri.path().to_string(),
        query: uri.query().map(str::to_string),
        authorization: headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        x_api_key: headers
            .get(X_API_KEY)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        chisei_agent: headers
            .get(X_CHISEI_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        accept_encoding: headers
            .get(ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        body: String::from_utf8(body.to_vec()).unwrap(),
    });
    if let Some(delay) = state.delay {
        tokio::time::sleep(delay).await;
    }

    let mut builder = Response::builder().status(state.status);
    if !state.content_type.is_empty() {
        builder = builder.header(axum::http::header::CONTENT_TYPE, state.content_type);
    }
    builder.body(Body::from(state.response_body)).unwrap()
}

async fn spawn_fake_upstream(
    response_body: &'static str,
    content_type: &'static str,
) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
    spawn_fake_upstream_with_delay(response_body, content_type, None).await
}

/// Serves an Ollama `/api/tags` listing so the control-plane resolver can
/// validate an `ollama/<model>` without a live Ollama server (otherwise
/// resolution is environment-dependent: it passes only where Ollama runs).
async fn spawn_fake_ollama_tags(model: &str) -> String {
    let body = format!(r#"{{"models":[{{"name":"{model}"}}]}}"#);
    let app = Router::new().route(
        "/api/tags",
        any(move || {
            let body = body.clone();
            async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn spawn_fake_upstream_with_delay(
    response_body: &'static str,
    content_type: &'static str,
    delay: Option<Duration>,
) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
    spawn_fake_upstream_with_status(response_body, content_type, StatusCode::OK, delay).await
}

async fn spawn_fake_upstream_with_status(
    response_body: &'static str,
    content_type: &'static str,
    status: StatusCode,
    delay: Option<Duration>,
) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = FakeUpstreamState {
        requests: requests.clone(),
        response_body,
        content_type,
        status,
        delay,
    };
    let app = Router::new()
        .route("/{*path}", any(fake_upstream))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/v1"), requests)
}

/// Streams `chunks` as separate body frames with `delay` between them and
/// no Content-Type header, like the ChatGPT Codex backend.
async fn spawn_fake_chunked_upstream(chunks: &'static [&'static str], delay: Duration) -> String {
    let handler = move || async move {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::convert::Infallible>>(1);
        tokio::spawn(async move {
            for (index, chunk) in chunks.iter().enumerate() {
                if index > 0 {
                    tokio::time::sleep(delay).await;
                }
                if tx.send(Ok(chunk.to_string())).await.is_err() {
                    return;
                }
            }
        });
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from_stream(ReceiverStream::new(rx)))
            .unwrap()
    };
    let app = Router::new().route("/{*path}", any(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/v1")
}

async fn spawn_fake_terminal_then_error_upstream() -> String {
    let handler = || async {
        let terminal = Bytes::from_static(
            b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n",
        );
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            tx.send(Ok::<_, std::io::Error>(terminal)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "reset after terminal",
                )))
                .await;
        });
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(ReceiverStream::new(rx)))
            .unwrap()
    };
    let app = Router::new().route("/{*path}", any(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/v1")
}

/// Usage recording for streamed responses happens in a background task
/// after the last chunk is delivered, so poll instead of asserting once.
async fn wait_for_llm_calls(db: &RuntimeDb, count: usize) -> Vec<HashMap<String, String>> {
    for _ in 0..100 {
        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        if rows.len() >= count {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    db.query_rows("llm_calls", &RowQuery::default()).unwrap()
}

async fn spawn_gateway(openai_base_url: String) -> String {
    spawn_gateway_with_preflight(openai_base_url).await
}

async fn spawn_gateway_with_preflight(openai_base_url: String) -> String {
    let (chisei_target, _) = spawn_control_plane().await;
    let config = GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::from([(
            "sk-chisei-codex-app".to_string(),
            GatewayIdentity {
                agent: "codex-app".to_string(),
                project: "default".to_string(),
                user_id: "agent:codex-app".to_string(),
                key_id: "codex-app".to_string(),
                tier: "low-risk".to_string(),
            },
        )]),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    };
    spawn_gateway_with_config(config).await
}

async fn spawn_gateway_with_timeouts(
    openai_base_url: String,
    http_timeouts: HttpTimeouts,
) -> String {
    let (chisei_target, _) = spawn_control_plane().await;
    let config = GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::from([(
            "sk-chisei-codex-app".to_string(),
            GatewayIdentity {
                agent: "codex-app".to_string(),
                project: "default".to_string(),
                user_id: "agent:codex-app".to_string(),
                key_id: "codex-app".to_string(),
                tier: "low-risk".to_string(),
            },
        )]),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    };
    spawn_gateway_with_runtime(
        config,
        TestRuntime::new(DEFAULT_KEY_CACHE_TTL).with_http_timeouts(http_timeouts),
    )
    .await
}

async fn spawn_gateway_with_config(config: GatewayConfig) -> String {
    spawn_gateway_with_runtime(config, test_gateway_runtime()).await
}

/// Serve the gateway over `runtime` with a recovery spool of its own, so
/// parallel tests never share one.
async fn spawn_gateway_with_runtime(config: GatewayConfig, runtime: TestRuntime) -> String {
    let runtime = runtime.with_recovery_spool_path(std::env::temp_dir().join(format!(
        "chisei-gateway-recovery-{}.jsonl",
        uuid::Uuid::new_v4()
    )));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            chisei_gateway::gateway::test_support::app(config, runtime),
        )
        .await
        .unwrap();
    });
    format!("http://{addr}")
}

fn test_gateway_runtime() -> TestRuntime {
    TestRuntime::new(DEFAULT_KEY_CACHE_TTL).with_control_plane_retries(
        4,
        Duration::from_millis(50),
        Duration::from_secs(10),
    )
}

fn short_http_timeouts() -> HttpTimeouts {
    HttpTimeouts {
        connect_timeout: Duration::from_secs(1),
        read_timeout: Duration::from_millis(50),
        pool_idle_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(5),
    }
}

fn test_config() -> Config {
    Config {
        grpc_port: 0,
        sekai_bind: None,
        ops_port: None,
        ops_bind: "127.0.0.1".into(),
        http_port: None,
        http_bind: "127.0.0.1".into(),
        sekai_socket: None,
        db_path: ":memory:".into(),
        anthropic_api_key: Some("test-anthropic-key".into()),
        openai_api_key: Some("test-openai-key".into()),
        ollama_url: "http://127.0.0.1:11434".into(),
        native_llm_url: None,
        sample_rate: 0.0,
        sample_risk_threshold: 0.7,
        scoring_enabled: false,
        scoring_interval_secs: 60,
        scoring_model: "claude-opus-4-8".into(),
        scoring_batch_size: 16,
        default_data_class: "unclassified".into(),
        safe_egress_providers: vec![],
        gateway_provided_providers: vec![],
        gateway_key: None,
        gateway_url: sekai_chisei::config::DEFAULT_GATEWAY_URL.into(),
        routing_endpoint_allowlist: vec![],
        routing_credential_refs: vec![],
        gateway_receipt_principals: vec![],
        leak_review_model: None,
        tls_cert: None,
        tls_key: None,
        allow_plaintext: false,
        insecure: false,
        permit_signing_key: None,
        permit_issuer: "chisei.local".into(),
        permit_key_id: "permit-key-1".into(),
        governed_subject_provenance_signing_key: None,
        governed_subject_provenance_key_not_before_ms: 0,
        governed_subject_provenance_key_expires_at_ms: i64::MAX,
        governed_subject_provenance_ttl_ms: 24 * 60 * 60 * 1_000,
        site_id: "local".into(),
        budget_topology: Default::default(),
        assertion_issuer: None,
        assertion_audience: None,
        assertion_hmac_key: None,
        sekai_endpoint: None,
        actor_chain_enforcement: false,
        principal_requests_per_minute: 60,
        agent_requests_per_minute: 60,
    }
}

async fn spawn_control_plane() -> (String, Arc<RuntimeDb>) {
    spawn_control_plane_with_config(test_config()).await
}

async fn spawn_control_plane_with_config(config: Config) -> (String, Arc<RuntimeDb>) {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    for (agent, project, secret) in [
        ("codex-app", "default", "sk-chisei-codex-app"),
        ("claude-code", "default", "sk-chisei-claude-code"),
        (
            "codex-app",
            "sekai-chisei",
            "sk-chisei-codex-app-sekai-chisei",
        ),
    ] {
        let _ = db.create_object(&sekai_chisei::domain::Object {
            id: format!("gateway-key-{agent}-{project}"),
            kind: "gateway_key".to_string(),
            name: agent.to_string(),
            namespace: project.to_string(),
            external_id: format!("gateway_key:{agent}:{project}"),
            properties: HashMap::from([
                ("agent".to_string(), agent.to_string()),
                ("project".to_string(), project.to_string()),
                ("status".to_string(), "active".to_string()),
                ("key_hash".to_string(), hash_gateway_key(secret)),
            ]),
            created: 0,
            updated: 0,
        });
    }

    spawn_control_plane_from_db(config, db).await
}

async fn spawn_control_plane_from_db(
    config: Config,
    db: Arc<RuntimeDb>,
) -> (String, Arc<RuntimeDb>) {
    let sekai_store = sekai_chisei::db::store::SekaiStore::from_shared_runtime(db.clone());
    let sekai_svc = SekaiServiceImpl::new(sekai_store.clone());
    let chisei_store = sekai_chisei::chisei_store::ChiseiStore::from_shared_runtime(db.clone());
    let _ = sekai_chisei::chisei::model_review::enable_registry_provider_families(&chisei_store);
    let chisei_svc = ChiseiServiceImpl::new(chisei_store, config)
        .with_sekai_facts(sekai_chisei::chisei::sekai_facts::SekaiFacts::in_process(
            sekai_store,
        ))
        .unwrap();
    chisei_svc.seed_allow_by_default_context_admission(&["default", "sekai-chisei"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(SekaiServiceServer::new(sekai_svc))
            .add_service(ChiseiServiceServer::new(chisei_svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Wait until the spawned gRPC server actually serves an RPC before
    // returning. Otherwise a fail-closed gateway started next can race the
    // server's readiness and 503 on its first policy projection (flaky under
    // CI parallelism). Any served response — success or an application-level
    // status — proves the server is accepting requests; only transport-level
    // errors mean not-ready-yet.
    let target = format!("http://{addr}");
    for _ in 0..250 {
        if let Ok(channel) = connect_sekai(&target).await {
            let served = ChiseiServiceClient::new(channel)
                .get_effective_policy_summary(GrpcRequest::new(GetEffectivePolicySummaryRequest {
                    namespace: "__readiness_probe__".to_string(),
                    provider: String::new(),
                }))
                .await
                .map(|_| true)
                .unwrap_or_else(|status| {
                    !matches!(
                        status.code(),
                        tonic::Code::Unavailable | tonic::Code::Unknown
                    )
                });
            if served {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    (target, db)
}

async fn seed_regressed_namespace(target: &str, db: &Arc<RuntimeDb>, namespace: &str) {
    let channel = connect_sekai(target).await.unwrap();
    let mut chisei = ChiseiServiceClient::new(channel);
    chisei
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: namespace.to_string(),
            allowed_runtimes: vec!["openai".to_string()],
            allowed_models: vec!["gpt-5.5".to_string(), "gpt-5.5-mini".to_string()],
            default_runtime: "openai".to_string(),
            default_model: "gpt-5.5".to_string(),
            data_class: String::new(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
            impact_route_policy_json: String::new(),
        }))
        .await
        .unwrap();
    let eval = EvalStore::with_db(
        sekai_chisei::chisei_store::ChiseiStore::from_shared_runtime(db.clone()),
    );
    eval.put_suite(InternalEvalSuite {
        id: "gateway-suite".to_string(),
        name: "Gateway suite".to_string(),
        description: String::new(),
        cases: vec![InternalEvalCase {
            id: "case-1".to_string(),
            name: "case".to_string(),
            namespace: namespace.to_string(),
            spec: "spec".to_string(),
            assertions: vec![],
        }],
    })
    .unwrap();
    for (id, score, timestamp) in [("run-1", 92, 100), ("run-2", 60, 200)] {
        eval.put_run(InternalEvalRun {
            id: id.to_string(),
            suite_id: "gateway-suite".to_string(),
            config_ref: "gpt-5.5".to_string(),
            results: vec![InternalCaseResult {
                case_id: "case-1".to_string(),
                passed: score >= 80,
                status: if score >= 80 { "done" } else { "failed" }.to_string(),
                result: "result".to_string(),
                score,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp,
        })
        .unwrap();
        eval.track_iteration("gateway-suite", id, namespace, &format!("hash-{id}"))
            .unwrap();
    }
}

#[tokio::test]
async fn responses_proxy_forwards_body_query_and_rewrites_auth() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","object":"response","status":"completed"}"#,
        "application/json",
    )
    .await;
    let gateway_base = spawn_gateway(upstream_base).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{gateway_base}/v1/responses?trace=1"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .header("x-codex-test", "yes")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.text().await.unwrap(),
        r#"{"id":"resp_1","object":"response","status":"completed"}"#
    );

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/responses");
    assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert!(requests[0].body.contains(r#""model":"gpt-5.5""#));
}

#[tokio::test]
async fn invalid_models_do_not_consume_request_aliases() {
    let (chisei_target, db) = spawn_control_plane().await;
    let mut config = routing_config();
    config.chisei_grpc_target = Some(chisei_target);
    let gateway_base = spawn_gateway_with_config(config).await;
    let client = reqwest::Client::new();
    let send = || {
        client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-request-id", "early-refusal-attempt")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .json(&serde_json::json!({
                "model": "unknown/provider-model",
                "input": "hello"
            }))
    };

    let first = send().send().await.unwrap();
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    assert!(
        db.find_operation_receipt_by_lookup_request_id("early-refusal-attempt", None, None)
            .unwrap()
            .is_none()
    );
    let second = send().send().await.unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pre_dispatch_refusals_do_not_strand_request_aliases() {
    let (chisei_target, db) = spawn_control_plane().await;
    let mut config = routing_config();
    config.chisei_grpc_target = Some(chisei_target);
    let gateway_base = spawn_gateway_with_config(config).await;
    let client = reqwest::Client::new();
    let send = || {
        client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-request-id", "pre-dispatch-refusal")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "input": "hello",
                "chisei_context": {
                    "objects": [{"ref": "ticker:AAPL", "fields": ["score"]}]
                }
            }))
    };

    for _ in 0..2 {
        let response = send().send().await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_ne!(response.status(), StatusCode::CONFLICT);
    }
    assert!(
        db.find_operation_receipt_by_lookup_request_id("pre-dispatch-refusal", None, None)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn missing_provider_credentials_do_not_strand_request_aliases() {
    let (chisei_target, _db) = spawn_control_plane().await;
    let mut config = routing_config();
    config.chisei_grpc_target = Some(chisei_target);
    config.openai_api_key = None;
    config.rewrite_openai_passthrough_auth = true;
    let gateway_base = spawn_gateway_with_config(config).await;
    let client = reqwest::Client::new();
    let send = || {
        client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-request-id", "missing-provider-credential")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .json(&serde_json::json!({
                "model": "openai/gpt-5.5",
                "input": "hello"
            }))
    };

    for _ in 0..2 {
        let response = send().send().await.unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_ne!(status, StatusCode::CONFLICT, "{body}");
    }
}

#[tokio::test]
async fn upstream_timeout_returns_gateway_error() {
    let (upstream_base, _requests) = spawn_fake_upstream_with_delay(
        r#"{"id":"resp_1","object":"response","status":"completed"}"#,
        "application/json",
        Some(Duration::from_millis(200)),
    )
    .await;
    let gateway_base = spawn_gateway_with_timeouts(upstream_base, short_http_timeouts()).await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let body = resp.text().await.unwrap();
    assert!(body.contains("upstream_error"), "{body}");
    assert!(body.contains("timed out"), "{body}");
}

#[tokio::test]
async fn responses_proxy_preserves_sse_body() {
    let sse = "event: response.created\n\
               data: {\"type\":\"response.created\"}\n\n\
               event: response.completed\n\
               data: {\"type\":\"response.completed\"}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let gateway_base = spawn_gateway(upstream_base).await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello",
            "stream": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(resp.text().await.unwrap(), sse);
}

#[tokio::test]
async fn received_terminal_is_preserved_after_transport_error() {
    let upstream_base = spawn_fake_terminal_then_error_upstream().await;
    let gateway_base = spawn_gateway(upstream_base).await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello",
            "stream": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("response.completed"), "{body}");
    assert!(!body.contains("chisei.response.interrupted"), "{body}");
}

#[tokio::test]
async fn models_proxy_forwards_to_openai_upstream() {
    let upstream_body = r#"{"object":"list","data":[{"id":"gpt-5.5","object":"model"}]}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .get(format!("{gateway_base}/v1/models?client_version=0.141.0"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .header("x-chisei-action-risk", "low")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = reqwest::Client::new()
        .get(format!("{gateway_base}/v1/models?client_version=0.141.0"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let response_body = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{response_body}");
    assert_eq!(response_body, upstream_body);

    let detail = reqwest::Client::new()
        .get(format!("{gateway_base}/models/gpt-5.5"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .header("x-chisei-action-risk", "low")
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);

    let prefixed_body = reqwest::Client::new()
        .post(format!("{gateway_base}/models-export"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({"input": "classified"}))
        .send()
        .await
        .unwrap();
    assert_eq!(prefixed_body.status(), StatusCode::NOT_FOUND);

    let metadata_body = reqwest::Client::new()
        .get(format!("{gateway_base}/models/gpt-5.5"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .header("x-chisei-action-risk", "low")
        .body("classified")
        .send()
        .await
        .unwrap();
    assert_eq!(metadata_body.status(), StatusCode::FORBIDDEN);

    // A models suffix that the provider could resolve to another endpoint never
    // leaves the gateway with its credential.
    for path in ["/v1/models/%2e%2e%2ffiles", "/v1/models/gpt-5.5/files"] {
        let escaped = reqwest::Client::new()
            .get(format!("{gateway_base}{path}"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .send()
            .await
            .unwrap();
        assert_eq!(escaped.status(), StatusCode::NOT_FOUND, "{path}");
    }

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/v1/models");
    assert_eq!(requests[0].query.as_deref(), Some("client_version=0.141.0"));
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert_eq!(requests[1].path, "/v1/models/gpt-5.5");
}

#[tokio::test]
async fn anthropic_models_proxy_uses_anthropic_path_and_api_key() {
    let upstream_body = r#"{"data":[{"id":"claude-sonnet-4-20250514","type":"model"}]}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let response = reqwest::Client::new()
        .get(format!("{gateway_base}/v1/models"))
        .bearer_auth("sk-chisei-codex-app")
        .header("anthropic-version", "2023-06-01")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .send()
        .await
        .unwrap();

    let status = response.status();
    let response_body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{response_body}");
    assert_eq!(response_body, upstream_body);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/models");
    assert_eq!(requests[0].x_api_key.as_deref(), Some("real-anthropic-key"));
    assert_eq!(requests[0].authorization, None);
}

#[tokio::test]
async fn openai_passthrough_preserves_client_auth_and_strips_chisei_headers() {
    let upstream_body = r#"{"id":"resp_1","object":"response","status":"completed"}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: None,
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("native-openai-oauth-token")
        .header(X_CHISEI_AGENT.as_str(), "codex-app")
        .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
        .header(X_CHISEI_DATA_CLASS.as_str(), "unclassified")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer native-openai-oauth-token")
    );
    assert_eq!(requests[0].x_api_key, None);
    assert_eq!(requests[0].chisei_agent, None);
}

#[tokio::test]
async fn openai_passthrough_can_rewrite_upstream_auth_for_codex_local_login() {
    let upstream_body = r#"{"id":"resp_1","object":"response","status":"completed"}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: true,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("codex-local-login-token")
        .header(X_CHISEI_AGENT.as_str(), "codex-app")
        .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
        .header(X_CHISEI_DATA_CLASS.as_str(), "unclassified")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert_eq!(requests[0].x_api_key, None);
    assert_eq!(requests[0].chisei_agent, None);
}

#[tokio::test]
async fn anthropic_passthrough_preserves_client_auth_and_strips_chisei_headers() {
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":8,"output_tokens":6}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("native-claude-oauth-token")
        .header(X_CHISEI_AGENT.as_str(), "claude-code")
        .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
        .header(X_CHISEI_DATA_CLASS.as_str(), "unclassified")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer native-claude-oauth-token")
    );
    assert_eq!(requests[0].x_api_key, None);
    assert_eq!(requests[0].chisei_agent, None);
}

#[tokio::test]
async fn anthropic_messages_proxy_records_usage_and_strips_accept_encoding() {
    // Non-streaming Anthropic shape: usage lands on the llm_calls row, and
    // the gateway must strip the client's Accept-Encoding so the upstream
    // body comes back identity-encoded (parseable) rather than compressed.
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":8,"output_tokens":6}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: "default".to_string(),
            allowed_runtimes: vec!["anthropic".to_string()],
            allowed_models: vec!["claude-sonnet-4-6".to_string()],
            default_runtime: "anthropic".to_string(),
            default_model: "claude-sonnet-4-6".to_string(),
            data_class: "open".to_string(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
            impact_route_policy_json: String::new(),
        }))
        .await
        .unwrap();
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .header(X_CHISEI_DATA_CLASS.as_str(), "open")
        // Claude Code advertises compression; the gateway must strip it.
        .header(ACCEPT_ENCODING.as_str(), "gzip, deflate, br, zstd")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/messages");
        // Regression: Accept-Encoding must not reach the upstream.
        assert_eq!(requests[0].accept_encoding, None);
    }

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("agent").map(String::as_str),
        Some("claude-code")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("8"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("6"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("14"));
    assert_eq!(rows[0].get("data_class").map(String::as_str), Some("open"));

    let downgraded = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .header(X_CHISEI_DATA_CLASS.as_str(), "sensitive")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "classified"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(downgraded.status(), StatusCode::FORBIDDEN);
    assert_eq!(requests.lock().unwrap().len(), 1);

    let unclassified_body = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .header(X_CHISEI_DATA_CLASS.as_str(), "sensitive")
        .json(&serde_json::json!({
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "classified"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unclassified_body.status(), StatusCode::FORBIDDEN);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn anthropic_messages_streaming_records_usage() {
    // Streaming Anthropic shape (what Claude Code always sends): usage is
    // split across message_start (input_tokens) and message_delta
    // (output_tokens) and folded via merge_usage.
    let sse = "event: message_start\n\
               data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":11,\"output_tokens\":0}}}\n\n\
               event: content_block_delta\n\
               data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n\
               event: message_delta\n\
               data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n\
               event: message_stop\n\
               data: {\"type\":\"message_stop\"}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), sse);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("11"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("7"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("18"));
}

/// Fields of every `gen_ai.client` span whose operation id contains
/// [`GENAI_TEST_OPERATION`], plus the parent span's name.
///
/// Installed once as the process-global subscriber: a thread-scoped one races
/// the global callsite-interest cache against concurrently running tests.
#[derive(Default)]
struct GenAiSpanCapture {
    active: std::collections::HashMap<u64, usize>,
    spans: Vec<Vec<(String, String)>>,
}

const GENAI_TEST_OPERATION: &str = "op-genai-gateway";

struct GenAiSpanLayer(&'static std::sync::Mutex<GenAiSpanCapture>);

#[derive(Default)]
struct FieldList(Vec<(String, String)>);

impl tracing::field::Visit for FieldList {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().into(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push((field.name().into(), value.into()));
    }
}

impl<S> tracing_subscriber::Layer<S> for GenAiSpanLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if attrs.metadata().name() != "gen_ai.client" {
            return;
        }
        let mut fields = FieldList::default();
        attrs.record(&mut fields);
        let ours = fields.0.iter().any(|(key, value)| {
            key == "sekai.operation_id" && value.contains(GENAI_TEST_OPERATION)
        });
        if !ours {
            return;
        }
        let parent = ctx
            .span(id)
            .and_then(|span| span.parent())
            .map(|parent| parent.name().to_string())
            .unwrap_or_default();
        fields.0.push(("parent".into(), parent));
        let mut capture = self.0.lock().unwrap();
        let index = capture.spans.len();
        capture.spans.push(fields.0);
        capture.active.insert(id.into_u64(), index);
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut capture = self.0.lock().unwrap();
        if let Some(&index) = capture.active.get(&id.into_u64()) {
            let mut fields = FieldList::default();
            values.record(&mut fields);
            capture.spans[index].extend(fields.0);
        }
    }

    fn on_close(&self, id: tracing::span::Id, _: tracing_subscriber::layer::Context<'_, S>) {
        // Span ids are reused after close.
        self.0.lock().unwrap().active.remove(&id.into_u64());
    }
}

fn genai_span_capture() -> &'static std::sync::Mutex<GenAiSpanCapture> {
    use tracing_subscriber::layer::SubscriberExt as _;
    static CAPTURE: std::sync::OnceLock<&'static std::sync::Mutex<GenAiSpanCapture>> =
        std::sync::OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture: &'static _ = Box::leak(Box::default());
        tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(GenAiSpanLayer(capture)),
        )
        .expect("no other global subscriber in the gateway test binary");
        capture
    })
}

#[tokio::test]
async fn proxied_model_call_exports_a_content_free_genai_span() {
    let capture = genai_span_capture();
    tracing::callsite::rebuild_interest_cache();

    let sse = "event: message_start\n\
               data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":11,\"output_tokens\":0}}}\n\n\
               event: content_block_delta\n\
               data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"SECRET-COMPLETION\"}}\n\n\
               event: message_delta\n\
               data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n\
               event: message_stop\n\
               data: {\"type\":\"message_stop\"}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .header(X_CHISEI_OPERATION_ID.as_str(), GENAI_TEST_OPERATION)
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "SECRET-PROMPT"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.text().await.unwrap();
    wait_for_llm_calls(&db, 1).await;

    let spans = capture.lock().unwrap().spans.clone();
    assert_eq!(spans.len(), 1, "one span per provider call: {spans:?}");
    let fields = &spans[0];
    let field = |name: &str| -> Vec<&str> {
        fields
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    };
    assert_eq!(field("parent"), ["gateway.http"], "{fields:?}");
    assert_eq!(field("otel.kind"), ["client"]);
    assert_eq!(field("gen_ai.operation.name"), ["chat"]);
    assert_eq!(field("gen_ai.provider.name"), ["anthropic"]);
    assert_eq!(field("gen_ai.request.model"), ["claude-sonnet-4-6"]);
    assert_eq!(field("gen_ai.usage.input_tokens"), ["11"]);
    assert_eq!(field("gen_ai.usage.output_tokens"), ["7"]);
    assert_eq!(field("gen_ai.response.finish_reasons"), ["end_turn"]);
    assert!(field("error.type").is_empty());
    let operation = field("sekai.operation_id");
    assert!(
        operation.len() == 1 && operation[0].contains(GENAI_TEST_OPERATION),
        "{operation:?}"
    );
    assert!(
        fields.iter().all(|(_, value)| !value.contains("SECRET")),
        "content reached span fields: {fields:?}"
    );
}

#[tokio::test]
async fn chat_completions_proxy_records_usage_and_rewrites_auth() {
    let upstream_body = r#"{
        "id":"chatcmpl_1",
        "object":"chat.completion",
        "usage":{"prompt_tokens":9,"completion_tokens":4,"total_tokens":13}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/chat/completions?trace=1"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/chat/completions");
    assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("model").map(String::as_str), Some("gpt-5.5"));
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("9"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("4"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("13"));
}

#[tokio::test]
async fn eval_regression_signal_rewrites_model_and_records_audit() {
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"gateway sampled answer"}]}],
        "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    seed_regressed_namespace(&chisei_target, &db, "default").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5-mini", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(forwarded["model"], "gpt-5.5");
    drop(requests);

    let decisions = db
        .list_decisions(&sekai_chisei::sekai::audit::DecisionFilter {
            action: Some("gateway.eval_regression".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].actor, "chisei-gateway");
    assert_eq!(decisions[0].outcome, "routed");
    assert_eq!(
        decisions[0]
            .evidence
            .get("requested_model")
            .map(String::as_str),
        Some("gpt-5.5-mini")
    );
    assert_eq!(
        decisions[0]
            .evidence
            .get("resolved_model")
            .map(String::as_str),
        Some("gpt-5.5")
    );
    assert_eq!(
        decisions[0].evidence.get("key_id").map(String::as_str),
        Some("codex-app")
    );
    assert_eq!(
        decisions[0].evidence.get("user_id").map(String::as_str),
        Some("agent:codex-app")
    );
}

#[tokio::test]
async fn gateway_key_policy_scope_rewrites_model() {
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"key scoped answer"}]}],
        "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: "gateway_key:codex-app".to_string(),
            allowed_runtimes: vec!["openai".to_string()],
            allowed_models: vec!["gpt-5.5".to_string()],
            default_runtime: "openai".to_string(),
            default_model: "gpt-5.5".to_string(),
            data_class: String::new(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
            impact_route_policy_json: String::new(),
        }))
        .await
        .unwrap();
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5-mini", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(forwarded["model"], "gpt-5.5");
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("key_id").map(String::as_str), Some("codex-app"));
    assert_eq!(
        rows[0].get("resolved_model").map(String::as_str),
        Some("openai/gpt-5.5")
    );

    let decisions = db
        .list_decisions(&sekai_chisei::sekai::audit::DecisionFilter {
            action: Some("gateway.model_rewrite".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0]
            .evidence
            .get("resolved_model")
            .map(String::as_str),
        Some("gpt-5.5")
    );
}

#[tokio::test]
async fn chat_completions_streaming_response_records_usage_after_passthrough() {
    let sse = "data: {\"id\":\"chatcmpl_1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
               data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n\
               data: [DONE]\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/chat/completions"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true,
            "stream_options": {"include_usage": true}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), sse);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("3"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("2"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("5"));
}

#[tokio::test]
async fn anthropic_messages_proxy_records_usage_and_rewrites_x_api_key() {
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":8,"output_tokens":6}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages?trace=1"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/messages");
    assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
    assert_eq!(requests[0].authorization, None);
    assert_eq!(requests[0].x_api_key.as_deref(), Some("real-anthropic-key"));
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("agent").map(String::as_str),
        Some("claude-code")
    );
    assert_eq!(
        rows[0].get("provider").map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(
        rows[0].get("model").map(String::as_str),
        Some("claude-sonnet-4-20250514")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("8"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("6"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("14"));
}

#[tokio::test]
async fn anthropic_cache_creation_and_savings_are_recorded_on_llm_call() {
    // Anthropic reports input_tokens as the uncached count, with cache-read
    // and cache-creation tokens tracked separately.
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":10,"cache_read_input_tokens":100,"cache_creation_input_tokens":20,"output_tokens":5}
    }"#;
    let (upstream_base, _requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    // input 3 usd/1M, output 15 usd/1M, cached 0.3 usd/1M.
    let pricing = HashMap::from([(
        "claude-sonnet-4-20250514".to_string(),
        ModelPricing {
            input_usd_micros_per_million: 3_000_000,
            output_usd_micros_per_million: 15_000_000,
            cached_input_usd_micros_per_million: 300_000,
            ..Default::default()
        },
    )]);
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing,
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("10"));
    assert_eq!(
        rows[0].get("cache_read_input_tokens").map(String::as_str),
        Some("100")
    );
    assert_eq!(
        rows[0]
            .get("cache_creation_input_tokens")
            .map(String::as_str),
        Some("20")
    );
    // Anthropic cost: 10 uncached*3 + 100 cache-read*0.3 + 20 cache-write*3
    // + 5 output*15 = 30 + 30 + 60 + 75 = 195 micros.
    assert_eq!(
        rows[0].get("cost_usd_micros").map(String::as_str),
        Some("195")
    );
    // Savings: 100 cache-read tokens * (3 - 0.3) usd/1M = 270 micros.
    assert_eq!(
        rows[0].get("cache_savings_usd_micros").map(String::as_str),
        Some("270")
    );
}

#[tokio::test]
async fn anthropic_messages_can_translate_to_openai_chat_when_policy_routes_cross_provider() {
    let upstream_body = r#"{
        "id":"chatcmpl_1",
        "object":"chat.completion",
        "model":"gpt-5.5",
        "choices":[{"index":0,"message":{"role":"assistant","content":"translated ok"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: "default".to_string(),
            allowed_runtimes: vec!["openai".to_string()],
            allowed_models: vec!["gpt-5.5".to_string()],
            default_runtime: "openai".to_string(),
            default_model: "gpt-5.5".to_string(),
            data_class: String::new(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
            impact_route_policy_json: String::new(),
        }))
        .await
        .unwrap();
    let (denied_upstream_base, denied_requests) =
        spawn_fake_upstream(r#"{"id":"unexpected"}"#, "application/json").await;
    let denied_gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: denied_upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;
    let denied = reqwest::Client::new()
        .post(format!("{denied_gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "auto",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(
        denied_requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.path != "/v1/chat/completions")
    );

    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "auto",
            "max_tokens": 64,
            "system": "stay terse",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["type"], "message");
    assert_eq!(body["model"], "gpt-5.5");
    assert_eq!(body["content"][0]["text"], "translated ok");
    assert_eq!(body["usage"]["input_tokens"], 11);
    assert_eq!(body["usage"]["output_tokens"], 4);

    let requests = requests.lock().unwrap();
    let requests = requests
        .iter()
        .filter(|request| request.path == "/v1/chat/completions")
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/chat/completions");
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert_eq!(requests[0].x_api_key, None);
    let translated: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(translated["model"], "gpt-5.5");
    assert_eq!(translated["messages"][0]["role"], "system");
    assert_eq!(translated["messages"][0]["content"], "stay terse");
    assert_eq!(translated["messages"][1]["role"], "user");
    assert_eq!(translated["messages"][1]["content"], "hello");
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    let row = rows
        .iter()
        .find(|row| row.get("resolved_model").map(String::as_str) == Some("openai/gpt-5.5"))
        .expect("allowed cross-provider call should be recorded");
    assert_eq!(row.get("provider").map(String::as_str), Some("openai"));
    assert_eq!(row.get("model").map(String::as_str), Some("auto"));
    assert_eq!(
        row.get("resolved_model").map(String::as_str),
        Some("openai/gpt-5.5")
    );
    assert_eq!(row.get("input_tokens").map(String::as_str), Some("11"));
    assert_eq!(row.get("output_tokens").map(String::as_str), Some("4"));

    let decisions = db
        .list_decisions(&sekai_chisei::sekai::audit::DecisionFilter {
            action: Some("gateway.cross_provider_translate".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "translated");
}

/// Seeds a cross-provider namespace policy: Anthropic client models allowed,
/// but `auto`/default resolves to an OpenAI-family model so the gateway
/// translates. Returns nothing; caller drives the gateway.
async fn seed_cross_provider_policy(target: &str, default_model: &str, runtime: &str) {
    let channel = connect_sekai(target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: "default".to_string(),
            allowed_runtimes: vec![runtime.to_string()],
            allowed_models: vec![default_model.to_string()],
            default_runtime: runtime.to_string(),
            default_model: default_model.to_string(),
            data_class: String::new(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
            impact_route_policy_json: String::new(),
        }))
        .await
        .unwrap();
    wait_for_seeded_gateway_decision(target, default_model, runtime).await;
}

/// A control-plane request as the gateway sends it: under its own principal.
fn gateway_principal_request<T>(message: T) -> GrpcRequest<T> {
    let mut request = GrpcRequest::new(message);
    request
        .metadata_mut()
        .insert("x-principal", "chisei-gateway".parse().unwrap());
    request
}

async fn wait_for_seeded_gateway_decision(target: &str, default_model: &str, runtime: &str) {
    let request = DecideGatewayExecutionRequest {
        contract_version: "gateway.decide/v2".to_string(),
        namespace: "default".to_string(),
        requested_model: default_model.to_string(),
        operation_class: "gateway.http".to_string(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: "seeded-policy-readiness".to_string(),
        correlation_attempt: 1,
        estimated_tokens: 1,
        task_class: "general".to_string(),
        preferred_runtime: runtime.to_string(),
        project: "default".to_string(),
        agent: "claude-code".to_string(),
        key_id: String::new(),
        work_unit: String::new(),
        local_free_available: true,
        user_id: "claude-code".to_string(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
        expected_calls: 1,
        pipeline_spec: String::new(),
        action_claim: None,
    };
    for _ in 0..250 {
        let channel = connect_sekai(target).await.unwrap();
        match tokio::time::timeout(
            Duration::from_secs(5),
            ChiseiServiceClient::new(channel)
                .decide_gateway_execution(gateway_principal_request(request.clone())),
        )
        .await
        {
            Ok(Ok(response)) if response.get_ref().admitted => return,
            Ok(Ok(response)) => panic!(
                "seeded gateway policy was not admitted: {}",
                response.get_ref().deny_message
            ),
            Ok(Err(status))
                if !matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::Unknown | tonic::Code::Cancelled
                ) =>
            {
                panic!("seeded gateway policy readiness failed: {status}")
            }
            _ => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("seeded gateway policy did not become ready");
}

#[tokio::test]
async fn anthropic_streaming_translates_to_openai_chat_stream_cross_provider() {
    // Upstream OpenAI-compatible chat SSE stream.
    let sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n\
               data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"translated\"}}]}\n\n\
               data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" ok\"},\"finish_reason\":null}]}\n\n\
               data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
               data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4,\"total_tokens\":15}}\n\n\
               data: [DONE]\n\n";
    let (upstream_base, requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    seed_cross_provider_policy(&chisei_target, "gpt-5.5", "openai").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let body = resp.text().await.unwrap();
    // Client receives well-formed Anthropic Messages SSE events.
    assert!(body.contains("event: message_start"), "{body}");
    assert!(body.contains("\"model\":\"gpt-5.5\""), "{body}");
    assert!(!body.contains("openai/gpt-5.5"), "{body}");
    assert!(body.contains("event: content_block_start"), "{body}");
    assert!(body.contains("event: content_block_delta"), "{body}");
    assert!(body.contains("\"text\":\"translated\""), "{body}");
    assert!(body.contains("\"text\":\" ok\""), "{body}");
    assert!(body.contains("event: message_delta"), "{body}");
    assert!(body.contains("event: message_stop"), "{body}");
    // Client-facing usage carries the upstream completion tokens, not zero.
    assert!(body.contains("\"output_tokens\":4"), "{body}");

    // Upstream got a streaming chat-completions request.
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/chat/completions");
        let translated: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(translated["model"], "gpt-5.5");
        assert_eq!(translated["stream"], true);
    }

    // Usage is metered from the tapped upstream OpenAI stream.
    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("11"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("4"));
}

#[tokio::test]
async fn anthropic_streaming_with_tools_is_denied_cross_provider() {
    let (upstream_base, requests) =
        spawn_fake_upstream("data: [DONE]\n\n", "text/event-stream").await;
    let (chisei_target, _db) = spawn_control_plane().await;
    seed_cross_provider_policy(&chisei_target, "gpt-5.5", "openai").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "stream": true,
            "tools": [{"name": "get_weather", "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "capability_unsupported");
    // Nothing was forwarded upstream.
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn anthropic_non_streaming_routes_to_resolved_ollama_backend() {
    // Cross-provider resolved to an Ollama model: route to the Ollama base,
    // strip the ollama/ prefix, and send no upstream auth.
    let upstream_body = r#"{
        "id":"chatcmpl_1",
        "object":"chat.completion",
        "model":"llama3.2:latest",
        "choices":[{"index":0,"message":{"role":"assistant","content":"local ok"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    // Point the control-plane resolver's Ollama listing at a fake /api/tags
    // so the model resolves without a live Ollama server (CI has none). A
    // distinctive name that a real local Ollama would not have guarantees
    // this test exercises the fake listing, not an ambient Ollama install.
    let ollama_tags = spawn_fake_ollama_tags("ci-fake-ollama:latest").await;
    let mut cp_config = test_config();
    cp_config.ollama_url = ollama_tags;
    let (chisei_target, db) = spawn_control_plane_with_config(cp_config).await;
    seed_cross_provider_policy(&chisei_target, "ollama/ci-fake-ollama:latest", "ollama").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        // OpenAI base points nowhere; the request must go to the Ollama base.
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: upstream_base,
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "gateway response: {body}");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["type"], "message");
    assert_eq!(body["content"][0]["text"], "local ok");

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/chat/completions");
    // Ollama gets no upstream auth.
    assert_eq!(requests[0].authorization, None);
    assert_eq!(requests[0].x_api_key, None);
    // The ollama/ prefix is stripped from the resolved model.
    let translated: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(translated["model"], "ci-fake-ollama:latest");
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("provider").map(String::as_str), Some("ollama"));
    let decisions = db
        .list_decisions(&sekai_chisei::sekai::audit::DecisionFilter {
            action: Some("gateway.cross_provider_translate".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0]
            .evidence
            .get("resolved_provider")
            .map(String::as_str),
        Some("ollama")
    );
}

#[tokio::test]
async fn cross_provider_passthrough_strips_client_anthropic_credential() {
    // Security: in passthrough mode a client presents its own Anthropic
    // credential. When policy routes cross-provider to OpenAI, that credential
    // must NOT be forwarded to api.openai.com; the gateway applies its own
    // OpenAI key instead.
    let upstream_body = r#"{
        "id":"chatcmpl_1",
        "object":"chat.completion",
        "model":"gpt-5.5",
        "choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _db) = spawn_control_plane().await;
    seed_cross_provider_policy(&chisei_target, "gpt-5.5", "openai").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        // Passthrough mode, no OpenAI rewrite: the client credential would be
        // forwarded verbatim if not for the cross-provider stripping.
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-ant-oat-client-subscription-secret")
        .header(X_CHISEI_AGENT.as_str(), "claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    // The upstream got the gateway's OpenAI key, never the client's token.
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert_ne!(
        requests[0].authorization.as_deref(),
        Some("Bearer sk-ant-oat-client-subscription-secret")
    );
    assert_eq!(requests[0].x_api_key, None);
}

#[tokio::test]
async fn anthropic_messages_streaming_merges_usage_events() {
    let sse = "event: message_start\n\
               data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":100,\"cache_creation_input_tokens\":30,\"cache_creation\":{\"ephemeral_5m_input_tokens\":20,\"ephemeral_1h_input_tokens\":10},\"output_tokens\":1}}}\n\n\
               event: content_block_delta\n\
               data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n\
               event: message_delta\n\
               data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), sse);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("provider").map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("10"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("7"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("147"));
    assert_eq!(
        rows[0].get("cache_read_input_tokens").map(String::as_str),
        Some("100")
    );
    assert_eq!(
        rows[0]
            .get("cache_creation_5m_input_tokens")
            .map(String::as_str),
        Some("20")
    );
    assert_eq!(
        rows[0]
            .get("cache_creation_1h_input_tokens")
            .map(String::as_str),
        Some("10")
    );
}

#[tokio::test]
async fn anthropic_count_tokens_proxy_records_input_tokens() {
    let upstream_body = r#"{"input_tokens":17}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages/count_tokens"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);
    assert_eq!(
        requests.lock().unwrap()[0].path,
        "/v1/messages/count_tokens"
    );

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("provider").map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("17"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("0"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("17"));
}

#[tokio::test]
async fn unknown_key_rejection_records_audit_decision() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let (chisei_target, db) = spawn_control_plane().await;
    let mut gateway_keys = HashMap::new();
    gateway_keys.insert(
        "sk-chisei-known".to_string(),
        GatewayIdentity {
            agent: "codex-app".to_string(),
            project: "sekai-chisei".to_string(),
            user_id: "agent:codex-app".to_string(),
            key_id: "codex-app".to_string(),
            tier: DEFAULT_GATEWAY_TIER.to_string(),
        },
    );
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys,
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-unknown")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(requests.lock().unwrap().is_empty());

    let decisions = db
        .list_decisions(&sekai_chisei::sekai::audit::DecisionFilter {
            action: Some("gateway.auth_failed".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].actor, "chisei-gateway");
    assert_eq!(decisions[0].outcome, "denied");
    assert_eq!(decisions[0].target_id, "llm_calls");
    assert_eq!(decisions[0].reason, "unknown chisei gateway key");
    assert_eq!(
        decisions[0]
            .evidence
            .get("presented_key")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn admin_refresh_clears_gateway_key_cache() {
    let upstream_body = r#"{"id":"resp_1","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_runtime(
        GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
            native_base_url: None,
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            pricing: HashMap::new(),
            allow_cross_provider: false,
        },
        TestRuntime::new(Duration::from_secs(60 * 60)).with_admin_token("admin-secret"),
    )
    .await;
    let client = reqwest::Client::new();
    let new_key = "sk-chisei-new-worker";

    let first = client
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth(new_key)
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    assert!(requests.lock().unwrap().is_empty());

    db.create_object(&sekai_chisei::domain::Object {
        id: "gateway-key-new-worker".to_string(),
        kind: "gateway_key".to_string(),
        name: "new-worker".to_string(),
        namespace: "default".to_string(),
        external_id: "gateway_key:new-worker:default".to_string(),
        properties: HashMap::from([
            ("agent".to_string(), "new-worker".to_string()),
            ("project".to_string(), "default".to_string()),
            ("status".to_string(), "active".to_string()),
            ("key_hash".to_string(), hash_gateway_key(new_key)),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();

    let cached_miss = client
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth(new_key)
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(cached_miss.status(), StatusCode::UNAUTHORIZED);

    let unauthorized_refresh = client
        .post(format!("{gateway_base}/_chisei/admin/refresh"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized_refresh.status(), StatusCode::UNAUTHORIZED);

    let refresh = client
        .post(format!("{gateway_base}/_chisei/admin/refresh"))
        .bearer_auth("admin-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::OK);
    let refresh_body: serde_json::Value = refresh.json().await.unwrap();
    assert_eq!(refresh_body["refreshed"], true);
    assert_eq!(refresh_body["cleared_key_cache_entries"], 1);

    let accepted = client
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth(new_key)
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accepted.text().await.unwrap(), upstream_body);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn available_models_endpoint_is_authenticated_filterable_and_redacted() {
    let (upstream_base, _) =
        spawn_fake_upstream(r#"{"data":[{"id":"gpt-5.5"}]}"#, "application/json").await;
    let gateway_base = spawn_gateway(upstream_base).await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{gateway_base}/v1/chisei/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = client
        .get(format!("{gateway_base}/v1/chisei/models?provider=openai"))
        .bearer_auth("sk-chisei-codex-app")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["version"], "chisei.available-models/v1");
    assert!(
        value["models"]
            .as_array()
            .unwrap()
            .iter()
            .all(|model| model["provider"] == "openai")
    );
    assert!(body.contains("openai/gpt-5.5"));
    assert!(!body.contains("real-openai-key"));
    assert!(!body.contains("real-anthropic-key"));
    assert!(!body.contains("discovery_source"));
}

#[tokio::test]
async fn provider_capability_matrix_endpoint_is_versioned_and_does_not_dump_unentitled_profiles() {
    let (upstream_base, _) =
        spawn_fake_upstream(r#"{"data":[{"id":"gpt-5.5"}]}"#, "application/json").await;
    let gateway_base = spawn_gateway(upstream_base).await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{gateway_base}/v1/chisei/capabilities"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = client
        .get(format!("{gateway_base}/v1/chisei/capabilities"))
        .bearer_auth("sk-chisei-codex-app")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-chisei-capability-catalog")
            .and_then(|value| value.to_str().ok()),
        Some(CAPABILITY_MATRIX_VERSION)
    );
    let body = response.text().await.unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["version"], CAPABILITY_MATRIX_VERSION);
    assert_eq!(value["grant_semantics"], false);
    let providers = value["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|profile| profile["provider"].as_str())
        .collect::<Vec<_>>();
    assert!(providers.contains(&"openai"), "{providers:?}");
    assert!(
        !providers.contains(&"meta"),
        "experimental unconfigured meta must not appear: {providers:?}"
    );
    assert!(!body.contains("real-openai-key"));
    assert!(!body.contains("real-anthropic-key"));
    assert!(!body.contains("sekai.semantic."));
    assert!(!body.contains("authorization_context"));
}

#[tokio::test]
async fn budget_denial_records_audit_decision() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let (chisei_target, db) = spawn_control_plane().await;

    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
            user_id: String::new(),
            max_tokens: 1,
            period_type: "day".to_string(),
            subject: String::new(),
            project: "default".to_string(),
            agent: "codex-app".to_string(),
            key_id: String::new(),
            work_unit: String::new(),
            metric: String::new(),
        }))
        .await
        .unwrap();

    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: String::new(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(requests.lock().unwrap().is_empty());

    let decisions = db
        .list_decisions(&sekai_chisei::sekai::audit::DecisionFilter {
            action: Some("gateway.budget_denied".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].actor, "chisei-gateway");
    assert_eq!(decisions[0].outcome, "denied");
    assert_eq!(decisions[0].target_id, "llm_calls");
    assert_eq!(
        decisions[0].evidence.get("user_id").map(String::as_str),
        Some("agent:codex-app")
    );

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("status").map(String::as_str), Some("429"));
    assert_eq!(
        rows[0].get("error_type").map(String::as_str),
        Some("budget_exceeded")
    );
    assert_eq!(
        rows[0]
            .get("refusal_reason")
            .map(|reason| reason.contains("budget exceeded")),
        Some(true)
    );
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("provider").map(String::as_str), Some("openai"));
}

#[tokio::test]
async fn project_budget_denial_blocks_gateway_call() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let (chisei_target, db) = spawn_control_plane().await;

    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
            user_id: "project:default".to_string(),
            max_tokens: 1,
            period_type: "day".to_string(),
            subject: "project:default".to_string(),
            project: "default".to_string(),
            agent: String::new(),
            key_id: String::new(),
            work_unit: String::new(),
            metric: String::new(),
        }))
        .await
        .unwrap();

    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: String::new(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(requests.lock().unwrap().is_empty());

    let decisions = db
        .list_decisions(&sekai_chisei::sekai::audit::DecisionFilter {
            action: Some("gateway.budget_denied".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0]
            .evidence
            .get("budget_subject")
            .map(String::as_str),
        Some("project:default")
    );

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("status").map(String::as_str), Some("429"));
    assert_eq!(
        rows[0]
            .get("refusal_reason")
            .map(|reason| reason.contains("project:default")),
        Some(true)
    );
}

#[tokio::test]
async fn non_streaming_response_records_usage_and_appends_llm_call() {
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"gateway sampled answer"}]}],
        "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
    }"#;
    let (upstream_base, _requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let mut config = test_config();
    config.sample_rate = 1.0;
    config.scoring_enabled = true;
    let (chisei_target, db) = spawn_control_plane_with_config(config).await;
    let pricing = HashMap::from([(
        "gpt-5.5".to_string(),
        ModelPricing {
            input_usd_micros_per_million: 1_000_000,
            output_usd_micros_per_million: 2_000_000,
            cached_input_usd_micros_per_million: 1_000_000,
            ..Default::default()
        },
    )]);
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing,
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-work-unit", "wu-cost-1")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("project").map(String::as_str), Some("default"));
    assert_eq!(rows[0].get("model").map(String::as_str), Some("gpt-5.5"));
    assert_eq!(
        rows[0].get("resolved_model").map(String::as_str),
        Some("openai/gpt-5.5")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("7"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("5"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("12"));
    // No cache tokens in this response, so the cache keys are omitted.
    assert_eq!(rows[0].get("cache_read_input_tokens"), None);
    assert_eq!(rows[0].get("cache_creation_input_tokens"), None);
    assert_eq!(rows[0].get("cache_savings_usd_micros"), None);
    assert_eq!(
        rows[0].get("cost_usd_micros").map(String::as_str),
        Some("17")
    );
    assert_eq!(
        rows[0].get("cost_usd").map(String::as_str),
        Some("0.000017")
    );
    assert_eq!(
        rows[0].get("work_unit_id").map(String::as_str),
        Some("wu-cost-1")
    );
    assert_eq!(
        rows[0].get("pipeline_sampled").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        rows[0].get("sample_reason").map(String::as_str),
        Some("base")
    );
    assert_eq!(rows[0].get("sample_rate").map(String::as_str), Some("1"));

    let work_unit = db
        .find_by_external_id("work_unit:wu-cost-1")
        .unwrap()
        .unwrap();
    let request_id = rows[0].get("request_id").unwrap();
    let llm_call = db
        .find_by_external_id(&format!("llm_call:{request_id}"))
        .unwrap()
        .unwrap();
    let links = db
        .get_links(
            &work_unit.id,
            "incurs_usage",
            &sekai_chisei::domain::Direction::Outgoing,
        )
        .unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].to_id, llm_call.id);

    let decisions = db
        .list_decisions(&sekai_chisei::sekai::audit::DecisionFilter {
            action: Some("gateway.sampled".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].reason, "base");

    let observations = db.list_unscored_observations(10).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].request_id, *request_id);
    assert_eq!(observations[0].namespace, "default");
    assert_eq!(observations[0].output_content, "gateway sampled answer");
    assert_eq!(observations[0].sample_reason, "base");
}

#[tokio::test]
async fn cache_tokens_and_savings_are_recorded_on_llm_call() {
    // OpenAI reports cached tokens as a subset of prompt/input tokens.
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"cached answer"}]}],
        "usage":{"input_tokens":100,"output_tokens":5,"total_tokens":105,"prompt_tokens_details":{"cached_tokens":80}}
    }"#;
    let (upstream_base, _requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    // input 1 usd/1M, output 2 usd/1M, cached 0.1 usd/1M.
    let pricing = HashMap::from([(
        "gpt-5.5".to_string(),
        ModelPricing {
            input_usd_micros_per_million: 1_000_000,
            output_usd_micros_per_million: 2_000_000,
            cached_input_usd_micros_per_million: 100_000,
            ..Default::default()
        },
    )]);
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing,
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("100"));
    assert_eq!(
        rows[0].get("cache_read_input_tokens").map(String::as_str),
        Some("80")
    );
    // No cache-creation tokens in this response.
    assert_eq!(rows[0].get("cache_creation_input_tokens"), None);
    // Cost = 20 uncached * 1 + 80 cached * 0.1 + 5 output * 2 = 38 micros.
    assert_eq!(
        rows[0].get("cost_usd_micros").map(String::as_str),
        Some("38")
    );
    // Savings = 80 cache-read tokens * (1 - 0.1) usd/1M = 72 micros.
    assert_eq!(
        rows[0].get("cache_savings_usd_micros").map(String::as_str),
        Some("72")
    );
    assert_eq!(
        rows[0].get("cache_savings_usd").map(String::as_str),
        Some("0.000072")
    );
}

#[tokio::test]
async fn streaming_response_records_usage_after_passthrough() {
    let sse = "event: response.created\n\
               data: {\"type\":\"response.created\"}\n\n\
               event: response.completed\n\
               data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":13,\"total_tokens\":24}}}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello", "stream": true}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), sse);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("11"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("13"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("24"));
}

// Captured from chatgpt.com/backend-api/codex/responses: the ChatGPT Codex
// backend streams SSE with no Content-Type header, emits "usage": null on
// response.created, and carries real usage on response.completed.
const CODEX_BACKEND_SSE: &str = "event: response.created\n\
data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_codex\",\"status\":\"in_progress\",\"usage\":null,\"tool_usage\":{\"image_gen\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0},\"web_search\":{\"num_requests\":0}}}}\n\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n\
event: response.completed\n\
data: {\"type\":\"response.completed\",\"sequence_number\":9,\"response\":{\"id\":\"resp_codex\",\"status\":\"completed\",\"output\":[{\"id\":\"msg_1\",\"type\":\"message\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}],\"role\":\"assistant\"}],\"usage\":{\"input_tokens\":45,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens\":5,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":50},\"tool_usage\":{\"image_gen\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0},\"web_search\":{\"num_requests\":0}}}}\n\n";

#[tokio::test]
async fn codex_backend_sse_without_content_type_records_usage() {
    let (upstream_base, _requests) = spawn_fake_upstream(CODEX_BACKEND_SSE, "").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello", "stream": true}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), CODEX_BACKEND_SSE);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("45"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("5"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("50"));
}

#[tokio::test]
async fn codex_backend_sse_without_content_type_streams_incrementally() {
    const CHUNKS: &[&str] = &[
        "event: response.created\n\
         data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_codex\",\"status\":\"in_progress\",\"usage\":null}}\n\n",
        "event: response.output_text.delta\n\
         data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
        "event: response.completed\n\
         data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codex\",\"status\":\"completed\",\"usage\":{\"input_tokens\":45,\"output_tokens\":5,\"total_tokens\":50}}}\n\n",
    ];
    let upstream_base = spawn_fake_chunked_upstream(CHUNKS, Duration::from_millis(150)).await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let mut resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello", "stream": true}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let first = resp.chunk().await.unwrap().unwrap();
    let mut body = String::from_utf8(first.to_vec()).unwrap();
    assert!(body.contains("response.created"));
    assert!(
        !body.contains("response.completed"),
        "gateway buffered the SSE body instead of streaming it: {body}"
    );
    while let Some(chunk) = resp.chunk().await.unwrap() {
        body.push_str(std::str::from_utf8(&chunk).unwrap());
    }
    assert_eq!(body, CHUNKS.concat());

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("45"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("5"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("50"));
}

#[tokio::test]
async fn json_body_without_content_type_streams_and_records_usage() {
    // The blank line between fields must survive the SSE usage tap: a
    // non-SSE body split on event boundaries would lose its usage.
    let upstream_body = "{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\n\n\"usage\":{\"input_tokens\":8,\"output_tokens\":6,\"total_tokens\":14},\n\n\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}]}";
    let (upstream_base, _requests) = spawn_fake_upstream(upstream_body, "").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("8"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("6"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("14"));
    assert_eq!(rows[0].get("terminal_outcome").map(String::as_str), None);
}

#[tokio::test]
async fn responses_errors_without_content_type_are_normalized() {
    for upstream_body in [
        r#"{"error":{"message":"provider rejected request"}}"#,
        "",
        "data: {\"error\":{\"message\":\"provider rejected request\"}}\n\n",
    ] {
        let (upstream_base, _requests) =
            spawn_fake_upstream_with_status(upstream_body, "", StatusCode::BAD_REQUEST, None).await;
        let gateway_base = spawn_gateway_with_preflight(upstream_base).await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        let status = resp.status();
        let body = resp.text().await.unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"]["code"], "invalid_request");
    }
}

#[tokio::test]
async fn responses_client_errors_use_stable_error_codes() {
    for (status, expected_code) in [
        (StatusCode::UNAUTHORIZED, "authentication_error"),
        (StatusCode::PAYMENT_REQUIRED, "upstream_unavailable"),
        (StatusCode::FORBIDDEN, "authentication_error"),
        (StatusCode::CONFLICT, "invalid_request"),
    ] {
        let (upstream_base, _requests) = spawn_fake_upstream_with_status(
            r#"{"error":{"code":"vendor_specific","message":"rejected"}}"#,
            "application/json",
            status,
            None,
        )
        .await;
        let gateway_base = spawn_gateway_with_preflight(upstream_base).await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), status);
        assert_eq!(resp.headers()[&X_CHISEI_RETRY_SAFETY], "safe");
        let body: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["error"]["code"], expected_code);
        assert_eq!(body["error"]["message"], "rejected");
    }
}

#[tokio::test]
async fn retryable_responses_errors_are_normalized() {
    let upstream_body = r#"{"error":{"code":"vendor_busy","message":"try later"}}"#;
    let (upstream_base, _requests) = spawn_fake_upstream_with_status(
        upstream_body,
        "application/json",
        StatusCode::TOO_MANY_REQUESTS,
        None,
    )
    .await;
    let gateway_base = spawn_gateway_with_preflight(upstream_base).await;
    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers()[&X_CHISEI_RETRY_SAFETY], "safe");
    let body: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "rate_limited");
    assert_eq!(body["error"]["message"], "try later");
}

/// #2700: with a gateway key, native execution reaches the provider only
/// through the gateway, and a Chisei process with no provider keys completes
/// the plan. The gateway swaps its own provider key in; the native receipt
/// still names the plan.
#[tokio::test]
async fn native_execution_egresses_through_the_gateway_without_provider_keys() {
    use sekai_proto::chisei::{
        ChatMessage, ExecutePlanRequest, ExecutionInput, GetOperationReceiptRequest,
        PlanExecutionRequest,
    };
    const SSE: &str = concat!(
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-5.5\",",
        "\"choices\":[{\"index\":0,\"delta\":{\"content\":\"via gateway\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-5.5\",",
        "\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],",
        "\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\n",
        "data: [DONE]\n\n",
    );
    let (upstream_base, requests) = spawn_fake_upstream(SSE, "text/event-stream").await;
    let gateway_base = spawn_gateway(upstream_base).await;
    let mut config = test_config();
    config.openai_api_key = None;
    config.anthropic_api_key = None;
    config.gateway_provided_providers = vec!["openai".into()];
    config.gateway_key = Some("sk-chisei-codex-app".into());
    config.gateway_url = format!("{gateway_base}/v1");
    let (target, _db) = spawn_control_plane_with_config(config).await;
    let mut chisei = ChiseiServiceClient::new(connect_sekai(&target).await.unwrap());

    let request_id = format!("native-gateway-{}", uuid::Uuid::new_v4().simple());
    let plan = chisei
        .plan_execution(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: request_id.clone(),
                namespace: "default".into(),
                spec: "Reply.".into(),
                preferred_model: "openai/gpt-5.5".into(),
                task_type: "question".into(),
                user_id: "native-user".into(),
                max_tokens: 32,
                messages: vec![ChatMessage {
                    role: "user".into(),
                    content: "Reply.".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .plan
        .expect("plan");
    assert!(plan.executable, "{plan:?}");
    let plan_id = plan.plan_id.clone();
    let mut stream = chisei
        .execute_plan_stream(ExecutePlanRequest { plan: Some(plan) })
        .await
        .unwrap()
        .into_inner();
    let mut reply = String::new();
    while let Some(event) = stream.message().await.unwrap() {
        if let Some(response) = event.response {
            reply = response.content;
        }
    }
    assert_eq!(reply, "via gateway");

    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "only the gateway reaches the upstream");
        assert_eq!(requests[0].path, "/v1/chat/completions");
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer real-openai-key"),
            "the gateway supplies the provider key"
        );
    }
    let receipt = chisei
        .get_operation_receipt(GetOperationReceiptRequest {
            request_id,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        receipt.receipt_json.contains(&plan_id),
        "native receipt names the plan: {}",
        receipt.receipt_json
    );
}

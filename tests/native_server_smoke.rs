//! Process-level product-palette smoke for the shipped `sekai-chisei` binary.
//!
//! Library tests under `tests/` never run `main`. This file starts the compiled
//! server, a loopback OpenAI-compatible fake for Ollama, and drives the public
//! operator (`sekaictl`) and gRPC surfaces over a temp Unix socket.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::Read;
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Router, http::StatusCode};
use sekai_chisei::chisei::lookup_first::{
    LOOKUP_HIT_STOP_REASON, LOOKUP_PROVIDER, LOOKUP_REFUSAL_ATTR,
};
use sekai_chisei::grpc::client::connect_sekai;
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::chisei::{
    ChatMessage, ExecutePlanRequest, ExecutionInput, GetEffectivePolicySummaryRequest,
    GetOperationReceiptRequest, ListKiokuCandidatesRequest, PlanExecutionRequest,
    RecordUsageRequest, SetBudgetLimitRequest,
};
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    AcquireLeaseRequest, CreateObjectRequest, EnsureTeamNamespaceRequest, GetLeaseRequest,
    GetLinkedObjectsRequest, GetObjectRequest, GraphQuery, ListFilter, ListObjectsRequest, Object,
    ReleaseLeaseRequest, TraverseRequest,
};
use sekai_chisei::sekai::semantic::CAPABILITY_RESOLVE_REF;
use serde_json::{Value, json};
use tokio::sync::watch;
use tonic::{Code, Request};

const WAIT_BUDGET: Duration = Duration::from_secs(20);
const MOCK_REPLY: &str = "sekai-chisei palette mock ok";
const MOCK_MODEL: &str = "ollama/llama3.2:latest";
const CONTEXT_FACT_VERDICT: &str = "palette-degraded";
const CONTEXT_FACT_CONVICTION: &str = "0.91";

#[derive(Clone)]
struct FakeLlmState {
    reply: &'static str,
    captured: Arc<Mutex<Vec<Value>>>,
}

struct FakeLlm {
    url: String,
    captured: Arc<Mutex<Vec<Value>>>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeLlm {
    async fn spawn() -> Self {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, mut stopped) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake llm");
        let url = format!("http://{}", listener.local_addr().expect("fake llm addr"));
        let app = Router::new()
            .route("/api/tags", get(fake_ollama_tags))
            .route("/v1/chat/completions", post(fake_chat_completions))
            .with_state(FakeLlmState {
                reply: MOCK_REPLY,
                captured: captured.clone(),
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.changed().await;
                })
                .await
                .expect("fake llm serve");
        });
        Self {
            url,
            captured,
            shutdown,
            task,
        }
    }

    fn captured_prompt(&self) -> String {
        self.captured
            .lock()
            .expect("fake llm capture")
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Drop for FakeLlm {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

async fn fake_ollama_tags() -> Json<Value> {
    Json(json!({
        "models": [{
            "name": "llama3.2:latest",
            "details": { "parameter_size": "3B", "context_length": 8192 },
            "capabilities": ["completion"]
        }]
    }))
}

async fn fake_chat_completions(
    State(state): State<FakeLlmState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    state
        .captured
        .lock()
        .expect("fake llm capture")
        .push(body.clone());
    let reply = state.reply;
    if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
        let delta = json!({
            "id": "chatcmpl_palette",
            "object": "chat.completion.chunk",
            "choices": [{ "index": 0, "delta": { "content": reply }, "finish_reason": null }]
        });
        let done = json!({
            "id": "chatcmpl_palette",
            "object": "chat.completion.chunk",
            "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 8, "completion_tokens": 6 }
        });
        let sse = format!("data: {delta}\n\ndata: {done}\n\ndata: [DONE]\n\n");
        ([(CONTENT_TYPE, "text/event-stream")], sse).into_response()
    } else {
        (
            StatusCode::OK,
            Json(json!({
                "id": "chatcmpl_palette",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": { "role": "assistant", "content": reply },
                    "finish_reason": "stop"
                }],
                "usage": { "prompt_tokens": 8, "completion_tokens": 6 }
            })),
        )
            .into_response()
    }
}

struct NativeServer {
    child: Child,
    /// Keeps the temp workspace alive for the socket, database, and logs.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    socket: PathBuf,
    grpc_port: u16,
    log_path: PathBuf,
}

impl NativeServer {
    fn spawn() -> Self {
        Self::spawn_with_ollama(None)
    }

    fn spawn_with_ollama(ollama_url: Option<&str>) -> Self {
        static START_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _start = START_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("native server start lock");
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("sekai.sock");
        let sekai_db = dir.path().join("sekai.db");
        let chisei_db = dir.path().join("chisei.db");
        let log_path = dir.path().join("sekai.log");
        let grpc_port = free_tcp_port();
        let log = std::fs::File::create(&log_path).expect("server log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"));
        command
            .env("SEKAI_SOCKET", &socket)
            .env("SEKAI_DB_PATH", &sekai_db)
            .env("CHISEI_DB_PATH", &chisei_db)
            .env("GRPC_PORT", grpc_port.to_string())
            .env("OPS_PORT", "")
            .env("OPS_BIND", "127.0.0.1")
            .env("RUST_LOG", "error")
            .env("LLM_HTTP_CONNECT_TIMEOUT_SECS", "2")
            .env("LLM_HTTP_READ_TIMEOUT_SECS", "5")
            .env("LLM_HTTP_REQUEST_TIMEOUT_SECS", "5")
            // Product-palette RPCs still classified experimental on current main.
            .env("SEKAI_EXPERIMENTAL_RPCS", "1")
            .env_remove("SEKAI_INSECURE")
            .env_remove("SEKAI_CREDENTIAL")
            .env_remove("SEKAI_BIND")
            .env_remove("SEKAI_ALLOW_PLAINTEXT")
            .env_remove("SEKAI_TLS_CERT")
            .env_remove("SEKAI_TLS_KEY")
            .env_remove("SEKAI_DB_BACKEND")
            .env_remove("DATABASE_URL")
            .env_remove("DB_PATH")
            .env_remove("SEKAI_SHARED_STORE")
            .env_remove("SEKAI_DATABASE_URL")
            .env_remove("CHISEI_DATABASE_URL")
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("XAI_API_KEY")
            .env_remove("NATIVE_LLM_URL")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log));
        if let Some(url) = ollama_url {
            command.env("OLLAMA_URL", url);
        } else {
            command.env_remove("OLLAMA_URL");
        }
        let child = command.spawn().expect("spawn sekai-chisei");
        let mut server = Self {
            child,
            dir,
            socket,
            grpc_port,
            log_path,
        };
        server.wait_until_ready();
        server
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + WAIT_BUDGET;
        loop {
            if UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("poll server") {
                panic!(
                    "sekai-chisei exited {status} before the Unix socket was ready\n{}",
                    self.logs()
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "timed out waiting for {}\n{}",
                    self.socket.display(),
                    self.logs()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn logs(&self) -> String {
        let mut contents = String::new();
        if let Ok(mut file) = std::fs::File::open(&self.log_path) {
            let _ = file.read_to_string(&mut contents);
        }
        contents
    }

    fn sekaictl(&mut self, args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_sekaictl"))
            .args(args)
            .env("SEKAI_SOCKET", &self.socket)
            .env_remove("CHISEI_GRPC_URL")
            .env_remove("SEKAI_CREDENTIAL")
            .output()
            .expect("run sekaictl");
        if self.child.try_wait().expect("poll server").is_some() {
            panic!(
                "sekai-chisei exited while running sekaictl {args:?}\nsekaictl stdout: {}\nsekaictl stderr: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                self.logs()
            );
        }
        output
    }

    fn fixture(&self, relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
    }

    fn socket_str(&self) -> String {
        self.socket.to_str().expect("utf8 socket").to_string()
    }

    fn seed_demo(&mut self) {
        let socket = self.socket_str();
        let domain = self.fixture("tests/fixtures/product_loop/domain-v1.json");
        let seed = self.fixture("tests/fixtures/product_loop/seed-v1.json");
        let apply = self.sekaictl_retry(
            &[
                "ontology",
                "apply",
                "--file",
                domain.to_str().unwrap(),
                "--target",
                &socket,
            ],
            "ontology apply",
        );
        assert_success(&apply, "ontology apply", &self.logs());
        let seeded = self.sekaictl_retry(
            &[
                "ontology",
                "seed",
                "--file",
                seed.to_str().unwrap(),
                "--target",
                &socket,
            ],
            "ontology seed",
        );
        assert_success(&seeded, "ontology seed", &self.logs());
    }

    fn sekaictl_retry(&mut self, args: &[&str], label: &str) -> Output {
        let mut last = self.sekaictl(args);
        for attempt in 1..6 {
            if last.status.success() {
                return last;
            }
            let stderr = String::from_utf8_lossy(&last.stderr);
            if !stderr.contains("database is locked") {
                break;
            }
            std::thread::sleep(Duration::from_millis(50 * attempt));
            last = self.sekaictl(args);
        }
        let _ = label;
        last
    }

    async fn sekai(&self) -> SekaiServiceClient<sekai_chisei::grpc::client::GatewayClient> {
        SekaiServiceClient::new(self.channel().await)
    }

    async fn chisei(&self) -> ChiseiServiceClient<sekai_chisei::grpc::client::GatewayClient> {
        ChiseiServiceClient::new(self.channel().await)
    }

    async fn channel(&self) -> sekai_chisei::grpc::client::GatewayClient {
        connect_sekai(&self.socket_str())
            .await
            .unwrap_or_else(|error| panic!("connect local socket: {error}\n{}", self.logs()))
    }

    async fn seed_context_fact(&self) {
        self.sekai()
            .await
            .create_object(CreateObjectRequest {
                object: Some(Object {
                    id: "palette-billing".into(),
                    kind: "component".into(),
                    name: "palette-billing".into(),
                    namespace: "demo".into(),
                    external_id: "component:palette-billing".into(),
                    properties: HashMap::from([
                        ("verdict".into(), CONTEXT_FACT_VERDICT.into()),
                        ("conviction".into(), CONTEXT_FACT_CONVICTION.into()),
                    ]),
                    created: 0,
                    updated: 0,
                }),
                lease_precondition: None,
            })
            .await
            .unwrap_or_else(|error| panic!("create context object: {error}\n{}", self.logs()));
    }

    async fn seed_lookup_object(&self, id: &str) {
        self.sekai()
            .await
            .create_object(CreateObjectRequest {
                object: Some(Object {
                    id: id.into(),
                    kind: "component".into(),
                    name: id.into(),
                    namespace: "demo".into(),
                    external_id: format!("component:{id}"),
                    properties: HashMap::from([("color".into(), "red".into())]),
                    created: 0,
                    updated: 0,
                }),
                lease_precondition: None,
            })
            .await
            .unwrap_or_else(|error| panic!("create lookup object: {error}\n{}", self.logs()));
    }

    async fn grant_namespace(&self, namespace: &str, principal: &str, role: &str) {
        self.sekai()
            .await
            .ensure_team_namespace(EnsureTeamNamespaceRequest {
                namespace: namespace.into(),
                principal: principal.into(),
                role: role.into(),
            })
            .await
            .unwrap_or_else(|error| panic!("ensure team namespace: {error}\n{}", self.logs()));
    }

    fn create_principal_token(&mut self, principal: &str) -> String {
        let created = self.sekaictl(&["admin", "access", "credential", "create", principal]);
        assert_success(&created, "credential create", &self.logs());
        let token = stdout(&created).trim().to_string();
        assert!(!token.is_empty(), "create should print a bearer token");
        token
    }
}

impl Drop for NativeServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_tcp_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn tcp_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(200),
    )
    .is_ok()
}

fn assert_success(output: &Output, label: &str, logs: &str) {
    assert!(
        output.status.success(),
        "{label} failed ({:?})\nstdout: {}\nstderr: {}\n{logs}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

async fn mocked_server() -> (FakeLlm, NativeServer) {
    let fake = FakeLlm::spawn().await;
    let server = NativeServer::spawn_with_ollama(Some(&fake.url));
    (fake, server)
}

async fn seeded_server() -> (FakeLlm, NativeServer) {
    let (fake, mut server) = mocked_server().await;
    server.seed_demo();
    (fake, server)
}

async fn execute_mocked_plan(
    server: &NativeServer,
    chisei: &mut ChiseiServiceClient<sekai_chisei::grpc::client::GatewayClient>,
) -> (String, String) {
    let request_id = format!("palette-{}", uuid::Uuid::new_v4().simple());
    let plan = chisei
        .plan_execution(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: request_id.clone(),
                namespace: "demo".into(),
                spec: "Reply with the mock phrase.".into(),
                preferred_model: MOCK_MODEL.into(),
                task_type: "question".into(),
                user_id: "palette-user".into(),
                max_tokens: 32,
                messages: vec![ChatMessage {
                    role: "user".into(),
                    content: "Reply with the mock phrase.".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            gunshi_allocation: None,
        })
        .await
        .unwrap_or_else(|error| panic!("plan execution: {error}\n{}", server.logs()))
        .into_inner()
        .plan
        .expect("plan");
    assert!(
        plan.executable,
        "plan against the mocked Ollama provider should be executable\n{plan:?}\n{}",
        server.logs()
    );
    assert!(
        plan.resolved_model.contains("ollama"),
        "plan should resolve to ollama, got {}\n{}",
        plan.resolved_model,
        server.logs()
    );
    let mut stream = chisei
        .execute_plan_stream(ExecutePlanRequest { plan: Some(plan) })
        .await
        .unwrap_or_else(|error| panic!("execute plan: {error}\n{}", server.logs()))
        .into_inner();
    let mut reply = String::new();
    while let Some(event) = stream
        .message()
        .await
        .unwrap_or_else(|error| panic!("execute stream: {error}\n{}", server.logs()))
    {
        if let Some(response) = event.response {
            reply = response.content;
        }
    }
    (request_id, reply)
}

fn bearer<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("metadata"),
    );
    request
}

async fn plan_resolve_ref(
    server: &NativeServer,
    chisei: &mut ChiseiServiceClient<sekai_chisei::grpc::client::GatewayClient>,
    spec: &str,
) -> sekai_chisei::grpc::pb::chisei::ExecutionPlan {
    chisei
        .plan_execution(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: format!("palette-lookup-{}", uuid::Uuid::new_v4().simple()),
                namespace: "demo".into(),
                spec: spec.into(),
                preferred_model: MOCK_MODEL.into(),
                task_type: CAPABILITY_RESOLVE_REF.into(),
                user_id: "palette-user".into(),
                max_tokens: 32,
                ..Default::default()
            }),
            gunshi_allocation: None,
        })
        .await
        .unwrap_or_else(|error| panic!("plan resolve_ref: {error}\n{}", server.logs()))
        .into_inner()
        .plan
        .expect("plan")
}

async fn collect_execute(
    server: &NativeServer,
    chisei: &mut ChiseiServiceClient<sekai_chisei::grpc::client::GatewayClient>,
    plan: sekai_chisei::grpc::pb::chisei::ExecutionPlan,
) -> sekai_chisei::grpc::pb::chisei::PlannedChatResponse {
    let mut stream = chisei
        .execute_plan_stream(ExecutePlanRequest { plan: Some(plan) })
        .await
        .unwrap_or_else(|error| panic!("execute plan: {error}\n{}", server.logs()))
        .into_inner();
    let mut response = None;
    while let Some(event) = stream
        .message()
        .await
        .unwrap_or_else(|error| panic!("execute stream: {error}\n{}", server.logs()))
    {
        if event.response.is_some() {
            response = event.response;
        }
    }
    response.expect("execute returned a response")
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_applies_ontology() {
    let (_fake, mut server) = mocked_server().await;
    let socket = server.socket_str();
    let domain = server.fixture("tests/fixtures/product_loop/domain-v1.json");
    let apply = server.sekaictl(&[
        "ontology",
        "apply",
        "--file",
        domain.to_str().unwrap(),
        "--target",
        &socket,
    ]);
    assert_success(&apply, "ontology apply", &server.logs());
    let apply_out = stdout(&apply);
    assert!(
        apply_out.contains("class: Service") && apply_out.contains("relation: affects"),
        "apply should create the product-loop domain\n{apply_out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_seeds_graph() {
    let (_fake, mut server) = mocked_server().await;
    let socket = server.socket_str();
    let domain = server.fixture("tests/fixtures/product_loop/domain-v1.json");
    let seed = server.fixture("tests/fixtures/product_loop/seed-v1.json");
    assert_success(
        &server.sekaictl(&[
            "ontology",
            "apply",
            "--file",
            domain.to_str().unwrap(),
            "--target",
            &socket,
        ]),
        "ontology apply",
        &server.logs(),
    );
    let seeded = server.sekaictl(&[
        "ontology",
        "seed",
        "--file",
        seed.to_str().unwrap(),
        "--target",
        &socket,
    ]);
    assert_success(&seeded, "ontology seed", &server.logs());
    let seed_text = stdout(&seeded);
    assert!(
        seed_text.contains("object: svc-api") && seed_text.contains("object: inc-1"),
        "seed should create the product-loop objects\n{seed_text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_lists_objects() {
    let (_fake, server) = seeded_server().await;
    let listed = server
        .sekai()
        .await
        .list_objects(ListObjectsRequest {
            filter: Some(ListFilter {
                kind: "component".into(),
                namespace: "demo".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("list objects: {error}\n{}", server.logs()))
        .into_inner();
    assert!(
        listed.objects.iter().any(|object| object.id == "svc-api"),
        "list should return the seeded component\n{listed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_gets_object() {
    let (_fake, server) = seeded_server().await;
    let got = server
        .sekai()
        .await
        .get_object(GetObjectRequest { id: "inc-1".into() })
        .await
        .unwrap_or_else(|error| panic!("get object: {error}\n{}", server.logs()))
        .into_inner()
        .object
        .expect("incident object");
    assert_eq!(got.kind, "incident");
    assert_eq!(got.namespace, "demo");
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_follows_links() {
    let (_fake, server) = seeded_server().await;
    let linked = server
        .sekai()
        .await
        .get_linked_objects(GetLinkedObjectsRequest {
            object_id: "inc-1".into(),
            relation: "affects".into(),
            direction: "out".into(),
        })
        .await
        .unwrap_or_else(|error| panic!("get linked objects: {error}\n{}", server.logs()))
        .into_inner();
    assert!(
        linked.objects.iter().any(|object| object.id == "svc-api"),
        "incident should affect svc-api\n{linked:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_traverses_graph() {
    let (_fake, server) = seeded_server().await;
    let traversed = server
        .sekai()
        .await
        .traverse(TraverseRequest {
            query: Some(GraphQuery {
                start_id: "inc-1".into(),
                direction: "out".into(),
                max_depth: 2,
                ..Default::default()
            }),
        })
        .await
        .unwrap_or_else(|error| panic!("traverse: {error}\n{}", server.logs()))
        .into_inner()
        .result
        .expect("traverse result");
    assert!(
        traversed
            .objects
            .iter()
            .any(|object| object.id == "svc-api"),
        "traverse should reach the seeded service\n{traversed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_acquires_and_releases_lease() {
    let (_fake, server) = seeded_server().await;
    let mut sekai = server.sekai().await;
    let lease = sekai
        .acquire_lease(AcquireLeaseRequest {
            namespace: "demo".into(),
            key: "object:svc-api".into(),
            owner: "local".into(),
            ttl_ms: 30_000,
            request_id: "palette-lease".into(),
        })
        .await
        .unwrap_or_else(|error| panic!("acquire lease: {error}\n{}", server.logs()))
        .into_inner()
        .lease
        .expect("lease");
    assert_eq!(lease.owner, "local");
    let loaded = sekai
        .get_lease(GetLeaseRequest {
            namespace: "demo".into(),
            key: "object:svc-api".into(),
        })
        .await
        .unwrap_or_else(|error| panic!("get lease: {error}\n{}", server.logs()))
        .into_inner()
        .lease
        .expect("loaded lease");
    assert_eq!(loaded.generation, lease.generation);
    sekai
        .release_lease(ReleaseLeaseRequest {
            namespace: "demo".into(),
            key: "object:svc-api".into(),
            fencing_token: lease.fencing_token,
            request_id: "palette-lease-release".into(),
        })
        .await
        .unwrap_or_else(|error| panic!("release lease: {error}\n{}", server.logs()));
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_creates_credential() {
    let (_fake, mut server) = mocked_server().await;
    let created = server.sekaictl(&["admin", "access", "credential", "create", "smoke-agent"]);
    assert_success(&created, "credential create", &server.logs());
    assert!(
        !stdout(&created).trim().is_empty(),
        "credential create should print a token"
    );
    let listed_creds = server.sekaictl(&["admin", "access", "credential", "list"]);
    assert_success(&listed_creds, "credential list", &server.logs());
    assert!(
        stdout(&listed_creds).contains("smoke-agent"),
        "credential list should include smoke-agent\n{}",
        stdout(&listed_creds)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_sets_action_policy() {
    let (_fake, mut server) = mocked_server().await;
    let set_policy = server.sekaictl(&[
        "admin",
        "governance",
        "action",
        "policy",
        "set",
        "--scope",
        "demo",
        "--default",
        "allow",
    ]);
    assert_success(&set_policy, "action policy set", &server.logs());
    let get_policy = server.sekaictl(&[
        "admin",
        "governance",
        "action",
        "policy",
        "get",
        "--scope",
        "demo",
    ]);
    assert_success(&get_policy, "action policy get", &server.logs());
    assert!(
        stdout(&get_policy).contains("default_decision: allow"),
        "action policy should round-trip\n{}",
        stdout(&get_policy)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_records_budget_usage() {
    let (_fake, server) = mocked_server().await;
    let mut chisei = server.chisei().await;
    chisei
        .set_budget_limit(SetBudgetLimitRequest {
            user_id: "palette-user".into(),
            max_tokens: 50_000,
            period_type: "daily".into(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("set budget: {error}\n{}", server.logs()));
    let usage = chisei
        .record_usage(RecordUsageRequest {
            user_id: "palette-user".into(),
            tokens_used: 12,
            idempotency_key: "palette-usage".into(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("record usage: {error}\n{}", server.logs()))
        .into_inner();
    assert!(
        usage
            .usage
            .as_ref()
            .is_some_and(|recorded| recorded.tokens_used >= 12),
        "budget should accept recorded usage\n{usage:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_lists_models() {
    let (_fake, mut server) = mocked_server().await;
    let socket = server.socket_str();
    let models = server.sekaictl(&[
        "models",
        "list",
        "--json",
        "--namespace",
        "demo",
        "--target",
        &socket,
    ]);
    assert_success(&models, "models list", &server.logs());
    let models_json: Value = serde_json::from_slice(&models.stdout).expect("models json");
    assert!(
        models_json.get("models").is_some(),
        "policy summary should expose models\n{models_json}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_lists_memory_candidates() {
    let (_fake, mut server) = mocked_server().await;
    let candidates = server.sekaictl(&[
        "admin",
        "governance",
        "memory",
        "candidates",
        "--namespace",
        "demo",
    ]);
    assert_success(&candidates, "memory candidates", &server.logs());
    let empty_memory = server
        .chisei()
        .await
        .list_kioku_candidates(ListKiokuCandidatesRequest {
            namespace: "demo".into(),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("list kioku: {error}\n{}", server.logs()))
        .into_inner();
    assert!(
        empty_memory.candidates.is_empty(),
        "fresh namespace should have no memory candidates"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_enriches_prompt_with_object_facts() {
    let (fake, server) = mocked_server().await;
    server.seed_context_fact().await;
    let mut chisei = server.chisei().await;
    let spec = "Inspect component:{palette-billing} for the outage";
    let plan = chisei
        .plan_execution(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: format!("palette-ctx-{}", uuid::Uuid::new_v4().simple()),
                namespace: "demo".into(),
                spec: spec.into(),
                preferred_model: MOCK_MODEL.into(),
                task_type: "question".into(),
                user_id: "palette-user".into(),
                max_tokens: 32,
                messages: vec![ChatMessage {
                    role: "user".into(),
                    content: spec.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            gunshi_allocation: None,
        })
        .await
        .unwrap_or_else(|error| panic!("plan execution: {error}\n{}", server.logs()))
        .into_inner()
        .plan
        .expect("plan");
    assert!(
        plan.executable,
        "plan should be executable\n{plan:?}\n{}",
        server.logs()
    );
    assert!(
        plan.enriched_spec.contains("[Object context]"),
        "plan should attach object context\n{}\n{}",
        plan.enriched_spec,
        server.logs()
    );
    assert!(
        plan.enriched_spec
            .contains(&format!("prior_verdict: {CONTEXT_FACT_VERDICT}")),
        "plan should inject the stored verdict\n{}",
        plan.enriched_spec
    );
    assert!(
        plan.enriched_spec
            .contains(&format!("conviction: {CONTEXT_FACT_CONVICTION}")),
        "plan should inject the stored conviction\n{}",
        plan.enriched_spec
    );
    assert!(
        plan.enriched_spec.contains("palette-billing"),
        "local ollama should keep object identity\n{}",
        plan.enriched_spec
    );

    let mut stream = chisei
        .execute_plan_stream(ExecutePlanRequest { plan: Some(plan) })
        .await
        .unwrap_or_else(|error| panic!("execute plan: {error}\n{}", server.logs()))
        .into_inner();
    while stream
        .message()
        .await
        .unwrap_or_else(|error| panic!("execute stream: {error}\n{}", server.logs()))
        .is_some()
    {}

    let prompt = fake.captured_prompt();
    assert!(
        prompt.contains("[Object context]")
            && prompt.contains(&format!("prior_verdict: {CONTEXT_FACT_VERDICT}"))
            && prompt.contains(&format!("conviction: {CONTEXT_FACT_CONVICTION}")),
        "mocked provider should receive the enriched prompt\n{prompt}\n{}",
        server.logs()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_plans_and_executes_with_mocked_llm() {
    let (_fake, server) = mocked_server().await;
    let mut chisei = server.chisei().await;
    let (_request_id, reply) = execute_mocked_plan(&server, &mut chisei).await;
    assert!(
        reply.contains(MOCK_REPLY),
        "execute should return the mocked completion, got {reply:?}\n{}",
        server.logs()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_persists_receipt() {
    let (_fake, mut server) = mocked_server().await;
    let mut chisei = server.chisei().await;
    let (request_id, _reply) = execute_mocked_plan(&server, &mut chisei).await;
    let receipt = chisei
        .get_operation_receipt(GetOperationReceiptRequest {
            request_id: request_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("get receipt: {error}\n{}", server.logs()))
        .into_inner();
    assert!(
        !receipt.receipt_json.trim().is_empty(),
        "execution should persist a receipt"
    );
    let receipt_cli = server.sekaictl(&["receipt", &request_id, "--request-id"]);
    assert_success(&receipt_cli, "receipt cli", &server.logs());
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_lookup_first_hit_skips_provider() {
    let (fake, server) = mocked_server().await;
    server.seed_lookup_object("lookup-root").await;
    let mut chisei = server.chisei().await;
    let plan = plan_resolve_ref(&server, &mut chisei, r#"{"object_id":"lookup-root"}"#).await;
    assert!(
        plan.executable,
        "lookup-first hit should still plan as executable\n{plan:?}\n{}",
        server.logs()
    );
    let response = collect_execute(&server, &mut chisei, plan).await;
    assert_eq!(response.provider, LOOKUP_PROVIDER);
    assert_eq!(response.stop_reason, LOOKUP_HIT_STOP_REASON);
    assert_eq!(response.input_tokens, 0);
    assert_eq!(response.output_tokens, 0);
    assert!(
        response.content.contains("lookup-root"),
        "lookup hit should return the object\n{}",
        response.content
    );
    assert!(
        fake.captured_prompt().is_empty(),
        "lookup hit must not call the provider\n{}\n{}",
        fake.captured_prompt(),
        server.logs()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_lookup_first_miss_uses_model_path() {
    let (fake, server) = mocked_server().await;
    let mut chisei = server.chisei().await;
    let plan = plan_resolve_ref(&server, &mut chisei, r#"{"object_id":"does-not-exist"}"#).await;
    assert!(
        plan.executable,
        "incomplete lookup should fail closed to an executable model path\n{plan:?}\n{}",
        server.logs()
    );
    let request_id = plan.input.as_ref().expect("plan input").request_id.clone();
    let response = collect_execute(&server, &mut chisei, plan).await;
    assert_ne!(response.provider, LOOKUP_PROVIDER);
    assert!(
        !fake.captured_prompt().is_empty(),
        "lookup miss should call the mocked provider\n{}",
        server.logs()
    );
    let receipt = chisei
        .get_operation_receipt(GetOperationReceiptRequest {
            request_id,
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("get receipt: {error}\n{}", server.logs()))
        .into_inner()
        .receipt_json;
    assert!(
        receipt.contains(LOOKUP_REFUSAL_ATTR) && receipt.contains("incomplete"),
        "receipt should record lookup_refusal=incomplete\n{receipt}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_budget_denies_unaffordable_plan() {
    let (_fake, server) = mocked_server().await;
    let mut chisei = server.chisei().await;
    chisei
        .set_budget_limit(SetBudgetLimitRequest {
            user_id: "broke-user".into(),
            max_tokens: 1,
            period_type: "daily".into(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("set budget: {error}\n{}", server.logs()));
    let plan = chisei
        .plan_execution(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: format!("palette-budget-{}", uuid::Uuid::new_v4().simple()),
                namespace: "demo".into(),
                spec: "This request is intentionally too expensive for a one-token budget.".into(),
                preferred_model: MOCK_MODEL.into(),
                task_type: "question".into(),
                user_id: "broke-user".into(),
                max_tokens: 32,
                ..Default::default()
            }),
            gunshi_allocation: None,
        })
        .await
        .unwrap_or_else(|error| panic!("plan execution: {error}\n{}", server.logs()))
        .into_inner()
        .plan
        .expect("plan");
    assert!(
        !plan.executable,
        "plan should be refused when the estimate exceeds the budget\n{plan:?}\n{}",
        server.logs()
    );
    let budget = plan.budget.expect("budget verdict");
    assert!(!budget.allowed, "budget verdict should deny\n{budget:?}");
    assert!(
        budget.reason.contains("budget exceeded"),
        "deny reason should name the budget\n{}",
        budget.reason
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_accepts_principal_credential_over_uds() {
    let (_fake, mut server) = mocked_server().await;
    let created = server.sekaictl(&["admin", "access", "credential", "create", "palette-agent"]);
    assert_success(&created, "credential create", &server.logs());
    let token = stdout(&created).trim().to_string();
    assert!(!token.is_empty(), "create should print a bearer token");

    let mut chisei = server.chisei().await;
    let local = chisei
        .get_effective_policy_summary(GetEffectivePolicySummaryRequest {
            namespace: "demo".into(),
            provider: String::new(),
        })
        .await
        .unwrap_or_else(|error| panic!("local UDS policy summary: {error}\n{}", server.logs()));
    assert_eq!(local.into_inner().namespace, "demo");

    let denied = chisei
        .get_effective_policy_summary(bearer(
            &token,
            GetEffectivePolicySummaryRequest {
                namespace: "demo".into(),
                provider: String::new(),
            },
        ))
        .await
        .expect_err("palette-agent has no namespace grant");
    assert_eq!(
        denied.code(),
        Code::PermissionDenied,
        "valid credential should authenticate and then fail ACL, not Unauthenticated: {denied}\n{}",
        server.logs()
    );
    assert!(
        denied.message().contains("namespace access denied"),
        "credential principal must not inherit UDS local: {denied}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_grant_then_allows_credential() {
    let (_fake, mut server) = mocked_server().await;
    let token = server.create_principal_token("palette-agent");
    let mut chisei = server.chisei().await;
    let denied = chisei
        .get_effective_policy_summary(bearer(
            &token,
            GetEffectivePolicySummaryRequest {
                namespace: "demo".into(),
                provider: String::new(),
            },
        ))
        .await
        .expect_err("palette-agent has no namespace grant yet");
    assert_eq!(denied.code(), Code::PermissionDenied);

    server
        .grant_namespace("demo", "palette-agent", "viewer")
        .await;

    let allowed = chisei
        .get_effective_policy_summary(bearer(
            &token,
            GetEffectivePolicySummaryRequest {
                namespace: "demo".into(),
                provider: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "granted principal should read policy: {error}\n{}",
                server.logs()
            )
        })
        .into_inner();
    assert_eq!(allowed.namespace, "demo");
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_rotates_and_revokes_credential() {
    let (_fake, mut server) = mocked_server().await;
    let token = server.create_principal_token("palette-agent");
    server
        .grant_namespace("demo", "palette-agent", "viewer")
        .await;
    let mut chisei = server.chisei().await;

    chisei
        .get_effective_policy_summary(bearer(
            &token,
            GetEffectivePolicySummaryRequest {
                namespace: "demo".into(),
                provider: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("original token should work: {error}\n{}", server.logs()));

    let rotated = server.sekaictl(&["admin", "access", "credential", "rotate", "palette-agent"]);
    assert_success(&rotated, "credential rotate", &server.logs());
    let rotated_token = stdout(&rotated).trim().to_string();
    assert!(!rotated_token.is_empty(), "rotate should print a new token");
    assert_ne!(rotated_token, token, "rotate should replace the secret");

    let stale = chisei
        .get_effective_policy_summary(bearer(
            &token,
            GetEffectivePolicySummaryRequest {
                namespace: "demo".into(),
                provider: String::new(),
            },
        ))
        .await
        .expect_err("rotated-away token must fail");
    assert_eq!(
        stale.code(),
        Code::Unauthenticated,
        "old token after rotate should be Unauthenticated: {stale}\n{}",
        server.logs()
    );

    chisei
        .get_effective_policy_summary(bearer(
            &rotated_token,
            GetEffectivePolicySummaryRequest {
                namespace: "demo".into(),
                provider: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("rotated token should work: {error}\n{}", server.logs()));

    let revoked = server.sekaictl(&["admin", "access", "credential", "revoke", "palette-agent"]);
    assert_success(&revoked, "credential revoke", &server.logs());

    let dead = chisei
        .get_effective_policy_summary(bearer(
            &rotated_token,
            GetEffectivePolicySummaryRequest {
                namespace: "demo".into(),
                provider: String::new(),
            },
        ))
        .await
        .expect_err("revoked token must fail");
    assert_eq!(
        dead.code(),
        Code::Unauthenticated,
        "token after revoke should be Unauthenticated: {dead}\n{}",
        server.logs()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_keeps_tcp_closed_without_insecure() {
    let server = NativeServer::spawn();
    assert!(
        !tcp_open(server.grpc_port),
        "TCP 127.0.0.1:{} should stay closed without SEKAI_INSECURE or a durable credential\n{}",
        server.grpc_port,
        server.logs()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_rejects_invalid_bearer() {
    let server = NativeServer::spawn();
    let mut client = server.chisei().await;
    let mut request = Request::new(GetEffectivePolicySummaryRequest {
        namespace: "demo".into(),
        provider: String::new(),
    });
    request.metadata_mut().insert(
        "authorization",
        "Bearer definitely-not-a-credential"
            .parse()
            .expect("metadata"),
    );
    let error = client
        .get_effective_policy_summary(request)
        .await
        .expect_err("invalid bearer must fail");
    assert_eq!(
        error.code(),
        Code::Unauthenticated,
        "invalid bearer should be unauthenticated, got {error}\n{}",
        server.logs()
    );
}

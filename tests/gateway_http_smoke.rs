//! Process-level HTTP smoke for the shipped `chisei-gateway` binary.
//!
//! Native gRPC smoke never starts the gateway. This file starts `sekai-chisei`,
//! `sekaictl admin gateway setup`, a loopback OpenAI/Anthropic fake, and the
//! compiled gateway, then drives the public HTTP routes.

#![cfg(unix)]

use std::io::Read;
use std::net::TcpListener as StdTcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::Uri;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::any;
use serde_json::{Value, json};
use tokio::sync::watch;

const WAIT_BUDGET: Duration = Duration::from_secs(20);
const CODEX_KEY: &str = "sk-chisei-codex-app";
const CLAUDE_KEY: &str = "sk-chisei-claude-code";
const RESPONSES_REPLY: &str = "chisei gateway responses smoke ok";
const MESSAGES_REPLY: &str = "chisei gateway messages smoke ok";

#[derive(Clone)]
struct FakeState {
    captured: Arc<Mutex<Vec<String>>>,
}

struct FakeUpstream {
    url: String,
    captured: Arc<Mutex<Vec<String>>>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeUpstream {
    async fn spawn() -> Self {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, mut stopped) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake upstream");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("fake upstream addr")
        );
        let app = Router::new()
            .fallback(any(fake_provider))
            .with_state(FakeState {
                captured: captured.clone(),
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.changed().await;
                })
                .await
                .expect("fake upstream serve");
        });
        Self {
            url,
            captured,
            shutdown,
            task,
        }
    }

    fn hit_count(&self) -> usize {
        self.captured.lock().expect("capture").len()
    }

    fn openai_base(&self) -> String {
        format!("{}/v1", self.url.trim_end_matches('/'))
    }

    fn anthropic_base(&self) -> String {
        self.openai_base()
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

async fn fake_provider(State(state): State<FakeState>, uri: Uri, body: Bytes) -> impl IntoResponse {
    let path = uri.path().to_string();
    state.captured.lock().expect("capture").push(path.clone());
    let parsed: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    let stream = parsed
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if path.contains("/messages") && !path.contains("count_tokens") {
        if stream {
            let sse = format!(
                "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{}}}}\n\n\
                 event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":{MESSAGES_REPLY:?}}}}}\n\n\
                 event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
            );
            return ([(CONTENT_TYPE, "text/event-stream")], sse).into_response();
        }
        return Json(json!({
            "id": "msg_smoke",
            "type": "message",
            "role": "assistant",
            "model": parsed.get("model").and_then(Value::as_str).unwrap_or("claude-sonnet-4-8"),
            "content": [{ "type": "text", "text": MESSAGES_REPLY }],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 5, "output_tokens": 3 }
        }))
        .into_response();
    }
    if path.contains("/chat/completions") {
        if stream {
            let delta = json!({"id":"chatcmpl_smoke","object":"chat.completion.chunk","choices":[{"delta":{"content": RESPONSES_REPLY},"finish_reason":null}]});
            let done = json!({"id":"chatcmpl_smoke","object":"chat.completion.chunk","choices":[{"delta":{},"finish_reason":"stop"}]});
            let sse = format!("data: {delta}\n\ndata: {done}\n\ndata: [DONE]\n\n");
            return ([(CONTENT_TYPE, "text/event-stream")], sse).into_response();
        }
        return Json(json!({
            "id": "chatcmpl_smoke",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": RESPONSES_REPLY },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 6, "completion_tokens": 4, "total_tokens": 10 }
        }))
        .into_response();
    }
    if stream {
        let sse = format!(
            "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"delta\":{RESPONSES_REPLY:?}}}\n\n\
             event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"resp_smoke\",\"status\":\"completed\",\"output\":[{{\"type\":\"message\",\"content\":[{{\"type\":\"output_text\",\"text\":{RESPONSES_REPLY:?}}}]}}]}}}}\n\n"
        );
        return ([(CONTENT_TYPE, "text/event-stream")], sse).into_response();
    }
    Json(json!({
        "id": "resp_smoke",
        "object": "response",
        "status": "completed",
        "model": parsed.get("model").and_then(Value::as_str).unwrap_or("gpt-5.5"),
        "output": [{
            "id": "msg_smoke",
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{ "type": "output_text", "text": RESPONSES_REPLY, "annotations": [] }]
        }],
        "usage": { "input_tokens": 7, "output_tokens": 5, "total_tokens": 12 }
    }))
    .into_response()
}

struct KillOnDrop(Option<Child>);

impl KillOnDrop {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct GatewayStack {
    fake: FakeUpstream,
    control_plane: KillOnDrop,
    /// Kept so Drop kills the gateway process.
    #[allow(dead_code)]
    gateway: KillOnDrop,
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    base: String,
    log_path: PathBuf,
    gateway_log_path: PathBuf,
}

impl GatewayStack {
    async fn spawn() -> Self {
        let fake = FakeUpstream::spawn().await;
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("sekai.sock");
        let db_path = dir.path().join("sekai.db");
        let log_path = dir.path().join("sekai.log");
        let gateway_log_path = dir.path().join("gateway.log");
        let grpc_port = free_tcp_port();
        let log = std::fs::File::create(&log_path).expect("control-plane log");
        let mut control_plane = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"));
        control_plane
            .env("SEKAI_SOCKET", &socket)
            .env("DB_PATH", &db_path)
            .env("GRPC_PORT", grpc_port.to_string())
            .env("OPS_PORT", "")
            .env("OPS_BIND", "127.0.0.1")
            .env("RUST_LOG", "error")
            .env("OPENAI_API_KEY", "control-plane-openai-smoke-key")
            .env("ANTHROPIC_API_KEY", "control-plane-anthropic-smoke-key")
            .env_remove("SEKAI_INSECURE")
            .env_remove("SEKAI_CREDENTIAL")
            .env_remove("SEKAI_BIND")
            .env_remove("SEKAI_DB_BACKEND")
            .env_remove("DATABASE_URL")
            .env_remove("SEKAI_DB_PATH")
            .env_remove("CHISEI_DB_PATH")
            .env_remove("SEKAI_DATABASE_URL")
            .env_remove("CHISEI_DATABASE_URL")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log));
        let control_plane = KillOnDrop::new(control_plane.spawn().expect("spawn sekai-chisei"));
        wait_for_socket(&socket, &log_path);

        let setup_codex = sekaictl(
            &socket,
            &log_path,
            &[
                "admin",
                "gateway",
                "setup",
                "--agent",
                "codex-app",
                "--project",
                "sekai-chisei",
                "--gateway-key-name",
                "codex-app",
                "--gateway-key",
                CODEX_KEY,
                "--budget",
                "500000",
                "--budget-period",
                "day",
                "--default-runtime",
                "openai",
                "--default-model",
                "gpt-5.5",
                "--allowed-model",
                "gpt-5.5",
            ],
        );
        assert_success(&setup_codex, "gateway setup codex", &logs(&log_path));

        let setup_claude = sekaictl(
            &socket,
            &log_path,
            &[
                "admin",
                "gateway",
                "setup",
                "--agent",
                "claude-code",
                "--project",
                "default",
                "--gateway-key-name",
                "claude-code",
                "--gateway-key",
                CLAUDE_KEY,
                "--budget",
                "500000",
                "--budget-period",
                "day",
                "--default-runtime",
                "anthropic",
                "--default-model",
                "claude-sonnet-4-8",
                "--allowed-model",
                "claude-sonnet-4-8",
            ],
        );
        assert_success(&setup_claude, "gateway setup claude", &logs(&log_path));

        let mut gateway = None;
        let mut base = String::new();
        for attempt in 1..=10 {
            let gateway_port = free_tcp_port();
            let attempt_log = dir.path().join(format!("gateway-{attempt}.log"));
            let log_file = std::fs::File::create(&attempt_log).expect("gateway log");
            let child = Command::new(chisei_gateway_bin())
                .env("SEKAI_SOCKET", &socket)
                .env("DB_PATH", &db_path)
                .env("GATEWAY_BIND", format!("127.0.0.1:{gateway_port}"))
                .env("CHISEI_OPENAI_BASE_URL", fake.openai_base())
                .env("CHISEI_ANTHROPIC_BASE_URL", fake.anthropic_base())
                .env("OPENAI_API_KEY", "control-plane-openai-smoke-key")
                .env("ANTHROPIC_API_KEY", "control-plane-anthropic-smoke-key")
                .env("CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH", "1")
                .env("CHISEI_GATEWAY_CONTROL_PLANE_RETRIES", "0")
                .env("CHISEI_GATEWAY_CONTROL_PLANE_TIMEOUT_MS", "5000")
                .env(
                    "CHISEI_GATEWAY_USAGE_RECOVERY_PATH",
                    dir.path().join("usage-recovery.json"),
                )
                .env(
                    "CHISEI_GATEWAY_RECOVERY_SPOOL_PATH",
                    dir.path().join("recovery-spool"),
                )
                .env(
                    "CHISEI_GATEWAY_PRICING",
                    "gpt-5.5=1:2,claude-sonnet-4-8=3:15",
                )
                .env("RUST_LOG", "error")
                .env_remove("CHISEI_GRPC_URL")
                .stdout(Stdio::from(
                    log_file.try_clone().expect("clone gateway log"),
                ))
                .stderr(Stdio::from(log_file))
                .spawn()
                .expect("spawn chisei-gateway");
            let candidate = format!("http://127.0.0.1:{gateway_port}");
            if wait_for_http(
                &format!("{candidate}/healthz"),
                &attempt_log,
                Duration::from_secs(2),
            )
            .await
            {
                let _ = std::fs::copy(&attempt_log, &gateway_log_path);
                gateway = Some(child);
                base = candidate;
                break;
            }
            let _ = {
                let mut child = child;
                let _ = child.kill();
                child.wait()
            };
        }
        let gateway = KillOnDrop::new(gateway.unwrap_or_else(|| {
            panic!(
                "failed to start chisei-gateway after port retries\n{}",
                logs(&gateway_log_path)
            )
        }));
        Self {
            fake,
            control_plane,
            gateway,
            dir,
            base,
            log_path,
            gateway_log_path,
        }
    }

    fn logs(&self) -> String {
        format!(
            "control plane:\n{}\ngateway:\n{}",
            logs(&self.log_path),
            logs(&self.gateway_log_path)
        )
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        http_client()
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap_or_else(|error| panic!("GET {path}: {error}\n{}", self.logs()))
    }

    async fn post_json(
        &self,
        path: &str,
        headers: &[(&str, &str)],
        body: Value,
    ) -> reqwest::Response {
        let mut request = http_client()
            .post(format!("{}{path}", self.base))
            .json(&body);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request
            .send()
            .await
            .unwrap_or_else(|error| panic!("POST {path}: {error}\n{}", self.logs()))
    }

    fn kill_control_plane(&mut self) {
        if let Some(mut child) = self.control_plane.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn chisei_gateway_bin() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let sekaictl = PathBuf::from(env!("CARGO_BIN_EXE_sekaictl"));
            let target_dir = sekaictl
                .parent()
                .and_then(Path::parent)
                .expect("cargo target dir");
            let mut cmd = Command::new(env!("CARGO"));
            cmd.args([
                "build",
                "-p",
                "chisei-gateway",
                "--bin",
                "chisei-gateway",
                "--locked",
                "--message-format=json",
                "--target-dir",
            ])
            .arg(target_dir)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stderr(Stdio::piped());
            if !cfg!(debug_assertions) {
                cmd.arg("--release");
            }
            let output = cmd.output().expect("build chisei-gateway");
            assert!(
                output.status.success(),
                "failed to build chisei-gateway: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            artifact_executable(&output.stdout).unwrap_or_else(|| {
                let mut bin = sekaictl;
                bin.set_file_name("chisei-gateway");
                assert!(
                    bin.is_file(),
                    "chisei-gateway binary missing at {}",
                    bin.display()
                );
                bin
            })
        })
        .clone()
}

fn artifact_executable(stdout: &[u8]) -> Option<PathBuf> {
    String::from_utf8_lossy(stdout)
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|message| {
            if message.get("reason").and_then(Value::as_str) != Some("compiler-artifact") {
                return None;
            }
            let is_gateway =
                message.pointer("/target/name").and_then(Value::as_str) == Some("chisei-gateway");
            if !is_gateway {
                return None;
            }
            message
                .get("executable")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .expect("http client")
}

fn free_tcp_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn logs(path: &Path) -> String {
    let mut contents = String::new();
    if let Ok(mut file) = std::fs::File::open(path) {
        let _ = file.read_to_string(&mut contents);
    }
    contents
}

fn wait_for_socket(socket: &Path, log_path: &Path) {
    let deadline = Instant::now() + WAIT_BUDGET;
    loop {
        if UnixStream::connect(socket).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {}\n{}",
                socket.display(),
                logs(log_path)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn wait_for_http(url: &str, log_path: &Path, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    let client = http_client();
    loop {
        if let Ok(response) = client.get(url).send().await
            && response.status().is_success()
        {
            return true;
        }
        if Instant::now() >= deadline {
            let _ = log_path;
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn sekaictl(socket: &Path, log_path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sekaictl"))
        .args(args)
        .env("SEKAI_SOCKET", socket)
        .env_remove("CHISEI_GRPC_URL")
        .env_remove("SEKAI_CREDENTIAL")
        .output()
        .unwrap_or_else(|error| panic!("sekaictl {args:?}: {error}\n{}", logs(log_path)))
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

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_serves_healthz() {
    let stack = GatewayStack::spawn().await;
    let response = stack.get("/healthz").await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "healthz\n{}",
        stack.logs()
    );
    let body: Value = response.json().await.expect("healthz json");
    assert_eq!(body["status"], "healthy");
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_rejects_missing_key() {
    let stack = GatewayStack::spawn().await;
    let response = stack
        .post_json(
            "/v1/responses",
            &[("content-type", "application/json")],
            json!({"model": "gpt-5.5", "input": "hello"}),
        )
        .await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "missing key should be 401\n{}\n{}",
        response.text().await.unwrap_or_default(),
        stack.logs()
    );
    assert_eq!(
        stack.fake.hit_count(),
        0,
        "missing key must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_rejects_wrong_key() {
    let stack = GatewayStack::spawn().await;
    let response = stack
        .post_json(
            "/v1/responses",
            &[
                ("authorization", "Bearer sk-definitely-not-a-gateway-key"),
                ("content-type", "application/json"),
            ],
            json!({"model": "gpt-5.5", "input": "hello"}),
        )
        .await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "wrong key should be 401\n{}\n{}",
        response.text().await.unwrap_or_default(),
        stack.logs()
    );
    assert_eq!(
        stack.fake.hit_count(),
        0,
        "wrong key must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_rejects_disallowed_model() {
    let stack = GatewayStack::spawn().await;
    let response = stack
        .post_json(
            "/v1/responses",
            &[
                ("authorization", &format!("Bearer {CODEX_KEY}")),
                ("content-type", "application/json"),
            ],
            json!({"model": "claude-sonnet-4-8", "input": "hello"}),
        )
        .await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::FORBIDDEN,
        "cross-provider / disallowed model should be 403\n{}\n{}",
        response.text().await.unwrap_or_default(),
        stack.logs()
    );
    assert_eq!(
        stack.fake.hit_count(),
        0,
        "disallowed model must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_proxies_chat_completions() {
    let stack = GatewayStack::spawn().await;
    let response = stack
        .post_json(
            "/v1/chat/completions",
            &[
                ("authorization", &format!("Bearer {CODEX_KEY}")),
                ("content-type", "application/json"),
            ],
            json!({
                "model": "gpt-5.5",
                "messages": [{ "role": "user", "content": "hello gateway" }]
            }),
        )
        .await;
    let status = response.status();
    let body = response.text().await.expect("chat completions body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "chat/completions\n{body}\n{}",
        stack.logs()
    );
    assert!(
        body.contains(RESPONSES_REPLY),
        "chat/completions should include the fake completion\n{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_streams_openai_responses() {
    let stack = GatewayStack::spawn().await;
    let response = stack
        .post_json(
            "/v1/responses",
            &[
                ("authorization", &format!("Bearer {CODEX_KEY}")),
                ("content-type", "application/json"),
            ],
            json!({"model": "gpt-5.5", "input": "hello stream", "stream": true}),
        )
        .await;
    let status = response.status();
    let body = response.text().await.expect("stream body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "streamed responses\n{body}\n{}",
        stack.logs()
    );
    assert!(
        body.contains(RESPONSES_REPLY),
        "stream should include the fake completion\n{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_streams_anthropic_messages() {
    let stack = GatewayStack::spawn().await;
    let response = stack
        .post_json(
            "/v1/messages",
            &[
                ("x-api-key", CLAUDE_KEY),
                ("content-type", "application/json"),
            ],
            json!({
                "model": "claude-sonnet-4-8",
                "max_tokens": 16,
                "stream": true,
                "messages": [{ "role": "user", "content": "hello stream" }]
            }),
        )
        .await;
    let status = response.status();
    let body = response.text().await.expect("anthropic stream body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "streamed messages\n{body}\n{}",
        stack.logs()
    );
    assert!(
        body.contains(MESSAGES_REPLY),
        "anthropic stream should include the fake completion\n{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_serves_readyz() {
    let stack = GatewayStack::spawn().await;
    let response = stack.get("/readyz").await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "readyz with a live control plane\n{}\n{}",
        response.text().await.unwrap_or_default(),
        stack.logs()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_fail_closed_when_control_plane_down() {
    let mut stack = GatewayStack::spawn().await;
    stack.kill_control_plane();
    let response = stack
        .post_json(
            "/v1/responses",
            &[
                ("authorization", &format!("Bearer {CODEX_KEY}")),
                ("content-type", "application/json"),
            ],
            json!({"model": "gpt-5.5", "input": "hello"}),
        )
        .await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "dead control plane should fail closed\n{}\n{}",
        response.text().await.unwrap_or_default(),
        stack.logs()
    );
    assert_eq!(
        stack.fake.hit_count(),
        0,
        "dead control plane must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_proxies_openai_responses() {
    let stack = GatewayStack::spawn().await;
    let response = stack
        .post_json(
            "/v1/responses",
            &[
                ("authorization", &format!("Bearer {CODEX_KEY}")),
                ("content-type", "application/json"),
            ],
            json!({"model": "gpt-5.5", "input": "hello gateway"}),
        )
        .await;
    let status = response.status();
    let body = response.text().await.expect("responses body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "responses\n{body}\n{}",
        stack.logs()
    );
    assert!(
        body.contains(RESPONSES_REPLY),
        "responses body should include the fake completion\n{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_proxies_anthropic_messages() {
    let stack = GatewayStack::spawn().await;
    let response = stack
        .post_json(
            "/v1/messages",
            &[
                ("x-api-key", CLAUDE_KEY),
                ("content-type", "application/json"),
            ],
            json!({
                "model": "claude-sonnet-4-8",
                "max_tokens": 16,
                "messages": [{ "role": "user", "content": "hello gateway" }]
            }),
        )
        .await;
    let status = response.status();
    let body = response.text().await.expect("messages body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "messages\n{body}\n{}",
        stack.logs()
    );
    assert!(
        body.contains(MESSAGES_REPLY),
        "messages body should include the fake completion\n{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_gateway_lists_models() {
    let stack = GatewayStack::spawn().await;
    let response = http_client()
        .get(format!("{}/v1/models", stack.base))
        .header("authorization", format!("Bearer {CODEX_KEY}"))
        .send()
        .await
        .unwrap_or_else(|error| panic!("GET /v1/models: {error}\n{}", stack.logs()));
    let status = response.status();
    let body = response.text().await.expect("models body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "models\n{body}\n{}",
        stack.logs()
    );
    assert!(
        body.contains("gpt-5.5") || body.contains("data"),
        "models list should be non-empty JSON\n{body}"
    );
}

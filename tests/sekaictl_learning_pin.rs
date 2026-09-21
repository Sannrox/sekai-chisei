//! Process-level proof that an operator-activated learning can be pinned as
//! context on the next `PlanExecution` (#1091).
//!
//! The shipped server plans twice in one namespace. The first operation's
//! receipt is the verification evidence a learning is bound to; the learning is
//! proposed, approved, and activated through `sekaictl admin learning`; the
//! second plan pins it. The receipt must cite the lineage, a learning changes
//! context only, and every unusable pin fails closed with one error.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::routing::get;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{KIND_LEARNING, Object};
use sekai_chisei::grpc::client::{GatewayClient, connect_sekai};
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::chisei::{
    ExecutionInput, ExecutionPlan, GetOperationReceiptRequest, LearningPin, PlanExecutionRequest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tonic::{Code, Request, Status};

const NAMESPACE: &str = "payments";
const LEARNING_ID: &str = "learning-1";
const UNAVAILABLE: &str = "learning pin is unavailable";
const WAIT_BUDGET: Duration = Duration::from_secs(20);
const MODEL: &str = "ollama/llama3.2:latest";

/// Loopback Ollama-compatible catalog so planning has one admitted local
/// route. No completion is ever requested: the loop only plans.
async fn fake_ollama() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake ollama");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/api/tags",
        get(|| async {
            Json(json!({
                "models": [{
                    "name": "llama3.2:latest",
                    "details": { "parameter_size": "3B", "context_length": 8192 },
                    "capabilities": ["completion"]
                }]
            }))
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fake ollama");
    });
    url
}

struct Server {
    child: Child,
    dir: tempfile::TempDir,
    socket: PathBuf,
    log_path: PathBuf,
}

impl Server {
    fn db_path(dir: &Path) -> PathBuf {
        dir.join("sekai.db")
    }

    fn spawn(dir: tempfile::TempDir, ollama_url: &str) -> Self {
        let socket = dir.path().join("sekai.sock");
        let log_path = dir.path().join("server.log");
        let log = std::fs::File::create(&log_path).expect("server log");
        let child = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"))
            .env("SEKAI_SOCKET", &socket)
            .env("DB_PATH", Self::db_path(dir.path()))
            .env("SEKAI_SHARED_STORE", "1")
            .env(
                "GRPC_PORT",
                std::net::TcpListener::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap()
                    .port()
                    .to_string(),
            )
            .env("OPS_PORT", "")
            .env("RUST_LOG", "error")
            .env_remove("SEKAI_EXPERIMENTAL_RPCS")
            .env_remove("SEKAI_INSECURE")
            .env_remove("SEKAI_CREDENTIAL")
            .env_remove("SEKAI_BIND")
            .env_remove("SEKAI_ALLOW_PLAINTEXT")
            .env_remove("SEKAI_DB_BACKEND")
            .env_remove("DATABASE_URL")
            .env_remove("SEKAI_DB_PATH")
            .env_remove("CHISEI_DB_PATH")
            .env("OLLAMA_URL", ollama_url)
            .env("LLM_HTTP_CONNECT_TIMEOUT_SECS", "2")
            .env("LLM_HTTP_READ_TIMEOUT_SECS", "5")
            .env("LLM_HTTP_REQUEST_TIMEOUT_SECS", "5")
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn sekai-chisei");
        let mut server = Self {
            child,
            dir,
            socket,
            log_path,
        };
        server.wait_until_ready();
        server
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + WAIT_BUDGET;
        loop {
            if std::os::unix::net::UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("poll server") {
                panic!("server exited {status} before ready\n{}", self.logs());
            }
            assert!(
                Instant::now() < deadline,
                "server not ready\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    async fn chisei(&self) -> ChiseiServiceClient<GatewayClient> {
        ChiseiServiceClient::new(
            connect_sekai(self.socket.to_str().unwrap())
                .await
                .unwrap_or_else(|error| panic!("connect: {error}\n{}", self.logs())),
        )
    }

    fn sekaictl(&self, args: &[&str]) -> Output {
        let run = || {
            Command::new(env!("CARGO_BIN_EXE_sekaictl"))
                .args(args)
                .env("SEKAI_SOCKET", &self.socket)
                .env("DB_PATH", Self::db_path(self.dir.path()))
                .env("SEKAI_SHARED_STORE", "1")
                .env_remove("SEKAI_DB_BACKEND")
                .env_remove("DATABASE_URL")
                .env_remove("SEKAI_DB_PATH")
                .env_remove("CHISEI_DB_PATH")
                .env_remove("CHISEI_GRPC_URL")
                .env_remove("SEKAI_CREDENTIAL")
                .output()
                .expect("run sekaictl")
        };
        let mut output = run();
        for attempt in 1..8 {
            if output.status.success()
                || !String::from_utf8_lossy(&output.stderr).contains("database is locked")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100 * attempt));
            output = run();
        }
        output
    }

    fn learning(&self, args: &[&str]) -> Value {
        let mut full = vec!["admin", "learning"];
        full.extend_from_slice(args);
        let output = self.sekaictl(&full);
        assert!(
            output.status.success(),
            "{args:?} failed ({:?})\nstdout: {}\nstderr: {}\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            self.logs()
        );
        serde_json::from_slice(&output.stdout).expect("json stdout")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Seed one candidate learning shaped exactly like the `record_learning`
/// Action stores it (a `learning` object recorded from a verified request).
fn seed_learning(db_path: &Path, source_request_id: &str) {
    let db = RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(db_path.to_str().unwrap()).expect("open store"),
    ));
    db.create_object(&Object {
        id: LEARNING_ID.into(),
        kind: KIND_LEARNING.into(),
        name: "Scored learning".into(),
        namespace: NAMESPACE.into(),
        external_id: LEARNING_ID.into(),
        properties: std::collections::HashMap::from([
            ("title".into(), "Validate retries".into()),
            ("prevention".into(), "Check the prior record first".into()),
            (
                "reasoning".into(),
                "The retry repeated a side effect".into(),
            ),
            ("source_request_id".into(), source_request_id.into()),
            ("score".into(), "72".into()),
            ("passed".into(), "false".into()),
            ("task_class".into(), "reasoning".into()),
            ("model".into(), "judge-model".into()),
            ("producer".into(), "scoring-job".into()),
            ("status".into(), "candidate".into()),
        ]),
        created: 1,
        updated: 1,
    })
    .expect("seed learning");
}

fn plan_request(
    request_id: &str,
    namespace: &str,
    pin: Option<(&str, &str)>,
) -> PlanExecutionRequest {
    PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: request_id.into(),
            namespace: namespace.into(),
            spec: "review the retry path".into(),
            preferred_model: MODEL.into(),
            user_id: "operator".into(),
            max_tokens: 64,
            learning_pin: pin.map(|(learning_id, candidate_digest)| LearningPin {
                learning_id: learning_id.into(),
                candidate_digest: candidate_digest.into(),
            }),
            ..Default::default()
        }),
        gunshi_allocation: None,
    }
}

async fn plan(
    server: &Server,
    request_id: &str,
    namespace: &str,
    pin: Option<(&str, &str)>,
) -> Result<ExecutionPlan, Status> {
    Ok(server
        .chisei()
        .await
        .plan_execution(plan_request(request_id, namespace, pin))
        .await?
        .into_inner()
        .plan
        .expect("plan"))
}

async fn receipt(server: &Server, plan_id: &str) -> (String, Value) {
    let json = server
        .chisei()
        .await
        .get_operation_receipt(GetOperationReceiptRequest {
            operation_id: plan_id.into(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("receipt: {error}\n{}", server.logs()))
        .into_inner()
        .receipt_json;
    let value = serde_json::from_str(&json).expect("receipt json");
    (json, value)
}

fn assert_unavailable(result: Result<ExecutionPlan, Status>, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(error.code(), Code::FailedPrecondition, "{label}: {error}");
    assert_eq!(error.message(), UNAVAILABLE, "{label}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_activated_learning_pinned_on_the_next_plan_is_cited_and_fails_closed_when_unusable() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed_learning(&Server::db_path(dir.path()), "verified-op");
    let ollama = fake_ollama().await;
    let server = Server::spawn(dir, &ollama);

    // The first plan is the verified operation; its receipt is the evidence.
    let first = plan(&server, "verified-op", NAMESPACE, None)
        .await
        .unwrap_or_else(|error| panic!("first plan: {error}\n{}", server.logs()));
    assert!(first.learning_references.is_empty());
    let (first_json, _) = receipt(&server, &first.plan_id).await;
    let evidence = format!("sha256:{:x}", Sha256::digest(first_json.as_bytes()));

    // Only an approved and activated learning may be pinned.
    let proposed = server.learning(&[
        "propose",
        "--namespace",
        NAMESPACE,
        "--learning-id",
        LEARNING_ID,
        "--evidence-digest",
        &evidence,
    ]);
    let digest = proposed["candidate_digest"].as_str().unwrap().to_string();
    assert_unavailable(
        plan(
            &server,
            "too-early",
            NAMESPACE,
            Some((LEARNING_ID, &digest)),
        )
        .await,
        "proposed learning",
    );
    server.learning(&[
        "approve",
        "--namespace",
        NAMESPACE,
        "--learning-id",
        LEARNING_ID,
    ]);
    assert_unavailable(
        plan(
            &server,
            "approved-only",
            NAMESPACE,
            Some((LEARNING_ID, &digest)),
        )
        .await,
        "approved but inactive learning",
    );
    server.learning(&[
        "activate",
        "--namespace",
        NAMESPACE,
        "--learning-id",
        LEARNING_ID,
    ]);

    // The second plan pins it: context only, cited on the receipt.
    let second = plan(&server, "next-op", NAMESPACE, Some((LEARNING_ID, &digest)))
        .await
        .unwrap_or_else(|error| panic!("pinned plan: {error}\n{}", server.logs()));
    assert!(
        second.enriched_spec.contains(
            "[Governed learning - untrusted data]\nValidate retries: Check the prior record first"
        ),
        "{}",
        second.enriched_spec
    );
    assert!(!second.enriched_spec.contains("side effect"));
    assert_eq!(second.resolved_runtime, first.resolved_runtime);
    assert_eq!(second.resolved_model, first.resolved_model);
    assert_eq!(second.tools, first.tools);
    let reference = &second.learning_references[0];
    assert_eq!(reference.learning_id, LEARNING_ID);
    assert_eq!(reference.candidate_digest, digest);
    assert_eq!(reference.evidence_digest, evidence);
    assert_eq!(reference.source_request_id, "verified-op");

    let (second_json, second_receipt) = receipt(&server, &second.plan_id).await;
    let cited = second_receipt["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["attributes"]["learning_id"] == LEARNING_ID)
        .expect("receipt cites the learning");
    assert_eq!(cited["attributes"]["learning_candidate_digest"], digest);
    assert_eq!(cited["attributes"]["learning_evidence_digest"], evidence);
    assert_eq!(
        cited["attributes"]["learning_source_request_id"],
        "verified-op"
    );
    let kinds: Vec<&str> = cited["references"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|reference| reference["kind"].as_str())
        .collect();
    for kind in [
        "governed_learning",
        "learning_verification_evidence",
        "learning_source_request",
    ] {
        assert!(kinds.contains(&kind), "missing {kind} in {kinds:?}");
    }
    assert!(!second_json.contains("Check the prior record first"));

    // A wrong digest, an unknown learning, and another namespace are
    // indistinguishable.
    let other = format!("sha256:{}", "b".repeat(64));
    assert_unavailable(
        plan(
            &server,
            "bad-digest",
            NAMESPACE,
            Some((LEARNING_ID, &other)),
        )
        .await,
        "wrong digest",
    );
    assert_unavailable(
        plan(&server, "unknown", NAMESPACE, Some(("missing", &digest))).await,
        "unknown learning",
    );
    assert_unavailable(
        plan(&server, "elsewhere", "other", Some((LEARNING_ID, &digest))).await,
        "another namespace",
    );

    // A principal without namespace access cannot inject a learning at all.
    let created = server.sekaictl(&["admin", "access", "credential", "create", "intruder"]);
    assert!(created.status.success(), "{created:?}\n{}", server.logs());
    let token = String::from_utf8_lossy(&created.stdout).trim().to_string();
    let mut request = Request::new(plan_request(
        "intruder-op",
        NAMESPACE,
        Some((LEARNING_ID, &digest)),
    ));
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("metadata"),
    );
    let denied = server
        .chisei()
        .await
        .plan_execution(request)
        .await
        .expect_err("an outsider cannot pin a learning");
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert!(!denied.message().contains("learning"));

    // The operator can disable it; the next plan fails closed.
    server.learning(&[
        "rollback",
        "--namespace",
        NAMESPACE,
        "--learning-id",
        LEARNING_ID,
    ]);
    assert_unavailable(
        plan(
            &server,
            "after-rollback",
            NAMESPACE,
            Some((LEARNING_ID, &digest)),
        )
        .await,
        "rolled-back learning",
    );
    let unpinned = plan(&server, "still-plans", NAMESPACE, None)
        .await
        .expect("planning without a pin is unaffected");
    assert!(unpinned.learning_references.is_empty());
}

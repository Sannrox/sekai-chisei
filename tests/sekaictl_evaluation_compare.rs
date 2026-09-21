//! Process-level proof of the evaluation loop `sekaictl admin evaluation plan`
//! drives against the shipped server: publish a plan, resolve two pinned
//! subjects, execute both, and compare the receipted outcomes (#1090).
//!
//! The server first starts with experimental RPCs enabled only to publish the
//! operator-owned evaluator definition, then restarts on the same store with
//! the default gate so the loop itself proves the promoted RPCs are reachable
//! without any experimental flag. Invariants are seeded into the store before
//! boot because governed facts have no wire authoring RPC.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sekai_chisei::chisei::evaluation_execution::{
    EXECUTION_REQUEST_CONTRACT, EXECUTOR_VERSION,
    SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST,
    SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE,
};
use sekai_chisei::chisei::evaluation_manifest::{RESOLUTION_REQUEST_CONTRACT, RESOLVER_VERSION};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::client::connect_sekai;
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::chisei::{
    EvaluationExecutionRequest, EvaluationResolutionRequest, EvaluatorDefinition,
    EvaluatorResourceLimits, ExecuteEvaluationManifestRequest, GetOperationReceiptRequest,
    PutEvaluatorDefinitionRequest, ResolveEvaluationPlanRequest,
};
use sekai_chisei::sekai::governed_facts::{
    FactApplicability, GovernedFactInput, GovernedFactType, PROFILE_CONTRACT_VERSION,
    VerificationContract, apply_profile, put_fact,
};
use serde_json::{Value, json};
use tonic::{Code, Request};

const NAMESPACE: &str = "acme";
const SUBJECT_PROFILE: &str = "example.software-release-candidate/v2";
const SUBJECT_SCHEMA: &str = "schema://example/software-release-candidate/v2";
const DIGEST_SCHEMA: &str = "schema://example/subject-content-digest/v1";
const RESULT_SCHEMA: &str = "schema://example/pass-fail/v1";
const WAIT_BUDGET: Duration = Duration::from_secs(20);

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn start(&self, experimental: bool) -> Running {
        static START_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _start = START_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("server start lock");
        let socket = self.path("sekai.sock");
        let _ = std::fs::remove_file(&socket);
        let log_path = self.path("server.log");
        let log = std::fs::File::create(&log_path).expect("server log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"));
        command
            .env("SEKAI_SOCKET", &socket)
            .env("DB_PATH", self.path("sekai.db"))
            .env("SEKAI_SHARED_STORE", "1")
            .env("GRPC_PORT", free_tcp_port().to_string())
            .env("OPS_PORT", "")
            .env("OPS_BIND", "127.0.0.1")
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
            .env_remove("OLLAMA_URL")
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log));
        if experimental {
            command.env("SEKAI_EXPERIMENTAL_RPCS", "1");
        }
        let child = command.spawn().expect("spawn sekai-chisei");
        let mut running = Running {
            child,
            socket,
            log_path,
        };
        running.wait_until_ready();
        running
    }
}

struct Running {
    child: Child,
    socket: PathBuf,
    log_path: PathBuf,
}

impl Running {
    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + WAIT_BUDGET;
        loop {
            if std::os::unix::net::UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("poll server") {
                panic!(
                    "sekai-chisei exited {status} before its socket was ready\n{}",
                    self.logs()
                );
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the server socket\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn socket_str(&self) -> &str {
        self.socket.to_str().expect("utf8 socket")
    }

    async fn chisei(&self) -> ChiseiServiceClient<sekai_chisei::grpc::client::GatewayClient> {
        ChiseiServiceClient::new(
            connect_sekai(self.socket_str())
                .await
                .unwrap_or_else(|error| panic!("connect: {error}\n{}", self.logs())),
        )
    }

    fn sekaictl(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sekaictl"))
            .args(args)
            .env("SEKAI_SOCKET", &self.socket)
            .env_remove("CHISEI_GRPC_URL")
            .env_remove("SEKAI_CREDENTIAL")
            .output()
            .expect("run sekaictl")
    }

    fn plan_command(&self, args: &[&str]) -> Output {
        let mut full = vec!["admin", "evaluation", "plan"];
        full.extend_from_slice(args);
        self.sekaictl(&full)
    }

    fn json_ok(&self, args: &[&str]) -> Value {
        let output = self.plan_command(args);
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

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bearer<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("metadata"),
    );
    request
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Seed one active invariant the compiled digest-equality evaluator can
/// verify. Governed facts are authored through the domain library, not RPC.
fn seed_invariant(db_path: &Path) -> String {
    let db = RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(db_path.to_str().expect("utf8 db path")).expect("open store"),
    ));
    apply_profile(&db, NAMESPACE, PROFILE_CONTRACT_VERSION, "root", 1).expect("apply profile");
    put_fact(
        &db,
        GovernedFactInput {
            contract_version: PROFILE_CONTRACT_VERSION.into(),
            namespace: NAMESPACE.into(),
            fact_id: "release-content-digest".into(),
            version: "1.0.0".into(),
            fact_type: GovernedFactType::Invariant,
            status: "active".into(),
            statement: "The release content digest matches the reviewed digest.".into(),
            applicability: FactApplicability {
                subject_profiles: vec![SUBJECT_PROFILE.into()],
                subject_refs: vec![],
            },
            verification: VerificationContract {
                predicate_kind: SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE.into(),
                input_schema: DIGEST_SCHEMA.into(),
                result_schema: RESULT_SCHEMA.into(),
                evidence_types: vec![],
            },
            requirement_version_ids: vec![],
            evidence_refs: vec![],
            source_ref: "repo://requirements/release-content-digest@1".into(),
            effective_from_ms: 1,
            supersedes_object_id: String::new(),
            access_marking: String::new(),
        },
        "root",
        2,
    )
    .expect("put invariant")
    .object_id
}

async fn publish_evaluator_definition(server: &Running) -> String {
    let record = server
        .chisei()
        .await
        .put_evaluator_definition(PutEvaluatorDefinitionRequest {
            definition: Some(EvaluatorDefinition {
                contract_version: "chisei.evaluator-definition/v1".into(),
                namespace: NAMESPACE.into(),
                evaluator_id: "release-content-digest".into(),
                version: "1.0.0".into(),
                implementation_digest: SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST
                    .into(),
                execution_class: "deterministic_builtin/v1".into(),
                supported_predicate_kinds: vec![SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE.into()],
                supported_input_schemas: vec![SUBJECT_SCHEMA.into(), DIGEST_SCHEMA.into()],
                supported_result_schemas: vec![RESULT_SCHEMA.into()],
                parameter_schema_json: r#"{"type":"object","properties":{"expected_content_digest":{"type":"string","minLength":71,"maxLength":71}},"required":["expected_content_digest"],"additionalProperties":false}"#.into(),
                evidence_classifications: vec!["internal".into()],
                resource_limits: Some(EvaluatorResourceLimits {
                    timeout_ms: 1_000,
                    max_input_bytes: 4_096,
                    max_output_bytes: 1_024,
                    max_evidence_items: 8,
                }),
                source_ref: "repo://evaluators/release-content-digest@1".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("publish evaluator definition: {error}\n{}", server.logs()))
        .into_inner()
        .record
        .expect("definition record");
    record.definition.expect("definition").definition_id
}

fn write_json(workspace: &Workspace, name: &str, value: &Value) -> PathBuf {
    let path = workspace.path(name);
    std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).expect("write document");
    path
}

fn plan_document(definition_id: &str, invariant_id: &str, expected_digest: &str) -> Value {
    json!({
        "contract_version": "chisei.evaluation-plan/v1",
        "namespace": NAMESPACE,
        "plan_id": "software-release",
        "version": "1.0.0",
        "accepted_subject_profiles": [SUBJECT_PROFILE],
        "nodes": [
            {
                "node_id": "artifact-digest",
                "evaluator_definition_id": definition_id,
                "depends_on_node_ids": [],
                "input_bindings": [
                    {"name": "release", "source_kind": "subject", "schema_id": SUBJECT_SCHEMA},
                    {"name": "expected-digest", "source_kind": "invariant", "schema_id": DIGEST_SCHEMA}
                ],
                "parameters": {"expected_content_digest": expected_digest},
                "invariant_version_ids": [invariant_id],
                "classification": "required"
            }
        ],
        "reducer": "required_all_pass_advisory_observed/v1",
        "source_ref": "repo://evaluation-plans/software-release@1.0.0"
    })
}

fn resolution_document(plan_version_id: &str, request_id: &str, subject_digest: &str) -> Value {
    json!({
        "namespace": NAMESPACE,
        "request_id": request_id,
        "plan_version_id": plan_version_id,
        "subject_profile": SUBJECT_PROFILE,
        "subject_identity": format!("release:{request_id}"),
        "subject_content_digest": subject_digest,
        "evidence_object_ids": [],
        "evaluation_time_ms": 1_785_448_800_000_i64
    })
}

fn resolve_manifest(
    server: &Running,
    workspace: &Workspace,
    plan_version_id: &str,
    request_id: &str,
    subject_digest: &str,
) -> String {
    let resolution = write_json(
        workspace,
        &format!("{request_id}.json"),
        &resolution_document(plan_version_id, request_id, subject_digest),
    );
    let resolved = server.json_ok(&["resolve", resolution.to_str().unwrap(), "--json"]);
    resolved["manifest"]["manifest_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("resolve output has no manifest digest: {resolved}"))
        .to_string()
}

fn execute(server: &Running, manifest_digest: &str) -> Output {
    server.plan_command(&["execute", NAMESPACE, manifest_digest, "--yes", "--json"])
}

#[tokio::test(flavor = "multi_thread")]
async fn compare_diffs_two_pinned_executions_through_the_shipped_binaries() {
    let workspace = Workspace::new();
    let invariant_id = seed_invariant(&workspace.path("sekai.db"));

    let definition_id = {
        let setup = workspace.start(true);
        publish_evaluator_definition(&setup).await
    };

    // Default gate: no experimental flag from here on.
    let server = workspace.start(false);
    let reviewed = digest('b');
    let plan = write_json(
        &workspace,
        "plan.json",
        &plan_document(&definition_id, &invariant_id, &reviewed),
    );
    let applied = server.json_ok(&["apply", plan.to_str().unwrap(), "--json"]);
    let plan_version_id = applied["plan"]["plan_version_id"]
        .as_str()
        .unwrap_or_else(|| panic!("apply output has no plan version: {applied}"))
        .to_string();

    let baseline_digest =
        resolve_manifest(&server, &workspace, &plan_version_id, "baseline", &reviewed);
    let candidate_digest = resolve_manifest(
        &server,
        &workspace,
        &plan_version_id,
        "candidate",
        &digest('c'),
    );

    let baseline_run = execute(&server, &baseline_digest);
    assert_eq!(baseline_run.status.code(), Some(0), "{baseline_run:?}");
    let candidate_run = execute(&server, &candidate_digest);
    assert_eq!(
        candidate_run.status.code(),
        Some(7),
        "a subject digest mismatch is a fixed-gate denial\n{candidate_run:?}"
    );
    let candidate_projection: Value = serde_json::from_slice(&candidate_run.stdout).unwrap();

    // Regression: baseline allows, candidate is denied.
    let compared = server.plan_command(&[
        "compare",
        NAMESPACE,
        &baseline_digest,
        &candidate_digest,
        "--json",
    ]);
    assert_eq!(
        compared.status.code(),
        Some(8),
        "regression must be a distinct nonzero exit\n{compared:?}"
    );
    assert!(!compared.stderr.is_empty());
    let report: Value = serde_json::from_slice(&compared.stdout).expect("compare json");
    assert_eq!(
        report["schema_version"],
        "sekaictl.evaluation-plan-output/v1"
    );
    assert_eq!(report["command"], "compare");
    assert_eq!(report["status"], "regressed");
    let comparison = &report["comparison"];
    assert_eq!(
        comparison["contract_version"],
        "chisei.evaluation-comparison/v1"
    );
    assert_eq!(comparison["gate"]["baseline_verdict"], "allow");
    assert_eq!(comparison["gate"]["candidate_verdict"], "deny");
    assert_eq!(comparison["baseline"]["manifest_digest"], baseline_digest);
    assert_eq!(comparison["candidate"]["manifest_digest"], candidate_digest);
    let node = &comparison["nodes"][0];
    assert_eq!(node["node_id"], "artifact-digest");
    assert_eq!(node["baseline"]["status"], "pass");
    assert_eq!(node["candidate"]["status"], "fail");
    assert_eq!(node["change"], "regressed");
    assert_eq!(comparison["summary"]["required_regressions"], 1);
    assert_eq!(
        comparison["candidate"]["decision_digest"],
        candidate_projection["execution"]["decision"]["decision_digest"],
        "the diff cites the receipted gate decision that execute reported"
    );

    // The same evidence in the other direction is an improvement and exits 0.
    let improved = server.json_ok(&[
        "compare",
        NAMESPACE,
        &candidate_digest,
        &baseline_digest,
        "--json",
    ]);
    assert_eq!(improved["status"], "improved");
    assert_eq!(improved["comparison"]["nodes"][0]["change"], "improved");

    // Human output names the outcome, the gate movement, and each node.
    let human = server.plan_command(&["compare", NAMESPACE, &baseline_digest, &candidate_digest]);
    assert_eq!(human.status.code(), Some(8));
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("Comparison: regressed"), "{text}");
    assert!(text.contains("Gate: allow -> deny (regressed)"), "{text}");
    assert!(
        text.contains("artifact-digest [required] pass -> [required] fail (regressed)"),
        "{text}"
    );

    // Comparison reads receipts only: it never executes an unexecuted manifest.
    let unexecuted_digest = resolve_manifest(
        &server,
        &workspace,
        &plan_version_id,
        "never-executed",
        &digest('d'),
    );
    let unexecuted = server.plan_command(&[
        "compare",
        NAMESPACE,
        &baseline_digest,
        &unexecuted_digest,
        "--json",
    ]);
    assert_eq!(
        unexecuted.status.code(),
        Some(3),
        "an unexecuted manifest is absent, not silently executed\n{unexecuted:?}"
    );
    assert!(unexecuted.stdout.is_empty());
    let still_absent = server.plan_command(&[
        "compare",
        NAMESPACE,
        &unexecuted_digest,
        &baseline_digest,
        "--json",
    ]);
    assert_eq!(
        still_absent.status.code(),
        Some(3),
        "compare must not have executed it"
    );

    // Input discipline fails before any connection is used.
    let same = server.plan_command(&["compare", NAMESPACE, &baseline_digest, &baseline_digest]);
    assert_eq!(same.status.code(), Some(2), "{same:?}");
    let alias = server.plan_command(&["compare", NAMESPACE, "latest", &candidate_digest]);
    assert_eq!(alias.status.code(), Some(2), "{alias:?}");

    // A different namespace cannot see these executions, and says nothing more.
    let foreign = server.plan_command(&[
        "compare",
        "other",
        &baseline_digest,
        &candidate_digest,
        "--json",
    ]);
    assert_eq!(foreign.status.code(), Some(3), "{foreign:?}");
    assert!(foreign.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_principal_without_access_cannot_read_evaluation_plans_manifests_or_receipts() {
    let workspace = Workspace::new();
    let invariant_id = seed_invariant(&workspace.path("sekai.db"));
    let definition_id = {
        let setup = workspace.start(true);
        publish_evaluator_definition(&setup).await
    };
    let server = workspace.start(false);
    let reviewed = digest('b');
    let plan = write_json(
        &workspace,
        "plan.json",
        &plan_document(&definition_id, &invariant_id, &reviewed),
    );
    let applied = server.json_ok(&["apply", plan.to_str().unwrap(), "--json"]);
    let plan_version_id = applied["plan"]["plan_version_id"]
        .as_str()
        .unwrap()
        .to_string();
    let manifest_digest =
        resolve_manifest(&server, &workspace, &plan_version_id, "baseline", &reviewed);
    assert_eq!(execute(&server, &manifest_digest).status.code(), Some(0));

    let created = server.sekaictl(&["admin", "access", "credential", "create", "eval-intruder"]);
    assert!(created.status.success(), "{created:?}\n{}", server.logs());
    let token = String::from_utf8_lossy(&created.stdout).trim().to_string();
    assert!(!token.is_empty());

    let mut chisei = server.chisei().await;

    let receipt = chisei
        .get_operation_receipt(bearer(
            &token,
            GetOperationReceiptRequest {
                operation_id: format!(
                    "evaluation-execution:{}",
                    &manifest_digest["sha256:".len()..]
                ),
                ..Default::default()
            },
        ))
        .await
        .expect_err("another principal cannot read the execution receipt");
    assert_eq!(receipt.code(), Code::PermissionDenied);

    let resolution = EvaluationResolutionRequest {
        contract_version: RESOLUTION_REQUEST_CONTRACT.into(),
        resolver_version: RESOLVER_VERSION.into(),
        namespace: NAMESPACE.into(),
        request_id: "intruder".into(),
        plan_version_id: plan_version_id.clone(),
        subject_profile: SUBJECT_PROFILE.into(),
        subject_identity: "release:intruder".into(),
        subject_content_digest: reviewed.clone(),
        evidence_object_ids: vec![],
        evaluation_time_ms: 1_785_448_800_000,
    };
    let resolve = chisei
        .resolve_evaluation_plan(bearer(
            &token,
            ResolveEvaluationPlanRequest {
                resolution: Some(resolution),
            },
        ))
        .await
        .expect_err("another principal cannot resolve a plan it cannot read");
    assert_eq!(resolve.code(), Code::PermissionDenied);

    let executed = chisei
        .execute_evaluation_manifest(bearer(
            &token,
            ExecuteEvaluationManifestRequest {
                execution: Some(EvaluationExecutionRequest {
                    contract_version: EXECUTION_REQUEST_CONTRACT.into(),
                    executor_version: EXECUTOR_VERSION.into(),
                    namespace: NAMESPACE.into(),
                    manifest_digest: manifest_digest.clone(),
                    max_total_duration_ms: 1_000,
                }),
            },
        ))
        .await
        .expect_err("another principal cannot execute or replay a manifest");
    assert_eq!(executed.code(), Code::PermissionDenied);
}

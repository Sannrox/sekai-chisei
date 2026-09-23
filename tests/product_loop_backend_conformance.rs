//! Product-loop conformance for the shipped binary on both community backends (#1086).
//!
//! One scenario drives the stable loop through the public operator and gRPC
//! surfaces: define the ontology, seed facts, read them, submit a
//! governed Action, inspect its receipt, then activate an object-security
//! policy and observe a denied read. SQLite runs by default; PostgreSQL runs
//! the identical scenario when `SEKAI_TEST_POSTGRES_URL` names a TLS server
//! the test may create a scratch database on (`SEKAI_TEST_POSTGRES_CA_CERT`
//! supplies a private CA).

#![cfg(unix)]

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use sekai_chisei::grpc::client::connect_sekai;
use sekai_chisei::grpc::pb::chisei::GetOperationReceiptRequest;
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    ActivateObjectSecurityPoliciesRequest, EnsureTeamNamespaceRequest, GetActionInstanceRequest,
    GetObjectRequest, GovernedActionType, ListFilter, ListObjectsRequest,
    ObjectSecurityPolicyBinding, PutGovernedActionTypeRequest,
    PutObjectSecurityPolicyRevisionRequest, SubmitActionInstanceRequest,
};
use tonic::{Code, Request};

const WAIT_BUDGET: Duration = Duration::from_secs(30);

enum Backend {
    Sqlite,
    Postgres {
        url: String,
        ca_cert: Option<String>,
    },
}

struct LoopServer {
    child: Child,
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    socket: PathBuf,
    log_path: PathBuf,
}

impl LoopServer {
    fn spawn(backend: &Backend) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("sekai.sock");
        let log_path = dir.path().join("sekai.log");
        let log = std::fs::File::create(&log_path).expect("server log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"));
        command
            .env("SEKAI_SOCKET", &socket)
            .env("SEKAI_SHARED_STORE", "1")
            .env("GRPC_PORT", "0")
            .env("OPS_PORT", "")
            .env("RUST_LOG", "error")
            .env("SEKAI_EXPERIMENTAL_RPCS", "1")
            .env_remove("SEKAI_INSECURE")
            .env_remove("SEKAI_CREDENTIAL")
            .env_remove("SEKAI_BIND")
            .env_remove("SEKAI_DB_PATH")
            .env_remove("CHISEI_DB_PATH")
            .env_remove("SEKAI_DATABASE_URL")
            .env_remove("CHISEI_DATABASE_URL")
            .env_remove("OLLAMA_URL")
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log));
        match backend {
            Backend::Sqlite => {
                command
                    .env("DB_PATH", dir.path().join("sekai.db"))
                    .env_remove("SEKAI_DB_BACKEND")
                    .env_remove("DATABASE_URL");
            }
            Backend::Postgres { url, ca_cert } => {
                command
                    .env("SEKAI_DB_BACKEND", "postgres")
                    .env("DATABASE_URL", url)
                    .env_remove("DB_PATH");
                match ca_cert {
                    Some(path) => command.env("SEKAI_POSTGRES_CA_CERT", path),
                    None => command.env_remove("SEKAI_POSTGRES_CA_CERT"),
                };
            }
        }
        let child = command.spawn().expect("spawn sekai-chisei");
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
        while UnixStream::connect(&self.socket).is_err() {
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
        let mut contents = String::new();
        if let Ok(mut file) = std::fs::File::open(&self.log_path) {
            let _ = file.read_to_string(&mut contents);
        }
        contents
    }

    fn socket_str(&self) -> String {
        self.socket.to_str().expect("utf8 socket").to_string()
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

    fn sekaictl_ok(&self, args: &[&str]) -> String {
        let output = self.sekaictl(args);
        assert!(
            output.status.success(),
            "sekaictl {args:?} failed\nstdout: {}\nstderr: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            self.logs()
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn token(&self, principal: &str) -> String {
        let token = self.sekaictl_ok(&["admin", "access", "credential", "create", principal]);
        token.trim().to_string()
    }

    async fn sekai(&self) -> SekaiServiceClient<sekai_chisei::grpc::client::GatewayClient> {
        SekaiServiceClient::new(connect_sekai(&self.socket_str()).await.expect("connect"))
    }

    async fn chisei(&self) -> ChiseiServiceClient<sekai_chisei::grpc::client::GatewayClient> {
        ChiseiServiceClient::new(connect_sekai(&self.socket_str()).await.expect("connect"))
    }

    fn panics(&self) -> usize {
        self.logs().matches("panicked").count()
    }
}

impl Drop for LoopServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fixture(relative: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(relative)
        .to_str()
        .expect("utf8 fixture")
        .to_string()
}

fn bearer<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("bearer metadata"),
    );
    request
}

async fn exercise_product_loop(server: &LoopServer) {
    let socket = server.socket_str();
    let logs = || server.logs();

    // Define the ontology and seed facts through the operator CLI.
    let applied = server.sekaictl_ok(&[
        "ontology",
        "apply",
        "--file",
        &fixture("tests/fixtures/product_loop/domain-v1.json"),
        "--target",
        &socket,
    ]);
    assert!(applied.contains("class: Incident") && applied.contains("relation: affects"));
    let seeded = server.sekaictl_ok(&[
        "ontology",
        "seed",
        "--file",
        &fixture("tests/fixtures/product_loop/seed-v1.json"),
        "--target",
        &socket,
    ]);
    assert!(seeded.contains("object: inc-1"), "{seeded}");

    let mut sekai = server.sekai().await;
    let incident = sekai
        .get_object(GetObjectRequest { id: "inc-1".into() })
        .await
        .unwrap_or_else(|error| panic!("get object: {error}\n{}", logs()))
        .into_inner()
        .object
        .expect("incident");
    assert_eq!(incident.kind, "incident");
    let listed = sekai
        .list_objects(ListObjectsRequest {
            filter: Some(ListFilter {
                kind: "component".into(),
                namespace: "demo".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("list objects: {error}\n{}", logs()))
        .into_inner();
    assert!(listed.objects.iter().any(|object| object.id == "svc-api"));

    // EvaluateObjectSet needs a published definition revision, which no
    // public RPC can create from an empty namespace yet (#1152); the in-process
    // `postgres_evaluate_object_set_matches_sqlite` test covers it.

    // Principals for the governed reads and the Action.
    let agent = server.token("loop-agent");
    let reader = server.token("loop-reader");
    for (principal, role) in [("loop-agent", "editor"), ("loop-reader", "viewer")] {
        sekai
            .ensure_team_namespace(EnsureTeamNamespaceRequest {
                namespace: "demo".into(),
                principal: principal.into(),
                role: role.into(),
            })
            .await
            .unwrap_or_else(|error| panic!("grant {principal}: {error}\n{}", logs()));
    }
    // Object security: the viewer reads the incident until an owner-only
    // policy is active, then the same read is denied.
    sekai
        .get_object(bearer(&reader, GetObjectRequest { id: "inc-1".into() }))
        .await
        .unwrap_or_else(|error| panic!("viewer read before policy: {error}\n{}", logs()));
    // Activation binds every instantiated kind in the namespace, including
    // the team boundary object: services stay readable, incidents become
    // owner-only.
    let mut bindings = Vec::new();
    for (kind, predicate) in [
        ("component", serde_json::json!({"kind":"allow_all"})),
        ("namespace", serde_json::json!({"kind":"allow_all"})),
        (
            "incident",
            serde_json::json!({"kind":"subject_equals_property","property":"owner"}),
        ),
    ] {
        let policy = serde_json::to_vec(&serde_json::json!({
            "contract_version": "sekai.object-security-policy/v1",
            "namespace": "demo",
            "kind": kind,
            "rules": [{"operation":"read","predicates":[predicate]}],
            "property_grants": [{"property":"owner","access":"read"}]
        }))
        .expect("policy json");
        let revision = sekai
            .put_object_security_policy_revision(PutObjectSecurityPolicyRevisionRequest {
                canonical_policy_json: policy,
                idempotency_key: format!("loop-policy-{kind}"),
            })
            .await
            .unwrap_or_else(|error| panic!("put {kind} policy: {error}\n{}", logs()))
            .into_inner()
            .revision
            .expect("revision");
        bindings.push(ObjectSecurityPolicyBinding {
            kind: kind.into(),
            revision_digest: revision.revision_digest,
        });
    }
    sekai
        .activate_object_security_policies(ActivateObjectSecurityPoliciesRequest {
            namespace: "demo".into(),
            policies: bindings,
            idempotency_key: "loop-activate".into(),
        })
        .await
        .unwrap_or_else(|error| panic!("activate policy: {error}\n{}", logs()));
    sekai
        .get_object(bearer(
            &reader,
            GetObjectRequest {
                id: "svc-api".into(),
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("viewer reads the service: {error}\n{}", logs()));
    let denied = sekai
        .get_object(bearer(&reader, GetObjectRequest { id: "inc-1".into() }))
        .await
        .expect_err("owner-only policy denies the viewer");
    assert!(
        matches!(denied.code(), Code::NotFound | Code::PermissionDenied),
        "{denied:?}"
    );
    assert!(!denied.message().contains("elevated latency"));

    // Submit a governed Action and read the instance and its receipt.
    server.sekaictl_ok(&[
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
    sekai
        .put_governed_action_type(PutGovernedActionTypeRequest {
            r#type: Some(GovernedActionType {
                namespace: "demo".into(),
                type_id: "incident.acknowledge".into(),
                version: "1".into(),
                description: "Acknowledge an incident".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"note":{"type":"string"}},"required":["note"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec!["notify".into()],
                enabled: true,
                ..Default::default()
            }),
            request_id: String::new(),
        })
        .await
        .unwrap_or_else(|error| panic!("put action type: {error}\n{}", logs()));
    let submitted = sekai
        .submit_action_instance(bearer(
            &agent,
            SubmitActionInstanceRequest {
                namespace: "demo".into(),
                type_id: "incident.acknowledge".into(),
                version: "1".into(),
                parameters_json: r#"{"note":"on it"}"#.into(),
                idempotency_key: "loop-ack".into(),
                request_id: "operation-loop-ack".into(),
                ..Default::default()
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("submit: {error}\n{}", logs()))
        .into_inner()
        .instance
        .expect("instance");
    assert_eq!(submitted.status, "admitted");
    let stored = sekai
        .get_action_instance(bearer(
            &agent,
            GetActionInstanceRequest {
                instance_id: submitted.instance_id.clone(),
                ..Default::default()
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("get instance: {error}\n{}", logs()))
        .into_inner()
        .instance
        .expect("instance");
    assert_eq!(stored.operation_id, submitted.operation_id);
    let receipt = server
        .chisei()
        .await
        .get_operation_receipt(GetOperationReceiptRequest {
            operation_id: submitted.operation_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("receipt: {error}\n{}", logs()))
        .into_inner();
    assert!(
        format!("{receipt:?}").contains(&submitted.operation_id),
        "{receipt:?}"
    );

    assert_eq!(server.panics(), 0, "{}", logs());
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_runs_the_product_loop() {
    let server = LoopServer::spawn(&Backend::Sqlite);
    exercise_product_loop(&server).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
async fn postgres_runs_the_product_loop() {
    let scratch = ScratchDatabase::create();
    let server = LoopServer::spawn(&Backend::Postgres {
        url: scratch.url.clone(),
        ca_cert: scratch.ca_cert.clone(),
    });
    exercise_product_loop(&server).await;
}

/// A throwaway database on the conformance server so reruns start clean.
struct ScratchDatabase {
    admin_url: String,
    ca_cert: Option<String>,
    name: String,
    url: String,
}

impl ScratchDatabase {
    fn create() -> Self {
        let admin_url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must identify a PostgreSQL test server");
        let ca_cert = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT").ok();
        let name = format!("sekai_loop_{}", uuid::Uuid::new_v4().simple());
        let (base, query) = match admin_url.split_once('?') {
            Some((base, query)) => (base, format!("?{query}")),
            None => (admin_url.as_str(), String::new()),
        };
        let prefix = base.rsplit_once('/').expect("database URL path").0;
        let url = format!("{prefix}/{name}{query}");
        let scratch = Self {
            admin_url,
            ca_cert,
            name,
            url,
        };
        // The synchronous client runs its own runtime; keep it off this one.
        tokio::task::block_in_place(|| {
            scratch
                .client()
                .batch_execute(&format!("CREATE DATABASE {}", scratch.name))
                .expect("create scratch database")
        });
        scratch
    }

    fn client(&self) -> postgres::Client {
        let mut builder = native_tls::TlsConnector::builder();
        if let Some(path) = &self.ca_cert {
            let pem = std::fs::read(path).expect("read CA certificate");
            builder.add_root_certificate(
                native_tls::Certificate::from_pem(&pem).expect("parse CA certificate"),
            );
        }
        let tls = postgres_native_tls::MakeTlsConnector::new(builder.build().expect("tls"));
        postgres::Client::connect(&self.admin_url, tls).expect("connect admin database")
    }
}

impl Drop for ScratchDatabase {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            let _ = self.client().batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
        });
    }
}

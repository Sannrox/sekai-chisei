//! Black-box process isolation for the Sekai and Chisei binaries.

use std::fs;
use std::future::Future;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::gateway_keys::hash_gateway_key;
use sekai_chisei::grpc::pb::chisei::GetOperationReceiptRequest;
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{GetActionInstanceRequest, SubmitActionInstanceRequest};
use sekai_chisei::sekai::governed_action_type::{EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType};
use tempfile::tempdir;

const TOKEN: &str = "plane-hop-token";

#[derive(Clone, Default)]
struct ProcessKiller(Arc<Mutex<Vec<u32>>>);

impl ProcessKiller {
    fn register(&self, pid: u32) {
        self.0.lock().expect("process killer").push(pid);
    }

    fn kill_all(&self) {
        for pid in self.0.lock().expect("process killer").iter() {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
    }
}

struct ChildGuard {
    child: Child,
    stderr_path: PathBuf,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl ChildGuard {
    fn stderr_text(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn seed_sekai(path: &Path) {
    let store = SekaiStore::open_sqlite(path.to_str().unwrap());
    store
        .runtime().put_governed_action_type(
            GovernedActionType {
                namespace: "acme".into(),
                type_id: "dispatch".into(),
                version: "1".into(),
                description: "dispatch work".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                enabled: true,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
    store
        .runtime()
        .create_principal_credential("operator", &hash_gateway_key(TOKEN), 1)
        .unwrap();
}

fn spawn_plane(
    bin: &str,
    port: u16,
    extras: &[(&str, &str)],
    killer: &ProcessKiller,
    stderr_path: PathBuf,
) -> ChildGuard {
    let stderr = fs::File::create(&stderr_path).expect("child stderr file");
    let mut command = Command::new(bin);
    command
        .env("SEKAI_INSECURE", "1")
        .env("SEKAI_BIND", "127.0.0.1")
        .env("GRPC_PORT", port.to_string())
        .env("SEKAI_SOCKET", "")
        .env("OPS_PORT", "")
        .env("SEKAI_HTTP_PORT", "")
        .env_remove("SEKAI_DB_PATH")
        .env_remove("CHISEI_DB_PATH")
        .env_remove("SEKAI_DATABASE_URL")
        .env_remove("CHISEI_DATABASE_URL")
        .env_remove("DATABASE_URL")
        .stdout(Stdio::null())
        .stderr(stderr);
    for (key, value) in extras {
        command.env(key, value);
    }
    let child = command.spawn().unwrap();
    killer.register(child.id());
    ChildGuard { child, stderr_path }
}

/// Wait until this child binds `port`. Fail immediately if the child exits
/// (bind TOCTOU, boot error) and include stderr. A pre-existing occupant of
/// a stolen `free_port()` is not this child: require an observed closed-to-
/// open transition while the process is still alive. Reference-platform analog:
/// go-java-launcher ProcessMonitor identifies the service by child PID.
fn wait_ready(child: &mut ChildGuard, port: u16, label: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let addr = format!("127.0.0.1:{port}");
    let mut saw_closed = false;
    loop {
        if let Some(status) = child.child.try_wait().map_err(|error| error.to_string())? {
            return Err(format!(
                "{label} on {addr} exited {status}: {}",
                child.stderr_text()
            ));
        }
        if std::net::TcpStream::connect(&addr).is_ok() {
            if saw_closed {
                return Ok(());
            }
        } else {
            saw_closed = true;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{label} on {addr} did not become ready: {}",
                child.stderr_text()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_listening_plane(
    bin: &str,
    extras: &[(&str, &str)],
    killer: &ProcessKiller,
    log_dir: &Path,
    label: &str,
) -> (ChildGuard, u16) {
    let mut last_error = String::new();
    for attempt in 0..5 {
        let port = free_port();
        let stderr_path = log_dir.join(format!("{label}-{attempt}.stderr"));
        let mut child = spawn_plane(bin, port, extras, killer, stderr_path);
        match wait_ready(&mut child, port, label) {
            Ok(()) => return (child, port),
            Err(error) if error.contains("exited") => last_error = error,
            Err(error) => panic!("{error}"),
        }
    }
    panic!("{label} did not become ready after retries: {last_error}");
}

fn run_until_exit(mut command: Command, timeout: Duration) -> std::process::ExitStatus {
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("command exceeded {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn plane_endpoint(port: u16) -> tonic::transport::Channel {
    tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap()
}

async fn sekai_client(port: u16) -> SekaiServiceClient<tonic::transport::Channel> {
    SekaiServiceClient::new(plane_endpoint(port).await)
}

async fn chisei_client(port: u16) -> ChiseiServiceClient<tonic::transport::Channel> {
    ChiseiServiceClient::new(plane_endpoint(port).await)
}

fn run_async_with_deadline<F>(timeout: Duration, killer: ProcessKiller, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("two-plane-deadline".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(future)
            }));
            let _ = tx.send(result);
        })
        .unwrap();
    match rx.recv_timeout(timeout) {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => {
            killer.kill_all();
            std::panic::resume_unwind(panic)
        }
        Err(_) => {
            killer.kill_all();
            eprintln!("two-plane process test exceeded {timeout:?}");
            // A leftover worker thread would keep this test binary alive and
            // stall `cargo test-all`. Exit the process after killing children.
            std::process::exit(101);
        }
    }
}

fn with_bearer<T>(mut request: tonic::Request<T>, token: &str) -> tonic::Request<T> {
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

#[test]
fn wait_ready_fails_fast_when_child_exits() {
    let dir = tempdir().unwrap();
    let stderr_path = dir.path().join("dead.stderr");
    fs::write(&stderr_path, "bind failed\n").unwrap();
    let mut command = Command::new("sh");
    command
        .args(["-c", "exit 7"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn().unwrap();
    let mut guard = ChildGuard { child, stderr_path };
    let error = wait_ready(&mut guard, 1, "dead-plane").unwrap_err();
    assert!(
        error.contains("exited") && error.contains("bind failed"),
        "{error}"
    );
}

#[test]
fn wait_ready_rejects_foreign_listener_when_child_exits() {
    let dir = tempdir().unwrap();
    let stderr_path = dir.path().join("stolen.stderr");
    fs::write(&stderr_path, "Address already in use\n").unwrap();
    let occupant = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupant.local_addr().unwrap().port();
    let mut command = Command::new("sh");
    command
        .args(["-c", "sleep 3; exit 1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn().unwrap();
    let mut guard = ChildGuard { child, stderr_path };
    let error = wait_ready(&mut guard, port, "stolen-port").unwrap_err();
    assert!(
        error.contains("exited") && error.contains("Address already in use"),
        "{error}"
    );
    drop(occupant);
}

#[test]
fn chisei_plane_without_sekai_endpoint_refuses_to_boot() {
    let dir = tempdir().unwrap();
    let chisei_db = dir.path().join("chisei.db");
    let mut command = Command::new(env!("CARGO_BIN_EXE_chisei-plane"));
    command
        .env("SEKAI_INSECURE", "1")
        .env("SEKAI_BIND", "127.0.0.1")
        .env("GRPC_PORT", free_port().to_string())
        .env("SEKAI_SOCKET", "")
        .env("OPS_PORT", "")
        .env("SEKAI_HTTP_PORT", "")
        .env("CHISEI_DB_PATH", chisei_db.to_str().unwrap())
        .env_remove("SEKAI_ENDPOINT")
        .env_remove("SEKAI_DB_PATH")
        .env_remove("SEKAI_DATABASE_URL")
        .env_remove("CHISEI_DATABASE_URL")
        .env_remove("DATABASE_URL")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = command.output().unwrap();
    assert!(
        !output.status.success(),
        "chisei-plane booted without SEKAI_ENDPOINT"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SEKAI_ENDPOINT"),
        "expected actionable SEKAI_ENDPOINT error, got {stderr}"
    );
}

#[test]
fn two_plane_processes_submit_receipt_and_reject_wrong_plane() {
    let killer = ProcessKiller::default();
    run_async_with_deadline(
        Duration::from_secs(45),
        killer.clone(),
        two_plane_processes_submit_receipt_and_reject_wrong_plane_inner(killer),
    );
}

async fn two_plane_processes_submit_receipt_and_reject_wrong_plane_inner(killer: ProcessKiller) {
    let dir = tempdir().unwrap();
    let sekai_db = dir.path().join("sekai.db");
    let chisei_db = dir.path().join("chisei.db");
    seed_sekai(&sekai_db);

    let sekai_bin = env!("CARGO_BIN_EXE_sekai-plane");
    let chisei_bin = env!("CARGO_BIN_EXE_chisei-plane");
    let logs = dir.path();

    let (_sekai, sekai_port) = spawn_listening_plane(
        sekai_bin,
        &[("SEKAI_DB_PATH", sekai_db.to_str().unwrap())],
        &killer,
        logs,
        "sekai-plane",
    );
    let endpoint = format!("http://127.0.0.1:{sekai_port}");
    let (_chisei, chisei_port) = spawn_listening_plane(
        chisei_bin,
        &[
            ("CHISEI_DB_PATH", chisei_db.to_str().unwrap()),
            ("SEKAI_ENDPOINT", endpoint.as_str()),
            ("SEKAI_CREDENTIAL", TOKEN),
        ],
        &killer,
        logs,
        "chisei-plane",
    );

    let mut sekai = sekai_client(sekai_port).await;
    let mut chisei = chisei_client(chisei_port).await;

    let denied = sekai
        .submit_action_instance(with_bearer(
            tonic::Request::new(SubmitActionInstanceRequest {
                namespace: "acme".into(),
                type_id: "dispatch".into(),
                version: "1".into(),
                parameters_json: r#"{"runtime":"shikigami"}"#.into(),
                idempotency_key: "op-plane-deny".into(),
                evidence_submission_ids: Vec::new(),
                request_id: "op-plane-deny".into(),
                ontology_digest: String::new(),
            }),
            "wrong-token",
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::Unauthenticated);

    let submitted = sekai
        .submit_action_instance(tonic::Request::new(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            idempotency_key: "op-plane-ok".into(),
            evidence_submission_ids: Vec::new(),
            request_id: "op-plane-ok".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    let instance = submitted.instance.expect("admitted instance");
    assert_eq!(instance.status, "admitted");
    assert_eq!(instance.operation_id, "op-plane-ok");

    let looked_up = sekai
        .get_action_instance(tonic::Request::new(GetActionInstanceRequest {
            instance_id: String::new(),
            namespace: String::new(),
            idempotency_key: String::new(),
            operation_id: "op-plane-ok".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        looked_up.instance.expect("commit").instance_id,
        instance.instance_id
    );

    let receipt = chisei
        .get_operation_receipt(tonic::Request::new(GetOperationReceiptRequest {
            operation_id: "op-plane-ok".into(),
            request_id: String::new(),
            caller_scope: String::new(),
            attempt: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(
        receipt.receipt_json.contains(&instance.instance_id),
        "{}",
        receipt.receipt_json
    );

    let wrong_receipt = SekaiServiceClient::new(plane_endpoint(sekai_port).await);
    // Reuse the Chisei client type against the Sekai listener.
    let wrong = ChiseiServiceClient::new(plane_endpoint(sekai_port).await)
        .get_operation_receipt(tonic::Request::new(GetOperationReceiptRequest {
            operation_id: "op-plane-ok".into(),
            request_id: String::new(),
            caller_scope: String::new(),
            attempt: 0,
        }))
        .await
        .unwrap_err();
    assert_eq!(wrong.code(), tonic::Code::FailedPrecondition);
    assert!(wrong.message().contains("wrong-plane"), "{wrong}");

    let wrong_submit = SekaiServiceClient::new(plane_endpoint(chisei_port).await)
        .submit_action_instance(tonic::Request::new(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            idempotency_key: "op-wrong".into(),
            evidence_submission_ids: Vec::new(),
            request_id: "op-wrong".into(),
            ontology_digest: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(wrong_submit.code(), tonic::Code::FailedPrecondition);
    assert!(
        wrong_submit.message().contains("wrong-plane"),
        "{wrong_submit}"
    );
    let _ = wrong_receipt;
    drop(_sekai);
    drop(_chisei);

    let mut refuse = Command::new(sekai_bin);
    refuse
        .env("SEKAI_INSECURE", "1")
        .env("SEKAI_BIND", "127.0.0.1")
        .env("GRPC_PORT", free_port().to_string())
        .env("SEKAI_SOCKET", "")
        .env("OPS_PORT", "")
        .env("SEKAI_HTTP_PORT", "")
        .env_remove("CHISEI_DB_PATH")
        .env_remove("CHISEI_DATABASE_URL")
        .env("SEKAI_DB_PATH", chisei_db.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = run_until_exit(refuse, Duration::from_secs(10));
    assert!(!status.success(), "sekai process opened a Chisei store");
}

#[test]
fn sekai_binary_refuses_chisei_destination_variables() {
    let dir = tempdir().unwrap();
    let sekai_db = dir.path().join("sekai.db");
    let chisei_db = dir.path().join("chisei.db");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sekai-plane"));
    command
        .env("SEKAI_INSECURE", "1")
        .env("SEKAI_BIND", "127.0.0.1")
        .env("GRPC_PORT", free_port().to_string())
        .env("SEKAI_SOCKET", "")
        .env("OPS_PORT", "")
        .env("SEKAI_HTTP_PORT", "")
        .env("SEKAI_DB_PATH", sekai_db.to_str().unwrap())
        .env("CHISEI_DB_PATH", chisei_db.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = run_until_exit(command, Duration::from_secs(10));
    assert!(!status.success());
}

//! Black-box process isolation for the Sekai and Chisei binaries.

use std::future::Future;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
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
        for pid in self.0.lock().expect("process killer").iter().copied() {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
        .put_governed_action_type(
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
        .create_principal_credential("operator", &hash_gateway_key(TOKEN), 1)
        .unwrap();
}

fn spawn_plane(
    bin: &str,
    port: u16,
    extras: &[(&str, &str)],
    killer: &ProcessKiller,
) -> ChildGuard {
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
        .stderr(Stdio::null());
    for (key, value) in extras {
        command.env(key, value);
    }
    let child = command.spawn().unwrap();
    killer.register(child.id());
    ChildGuard(child)
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let addr = format!("127.0.0.1:{port}");
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(&addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("process on {addr} did not become ready");
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

    let sekai_port = free_port();
    let chisei_port = free_port();
    let sekai_bin = env!("CARGO_BIN_EXE_sekai");
    let chisei_bin = env!("CARGO_BIN_EXE_chisei");

    let _sekai = spawn_plane(
        sekai_bin,
        sekai_port,
        &[("SEKAI_DB_PATH", sekai_db.to_str().unwrap())],
        &killer,
    );
    let _chisei = spawn_plane(
        chisei_bin,
        chisei_port,
        &[
            ("CHISEI_DB_PATH", chisei_db.to_str().unwrap()),
            ("SEKAI_ENDPOINT", &format!("http://127.0.0.1:{sekai_port}")),
            ("SEKAI_CREDENTIAL", TOKEN),
        ],
        &killer,
    );
    wait_ready(sekai_port);
    wait_ready(chisei_port);

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
    let mut command = Command::new(env!("CARGO_BIN_EXE_sekai"));
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

//! Combined-mode two-store public API: destination paths open two files and
//! plane writes stay on the owning store.

use std::collections::HashMap;
use std::path::Path;

#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};

use sekai_chisei::chisei::budget::BudgetTracker;
use sekai_chisei::combined_stores::CombinedStoreSources;
use sekai_chisei::config::Config;
use sekai_chisei::db::store::{ChiseiStore, SekaiStore};
use sekai_chisei::grpc::build_services;
use sekai_chisei::grpc::client::connect_sekai;
use sekai_chisei::grpc::pb::chisei::SetBudgetLimitRequest;
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::chisei::chisei_service_server::ChiseiService;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{CreateObjectRequest, GetObjectRequest, Object};
use sekai_chisei::runtime_backend::BackendIdentity;
use tonic::Request;

const OBJECT_ID: &str = "two-store-component";
const BUDGET_USER: &str = "two-store-user";
const BUDGET_LIMIT: i32 = 12_000;
const WAIT_BUDGET: Duration = Duration::from_secs(20);

fn destination_sources(sekai: &Path, chisei: &Path) -> CombinedStoreSources {
    CombinedStoreSources {
        backend: Some(BackendIdentity::Sqlite),
        default_sqlite_path: "unused.db".into(),
        sekai_sqlite_path: Some(sekai.to_string_lossy().into_owned()),
        chisei_sqlite_path: Some(chisei.to_string_lossy().into_owned()),
        postgres_max_connections: 16,
        ..CombinedStoreSources::default()
    }
}

fn test_config() -> Config {
    let mut config = Config::from_env();
    config.scoring_enabled = false;
    config.ops_port = None;
    config.http_port = None;
    config
}

fn create_object_request() -> CreateObjectRequest {
    CreateObjectRequest {
        object: Some(Object {
            id: OBJECT_ID.into(),
            kind: "component".into(),
            name: OBJECT_ID.into(),
            namespace: "demo".into(),
            external_id: format!("component:{OBJECT_ID}"),
            properties: HashMap::from([("plane".into(), "sekai".into())]),
            created: 0,
            updated: 0,
        }),
        lease_precondition: None,
    }
}

fn assert_plane_isolation(sekai_path: &Path, chisei_path: &Path) {
    let sekai = SekaiStore::open_sqlite(sekai_path.to_str().unwrap());
    assert!(
        sekai.get_object(OBJECT_ID).unwrap().is_some(),
        "Sekai fact must persist on the Sekai file"
    );
    assert_eq!(
        BudgetTracker::new(ChiseiStore::open_sqlite(sekai_path.to_str().unwrap()))
            .get_usage(BUDGET_USER)
            .max_tokens,
        0,
        "Chisei budget must not persist on the Sekai file"
    );

    let chisei = ChiseiStore::open_sqlite(chisei_path.to_str().unwrap());
    assert!(
        chisei.get_object(OBJECT_ID).unwrap().is_none(),
        "Sekai fact must not persist on the Chisei file"
    );
    assert_eq!(
        BudgetTracker::new(chisei).get_usage(BUDGET_USER).max_tokens,
        BUDGET_LIMIT,
        "Chisei budget must persist on the Chisei file"
    );
}

#[tokio::test]
async fn combined_two_store_public_api_isolates_plane_writes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let sekai_path = dir.path().join("sekai.db");
    let chisei_path = dir.path().join("chisei.db");
    let layout = destination_sources(&sekai_path, &chisei_path)
        .open()
        .expect("open destination pair");
    assert!(layout.is_split());
    assert_ne!(layout.sekai_identity(), layout.chisei_identity());

    let (sekai, chisei) = build_services(&test_config(), &layout);
    sekai
        .create_object(Request::new(create_object_request()))
        .await
        .expect("create object");
    chisei
        .set_budget_limit(Request::new(SetBudgetLimitRequest {
            user_id: BUDGET_USER.into(),
            max_tokens: BUDGET_LIMIT,
            period_type: "daily".into(),
            ..Default::default()
        }))
        .await
        .expect("set budget");
    let fetched = sekai
        .get_object(Request::new(GetObjectRequest {
            id: OBJECT_ID.into(),
        }))
        .await
        .expect("get object")
        .into_inner();
    assert_eq!(fetched.object.expect("object").id, OBJECT_ID);

    drop(sekai);
    drop(chisei);
    drop(layout);
    assert_plane_isolation(&sekai_path, &chisei_path);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_opens_two_sqlite_stores() {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("sekai.sock");
    let sekai_path = dir.path().join("sekai.db");
    let chisei_path = dir.path().join("chisei.db");
    let log_path = dir.path().join("sekai.log");
    let log = std::fs::File::create(&log_path).expect("server log");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"));
    command
        .env("SEKAI_SOCKET", &socket)
        .env("SEKAI_DB_PATH", &sekai_path)
        .env("CHISEI_DB_PATH", &chisei_path)
        .env("DB_PATH", &sekai_path)
        .env("GRPC_PORT", "0")
        .env("OPS_PORT", "")
        .env("OPS_BIND", "127.0.0.1")
        .env("SEKAI_HTTP_PORT", "")
        .env("RUST_LOG", "error")
        .env("SEKAI_INSECURE", "1")
        .env("SEKAI_BIND", "127.0.0.1")
        .env_remove("SEKAI_CREDENTIAL")
        .env_remove("SEKAI_DB_BACKEND")
        .env_remove("DATABASE_URL")
        .env_remove("SEKAI_DATABASE_URL")
        .env_remove("CHISEI_DATABASE_URL")
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log));
    let mut child = KillOnDrop(command.spawn().expect("spawn sekai-chisei"));
    wait_until_ready(&socket, &mut child.0, &log_path);

    let channel = connect_sekai(socket.to_str().expect("utf8 socket"))
        .await
        .unwrap_or_else(|error| panic!("connect: {error}\n{}", read_log(&log_path)));
    let mut sekai = SekaiServiceClient::new(channel.clone());
    let mut chisei = ChiseiServiceClient::new(channel);
    sekai
        .create_object(create_object_request())
        .await
        .unwrap_or_else(|error| panic!("create object: {error}\n{}", read_log(&log_path)));
    chisei
        .set_budget_limit(SetBudgetLimitRequest {
            user_id: BUDGET_USER.into(),
            max_tokens: BUDGET_LIMIT,
            period_type: "daily".into(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("set budget: {error}\n{}", read_log(&log_path)));

    drop(sekai);
    drop(chisei);
    drop(child);
    assert_plane_isolation(&sekai_path, &chisei_path);
}

#[cfg(unix)]
struct KillOnDrop(Child);

#[cfg(unix)]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
fn wait_until_ready(socket: &Path, child: &mut Child, log_path: &Path) {
    let deadline = Instant::now() + WAIT_BUDGET;
    loop {
        if UnixStream::connect(socket).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll server") {
            panic!(
                "sekai-chisei exited {status} before the Unix socket was ready\n{}",
                read_log(log_path)
            );
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {}\n{}",
                socket.display(),
                read_log(log_path)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_log(path: &Path) -> String {
    let mut contents = String::new();
    if let Ok(mut file) = std::fs::File::open(path) {
        let _ = file.read_to_string(&mut contents);
    }
    contents
}

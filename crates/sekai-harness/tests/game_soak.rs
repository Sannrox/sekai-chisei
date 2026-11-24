//! A short game soak against the shipped binary (#1626).
//!
//! Two bounded runs with one seed, in two namespaces of one deployment,
//! go through the same public gRPC path as a real soak: bots propose
//! governed Actions, intake applies battle batches, and the statistics
//! transform runs with lineage. Both runs apply exactly the scripted
//! Action sequence, and the harness writes the throughput document.
#![cfg(unix)]

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sekai_chisei::grpc::client::{GatewayClient, connect_sekai};
use sekai_chisei::grpc::pb::sekai::ListActionInstancesRequest;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::sekai::synthetic::SizePreset;
use sekai_harness::game_soak::{HardwareProfile, SoakSpec, run, script};

/// The shipped `sekai-chisei` binary. It belongs to the root package, so
/// Cargo does not hand this crate its path; `cargo test --workspace` builds it
/// into the same target directory before any test runs.
fn server_bin() -> PathBuf {
    let mut bin = std::env::current_exe().expect("test binary path");
    bin.pop();
    if bin.ends_with("deps") {
        bin.pop();
    }
    bin.push("sekai-chisei");
    assert!(
        bin.is_file(),
        "{} is missing: build `sekai-chisei` first (cargo build -p sekai-chisei --bin sekai-chisei) \
         or run the workspace tests",
        bin.display()
    );
    bin
}

/// One SQLite-backed server on a private socket, killed on drop.
struct SoakServer {
    child: Child,
    _dir: tempfile::TempDir,
    socket: PathBuf,
    log_path: PathBuf,
}

impl SoakServer {
    fn spawn() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("sekai.sock");
        let log_path = dir.path().join("sekai.log");
        let log = std::fs::File::create(&log_path).expect("server log");
        let child = Command::new(server_bin())
            .env("SEKAI_SOCKET", &socket)
            .env("GRPC_PORT", "0")
            .env("OPS_PORT", "")
            .env("RUST_LOG", "error")
            .env("SEKAI_EXPERIMENTAL_RPCS", "1")
            .env("SEKAI_DATA_DIR", dir.path())
            .env("SEKAI_DB_PATH", dir.path().join("sekai.db"))
            .env("CHISEI_DB_PATH", dir.path().join("chisei.db"))
            .env_remove("SEKAI_OBJECT_LOG")
            .env_remove("SEKAI_OBJECT_LOG_HOST")
            .env_remove("SEKAI_DB_BACKEND")
            .env_remove("SEKAI_DATABASE_URL")
            .env_remove("CHISEI_DATABASE_URL")
            .env_remove("SEKAI_INSECURE")
            .env_remove("SEKAI_CREDENTIAL")
            .env_remove("SEKAI_BIND")
            .env_remove("OLLAMA_URL")
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn sekai-chisei");
        let mut server = Self {
            child,
            _dir: dir,
            socket,
            log_path,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while UnixStream::connect(&server.socket).is_err() {
            if let Some(status) = server.child.try_wait().expect("poll server") {
                panic!("server exited {status} before ready\n{}", server.logs());
            }
            assert!(
                Instant::now() < deadline,
                "server not ready\n{}",
                server.logs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        server
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn socket_str(&self) -> String {
        self.socket.to_str().expect("utf8 socket").to_string()
    }

    async fn sekai(&self) -> SekaiServiceClient<GatewayClient> {
        SekaiServiceClient::new(connect_sekai(&self.socket_str()).await.expect("connect"))
    }

    fn panics(&self) -> usize {
        self.logs().matches("panicked").count()
    }
}

impl Drop for SoakServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_seed_applies_one_action_sequence_and_writes_the_document() {
    let server = SoakServer::spawn();
    let spec = SoakSpec {
        seed: 7,
        preset: SizePreset::Demo,
        bots: 2,
        rounds: 3,
        batch_records: 5,
    };
    let hardware = HardwareProfile {
        description: "test runner".into(),
        cores: 1,
        operating_system: "test os".into(),
        rustc: "rustc test".into(),
        build_profile: "debug".into(),
    };
    let mut sekai = server.sekai().await;
    let mut digests = Vec::new();
    for namespace in ["soak-first", "soak-second"] {
        let script = script(&spec, namespace).unwrap();
        let report = run(
            &server.socket_str(),
            &script,
            hardware.clone(),
            "2026-01-01T00:00:00Z".into(),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}\n{}", server.logs()));
        assert_eq!(report.actions.proposed, 6);
        assert_eq!(report.actions.applied, 6);
        assert_eq!(report.intake.batches, 3);
        assert_eq!(report.intake.records, 15);
        assert!(report.transform.runs >= 1);
        assert!(report.transform.lineage_chained);
        assert!(report.transform.output_rows > 0);

        // The plane holds exactly the scripted proposals, each applied
        // under its bot's own principal.
        let applied: HashMap<String, _> = sekai
            .list_action_instances(ListActionInstancesRequest {
                namespace: namespace.into(),
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .instances
            .into_iter()
            .map(|instance| (instance.idempotency_key.clone(), instance))
            .collect();
        assert_eq!(applied.len(), 6);
        for (bot, proposals) in script.proposals().into_iter().enumerate() {
            for proposal in proposals {
                let instance = &applied[&proposal.idempotency_key];
                assert_eq!(instance.status, "admitted");
                assert_eq!(instance.principal, script.bot_principal(bot));
                assert_eq!(instance.parameters_json, proposal.parameters_json);
            }
        }

        let out = tempfile::tempdir().unwrap();
        report.write(out.path()).unwrap();
        let document = std::fs::read_to_string(out.path().join("report.md")).unwrap();
        assert!(document.contains("Actions/s"), "{document}");
        assert!(document.contains(&script.action_digest));
        assert!(!document.contains(&server.socket_str()));
        assert!(!document.contains(namespace));
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.path().join("report.json")).unwrap())
                .unwrap();
        assert_eq!(json["contract_version"], "sekai.game-soak-report/v1");
        digests.push(report.workload.action_digest);
    }
    assert_eq!(digests[0], digests[1]);
    assert_eq!(server.panics(), 0, "{}", server.logs());
}

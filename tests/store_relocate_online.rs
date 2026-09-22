//! Process-level proof that `sekaictl admin store relocate` runs online
//! (#1107): a writer keeps landing Chisei rows on the historical store while
//! the shipped CLI bulk-copies it, every acknowledged write reaches the Chisei
//! destination, writes after the fence are refused by the source database
//! itself, and the Split server boots on the relocated pair.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sekai_chisei::chisei::budget::{BudgetTracker, PeriodType};
use sekai_chisei::db::store::ChiseiStore;
use sekai_chisei::runtime_backend::{BackendIdentity, RuntimeBackend, RuntimeBackendConfig};
use serde_json::Value;

const WAIT_BUDGET: Duration = Duration::from_secs(20);
const SEEDED_USERS: i32 = 200;

fn init_sqlite(path: &str) {
    RuntimeBackend::initialize(
        RuntimeBackendConfig::from_sources(
            BackendIdentity::Sqlite,
            Some(path),
            path,
            None,
            16,
            None,
        )
        .expect("backend config"),
    )
    .expect("initialize store");
}

fn tracker(path: &str) -> BudgetTracker {
    BudgetTracker::new(ChiseiStore::open_sqlite(path))
}

fn limit_for(index: i32) -> i32 {
    1_000 + index
}

#[test]
fn relocate_keeps_every_acknowledged_write_and_fences_the_source_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("legacy.db");
    let chisei = dir.path().join("chisei.db");
    let source_s = source.to_str().expect("utf8").to_string();
    let chisei_s = chisei.to_str().expect("utf8").to_string();
    init_sqlite(&source_s);
    for index in 0..SEEDED_USERS {
        tracker(&source_s)
            .set_limit(
                &format!("seed-{index}"),
                limit_for(index),
                PeriodType::Daily,
            )
            .expect("seed budget");
    }

    // A Shared-mode writer that keeps running across the relocate.
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let stop = Arc::clone(&stop);
        let source_s = source_s.clone();
        std::thread::spawn(move || {
            let mut acknowledged = Vec::new();
            let mut fenced = 0usize;
            let mut index = 0;
            while !stop.load(Ordering::SeqCst) {
                match tracker(&source_s).set_limit(
                    &format!("live-{index}"),
                    limit_for(index),
                    PeriodType::Daily,
                ) {
                    Ok(()) => acknowledged.push(index),
                    Err(error) if error.to_string().contains("writer fence raised") => fenced += 1,
                    Err(_) => {}
                }
                index += 1;
            }
            (acknowledged, fenced)
        })
    };

    let output = Command::new(env!("CARGO_BIN_EXE_sekaictl"))
        .args([
            "admin", "store", "relocate", "--source", &source_s, "--sekai", &source_s, "--chisei",
            &chisei_s,
        ])
        .output()
        .expect("run sekaictl");
    stop.store(true, Ordering::SeqCst);
    let (acknowledged, _fenced) = writer.join().expect("writer thread");
    assert!(
        output.status.success(),
        "relocate failed ({:?})\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["fence_raised"], true, "{report}");
    assert!(report["fence_window_ms"].is_u64(), "{report}");
    assert!(report["recopied"].is_array(), "{report}");

    for index in 0..SEEDED_USERS {
        assert_eq!(
            tracker(&chisei_s)
                .get_usage(&format!("seed-{index}"))
                .max_tokens,
            limit_for(index)
        );
    }
    for index in &acknowledged {
        assert_eq!(
            tracker(&chisei_s)
                .get_usage(&format!("live-{index}"))
                .max_tokens,
            limit_for(*index),
            "acknowledged write live-{index} did not reach the Chisei store\n{report}"
        );
    }

    let late = tracker(&source_s)
        .set_limit("after-fence", 1, PeriodType::Daily)
        .expect_err("the source database refuses Chisei writes after the fence")
        .to_string();
    assert!(late.contains("writer fence raised"), "{late}");

    boot_split_server(dir.path(), &source, &chisei);
}

fn boot_split_server(dir: &Path, sekai: &Path, chisei: &Path) {
    let socket: PathBuf = dir.join("sekai.sock");
    let log_path = dir.join("server.log");
    let log = std::fs::File::create(&log_path).expect("server log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"))
        .env("SEKAI_SOCKET", &socket)
        .env("SEKAI_DB_PATH", sekai)
        .env("CHISEI_DB_PATH", chisei)
        .env("GRPC_PORT", free_tcp_port().to_string())
        .env("OPS_PORT", "")
        .env("OPS_BIND", "127.0.0.1")
        .env("RUST_LOG", "error")
        .env_remove("SEKAI_SHARED_STORE")
        .env_remove("DB_PATH")
        .env_remove("SEKAI_EXPERIMENTAL_RPCS")
        .env_remove("SEKAI_INSECURE")
        .env_remove("SEKAI_CREDENTIAL")
        .env_remove("SEKAI_BIND")
        .env_remove("SEKAI_ALLOW_PLAINTEXT")
        .env_remove("SEKAI_DB_BACKEND")
        .env_remove("DATABASE_URL")
        .env_remove("OLLAMA_URL")
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn sekai-chisei");
    let deadline = Instant::now() + WAIT_BUDGET;
    let ready = loop {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            break Ok(());
        }
        if let Some(status) = child.try_wait().expect("poll server") {
            break Err(format!("exited {status}"));
        }
        if Instant::now() >= deadline {
            break Err("timed out".to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();
    if let Err(reason) = ready {
        panic!(
            "Split server on the relocated pair {reason} before its socket was ready\n{}",
            std::fs::read_to_string(&log_path).unwrap_or_default()
        );
    }
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

//! Process-level proof of Split per-plane pool sizing (#1109): the shipped
//! server accepts per-plane sizes that fit the process ceiling, reports pool
//! checkouts per plane on `/metrics` so starvation of one plane is
//! measurable, and refuses to start when the sizes exceed the ceiling.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WAIT_BUDGET: Duration = Duration::from_secs(20);

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn split_server(dir: &Path, ops_port: u16, sekai: &str, chisei: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"));
    command
        .env("SEKAI_SOCKET", dir.join("sekai.sock"))
        .env("SEKAI_DB_PATH", dir.join("sekai.db"))
        .env("CHISEI_DB_PATH", dir.join("chisei.db"))
        .env("GRPC_PORT", free_tcp_port().to_string())
        .env("OPS_PORT", ops_port.to_string())
        .env("OPS_BIND", "127.0.0.1")
        .env("RUST_LOG", "error")
        .env("SEKAI_POSTGRES_MAX_CONNECTIONS", "16")
        .env("SEKAI_POSTGRES_SEKAI_CONNECTIONS", sekai)
        .env("SEKAI_POSTGRES_CHISEI_CONNECTIONS", chisei)
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
        .env_remove("ANTHROPIC_API_KEY");
    command
}

fn http_get(port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn split_pools_take_per_plane_sizes_and_report_checkouts_per_plane() {
    let dir = tempfile::tempdir().expect("temp dir");
    let ops_port = free_tcp_port();
    let log_path = dir.path().join("server.log");
    let log = std::fs::File::create(&log_path).expect("server log");
    let mut running = Running(
        split_server(dir.path(), ops_port, "12", "4")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn sekai-chisei"),
    );
    let logs = || std::fs::read_to_string(&log_path).unwrap_or_default();

    let deadline = Instant::now() + WAIT_BUDGET;
    let metrics = loop {
        if let Some(status) = running.0.try_wait().expect("poll server") {
            panic!("server exited {status} before serving metrics\n{}", logs());
        }
        // Readiness reads both stores, so each plane checks out a connection.
        let _ = http_get(ops_port, "/readyz");
        if let Some(body) = http_get(ops_port, "/metrics")
            && body.contains(r#"plane="sekai""#)
            && body.contains(r#"plane="chisei""#)
        {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "per-plane pool metrics never appeared\n{}",
            logs()
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    for plane in ["sekai", "chisei"] {
        assert!(
            metrics.lines().any(|line| {
                line.starts_with("sekai_db_pool_checkout_seconds_count")
                    && line.contains(&format!(r#"plane="{plane}""#))
                    && line.contains(r#"outcome="ok""#)
            }),
            "no checkout series for plane {plane}\n{metrics}"
        );
        assert!(
            metrics.lines().any(|line| {
                line.starts_with("sekai_db_pool_in_use_ratio")
                    && line.contains(&format!(r#"plane="{plane}""#))
            }),
            "no in-use ratio for plane {plane}\n{metrics}"
        );
    }
    // Migrations check out connections before the plane label is set, but
    // the metrics recorder is installed only when the ops listener starts,
    // after both stores open. Every recorded checkout is therefore labeled.
    assert!(
        !metrics.contains(r#"plane="shared""#),
        "a Split server must not report a shared pool\n{metrics}"
    );
}

#[test]
fn split_pool_sizes_over_the_process_ceiling_refuse_to_start() {
    let dir = tempfile::tempdir().expect("temp dir");
    let output = split_server(dir.path(), free_tcp_port(), "12", "8")
        .output()
        .expect("run sekai-chisei");
    assert!(
        !output.status.success(),
        "over-budget Split pools must not start"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("exceed SEKAI_POSTGRES_MAX_CONNECTIONS (16)")
            || stdout.contains("exceed SEKAI_POSTGRES_MAX_CONNECTIONS (16)"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
}

//! Boot with `SEKAI_TLS_CERT` / `SEKAI_TLS_KEY` must stay up and accept TLS gRPC.

use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;

const WAIT_BUDGET: Duration = Duration::from_secs(20);
const SERVER_CERT: &[u8] = include_bytes!("../crates/sekai-client/tests/fixtures/tls/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../crates/sekai-client/tests/fixtures/tls/server.key");
const TRUSTED_CA: &[u8] =
    include_bytes!("../crates/sekai-client/tests/fixtures/tls/trusted-ca.pem");

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
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

fn read_log(path: &Path) -> String {
    let mut contents = String::new();
    if let Ok(mut file) = std::fs::File::open(path) {
        let _ = file.read_to_string(&mut contents);
    }
    contents
}

fn wait_until_listening(port: u16, child: &mut Child, log_path: &Path) {
    let deadline = Instant::now() + WAIT_BUDGET;
    let addr = format!("127.0.0.1:{port}");
    loop {
        if let Some(status) = child.try_wait().expect("poll server") {
            panic!(
                "sekai-chisei exited {status} before TLS gRPC listened on {addr}\n{}",
                read_log(log_path)
            );
        }
        // A stolen `free_port()` fails bind and the child exits above. A
        // healthy child that binds before the first poll must still count as
        // ready; requiring a closed-to-open edge hangs until WAIT_BUDGET.
        if std::net::TcpStream::connect(&addr).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for TLS gRPC on {addr}\n{}",
                read_log(log_path)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_serves_grpc_over_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    std::fs::write(&cert_path, SERVER_CERT).expect("write cert");
    std::fs::write(&key_path, SERVER_KEY).expect("write key");
    let log_path = dir.path().join("sekai.log");
    let log = std::fs::File::create(&log_path).expect("server log");
    let port = free_port();

    let mut command = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"));
    command
        .env("SEKAI_DB_PATH", dir.path().join("sekai.db"))
        .env("CHISEI_DB_PATH", dir.path().join("chisei.db"))
        .env("GRPC_PORT", port.to_string())
        .env("OPS_PORT", "")
        .env("SEKAI_HTTP_PORT", "")
        .env("SEKAI_SOCKET", "")
        .env("SEKAI_INSECURE", "1")
        .env("SEKAI_BIND", "127.0.0.1")
        .env("SEKAI_TLS_CERT", &cert_path)
        .env("SEKAI_TLS_KEY", &key_path)
        .env("RUST_LOG", "error")
        .env_remove("SEKAI_ALLOW_PLAINTEXT")
        .env_remove("SEKAI_CREDENTIAL")
        .env_remove("SEKAI_DB_BACKEND")
        .env_remove("DATABASE_URL")
        .env_remove("SEKAI_DATABASE_URL")
        .env_remove("CHISEI_DATABASE_URL")
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log));
    let mut child = KillOnDrop(command.spawn().expect("spawn sekai-chisei"));
    wait_until_listening(port, &mut child.0, &log_path);

    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(TRUSTED_CA));
    let channel = Channel::from_shared(format!("https://127.0.0.1:{port}"))
        .expect("tls endpoint")
        .tls_config(tls)
        .expect("client tls")
        .connect()
        .await
        .unwrap_or_else(|error| panic!("tls connect: {error}\n{}", read_log(&log_path)));
    let response = HealthClient::new(channel)
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .unwrap_or_else(|error| panic!("health check: {error}\n{}", read_log(&log_path)))
        .into_inner();
    assert_eq!(response.status, tonic_health::ServingStatus::Serving as i32);
}

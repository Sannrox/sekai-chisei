//! Boot with `SEKAI_TLS_CERT` / `SEKAI_TLS_KEY` must stay up and accept TLS gRPC.
//! `SEKAI_TLS_CLIENT_CA` requires a client certificate signed by that CA.

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;

const WAIT_BUDGET: Duration = Duration::from_secs(20);
const SERVER_CERT: &[u8] = include_bytes!("../crates/sekai-client/tests/fixtures/tls/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../crates/sekai-client/tests/fixtures/tls/server.key");
const TRUSTED_CA: &[u8] =
    include_bytes!("../crates/sekai-client/tests/fixtures/tls/trusted-ca.pem");
const CLIENT_CA: &[u8] = include_bytes!("../crates/sekai-client/tests/fixtures/tls/client-ca.pem");
const CLIENT_CERT: &[u8] = include_bytes!("../crates/sekai-client/tests/fixtures/tls/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../crates/sekai-client/tests/fixtures/tls/client.key");
const OTHER_CLIENT_CERT: &[u8] =
    include_bytes!("../crates/sekai-client/tests/fixtures/tls/other-client.pem");
const OTHER_CLIENT_KEY: &[u8] =
    include_bytes!("../crates/sekai-client/tests/fixtures/tls/other-client.key");

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

struct TlsServer {
    _child: KillOnDrop,
    port: u16,
    log_path: PathBuf,
}

fn tls_boot_command(
    dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    port: u16,
    log: &std::fs::File,
    client_ca: Option<&Path>,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"));
    command
        .env("SEKAI_DB_PATH", dir.join("sekai.db"))
        .env("CHISEI_DB_PATH", dir.join("chisei.db"))
        .env("GRPC_PORT", port.to_string())
        .env("OPS_PORT", "")
        .env("SEKAI_HTTP_PORT", "")
        .env("SEKAI_SOCKET", "")
        .env("SEKAI_INSECURE", "1")
        .env("SEKAI_BIND", "127.0.0.1")
        .env("SEKAI_TLS_CERT", cert_path)
        .env("SEKAI_TLS_KEY", key_path)
        .env("RUST_LOG", "error")
        .env_remove("SEKAI_ALLOW_PLAINTEXT")
        .env_remove("SEKAI_CREDENTIAL")
        .env_remove("SEKAI_DB_BACKEND")
        .env_remove("DATABASE_URL")
        .env_remove("SEKAI_DATABASE_URL")
        .env_remove("CHISEI_DATABASE_URL")
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log.try_clone().expect("clone log")));
    match client_ca {
        Some(path) => {
            command.env("SEKAI_TLS_CLIENT_CA", path);
        }
        None => {
            command.env_remove("SEKAI_TLS_CLIENT_CA");
        }
    }
    command
}

fn spawn_tls_server(dir: &Path, client_ca: Option<&Path>) -> TlsServer {
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    std::fs::write(&cert_path, SERVER_CERT).expect("write cert");
    std::fs::write(&key_path, SERVER_KEY).expect("write key");
    let log_path = dir.join("sekai.log");
    let log = std::fs::File::create(&log_path).expect("server log");
    let port = free_port();
    let mut child = KillOnDrop(
        tls_boot_command(dir, &cert_path, &key_path, port, &log, client_ca)
            .spawn()
            .expect("spawn sekai-chisei"),
    );
    wait_until_listening(port, &mut child.0, &log_path);
    TlsServer {
        _child: child,
        port,
        log_path,
    }
}

fn client_tls(identity: Option<Identity>) -> ClientTlsConfig {
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(TRUSTED_CA));
    match identity {
        Some(identity) => tls.identity(identity),
        None => tls,
    }
}

async fn health_connect(port: u16, tls: ClientTlsConfig, log_path: &Path) -> Result<i32, String> {
    let channel = Channel::from_shared(format!("https://127.0.0.1:{port}"))
        .map_err(|error| error.to_string())?
        .tls_config(tls)
        .map_err(|error| error.to_string())?
        .connect()
        .await
        .map_err(|error| format!("tls connect: {error}\n{}", read_log(log_path)))?;
    let response = HealthClient::new(channel)
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .map_err(|error| format!("health check: {error}\n{}", read_log(log_path)))?
        .into_inner();
    Ok(response.status)
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_serves_grpc_over_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("temp dir");
    let server = spawn_tls_server(dir.path(), None);
    let status = health_connect(server.port, client_tls(None), &server.log_path)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(status, tonic_health::ServingStatus::Serving as i32);
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_binary_requires_client_certificate_when_client_ca_is_set() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("temp dir");
    let ca_path = dir.path().join("client-ca.pem");
    std::fs::write(&ca_path, CLIENT_CA).expect("write client CA");
    let server = spawn_tls_server(dir.path(), Some(&ca_path));

    let without_cert = health_connect(server.port, client_tls(None), &server.log_path).await;
    assert!(
        without_cert.is_err(),
        "missing client certificate must be refused: {without_cert:?}"
    );

    let other = health_connect(
        server.port,
        client_tls(Some(Identity::from_pem(
            OTHER_CLIENT_CERT,
            OTHER_CLIENT_KEY,
        ))),
        &server.log_path,
    )
    .await;
    assert!(
        other.is_err(),
        "client certificate signed by another CA must be refused: {other:?}"
    );

    let status = health_connect(
        server.port,
        client_tls(Some(Identity::from_pem(CLIENT_CERT, CLIENT_KEY))),
        &server.log_path,
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(status, tonic_health::ServingStatus::Serving as i32);
}

#[tokio::test(flavor = "multi_thread")]
async fn unreadable_client_ca_exits_before_listen() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    std::fs::write(&cert_path, SERVER_CERT).expect("write cert");
    std::fs::write(&key_path, SERVER_KEY).expect("write key");
    let missing_ca = dir.path().join("missing-ca.pem");
    let log_path = dir.path().join("sekai.log");
    let log = std::fs::File::create(&log_path).expect("server log");
    let port = free_port();

    let mut child = KillOnDrop(
        tls_boot_command(
            dir.path(),
            &cert_path,
            &key_path,
            port,
            &log,
            Some(&missing_ca),
        )
        .spawn()
        .expect("spawn sekai-chisei"),
    );
    let deadline = Instant::now() + WAIT_BUDGET;
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("poll server") {
            break status;
        }
        if Instant::now() >= deadline {
            panic!(
                "process stayed up with unreadable SEKAI_TLS_CLIENT_CA\n{}",
                read_log(&log_path)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        !status.success(),
        "expected fail-closed startup, got {status}"
    );
    let log = read_log(&log_path);
    assert!(
        log.contains("SEKAI_TLS_CLIENT_CA") || log.contains("unreadable"),
        "fail-closed startup must name the client CA: {log}"
    );
}

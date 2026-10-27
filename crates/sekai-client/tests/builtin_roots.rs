//! `ClientConfig::without_builtin_roots` trusts only the configured CA.
//!
//! The fixtures under `tests/fixtures/tls/` are test-only: two private CAs
//! and a `localhost` server certificate signed by `trusted-ca.pem`, valid for
//! a century. A certificate chaining to a public root cannot be issued
//! offline, so the refusal side is shown with a second private CA.

use std::time::Duration;

use sekai_client::{ClientConfig, CoreLoopClient};
use tokio::net::TcpListener;
use tonic::service::Routes;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Identity, Server, ServerTlsConfig};

const TRUSTED_CA: &[u8] = include_bytes!("fixtures/tls/trusted-ca.pem");
const OTHER_CA: &[u8] = include_bytes!("fixtures/tls/other-ca.pem");
const SERVER_CERT: &[u8] = include_bytes!("fixtures/tls/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("fixtures/tls/server.key");

/// An HTTPS gRPC server on an ephemeral port with the fixture certificate;
/// returns its target URL.
async fn tls_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tls = ServerTlsConfig::new().identity(Identity::from_pem(SERVER_CERT, SERVER_KEY));
    let router = Server::builder()
        .tls_config(tls)
        .unwrap()
        .add_routes(Routes::default());
    tokio::spawn(router.serve_with_incoming(TcpIncoming::from(listener)));
    format!("https://localhost:{port}")
}

fn config(target: &str) -> ClientConfig {
    ClientConfig::new(target, "test").with_default_timeout(Duration::from_secs(5))
}

#[tokio::test]
async fn only_the_configured_ca_is_trusted_without_builtin_roots() {
    let target = tls_server().await;

    let trusted = config(&target)
        .with_tls_ca_certificate(TRUSTED_CA.to_vec())
        .without_builtin_roots();
    assert!(CoreLoopClient::connect(trusted).await.is_ok());

    let untrusted = config(&target)
        .with_tls_ca_certificate(OTHER_CA.to_vec())
        .without_builtin_roots();
    assert!(CoreLoopClient::connect(untrusted).await.is_err());
}

#[tokio::test]
async fn without_builtin_roots_needs_a_configured_ca() {
    let refused = config("https://localhost:1").without_builtin_roots();
    let error = CoreLoopClient::connect(refused).await.err().unwrap();
    assert_eq!(error, sekai_client::SdkError::invalid_argument());
}

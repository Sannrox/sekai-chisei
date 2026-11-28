//! Process settings, Tenkai dependency-document gate, ops probes, and the
//! runner loop. Call [`run`] from the binary; tests drive the pieces.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use crate::ezu::{AdapterConfig, Error as AdapterError, FenceRunner, GeoFeedRunner, Sekai, Step};
use crate::http::HttpEzu;
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;

/// Contracts Ezu's Tenkai product provides. Both must be present.
pub const EZU_QUERY: &str = "ezu.query";
pub const EZU_EVENTS: &str = "ezu.events";
const DEFAULT_DEPENDENCIES: &str = "/etc/tenkai/dependencies.json";
const DEFAULT_OPS_BIND: &str = "127.0.0.1";
const DEFAULT_OPS_PORT: u16 = 9464;
const DEFAULT_LEASE_TTL_MS: i64 = 15_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ENGINE_POLL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DependencyDocument {
    version: u32,
    #[serde(default)]
    contracts: std::collections::BTreeMap<String, DependencyContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum DependencyContract {
    Present {
        product: String,
        release: String,
        contract: String,
    },
    Absent,
}

/// Whether Tenkai's dependency document lists an Ezu engine.
///
/// A missing, unreadable, or invalid document means the engine is absent.
/// Endpoints and credentials are not in the document.
pub fn ezu_engine_present(path: &Path) -> bool {
    let Some(document) = load_document(path) else {
        return false;
    };
    contract_present(&document, EZU_QUERY) && contract_present(&document, EZU_EVENTS)
}

fn load_document(path: &Path) -> Option<DependencyDocument> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn contract_present(document: &DependencyDocument, contract: &str) -> bool {
    matches!(
        document.contracts.get(contract),
        Some(DependencyContract::Present { .. })
    )
}

/// Probe result for `/readyz`. Idle is ready: without Ezu the process must
/// not block Tenkai apply of the rest of the product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Ezu contracts are absent; no adapter work.
    Idle,
    /// Ezu is present and both hops answer.
    Ready,
    /// Ezu is present but a hop failed.
    NotReady,
}

/// Ready when the engine is absent, or when it is present and both the
/// plane and Ezu answer. That is the work this replica can do.
pub fn readiness(engine_present: bool, plane_ok: bool, ezu_ok: bool) -> Readiness {
    if !engine_present {
        return Readiness::Idle;
    }
    if plane_ok && ezu_ok {
        Readiness::Ready
    } else {
        Readiness::NotReady
    }
}

impl Readiness {
    fn http(self) -> (StatusCode, &'static str) {
        match self {
            Self::Idle => (StatusCode::OK, "idle"),
            Self::Ready => (StatusCode::OK, "ok"),
            Self::NotReady => (StatusCode::SERVICE_UNAVAILABLE, "not ready"),
        }
    }
}

/// Host settings. Built from the environment by [`Settings::from_env`].
#[derive(Debug, Clone)]
pub struct Settings {
    pub dependencies_path: PathBuf,
    pub ops_bind: String,
    pub ops_port: u16,
    pub sekai_endpoint: String,
    pub sekai_credential: String,
    pub sekai_tls_ca: Option<PathBuf>,
    pub ezu_url: String,
    pub ezu_token: String,
    pub config: AdapterConfig,
    pub owner: String,
    pub lease_ttl_ms: i64,
}

impl Settings {
    /// Reads process environment. Missing Ezu URL or bearer is allowed
    /// until the engine is present; then [`run`] refuses to start work.
    pub fn from_env() -> Result<Self, String> {
        Self::from_vars(|key| std::env::var(key).ok())
    }

    pub fn from_vars(vars: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let config = load_config(
            vars("EZU_ADAPTER_CONFIG_FILE").as_deref(),
            vars("EZU_ADAPTER_CONFIG").as_deref(),
        )?;
        let owner = vars("EZU_ADAPTER_OWNER")
            .or_else(|| vars("HOSTNAME"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "ezu-adapter".into());
        let lease_ttl_ms = match vars("EZU_ADAPTER_LEASE_TTL_MS") {
            Some(raw) => raw
                .parse::<i64>()
                .map_err(|_| "EZU_ADAPTER_LEASE_TTL_MS is not an integer".to_string())
                .and_then(|ms| {
                    (ms > 0)
                        .then_some(ms)
                        .ok_or_else(|| "EZU_ADAPTER_LEASE_TTL_MS must be positive".to_string())
                })?,
            None => DEFAULT_LEASE_TTL_MS,
        };
        let ops_port = match vars("OPS_PORT") {
            Some(raw) if raw.is_empty() => {
                return Err("OPS_PORT is empty; the adapter needs ops probes".into());
            }
            Some(raw) => raw
                .parse::<u16>()
                .map_err(|_| "OPS_PORT is not a port".to_string())?,
            None => DEFAULT_OPS_PORT,
        };
        Ok(Self {
            dependencies_path: vars("TENKAI_DEPENDENCIES_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_DEPENDENCIES)),
            ops_bind: vars("OPS_BIND").unwrap_or_else(|| DEFAULT_OPS_BIND.into()),
            ops_port,
            sekai_endpoint: vars("SEKAI_ENDPOINT")
                .unwrap_or_else(|| "https://sekai-chisei:50051".into()),
            sekai_credential: vars("SEKAI_CREDENTIAL").unwrap_or_default(),
            sekai_tls_ca: vars("SEKAI_TLS_CA")
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from),
            ezu_url: vars("EZU_URL").unwrap_or_default(),
            ezu_token: vars("EZU_TOKEN").unwrap_or_default(),
            config,
            owner,
            lease_ttl_ms,
        })
    }
}

fn load_config(file: Option<&str>, inline: Option<&str>) -> Result<AdapterConfig, String> {
    if let Some(path) = file.filter(|path| !path.is_empty()) {
        let raw = std::fs::read_to_string(path)
            .map_err(|error| format!("EZU_ADAPTER_CONFIG_FILE: {error}"))?;
        return serde_json::from_str(&raw).map_err(|error| format!("adapter config: {error}"));
    }
    match inline.filter(|raw| !raw.is_empty()) {
        Some(raw) => serde_json::from_str(raw).map_err(|error| format!("adapter config: {error}")),
        None => Ok(AdapterConfig::default()),
    }
}

#[derive(Clone)]
struct OpsState {
    engine: watch::Receiver<bool>,
    hops: watch::Receiver<Hops>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Hops {
    plane_ok: bool,
    ezu_ok: bool,
}

/// Serves `/healthz` and `/readyz`, then runs feeds and bindings when an
/// Ezu engine is present. Without one, probes stay idle-ready. The
/// dependency document is re-read so a later Ezu engine starts work.
pub async fn run(settings: Settings) -> Result<(), String> {
    let (hops_tx, hops_rx) = watch::channel(Hops::default());
    let (engine_tx, engine_rx) = watch::channel(false);
    let (_ops, _addr) = serve_ops(&settings, engine_rx, hops_rx).await?;
    let mut announced_idle = false;
    'outer: loop {
        let present = ezu_engine_present(&settings.dependencies_path);
        let _ = engine_tx.send(present);
        if !present {
            let _ = hops_tx.send(Hops::default());
            if !announced_idle {
                tracing::info!("Ezu engine absent; adapter idle");
                announced_idle = true;
            }
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok(()),
                _ = tokio::time::sleep(ENGINE_POLL) => continue,
            }
        }
        announced_idle = false;
        if settings.ezu_url.trim().is_empty() || settings.ezu_token.trim().is_empty() {
            return Err("EZU_URL and EZU_TOKEN are required when an Ezu engine is present".into());
        }
        if settings.sekai_credential.trim().is_empty() {
            return Err("SEKAI_CREDENTIAL is required when an Ezu engine is present".into());
        }
        let ezu = HttpEzu::new(&settings.ezu_url, &settings.ezu_token);
        let client = loop {
            match connect_plane(&settings).await {
                Ok(client) => break client,
                Err(error) => {
                    tracing::warn!(%error, "plane is unreachable");
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => return Ok(()),
                        _ = tokio::time::sleep(ENGINE_POLL) => {
                            if !ezu_engine_present(&settings.dependencies_path) {
                                continue 'outer;
                            }
                        }
                    }
                }
            }
        };
        let sekai = Sekai::new(client, settings.sekai_credential.clone());
        let hops = hops_tx.clone();
        let ping_ezu = ezu.clone();
        let ping_sekai = sekai.clone();
        let ping = tokio::spawn(async move {
            loop {
                let ezu_ok = ping_ezu.ping().await.is_ok();
                let plane_ok = plane_reachable(&ping_sekai).await;
                let _ = hops.send(Hops { plane_ok, ezu_ok });
                tokio::time::sleep(ENGINE_POLL).await;
            }
        });
        let path = settings.dependencies_path.clone();
        let watch_doc = async {
            loop {
                tokio::time::sleep(ENGINE_POLL).await;
                if !ezu_engine_present(&path) {
                    return;
                }
            }
        };
        let work = run_loops(sekai, ezu, settings.clone());
        tokio::select! {
            () = work => {
                ping.abort();
                return Ok(());
            }
            _ = tokio::signal::ctrl_c() => {
                ping.abort();
                return Ok(());
            }
            () = watch_doc => {
                ping.abort();
                tracing::info!("Ezu engine left; adapter idle");
            }
        }
    }
}

async fn serve_ops(
    settings: &Settings,
    engine: watch::Receiver<bool>,
    hops: watch::Receiver<Hops>,
) -> Result<(tokio::task::JoinHandle<()>, SocketAddr), String> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(OpsState { engine, hops });
    let bind = format!("{}:{}", settings.ops_bind, settings.ops_port);
    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|error| format!("ops bind {bind}: {error}"))?;
    let addr = listener
        .local_addr()
        .map_err(|error| format!("ops addr: {error}"))?;
    Ok((
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                tracing::error!(%error, "ops listener exited");
            }
        }),
        addr,
    ))
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<OpsState>) -> impl IntoResponse {
    let hops = *state.hops.borrow();
    readiness(*state.engine.borrow(), hops.plane_ok, hops.ezu_ok).http()
}

async fn connect_plane(settings: &Settings) -> Result<SekaiServiceClient<Channel>, String> {
    let target = settings.sekai_endpoint.trim();
    if target.is_empty() {
        return Err("SEKAI_ENDPOINT is empty".into());
    }
    if settings.sekai_credential.trim().is_empty() {
        return Err("SEKAI_CREDENTIAL is empty".into());
    }
    let loopback =
        target.contains("127.0.0.1") || target.contains("localhost") || target.contains("[::1]");
    if !target.starts_with("https://") && !loopback {
        return Err("a credential is only sent over https or to a loopback target".into());
    }
    let mut endpoint = Endpoint::from_shared(target.to_string())
        .map_err(|_| "SEKAI_ENDPOINT is not a URI".to_string())?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(CONNECT_TIMEOUT);
    if target.starts_with("https://") {
        let mut tls = ClientTlsConfig::new().with_native_roots();
        if let Some(path) = settings.sekai_tls_ca.as_ref() {
            let cert = std::fs::read(path).map_err(|error| format!("SEKAI_TLS_CA: {error}"))?;
            tls = tls.ca_certificate(Certificate::from_pem(cert));
        }
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|error| format!("plane TLS: {error}"))?;
    }
    let channel = endpoint
        .connect()
        .await
        .map_err(|error| format!("plane is unreachable: {error}"))?;
    Ok(SekaiServiceClient::new(channel))
}

async fn plane_reachable(sekai: &Sekai) -> bool {
    sekai.probe().await.is_ok()
}

async fn run_loops(sekai: Sekai, ezu: HttpEzu, settings: Settings) {
    let ezu = Arc::new(ezu);
    loop {
        for feed in &settings.config.feeds {
            match GeoFeedRunner::start(
                sekai.clone(),
                feed.clone(),
                &settings.owner,
                settings.lease_ttl_ms,
            )
            .await
            {
                Ok(Some(mut runner)) => loop {
                    match runner.step(ezu.as_ref()).await {
                        Ok(Step::Worked) => {}
                        Ok(Step::Idle) => break,
                        Err(AdapterError::LeaseLost) => break,
                        Err(error) => {
                            tracing::warn!(%error, collection = %feed.collection, "geo feed step failed");
                            break;
                        }
                    }
                },
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, collection = %feed.collection, "geo feed start failed")
                }
            }
        }
        for binding in &settings.config.bindings {
            match FenceRunner::start(
                sekai.clone(),
                binding.clone(),
                &settings.owner,
                settings.lease_ttl_ms,
            )
            .await
            {
                Ok(Some(mut runner)) => loop {
                    match runner.step(ezu.as_ref()).await {
                        Ok(Step::Worked) => {}
                        Ok(Step::Idle) => break,
                        Err(AdapterError::LeaseLost) => break,
                        Err(error) => {
                            tracing::warn!(%error, binding = %binding.binding_id, "fence step failed");
                            break;
                        }
                    }
                },
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, binding = %binding.binding_id, "fence start failed")
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_doc(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("tenkai-dependencies.json");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(body.as_bytes()).expect("write");
        (dir, path)
    }

    #[test]
    fn missing_document_is_engine_absent() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        assert!(!ezu_engine_present(&dir.path().join("missing.json")));
    }

    #[test]
    fn invalid_document_is_engine_absent() {
        let (_dir, path) = write_doc("{not json");
        assert!(!ezu_engine_present(&path));
    }

    #[test]
    fn both_ezu_contracts_are_the_engine() {
        let json = r#"{"version":1,"contracts":{"ezu.query":{"state":"present","product":"ezu","release":"0.1.0","contract":"0.1.0"},"ezu.events":{"state":"present","product":"ezu","release":"0.1.0","contract":"0.1.0"}}}"#;
        let (_dir, path) = write_doc(json);
        assert!(ezu_engine_present(&path));
    }

    #[test]
    fn one_ezu_contract_is_not_the_engine() {
        let json = r#"{"version":1,"contracts":{"ezu.query":{"state":"present","product":"ezu","release":"0.1.0","contract":"0.1.0"},"ezu.events":{"state":"absent"}}}"#;
        let (_dir, path) = write_doc(json);
        assert!(!ezu_engine_present(&path));
    }

    #[test]
    fn kubernetes_product_optionally_requires_the_ezu_contracts() {
        let product = include_str!("../../../deploy/kubernetes/tenkai.toml");
        for contract in [EZU_QUERY, EZU_EVENTS] {
            assert!(
                product.contains(&format!("\"{contract}\"")),
                "{contract} is not in the kubernetes product requires"
            );
        }
        assert!(
            product.contains("optional = true"),
            "ezu requires must be optional so installs without Ezu still plan"
        );
    }

    #[test]
    fn apple_container_product_does_not_require_ezu() {
        let product = include_str!("../../../deploy/tenkai.toml");
        assert!(!product.contains("ezu.query"));
        assert!(!product.contains("ezu.events"));
    }

    #[test]
    fn absent_engine_is_idle_ready() {
        assert_eq!(readiness(false, false, false), Readiness::Idle);
        assert_eq!(readiness(false, true, true), Readiness::Idle);
    }

    #[test]
    fn present_engine_needs_both_hops() {
        assert_eq!(readiness(true, true, true), Readiness::Ready);
        assert_eq!(readiness(true, false, true), Readiness::NotReady);
        assert_eq!(readiness(true, true, false), Readiness::NotReady);
    }

    #[test]
    fn settings_load_empty_config_and_optional_ezu_secret() {
        let settings = Settings::from_vars(|key| match key {
            "SEKAI_ENDPOINT" => Some("https://sekai-chisei:50051".into()),
            "HOSTNAME" => Some("sekai-ezu-adapter-0".into()),
            _ => None,
        })
        .expect("settings");
        assert!(settings.ezu_url.is_empty());
        assert!(settings.ezu_token.is_empty());
        assert!(settings.config.feeds.is_empty());
        assert_eq!(settings.owner, "sekai-ezu-adapter-0");
        assert_eq!(settings.lease_ttl_ms, DEFAULT_LEASE_TTL_MS);
    }

    #[test]
    fn settings_load_config_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("adapter.json");
        std::fs::write(
            &path,
            r#"{"feeds":[{"namespace":"fleet","kind":"vehicle","geometry_property":"loc","collection":"vehicles"}]}"#,
        )
        .unwrap();
        let path_str = path.to_string_lossy().into_owned();
        let settings = Settings::from_vars(|key| match key {
            "EZU_ADAPTER_CONFIG_FILE" => Some(path_str.clone()),
            _ => None,
        })
        .expect("settings");
        assert_eq!(settings.config.feeds.len(), 1);
        assert_eq!(settings.config.feeds[0].collection, "vehicles");
    }

    #[test]
    fn unknown_config_fields_are_refused() {
        let error = load_config(None, Some(r#"{"feeds":[],"extra":true}"#)).unwrap_err();
        assert!(error.contains("adapter config"), "{error}");
    }

    fn ops_settings() -> Settings {
        Settings {
            dependencies_path: PathBuf::from("/nonexistent"),
            ops_bind: "127.0.0.1".into(),
            ops_port: 0,
            sekai_endpoint: "https://sekai-chisei:50051".into(),
            sekai_credential: String::new(),
            sekai_tls_ca: None,
            ezu_url: String::new(),
            ezu_token: String::new(),
            config: AdapterConfig::default(),
            owner: "test".into(),
            lease_ttl_ms: DEFAULT_LEASE_TTL_MS,
        }
    }

    #[tokio::test]
    async fn ops_is_idle_ready_when_the_engine_is_absent() {
        let (_engine_tx, engine_rx) = watch::channel(false);
        let (_tx, rx) = watch::channel(Hops::default());
        let (_task, addr) = serve_ops(&ops_settings(), engine_rx, rx)
            .await
            .expect("ops");
        let client = reqwest::Client::new();
        let health = client
            .get(format!("http://{addr}/healthz"))
            .send()
            .await
            .expect("healthz");
        assert_eq!(health.status(), reqwest::StatusCode::OK);
        assert_eq!(health.text().await.expect("body"), "ok");
        let ready = client
            .get(format!("http://{addr}/readyz"))
            .send()
            .await
            .expect("readyz");
        assert_eq!(ready.status(), reqwest::StatusCode::OK);
        assert_eq!(ready.text().await.expect("body"), "idle");
    }

    #[tokio::test]
    async fn ops_needs_both_hops_when_the_engine_is_present() {
        let (_engine_tx, engine_rx) = watch::channel(true);
        let (_tx, rx) = watch::channel(Hops::default());
        let (_task, addr) = serve_ops(&ops_settings(), engine_rx, rx)
            .await
            .expect("ops");
        let client = reqwest::Client::new();
        let ready = client
            .get(format!("http://{addr}/readyz"))
            .send()
            .await
            .expect("readyz");
        assert_eq!(ready.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        let (_engine_tx, engine_rx) = watch::channel(true);
        let (tx, rx) = watch::channel(Hops {
            plane_ok: true,
            ezu_ok: true,
        });
        let (_task, addr) = serve_ops(&ops_settings(), engine_rx, rx)
            .await
            .expect("ops");
        let _keep = tx;
        let ready = client
            .get(format!("http://{addr}/readyz"))
            .send()
            .await
            .expect("readyz");
        assert_eq!(ready.status(), reqwest::StatusCode::OK);
        assert_eq!(ready.text().await.expect("body"), "ok");
    }

    #[tokio::test]
    async fn ops_leaves_idle_when_the_engine_watch_flips() {
        let (engine_tx, engine_rx) = watch::channel(false);
        let (_hops_tx, hops_rx) = watch::channel(Hops::default());
        let (_task, addr) = serve_ops(&ops_settings(), engine_rx, hops_rx)
            .await
            .expect("ops");
        let client = reqwest::Client::new();
        let ready = client
            .get(format!("http://{addr}/readyz"))
            .send()
            .await
            .expect("readyz");
        assert_eq!(ready.status(), reqwest::StatusCode::OK);
        assert_eq!(ready.text().await.expect("body"), "idle");
        engine_tx.send(true).expect("flip");
        let ready = client
            .get(format!("http://{addr}/readyz"))
            .send()
            .await
            .expect("readyz");
        assert_eq!(ready.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn present_engine_without_secret_refuses_to_run() {
        let json = r#"{"version":1,"contracts":{"ezu.query":{"state":"present","product":"ezu","release":"0.1.0","contract":"0.1.0"},"ezu.events":{"state":"present","product":"ezu","release":"0.1.0","contract":"0.1.0"}}}"#;
        let (_dir, path) = write_doc(json);
        let mut settings = ops_settings();
        settings.dependencies_path = path;
        let error = run(settings).await.expect_err("secret required");
        assert!(
            error.contains("EZU_URL") && error.contains("EZU_TOKEN"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn appearing_engine_without_secret_starts_work() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("tenkai-dependencies.json");
        let mut settings = ops_settings();
        settings.dependencies_path = path.clone();
        let running = tokio::spawn(run(settings));
        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(
            &path,
            r#"{"version":1,"contracts":{"ezu.query":{"state":"present","product":"ezu","release":"0.1.0","contract":"0.1.0"},"ezu.events":{"state":"present","product":"ezu","release":"0.1.0","contract":"0.1.0"}}}"#,
        )
        .expect("write");
        let joined = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("picked up the document");
        let error = joined.expect("join").expect_err("secret required");
        assert!(error.contains("EZU_URL"), "{error}");
    }
}

//! `sekai-connector-runtime <config.json>`: serves the configured
//! namespaces until interrupted.
//!
//! The configuration names the plane, this runtime's id, principal,
//! namespaces and placement labels, and the operator's credential
//! bindings, and optionally a CA file relational Sources trust and a
//! `gateway_url` model steps call (#3025). The plane bearer comes from
//! `SEKAI_CREDENTIAL` and the gateway key from `CHISEI_GATEWAY_KEY`, never
//! from the file.

use std::collections::BTreeMap;
use std::future::Future;
use std::process::ExitCode;
use std::time::Duration;

use sekai_client::ClientConfig;
use std::path::PathBuf;

use sekai_connector_runtime::{
    Connectors, CredentialBindings, Runtime, RuntimeOptions, github, llm_rows::GatewayRoute,
    relational,
};
use sekai_source_sdk::{GITHUB_CONNECTOR, RELATIONAL_CONNECTOR};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    plane: String,
    principal: String,
    runtime_id: String,
    namespaces: Vec<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default = "default_lease_ms")]
    lease_ms: u64,
    #[serde(default = "default_poll_ms")]
    poll_ms: u64,
    #[serde(default)]
    credentials: CredentialBindings,
    /// A PEM CA certificate relational Sources trust next to the system
    /// roots, for a database behind a private CA.
    #[serde(default)]
    relational_ca_file: Option<PathBuf>,
    /// The model egress gateway's compatible surface, such as
    /// `http://127.0.0.1:8788/v1`. When set, the runtime runs `llm-rows`
    /// transform steps through it with the key in `CHISEI_GATEWAY_KEY`.
    #[serde(default)]
    gateway_url: Option<String>,
}

/// The gateway route for `url`, refusing a URL with no key.
fn gateway_route(url: Option<String>, key: Option<String>) -> Result<Option<GatewayRoute>, String> {
    let Some(base_url) = url.filter(|url| !url.trim().is_empty()) else {
        return Ok(None);
    };
    let key = key
        .filter(|key| !key.trim().is_empty())
        .ok_or("gateway_url needs the gateway key in CHISEI_GATEWAY_KEY")?;
    Ok(Some(GatewayRoute { base_url, key }))
}

fn default_lease_ms() -> u64 {
    60_000
}

fn default_poll_ms() -> u64 {
    5_000
}

/// Parses the runtime config and refuses timer settings the runtime cannot
/// run: a zero poll interval, or a lease too short to heartbeat within.
fn parse_config(text: &str) -> Result<Config, String> {
    let config: Config =
        serde_json::from_str(text).map_err(|error| format!("parse config: {error}"))?;
    if config.poll_ms == 0 {
        return Err("parse config: poll_ms must be at least 1".into());
    }
    if config.lease_ms < 3 {
        return Err(
            "parse config: lease_ms must be at least 3 so the runtime can heartbeat within it"
                .into(),
        );
    }
    Ok(config)
}

#[tokio::main]
async fn main() -> ExitCode {
    match serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sekai-connector-runtime: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> Result<(), String> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: sekai-connector-runtime <config.json>")?;
    let text = std::fs::read_to_string(&path).map_err(|error| format!("read config: {error}"))?;
    let config = parse_config(&text)?;
    let mut plane = ClientConfig::new(config.plane, config.principal);
    if let Ok(token) = std::env::var("SEKAI_CREDENTIAL") {
        plane = plane.with_token(token).map_err(|error| error.to_string())?;
    }
    let ca = config
        .relational_ca_file
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .map_err(|error| format!("read relational CA file: {error}"))?;
    let tls = relational::tls(ca.as_deref())?;
    let gateway = gateway_route(config.gateway_url, std::env::var("CHISEI_GATEWAY_KEY").ok())?;
    let connectors = Connectors::default()
        .with(&GITHUB_CONNECTOR, github::open)
        .with(&RELATIONAL_CONNECTOR, move |prepared| {
            relational::open(prepared, &tls)
        });
    let runtime = Runtime::connect(
        plane,
        &config.namespaces,
        RuntimeOptions {
            runtime_id: config.runtime_id,
            labels: config.labels,
            lease: Duration::from_millis(config.lease_ms),
        },
        config.credentials,
        connectors,
    )
    .await
    .map_err(|error| error.to_string())?;
    let runtime = match gateway {
        Some(route) => runtime.with_gateway(route),
        None => runtime,
    };
    runtime
        .register()
        .await
        .map_err(|error| error.to_string())?;
    runtime
        .serve(Duration::from_millis(config.poll_ms), shutdown_signal()?)
        .await;
    Ok(())
}

/// Resolves on SIGINT or SIGTERM (unix) or Ctrl-C (elsewhere) so
/// `Runtime::serve` returns between passes. Installing the handler is
/// fallible: a process that cannot listen exits with an error instead of
/// succeeding without work.
fn shutdown_signal() -> Result<impl Future<Output = ()>, String> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::SignalKind;
        let mut sigterm = unix_signal(SignalKind::terminate(), "SIGTERM")?;
        let mut sigint = unix_signal(SignalKind::interrupt(), "SIGINT")?;
        Ok(async move {
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = sigint.recv() => {}
            }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            tokio::signal::ctrl_c().await.expect("listen for interrupt");
        })
    }
}

#[cfg(unix)]
fn unix_signal(
    kind: tokio::signal::unix::SignalKind,
    name: &'static str,
) -> Result<tokio::signal::unix::Signal, String> {
    tokio::signal::unix::signal(kind).map_err(|error| format!("listen for {name}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{gateway_route, parse_config, shutdown_signal};

    #[test]
    fn a_gateway_url_without_a_key_is_refused() {
        assert!(gateway_route(None, None).unwrap().is_none());
        let refused = gateway_route(Some("http://127.0.0.1:8788/v1".into()), None).unwrap_err();
        assert!(refused.contains("CHISEI_GATEWAY_KEY"), "{refused}");
        let route = gateway_route(Some("http://127.0.0.1:8788/v1".into()), Some("k".into()))
            .unwrap()
            .unwrap();
        assert_eq!(route.base_url, "http://127.0.0.1:8788/v1");
    }

    fn config(timers: &str) -> String {
        format!(
            r#"{{"plane":"http://127.0.0.1:1","principal":"p","runtime_id":"r","namespaces":["acme"]{timers}}}"#
        )
    }

    #[test]
    fn zero_poll_and_unheartbeatable_lease_are_refused_by_name() {
        assert!(parse_config(&config("")).is_ok());
        let poll = parse_config(&config(r#","poll_ms":0"#)).err().unwrap();
        assert!(poll.contains("poll_ms"), "{poll}");
        let lease = parse_config(&config(r#","lease_ms":2"#)).err().unwrap();
        assert!(lease.contains("lease_ms"), "{lease}");
        assert!(parse_config(&config(r#","lease_ms":3,"poll_ms":1"#)).is_ok());
    }

    #[cfg(unix)]
    fn raise(signal: &str) {
        let ok = std::process::Command::new("kill")
            .args(["-s", signal, &std::process::id().to_string()])
            .status()
            .expect("run kill")
            .success();
        assert!(ok, "kill -s {signal}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_term_and_int_resolve_the_shutdown_future() {
        let term = shutdown_signal().expect("install SIGTERM listener");
        raise("TERM");
        tokio::time::timeout(std::time::Duration::from_secs(2), term)
            .await
            .expect("SIGTERM should resolve shutdown");

        let interrupt = shutdown_signal().expect("install SIGINT listener");
        raise("INT");
        tokio::time::timeout(std::time::Duration::from_secs(2), interrupt)
            .await
            .expect("SIGINT should resolve shutdown");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_signal_handler_install_is_an_error() {
        // SIGKILL cannot be caught; the OS refuses the handler.
        let error = super::unix_signal(tokio::signal::unix::SignalKind::from_raw(9), "SIGKILL")
            .expect_err("SIGKILL cannot be caught");
        assert!(error.contains("listen for SIGKILL"), "{error}");
    }
}

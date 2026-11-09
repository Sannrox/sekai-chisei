//! `sekai-connector-runtime <config.json>`: serves the configured
//! namespaces until interrupted.
//!
//! The configuration names the plane, this runtime's id, principal,
//! namespaces and placement labels, and the operator's credential
//! bindings. The plane bearer comes from `SEKAI_CREDENTIAL`, never from
//! the file.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::time::Duration;

use sekai_client::ClientConfig;
use sekai_connector_runtime::{Connectors, CredentialBindings, Runtime, RuntimeOptions, github};
use sekai_source_sdk::GITHUB_CONNECTOR;
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
}

fn default_lease_ms() -> u64 {
    60_000
}

fn default_poll_ms() -> u64 {
    5_000
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
    let config: Config =
        serde_json::from_str(&text).map_err(|error| format!("parse config: {error}"))?;
    let mut plane = ClientConfig::new(config.plane, config.principal);
    if let Ok(token) = std::env::var("SEKAI_CREDENTIAL") {
        plane = plane.with_token(token).map_err(|error| error.to_string())?;
    }
    let runtime = Runtime::connect(
        plane,
        &config.namespaces,
        RuntimeOptions {
            runtime_id: config.runtime_id,
            labels: config.labels,
            lease: Duration::from_millis(config.lease_ms),
        },
        config.credentials,
        Connectors::default().with(&GITHUB_CONNECTOR, github::open),
    )
    .await
    .map_err(|error| error.to_string())?;
    runtime
        .register()
        .await
        .map_err(|error| error.to_string())?;
    runtime
        .serve(Duration::from_millis(config.poll_ms), async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    Ok(())
}

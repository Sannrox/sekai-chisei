//! sekaictl admin sync webhook and source-health commands (#673, #685).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::source_health::{self, report_source_health};
use crate::sekai::source_webhook::{self, SourceWebhookDelivery};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin sync pin-webhook-key --namespace <ns> --source-instance <owner/repo> --key-id <id> --public-key-hex <hex> [--actor <principal>]\n  sekaictl admin sync list-webhook-keys [--namespace <ns>] [--source-instance <owner/repo>]\n  sekaictl admin sync admit-webhook --bundle <file> [--actor <principal>]\n  sekaictl admin sync health --namespace <ns> --source-instance <owner/repo> --type-digest <digest> [--actor <principal>] [--delayed-after-ms <n>]"
}

pub async fn run_sync_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("pin-webhook-key") => pin_key(parse_pin(&args[1..])?).await,
        Some("list-webhook-keys") => list_keys(parse_list(&args[1..])?).await,
        Some("admit-webhook") => admit(parse_admit(&args[1..])?).await,
        Some("health") => health(parse_health(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

struct PinConfig {
    namespace: String,
    source_instance: String,
    key_id: String,
    public_key_hex: String,
    actor: String,
}

async fn pin_key(config: PinConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let pin = source_webhook::pin_source_webhook_key(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.source_instance,
        &config.key_id,
        &config.public_key_hex,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&pin)?);
    Ok(())
}

struct ListConfig {
    namespace: Option<String>,
    source_instance: Option<String>,
}

async fn list_keys(config: ListConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let pins = source_webhook::list_source_webhook_keys(
        db.as_ref(),
        config.namespace.as_deref(),
        config.source_instance.as_deref(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&pins)?);
    Ok(())
}

struct AdmitConfig {
    bundle: PathBuf,
    actor: String,
}

async fn admit(config: AdmitConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let bytes = std::fs::read(&config.bundle)?;
    let delivery: SourceWebhookDelivery =
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let result = source_webhook::admit_source_webhook(
        db.as_ref(),
        &config.actor,
        &delivery,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn parse_pin(args: &[String]) -> Result<PinConfig, String> {
    let mut namespace = None;
    let mut source_instance = None;
    let mut key_id = None;
    let mut public_key_hex = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--source-instance" => {
                source_instance = Some(require_value(args, i, "--source-instance")?);
                i += 2;
            }
            "--key-id" => {
                key_id = Some(require_value(args, i, "--key-id")?);
                i += 2;
            }
            "--public-key-hex" => {
                public_key_hex = Some(require_value(args, i, "--public-key-hex")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown pin-webhook-key option {other}")),
        }
    }
    Ok(PinConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        source_instance: source_instance.ok_or("--source-instance is required")?,
        key_id: key_id.ok_or("--key-id is required")?,
        public_key_hex: public_key_hex.ok_or("--public-key-hex is required")?,
        actor,
    })
}

fn parse_list(args: &[String]) -> Result<ListConfig, String> {
    let mut namespace = None;
    let mut source_instance = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--source-instance" => {
                source_instance = Some(require_value(args, i, "--source-instance")?);
                i += 2;
            }
            other => return Err(format!("unknown list-webhook-keys option {other}")),
        }
    }
    Ok(ListConfig {
        namespace,
        source_instance,
    })
}

fn parse_admit(args: &[String]) -> Result<AdmitConfig, String> {
    let mut bundle = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                bundle = Some(PathBuf::from(require_value(args, i, "--bundle")?));
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown admit-webhook option {other}")),
        }
    }
    Ok(AdmitConfig {
        bundle: bundle.ok_or("--bundle is required")?,
        actor,
    })
}

struct HealthConfig {
    namespace: String,
    source_instance: String,
    type_digest: String,
    delayed_after_ms: Option<i64>,
    actor: String,
}

async fn health(config: HealthConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let query = source_health::parse_source_health_query(
        &config.namespace,
        &config.source_instance,
        &config.type_digest,
        config.delayed_after_ms,
        None,
    )
    .map_err(std::io::Error::other)?;
    let report = report_source_health(
        db.as_ref(),
        &config.actor,
        &query,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_health(args: &[String]) -> Result<HealthConfig, String> {
    let mut namespace = None;
    let mut source_instance = None;
    let mut type_digest = None;
    let mut delayed_after_ms = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--source-instance" => {
                source_instance = Some(require_value(args, i, "--source-instance")?);
                i += 2;
            }
            "--type-digest" => {
                type_digest = Some(require_value(args, i, "--type-digest")?);
                i += 2;
            }
            "--delayed-after-ms" => {
                delayed_after_ms = Some(
                    require_value(args, i, "--delayed-after-ms")?
                        .parse::<i64>()
                        .map_err(|_| "--delayed-after-ms must be an integer".to_string())?,
                );
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown health option {other}")),
        }
    }
    Ok(HealthConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        source_instance: source_instance.ok_or("--source-instance is required")?,
        type_digest: type_digest.ok_or("--type-digest is required")?,
        delayed_after_ms,
        actor,
    })
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

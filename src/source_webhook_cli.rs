//! sekaictl admin sync webhook, source-health, quarantine, and descriptor
//! commands (#673, #685, #818, #820).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::object_sync::SourceBatch;
use crate::sekai::source_health::{self, report_source_health};
use crate::sekai::source_quarantine::{
    self, apply_corrected_source_batch, inspect_latest_quarantine, preview_source_batch,
};
use crate::sekai::source_webhook::{self, SourceWebhookDelivery};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin sync pin-webhook-key --namespace <ns> --source-instance <owner/repo> --key-id <id> --public-key-hex <hex> [--actor <principal>]\n  sekaictl admin sync list-webhook-keys [--namespace <ns>] [--source-instance <owner/repo>]\n  sekaictl admin sync admit-webhook --bundle <file> [--actor <principal>]\n  sekaictl admin sync health --namespace <ns> --source-instance <owner/repo> --type-digest <digest> [--actor <principal>] [--delayed-after-ms <n>]\n  sekaictl admin sync inspect-quarantine --namespace <ns> --source-instance <owner/repo> --type-digest <digest> [--actor <principal>]\n  sekaictl admin sync preview-batch --batch <file> [--actor <principal>]\n  sekaictl admin sync apply-batch --batch <file> [--actor <principal>]\n  sekaictl admin sync register-descriptor --namespace <ns> --descriptor <file> [--actor <principal>]\n  sekaictl admin sync inspect-descriptor --namespace <ns> --digest <digest> [--actor <principal>]\n  sekaictl admin sync retire-descriptor --namespace <ns> --digest <digest> [--actor <principal>]"
}

pub async fn run_sync_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("pin-webhook-key") => pin_key(parse_pin(&args[1..])?).await,
        Some("list-webhook-keys") => list_keys(parse_list(&args[1..])?).await,
        Some("admit-webhook") => admit(parse_admit(&args[1..])?).await,
        Some("health") => health(parse_health(&args[1..])?).await,
        Some("inspect-quarantine") => {
            inspect_quarantine(parse_inspect_quarantine(&args[1..])?).await
        }
        Some("preview-batch") => preview_batch(parse_batch(&args[1..], "preview-batch")?).await,
        Some("apply-batch") => apply_batch(parse_batch(&args[1..], "apply-batch")?).await,
        Some("register-descriptor") => {
            register_descriptor(parse_register_descriptor(&args[1..])?).await
        }
        Some("inspect-descriptor") => {
            inspect_descriptor(parse_inspect_descriptor(&args[1..])?).await
        }
        Some("retire-descriptor") => retire_descriptor(parse_retire_descriptor(&args[1..])?).await,
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

async fn inspect_quarantine(config: InspectQuarantineConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let query = source_quarantine::parse_source_quarantine_query(
        &config.namespace,
        &config.source_instance,
        &config.type_digest,
    )
    .map_err(std::io::Error::other)?;
    let report = inspect_latest_quarantine(
        db.as_ref(),
        &config.actor,
        &query,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_inspect_quarantine(args: &[String]) -> Result<InspectQuarantineConfig, String> {
    let mut namespace = None;
    let mut source_instance = None;
    let mut type_digest = None;
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
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown inspect-quarantine option {other}")),
        }
    }
    Ok(InspectQuarantineConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        source_instance: source_instance.ok_or("--source-instance is required")?,
        type_digest: type_digest.ok_or("--type-digest is required")?,
        actor,
    })
}

struct InspectQuarantineConfig {
    namespace: String,
    source_instance: String,
    type_digest: String,
    actor: String,
}

struct BatchConfig {
    batch: PathBuf,
    actor: String,
}

async fn preview_batch(config: BatchConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let batch = load_source_batch(&config.batch)?;
    let report = preview_source_batch(
        db.as_ref(),
        &config.actor,
        &batch,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn apply_batch(config: BatchConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let batch = load_source_batch(&config.batch)?;
    let report = apply_corrected_source_batch(
        db.as_ref(),
        &config.actor,
        &batch,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_batch(args: &[String], command: &str) -> Result<BatchConfig, String> {
    let mut batch = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--batch" => {
                batch = Some(PathBuf::from(require_value(args, i, "--batch")?));
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown {command} option {other}")),
        }
    }
    Ok(BatchConfig {
        batch: batch.ok_or("--batch is required")?,
        actor,
    })
}

fn load_source_batch(path: &PathBuf) -> Result<SourceBatch, BoxErr> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

struct RegisterDescriptorConfig {
    namespace: String,
    descriptor: PathBuf,
    actor: String,
}

async fn register_descriptor(config: RegisterDescriptorConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let proposed: crate::sekai::source_type_descriptor::ProposedSourceTypeDescriptor =
        serde_json::from_slice(&std::fs::read(&config.descriptor)?)?;
    let admitted = crate::sekai::source_type_descriptor::register_source_type_descriptor(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &proposed,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&admitted)?);
    Ok(())
}

fn parse_register_descriptor(args: &[String]) -> Result<RegisterDescriptorConfig, String> {
    let mut namespace = None;
    let mut descriptor = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--descriptor" => {
                descriptor = Some(PathBuf::from(require_value(args, i, "--descriptor")?));
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown register-descriptor option {other}")),
        }
    }
    Ok(RegisterDescriptorConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        descriptor: descriptor.ok_or("--descriptor is required")?,
        actor,
    })
}

struct InspectDescriptorConfig {
    namespace: String,
    digest: String,
    actor: String,
}

async fn inspect_descriptor(config: InspectDescriptorConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let admitted = crate::sekai::source_type_descriptor::inspect_source_type_descriptor(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.digest,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&admitted)?);
    Ok(())
}

fn parse_inspect_descriptor(args: &[String]) -> Result<InspectDescriptorConfig, String> {
    parse_namespace_digest(args, "inspect-descriptor")
}

async fn retire_descriptor(config: InspectDescriptorConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let admitted = crate::sekai::source_type_descriptor::retire_source_type_descriptor(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.digest,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&admitted)?);
    Ok(())
}

fn parse_retire_descriptor(args: &[String]) -> Result<InspectDescriptorConfig, String> {
    parse_namespace_digest(args, "retire-descriptor")
}

fn parse_namespace_digest(
    args: &[String],
    command: &str,
) -> Result<InspectDescriptorConfig, String> {
    let mut namespace = None;
    let mut digest = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--digest" => {
                digest = Some(require_value(args, i, "--digest")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown {command} option {other}")),
        }
    }
    Ok(InspectDescriptorConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        digest: digest.ok_or("--digest is required")?,
        actor,
    })
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

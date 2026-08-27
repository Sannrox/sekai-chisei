//! sekaictl admin documents commands (#688).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::document::{self, DocumentRendition, DocumentRetrieve, GovernedDocument};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin documents admit --document <file> [--actor <principal>]\n  sekaictl admin documents attach-rendition --rendition <file> [--actor <principal>]\n  sekaictl admin documents get --namespace <ns> --document-id <id> --purpose <purpose> [--field <name>]... [--classification-ceiling <token>] [--actor <principal>]\n  sekaictl admin documents hold --namespace <ns> --document-id <id> --hold-id <id> --reason <text> [--actor <principal>]\n  sekaictl admin documents release-hold --namespace <ns> --document-id <id> --hold-id <id> [--actor <principal>]\n  sekaictl admin documents expire --namespace <ns> --document-id <id> [--actor <principal>]\n  sekaictl admin documents delete --namespace <ns> --document-id <id> [--actor <principal>]\n  --classification-ceiling may only restrict a sealed principal profile"
}

pub async fn run_documents_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("admit") => admit(parse_file_actor(&args[1..], "--document")?).await,
        Some("attach-rendition") => attach(parse_file_actor(&args[1..], "--rendition")?).await,
        Some("get") => get(parse_get(&args[1..])?).await,
        Some("hold") => hold(parse_hold(&args[1..])?).await,
        Some("release-hold") => release(parse_release(&args[1..])?).await,
        Some("expire") => expire(parse_document_actor(&args[1..])?).await,
        Some("delete") => delete(parse_document_actor(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

struct FileActor {
    path: PathBuf,
    actor: String,
}

async fn admit(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let document: GovernedDocument =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let admitted = document::admit_document(
        db.as_ref(),
        &config.actor,
        &document,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&admitted)?);
    Ok(())
}

async fn attach(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let rendition: DocumentRendition =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let attached = document::attach_rendition(
        db.as_ref(),
        &config.actor,
        &rendition,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&attached)?);
    Ok(())
}

struct GetConfig {
    namespace: String,
    document_id: String,
    purpose: String,
    fields: Vec<String>,
    classification_ceiling: Option<String>,
    actor: String,
}

async fn get(config: GetConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let view = document::retrieve_document(
        db.as_ref(),
        &config.actor,
        &DocumentRetrieve {
            namespace: config.namespace,
            document_id: config.document_id,
            purpose: Some(config.purpose),
            fields: config.fields,
            classification_ceiling: config.classification_ceiling,
        },
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}

struct HoldConfig {
    namespace: String,
    document_id: String,
    hold_id: String,
    reason: String,
    actor: String,
}

async fn hold(config: HoldConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let held = document::place_hold(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.document_id,
        &config.hold_id,
        &config.reason,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&held)?);
    Ok(())
}

struct ReleaseConfig {
    namespace: String,
    document_id: String,
    hold_id: String,
    actor: String,
}

async fn release(config: ReleaseConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let released = document::release_hold(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.document_id,
        &config.hold_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&released)?);
    Ok(())
}

struct DocumentActor {
    namespace: String,
    document_id: String,
    actor: String,
}

async fn expire(config: DocumentActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let expired = document::expire_document(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.document_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&expired)?);
    Ok(())
}

async fn delete(config: DocumentActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let deleted = document::delete_document(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.document_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&deleted)?);
    Ok(())
}

fn parse_file_actor(args: &[String], path_flag: &str) -> Result<FileActor, String> {
    let mut path = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag if flag == path_flag => {
                path = Some(PathBuf::from(require_value(args, i, path_flag)?));
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(FileActor {
        path: path.ok_or(format!("{path_flag} is required"))?,
        actor,
    })
}

fn parse_get(args: &[String]) -> Result<GetConfig, String> {
    let mut namespace = None;
    let mut document_id = None;
    let mut purpose = None;
    let mut fields = Vec::new();
    let mut classification_ceiling = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--document-id" => {
                document_id = Some(require_value(args, i, "--document-id")?);
                i += 2;
            }
            "--purpose" => {
                purpose = Some(require_value(args, i, "--purpose")?);
                i += 2;
            }
            "--field" => {
                fields.push(require_value(args, i, "--field")?);
                i += 2;
            }
            "--classification-ceiling" => {
                classification_ceiling = Some(require_value(args, i, "--classification-ceiling")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown get option {other}")),
        }
    }
    Ok(GetConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        document_id: document_id.ok_or("--document-id is required")?,
        purpose: purpose.ok_or("--purpose is required")?,
        fields,
        classification_ceiling,
        actor,
    })
}

fn parse_hold(args: &[String]) -> Result<HoldConfig, String> {
    let mut namespace = None;
    let mut document_id = None;
    let mut hold_id = None;
    let mut reason = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--document-id" => {
                document_id = Some(require_value(args, i, "--document-id")?);
                i += 2;
            }
            "--hold-id" => {
                hold_id = Some(require_value(args, i, "--hold-id")?);
                i += 2;
            }
            "--reason" => {
                reason = Some(require_value(args, i, "--reason")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown hold option {other}")),
        }
    }
    Ok(HoldConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        document_id: document_id.ok_or("--document-id is required")?,
        hold_id: hold_id.ok_or("--hold-id is required")?,
        reason: reason.ok_or("--reason is required")?,
        actor,
    })
}

fn parse_release(args: &[String]) -> Result<ReleaseConfig, String> {
    let mut namespace = None;
    let mut document_id = None;
    let mut hold_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--document-id" => {
                document_id = Some(require_value(args, i, "--document-id")?);
                i += 2;
            }
            "--hold-id" => {
                hold_id = Some(require_value(args, i, "--hold-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown release-hold option {other}")),
        }
    }
    Ok(ReleaseConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        document_id: document_id.ok_or("--document-id is required")?,
        hold_id: hold_id.ok_or("--hold-id is required")?,
        actor,
    })
}

fn parse_document_actor(args: &[String]) -> Result<DocumentActor, String> {
    let mut namespace = None;
    let mut document_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--document-id" => {
                document_id = Some(require_value(args, i, "--document-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(DocumentActor {
        namespace: namespace.ok_or("--namespace is required")?,
        document_id: document_id.ok_or("--document-id is required")?,
        actor,
    })
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .filter(|value| !value.is_empty() && !value.starts_with("--"))
        .ok_or_else(|| format!("{flag} requires a value"))
}

//! sekaictl admin streams commands (#684, #691).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::event_stream::{self, EventStreamBatch, EventStreamBinding};
use crate::sekai::event_subscription::{self, EventSubscription, EventSubscriptionPage};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin streams register --binding <file> [--actor <principal>]\n  sekaictl admin streams project --batch <file> [--actor <principal>]\n  sekaictl admin streams checkpoint --stream-id <id>\n  sekaictl admin streams subscribe --binding <file> [--actor <principal>]\n  sekaictl admin streams pull --page <file> [--actor <principal>]\n  sekaictl admin streams revoke --namespace <ns> --subscription-id <id> [--actor <principal>]\n  sekaictl admin streams cursor --namespace <ns> --subscription-id <id> [--actor <principal>]"
}

pub async fn run_streams_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("register") => register(parse_file_actor(&args[1..], "--binding")?).await,
        Some("project") => project(parse_file_actor(&args[1..], "--batch")?).await,
        Some("checkpoint") => checkpoint(parse_stream_id(&args[1..])?).await,
        Some("subscribe") => subscribe(parse_file_actor(&args[1..], "--binding")?).await,
        Some("pull") => pull(parse_file_actor(&args[1..], "--page")?).await,
        Some("revoke") => revoke(parse_subscription_ref(&args[1..])?).await,
        Some("cursor") => cursor(parse_subscription_ref(&args[1..])?).await,
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

async fn register(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let binding: EventStreamBinding =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let registered = event_stream::register_event_stream(
        db.as_ref(),
        &config.actor,
        &binding,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&registered)?);
    Ok(())
}

async fn project(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let batch: EventStreamBatch =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let projection = event_stream::project_event_batch(
        db.as_ref(),
        &config.actor,
        &batch,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&projection)?);
    Ok(())
}

async fn checkpoint(stream_id: String) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let checkpoint = db
        .get_event_stream_checkpoint(&stream_id)
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&checkpoint)?);
    Ok(())
}

async fn subscribe(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let binding: EventSubscription =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let registered = event_subscription::register_event_subscription(
        db.as_ref(),
        &config.actor,
        &binding,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&registered)?);
    Ok(())
}

async fn pull(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let page: EventSubscriptionPage =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let delivery = event_subscription::deliver_subscription_page(
        db.as_ref(),
        &config.actor,
        &page,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&delivery)?);
    Ok(())
}

async fn revoke(reference: SubscriptionRef) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let revoked = event_subscription::revoke_event_subscription(
        db.as_ref(),
        &reference.actor,
        &reference.namespace,
        &reference.subscription_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&revoked)?);
    Ok(())
}

async fn cursor(reference: SubscriptionRef) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let subscription = event_subscription::inspect_event_subscription(
        db.as_ref(),
        &reference.actor,
        &reference.namespace,
        &reference.subscription_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&subscription)?);
    Ok(())
}

fn parse_file_actor(args: &[String], file_flag: &str) -> Result<FileActor, String> {
    let mut path = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag if flag == file_flag => {
                path = Some(PathBuf::from(require_value(args, i, file_flag)?));
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
        path: path.ok_or_else(|| format!("{file_flag} is required"))?,
        actor,
    })
}

fn parse_stream_id(args: &[String]) -> Result<String, String> {
    let mut stream_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--stream-id" => {
                stream_id = Some(require_value(args, i, "--stream-id")?);
                i += 2;
            }
            other => return Err(format!("unknown checkpoint option {other}")),
        }
    }
    stream_id.ok_or_else(|| "--stream-id is required".into())
}

struct SubscriptionRef {
    namespace: String,
    subscription_id: String,
    actor: String,
}

fn parse_subscription_ref(args: &[String]) -> Result<SubscriptionRef, String> {
    let mut namespace = None;
    let mut subscription_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--subscription-id" => {
                subscription_id = Some(require_value(args, i, "--subscription-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown subscription option {other}")),
        }
    }
    Ok(SubscriptionRef {
        namespace: namespace.ok_or_else(|| "--namespace is required".to_string())?,
        subscription_id: subscription_id
            .ok_or_else(|| "--subscription-id is required".to_string())?,
        actor,
    })
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

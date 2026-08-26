//! sekaictl admin streams commands (#684).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::event_stream::{self, EventStreamBatch, EventStreamBinding};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin streams register --binding <file> [--actor <principal>]\n  sekaictl admin streams project --batch <file> [--actor <principal>]\n  sekaictl admin streams checkpoint --stream-id <id>"
}

pub async fn run_streams_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("register") => register(parse_file_actor(&args[1..], "--binding")?).await,
        Some("project") => project(parse_file_actor(&args[1..], "--batch")?).await,
        Some("checkpoint") => checkpoint(parse_stream_id(&args[1..])?).await,
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

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

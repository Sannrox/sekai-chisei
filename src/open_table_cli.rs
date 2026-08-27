//! sekaictl admin tables commands (#682).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::dataset::RowFilter;
use crate::sekai::open_table::{self, OpenTableQuery, OpenTableSnapshot, OpenTableSource};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin tables register --source <file> [--actor <principal>]\n  sekaictl admin tables admit-snapshot --snapshot <file> [--actor <principal>]\n  sekaictl admin tables query --source-id <id> [--column <name>]... [--filter <column=op:value>]... [--snapshot-digest <digest>] [--classification-ceiling <token>] [--actor <principal>]\n  --classification-ceiling may only restrict a sealed principal profile"
}

pub async fn run_tables_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("register") => register(parse_register(&args[1..])?).await,
        Some("admit-snapshot") => admit(parse_admit(&args[1..])?).await,
        Some("query") => query(parse_query(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

struct RegisterConfig {
    source: PathBuf,
    actor: String,
}

async fn register(config: RegisterConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let bytes = std::fs::read(&config.source)?;
    let source: OpenTableSource = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let registered = open_table::register_open_table(
        db.as_ref(),
        &config.actor,
        &source,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&registered)?);
    Ok(())
}

struct AdmitConfig {
    snapshot: PathBuf,
    actor: String,
}

async fn admit(config: AdmitConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let bytes = std::fs::read(&config.snapshot)?;
    let snapshot: OpenTableSnapshot =
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let admitted = open_table::admit_open_table_snapshot(db.as_ref(), &config.actor, &snapshot)
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&admitted)?);
    Ok(())
}

struct QueryConfig {
    source_id: String,
    columns: Vec<String>,
    filters: Vec<RowFilter>,
    snapshot_digest: Option<String>,
    classification_ceiling: Option<String>,
    actor: String,
}

async fn query(config: QueryConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let projection = open_table::query_open_table(
        db.as_ref(),
        &config.actor,
        &OpenTableQuery {
            source_id: config.source_id,
            columns: config.columns,
            filters: config.filters,
            snapshot_digest: config.snapshot_digest,
            classification_ceiling: config.classification_ceiling,
        },
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&projection)?);
    Ok(())
}

fn parse_register(args: &[String]) -> Result<RegisterConfig, String> {
    let mut source = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                source = Some(PathBuf::from(require_value(args, i, "--source")?));
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown register option {other}")),
        }
    }
    Ok(RegisterConfig {
        source: source.ok_or("--source is required")?,
        actor,
    })
}

fn parse_admit(args: &[String]) -> Result<AdmitConfig, String> {
    let mut snapshot = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--snapshot" => {
                snapshot = Some(PathBuf::from(require_value(args, i, "--snapshot")?));
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown admit-snapshot option {other}")),
        }
    }
    Ok(AdmitConfig {
        snapshot: snapshot.ok_or("--snapshot is required")?,
        actor,
    })
}

fn parse_query(args: &[String]) -> Result<QueryConfig, String> {
    let mut source_id = None;
    let mut columns = Vec::new();
    let mut filters = Vec::new();
    let mut snapshot_digest = None;
    let mut classification_ceiling = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source-id" => {
                source_id = Some(require_value(args, i, "--source-id")?);
                i += 2;
            }
            "--column" => {
                columns.push(require_value(args, i, "--column")?);
                i += 2;
            }
            "--filter" => {
                filters.push(parse_filter(&require_value(args, i, "--filter")?)?);
                i += 2;
            }
            "--snapshot-digest" => {
                snapshot_digest = Some(require_value(args, i, "--snapshot-digest")?);
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
            other => return Err(format!("unknown query option {other}")),
        }
    }
    Ok(QueryConfig {
        source_id: source_id.ok_or("--source-id is required")?,
        columns,
        filters,
        snapshot_digest,
        classification_ceiling,
        actor,
    })
}

fn parse_filter(value: &str) -> Result<RowFilter, String> {
    let (column, rest) = value
        .split_once('=')
        .ok_or_else(|| "filter must be column=op:value".to_string())?;
    let (op, expected) = rest
        .split_once(':')
        .ok_or_else(|| "filter must be column=op:value".to_string())?;
    if column.is_empty() || op.is_empty() {
        return Err("filter must be column=op:value".into());
    }
    Ok(RowFilter {
        column: column.into(),
        op: op.into(),
        value: expected.into(),
    })
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

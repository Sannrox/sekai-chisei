//! sekaictl admin lakehouse commands (#712).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::lakehouse_snapshot::{self, LakehouseSnapshot};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin lakehouse register --snapshot <file> [--actor <principal>]\n  sekaictl admin lakehouse reimport --snapshot <file> [--actor <principal>]\n  sekaictl admin lakehouse upgrade --snapshot <file> [--actor <principal>]\n  sekaictl admin lakehouse redact --namespace <ns> --snapshot-id <id> --column <name> [--actor <principal>]\n  sekaictl admin lakehouse delete --namespace <ns> --snapshot-id <id> --partition <key> [--actor <principal>]\n  sekaictl admin lakehouse get --namespace <ns> --snapshot-id <id> [--actor <principal>]\n  sekaictl admin lakehouse revoke --namespace <ns> --snapshot-id <id> [--actor <principal>]"
}

pub async fn run_lakehouse_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("register") => register(parse_file(&args[1..])?).await,
        Some("reimport") => reimport(parse_file(&args[1..])?).await,
        Some("upgrade") => upgrade(parse_file(&args[1..])?).await,
        Some("redact") => redact(parse_mutation(&args[1..], "--column")?).await,
        Some("delete") => delete_partition(parse_mutation(&args[1..], "--partition")?).await,
        Some("get") => get(parse_identity(&args[1..])?).await,
        Some("revoke") => revoke(parse_identity(&args[1..])?).await,
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

struct Identity {
    namespace: String,
    snapshot_id: String,
    actor: String,
}

struct Mutation {
    identity: Identity,
    value: String,
}

async fn register(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let snapshot: LakehouseSnapshot =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let exported = lakehouse_snapshot::register_snapshot(
        db.as_ref(),
        &config.actor,
        &snapshot,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&exported)?);
    Ok(())
}

async fn reimport(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let snapshot: LakehouseSnapshot =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let exported = lakehouse_snapshot::reimport_snapshot(
        db.as_ref(),
        &config.actor,
        &snapshot,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&exported)?);
    Ok(())
}

async fn upgrade(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let snapshot: LakehouseSnapshot =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let exported = lakehouse_snapshot::upgrade_schema(
        db.as_ref(),
        &config.actor,
        &snapshot,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&exported)?);
    Ok(())
}

async fn redact(config: Mutation) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let snapshot = lakehouse_snapshot::redact_columns(
        db.as_ref(),
        &config.identity.actor,
        &config.identity.namespace,
        &config.identity.snapshot_id,
        &[config.value],
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

async fn delete_partition(config: Mutation) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let snapshot = lakehouse_snapshot::delete_partitions(
        db.as_ref(),
        &config.identity.actor,
        &config.identity.namespace,
        &config.identity.snapshot_id,
        &[config.value],
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

async fn get(config: Identity) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let snapshot = lakehouse_snapshot::get_snapshot(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.snapshot_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

async fn revoke(config: Identity) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let revoked = lakehouse_snapshot::revoke_snapshot(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.snapshot_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&revoked)?);
    Ok(())
}

fn parse_file(args: &[String]) -> Result<FileActor, String> {
    let mut path = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--snapshot" => {
                path = Some(PathBuf::from(require_value(args, i, "--snapshot")?));
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
        path: path.ok_or("--snapshot is required")?,
        actor,
    })
}

fn parse_identity(args: &[String]) -> Result<Identity, String> {
    let (identity, extra) = parse_identity_inner(args)?;
    if extra.is_some() {
        return Err("unknown option".into());
    }
    Ok(identity)
}

fn parse_mutation(args: &[String], flag: &str) -> Result<Mutation, String> {
    let mut value = None;
    let mut namespace = None;
    let mut snapshot_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--snapshot-id" => {
                snapshot_id = Some(require_value(args, i, "--snapshot-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            name if name == flag => {
                value = Some(require_value(args, i, flag)?);
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(Mutation {
        identity: Identity {
            namespace: namespace.ok_or("--namespace is required")?,
            snapshot_id: snapshot_id.ok_or("--snapshot-id is required")?,
            actor,
        },
        value: value.ok_or(format!("{flag} is required"))?,
    })
}

fn parse_identity_inner(args: &[String]) -> Result<(Identity, Option<String>), String> {
    let mut namespace = None;
    let mut snapshot_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--snapshot-id" => {
                snapshot_id = Some(require_value(args, i, "--snapshot-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok((
        Identity {
            namespace: namespace.ok_or("--namespace is required")?,
            snapshot_id: snapshot_id.ok_or("--snapshot-id is required")?,
            actor,
        },
        None,
    ))
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .filter(|value| !value.is_empty() && !value.starts_with("--"))
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_names_the_shipped_admin_lakehouse_surface() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin lakehouse register"));
        assert!(usage.contains("upgrade"));
        assert!(usage.contains("redact"));
        assert!(usage.contains("reimport"));
        assert!(usage.contains("revoke"));
    }
}

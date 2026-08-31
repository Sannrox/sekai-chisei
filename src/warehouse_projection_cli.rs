//! sekaictl admin warehouse commands (#711).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::warehouse_projection::{self, WarehousePage, WarehouseProjection};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin warehouse register --projection <file> [--actor <principal>]\n  sekaictl admin warehouse export --page <file> [--actor <principal>]\n  sekaictl admin warehouse get --namespace <ns> --projection-id <id> [--actor <principal>]\n  sekaictl admin warehouse revoke --namespace <ns> --projection-id <id> [--actor <principal>]"
}

pub async fn run_warehouse_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("register") => register(parse_file(&args[1..], "--projection")?).await,
        Some("export") => export(parse_file(&args[1..], "--page")?).await,
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

async fn register(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let projection: WarehouseProjection =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let registered = warehouse_projection::register_projection(
        db.as_ref(),
        &config.actor,
        &projection,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&registered)?);
    Ok(())
}

async fn export(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let page: WarehousePage =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let exported = warehouse_projection::export_page(
        db.as_ref(),
        &config.actor,
        &page,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&exported)?);
    Ok(())
}

struct Identity {
    namespace: String,
    projection_id: String,
    actor: String,
}

async fn get(config: Identity) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let projection = warehouse_projection::get_projection(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.projection_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&projection)?);
    Ok(())
}

async fn revoke(config: Identity) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let revoked = warehouse_projection::revoke_projection(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.projection_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&revoked)?);
    Ok(())
}

fn parse_file(args: &[String], flag: &str) -> Result<FileActor, String> {
    let mut path = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            name if name == flag => {
                path = Some(PathBuf::from(require_value(args, i, flag)?));
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
        path: path.ok_or(format!("{flag} is required"))?,
        actor,
    })
}

fn parse_identity(args: &[String]) -> Result<Identity, String> {
    let mut namespace = None;
    let mut projection_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--projection-id" => {
                projection_id = Some(require_value(args, i, "--projection-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(Identity {
        namespace: namespace.ok_or("--namespace is required")?,
        projection_id: projection_id.ok_or("--projection-id is required")?,
        actor,
    })
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
    fn usage_names_the_shipped_admin_warehouse_surface() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin warehouse register"));
        assert!(usage.contains("export"));
        assert!(usage.contains("revoke"));
    }
}

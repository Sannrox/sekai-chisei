//! sekaictl admin network commands (#708).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::federation_network::{self, NetworkContract, NetworkExchange};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin network accept --contract <file> [--actor <principal>]\n  sekaictl admin network exchange --exchange <file> [--actor <principal>]\n  sekaictl admin network get --namespace <ns> --contract-id <id> [--actor <principal>]\n  sekaictl admin network peer-loss --namespace <ns> --contract-id <id> [--actor <principal>]\n  sekaictl admin network reconnect --namespace <ns> --contract-id <id> [--actor <principal>]\n  sekaictl admin network revoke --namespace <ns> --contract-id <id> [--actor <principal>]"
}

pub async fn run_network_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("accept") => accept(parse_file(&args[1..], "--contract")?).await,
        Some("exchange") => exchange(parse_file(&args[1..], "--exchange")?).await,
        Some("get") => get(parse_contract_actor(&args[1..])?).await,
        Some("peer-loss") => peer_loss(parse_contract_actor(&args[1..])?).await,
        Some("reconnect") => reconnect(parse_contract_actor(&args[1..])?).await,
        Some("revoke") => revoke(parse_contract_actor(&args[1..])?).await,
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

async fn accept(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let contract: NetworkContract =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let accepted = federation_network::accept_contract(
        db.as_ref(),
        &config.actor,
        &contract,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&accepted)?);
    Ok(())
}

async fn exchange(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let item: NetworkExchange =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let admitted = federation_network::exchange(
        db.as_ref(),
        &config.actor,
        &item,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&admitted)?);
    Ok(())
}

struct ContractActor {
    namespace: String,
    contract_id: String,
    actor: String,
}

async fn get(config: ContractActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let contract = federation_network::get_contract(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.contract_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&contract)?);
    Ok(())
}

async fn peer_loss(config: ContractActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let contract = federation_network::mark_peer_lost(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.contract_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&contract)?);
    Ok(())
}

async fn reconnect(config: ContractActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let contract = federation_network::reconnect(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.contract_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&contract)?);
    Ok(())
}

async fn revoke(config: ContractActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let contract = federation_network::revoke_contract(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.contract_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&contract)?);
    Ok(())
}

fn parse_file(args: &[String], path_flag: &str) -> Result<FileActor, String> {
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

fn parse_contract_actor(args: &[String]) -> Result<ContractActor, String> {
    let mut namespace = None;
    let mut contract_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--contract-id" => {
                contract_id = Some(require_value(args, i, "--contract-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(ContractActor {
        namespace: namespace.ok_or("--namespace is required")?,
        contract_id: contract_id.ok_or("--contract-id is required")?,
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
    fn usage_names_the_shipped_admin_network_surface() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin network accept"));
        assert!(usage.contains("exchange"));
        assert!(usage.contains("peer-loss"));
    }
}

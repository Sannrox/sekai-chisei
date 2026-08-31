//! sekaictl admin autonomy commands (#715).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::autonomous_envelope::{self, AutonomousEnvelope};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin autonomy admit --envelope <file> [--actor <principal>]\n  sekaictl admin autonomy get --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy stop --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy rollback --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy note-lease-loss --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy invalidate-receipt --namespace <ns> --envelope-id <id> [--actor <principal>]"
}

pub async fn run_autonomy_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("admit") => admit(parse_file(&args[1..])?).await,
        Some("get") => get(parse_identity(&args[1..])?).await,
        Some("stop") => stop(parse_identity(&args[1..])?).await,
        Some("rollback") => rollback(parse_identity(&args[1..])?).await,
        Some("note-lease-loss") => lease_loss(parse_identity(&args[1..])?).await,
        Some("invalidate-receipt") => invalidate(parse_identity(&args[1..])?).await,
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
    envelope_id: String,
    actor: String,
}

async fn admit(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let envelope: AutonomousEnvelope =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let admitted = autonomous_envelope::admit_envelope(
        db.as_ref(),
        &config.actor,
        &envelope,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&admitted)?);
    Ok(())
}

async fn get(config: Identity) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let envelope = autonomous_envelope::get_envelope(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.envelope_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

async fn stop(config: Identity) -> Result<(), BoxErr> {
    mutate(config, Mutate::Stop).await
}

async fn rollback(config: Identity) -> Result<(), BoxErr> {
    mutate(config, Mutate::Rollback).await
}

async fn lease_loss(config: Identity) -> Result<(), BoxErr> {
    mutate(config, Mutate::LeaseLoss).await
}

async fn invalidate(config: Identity) -> Result<(), BoxErr> {
    mutate(config, Mutate::Invalidate).await
}

enum Mutate {
    Stop,
    Rollback,
    LeaseLoss,
    Invalidate,
}

async fn mutate(config: Identity, op: Mutate) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let now = Utc::now().timestamp_millis();
    let envelope = match op {
        Mutate::Stop => autonomous_envelope::stop_envelope(
            db.as_ref(),
            &config.actor,
            &config.namespace,
            &config.envelope_id,
            now,
        ),
        Mutate::Rollback => autonomous_envelope::rollback_envelope(
            db.as_ref(),
            &config.actor,
            &config.namespace,
            &config.envelope_id,
            now,
        ),
        Mutate::LeaseLoss => autonomous_envelope::note_lease_loss(
            db.as_ref(),
            &config.actor,
            &config.namespace,
            &config.envelope_id,
            now,
        ),
        Mutate::Invalidate => autonomous_envelope::invalidate_receipt(
            db.as_ref(),
            &config.actor,
            &config.namespace,
            &config.envelope_id,
            now,
        ),
    }
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

fn parse_file(args: &[String]) -> Result<FileActor, String> {
    let mut path = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--envelope" => {
                path = Some(PathBuf::from(require_value(args, i, "--envelope")?));
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
        path: path.ok_or("--envelope is required")?,
        actor,
    })
}

fn parse_identity(args: &[String]) -> Result<Identity, String> {
    let mut namespace = None;
    let mut envelope_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--envelope-id" => {
                envelope_id = Some(require_value(args, i, "--envelope-id")?);
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
        envelope_id: envelope_id.ok_or("--envelope-id is required")?,
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
    fn usage_names_the_shipped_admin_autonomy_surface() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin autonomy admit"));
        assert!(usage.contains("stop"));
        assert!(usage.contains("rollback"));
        assert!(usage.contains("invalidate-receipt"));
    }
}

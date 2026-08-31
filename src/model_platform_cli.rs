//! sekaictl admin providers commands (#713).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::model_platform::{self, ModelPlatformCertification};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin providers certify --certification <file> [--actor <principal>]\n  sekaictl admin providers get --namespace <ns> --certification-id <id> [--actor <principal>]\n  sekaictl admin providers verify --namespace <ns> --certification-id <id> --certification <file> [--actor <principal>]\n  sekaictl admin providers revoke --namespace <ns> --certification-id <id> [--actor <principal>]"
}

pub async fn run_providers_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("certify") => certify(parse_file(&args[1..])?).await,
        Some("get") => get(parse_identity(&args[1..])?).await,
        Some("verify") => verify(parse_verify(&args[1..])?).await,
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
    certification_id: String,
    actor: String,
}

struct Verify {
    identity: Identity,
    path: PathBuf,
}

async fn certify(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let certification: ModelPlatformCertification =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let certified = model_platform::certify_model_platform(
        db.as_ref(),
        &config.actor,
        &certification,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&certified)?);
    Ok(())
}

async fn get(config: Identity) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let certified = model_platform::get_model_platform(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.certification_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&certified)?);
    Ok(())
}

async fn verify(config: Verify) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let submitted: ModelPlatformCertification =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let verified = model_platform::verify_model_platform(
        db.as_ref(),
        &config.identity.actor,
        &config.identity.namespace,
        &config.identity.certification_id,
        &submitted,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&verified)?);
    Ok(())
}

async fn revoke(config: Identity) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let revoked = model_platform::revoke_model_platform(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.certification_id,
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
            "--certification" => {
                path = Some(PathBuf::from(require_value(args, i, "--certification")?));
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
        path: path.ok_or("--certification is required")?,
        actor,
    })
}

fn parse_identity(args: &[String]) -> Result<Identity, String> {
    let mut namespace = None;
    let mut certification_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--certification-id" => {
                certification_id = Some(require_value(args, i, "--certification-id")?);
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
        certification_id: certification_id.ok_or("--certification-id is required")?,
        actor,
    })
}

fn parse_verify(args: &[String]) -> Result<Verify, String> {
    let mut path = None;
    let mut namespace = None;
    let mut certification_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--certification-id" => {
                certification_id = Some(require_value(args, i, "--certification-id")?);
                i += 2;
            }
            "--certification" => {
                path = Some(PathBuf::from(require_value(args, i, "--certification")?));
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(Verify {
        identity: Identity {
            namespace: namespace.ok_or("--namespace is required")?,
            certification_id: certification_id.ok_or("--certification-id is required")?,
            actor,
        },
        path: path.ok_or("--certification is required")?,
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
    fn usage_names_the_shipped_admin_providers_surface() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin providers certify"));
        assert!(usage.contains("verify"));
        assert!(usage.contains("revoke"));
    }
}

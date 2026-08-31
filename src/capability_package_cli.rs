//! sekaictl admin packages commands (#707).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::capability_package::{self, CapabilityPackageCertification};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin packages certify --certification <file> [--actor <principal>]\n  sekaictl admin packages get --namespace <ns> --certification-id <id> [--actor <principal>]\n  sekaictl admin packages verify --namespace <ns> --certification-id <id> --certification <file> [--actor <principal>]\n  sekaictl admin packages revoke --namespace <ns> --certification-id <id> --reason <text> [--actor <principal>]"
}

pub async fn run_packages_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("certify") => certify(parse_file_actor(&args[1..])?).await,
        Some("get") => get(parse_get(&args[1..])?).await,
        Some("verify") => verify(parse_verify(&args[1..])?).await,
        Some("revoke") => revoke(parse_revoke(&args[1..])?).await,
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

async fn certify(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let certification: CapabilityPackageCertification =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let certified = capability_package::certify_package(
        db.as_ref(),
        &config.actor,
        &certification,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&certified)?);
    Ok(())
}

struct GetConfig {
    namespace: String,
    certification_id: String,
    actor: String,
}

async fn get(config: GetConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let package = capability_package::get_package(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.certification_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&package)?);
    Ok(())
}

struct VerifyConfig {
    namespace: String,
    certification_id: String,
    path: PathBuf,
    actor: String,
}

async fn verify(config: VerifyConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let submitted: CapabilityPackageCertification =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let verified = capability_package::verify_package(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.certification_id,
        &submitted,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&verified)?);
    Ok(())
}

struct RevokeConfig {
    namespace: String,
    certification_id: String,
    reason: String,
    actor: String,
}

async fn revoke(config: RevokeConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let revoked = capability_package::revoke_package(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.certification_id,
        &config.reason,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&revoked)?);
    Ok(())
}

fn parse_file_actor(args: &[String]) -> Result<FileActor, String> {
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

fn parse_get(args: &[String]) -> Result<GetConfig, String> {
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
            other => return Err(format!("unknown get option {other}")),
        }
    }
    Ok(GetConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        certification_id: certification_id.ok_or("--certification-id is required")?,
        actor,
    })
}

fn parse_verify(args: &[String]) -> Result<VerifyConfig, String> {
    let mut namespace = None;
    let mut certification_id = None;
    let mut path = None;
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
            other => return Err(format!("unknown verify option {other}")),
        }
    }
    Ok(VerifyConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        certification_id: certification_id.ok_or("--certification-id is required")?,
        path: path.ok_or("--certification is required")?,
        actor,
    })
}

fn parse_revoke(args: &[String]) -> Result<RevokeConfig, String> {
    let mut namespace = None;
    let mut certification_id = None;
    let mut reason = None;
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
            "--reason" => {
                reason = Some(require_value(args, i, "--reason")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown revoke option {other}")),
        }
    }
    Ok(RevokeConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        certification_id: certification_id.ok_or("--certification-id is required")?,
        reason: reason.ok_or("--reason is required")?,
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
    fn usage_names_the_shipped_admin_packages_surface() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin packages certify"));
        assert!(usage.contains("verify"));
        assert!(usage.contains("revoke"));
    }

    #[test]
    fn parses_verify_against_a_certification_file() {
        let config = parse_verify(&[
            "--namespace".into(),
            "ops".into(),
            "--certification-id".into(),
            "cert:1".into(),
            "--certification".into(),
            "./cert.json".into(),
            "--actor".into(),
            "reviewer".into(),
        ])
        .unwrap();
        assert_eq!(config.namespace, "ops");
        assert_eq!(config.certification_id, "cert:1");
        assert_eq!(config.actor, "reviewer");
    }
}

//! sekaictl admin autonomy commands (#715, #1469, #1990).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::agent_autonomy::{self, AutonomyThreshold};
use crate::sekai::autonomous_envelope::{self, AutonomousEnvelope};
use crate::sekai::security_precision;
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin autonomy admit --envelope <file> [--actor <principal>]\n  sekaictl admin autonomy get --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy stop --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy rollback --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy note-lease-loss --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy invalidate-receipt --namespace <ns> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy offer --namespace <ns> --principal <agent> --type <type_id> [--actor <principal>]\n  sekaictl admin autonomy grant-auto-apply --namespace <ns> --principal <agent> --type <type_id> --envelope-id <id> [--actor <principal>]\n  sekaictl admin autonomy revoke-auto-apply --namespace <ns> --principal <agent> --type <type_id> --reason <reason> [--actor <principal>]\n  sekaictl admin autonomy disposition-precision --namespace <ns>"
}

pub async fn run_autonomy_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("admit") => admit(parse_file(&args[1..])?).await,
        Some("get") => get(parse_identity(&args[1..])?).await,
        Some("stop") => stop(parse_identity(&args[1..])?).await,
        Some("rollback") => rollback(parse_identity(&args[1..])?).await,
        Some("note-lease-loss") => lease_loss(parse_identity(&args[1..])?).await,
        Some("invalidate-receipt") => invalidate(parse_identity(&args[1..])?).await,
        Some("offer") => offer(parse_grant(&args[1..], false, false)?).await,
        Some("grant-auto-apply") => grant_auto_apply(parse_grant(&args[1..], true, false)?).await,
        Some("revoke-auto-apply") => revoke_auto_apply(parse_grant(&args[1..], false, true)?).await,
        Some("disposition-precision") => disposition_precision(parse_namespace(&args[1..])?).await,
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

struct GrantArgs {
    namespace: String,
    principal: String,
    type_id: String,
    envelope_id: String,
    reason: String,
    actor: String,
}

async fn offer(config: GrantArgs) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let snapshot = agent_autonomy::offer(
        db.as_ref(),
        &config.namespace,
        &config.principal,
        &config.type_id,
        AutonomyThreshold::production(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

/// Security disposition precision per agent recorder, revision and finding
/// class, over the production window.
async fn disposition_precision(namespace: String) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let rows = security_precision::disposition_precision(
        db.as_ref(),
        &namespace,
        security_precision::PrecisionWindow::production(),
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}

fn parse_namespace(args: &[String]) -> Result<String, String> {
    match args {
        [flag, namespace] if flag == "--namespace" && !namespace.trim().is_empty() => {
            Ok(namespace.clone())
        }
        _ => Err("disposition-precision needs --namespace <ns>".into()),
    }
}

async fn grant_auto_apply(config: GrantArgs) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let grant = agent_autonomy::grant_auto_apply(
        db.as_ref(),
        agent_autonomy::GrantAutoApplyRequest {
            actor: &config.actor,
            namespace: &config.namespace,
            principal: &config.principal,
            type_id: &config.type_id,
            envelope_id: &config.envelope_id,
            now_ms: Utc::now().timestamp_millis(),
            threshold: AutonomyThreshold::production(),
        },
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&grant)?);
    Ok(())
}

async fn revoke_auto_apply(config: GrantArgs) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let revoked = agent_autonomy::revoke_auto_apply(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.principal,
        &config.type_id,
        &config.reason,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&revoked)?);
    Ok(())
}

fn parse_grant(
    args: &[String],
    need_envelope: bool,
    need_reason: bool,
) -> Result<GrantArgs, String> {
    let mut namespace = None;
    let mut principal = None;
    let mut type_id = None;
    let mut envelope_id = None;
    let mut reason = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--principal" => {
                principal = Some(require_value(args, i, "--principal")?);
                i += 2;
            }
            "--type" => {
                type_id = Some(require_value(args, i, "--type")?);
                i += 2;
            }
            "--envelope-id" => {
                envelope_id = Some(require_value(args, i, "--envelope-id")?);
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
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(GrantArgs {
        namespace: namespace.ok_or("--namespace is required")?,
        principal: principal.ok_or("--principal is required")?,
        type_id: type_id.ok_or("--type is required")?,
        envelope_id: if need_envelope {
            envelope_id.ok_or("--envelope-id is required")?
        } else {
            envelope_id.unwrap_or_default()
        },
        reason: if need_reason {
            reason.ok_or("--reason is required")?
        } else {
            reason.unwrap_or_default()
        },
        actor,
    })
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
        assert!(usage.contains("grant-auto-apply"));
        assert!(usage.contains("revoke-auto-apply"));
        assert!(usage.contains("offer"));
    }
}

//! sekaictl admin learning change commands (#714).

use crate::chisei::learning_change::{self, ProposeLearningChange};
use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use chrono::Utc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin learning propose --namespace <ns> --learning-id <id> --evidence-digest <digest> [--actor <principal>]\n  sekaictl admin learning approve --namespace <ns> --learning-id <id> [--actor <principal>]\n  sekaictl admin learning activate --namespace <ns> --learning-id <id> [--actor <principal>]\n  sekaictl admin learning rollback --namespace <ns> --learning-id <id> [--actor <principal>]\n  sekaictl admin learning inspect --namespace <ns> --learning-id <id>\n  sekaictl admin learning show --namespace <ns> --learning-id <id>\n  sekaictl admin learning list [--namespace <ns>]\n  sekaictl admin learning note-lease-loss --namespace <ns> --learning-id <id> [--actor <principal>]"
}

pub async fn run_learning_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("propose") => propose(parse_propose(&args[1..])?).await,
        Some("approve") => mutate(parse_target(&args[1..], "approve")?, MutateOp::Approve).await,
        Some("activate") => mutate(parse_target(&args[1..], "activate")?, MutateOp::Activate).await,
        Some("rollback") => mutate(parse_target(&args[1..], "rollback")?, MutateOp::Rollback).await,
        Some("note-lease-loss") => {
            mutate(
                parse_target(&args[1..], "note-lease-loss")?,
                MutateOp::LeaseLoss,
            )
            .await
        }
        Some("inspect") => inspect(parse_show(&args[1..], "inspect")?).await,
        Some("show") => show(parse_show(&args[1..], "show")?).await,
        Some("list") => list_changes(parse_list(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

struct ProposeConfig {
    namespace: String,
    learning_id: String,
    evidence_digest: String,
    actor: String,
}

struct TargetConfig {
    namespace: String,
    learning_id: String,
    actor: String,
}

enum MutateOp {
    Approve,
    Activate,
    Rollback,
    LeaseLoss,
}

async fn propose(config: ProposeConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record = learning_change::propose_change(
        db.as_ref(),
        &config.actor,
        &ProposeLearningChange {
            namespace: config.namespace,
            learning_id: config.learning_id,
            evidence_digest: config.evidence_digest,
        },
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

async fn mutate(config: TargetConfig, op: MutateOp) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let now = Utc::now().timestamp_millis();
    let record = match op {
        MutateOp::Approve => learning_change::approve_change(
            db.as_ref(),
            &config.actor,
            &config.namespace,
            &config.learning_id,
            now,
        ),
        MutateOp::Activate => learning_change::activate_change(
            db.as_ref(),
            &config.actor,
            &config.namespace,
            &config.learning_id,
            now,
        ),
        MutateOp::Rollback => learning_change::rollback_change(
            db.as_ref(),
            &config.actor,
            &config.namespace,
            &config.learning_id,
            now,
        ),
        MutateOp::LeaseLoss => learning_change::note_lease_loss(
            db.as_ref(),
            &config.actor,
            &config.namespace,
            &config.learning_id,
            now,
        ),
    }
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

async fn inspect(config: TargetConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let comparison =
        learning_change::inspect_change(db.as_ref(), &config.namespace, &config.learning_id)
            .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&comparison)?);
    Ok(())
}

async fn show(config: TargetConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record = learning_change::get_change(db.as_ref(), &config.namespace, &config.learning_id)
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

async fn list_changes(namespace: Option<String>) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let records = learning_change::list_changes(db.as_ref(), namespace.as_deref())
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_propose(args: &[String]) -> Result<ProposeConfig, String> {
    let mut namespace = None;
    let mut learning_id = None;
    let mut evidence_digest = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--learning-id" => {
                learning_id = Some(require_value(args, i, "--learning-id")?);
                i += 2;
            }
            "--evidence-digest" => {
                evidence_digest = Some(require_value(args, i, "--evidence-digest")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown propose option {other}")),
        }
    }
    Ok(ProposeConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        learning_id: learning_id.ok_or("--learning-id is required")?,
        evidence_digest: evidence_digest.ok_or("--evidence-digest is required")?,
        actor,
    })
}

fn parse_target(args: &[String], command: &str) -> Result<TargetConfig, String> {
    let mut parsed = parse_show(args, command)?;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--actor" {
            parsed.actor = require_value(args, i, "--actor")?;
        }
        i += 1;
    }
    Ok(parsed)
}

fn parse_show(args: &[String], command: &str) -> Result<TargetConfig, String> {
    let mut namespace = None;
    let mut learning_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--learning-id" => {
                learning_id = Some(require_value(args, i, "--learning-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown {command} option {other}")),
        }
    }
    Ok(TargetConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        learning_id: learning_id.ok_or("--learning-id is required")?,
        actor,
    })
}

fn parse_list(args: &[String]) -> Result<Option<String>, String> {
    let mut namespace = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            other => return Err(format!("unknown list option {other}")),
        }
    }
    Ok(namespace)
}

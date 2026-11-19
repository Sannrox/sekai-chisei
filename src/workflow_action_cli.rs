//! sekaictl admin workflow commands (#709).

use crate::cli_args::require_value;
use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::workflow_action::{self, WorkflowStepEnvelope};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin workflow submit --envelope <file> [--actor <principal>]\n  sekaictl admin workflow park --envelope <file> [--actor <principal>]\n  sekaictl admin workflow resume --envelope <file> [--actor <principal>]\n  sekaictl admin workflow cancel --envelope <file> [--actor <principal>]\n  sekaictl admin workflow callback --envelope <file> --payload-digest <sha256:...> [--actor <principal>]\n  sekaictl admin workflow get --namespace <ns> --binding-id <id> [--actor <principal>]\n  sekaictl admin workflow reconcile --namespace <ns> --binding-id <id> [--actor <principal>]"
}

pub async fn run_workflow_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("submit") => submit(parse_envelope(&args[1..])?).await,
        Some("park") => park(parse_envelope(&args[1..])?).await,
        Some("resume") => resume(parse_envelope(&args[1..])?).await,
        Some("cancel") => cancel(parse_envelope(&args[1..])?).await,
        Some("callback") => callback(parse_callback(&args[1..])?).await,
        Some("get") => get(parse_binding_actor(&args[1..])?).await,
        Some("reconcile") => reconcile(parse_binding_actor(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

struct EnvelopeActor {
    path: PathBuf,
    actor: String,
}

async fn submit(config: EnvelopeActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let envelope = read_envelope(&config.path)?;
    let binding = workflow_action::submit_step(
        db.as_ref(),
        &config.actor,
        &envelope,
        Utc::now().timestamp_millis(),
        None,
        None,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&binding)?);
    Ok(())
}

async fn park(config: EnvelopeActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let envelope = read_envelope(&config.path)?;
    let binding = workflow_action::park_step(
        db.as_ref(),
        &config.actor,
        &envelope,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&binding)?);
    Ok(())
}

async fn resume(config: EnvelopeActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let envelope = read_envelope(&config.path)?;
    let binding = workflow_action::resume_step(
        db.as_ref(),
        &config.actor,
        &envelope,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&binding)?);
    Ok(())
}

async fn cancel(config: EnvelopeActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let envelope = read_envelope(&config.path)?;
    let binding = workflow_action::cancel_step(
        db.as_ref(),
        &config.actor,
        &envelope,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&binding)?);
    Ok(())
}

struct CallbackActor {
    path: PathBuf,
    payload_digest: String,
    actor: String,
}

async fn callback(config: CallbackActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let envelope = read_envelope(&config.path)?;
    let binding = workflow_action::callback_step(
        db.as_ref(),
        &config.actor,
        &envelope,
        &config.payload_digest,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&binding)?);
    Ok(())
}

struct BindingActor {
    namespace: String,
    binding_id: String,
    actor: String,
}

async fn get(config: BindingActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let binding = workflow_action::get_binding(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.binding_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&binding)?);
    Ok(())
}

async fn reconcile(config: BindingActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let report = workflow_action::reconcile_receipt(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.binding_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn read_envelope(path: &PathBuf) -> Result<WorkflowStepEnvelope, BoxErr> {
    Ok(serde_json::from_slice(&std::fs::read(path)?).map_err(std::io::Error::other)?)
}

fn parse_envelope(args: &[String]) -> Result<EnvelopeActor, String> {
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
    Ok(EnvelopeActor {
        path: path.ok_or("--envelope is required")?,
        actor,
    })
}

fn parse_callback(args: &[String]) -> Result<CallbackActor, String> {
    let mut path = None;
    let mut payload_digest = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--envelope" => {
                path = Some(PathBuf::from(require_value(args, i, "--envelope")?));
                i += 2;
            }
            "--payload-digest" => {
                payload_digest = Some(require_value(args, i, "--payload-digest")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(CallbackActor {
        path: path.ok_or("--envelope is required")?,
        payload_digest: payload_digest.ok_or("--payload-digest is required")?,
        actor,
    })
}

fn parse_binding_actor(args: &[String]) -> Result<BindingActor, String> {
    let mut namespace = None;
    let mut binding_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--binding-id" => {
                binding_id = Some(require_value(args, i, "--binding-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(BindingActor {
        namespace: namespace.ok_or("--namespace is required")?,
        binding_id: binding_id.ok_or("--binding-id is required")?,
        actor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_names_the_shipped_admin_workflow_surface() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin workflow submit"));
        assert!(usage.contains("park"));
        assert!(usage.contains("callback"));
        assert!(usage.contains("reconcile"));
    }

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn envelope_parser_defaults_the_actor_and_refuses_bad_input() {
        let parsed = parse_envelope(&args(&["--envelope", "step.json"])).unwrap();
        assert_eq!(parsed.path, PathBuf::from("step.json"));
        assert_eq!(parsed.actor, "operator");
        let parsed =
            parse_envelope(&args(&["--actor", "agent:ops", "--envelope", "step.json"])).unwrap();
        assert_eq!(parsed.actor, "agent:ops");

        let refused = |raw: &[&str]| parse_envelope(&args(raw)).err().unwrap();
        assert_eq!(refused(&[]), "--envelope is required");
        assert_eq!(refused(&["--envelope"]), "--envelope requires a value");
        assert_eq!(
            refused(&["--envelope", "x", "--force"]),
            "unknown option --force"
        );
        // A flag never takes the next flag as its value.
        assert_eq!(
            refused(&["--actor", "--envelope", "x"]),
            "--actor requires a value"
        );
    }

    #[test]
    fn callback_parser_defaults_the_actor_and_requires_both_flags() {
        let parsed = parse_callback(&args(&[
            "--envelope",
            "step.json",
            "--payload-digest",
            "sha256:abc",
        ]))
        .unwrap();
        assert_eq!(parsed.path, PathBuf::from("step.json"));
        assert_eq!(parsed.payload_digest, "sha256:abc");
        assert_eq!(parsed.actor, "operator");
        let parsed = parse_callback(&args(&[
            "--envelope",
            "step.json",
            "--payload-digest",
            "sha256:abc",
            "--actor",
            "agent:ops",
        ]))
        .unwrap();
        assert_eq!(parsed.actor, "agent:ops");

        let refused = |raw: &[&str]| parse_callback(&args(raw)).err().unwrap();
        assert_eq!(
            refused(&["--payload-digest", "sha256:abc"]),
            "--envelope is required"
        );
        assert_eq!(
            refused(&["--envelope", "step.json"]),
            "--payload-digest is required"
        );
        assert_eq!(
            refused(&["--envelope", "step.json", "--payload-digest"]),
            "--payload-digest requires a value"
        );
        assert_eq!(refused(&["--digest", "x"]), "unknown option --digest");
    }

    #[test]
    fn binding_parser_defaults_the_actor_and_requires_both_flags() {
        let parsed =
            parse_binding_actor(&args(&["--namespace", "ops", "--binding-id", "b-1"])).unwrap();
        assert_eq!(parsed.namespace, "ops");
        assert_eq!(parsed.binding_id, "b-1");
        assert_eq!(parsed.actor, "operator");
        let parsed = parse_binding_actor(&args(&[
            "--namespace",
            "ops",
            "--binding-id",
            "b-1",
            "--actor",
            "agent:ops",
        ]))
        .unwrap();
        assert_eq!(parsed.actor, "agent:ops");

        let refused = |raw: &[&str]| parse_binding_actor(&args(raw)).err().unwrap();
        assert_eq!(refused(&["--binding-id", "b-1"]), "--namespace is required");
        assert_eq!(refused(&["--namespace", "ops"]), "--binding-id is required");
        assert_eq!(
            refused(&["--namespace", "ops", "--binding-id"]),
            "--binding-id requires a value"
        );
        assert_eq!(refused(&["--ns", "ops"]), "unknown option --ns");
    }
}

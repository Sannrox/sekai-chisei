//! sekaictl admin images commands (#696).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::image::{self, GovernedImage, ImageAnnotation, ImageRendition, ImageRetrieve};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin images admit --image <file> [--actor <principal>]\n  sekaictl admin images attach-rendition --rendition <file> [--actor <principal>]\n  sekaictl admin images attach-annotation --annotation <file> [--actor <principal>]\n  sekaictl admin images get --namespace <ns> --image-id <id> --purpose <purpose> [--field <name>]... [--classification-ceiling <token>] [--actor <principal>]\n  sekaictl admin images hold --namespace <ns> --image-id <id> --hold-id <id> --reason <text> [--actor <principal>]\n  sekaictl admin images release-hold --namespace <ns> --image-id <id> --hold-id <id> [--actor <principal>]\n  sekaictl admin images expire --namespace <ns> --image-id <id> [--actor <principal>]\n  sekaictl admin images delete --namespace <ns> --image-id <id> [--actor <principal>]\n  --classification-ceiling may only restrict a sealed principal profile"
}

pub async fn run_images_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("admit") => admit(parse_file_actor(&args[1..], "--image")?).await,
        Some("attach-rendition") => attach(parse_file_actor(&args[1..], "--rendition")?).await,
        Some("attach-annotation") => {
            attach_annotation(parse_file_actor(&args[1..], "--annotation")?).await
        }
        Some("get") => get(parse_get(&args[1..])?).await,
        Some("hold") => hold(parse_hold(&args[1..])?).await,
        Some("release-hold") => release(parse_release(&args[1..])?).await,
        Some("expire") => expire(parse_image_actor(&args[1..])?).await,
        Some("delete") => delete(parse_image_actor(&args[1..])?).await,
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

async fn admit(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let image: GovernedImage =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let admitted = image::admit_image(
        db.as_ref(),
        &config.actor,
        &image,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&admitted)?);
    Ok(())
}

async fn attach(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let rendition: ImageRendition =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let attached = image::attach_rendition(
        db.as_ref(),
        &config.actor,
        &rendition,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&attached)?);
    Ok(())
}

async fn attach_annotation(config: FileActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let annotation: ImageAnnotation =
        serde_json::from_slice(&std::fs::read(&config.path)?).map_err(std::io::Error::other)?;
    let attached = image::attach_annotation(
        db.as_ref(),
        &config.actor,
        &annotation,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&attached)?);
    Ok(())
}

struct GetConfig {
    namespace: String,
    image_id: String,
    purpose: String,
    fields: Vec<String>,
    classification_ceiling: Option<String>,
    actor: String,
}

async fn get(config: GetConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let view = image::retrieve_image(
        db.as_ref(),
        &config.actor,
        &ImageRetrieve {
            namespace: config.namespace,
            image_id: config.image_id,
            purpose: Some(config.purpose),
            fields: config.fields,
            classification_ceiling: config.classification_ceiling,
        },
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}

struct HoldConfig {
    namespace: String,
    image_id: String,
    hold_id: String,
    reason: String,
    actor: String,
}

async fn hold(config: HoldConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let held = image::place_hold(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.image_id,
        &config.hold_id,
        &config.reason,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&held)?);
    Ok(())
}

struct ReleaseConfig {
    namespace: String,
    image_id: String,
    hold_id: String,
    actor: String,
}

async fn release(config: ReleaseConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let released = image::release_hold(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.image_id,
        &config.hold_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&released)?);
    Ok(())
}

struct ImageActor {
    namespace: String,
    image_id: String,
    actor: String,
}

async fn expire(config: ImageActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let expired = image::expire_image(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.image_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&expired)?);
    Ok(())
}

async fn delete(config: ImageActor) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let deleted = image::delete_image(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.image_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&deleted)?);
    Ok(())
}

fn parse_file_actor(args: &[String], path_flag: &str) -> Result<FileActor, String> {
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

fn parse_get(args: &[String]) -> Result<GetConfig, String> {
    let mut namespace = None;
    let mut image_id = None;
    let mut purpose = None;
    let mut fields = Vec::new();
    let mut classification_ceiling = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--image-id" => {
                image_id = Some(require_value(args, i, "--image-id")?);
                i += 2;
            }
            "--purpose" => {
                purpose = Some(require_value(args, i, "--purpose")?);
                i += 2;
            }
            "--field" => {
                fields.push(require_value(args, i, "--field")?);
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
            other => return Err(format!("unknown get option {other}")),
        }
    }
    Ok(GetConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        image_id: image_id.ok_or("--image-id is required")?,
        purpose: purpose.ok_or("--purpose is required")?,
        fields,
        classification_ceiling,
        actor,
    })
}

fn parse_hold(args: &[String]) -> Result<HoldConfig, String> {
    let mut namespace = None;
    let mut image_id = None;
    let mut hold_id = None;
    let mut reason = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--image-id" => {
                image_id = Some(require_value(args, i, "--image-id")?);
                i += 2;
            }
            "--hold-id" => {
                hold_id = Some(require_value(args, i, "--hold-id")?);
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
            other => return Err(format!("unknown hold option {other}")),
        }
    }
    Ok(HoldConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        image_id: image_id.ok_or("--image-id is required")?,
        hold_id: hold_id.ok_or("--hold-id is required")?,
        reason: reason.ok_or("--reason is required")?,
        actor,
    })
}

fn parse_release(args: &[String]) -> Result<ReleaseConfig, String> {
    let mut namespace = None;
    let mut image_id = None;
    let mut hold_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--image-id" => {
                image_id = Some(require_value(args, i, "--image-id")?);
                i += 2;
            }
            "--hold-id" => {
                hold_id = Some(require_value(args, i, "--hold-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown release-hold option {other}")),
        }
    }
    Ok(ReleaseConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        image_id: image_id.ok_or("--image-id is required")?,
        hold_id: hold_id.ok_or("--hold-id is required")?,
        actor,
    })
}

fn parse_image_actor(args: &[String]) -> Result<ImageActor, String> {
    let mut namespace = None;
    let mut image_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--image-id" => {
                image_id = Some(require_value(args, i, "--image-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(ImageActor {
        namespace: namespace.ok_or("--namespace is required")?,
        image_id: image_id.ok_or("--image-id is required")?,
        actor,
    })
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .filter(|value| !value.is_empty() && !value.starts_with("--"))
        .ok_or_else(|| format!("{flag} requires a value"))
}

//! sekaictl admin sdk-packages commands (#702).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::client_package::{self, ClientPackage, PackageArtifacts};
use chrono::Utc;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin sdk-packages publish --package <file> --protocol <file> --source <file> --artifact <file> [--actor <principal>]\n  sekaictl admin sdk-packages get --namespace <ns> --package-id <id> [--actor <principal>]\n  sekaictl admin sdk-packages verify --namespace <ns> --package-id <id> --protocol <file> --source <file> --artifact <file> [--actor <principal>]\n  sekaictl admin sdk-packages smoke --namespace <ns> --package-id <id> --protocol <file> --source <file> --artifact <file> [--actor <principal>]"
}

pub async fn run_sdk_packages_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("publish") => publish(parse_publish(&args[1..])?).await,
        Some("get") => get(parse_get(&args[1..])?).await,
        Some("verify") => verify(parse_verify(&args[1..])?).await,
        Some("smoke") => smoke(parse_verify(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

fn read_artifacts(
    protocol: &PathBuf,
    source: &PathBuf,
    artifact: &PathBuf,
) -> Result<PackageArtifacts, BoxErr> {
    Ok(client_package::artifacts_from(
        &std::fs::read_to_string(protocol)?,
        &std::fs::read_to_string(source)?,
        &std::fs::read(artifact)?,
    )
    .map_err(std::io::Error::other)?)
}

struct PublishConfig {
    package: PathBuf,
    protocol: PathBuf,
    source: PathBuf,
    artifact: PathBuf,
    actor: String,
}

async fn publish(config: PublishConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let mut package: ClientPackage =
        serde_json::from_slice(&std::fs::read(&config.package)?).map_err(std::io::Error::other)?;
    let artifacts = read_artifacts(&config.protocol, &config.source, &config.artifact)?;
    fill_digest(&mut package.protocol_digest, &artifacts.protocol)?;
    fill_digest(&mut package.source_digest, &artifacts.source)?;
    fill_digest(&mut package.package_digest, &artifacts.package)?;
    let published = client_package::publish_client_package(
        db.as_ref(),
        &config.actor,
        &package,
        &artifacts,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&published)?);
    Ok(())
}

struct GetConfig {
    namespace: String,
    package_id: String,
    actor: String,
}

async fn get(config: GetConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let package = client_package::get_client_package(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.package_id,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&package)?);
    Ok(())
}

struct VerifyConfig {
    namespace: String,
    package_id: String,
    protocol: PathBuf,
    source: PathBuf,
    artifact: PathBuf,
    actor: String,
}

async fn verify(config: VerifyConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let artifacts = read_artifacts(&config.protocol, &config.source, &config.artifact)?;
    let package = client_package::verify_client_package(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.package_id,
        &artifacts,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&package)?);
    Ok(())
}

async fn smoke(config: VerifyConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let artifacts = read_artifacts(&config.protocol, &config.source, &config.artifact)?;
    let package = client_package::smoke_client_package(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.package_id,
        &artifacts,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&package)?);
    Ok(())
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].as_str())
}

fn required_flag(args: &[String], name: &str) -> Result<String, BoxErr> {
    flag(args, name)
        .map(str::to_string)
        .ok_or_else(|| std::io::Error::other(usage()).into())
}

fn fill_digest(pin: &mut String, computed: &str) -> Result<(), BoxErr> {
    if pin.is_empty() {
        *pin = computed.into();
        return Ok(());
    }
    if pin != computed {
        return Err(std::io::Error::other(client_package::PACKAGE_UNAVAILABLE).into());
    }
    Ok(())
}

fn parse_actor(args: &[String]) -> String {
    flag(args, "--actor").unwrap_or("root").to_string()
}

fn parse_publish(args: &[String]) -> Result<PublishConfig, BoxErr> {
    Ok(PublishConfig {
        package: required_flag(args, "--package")?.into(),
        protocol: required_flag(args, "--protocol")?.into(),
        source: required_flag(args, "--source")?.into(),
        artifact: required_flag(args, "--artifact")?.into(),
        actor: parse_actor(args),
    })
}

fn parse_get(args: &[String]) -> Result<GetConfig, BoxErr> {
    Ok(GetConfig {
        namespace: required_flag(args, "--namespace")?,
        package_id: required_flag(args, "--package-id")?,
        actor: parse_actor(args),
    })
}

fn parse_verify(args: &[String]) -> Result<VerifyConfig, BoxErr> {
    Ok(VerifyConfig {
        namespace: required_flag(args, "--namespace")?,
        package_id: required_flag(args, "--package-id")?,
        protocol: required_flag(args, "--protocol")?.into(),
        source: required_flag(args, "--source")?.into(),
        artifact: required_flag(args, "--artifact")?.into(),
        actor: parse_actor(args),
    })
}

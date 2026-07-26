//! sekaictl compliance export/verify commands (#297).

use crate::compliance_export::{
    ComplianceExportBundle, ComplianceExportRequest, RedactionMode, compliance_bundle_bytes,
    export_compliance_from_db, sign_compliance_export, verify_compliance_export,
};
use crate::config::Config;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl compliance export --namespace <ns> --from-ms <ts> --to-ms <ts> --output <file> [--redact] [--request-id <id>] [--actor <principal>] [--signing-key <file> --identity <id> --key-id <id>]\n  sekaictl compliance verify <bundle> [--trusted-key <file>]"
}

pub async fn run_compliance_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("export") => export(parse_export(&args[1..])?).await,
        Some("verify") => verify(parse_verify(&args[1..])?),
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

#[derive(Debug, Clone)]
struct ExportConfig {
    namespace: String,
    from_ms: i64,
    to_ms: i64,
    output: PathBuf,
    redact: bool,
    request_id: String,
    actor: String,
    signing_key: Option<PathBuf>,
    identity: Option<String>,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
struct VerifyConfig {
    bundle: PathBuf,
    trusted_key: Option<PathBuf>,
}

async fn export(config: ExportConfig) -> Result<(), BoxErr> {
    let cfg = Config::from_env();
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&cfg.db_path)?));
    let request = ComplianceExportRequest {
        namespace: config.namespace,
        start_timestamp_ms: config.from_ms,
        end_timestamp_ms: config.to_ms,
        redaction: if config.redact {
            RedactionMode::Redacted
        } else {
            RedactionMode::Full
        },
        actor: config.actor,
        request_id: config.request_id,
    };
    let mut bundle = export_compliance_from_db(&db, &request, Utc::now().timestamp_millis())?;
    if let (Some(key_path), Some(identity), Some(key_id)) =
        (&config.signing_key, &config.identity, &config.key_id)
    {
        let signing = load_signing_key(key_path)?;
        sign_compliance_export(
            &mut bundle,
            &signing,
            identity,
            key_id,
            Utc::now().timestamp_millis(),
        )?;
    }
    std::fs::write(&config.output, compliance_bundle_bytes(&bundle)?)?;
    println!(
        "exported {} receipts={} decisions={} digest={}",
        config.output.display(),
        bundle.manifest.receipt_count,
        bundle.manifest.decision_count,
        bundle.manifest.content_digest
    );
    Ok(())
}

fn verify(config: VerifyConfig) -> Result<(), BoxErr> {
    let bundle: ComplianceExportBundle = serde_json::from_slice(&std::fs::read(&config.bundle)?)?;
    let trusted = match &config.trusted_key {
        Some(path) => Some(encode_hex(load_verifying_key(path)?.as_bytes())),
        None => None,
    };
    let report = verify_compliance_export(&bundle, trusted.as_deref());
    if report.ok {
        println!(
            "ok content_digest_ok={} signature_ok={} receipts={} decisions={}",
            report.content_digest_ok,
            report.signature_ok,
            bundle.manifest.receipt_count,
            bundle.manifest.decision_count
        );
        Ok(())
    } else {
        for error in &report.errors {
            eprintln!("error: {error}");
        }
        Err(std::io::Error::other("compliance bundle verification failed").into())
    }
}

fn parse_export(args: &[String]) -> Result<ExportConfig, String> {
    let mut namespace = None;
    let mut from_ms = None;
    let mut to_ms = None;
    let mut output = None;
    let mut redact = false;
    let mut request_id = format!("compliance-export-{}", Utc::now().timestamp_millis());
    let mut actor = std::env::var("SEKAI_ACTOR").unwrap_or_else(|_| "local-operator".into());
    let mut signing_key = None;
    let mut identity = None;
    let mut key_id = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, index, "--namespace")?);
                index += 2;
            }
            "--from-ms" => {
                from_ms = Some(parse_i64(&require_value(args, index, "--from-ms")?)?);
                index += 2;
            }
            "--to-ms" => {
                to_ms = Some(parse_i64(&require_value(args, index, "--to-ms")?)?);
                index += 2;
            }
            "--output" => {
                output = Some(PathBuf::from(require_value(args, index, "--output")?));
                index += 2;
            }
            "--redact" => {
                redact = true;
                index += 1;
            }
            "--request-id" => {
                request_id = require_value(args, index, "--request-id")?;
                index += 2;
            }
            "--actor" => {
                actor = require_value(args, index, "--actor")?;
                index += 2;
            }
            "--signing-key" => {
                signing_key = Some(PathBuf::from(require_value(args, index, "--signing-key")?));
                index += 2;
            }
            "--identity" => {
                identity = Some(require_value(args, index, "--identity")?);
                index += 2;
            }
            "--key-id" => {
                key_id = Some(require_value(args, index, "--key-id")?);
                index += 2;
            }
            other => return Err(format!("unknown export flag: {other}")),
        }
    }
    Ok(ExportConfig {
        namespace: namespace.ok_or("--namespace required")?,
        from_ms: from_ms.ok_or("--from-ms required")?,
        to_ms: to_ms.ok_or("--to-ms required")?,
        output: output.ok_or("--output required")?,
        redact,
        request_id,
        actor,
        signing_key,
        identity,
        key_id,
    })
}

fn parse_verify(args: &[String]) -> Result<VerifyConfig, String> {
    let mut bundle = None;
    let mut trusted_key = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--trusted-key" => {
                trusted_key = Some(PathBuf::from(require_value(args, index, "--trusted-key")?));
                index += 2;
            }
            other if !other.starts_with('-') && bundle.is_none() => {
                bundle = Some(PathBuf::from(other));
                index += 1;
            }
            other => return Err(format!("unknown verify flag: {other}")),
        }
    }
    Ok(VerifyConfig {
        bundle: bundle.ok_or("bundle path required")?,
        trusted_key,
    })
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_i64(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|error| format!("invalid integer {value}: {error}"))
}

fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let seed = if bytes.len() == 32 {
        bytes
    } else {
        decode_hex(String::from_utf8_lossy(&bytes).trim())?
    };
    let array: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "signing key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&array))
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let key = if bytes.len() == 32 {
        bytes
    } else {
        decode_hex(String::from_utf8_lossy(&bytes).trim())?
    };
    let array: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&array).map_err(|error| format!("invalid public key: {error}"))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&trimmed[index..index + 2], 16)
                .map_err(|error| format!("invalid hex: {error}"))
        })
        .collect()
}

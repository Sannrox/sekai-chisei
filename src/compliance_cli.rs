//! sekaictl admin assurance compliance export/verify commands (#297).

use crate::compliance_export::{
    ComplianceExportBundle, ComplianceExportRequest, RedactionMode, compliance_bundle_bytes,
    export_compliance_from_db, record_compliance_export_success, sign_compliance_export,
    verify_compliance_export,
};
use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin assurance compliance export --namespace <ns> --from-ms <ts> --to-ms <ts> --output <file> [--redact] [--request-id <id>] [--actor <principal>] [--signing-key <file> --identity <id> --key-id <id>]\n  sekaictl admin assurance compliance verify <bundle> [--trusted-key <file>]\n  sekaictl admin assurance compliance trust-root --namespace <ns> --site-identity <id> --key-id <id> --public-key-hex <hex> [--actor <principal>]\n  sekaictl admin assurance compliance import-peer --namespace <ns> --bundle <file> [--actor <principal>]\n  sekaictl admin assurance compliance list-trust-roots --namespace <ns>"
}

pub async fn run_compliance_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("export") => export(parse_export(&args[1..])?).await,
        Some("verify") => verify(parse_verify(&args[1..])?),
        Some("trust-root") => trust_root(parse_trust_root(&args[1..])?).await,
        Some("import-peer") => import_peer(parse_import_peer(&args[1..])?).await,
        Some("list-trust-roots") => list_trust_roots(parse_list_trust_roots(&args[1..])?).await,
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
    // Local sekaictl export uses the host database configuration as the trust
    // boundary, matching receipt/report CLIs. Callers who can open the runtime
    // store can already read the underlying tables. Networked multi-tenant
    // export must go through an authorized gRPC surface (follow-up).
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    let db = backend.database();
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
    if config.output.exists() {
        return Err(std::io::Error::other(format!(
            "output already exists: {} (refusing to overwrite a compliance artifact)",
            config.output.display()
        ))
        .into());
    }
    let signing_parts = [
        config.signing_key.is_some(),
        config.identity.is_some(),
        config.key_id.is_some(),
    ];
    if signing_parts.iter().any(|present| *present) && !signing_parts.iter().all(|present| *present)
    {
        return Err(std::io::Error::other(
            "signing requires all of --signing-key, --identity, and --key-id (or none)",
        )
        .into());
    }

    let exported_at = Utc::now().timestamp_millis();
    let mut bundle = export_compliance_from_db(db.as_ref(), &request, exported_at)?;
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

    // Unique create-new staging file (no symlink follow), publish, then audit.
    let parent = config
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staged = parent.join(format!(
        ".compliance-export-{}-{}.partial",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let write_result = (|| {
            let mut file = options.open(&staged)?;
            file.write_all(&compliance_bundle_bytes(&bundle)?)?;
            file.sync_all()?;
            Ok::<(), BoxErr>(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&staged);
            return Err(error);
        }
    }
    // hard_link fails if the destination already exists (no silent overwrite).
    if let Err(error) = std::fs::hard_link(&staged, &config.output) {
        let _ = std::fs::remove_file(&staged);
        return Err(std::io::Error::new(
            error.kind(),
            format!(
                "failed to publish {}: {error} (destination must not already exist)",
                config.output.display()
            ),
        )
        .into());
    }
    let _ = std::fs::remove_file(&staged);
    // Make the published directory entry durable before recording success.
    match std::fs::File::open(parent) {
        Ok(dir) => {
            if let Err(error) = dir.sync_all() {
                let _ = std::fs::remove_file(&config.output);
                return Err(error.into());
            }
        }
        Err(error) => {
            // On platforms where the parent cannot be opened as a file, fail
            // closed rather than claiming durable publication without evidence.
            let _ = std::fs::remove_file(&config.output);
            return Err(error.into());
        }
    }
    if let Err(error) = record_compliance_export_success(
        db.as_ref(),
        &request,
        &bundle,
        Utc::now().timestamp_millis(),
    ) {
        // Best-effort compensation: remove only the file this invocation
        // published if audit fails so we do not leave an unaudited artifact.
        let _ = std::fs::remove_file(&config.output);
        return Err(error.into());
    }
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

#[derive(Debug, Clone)]
struct TrustRootConfig {
    namespace: String,
    site_identity: String,
    key_id: String,
    public_key_hex: String,
    actor: String,
}

#[derive(Debug, Clone)]
struct ImportPeerConfig {
    namespace: String,
    bundle: PathBuf,
    actor: String,
}

#[derive(Debug, Clone)]
struct ListTrustRootsConfig {
    namespace: String,
}

async fn open_local_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

async fn trust_root(config: TrustRootConfig) -> Result<(), BoxErr> {
    let db = open_local_db().await?;
    let root = crate::sekai::peer_import::PeerTrustRoot {
        namespace: config.namespace,
        site_identity: config.site_identity,
        key_id: config.key_id,
        public_key_hex: config.public_key_hex,
        enabled: true,
        created_by: config.actor,
        created_at_ms: Utc::now().timestamp_millis(),
    };
    crate::sekai::peer_import::put_trust_root(db.as_ref(), &root).map_err(std::io::Error::other)?;
    println!(
        "trusted peer site={} key_id={} namespace={}",
        root.site_identity, root.key_id, root.namespace
    );
    Ok(())
}

async fn import_peer(config: ImportPeerConfig) -> Result<(), BoxErr> {
    let db = open_local_db().await?;
    let bundle: ComplianceExportBundle = serde_json::from_slice(&std::fs::read(&config.bundle)?)?;
    let result = crate::sekai::peer_import::import_compliance_bundle(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &bundle,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!(
        "imported id={} digest={} receipts={} decisions={} permit_authority={}",
        result.record.import_id,
        result.record.bundle_content_digest,
        result.record.receipt_count,
        result.record.decision_count,
        result.record.permit_authority
    );
    Ok(())
}

async fn list_trust_roots(config: ListTrustRootsConfig) -> Result<(), BoxErr> {
    let db = open_local_db().await?;
    let roots = crate::sekai::peer_import::list_trust_roots(db.as_ref(), &config.namespace)
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&roots)?);
    Ok(())
}

fn parse_trust_root(args: &[String]) -> Result<TrustRootConfig, String> {
    let mut namespace = None;
    let mut site_identity = None;
    let mut key_id = None;
    let mut public_key_hex = None;
    let mut actor = std::env::var("SEKAI_ACTOR").unwrap_or_else(|_| "local-operator".into());
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, index, "--namespace")?);
                index += 2;
            }
            "--site-identity" => {
                site_identity = Some(require_value(args, index, "--site-identity")?);
                index += 2;
            }
            "--key-id" => {
                key_id = Some(require_value(args, index, "--key-id")?);
                index += 2;
            }
            "--public-key-hex" => {
                public_key_hex = Some(require_value(args, index, "--public-key-hex")?);
                index += 2;
            }
            "--actor" => {
                actor = require_value(args, index, "--actor")?;
                index += 2;
            }
            other => return Err(format!("unknown trust-root option {other}")),
        }
    }
    Ok(TrustRootConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        site_identity: site_identity.ok_or("--site-identity is required")?,
        key_id: key_id.ok_or("--key-id is required")?,
        public_key_hex: public_key_hex.ok_or("--public-key-hex is required")?,
        actor,
    })
}

fn parse_import_peer(args: &[String]) -> Result<ImportPeerConfig, String> {
    let mut namespace = None;
    let mut bundle = None;
    let mut actor = std::env::var("SEKAI_ACTOR").unwrap_or_else(|_| "local-operator".into());
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, index, "--namespace")?);
                index += 2;
            }
            "--bundle" => {
                bundle = Some(PathBuf::from(require_value(args, index, "--bundle")?));
                index += 2;
            }
            "--actor" => {
                actor = require_value(args, index, "--actor")?;
                index += 2;
            }
            other => return Err(format!("unknown import-peer option {other}")),
        }
    }
    Ok(ImportPeerConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        bundle: bundle.ok_or("--bundle is required")?,
        actor,
    })
}

fn parse_list_trust_roots(args: &[String]) -> Result<ListTrustRootsConfig, String> {
    let mut namespace = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, index, "--namespace")?);
                index += 2;
            }
            other => return Err(format!("unknown list-trust-roots option {other}")),
        }
    }
    Ok(ListTrustRootsConfig {
        namespace: namespace.ok_or("--namespace is required")?,
    })
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

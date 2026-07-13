use crate::chisei::receipt::OperationReceipt;
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::GetOperationReceiptRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::sekai::attestation::PolicyAttestation;
use crate::shomei::{
    AttestationBundle, KeyMetadata, KeyState, TrustedKeyring, VerificationReport,
    canonical_bundle_bytes, in_toto_verification_statement, verify_bundle,
};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl attest export <operation-id> --output <bundle> [--signing-key <file> --identity <signer> --key-id <id>] [--artifact <reference>=<path>]... [--policy-attestation <file>]...\n  sekaictl attest verify <bundle> [--trusted-key <file> --identity <signer> --key-id <id> --key-state <active|rotated|revoked|unknown>] [--valid-from-ms <time>] [--valid-until-ms <time>] [--revoked-at-ms <time>] [--successor-key-id <id>] [--integrity-only] [--format <text|json|in-toto>]"
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportConfig {
    operation_id: String,
    output: PathBuf,
    signing_key: PathBuf,
    identity: String,
    key_id: String,
    artifacts: Vec<(String, PathBuf)>,
    policy_attestations: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifyConfig {
    bundle: PathBuf,
    trusted_key: PathBuf,
    identity: String,
    key_id: String,
    integrity_only: bool,
    key_metadata: KeyMetadata,
    format: ReportFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportFormat {
    Text,
    Json,
    InToto,
}

pub async fn run_attest_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("export") => export(parse_export(&args[1..])?).await,
        Some("verify") => verify(parse_verify(&args[1..])?),
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn export(config: ExportConfig) -> Result<(), BoxErr> {
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".to_string());
    let receipt_json = ChiseiServiceClient::new(connect_sekai(&target).await?)
        .get_operation_receipt(GetOperationReceiptRequest {
            operation_id: config.operation_id,
        })
        .await?
        .into_inner()
        .receipt_json;
    let receipt: OperationReceipt = serde_json::from_str(&receipt_json)?;
    let signing_key = load_signing_key(&config.signing_key)?;
    let mut bundle = AttestationBundle::unsigned(receipt)?;
    for (reference, path) in &config.artifacts {
        bundle.attach_artifact(reference, None, &std::fs::read(path)?)?;
    }
    for path in &config.policy_attestations {
        let attestation: PolicyAttestation = serde_json::from_slice(&std::fs::read(path)?)?;
        bundle.attach_policy_attestation(attestation)?;
    }
    bundle.sign(
        &signing_key,
        &config.identity,
        &config.key_id,
        Utc::now().timestamp_millis(),
    )?;
    std::fs::write(&config.output, canonical_bundle_bytes(&bundle)?)?;
    println!("exported {}", config.output.display());
    Ok(())
}

fn verify(config: VerifyConfig) -> Result<(), BoxErr> {
    let bundle: AttestationBundle = serde_json::from_slice(&std::fs::read(&config.bundle)?)?;
    let mut trusted_keys = TrustedKeyring::new();
    trusted_keys.trust_with_metadata(
        config.identity,
        config.key_id,
        load_verifying_key(&config.trusted_key)?,
        config.key_metadata,
    )?;
    let report = verify_bundle(&bundle, &trusted_keys);
    render_report(&bundle, &report, config.format)?;
    if !report.integrity.valid {
        return Err(std::io::Error::other("attestation integrity verification failed").into());
    }
    if !config.integrity_only && !report.policy.compliant {
        return Err(std::io::Error::other("attestation policy verification failed").into());
    }
    Ok(())
}

fn render_report(
    bundle: &AttestationBundle,
    report: &VerificationReport,
    format: ReportFormat,
) -> Result<(), BoxErr> {
    match format {
        ReportFormat::Json => {
            println!("{}", serde_json::to_string_pretty(report)?);
            return Ok(());
        }
        ReportFormat::InToto => {
            println!(
                "{}",
                serde_json::to_string_pretty(&in_toto_verification_statement(bundle, report))?
            );
            return Ok(());
        }
        ReportFormat::Text => {}
    }
    println!("integrity: {}", report.integrity.valid);
    println!("policy_compliant: {}", report.policy.compliant);
    println!("key_state: {:?}", report.policy.key.state);
    println!(
        "key_acceptable_at_verification: {}",
        report.policy.key.acceptable_at_verification
    );
    if let Some(signature) = &bundle.signature {
        println!("signer: {}", signature.signer.identity);
        println!("key_id: {}", signature.signer.key_id);
    }
    for error in &report.integrity.errors {
        println!("integrity_error: {error}");
    }
    for error in &report.policy.errors {
        println!("policy_error: {error}");
    }
    for error in &report.policy.key.errors {
        println!("key_error: {error}");
    }
    for attestation in &report.policy.policy_attestations {
        println!(
            "policy_attestation: {} valid={} replay={}",
            attestation.id, attestation.valid, attestation.replayed_decision
        );
        for error in &attestation.errors {
            println!("policy_attestation_error: {} {error}", attestation.id);
        }
    }
    if !report.policy.missing_surfaces.is_empty() {
        println!(
            "missing_surfaces: {}",
            report.policy.missing_surfaces.join(",")
        );
    }
    if !report.policy.missing_artifacts.is_empty() {
        println!(
            "missing_artifacts: {}",
            report.policy.missing_artifacts.join(",")
        );
    }
    for declaration in &report.policy.coverage {
        println!(
            "coverage: {:?} {} {}",
            declaration.disposition, declaration.kind, declaration.reference
        );
    }
    Ok(())
}

#[cfg(test)]
fn sign_receipt(
    receipt: OperationReceipt,
    signing_key: &SigningKey,
    identity: &str,
    key_id: &str,
    signed_at_ms: i64,
) -> Result<AttestationBundle, String> {
    let mut bundle = AttestationBundle::unsigned(receipt)?;
    bundle.sign(signing_key, identity, key_id, signed_at_ms)?;
    Ok(bundle)
}

fn parse_export(args: &[String]) -> Result<ExportConfig, String> {
    let operation_id = positional(args, 0).ok_or_else(|| usage().to_string())?;
    let output = flag(args, "--output")
        .map(PathBuf::from)
        .ok_or_else(|| "--output is required".to_string())?;
    let signing_key = flag(args, "--signing-key")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("SHOMEI_SIGNING_KEY_FILE").map(PathBuf::from))
        .ok_or_else(|| "--signing-key or SHOMEI_SIGNING_KEY_FILE is required".to_string())?;
    let identity = flag(args, "--identity")
        .or_else(|| std::env::var("SHOMEI_SIGNER_IDENTITY").ok())
        .ok_or_else(|| "--identity or SHOMEI_SIGNER_IDENTITY is required".to_string())?;
    let key_id = flag(args, "--key-id")
        .or_else(|| std::env::var("SHOMEI_KEY_ID").ok())
        .ok_or_else(|| "--key-id or SHOMEI_KEY_ID is required".to_string())?;
    let artifacts = flags(args, "--artifact")
        .into_iter()
        .map(|value| {
            let (reference, path) = value
                .split_once('=')
                .ok_or_else(|| "--artifact must use <reference>=<path>".to_string())?;
            if reference.trim().is_empty() || path.trim().is_empty() {
                return Err("--artifact must use <reference>=<path>".into());
            }
            Ok((reference.to_string(), PathBuf::from(path)))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let policy_attestations = flags(args, "--policy-attestation")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    Ok(ExportConfig {
        operation_id,
        output,
        signing_key,
        identity,
        key_id,
        artifacts,
        policy_attestations,
    })
}

fn parse_verify(args: &[String]) -> Result<VerifyConfig, String> {
    let bundle = positional(args, 0)
        .map(PathBuf::from)
        .ok_or_else(|| usage().to_string())?;
    let trusted_key = flag(args, "--trusted-key")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("SHOMEI_TRUSTED_KEY_FILE").map(PathBuf::from))
        .ok_or_else(|| "--trusted-key or SHOMEI_TRUSTED_KEY_FILE is required".to_string())?;
    let identity = flag(args, "--identity")
        .or_else(|| std::env::var("SHOMEI_TRUSTED_IDENTITY").ok())
        .ok_or_else(|| "--identity or SHOMEI_TRUSTED_IDENTITY is required".to_string())?;
    let key_id = flag(args, "--key-id")
        .or_else(|| std::env::var("SHOMEI_TRUSTED_KEY_ID").ok())
        .ok_or_else(|| "--key-id or SHOMEI_TRUSTED_KEY_ID is required".to_string())?;
    let key_state = flag(args, "--key-state")
        .or_else(|| std::env::var("SHOMEI_TRUSTED_KEY_STATE").ok())
        .ok_or_else(|| "--key-state or SHOMEI_TRUSTED_KEY_STATE is required".to_string())?;
    let parse_optional_time = |flag_name: &str, env_name: &str| -> Result<Option<i64>, String> {
        flag(args, flag_name)
            .or_else(|| std::env::var(env_name).ok())
            .map(|value| {
                value
                    .parse::<i64>()
                    .map_err(|_| format!("{flag_name} must be an integer timestamp"))
            })
            .transpose()
    };
    let key_metadata = KeyMetadata {
        state: parse_key_state(&key_state)?,
        valid_from_ms: parse_optional_time("--valid-from-ms", "SHOMEI_KEY_VALID_FROM_MS")?,
        valid_until_ms: parse_optional_time("--valid-until-ms", "SHOMEI_KEY_VALID_UNTIL_MS")?,
        revoked_at_ms: parse_optional_time("--revoked-at-ms", "SHOMEI_KEY_REVOKED_AT_MS")?,
        successor_key_id: flag(args, "--successor-key-id")
            .or_else(|| std::env::var("SHOMEI_SUCCESSOR_KEY_ID").ok()),
    };
    let format = if args.iter().any(|arg| arg == "--format") {
        parse_report_format(
            &flag(args, "--format").ok_or_else(|| "--format requires a value".to_string())?,
        )?
    } else {
        ReportFormat::Text
    };
    Ok(VerifyConfig {
        bundle,
        trusted_key,
        identity,
        key_id,
        integrity_only: args.iter().any(|arg| arg == "--integrity-only"),
        key_metadata,
        format,
    })
}

fn positional(args: &[String], wanted: usize) -> Option<String> {
    let mut position = 0;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--integrity-only" {
            index += 1;
            continue;
        }
        if args[index].starts_with('-') {
            index += 2;
            continue;
        }
        if position == wanted {
            return Some(args[index].clone());
        }
        position += 1;
        index += 1;
    }
    None
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn flags(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
}

fn parse_key_state(value: &str) -> Result<KeyState, String> {
    match value.trim() {
        "active" => Ok(KeyState::Active),
        "rotated" => Ok(KeyState::Rotated),
        "revoked" => Ok(KeyState::Revoked),
        "unknown" => Ok(KeyState::Unknown),
        _ => Err("--key-state must be active, rotated, revoked, or unknown".into()),
    }
}

fn parse_report_format(value: &str) -> Result<ReportFormat, String> {
    match value.trim() {
        "text" => Ok(ReportFormat::Text),
        "json" => Ok(ReportFormat::Json),
        "in-toto" => Ok(ReportFormat::InToto),
        _ => Err("--format must be text, json, or in-toto".into()),
    }
}

fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&decode_hex_key(
        "signing key",
        &std::fs::read_to_string(path).map_err(|error| error.to_string())?,
    )?))
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(&decode_hex_key(
        "trusted public key",
        &std::fs::read_to_string(path).map_err(|error| error.to_string())?,
    )?)
    .map_err(|error| format!("invalid trusted public key: {error}"))
}

fn decode_hex_key(field: &str, value: &str) -> Result<[u8; 32], String> {
    let value = value.trim();
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{field} must contain exactly 32 hexadecimal bytes"));
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{field} is not hexadecimal"))?;
        decoded[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("{field} is not hexadecimal"))?;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptEventKind,
    };
    use std::collections::BTreeMap;

    fn receipt(schema_version: &str) -> OperationReceipt {
        let kinds = [
            ReceiptEventKind::IntentRecorded,
            ReceiptEventKind::PolicyDecided,
            ReceiptEventKind::RouteSelected,
            ReceiptEventKind::BudgetDecided,
            ReceiptEventKind::OutcomeRecorded,
        ];
        let events = kinds
            .into_iter()
            .enumerate()
            .map(|(index, kind)| OperationReceiptEvent {
                event_id: format!("event-{index}"),
                operation_id: "op-1".into(),
                parent_event_id: index.checked_sub(1).map(|parent| format!("event-{parent}")),
                timestamp_ms: index as i64,
                kind,
                surface: kind.surface(),
                actor: "agent:test".into(),
                references: vec![],
                attributes: BTreeMap::new(),
            })
            .collect();
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "default".into(),
            operation_class: "model_inference".into(),
            initiating_actor: "agent:test".into(),
            schema_version: schema_version.into(),
            policy_version: "policy-v1".into(),
            started_at_ms: 0,
            completed_at_ms: Some(4),
            events,
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
        }
    }

    #[test]
    fn native_and_gateway_receipts_share_the_export_contract() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        for schema in ["chisei.execution/v1", "chisei.gateway/v1"] {
            let bundle =
                sign_receipt(receipt(schema), &signing_key, "node:test", "key-1", 10).unwrap();
            let mut trusted = TrustedKeyring::new();
            trusted
                .trust("node:test", "key-1", signing_key.verifying_key())
                .unwrap();
            assert!(verify_bundle(&bundle, &trusted).integrity.valid);
        }
    }

    #[test]
    fn export_parser_requires_an_output() {
        let error = parse_export(&["op-1".into()]).unwrap_err();
        assert_eq!(error, "--output is required");
    }

    #[test]
    fn export_parser_accepts_repeated_artifacts() {
        let config = parse_export(&[
            "op-1".into(),
            "--output".into(),
            "bundle.json".into(),
            "--signing-key".into(),
            "key.hex".into(),
            "--identity".into(),
            "node:test".into(),
            "--key-id".into(),
            "key-1".into(),
            "--artifact".into(),
            "artifact://one=one.txt".into(),
            "--artifact".into(),
            "artifact://two=two.txt".into(),
        ])
        .unwrap();
        assert_eq!(config.artifacts.len(), 2);
    }

    #[test]
    fn hex_key_decoder_is_strict() {
        assert_eq!(decode_hex_key("key", &"07".repeat(32)).unwrap(), [7; 32]);
        assert!(decode_hex_key("key", "zz").is_err());
    }

    #[test]
    fn verify_parser_requires_trusted_identity_metadata() {
        let error = parse_verify(&[
            "bundle.json".into(),
            "--trusted-key".into(),
            "key.pub".into(),
        ])
        .unwrap_err();
        assert_eq!(error, "--identity or SHOMEI_TRUSTED_IDENTITY is required");
    }

    #[test]
    fn verify_parser_accepts_boolean_flag_before_bundle() {
        let config = parse_verify(&[
            "--integrity-only".into(),
            "--trusted-key".into(),
            "key.pub".into(),
            "--identity".into(),
            "node:test".into(),
            "--key-id".into(),
            "key-1".into(),
            "--key-state".into(),
            "active".into(),
            "bundle.json".into(),
        ])
        .unwrap();
        assert_eq!(config.bundle, PathBuf::from("bundle.json"));
        assert!(config.integrity_only);
    }

    #[test]
    fn key_state_parser_supports_lifecycle_states() {
        assert_eq!(parse_key_state("active").unwrap(), KeyState::Active);
        assert_eq!(parse_key_state("rotated").unwrap(), KeyState::Rotated);
        assert_eq!(parse_key_state("revoked").unwrap(), KeyState::Revoked);
        assert_eq!(parse_key_state("unknown").unwrap(), KeyState::Unknown);
        assert!(parse_key_state("compromised").is_err());
    }

    #[test]
    fn report_format_parser_supports_external_formats() {
        assert_eq!(parse_report_format("text").unwrap(), ReportFormat::Text);
        assert_eq!(parse_report_format("json").unwrap(), ReportFormat::Json);
        assert_eq!(
            parse_report_format("in-toto").unwrap(),
            ReportFormat::InToto
        );
        assert!(parse_report_format("sarif").is_err());
    }

    #[test]
    fn verify_parser_rejects_missing_report_format_value() {
        let error = parse_verify(&[
            "bundle.json".into(),
            "--trusted-key".into(),
            "key.pub".into(),
            "--identity".into(),
            "node:test".into(),
            "--key-id".into(),
            "key-1".into(),
            "--key-state".into(),
            "active".into(),
            "--format".into(),
        ])
        .unwrap_err();
        assert_eq!(error, "--format requires a value");
    }
}

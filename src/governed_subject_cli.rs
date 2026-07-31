//! Fixed local adapters for registered governed-subject profiles.

use crate::chisei::governed_subject::{
    ALLOW_PROFILE, ENVELOPE_VERSION, SOFTWARE_RELEASE_PROFILE, SoftwareReleaseCandidate,
};
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{
    EvaluateGovernedSubjectRequest, ExportGovernedSubjectProvenanceRequest,
    GetGovernedSubjectProvenanceTrustRootRequest, GovernedSubjectEnvelope,
    GovernedSubjectProvenanceEnvelope, GovernedSubjectReference,
};
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "Usage:\n\
     sekaictl admin governance subject software-release <candidate.json> --namespace <name> --request-id <id> [--evaluation-profile <profile>] [--target <url-or-socket>]\n\
     sekaictl admin governance subject provenance export <candidate.json> --operation-id <id> --receipt-digest <sha256:...> --export-id <id> [--output <path>] [--target <url-or-socket>]\n\
     sekaictl admin governance subject provenance trust-root --export-id <id> [--output <path>] [--target <url-or-socket>]"
}

pub async fn run(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("software-release") => run_software_release(args).await,
        Some("provenance") => run_provenance(args.into_iter().skip(1).collect()).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn run_software_release(args: Vec<String>) -> Result<(), BoxErr> {
    let path = args
        .get(1)
        .filter(|value| !value.starts_with('-'))
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other(usage()))?;
    let flag = |name: &str| {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].clone())
    };
    let namespace = flag("--namespace").ok_or_else(|| std::io::Error::other(usage()))?;
    let request_id = flag("--request-id").ok_or_else(|| std::io::Error::other(usage()))?;
    let evaluation_profile = flag("--evaluation-profile").unwrap_or_else(|| ALLOW_PROFILE.into());
    let target = flag("--target")
        .or_else(|| std::env::var("CHISEI_GRPC_URL").ok())
        .or_else(|| std::env::var("SEKAI_SOCKET").ok())
        .unwrap_or_else(|| "./data/sekai.sock".into());
    let bytes = std::fs::read(&path)?;
    let candidate: SoftwareReleaseCandidate = serde_json::from_slice(&bytes)?;
    let subject_identity = candidate
        .canonical_identity()
        .map_err(std::io::Error::other)?;
    let content_digest = candidate
        .canonical_content_digest()
        .map_err(std::io::Error::other)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let references = vec![
        reference(
            "source_tree",
            &candidate.source_tree_digest,
            &candidate.source_tree_digest,
            now_ms,
        ),
        reference(
            "manifest",
            &candidate.manifest_digest,
            &candidate.manifest_digest,
            now_ms,
        ),
        reference(
            "artifact",
            &candidate.artifact_reference,
            &candidate.artifact_digest,
            now_ms,
        ),
        reference(
            "build_definition",
            &candidate.build_definition_digest,
            &candidate.build_definition_digest,
            now_ms,
        ),
    ];
    let mut client = ChiseiServiceClient::new(connect_sekai(&target).await?);
    let response = client
        .evaluate_governed_subject(EvaluateGovernedSubjectRequest {
            subject: Some(GovernedSubjectEnvelope {
                version: ENVELOPE_VERSION.into(),
                namespace,
                request_id,
                subject_profile: SOFTWARE_RELEASE_PROFILE.into(),
                subject_identity,
                content_digest,
                references,
                evaluation_profile,
            }),
        })
        .await?
        .into_inner()
        .result
        .ok_or_else(|| std::io::Error::other("governed-subject result missing"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "version": response.version,
            "decision": response.decision,
            "operation_id": response.operation_id,
            "receipt_schema": response.receipt_schema,
            "receipt_digest": response.receipt_digest,
            "references": response.references.into_iter().map(|reference| serde_json::json!({
                "kind": reference.kind,
                "reference": reference.reference,
                "content_digest": reference.content_digest,
                "observed_at_ms": reference.observed_at_ms,
            })).collect::<Vec<_>>(),
            "fresh": response.fresh,
            "failure_code": response.failure_code,
            "failure_message": response.failure_message,
        }))?
    );
    Ok(())
}

async fn run_provenance(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("export") => run_provenance_export(args).await,
        Some("trust-root") => run_provenance_trust_root(args).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn run_provenance_export(args: Vec<String>) -> Result<(), BoxErr> {
    let path = args
        .get(1)
        .filter(|value| !value.starts_with('-'))
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other(usage()))?;
    let operation_id =
        flag(&args, "--operation-id").ok_or_else(|| std::io::Error::other(usage()))?;
    let receipt_digest =
        flag(&args, "--receipt-digest").ok_or_else(|| std::io::Error::other(usage()))?;
    let export_id = flag(&args, "--export-id").ok_or_else(|| std::io::Error::other(usage()))?;
    let output = flag(&args, "--output").map(PathBuf::from);
    let target = target(&args);
    let candidate: SoftwareReleaseCandidate = serde_json::from_slice(&std::fs::read(path)?)?;
    let subject_identity = candidate
        .canonical_identity()
        .map_err(std::io::Error::other)?;
    let subject_content_digest = candidate
        .canonical_content_digest()
        .map_err(std::io::Error::other)?;
    let mut client = ChiseiServiceClient::new(connect_sekai(&target).await?);
    let response = client
        .export_governed_subject_provenance(ExportGovernedSubjectProvenanceRequest {
            export_id,
            operation_id,
            expected_subject_identity: subject_identity,
            expected_subject_content_digest: subject_content_digest,
            expected_manifest_digest: candidate.manifest_digest,
            expected_artifact_digest: candidate.artifact_digest,
            expected_receipt_digest: receipt_digest,
        })
        .await?
        .into_inner();
    let envelope = response
        .envelope
        .ok_or_else(|| std::io::Error::other("provenance export omitted its envelope"))?;
    let bytes = serde_json::to_vec_pretty(&provenance_envelope_json(envelope))?;
    write_or_print(output, &bytes)?;
    Ok(())
}

async fn run_provenance_trust_root(args: Vec<String>) -> Result<(), BoxErr> {
    let export_id = flag(&args, "--export-id").ok_or_else(|| std::io::Error::other(usage()))?;
    let output = flag(&args, "--output").map(PathBuf::from);
    let target = target(&args);
    let mut client = ChiseiServiceClient::new(connect_sekai(&target).await?);
    let root = client
        .get_governed_subject_provenance_trust_root(GetGovernedSubjectProvenanceTrustRootRequest {
            export_id,
        })
        .await?
        .into_inner()
        .trust_root
        .ok_or_else(|| std::io::Error::other("provenance trust-root response omitted its root"))?;
    let bytes =
        trust_root_toml(root.version, &root.key_id, &root.identity, &root.public_key).into_bytes();
    write_or_print(output, &bytes)?;
    Ok(())
}

fn provenance_envelope_json(envelope: GovernedSubjectProvenanceEnvelope) -> serde_json::Value {
    serde_json::json!({
        "profile": envelope.profile,
        "issuer": envelope.issuer,
        "issuer_key_id": envelope.issuer_key_id,
        "subject": envelope.subject,
        "content_digest": envelope.content_digest,
        "decision": envelope.decision,
        "receipt_schema": envelope.receipt_schema,
        "receipt_digest": envelope.receipt_digest,
        "governed_references": envelope.governed_references.into_iter().map(|reference| serde_json::json!({
            "kind": reference.kind,
            "id": reference.id,
            "digest": reference.digest,
        })).collect::<Vec<_>>(),
        "observed_at_unix_ms": envelope.observed_at_unix_ms,
        "expires_at_unix_ms": envelope.expires_at_unix_ms,
        "signature": envelope.signature,
    })
}

fn trust_root_toml(version: u32, key_id: &str, identity: &str, public_key: &str) -> String {
    format!(
        "version = {version}\n\n[[signers]]\nkey_id = {key_id:?}\nidentity = {identity:?}\npublic_key = {public_key:?}\n"
    )
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn target(args: &[String]) -> String {
    flag(args, "--target")
        .or_else(|| std::env::var("CHISEI_GRPC_URL").ok())
        .or_else(|| std::env::var("SEKAI_SOCKET").ok())
        .unwrap_or_else(|| "./data/sekai.sock".into())
}

fn write_or_print(output: Option<PathBuf>, bytes: &[u8]) -> Result<(), BoxErr> {
    if let Some(path) = output {
        std::fs::write(path, bytes)?;
    } else {
        println!("{}", String::from_utf8_lossy(bytes));
    }
    Ok(())
}

fn reference(
    kind: &str,
    reference: &str,
    content_digest: &str,
    observed_at_ms: i64,
) -> GovernedSubjectReference {
    GovernedSubjectReference {
        kind: kind.into(),
        reference: reference.into(),
        content_digest: content_digest.into(),
        observed_at_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::pb::chisei::GovernedSubjectProvenanceReference;

    #[test]
    fn tenkai_envelope_output_has_only_the_compiled_contract_fields() {
        let value = provenance_envelope_json(GovernedSubjectProvenanceEnvelope {
            profile: "example.governed-subject-receipt/v1".into(),
            issuer: "sekai-chisei".into(),
            issuer_key_id: format!("sha256:{}", "1".repeat(64)),
            subject: "subject-1".into(),
            content_digest: format!("sha256:{}", "2".repeat(64)),
            decision: "allow".into(),
            receipt_schema: "chisei.governed-subject-receipt/v1".into(),
            receipt_digest: format!("sha256:{}", "3".repeat(64)),
            governed_references: vec![GovernedSubjectProvenanceReference {
                kind: "operation".into(),
                id: "operation-1".into(),
                digest: format!("sha256:{}", "3".repeat(64)),
            }],
            observed_at_unix_ms: 1,
            expires_at_unix_ms: 2,
            signature: "signature".into(),
        });
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "content_digest",
                "decision",
                "expires_at_unix_ms",
                "governed_references",
                "issuer",
                "issuer_key_id",
                "observed_at_unix_ms",
                "profile",
                "receipt_digest",
                "receipt_schema",
                "signature",
                "subject",
            ]
        );
        let serialized = serde_json::to_string(&value).unwrap();
        for forbidden in [
            "private_key",
            "source_tree",
            "repository_path",
            "prompt",
            "credential",
            "arbitrary_metadata",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn trust_root_output_is_tenkai_toml_and_public_only() {
        let output = trust_root_toml(1, "sha256:key", "sekai-chisei", "public");
        assert_eq!(
            output,
            "version = 1\n\n[[signers]]\nkey_id = \"sha256:key\"\nidentity = \"sekai-chisei\"\npublic_key = \"public\"\n"
        );
        assert!(!output.contains("private"));
    }
}

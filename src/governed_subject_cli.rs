//! Fixed local adapters for registered governed-subject profiles.

use crate::chisei::governed_subject::{
    ALLOW_PROFILE, ENVELOPE_VERSION, SOFTWARE_RELEASE_PROFILE, SoftwareReleaseCandidate,
};
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{
    EvaluateGovernedSubjectRequest, GovernedSubjectEnvelope, GovernedSubjectReference,
};
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin governance subject software-release <candidate.json> --namespace <name> --request-id <id> [--evaluation-profile <profile>] [--target <url-or-socket>]"
}

pub async fn run(args: Vec<String>) -> Result<(), BoxErr> {
    if args.first().map(String::as_str) != Some("software-release") {
        return Err(std::io::Error::other(usage()).into());
    }
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

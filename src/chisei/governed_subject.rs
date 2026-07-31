//! Bounded, domain-neutral governed-subject evaluation contracts.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use super::evaluation_execution::{DEFAULT_TOTAL_DURATION_MS, MAX_TOTAL_DURATION_MS};

pub const ENVELOPE_VERSION: &str = "chisei.governed-subject/v1";
pub const RESULT_VERSION: &str = "chisei.governed-subject-result/v1";
pub const RECEIPT_SCHEMA_VERSION: &str = "chisei.governed-subject-receipt/v1";
pub const PLAN_BACKED_REQUEST_VERSION: &str = "chisei.plan-backed-governed-subject-evaluation/v1";
pub const PLAN_BACKED_RESULT_VERSION: &str = "chisei.plan-backed-governed-subject-decision/v1";
pub const PLAN_BACKED_RECEIPT_SCHEMA_VERSION: &str =
    "chisei.plan-backed-governed-subject-receipt/v1";
pub const PLAN_BACKED_OPERATION_CLASS: &str = "plan_backed_governed_subject_evaluation";
pub const MAX_REFERENCES: usize = 16;
pub const MAX_FIELD_BYTES: usize = 256;
pub const MAX_REFERENCE_BYTES: usize = 512;
pub const MAX_PLAN_EVIDENCE: usize = 1_024;
pub const MAX_EVIDENCE_AGE_MS: i64 = 24 * 60 * 60 * 1000;

pub const SOFTWARE_RELEASE_PROFILE: &str = "example.software-release-candidate/v1";
pub const SOFTWARE_RELEASE_PLAN_PROFILE: &str = "example.software-release-candidate/v2";
pub const POLICY_BUNDLE_PROFILE: &str = "example.policy-bundle/v1";

pub const ALLOW_PROFILE: &str = "chisei.subject-evaluation/allow/v1";
pub const DENY_PROFILE: &str = "chisei.subject-evaluation/deny/v1";
pub const UNAVAILABLE_PROFILE: &str = "chisei.subject-evaluation/unavailable/v1";
pub const TIMEOUT_PROFILE: &str = "chisei.subject-evaluation/timeout/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedSubjectReference {
    pub kind: String,
    pub reference: String,
    pub content_digest: String,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedSubjectEnvelope {
    pub version: String,
    pub namespace: String,
    pub request_id: String,
    pub subject_profile: String,
    pub subject_identity: String,
    pub content_digest: String,
    pub references: Vec<GovernedSubjectReference>,
    pub evaluation_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedSubjectResult {
    pub version: String,
    pub decision: String,
    pub operation_id: String,
    pub receipt_schema: String,
    pub receipt_digest: String,
    pub references: Vec<GovernedSubjectReference>,
    pub fresh: bool,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
}

/// A deliberately situation-specific entry contract for software release
/// candidates. Other subject families add their own profile adapter rather
/// than inheriting implicit evaluator or evidence semantics from this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanBackedSubjectEvaluationRequest {
    pub contract_version: String,
    pub namespace: String,
    pub request_id: String,
    pub subject_profile: String,
    pub subject_identity: String,
    pub subject_content_digest: String,
    pub plan_version_id: String,
    pub evidence_object_ids: Vec<String>,
    pub evaluation_time_ms: i64,
    pub max_total_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPlanBackedSubjectEvaluation {
    pub request: PlanBackedSubjectEvaluationRequest,
    pub actor: String,
    pub binding_digest: String,
    pub operation_id: String,
    pub resolution_request_id: String,
}

pub fn prepare_plan_backed_evaluation(
    mut request: PlanBackedSubjectEvaluationRequest,
    actor: &str,
) -> Result<PreparedPlanBackedSubjectEvaluation, String> {
    if request.contract_version != PLAN_BACKED_REQUEST_VERSION {
        return Err("unsupported plan-backed governed-subject contract".into());
    }
    for (name, value) in [
        ("namespace", request.namespace.as_str()),
        ("request_id", request.request_id.as_str()),
        ("subject_profile", request.subject_profile.as_str()),
        ("subject_identity", request.subject_identity.as_str()),
        ("plan_version_id", request.plan_version_id.as_str()),
        ("actor", actor),
    ] {
        validate_bounded(name, value, MAX_REFERENCE_BYTES)?;
    }
    if request.subject_profile != SOFTWARE_RELEASE_PLAN_PROFILE {
        return Err("unsupported plan-backed governed-subject profile".into());
    }
    if request.subject_identity.contains("://")
        || request.subject_identity.starts_with('/')
        || request.subject_identity.contains("../")
    {
        return Err("subject_identity must be opaque, not a URL or path".into());
    }
    validate_digest("subject_content_digest", &request.subject_content_digest)?;
    if request.evaluation_time_ms <= 0 {
        return Err("evaluation_time_ms must be positive".into());
    }
    if request.max_total_duration_ms == 0 {
        request.max_total_duration_ms = DEFAULT_TOTAL_DURATION_MS;
    }
    if request.max_total_duration_ms > MAX_TOTAL_DURATION_MS {
        return Err(format!(
            "max_total_duration_ms exceeds {MAX_TOTAL_DURATION_MS}"
        ));
    }
    if request.evidence_object_ids.len() > MAX_PLAN_EVIDENCE {
        return Err(format!(
            "evidence_object_ids exceeds the limit of {MAX_PLAN_EVIDENCE}"
        ));
    }
    for evidence_id in &request.evidence_object_ids {
        validate_bounded("evidence_object_id", evidence_id, MAX_REFERENCE_BYTES)?;
    }
    request.evidence_object_ids.sort();
    if request
        .evidence_object_ids
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err("evidence_object_ids contains duplicates".into());
    }
    let binding_bytes = serde_json::to_vec(&(
        actor,
        request.contract_version.as_str(),
        request.namespace.as_str(),
        request.request_id.as_str(),
        request.subject_profile.as_str(),
        request.subject_identity.as_str(),
        request.subject_content_digest.as_str(),
        request.plan_version_id.as_str(),
        request.evidence_object_ids.as_slice(),
        request.evaluation_time_ms,
        request.max_total_duration_ms,
    ))
    .map_err(|error| error.to_string())?;
    let binding_digest = format!("sha256:{:x}", Sha256::digest(binding_bytes));
    let operation_digest = Sha256::digest(format!(
        "{}\0{}\0{}",
        request.namespace, actor, request.request_id
    ));
    let operation_id = format!("governed-subject-plan-{operation_digest:x}");
    let resolution_request_id = format!("{operation_id}:resolution");
    Ok(PreparedPlanBackedSubjectEvaluation {
        request,
        actor: actor.into(),
        binding_digest,
        operation_id,
        resolution_request_id,
    })
}

pub fn plan_backed_caller_scope(namespace: &str, actor: &str) -> String {
    format!(
        "governed-subject-plan:{}:{namespace}:{actor}",
        namespace.len()
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareReleaseCandidate {
    pub revision: String,
    pub source_tree_digest: String,
    pub manifest_digest: String,
    pub artifact_reference: String,
    pub artifact_digest: String,
    pub build_definition_digest: String,
}

impl SoftwareReleaseCandidate {
    pub fn canonical_identity(&self) -> Result<String, String> {
        for (name, value) in [
            ("revision", self.revision.as_str()),
            ("source_tree_digest", self.source_tree_digest.as_str()),
            ("manifest_digest", self.manifest_digest.as_str()),
            ("artifact_reference", self.artifact_reference.as_str()),
            ("artifact_digest", self.artifact_digest.as_str()),
            (
                "build_definition_digest",
                self.build_definition_digest.as_str(),
            ),
        ] {
            validate_bounded(name, value, MAX_REFERENCE_BYTES)?;
        }
        for (name, value) in [
            ("source_tree_digest", self.source_tree_digest.as_str()),
            ("manifest_digest", self.manifest_digest.as_str()),
            ("artifact_digest", self.artifact_digest.as_str()),
            (
                "build_definition_digest",
                self.build_definition_digest.as_str(),
            ),
        ] {
            validate_digest(name, value)?;
        }
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    pub fn canonical_content_digest(&self) -> Result<String, String> {
        self.canonical_identity()
    }
}

pub fn validate_envelope(
    envelope: &GovernedSubjectEnvelope,
    actor: &str,
    now_ms: i64,
) -> Result<bool, String> {
    if envelope.version != ENVELOPE_VERSION {
        return Err("unknown governed-subject envelope version".into());
    }
    for (name, value) in [
        ("namespace", envelope.namespace.as_str()),
        ("request_id", envelope.request_id.as_str()),
        ("subject_profile", envelope.subject_profile.as_str()),
        ("subject_identity", envelope.subject_identity.as_str()),
        ("evaluation_profile", envelope.evaluation_profile.as_str()),
        ("actor", actor),
    ] {
        validate_bounded(name, value, MAX_FIELD_BYTES)?;
    }
    validate_digest("content_digest", &envelope.content_digest)?;
    if envelope.subject_identity.contains("://")
        || envelope.subject_identity.starts_with('/')
        || envelope.subject_identity.contains("../")
    {
        return Err("subject_identity must be opaque, not a URL or path".into());
    }
    if envelope.references.is_empty() || envelope.references.len() > MAX_REFERENCES {
        return Err(format!(
            "governed references must contain 1..={MAX_REFERENCES} entries"
        ));
    }
    let allowed_kinds: &[&str] = match envelope.subject_profile.as_str() {
        SOFTWARE_RELEASE_PROFILE => &["source_tree", "manifest", "artifact", "build_definition"],
        POLICY_BUNDLE_PROFILE => &["policy_document", "policy_schema"],
        _ => return Err("unknown governed-subject profile".into()),
    };
    let required_kinds = allowed_kinds.iter().copied().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut fresh = true;
    for reference in &envelope.references {
        validate_bounded("reference kind", &reference.kind, MAX_FIELD_BYTES)?;
        validate_bounded(
            "governed reference",
            &reference.reference,
            MAX_REFERENCE_BYTES,
        )?;
        validate_digest("reference content_digest", &reference.content_digest)?;
        if !allowed_kinds.contains(&reference.kind.as_str()) {
            return Err("subject profile does not allow this reference kind".into());
        }
        if !seen.insert(reference.kind.as_str()) {
            return Err("duplicate governed reference kind".into());
        }
        if reference.reference.contains("://")
            || reference.reference.starts_with('/')
            || reference.reference.contains("../")
        {
            return Err("governed references must be opaque, not URLs or paths".into());
        }
        if reference.observed_at_ms <= 0 || reference.observed_at_ms > now_ms {
            return Err("reference observed_at_ms must be positive and not in the future".into());
        }
        if now_ms - reference.observed_at_ms > MAX_EVIDENCE_AGE_MS {
            fresh = false;
        }
    }
    if seen != required_kinds {
        return Err("subject profile references are incomplete".into());
    }
    match envelope.evaluation_profile.as_str() {
        ALLOW_PROFILE | DENY_PROFILE | UNAVAILABLE_PROFILE | TIMEOUT_PROFILE => {}
        _ => return Err("unknown or incompatible evaluation profile".into()),
    }
    Ok(fresh)
}

pub fn binding_digest(envelope: &GovernedSubjectEnvelope, actor: &str) -> String {
    let mut references = envelope
        .references
        .iter()
        .map(|reference| {
            (
                reference.kind.as_str(),
                reference.reference.as_str(),
                reference.content_digest.as_str(),
            )
        })
        .collect::<Vec<_>>();
    references.sort_unstable();
    // Observation time is validated and the first accepted value is retained
    // on the receipt, but it is not subject identity: a transport retry may
    // reconstruct the same evidence envelope at a later wall-clock instant.
    let bytes = serde_json::to_vec(&(
        actor,
        envelope.version.as_str(),
        envelope.namespace.as_str(),
        envelope.request_id.as_str(),
        envelope.subject_profile.as_str(),
        envelope.subject_identity.as_str(),
        envelope.content_digest.as_str(),
        references,
        envelope.evaluation_profile.as_str(),
    ))
    .unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn operation_id(namespace: &str, actor: &str, request_id: &str) -> String {
    let digest = Sha256::digest(format!("{namespace}\0{actor}\0{request_id}"));
    format!("governed-subject-{:x}", digest)
}

pub fn caller_scope(namespace: &str, actor: &str) -> String {
    format!("governed-subject:{}:{namespace}:{actor}", namespace.len())
}

pub fn evaluation(profile: &str, fresh: bool) -> (&'static str, Option<&'static str>) {
    if !fresh {
        return ("unknown", Some("stale_evidence"));
    }
    match profile {
        ALLOW_PROFILE => ("allow", None),
        DENY_PROFILE => ("deny", None),
        UNAVAILABLE_PROFILE => ("unavailable", Some("evaluation_unavailable")),
        TIMEOUT_PROFILE => ("unknown", Some("evaluation_timeout")),
        _ => ("unknown", Some("invalid_evaluation_profile")),
    }
}

fn validate_bounded(name: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.trim() != value || value.len() > max {
        return Err(format!(
            "{name} must be non-empty, canonical, and at most {max} bytes"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{name} contains control characters"));
    }
    Ok(())
}

fn validate_digest(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn candidate_identity_binds_every_field() {
        let candidate = SoftwareReleaseCandidate {
            revision: "v1.2.3".into(),
            source_tree_digest: digest('a'),
            manifest_digest: digest('b'),
            artifact_reference: "artifact-42".into(),
            artifact_digest: digest('d'),
            build_definition_digest: digest('c'),
        };
        let golden = candidate.canonical_identity().unwrap();
        assert_eq!(
            golden,
            "sha256:f3f07c340b36e4d4129e5a720be11deec2c7226c6338e035b8c53f595429372d"
        );
        for changed in [
            SoftwareReleaseCandidate {
                revision: "v1.2.4".into(),
                ..candidate.clone()
            },
            SoftwareReleaseCandidate {
                source_tree_digest: digest('d'),
                ..candidate.clone()
            },
            SoftwareReleaseCandidate {
                manifest_digest: digest('d'),
                ..candidate.clone()
            },
            SoftwareReleaseCandidate {
                artifact_reference: "artifact-43".into(),
                ..candidate.clone()
            },
            SoftwareReleaseCandidate {
                artifact_digest: digest('e'),
                ..candidate.clone()
            },
            SoftwareReleaseCandidate {
                build_definition_digest: digest('d'),
                ..candidate.clone()
            },
        ] {
            assert_ne!(changed.canonical_identity().unwrap(), golden);
        }
    }

    #[test]
    fn plan_backed_request_is_profile_specific_canonical_and_actor_bound() {
        let request = PlanBackedSubjectEvaluationRequest {
            contract_version: PLAN_BACKED_REQUEST_VERSION.into(),
            namespace: "release".into(),
            request_id: "candidate-42".into(),
            subject_profile: SOFTWARE_RELEASE_PLAN_PROFILE.into(),
            subject_identity: "release-candidate:42".into(),
            subject_content_digest: digest('a'),
            plan_version_id: "evaluation-plan:release:1".into(),
            evidence_object_ids: vec!["evidence:z".into(), "evidence:a".into()],
            evaluation_time_ms: 42,
            max_total_duration_ms: 1_000,
        };
        let prepared = prepare_plan_backed_evaluation(request.clone(), "release-bot").unwrap();
        assert_eq!(
            prepared.request.evidence_object_ids,
            vec!["evidence:a", "evidence:z"]
        );
        assert!(prepared.operation_id.starts_with("governed-subject-plan-"));
        assert_eq!(
            prepare_plan_backed_evaluation(request.clone(), "release-bot")
                .unwrap()
                .binding_digest,
            prepared.binding_digest
        );
        assert_ne!(
            prepare_plan_backed_evaluation(request.clone(), "other-bot")
                .unwrap()
                .binding_digest,
            prepared.binding_digest
        );
        let mut defaulted_budget = request.clone();
        defaulted_budget.max_total_duration_ms = 0;
        let mut explicit_budget = request.clone();
        explicit_budget.max_total_duration_ms = DEFAULT_TOTAL_DURATION_MS;
        let defaulted = prepare_plan_backed_evaluation(defaulted_budget, "release-bot").unwrap();
        let explicit = prepare_plan_backed_evaluation(explicit_budget, "release-bot").unwrap();
        assert_eq!(
            defaulted.request.max_total_duration_ms,
            DEFAULT_TOTAL_DURATION_MS
        );
        assert_eq!(defaulted.binding_digest, explicit.binding_digest);

        let mut old_profile = request.clone();
        old_profile.subject_profile = SOFTWARE_RELEASE_PROFILE.into();
        assert!(prepare_plan_backed_evaluation(old_profile, "release-bot").is_err());
        let mut duplicate = request;
        duplicate.evidence_object_ids = vec!["evidence:a".into(), "evidence:a".into()];
        assert!(prepare_plan_backed_evaluation(duplicate, "release-bot").is_err());
    }

    #[test]
    fn validator_fails_closed_for_unknown_duplicate_and_oversized_inputs() {
        let now = 10_000;
        let mut envelope = GovernedSubjectEnvelope {
            version: ENVELOPE_VERSION.into(),
            namespace: "default".into(),
            request_id: "request-1".into(),
            subject_profile: POLICY_BUNDLE_PROFILE.into(),
            subject_identity: "policy-bundle-1".into(),
            content_digest: digest('a'),
            references: vec![
                GovernedSubjectReference {
                    kind: "policy_document".into(),
                    reference: "document-1".into(),
                    content_digest: digest('b'),
                    observed_at_ms: now,
                },
                GovernedSubjectReference {
                    kind: "policy_schema".into(),
                    reference: "schema-1".into(),
                    content_digest: digest('c'),
                    observed_at_ms: now,
                },
            ],
            evaluation_profile: ALLOW_PROFILE.into(),
        };
        assert_eq!(validate_envelope(&envelope, "root", now), Ok(true));

        envelope.subject_profile = "unknown/v1".into();
        assert!(validate_envelope(&envelope, "root", now).is_err());
        envelope.subject_profile = POLICY_BUNDLE_PROFILE.into();
        envelope.references[1].kind = "policy_document".into();
        assert!(validate_envelope(&envelope, "root", now).is_err());
        envelope.references[1].kind = "policy_schema".into();
        envelope.references[1].reference = "x".repeat(MAX_REFERENCE_BYTES + 1);
        assert!(validate_envelope(&envelope, "root", now).is_err());
        envelope.references[1].reference = "schema-1".into();
        envelope.references[1].observed_at_ms = now + 1;
        assert!(validate_envelope(&envelope, "root", now).is_err());
    }

    #[test]
    fn software_release_candidate_rejects_unknown_fields() {
        let json = format!(
            r#"{{
                "revision":"v1.2.3",
                "source_tree_digest":"{}",
                "manifest_digest":"{}",
                "artifact_reference":"artifact-42",
                "artifact_digest":"{}",
                "build_definition_digest":"{}",
                "repository_path":"/secret"
            }}"#,
            digest('a'),
            digest('b'),
            digest('d'),
            digest('c')
        );
        assert!(serde_json::from_str::<SoftwareReleaseCandidate>(&json).is_err());
    }

    #[test]
    fn candidate_content_digest_ignores_json_formatting_and_key_order() {
        let compact = format!(
            r#"{{"revision":"v1","source_tree_digest":"{}","manifest_digest":"{}","artifact_reference":"artifact","artifact_digest":"{}","build_definition_digest":"{}"}}"#,
            digest('a'),
            digest('b'),
            digest('c'),
            digest('d')
        );
        let reordered = format!(
            r#"{{
              "artifact_digest":"{}",
              "artifact_reference":"artifact",
              "build_definition_digest":"{}",
              "manifest_digest":"{}",
              "revision":"v1",
              "source_tree_digest":"{}"
            }}"#,
            digest('c'),
            digest('d'),
            digest('b'),
            digest('a')
        );
        let first: SoftwareReleaseCandidate = serde_json::from_str(&compact).unwrap();
        let second: SoftwareReleaseCandidate = serde_json::from_str(&reordered).unwrap();
        assert_eq!(
            first.canonical_content_digest().unwrap(),
            second.canonical_content_digest().unwrap()
        );
    }

    #[test]
    fn caller_scope_is_unambiguous_across_colon_boundaries() {
        assert_ne!(caller_scope("a:b", "c"), caller_scope("a", "b:c"));
    }
}

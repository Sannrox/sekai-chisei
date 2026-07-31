//! Canonical, content-bound evaluation manifests.
//!
//! Resolution freezes exact immutable inputs for later deterministic
//! execution. This module owns only closed documents and canonicalization;
//! authorization and live Sekai lookups remain at the service boundary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const RESOLUTION_REQUEST_CONTRACT: &str = "chisei.evaluation-resolution-request/v1";
pub const MANIFEST_CONTRACT: &str = "chisei.resolved-evaluation-manifest/v1";
pub const RESOLVER_VERSION: &str = "chisei.evaluation-resolver/v1";
pub const RESOLUTION_RESOLVED: &str = "resolved";
pub const RESOLUTION_UNKNOWN: &str = "unknown";
pub const RESOLUTION_UNAVAILABLE: &str = "unavailable";
pub const FINDING_BLOCKING: &str = "blocking";
pub const FINDING_ADVISORY: &str = "advisory";
pub const MAX_REQUEST_EVIDENCE: usize = 1_024;
pub const MAX_MANIFEST_EVIDENCE: usize = 1_024;
pub const MAX_FINDINGS: usize = 256;
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_STRING_BYTES: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationResolutionRequest {
    pub contract_version: String,
    pub resolver_version: String,
    pub namespace: String,
    pub request_id: String,
    pub plan_version_id: String,
    pub subject_profile: String,
    pub subject_identity: String,
    pub subject_content_digest: String,
    pub evidence_object_ids: Vec<String>,
    pub evaluation_time_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedResolutionRequest {
    pub request: EvaluationResolutionRequest,
    pub actor: String,
    pub request_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEvaluatorBinding {
    pub definition_id: String,
    pub definition_digest: String,
    pub implementation_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEvidenceBinding {
    pub evidence_object_id: String,
    pub submission_id: String,
    pub content_digest: String,
    pub evidence_type: String,
    pub schema_id: String,
    pub schema_version: String,
    pub classification: String,
    pub observed_at_ms: i64,
    pub expires_at_ms: i64,
    pub source_identity_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedWaiverBinding {
    pub waiver_version_id: String,
    pub content_digest: String,
    pub evidence_object_ids: Vec<String>,
    pub invariant_version_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedRequirementBinding {
    pub requirement_version_id: String,
    pub content_digest: String,
    pub provenance_evidence_object_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedInvariantBinding {
    pub invariant_version_id: String,
    pub content_digest: String,
    pub predicate_kind: String,
    pub input_schema: String,
    pub result_schema: String,
    pub evidence_types: Vec<String>,
    pub provenance_evidence_object_ids: Vec<String>,
    pub waiver_version_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedInputBinding {
    pub name: String,
    pub source_kind: String,
    pub schema_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEvaluationNode {
    pub node_id: String,
    pub evaluator: ResolvedEvaluatorBinding,
    pub depends_on_node_ids: Vec<String>,
    pub input_bindings: Vec<ResolvedInputBinding>,
    pub parameters_json: String,
    pub invariants: Vec<ResolvedInvariantBinding>,
    pub evidence_object_ids: Vec<String>,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEvaluationManifest {
    pub contract_version: String,
    pub resolver_version: String,
    pub manifest_id: String,
    pub manifest_digest: String,
    pub namespace: String,
    pub plan_version_id: String,
    pub plan_digest: String,
    pub subject_profile: String,
    pub subject_identity: String,
    pub subject_content_digest: String,
    pub invariant_set_id: String,
    pub invariant_set_digest: String,
    pub invariant_profile_digest: String,
    pub evaluation_time_ms: i64,
    pub resolved_by: String,
    pub requirements: Vec<ResolvedRequirementBinding>,
    pub nodes: Vec<ResolvedEvaluationNode>,
    pub evidence: Vec<ResolvedEvidenceBinding>,
    pub waivers: Vec<ResolvedWaiverBinding>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationResolutionFinding {
    pub code: String,
    pub severity: String,
    pub node_id: String,
    pub invariant_version_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationResolutionOutcome {
    pub status: String,
    pub manifest: Option<ResolvedEvaluationManifest>,
    pub findings: Vec<EvaluationResolutionFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationManifestReplay {
    pub request_digest: String,
    pub manifest: ResolvedEvaluationManifest,
}

#[derive(Serialize)]
struct CanonicalManifest<'a> {
    contract_version: &'a str,
    resolver_version: &'a str,
    namespace: &'a str,
    plan_version_id: &'a str,
    plan_digest: &'a str,
    subject_profile: &'a str,
    subject_identity: &'a str,
    subject_content_digest: &'a str,
    invariant_set_id: &'a str,
    invariant_set_digest: &'a str,
    invariant_profile_digest: &'a str,
    evaluation_time_ms: i64,
    resolved_by: &'a str,
    requirements: &'a [ResolvedRequirementBinding],
    nodes: &'a [ResolvedEvaluationNode],
    evidence: &'a [ResolvedEvidenceBinding],
    waivers: &'a [ResolvedWaiverBinding],
}

pub fn prepare_resolution_request(
    mut request: EvaluationResolutionRequest,
    actor: &str,
) -> Result<PreparedResolutionRequest, String> {
    if request.contract_version != RESOLUTION_REQUEST_CONTRACT {
        return Err("unsupported evaluation resolution request contract".into());
    }
    if request.resolver_version != RESOLVER_VERSION {
        return Err("unsupported evaluation resolver version".into());
    }
    for (field, value) in [
        ("namespace", request.namespace.as_str()),
        ("request_id", request.request_id.as_str()),
        ("plan_version_id", request.plan_version_id.as_str()),
        ("subject_profile", request.subject_profile.as_str()),
        ("subject_identity", request.subject_identity.as_str()),
    ] {
        validate_reference(field, value)?;
    }
    validate_digest("subject_content_digest", &request.subject_content_digest)?;
    if actor.trim().is_empty() {
        return Err("authenticated actor required".into());
    }
    if request.evaluation_time_ms <= 0 {
        return Err("evaluation_time_ms must be positive".into());
    }
    if request.evidence_object_ids.len() > MAX_REQUEST_EVIDENCE {
        return Err(format!(
            "evidence_object_ids exceeds the limit of {MAX_REQUEST_EVIDENCE}"
        ));
    }
    for evidence_id in &request.evidence_object_ids {
        validate_reference("evidence_object_id", evidence_id)?;
    }
    request.evidence_object_ids.sort();
    if request
        .evidence_object_ids
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err("evidence_object_ids contains duplicates".into());
    }
    let request_digest = digest_json(&(
        request.contract_version.as_str(),
        request.resolver_version.as_str(),
        request.namespace.as_str(),
        request.plan_version_id.as_str(),
        request.subject_profile.as_str(),
        request.subject_identity.as_str(),
        request.subject_content_digest.as_str(),
        request.evidence_object_ids.as_slice(),
        request.evaluation_time_ms,
        actor,
    ))?;
    Ok(PreparedResolutionRequest {
        request,
        actor: actor.into(),
        request_digest,
    })
}

pub fn prepare_manifest(
    mut manifest: ResolvedEvaluationManifest,
) -> Result<ResolvedEvaluationManifest, String> {
    if manifest.contract_version != MANIFEST_CONTRACT
        || manifest.resolver_version != RESOLVER_VERSION
    {
        return Err("unsupported resolved evaluation manifest contract".into());
    }
    for (field, value) in [
        ("namespace", manifest.namespace.as_str()),
        ("plan_version_id", manifest.plan_version_id.as_str()),
        ("subject_profile", manifest.subject_profile.as_str()),
        ("subject_identity", manifest.subject_identity.as_str()),
        ("invariant_set_id", manifest.invariant_set_id.as_str()),
        ("resolved_by", manifest.resolved_by.as_str()),
    ] {
        validate_reference(field, value)?;
    }
    for (field, value) in [
        ("plan_digest", manifest.plan_digest.as_str()),
        (
            "subject_content_digest",
            manifest.subject_content_digest.as_str(),
        ),
        (
            "invariant_set_digest",
            manifest.invariant_set_digest.as_str(),
        ),
        (
            "invariant_profile_digest",
            manifest.invariant_profile_digest.as_str(),
        ),
    ] {
        validate_digest(field, value)?;
    }
    if manifest.evaluation_time_ms <= 0 || manifest.created_at_ms <= 0 || manifest.nodes.is_empty()
    {
        return Err("manifest requires nodes and positive evaluation/creation times".into());
    }
    if manifest.evidence.len() > MAX_MANIFEST_EVIDENCE {
        return Err(format!(
            "manifest evidence exceeds the limit of {MAX_MANIFEST_EVIDENCE}"
        ));
    }
    normalize_manifest(&mut manifest)?;
    manifest.manifest_digest = digest_json(&CanonicalManifest {
        contract_version: &manifest.contract_version,
        resolver_version: &manifest.resolver_version,
        namespace: &manifest.namespace,
        plan_version_id: &manifest.plan_version_id,
        plan_digest: &manifest.plan_digest,
        subject_profile: &manifest.subject_profile,
        subject_identity: &manifest.subject_identity,
        subject_content_digest: &manifest.subject_content_digest,
        invariant_set_id: &manifest.invariant_set_id,
        invariant_set_digest: &manifest.invariant_set_digest,
        invariant_profile_digest: &manifest.invariant_profile_digest,
        evaluation_time_ms: manifest.evaluation_time_ms,
        resolved_by: &manifest.resolved_by,
        requirements: &manifest.requirements,
        nodes: &manifest.nodes,
        evidence: &manifest.evidence,
        waivers: &manifest.waivers,
    })?;
    manifest.manifest_id = format!(
        "evaluation-manifest:{}",
        manifest
            .manifest_digest
            .strip_prefix("sha256:")
            .unwrap_or(&manifest.manifest_digest)
    );
    let bytes = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "resolved evaluation manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        ));
    }
    Ok(manifest)
}

pub fn resolved_outcome(manifest: ResolvedEvaluationManifest) -> EvaluationResolutionOutcome {
    EvaluationResolutionOutcome {
        status: RESOLUTION_RESOLVED.into(),
        manifest: Some(manifest),
        findings: Vec::new(),
    }
}

pub fn blocked_outcome(status: &str, code: &str) -> EvaluationResolutionOutcome {
    EvaluationResolutionOutcome {
        status: status.into(),
        manifest: None,
        findings: vec![EvaluationResolutionFinding {
            code: code.into(),
            severity: FINDING_BLOCKING.into(),
            node_id: String::new(),
            invariant_version_id: String::new(),
        }],
    }
}

fn normalize_manifest(manifest: &mut ResolvedEvaluationManifest) -> Result<(), String> {
    manifest.requirements.sort_by(|left, right| {
        left.requirement_version_id
            .cmp(&right.requirement_version_id)
    });
    reject_duplicate(
        manifest
            .requirements
            .iter()
            .map(|requirement| requirement.requirement_version_id.as_str()),
        "manifest requirement",
    )?;
    for requirement in &mut manifest.requirements {
        validate_reference(
            "requirement_version_id",
            &requirement.requirement_version_id,
        )?;
        validate_digest("requirement content_digest", &requirement.content_digest)?;
        requirement.provenance_evidence_object_ids.sort();
        for evidence_id in &requirement.provenance_evidence_object_ids {
            validate_reference("requirement provenance evidence", evidence_id)?;
        }
        reject_duplicate(
            requirement
                .provenance_evidence_object_ids
                .iter()
                .map(String::as_str),
            "requirement provenance evidence",
        )?;
    }
    if manifest.nodes.len() > super::evaluation_plan::MAX_PLAN_NODES {
        return Err(format!(
            "manifest node count exceeds {}",
            super::evaluation_plan::MAX_PLAN_NODES
        ));
    }
    manifest
        .nodes
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));
    reject_duplicate(
        manifest.nodes.iter().map(|node| node.node_id.as_str()),
        "manifest node_id",
    )?;
    for node in &mut manifest.nodes {
        validate_reference("node_id", &node.node_id)?;
        validate_reference("evaluator definition_id", &node.evaluator.definition_id)?;
        validate_digest(
            "evaluator definition_digest",
            &node.evaluator.definition_digest,
        )?;
        validate_digest(
            "evaluator implementation_digest",
            &node.evaluator.implementation_digest,
        )?;
        if !matches!(
            node.classification.as_str(),
            super::evaluation_plan::NODE_REQUIRED | super::evaluation_plan::NODE_ADVISORY
        ) {
            return Err("manifest node classification is invalid".into());
        }
        if node.depends_on_node_ids.len() > super::evaluation_plan::MAX_NODE_DEPENDENCIES {
            return Err(format!(
                "manifest node dependency count exceeds {}",
                super::evaluation_plan::MAX_NODE_DEPENDENCIES
            ));
        }
        node.depends_on_node_ids.sort();
        for dependency in &node.depends_on_node_ids {
            validate_reference("node dependency", dependency)?;
        }
        reject_duplicate(
            node.depends_on_node_ids.iter().map(String::as_str),
            "node dependency",
        )?;
        if node.input_bindings.is_empty()
            || node.input_bindings.len() > super::evaluation_plan::MAX_NODE_BINDINGS
        {
            return Err(format!(
                "manifest node requires 1..={} input bindings",
                super::evaluation_plan::MAX_NODE_BINDINGS
            ));
        }
        node.input_bindings.sort_by(|left, right| {
            (&left.name, &left.source_kind, &left.schema_id).cmp(&(
                &right.name,
                &right.source_kind,
                &right.schema_id,
            ))
        });
        reject_duplicate(
            node.input_bindings
                .iter()
                .map(|binding| binding.name.as_str()),
            "input binding name",
        )?;
        for binding in &node.input_bindings {
            validate_reference("input binding name", &binding.name)?;
            validate_reference("input binding schema_id", &binding.schema_id)?;
            if !matches!(
                binding.source_kind.as_str(),
                super::evaluation_plan::INPUT_SUBJECT
                    | super::evaluation_plan::INPUT_INVARIANT
                    | super::evaluation_plan::INPUT_EVIDENCE
            ) {
                return Err("manifest input binding source_kind is invalid".into());
            }
        }
        let parameters: serde_json::Value = serde_json::from_str(&node.parameters_json)
            .map_err(|error| format!("manifest parameters_json must be JSON: {error}"))?;
        if !parameters.is_object() {
            return Err("manifest parameters_json must be a JSON object".into());
        }
        node.parameters_json =
            serde_json::to_string(&parameters).map_err(|error| error.to_string())?;
        if node.invariants.is_empty()
            || node.invariants.len() > super::evaluation_plan::MAX_NODE_INVARIANTS
        {
            return Err(format!(
                "manifest node requires 1..={} invariants",
                super::evaluation_plan::MAX_NODE_INVARIANTS
            ));
        }
        node.invariants
            .sort_by(|left, right| left.invariant_version_id.cmp(&right.invariant_version_id));
        reject_duplicate(
            node.invariants
                .iter()
                .map(|binding| binding.invariant_version_id.as_str()),
            "node invariant",
        )?;
        for invariant in &mut node.invariants {
            validate_reference("invariant_version_id", &invariant.invariant_version_id)?;
            validate_digest("invariant content_digest", &invariant.content_digest)?;
            for (field, value) in [
                (
                    "invariant predicate_kind",
                    invariant.predicate_kind.as_str(),
                ),
                ("invariant input_schema", invariant.input_schema.as_str()),
                ("invariant result_schema", invariant.result_schema.as_str()),
            ] {
                validate_reference(field, value)?;
            }
            invariant.evidence_types.sort();
            for evidence_type in &invariant.evidence_types {
                validate_reference("invariant evidence type", evidence_type)?;
            }
            reject_duplicate(
                invariant.evidence_types.iter().map(String::as_str),
                "invariant evidence type",
            )?;
            invariant.provenance_evidence_object_ids.sort();
            for evidence_id in &invariant.provenance_evidence_object_ids {
                validate_reference("invariant provenance evidence", evidence_id)?;
            }
            reject_duplicate(
                invariant
                    .provenance_evidence_object_ids
                    .iter()
                    .map(String::as_str),
                "invariant provenance evidence",
            )?;
            invariant.waiver_version_ids.sort();
            for waiver_id in &invariant.waiver_version_ids {
                validate_reference("invariant waiver", waiver_id)?;
            }
            reject_duplicate(
                invariant.waiver_version_ids.iter().map(String::as_str),
                "invariant waiver",
            )?;
        }
        node.evidence_object_ids.sort();
        for evidence_id in &node.evidence_object_ids {
            validate_reference("node evidence", evidence_id)?;
        }
        reject_duplicate(
            node.evidence_object_ids.iter().map(String::as_str),
            "node evidence",
        )?;
    }
    validate_manifest_graph(&manifest.nodes)?;
    manifest
        .evidence
        .sort_by(|left, right| left.evidence_object_id.cmp(&right.evidence_object_id));
    reject_duplicate(
        manifest
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_object_id.as_str()),
        "manifest evidence",
    )?;
    for evidence in &manifest.evidence {
        for (field, value) in [
            ("evidence_object_id", evidence.evidence_object_id.as_str()),
            ("evidence submission_id", evidence.submission_id.as_str()),
            ("evidence type", evidence.evidence_type.as_str()),
            ("evidence schema_id", evidence.schema_id.as_str()),
            ("evidence schema_version", evidence.schema_version.as_str()),
            ("evidence classification", evidence.classification.as_str()),
        ] {
            validate_reference(field, value)?;
        }
        validate_digest("evidence content_digest", &evidence.content_digest)?;
        validate_digest(
            "evidence source_identity_digest",
            &evidence.source_identity_digest,
        )?;
        if evidence.observed_at_ms <= 0
            || (evidence.expires_at_ms != 0 && evidence.expires_at_ms <= evidence.observed_at_ms)
        {
            return Err("manifest evidence timestamps are invalid".into());
        }
        if !matches!(
            evidence.classification.as_str(),
            "public" | "internal" | "confidential" | "restricted"
        ) {
            return Err("manifest evidence classification is invalid".into());
        }
    }
    manifest
        .waivers
        .sort_by(|left, right| left.waiver_version_id.cmp(&right.waiver_version_id));
    reject_duplicate(
        manifest
            .waivers
            .iter()
            .map(|waiver| waiver.waiver_version_id.as_str()),
        "manifest waiver",
    )?;
    for waiver in &mut manifest.waivers {
        validate_reference("waiver_version_id", &waiver.waiver_version_id)?;
        validate_digest("waiver content_digest", &waiver.content_digest)?;
        if waiver.invariant_version_ids.is_empty() {
            return Err("manifest waiver requires target invariants".into());
        }
        waiver.invariant_version_ids.sort();
        for invariant_id in &waiver.invariant_version_ids {
            validate_reference("waiver invariant", invariant_id)?;
        }
        reject_duplicate(
            waiver.invariant_version_ids.iter().map(String::as_str),
            "waiver invariant",
        )?;
        waiver.evidence_object_ids.sort();
        for evidence_id in &waiver.evidence_object_ids {
            validate_reference("waiver evidence", evidence_id)?;
        }
        reject_duplicate(
            waiver.evidence_object_ids.iter().map(String::as_str),
            "waiver evidence",
        )?;
    }
    validate_manifest_references(manifest)?;
    Ok(())
}

fn validate_manifest_graph(nodes: &[ResolvedEvaluationNode]) -> Result<(), String> {
    let mut inbound = nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node.depends_on_node_ids.len()))
        .collect::<BTreeMap<_, _>>();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        for dependency in &node.depends_on_node_ids {
            if dependency == &node.node_id || !inbound.contains_key(dependency.as_str()) {
                return Err("manifest contains an unknown or self node dependency".into());
            }
            dependents
                .entry(dependency)
                .or_default()
                .push(&node.node_id);
        }
    }
    let mut ready = inbound
        .iter()
        .filter_map(|(node_id, count)| (*count == 0).then_some(*node_id))
        .collect::<VecDeque<_>>();
    let mut visited = 0;
    while let Some(node_id) = ready.pop_front() {
        visited += 1;
        for dependent in dependents.get(node_id).into_iter().flatten() {
            let count = inbound.get_mut(dependent).expect("known manifest node");
            *count -= 1;
            if *count == 0 {
                ready.push_back(dependent);
            }
        }
    }
    if visited != nodes.len() {
        return Err("manifest evaluation graph contains a cycle".into());
    }
    Ok(())
}

fn validate_manifest_references(manifest: &ResolvedEvaluationManifest) -> Result<(), String> {
    let evidence_ids = manifest
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_object_id.as_str())
        .collect::<BTreeSet<_>>();
    let waiver_by_id = manifest
        .waivers
        .iter()
        .map(|waiver| (waiver.waiver_version_id.as_str(), waiver))
        .collect::<BTreeMap<_, _>>();
    let mut referenced_evidence = BTreeSet::new();
    for requirement in &manifest.requirements {
        referenced_evidence.extend(
            requirement
                .provenance_evidence_object_ids
                .iter()
                .map(String::as_str),
        );
    }
    let mut invariant_bindings: BTreeMap<&str, &ResolvedInvariantBinding> = BTreeMap::new();
    for node in &manifest.nodes {
        referenced_evidence.extend(node.evidence_object_ids.iter().map(String::as_str));
        for invariant in &node.invariants {
            if let Some(existing) =
                invariant_bindings.insert(&invariant.invariant_version_id, invariant)
                && existing != invariant
            {
                return Err("manifest repeats an invariant with conflicting content".into());
            }
            referenced_evidence.extend(
                invariant
                    .provenance_evidence_object_ids
                    .iter()
                    .map(String::as_str),
            );
            for waiver_id in &invariant.waiver_version_ids {
                let Some(waiver) = waiver_by_id.get(waiver_id.as_str()) else {
                    return Err("manifest invariant references an unknown waiver".into());
                };
                if !waiver
                    .invariant_version_ids
                    .contains(&invariant.invariant_version_id)
                {
                    return Err("manifest waiver does not cover its referenced invariant".into());
                }
            }
        }
    }
    for waiver in &manifest.waivers {
        referenced_evidence.extend(waiver.evidence_object_ids.iter().map(String::as_str));
    }
    if referenced_evidence != evidence_ids {
        return Err("manifest evidence closure is incomplete or contains unbound evidence".into());
    }
    Ok(())
}

fn reject_duplicate<'a>(values: impl Iterator<Item = &'a str>, field: &str) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicates"));
        }
    }
    Ok(())
}

fn validate_reference(field: &str, value: &str) -> Result<(), String> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!("{field} is invalid"));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{field} must be a sha256 digest"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be a lowercase sha256 digest"));
    }
    Ok(())
}

pub fn digest_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> EvaluationResolutionRequest {
        EvaluationResolutionRequest {
            contract_version: RESOLUTION_REQUEST_CONTRACT.into(),
            resolver_version: RESOLVER_VERSION.into(),
            namespace: "acme".into(),
            request_id: "resolve-1".into(),
            plan_version_id: "plan:1".into(),
            subject_profile: "document/v1".into(),
            subject_identity: "document:42".into(),
            subject_content_digest: format!("sha256:{}", "a".repeat(64)),
            evidence_object_ids: vec!["evidence:b".into(), "evidence:a".into()],
            evaluation_time_ms: 42,
        }
    }

    fn manifest() -> ResolvedEvaluationManifest {
        ResolvedEvaluationManifest {
            contract_version: MANIFEST_CONTRACT.into(),
            resolver_version: RESOLVER_VERSION.into(),
            manifest_id: String::new(),
            manifest_digest: String::new(),
            namespace: "acme".into(),
            plan_version_id: "plan:1".into(),
            plan_digest: format!("sha256:{}", "b".repeat(64)),
            subject_profile: "document/v1".into(),
            subject_identity: "document:42".into(),
            subject_content_digest: format!("sha256:{}", "a".repeat(64)),
            invariant_set_id: "invariant-set:1".into(),
            invariant_set_digest: format!("sha256:{}", "c".repeat(64)),
            invariant_profile_digest: format!("sha256:{}", "d".repeat(64)),
            evaluation_time_ms: 42,
            resolved_by: "local".into(),
            requirements: vec![],
            nodes: vec![ResolvedEvaluationNode {
                node_id: "schema".into(),
                evaluator: ResolvedEvaluatorBinding {
                    definition_id: "definition:1".into(),
                    definition_digest: format!("sha256:{}", "e".repeat(64)),
                    implementation_digest: format!("sha256:{}", "f".repeat(64)),
                },
                depends_on_node_ids: vec![],
                input_bindings: vec![ResolvedInputBinding {
                    name: "subject".into(),
                    source_kind: "subject".into(),
                    schema_id: "schema://document/v1".into(),
                }],
                parameters_json: "{}".into(),
                invariants: vec![ResolvedInvariantBinding {
                    invariant_version_id: "invariant:1".into(),
                    content_digest: format!("sha256:{}", "1".repeat(64)),
                    predicate_kind: "schema_conforms".into(),
                    input_schema: "schema://document/v1".into(),
                    result_schema: "schema://pass-fail/v1".into(),
                    evidence_types: vec![],
                    provenance_evidence_object_ids: vec![],
                    waiver_version_ids: vec![],
                }],
                evidence_object_ids: vec![],
                classification: "required".into(),
            }],
            evidence: vec![],
            waivers: vec![],
            created_at_ms: 100,
        }
    }

    #[test]
    fn resolution_request_is_canonical_and_actor_bound() {
        let prepared = prepare_resolution_request(request(), "local").unwrap();
        assert_eq!(
            prepared.request.evidence_object_ids,
            vec!["evidence:a", "evidence:b"]
        );
        let replay = prepare_resolution_request(request(), "local").unwrap();
        assert_eq!(prepared.request_digest, replay.request_digest);
        assert_ne!(
            prepared.request_digest,
            prepare_resolution_request(request(), "root")
                .unwrap()
                .request_digest
        );
    }

    #[test]
    fn manifest_digest_changes_for_each_frozen_input() {
        let base = prepare_manifest(manifest()).unwrap();
        let mut changed = manifest();
        changed.evaluation_time_ms += 1;
        assert_ne!(
            base.manifest_digest,
            prepare_manifest(changed).unwrap().manifest_digest
        );
        let mut changed = manifest();
        changed.subject_content_digest = format!("sha256:{}", "2".repeat(64));
        assert_ne!(
            base.manifest_digest,
            prepare_manifest(changed).unwrap().manifest_digest
        );
        let mut changed = manifest();
        changed.nodes[0].evaluator.implementation_digest = format!("sha256:{}", "3".repeat(64));
        assert_ne!(
            base.manifest_digest,
            prepare_manifest(changed).unwrap().manifest_digest
        );
    }

    #[test]
    fn manifest_canonicalization_sorts_set_like_inputs() {
        let base = prepare_manifest(manifest()).unwrap();
        let mut reordered = manifest();
        reordered.nodes[0].invariants[0].evidence_types = vec!["z".into(), "a".into()];
        let first = prepare_manifest(reordered.clone()).unwrap();
        reordered.nodes[0].invariants[0].evidence_types.reverse();
        let second = prepare_manifest(reordered).unwrap();
        assert_eq!(first.manifest_digest, second.manifest_digest);
        assert_ne!(base.manifest_digest, first.manifest_digest);
    }
}

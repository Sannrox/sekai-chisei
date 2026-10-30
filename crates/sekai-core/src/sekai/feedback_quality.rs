//! Verify later observations against published findings and record issue quality (#1233).
//!
//! Comparable operations of the same problem class are matched to the original
//! finding. Successful comparable operations, absent telemetry, expected waits,
//! and unrelated workloads stay distinct. Recovery and verified reproduction
//! are recorded only from measured signals. Issue closure, learning activation,
//! and detector-policy changes stay maintainer-controlled.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, Object};
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use crate::sekai::feedback_investigation::{
    ObservationView, observation_view, parse_occurrence_ids, precludes_tenkai_defect,
};
use crate::sekai::feedback_package::{
    ACTION_INVESTIGATION, ACTION_VERIFICATION, KIND_FINDING, KIND_INVESTIGATION_RESULT,
    KIND_OBSERVATION, KIND_VERIFICATION, PACKAGE_VERSION,
};
use crate::sekai::object_security::PrincipalPolicyContext;

pub const RUNTIME_ID: &str = "feedback-quality";
pub const POLL_INTERVAL_SECS: u64 = 15;
pub const RESULT_CONFIRMED: &str = "confirmed";
pub const RESULT_REFUTED: &str = "refuted";
pub const RESULT_INCONCLUSIVE: &str = "inconclusive";
pub const QUALITY_CASE_VERSION: &str = "feedback.quality-eval-case/v1";

const _: () = assert!(POLL_INTERVAL_SECS == 15);

/// How a later observation compares to the original finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchClass {
    ComparableSuccess,
    AbsentTelemetry,
    ExpectedWait,
    UnrelatedWorkload,
    Recurrence,
    Recovery,
    VerifiedReproduction,
}

impl MatchClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComparableSuccess => "comparable_success",
            Self::AbsentTelemetry => "absent_telemetry",
            Self::ExpectedWait => "expected_wait",
            Self::UnrelatedWorkload => "unrelated_workload",
            Self::Recurrence => "recurrence",
            Self::Recovery => "recovery",
            Self::VerifiedReproduction => "verified_reproduction",
        }
    }
}

/// Disposition of the original report. Never closes the tracker issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueQuality {
    Useful,
    Duplicate,
    FalsePositive,
    Recurring,
    Improved,
}

impl IssueQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Useful => "useful",
            Self::Duplicate => "duplicate",
            Self::FalsePositive => "false_positive",
            Self::Recurring => "recurring",
            Self::Improved => "improved",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityObservation {
    pub view: ObservationView,
    pub tenkai_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationMatch {
    pub observation_id: String,
    pub class: MatchClass,
    pub tenkai_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityRecord {
    pub namespace: String,
    pub finding_id: String,
    pub investigation_id: String,
    pub verification_id: String,
    pub signature: String,
    pub match_class: MatchClass,
    pub quality: IssueQuality,
    pub tenkai_versions: Vec<String>,
    pub evidence_coverage: String,
    pub verification_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluateReport {
    pub records: Vec<QualityRecord>,
}

/// Inspectable evaluation corpus case. No free-form observation text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityCorpusCase {
    pub contract_version: String,
    pub namespace: String,
    pub finding_id: String,
    pub signature: String,
    pub quality: String,
    pub match_class: String,
    pub verification_result: String,
    pub tenkai_versions: String,
    pub evidence_coverage: String,
}

/// Closure, learning, and detector-policy changes stay with a maintainer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintainerControl {
    pub close_issue: bool,
    pub activate_learning: bool,
    pub change_detector_policy: bool,
}

#[derive(Debug)]
pub enum QualityError {
    Internal(String),
}

pub fn maintainer_control() -> MaintainerControl {
    MaintainerControl {
        close_issue: false,
        activate_learning: false,
        change_detector_policy: false,
    }
}

pub fn quality_corpus_case(record: &QualityRecord) -> QualityCorpusCase {
    QualityCorpusCase {
        contract_version: QUALITY_CASE_VERSION.into(),
        namespace: record.namespace.clone(),
        finding_id: record.finding_id.clone(),
        signature: redact_private_tokens(&record.signature),
        quality: record.quality.as_str().into(),
        match_class: record.match_class.as_str().into(),
        verification_result: record.verification_result.clone(),
        tenkai_versions: redact_private_tokens(&record.tenkai_versions.join(",")),
        evidence_coverage: record.evidence_coverage.clone(),
    }
}

fn redact_private_tokens(text: &str) -> String {
    let mut out = String::new();
    for token in text.split(|c: char| c.is_whitespace() || c == ',') {
        if !out.is_empty() {
            out.push(',');
        }
        if token.starts_with("/Users/")
            || token.starts_with("/home/")
            || token.contains(".internal.")
            || token.parse::<std::net::IpAddr>().is_ok()
            || (token.contains('/') && token.contains('#'))
        {
            out.push_str("[redacted]");
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Keep length without retaining free-form content.
pub fn redact_quality_text(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.len() <= 48 {
        return "[redacted]".into();
    }
    format!("[redacted:{} chars]", trimmed.chars().count())
}

pub fn operation_class(signature: &str) -> &str {
    signature
        .rsplit_once(':')
        .map(|(left, _)| left)
        .unwrap_or(signature)
}

pub fn tenkai_version_from(view: &ObservationView, object: &Object) -> String {
    if let Some(version) = object
        .properties
        .get("tenkai_version")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return version.to_string();
    }
    for occurrence in &view.occurrence_ids {
        if let Some((_, version)) = occurrence.rsplit_once('@') {
            let version = version.trim();
            if !version.is_empty() {
                return version.to_string();
            }
        }
    }
    String::new()
}

pub fn quality_observation(object: &Object) -> Option<QualityObservation> {
    let view = observation_view(object)?;
    let tenkai_version = tenkai_version_from(&view, object);
    Some(QualityObservation {
        view,
        tenkai_version,
    })
}

/// Classify one later observation against the original finding's trigger.
pub fn classify_observation(
    original: &QualityObservation,
    later: &QualityObservation,
) -> MatchClass {
    if later.view.object_id == original.view.object_id {
        return MatchClass::UnrelatedWorkload;
    }
    if later.view.problem_signature != original.view.problem_signature {
        return MatchClass::UnrelatedWorkload;
    }
    let classification = later.view.classification.as_str();
    if matches!(classification, "cancelled" | "blocked") || precludes_tenkai_defect(&later.view) {
        if matches!(classification, "ok" | "reconciled") {
            return if original.view.classification == "defect" {
                MatchClass::Recovery
            } else {
                MatchClass::ComparableSuccess
            };
        }
        return MatchClass::ExpectedWait;
    }
    if matches!(classification, "ok" | "reconciled") {
        return if original.view.classification == "defect" {
            MatchClass::Recovery
        } else {
            MatchClass::ComparableSuccess
        };
    }
    if classification == "reproduced" {
        return MatchClass::VerifiedReproduction;
    }
    MatchClass::Recurrence
}

pub fn primary_match_class(matches: &[ObservationMatch], _had_later: bool) -> MatchClass {
    let relevant: Vec<&ObservationMatch> = matches
        .iter()
        .filter(|item| item.class != MatchClass::UnrelatedWorkload)
        .collect();
    if relevant
        .iter()
        .any(|item| item.class == MatchClass::Recovery)
    {
        return MatchClass::Recovery;
    }
    if relevant
        .iter()
        .any(|item| item.class == MatchClass::VerifiedReproduction)
    {
        return MatchClass::VerifiedReproduction;
    }
    if relevant
        .iter()
        .any(|item| item.class == MatchClass::Recurrence)
    {
        return MatchClass::Recurrence;
    }
    if relevant
        .iter()
        .any(|item| item.class == MatchClass::ComparableSuccess)
    {
        return MatchClass::ComparableSuccess;
    }
    if relevant
        .iter()
        .any(|item| item.class == MatchClass::ExpectedWait)
    {
        return MatchClass::ExpectedWait;
    }
    MatchClass::AbsentTelemetry
}

pub fn decide_quality(
    duplicate: bool,
    match_class: MatchClass,
    matches: &[ObservationMatch],
) -> IssueQuality {
    if duplicate {
        return IssueQuality::Duplicate;
    }
    let relevant: Vec<&ObservationMatch> = matches
        .iter()
        .filter(|item| item.class != MatchClass::UnrelatedWorkload)
        .collect();
    let only_waits = !relevant.is_empty()
        && relevant
            .iter()
            .all(|item| item.class == MatchClass::ExpectedWait);
    if only_waits || match_class == MatchClass::ExpectedWait {
        return IssueQuality::FalsePositive;
    }
    if match_class == MatchClass::Recovery
        && !relevant
            .iter()
            .any(|item| item.class == MatchClass::Recurrence)
    {
        return IssueQuality::Improved;
    }
    if match_class == MatchClass::Recurrence || match_class == MatchClass::VerifiedReproduction {
        return IssueQuality::Recurring;
    }
    IssueQuality::Useful
}

pub fn verification_result(match_class: MatchClass) -> &'static str {
    match match_class {
        MatchClass::Recovery | MatchClass::ComparableSuccess => RESULT_CONFIRMED,
        MatchClass::Recurrence | MatchClass::VerifiedReproduction => RESULT_REFUTED,
        MatchClass::AbsentTelemetry | MatchClass::ExpectedWait | MatchClass::UnrelatedWorkload => {
            RESULT_INCONCLUSIVE
        }
    }
}

pub fn evidence_coverage(match_class: MatchClass, matches: &[ObservationMatch]) -> String {
    let mut parts = BTreeSet::new();
    parts.insert(match_class.as_str().to_string());
    for item in matches {
        parts.insert(item.class.as_str().to_string());
    }
    parts.into_iter().collect::<Vec<_>>().join(",")
}

pub fn retain_tenkai_versions(
    matches: &[ObservationMatch],
    original: &QualityObservation,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut versions = Vec::new();
    for version in std::iter::once(original.tenkai_version.as_str()).chain(
        matches
            .iter()
            .filter(|item| {
                !matches!(
                    item.class,
                    MatchClass::UnrelatedWorkload | MatchClass::ExpectedWait
                )
            })
            .map(|item| item.tenkai_version.as_str()),
    ) {
        let version = version.trim();
        if version.is_empty() || !seen.insert(version.to_string()) {
            continue;
        }
        versions.push(version.to_string());
    }
    versions
}

fn finding_signature(db: &RuntimeDb, finding: &Object) -> Result<Option<String>, QualityError> {
    let Some(observation_id) = finding.properties.get("observation_id") else {
        return Ok(None);
    };
    let Some(observation) = db
        .get_object(observation_id)
        .map_err(|error| QualityError::Internal(error.to_string()))?
    else {
        return Ok(None);
    };
    Ok(observation
        .properties
        .get("problem_signature")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string))
}

fn list_projected(
    db: &RuntimeDb,
    namespace: &str,
    kind: &str,
) -> Result<Vec<Object>, QualityError> {
    let listed = db
        .list_objects(&ListFilter {
            kind: Some(kind.into()),
            namespace: Some(namespace.into()),
            limit: 256,
            ..ListFilter::default()
        })
        .map_err(|error| QualityError::Internal(error.to_string()))?;
    let mut out = Vec::new();
    for object in listed {
        out.push(
            db.project_object_property_grants(object)
                .map_err(|error| QualityError::Internal(error.to_string()))?,
        );
    }
    Ok(out)
}

fn quality_key(parts: &[&str]) -> String {
    let digest = format!("{:x}", Sha256::digest(parts.join("\0").as_bytes()));
    digest[..16].to_string()
}

fn assessment_fingerprint(
    match_class: MatchClass,
    quality: IssueQuality,
    matches: &[ObservationMatch],
) -> String {
    let mut ids: Vec<&str> = matches
        .iter()
        .map(|item| item.observation_id.as_str())
        .collect();
    ids.sort_unstable();
    quality_key(&[match_class.as_str(), quality.as_str(), &ids.join(",")])
}

pub fn verification_object_id(namespace: &str, finding_id: &str, fingerprint: &str) -> String {
    format!(
        "fb-ver-{}",
        quality_key(&[namespace, finding_id, fingerprint])
    )
}

pub fn quality_investigation_id(namespace: &str, finding_id: &str) -> String {
    format!("fb-inv-quality-{}", quality_key(&[namespace, finding_id]))
}

fn measured_investigation_for_signature(
    db: &RuntimeDb,
    namespace: &str,
    signature: &str,
) -> Result<Option<Object>, QualityError> {
    for object in list_projected(db, namespace, KIND_INVESTIGATION_RESULT)? {
        if object.properties.get("measured").map(String::as_str) != Some("true") {
            continue;
        }
        let Some(observation_id) = object.properties.get("observation_id") else {
            continue;
        };
        let Some(observation) = db
            .get_object(observation_id)
            .map_err(|error| QualityError::Internal(error.to_string()))?
        else {
            continue;
        };
        if observation
            .properties
            .get("problem_signature")
            .map(String::as_str)
            == Some(signature)
        {
            return Ok(Some(object));
        }
    }
    Ok(None)
}

fn admit(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    type_id: &str,
    parameters: serde_json::Value,
    idempotency_key: &str,
    now_ms: i64,
) -> Result<(), QualityError> {
    match ActionInstanceAdmission::new(db, None).admit(
        ActionInstanceAdmissionRequest {
            agent_turn: None,
            namespace: namespace.into(),
            type_id: type_id.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: parameters.to_string(),
            idempotency_key: idempotency_key.into(),
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: String::new(),
            autonomous_envelope_id: String::new(),
            policy_context: PrincipalPolicyContext::default(),
            delegating_actor: None,
            budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
            expected_object_revision: String::new(),
            offline: None,
        },
        actor,
        now_ms,
    ) {
        Ok(_) => Ok(()),
        Err(error) => {
            let rendered = format!("{error:?}");
            if rendered.contains("already exists") || rendered.contains("AlreadyExists") {
                Ok(())
            } else {
                Err(QualityError::Internal(rendered))
            }
        }
    }
}

fn ensure_measured_investigation(
    db: &RuntimeDb,
    actor: &str,
    finding: &Object,
    original: &QualityObservation,
    signature: &str,
    now_ms: i64,
) -> Result<String, QualityError> {
    if let Some(existing) = measured_investigation_for_signature(db, &finding.namespace, signature)?
    {
        return Ok(existing.id);
    }
    let investigation_id = quality_investigation_id(&finding.namespace, &finding.id);
    admit(
        db,
        actor,
        &finding.namespace,
        ACTION_INVESTIGATION,
        serde_json::json!({
            "object_id": investigation_id,
            "name": signature,
            "observation_id": original.view.object_id,
            "outcome": "quality-evaluation",
            "measured": true,
        }),
        &format!(
            "feedback:inv-quality:{}",
            quality_key(&[&finding.namespace, &finding.id])
        ),
        now_ms,
    )?;
    Ok(investigation_id)
}

fn write_verification(
    db: &RuntimeDb,
    actor: &str,
    record: &QualityRecord,
    now_ms: i64,
) -> Result<(), QualityError> {
    admit(
        db,
        actor,
        &record.namespace,
        ACTION_VERIFICATION,
        serde_json::json!({
            "object_id": record.verification_id,
            "name": record.signature,
            "subject_id": record.investigation_id,
            "subject_kind": KIND_INVESTIGATION_RESULT,
            "result": record.verification_result,
            "finding_id": record.finding_id,
            "match_class": record.match_class.as_str(),
            "quality": record.quality.as_str(),
            "tenkai_versions": record.tenkai_versions.join(","),
            "evidence_coverage": record.evidence_coverage,
        }),
        &format!("feedback:ver:{}", record.verification_id),
        now_ms,
    )
}

/// Evaluate one finding against later observations. Does not close issues.
pub fn evaluate_finding(
    db: &RuntimeDb,
    finding: &Object,
    earlier_signatures: &HashMap<String, String>,
    actor: &str,
    now_ms: i64,
) -> Result<Option<QualityRecord>, QualityError> {
    if finding.kind != KIND_FINDING {
        return Ok(None);
    }
    let Some(signature) = finding_signature(db, finding)? else {
        return Ok(None);
    };
    let Some(observation_id) = finding.properties.get("observation_id") else {
        return Ok(None);
    };
    let Some(trigger_object) = db
        .get_object(observation_id)
        .map_err(|error| QualityError::Internal(error.to_string()))?
    else {
        return Ok(None);
    };
    let trigger = db
        .project_object_property_grants(trigger_object)
        .map_err(|error| QualityError::Internal(error.to_string()))?;
    let Some(original) = quality_observation(&trigger) else {
        return Ok(None);
    };
    let observations = list_projected(db, &finding.namespace, KIND_OBSERVATION)?;
    let mut matches = Vec::new();
    let mut had_later = false;
    for object in observations {
        let Some(later) = quality_observation(&object) else {
            continue;
        };
        if later.view.created_ms < finding.created {
            continue;
        }
        if later.view.object_id == original.view.object_id {
            continue;
        }
        had_later = true;
        let class = classify_observation(&original, &later);
        matches.push(ObservationMatch {
            observation_id: later.view.object_id,
            class,
            tenkai_version: later.tenkai_version,
        });
    }
    let match_class = primary_match_class(&matches, had_later);
    let duplicate = earlier_signatures
        .get(&signature)
        .is_some_and(|id| id != &finding.id);
    let quality = decide_quality(duplicate, match_class, &matches);
    let fingerprint = assessment_fingerprint(match_class, quality, &matches);
    let investigation_id =
        ensure_measured_investigation(db, actor, finding, &original, &signature, now_ms)?;
    let record = QualityRecord {
        namespace: finding.namespace.clone(),
        finding_id: finding.id.clone(),
        investigation_id,
        verification_id: verification_object_id(&finding.namespace, &finding.id, &fingerprint),
        signature,
        match_class,
        quality,
        tenkai_versions: retain_tenkai_versions(&matches, &original),
        evidence_coverage: evidence_coverage(match_class, &matches),
        verification_result: verification_result(match_class).into(),
    };
    write_verification(db, actor, &record, now_ms)?;
    Ok(Some(record))
}

/// Evaluate every finding in a namespace. Never mutates GitHub, learning, or detector policy.
pub fn evaluate_namespace(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<EvaluateReport, QualityError> {
    let mut findings = list_projected(db, namespace, KIND_FINDING)?;
    findings.sort_by(|left, right| {
        left.created
            .cmp(&right.created)
            .then(left.id.cmp(&right.id))
    });
    let mut earlier_signatures = HashMap::new();
    let mut records = Vec::new();
    for finding in findings {
        let Some(record) = evaluate_finding(db, &finding, &earlier_signatures, actor, now_ms)?
        else {
            continue;
        };
        earlier_signatures
            .entry(record.signature.clone())
            .or_insert_with(|| record.finding_id.clone());
        records.push(record);
    }
    Ok(EvaluateReport { records })
}

pub fn load_verification(
    db: &RuntimeDb,
    verification_id: &str,
) -> Result<Option<Object>, QualityError> {
    db.get_object(verification_id)
        .map_err(|error| QualityError::Internal(error.to_string()))
}

/// Latest quality verification per finding in the namespace.
pub fn inspect_quality_corpus(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<Vec<QualityCorpusCase>, QualityError> {
    let mut listed = list_projected(db, namespace, KIND_VERIFICATION)?;
    listed.sort_by(|left, right| {
        left.created
            .cmp(&right.created)
            .then(left.id.cmp(&right.id))
    });
    let mut latest: HashMap<String, Object> = HashMap::new();
    for object in listed {
        let Some(finding_id) = object.properties.get("finding_id").cloned() else {
            continue;
        };
        if object
            .properties
            .get("quality")
            .map(String::as_str)
            .unwrap_or("")
            .is_empty()
        {
            continue;
        }
        latest.insert(finding_id, object);
    }
    let mut cases: Vec<QualityCorpusCase> = latest
        .into_values()
        .map(|object| QualityCorpusCase {
            contract_version: QUALITY_CASE_VERSION.into(),
            namespace: object.namespace,
            finding_id: object
                .properties
                .get("finding_id")
                .cloned()
                .unwrap_or_default(),
            signature: object.name,
            quality: object
                .properties
                .get("quality")
                .cloned()
                .unwrap_or_default(),
            match_class: object
                .properties
                .get("match_class")
                .cloned()
                .unwrap_or_default(),
            verification_result: object.properties.get("result").cloned().unwrap_or_default(),
            tenkai_versions: object
                .properties
                .get("tenkai_versions")
                .cloned()
                .unwrap_or_default(),
            evidence_coverage: object
                .properties
                .get("evidence_coverage")
                .cloned()
                .unwrap_or_default(),
        })
        .collect();
    cases.sort_by(|left, right| {
        left.finding_id
            .cmp(&right.finding_id)
            .then(left.quality.cmp(&right.quality))
    });
    Ok(cases)
}

/// Occurrence identifiers with an optional `@version` suffix.
pub fn occurrence_id(raw: &str) -> String {
    parse_occurrence_ids(raw)
        .into_iter()
        .next()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceEnvelope, EvidenceIntent, EvidenceSignal,
        EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle;
    use crate::sekai::evidence_store::{EvidenceProducerCapability, canonical_content_digest};
    use crate::sekai::feedback_investigation::{
        Attribution, InvestigationAnalysis, record_investigation,
    };
    use crate::sekai::feedback_package::{
        ACTION_OBSERVATION, EVIDENCE_SCHEMA_VERSION, EVIDENCE_TYPE, install,
    };
    use serde_json::json;
    use std::collections::BTreeSet;

    const NAMESPACE: &str = "ops";
    const OTHER: &str = "other";
    const ACTOR: &str = "reviewer";

    fn db() -> RuntimeDb {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        runtime
            .upsert_evidence_producer(&producer(), 1_000)
            .unwrap();
        runtime
    }

    fn producer() -> EvidenceProducerCapability {
        EvidenceProducerCapability {
            producer_identity: "producer:feedback".into(),
            config_version: 1,
            source_types: vec!["feedback_source".into()],
            source_instances: vec!["feedback:checks".into()],
            namespaces: vec![NAMESPACE.into(), OTHER.into()],
            evidence_types: vec![EVIDENCE_TYPE.into()],
            target_kinds: vec![KIND_OBSERVATION.into()],
            classification_ceiling: crate::sekai::evidence::EvidenceClassification::Confidential,
            allowed_intents: vec![EvidenceIntent::Upsert],
            allow_operation_attachment: true,
            replay_window_ms: 86_400_000,
            max_clock_skew_ms: 60_000,
            max_payload_bytes: 4_096,
            max_relationships: 4,
            rate_limit_per_minute: 1_000,
            max_retained_submissions: 100,
            revoked: false,
        }
    }

    fn envelope(
        namespace: &str,
        external_id: &str,
        signature: &str,
        occurrence: &str,
        classification: &str,
        at_ms: i64,
    ) -> EvidenceEnvelope {
        let content = json!({
            "problem_signature": signature,
            "occurrence_ids": occurrence,
            "classification": classification,
            "disposition": "open"
        });
        EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "feedback_source".into(),
            source_instance: "feedback:checks".into(),
            source_record_id: external_id.into(),
            source_version: "attempt-1".into(),
            source_sequence: 1,
            target: EvidenceTarget {
                namespace: namespace.into(),
                object_external_id: external_id.into(),
                object_kind: KIND_OBSERVATION.into(),
            },
            evidence_type: EVIDENCE_TYPE.into(),
            signal: EvidenceSignal::OperationalHealth,
            schema_id: EVIDENCE_TYPE.into(),
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: at_ms,
            collected_at_ms: at_ms.saturating_add(10),
            expires_at_ms: Some(at_ms.saturating_add(60_000_000)),
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: "producer:feedback".into(),
            confidence_bps: 9_000,
            classification: crate::sekai::evidence::EvidenceClassification::Internal,
            provenance: Default::default(),
            idempotency_key: format!("delivery-{namespace}-{external_id}"),
            intent: EvidenceIntent::Upsert,
            causality: None,
        }
    }

    fn record_observation(
        runtime: &RuntimeDb,
        namespace: &str,
        id: &str,
        signature: &str,
        occurrence: &str,
        classification: &str,
        created_ms: i64,
    ) {
        let admission = EvidenceAdmissionLifecycle::new(runtime)
            .admit(
                &envelope(
                    namespace,
                    id,
                    signature,
                    occurrence,
                    classification,
                    created_ms,
                ),
                "producer:feedback",
                created_ms,
            )
            .unwrap();
        let evidence_id = admission.submission.id.clone();
        ActionInstanceAdmission::new(runtime, None)
            .admit(
                ActionInstanceAdmissionRequest {
                    agent_turn: None,
                    namespace: namespace.into(),
                    type_id: ACTION_OBSERVATION.into(),
                    version: PACKAGE_VERSION.into(),
                    parameters_json: json!({
                        "object_id": id,
                        "name": signature,
                        "source_evidence": evidence_id,
                        "problem_signature": signature,
                        "occurrence_ids": occurrence,
                        "classification": classification,
                        "disposition": "open"
                    })
                    .to_string(),
                    idempotency_key: format!("obs-{namespace}-{id}"),
                    evidence_submission_ids: vec![evidence_id],
                    request_id: String::new(),
                    ontology_digest: String::new(),
                    autonomous_envelope_id: String::new(),
                    policy_context: PrincipalPolicyContext::default(),
                    delegating_actor: None,
                    budget_already_reserved: false,
                    resource_tenant: String::new(),
                    binding_markings: Vec::new(),
                    source_object_id: String::new(),
                    marking_gate: Default::default(),
                    expected_object_revision: String::new(),
                    offline: None,
                },
                ACTOR,
                created_ms,
            )
            .unwrap();
        let mut stored = runtime.get_object(id).unwrap().unwrap();
        stored.created = created_ms;
        stored.updated = created_ms;
        runtime.update_object(&stored).unwrap();
    }

    fn tenkai_analysis() -> InvestigationAnalysis {
        InvestigationAnalysis {
            observed_facts: vec!["controller retry exhausted".into()],
            hypotheses: vec!["lease fencing dropped".into()],
            impact: "apply cannot finish".into(),
            attribution: Attribution::Tenkai,
            proposed_reproduction: "replay the same plan".into(),
            missing_evidence: Vec::new(),
            independently_verified_reproduction: true,
        }
    }

    fn seed_finding(runtime: &RuntimeDb, prefix: &str, signature: &str, version: &str) -> Object {
        for index in 1..=3 {
            record_observation(
                runtime,
                NAMESPACE,
                &format!("{prefix}-{index}"),
                signature,
                &format!("{prefix}-op-{index}@{version}"),
                "defect",
                1_000 * i64::from(index),
            );
        }
        let cluster = crate::sekai::feedback_investigation::gather_cluster(
            runtime,
            NAMESPACE,
            &format!("{prefix}-3"),
            10_000,
        )
        .unwrap();
        let report =
            record_investigation(runtime, &cluster, &tenkai_analysis(), ACTOR, 10_000).unwrap();
        let mut finding = runtime.get_object(&report.finding_id).unwrap().unwrap();
        finding.created = 10_000;
        finding.updated = 10_000;
        runtime.update_object(&finding).unwrap();
        finding
    }

    fn record_for(report: &EvaluateReport, quality: IssueQuality) -> &QualityRecord {
        report
            .records
            .iter()
            .find(|record| record.quality == quality)
            .unwrap_or_else(|| panic!("missing {quality:?} in {:?}", report.records))
    }

    #[test]
    fn seeded_cases_are_inspectable() {
        let runtime = db();
        let useful = seed_finding(&runtime, "use", "api:timeout", "0.5.0");

        let improved = seed_finding(&runtime, "imp", "deploy:lease", "0.5.0");
        record_observation(
            &runtime,
            NAMESPACE,
            "imp-ok",
            "deploy:lease",
            "imp-op-ok@0.6.0",
            "ok",
            21_000,
        );

        let recurring = seed_finding(&runtime, "rec", "sync:fence", "0.5.0");
        record_observation(
            &runtime,
            NAMESPACE,
            "rec-again",
            "sync:fence",
            "rec-op-again@0.5.0",
            "defect",
            22_000,
        );

        let false_positive = seed_finding(&runtime, "fp", "gate:blocked", "0.5.0");
        record_observation(
            &runtime,
            NAMESPACE,
            "fp-wait",
            "gate:blocked",
            "fp-op-wait@0.5.0",
            "blocked",
            23_000,
        );

        let duplicate_first = seed_finding(&runtime, "dup", "api:dup", "0.5.0");
        let duplicate_second = seed_finding(&runtime, "dup2", "api:dup", "0.5.0");

        let report = evaluate_namespace(&runtime, NAMESPACE, ACTOR, 30_000).unwrap();
        assert!(report.records.len() >= 5);

        let useful_record = report
            .records
            .iter()
            .find(|record| record.finding_id == useful.id)
            .expect("useful");
        assert_eq!(useful_record.quality, IssueQuality::Useful);
        assert_eq!(useful_record.match_class, MatchClass::AbsentTelemetry);
        assert_eq!(useful_record.verification_result, RESULT_INCONCLUSIVE);
        assert!(useful_record.tenkai_versions.contains(&"0.5.0".into()));
        let stored = load_verification(&runtime, &useful_record.verification_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.kind, KIND_VERIFICATION);
        assert_eq!(
            stored.properties.get("quality").map(String::as_str),
            Some("useful")
        );

        let improved_record = report
            .records
            .iter()
            .find(|record| record.finding_id == improved.id)
            .expect("improved");
        assert_eq!(improved_record.quality, IssueQuality::Improved);
        assert_eq!(improved_record.match_class, MatchClass::Recovery);
        assert_eq!(improved_record.verification_result, RESULT_CONFIRMED);
        assert!(improved_record.tenkai_versions.contains(&"0.6.0".into()));

        let recurring_record = report
            .records
            .iter()
            .find(|record| record.finding_id == recurring.id)
            .expect("recurring");
        assert_eq!(recurring_record.quality, IssueQuality::Recurring);
        assert_eq!(recurring_record.match_class, MatchClass::Recurrence);
        assert_eq!(recurring_record.verification_result, RESULT_REFUTED);

        let false_record = report
            .records
            .iter()
            .find(|record| record.finding_id == false_positive.id)
            .expect("false-positive");
        assert_eq!(false_record.quality, IssueQuality::FalsePositive);
        assert_eq!(false_record.match_class, MatchClass::ExpectedWait);
        assert_eq!(false_record.verification_result, RESULT_INCONCLUSIVE);

        let first_dup = report
            .records
            .iter()
            .find(|record| record.finding_id == duplicate_first.id)
            .expect("first dup");
        let second_dup = report
            .records
            .iter()
            .find(|record| record.finding_id == duplicate_second.id)
            .expect("second dup");
        assert_ne!(first_dup.quality, IssueQuality::Duplicate);
        assert_eq!(second_dup.quality, IssueQuality::Duplicate);
        let _ = record_for(&report, IssueQuality::Duplicate);

        let corpus = inspect_quality_corpus(&runtime, NAMESPACE).unwrap();
        let qualities: BTreeSet<_> = corpus.iter().map(|case| case.quality.as_str()).collect();
        assert!(qualities.contains("useful"));
        assert!(qualities.contains("improved"));
        assert!(qualities.contains("recurring"));
        assert!(qualities.contains("false_positive"));
        assert!(qualities.contains("duplicate"));
        assert!(
            corpus
                .iter()
                .all(|case| case.contract_version == QUALITY_CASE_VERSION
                    && case.namespace == NAMESPACE
                    && !case.quality.contains(' ')
                    && redact_quality_text("controller retry exhausted") == "[redacted]")
        );

        let again = evaluate_namespace(&runtime, NAMESPACE, ACTOR, 31_000).unwrap();
        assert_eq!(again.records.len(), report.records.len());
    }

    #[test]
    fn absent_telemetry_does_not_confirm() {
        let runtime = db();
        let finding = seed_finding(&runtime, "abs", "api:gone", "0.5.0");
        record_observation(
            &runtime,
            NAMESPACE,
            "abs-other",
            "other:workload",
            "abs-other-op@0.9.0",
            "defect",
            20_000,
        );
        let report = evaluate_namespace(&runtime, NAMESPACE, ACTOR, 30_000).unwrap();
        let record = report
            .records
            .iter()
            .find(|record| record.finding_id == finding.id)
            .expect("absent");
        assert_eq!(record.match_class, MatchClass::AbsentTelemetry);
        assert_eq!(record.verification_result, RESULT_INCONCLUSIVE);
        assert_ne!(record.verification_result, RESULT_CONFIRMED);
        assert!(!record.tenkai_versions.contains(&"0.9.0".into()));
    }

    #[test]
    fn comparable_success_keeps_versions_and_skips_waits() {
        let original = QualityObservation {
            view: ObservationView {
                object_id: "o-1".into(),
                created_ms: 1,
                problem_signature: "api:timeout".into(),
                occurrence_ids: vec!["op-1@0.5.0".into()],
                classification: "defect".into(),
                disposition: "open".into(),
                source_evidence: "ev".into(),
            },
            tenkai_version: "0.5.0".into(),
        };
        let success = QualityObservation {
            view: ObservationView {
                object_id: "o-2".into(),
                created_ms: 2,
                problem_signature: "api:timeout".into(),
                occurrence_ids: vec!["op-2@0.5.1".into()],
                classification: "ok".into(),
                disposition: "open".into(),
                source_evidence: "ev".into(),
            },
            tenkai_version: "0.5.1".into(),
        };
        let wait = QualityObservation {
            view: ObservationView {
                object_id: "o-3".into(),
                created_ms: 3,
                problem_signature: "api:timeout".into(),
                occurrence_ids: vec!["op-3@0.5.2".into()],
                classification: "blocked".into(),
                disposition: "open".into(),
                source_evidence: "ev".into(),
            },
            tenkai_version: "0.5.2".into(),
        };
        let other = QualityObservation {
            view: ObservationView {
                object_id: "o-4".into(),
                created_ms: 4,
                problem_signature: "batch:other".into(),
                occurrence_ids: vec!["op-4@9.9.9".into()],
                classification: "defect".into(),
                disposition: "open".into(),
                source_evidence: "ev".into(),
            },
            tenkai_version: "9.9.9".into(),
        };
        assert_eq!(operation_class("api:timeout"), "api");
        assert_eq!(occurrence_id("op-2@0.5.1,op-2@0.5.1"), "op-2@0.5.1");
        assert_eq!(
            classify_observation(&original, &success),
            MatchClass::Recovery
        );
        assert_eq!(
            classify_observation(&original, &wait),
            MatchClass::ExpectedWait
        );
        assert_eq!(
            classify_observation(&original, &other),
            MatchClass::UnrelatedWorkload
        );
        let matches = vec![
            ObservationMatch {
                observation_id: "o-2".into(),
                class: MatchClass::Recovery,
                tenkai_version: "0.5.1".into(),
            },
            ObservationMatch {
                observation_id: "o-3".into(),
                class: MatchClass::ExpectedWait,
                tenkai_version: "0.5.2".into(),
            },
            ObservationMatch {
                observation_id: "o-4".into(),
                class: MatchClass::UnrelatedWorkload,
                tenkai_version: "9.9.9".into(),
            },
        ];
        let versions = retain_tenkai_versions(&matches, &original);
        assert_eq!(versions, vec!["0.5.0", "0.5.1"]);
        assert_eq!(
            decide_quality(false, MatchClass::Recovery, &matches),
            IssueQuality::Improved
        );
    }

    #[test]
    fn namespace_isolation_and_no_tracker_or_learning_side_effects() {
        let runtime = db();
        install(&runtime, OTHER, ACTOR, 1_000).unwrap();
        let finding = seed_finding(&runtime, "ns", "api:ns", "0.5.0");
        record_observation(
            &runtime,
            OTHER,
            "other-1",
            "api:ns",
            "other-op@1.0.0",
            "ok",
            20_000,
        );
        let report = evaluate_namespace(&runtime, NAMESPACE, ACTOR, 30_000).unwrap();
        let record = report
            .records
            .iter()
            .find(|record| record.finding_id == finding.id)
            .expect("ns record");
        assert_eq!(record.match_class, MatchClass::AbsentTelemetry);
        assert_eq!(record.verification_result, RESULT_INCONCLUSIVE);
        assert_eq!(record.namespace, NAMESPACE);
        let other = evaluate_namespace(&runtime, OTHER, ACTOR, 30_000).unwrap();
        assert!(
            other
                .records
                .iter()
                .all(|record| record.finding_id != finding.id)
        );
        assert!(
            runtime
                .list_objects(&ListFilter {
                    kind: Some(KIND_VERIFICATION.into()),
                    namespace: Some(NAMESPACE.into()),
                    limit: 16,
                    ..ListFilter::default()
                })
                .unwrap()
                .iter()
                .all(|object| object.namespace == NAMESPACE)
        );
        let control = maintainer_control();
        assert!(!control.close_issue);
        assert!(!control.activate_learning);
        assert!(!control.change_detector_policy);
        assert!(
            inspect_quality_corpus(&runtime, OTHER)
                .unwrap()
                .iter()
                .all(|case| case.namespace == OTHER)
        );
    }
}

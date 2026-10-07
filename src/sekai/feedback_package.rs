//! Versioned evidence and finding domain package (#1230).
//!
//! Types only: ontology classes, ObjectTypes, governed Action types, an
//! evidence schema, and an evaluation member. Live instances are written
//! through existing evidence and `SubmitActionInstance` contracts.
//! Certification is not a runtime grant.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::capability_package::{
    CapabilityPackageCertification, MEMBER_ACTION_TYPE, MEMBER_EVALUATION, MEMBER_ONTOLOGY,
    PACKAGE_CONTRACT, PackageMember, certification_digest_for, certify_package, package_digest_for,
};
use crate::sekai::evidence::{EvidenceIntent, EvidenceLifecycleState};
use crate::sekai::evidence_store::{EvidenceSchemaDefinition, EvidenceSubmissionRecord};
use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
use crate::sekai::schema::{
    ObjectType, PropertyDef, PropertyType, default_property_classification,
};

pub const PACKAGE_ID: &str = "pkg:feedback.evidence-finding/v1";
pub const PACKAGE_VERSION: &str = "1";
pub const CERTIFICATION_ID: &str = "cert:feedback.evidence-finding/v1";
pub const KIND_OBSERVATION: &str = "feedback_observation";
pub const KIND_FINDING: &str = "feedback_finding";
pub const KIND_INVESTIGATION_RESULT: &str = "feedback_investigation_result";
pub const KIND_HYPOTHESIS: &str = "feedback_hypothesis";
pub const KIND_EXTERNAL_ISSUE: &str = "feedback_external_issue";
pub const KIND_VERIFICATION: &str = "feedback_verification";
pub const ACTION_OBSERVATION: &str = "feedback.observation.record";
pub const ACTION_FINDING: &str = "feedback.finding.record";
pub const ACTION_INVESTIGATION: &str = "feedback.investigation.record";
pub const ACTION_HYPOTHESIS: &str = "feedback.hypothesis.record";
pub const ACTION_EXTERNAL_ISSUE: &str = "feedback.external_issue.record";
pub const ACTION_VERIFICATION: &str = "feedback.verification.record";
pub const EVIDENCE_TYPE: &str = "feedback.observation";
pub const EVIDENCE_SCHEMA_VERSION: &str = "1.0.0";

pub const ONTOLOGY_JSON: &str = include_str!("../../tests/fixtures/feedback/ontology-v1.json");
pub const DOMAIN_JSON: &str = include_str!("../../tests/fixtures/feedback/domain-v1.json");
pub const ACTION_TYPES_JSON: &str =
    include_str!("../../tests/fixtures/feedback/action-types-v1.json");
pub const EVALUATION_JSON: &str = include_str!("../../tests/fixtures/feedback/evaluation-v1.json");
pub const EVIDENCE_SCHEMA_JSON: &str =
    include_str!("../../tests/fixtures/feedback/evidence-schema-v1.json");

const MEMBER_ONTOLOGY_ID: &str = "feedback.ontology/v1";
const MEMBER_ACTION_ID: &str = "feedback.actions/v1";
const MEMBER_EVALUATION_ID: &str = "feedback.evaluation/v1";

#[derive(Deserialize)]
struct DomainDocument {
    classes: Vec<DomainClass>,
}

#[derive(Deserialize)]
struct DomainClass {
    mapped_kind: String,
    #[serde(default)]
    kind_description: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    properties: Vec<DomainProperty>,
}

#[derive(Deserialize)]
struct DomainProperty {
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct ActionTypesDocument {
    actions: Vec<ActionTypeFixture>,
}

#[derive(Deserialize)]
struct ActionTypeFixture {
    type_id: String,
    description: String,
    object_kind: String,
    object_mutation: String,
    parameter_schema: serde_json::Value,
}

/// Register package ObjectTypes, Action types, and the evidence schema, then
/// certify the ontology, action-type, and evaluation members.
pub fn install(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<CapabilityPackageCertification, String> {
    register_object_types(db)?;
    register_action_types(db, namespace, actor, now_ms)?;
    register_evidence_schema(db, now_ms)?;
    certify(db, namespace, actor, now_ms)
}

fn register_object_types(db: &RuntimeDb) -> Result<(), String> {
    let document: DomainDocument = serde_json::from_str(DOMAIN_JSON)
        .map_err(|error| format!("feedback domain fixture: {error}"))?;
    for class in document.classes {
        let kind = class.mapped_kind.trim();
        if kind.is_empty() {
            continue;
        }
        let mut object_type = ObjectType {
            kind: kind.to_string(),
            description: if class.kind_description.trim().is_empty() {
                class.description
            } else {
                class.kind_description
            },
            properties: class
                .properties
                .iter()
                .map(object_property)
                .collect::<Result<Vec<_>, _>>()?,
            is_builtin: false,
            implements: Vec::new(),
        };
        if object_type.kind == KIND_VERIFICATION
            && let Some(property) = object_type
                .properties
                .iter_mut()
                .find(|property| property.name == "subject_kind")
        {
            property.prop_type = PropertyType::Enum;
            property.enum_values = vec![KIND_INVESTIGATION_RESULT.into()];
        }
        db.upsert_object_type(&object_type)?;
    }
    Ok(())
}

fn object_property(property: &DomainProperty) -> Result<PropertyDef, String> {
    let prop_type = PropertyType::parse(&property.value_type).ok_or_else(|| {
        format!(
            "unknown feedback property type {} for {}",
            property.value_type, property.name
        )
    })?;
    Ok(PropertyDef {
        name: property.name.clone(),
        prop_type,
        required: property.required,
        description: property.description.clone(),
        enum_values: Vec::new(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: default_property_classification(),
        struct_fields: Vec::new(),
    })
}

fn register_action_types(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<(), String> {
    let document: ActionTypesDocument = serde_json::from_str(ACTION_TYPES_JSON)
        .map_err(|error| format!("feedback action-types fixture: {error}"))?;
    for action in document.actions {
        let parameter_schema_json = serde_json::to_string(&action.parameter_schema)
            .map_err(|error| format!("feedback action parameter schema: {error}"))?;
        db.put_governed_action_type(
            GovernedActionType {
                namespace: namespace.into(),
                type_id: action.type_id,
                version: PACKAGE_VERSION.into(),
                description: action.description,
                parameter_schema_json,
                allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                object_kind: action.object_kind,
                object_mutation: action.object_mutation,
                enabled: true,
                ..Default::default()
            },
            actor,
            now_ms,
        )?;
    }
    Ok(())
}

fn register_evidence_schema(db: &RuntimeDb, now_ms: i64) -> Result<(), String> {
    let definition: EvidenceSchemaDefinition = serde_json::from_str(EVIDENCE_SCHEMA_JSON)
        .map_err(|error| format!("feedback evidence schema fixture: {error}"))?;
    db.register_evidence_schema(&definition, now_ms)
}

fn certify(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<CapabilityPackageCertification, String> {
    let mut members = vec![
        PackageMember {
            kind: MEMBER_ONTOLOGY.into(),
            member_id: MEMBER_ONTOLOGY_ID.into(),
            digest: fixture_digest(ONTOLOGY_JSON.as_bytes()),
        },
        PackageMember {
            kind: MEMBER_ACTION_TYPE.into(),
            member_id: MEMBER_ACTION_ID.into(),
            digest: fixture_digest(ACTION_TYPES_JSON.as_bytes()),
        },
        PackageMember {
            kind: MEMBER_EVALUATION.into(),
            member_id: MEMBER_EVALUATION_ID.into(),
            digest: fixture_digest(EVALUATION_JSON.as_bytes()),
        },
    ];
    members.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then(left.member_id.cmp(&right.member_id))
    });
    let compatibility = vec![
        "sekai.evidence/v1".into(),
        "sekai.governed-action/v1".into(),
        "sekai.ontology-product/v1".into(),
    ];
    let package_digest = package_digest_for(PACKAGE_ID, &members, &compatibility)?;
    let mut certification = CapabilityPackageCertification {
        contract_version: PACKAGE_CONTRACT.into(),
        certification_id: CERTIFICATION_ID.into(),
        namespace: namespace.into(),
        owner: actor.into(),
        package_id: PACKAGE_ID.into(),
        package_digest: package_digest.clone(),
        signer_id: actor.into(),
        signer_digest: fixture_digest(actor.as_bytes()),
        members,
        compatibility,
        test_suite_digest: fixture_digest(b"feedback-package-suite/v1"),
        test_result_digest: fixture_digest(b"feedback-package-pass/v1"),
        revocation: String::new(),
        revocation_reason: String::new(),
        revoked_at_ms: 0,
        predecessor_id: String::new(),
        superseded_by: String::new(),
        certification_digest: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    };
    certification.certification_digest = certification_digest_for(&certification, &package_digest)?;
    certify_package(db, actor, &certification, now_ms)
}

fn fixture_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Package write rules on top of ObjectType schema: observations require
/// accepted source evidence with a unique namespace/external identity, and
/// verification subjects must be measured investigation results.
pub(crate) fn validate_object_write(
    db: &RuntimeDb,
    object: &mut Object,
    now_ms: i64,
) -> Result<(), String> {
    match object.kind.as_str() {
        KIND_OBSERVATION => validate_observation_evidence(db, object, now_ms),
        KIND_VERIFICATION => validate_verification_subject(db, object),
        _ => Ok(()),
    }
}

fn validate_observation_evidence(
    db: &RuntimeDb,
    object: &mut Object,
    now_ms: i64,
) -> Result<(), String> {
    let evidence_id = object
        .properties
        .get("source_evidence")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "source_evidence is required".to_string())?
        .to_string();
    let submission = db
        .get_evidence_submission(&evidence_id)?
        .ok_or_else(|| format!("unknown source evidence {evidence_id}"))?;
    require_usable_source_evidence(&submission, now_ms)?;
    if submission.namespace != object.namespace {
        return Err("source evidence is not in the observation namespace".into());
    }
    if submission.target_kind != KIND_OBSERVATION {
        return Err("source evidence does not target an observation".into());
    }
    // Plan-time check for a precise error. Commit uniqueness is the partial
    // unique index on observation (namespace, external_id).
    for existing in db.find_all_by_external_id(&submission.target_external_id)? {
        if existing.namespace == object.namespace && existing.id != object.id {
            return Err(format!(
                "observation external identity {} already exists as {}",
                submission.target_external_id, existing.id
            ));
        }
    }
    object.external_id = submission.target_external_id;
    Ok(())
}

fn require_usable_source_evidence(
    submission: &EvidenceSubmissionRecord,
    now_ms: i64,
) -> Result<(), String> {
    if submission.intent != EvidenceIntent::Upsert {
        return Err(format!("source evidence {} is not accepted", submission.id));
    }
    let awaiting_target = submission.lifecycle_state == EvidenceLifecycleState::Quarantined
        && submission.rejection_code.as_deref() == Some("projection_target_missing");
    let accepted = submission.rejection_code.is_none()
        && matches!(
            submission.lifecycle_state,
            EvidenceLifecycleState::Authorized
                | EvidenceLifecycleState::Projected
                | EvidenceLifecycleState::Available
        );
    if !accepted && !awaiting_target {
        return Err(format!("source evidence {} is not accepted", submission.id));
    }
    if submission
        .expires_at_ms
        .is_some_and(|expires_at| expires_at <= now_ms)
    {
        return Err(format!("source evidence {} has expired", submission.id));
    }
    Ok(())
}

/// Retry evidence projection after admission is durable so a compensated
/// observation write cannot leave projected evidence pointing at a deleted
/// object.
pub(crate) fn complete_object_write(db: &RuntimeDb, object: &Object, now_ms: i64) {
    if object.kind != KIND_OBSERVATION {
        return;
    }
    let Some(evidence_id) = object.properties.get("source_evidence") else {
        return;
    };
    let _ = db.project_evidence_submission(evidence_id, now_ms);
}

fn validate_verification_subject(db: &RuntimeDb, object: &Object) -> Result<(), String> {
    let subject_id = object
        .properties
        .get("subject_id")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "subject_id is required".to_string())?;
    let claimed_kind = object
        .properties
        .get("subject_kind")
        .map(String::as_str)
        .unwrap_or_default();
    if claimed_kind != KIND_INVESTIGATION_RESULT {
        return Err("verification subject_kind must be feedback_investigation_result".into());
    }
    let subject = db
        .get_object(subject_id)?
        .ok_or_else(|| format!("verification subject {subject_id} not found"))?;
    if subject.namespace != object.namespace {
        return Err("verification subject is not in the verification namespace".into());
    }
    if subject.kind != KIND_INVESTIGATION_RESULT {
        return Err("verification subject is not an investigation result".into());
    }
    if subject.properties.get("measured").map(String::as_str) != Some("true") {
        return Err("verification subject is not a measured investigation result".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::domain::Object;
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
    };
    use crate::sekai::capability_package::{get_package, verify_package};
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceEnvelope, EvidenceIntent, EvidenceLifecycleState,
        EvidenceSignal, EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle;
    use crate::sekai::evidence_store::{EvidenceProducerCapability, canonical_content_digest};
    use crate::sekai::object_security::PrincipalPolicyContext;
    use sekai_ontology::{Ontology, SqliteOntology};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier};
    use std::thread;

    const NAMESPACE: &str = "ops";
    const ACTOR: &str = "reviewer";
    const ONTOLOGY_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn installed() -> RuntimeDb {
        let runtime = db();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        runtime
    }

    fn installed_file() -> (tempfile::TempDir, RuntimeDb) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let runtime = RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(path.to_str().expect("utf-8 path")).expect("file sqlite"),
        ));
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        (dir, runtime)
    }

    fn observation_object(id: &str, external_id: &str) -> Object {
        Object {
            id: id.into(),
            kind: KIND_OBSERVATION.into(),
            name: id.into(),
            namespace: NAMESPACE.into(),
            external_id: external_id.into(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        }
    }

    fn producer() -> EvidenceProducerCapability {
        EvidenceProducerCapability {
            producer_identity: "producer:feedback".into(),
            config_version: 1,
            source_types: vec!["feedback_source".into()],
            source_instances: vec!["feedback:checks".into()],
            namespaces: vec![NAMESPACE.into()],
            evidence_types: vec![EVIDENCE_TYPE.into()],
            target_kinds: vec![KIND_OBSERVATION.into()],
            classification_ceiling: crate::sekai::evidence::EvidenceClassification::Confidential,
            allowed_intents: vec![
                EvidenceIntent::Upsert,
                EvidenceIntent::Retract,
                EvidenceIntent::MarkStale,
            ],
            allow_operation_attachment: true,
            replay_window_ms: 10_000,
            max_clock_skew_ms: 1_000,
            max_payload_bytes: 4_096,
            max_relationships: 4,
            rate_limit_per_minute: 20,
            max_retained_submissions: 100,
            revoked: false,
        }
    }

    fn observation_envelope() -> EvidenceEnvelope {
        let content = json!({
            "problem_signature": "sig:timeout",
            "occurrence_ids": "occ-1,occ-2",
            "classification": "defect",
            "disposition": "open"
        });
        EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "feedback_source".into(),
            source_instance: "feedback:checks".into(),
            source_record_id: "run-1".into(),
            source_version: "attempt-1".into(),
            source_sequence: 1,
            target: EvidenceTarget {
                namespace: NAMESPACE.into(),
                object_external_id: "obs-1".into(),
                object_kind: KIND_OBSERVATION.into(),
            },
            evidence_type: EVIDENCE_TYPE.into(),
            signal: EvidenceSignal::OperationalHealth,
            schema_id: EVIDENCE_TYPE.into(),
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: 1_000,
            collected_at_ms: 1_010,
            expires_at_ms: Some(60_000),
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: "producer:feedback".into(),
            confidence_bps: 9_000,
            classification: crate::sekai::evidence::EvidenceClassification::Internal,
            provenance: BTreeMap::new(),
            idempotency_key: "delivery-1".into(),
            intent: EvidenceIntent::Upsert,
            causality: None,
        }
    }

    fn admit_source_evidence(
        runtime: &RuntimeDb,
        envelope: &EvidenceEnvelope,
        now_ms: i64,
    ) -> crate::sekai::evidence_admission_lifecycle::EvidenceAdmissionOutcome {
        EvidenceAdmissionLifecycle::new(runtime)
            .admit(envelope, "producer:feedback", now_ms)
            .unwrap()
    }

    fn admit_request(
        type_id: &str,
        parameters_json: &str,
        idempotency_key: &str,
        evidence_ids: Vec<String>,
    ) -> ActionInstanceAdmissionRequest {
        ActionInstanceAdmissionRequest {
            namespace: NAMESPACE.into(),
            type_id: type_id.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: parameters_json.into(),
            idempotency_key: idempotency_key.into(),
            evidence_submission_ids: evidence_ids,
            request_id: String::new(),
            ontology_digest: ONTOLOGY_DIGEST.into(),
            autonomous_envelope_id: String::new(),
            policy_context: PrincipalPolicyContext::default(),
            budget_already_reserved: false,
        }
    }

    #[test]
    fn portable_ontology_imports_with_validation_and_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feedback-ontology.db");
        let mut ontology = SqliteOntology::initialize(&path).unwrap();
        ontology.import_json(ONTOLOGY_JSON).unwrap();
        let issues = ontology.validate().unwrap();
        assert!(issues.is_empty(), "{issues:?}");
        let exported = ontology.export().unwrap();
        assert!(exported.classes.iter().any(|class| {
            class.name == "Hypothesis"
                && class
                    .disjoint_classes
                    .contains(&"InvestigationResult".into())
                && class
                    .disjoint_classes
                    .contains(&"VerificationRecord".into())
        }));
        assert!(
            exported
                .provenance
                .iter()
                .any(|record| record.subject == "Hypothesis" && !record.source.is_empty())
        );
    }

    #[test]
    fn package_certifies_ontology_action_and_evaluation_members() {
        let runtime = installed();
        let certified = get_package(&runtime, ACTOR, NAMESPACE, CERTIFICATION_ID).unwrap();
        assert_eq!(certified.package_id, PACKAGE_ID);
        let kinds: Vec<_> = certified
            .members
            .iter()
            .map(|member| member.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            [MEMBER_ACTION_TYPE, MEMBER_EVALUATION, MEMBER_ONTOLOGY]
        );
        verify_package(&runtime, ACTOR, NAMESPACE, CERTIFICATION_ID, &certified).unwrap();
        assert!(runtime.get_object_type(KIND_OBSERVATION).unwrap().is_some());
        assert!(runtime.get_object_type(KIND_HYPOTHESIS).unwrap().is_some());
        let verification = runtime
            .get_object_type(KIND_VERIFICATION)
            .unwrap()
            .expect("verification kind");
        let subject_kind = verification
            .properties
            .iter()
            .find(|property| property.name == "subject_kind")
            .expect("subject_kind");
        assert_eq!(subject_kind.enum_values, [KIND_INVESTIGATION_RESULT]);
    }

    #[test]
    fn accepted_evidence_then_observation_action_retains_lineage_fields() {
        let runtime = installed();
        runtime
            .upsert_evidence_producer(&producer(), 1_000)
            .unwrap();
        let admission = admit_source_evidence(&runtime, &observation_envelope(), 1_100);
        assert!(admission.admitted);
        assert_eq!(
            admission.submission.lifecycle_state,
            EvidenceLifecycleState::Quarantined
        );
        assert_eq!(
            admission.submission.rejection_code.as_deref(),
            Some("projection_target_missing")
        );
        let evidence_id = admission.submission.id.clone();
        let parameters = serde_json::json!({
            "object_id": "obs-1",
            "name": "timeout",
            "source_evidence": evidence_id,
            "problem_signature": "sig:timeout",
            "occurrence_ids": "occ-1,occ-2",
            "classification": "defect",
            "disposition": "open"
        });
        ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_OBSERVATION,
                    &parameters.to_string(),
                    "obs-admit-1",
                    vec![evidence_id.clone()],
                ),
                ACTOR,
                2_000,
            )
            .unwrap();
        let stored = runtime.get_object("obs-1").unwrap().expect("observation");
        assert_eq!(stored.kind, KIND_OBSERVATION);
        assert_eq!(stored.namespace, NAMESPACE);
        assert_eq!(stored.external_id, "obs-1");
        let projected = runtime
            .get_evidence_submission(&evidence_id)
            .unwrap()
            .expect("projected evidence");
        assert_eq!(projected.lifecycle_state, EvidenceLifecycleState::Available);
        assert!(projected.rejection_code.is_none());
        assert_eq!(
            stored.properties.get("source_evidence").map(String::as_str),
            Some(evidence_id.as_str())
        );
        assert_eq!(
            stored
                .properties
                .get("problem_signature")
                .map(String::as_str),
            Some("sig:timeout")
        );
        assert_eq!(
            stored.properties.get("occurrence_ids").map(String::as_str),
            Some("occ-1,occ-2")
        );
        assert_eq!(
            stored.properties.get("classification").map(String::as_str),
            Some("defect")
        );
        assert_eq!(
            stored.properties.get("disposition").map(String::as_str),
            Some("open")
        );
    }

    #[test]
    fn observation_action_rejects_missing_required_properties() {
        let runtime = installed();
        let error = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_OBSERVATION,
                    r#"{"object_id":"obs-missing","name":"timeout"}"#,
                    "obs-missing",
                    vec![],
                ),
                ACTOR,
                2_000,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::InvalidArgument(_)
        ));
        assert!(runtime.get_object("obs-missing").unwrap().is_none());
    }

    #[test]
    fn observation_action_requires_accepted_source_evidence() {
        let runtime = installed();
        runtime
            .upsert_evidence_producer(&producer(), 1_000)
            .unwrap();
        let error = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_OBSERVATION,
                    r#"{"object_id":"obs-1","name":"timeout","source_evidence":"missing","problem_signature":"sig:timeout","occurrence_ids":"occ-1","classification":"defect","disposition":"open"}"#,
                    "obs-no-evidence",
                    vec![],
                ),
                ACTOR,
                2_000,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert!(runtime.get_object("obs-1").unwrap().is_none());

        let mut invalid = observation_envelope();
        invalid.content_digest = "0".repeat(64);
        let rejected = runtime
            .submit_evidence(&invalid, "producer:feedback", 1_100)
            .unwrap();
        assert!(!rejected.accepted);
        let parameters = serde_json::json!({
            "object_id": "obs-1",
            "name": "timeout",
            "source_evidence": rejected.submission.id,
            "problem_signature": "sig:timeout",
            "occurrence_ids": "occ-1",
            "classification": "defect",
            "disposition": "open"
        });
        let error = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_OBSERVATION,
                    &parameters.to_string(),
                    "obs-rejected-evidence",
                    vec![rejected.submission.id.clone()],
                ),
                ACTOR,
                2_000,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert!(runtime.get_object("obs-1").unwrap().is_none());

        let mut expired = observation_envelope();
        expired.idempotency_key = "delivery-expired".into();
        expired.source_record_id = "run-expired".into();
        expired.expires_at_ms = Some(1_500);
        let accepted = runtime
            .submit_evidence(&expired, "producer:feedback", 1_100)
            .unwrap();
        assert!(accepted.accepted);
        let parameters = serde_json::json!({
            "object_id": "obs-1",
            "name": "timeout",
            "source_evidence": accepted.submission.id,
            "problem_signature": "sig:timeout",
            "occurrence_ids": "occ-1",
            "classification": "defect",
            "disposition": "open"
        });
        let error = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_OBSERVATION,
                    &parameters.to_string(),
                    "obs-expired-evidence",
                    vec![accepted.submission.id.clone()],
                ),
                ACTOR,
                2_000,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert!(runtime.get_object("obs-1").unwrap().is_none());
    }

    #[test]
    fn observation_action_rejects_duplicate_external_identity() {
        let runtime = installed();
        runtime
            .upsert_evidence_producer(&producer(), 1_000)
            .unwrap();
        let admission = admit_source_evidence(&runtime, &observation_envelope(), 1_100);
        assert!(admission.admitted);
        let evidence_id = admission.submission.id.clone();
        let first = serde_json::json!({
            "object_id": "obs-1",
            "name": "timeout",
            "source_evidence": evidence_id,
            "problem_signature": "sig:timeout",
            "occurrence_ids": "occ-1",
            "classification": "defect",
            "disposition": "open"
        });
        ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_OBSERVATION,
                    &first.to_string(),
                    "obs-admit-1",
                    vec![evidence_id.clone()],
                ),
                ACTOR,
                2_000,
            )
            .unwrap();
        let duplicate = serde_json::json!({
            "object_id": "obs-2",
            "name": "timeout-copy",
            "source_evidence": evidence_id,
            "problem_signature": "sig:timeout",
            "occurrence_ids": "occ-1",
            "classification": "defect",
            "disposition": "open"
        });
        let error = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_OBSERVATION,
                    &duplicate.to_string(),
                    "obs-admit-2",
                    vec![evidence_id.clone()],
                ),
                ACTOR,
                2_100,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert!(runtime.get_object("obs-2").unwrap().is_none());
        assert_eq!(
            runtime
                .get_object("obs-1")
                .unwrap()
                .expect("first observation")
                .external_id,
            "obs-1"
        );
    }

    #[test]
    fn observation_store_rejects_duplicate_external_identity_without_plan_time() {
        let runtime = db();
        runtime
            .create_object_with_audit(&observation_object("obs-1", "obs-1"), ACTOR)
            .unwrap();
        let error = runtime
            .create_object_with_audit(&observation_object("obs-2", "obs-1"), ACTOR)
            .unwrap_err();
        assert!(
            error.contains("UNIQUE constraint failed")
                || error.contains("duplicate key value violates unique constraint"),
            "{error}"
        );
        assert!(runtime.get_object("obs-2").unwrap().is_none());
        let mut other_ns = observation_object("obs-ns2", "obs-1");
        other_ns.namespace = "other".into();
        runtime.create_object_with_audit(&other_ns, ACTOR).unwrap();
        let mut gadget = observation_object("gadget-1", "");
        gadget.kind = "gadget".into();
        runtime.create_object_with_audit(&gadget, ACTOR).unwrap();
        let mut gadget_two = observation_object("gadget-2", "");
        gadget_two.kind = "gadget".into();
        runtime
            .create_object_with_audit(&gadget_two, ACTOR)
            .unwrap();
    }

    #[test]
    fn concurrent_observation_admits_keep_one_external_identity() {
        let (_dir, runtime) = installed_file();
        let runtime = Arc::new(runtime);
        runtime
            .upsert_evidence_producer(&producer(), 1_000)
            .unwrap();
        let admission = admit_source_evidence(&runtime, &observation_envelope(), 1_100);
        assert!(admission.admitted);
        let evidence_id = admission.submission.id.clone();
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = ["obs-a", "obs-b"]
            .into_iter()
            .map(|object_id| {
                let runtime = Arc::clone(&runtime);
                let evidence_id = evidence_id.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let parameters = json!({
                        "object_id": object_id,
                        "name": object_id,
                        "source_evidence": evidence_id,
                        "problem_signature": "sig:timeout",
                        "occurrence_ids": "occ-1",
                        "classification": "defect",
                        "disposition": "open"
                    });
                    barrier.wait();
                    ActionInstanceAdmission::new(runtime.as_ref(), None).admit(
                        admit_request(
                            ACTION_OBSERVATION,
                            &parameters.to_string(),
                            &format!("obs-admit-{object_id}"),
                            vec![evidence_id],
                        ),
                        ACTOR,
                        2_000,
                    )
                })
            })
            .collect();
        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect();
        let wins = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        let losses = outcomes.iter().filter(|outcome| outcome.is_err()).count();
        assert_eq!(wins, 1, "{outcomes:?}");
        assert_eq!(losses, 1, "{outcomes:?}");
        assert!(
            outcomes.iter().any(|outcome| matches!(
                outcome,
                Err(ActionInstanceAdmissionError::FailedPrecondition(_))
            )),
            "{outcomes:?}"
        );
        let stored: Vec<_> = ["obs-a", "obs-b"]
            .into_iter()
            .filter_map(|id| runtime.get_object(id).unwrap())
            .collect();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].external_id, "obs-1");
    }

    #[test]
    fn invalid_stale_conflicting_and_unauthorized_evidence_does_not_create_observation() {
        let runtime = installed();
        runtime
            .upsert_evidence_producer(&producer(), 1_000)
            .unwrap();

        let mut invalid = observation_envelope();
        invalid.content_digest = "0".repeat(64);
        invalid.idempotency_key = "delivery-invalid".into();
        let rejected = runtime
            .submit_evidence(&invalid, "producer:feedback", 1_100)
            .unwrap();
        assert!(!rejected.accepted);
        assert_eq!(
            rejected.submission.rejection_code.as_deref(),
            Some("digest_mismatch")
        );

        let mut stale = observation_envelope();
        stale.idempotency_key = "delivery-stale".into();
        stale.source_record_id = "run-stale".into();
        let rejected = runtime
            .submit_evidence(&stale, "producer:feedback", 20_000)
            .unwrap();
        assert!(!rejected.accepted);
        assert_eq!(
            rejected.submission.rejection_code.as_deref(),
            Some("replay_window_expired")
        );

        let first = runtime
            .submit_evidence(&observation_envelope(), "producer:feedback", 1_100)
            .unwrap();
        assert!(first.accepted);
        let mut conflicting = observation_envelope();
        conflicting.content = json!({"problem_signature": "other"});
        conflicting.content_digest = canonical_content_digest(&conflicting.content).unwrap();
        let rejected = runtime
            .submit_evidence(&conflicting, "producer:feedback", 1_200)
            .unwrap();
        assert!(!rejected.accepted);
        assert_eq!(
            rejected.submission.rejection_code.as_deref(),
            Some("idempotency_conflict")
        );

        let mut unauthorized = observation_envelope();
        unauthorized.idempotency_key = "delivery-unauthorized".into();
        unauthorized.source_record_id = "run-unauth".into();
        unauthorized.target.namespace = "other".into();
        let rejected = runtime
            .submit_evidence(&unauthorized, "producer:feedback", 1_100)
            .unwrap();
        assert!(!rejected.accepted);
        assert_eq!(
            rejected.submission.rejection_code.as_deref(),
            Some("namespace_forbidden")
        );

        assert!(runtime.get_object("obs-1").unwrap().is_none());
    }

    #[test]
    fn hypothesis_cannot_satisfy_verification_subject_kind() {
        let runtime = installed();
        let hypothesis = serde_json::json!({
            "object_id": "hyp-1",
            "name": "maybe cache",
            "observation_id": "obs-1",
            "statement": "cache expiry"
        });
        ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(ACTION_HYPOTHESIS, &hypothesis.to_string(), "hyp-1", vec![]),
                ACTOR,
                2_000,
            )
            .unwrap();
        assert_eq!(
            runtime
                .get_object("hyp-1")
                .unwrap()
                .expect("hypothesis")
                .kind,
            KIND_HYPOTHESIS
        );

        let error = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_VERIFICATION,
                    r#"{"object_id":"ver-1","name":"check","subject_id":"hyp-1","subject_kind":"feedback_hypothesis","result":"confirmed"}"#,
                    "ver-hyp",
                    vec![],
                ),
                ACTOR,
                3_000,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::InvalidArgument(_)
        ));
        assert!(runtime.get_object("ver-1").unwrap().is_none());

        let error = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_VERIFICATION,
                    r#"{"object_id":"ver-lie","name":"check","subject_id":"hyp-1","subject_kind":"feedback_investigation_result","result":"confirmed"}"#,
                    "ver-lie",
                    vec![],
                ),
                ACTOR,
                3_100,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert!(runtime.get_object("ver-lie").unwrap().is_none());

        let unmeasured = serde_json::json!({
            "object_id": "inv-unmeasured",
            "name": "guess",
            "observation_id": "obs-1",
            "outcome": "reproduced",
            "measured": false
        });
        ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_INVESTIGATION,
                    &unmeasured.to_string(),
                    "inv-unmeasured",
                    vec![],
                ),
                ACTOR,
                3_200,
            )
            .unwrap();
        let error = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_VERIFICATION,
                    r#"{"object_id":"ver-unmeasured","name":"check","subject_id":"inv-unmeasured","subject_kind":"feedback_investigation_result","result":"confirmed"}"#,
                    "ver-unmeasured",
                    vec![],
                ),
                ACTOR,
                3_300,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::FailedPrecondition(_)
        ));
        assert!(runtime.get_object("ver-unmeasured").unwrap().is_none());

        let investigation = serde_json::json!({
            "object_id": "inv-1",
            "name": "measured",
            "observation_id": "obs-1",
            "outcome": "reproduced",
            "measured": true
        });
        ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_INVESTIGATION,
                    &investigation.to_string(),
                    "inv-1",
                    vec![],
                ),
                ACTOR,
                4_000,
            )
            .unwrap();
        ActionInstanceAdmission::new(&runtime, None)
            .admit(
                admit_request(
                    ACTION_VERIFICATION,
                    r#"{"object_id":"ver-2","name":"check","subject_id":"inv-1","subject_kind":"feedback_investigation_result","result":"confirmed"}"#,
                    "ver-inv",
                    vec![],
                ),
                ACTOR,
                5_000,
            )
            .unwrap();
        let stored = runtime.get_object("ver-2").unwrap().expect("verification");
        assert_eq!(stored.kind, KIND_VERIFICATION);
        assert_eq!(
            stored.properties.get("subject_kind").map(String::as_str),
            Some(KIND_INVESTIGATION_RESULT)
        );
    }
}

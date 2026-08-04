//! Deterministic, domain-local replication fixture for the epistemic surfaces.
//!
//! This example deliberately keeps ResearchQuestion/Claim/Protocol/etc. in a
//! versioned package under `examples/`. The control plane sees only its normal
//! schema, evidence, governed-subject, evaluation, receipt, policy, and Kioku
//! contracts.

use sekai_chisei::chisei::epistemic_descriptor::{
    EpistemicDescriptor, EvidenceStatus, LifecycleStatus,
};
use sekai_chisei::chisei::epistemic_eval::{
    CLAIM_ONLY_CONTEXT_VARIANT, EPISTEMIC_CASE_EVIDENCE_CONTRACT, EPISTEMIC_EVALUATION_CONTRACT,
    EPISTEMIC_FRAMED_CONTEXT_VARIANT, EpistemicCaseAuthority, EpistemicCaseEvidence,
    EpistemicComparisonReport, EpistemicOutcomeEvidence, EpistemicReceiptEvidence,
    EpistemicRegressionPolicy, FIXTURE_CONTESTED, FIXTURE_HIGH_CONFIDENCE_WRONG,
    FIXTURE_INSUFFICIENT, FIXTURE_IRRELEVANT, FIXTURE_STALE, FIXTURE_SUPPORTING_ONLY,
    canonical_epistemic_outcome_digest, canonical_epistemic_receipt_digest, compare_epistemic_runs,
};
use sekai_chisei::chisei::eval::{Case, CaseResult, EvalStore, Run, Suite};
use sekai_chisei::chisei::evaluation_execution::{
    EVALUATOR_RESULT_CONTRACT, EvaluationGateDecision, EvaluationStepReceipt,
    SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST,
    SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE,
};
use sekai_chisei::chisei::evaluation_manifest::ResolvedEvaluationManifest;
use sekai_chisei::chisei::evaluation_plan::{
    DETERMINISTIC_EXECUTION_CLASS, EVALUATION_PLAN_CONTRACT, EVALUATOR_DEFINITION_CONTRACT,
    EvaluationInputBinding, EvaluationPlan, EvaluationPlanNode, EvaluatorDefinition,
    EvaluatorResourceLimits, FIXED_REDUCER, INPUT_INVARIANT, NODE_REQUIRED, prepare_definition,
    prepare_plan,
};
use sekai_chisei::chisei::governed_subject::{
    ALLOW_PROFILE, ENVELOPE_VERSION, GovernedSubjectEnvelope, GovernedSubjectReference,
    SOFTWARE_RELEASE_PROFILE, SoftwareReleaseCandidate, binding_digest,
    evaluation as evaluate_subject, operation_id, validate_envelope,
};
use sekai_chisei::chisei::kioku::{
    CandidateDerivation, HumanMemoryReview, HumanReviewAction, KiokuEvidenceBasis,
    KiokuEvidenceReassessmentRequest, MemoryEvidenceStance, MemoryKind, MemoryLifecycleEvent,
    MemoryLifecycleState, MemoryOutcomeObservation, VerifiedOutcome,
};
use sekai_chisei::chisei::policy::{
    CONTEXT_ADMISSION_POLICY_VERSION, ContextAdmissionAction, ContextAdmissionPolicy,
    ContextAdmissionRule, OperationRisk,
};
use sekai_chisei::chisei::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind,
};
use sekai_chisei::config::Config;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::domain::Object;
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::pb::chisei::{
    self, chisei_service_server::ChiseiService as ChiseiGrpcService,
};
use sekai_chisei::sekai::evidence::{
    EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
    EvidenceLifecycleState, EvidenceSignal, EvidenceTarget, SchemaCompatibility,
};
use sekai_chisei::sekai::evidence_store::{
    EvidenceProducerCapability, EvidenceSchemaDefinition, EvidenceSubmissionRecord,
    canonical_content_digest,
};
use sekai_chisei::sekai::governed_facts::{self, GovernedFactType};
use sekai_chisei::sekai::schema::{ObjectType, PropertyDef, PropertyType};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tonic::Request;

const CONTRACT_VERSION: &str = "example.epistemic-replication/v1";
const DOMAIN_CONTRACT_VERSION: &str = "example.epistemic-replication-domain/v1";
const SCHEMA_PACKAGE: &str = include_str!("epistemic-replication/profile-v1.json");
const EXECUTABLE_SOURCE: &str = include_str!("epistemic_replication.rs");
const NAMESPACE: &str = "replication-fixture";
const ACTOR: &str = "example.operator";
const PRODUCER_A: &str = "replication-lab-a/v1";
const PRODUCER_B: &str = "replication-lab-b/v1";
const SOURCE_TYPE: &str = "replication_lab";
const EVIDENCE_TYPE: &str = "replication.result";
const EVIDENCE_SCHEMA: &str = "example.epistemic-replication.result";
const CLAIM_EXTERNAL_ID: &str = "claim:replication-001";
const CLAIM_OBJECT_ID: &str = "claim-1";
const CLAIM_IDENTITY: &str = "claim-replication-001";
const REPLICATION_CLAIM_PROFILE: &str = "replication.claim/v1";
const PROTOCOL_ID: &str = "protocol-replication-v1";
const ARTIFACT_ID: &str = "artifact-replication-code-v1";
const OUTCOME_METRIC: &str = "replication_success";
const NOW_MS: i64 = 1_700_000_100_000;
const OBSERVED_AT_MS: i64 = 1_700_000_000_000;
const EVALUATION_AT_MS: i64 = NOW_MS + 100;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DomainSchemaPackage {
    contract_version: String,
    schema_id: String,
    version: String,
    classes: Vec<DomainClass>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DomainClass {
    name: String,
    description: String,
    properties: Vec<DomainProperty>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DomainProperty {
    name: String,
    property_type: String,
    required: bool,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Clone, Copy)]
struct ArmMetrics {
    task_success: bool,
    unsupported_claim_count: u32,
    claim_count: u32,
    contradiction_present: bool,
    contradiction_handled: bool,
    expected_confidence_micros: u32,
    observed_confidence_micros: u32,
    input_tokens: u32,
    output_tokens: u32,
    latency_ms: u64,
    context_admitted: bool,
    provider_blocked: bool,
}

#[derive(Debug, Clone, Copy)]
struct PersistedCaseMetrics {
    task_success: bool,
    unsupported_claim_count: u32,
    claim_count: u32,
    contradiction_present: bool,
    contradiction_handled: bool,
    expected_confidence_micros: u32,
    observed_confidence_micros: u32,
    input_tokens: u32,
    output_tokens: u32,
    latency_ms: u64,
    context_admitted: bool,
    provider_blocked: bool,
}

#[derive(Debug, Clone)]
struct FixtureCase {
    id: &'static str,
    kind: &'static str,
}

struct EpistemicFixtureContext<'a> {
    claim_digest: &'a str,
    claim_only_policy: &'a ContextAdmissionPolicy,
    epistemic_policy: &'a ContextAdmissionPolicy,
    supporting: &'a EpistemicDescriptor,
    contested: &'a EpistemicDescriptor,
    insufficient: &'a EpistemicDescriptor,
    stale: &'a EpistemicDescriptor,
    retracted: &'a EpistemicDescriptor,
}

impl EpistemicFixtureContext<'_> {
    fn applicability_for(kind: &str) -> &'static str {
        if kind == FIXTURE_IRRELEVANT {
            "unrelated"
        } else {
            "replication"
        }
    }

    fn descriptor_for(&self, kind: &str) -> Result<&EpistemicDescriptor, String> {
        match kind {
            FIXTURE_SUPPORTING_ONLY | FIXTURE_IRRELEVANT => Ok(self.supporting),
            FIXTURE_CONTESTED => Ok(self.contested),
            FIXTURE_INSUFFICIENT => Ok(self.insufficient),
            FIXTURE_STALE => Ok(self.stale),
            FIXTURE_HIGH_CONFIDENCE_WRONG => Ok(self.retracted),
            other => Err(format!("unknown epistemic fixture kind: {other}")),
        }
    }

    fn policy_for_variant(&self, variant: &str) -> Result<&ContextAdmissionPolicy, String> {
        match variant {
            CLAIM_ONLY_CONTEXT_VARIANT => Ok(self.claim_only_policy),
            EPISTEMIC_FRAMED_CONTEXT_VARIANT => Ok(self.epistemic_policy),
            other => Err(format!("unknown context variant: {other}")),
        }
    }

    fn operation_risk_for(kind: &str) -> OperationRisk {
        if matches!(kind, FIXTURE_CONTESTED | FIXTURE_HIGH_CONFIDENCE_WRONG) {
            OperationRisk::High
        } else {
            OperationRisk::Low
        }
    }

    fn stable_descriptor(descriptor: &EpistemicDescriptor) -> Value {
        json!({
            "contract_version": descriptor.contract_version,
            "origin_class": descriptor.origin_class,
            "evidence_status": descriptor.evidence_status,
            "lifecycle_status": descriptor.lifecycle_status,
            "producer_confidence_bps": descriptor.producer_confidence_bps,
            "confidence_basis": descriptor.confidence_basis,
            "observed_at_ms": descriptor.observed_at_ms,
            "derivation_ref": descriptor.derivation_ref,
            "source_digests": descriptor.source_digests,
            "source_row_count": descriptor.source_row_count,
            "source_rows_truncated": descriptor.source_rows_truncated,
            "supporting_evidence_count": descriptor.supporting_evidence_count,
            "contradicting_evidence_count": descriptor.contradicting_evidence_count,
        })
    }

    fn case_digest(&self, case: &FixtureCase) -> Result<String, String> {
        // The two arms deliberately share one authorized, post-review memory
        // snapshot. Only the context configuration (claim-only versus
        // epistemic-framed admission policy) may differ.
        let descriptor = self.descriptor_for(case.kind)?;
        let claim_only_policy = self.policy_for_variant(CLAIM_ONLY_CONTEXT_VARIANT)?;
        let epistemic_policy = self.policy_for_variant(EPISTEMIC_FRAMED_CONTEXT_VARIANT)?;
        let baseline_decision = claim_only_policy.decide(
            descriptor,
            Some(Self::applicability_for(case.kind)),
            Self::operation_risk_for(case.kind),
        )?;
        let candidate_decision = epistemic_policy.decide(
            descriptor,
            Some(Self::applicability_for(case.kind)),
            Self::operation_risk_for(case.kind),
        )?;
        // External submission IDs are UUIDs allocated at admission time. Bind
        // the case to stable descriptor facts and content digests, not those
        // transport identities, so a fresh local run has the same fixture ID.
        Ok(digest_value(&json!({
            "claim_digest": self.claim_digest,
            "fixture_kind": case.kind,
            "memory_snapshot": Self::stable_descriptor(descriptor),
            "baseline_policy_version": baseline_decision.policy_version,
            "candidate_policy_version": candidate_decision.policy_version,
            "baseline_policy_action": baseline_decision.action.as_str(),
            "candidate_policy_action": candidate_decision.action.as_str(),
        })))
    }

    fn validate(&self) -> Result<(), String> {
        for (name, descriptor) in [
            ("supporting", self.supporting),
            ("contested", self.contested),
            ("insufficient", self.insufficient),
            ("stale", self.stale),
            ("retracted", self.retracted),
        ] {
            descriptor
                .validate()
                .map_err(|error| format!("{name} fixture descriptor is invalid: {error}"))?;
        }
        self.claim_only_policy
            .validate()
            .map_err(|error| format!("claim-only policy is invalid: {error}"))?;
        self.epistemic_policy
            .validate()
            .map_err(|error| format!("epistemic policy is invalid: {error}"))?;
        Ok(())
    }
}

fn derive_arm_metrics(
    case: &FixtureCase,
    variant: &str,
    context: &EpistemicFixtureContext<'_>,
) -> Result<ArmMetrics, String> {
    let descriptor = context.descriptor_for(case.kind)?;
    let operation_risk = EpistemicFixtureContext::operation_risk_for(case.kind);
    let policy = context.policy_for_variant(variant)?;
    let decision = policy.decide(
        descriptor,
        Some(EpistemicFixtureContext::applicability_for(case.kind)),
        operation_risk,
    )?;
    let framed = variant == EPISTEMIC_FRAMED_CONTEXT_VARIANT;
    let current = descriptor.lifecycle_status == LifecycleStatus::Current;
    let claim_count = descriptor.source_row_count.unwrap_or(0);
    let supporting_count = descriptor.supporting_evidence_count.unwrap_or_else(|| {
        if descriptor.evidence_status == EvidenceStatus::Supported {
            claim_count
        } else {
            0
        }
    });
    let contradicting_count = descriptor.contradicting_evidence_count.unwrap_or_else(|| {
        if descriptor.evidence_status == EvidenceStatus::Contested {
            1
        } else {
            0
        }
    });
    let contradiction_present = contradicting_count > 0;
    let contradiction_handled = framed
        && contradiction_present
        && decision.admits_context()
        && !decision.blocks_provider()
        && current;
    let task_success = match case.kind {
        FIXTURE_SUPPORTING_ONLY => current && decision.admits_context() && supporting_count > 0,
        FIXTURE_CONTESTED => {
            current
                && decision.admits_context()
                && (!contradiction_present || contradiction_handled)
        }
        FIXTURE_HIGH_CONFIDENCE_WRONG => false,
        FIXTURE_INSUFFICIENT => current && decision.admits_context() && supporting_count > 0,
        FIXTURE_STALE => current && decision.admits_context(),
        FIXTURE_IRRELEVANT => current && decision.admits_context() && claim_count > 0,
        other => return Err(format!("unknown epistemic fixture kind: {other}")),
    };
    let unsupported_claim_count = if !current {
        claim_count
    } else if contradiction_present && !contradiction_handled {
        1
    } else {
        0
    };
    let expected_confidence_micros = descriptor
        .producer_confidence_bps
        .map(|value| u32::from(value) * 100)
        .unwrap_or(0);
    let observed_confidence_micros =
        if !framed && (contradiction_present || case.kind == FIXTURE_HIGH_CONFIDENCE_WRONG) {
            expected_confidence_micros
                .saturating_add(200_000)
                .min(1_000_000)
        } else {
            expected_confidence_micros
        };
    let context_admitted = decision.admits_context();
    let provider_blocked = decision.blocks_provider();
    if task_success && provider_blocked {
        return Err(format!(
            "fixture {} reports success while its context policy blocks provider execution",
            case.id
        ));
    }
    Ok(ArmMetrics {
        task_success,
        unsupported_claim_count,
        claim_count,
        contradiction_present,
        contradiction_handled,
        expected_confidence_micros,
        observed_confidence_micros,
        input_tokens: 12 + claim_count.saturating_mul(2),
        output_tokens: 8,
        latency_ms: 5,
        context_admitted,
        provider_blocked,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EpistemicCaseDigestProjection {
    pub case_id: String,
    pub fixture_kind: String,
    pub baseline_receipt_digest: String,
    pub baseline_outcome_digest: String,
    pub candidate_receipt_digest: String,
    pub candidate_outcome_digest: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub contract_version: String,
    pub domain_schema_package_digest: String,
    pub domain_class_count: usize,
    pub seeded_object_count: usize,
    pub claim_identity: String,
    pub protocol_identity: String,
    pub artifact_identity: String,
    pub independent_result_producers: Vec<String>,
    pub evidence_fixture_states: BTreeMap<String, String>,
    pub contested_descriptor_status: String,
    pub insufficient_descriptor_status: String,
    pub stale_descriptor_lifecycle: String,
    pub retracted_descriptor_lifecycle: String,
    pub kioku_memory_id: String,
    pub kioku_evidence_stances: Vec<String>,
    pub kioku_state_before_review: String,
    pub kioku_state_after_review: String,
    pub kioku_policy_action: String,
    pub unknown_policy_action: String,
    pub stale_policy_action: String,
    pub superseded: bool,
    pub governed_subject_fresh: bool,
    pub governed_subject_binding_digest: String,
    pub governed_subject_operation_id: String,
    pub governed_subject_claim_only_decision: String,
    pub epistemic_framed_context_action: String,
    pub stale_governed_subject_decision: String,
    pub evaluation_plan_version_id: String,
    pub evaluation_plan_digest: String,
    pub evaluation_manifest_digest: String,
    pub evaluation_step_status: String,
    pub evaluation_verdict: String,
    pub receipt_operation_id: String,
    pub evaluation_step_receipt_digest: String,
    pub evaluation_gate_decision_digest: String,
    pub epistemic_case_digests: Vec<EpistemicCaseDigestProjection>,
    pub epistemic_comparison: EpistemicComparisonReport,
}

fn digest_value<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("fixture values are serializable");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn apply_domain_schema(db: &RuntimeDb) -> Result<(DomainSchemaPackage, String), String> {
    let package: DomainSchemaPackage = serde_json::from_str(SCHEMA_PACKAGE)
        .map_err(|error| format!("domain schema package is invalid: {error}"))?;
    if package.contract_version != DOMAIN_CONTRACT_VERSION || package.version != "1.0.0" {
        return Err("unsupported replication domain schema package".into());
    }
    if package.schema_id != "example.epistemic-replication" || package.classes.len() != 8 {
        return Err("replication domain schema package has an unexpected shape".into());
    }
    for class in &package.classes {
        let properties = class
            .properties
            .iter()
            .map(|property| {
                let prop_type = PropertyType::parse(&property.property_type).ok_or_else(|| {
                    format!(
                        "unsupported property type {} for {}",
                        property.property_type, property.name
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
                    classification: "internal".into(),
                    struct_fields: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        db.upsert_object_type(&ObjectType {
            kind: class.name.clone(),
            description: class.description.clone(),
            properties,
            is_builtin: false,
            implements: Vec::new(),
        })?;
    }
    Ok((package.clone(), digest_value(&package)))
}

fn seed_domain_objects(
    db: &RuntimeDb,
    claim_digest: &str,
    protocol_digest: &str,
) -> Result<usize, String> {
    let mut objects = Vec::new();
    let mut add =
        |id: &str, kind: &str, external_id: &str, properties: BTreeMap<String, String>| {
            objects.push(Object {
                id: id.into(),
                kind: kind.into(),
                name: external_id.into(),
                namespace: NAMESPACE.into(),
                external_id: external_id.into(),
                properties: properties.into_iter().collect::<HashMap<_, _>>(),
                created: NOW_MS,
                updated: NOW_MS,
            });
        };
    add(
        "question-1",
        "ResearchQuestion",
        "question:replication-001",
        BTreeMap::from([(
            "prompt".into(),
            "Does the fixed protocol reproduce the claim?".into(),
        )]),
    );
    add(
        CLAIM_OBJECT_ID,
        "Claim",
        CLAIM_EXTERNAL_ID,
        BTreeMap::from([
            ("text".into(), "the protocol reproduces the claim".into()),
            ("protocol_id".into(), PROTOCOL_ID.into()),
            ("artifact_id".into(), ARTIFACT_ID.into()),
            ("content_digest".into(), claim_digest.into()),
        ]),
    );
    add(
        "protocol-1",
        "Protocol",
        "protocol:replication-v1",
        BTreeMap::from([
            ("name".into(), "fixed-replication".into()),
            ("version".into(), "1.0.0".into()),
            ("digest".into(), protocol_digest.into()),
        ]),
    );
    add(
        "run-lab-a",
        "ExperimentRun",
        "run:lab-a",
        BTreeMap::from([
            ("run_id".into(), "run:lab-a".into()),
            ("producer".into(), PRODUCER_A.into()),
            ("result".into(), "supporting".into()),
        ]),
    );
    add(
        "run-lab-b",
        "ExperimentRun",
        "run:lab-b",
        BTreeMap::from([
            ("run_id".into(), "run:lab-b".into()),
            ("producer".into(), PRODUCER_B.into()),
            ("result".into(), "contradicting".into()),
        ]),
    );
    add(
        "replication-1",
        "Replication",
        "replication:001",
        BTreeMap::from([
            ("claim_id".into(), CLAIM_EXTERNAL_ID.into()),
            ("protocol_id".into(), PROTOCOL_ID.into()),
            ("run_ids".into(), "run:lab-a,run:lab-b".into()),
        ]),
    );
    add(
        "observation-a",
        "Observation",
        "observation:lab-a",
        BTreeMap::from([
            ("run_id".into(), "run:lab-a".into()),
            ("metric".into(), OUTCOME_METRIC.into()),
            ("value".into(), "1.0".into()),
        ]),
    );
    add(
        "observation-b",
        "Observation",
        "observation:lab-b",
        BTreeMap::from([
            ("run_id".into(), "run:lab-b".into()),
            ("metric".into(), OUTCOME_METRIC.into()),
            ("value".into(), "0.0".into()),
        ]),
    );
    add(
        "outcome-a",
        "Outcome",
        "outcome:lab-a",
        BTreeMap::from([
            ("run_id".into(), "run:lab-a".into()),
            ("status".into(), "supporting".into()),
        ]),
    );
    add(
        "outcome-b",
        "Outcome",
        "outcome:lab-b",
        BTreeMap::from([
            ("run_id".into(), "run:lab-b".into()),
            ("status".into(), "contradicting".into()),
        ]),
    );
    add(
        "context-claim-only",
        "Context",
        "context:claim-only",
        BTreeMap::from([
            ("claim_id".into(), CLAIM_EXTERNAL_ID.into()),
            ("variant".into(), CLAIM_ONLY_CONTEXT_VARIANT.into()),
        ]),
    );
    add(
        "context-epistemic",
        "Context",
        "context:epistemic-framed",
        BTreeMap::from([
            ("claim_id".into(), CLAIM_EXTERNAL_ID.into()),
            ("variant".into(), EPISTEMIC_FRAMED_CONTEXT_VARIANT.into()),
        ]),
    );
    for object in &objects {
        db.create_object(object)?;
    }
    Ok(objects.len())
}

fn configure_evidence(db: &RuntimeDb) -> Result<(), String> {
    for (producer, instance) in [(PRODUCER_A, "lab-a"), (PRODUCER_B, "lab-b")] {
        db.upsert_evidence_producer(
            &EvidenceProducerCapability {
                producer_identity: producer.into(),
                config_version: 1,
                source_types: vec![SOURCE_TYPE.into()],
                source_instances: vec![instance.into()],
                namespaces: vec![NAMESPACE.into()],
                evidence_types: vec![EVIDENCE_TYPE.into()],
                target_kinds: vec!["Claim".into()],
                classification_ceiling: EvidenceClassification::Internal,
                allowed_intents: vec![
                    EvidenceIntent::Upsert,
                    EvidenceIntent::Retract,
                    EvidenceIntent::MarkStale,
                ],
                allow_operation_attachment: false,
                replay_window_ms: 1_000_000,
                max_clock_skew_ms: 0,
                max_payload_bytes: 8 * 1024,
                max_relationships: 4,
                rate_limit_per_minute: 100,
                max_retained_submissions: 100,
                revoked: false,
            },
            NOW_MS,
        )?;
    }
    db.register_evidence_schema(
        &EvidenceSchemaDefinition {
            schema_id: EVIDENCE_SCHEMA.into(),
            schema_version: "1.0.0".into(),
            evidence_type: EVIDENCE_TYPE.into(),
            compatible_versions: Vec::new(),
        },
        NOW_MS,
    )
}

fn admit_and_project(
    db: &RuntimeDb,
    producer: &str,
    source_instance: &str,
    source_record_id: &str,
    source_sequence: i64,
    intent: EvidenceIntent,
    content: Value,
) -> Result<EvidenceSubmissionRecord, String> {
    let claim_digest = content
        .get("claim_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "replication evidence must bind the claim digest".to_string())?
        .to_owned();
    let envelope = EvidenceEnvelope {
        contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: SOURCE_TYPE.into(),
        source_instance: source_instance.into(),
        source_record_id: source_record_id.into(),
        source_version: format!("version-{source_sequence}"),
        source_sequence,
        target: EvidenceTarget {
            namespace: NAMESPACE.into(),
            object_external_id: CLAIM_EXTERNAL_ID.into(),
            object_kind: "Claim".into(),
        },
        evidence_type: EVIDENCE_TYPE.into(),
        signal: EvidenceSignal::Verification,
        schema_id: EVIDENCE_SCHEMA.into(),
        schema_version: "1.0.0".into(),
        schema_compatibility: SchemaCompatibility::Exact,
        observed_at_ms: OBSERVED_AT_MS + source_sequence,
        collected_at_ms: OBSERVED_AT_MS + source_sequence + 1,
        expires_at_ms: Some(NOW_MS + 1_000_000),
        content_digest: canonical_content_digest(&content)?,
        content,
        relationships: Vec::new(),
        producer_identity: producer.into(),
        confidence_bps: 8_000,
        classification: EvidenceClassification::Internal,
        provenance: BTreeMap::from([
            ("fixture_version".into(), "epistemic-replication/v1".into()),
            ("claim_digest".into(), claim_digest),
            ("protocol_id".into(), PROTOCOL_ID.into()),
            ("artifact_id".into(), ARTIFACT_ID.into()),
        ]),
        idempotency_key: format!("{source_instance}:{source_record_id}:{source_sequence}"),
        intent,
        causality: None,
    };
    let admission = db.submit_evidence(&envelope, producer, NOW_MS)?;
    if !admission.accepted {
        return Err(format!(
            "evidence admission was rejected: {}",
            admission
                .submission
                .rejection_code
                .unwrap_or_else(|| "unknown".into())
        ));
    }
    let projection = db.project_evidence_submission(&admission.submission.id, NOW_MS)?;
    if !projection.projected {
        return Err(format!(
            "evidence projection failed: {}",
            projection.failure_code.unwrap_or_else(|| "unknown".into())
        ));
    }
    db.get_evidence_submission(&admission.submission.id)?
        .ok_or_else(|| "projected evidence submission disappeared".into())
}

fn complete_receipt_at(
    operation_id: &str,
    request_id: &str,
    reference_kind: &str,
    reference: &str,
    reference_digest: &str,
    passed: bool,
    timestamp_ms: i64,
) -> OperationReceipt {
    let intent_id = format!("{operation_id}:intent");
    let policy_id = format!("{operation_id}:policy");
    let route_id = format!("{operation_id}:route");
    let budget_id = format!("{operation_id}:budget");
    let verification_id = format!("{operation_id}:verification");
    let outcome_id = format!("{operation_id}:outcome");
    let reference = GovernedReference {
        kind: reference_kind.into(),
        reference: reference.into(),
        content_hash: Some(reference_digest.into()),
        disclosed_fields: vec!["identity".into(), "content_digest".into()],
        omitted: false,
        omission_reason: None,
    };
    let event = |event_id: String,
                 parent_event_id: Option<String>,
                 kind: ReceiptEventKind,
                 references: Vec<GovernedReference>,
                 attributes: BTreeMap<String, String>|
     -> OperationReceiptEvent {
        OperationReceiptEvent {
            event_id,
            operation_id: operation_id.into(),
            parent_event_id,
            timestamp_ms,
            kind,
            surface: kind.surface(),
            actor: ACTOR.into(),
            references,
            attributes,
        }
    };
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.into(),
        parent_operation_id: None,
        namespace: NAMESPACE.into(),
        operation_class: "replication.evaluate".into(),
        initiating_actor: ACTOR.into(),
        schema_version: "example.epistemic-replication/v1".into(),
        policy_version: "replication-policy/v1".into(),
        started_at_ms: timestamp_ms,
        completed_at_ms: Some(timestamp_ms + 5),
        events: vec![
            event(
                intent_id.clone(),
                None,
                ReceiptEventKind::IntentRecorded,
                vec![reference.clone()],
                BTreeMap::from([("request_id".into(), request_id.into())]),
            ),
            event(
                policy_id.clone(),
                Some(intent_id.clone()),
                ReceiptEventKind::PolicyDecided,
                vec![reference.clone()],
                BTreeMap::from([("policy_version".into(), "replication-policy/v1".into())]),
            ),
            event(
                route_id.clone(),
                Some(policy_id.clone()),
                ReceiptEventKind::RouteSelected,
                vec![reference.clone()],
                BTreeMap::from([("producer".into(), "replication-adapter/v1".into())]),
            ),
            event(
                budget_id.clone(),
                Some(route_id.clone()),
                ReceiptEventKind::BudgetDecided,
                vec![reference.clone()],
                BTreeMap::from([("token_capacity".into(), "32".into())]),
            ),
            event(
                verification_id.clone(),
                Some(budget_id.clone()),
                ReceiptEventKind::VerificationRecorded,
                vec![reference.clone()],
                BTreeMap::from([("verification".into(), "independent-replication".into())]),
            ),
            event(
                outcome_id,
                Some(verification_id),
                ReceiptEventKind::OutcomeRecorded,
                vec![reference],
                BTreeMap::from([
                    ("outcome_metric".into(), OUTCOME_METRIC.into()),
                    (
                        "outcome_value".into(),
                        if passed { "1.0" } else { "0.0" }.into(),
                    ),
                    ("passed".into(), passed.to_string()),
                ]),
            ),
        ],
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
    }
}

fn complete_case_receipt(
    operation_id: &str,
    request_id: &str,
    case_id: &str,
    source_content_digest: &str,
    metrics: ArmMetrics,
) -> OperationReceipt {
    let mut receipt = complete_receipt_at(
        operation_id,
        request_id,
        "evaluation_case",
        case_id,
        source_content_digest,
        metrics.task_success,
        EVALUATION_AT_MS,
    );
    for event in &mut receipt.events {
        match event.kind {
            ReceiptEventKind::VerificationRecorded => {
                event.attributes.extend(BTreeMap::from([
                    (
                        "expected_confidence_micros".into(),
                        metrics.expected_confidence_micros.to_string(),
                    ),
                    (
                        "observed_confidence_micros".into(),
                        metrics.observed_confidence_micros.to_string(),
                    ),
                    ("input_tokens".into(), metrics.input_tokens.to_string()),
                    ("output_tokens".into(), metrics.output_tokens.to_string()),
                    ("latency_ms".into(), metrics.latency_ms.to_string()),
                    (
                        "context_admitted".into(),
                        metrics.context_admitted.to_string(),
                    ),
                    (
                        "provider_blocked".into(),
                        metrics.provider_blocked.to_string(),
                    ),
                ]));
            }
            ReceiptEventKind::OutcomeRecorded => {
                event.attributes.extend(BTreeMap::from([
                    (
                        "unsupported_claim_count".into(),
                        metrics.unsupported_claim_count.to_string(),
                    ),
                    ("claim_count".into(), metrics.claim_count.to_string()),
                    (
                        "contradiction_present".into(),
                        metrics.contradiction_present.to_string(),
                    ),
                    (
                        "contradiction_handled".into(),
                        metrics.contradiction_handled.to_string(),
                    ),
                ]));
            }
            _ => {}
        }
    }
    receipt
}

fn parse_case_metrics(receipt: &OperationReceipt) -> Result<PersistedCaseMetrics, String> {
    let verification = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::VerificationRecorded)
        .ok_or_else(|| "evaluation case receipt lacks verification event".to_string())?;
    let outcome = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        .ok_or_else(|| "evaluation case receipt lacks outcome event".to_string())?;
    let parse_u32 = |attributes: &BTreeMap<String, String>, key: &str| {
        attributes
            .get(key)
            .ok_or_else(|| format!("evaluation case receipt lacks {key}"))?
            .parse::<u32>()
            .map_err(|error| format!("evaluation case receipt {key} is invalid: {error}"))
    };
    let parse_bool = |attributes: &BTreeMap<String, String>, key: &str| {
        attributes
            .get(key)
            .ok_or_else(|| format!("evaluation case receipt lacks {key}"))?
            .parse::<bool>()
            .map_err(|error| format!("evaluation case receipt {key} is invalid: {error}"))
    };
    let latency_ms = verification
        .attributes
        .get("latency_ms")
        .ok_or_else(|| "evaluation case receipt lacks latency_ms".to_string())?
        .parse::<u64>()
        .map_err(|error| format!("evaluation case receipt latency_ms is invalid: {error}"))?;
    Ok(PersistedCaseMetrics {
        task_success: outcome
            .attributes
            .get("passed")
            .ok_or_else(|| "evaluation case receipt lacks passed".to_string())?
            .parse::<bool>()
            .map_err(|error| format!("evaluation case receipt passed is invalid: {error}"))?,
        unsupported_claim_count: parse_u32(&outcome.attributes, "unsupported_claim_count")?,
        claim_count: parse_u32(&outcome.attributes, "claim_count")?,
        contradiction_present: parse_bool(&outcome.attributes, "contradiction_present")?,
        contradiction_handled: parse_bool(&outcome.attributes, "contradiction_handled")?,
        expected_confidence_micros: parse_u32(
            &verification.attributes,
            "expected_confidence_micros",
        )?,
        observed_confidence_micros: parse_u32(
            &verification.attributes,
            "observed_confidence_micros",
        )?,
        input_tokens: parse_u32(&verification.attributes, "input_tokens")?,
        output_tokens: parse_u32(&verification.attributes, "output_tokens")?,
        latency_ms,
        context_admitted: parse_bool(&verification.attributes, "context_admitted")?,
        provider_blocked: parse_bool(&verification.attributes, "provider_blocked")?,
    })
}

fn fixture_cases() -> [FixtureCase; 6] {
    [
        FixtureCase {
            id: "case-supporting-only",
            kind: FIXTURE_SUPPORTING_ONLY,
        },
        FixtureCase {
            id: "case-contested",
            kind: FIXTURE_CONTESTED,
        },
        FixtureCase {
            id: "case-insufficient",
            kind: FIXTURE_INSUFFICIENT,
        },
        FixtureCase {
            id: "case-stale",
            kind: FIXTURE_STALE,
        },
        FixtureCase {
            id: "case-irrelevant",
            kind: FIXTURE_IRRELEVANT,
        },
        FixtureCase {
            id: "case-high-confidence-wrong",
            kind: FIXTURE_HIGH_CONFIDENCE_WRONG,
        },
    ]
}

fn record_eval_case(
    db: &RuntimeDb,
    memory_id: &str,
    source_content_digest: &str,
    eligible_memory_set_digest: &str,
    case: &FixtureCase,
    variant: &str,
    metrics: ArmMetrics,
) -> Result<(CaseResult, EpistemicCaseAuthority), String> {
    let operation_id = format!("eval-{variant}-{}", case.id);
    let request_id = format!("request-{variant}-{}", case.id);
    let receipt = complete_case_receipt(
        &operation_id,
        &request_id,
        case.id,
        source_content_digest,
        metrics,
    );
    if !receipt.completeness().complete {
        return Err(format!(
            "fixture receipt is incomplete: {:?}",
            receipt.completeness().errors
        ));
    }
    db.put_operation_receipt(&receipt)?;
    let persisted_receipt = db
        .get_operation_receipt(&operation_id)?
        .ok_or_else(|| "evaluation case receipt was not persisted".to_string())?;
    let persisted = parse_case_metrics(&persisted_receipt)?;
    if persisted.provider_blocked && persisted.task_success {
        return Err("a provider-blocked evaluation case cannot pass".into());
    }
    db.record_kioku_lifecycle_event(&MemoryLifecycleEvent {
        memory_id: memory_id.into(),
        memory_version: 1,
        action: if persisted.context_admitted {
            "injected"
        } else {
            "held_out"
        }
        .into(),
        from_state: Some("active".into()),
        to_state: "active".into(),
        actor: ACTOR.into(),
        reason: format!("pipeline operation {operation_id}"),
        recorded_at_ms: EVALUATION_AT_MS,
    })?;
    db.record_kioku_outcome(&MemoryOutcomeObservation {
        memory_id: memory_id.into(),
        memory_version: 1,
        operation_id: operation_id.clone(),
        request_id,
        memory_applied: persisted.context_admitted,
        outcome_metric: OUTCOME_METRIC.into(),
        outcome_value: if persisted.task_success { 1.0 } else { 0.0 },
        passed: persisted.task_success,
        recorded_at_ms: EVALUATION_AT_MS,
    })?;
    let receipt_evidence = EpistemicReceiptEvidence {
        operation_id,
        task_success: persisted.task_success,
        observed_confidence_micros: persisted.observed_confidence_micros,
        input_tokens: persisted.input_tokens,
        output_tokens: persisted.output_tokens,
        latency_ms: persisted.latency_ms,
    };
    let outcome_evidence = EpistemicOutcomeEvidence {
        memory_id: memory_id.into(),
        memory_version: 1,
        operation_id: receipt_evidence.operation_id.clone(),
        unsupported_claim_count: persisted.unsupported_claim_count,
        claim_count: persisted.claim_count,
        contradiction_present: persisted.contradiction_present,
        contradiction_handled: persisted.contradiction_handled,
    };
    let receipt_digest = canonical_epistemic_receipt_digest(&receipt_evidence)?;
    let outcome_digest = canonical_epistemic_outcome_digest(&outcome_evidence)?;
    let evidence = EpistemicCaseEvidence {
        contract_version: EPISTEMIC_CASE_EVIDENCE_CONTRACT.into(),
        context_variant: variant.into(),
        fixture_kind: case.kind.into(),
        eligible_memory_set_digest: eligible_memory_set_digest.into(),
        classification_ceiling: "internal".into(),
        source_content_digest: source_content_digest.into(),
        token_capacity: persisted.input_tokens + persisted.output_tokens + 8,
        task_success: persisted.task_success,
        unsupported_claim_count: persisted.unsupported_claim_count,
        claim_count: persisted.claim_count,
        contradiction_present: persisted.contradiction_present,
        contradiction_handled: persisted.contradiction_handled,
        expected_confidence_micros: persisted.expected_confidence_micros,
        observed_confidence_micros: persisted.observed_confidence_micros,
        input_tokens: persisted.input_tokens,
        output_tokens: persisted.output_tokens,
        receipt_digest,
        outcome_digest,
    };
    let result = CaseResult {
        case_id: case.id.into(),
        passed: persisted.task_success,
        status: "done".into(),
        result: serde_json::to_string(&evidence).map_err(|error| error.to_string())?,
        score: if persisted.task_success { 100 } else { 0 },
        reason: String::new(),
        elapsed: persisted.latency_ms as i64,
    };
    let authority = EpistemicCaseAuthority {
        fixture_kind: case.kind.into(),
        eligible_memory_set_digest: eligible_memory_set_digest.into(),
        classification_ceiling: "internal".into(),
        source_content_digest: source_content_digest.into(),
        token_capacity: persisted.input_tokens + persisted.output_tokens + 8,
        expected_confidence_micros: persisted.expected_confidence_micros,
        receipt: receipt_evidence,
        outcome: outcome_evidence,
    };
    Ok((result, authority))
}

fn run_epistemic_comparison(
    db: &RuntimeDb,
    memory_id: &str,
    context: &EpistemicFixtureContext<'_>,
) -> Result<
    (
        EpistemicComparisonReport,
        Vec<EpistemicCaseDigestProjection>,
    ),
    String,
> {
    context.validate()?;
    let suite_id = "epistemic-replication-fixtures-v1";
    let cases = fixture_cases();
    let suite = Suite {
        id: suite_id.into(),
        name: "Epistemic replication fixtures".into(),
        description: "Payload-free deterministic claim-only/framed comparison".into(),
        cases: cases
            .iter()
            .map(|case| Case {
                id: case.id.into(),
                name: case.kind.into(),
                namespace: NAMESPACE.into(),
                spec: format!("fixture:{}", case.kind),
                assertions: Vec::new(),
            })
            .collect(),
    };
    let store = EvalStore::new();
    store.put_suite(suite)?;
    let mut baseline_results = Vec::new();
    let mut candidate_results = Vec::new();
    let mut baseline_authority = BTreeMap::new();
    let mut candidate_authority = BTreeMap::new();
    let mut case_digests = Vec::new();
    for case in &cases {
        let case_source_digest = context.case_digest(case)?;
        let eligible_memory_set_digest = digest_value(&json!({
            "memory_id": memory_id,
            "memory_version": 1,
            "classification_ceiling": "internal",
            "case_context_digest": case_source_digest,
        }));
        let baseline_metrics = derive_arm_metrics(case, CLAIM_ONLY_CONTEXT_VARIANT, context)?;
        let candidate_metrics =
            derive_arm_metrics(case, EPISTEMIC_FRAMED_CONTEXT_VARIANT, context)?;
        let (baseline_result, baseline_case_authority) = record_eval_case(
            db,
            memory_id,
            &case_source_digest,
            &eligible_memory_set_digest,
            case,
            CLAIM_ONLY_CONTEXT_VARIANT,
            baseline_metrics,
        )?;
        let (candidate_result, candidate_case_authority) = record_eval_case(
            db,
            memory_id,
            &case_source_digest,
            &eligible_memory_set_digest,
            case,
            EPISTEMIC_FRAMED_CONTEXT_VARIANT,
            candidate_metrics,
        )?;
        case_digests.push(EpistemicCaseDigestProjection {
            case_id: case.id.into(),
            fixture_kind: case.kind.into(),
            baseline_receipt_digest: canonical_epistemic_receipt_digest(
                &baseline_case_authority.receipt,
            )?,
            baseline_outcome_digest: canonical_epistemic_outcome_digest(
                &baseline_case_authority.outcome,
            )?,
            candidate_receipt_digest: canonical_epistemic_receipt_digest(
                &candidate_case_authority.receipt,
            )?,
            candidate_outcome_digest: canonical_epistemic_outcome_digest(
                &candidate_case_authority.outcome,
            )?,
        });
        baseline_authority.insert(case.id.into(), baseline_case_authority);
        candidate_authority.insert(case.id.into(), candidate_case_authority);
        baseline_results.push(baseline_result);
        candidate_results.push(candidate_result);
    }
    store.put_run(Run {
        id: "run-claim-only-v1".into(),
        suite_id: suite_id.into(),
        config_ref: "kioku-context:claim-only:v1".into(),
        results: baseline_results,
        timestamp: EVALUATION_AT_MS + 10,
    })?;
    store.put_run(Run {
        id: "run-epistemic-framed-v1".into(),
        suite_id: suite_id.into(),
        config_ref: "kioku-context:epistemic:v1".into(),
        results: candidate_results,
        timestamp: EVALUATION_AT_MS + 10,
    })?;
    let comparison = compare_epistemic_runs(
        &store,
        "run-claim-only-v1",
        "run-epistemic-framed-v1",
        &baseline_authority,
        &candidate_authority,
        EpistemicRegressionPolicy::default(),
    )?;
    Ok((comparison, case_digests))
}

fn fixture_config() -> Config {
    let mut config = Config::from_env();
    config.db_path = ":memory:".into();
    config
}

fn authenticated_request<T>(body: T) -> Request<T> {
    let mut request = Request::new(body);
    request.metadata_mut().insert(
        "x-principal",
        "root".parse().expect("static principal metadata"),
    );
    request
}

fn block_on_fixture<F>(future: F) -> Result<F::Output, String>
where
    F: std::future::Future,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("fixture runtime failed: {error}"))
        .map(|runtime| runtime.block_on(future))
}

fn install_governed_invariant(
    db: &RuntimeDb,
) -> Result<governed_facts::GovernedFactVersion, String> {
    governed_facts::apply_profile(
        db,
        NAMESPACE,
        governed_facts::PROFILE_CONTRACT_VERSION,
        ACTOR,
        NOW_MS,
    )?;
    governed_facts::put_fact(
        db,
        governed_facts::GovernedFactInput {
            contract_version: governed_facts::PROFILE_CONTRACT_VERSION.into(),
            namespace: NAMESPACE.into(),
            fact_id: "replication-claim-digest".into(),
            version: "1.0.0".into(),
            fact_type: GovernedFactType::Invariant,
            status: "active".into(),
            statement: "The replication claim content digest matches the immutable subject input."
                .into(),
            applicability: governed_facts::FactApplicability {
                subject_profiles: vec![REPLICATION_CLAIM_PROFILE.into()],
                subject_refs: Vec::new(),
            },
            verification: governed_facts::VerificationContract {
                predicate_kind: SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE.into(),
                input_schema: "schema://replication-claim/v1".into(),
                result_schema: EVALUATOR_RESULT_CONTRACT.into(),
                evidence_types: Vec::new(),
            },
            requirement_version_ids: Vec::new(),
            evidence_refs: Vec::new(),
            source_ref: "repo://examples/epistemic-replication/invariant@1.0.0".into(),
            effective_from_ms: NOW_MS - 1,
            supersedes_object_id: String::new(),
            access_marking: String::new(),
        },
        ACTOR,
        NOW_MS,
    )
}

fn install_evaluation_plan(
    db: &RuntimeDb,
    subject_content_digest: &str,
) -> Result<(EvaluationPlan, String), String> {
    let invariant = install_governed_invariant(db)?;
    let definition = prepare_definition(
        EvaluatorDefinition {
            contract_version: EVALUATOR_DEFINITION_CONTRACT.into(),
            definition_id: String::new(),
            namespace: NAMESPACE.into(),
            evaluator_id: "subject-content-digest-equality".into(),
            version: "1.0.0".into(),
            implementation_digest: SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST.into(),
            execution_class: DETERMINISTIC_EXECUTION_CLASS.into(),
            supported_predicate_kinds: vec![SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE.into()],
            supported_input_schemas: vec!["schema://replication-claim/v1".into()],
            supported_result_schemas: vec![EVALUATOR_RESULT_CONTRACT.into()],
            parameter_schema_json: r#"{"type":"object","properties":{"expected_content_digest":{"type":"string"}},"required":["expected_content_digest"],"additionalProperties":false}"#.into(),
            evidence_classifications: vec!["internal".into()],
            resource_limits: EvaluatorResourceLimits {
                timeout_ms: 1_000,
                max_input_bytes: 64 * 1024,
                max_output_bytes: 8 * 1024,
                max_evidence_items: 8,
            },
            adapter_endpoint: String::new(),
            stochastic_policy: None,
            source_ref: "repo://examples/epistemic-replication/evaluator@1.0.0".into(),
            content_digest: String::new(),
            created_by: String::new(),
            created_at_ms: 0,
        },
        ACTOR,
        NOW_MS,
    )?;
    let plan = prepare_plan(
        EvaluationPlan {
            contract_version: EVALUATION_PLAN_CONTRACT.into(),
            plan_version_id: String::new(),
            namespace: NAMESPACE.into(),
            plan_id: "replication-claim-evaluation".into(),
            version: "1.0.0".into(),
            accepted_subject_profiles: vec![REPLICATION_CLAIM_PROFILE.into()],
            nodes: vec![EvaluationPlanNode {
                node_id: "claim-digest".into(),
                evaluator_definition_id: definition.definition_id.clone(),
                depends_on_node_ids: Vec::new(),
                input_bindings: vec![EvaluationInputBinding {
                    name: "claim".into(),
                    source_kind: INPUT_INVARIANT.into(),
                    schema_id: "schema://replication-claim/v1".into(),
                }],
                parameters_json: serde_json::to_string(&json!({
                    "expected_content_digest": subject_content_digest,
                }))
                .map_err(|error| error.to_string())?,
                invariant_version_ids: vec![invariant.object_id],
                classification: NODE_REQUIRED.into(),
            }],
            reducer: FIXED_REDUCER.into(),
            source_ref: "repo://examples/epistemic-replication/plan@1.0.0".into(),
            content_digest: String::new(),
            created_by: String::new(),
            created_at_ms: 0,
        },
        ACTOR,
        NOW_MS,
    )?;
    let service = ChiseiServiceImpl::new(Arc::new(db.clone()), fixture_config());
    let definition_response = block_on_fixture(ChiseiGrpcService::put_evaluator_definition(
        &service,
        authenticated_request(chisei::PutEvaluatorDefinitionRequest {
            definition: Some(chisei::EvaluatorDefinition {
                contract_version: definition.contract_version.clone(),
                definition_id: definition.definition_id.clone(),
                namespace: definition.namespace.clone(),
                evaluator_id: definition.evaluator_id.clone(),
                version: definition.version.clone(),
                implementation_digest: definition.implementation_digest.clone(),
                execution_class: definition.execution_class.clone(),
                supported_predicate_kinds: definition.supported_predicate_kinds.clone(),
                supported_input_schemas: definition.supported_input_schemas.clone(),
                supported_result_schemas: definition.supported_result_schemas.clone(),
                parameter_schema_json: definition.parameter_schema_json.clone(),
                evidence_classifications: definition.evidence_classifications.clone(),
                resource_limits: Some(chisei::EvaluatorResourceLimits {
                    timeout_ms: definition.resource_limits.timeout_ms,
                    max_input_bytes: definition.resource_limits.max_input_bytes,
                    max_output_bytes: definition.resource_limits.max_output_bytes,
                    max_evidence_items: definition.resource_limits.max_evidence_items,
                }),
                adapter_endpoint: definition.adapter_endpoint.clone(),
                source_ref: definition.source_ref.clone(),
                content_digest: String::new(),
                created_by: String::new(),
                created_at_ms: 0,
                stochastic_policy: None,
            }),
            ..Default::default()
        }),
    ))?
    .map_err(|error| error.to_string())?;
    let stored_definition = definition_response
        .into_inner()
        .record
        .and_then(|record| record.definition)
        .ok_or_else(|| "evaluator publication returned no definition".to_string())?;
    if stored_definition.definition_id != definition.definition_id {
        return Err("published evaluator definition identity changed".into());
    }
    let plan_response = block_on_fixture(ChiseiGrpcService::put_evaluation_plan(
        &service,
        authenticated_request(chisei::PutEvaluationPlanRequest {
            plan: Some(chisei::EvaluationPlan {
                contract_version: plan.contract_version.clone(),
                plan_version_id: plan.plan_version_id.clone(),
                namespace: plan.namespace.clone(),
                plan_id: plan.plan_id.clone(),
                version: plan.version.clone(),
                accepted_subject_profiles: plan.accepted_subject_profiles.clone(),
                nodes: plan
                    .nodes
                    .iter()
                    .map(|node| chisei::EvaluationPlanNode {
                        node_id: node.node_id.clone(),
                        evaluator_definition_id: node.evaluator_definition_id.clone(),
                        depends_on_node_ids: node.depends_on_node_ids.clone(),
                        input_bindings: node
                            .input_bindings
                            .iter()
                            .map(|binding| chisei::EvaluationInputBinding {
                                name: binding.name.clone(),
                                source_kind: binding.source_kind.clone(),
                                schema_id: binding.schema_id.clone(),
                            })
                            .collect(),
                        parameters_json: node.parameters_json.clone(),
                        invariant_version_ids: node.invariant_version_ids.clone(),
                        classification: node.classification.clone(),
                    })
                    .collect(),
                reducer: plan.reducer.clone(),
                source_ref: plan.source_ref.clone(),
                content_digest: String::new(),
                created_by: String::new(),
                created_at_ms: 0,
            }),
        }),
    ))?
    .map_err(|error| error.to_string())?;
    let published_plan_id = plan_response
        .into_inner()
        .plan
        .map(|plan| plan.plan_version_id)
        .ok_or_else(|| "evaluation plan publication returned no plan".to_string())?;
    let stored_plan = db
        .get_evaluation_plan(&published_plan_id)?
        .ok_or_else(|| "published evaluation plan disappeared".to_string())?;
    Ok((stored_plan, stored_definition.content_digest))
}

fn execute_evaluation_plan(
    db: &RuntimeDb,
    plan: &EvaluationPlan,
    subject_content_digest: &str,
) -> Result<
    (
        ResolvedEvaluationManifest,
        String,
        String,
        OperationReceipt,
        String,
        String,
    ),
    String,
> {
    let service = ChiseiServiceImpl::new(Arc::new(db.clone()), fixture_config());
    let (manifest_digest, step_status, verdict, operation_id) = block_on_fixture(async {
        let resolution = ChiseiGrpcService::resolve_evaluation_plan(
            &service,
            authenticated_request(chisei::ResolveEvaluationPlanRequest {
                resolution: Some(chisei::EvaluationResolutionRequest {
                    contract_version:
                        sekai_chisei::chisei::evaluation_manifest::RESOLUTION_REQUEST_CONTRACT
                            .into(),
                    resolver_version: sekai_chisei::chisei::evaluation_manifest::RESOLVER_VERSION
                        .into(),
                    namespace: NAMESPACE.into(),
                    request_id: "resolve-replication-claim".into(),
                    plan_version_id: plan.plan_version_id.clone(),
                    subject_profile: REPLICATION_CLAIM_PROFILE.into(),
                    subject_identity: CLAIM_IDENTITY.into(),
                    subject_content_digest: subject_content_digest.into(),
                    evidence_object_ids: Vec::new(),
                    evaluation_time_ms: NOW_MS,
                }),
            }),
        )
        .await
        .map_err(|error| error.to_string())?
        .into_inner();
        if resolution.status != "resolved" {
            return Err(format!(
                "evaluation resolution did not resolve: {}",
                resolution
                    .findings
                    .first()
                    .map(|finding| finding.code.as_str())
                    .unwrap_or(resolution.status.as_str())
            ));
        }
        let manifest = resolution
            .manifest
            .ok_or_else(|| "resolved evaluation response lacks manifest".to_string())?;
        let execution = ChiseiGrpcService::execute_evaluation_manifest(
            &service,
            authenticated_request(chisei::ExecuteEvaluationManifestRequest {
                execution: Some(chisei::EvaluationExecutionRequest {
                    contract_version:
                        sekai_chisei::chisei::evaluation_execution::EXECUTION_REQUEST_CONTRACT
                            .into(),
                    executor_version: sekai_chisei::chisei::evaluation_execution::EXECUTOR_VERSION
                        .into(),
                    namespace: NAMESPACE.into(),
                    manifest_digest: manifest.manifest_digest.clone(),
                    max_total_duration_ms: 1_000,
                }),
            }),
        )
        .await
        .map_err(|error| error.to_string())?
        .into_inner()
        .execution
        .ok_or_else(|| "evaluation execution response lacks projection".to_string())?;
        let step_status = execution
            .steps
            .first()
            .map(|step| step.status.clone())
            .ok_or_else(|| "evaluation execution response lacks step".to_string())?;
        let verdict = execution.status.clone();
        Ok((
            manifest.manifest_digest,
            step_status,
            verdict,
            execution.operation_id,
        ))
    })??;
    let manifest = db
        .get_evaluation_manifest(&manifest_digest)?
        .ok_or_else(|| "resolved evaluation manifest was not persisted".to_string())?;
    let receipt = db
        .get_operation_receipt(&operation_id)?
        .ok_or_else(|| "evaluation execution receipt was not persisted".to_string())?;
    let step = receipt
        .events
        .iter()
        .find_map(|event| event.attributes.get("evaluation_step_receipt"))
        .ok_or_else(|| "evaluation receipt lacks canonical step receipt".to_string())
        .and_then(|value| {
            serde_json::from_str::<EvaluationStepReceipt>(value)
                .map_err(|error| format!("evaluation step receipt is invalid: {error}"))
        })?;
    let gate = receipt
        .events
        .iter()
        .find_map(|event| event.attributes.get("evaluation_gate_decision"))
        .ok_or_else(|| "evaluation receipt lacks canonical gate decision".to_string())
        .and_then(|value| {
            serde_json::from_str::<EvaluationGateDecision>(value)
                .map_err(|error| format!("evaluation gate decision is invalid: {error}"))
        })?;
    if step.status != step_status || gate.verdict != verdict || gate.verdict != "allow" {
        return Err("evaluation projection and receipt diverged".into());
    }
    Ok((
        manifest,
        step_status,
        verdict,
        receipt,
        step.step_receipt_digest,
        gate.decision_digest,
    ))
}

pub fn run() -> Result<Report, String> {
    let db = RuntimeDb::memory();
    let (package, package_digest) = apply_domain_schema(&db)?;
    let source_tree_digest = digest_value(&json!({
        "schema_package": SCHEMA_PACKAGE,
        "executable_source": EXECUTABLE_SOURCE,
    }));

    let protocol = json!({
        "id": PROTOCOL_ID,
        "name": "fixed-replication",
        "version": "1.0.0",
        "steps": ["admit", "evaluate", "compare"],
    });
    let artifact = json!({
        "id": ARTIFACT_ID,
        "content": "deterministic-replication-fixture",
        "version": "1.0.0",
    });
    let protocol_digest = digest_value(&protocol);
    let artifact_digest = digest_value(&artifact);
    let claim = json!({
        "id": CLAIM_IDENTITY,
        "text": "the protocol reproduces the claim",
        "protocol_id": PROTOCOL_ID,
        "protocol_digest": protocol_digest,
        "artifact_id": ARTIFACT_ID,
        "artifact_digest": artifact_digest,
    });
    let claim_digest = digest_value(&claim);
    let seeded_object_count = seed_domain_objects(&db, &claim_digest, &protocol_digest)?;

    configure_evidence(&db)?;
    let supporting = admit_and_project(
        &db,
        PRODUCER_A,
        "lab-a",
        "run-supporting",
        1,
        EvidenceIntent::Upsert,
        json!({"claim": CLAIM_IDENTITY, "claim_digest": claim_digest, "result": "supports", "value": 1.0}),
    )?;
    let contradicting = admit_and_project(
        &db,
        PRODUCER_B,
        "lab-b",
        "run-contradicting",
        1,
        EvidenceIntent::Upsert,
        json!({"claim": CLAIM_IDENTITY, "claim_digest": claim_digest, "result": "contradicts", "value": 0.0}),
    )?;
    let stale_original = admit_and_project(
        &db,
        PRODUCER_A,
        "lab-a",
        "run-stale",
        1,
        EvidenceIntent::Upsert,
        json!({"claim": CLAIM_IDENTITY, "claim_digest": claim_digest, "result": "stale-fixture", "value": 1.0}),
    )?;
    let stale_marker = admit_and_project(
        &db,
        PRODUCER_A,
        "lab-a",
        "run-stale",
        2,
        EvidenceIntent::MarkStale,
        json!({"claim": CLAIM_IDENTITY, "claim_digest": claim_digest, "lifecycle": "stale"}),
    )?;
    let stale_original = db
        .get_evidence_submission(&stale_original.id)?
        .ok_or_else(|| "stale evidence submission disappeared".to_string())?;
    let retracted_original = admit_and_project(
        &db,
        PRODUCER_B,
        "lab-b",
        "run-retracted",
        1,
        EvidenceIntent::Upsert,
        json!({"claim": CLAIM_IDENTITY, "claim_digest": claim_digest, "result": "retracted-fixture", "value": 1.0}),
    )?;
    let retracted_marker = admit_and_project(
        &db,
        PRODUCER_B,
        "lab-b",
        "run-retracted",
        2,
        EvidenceIntent::Retract,
        json!({"claim": CLAIM_IDENTITY, "claim_digest": claim_digest, "lifecycle": "retracted"}),
    )?;
    let retracted_original = db
        .get_evidence_submission(&retracted_original.id)?
        .ok_or_else(|| "retracted evidence submission disappeared".to_string())?;

    let supporting_receipt = complete_receipt_at(
        "replication-run-lab-a",
        "replication-request-lab-a",
        "evidence",
        &supporting.id,
        &supporting.content_digest,
        true,
        supporting.observed_at_ms,
    );
    let contradicting_receipt = complete_receipt_at(
        "replication-run-lab-b",
        "replication-request-lab-b",
        "evidence",
        &contradicting.id,
        &contradicting.content_digest,
        false,
        contradicting.observed_at_ms,
    );
    if !supporting_receipt.completeness().complete || !contradicting_receipt.completeness().complete
    {
        return Err("replication result receipts are incomplete".into());
    }
    db.put_operation_receipt(&supporting_receipt)?;
    db.put_operation_receipt(&contradicting_receipt)?;
    let candidate = db.produce_kioku_candidate(CandidateDerivation {
        id: "memory:replication-claim-001".into(),
        kind: MemoryKind::Claim,
        claim: "the protocol reproduces the claim".into(),
        outcome_definition: format!("{OUTCOME_METRIC} == 1"),
        outcomes: vec![
            VerifiedOutcome {
                receipt: supporting_receipt.clone(),
                passed: true,
                outcome_metric: OUTCOME_METRIC.into(),
                outcome_value: 1.0,
            },
            VerifiedOutcome {
                receipt: contradicting_receipt.clone(),
                passed: false,
                outcome_metric: OUTCOME_METRIC.into(),
                outcome_value: 0.0,
            },
        ],
        affinity_object_ids: vec![CLAIM_OBJECT_ID.into()],
        producer_identity: "replication-adapter/v1".into(),
        classification: EvidenceClassification::Internal,
        created_at_ms: NOW_MS,
        expires_at_ms: Some(NOW_MS + 1_000_000),
        retention_until_ms: Some(NOW_MS + 2_000_000),
    })?;
    let supporting_candidate = db.produce_kioku_candidate(CandidateDerivation {
        id: "memory:replication-supporting-only".into(),
        kind: MemoryKind::Claim,
        claim: "the protocol reproduces the claim with supporting evidence only".into(),
        outcome_definition: format!("{OUTCOME_METRIC} == 1"),
        outcomes: vec![VerifiedOutcome {
            receipt: supporting_receipt,
            passed: true,
            outcome_metric: OUTCOME_METRIC.into(),
            outcome_value: 1.0,
        }],
        affinity_object_ids: vec![CLAIM_OBJECT_ID.into()],
        producer_identity: "replication-adapter/v1".into(),
        classification: EvidenceClassification::Internal,
        created_at_ms: NOW_MS,
        expires_at_ms: Some(NOW_MS + 1_000_000),
        retention_until_ms: Some(NOW_MS + 2_000_000),
    })?;
    let supporting_memory = db.review_kioku_candidate(
        &supporting_candidate.id,
        supporting_candidate.version,
        HumanMemoryReview {
            action: HumanReviewAction::Promote,
            reviewer: "local".into(),
            rationale: "local human review confirmed the supporting-only fixture".into(),
            reviewed_at_ms: NOW_MS + 5,
        },
    )?;
    let candidate_evidence = db.list_kioku_evidence(&candidate.id, candidate.version)?;
    let candidate_descriptor = EpistemicDescriptor::from_kioku(&candidate, &candidate_evidence);
    let insufficient_candidate_descriptor = EpistemicDescriptor::from_kioku(&candidate, &[]);
    let stale_descriptor = EpistemicDescriptor::from_external_evidence(&stale_original);
    let retracted_descriptor = EpistemicDescriptor::from_external_evidence(&retracted_original);
    if candidate_descriptor.evidence_status != EvidenceStatus::Contested
        || insufficient_candidate_descriptor.evidence_status != EvidenceStatus::Insufficient
        || stale_descriptor.lifecycle_status != LifecycleStatus::Stale
        || retracted_descriptor.lifecycle_status != LifecycleStatus::Retracted
    {
        return Err(format!(
            "epistemic descriptor fixture did not preserve source states: contested={}, insufficient={}, stale={}, retracted={}",
            candidate_descriptor.evidence_status.as_str(),
            insufficient_candidate_descriptor.evidence_status.as_str(),
            stale_descriptor.lifecycle_status.as_str(),
            retracted_descriptor.lifecycle_status.as_str(),
        ));
    }
    let policy = ContextAdmissionPolicy {
        contract_version: CONTEXT_ADMISSION_POLICY_VERSION.into(),
        default_action: ContextAdmissionAction::Include,
        unknown_action: ContextAdmissionAction::HoldOut,
        rules: vec![
            ContextAdmissionRule {
                action: ContextAdmissionAction::RequireReview,
                origin_classes: Vec::new(),
                evidence_statuses: vec![EvidenceStatus::Contested],
                lifecycle_statuses: vec![LifecycleStatus::Unknown],
                applicability: Some("replication".into()),
                confidence_basis: None,
                min_confidence_bps: None,
                max_confidence_bps: None,
                operation_risk: Some(OperationRisk::High),
            },
            ContextAdmissionRule {
                action: ContextAdmissionAction::HoldOut,
                origin_classes: Vec::new(),
                evidence_statuses: Vec::new(),
                lifecycle_statuses: vec![LifecycleStatus::Stale, LifecycleStatus::Retracted],
                applicability: None,
                confidence_basis: None,
                min_confidence_bps: None,
                max_confidence_bps: None,
                operation_risk: None,
            },
        ],
    };
    // The comparison holds the authorized post-review memory snapshot
    // constant. This explicit baseline policy represents a claim-only context
    // configuration: contested high-risk context remains blocked until a
    // caller opts into the epistemic-framed policy below.
    let claim_only_policy = ContextAdmissionPolicy {
        contract_version: CONTEXT_ADMISSION_POLICY_VERSION.into(),
        default_action: ContextAdmissionAction::Include,
        unknown_action: ContextAdmissionAction::HoldOut,
        rules: vec![
            ContextAdmissionRule {
                action: ContextAdmissionAction::RequireReview,
                origin_classes: Vec::new(),
                evidence_statuses: vec![EvidenceStatus::Contested],
                lifecycle_statuses: Vec::new(),
                applicability: Some("replication".into()),
                confidence_basis: None,
                min_confidence_bps: None,
                max_confidence_bps: None,
                operation_risk: Some(OperationRisk::High),
            },
            ContextAdmissionRule {
                action: ContextAdmissionAction::HoldOut,
                origin_classes: Vec::new(),
                evidence_statuses: Vec::new(),
                lifecycle_statuses: vec![LifecycleStatus::Stale, LifecycleStatus::Retracted],
                applicability: None,
                confidence_basis: None,
                min_confidence_bps: None,
                max_confidence_bps: None,
                operation_risk: None,
            },
        ],
    };
    let kioku_policy = policy.decide(
        &candidate_descriptor,
        Some("replication"),
        OperationRisk::High,
    )?;
    let unknown_policy =
        policy.decide(&EpistemicDescriptor::unknown(), None, OperationRisk::Low)?;
    let stale_policy = policy.decide(&stale_descriptor, None, OperationRisk::Low)?;
    let state_before_review = candidate.state;
    let initial_reviewed = db.review_kioku_candidate(
        &candidate.id,
        candidate.version,
        HumanMemoryReview {
            action: HumanReviewAction::Promote,
            reviewer: "local".into(),
            rationale: "local human review inspected independent support and contradiction".into(),
            reviewed_at_ms: NOW_MS + 10,
        },
    )?;
    let initial_reviewed_evidence =
        db.list_kioku_evidence(&initial_reviewed.id, initial_reviewed.version)?;
    let reassessment_basis = initial_reviewed_evidence
        .iter()
        .map(|link| {
            let source_submission_id = match link.evidence_reference.as_str() {
                value if value == supporting.id => supporting.id.clone(),
                value if value == contradicting.id => contradicting.id.clone(),
                other => {
                    return Err(format!(
                        "Kioku evidence link is not bound to an admitted submission: {other}"
                    ));
                }
            };
            Ok(KiokuEvidenceBasis {
                evidence_reference: link.evidence_reference.clone(),
                evidence_digest: link.evidence_digest.clone(),
                source_submission_id,
                stance: link.stance,
                lifecycle_state: EvidenceLifecycleState::Available,
                observed_at_ms: link.observed_at_ms,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let reassessed = db.reassess_kioku_memory(KiokuEvidenceReassessmentRequest {
        memory_id: initial_reviewed.id.clone(),
        memory_version: initial_reviewed.version,
        reassessment_key: "bind-admitted-submissions-v1".into(),
        actor: "local".into(),
        evidence_basis: reassessment_basis,
        now_ms: NOW_MS + 20,
    })?;
    let reviewed = db.review_kioku_candidate(
        &reassessed.candidate.id,
        reassessed.candidate.version,
        HumanMemoryReview {
            action: HumanReviewAction::Promote,
            reviewer: "local".into(),
            rationale: "local human review confirmed admitted submission provenance".into(),
            reviewed_at_ms: NOW_MS + 30,
        },
    )?;
    let reviewed_evidence = db.list_kioku_evidence(&reviewed.id, reviewed.version)?;
    if reviewed.evidence_basis.len() != 2
        || reviewed
            .evidence_basis
            .iter()
            .any(|basis| basis.source_submission_id.is_empty())
    {
        return Err("promoted Kioku memory lacks admitted submission provenance".into());
    }
    let reviewed_descriptor = EpistemicDescriptor::from_kioku(&reviewed, &reviewed_evidence);
    let supporting_memory_evidence =
        db.list_kioku_evidence(&supporting_memory.id, supporting_memory.version)?;
    let supporting_descriptor =
        EpistemicDescriptor::from_kioku(&supporting_memory, &supporting_memory_evidence);
    let insufficient_descriptor = EpistemicDescriptor::from_kioku(&supporting_memory, &[]);
    if reviewed.state != MemoryLifecycleState::Active
        || reviewed_descriptor.evidence_status != EvidenceStatus::Contested
    {
        return Err("human review did not activate the contested candidate safely".into());
    }

    let (plan, definition_digest) = install_evaluation_plan(&db, &claim_digest)?;
    let (
        manifest,
        evaluation_step_status,
        evaluation_verdict,
        evaluation_receipt,
        evaluation_step_receipt_digest,
        evaluation_gate_decision_digest,
    ) = execute_evaluation_plan(&db, &plan, &claim_digest)?;
    if manifest.subject_profile != REPLICATION_CLAIM_PROFILE
        || manifest.subject_identity != CLAIM_IDENTITY
        || manifest.subject_content_digest != claim_digest
        || manifest.nodes[0].evaluator.definition_digest != definition_digest
    {
        return Err("claim evaluation manifest binding diverged".into());
    }
    let software_release_candidate = SoftwareReleaseCandidate {
        revision: "replication-fixture-v1".into(),
        source_tree_digest: source_tree_digest.clone(),
        manifest_digest: protocol_digest.clone(),
        artifact_reference: ARTIFACT_ID.into(),
        artifact_digest: artifact_digest.clone(),
        build_definition_digest: plan.content_digest.clone(),
    };
    let software_release_identity = software_release_candidate.canonical_identity()?;
    let software_release_content_digest = software_release_candidate.canonical_content_digest()?;
    let subject = GovernedSubjectEnvelope {
        version: ENVELOPE_VERSION.into(),
        namespace: NAMESPACE.into(),
        request_id: "subject-evaluation-replication-001".into(),
        subject_profile: SOFTWARE_RELEASE_PROFILE.into(),
        subject_identity: software_release_identity,
        content_digest: software_release_content_digest,
        references: vec![
            GovernedSubjectReference {
                kind: "source_tree".into(),
                reference: "replication-fixture-source+schema-v1".into(),
                content_digest: source_tree_digest,
                observed_at_ms: OBSERVED_AT_MS,
            },
            GovernedSubjectReference {
                kind: "manifest".into(),
                reference: PROTOCOL_ID.into(),
                content_digest: protocol_digest.clone(),
                observed_at_ms: OBSERVED_AT_MS,
            },
            GovernedSubjectReference {
                kind: "artifact".into(),
                reference: ARTIFACT_ID.into(),
                content_digest: artifact_digest.clone(),
                observed_at_ms: OBSERVED_AT_MS,
            },
            GovernedSubjectReference {
                kind: "build_definition".into(),
                reference: "replication-evaluation-plan-v1".into(),
                content_digest: plan.content_digest.clone(),
                observed_at_ms: OBSERVED_AT_MS,
            },
        ],
        evaluation_profile: ALLOW_PROFILE.into(),
    };
    let subject_fresh = validate_envelope(&subject, "local", NOW_MS)?;
    let subject_binding = binding_digest(&subject, "local");
    let subject_operation = operation_id(NAMESPACE, "local", &subject.request_id);
    let (claim_only_decision, _) = evaluate_subject(ALLOW_PROFILE, subject_fresh);
    let (stale_subject_decision, _) = evaluate_subject(ALLOW_PROFILE, false);
    let fixture_context = EpistemicFixtureContext {
        claim_digest: &claim_digest,
        claim_only_policy: &claim_only_policy,
        epistemic_policy: &policy,
        supporting: &supporting_descriptor,
        contested: &reviewed_descriptor,
        insufficient: &insufficient_descriptor,
        stale: &stale_descriptor,
        retracted: &retracted_descriptor,
    };
    let (comparison, epistemic_case_digests) =
        run_epistemic_comparison(&db, &reviewed.id, &fixture_context)?;
    let epistemic_framed_context_decision = policy.decide(
        &reviewed_descriptor,
        Some("replication"),
        OperationRisk::High,
    )?;
    let reviewed_at = reviewed
        .reviewed_at_ms
        .ok_or_else(|| "promoted memory lacks review timestamp".to_string())?;
    let first_case_receipt = db
        .get_operation_receipt("eval-claim_only-case-supporting-only")?
        .ok_or_else(|| "comparison case receipt was not persisted".to_string())?;
    if first_case_receipt.started_at_ms <= reviewed_at
        || first_case_receipt
            .completed_at_ms
            .is_none_or(|completed_at| completed_at <= reviewed_at)
    {
        return Err("comparison evidence predates human memory promotion".into());
    }
    if comparison.contract_version != EPISTEMIC_EVALUATION_CONTRACT
        || !comparison.regression_gate.allowed
    {
        return Err(format!(
            "epistemic comparison did not pass its deterministic gate: {}",
            comparison.regression_gate.reason
        ));
    }
    let evidence_fixture_states = BTreeMap::from([
        (
            "supporting".into(),
            supporting.lifecycle_state.as_str().into(),
        ),
        (
            "contradicting".into(),
            contradicting.lifecycle_state.as_str().into(),
        ),
        (
            "stale".into(),
            stale_original.lifecycle_state.as_str().into(),
        ),
        (
            "stale_marker".into(),
            stale_marker.lifecycle_state.as_str().into(),
        ),
        (
            "retracted".into(),
            retracted_original.lifecycle_state.as_str().into(),
        ),
        (
            "retracted_marker".into(),
            retracted_marker.lifecycle_state.as_str().into(),
        ),
        ("insufficient_evidence".into(), "not_admitted".into()),
    ]);
    Ok(Report {
        contract_version: CONTRACT_VERSION.into(),
        domain_schema_package_digest: package_digest,
        domain_class_count: package.classes.len(),
        seeded_object_count,
        claim_identity: CLAIM_IDENTITY.into(),
        protocol_identity: PROTOCOL_ID.into(),
        artifact_identity: ARTIFACT_ID.into(),
        independent_result_producers: vec![PRODUCER_A.into(), PRODUCER_B.into()],
        evidence_fixture_states,
        contested_descriptor_status: candidate_descriptor.evidence_status.as_str().into(),
        insufficient_descriptor_status: insufficient_descriptor.evidence_status.as_str().into(),
        stale_descriptor_lifecycle: stale_descriptor.lifecycle_status.as_str().into(),
        retracted_descriptor_lifecycle: retracted_descriptor.lifecycle_status.as_str().into(),
        kioku_memory_id: reviewed.id.clone(),
        kioku_evidence_stances: candidate_evidence
            .iter()
            .map(|link| match link.stance {
                MemoryEvidenceStance::Supporting => "supporting".into(),
                MemoryEvidenceStance::Contradicting => "contradicting".into(),
            })
            .collect(),
        kioku_state_before_review: state_before_review.as_str().into(),
        kioku_state_after_review: reviewed.state.as_str().into(),
        kioku_policy_action: kioku_policy.action.as_str().into(),
        unknown_policy_action: unknown_policy.action.as_str().into(),
        stale_policy_action: stale_policy.action.as_str().into(),
        superseded: reviewed.supersedes.is_some(),
        governed_subject_fresh: subject_fresh,
        governed_subject_binding_digest: subject_binding,
        governed_subject_operation_id: subject_operation,
        governed_subject_claim_only_decision: claim_only_decision.into(),
        epistemic_framed_context_action: epistemic_framed_context_decision.action.as_str().into(),
        stale_governed_subject_decision: stale_subject_decision.into(),
        evaluation_plan_version_id: plan.plan_version_id,
        evaluation_plan_digest: plan.content_digest,
        evaluation_manifest_digest: manifest.manifest_digest,
        evaluation_step_status,
        evaluation_verdict,
        receipt_operation_id: evaluation_receipt.operation_id,
        evaluation_step_receipt_digest,
        evaluation_gate_decision_digest,
        epistemic_case_digests,
        epistemic_comparison: comparison,
    })
}

#[allow(dead_code)]
pub fn main() {
    match run() {
        Ok(report) => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report is serializable")
        ),
        Err(error) => {
            eprintln!("epistemic replication fixture failed: {error}");
            std::process::exit(1);
        }
    }
}

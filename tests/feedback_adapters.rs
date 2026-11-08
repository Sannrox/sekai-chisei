//! Feedback runtimes outside the plane: investigation through public RPCs
//! against an in-process plane. The analyzer is scripted; the plane, claims,
//! bindings, and Action writes are real.

#[allow(dead_code)]
#[path = "../adapters/feedback_investigation.rs"]
mod feedback_investigation;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::Arc;

use feedback_investigation::{
    AnalysisError, AnalysisRequest, Attribution, FeedbackAnalyzer, FilingDecision,
    InvestigationAnalysis, Investigator, PROMPT_OBSERVATION_CAP, analysis_input,
    publication_permitted,
};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    ClaimActionWorkRequest, GetObjectRequest, ListClaimableActionWorkRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::action_binding::{
    ACTION_BINDING_CONTRACT, ActionBinding, ParameterSource,
};
use sekai_chisei::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use sekai_chisei::sekai::evidence::{
    EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
    EvidenceSignal, EvidenceTarget, SchemaCompatibility,
};
use sekai_chisei::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle;
use sekai_chisei::sekai::evidence_store::{EvidenceProducerCapability, canonical_content_digest};
use sekai_chisei::sekai::feedback_package::{
    ACTION_DISPATCH, ACTION_OBSERVATION, EVIDENCE_SCHEMA_VERSION, EVIDENCE_TYPE,
    INVESTIGATION_RUNTIME, KIND_FINDING, KIND_HYPOTHESIS, KIND_OBSERVATION, PACKAGE_VERSION,
    install,
};
use sekai_chisei::sekai::object_change_subscription::OP_CREATE;
use sekai_chisei::sekai::security::Role;
use serde_json::json;
use tonic::Request;
use tonic::metadata::MetadataValue;

const NAMESPACE: &str = "ops";
const OPERATOR: &str = "operator";
const PRODUCER: &str = "producer:feedback";
const BINDING: &str = "feedback-dispatch";
const SIGNATURE: &str = "api:tenkai_failed";

struct Plane {
    db: Arc<RuntimeDb>,
    sekai: SekaiServiceImpl,
}

fn plane() -> Plane {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let now = now_ms();
    for (principal, role) in [
        (OPERATOR, Role::Admin),
        (INVESTIGATION_RUNTIME, Role::Editor),
    ] {
        db.ensure_team_namespace(NAMESPACE, principal, role, OPERATOR)
            .unwrap();
    }
    install(&db, NAMESPACE, OPERATOR, now).unwrap();
    db.upsert_evidence_producer(&producer(), now).unwrap();
    db.put_action_binding(&dispatch_binding(), OPERATOR, now)
        .unwrap();
    let store = sekai_chisei::db::store::SekaiStore::from_shared_runtime(db.clone());
    Plane {
        db,
        sekai: SekaiServiceImpl::new(store),
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn dispatch_binding() -> ActionBinding {
    ActionBinding {
        contract_version: ACTION_BINDING_CONTRACT.into(),
        binding_id: BINDING.into(),
        namespace: NAMESPACE.into(),
        kind: KIND_OBSERVATION.into(),
        property_filters: Vec::new(),
        ops: vec![OP_CREATE.into()],
        type_id: ACTION_DISPATCH.into(),
        version: PACKAGE_VERSION.into(),
        run_as: INVESTIGATION_RUNTIME.into(),
        parameters: BTreeMap::from([
            ("observation_id".into(), ParameterSource::ObjectId),
            (
                "runtime".into(),
                ParameterSource::Constant(INVESTIGATION_RUNTIME.into()),
            ),
        ]),
        markings: Vec::new(),
        enabled: true,
        revision: 0,
        created_by: String::new(),
        updated_at_ms: 0,
    }
}

fn producer() -> EvidenceProducerCapability {
    EvidenceProducerCapability {
        producer_identity: PRODUCER.into(),
        config_version: 1,
        source_types: vec!["feedback_source".into()],
        source_instances: vec!["feedback:checks".into()],
        namespaces: vec![NAMESPACE.into()],
        evidence_types: vec![EVIDENCE_TYPE.into()],
        target_kinds: vec![KIND_OBSERVATION.into()],
        classification_ceiling: EvidenceClassification::Confidential,
        allowed_intents: vec![EvidenceIntent::Upsert],
        allow_operation_attachment: true,
        replay_window_ms: 60_000,
        max_clock_skew_ms: 60_000,
        max_payload_bytes: 4_096,
        max_relationships: 4,
        rate_limit_per_minute: 1_000,
        max_retained_submissions: 1_000,
        revoked: false,
    }
}

/// Seed one observation the way a producer delivers it: accepted evidence,
/// then the observation Action naming it.
fn observe(db: &RuntimeDb, id: &str, occurrence: &str, classification: &str) {
    let now = now_ms();
    let content = json!({
        "problem_signature": SIGNATURE,
        "occurrence_ids": occurrence,
        "classification": classification,
        "disposition": "open"
    });
    let envelope = EvidenceEnvelope {
        contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: "feedback_source".into(),
        source_instance: "feedback:checks".into(),
        source_record_id: id.into(),
        source_version: "attempt-1".into(),
        source_sequence: 1,
        target: EvidenceTarget {
            namespace: NAMESPACE.into(),
            object_external_id: id.into(),
            object_kind: KIND_OBSERVATION.into(),
        },
        evidence_type: EVIDENCE_TYPE.into(),
        signal: EvidenceSignal::OperationalHealth,
        schema_id: EVIDENCE_TYPE.into(),
        schema_version: EVIDENCE_SCHEMA_VERSION.into(),
        schema_compatibility: SchemaCompatibility::Exact,
        observed_at_ms: now,
        collected_at_ms: now,
        expires_at_ms: Some(now + 3_600_000),
        content_digest: canonical_content_digest(&content).unwrap(),
        content,
        relationships: vec![],
        producer_identity: PRODUCER.into(),
        confidence_bps: 9_000,
        classification: EvidenceClassification::Internal,
        provenance: Default::default(),
        idempotency_key: format!("delivery-{id}"),
        intent: EvidenceIntent::Upsert,
        causality: None,
    };
    let evidence = EvidenceAdmissionLifecycle::new(db)
        .admit(&envelope, PRODUCER, now)
        .unwrap()
        .submission
        .id;
    ActionInstanceAdmission::new(db, None)
        .admit(
            ActionInstanceAdmissionRequest {
                agent_turn: None,
                namespace: NAMESPACE.into(),
                type_id: ACTION_OBSERVATION.into(),
                version: PACKAGE_VERSION.into(),
                parameters_json: json!({
                    "object_id": id,
                    "name": SIGNATURE,
                    "source_evidence": evidence,
                    "problem_signature": SIGNATURE,
                    "occurrence_ids": occurrence,
                    "classification": classification,
                    "disposition": "open"
                })
                .to_string(),
                idempotency_key: format!("obs-{id}"),
                evidence_submission_ids: vec![evidence],
                request_id: String::new(),
                ontology_digest: String::new(),
                autonomous_envelope_id: String::new(),
                policy_context: Default::default(),
                delegating_actor: None,
                budget_already_reserved: false,
                resource_tenant: String::new(),
                binding_markings: Vec::new(),
                source_object_id: String::new(),
                marking_gate: Default::default(),
                expected_object_revision: String::new(),
                offline: None,
            },
            OPERATOR,
            now,
        )
        .unwrap();
}

/// Returns a fixed analysis and counts how often the model would be called.
struct Scripted {
    analysis: Result<InvestigationAnalysis, ()>,
    calls: Cell<usize>,
}

impl Scripted {
    fn tenkai() -> Self {
        Self {
            analysis: Ok(InvestigationAnalysis {
                observed_facts: vec!["step failed in the controller".into()],
                hypotheses: vec!["lease fencing dropped".into()],
                impact: "apply cannot finish".into(),
                attribution: Attribution::Tenkai,
                proposed_reproduction: "replay the same plan".into(),
                missing_evidence: Vec::new(),
                // Model-proposed; must not count as measured.
                independently_verified_reproduction: true,
            }),
            calls: Cell::new(0),
        }
    }

    fn out_of_budget() -> Self {
        Self {
            analysis: Err(()),
            calls: Cell::new(0),
        }
    }
}

impl FeedbackAnalyzer for Scripted {
    async fn analyze(&self, _: &AnalysisRequest) -> Result<InvestigationAnalysis, AnalysisError> {
        self.calls.set(self.calls.get() + 1);
        self.analysis
            .clone()
            .map_err(|()| AnalysisError::BudgetExhausted)
    }
}

fn investigator() -> Investigator {
    Investigator {
        namespace: NAMESPACE.into(),
        binding_id: BINDING.into(),
    }
}

async fn object(sekai: &SekaiServiceImpl, id: &str) -> sekai_chisei::grpc::pb::sekai::Object {
    sekai
        .get_object(with_principal(GetObjectRequest { id: id.into() }, OPERATOR))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap()
}

fn with_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    request
}

/// A plane whose dispatch binding has run once: the binding is a change
/// subscription, so only observations created after its first run dispatch.
async fn armed_plane() -> Plane {
    let plane = plane();
    investigator().run_binding(&plane.sekai).await.unwrap();
    plane
}

/// Investigate every claimable dispatch; returns the reports in order.
async fn drain(
    plane: &Plane,
    analyzer: &Scripted,
) -> Vec<feedback_investigation::InvestigateReport> {
    let runtime = investigator();
    runtime.run_binding(&plane.sekai).await.unwrap();
    let mut reports = Vec::new();
    while let Some(report) = runtime
        .run_once(&plane.sekai, analyzer, now_ms())
        .await
        .unwrap()
    {
        reports.push(report);
    }
    reports
}

#[tokio::test]
async fn three_operations_qualify_with_one_model_call() {
    let plane = armed_plane().await;
    for (id, op) in [("o-1", "op-1"), ("o-2", "op-2"), ("o-3", "op-3")] {
        observe(&plane.db, id, op, "defect");
    }
    let analyzer = Scripted::tenkai();
    let reports = drain(&plane, &analyzer).await;

    assert_eq!(reports.len(), 3, "one report per dispatch");
    assert_eq!(
        analyzer.calls.get(),
        1,
        "one model call per signature window"
    );
    assert_eq!(reports.iter().filter(|report| report.analyzed).count(), 1);
    let last = reports.last().unwrap();
    assert_eq!(last.filing, FilingDecision::Qualifying);
    let finding = object(&plane.sekai, &last.finding_id).await;
    assert_eq!(finding.kind, KIND_FINDING);
    assert!(publication_permitted(&finding));
    let investigation = object(&plane.sekai, &last.investigation_id).await;
    assert_eq!(
        investigation.properties.get("measured").map(String::as_str),
        Some("false")
    );
    let hypothesis = &reports
        .iter()
        .find(|report| report.analyzed)
        .unwrap()
        .hypothesis_ids[0];
    assert_eq!(object(&plane.sekai, hypothesis).await.kind, KIND_HYPOTHESIS);
}

#[tokio::test]
async fn retries_of_one_operation_stay_internal() {
    let plane = armed_plane().await;
    observe(&plane.db, "o-1", "op-1", "defect");
    observe(&plane.db, "o-2", "op-1", "defect");
    let reports = drain(&plane, &Scripted::tenkai()).await;
    assert_eq!(reports.len(), 2);
    assert!(
        reports
            .iter()
            .all(|report| report.filing == FilingDecision::Internal)
    );
}

#[tokio::test]
async fn application_failures_never_qualify() {
    let plane = armed_plane().await;
    for (id, op) in [("o-1", "op-1"), ("o-2", "op-2"), ("o-3", "op-3")] {
        observe(&plane.db, id, op, "cancelled");
    }
    let reports = drain(&plane, &Scripted::tenkai()).await;
    assert_eq!(reports.last().unwrap().filing, FilingDecision::Internal);
}

#[tokio::test]
async fn budget_refusal_writes_nothing_and_releases_the_dispatch() {
    let plane = armed_plane().await;
    observe(&plane.db, "o-1", "op-1", "defect");
    let runtime = investigator();
    runtime.run_binding(&plane.sekai).await.unwrap();
    let analyzer = Scripted::out_of_budget();
    let report = runtime
        .run_once(&plane.sekai, &analyzer, now_ms())
        .await
        .unwrap();
    assert!(report.is_none());
    assert_eq!(analyzer.calls.get(), 1);
    let findings = plane
        .db
        .list_all_objects(&sekai_chisei::domain::ListFilter {
            kind: Some(KIND_FINDING.into()),
            namespace: Some(NAMESPACE.into()),
            ..Default::default()
        })
        .unwrap();
    assert!(findings.is_empty());
}

#[tokio::test]
async fn a_crashed_claim_is_taken_over_without_duplicate_records() {
    let plane = armed_plane().await;
    for (id, op) in [("o-1", "op-1"), ("o-2", "op-2"), ("o-3", "op-3")] {
        observe(&plane.db, id, op, "defect");
    }
    let runtime = investigator();
    runtime.run_binding(&plane.sekai).await.unwrap();
    // A runtime claims every dispatch with a short lease, then dies.
    let claimable = plane
        .sekai
        .list_claimable_action_work(with_principal(
            ListClaimableActionWorkRequest {
                namespace: NAMESPACE.into(),
                runtime_id: INVESTIGATION_RUNTIME.into(),
                limit: 16,
            },
            INVESTIGATION_RUNTIME,
        ))
        .await
        .unwrap()
        .into_inner()
        .effects;
    assert_eq!(claimable.len(), 3);
    for effect in &claimable {
        plane
            .sekai
            .claim_action_work(with_principal(
                ClaimActionWorkRequest {
                    effect_id: effect.effect_id.clone(),
                    runtime_id: INVESTIGATION_RUNTIME.into(),
                    request_id: format!("crashed-{}", effect.effect_id),
                    ttl_ms: 1,
                },
                INVESTIGATION_RUNTIME,
            ))
            .await
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let analyzer = Scripted::tenkai();
    let first = drain(&plane, &analyzer).await;
    assert_eq!(first.len(), 3, "expired claims are taken over");
    // A second runtime finds nothing left and records nothing new.
    let second = drain(&plane, &analyzer).await;
    assert!(second.is_empty());
    let findings = plane
        .db
        .list_all_objects(&sekai_chisei::domain::ListFilter {
            kind: Some(KIND_FINDING.into()),
            namespace: Some(NAMESPACE.into()),
            ..Default::default()
        })
        .unwrap();
    let ids: std::collections::BTreeSet<_> = findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids.len(), findings.len());
    assert!(
        findings.len() <= 2,
        "one finding per classification: {ids:?}"
    );
}

#[test]
fn the_prompt_is_sent_once_and_bounded() {
    let observations = (0..PROMPT_OBSERVATION_CAP * 4)
        .map(|index| feedback_investigation::ObservationView {
            object_id: format!("o-{index}"),
            created_ms: index as i64,
            problem_signature: SIGNATURE.into(),
            occurrence_ids: vec![format!("op-{index}")],
            classification: "defect".into(),
            disposition: "open".into(),
        })
        .collect::<Vec<_>>();
    let request = AnalysisRequest {
        namespace: NAMESPACE.into(),
        signature: SIGNATURE.into(),
        distinct_operations: observations.len(),
        observations,
    };
    let input = analysis_input(&request, INVESTIGATION_RUNTIME);
    assert!(input.messages.is_empty(), "spec only, never both");
    assert_eq!(input.spec.matches("- id=").count(), PROMPT_OBSERVATION_CAP);
    assert!(
        input
            .spec
            .contains(&format!("o-{}", PROMPT_OBSERVATION_CAP * 4 - 1))
    );
    assert!(input.estimated_tokens > 1_024);
}

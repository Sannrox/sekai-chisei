//! Feedback runtimes outside the plane: investigation and GitHub publication
//! through public RPCs against an in-process plane. The analyzer and GitHub
//! are scripted; the plane, claims, bindings, permits, and Action writes are
//! real.

#[allow(dead_code)]
#[path = "../adapters/feedback_investigation.rs"]
mod feedback_investigation;

#[allow(dead_code)]
#[path = "../adapters/source_writeback.rs"]
mod source_writeback;

#[allow(dead_code)]
#[path = "../adapters/feedback_github_issues.rs"]
mod feedback_github_issues;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;

use feedback_github_issues::{
    ABSENT, GitHubIssue, GitHubIssues, IssuePublisher, IssueTracker, Publish, draft,
    maintainer_text,
};
use feedback_investigation::{
    AnalysisError, AnalysisRequest, Attribution, Dispatch, FeedbackAnalyzer, FilingDecision,
    InvestigationAnalysis, Investigator, PROMPT_OBSERVATION_CAP, analysis_input,
    publication_permitted,
};
use sekai_chisei::chisei::external_permit::signing_key_from_hex;
use sekai_chisei::chisei::sekai_facts::SekaiFacts;
use sekai_chisei::config::Config;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    ClaimActionWorkRequest, GetObjectRequest, ListClaimableActionWorkRequest,
    SubmitActionInstanceRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::action_binding::{
    ACTION_BINDING_CONTRACT, ActionBinding, ParameterSource,
};
use sekai_chisei::sekai::action_effect::EFFECT_STATUS_CLAIMED;
use sekai_chisei::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use sekai_chisei::sekai::action_policy::ActionPolicy;
use sekai_chisei::sekai::evidence::{
    EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
    EvidenceSignal, EvidenceTarget, SchemaCompatibility,
};
use sekai_chisei::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle;
use sekai_chisei::sekai::evidence_store::{EvidenceProducerCapability, canonical_content_digest};
use sekai_chisei::sekai::execution_evidence::EXECUTION_EVIDENCE_TYPE;
use sekai_chisei::sekai::feedback_package::{
    ACTION_DISPATCH, ACTION_INVESTIGATION, ACTION_OBSERVATION, EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_TYPE, INVESTIGATION_RUNTIME, KIND_FINDING, KIND_HYPOTHESIS, KIND_INVESTIGATION_RESULT,
    KIND_OBSERVATION, PACKAGE_VERSION, install,
};
use sekai_chisei::sekai::object_change_subscription::OP_CREATE;
use sekai_chisei::sekai::security::Role;
use serde_json::json;
use source_writeback::{PermitTrust, WritebackIntent, WritebackProfile};
use tonic::Request;
use tonic::metadata::MetadataValue;

const NAMESPACE: &str = "ops";
const OPERATOR: &str = "local";
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

/// One attempt of `operation` in the `prod` scope, observed now.
fn observe(db: &RuntimeDb, id: &str, operation: &str, classification: &str) {
    observe_at(db, id, operation, "prod", now_ms(), classification);
}

/// Seed one observation the way a producer delivers it: accepted evidence,
/// then the observation Action naming it. The occurrence is the attempt, so
/// every observation has its own; `operation` groups attempts.
fn observe_at(
    db: &RuntimeDb,
    id: &str,
    operation: &str,
    scope: &str,
    observed_at_ms: i64,
    classification: &str,
) {
    let now = now_ms();
    let content = json!({
        "problem_signature": SIGNATURE,
        "occurrence_ids": id,
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
                    "occurrence_ids": id,
                    "operation_id": operation,
                    "observed_at_ms": observed_at_ms,
                    "scope": scope,
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
    analysis: Result<InvestigationAnalysis, fn() -> AnalysisError>,
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

    fn failing(error: fn() -> AnalysisError) -> Self {
        Self {
            analysis: Err(error),
            calls: Cell::new(0),
        }
    }
}

impl FeedbackAnalyzer for Scripted {
    async fn analyze(&self, _: &AnalysisRequest) -> Result<InvestigationAnalysis, AnalysisError> {
        self.calls.set(self.calls.get() + 1);
        self.analysis.clone().map_err(|error| error())
    }
}

fn investigator() -> Investigator {
    Investigator {
        namespace: NAMESPACE.into(),
        binding_id: BINDING.into(),
        instance_id: uuid::Uuid::new_v4().to_string(),
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
    while let Some(dispatch) = runtime
        .run_once(&plane.sekai, analyzer, now_ms())
        .await
        .unwrap()
    {
        if let Dispatch::Investigated(report) = dispatch {
            reports.push(report);
        }
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
    observe(&plane.db, "o-3", "op-1", "defect");
    let reports = drain(&plane, &Scripted::tenkai()).await;
    assert_eq!(reports.len(), 3);
    assert!(
        reports
            .iter()
            .all(|report| report.filing == FilingDecision::Internal)
    );
}

#[tokio::test]
async fn a_drained_backlog_is_not_recurrence() {
    let plane = armed_plane().await;
    let day = feedback_investigation::RECURRENCE_WINDOW_MS;
    let now = now_ms();
    for (index, (id, op)) in [("o-1", "op-1"), ("o-2", "op-2"), ("o-3", "op-3")]
        .into_iter()
        .enumerate()
    {
        // Observed days apart, ingested together after an outage.
        observe_at(
            &plane.db,
            id,
            op,
            "prod",
            now - index as i64 * 2 * day,
            "defect",
        );
    }
    let analyzer = Scripted::tenkai();
    let reports = drain(&plane, &analyzer).await;
    assert_eq!(
        analyzer.calls.get(),
        1,
        "expired triggers are never analyzed"
    );
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].filing, FilingDecision::Internal);
}

#[tokio::test]
async fn a_blank_scope_is_never_investigated() {
    let plane = armed_plane().await;
    observe_at(&plane.db, "o-1", "op-1", " ", now_ms(), "defect");
    let runtime = investigator();
    runtime.run_binding(&plane.sekai).await.unwrap();
    let analyzer = Scripted::tenkai();
    assert!(
        runtime
            .run_once(&plane.sekai, &analyzer, now_ms())
            .await
            .is_err()
    );
    assert_eq!(analyzer.calls.get(), 0);
}

#[tokio::test]
async fn one_signature_in_two_scopes_is_two_problems() {
    let plane = armed_plane().await;
    let now = now_ms();
    for (id, op, scope) in [
        ("o-1", "op-1", "prod"),
        ("o-2", "op-2", "prod"),
        ("o-3", "op-3", "staging"),
    ] {
        observe_at(&plane.db, id, op, scope, now, "defect");
    }
    let analyzer = Scripted::tenkai();
    let reports = drain(&plane, &analyzer).await;
    assert_eq!(analyzer.calls.get(), 2, "one model call per scope");
    assert!(
        reports
            .iter()
            .all(|report| report.filing == FilingDecision::Internal)
    );
}

/// Submit one investigation result as `principal`, which the plane stamps.
async fn record_investigation(plane: &Plane, principal: &str, parameters: serde_json::Value) {
    let key = parameters["object_id"].as_str().unwrap().to_string();
    plane
        .sekai
        .submit_action_instance(with_principal(
            SubmitActionInstanceRequest {
                namespace: NAMESPACE.into(),
                type_id: ACTION_INVESTIGATION.into(),
                version: PACKAGE_VERSION.into(),
                parameters_json: parameters.to_string(),
                idempotency_key: key,
                ..Default::default()
            },
            principal,
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_object_planted_at_the_bucket_id_is_never_trusted() {
    let plane = armed_plane().await;
    observe(&plane.db, "o-1", "op-1", "defect");
    let window = now_ms().div_euclid(feedback_investigation::RECURRENCE_WINDOW_MS);
    // Both windows, so a run that crosses midnight still meets the plant.
    for window in [window, window + 1] {
        let request = AnalysisRequest {
            namespace: NAMESPACE.into(),
            signature: SIGNATURE.into(),
            scope: "prod".into(),
            observations: Vec::new(),
            distinct_operations: 0,
            window,
        };
        let request_id = analysis_input(&request, INVESTIGATION_RUNTIME).request_id;
        let key = request_id.strip_prefix("feedback-inv-").unwrap();
        record_investigation(
            &plane,
            OPERATOR,
            json!({
                "object_id": format!("fb-inv-{key}"),
                "name": SIGNATURE,
                "observation_id": "o-1",
                "outcome": "{\"attribution\":\"tenkai\"}",
                "measured": false,
            }),
        )
        .await;
    }
    let runtime = investigator();
    runtime.run_binding(&plane.sekai).await.unwrap();
    let analyzer = Scripted::tenkai();
    assert!(
        runtime
            .run_once(&plane.sekai, &analyzer, now_ms())
            .await
            .is_err()
    );
    assert_eq!(analyzer.calls.get(), 0);
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
async fn a_writer_submitted_measurement_does_not_qualify() {
    let plane = armed_plane().await;
    observe(&plane.db, "o-1", "op-1", "defect");
    plane
        .sekai
        .submit_action_instance(with_principal(
            SubmitActionInstanceRequest {
                namespace: NAMESPACE.into(),
                type_id: ACTION_INVESTIGATION.into(),
                version: PACKAGE_VERSION.into(),
                parameters_json: json!({
                    "object_id": "inv-forged",
                    "name": SIGNATURE,
                    "observation_id": "o-1",
                    "outcome": "reproduced",
                    "measured": true,
                })
                .to_string(),
                idempotency_key: "forged".into(),
                ..Default::default()
            },
            OPERATOR,
        ))
        .await
        .unwrap();
    let reports = drain(&plane, &Scripted::tenkai()).await;
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].filing, FilingDecision::Internal);
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

async fn claimable(plane: &Plane) -> Vec<sekai_chisei::grpc::pb::sekai::ActionEffect> {
    plane
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
        .effects
}

#[tokio::test]
async fn budget_and_outages_write_nothing_and_leave_the_dispatch_for_retry() {
    let refusals: [fn() -> AnalysisError; 2] = [
        || AnalysisError::BudgetExhausted,
        || AnalysisError::Unavailable("planner unreachable".into()),
    ];
    for refusal in refusals {
        let plane = armed_plane().await;
        observe(&plane.db, "o-1", "op-1", "defect");
        let runtime = investigator();
        runtime.run_binding(&plane.sekai).await.unwrap();
        let dispatch = claimable(&plane).await.remove(0).effect_id;
        let analyzer = Scripted::failing(refusal);
        assert!(
            runtime
                .run_once(&plane.sekai, &analyzer, now_ms())
                .await
                .is_err()
        );
        assert_eq!(analyzer.calls.get(), 1);
        for kind in [KIND_INVESTIGATION_RESULT, KIND_FINDING] {
            let written = plane
                .db
                .list_all_objects(&sekai_chisei::domain::ListFilter {
                    kind: Some(kind.into()),
                    namespace: Some(NAMESPACE.into()),
                    ..Default::default()
                })
                .unwrap();
            assert!(written.is_empty(), "no {kind} anchors the bucket");
        }
        let effect = plane.db.get_action_effect(&dispatch).unwrap().unwrap();
        assert_eq!(
            effect.status, EFFECT_STATUS_CLAIMED,
            "unacked, so it is offered again when the lease expires"
        );
    }
}

#[tokio::test]
async fn two_processes_never_share_a_live_claim() {
    let plane = armed_plane().await;
    observe(&plane.db, "o-1", "op-1", "defect");
    let (first, second) = (investigator(), investigator());
    first.run_binding(&plane.sekai).await.unwrap();
    // Both list the dispatch before either claims it.
    let listed = claimable(&plane).await;
    assert!(first.claim(&plane.sekai).await.unwrap().is_some());
    let late = plane
        .sekai
        .claim_action_work(with_principal(
            ClaimActionWorkRequest {
                effect_id: listed[0].effect_id.clone(),
                runtime_id: INVESTIGATION_RUNTIME.into(),
                request_id: second.claim_request_id(&listed[0].effect_id),
                ttl_ms: 60_000,
            },
            INVESTIGATION_RUNTIME,
        ))
        .await;
    assert!(late.is_err(), "the second process loses the race");
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
    let pending = claimable(&plane).await;
    assert_eq!(pending.len(), 3);
    for effect in &pending {
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
            observed_ms: index as i64,
            problem_signature: SIGNATURE.into(),
            scope: "prod".into(),
            operation_id: format!("op-{index}"),
            classification: "defect".into(),
            disposition: "open".into(),
        })
        .collect::<Vec<_>>();
    let request = AnalysisRequest {
        namespace: NAMESPACE.into(),
        signature: SIGNATURE.into(),
        scope: "prod".into(),
        distinct_operations: observations.len(),
        observations,
        window: 7,
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
    let next_window = AnalysisRequest {
        window: 8,
        ..request.clone()
    };
    assert_ne!(
        analysis_input(&next_window, INVESTIGATION_RUNTIME).request_id,
        input.request_id,
        "each window keeps its own planner records"
    );
}

// ---- GitHub publication ----

const EXECUTOR: &str = "executor:github-issues";
const EXECUTOR_LOGIN: &str = "feedback-bot";
const REPOSITORY: &str = "tenkai-org/tenkai";
const PERMIT_SEED: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const PERMIT_ISSUER: &str = "issuer:test";
const PERMIT_KEY_ID: &str = "key-1";

/// In-memory repository. `lose_next_create` commits the issue and then fails,
/// the way a dropped response looks to the executor.
#[derive(Default)]
struct FakeGitHub {
    issues: RefCell<Vec<GitHubIssue>>,
    creates: Cell<usize>,
    updates: Cell<usize>,
    lose_next_create: Cell<bool>,
    clock: Cell<i64>,
}

impl FakeGitHub {
    fn tick(&self) -> i64 {
        self.clock.set(self.clock.get().max(now_ms()) + 1);
        self.clock.get()
    }

    /// An issue opened by `author`, the way anyone can on a public repository.
    fn open_as(&self, author: &str, title: &str, body: &str) -> GitHubIssue {
        let at = self.tick();
        let issue = GitHubIssue {
            number: self.issues.borrow().len() as u64 + 1,
            title: title.into(),
            body: body.into(),
            created_ms: at,
            updated_ms: at,
            author: author.into(),
        };
        self.issues.borrow_mut().push(issue.clone());
        issue
    }
}

impl GitHubIssues for FakeGitHub {
    fn login(&self) -> &str {
        EXECUTOR_LOGIN
    }

    fn list(&self) -> Result<Vec<GitHubIssue>, String> {
        Ok(self.issues.borrow().clone())
    }

    fn create(&self, title: &str, body: &str) -> Result<GitHubIssue, String> {
        let issue = self.open_as(EXECUTOR_LOGIN, title, body);
        self.creates.set(self.creates.get() + 1);
        if self.lose_next_create.replace(false) {
            return Err("response lost".into());
        }
        Ok(issue)
    }

    fn update(&self, number: u64, title: &str, body: &str) -> Result<GitHubIssue, String> {
        let at = self.tick();
        let mut issues = self.issues.borrow_mut();
        let issue = issues
            .iter_mut()
            .find(|issue| issue.number == number)
            .ok_or("no such issue")?;
        issue.title = title.into();
        issue.body = body.into();
        issue.updated_ms = at;
        self.updates.set(self.updates.get() + 1);
        Ok(issue.clone())
    }
}

struct Publication {
    plane: Plane,
    chisei: ChiseiServiceImpl,
    profile: WritebackProfile,
    tracker: IssueTracker<FakeGitHub>,
    publisher: IssuePublisher,
    finding_id: String,
}

/// A plane with one qualifying finding and a bootstrapped writeback profile.
async fn publication() -> Publication {
    let plane = armed_plane().await;
    for (id, op) in [("o-1", "op-1"), ("o-2", "op-2"), ("o-3", "op-3")] {
        observe(&plane.db, id, op, "defect");
    }
    let finding_id = drain(&plane, &Scripted::tenkai())
        .await
        .into_iter()
        .rfind(|report| report.filing == FilingDecision::Qualifying)
        .unwrap()
        .finding_id;
    let now = now_ms();
    plane
        .db
        .upsert_action_policy(&ActionPolicy::allow_all(format!("agent:{OPERATOR}")))
        .unwrap();
    plane
        .db
        .upsert_evidence_producer(
            &EvidenceProducerCapability {
                producer_identity: EXECUTOR.into(),
                source_types: vec!["host_executor".into()],
                source_instances: vec![format!("{EXECUTOR}:writeback")],
                evidence_types: vec![EXECUTION_EVIDENCE_TYPE.into()],
                target_kinds: vec![KIND_FINDING.into(), "action".into()],
                max_payload_bytes: 64 * 1024,
                max_relationships: 8,
                ..producer()
            },
            now,
        )
        .unwrap();
    let store = SekaiStore::from_shared_runtime(plane.db.clone());
    let chisei = ChiseiServiceImpl::new(
        sekai_chisei::chisei_store::ChiseiStore::from_shared_runtime(plane.db.clone()),
        fixture_config(),
    )
    .with_sekai_facts(SekaiFacts::in_process(store))
    .unwrap();
    let profile = WritebackProfile {
        namespace: NAMESPACE.into(),
        action_type_id: "feedback.github_issue.write".into(),
        action_type_version: "1".into(),
        external_action_type: "github.issues.write/v1".into(),
        parameter_schema: "github.issues.write.params/v1".into(),
        executor: EXECUTOR.into(),
        harness: "harness:feedback-github".into(),
        host_capability: "github.issues.write/v1".into(),
        target_kind: KIND_FINDING.into(),
    };
    profile.bootstrap(&plane.sekai, OPERATOR).await.unwrap();
    Publication {
        plane,
        chisei,
        profile,
        tracker: IssueTracker {
            github: FakeGitHub::default(),
            repository: REPOSITORY.into(),
            daily_cap: 0,
        },
        publisher: IssuePublisher {
            namespace: NAMESPACE.into(),
            principal: OPERATOR.into(),
        },
        finding_id,
    }
}

impl Publication {
    async fn decide(&self) -> Publish {
        self.publisher
            .decide(&self.plane.sekai, &self.tracker, &self.finding_id)
            .await
            .unwrap()
    }

    async fn write(&self, intent: &WritebackIntent) -> Result<String, String> {
        let key = signing_key_from_hex(PERMIT_SEED).unwrap().verifying_key();
        let trust = PermitTrust {
            key: &key,
            issuer: PERMIT_ISSUER,
            key_id: PERMIT_KEY_ID,
        };
        self.profile
            .run(
                &self.plane.sekai,
                &self.chisei,
                &self.tracker,
                OPERATOR,
                &trust,
                intent,
            )
            .await
            .map(|outcome| outcome.new_version)
    }

    /// Decide and write until nothing is left to do.
    async fn publish(&self) {
        while let Publish::Write(intent) = self.decide().await {
            self.write(&intent).await.unwrap();
        }
    }

    fn issue_count(&self) -> usize {
        self.tracker.github.issues.borrow().len()
    }
}

fn written(publish: Publish) -> WritebackIntent {
    match publish {
        Publish::Write(intent) => intent,
        other => panic!("expected a write, got {other:?}"),
    }
}

#[tokio::test]
async fn a_qualifying_finding_publishes_one_sanitized_issue() {
    let publication = publication().await;
    publication.publish().await;
    let issues = publication.tracker.github.issues.borrow();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].title, "feedback: api tenkai_failed");
    assert!(
        issues[0]
            .body
            .contains("3 observations across 3 operations.")
    );
    assert!(issues[0].body.contains("## Attribution\n\ntenkai"));
    assert!(issues[0].body.contains("Not independently measured."));
}

#[tokio::test]
async fn a_measured_reproduction_of_any_observation_is_published() {
    let publication = publication().await;
    record_investigation(
        &publication.plane,
        INVESTIGATION_RUNTIME,
        json!({
            // Sorts before the bucket analysis on the same observation.
            "object_id": "a-measured",
            "name": SIGNATURE,
            "observation_id": "o-1",
            "outcome": "reproduced",
            "measured": true,
        }),
    )
    .await;
    publication.publish().await;
    let issues = publication.tracker.github.issues.borrow();
    assert!(issues[0].body.contains("## Reproduction\n\nMeasured."));
    assert!(issues[0].body.contains("## Attribution\n\ntenkai"));
}

#[tokio::test]
async fn a_lost_create_is_reconciled_without_a_second_issue() {
    let publication = publication().await;
    let intent = written(publication.decide().await);
    assert_eq!(intent.expected_version, ABSENT);
    publication.tracker.github.lose_next_create.set(true);
    assert!(publication.write(&intent).await.is_err());
    // The issue exists; the next decision sees it and has nothing to change.
    assert_eq!(publication.decide().await, Publish::Unchanged);
    assert_eq!(publication.tracker.github.creates.get(), 1);
    // Replaying the stale intent is refused instead of creating again.
    assert!(publication.write(&intent).await.is_err());
    assert_eq!(publication.issue_count(), 1);
}

#[tokio::test]
async fn an_unchanged_finding_needs_no_permit_or_write() {
    let publication = publication().await;
    publication.publish().await;
    let writes =
        || publication.tracker.github.creates.get() + publication.tracker.github.updates.get();
    let before = writes();
    for _ in 0..3 {
        assert_eq!(publication.decide().await, Publish::Unchanged);
    }
    assert_eq!(writes(), before);
}

#[tokio::test]
async fn another_namespaces_marker_is_never_adopted() {
    let publication = publication().await;
    let foreign = draft("other", SIGNATURE, "prod", None, false, &[]);
    publication
        .tracker
        .github
        .create(&foreign.title, &foreign.managed_body)
        .unwrap();
    let intent = written(publication.decide().await);
    assert_eq!(intent.expected_version, ABSENT);
    publication.write(&intent).await.unwrap();
    assert_eq!(publication.issue_count(), 2);
}

#[tokio::test]
async fn issues_opened_by_others_are_never_adopted_or_counted() {
    let publication = publication().await;
    let ours = written(publication.decide().await);
    let github = &publication.tracker.github;
    // A copy of the real managed section, plus enough spam to fill the cap.
    let copy = format!("<!-- {} -->\nhijack", ours.key);
    github.open_as("outsider", "copied", &copy);
    for _ in 0..feedback_github_issues::DEFAULT_DAILY_CAP {
        github.open_as("outsider", "spam", "<!-- sekai-feedback:0000 -->");
    }
    let intent = written(publication.decide().await);
    assert_eq!(intent.expected_version, ABSENT);
    publication.write(&intent).await.unwrap();
    let issues = github.issues.borrow();
    assert_eq!(issues[0].body, copy, "the outsider's issue is untouched");
    assert_eq!(issues.last().unwrap().author, EXECUTOR_LOGIN);
}

#[tokio::test]
async fn a_new_occurrence_updates_the_managed_section_and_keeps_maintainer_text() {
    let publication = publication().await;
    publication.publish().await;
    {
        let mut issues = publication.tracker.github.issues.borrow_mut();
        issues[0]
            .body
            .push_str("\n\nMaintainer: tracked in the next release.");
        issues[0].updated_ms += 1;
    }
    observe(&publication.plane.db, "o-4", "op-4", "defect");
    let intent = written(publication.decide().await);
    assert_ne!(intent.expected_version, ABSENT);
    publication.write(&intent).await.unwrap();
    let issues = publication.tracker.github.issues.borrow();
    assert_eq!(issues.len(), 1);
    assert!(
        issues[0]
            .body
            .contains("4 observations across 4 operations.")
    );
    assert!(
        issues[0]
            .body
            .ends_with("Maintainer: tracked in the next release.")
    );
}

#[tokio::test]
async fn a_marker_quoted_in_maintainer_text_is_not_a_match() {
    let publication = publication().await;
    let ours = written(publication.decide().await);
    let quoting = draft(NAMESPACE, "api:other_failure", "prod", None, false, &[]);
    publication
        .tracker
        .github
        .create(
            &quoting.title,
            &format!("{}\n\nRelated: <!-- {} -->", quoting.managed_body, ours.key),
        )
        .unwrap();
    assert_eq!(written(publication.decide().await).expected_version, ABSENT);
}

#[tokio::test]
async fn a_lost_end_marker_refuses_the_update_and_keeps_maintainer_text() {
    let publication = publication().await;
    publication.publish().await;
    let edited = {
        let mut issues = publication.tracker.github.issues.borrow_mut();
        issues[0].body =
            issues[0].body.replace("<!-- /sekai-feedback -->", "") + "\n\nMaintainer notes.";
        issues[0].updated_ms += 1;
        issues[0].body.clone()
    };
    observe(&publication.plane.db, "o-4", "op-4", "defect");
    let error = publication
        .publisher
        .decide(
            &publication.plane.sekai,
            &publication.tracker,
            &publication.finding_id,
        )
        .await
        .unwrap_err();
    assert!(error.contains("end marker"), "{error}");
    assert_eq!(publication.tracker.github.issues.borrow()[0].body, edited);
}

#[tokio::test]
async fn the_daily_cap_defers_new_issues() {
    let publication = publication().await;
    for index in 0..feedback_github_issues::DEFAULT_DAILY_CAP {
        let other = draft(
            NAMESPACE,
            &format!("api:other_{index}"),
            "prod",
            None,
            false,
            &[],
        );
        publication
            .tracker
            .github
            .create(&other.title, &other.managed_body)
            .unwrap();
    }
    assert_eq!(publication.decide().await, Publish::DailyCapReached);
}

#[test]
fn signature_text_cannot_format_ping_or_end_the_managed_section() {
    let issue = draft(
        NAMESPACE,
        "api @acme/oncall:<!--/sekai-feedback--> **x**",
        "prod",
        None,
        false,
        &[],
    );
    for needle in ["@", "<!--/", "**"] {
        assert!(!issue.title.contains(needle), "{}", issue.title);
    }
    let body = issue
        .managed_body
        .replacen("<!-- /sekai-feedback -->", "", 1);
    assert!(!body.contains("sekai-feedback-->"), "{body}");
    assert!(!body.contains('@'), "{body}");
    assert_eq!(maintainer_text(&issue.managed_body).as_deref(), Some(""));
}

#[test]
fn the_published_reason_is_the_last_signature_segment() {
    let issue = draft(
        NAMESPACE,
        "controller:apply:tenkai_failed",
        "prod",
        None,
        false,
        &[],
    );
    assert!(
        issue.managed_body.contains("## Reason\n\ntenkai_failed"),
        "{}",
        issue.managed_body
    );
}

#[test]
fn only_plain_identifiers_and_semver_are_published() {
    for (signature, fragment) in [
        (
            "connect(db01.tenant.example):timeout",
            "db01.tenant.example",
        ),
        ("file=/home/ops/.ssh/id_rsa:read_failed", "id_rsa"),
        ("user=ops@tenant.example:denied", "tenant.example"),
        ("api:fd00::1234", "1234"),
        ("open(C:\\Users\\alice\\secret.txt):failed", "alice"),
        ("sync github.com/acme/private-ops:failed", "private-ops"),
        (
            "tenkai-org/tenkai-private/issues/4:failed",
            "tenkai-private",
        ),
    ] {
        let issue = draft(NAMESPACE, signature, "prod", None, false, &[]);
        for text in [&issue.title, &issue.managed_body] {
            assert!(!text.contains(fragment), "{fragment:?} leaked: {text}");
        }
    }
    let plain = draft(NAMESPACE, "api:tenkai_failed", "prod", None, false, &[]);
    assert_eq!(plain.title, "feedback: api tenkai_failed");
    let mut observation = sekai_chisei::grpc::pb::sekai::Object::default();
    for (version, published) in [
        ("0.7.1", true),
        ("0.7.1-rc.1", true),
        ("10.1.2.3", false),
        ("ops.host", false),
        ("1.0.0-db01.tenant.example", false),
        ("0.7.1+ops-alice", false),
        ("1.2.3-10.0.0.12", false),
    ] {
        observation
            .properties
            .insert("tenkai_version".into(), version.into());
        let issue = draft(
            NAMESPACE,
            SIGNATURE,
            "prod",
            None,
            false,
            std::slice::from_ref(&observation),
        );
        assert_eq!(issue.managed_body.contains(version), published, "{version}");
    }
}

fn fixture_config() -> Config {
    Config {
        grpc_port: 0,
        sekai_bind: None,
        ops_port: None,
        ops_bind: "127.0.0.1".into(),
        http_port: None,
        http_bind: "127.0.0.1".into(),
        sekai_socket: None,
        db_path: ":memory:".into(),
        anthropic_api_key: None,
        openai_api_key: None,
        ollama_url: "http://127.0.0.1:11434".into(),
        native_llm_url: None,
        sample_rate: 0.0,
        sample_risk_threshold: 0.7,
        scoring_enabled: false,
        scoring_interval_secs: 60,
        scoring_model: "claude-opus-4-8".into(),
        scoring_batch_size: 16,
        default_data_class: "unclassified".into(),
        safe_egress_providers: vec![],
        gateway_provided_providers: vec![],
        routing_endpoint_allowlist: vec![],
        routing_credential_refs: vec![],
        gateway_receipt_principals: vec![],
        leak_review_model: None,
        tls_cert: None,
        tls_key: None,
        allow_plaintext: false,
        insecure: true,
        permit_signing_key: Some(PERMIT_SEED.into()),
        permit_issuer: PERMIT_ISSUER.into(),
        permit_key_id: PERMIT_KEY_ID.into(),
        governed_subject_provenance_signing_key: Some("09".repeat(32)),
        governed_subject_provenance_key_not_before_ms: 0,
        governed_subject_provenance_key_expires_at_ms: i64::MAX,
        governed_subject_provenance_ttl_ms: 24 * 60 * 60 * 1_000,
        site_id: "local".into(),
        budget_topology: Default::default(),
        assertion_issuer: None,
        assertion_audience: None,
        assertion_hmac_key: None,
        sekai_endpoint: None,
        actor_chain_enforcement: false,
        principal_requests_per_minute: 60,
        agent_requests_per_minute: 60,
    }
}

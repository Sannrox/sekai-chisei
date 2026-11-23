//! Stage spans a governed Action admission emits (#2642).
//!
//! A separate test binary so its process-global subscriber does not race the
//! library tests' own global log capture.

use std::sync::Mutex;

use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt as _};

use sekai_core::db::runtime_db::RuntimeDb;
use sekai_core::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use sekai_core::sekai::action_ports::ActionBudgetPort;
use sekai_core::sekai::governed_action_type::{EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType};
use sekai_core::sekai::object_security::PrincipalPolicyContext;

/// Every stage span opened, as `(span id, stage, outcome)` in open order.
/// The only spans recorded are those carrying a `stage` field.
#[derive(Default)]
struct Stages {
    spans: Mutex<Vec<(u64, String, String)>>,
}

struct Field<'a>(&'a str, Option<String>);

impl tracing::field::Visit for Field<'_> {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == self.0 {
            self.1 = Some(value.into());
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for &'static Stages {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        _: Context<'_, S>,
    ) {
        let mut stage = Field("stage", None);
        attrs.record(&mut stage);
        if let Some(stage) = stage.1 {
            self.spans
                .lock()
                .unwrap()
                .push((id.into_u64(), stage, String::new()));
        }
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _: Context<'_, S>,
    ) {
        let mut outcome = Field("outcome", None);
        values.record(&mut outcome);
        if let Some(outcome) = outcome.1
            && let Some(span) = self
                .spans
                .lock()
                .unwrap()
                .iter_mut()
                // The registry reuses ids of closed spans; the newest is live.
                .rfind(|s| s.0 == id.into_u64())
        {
            span.2 = outcome;
        }
    }
}

struct ExhaustedBudget;

impl ActionBudgetPort for ExhaustedBudget {
    fn check(&self, _subject: &str, _amount: i32) -> Result<(), String> {
        Err("exhausted".into())
    }

    fn record(&self, _subject: &str, _amount: i32) {}

    fn record_once(&self, _: &str, _: i32, _: &str, _: i64) -> Result<(), String> {
        Err("exhausted".into())
    }
}

fn dispatch_request() -> ActionInstanceAdmissionRequest {
    ActionInstanceAdmissionRequest {
        agent_turn: None,
        namespace: "acme".into(),
        type_id: "dispatch".into(),
        version: "1".into(),
        parameters_json: r#"{"runtime":"shikigami"}"#.into(),
        idempotency_key: "idem-1".into(),
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
        binding_approval_rule: String::new(),
        offline: None,
    }
}

#[test]
fn exhausted_budget_traces_a_refused_budget_stage_after_policy() {
    let stages: &'static Stages = Box::leak(Box::default());
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(stages))
        .expect("only subscriber in this binary");

    let db = RuntimeDb::memory();
    db.put_governed_action_type(
        GovernedActionType {
            namespace: "acme".into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
            enabled: true,
            ..Default::default()
        },
        "operator",
        1,
    )
    .unwrap();
    stages.spans.lock().unwrap().clear();

    // Store checkouts trace only inside a request span, as a gRPC handler's.
    let denied = tracing::info_span!("request").in_scope(|| {
        ActionInstanceAdmission::new(&db, Some(&ExhaustedBudget))
            .admit(dispatch_request(), "alice", 10)
            .unwrap()
    });
    assert_eq!(denied.instance.budget_decision, "budget_exceeded");

    let spans = stages.spans.lock().unwrap();
    let deciding: Vec<_> = spans
        .iter()
        .filter(|(_, stage, _)| stage != "persistence")
        .map(|(_, stage, outcome)| (stage.as_str(), outcome.as_str()))
        .collect();
    assert_eq!(deciding, [("policy_decision", "ok"), ("budget", "refused")]);
    assert!(
        spans
            .iter()
            .any(|(_, stage, outcome)| stage == "persistence" && outcome == "ok"),
        "{spans:?}"
    );
}

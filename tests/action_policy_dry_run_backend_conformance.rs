//! SQLite/PostgreSQL conformance for the historical Action policy dry-run
//! (#2121): real admissions record their policy decision (#3016), and a
//! candidate replays them without writing anything but its audit decision.

use sekai_chisei::chisei::action_policy_dry_run::ActionDryRunDelta;
use sekai_chisei::composition::action_policy_dry_run::run_action_policy_dry_run;
use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{ListFilter, Object};
use sekai_chisei::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use sekai_chisei::sekai::action_policy::{ActionDecision, ActionPolicy};
use sekai_chisei::sekai::audit::DecisionFilter;
use sekai_chisei::sekai::governed_action_type::{EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType};
use sekai_chisei::sekai::risk_class::RiskClass;
use sekai_chisei::sekai::security::{Grant, Role};
use std::collections::HashMap;
use std::sync::Arc;

fn seed_namespace(db: &RuntimeDb, namespace: &str, principal: &str) {
    let object_id = format!("ns-{namespace}");
    db.create_object(&Object {
        id: object_id.clone(),
        kind: "namespace".into(),
        name: namespace.into(),
        namespace: String::new(),
        external_id: format!("namespace:{namespace}"),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    })
    .unwrap();
    db.create_grant(&Grant {
        id: format!("g-{namespace}-{principal}"),
        object_id,
        principal: principal.into(),
        role: Role::Viewer,
        created: 1,
        ..Default::default()
    })
    .unwrap();
}

fn submit(namespace: &str, key: &str) -> ActionInstanceAdmissionRequest {
    ActionInstanceAdmissionRequest {
        agent_turn: None,
        namespace: namespace.into(),
        type_id: "dispatch".into(),
        version: "1".into(),
        parameters_json: r#"{"runtime":"shikigami"}"#.into(),
        idempotency_key: key.into(),
        evidence_submission_ids: Vec::new(),
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
        binding_approval_rule: String::new(),
        binding_id: String::new(),
        offline: None,
    }
}

/// Everything a dry-run must leave alone.
fn state(db: &RuntimeDb, namespace: &str) -> (Vec<String>, Vec<String>) {
    let mut objects: Vec<String> = db
        .list_all_objects(&ListFilter::default())
        .unwrap()
        .into_iter()
        .map(|object| {
            let properties: std::collections::BTreeMap<_, _> =
                object.properties.into_iter().collect();
            format!("{}:{}:{properties:?}", object.id, object.updated)
        })
        .collect();
    objects.sort();
    let instances = db
        .list_action_instances(namespace, None, None, 100)
        .unwrap()
        .into_iter()
        .map(|instance| format!("{}:{}", instance.instance_id, instance.status))
        .collect();
    (objects, instances)
}

fn exercise(db: &RuntimeDb, namespace: &str) {
    seed_namespace(db, namespace, "auditor");
    db.put_governed_action_type(
        GovernedActionType {
            namespace: namespace.into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            description: "dispatch work".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
            enabled: true,
            ..Default::default()
        },
        "operator",
        1,
    )
    .unwrap();
    let current = ActionPolicy::allow_all(namespace);
    db.upsert_action_policy(&current).unwrap();
    // Carol's own policy decides her submits; a namespace candidate does
    // not replace it.
    db.upsert_action_policy(&ActionPolicy::allow_all("agent:carol"))
        .unwrap();
    let admission = ActionInstanceAdmission::new(db, None);
    for (actor, at) in [("alice", 1_000), ("bob", 1_001), ("carol", 1_002)] {
        let admitted = admission
            .admit(submit(namespace, actor), actor, at)
            .unwrap()
            .instance;
        assert_eq!(admitted.status, "admitted");
    }

    let mut candidate = current.clone();
    candidate
        .risk_overrides
        .insert(RiskClass::Write, ActionDecision::RequireApproval);
    let before = state(db, namespace);
    let report =
        run_action_policy_dry_run(db, "auditor", namespace, 0, 10_000, &candidate, "console")
            .unwrap();
    assert_eq!(report.counts.evaluated, 3);
    assert_eq!(report.counts.unchanged, 1);
    assert_eq!(report.counts.would_require_approval, 2);
    let changed = &report.samples[&ActionDryRunDelta::WouldRequireApproval];
    assert_eq!(changed.len(), 2);
    for sample in changed {
        assert_eq!(sample.historical_decision, "allow");
        assert_eq!(sample.historical_policy_version, current.version());
        assert_eq!(sample.candidate_rule, "risk_override:write");
        assert!(sample.instance_id.starts_with("gai-"));
    }
    assert_eq!(state(db, namespace), before);
    let audited = db
        .list_decisions(&DecisionFilter {
            target_id: Some(namespace.into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|decision| decision.action == "action_policy.dry_run")
        .collect::<Vec<_>>();
    assert_eq!(audited.len(), 1);
    assert_eq!(
        audited[0].evidence["candidate_policy_version"],
        candidate.version()
    );
    assert_eq!(audited[0].evidence["would_require_approval"], "2");

    // No grant on the namespace: refused.
    assert!(
        run_action_policy_dry_run(db, "mallory", namespace, 0, 10_000, &candidate, "console")
            .is_err()
    );
}

#[test]
fn sqlite_action_policy_dry_run_conformance() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    exercise(&db, &format!("sqlite-{}", uuid::Uuid::new_v4().simple()));
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_action_policy_dry_run_conformance() {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    };
    exercise(
        &RuntimeDb::Postgres(Arc::new(db)),
        &format!("pg-{}", uuid::Uuid::new_v4().simple()),
    );
}

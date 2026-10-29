//! Action type impact class and cited-claim resolution on both backends
//! (#1910).

use sekai_chisei::chisei::action_impact::ImpactClass;
use sekai_chisei::db::{postgres::PostgresDb, runtime_db::RuntimeDb};
use sekai_chisei::sekai::action_effect::{ActionEffect, plan_effects_for_admit};
use sekai_chisei::sekai::action_instance::{ActionInstance, STATUS_ADMITTED};
use sekai_chisei::sekai::action_work_lifecycle::{
    ActionWorkLifecycle, CitedActionClaim, CitedClaimResolution, ClaimActionWork,
};
use sekai_chisei::sekai::governed_action_type::{EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType};
use std::sync::Arc;

const HOLDER: &str = "agent:alice";

fn action_type(namespace: &str, impact_class: &str) -> GovernedActionType {
    GovernedActionType {
        namespace: namespace.into(),
        type_id: "invade".into(),
        version: "1".into(),
        description: "Invade a neighbouring province".into(),
        parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
        allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
        impact_class: impact_class.into(),
        enabled: true,
        ..Default::default()
    }
}

fn seed_effect(db: &RuntimeDb, namespace: &str, prefix: &str) -> ActionEffect {
    let instance_id = format!("{prefix}-instance");
    let operation_id = format!("{prefix}-operation");
    let effect = plan_effects_for_admit(
        &instance_id,
        namespace,
        &operation_id,
        &[EFFECT_KIND_RUNTIME_DISPATCH.into()],
        r#"{"runtime":"shikigami"}"#,
        10,
        false,
    )
    .unwrap()
    .remove(0);
    db.put_action_effects(std::slice::from_ref(&effect))
        .unwrap();
    db.put_action_instance(&ActionInstance {
        agent_turn: None,
        instance_id,
        namespace: namespace.into(),
        type_id: "invade".into(),
        version: "1".into(),
        principal: "agent:submitter".into(),
        delegating_actor: None,
        parameters_json: r#"{"runtime":"shikigami"}"#.into(),
        request_digest: format!("{prefix}-digest"),
        idempotency_key: format!("{prefix}-idem"),
        operation_id,
        status: STATUS_ADMITTED.into(),
        deny_reason: String::new(),
        evidence_submission_ids: Vec::new(),
        policy_decision: "allow".into(),
        budget_decision: "allow".into(),
        created_at_ms: 10,
        decided_at_ms: 10,
        system_one_fill_json: String::new(),
        parked_object_digest: String::new(),
        decided_by: String::new(),
        approval_decision: String::new(),
        autonomous_envelope_id: String::new(),
        review: Default::default(),
        agent_action: false,
        admission_tenant: String::new(),
        resource_tenant: String::new(),
        marking: String::new(),
        conflict: None,
        approval: None,
        offline: None,
        admission_lease: None,
        admission_ontology_digest: None,
        admission_budget_already_reserved: false,
    })
    .unwrap();
    effect
}

fn exercise(db: RuntimeDb, prefix: &str) {
    let namespace = format!("{prefix}-realm");
    db.put_governed_action_type(action_type(&namespace, "high_impact"), "operator", 10)
        .unwrap();
    let stored = db
        .get_governed_action_type(&namespace, "invade", "1")
        .unwrap()
        .unwrap();
    assert_eq!(stored.impact(), Some(ImpactClass::HighImpact));
    // The class is part of the version: changing it needs a new version.
    let err = db
        .put_governed_action_type(action_type(&namespace, "routine"), "operator", 11)
        .unwrap_err();
    assert!(err.contains("immutable"), "{err}");

    let effect = seed_effect(&db, &namespace, prefix);
    let lifecycle = ActionWorkLifecycle::new(&db);
    let claimed = lifecycle
        .claim(
            ClaimActionWork {
                effect_id: &effect.effect_id,
                runtime_id: "shikigami",
                request_id: "claim-1",
                ttl_ms: 60_000,
            },
            HOLDER,
            100,
        )
        .unwrap()
        .effect;
    let resolve = |generation: u64, token: &str, caller: &str, namespace: &str, now: i64| {
        lifecycle
            .resolve_cited_claim(
                CitedActionClaim {
                    effect_id: &claimed.effect_id,
                    claim_generation: generation,
                    fencing_token: token,
                },
                caller,
                namespace,
                now,
            )
            .unwrap()
    };
    let generation = claimed.claim_generation;
    let token = claimed.claim_fencing_token.as_str();

    match resolve(generation, token, HOLDER, &namespace, 200) {
        CitedClaimResolution::Live(action_type) => {
            assert_eq!(action_type.impact(), Some(ImpactClass::HighImpact));
        }
        other => panic!("live claim resolved to {other:?}"),
    }
    assert_eq!(
        resolve(generation + 1, token, HOLDER, &namespace, 200),
        CitedClaimResolution::NotLive
    );
    assert_eq!(
        resolve(generation, "fx-forged", HOLDER, &namespace, 200),
        CitedClaimResolution::NotLive
    );
    assert_eq!(
        resolve(
            generation,
            token,
            HOLDER,
            &namespace,
            claimed.claim_expires_at_ms
        ),
        CitedClaimResolution::NotLive
    );
    assert_eq!(
        resolve(generation, token, "agent:bob", &namespace, 200),
        CitedClaimResolution::Foreign
    );
    assert_eq!(
        resolve(generation, token, HOLDER, "other-realm", 200),
        CitedClaimResolution::NotFound
    );

    // A claim taken without a recorded principal (an older plane) never
    // classifies.
    let legacy = seed_effect(&db, &namespace, &format!("{prefix}-legacy"));
    let legacy_claim = db
        .claim_action_work(
            &legacy.effect_id,
            "shikigami",
            "claim-legacy",
            "",
            60_000,
            100,
        )
        .unwrap();
    assert_eq!(
        lifecycle
            .resolve_cited_claim(
                CitedActionClaim {
                    effect_id: &legacy.effect_id,
                    claim_generation: legacy_claim.claim_generation,
                    fencing_token: &legacy_claim.claim_fencing_token,
                },
                "",
                &namespace,
                200,
            )
            .unwrap(),
        CitedClaimResolution::Foreign
    );
}

#[test]
fn sqlite_action_claim_impact_conformance() {
    exercise(RuntimeDb::memory(), "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
fn postgres_action_claim_impact_conformance() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(RuntimeDb::Postgres(Arc::new(postgres())), &prefix);
}

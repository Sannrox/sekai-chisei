use sekai_chisei::db::{postgres::PostgresDb, runtime_db::RuntimeDb};
use sekai_chisei::sekai::action_effect::{
    EFFECT_LIFECYCLE_AWAITING_CONTINUATION, EFFECT_LIFECYCLE_READY, EFFECT_STATUS_PARKED,
    EFFECT_STATUS_PENDING, plan_effects_for_admit,
};
use std::sync::Arc;

fn exercise(db: RuntimeDb, prefix: &str) {
    let mut effect = plan_effects_for_admit(
        &format!("{prefix}-instance"),
        &format!("{prefix}-namespace"),
        &format!("{prefix}-operation"),
        &["runtime_dispatch".into()],
        r#"{"runtime":"shikigami"}"#,
        10,
        false,
    )
    .unwrap()
    .remove(0);
    effect.effect_id = format!("{prefix}-effect");
    db.put_action_effects(&[effect.clone()]).unwrap();
    let claimed = db
        .claim_action_work(&effect.effect_id, "shikigami", "claim-1", 60_000, 100)
        .unwrap();
    let parked = db
        .park_action_work(
            &effect.effect_id,
            "shikigami",
            claimed.claim_generation,
            &claimed.claim_fencing_token,
            "await answer",
            "park-1",
            "",
            "",
            "",
            "runtime-principal",
            200,
        )
        .unwrap();
    assert_eq!(parked.effect.status, EFFECT_STATUS_PARKED);
    assert_eq!(
        parked.effect.effective_lifecycle_state(),
        EFFECT_LIFECYCLE_AWAITING_CONTINUATION
    );
    assert!(
        db.list_claimable_action_work(&effect.namespace, None, 300, 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        db.park_action_work(
            &effect.effect_id,
            "shikigami",
            claimed.claim_generation,
            &claimed.claim_fencing_token,
            "different",
            "park-1",
            "",
            "",
            "",
            "runtime-principal",
            300,
        )
        .unwrap_err()
        .contains("conflict")
    );

    let pending = db
        .submit_parked_resolution(
            &effect.effect_id,
            1,
            r#"{"answer":"continue"}"#,
            "operator answer",
            "resolve-1",
            "operator",
            "namespace-policy",
            "pending_approval",
            "approval-1",
            400,
        )
        .unwrap();
    assert_eq!(pending.action.status, "pending_approval");
    assert!(pending.continuation.is_none());
    db.authorize_parked_resolution_approval(
        &pending.action.resolution_action_id,
        &pending.action.approval_id,
    )
    .unwrap();
    let continuation = db
        .invoke_parked_resolution(
            &pending.action.resolution_action_id,
            &effect.effect_id,
            1,
            "approver",
            500,
        )
        .unwrap();
    assert_eq!(continuation.operation_id, effect.operation_id);
    let ready = db.get_action_effect(&effect.effect_id).unwrap().unwrap();
    assert_eq!(ready.status, EFFECT_STATUS_PENDING);
    assert_eq!(ready.effective_lifecycle_state(), EFFECT_LIFECYCLE_READY);

    let resumed = db
        .claim_action_work(&effect.effect_id, "shikigami", "claim-2", 60_000, 600)
        .unwrap();
    let active = db.get_active_continuation(&resumed).unwrap().unwrap();
    assert_eq!(active.0.resolution_id, continuation.resolution_id);
    assert!(
        !db.report_action_claim_event(
            &effect.effect_id,
            "shikigami",
            resumed.claim_generation,
            &resumed.claim_fencing_token,
            "resume_started",
            "",
            "",
            "event-1",
            700,
        )
        .unwrap()
    );
    assert!(
        db.report_action_claim_event(
            &effect.effect_id,
            "shikigami",
            resumed.claim_generation,
            &resumed.claim_fencing_token,
            "resume_started",
            "",
            "",
            "event-1",
            700,
        )
        .unwrap()
    );
}

#[test]
fn sqlite_parked_work_conformance() {
    exercise(RuntimeDb::memory(), "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    PostgresDb::connect(&url, 8).unwrap()
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
fn postgres_parked_work_conformance() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(RuntimeDb::Postgres(Arc::new(postgres())), &prefix);
}

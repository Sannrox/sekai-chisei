use sekai_chisei::db::action_governance::ActionGovernanceBackend;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::sekai::action::RiskClass;
use sekai_chisei::sekai::action_policy::{ActionDecision, ActionPolicy};
use std::sync::{Arc, Barrier};

use crate::postgres_scratch::ScratchDatabase;

fn exercise(db: &dyn ActionGovernanceBackend, prefix: &str) {
    let namespace = format!("{prefix}-namespace");
    let project = format!("project:{prefix}");
    let actor_scope = format!("agent:{prefix}-actor");

    let mut namespace_policy = ActionPolicy::allow_all(&namespace);
    namespace_policy.default_decision = ActionDecision::Deny;
    db.upsert_action_policy(&namespace_policy).unwrap();

    let mut project_policy = ActionPolicy::allow_all(&project);
    project_policy
        .risk_overrides
        .insert(RiskClass::Destructive, ActionDecision::RequireApproval);
    project_policy.max_deletes_per_work_unit = Some(2);
    db.upsert_action_policy(&project_policy).unwrap();

    let mut actor_policy = ActionPolicy::allow_all(&actor_scope);
    actor_policy
        .action_overrides
        .insert("rotate_key".into(), ActionDecision::RequireApproval);
    db.upsert_action_policy(&actor_policy).unwrap();
    db.upsert_action_policy(&actor_policy).unwrap();

    // Each backend starts empty, so the list is exactly these three scopes;
    // the repeated actor upsert replaced its row instead of adding one.
    let mut scopes: Vec<String> = db
        .list_action_policies()
        .unwrap()
        .into_iter()
        .map(|policy| policy.scope)
        .collect();
    scopes.sort();
    let mut expected = vec![namespace.clone(), project.clone(), actor_scope.clone()];
    expected.sort();
    assert_eq!(scopes, expected);
    let resolved = db
        .resolve_action_policy(
            &format!("{prefix}-actor"),
            &namespace,
            project.strip_prefix("project:").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(resolved.scope, actor_scope);
    assert_eq!(
        resolved.decide("rotate_key", RiskClass::Destructive),
        ActionDecision::RequireApproval
    );

    let work_unit = format!("{prefix}-work");
    assert_eq!(db.add_blast_radius(&work_unit, 2, 1).unwrap(), (2, 1));
    assert_eq!(db.add_blast_radius(&work_unit, 3, 1).unwrap(), (5, 2));
    assert_eq!(db.get_blast_radius(&work_unit).unwrap(), (5, 2));
}

#[test]
fn sqlite_action_governance_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_action_governance_conformance_and_restart() {
    let scratch = ScratchDatabase::create();
    let prefix = "pg";
    exercise(&scratch.connect(8), prefix);
    let restarted = scratch.connect(8);
    assert_eq!(
        restarted
            .get_blast_radius(&format!("{prefix}-work"))
            .unwrap(),
        (5, 2)
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_blast_radius_updates_do_not_get_lost() {
    let scratch = ScratchDatabase::create();
    let db = Arc::new(scratch.connect(8));
    let work = "race".to_string();
    let barrier = Arc::new(Barrier::new(9));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            let work = work.clone();
            std::thread::spawn(move || {
                barrier.wait();
                db.add_blast_radius(&work, 1, 1)
            })
        })
        .collect();
    barrier.wait();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    assert_eq!(db.get_blast_radius(&work).unwrap(), (8, 8));
}

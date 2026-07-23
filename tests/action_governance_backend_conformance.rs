use sekai_chisei::db::action_governance::ActionGovernanceBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::action::RiskClass;
use sekai_chisei::sekai::action_approval::{ActionApproval, ApprovalStatus};
use sekai_chisei::sekai::action_policy::{ActionDecision, ActionPolicy};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

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

    assert_eq!(db.list_action_policies().unwrap().len(), 3);
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

    let approval = ActionApproval::pending(
        format!("{prefix}-actor"),
        "rotate_key",
        HashMap::from([
            ("target".into(), "key-a".into()),
            ("api_key".into(), "secret".into()),
        ]),
        &work_unit,
        &project,
        "destructive",
        "key-a",
        100,
    );
    db.create_action_approval(&approval).unwrap();
    assert!(db.create_action_approval(&approval).is_err());
    assert_eq!(
        db.list_action_approvals(Some(ApprovalStatus::Pending))
            .unwrap(),
        vec![approval.clone()]
    );

    let mut approved = approval.clone();
    approved.status = ApprovalStatus::Approved;
    approved.decided_by = "admin".into();
    approved.outcome = "executed".into();
    approved.updated = 200;
    db.update_action_approval(&approved).unwrap();
    db.update_action_approval(&approved).unwrap();
    assert_eq!(
        db.get_action_approval(&approval.id)
            .unwrap()
            .unwrap()
            .status,
        ApprovalStatus::Approved
    );
    let mut denied = approved;
    denied.status = ApprovalStatus::Denied;
    denied.updated = 300;
    assert!(db.update_action_approval(&denied).is_err());
}

#[test]
fn sqlite_action_governance_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
}

#[test]
fn sqlite_conflicting_approval_decisions_have_one_winner() {
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(SekaiDb::new(directory.path().join("sekai.db").to_str().unwrap()).unwrap());
    let approval = ActionApproval::pending(
        "actor",
        "delete",
        HashMap::new(),
        "work",
        "namespace",
        "destructive",
        "target",
        100,
    );
    db.create_action_approval(&approval).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let handles = [ApprovalStatus::Approved, ApprovalStatus::Denied].map(|status| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let mut decision = approval.clone();
        std::thread::spawn(move || {
            decision.status = status;
            decision.updated = 200;
            decision.decided_by = status.as_str().into();
            barrier.wait();
            db.update_action_approval(&decision)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
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
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_action_governance_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    assert_eq!(
        restarted
            .get_blast_radius(&format!("{prefix}-work"))
            .unwrap(),
        (5, 2)
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_conflicting_approval_decisions_have_one_winner() {
    let db = Arc::new(postgres());
    let approval = ActionApproval::pending(
        "actor",
        "delete",
        HashMap::new(),
        "work",
        "namespace",
        "destructive",
        "target",
        100,
    );
    db.create_action_approval(&approval).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let handles = [ApprovalStatus::Approved, ApprovalStatus::Denied].map(|status| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let mut decision = approval.clone();
        std::thread::spawn(move || {
            decision.status = status;
            decision.updated = 200;
            decision.decided_by = status.as_str().into();
            barrier.wait();
            db.update_action_approval(&decision)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_blast_radius_updates_do_not_get_lost() {
    let db = Arc::new(postgres());
    let work = format!("race-{}", uuid::Uuid::new_v4().simple());
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

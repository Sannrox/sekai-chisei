use sekai_chisei::db::attestation::AttestationBackend;
use sekai_chisei::db::decision::DecisionBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::action_policy::ActionPolicy;
use sekai_chisei::sekai::attestation::{
    ACTION_POLICY_KIND, EVIDENCE_ATTESTATION_HASH, EVIDENCE_ATTESTATION_ID, PolicyAttestation,
    attestation_content_hash, policy_version, snapshot_action_policy,
};
use sekai_chisei::sekai::audit::{Decision, DecisionFilter};
use std::collections::HashMap;

trait DecisionHarness: DecisionBackend + AttestationBackend {}
impl DecisionHarness for SekaiDb {}
impl DecisionHarness for PostgresDb {}

fn decision(id: &str, actor: &str, action: &str, target: &str, ts: i64) -> Decision {
    Decision {
        id: id.into(),
        timestamp: ts,
        actor: actor.into(),
        action: action.into(),
        reason: "conformance".into(),
        evidence: HashMap::from([
            ("namespace".into(), "acme".into()),
            ("note".into(), "ok".into()),
        ]),
        target_id: target.into(),
        outcome: "succeeded".into(),
    }
}

fn exercise(db: &dyn DecisionHarness, prefix: &str) {
    let a = decision(&format!("{prefix}-a"), "human:alice", "create", "obj-1", 10);
    let b = decision(&format!("{prefix}-b"), "human:bob", "update", "obj-1", 20);
    let c = decision(&format!("{prefix}-c"), "human:alice", "delete", "obj-2", 30);
    let d = decision(&format!("{prefix}-d"), "human:carol", "create", "obj-2", 30);

    db.record_decision(&a).unwrap();
    db.record_decisions(&[b.clone(), c.clone()]).unwrap();
    db.record_decision(&d).unwrap();

    assert!(
        db.record_decision(&Decision {
            id: String::new(),
            ..a.clone()
        })
        .unwrap_err()
        .contains("id required")
    );
    assert!(
        db.record_decision(&Decision {
            evidence: HashMap::from([("token".into(), "sk-live-secret-example".into())]),
            id: format!("{prefix}-secret"),
            ..a.clone()
        })
        .unwrap_err()
        .contains("secret")
    );
    assert!(
        db.get_decision(&format!("{prefix}-secret"))
            .unwrap()
            .is_none(),
        "rejected decisions leave no partial state"
    );

    // exact idempotent retry
    db.record_decisions_idempotently(std::slice::from_ref(&a))
        .unwrap();
    // conflicting body for the same id fails closed
    let mut conflict = a.clone();
    conflict.outcome = "failed".into();
    assert!(
        db.record_decisions_idempotently(&[conflict])
            .unwrap_err()
            .contains("conflicting")
    );
    assert_eq!(
        db.get_decision(&a.id).unwrap().unwrap().outcome,
        "succeeded"
    );

    let by_actor = db
        .list_decisions(&DecisionFilter {
            actor: Some("human:alice".into()),
            action: None,
            target_id: None,
            after: 0,
            limit: 0,
            offset: 0,
        })
        .unwrap()
        .into_iter()
        .filter(|item| item.id.starts_with(prefix))
        .collect::<Vec<_>>();
    assert_eq!(
        by_actor
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec![c.id.as_str(), a.id.as_str()]
    );

    let by_action = db
        .list_decisions(&DecisionFilter {
            actor: None,
            action: Some("create".into()),
            target_id: None,
            after: 0,
            limit: 0,
            offset: 0,
        })
        .unwrap()
        .into_iter()
        .filter(|item| item.id.starts_with(prefix))
        .map(|item| item.id)
        .collect::<Vec<_>>();
    assert_eq!(by_action, vec![d.id.clone(), a.id.clone()]);

    let by_target = db
        .list_decisions(&DecisionFilter {
            actor: None,
            action: None,
            target_id: Some("obj-1".into()),
            after: 0,
            limit: 0,
            offset: 0,
        })
        .unwrap()
        .into_iter()
        .filter(|item| item.id.starts_with(prefix))
        .map(|item| item.id)
        .collect::<Vec<_>>();
    assert_eq!(by_target, vec![b.id.clone(), a.id.clone()]);

    let after = db
        .list_decisions(&DecisionFilter {
            after: 15,
            limit: 0,
            offset: 0,
            ..DecisionFilter::default()
        })
        .unwrap()
        .into_iter()
        .filter(|item| item.id.starts_with(prefix))
        .map(|item| item.id)
        .collect::<Vec<_>>();
    // same-ms decisions stay ordered by insertion/seq
    assert_eq!(after, vec![d.id.clone(), c.id.clone(), b.id.clone()]);

    let page = db
        .list_decisions(&DecisionFilter {
            after: 0,
            limit: 2,
            offset: 1,
            ..DecisionFilter::default()
        })
        .unwrap()
        .into_iter()
        .filter(|item| item.id.starts_with(prefix))
        .map(|item| item.id)
        .collect::<Vec<_>>();
    // page is filtered after global offset, so only assert size bound
    assert!(page.len() <= 2);

    // optional attestation remains transactionally coupled
    let mut attested = decision(
        &format!("{prefix}-attested"),
        "human:alice",
        "create",
        "obj-1",
        40,
    );
    let policy = ActionPolicy::allow_all("acme");
    let snapshot = snapshot_action_policy(&policy);
    let mut attestation = PolicyAttestation {
        id: format!("{prefix}-attestation"),
        decision_id: attested.id.clone(),
        policy_kind: ACTION_POLICY_KIND.into(),
        policy_scope: "acme".into(),
        policy_version: policy_version(&snapshot),
        policy_snapshot: snapshot,
        inputs: HashMap::from([
            ("action".into(), "create".into()),
            ("actor".into(), "human:alice".into()),
            ("risk_class".into(), "write".into()),
            ("namespace".into(), "acme".into()),
        ]),
        decision: "allow".into(),
        content_hash: String::new(),
        created: 40,
    };
    attestation.content_hash = attestation_content_hash(&attestation);
    attested
        .evidence
        .insert(EVIDENCE_ATTESTATION_ID.into(), attestation.id.clone());
    attested.evidence.insert(
        EVIDENCE_ATTESTATION_HASH.into(),
        attestation.content_hash.clone(),
    );
    db.record_decision_with_attestation(&attested, Some(&attestation))
        .unwrap();
    assert_eq!(
        db.get_decision(&attested.id)
            .unwrap()
            .unwrap()
            .evidence
            .get(EVIDENCE_ATTESTATION_ID),
        Some(&attestation.id)
    );
    assert_eq!(
        db.get_attestation(&attestation.id)
            .unwrap()
            .unwrap()
            .decision_id,
        attested.id
    );
    let verification = db.verify_attestation(&attestation.id).unwrap();
    assert!(verification.ok, "{}", verification.error);
}

#[test]
fn sqlite_decision_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise(&db, "sqlite");
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
fn postgres_decision_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    assert_eq!(
        restarted
            .get_decision(&format!("{prefix}-a"))
            .unwrap()
            .unwrap()
            .actor,
        "human:alice"
    );
    assert!(
        restarted
            .list_decisions(&DecisionFilter {
                actor: Some("human:alice".into()),
                ..DecisionFilter::default()
            })
            .unwrap()
            .iter()
            .any(|item| item.id == format!("{prefix}-c"))
    );
}

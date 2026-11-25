//! `ApplyGraphChanges` store behavior matches on SQLite and PostgreSQL
//! (#3062): a batch commits all or none, each change is fenced on the state it
//! was authorized against, a request id replays its first result or refuses a
//! different body, and an Action instance applies once, only for its submitter
//! in its namespace.

use std::collections::HashMap;
use std::sync::{Arc, Barrier};

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::domain::{Link, Object};
use sekai_chisei::sekai::action_instance::{ActionInstance, STATUS_ADMITTED, STATUS_PARKED};
use sekai_chisei::sekai::graph_changes::{
    GraphChangeBatch, GraphChangeError, GraphChangeOutcome, GraphChangeReceipt, InstanceRefusal,
    PlannedGraphChange,
};
use sekai_types::object_change::ChangeAttribution;

use crate::postgres_scratch::ScratchDatabase;

fn object(id: &str, namespace: &str, properties: &[(&str, &str)]) -> Object {
    Object {
        id: id.into(),
        kind: "task".into(),
        name: id.into(),
        namespace: namespace.into(),
        external_id: String::new(),
        properties: properties
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        created: 10,
        updated: 10,
    }
}

fn patched(before: &Object, key: &str, value: &str) -> Object {
    let mut after = before.clone();
    after.properties.insert(key.into(), value.into());
    after.updated = before.updated + 1;
    after
}

fn batch(namespace: &str, request_id: &str, changes: Vec<PlannedGraphChange>) -> GraphChangeBatch {
    let receipt = GraphChangeReceipt {
        object_ids: changes
            .iter()
            .filter_map(|change| match change {
                PlannedGraphChange::CreateObject(object)
                | PlannedGraphChange::UpdateObject { object, .. } => Some(object.id.clone()),
                _ => None,
            })
            .collect(),
        links: Vec::new(),
    };
    GraphChangeBatch {
        namespace: namespace.into(),
        request_id: request_id.into(),
        request_digest: format!("digest-{request_id}"),
        actor: "agent:planner".into(),
        action_instance_id: String::new(),
        policy_generation: "legacy".into(),
        attribution: ChangeAttribution::direct(),
        changes,
        receipt,
        now_ms: 20,
    }
}

fn instance(id: &str, namespace: &str, principal: &str, status: &str) -> ActionInstance {
    ActionInstance {
        agent_turn: None,
        instance_id: id.into(),
        namespace: namespace.into(),
        type_id: "plan".into(),
        version: "1".into(),
        principal: principal.into(),
        delegating_actor: None,
        parameters_json: "{}".into(),
        request_digest: format!("{id}-digest"),
        idempotency_key: format!("{id}-idem"),
        operation_id: format!("{id}-op"),
        status: status.into(),
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
        erased_properties: Vec::new(),
        erased_request_digest: String::new(),
    }
}

fn props(db: &RuntimeDb, id: &str) -> HashMap<String, String> {
    db.get_object(id).unwrap().unwrap().properties
}

fn exercise(db: Arc<RuntimeDb>, prefix: &str) {
    let ns = format!("{prefix}-ns");
    let a = object(
        &format!("{prefix}-a"),
        &ns,
        &[("state", "open"), ("owner", "ann")],
    );
    db.create_object(&a).unwrap();

    // One batch creates an object, patches another and links them.
    let b = object(&format!("{prefix}-b"), &ns, &[("state", "new")]);
    let a1 = patched(&a, "state", "planned");
    let link = Link {
        id: format!("{prefix}-link"),
        from_id: a.id.clone(),
        to_id: b.id.clone(),
        relation: "blocks".into(),
        created: 20,
    };
    let first = batch(
        &ns,
        "r1",
        vec![
            PlannedGraphChange::CreateObject(b.clone()),
            PlannedGraphChange::UpdateObject {
                object: a1.clone(),
                expected: a.clone(),
            },
            PlannedGraphChange::CreateLink {
                link: link.clone(),
                from: a1.clone(),
                to: b.clone(),
            },
        ],
    );
    assert!(matches!(
        db.apply_graph_changes(&first).unwrap(),
        GraphChangeOutcome::Applied(_)
    ));
    assert_eq!(props(&db, &a.id)["state"], "planned");
    assert_eq!(props(&db, &a.id)["owner"], "ann");
    assert!(db.get_object(&b.id).unwrap().is_some());
    assert!(db.get_link(&link.id).unwrap().is_some());

    // The same request replays without writing; another body is refused.
    match db.apply_graph_changes(&first).unwrap() {
        GraphChangeOutcome::Replayed(receipt) => {
            assert_eq!(receipt.object_ids, vec![b.id.clone(), a.id.clone()])
        }
        other => panic!("expected replay, got {other:?}"),
    }
    let mut other_body = first.clone();
    other_body.request_digest = "digest-other".into();
    assert_eq!(
        db.apply_graph_changes(&other_body).unwrap_err(),
        GraphChangeError::RequestConflict
    );

    // A stale expectation late in a batch rolls back the earlier changes.
    let c = object(&format!("{prefix}-c"), &ns, &[]);
    let stale = batch(
        &ns,
        "r2",
        vec![
            PlannedGraphChange::CreateObject(c.clone()),
            PlannedGraphChange::UpdateObject {
                object: patched(&a, "state", "lost"),
                expected: a.clone(),
            },
        ],
    );
    assert_eq!(
        db.apply_graph_changes(&stale).unwrap_err(),
        GraphChangeError::ObjectChanged(a.id.clone())
    );
    assert!(db.get_object(&c.id).unwrap().is_none());
    assert_eq!(props(&db, &a.id)["state"], "planned");
    // Nothing was recorded, so the id is still free.
    assert!(db.get_graph_change_request(&ns, "r2").unwrap().is_none());

    // A deleted link endpoint that moved fails the delete.
    let unlink = batch(
        &ns,
        "r3",
        vec![PlannedGraphChange::DeleteLink {
            link: link.clone(),
            from: a.clone(),
            to: b.clone(),
        }],
    );
    assert_eq!(
        db.apply_graph_changes(&unlink).unwrap_err(),
        GraphChangeError::ObjectChanged(a.id.clone())
    );
    assert!(db.get_link(&link.id).unwrap().is_some());

    // Two patches from the same read: exactly one wins.
    let barrier = Arc::new(Barrier::new(2));
    let racers = ["x", "y"].map(|value| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let race = batch(
            &ns,
            &format!("race-{value}"),
            vec![PlannedGraphChange::UpdateObject {
                object: patched(&a1, "state", value),
                expected: a1.clone(),
            }],
        );
        std::thread::spawn(move || {
            barrier.wait();
            db.apply_graph_changes(&race)
        })
    });
    let results = racers.map(|racer| racer.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().any(|result| matches!(
        result,
        Err(GraphChangeError::ObjectChanged(id)) if *id == a.id
    )));

    // An Action instance applies once, for its submitter, in its namespace.
    let current = db.get_object(&a.id).unwrap().unwrap();
    for (id, owner, status) in [
        ("inst-ok", "agent:planner", STATUS_ADMITTED),
        ("inst-other", "agent:someone", STATUS_ADMITTED),
        ("inst-parked", "agent:planner", STATUS_PARKED),
    ] {
        db.put_action_instance(&instance(&format!("{prefix}-{id}"), &ns, owner, status))
            .unwrap();
    }
    let bound = |request_id: &str, instance_id: &str| {
        let mut bound = batch(
            &ns,
            request_id,
            vec![PlannedGraphChange::UpdateObject {
                object: patched(&current, "state", request_id),
                expected: current.clone(),
            }],
        );
        bound.action_instance_id = format!("{prefix}-{instance_id}");
        bound.attribution = ChangeAttribution::action(
            &bound.action_instance_id,
            &format!("{}-op", bound.action_instance_id),
        );
        bound
    };
    for (request_id, instance_id, refusal) in [
        ("i1", "inst-other", InstanceRefusal::NotAdmittedHere),
        ("i2", "inst-parked", InstanceRefusal::Parked),
        ("i3", "inst-missing", InstanceRefusal::NotAdmittedHere),
    ] {
        assert_eq!(
            db.apply_graph_changes(&bound(request_id, instance_id))
                .unwrap_err(),
            GraphChangeError::Instance(refusal)
        );
    }
    assert!(matches!(
        db.apply_graph_changes(&bound("i4", "inst-ok")).unwrap(),
        GraphChangeOutcome::Applied(_)
    ));
    assert_eq!(props(&db, &a.id)["state"], "i4");
    let again = bound("i5", "inst-ok");
    assert_eq!(
        db.apply_graph_changes(&again).unwrap_err(),
        GraphChangeError::Instance(InstanceRefusal::AlreadyApplied)
    );

    // Change audit names the writer the batch carries.
    let changes = db.list_object_changes(&a.id, 100, 0).unwrap();
    assert!(
        changes
            .iter()
            .any(|change| change.writer_ref == format!("{prefix}-inst-ok"))
    );
}

#[test]
fn sqlite_graph_changes_backend_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sekai.db");
    let db = RuntimeDb::Sqlite(Arc::new(
        sekai_chisei::db::sekai::SekaiDb::new(path.to_str().unwrap()).unwrap(),
    ));
    exercise(Arc::new(db), "sqlite");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_graph_changes_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(Arc::new(db), "pg");
}

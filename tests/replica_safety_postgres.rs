//! Two-replica PostgreSQL conformance for #2087.
//!
//! Ignored without `SEKAI_TEST_POSTGRES_URL`. Each case opens two independent
//! pools against one isolated database (process id plus suffix).

use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::replica_safety::{ReplicaSafetyInventory, TwoReplicaPostgres};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::action_instance::{
    ActionInstance, ParkedGrantOutcome, ParkedGrantWrite, STATUS_ADMITTED, STATUS_PARKED,
    compute_request_digest, object_state_digest,
};
use sekai_chisei::sekai::agent_turn::{self, Cause, Wake};
use sekai_chisei::sekai::coordination::{
    ADMISSION_POLICY_FIFO, ContentionScope, ReconcileFilter, WORK_UNIT_STATUS_PENDING,
    WORK_UNIT_STATUS_STALE, WorkUnit,
};
use sekai_chisei::sekai::deduplication::{ContentReferenceRequest, ContentScope};
use sekai_chisei::sekai::lease::LeaseError;
use sekai_chisei::sekai::retention::{CONTENT_EVENTS_DATASET, RetentionPolicy};
use sekai_chisei::sekai::site_agent_instance;
use std::collections::HashMap;
use std::sync::Arc;

const DAY_MS: i64 = 86_400_000;

fn open_pair() -> TwoReplicaPostgres {
    TwoReplicaPostgres::open().expect("two-replica PostgreSQL pair")
}

fn postgres(db: &RuntimeDb) -> &PostgresDb {
    match db {
        RuntimeDb::Postgres(store) => store,
        RuntimeDb::Sqlite(_) => panic!("expected PostgreSQL replica"),
    }
}

fn unique(label: &str) -> String {
    format!(
        "{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    )
}

fn scope(id: &str) -> ContentionScope {
    ContentionScope {
        id: id.into(),
        name: id.into(),
        parent_scope_id: String::new(),
        max_concurrency: 1,
        admission_policy: ADMISSION_POLICY_FIFO.into(),
        heartbeat_ttl_seconds: 2,
        timeout_seconds: 30,
        owner_principal: "owner".into(),
        created: 1,
        updated: 1,
    }
}

fn work(id: &str, scope_id: &str, created: i64, idempotency_key: &str) -> WorkUnit {
    WorkUnit {
        id: id.into(),
        kind: "build".into(),
        actor: "actor".into(),
        target_object_id: String::new(),
        status: WORK_UNIT_STATUS_PENDING.into(),
        requested_spec: "{}".into(),
        scope_id: scope_id.into(),
        priority: 0,
        timeout_seconds: 30,
        heartbeat_ttl_seconds: 2,
        created_at: created,
        admitted_at: 0,
        started_at: 0,
        finished_at: 0,
        last_heartbeat_at: 0,
        failure_reason: String::new(),
        cancel_reason: String::new(),
        owner_principal: "owner".into(),
        creator_principal: "creator".into(),
        idempotency_key: idempotency_key.into(),
        updated_at: created,
    }
}

fn parked_instance(id: &str, namespace: &str) -> ActionInstance {
    let parameters_json = r#"{"summary":"hello"}"#;
    ActionInstance {
        agent_turn: None,
        autonomous_envelope_id: String::new(),
        parked_object_digest: String::new(),
        decided_by: String::new(),
        approval_decision: String::new(),
        review: Default::default(),
        agent_action: false,
        admission_tenant: String::new(),
        resource_tenant: String::new(),
        instance_id: id.into(),
        namespace: namespace.into(),
        type_id: "review.intake".into(),
        version: "1.0.0".into(),
        principal: "tester".into(),
        delegating_actor: None,
        parameters_json: parameters_json.into(),
        request_digest: compute_request_digest(
            namespace,
            "review.intake",
            "1.0.0",
            parameters_json,
            &[],
        )
        .unwrap(),
        idempotency_key: format!("key-{id}"),
        operation_id: format!("op-{id}"),
        status: STATUS_PARKED.into(),
        deny_reason: String::new(),
        evidence_submission_ids: vec![],
        policy_decision: "allow".into(),
        budget_decision: "allow".into(),
        created_at_ms: 10,
        decided_at_ms: 10,
        system_one_fill_json: String::new(),
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

fn seed_parked_target(
    db: &RuntimeDb,
    ns: &str,
    instance_id: &str,
) -> (Object, String, ActionInstance) {
    let target = Object {
        id: unique("obj"),
        kind: "note".into(),
        name: "parked".into(),
        namespace: ns.into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    };
    db.create_object(&target).unwrap();
    let digest = object_state_digest(Some(&target)).unwrap();
    let parked = parked_instance(instance_id, ns);
    db.put_action_instance(&parked).unwrap();
    (target, digest, parked)
}

fn granted_object(target: &Object) -> Object {
    let mut updated = target.clone();
    updated.updated = 2;
    updated.name = "granted".into();
    updated
}

fn grant_label(result: &Result<ParkedGrantOutcome, String>) -> String {
    match result {
        Ok(ParkedGrantOutcome::Granted { .. }) => "Granted".into(),
        Ok(ParkedGrantOutcome::NotParked) => "NotParked".into(),
        Ok(ParkedGrantOutcome::Refused(reason)) => format!("Refused({reason})"),
        Ok(ParkedGrantOutcome::ClaimLost) => "ClaimLost".into(),
        Ok(ParkedGrantOutcome::Stale) => "Stale".into(),
        Err(error) => format!("Err({error})"),
    }
}

fn seed_site_agent(db: &RuntimeDb, ns: &str, name: &str) -> String {
    let id = format!("{ns}-{name}");
    db.create_object(&Object {
        id: id.clone(),
        kind: site_agent_instance::KIND.into(),
        name: name.into(),
        namespace: ns.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("principal_id".to_string(), format!("agent:{id}")),
            (
                site_agent_instance::FROZEN_PROPERTY.to_string(),
                "false".into(),
            ),
        ]),
        created: 1,
        updated: 1,
    })
    .unwrap();
    id
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_two_replica_harness_isolates_and_shares_state() {
    ReplicaSafetyInventory::load()
        .unwrap()
        .require_authoritative("sekai.leases")
        .unwrap();
    let pair = open_pair();
    let ns = unique("share");
    pair.a
        .acquire_lease(&ns, "k", "owner-a", 1_000, "req-a", "actor", "local", 10)
        .unwrap();
    assert!(
        pair.b
            .acquire_lease(&ns, "k", "owner-b", 1_000, "req-b", "actor", "local", 11)
            .is_err()
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_lease_acquire_has_one_winner() {
    let pair = open_pair();
    let ns = unique("lease");
    let results = pair.race_results(4, {
        let ns = ns.clone();
        move |index, db| {
            let owner = format!("worker-{index}");
            db.acquire_lease(&ns, "shared", &owner, 1_000, &owner, &owner, "local", 10)
        }
    });
    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 1, "results={results:?}");
    for err in results.iter().filter(|r| r.is_err()) {
        assert!(matches!(err.as_ref().unwrap_err(), LeaseError::Conflict(_)));
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_replica_loss_lease_takeover_does_not_double_apply() {
    let mut pair = open_pair();
    let ns = unique("loss");
    let acquired = pair
        .a
        .acquire_lease(&ns, "k", "owner-a", 100, "acq", "actor-a", "local", 10)
        .unwrap();
    pair.crash_a();
    let takeover = pair
        .b
        .takeover_expired_lease(
            &ns,
            "k",
            "owner-b",
            &acquired.fencing_token,
            acquired.expires_at_ms,
            100,
            "take-late",
            "actor-b",
            "local",
            acquired.expires_at_ms,
        )
        .unwrap();
    assert_eq!(takeover.owner, "owner-b");
    assert_eq!(takeover.generation, acquired.generation + 1);
    assert!(
        pair.b
            .refresh_lease(
                &ns,
                "k",
                &acquired.fencing_token,
                100,
                "stale-refresh",
                "actor-a",
                "local",
                acquired.expires_at_ms + 1
            )
            .is_err()
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_work_admission_has_one_winner() {
    let pair = open_pair();
    let scope_id = unique("scope");
    pair.a.create_contention_scope(&scope(&scope_id)).unwrap();
    let first = work("wu-a", &scope_id, 10, "key-a");
    let second = work("wu-b", &scope_id, 10, "key-b");
    pair.a.create_work_unit(&first).unwrap();
    pair.b.create_work_unit(&second).unwrap();
    let results = pair.race_results(2, |index, db| {
        let id = if index == 0 { "wu-a" } else { "wu-b" };
        db.try_admit_work_unit(id, id, 100)
    });
    let admitted = results
        .iter()
        .map(|r| r.as_ref().unwrap())
        .filter(|r| r.admitted)
        .count();
    assert_eq!(admitted, 1, "results={results:?}");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_stale_work_recovers_on_surviving_replica() {
    let mut pair = open_pair();
    let scope_id = unique("stale");
    pair.a.create_contention_scope(&scope(&scope_id)).unwrap();
    let unit = work("wu-stale", &scope_id, 10, "stale-key");
    pair.a.create_work_unit(&unit).unwrap();
    assert!(
        pair.a
            .try_admit_work_unit("wu-stale", "worker-a", 100)
            .unwrap()
            .admitted
    );
    pair.crash_a();
    let summary = pair
        .b
        .reconcile_work_units(
            100 + 2_000 * 2,
            &ReconcileFilter {
                work_unit_id: Some("wu-stale".into()),
                limit: 10,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(summary.work_units_reconciled >= 1, "summary={summary:?}");
    let after = pair.b.get_work_unit("wu-stale").unwrap().unwrap();
    assert_eq!(after.status, WORK_UNIT_STATUS_STALE);
    let next = work("wu-next", &scope_id, 20, "next-key");
    pair.b.create_work_unit(&next).unwrap();
    assert!(
        pair.b
            .try_admit_work_unit("wu-next", "worker-b", 100 + 2_000 * 2 + 1)
            .unwrap()
            .admitted
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_parked_grant_has_one_winner() {
    let pair = open_pair();
    let ns = unique("grant");
    let id = unique("ai");
    let (target, digest, parked) = seed_parked_target(&pair.a, &ns, &id);
    let granted = ActionInstance {
        status: STATUS_ADMITTED.into(),
        ..parked
    };
    let updated = granted_object(&target);
    let results = pair.race_results(2, {
        let granted = granted.clone();
        let object_id = target.id.clone();
        let digest = digest.clone();
        let updated = updated.clone();
        move |_index, db| {
            db.grant_parked_action_instance(
                &granted,
                &object_id,
                &digest,
                Some(&ParkedGrantWrite::Update(updated.clone())),
                &[],
                "approver",
                None,
            )
        }
    });
    let labels: Vec<String> = results.iter().map(grant_label).collect();
    let wins = labels.iter().filter(|l| *l == "Granted").count();
    let rest = labels
        .iter()
        .filter(|l| *l == "NotParked" || *l == "Stale")
        .count();
    assert_eq!(wins, 1, "results={labels:?}");
    assert_eq!(rest, 1, "results={labels:?}");
    let after = pair.b.get_object(&target.id).unwrap().unwrap();
    assert_eq!(after.name, "granted");
    assert_eq!(after.updated, 2);
    let instance = pair.b.get_action_instance(&id).unwrap().unwrap();
    assert_eq!(instance.status, STATUS_ADMITTED);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_retention_ticks_archive_once() {
    let pair = open_pair();
    let prefix = unique("ret");
    let scope = ContentScope {
        namespace: format!("{prefix}:namespace"),
        classification: "confidential".into(),
        encryption_key_id: "key-1".into(),
        residency: "eu".into(),
    };
    let request = ContentReferenceRequest {
        reference_id: format!("{prefix}:reference"),
        actor: format!("{prefix}:actor"),
        operation_id: format!("{prefix}:operation"),
        causal_identity: format!("{prefix}:cause"),
        idempotency_key: format!("{prefix}:put"),
        retention_until_ms: None,
        retention_hold: false,
        legal_hold: false,
        archived: false,
        receipt_required: false,
        attestation_required: false,
        preserve_tombstone: true,
    };
    postgres(&pair.a)
        .put_scoped_content(&scope, &request, b"race", 100)
        .unwrap();
    pair.a
        .set_retention_policy(&RetentionPolicy {
            dataset: CONTENT_EVENTS_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
    let count = |db: &RuntimeDb| {
        db.retention_archive_status()
            .unwrap()
            .records
            .iter()
            .find(|(dataset, _)| dataset == CONTENT_EVENTS_DATASET)
            .map_or(0, |(_, n)| *n)
    };
    let before = count(&pair.a);
    let results = pair.race_results(2, |_index, db| {
        db.archive_retained_records(2 * DAY_MS, false)
    });
    let archived: i32 = results
        .iter()
        .map(|run| run.as_ref().unwrap().content_events_archived)
        .sum();
    assert!(archived > 0, "results={results:?}");
    assert_eq!(count(&pair.b), before + i64::from(archived));
    assert!(pair.b.verify_retention_archive().unwrap().ok);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_agent_turn_claim_has_one_winner() {
    let pair = open_pair();
    let ns = unique("turn");
    let instance = seed_site_agent(&pair.a, &ns, "line");
    agent_turn::admit(
        &pair.a,
        Wake {
            namespace: ns.clone(),
            instance_id: instance,
            cause: Cause::Manual,
            cause_ref: "req-1".into(),
            due_at_ms: 100,
        },
        "plane",
        1,
    )
    .unwrap();
    let results = pair.race_results(4, {
        let ns = ns.clone();
        move |index, db| agent_turn::claim_next(&db, &ns, &format!("w{index}"), 1_000, 100, true)
    });
    let wins = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(wins, 1, "results={results:?}");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_crashed_replica_uncommitted_grant_does_not_double_apply() {
    let pair = open_pair();
    let ns = unique("crash");
    let id = unique("ai");
    let (target, digest, parked) = seed_parked_target(&pair.a, &ns, &id);
    let (ready, wait_ready) = std::sync::mpsc::sync_channel(1);
    let a = Arc::clone(&pair.a);
    let holder_object = target.id.clone();
    let holder_id = id.clone();
    let holder = std::thread::spawn(move || {
        let mut connection = postgres(&a).connection().expect("checkout");
        let mut tx = connection.transaction().expect("begin");
        // Object then Action, then an uncommitted mutation that must roll back.
        tx.query_opt(
            "SELECT 1 FROM sekai_objects WHERE id = $1 FOR UPDATE",
            &[&holder_object],
        )
        .expect("lock object");
        tx.execute(
            "UPDATE sekai_objects SET name = $2, updated = 99 WHERE id = $1",
            &[&holder_object, &"stolen"],
        )
        .expect("mutate object");
        tx.execute(
            "UPDATE sekai_action_instances SET status = $2 WHERE instance_id = $1",
            &[&holder_id, &STATUS_ADMITTED],
        )
        .expect("mutate action");
        let pid: i32 = tx
            .query_one("SELECT pg_backend_pid()", &[])
            .expect("backend pid")
            .get(0);
        ready.send(pid).expect("pid sent");
        let _ = tx.batch_execute("SELECT pg_sleep(30)");
    });
    let pid = wait_ready.recv().expect("holder ready");
    let mut peer = postgres(&pair.b).connection().expect("peer checkout");
    // Timeout waits until the backend is gone so row locks are released.
    let terminated: bool = peer
        .query_one("SELECT pg_terminate_backend($1, 5000)", &[&pid])
        .expect("kill replica A backend")
        .get(0);
    assert!(terminated, "replica A backend {pid} did not terminate");
    drop(peer);
    let rolled_back = pair.b.get_object(&target.id).unwrap().unwrap();
    assert_eq!(rolled_back.name, "parked");
    assert_eq!(rolled_back.updated, 1);
    let granted = ActionInstance {
        status: STATUS_ADMITTED.into(),
        ..parked
    };
    let outcome = pair
        .b
        .grant_parked_action_instance(
            &granted,
            &target.id,
            &digest,
            Some(&ParkedGrantWrite::Update(granted_object(&target))),
            &[],
            "approver",
            None,
        )
        .unwrap();
    assert!(
        matches!(outcome, ParkedGrantOutcome::Granted { .. }),
        "surviving replica must apply the grant once"
    );
    let after = pair.b.get_object(&target.id).unwrap().unwrap();
    assert_eq!(after.name, "granted");
    assert_eq!(after.updated, 2);
    let instance = pair.b.get_action_instance(&id).unwrap().unwrap();
    assert_eq!(instance.status, STATUS_ADMITTED);
    let _ = holder.join();
}

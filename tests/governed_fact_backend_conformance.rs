//! SQLite/PostgreSQL conformance for graph-backed governed facts (#462).

use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{KIND_EXTERNAL_EVIDENCE, Object};
use sekai_chisei::sekai::governed_facts::{
    FactApplicability, GovernedFactInput, GovernedFactType, GovernedWaiverInput,
    PROFILE_CONTRACT_VERSION, VerificationContract, apply_profile, list_facts, list_waivers,
    put_fact, put_waiver, resolve_invariant_set,
};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

fn applicability(subject_profile: &str) -> FactApplicability {
    FactApplicability {
        subject_profiles: vec![subject_profile.into()],
        subject_refs: Vec::new(),
    }
}

fn requirement(
    namespace: &str,
    fact_id: &str,
    subject_profile: &str,
    statement: &str,
) -> GovernedFactInput {
    GovernedFactInput {
        contract_version: PROFILE_CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        fact_id: fact_id.into(),
        version: "1.0.0".into(),
        fact_type: GovernedFactType::Requirement,
        status: "active".into(),
        statement: statement.into(),
        applicability: applicability(subject_profile),
        verification: VerificationContract::default(),
        requirement_version_ids: Vec::new(),
        evidence_refs: Vec::new(),
        source_ref: format!("policy:{fact_id}"),
        effective_from_ms: 100,
        supersedes_object_id: String::new(),
        access_marking: String::new(),
    }
}

fn invariant(
    namespace: &str,
    fact_id: &str,
    subject_profile: &str,
    requirement_id: &str,
    evidence_id: &str,
) -> GovernedFactInput {
    GovernedFactInput {
        contract_version: PROFILE_CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        fact_id: fact_id.into(),
        version: "1.0.0".into(),
        fact_type: GovernedFactType::Invariant,
        status: "active".into(),
        statement: "The observed evidence satisfies the declared compatibility contract.".into(),
        applicability: applicability(subject_profile),
        verification: VerificationContract {
            predicate_kind: "schema_conformance".into(),
            input_schema: "example.input/v1".into(),
            result_schema: "example.result/v1".into(),
            evidence_types: vec!["verification.result".into()],
        },
        requirement_version_ids: vec![requirement_id.into()],
        evidence_refs: vec![evidence_id.into()],
        source_ref: format!("policy:{fact_id}"),
        effective_from_ms: 100,
        supersedes_object_id: String::new(),
        access_marking: String::new(),
    }
}

fn exercise(db: &RuntimeDb, namespace: &str) -> (String, String) {
    let profile = apply_profile(
        db,
        namespace,
        PROFILE_CONTRACT_VERSION,
        "human:operator",
        10,
    )
    .unwrap();
    assert_eq!(
        apply_profile(
            db,
            namespace,
            PROFILE_CONTRACT_VERSION,
            "human:operator",
            11,
        )
        .unwrap()
        .object_id,
        profile.object_id
    );

    let evidence_id = format!("{namespace}-evidence");
    db.create_object_with_audit(
        &Object {
            id: evidence_id.clone(),
            kind: KIND_EXTERNAL_EVIDENCE.into(),
            name: "synthetic verification".into(),
            namespace: namespace.into(),
            external_id: format!("evidence:{namespace}"),
            properties: HashMap::new(),
            created: 20,
            updated: 20,
        },
        "adapter:synthetic",
    )
    .unwrap();

    let compatibility_requirement = put_fact(
        db,
        requirement(
            namespace,
            "api-compatibility",
            "example.api-contract/v1",
            "The subject preserves the declared API contract.",
        ),
        "human:operator",
        100,
    )
    .unwrap();
    let migration_requirement = put_fact(
        db,
        requirement(
            namespace,
            "migration-safety",
            "example.data-migration/v1",
            "The subject preserves recoverable stored data.",
        ),
        "human:operator",
        101,
    )
    .unwrap();
    let compatibility_invariant = put_fact(
        db,
        invariant(
            namespace,
            "api-schema-compatible",
            "example.api-contract/v1",
            &compatibility_requirement.object_id,
            &evidence_id,
        ),
        "human:operator",
        102,
    )
    .unwrap();
    let migration_invariant = put_fact(
        db,
        invariant(
            namespace,
            "migration-roundtrip-safe",
            "example.data-migration/v1",
            &migration_requirement.object_id,
            &evidence_id,
        ),
        "human:operator",
        103,
    )
    .unwrap();

    let waiver = put_waiver(
        db,
        GovernedWaiverInput {
            contract_version: PROFILE_CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            waiver_id: "api-compatibility-exception".into(),
            version: "1.0.0".into(),
            invariant_version_ids: vec![compatibility_invariant.object_id.clone()],
            applicability: applicability("example.api-contract/v1"),
            reason: "Synthetic bounded exception.".into(),
            evidence_refs: vec![evidence_id.clone()],
            source_ref: "decision:exception-1".into(),
            valid_from_ms: 120,
            expires_at_ms: 180,
            supersedes_object_id: String::new(),
            access_marking: String::new(),
        },
        "human:reviewer",
        120,
    )
    .unwrap();

    let api_set = resolve_invariant_set(
        &profile,
        list_facts(db, namespace).unwrap(),
        list_waivers(db, namespace).unwrap(),
        "example.api-contract/v1",
        "release:one",
        150,
        0,
    )
    .unwrap();
    assert_eq!(api_set.requirements.len(), 1);
    assert_eq!(api_set.invariants.len(), 1);
    assert_eq!(api_set.waivers, vec![waiver]);
    let migration_set = resolve_invariant_set(
        &profile,
        list_facts(db, namespace).unwrap(),
        list_waivers(db, namespace).unwrap(),
        "example.data-migration/v1",
        "migration:one",
        150,
        0,
    )
    .unwrap();
    assert_eq!(migration_set.requirements.len(), 1);
    assert_eq!(migration_set.invariants, vec![migration_invariant]);
    assert!(migration_set.waivers.is_empty());
    assert_ne!(api_set.set_digest, migration_set.set_digest);

    assert_eq!(
        put_fact(
            db,
            invariant(
                namespace,
                "api-schema-compatible",
                "example.api-contract/v1",
                &compatibility_requirement.object_id,
                &evidence_id,
            ),
            "human:operator",
            999,
        )
        .unwrap()
        .object_id,
        compatibility_invariant.object_id
    );
    let mut conflict = invariant(
        namespace,
        "api-schema-compatible",
        "example.api-contract/v1",
        &compatibility_requirement.object_id,
        &evidence_id,
    );
    conflict.statement = "Conflicting immutable content.".into();
    assert!(put_fact(db, conflict, "human:operator", 999).is_err());

    let mut invalid_reference = invariant(
        namespace,
        "missing-reference",
        "example.api-contract/v1",
        "absent-requirement",
        &evidence_id,
    );
    invalid_reference.version = "2.0.0".into();
    assert!(put_fact(db, invalid_reference, "human:operator", 999).is_err());
    assert!(
        list_facts(db, &format!("{namespace}-other"))
            .unwrap()
            .is_empty()
    );
    assert!(
        db.list_object_changes(&compatibility_invariant.object_id, 10, 0)
            .unwrap()
            .iter()
            .any(|change| change.field == "_created")
    );

    (
        compatibility_requirement.object_id,
        compatibility_invariant.object_id,
    )
}

fn exercise_concurrent_history(db: &RuntimeDb, namespace: &str) {
    let barrier = Arc::new(Barrier::new(2));
    let profile_threads = [db.clone(), db.clone()].map(|db| {
        let barrier = barrier.clone();
        let namespace = namespace.to_string();
        std::thread::spawn(move || {
            barrier.wait();
            apply_profile(
                &db,
                &namespace,
                PROFILE_CONTRACT_VERSION,
                "human:operator",
                10,
            )
        })
    });
    let profiles = profile_threads
        .into_iter()
        .map(|thread| thread.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(profiles[0].object_id, profiles[1].object_id);

    let first = put_fact(
        db,
        requirement(
            namespace,
            "concurrent-lifecycle",
            "example.concurrent/v1",
            "The subject has one linear governed history.",
        ),
        "human:operator",
        100,
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let successors = ["2.0.0", "3.0.0"].map(|version| {
        let db = db.clone();
        let barrier = barrier.clone();
        let namespace = namespace.to_string();
        let predecessor = first.object_id.clone();
        std::thread::spawn(move || {
            let mut successor = requirement(
                &namespace,
                "concurrent-lifecycle",
                "example.concurrent/v1",
                "The subject has one linear governed history.",
            );
            successor.version = version.into();
            successor.effective_from_ms = 200;
            successor.supersedes_object_id = predecessor;
            barrier.wait();
            put_fact(&db, successor, "human:operator", 200)
        })
    });
    let outcomes = successors
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );
    assert_eq!(list_facts(db, namespace).unwrap().len(), 2);
}

#[test]
fn sqlite_governed_fact_conformance_and_restart() {
    let path = std::env::temp_dir().join(format!(
        "sekai-governed-facts-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let namespace = format!("sqlite-{}", uuid::Uuid::new_v4().simple());
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap()));
    let (requirement_id, invariant_id) = exercise(&db, &namespace);
    exercise_concurrent_history(&db, &format!("{namespace}-race"));
    drop(db);

    let restarted = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap()));
    assert!(restarted.get_object(&requirement_id).unwrap().is_some());
    assert!(restarted.get_object(&invariant_id).unwrap().is_some());
    assert_eq!(list_facts(&restarted, &namespace).unwrap().len(), 4);
}

fn postgres() -> RuntimeDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    };
    RuntimeDb::Postgres(Arc::new(db))
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_governed_fact_conformance_and_restart() {
    let namespace = format!("pg-{}", uuid::Uuid::new_v4().simple());
    let db = postgres();
    let (requirement_id, invariant_id) = exercise(&db, &namespace);
    exercise_concurrent_history(&db, &format!("{namespace}-race"));
    drop(db);
    let restarted = postgres();
    assert!(restarted.get_object(&requirement_id).unwrap().is_some());
    assert!(restarted.get_object(&invariant_id).unwrap().is_some());
    assert_eq!(list_facts(&restarted, &namespace).unwrap().len(), 4);
}

use sekai_chisei::db::action::ActionTypeBackend;
use sekai_chisei::db::credential::CredentialBackend;
use sekai_chisei::db::dataset::DatasetBackend;
use sekai_chisei::db::lease::LeaseBackend;
use sekai_chisei::db::ontology::OntologyBackend;
use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::sekai::action::{ActionOp, ActionParamDef, ActionTypeDef};
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset, RowFilter, RowQuery, VirtualTable};
use sekai_chisei::sekai::ontology::{
    Cardinality, OntologyClass, OntologyProperty, OntologyRelation,
};
use sekai_chisei::sekai::schema::PropertyType;
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

fn exercise_datasets(db: &dyn DatasetBackend, prefix: &str) {
    let dataset_id = format!("{prefix}-dataset");
    let dataset = Dataset {
        id: dataset_id.clone(),
        name: "evidence".into(),
        columns: vec![
            ColumnDef {
                name: "kind".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
            ColumnDef {
                name: "secret".into(),
                col_type: "string".into(),
                classification: "sensitive".into(),
            },
        ],
        object_id: String::new(),
        created: 10,
    };
    db.create_dataset(&dataset).unwrap();
    assert!(db.create_dataset(&dataset).is_err());
    assert_eq!(db.get_dataset(&dataset_id).unwrap(), Some(dataset.clone()));

    let mut renamed = dataset.clone();
    renamed.name = "renamed".into();
    db.update_dataset(&renamed).unwrap();
    assert!(
        db.list_datasets()
            .unwrap()
            .iter()
            .any(|stored| stored.id == dataset_id && stored.name == "renamed")
    );
    assert_eq!(
        db.append_rows(
            &dataset_id,
            &[
                HashMap::from([
                    ("kind".into(), "build".into()),
                    ("secret".into(), "alpha".into()),
                ]),
                HashMap::from([
                    ("kind".into(), "test".into()),
                    ("secret".into(), "beta".into()),
                ]),
            ],
        )
        .unwrap(),
        2
    );
    let query = RowQuery {
        filters: vec![RowFilter {
            column: "kind".into(),
            op: "eq".into(),
            value: "build".into(),
        }],
        ..Default::default()
    };
    assert_eq!(db.query_rows(&dataset_id, &query).unwrap().len(), 1);
    let redacted = db
        .redact_dataset_fields(&dataset_id, "sensitive", &query.filters)
        .unwrap();
    assert_eq!(redacted.rows_updated, 1);
    assert_eq!(
        db.query_rows(&dataset_id, &query).unwrap()[0]["secret"],
        "[redacted]"
    );

    db.create_virtual_table(&VirtualTable {
        id: format!("{prefix}-virtual"),
        name: "builds".into(),
        dataset_id,
        filters: query.filters,
        columns: vec!["kind".into()],
        created: 11,
    })
    .unwrap();
    assert_eq!(db.list_virtual_tables().unwrap().len(), 1);
}

fn exercise_ontology(db: &dyn OntologyBackend, prefix: &str) {
    let parent = OntologyClass {
        name: format!("{prefix}-Artifact"),
        description: "artifact".into(),
        superclasses: vec![],
        equivalent_classes: vec![],
        disjoint_classes: vec![],
        properties: vec![OntologyProperty {
            name: "digest".into(),
            prop_type: PropertyType::String,
            required: true,
            description: String::new(),
        }],
        is_builtin: false,
        mapped_kind: "artifact".into(),
    };
    let child = OntologyClass {
        name: format!("{prefix}-Receipt"),
        description: "receipt".into(),
        superclasses: vec![parent.name.clone()],
        equivalent_classes: vec![],
        disjoint_classes: vec![],
        properties: vec![],
        is_builtin: false,
        mapped_kind: "receipt".into(),
    };
    db.upsert_ontology_class(&parent).unwrap();
    db.upsert_ontology_class(&child).unwrap();
    let relation = OntologyRelation {
        name: format!("{prefix}-proves"),
        description: "proof".into(),
        domain: child.name.clone(),
        range: parent.name.clone(),
        cardinality: Cardinality {
            min: 1,
            max: Some(1),
        },
        inverse: String::new(),
        transitive: false,
        is_builtin: false,
        mapped_relation: "proves".into(),
    };
    db.upsert_ontology_relation(&relation).unwrap();
    assert_eq!(
        db.get_ontology_relation(&relation.name)
            .unwrap()
            .unwrap()
            .domain,
        child.name
    );
    assert!(db.delete_ontology_relation(&relation.name).unwrap());
    assert!(db.delete_ontology_class(&child.name).unwrap());
    assert!(db.delete_ontology_class(&parent.name).unwrap());
}

fn exercise_actions(db: &dyn ActionTypeBackend, prefix: &str) {
    let action = ActionTypeDef {
        name: format!("{prefix}-tag"),
        description: "tag an artifact".into(),
        params: vec![ActionParamDef {
            name: "value".into(),
            param_type: PropertyType::String,
            required: true,
            enum_values: vec![],
        }],
        ops: vec![ActionOp {
            op: "set_property".into(),
            property: "tag".into(),
            value_from: "value".into(),
            relation: String::new(),
        }],
        target_kind: "artifact".into(),
        created: 10,
        required_purpose: String::new(),
    };
    assert_eq!(db.upsert_action_type(&action).unwrap(), action);
    assert_eq!(db.list_action_types().unwrap(), vec![action.clone()]);
    assert!(db.delete_action_type(&action.name).unwrap());
}

fn exercise_leases(db: &dyn LeaseBackend, prefix: &str) {
    let namespace = format!("{prefix}-namespace");
    let key = format!("{prefix}-key");
    let acquired = db
        .acquire_lease(
            &namespace, &key, "worker-a", 100, "acquire", "actor", "local", 10,
        )
        .unwrap();
    assert_eq!(
        db.acquire_lease(
            &namespace, &key, "worker-a", 100, "acquire", "actor", "local", 10
        )
        .unwrap(),
        acquired
    );
    assert!(
        db.acquire_lease(
            &namespace,
            &key,
            "worker-b",
            100,
            "different",
            "actor",
            "local",
            11
        )
        .is_err()
    );
    let refreshed = db
        .refresh_lease(
            &namespace,
            &key,
            &acquired.fencing_token,
            100,
            "refresh",
            "actor",
            "local",
            20,
        )
        .unwrap();
    assert_eq!(refreshed.expires_at_ms, 120);
    let takeover = db
        .takeover_expired_lease(
            &namespace,
            &key,
            "worker-b",
            &acquired.fencing_token,
            120,
            100,
            "takeover",
            "actor",
            "local",
            120,
        )
        .unwrap();
    assert_eq!(takeover.generation, acquired.generation + 1);
    assert!(
        db.release_lease(
            &namespace,
            &key,
            &acquired.fencing_token,
            "stale-release",
            "actor",
            "local",
            121
        )
        .is_err()
    );
}

fn exercise_credentials(db: &dyn CredentialBackend, prefix: &str) {
    let principal = format!("{prefix}-principal");
    let first_hash = format!("{prefix}-hash-a");
    let first = db
        .create_principal_credential(&principal, &first_hash, 10)
        .unwrap();
    assert!(first.tenant_id.is_empty());
    assert_eq!(
        db.get_principal_credential(&first_hash)
            .unwrap()
            .unwrap()
            .principal,
        principal
    );
    let second_hash = format!("{prefix}-hash-b");
    let rotated = db
        .rotate_principal_credential(&principal, &second_hash)
        .unwrap();
    assert_eq!(rotated.status, "active");
    assert!(db.get_principal_credential(&first_hash).unwrap().is_none());
    assert_eq!(
        db.list_credentials(Some(&principal), None).unwrap().len(),
        2
    );
    assert_eq!(
        db.revoke_principal_credential(&principal)
            .unwrap()
            .unwrap()
            .status,
        "revoked"
    );
}

fn exercise_backend(
    datasets: &dyn DatasetBackend,
    ontology: &dyn OntologyBackend,
    actions: &dyn ActionTypeBackend,
    leases: &dyn LeaseBackend,
    credentials: &dyn CredentialBackend,
    prefix: &str,
) {
    exercise_datasets(datasets, prefix);
    exercise_ontology(ontology, prefix);
    exercise_actions(actions, prefix);
    exercise_leases(leases, prefix);
    exercise_credentials(credentials, prefix);
}

#[test]
fn sqlite_reusable_sekai_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_backend(&db, &db, &db, &db, &db, "sqlite");
}

fn postgres_test_database() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        Ok(path) => {
            let certificate = std::fs::read(path).expect("read PostgreSQL test CA certificate");
            PostgresDb::connect_with_ca_certificate(&url, 8, &certificate).unwrap()
        }
        Err(_) => PostgresDb::connect(&url, 8).unwrap(),
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_reusable_sekai_conformance() {
    let db = postgres_test_database();
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise_backend(&db, &db, &db, &db, &db, &prefix);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_lease_acquisition_has_one_winner() {
    let db = Arc::new(postgres_test_database());
    let prefix = format!("race-{}", uuid::Uuid::new_v4().simple());
    let barrier = Arc::new(Barrier::new(3));
    let handles = ["a", "b"].map(|owner| {
        let db = db.clone();
        let barrier = barrier.clone();
        let namespace = prefix.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.acquire_lease(
                &namespace, "shared", owner, 1_000, owner, owner, "local", 10,
            )
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
}

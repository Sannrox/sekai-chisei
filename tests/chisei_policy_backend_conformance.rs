//! Shared SQLite/PostgreSQL conformance for namespace policy objects on the graph.

use sekai_chisei::chisei::policy::Policy;
use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::domain::Object;
use std::collections::HashMap;

trait PolicyHarness: GraphBackend {}
impl PolicyHarness for SekaiDb {}
impl PolicyHarness for PostgresDb {}

fn policy_properties(policy: &Policy) -> HashMap<String, String> {
    HashMap::from([
        ("allowed_runtimes".into(), policy.allowed_runtimes.join(",")),
        ("allowed_models".into(), policy.allowed_models.join(",")),
        ("default_runtime".into(), policy.default_runtime.clone()),
        ("default_model".into(), policy.default_model.clone()),
        ("data_class".into(), policy.data_class.clone()),
        ("policy_version".into(), policy.version()),
    ])
}

fn exercise(db: &dyn PolicyHarness, prefix: &str) {
    let namespace = format!("{prefix}-ns");
    let policy = Policy {
        allowed_runtimes: vec!["ollama".into()],
        allowed_models: vec!["llama".into()],
        default_runtime: "ollama".into(),
        default_model: "llama".into(),
        data_class: "internal".into(),
    };
    let object_id = format!("policy-{namespace}");
    let now = 1_000_i64;
    db.create_object(
        &Object {
            id: object_id.clone(),
            kind: "policy".into(),
            name: namespace.clone(),
            namespace: namespace.clone(),
            external_id: format!("policy:{namespace}"),
            properties: {
                let mut properties = policy_properties(&policy);
                properties.insert("namespace".into(), namespace.clone());
                properties
            },
            created: now,
            updated: now,
        },
        "human:admin",
    )
    .unwrap();
    let loaded = db.get_object(&object_id).unwrap().unwrap();
    assert_eq!(loaded.properties.get("default_model").unwrap(), "llama");
    assert_eq!(loaded.properties.get("data_class").unwrap(), "internal");

    let mut updated_policy = policy;
    updated_policy.default_model = "mistral".into();
    let mut updated = loaded.clone();
    updated.properties = {
        let mut properties = policy_properties(&updated_policy);
        properties.insert("namespace".into(), namespace);
        properties
    };
    updated.updated = now + 1;
    db.update_object(&updated, "human:admin", now).unwrap();
    let reloaded = db.get_object(&object_id).unwrap().unwrap();
    assert_eq!(reloaded.properties.get("default_model").unwrap(), "mistral");
}

#[test]
fn sqlite_chisei_policy_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
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
fn postgres_chisei_policy_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    let loaded = restarted
        .get_object(&format!("policy-{prefix}-ns"))
        .unwrap()
        .unwrap();
    assert_eq!(loaded.properties.get("default_model").unwrap(), "mistral");
}

//! Shared SQLite/PostgreSQL conformance for model review state (#1493).

use sekai_chisei::chisei::decision_ledger::DecisionFilter;
use sekai_chisei::chisei::model_review::{
    self, FamilyEnablementRecord, MODEL_REVIEW_CONTRACT, ModelReviewIdentity, ModelReviewRecord,
    ModelReviewStatus,
};
use sekai_chisei::chisei_store::{ChiseiDecisionStore, ChiseiModelReviewStore, ChiseiStore};
use sekai_chisei::db::runtime_db::RuntimeDb;

fn review(namespace: &str, model: &str, status: ModelReviewStatus, at: i64) -> ModelReviewRecord {
    ModelReviewRecord {
        namespace: namespace.into(),
        identity: ModelReviewIdentity::new("openai", model, ""),
        status,
        actor: "root".into(),
        reason: "conformance".into(),
        updated_at_ms: at,
    }
}

fn family(
    namespace: &str,
    region: &str,
    status: ModelReviewStatus,
    at: i64,
) -> FamilyEnablementRecord {
    FamilyEnablementRecord {
        namespace: namespace.into(),
        region_label: region.into(),
        family_id: "openai".into(),
        status,
        actor: "root".into(),
        reason: "family conformance".into(),
        updated_at_ms: at,
    }
}

fn exercise(store: &ChiseiStore, prefix: &str) {
    let namespace = format!("{prefix}-sales");
    let foreign = format!("{prefix}-ops");
    // The PostgreSQL database is shared with other runs: count from here.
    let rows_before = store.model_review_row_count().unwrap();
    model_review::set_model_review(
        store,
        review(&namespace, "gpt-4", ModelReviewStatus::Reviewed, 1),
    )
    .unwrap();
    model_review::set_model_review(
        store,
        review(&namespace, "gpt-4", ModelReviewStatus::Enabled, 2),
    )
    .unwrap();
    model_review::set_model_review(
        store,
        review(&foreign, "gpt-4", ModelReviewStatus::Enabled, 3),
    )
    .unwrap();
    let listed = model_review::list_model_reviews(store, &namespace).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, ModelReviewStatus::Enabled);
    assert_eq!(
        model_review::list_model_reviews(store, &foreign)
            .unwrap()
            .len(),
        1
    );

    model_review::revoke_model_review(
        store,
        review(&namespace, "gpt-4", ModelReviewStatus::Enabled, 4),
    )
    .unwrap();
    assert_eq!(
        model_review::list_model_reviews(store, &namespace).unwrap()[0].status,
        ModelReviewStatus::Revoked
    );

    model_review::set_family_enablement(
        store,
        family(&namespace, "us", ModelReviewStatus::Enabled, 5),
    )
    .unwrap();
    let families = model_review::list_family_enablement(store, &namespace).unwrap();
    assert_eq!(families.len(), 1);
    assert_eq!(families[0].region_label, "us");

    // Only this run's targets carry the prefix, so other runs' decisions
    // can neither crowd these out nor satisfy the assertions.
    let actions = |target_id: String| {
        let decisions = store
            .list_decisions(&DecisionFilter {
                actor: Some("root".into()),
                action: None,
                target_id: Some(target_id),
                after: 0,
                limit: 20,
                offset: 0,
            })
            .unwrap();
        assert!(decisions.iter().all(|row| {
            row.evidence.get("contract_version") == Some(&MODEL_REVIEW_CONTRACT.to_string())
        }));
        let mut actions = decisions
            .into_iter()
            .map(|row| row.action)
            .collect::<Vec<_>>();
        actions.sort();
        actions
    };
    let mut expected = vec![
        model_review::ACTION_SET.to_string(),
        model_review::ACTION_SET.to_string(),
        model_review::ACTION_REVOKE.to_string(),
    ];
    expected.sort();
    assert_eq!(
        actions(review(&namespace, "gpt-4", ModelReviewStatus::Enabled, 0).target_id()),
        expected
    );
    assert_eq!(
        actions(review(&foreign, "gpt-4", ModelReviewStatus::Enabled, 0).target_id()),
        vec![model_review::ACTION_SET.to_string()]
    );
    assert_eq!(
        actions(family(&namespace, "us", ModelReviewStatus::Enabled, 0).target_id()),
        vec![model_review::ACTION_FAMILY_SET.to_string()]
    );
    // One row per (namespace, model): the set, re-set, and revoke upsert it.
    assert_eq!(store.model_review_row_count().unwrap(), rows_before + 2);
}

#[test]
fn sqlite_model_review_backend_conformance() {
    exercise(&ChiseiStore::memory(), "sqlite");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_model_review_backend_conformance() {
    use sekai_chisei::db::postgres::PostgresDb;
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let postgres = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 4).unwrap()
    };
    let prefix = format!("pg-review-{}", uuid::Uuid::new_v4().simple());
    let store = ChiseiStore::from_shared_runtime(std::sync::Arc::new(RuntimeDb::Postgres(
        std::sync::Arc::new(postgres),
    )));
    exercise(&store, &prefix);
}

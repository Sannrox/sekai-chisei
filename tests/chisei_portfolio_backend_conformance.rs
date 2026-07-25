//! Shared SQLite/PostgreSQL conformance for portfolio observations and objectives.

use sekai_chisei::chisei::portfolio::{
    LEGACY_PROMPT_VARIANT, Objective, ObjectiveMode, Observation,
};
use sekai_chisei::db::chisei_portfolio_backend::ChiseiPortfolioBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};

trait PortfolioHarness: ChiseiPortfolioBackend {}
impl PortfolioHarness for SekaiDb {}
impl PortfolioHarness for PostgresDb {}

fn exercise(db: &dyn PortfolioHarness, prefix: &str) {
    let namespace = format!("{prefix}-ns");
    db.portfolio_record_observation(&Observation {
        namespace: namespace.clone(),
        task_class: "primary".into(),
        model: "cheap".into(),
        prompt_variant: LEGACY_PROMPT_VARIANT.into(),
        quality_score: 0.8,
        cost_usd_micros: 100,
        sample_count: 3,
        updated_at: 10,
    })
    .unwrap();
    db.portfolio_record_observation(&Observation {
        namespace: namespace.clone(),
        task_class: "primary".into(),
        model: "capable".into(),
        prompt_variant: LEGACY_PROMPT_VARIANT.into(),
        quality_score: 0.95,
        cost_usd_micros: 500,
        sample_count: 4,
        updated_at: 11,
    })
    .unwrap();
    let points = db.portfolio_points(&namespace, "primary").unwrap();
    assert!(points.iter().any(|point| point.model == "cheap"));
    assert!(points.iter().any(|point| point.model == "capable"));

    db.portfolio_set_objective(&Objective {
        namespace: namespace.clone(),
        mode: ObjectiveMode::MaximizeValue,
        budget_usd_micros: 10_000,
        quality_bar: 0.7,
        min_samples: 2,
        updated_at: 12,
    })
    .unwrap();
    let objective = db.portfolio_objective(&namespace).unwrap().unwrap();
    assert_eq!(objective.mode, ObjectiveMode::MaximizeValue);
    assert_eq!(objective.budget_usd_micros, 10_000);
}

#[test]
fn sqlite_chisei_portfolio_conformance() {
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
fn postgres_chisei_portfolio_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    let objective = restarted
        .portfolio_objective(&format!("{prefix}-ns"))
        .unwrap()
        .unwrap();
    assert_eq!(objective.budget_usd_micros, 10_000);
}

//! Shared SQLite/PostgreSQL conformance for portfolio observations and objectives.

use sekai_chisei::chisei::portfolio::{
    FrontierPoint, LEGACY_PROMPT_VARIANT, Objective, ObjectiveMode, Observation,
};
use sekai_chisei::chisei_store::chisei_portfolio_backend::ChiseiPortfolioBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};

use crate::postgres_scratch::ScratchDatabase;

trait PortfolioHarness: ChiseiPortfolioBackend {}
impl PortfolioHarness for SekaiDb {}
impl PortfolioHarness for PostgresDb {}

const NAMESPACE: &str = "portfolio-ns";

fn observation(model: &str, quality: f64, cost: i64, samples: i64, at: i64) -> Observation {
    Observation {
        namespace: NAMESPACE.into(),
        task_class: "primary".into(),
        model: model.into(),
        prompt_variant: LEGACY_PROMPT_VARIANT.into(),
        quality_score: quality,
        cost_usd_micros: cost,
        sample_count: samples,
        updated_at: at,
    }
}

fn objective() -> Objective {
    Objective {
        namespace: NAMESPACE.into(),
        mode: ObjectiveMode::MaximizeValue,
        budget_usd_micros: 10_000,
        quality_bar: 0.7,
        min_samples: 2,
        updated_at: 12,
    }
}

/// The points `exercise` leaves behind, cheapest first. Scores are binary
/// fractions so the sample-weighted merge is exact on both backends.
fn expected_points() -> Vec<FrontierPoint> {
    vec![
        FrontierPoint {
            model: "cheap".into(),
            prompt_variant: LEGACY_PROMPT_VARIANT.into(),
            // (0.5 * 3 + 0.25 * 1) / 4 and (100 * 3 + 200 * 1) / 4.
            quality_score: 0.4375,
            cost_usd_micros: 125,
            sample_count: 4,
            updated_at: 13,
        },
        FrontierPoint {
            model: "capable".into(),
            prompt_variant: LEGACY_PROMPT_VARIANT.into(),
            quality_score: 0.875,
            cost_usd_micros: 500,
            sample_count: 4,
            updated_at: 11,
        },
    ]
}

fn exercise(db: &dyn PortfolioHarness) {
    db.portfolio_record_observation(&observation("cheap", 0.5, 100, 3, 10))
        .unwrap();
    db.portfolio_record_observation(&observation("capable", 0.875, 500, 4, 11))
        .unwrap();
    // A second write for the same namespace, task class, model and prompt
    // variant merges into its point instead of adding one.
    db.portfolio_record_observation(&observation("cheap", 0.25, 200, 1, 13))
        .unwrap();
    assert_eq!(
        db.portfolio_points(NAMESPACE, "primary").unwrap(),
        expected_points()
    );
    assert!(db.portfolio_points(NAMESPACE, "other").unwrap().is_empty());

    db.portfolio_set_objective(&objective()).unwrap();
    assert_eq!(
        db.portfolio_objective(NAMESPACE).unwrap(),
        Some(objective())
    );
}

#[test]
fn sqlite_chisei_portfolio_conformance() {
    exercise(&sekai_chisei::chisei_store::memory_sekai_with_chisei_schema());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_chisei_portfolio_conformance_and_restart() {
    let scratch = ScratchDatabase::create();
    let connect = || sekai_chisei::chisei_store::postgres_with_chisei_schema(scratch.connect(8));
    exercise(&connect());
    let restarted = connect();
    assert_eq!(
        restarted.portfolio_points(NAMESPACE, "primary").unwrap(),
        expected_points()
    );
    assert_eq!(
        restarted.portfolio_objective(NAMESPACE).unwrap(),
        Some(objective())
    );
}

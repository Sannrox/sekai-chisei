//! Backend-neutral portfolio observation and objective persistence.

use crate::chisei::portfolio::{FrontierPoint, Objective, Observation};
use sekai_core::db::{postgres::PostgresDb, sekai::SekaiDb};

pub trait ChiseiPortfolioBackend: Send + Sync {
    fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String>;
    fn portfolio_points(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String>;
    fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String>;
    fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String>;
}

macro_rules! forward {
    ($target:ty, $ext:path) => {
        fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String> {
            <$target as $ext>::portfolio_record_observation(self, observation)
        }
        fn portfolio_points(
            &self,
            namespace: &str,
            task_class: &str,
        ) -> Result<Vec<FrontierPoint>, String> {
            <$target as $ext>::portfolio_points(self, namespace, task_class)
        }
        fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String> {
            <$target as $ext>::portfolio_set_objective(self, objective)
        }
        fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
            <$target as $ext>::portfolio_objective(self, namespace)
        }
    };
}

impl ChiseiPortfolioBackend for SekaiDb {
    forward!(
        SekaiDb,
        crate::chisei_store::chisei_portfolio::ChiseiPortfolioSekaiDbExt
    );
}
impl ChiseiPortfolioBackend for PostgresDb {
    forward!(
        PostgresDb,
        crate::chisei_store::postgres_portfolio::PostgresPortfolioPostgresDbExt
    );
}

//! Backend-neutral portfolio observation and objective persistence.

use crate::chisei::portfolio::{FrontierPoint, Objective, Observation};
use crate::db::{postgres::PostgresDb, sekai::SekaiDb};

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
    ($target:ty) => {
        fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String> {
            <$target>::portfolio_record_observation(self, observation)
        }
        fn portfolio_points(
            &self,
            namespace: &str,
            task_class: &str,
        ) -> Result<Vec<FrontierPoint>, String> {
            <$target>::portfolio_points(self, namespace, task_class)
        }
        fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String> {
            <$target>::portfolio_set_objective(self, objective)
        }
        fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
            <$target>::portfolio_objective(self, namespace)
        }
    };
}

impl ChiseiPortfolioBackend for SekaiDb {
    forward!(SekaiDb);
}
impl ChiseiPortfolioBackend for PostgresDb {
    forward!(PostgresDb);
}

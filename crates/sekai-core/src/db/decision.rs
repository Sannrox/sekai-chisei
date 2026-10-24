//! Backend-neutral decision audit persistence for RecordDecision/ListDecisions.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::audit::{Decision, DecisionFilter};

pub trait DecisionBackend: Send + Sync {
    fn record_decision(&self, decision: &Decision) -> Result<(), String>;
    fn record_decisions(&self, decisions: &[Decision]) -> Result<(), String>;
    fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String>;
    fn get_decision(&self, id: &str) -> Result<Option<Decision>, String>;
    fn list_decisions(&self, filter: &DecisionFilter) -> Result<Vec<Decision>, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn record_decision(&self, decision: &Decision) -> Result<(), String> {
            <$target>::record_decision(self, decision)
        }
        fn record_decisions(&self, decisions: &[Decision]) -> Result<(), String> {
            <$target>::record_decisions(self, decisions)
        }
        fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String> {
            <$target>::record_decisions_idempotently(self, decisions)
        }
        fn get_decision(&self, id: &str) -> Result<Option<Decision>, String> {
            <$target>::get_decision(self, id)
        }
        fn list_decisions(&self, filter: &DecisionFilter) -> Result<Vec<Decision>, String> {
            <$target>::list_decisions(self, filter)
        }
    };
}

impl DecisionBackend for SekaiDb {
    forward!(SekaiDb);
}
impl DecisionBackend for PostgresDb {
    forward!(PostgresDb);
}

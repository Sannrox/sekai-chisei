//! Backend-neutral governed-action policy persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::action_policy::ActionPolicy;

pub trait ActionGovernanceBackend: Send + Sync {
    fn upsert_action_policy(&self, policy: &ActionPolicy) -> Result<(), String>;
    fn get_action_policy(&self, scope: &str) -> Result<Option<ActionPolicy>, String>;
    fn list_action_policies(&self) -> Result<Vec<ActionPolicy>, String>;
    fn resolve_action_policy(
        &self,
        actor: &str,
        namespace: &str,
        project: &str,
    ) -> Result<Option<ActionPolicy>, String>;
    fn get_blast_radius(&self, work_unit: &str) -> Result<(u32, u32), String>;
    fn add_blast_radius(
        &self,
        work_unit: &str,
        mutations: u32,
        deletes: u32,
    ) -> Result<(u32, u32), String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn upsert_action_policy(&self, value: &ActionPolicy) -> Result<(), String> {
            <$target>::upsert_action_policy(self, value)
        }
        fn get_action_policy(&self, scope: &str) -> Result<Option<ActionPolicy>, String> {
            <$target>::get_action_policy(self, scope)
        }
        fn list_action_policies(&self) -> Result<Vec<ActionPolicy>, String> {
            <$target>::list_action_policies(self)
        }
        fn resolve_action_policy(
            &self,
            actor: &str,
            namespace: &str,
            project: &str,
        ) -> Result<Option<ActionPolicy>, String> {
            <$target>::resolve_action_policy(self, actor, namespace, project)
        }
        fn get_blast_radius(&self, work_unit: &str) -> Result<(u32, u32), String> {
            <$target>::get_blast_radius(self, work_unit)
        }
        fn add_blast_radius(
            &self,
            work_unit: &str,
            mutations: u32,
            deletes: u32,
        ) -> Result<(u32, u32), String> {
            <$target>::add_blast_radius(self, work_unit, mutations, deletes)
        }
    };
}

impl ActionGovernanceBackend for SekaiDb {
    forward!(SekaiDb);
}
impl ActionGovernanceBackend for PostgresDb {
    forward!(PostgresDb);
}

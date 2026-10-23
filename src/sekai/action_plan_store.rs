//! Intents, proposed plans and simulations (#1675) on both community
//! backends. Each record is stored once under its caller-supplied id; a
//! write of an existing id keeps the stored record and returns it, so the
//! caller can tell a retry from a conflict.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::action_plan::{PlanIntent, PlanSimulation, ProposedPlan};

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_plan_intents (
    namespace TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, intent_id)
);
CREATE TABLE IF NOT EXISTS sekai_plans (
    namespace TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, plan_id)
);
CREATE TABLE IF NOT EXISTS sekai_plan_simulations (
    namespace TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    simulation_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    simulated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, plan_id, simulation_id)
);
";

fn decode<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt plan record: {error}"))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

impl SekaiDb {
    pub(crate) fn migrate_action_plans(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    fn sqlite_one(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(sql, params, |row| row.get(0))
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn put_plan_intent(&self, intent: &PlanIntent) -> Result<PlanIntent, String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_plan_intents (namespace, intent_id, body_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                rusqlite::params![
                    intent.namespace,
                    intent.intent_id,
                    encode(intent)?,
                    intent.created_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_plan_intent(&intent.namespace, &intent.intent_id)?
            .ok_or_else(|| "plan intent vanished after write".into())
    }

    pub fn get_plan_intent(
        &self,
        namespace: &str,
        intent_id: &str,
    ) -> Result<Option<PlanIntent>, String> {
        self.sqlite_one(
            "SELECT body_json FROM sekai_plan_intents WHERE namespace = ?1 AND intent_id = ?2",
            &[&namespace, &intent_id],
        )?
        .map(|json| decode(&json))
        .transpose()
    }

    pub fn put_plan(&self, plan: &ProposedPlan) -> Result<ProposedPlan, String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_plans (namespace, plan_id, intent_id, body_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
                rusqlite::params![
                    plan.namespace,
                    plan.plan_id,
                    plan.intent_id,
                    encode(plan)?,
                    plan.created_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_plan(&plan.namespace, &plan.plan_id)?
            .ok_or_else(|| "plan vanished after write".into())
    }

    pub fn get_plan(&self, namespace: &str, plan_id: &str) -> Result<Option<ProposedPlan>, String> {
        self.sqlite_one(
            "SELECT body_json FROM sekai_plans WHERE namespace = ?1 AND plan_id = ?2",
            &[&namespace, &plan_id],
        )?
        .map(|json| decode(&json))
        .transpose()
    }

    pub fn put_plan_simulation(
        &self,
        simulation: &PlanSimulation,
    ) -> Result<PlanSimulation, String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_plan_simulations
                     (namespace, plan_id, simulation_id, digest, body_json, simulated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
                rusqlite::params![
                    simulation.namespace,
                    simulation.plan_id,
                    simulation.simulation_id,
                    simulation.digest,
                    encode(simulation)?,
                    simulation.simulated_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_plan_simulation(
            &simulation.namespace,
            &simulation.plan_id,
            &simulation.simulation_id,
        )?
        .ok_or_else(|| "plan simulation vanished after write".into())
    }

    pub fn get_plan_simulation(
        &self,
        namespace: &str,
        plan_id: &str,
        simulation_id: &str,
    ) -> Result<Option<PlanSimulation>, String> {
        self.sqlite_one(
            "SELECT body_json FROM sekai_plan_simulations
             WHERE namespace = ?1 AND plan_id = ?2 AND simulation_id = ?3",
            &[&namespace, &plan_id, &simulation_id],
        )?
        .map(|json| decode(&json))
        .transpose()
    }

    pub fn list_plan_simulations(
        &self,
        namespace: &str,
        plan_id: &str,
        limit: usize,
    ) -> Result<Vec<PlanSimulation>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT body_json FROM sekai_plan_simulations
                 WHERE namespace = ?1 AND plan_id = ?2
                 ORDER BY simulated_at_ms DESC, simulation_id DESC LIMIT ?3",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![namespace, plan_id, limit as i64], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| decode(&row.map_err(|error| error.to_string())?))
            .collect()
    }
}

impl PostgresDb {
    fn postgres_one(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Option<String>, String> {
        Ok(self
            .connection()?
            .query_opt(sql, params)
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0)))
    }

    pub fn put_plan_intent(&self, intent: &PlanIntent) -> Result<PlanIntent, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_plan_intents (namespace, intent_id, body_json, created_at_ms)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[
                    &intent.namespace,
                    &intent.intent_id,
                    &encode(intent)?,
                    &intent.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_plan_intent(&intent.namespace, &intent.intent_id)?
            .ok_or_else(|| "plan intent vanished after write".into())
    }

    pub fn get_plan_intent(
        &self,
        namespace: &str,
        intent_id: &str,
    ) -> Result<Option<PlanIntent>, String> {
        self.postgres_one(
            "SELECT body_json FROM sekai_plan_intents WHERE namespace = $1 AND intent_id = $2",
            &[&namespace, &intent_id],
        )?
        .map(|json| decode(&json))
        .transpose()
    }

    pub fn put_plan(&self, plan: &ProposedPlan) -> Result<ProposedPlan, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_plans (namespace, plan_id, intent_id, body_json, created_at_ms)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                &[
                    &plan.namespace,
                    &plan.plan_id,
                    &plan.intent_id,
                    &encode(plan)?,
                    &plan.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_plan(&plan.namespace, &plan.plan_id)?
            .ok_or_else(|| "plan vanished after write".into())
    }

    pub fn get_plan(&self, namespace: &str, plan_id: &str) -> Result<Option<ProposedPlan>, String> {
        self.postgres_one(
            "SELECT body_json FROM sekai_plans WHERE namespace = $1 AND plan_id = $2",
            &[&namespace, &plan_id],
        )?
        .map(|json| decode(&json))
        .transpose()
    }

    pub fn put_plan_simulation(
        &self,
        simulation: &PlanSimulation,
    ) -> Result<PlanSimulation, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_plan_simulations
                     (namespace, plan_id, simulation_id, digest, body_json, simulated_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                &[
                    &simulation.namespace,
                    &simulation.plan_id,
                    &simulation.simulation_id,
                    &simulation.digest,
                    &encode(simulation)?,
                    &simulation.simulated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_plan_simulation(
            &simulation.namespace,
            &simulation.plan_id,
            &simulation.simulation_id,
        )?
        .ok_or_else(|| "plan simulation vanished after write".into())
    }

    pub fn get_plan_simulation(
        &self,
        namespace: &str,
        plan_id: &str,
        simulation_id: &str,
    ) -> Result<Option<PlanSimulation>, String> {
        self.postgres_one(
            "SELECT body_json FROM sekai_plan_simulations
             WHERE namespace = $1 AND plan_id = $2 AND simulation_id = $3",
            &[&namespace, &plan_id, &simulation_id],
        )?
        .map(|json| decode(&json))
        .transpose()
    }

    pub fn list_plan_simulations(
        &self,
        namespace: &str,
        plan_id: &str,
        limit: usize,
    ) -> Result<Vec<PlanSimulation>, String> {
        self.connection()?
            .query(
                "SELECT body_json FROM sekai_plan_simulations
                 WHERE namespace = $1 AND plan_id = $2
                 ORDER BY simulated_at_ms DESC, simulation_id DESC LIMIT $3",
                &[&namespace, &plan_id, &(limit as i64)],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| decode(row.get(0)))
            .collect()
    }
}

/// Dispatches to the backend the plane runs on; PostgreSQL off the async
/// runtime.
macro_rules! dispatch {
    ($self:ident, $db:ident => $call:expr) => {
        match $self {
            Self::Sqlite($db) => $call,
            Self::Postgres($db) => crate::db::postgres::off_runtime(|| $call),
        }
    };
}

impl crate::db::runtime_db::RuntimeDb {
    pub fn put_plan_intent(&self, intent: &PlanIntent) -> Result<PlanIntent, String> {
        dispatch!(self, db => db.put_plan_intent(intent))
    }

    pub fn get_plan_intent(
        &self,
        namespace: &str,
        intent_id: &str,
    ) -> Result<Option<PlanIntent>, String> {
        dispatch!(self, db => db.get_plan_intent(namespace, intent_id))
    }

    pub fn put_plan(&self, plan: &ProposedPlan) -> Result<ProposedPlan, String> {
        dispatch!(self, db => db.put_plan(plan))
    }

    pub fn get_plan(&self, namespace: &str, plan_id: &str) -> Result<Option<ProposedPlan>, String> {
        dispatch!(self, db => db.get_plan(namespace, plan_id))
    }

    pub fn put_plan_simulation(
        &self,
        simulation: &PlanSimulation,
    ) -> Result<PlanSimulation, String> {
        dispatch!(self, db => db.put_plan_simulation(simulation))
    }

    pub fn get_plan_simulation(
        &self,
        namespace: &str,
        plan_id: &str,
        simulation_id: &str,
    ) -> Result<Option<PlanSimulation>, String> {
        dispatch!(self, db => db.get_plan_simulation(namespace, plan_id, simulation_id))
    }

    pub fn list_plan_simulations(
        &self,
        namespace: &str,
        plan_id: &str,
        limit: usize,
    ) -> Result<Vec<PlanSimulation>, String> {
        dispatch!(self, db => db.list_plan_simulations(namespace, plan_id, limit))
    }
}

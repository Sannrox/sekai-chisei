use crate::db::postgres::PostgresDb;
use crate::sekai::action_policy::{ActionPolicy, candidate_scopes};

impl PostgresDb {
    pub fn upsert_action_policy(&self, policy: &ActionPolicy) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp();
        let body = serde_json::to_string(&policy.to_properties()).map_err(|e| e.to_string())?;
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO sekai_action_policies(scope,properties_json,created,updated)
             VALUES($1,$2,$3,$3) ON CONFLICT(scope) DO UPDATE SET
             properties_json=EXCLUDED.properties_json,updated=EXCLUDED.updated",
            &[&policy.scope, &body, &now],
        )
        .map_err(|e| e.to_string())?;
        insert_audit(
            &mut tx,
            "policy.upsert",
            &policy.scope,
            "",
            "committed",
            now,
        )?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn get_action_policy(&self, scope: &str) -> Result<Option<ActionPolicy>, String> {
        self.connection()?
            .query_opt(
                "SELECT properties_json FROM sekai_action_policies WHERE scope=$1",
                &[&scope],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                let properties = serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action policy {scope}: {e}"))?;
                Ok(ActionPolicy::from_properties(scope, &properties))
            })
            .transpose()
    }

    pub fn list_action_policies(&self) -> Result<Vec<ActionPolicy>, String> {
        self.connection()?
            .query(
                "SELECT scope,properties_json FROM sekai_action_policies ORDER BY scope",
                &[],
            )
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|row| {
                let scope: String = row.get(0);
                let body: String = row.get(1);
                let properties = serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action policy {scope}: {e}"))?;
                Ok(ActionPolicy::from_properties(&scope, &properties))
            })
            .collect()
    }

    pub fn resolve_action_policy(
        &self,
        actor: &str,
        namespace: &str,
        project: &str,
    ) -> Result<Option<ActionPolicy>, String> {
        for scope in candidate_scopes(actor, namespace, project) {
            if let Some(policy) = self.get_action_policy(&scope)? {
                return Ok(Some(policy));
            }
        }
        Ok(None)
    }

    pub fn get_blast_radius(&self, work_unit: &str) -> Result<(u32, u32), String> {
        self.connection()?
            .query_opt(
                "SELECT mutations,deletes FROM sekai_action_blast_radius WHERE work_unit=$1",
                &[&work_unit],
            )
            .map_err(|e| e.to_string())?
            .map_or(Ok((0, 0)), |row| {
                let mutations: i64 = row.get(0);
                let deletes: i64 = row.get(1);
                Ok((
                    u32::try_from(mutations).unwrap_or(u32::MAX),
                    u32::try_from(deletes).unwrap_or(u32::MAX),
                ))
            })
    }

    pub fn add_blast_radius(
        &self,
        work_unit: &str,
        mutations: u32,
        deletes: u32,
    ) -> Result<(u32, u32), String> {
        let now = chrono::Utc::now().timestamp();
        let mutations = i64::from(mutations);
        let deletes = i64::from(deletes);
        let row = self
            .connection()?
            .query_one(
                "INSERT INTO sekai_action_blast_radius(work_unit,mutations,deletes,updated)
             VALUES($1,$2,$3,$4) ON CONFLICT(work_unit) DO UPDATE SET
             mutations=LEAST(sekai_action_blast_radius.mutations + EXCLUDED.mutations, 4294967295),
             deletes=LEAST(sekai_action_blast_radius.deletes + EXCLUDED.deletes, 4294967295),
             updated=EXCLUDED.updated RETURNING mutations,deletes",
                &[&work_unit, &mutations, &deletes, &now],
            )
            .map_err(|e| e.to_string())?;
        Ok((row.get::<_, i64>(0) as u32, row.get::<_, i64>(1) as u32))
    }
}

fn insert_audit(
    tx: &mut postgres::Transaction<'_>,
    operation: &str,
    target_id: &str,
    actor: &str,
    outcome: &str,
    created: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_action_governance_audit(operation,target_id,actor,outcome,created)
         VALUES($1,$2,$3,$4,$5)",
        &[&operation, &target_id, &actor, &outcome, &created],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

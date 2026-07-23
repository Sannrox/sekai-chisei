use crate::db::postgres::PostgresDb;
use crate::sekai::action::{ActionTypeDef, validate_action_type_definition};

impl PostgresDb {
    pub fn upsert_action_type(&self, action_type: &ActionTypeDef) -> Result<ActionTypeDef, String> {
        validate_action_type_definition(action_type, false)?;
        let mut stored = action_type.clone();
        let now = chrono::Utc::now().timestamp_millis();
        if stored.created <= 0 {
            stored.created = now;
        }
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 236))",
                &[&stored.name],
            )
            .map_err(|error| format!("lock action definition: {error}"))?;
        if let Some(row) = transaction
            .query_opt(
                "SELECT created FROM sekai_action_types WHERE name=$1 FOR UPDATE",
                &[&stored.name],
            )
            .map_err(|error| error.to_string())?
        {
            stored.created = row.get(0);
        }
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_action_types
                    (name,description,target_kind,body_json,created,updated)
                 VALUES ($1,$2,$3,$4,$5,$6)
                 ON CONFLICT(name) DO UPDATE SET
                    description=EXCLUDED.description,
                    target_kind=EXCLUDED.target_kind,
                    body_json=EXCLUDED.body_json,
                    updated=EXCLUDED.updated",
                &[
                    &stored.name,
                    &stored.description,
                    &stored.target_kind,
                    &body,
                    &stored.created,
                    &now,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    pub fn delete_action_type(&self, name: &str) -> Result<bool, String> {
        self.connection()?
            .execute("DELETE FROM sekai_action_types WHERE name=$1", &[&name])
            .map(|deleted| deleted > 0)
            .map_err(|error| error.to_string())
    }

    pub fn list_action_types(&self) -> Result<Vec<ActionTypeDef>, String> {
        self.connection()?
            .query(
                "SELECT body_json FROM sekai_action_types ORDER BY name",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let body: String = row.get(0);
                serde_json::from_str(&body)
                    .map_err(|error| format!("corrupt action definition: {error}"))
            })
            .collect()
    }
}

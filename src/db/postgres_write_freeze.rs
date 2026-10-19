use crate::db::postgres::PostgresDb;
use crate::sekai::audit::Decision;
use crate::sekai::write_freeze::WriteFreeze;

impl PostgresDb {
    pub fn set_write_freeze(&self, freeze: &WriteFreeze) -> Result<(), String> {
        freeze.validate()?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        upsert_write_freeze(&mut tx, freeze)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn set_write_freeze_with_decision(
        &self,
        freeze: &WriteFreeze,
        decision: &Decision,
    ) -> Result<(), String> {
        freeze.validate()?;
        crate::sekai::audit::validate_decision(decision)?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        upsert_write_freeze(&mut tx, freeze)?;
        crate::db::postgres_decision::insert_chained_decision(&mut tx, decision)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn list_write_freezes(&self) -> Result<Vec<WriteFreeze>, String> {
        self.connection()?
            .query(
                "SELECT scope_kind, scope_value, mode, reason, enabled, updated_ms
                 FROM sekai_write_freeze ORDER BY scope_kind, scope_value",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                Ok(WriteFreeze {
                    scope_kind: row.get(0),
                    scope_value: row.get(1),
                    mode: row.get(2),
                    reason: row.get(3),
                    enabled: row.get(4),
                    updated_ms: row.get(5),
                })
            })
            .collect()
    }
}

fn upsert_write_freeze(
    tx: &mut postgres::Transaction<'_>,
    freeze: &WriteFreeze,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_write_freeze (scope_kind, scope_value, mode, reason, enabled, updated_ms)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (scope_kind, scope_value) DO UPDATE SET
            mode = EXCLUDED.mode,
            reason = EXCLUDED.reason,
            enabled = EXCLUDED.enabled,
            updated_ms = EXCLUDED.updated_ms",
        &[
            &freeze.scope_kind,
            &freeze.scope_value,
            &freeze.mode,
            &freeze.reason,
            &freeze.enabled,
            &freeze.updated_ms,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

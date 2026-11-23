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
        guard_unfreeze(&mut tx, freeze)?;
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
        guard_unfreeze(&mut tx, freeze)?;
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

/// Refuse an unfreeze held by a security mitigation. The share lock on
/// `sekai_objects` waits out in-flight object writes and blocks new ones until
/// the freeze commits, so a racing apply commits before this read or after the
/// freeze write, where its own catch-up re-enables the freeze. It is taken
/// before the freeze row so it cannot deadlock against an apply.
fn guard_unfreeze(tx: &mut postgres::Transaction<'_>, freeze: &WriteFreeze) -> Result<(), String> {
    use crate::sekai::security_remediation::{
        KIND_MITIGATION, refuse_unfreeze_held_by, unfreeze_needs_guard,
    };
    if !unfreeze_needs_guard(freeze) {
        return Ok(());
    }
    tx.batch_execute("LOCK TABLE sekai_objects IN SHARE MODE")
        .map_err(|error| error.to_string())?;
    let mitigations = crate::db::postgres_objects::objects_of_kind(tx, KIND_MITIGATION)?;
    refuse_unfreeze_held_by(freeze, &mitigations)
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

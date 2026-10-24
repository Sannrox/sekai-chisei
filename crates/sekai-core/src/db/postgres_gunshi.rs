//! PostgreSQL persistence for Gunshi namespace allocation state (#1474).

use crate::db::postgres::PostgresDb;

impl PostgresDb {
    pub fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT state_json FROM chisei_gunshi_allocation_state WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0)))
    }

    /// Insert or CAS-update Gunshi allocation state.
    ///
    /// When `expected_revision` is `None`, the row must not exist yet (install).
    /// When `Some(rev)`, the existing `revision_id` must match for the update to apply.
    pub fn put_gunshi_allocation_state_cas(
        &self,
        namespace: &str,
        revision_id: &str,
        changed_at_ms: i64,
        state_json: &str,
        expected_revision: Option<&str>,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_opt(
                "SELECT revision_id FROM chisei_gunshi_allocation_state WHERE namespace = $1 FOR UPDATE",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0));
        match (current.as_deref(), expected_revision) {
            (None, None) => {
                // PostgreSQL cannot FOR UPDATE an absent key, so two first
                // installs can both pass SELECT and race the INSERT. Map that
                // conflict to Ok(false) instead of a unique-constraint error.
                let inserted = tx
                    .execute(
                        "INSERT INTO chisei_gunshi_allocation_state
                            (namespace, revision_id, changed_at_ms, state_json)
                         VALUES ($1, $2, $3, $4)
                         ON CONFLICT (namespace) DO NOTHING",
                        &[&namespace, &revision_id, &changed_at_ms, &state_json],
                    )
                    .map_err(|error| error.to_string())?;
                if inserted != 1 {
                    return Ok(false);
                }
            }
            (Some(existing), Some(expected)) if existing == expected => {
                let updated = tx
                    .execute(
                        "UPDATE chisei_gunshi_allocation_state
                         SET revision_id = $2, changed_at_ms = $3, state_json = $4
                         WHERE namespace = $1 AND revision_id = $5",
                        &[
                            &namespace,
                            &revision_id,
                            &changed_at_ms,
                            &state_json,
                            &expected,
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                if updated != 1 {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

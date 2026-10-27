//! PostgreSQL storage for fence bindings (ADR 0121). Same tables and
//! semantics as SQLite (`crates/sekai-core/src/sekai/fence_binding.rs`). Installs serialize on
//! a per-binding advisory lock so concurrent reinstalls each get their own
//! revision; the cursor write is conditional, so it needs none.

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::sekai::fence_binding::{FenceBinding, FenceEventId, FenceEventReceipt};

impl PostgresDb {
    pub fn put_fence_binding(
        &self,
        binding: &FenceBinding,
        actor: &str,
        now_ms: i64,
    ) -> Result<FenceBinding, String> {
        binding.validate()?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key =
            advisory_lock_key(&["fence_binding", &binding.namespace, &binding.binding_id]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let previous: Option<i64> = tx
            .query_opt(
                "SELECT revision FROM sekai_fence_bindings WHERE namespace = $1 AND binding_id = $2",
                &[&binding.namespace, &binding.binding_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        let mut stored = binding.clone();
        stored.revision = previous.map_or(1, |revision| revision as u64 + 1);
        stored.created_by = actor.to_string();
        stored.updated_at_ms = now_ms;
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_fence_bindings
                (namespace, binding_id, revision, body_json, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (namespace, binding_id) DO UPDATE SET
                revision = EXCLUDED.revision,
                body_json = EXCLUDED.body_json,
                run_id = '',
                run_lease_until_ms = 0,
                updated_at_ms = EXCLUDED.updated_at_ms",
            &[
                &stored.namespace,
                &stored.binding_id,
                &(stored.revision as i64),
                &body,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    pub fn get_fence_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<(FenceBinding, Option<FenceEventId>)>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT body_json, after_lsn, after_index
                 FROM sekai_fence_bindings WHERE namespace = $1 AND binding_id = $2",
                &[&namespace, &binding_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                let lsn: Option<i64> = row.get(1);
                let index: i64 = row.get(2);
                let binding: FenceBinding = serde_json::from_str(&body)
                    .map_err(|error| format!("corrupt fence binding: {error}"))?;
                Ok((binding, lsn.map(|lsn| (lsn as u64, index as u32))))
            })
            .transpose()
    }

    pub fn lease_fence_run(
        &self,
        binding: &FenceBinding,
        run_id: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        let held = if renew {
            "run_id = $4 AND run_lease_until_ms >= $5"
        } else {
            "(run_id = '' OR run_lease_until_ms < $5)"
        };
        let mut connection = self.connection()?;
        connection
            .execute(
                &format!(
                    "UPDATE sekai_fence_bindings SET run_id = $4, run_lease_until_ms = $6
                     WHERE namespace = $1 AND binding_id = $2 AND revision = $3 AND {held}"
                ),
                &[
                    &binding.namespace,
                    &binding.binding_id,
                    &(binding.revision as i64),
                    &run_id,
                    &now_ms,
                    &until_ms,
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    pub fn release_fence_run(&self, binding: &FenceBinding, run_id: &str) -> Result<(), String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "UPDATE sekai_fence_bindings SET run_id = '', run_lease_until_ms = 0
                 WHERE namespace = $1 AND binding_id = $2 AND run_id = $3",
                &[&binding.namespace, &binding.binding_id, &run_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn advance_fence_binding(
        &self,
        binding: &FenceBinding,
        run_id: &str,
        through: FenceEventId,
        receipts: &[FenceEventReceipt],
        now_ms: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let (lsn, index) = (through.0 as i64, through.1 as i64);
        let moved = tx
            .execute(
                "UPDATE sekai_fence_bindings
                 SET after_lsn = $4, after_index = $5, updated_at_ms = $6
                 WHERE namespace = $1 AND binding_id = $2 AND revision = $3
                   AND run_id = $7 AND run_lease_until_ms >= $6
                   AND (after_lsn IS NULL OR after_lsn < $4
                        OR (after_lsn = $4 AND after_index < $5))",
                &[
                    &binding.namespace,
                    &binding.binding_id,
                    &(binding.revision as i64),
                    &lsn,
                    &index,
                    &now_ms,
                    &run_id,
                ],
            )
            .map_err(|error| error.to_string())?
            == 1;
        if moved {
            for receipt in receipts {
                let json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
                tx.execute(
                    "INSERT INTO sekai_fence_binding_receipts
                        (namespace, binding_id, revision, lsn, event_index, receipt_json,
                         recorded_at_ms)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)
                     ON CONFLICT DO NOTHING",
                    &[
                        &binding.namespace,
                        &binding.binding_id,
                        &(binding.revision as i64),
                        &(receipt.lsn as i64),
                        &(receipt.index as i64),
                        &json,
                        &now_ms,
                    ],
                )
                .map_err(|error| error.to_string())?;
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(moved)
    }

    pub fn list_fence_binding_receipts(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Vec<FenceEventReceipt>, String> {
        let mut connection = self.connection()?;
        connection
            .query(
                "SELECT receipt_json FROM sekai_fence_binding_receipts
                 WHERE namespace = $1 AND binding_id = $2
                 ORDER BY lsn, event_index, revision",
                &[&namespace, &binding_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json)
                    .map_err(|error| format!("corrupt fence receipt: {error}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_fence_cursors_move_forward_once_per_revision() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = crate::db::runtime_db::RuntimeDb::Postgres(Arc::new(db.unwrap()));
        // A namespace of its own, so concurrent runs on one database do not
        // share a binding.
        let namespace = format!("fence-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        crate::sekai::fence_binding::tests::cursor_contract(&db, &namespace);
    }
}

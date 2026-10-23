//! PostgreSQL storage for offline sync scopes (#1632). Same tables and
//! semantics as SQLite (`src/db/sync_scope.rs`).

use crate::db::postgres::PostgresDb;
use crate::db::sync_scope::{definition_json, parse_definition};
use crate::sekai::sync_scope::{Member, SyncError, SyncPosition, SyncScope};

fn storage(error: impl ToString) -> SyncError {
    SyncError::Storage(error.to_string())
}

impl PostgresDb {
    pub fn put_sync_scope(&self, scope: &SyncScope) -> Result<SyncScope, SyncError> {
        let definition = definition_json(&scope.definition)?;
        let mut connection = self.connection().map_err(storage)?;
        let mut tx = connection.transaction().map_err(storage)?;
        let stored = tx
            .query_opt(
                "SELECT definition, updated_at_ms FROM sekai_sync_scopes
                 WHERE namespace = $1 AND owner = $2 AND scope_id = $3 FOR UPDATE",
                &[&scope.namespace, &scope.owner, &scope.scope_id],
            )
            .map_err(storage)?;
        if let Some(row) = &stored
            && row.get::<_, String>(0) == definition
        {
            return Ok(SyncScope {
                updated_at_ms: row.get(1),
                ..scope.clone()
            });
        }
        for table in ["sekai_sync_members", "sekai_sync_delivered"] {
            tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE position_id IN (
                         SELECT position_id FROM sekai_sync_positions
                         WHERE namespace = $1 AND owner = $2 AND scope_id = $3)"
                ),
                &[&scope.namespace, &scope.owner, &scope.scope_id],
            )
            .map_err(storage)?;
        }
        tx.execute(
            "DELETE FROM sekai_sync_positions WHERE namespace = $1 AND owner = $2 AND scope_id = $3",
            &[&scope.namespace, &scope.owner, &scope.scope_id],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO sekai_sync_scopes (namespace, owner, scope_id, definition, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (namespace, owner, scope_id)
             DO UPDATE SET definition = excluded.definition, updated_at_ms = excluded.updated_at_ms",
            &[
                &scope.namespace,
                &scope.owner,
                &scope.scope_id,
                &definition,
                &scope.updated_at_ms,
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(scope.clone())
    }

    pub fn get_sync_scope(
        &self,
        namespace: &str,
        owner: &str,
        scope_id: &str,
    ) -> Result<Option<SyncScope>, SyncError> {
        let row = self
            .connection()
            .map_err(storage)?
            .query_opt(
                "SELECT definition, updated_at_ms FROM sekai_sync_scopes
                 WHERE namespace = $1 AND owner = $2 AND scope_id = $3",
                &[&namespace, &owner, &scope_id],
            )
            .map_err(storage)?;
        row.map(|row| {
            Ok(SyncScope {
                namespace: namespace.to_string(),
                owner: owner.to_string(),
                scope_id: scope_id.to_string(),
                definition: parse_definition(&row.get::<_, String>(0))?,
                updated_at_ms: row.get(1),
            })
        })
        .transpose()
    }

    pub fn save_sync_position(
        &self,
        position: &SyncPosition,
        retire_others: bool,
        now_ms: i64,
    ) -> Result<(), SyncError> {
        let mut connection = self.connection().map_err(storage)?;
        let mut tx = connection.transaction().map_err(storage)?;
        if retire_others {
            // The scope row lock serializes snapshot replacement per scope.
            tx.execute(
                "SELECT 1 FROM sekai_sync_scopes
                 WHERE namespace = $1 AND owner = $2 AND scope_id = $3 FOR UPDATE",
                &[&position.namespace, &position.owner, &position.scope_id],
            )
            .map_err(storage)?;
            let stale: Vec<String> = tx
                .query(
                    "SELECT position_id FROM sekai_sync_positions
                     WHERE namespace = $1 AND owner = $2 AND scope_id = $3 AND position_id <> $4",
                    &[
                        &position.namespace,
                        &position.owner,
                        &position.scope_id,
                        &position.position_id,
                    ],
                )
                .map_err(storage)?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            Self::delete_sync_positions(&mut tx, "SELECT unnest($1::text[])", &[&stale])?;
        }
        let inserted = tx
            .execute(
                "INSERT INTO sekai_sync_positions (position_id, namespace, owner, scope_id,
                     authorization_pin, successor_id, origin_id, created_at_ms)
                 VALUES ($1, $2, $3, $4, $5, NULL, $6, $7) ON CONFLICT (position_id) DO NOTHING",
                &[
                    &position.position_id,
                    &position.namespace,
                    &position.owner,
                    &position.scope_id,
                    &position.authorization_pin,
                    &position.origin,
                    &now_ms,
                ],
            )
            .map_err(storage)?;
        if inserted > 0 {
            for member in &position.members {
                tx.execute(
                    "INSERT INTO sekai_sync_members (position_id, object_id, fingerprint)
                     VALUES ($1, $2, $3)",
                    &[
                        &position.position_id,
                        &member.object_id,
                        &member.fingerprint,
                    ],
                )
                .map_err(storage)?;
            }
        }
        tx.commit().map_err(storage)
    }

    pub fn get_sync_position(&self, position_id: &str) -> Result<Option<SyncPosition>, SyncError> {
        let mut connection = self.connection().map_err(storage)?;
        let Some(header) = connection
            .query_opt(
                "SELECT namespace, owner, scope_id, authorization_pin, successor_id, origin_id
                 FROM sekai_sync_positions WHERE position_id = $1",
                &[&position_id],
            )
            .map_err(storage)?
        else {
            return Ok(None);
        };
        let members = connection
            .query(
                "SELECT object_id, fingerprint FROM sekai_sync_members
                 WHERE position_id = $1 ORDER BY object_id",
                &[&position_id],
            )
            .map_err(storage)?
            .into_iter()
            .map(|row| Member {
                object_id: row.get(0),
                fingerprint: row.get(1),
            })
            .collect();
        let delivered = connection
            .query(
                "SELECT object_id, fingerprint FROM sekai_sync_delivered WHERE position_id = $1",
                &[&position_id],
            )
            .map_err(storage)?
            .into_iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
            .collect();
        Ok(Some(SyncPosition {
            position_id: position_id.to_string(),
            namespace: header.get(0),
            owner: header.get(1),
            scope_id: header.get(2),
            authorization_pin: header.get(3),
            members,
            successor: header.get(4),
            origin: header.get(5),
            delivered,
        }))
    }

    pub fn set_sync_successor(
        &self,
        position_id: &str,
        successor_id: &str,
    ) -> Result<Option<String>, SyncError> {
        let mut connection = self.connection().map_err(storage)?;
        connection
            .execute(
                "UPDATE sekai_sync_positions SET successor_id = $2
                 WHERE position_id = $1 AND successor_id IS NULL",
                &[&position_id, &successor_id],
            )
            .map_err(storage)?;
        Ok(connection
            .query_opt(
                "SELECT successor_id FROM sekai_sync_positions WHERE position_id = $1",
                &[&position_id],
            )
            .map_err(storage)?
            .and_then(|row| row.get::<_, Option<String>>(0)))
    }

    pub fn record_sync_delivery(
        &self,
        position_id: &str,
        delivered: &[(String, String)],
    ) -> Result<(), SyncError> {
        let mut connection = self.connection().map_err(storage)?;
        let mut tx = connection.transaction().map_err(storage)?;
        for (object_id, fingerprint) in delivered {
            tx.execute(
                "INSERT INTO sekai_sync_delivered (position_id, object_id, fingerprint)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (position_id, object_id) DO UPDATE SET fingerprint =
                     CASE WHEN sekai_sync_delivered.fingerprint = excluded.fingerprint
                          THEN excluded.fingerprint ELSE '?' END",
                &[&position_id, object_id, fingerprint],
            )
            .map_err(storage)?;
        }
        tx.commit().map_err(storage)
    }

    fn delete_sync_positions(
        tx: &mut postgres::Transaction<'_>,
        selection: &str,
        args: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<(), SyncError> {
        for table in [
            "sekai_sync_members",
            "sekai_sync_delivered",
            "sekai_sync_positions",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE position_id IN ({selection})"),
                args,
            )
            .map_err(storage)?;
        }
        Ok(())
    }

    pub fn prune_sync_before(&self, cursor: &str) -> Result<(), SyncError> {
        let mut connection = self.connection().map_err(storage)?;
        let mut tx = connection.transaction().map_err(storage)?;
        let stale: Vec<String> = tx
            .query(
                "SELECT position_id FROM sekai_sync_positions
                 WHERE position_id <> $1 AND (
                     position_id = (SELECT origin_id FROM sekai_sync_positions WHERE position_id = $1)
                     OR origin_id = (SELECT origin_id FROM sekai_sync_positions WHERE position_id = $1))",
                &[&cursor],
            )
            .map_err(storage)?
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        Self::delete_sync_positions(&mut tx, "SELECT unnest($1::text[])", &[&stale])?;
        tx.commit().map_err(storage)
    }
}

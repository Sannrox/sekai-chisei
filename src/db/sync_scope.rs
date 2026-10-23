//! SQLite storage for offline sync scopes (#1632), and the backend dispatch.
//! A position and its members are written once, keyed by a digest of their
//! content, so saving the same position twice is a no-op.

use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::sync_scope::{Member, ScopeDefinition, SyncError, SyncPosition, SyncScope};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sekai_sync_scopes (
    namespace TEXT NOT NULL,
    owner TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    definition TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, owner, scope_id)
);
CREATE TABLE IF NOT EXISTS sekai_sync_positions (
    position_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    owner TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    authorization_pin TEXT NOT NULL,
    successor_id TEXT,
    origin_id TEXT,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sekai_sync_positions_by_scope
    ON sekai_sync_positions (namespace, owner, scope_id);
CREATE TABLE IF NOT EXISTS sekai_sync_delivered (
    position_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (position_id, object_id)
);
CREATE TABLE IF NOT EXISTS sekai_sync_members (
    position_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (position_id, object_id)
);
";

fn storage(error: impl ToString) -> SyncError {
    SyncError::Storage(error.to_string())
}

pub(crate) fn definition_json(definition: &ScopeDefinition) -> Result<String, SyncError> {
    serde_json::to_string(definition).map_err(storage)
}

pub(crate) fn parse_definition(raw: &str) -> Result<ScopeDefinition, SyncError> {
    serde_json::from_str(raw).map_err(storage)
}

impl SekaiDb {
    pub(crate) fn migrate_sync_scopes(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(SCHEMA)
            .map_err(|error| error.to_string())
    }

    fn put_sync_scope(&self, scope: &SyncScope) -> Result<SyncScope, SyncError> {
        let definition = definition_json(&scope.definition)?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT definition FROM sekai_sync_scopes
                 WHERE namespace = ?1 AND owner = ?2 AND scope_id = ?3",
                params![scope.namespace, scope.owner, scope.scope_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if stored.as_deref() == Some(definition.as_str()) {
            return self_get(&tx, &scope.namespace, &scope.owner, &scope.scope_id)?
                .ok_or(SyncError::NotFound);
        }
        // A new definition invalidates every cursor of the old one.
        tx.execute(
            "DELETE FROM sekai_sync_delivered WHERE position_id IN (
                 SELECT position_id FROM sekai_sync_positions
                 WHERE namespace = ?1 AND owner = ?2 AND scope_id = ?3)",
            params![scope.namespace, scope.owner, scope.scope_id],
        )
        .map_err(storage)?;
        tx.execute(
            "DELETE FROM sekai_sync_members WHERE position_id IN (
                 SELECT position_id FROM sekai_sync_positions
                 WHERE namespace = ?1 AND owner = ?2 AND scope_id = ?3)",
            params![scope.namespace, scope.owner, scope.scope_id],
        )
        .map_err(storage)?;
        tx.execute(
            "DELETE FROM sekai_sync_positions WHERE namespace = ?1 AND owner = ?2 AND scope_id = ?3",
            params![scope.namespace, scope.owner, scope.scope_id],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO sekai_sync_scopes (namespace, owner, scope_id, definition, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (namespace, owner, scope_id)
             DO UPDATE SET definition = excluded.definition, updated_at_ms = excluded.updated_at_ms",
            params![
                scope.namespace,
                scope.owner,
                scope.scope_id,
                definition,
                scope.updated_at_ms
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(scope.clone())
    }

    fn get_sync_scope(
        &self,
        namespace: &str,
        owner: &str,
        scope_id: &str,
    ) -> Result<Option<SyncScope>, SyncError> {
        self_get(&self.conn(), namespace, owner, scope_id)
    }

    fn save_sync_position(
        &self,
        position: &SyncPosition,
        retire_others: bool,
        now_ms: i64,
    ) -> Result<(), SyncError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if retire_others {
            let stale = Self::sync_position_ids(
                &tx,
                "SELECT position_id FROM sekai_sync_positions
                 WHERE namespace = ?1 AND owner = ?2 AND scope_id = ?3 AND position_id <> ?4",
                &[
                    &position.namespace,
                    &position.owner,
                    &position.scope_id,
                    &position.position_id,
                ],
            )?;
            Self::delete_sync_positions(&tx, &stale)?;
        }
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO sekai_sync_positions (position_id, namespace, owner,
                     scope_id, authorization_pin, successor_id, origin_id, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
                params![
                    position.position_id,
                    position.namespace,
                    position.owner,
                    position.scope_id,
                    position.authorization_pin,
                    position.origin,
                    now_ms
                ],
            )
            .map_err(storage)?;
        if inserted > 0 {
            for member in &position.members {
                tx.execute(
                    "INSERT INTO sekai_sync_members (position_id, object_id, fingerprint)
                     VALUES (?1, ?2, ?3)",
                    params![position.position_id, member.object_id, member.fingerprint],
                )
                .map_err(storage)?;
            }
        }
        tx.commit().map_err(storage)
    }

    fn get_sync_position(&self, position_id: &str) -> Result<Option<SyncPosition>, SyncError> {
        let conn = self.conn();
        let header = conn
            .query_row(
                "SELECT namespace, owner, scope_id, authorization_pin, successor_id, origin_id
                 FROM sekai_sync_positions WHERE position_id = ?1",
                params![position_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let Some((namespace, owner, scope_id, authorization_pin, successor, origin)) = header
        else {
            return Ok(None);
        };
        let mut statement = conn
            .prepare(
                "SELECT object_id, fingerprint FROM sekai_sync_members
                 WHERE position_id = ?1 ORDER BY object_id",
            )
            .map_err(storage)?;
        let members = statement
            .query_map(params![position_id], |row| {
                Ok(Member {
                    object_id: row.get(0)?,
                    fingerprint: row.get(1)?,
                })
            })
            .map_err(storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage)?;
        let mut statement = conn
            .prepare(
                "SELECT object_id, fingerprint FROM sekai_sync_delivered WHERE position_id = ?1",
            )
            .map_err(storage)?;
        let delivered = statement
            .query_map(params![position_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?
            .collect::<rusqlite::Result<_>>()
            .map_err(storage)?;
        Ok(Some(SyncPosition {
            position_id: position_id.to_string(),
            namespace,
            owner,
            scope_id,
            authorization_pin,
            members,
            successor,
            origin,
            delivered,
        }))
    }

    fn set_sync_successor(
        &self,
        position_id: &str,
        successor_id: &str,
    ) -> Result<Option<String>, SyncError> {
        let conn = self.conn();
        conn.execute(
            "UPDATE sekai_sync_positions SET successor_id = ?2
             WHERE position_id = ?1 AND successor_id IS NULL",
            params![position_id, successor_id],
        )
        .map_err(storage)?;
        conn.query_row(
            "SELECT successor_id FROM sekai_sync_positions WHERE position_id = ?1",
            params![position_id],
            |row| row.get(0),
        )
        .optional()
        .map(Option::flatten)
        .map_err(storage)
    }

    /// Record deliveries; an object two answers delivered differently is
    /// marked ambiguous in the same statement, so concurrent retries cannot
    /// leave a baseline the client does not hold.
    fn record_sync_delivery(
        &self,
        position_id: &str,
        delivered: &[(String, String)],
    ) -> Result<(), SyncError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        for (object_id, fingerprint) in delivered {
            tx.execute(
                "INSERT INTO sekai_sync_delivered (position_id, object_id, fingerprint)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (position_id, object_id) DO UPDATE SET fingerprint =
                     CASE WHEN sekai_sync_delivered.fingerprint = excluded.fingerprint
                          THEN excluded.fingerprint ELSE '?' END",
                params![position_id, object_id, fingerprint],
            )
            .map_err(storage)?;
        }
        tx.commit().map_err(storage)
    }

    /// Delete `positions`, their members and deliveries.
    fn delete_sync_positions(
        tx: &rusqlite::Transaction<'_>,
        positions: &[String],
    ) -> Result<(), SyncError> {
        for id in positions {
            for table in [
                "sekai_sync_members",
                "sekai_sync_delivered",
                "sekai_sync_positions",
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE position_id = ?1"),
                    params![id],
                )
                .map_err(storage)?;
            }
        }
        Ok(())
    }

    fn sync_position_ids(
        tx: &rusqlite::Transaction<'_>,
        sql: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<String>, SyncError> {
        let mut statement = tx.prepare(sql).map_err(storage)?;
        let ids = statement
            .query_map(args, |row| row.get::<_, String>(0))
            .map_err(storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage)?;
        Ok(ids)
    }

    fn prune_sync_before(&self, cursor: &str) -> Result<(), SyncError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let stale = Self::sync_position_ids(
            &tx,
            "SELECT position_id FROM sekai_sync_positions
             WHERE position_id <> ?1 AND (
                 position_id = (SELECT origin_id FROM sekai_sync_positions WHERE position_id = ?1)
                 OR origin_id = (SELECT origin_id FROM sekai_sync_positions WHERE position_id = ?1))",
            &[&cursor],
        )?;
        Self::delete_sync_positions(&tx, &stale)?;
        tx.commit().map_err(storage)
    }
}

fn self_get(
    conn: &rusqlite::Connection,
    namespace: &str,
    owner: &str,
    scope_id: &str,
) -> Result<Option<SyncScope>, SyncError> {
    let row = conn
        .query_row(
            "SELECT definition, updated_at_ms FROM sekai_sync_scopes
             WHERE namespace = ?1 AND owner = ?2 AND scope_id = ?3",
            params![namespace, owner, scope_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(storage)?;
    row.map(|(definition, updated_at_ms)| {
        Ok(SyncScope {
            namespace: namespace.to_string(),
            owner: owner.to_string(),
            scope_id: scope_id.to_string(),
            definition: parse_definition(&definition)?,
            updated_at_ms,
        })
    })
    .transpose()
}

impl RuntimeDb {
    /// Store a scope. Changing its definition drops its cursors.
    pub fn put_sync_scope(&self, scope: &SyncScope) -> Result<SyncScope, SyncError> {
        match self {
            Self::Sqlite(db) => db.put_sync_scope(scope),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_sync_scope(scope)),
        }
    }

    pub fn get_sync_scope(
        &self,
        namespace: &str,
        owner: &str,
        scope_id: &str,
    ) -> Result<Option<SyncScope>, SyncError> {
        match self {
            Self::Sqlite(db) => db.get_sync_scope(namespace, owner, scope_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_sync_scope(namespace, owner, scope_id))
            }
        }
    }

    /// Store a position with its members; storing it again is a no-op.
    /// With `retire_others`, every other position of the scope goes in the
    /// same transaction (a new snapshot).
    pub fn save_sync_position(
        &self,
        position: &SyncPosition,
        retire_others: bool,
        now_ms: i64,
    ) -> Result<(), SyncError> {
        match self {
            Self::Sqlite(db) => db.save_sync_position(position, retire_others, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.save_sync_position(position, retire_others, now_ms)
            }),
        }
    }

    pub fn get_sync_position(&self, position_id: &str) -> Result<Option<SyncPosition>, SyncError> {
        match self {
            Self::Sqlite(db) => db.get_sync_position(position_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_sync_position(position_id))
            }
        }
    }

    /// Record the successor of `position_id` unless one is recorded. Returns
    /// the recorded successor, `None` when the position is gone.
    pub fn set_sync_successor(
        &self,
        position_id: &str,
        successor_id: &str,
    ) -> Result<Option<String>, SyncError> {
        match self {
            Self::Sqlite(db) => db.set_sync_successor(position_id, successor_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_sync_successor(position_id, successor_id)
            }),
        }
    }

    /// Record what a response ending at `position_id` delivered.
    pub fn record_sync_delivery(
        &self,
        position_id: &str,
        delivered: &[(String, String)],
    ) -> Result<(), SyncError> {
        match self {
            Self::Sqlite(db) => db.record_sync_delivery(position_id, delivered),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.record_sync_delivery(position_id, delivered))
            }
        }
    }

    /// The client read from `cursor`, so it holds that answer: drop the
    /// cursor it came from and that cursor's other answers. Never touches
    /// anything newer.
    pub fn prune_sync_before(&self, cursor: &str) -> Result<(), SyncError> {
        match self {
            Self::Sqlite(db) => db.prune_sync_before(cursor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.prune_sync_before(cursor)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disagreeing_deliveries_become_ambiguous() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let position = SyncPosition {
            position_id: "pos-1".into(),
            namespace: "ns".into(),
            owner: "alice".into(),
            scope_id: "s".into(),
            authorization_pin: "pin".into(),
            members: vec![Member {
                object_id: "a".into(),
                fingerprint: "f1".into(),
            }],
            successor: None,
            origin: None,
            delivered: Default::default(),
        };
        db.save_sync_position(&position, true, 1).unwrap();
        let deliver = |fingerprint: &str| {
            db.record_sync_delivery("pos-1", &[("a".into(), fingerprint.into())])
                .unwrap()
        };
        deliver("f2");
        deliver("f2");
        assert_eq!(
            db.get_sync_position("pos-1").unwrap().unwrap().delivered["a"],
            "f2"
        );
        deliver("f3");
        let stored = db.get_sync_position("pos-1").unwrap().unwrap();
        assert_eq!(stored.delivered["a"], crate::sekai::sync_scope::AMBIGUOUS);
        assert_eq!(
            stored.baseline()[0].fingerprint,
            crate::sekai::sync_scope::AMBIGUOUS
        );
    }
}

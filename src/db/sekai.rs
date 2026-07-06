use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use uuid::Uuid;

use crate::domain::{
    Direction, Link, ListFilter, MAX_LIST_LIMIT, Object, ObjectSet, PropertyFilter,
    is_valid_property_key,
};

pub struct SekaiDb {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct PrincipalCredential {
    pub id: String,
    pub principal: String,
    pub token_hash: String,
    pub status: String,
    pub created: i64,
    pub rotated_at: i64,
    pub revoked_at: i64,
}

impl SekaiDb {
    pub fn new(path: &str) -> Result<Self, String> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory().map_err(|e| e.to_string())?
        } else {
            std::fs::create_dir_all(
                std::path::Path::new(path)
                    .parent()
                    .unwrap_or(std::path::Path::new(".")),
            )
            .ok();
            Connection::open(path).map_err(|e| e.to_string())?
        };
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        if path != ":memory:" {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(|e| e.to_string())?;
        }
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate_all()?;
        db.register_sql_helpers()?;
        Ok(db)
    }

    pub(crate) fn conn(&self) -> MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(conn) => conn,
            Err(poisoned) => {
                crate::obs::metrics::record_db_lock_poisoned();
                tracing::error!(
                    "database connection lock was poisoned; recovering inner connection"
                );
                poisoned.into_inner()
            }
        }
    }

    pub fn db_lock_poisoned_total(&self) -> u64 {
        crate::obs::metrics::db_lock_poisoned_total()
    }

    pub(crate) fn migrate_all(&self) -> Result<(), String> {
        self.migrate()?;
        self.migrate_grants()?;
        self.migrate_principal_credentials()?;
        self.migrate_audit()?;
        self.migrate_task_observations()?;
        self.migrate_schema_types()?;
        self.migrate_coordination()?;
        self.migrate_datasets()?;
        self.migrate_functions()?;
        self.migrate_chisei()?;
        self.migrate_action_types()?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_objects (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT '',
                external_id TEXT NOT NULL DEFAULT '',
                properties TEXT NOT NULL DEFAULT '{}',
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_objects_kind ON sekai_objects(kind);
            CREATE INDEX IF NOT EXISTS idx_objects_external_id ON sekai_objects(external_id);
            CREATE TABLE IF NOT EXISTS sekai_links (
                id TEXT PRIMARY KEY,
                from_id TEXT NOT NULL,
                to_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_links_from ON sekai_links(from_id, relation);
            CREATE INDEX IF NOT EXISTS idx_links_to ON sekai_links(to_id, relation);
            CREATE TABLE IF NOT EXISTS sekai_object_sets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                filter TEXT NOT NULL,
                owner_principal TEXT NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_object_sets_owner_name ON sekai_object_sets(owner_principal, name);",
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn register_sql_helpers(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.create_scalar_function(
            "is_numeric_text",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let value: Option<String> = ctx.get(0).ok();
                Ok(value
                    .as_deref()
                    .and_then(|v| v.trim().parse::<f64>().ok())
                    .map(|v| v.is_finite())
                    .unwrap_or(false))
            },
        )
        .map_err(|e| e.to_string())
    }

    pub(crate) fn migrate_principal_credentials(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_principal_credentials (
                id TEXT PRIMARY KEY,
                principal TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                created INTEGER NOT NULL,
                rotated_at INTEGER NOT NULL DEFAULT 0,
                revoked_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_principal_credentials_token_hash ON sekai_principal_credentials(token_hash);
            CREATE INDEX IF NOT EXISTS idx_sekai_principal_credentials_principal ON sekai_principal_credentials(principal);",
        )
        .map_err(|e| e.to_string())
    }

    pub fn ping(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.query_row("SELECT 1", [], |_| Ok(()))
            .map_err(|e| e.to_string())
    }

    pub fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id, principal, token_hash, status, created, rotated_at, revoked_at FROM sekai_principal_credentials WHERE token_hash = ?1 AND status = 'active' ORDER BY created DESC LIMIT 1",
            params![token_hash],
            row_to_principal_credential,
        )
        .optional()
        .map_err(|error| error.to_string())
    }

    pub fn principal_credentials_activity_epoch(&self) -> Result<i64, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT COALESCE(MAX(value), 0) FROM (
                SELECT COALESCE(created, 0) AS value FROM sekai_principal_credentials
                UNION ALL
                SELECT COALESCE(rotated_at, 0) AS value FROM sekai_principal_credentials
                UNION ALL
                SELECT COALESCE(revoked_at, 0) AS value FROM sekai_principal_credentials
            )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())
    }

    pub fn create_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<PrincipalCredential, String> {
        let id = format!("credential-{}", Uuid::new_v4().simple());
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_principal_credentials (id, principal, token_hash, status, created, rotated_at, revoked_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id,
                principal,
                token_hash,
                "active",
                now,
                now,
                0_i64,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(PrincipalCredential {
            id,
            principal: principal.to_string(),
            token_hash: token_hash.to_string(),
            status: "active".to_string(),
            created: now,
            rotated_at: now,
            revoked_at: 0,
        })
    }

    pub fn rotate_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
    ) -> Result<PrincipalCredential, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;

        let mut active_stmt = tx
            .prepare(
                "SELECT id FROM sekai_principal_credentials WHERE principal = ?1 AND status = 'active' ORDER BY created DESC LIMIT 1",
            )
            .map_err(|e| e.to_string())?;
        let active_id = active_stmt
            .query_row(params![principal], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|e| e.to_string())?;
        drop(active_stmt);
        if let Some(active) = &active_id {
            tx.execute(
                "UPDATE sekai_principal_credentials SET status='revoked', revoked_at=?1 WHERE id=?2",
                params![now, active],
            )
            .map_err(|e| e.to_string())?;
        }
        let id = format!("credential-{}", Uuid::new_v4().simple());
        tx.execute(
            "INSERT INTO sekai_principal_credentials (id, principal, token_hash, status, created, rotated_at, revoked_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id,
                principal,
                token_hash,
                "active",
                now,
                now,
                0_i64
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(PrincipalCredential {
            id,
            principal: principal.to_string(),
            token_hash: token_hash.to_string(),
            status: "active".to_string(),
            created: now,
            rotated_at: now,
            revoked_at: 0,
        })
    }

    pub fn revoke_principal_credential(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, principal, token_hash, status, created, rotated_at, revoked_at FROM sekai_principal_credentials WHERE principal = ?1 AND status = 'active' ORDER BY created DESC LIMIT 1",
            )
            .map_err(|e| e.to_string())?;
        let credential: Option<PrincipalCredential> = stmt
            .query_row(params![principal], row_to_principal_credential)
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(credential) = &credential {
            conn.execute(
                "UPDATE sekai_principal_credentials SET status='revoked', revoked_at=?1 WHERE id=?2",
                params![now, credential.id],
            )
            .map_err(|e| e.to_string())?;
            let revoked = PrincipalCredential {
                status: "revoked".to_string(),
                revoked_at: now,
                ..credential.clone()
            };
            return Ok(Some(revoked));
        }
        Ok(None)
    }

    pub fn list_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        let conn = self.conn();
        let mut sql = "SELECT id, principal, token_hash, status, created, rotated_at, revoked_at FROM sekai_principal_credentials WHERE 1=1".to_string();
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(principal) = principal {
            sql.push_str(&format!(" AND principal = ?{}", args.len() + 1));
            args.push(Box::new(principal.to_string()));
        }
        if let Some(status) = status {
            sql.push_str(&format!(" AND status = ?{}", args.len() + 1));
            args.push(Box::new(status.to_string()));
        }
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            args.iter().map(|arg| arg.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_principal_credential)
            .map_err(|e| e.to_string())?;
        let parsed: Result<Vec<_>, rusqlite::Error> = rows.collect();
        parsed.map_err(|e| e.to_string())
    }

    pub fn list_active_credentials(&self) -> Result<Vec<PrincipalCredential>, String> {
        self.list_credentials(None, Some("active"))
    }

    pub fn create_object(&self, o: &Object) -> Result<(), String> {
        let conn = self.conn();
        let props = serde_json::to_string(&o.properties).unwrap_or_default();
        conn.execute(
            "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![o.id, o.kind, o.name, o.namespace, o.external_id, props, o.created, o.updated],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
            params![id],
            row_to_object,
        ).optional().map_err(|e| e.to_string())
    }

    pub fn update_object(&self, o: &Object) -> Result<(), String> {
        if self.update_object_with_existing(o)?.is_none() {
            return Err("not found".into());
        }
        Ok(())
    }

    pub fn update_object_with_existing(&self, o: &Object) -> Result<Option<Object>, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let before = tx
            .query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
                params![o.id],
                row_to_object,
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if before.is_none() {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(None);
        }
        let props = serde_json::to_string(&o.properties).unwrap_or_default();
        tx.execute(
            "UPDATE sekai_objects SET kind=?2, name=?3, namespace=?4, external_id=?5, properties=?6, updated=?7 WHERE id=?1",
            params![o.id, o.kind, o.name, o.namespace, o.external_id, props, o.updated],
        ).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(before)
    }

    pub fn delete_object(&self, id: &str) -> Result<(), String> {
        self.delete_object_with_existing(id)?;
        Ok(())
    }

    pub fn delete_object_with_existing(&self, id: &str) -> Result<Option<Object>, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let before = tx
            .query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
                params![id],
                row_to_object,
            )
            .optional()
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM sekai_objects WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM sekai_links WHERE from_id = ?1 OR to_id = ?1",
            params![id],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(before)
    }

    pub fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        let mut effective_filter = filter.clone();
        if effective_filter.limit <= 0 {
            effective_filter.limit = MAX_LIST_LIMIT;
        }
        if effective_filter.offset < 0 {
            effective_filter.offset = 0;
        }
        self.list_objects_with_total(&effective_filter)
            .map(|(objects, _)| objects)
    }

    pub fn list_all_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        let mut effective_filter = filter.clone();
        effective_filter.limit = i32::MAX;
        self.list_objects_with_total(&effective_filter)
            .map(|(objects, _)| objects)
    }

    pub fn list_objects_with_total(
        &self,
        filter: &ListFilter,
    ) -> Result<(Vec<Object>, i32), String> {
        let mut query = build_list_query(filter).map_err(|e| e.to_string())?;
        let base_param_count = query.where_param_count;
        let order_sql = build_order_by_sql(
            filter.order_by.as_str(),
            filter.descending,
            &mut query.params,
        )?;
        let effective_limit = if filter.limit == i32::MAX {
            i32::MAX
        } else if filter.limit <= 0 {
            MAX_LIST_LIMIT
        } else {
            filter.limit.min(MAX_LIST_LIMIT)
        };
        let conn = self.conn();
        let mut list_sql = format!(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects{}",
            query.where_sql
        );
        if let Some(order_sql) = order_sql.as_deref() {
            list_sql.push_str(order_sql);
        }
        list_sql.push_str(&format!(
            " LIMIT ?{} OFFSET ?{}",
            query.params.len() + 1,
            query.params.len() + 2
        ));
        query.params.push(Box::new(effective_limit));
        query.params.push(Box::new(filter.offset.max(0)));
        let mut stmt = conn.prepare(&list_sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                query
                    .params
                    .iter()
                    .map(|v| v.as_ref())
                    .collect::<Vec<&dyn rusqlite::types::ToSql>>()
                    .as_slice(),
                row_to_object,
            )
            .map_err(|e| e.to_string())?;
        let objects: Vec<Object> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let total = conn
            .query_row(
                &query.count_sql,
                query
                    .params
                    .iter()
                    .take(base_param_count)
                    .map(|v| v.as_ref())
                    .collect::<Vec<&dyn rusqlite::types::ToSql>>()
                    .as_slice(),
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| e.to_string())?;
        Ok((objects, total.min(i32::MAX as i64) as i32))
    }

    pub fn list_objects_with_total_for_principals(
        &self,
        filter: &ListFilter,
        principals: &[&str],
    ) -> Result<(Vec<Object>, i32), String> {
        let mut query = build_list_query(filter).map_err(|e| e.to_string())?;
        // Keep visibility params and order-by params disjoint to avoid placeholder
        // number collision for both list and count queries.
        let (visibility_filter, mut visibility_params) =
            build_visibility_filter(principals, query.params.len());
        query.params.append(&mut visibility_params);
        let order_sql = build_order_by_sql(
            filter.order_by.as_str(),
            filter.descending,
            &mut query.params,
        )?;
        let (count_visibility_filter, count_visibility_params) =
            build_visibility_filter_for_count_query(principals, query.where_param_count);
        let effective_limit = if filter.limit == i32::MAX {
            i32::MAX
        } else if filter.limit <= 0 {
            MAX_LIST_LIMIT
        } else {
            filter.limit.min(MAX_LIST_LIMIT)
        };
        let mut list_sql = format!(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects{}{}",
            query.where_sql, visibility_filter
        );
        if let Some(order_sql) = order_sql.as_deref() {
            list_sql.push_str(order_sql);
        }
        list_sql.push_str(&format!(
            " LIMIT ?{} OFFSET ?{}",
            query.params.len() + 1,
            query.params.len() + 2
        ));
        query.params.push(Box::new(effective_limit));
        query.params.push(Box::new(filter.offset.max(0)));
        let conn = self.conn();
        let mut stmt = conn.prepare(&list_sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                query
                    .params
                    .iter()
                    .map(|v| v.as_ref())
                    .collect::<Vec<&dyn rusqlite::types::ToSql>>()
                    .as_slice(),
                row_to_object,
            )
            .map_err(|e| e.to_string())?;
        let objects: Vec<Object> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let mut count_params: Vec<&dyn rusqlite::types::ToSql> = query
            .params
            .iter()
            .take(query.where_param_count)
            .map(|v| v.as_ref())
            .collect();
        count_params.extend(
            count_visibility_params
                .iter()
                .map(|v| v.as_ref() as &dyn rusqlite::types::ToSql),
        );
        let total = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM sekai_objects{}{}",
                    query.where_sql, count_visibility_filter
                ),
                count_params.as_slice(),
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| e.to_string())?;
        Ok((objects, total.min(i32::MAX as i64) as i32))
    }

    pub fn create_object_set(&self, set: &ObjectSet) -> Result<(), String> {
        let conn = self.conn();
        let filter = serde_json::to_string(&set.filter).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO sekai_object_sets (id, name, description, filter, owner_principal, created) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                set.id,
                set.name,
                set.description,
                filter,
                set.owner_principal,
                set.created,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_object_set(&self, id: &str) -> Result<Option<ObjectSet>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id, name, description, filter, owner_principal, created FROM sekai_object_sets WHERE id = ?1",
            params![id],
            |row| {
                let filter_json: String = row.get(3)?;
                let filter = serde_json::from_str::<ListFilter>(&filter_json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(ObjectSet {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    filter,
                    owner_principal: row.get(4)?,
                    created: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_object_sets(&self) -> Result<Vec<ObjectSet>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, name, description, filter, owner_principal, created FROM sekai_object_sets ORDER BY created, id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let filter_json: String = row.get(3)?;
                let filter = serde_json::from_str::<ListFilter>(&filter_json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(ObjectSet {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    filter,
                    owner_principal: row.get(4)?,
                    created: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let parsed: Result<Vec<_>, rusqlite::Error> = rows.collect();
        parsed.map_err(|e| e.to_string())
    }

    pub fn list_object_sets_for_principals(
        &self,
        principals: &[&str],
    ) -> Result<Vec<ObjectSet>, String> {
        if principals.is_empty() {
            return Ok(Vec::new());
        }
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let placeholders = principals
            .iter()
            .map(|principal| {
                let idx = params.len() + 1;
                params.push(Box::new((*principal).to_string()));
                format!("?{idx}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let conn = self.conn();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT id, name, description, filter, owner_principal, created FROM sekai_object_sets WHERE owner_principal IN ({placeholders}) ORDER BY created, id"
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params
                    .iter()
                    .map(|p| p.as_ref() as &dyn rusqlite::types::ToSql)
                    .collect::<Vec<_>>()
                    .as_slice(),
                |row| {
                    let filter_json: String = row.get(3)?;
                    let filter = serde_json::from_str::<ListFilter>(&filter_json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    Ok(ObjectSet {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        description: row.get(2)?,
                        filter,
                        owner_principal: row.get(4)?,
                        created: row.get(5)?,
                    })
                },
            )
            .map_err(|e| e.to_string())?;
        let parsed: Result<Vec<_>, rusqlite::Error> = rows.collect();
        parsed.map_err(|e| e.to_string())
    }

    pub fn delete_object_set(&self, id: &str) -> Result<bool, String> {
        let conn = self.conn();
        let removed = conn
            .execute("DELETE FROM sekai_object_sets WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(removed > 0)
    }

    pub fn delete_object_set_for_principals(
        &self,
        id: &str,
        principals: &[&str],
    ) -> Result<bool, String> {
        if principals.is_empty() {
            return Ok(false);
        }
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        params.push(Box::new(id.to_string()));
        let mut owner_placeholders = Vec::new();
        for principal in principals {
            let idx = params.len() + 1;
            params.push(Box::new((*principal).to_string()));
            owner_placeholders.push(format!("?{idx}"));
        }
        let owner_placeholders = owner_placeholders.join(",");
        let conn = self.conn();
        let removed = conn
            .execute(
                &format!(
                    "DELETE FROM sekai_object_sets WHERE id = ?1 AND owner_principal IN ({owner_placeholders})"
                ),
                params
                    .iter()
                    .map(|p| p.as_ref() as &dyn rusqlite::types::ToSql)
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .map_err(|e| e.to_string())?;
        Ok(removed > 0)
    }

    pub fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE external_id = ?1",
            params![external_id],
            row_to_object,
        ).optional().map_err(|e| e.to_string())
    }

    pub fn find_by_property(
        &self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>, String> {
        if key.is_empty() || !key.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err("invalid property key".into());
        }
        let conn = self.conn();
        let json_path = format!("$.{}", key);
        let mut stmt = conn.prepare(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE kind = ?1 AND json_extract(properties, ?2) = ?3"
        ).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![kind, json_path, value], row_to_object)
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn create_link(&self, l: &Link) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR IGNORE INTO sekai_links (id, from_id, to_id, relation, created) VALUES (?1,?2,?3,?4,?5)",
            params![l.id, l.from_id, l.to_id, l.relation, l.created],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_link(&self, id: &str) -> Result<(), String> {
        let conn = self.conn();
        conn.execute("DELETE FROM sekai_links WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_link(&self, id: &str) -> Result<Option<Link>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id, from_id, to_id, relation, created FROM sekai_links WHERE id = ?1",
            params![id],
            |row| {
                Ok(Link {
                    id: row.get(0)?,
                    from_id: row.get(1)?,
                    to_id: row.get(2)?,
                    relation: row.get(3)?,
                    created: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn get_links(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
    ) -> Result<Vec<Link>, String> {
        let conn = self.conn();
        let col = match dir {
            Direction::Outgoing => "from_id",
            Direction::Incoming => "to_id",
        };
        let sql = if relation.is_empty() {
            format!(
                "SELECT id, from_id, to_id, relation, created FROM sekai_links WHERE {} = ?1",
                col
            )
        } else {
            format!(
                "SELECT id, from_id, to_id, relation, created FROM sekai_links WHERE {} = ?1 AND relation = ?2",
                col
            )
        };
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut rows = if relation.is_empty() {
            stmt.query(params![object_id]).map_err(|e| e.to_string())?
        } else {
            stmt.query(params![object_id, relation])
                .map_err(|e| e.to_string())?
        };
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            results.push(row_to_link(row).map_err(|e| e.to_string())?);
        }
        Ok(results)
    }

    pub fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
    ) -> Result<Vec<Object>, String> {
        let links = self.get_links(object_id, relation, dir)?;
        let mut objects = Vec::new();
        for link in &links {
            let target_id = match dir {
                Direction::Outgoing => &link.to_id,
                Direction::Incoming => &link.from_id,
            };
            if let Ok(Some(obj)) = self.get_object(target_id) {
                objects.push(obj);
            }
        }
        Ok(objects)
    }
}

pub(crate) fn row_to_object(row: &rusqlite::Row) -> rusqlite::Result<Object> {
    let props_str: String = row.get(5)?;
    let properties: HashMap<String, String> = serde_json::from_str(&props_str).unwrap_or_default();
    Ok(Object {
        id: row.get(0)?,
        kind: row.get(1)?,
        name: row.get(2)?,
        namespace: row.get(3)?,
        external_id: row.get(4)?,
        properties,
        created: row.get(6)?,
        updated: row.get(7)?,
    })
}

struct ListQueryParts {
    where_sql: String,
    params: Vec<Box<dyn rusqlite::types::ToSql>>,
    count_sql: String,
    where_param_count: usize,
}

fn build_list_query(filter: &ListFilter) -> Result<ListQueryParts, String> {
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut where_parts: Vec<String> = Vec::new();

    if let Some(kind) = &filter.kind {
        where_parts.push(format!("kind = ?{}", params.len() + 1));
        params.push(Box::new(kind.clone()));
    }
    if let Some(name) = &filter.name {
        where_parts.push(format!("name = ?{}", params.len() + 1));
        params.push(Box::new(name.clone()));
    }
    if let Some(namespace) = &filter.namespace {
        where_parts.push(format!("namespace = ?{}", params.len() + 1));
        params.push(Box::new(namespace.clone()));
    }

    for property_filter in &filter.property_filters {
        let condition = build_property_filter_condition(property_filter, &mut params)?;
        where_parts.push(condition);
    }

    for interface_name in &filter.interface_filter {
        where_parts.push(format!(
            "EXISTS (
                SELECT 1 FROM sekai_object_types
                WHERE sekai_object_types.kind = sekai_objects.kind
                  AND EXISTS (
                    SELECT 1 FROM json_each(sekai_object_types.implements_json)
                    WHERE json_each.value = ?{}
                  )
            )",
            params.len() + 1
        ));
        params.push(Box::new(interface_name.clone()));
    }

    let where_sql = if where_parts.is_empty() {
        " WHERE 1 = 1".to_string()
    } else {
        format!(" WHERE {}", where_parts.join(" AND "))
    };
    let where_param_count = params.len();

    let count_sql = format!("SELECT COUNT(*) FROM sekai_objects{}", where_sql);

    Ok(ListQueryParts {
        where_sql,
        params,
        count_sql,
        where_param_count,
    })
}

fn build_visibility_filter(
    principals: &[&str],
    start_param: usize,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    build_visibility_filter_internal(principals, start_param)
}

fn build_visibility_filter_for_count_query(
    principals: &[&str],
    start_param: usize,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    build_visibility_filter_internal(principals, start_param)
}

fn build_visibility_filter_internal(
    principals: &[&str],
    start_param: usize,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let effective_principals: Vec<&str> = principals
        .iter()
        .copied()
        .filter(|principal| !principal.is_empty() && principal != &"anonymous")
        .collect();
    if effective_principals.is_empty() {
        return (
            " AND NOT EXISTS (SELECT 1 FROM sekai_grants WHERE object_id = sekai_objects.id)"
                .to_string(),
            Vec::new(),
        );
    }

    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let principal_placeholders = effective_principals
        .iter()
        .enumerate()
        .map(|(idx, principal)| {
            let param_idx = start_param + idx + 1;
            params.push(Box::new((*principal).to_string()));
            format!("?{param_idx}")
        })
        .collect::<Vec<_>>()
        .join(",");

    (
        format!(
            " AND (NOT EXISTS (SELECT 1 FROM sekai_grants WHERE object_id = sekai_objects.id) OR EXISTS (SELECT 1 FROM sekai_grants WHERE object_id = sekai_objects.id AND principal IN ({})))",
            principal_placeholders
        ),
        params,
    )
}

fn build_property_filter_condition(
    filter: &PropertyFilter,
    params: &mut Vec<Box<dyn rusqlite::types::ToSql>>,
) -> Result<String, String> {
    if !is_valid_property_key(&filter.key) {
        return Err("invalid property key".into());
    }

    let op = filter.op.to_lowercase();
    let path = format!("$.{}", filter.key);
    let mut make_path_expr = || {
        let path_param = format!("?{}", params.len() + 1);
        params.push(Box::new(path.clone()));
        format!("json_extract(properties, {path_param})")
    };

    match op.as_str() {
        "eq" => {
            let path_expr = make_path_expr();
            let value_param = format!("?{}", params.len() + 1);
            params.push(Box::new(filter.value.clone()));
            Ok(format!("{path_expr} = {value_param}"))
        }
        "ne" | "neq" => {
            let path_expr = make_path_expr();
            let value_param = format!("?{}", params.len() + 1);
            params.push(Box::new(filter.value.clone()));
            // ne/neq intentionally match only objects with an explicit property value and
            // do not include rows where the JSON path resolves to NULL.
            Ok(format!("{path_expr} != {value_param}"))
        }
        "contains" => {
            let path_expr = make_path_expr();
            let value_param = format!("?{}", params.len() + 1);
            params.push(Box::new(format!(
                "%{}%",
                escape_like_pattern(&filter.value)
            )));
            Ok(format!("{path_expr} LIKE {value_param} ESCAPE '\\'"))
        }
        "prefix" => {
            let path_expr = make_path_expr();
            let value_param = format!("?{}", params.len() + 1);
            params.push(Box::new(format!("{}%", escape_like_pattern(&filter.value))));
            Ok(format!("{path_expr} LIKE {value_param} ESCAPE '\\'"))
        }
        "in" => {
            let values: Vec<&str> = filter
                .value
                .split(',')
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .collect();
            if values.is_empty() {
                return Ok("0 = 1".into());
            }
            let path_expr = make_path_expr();
            let mut in_parts = Vec::new();
            for value in values {
                let value_param = format!("?{}", params.len() + 1);
                in_parts.push(value_param);
                params.push(Box::new(value.to_string()));
            }
            Ok(format!(
                "{path_expr} IN ({})",
                in_parts.into_iter().collect::<Vec<_>>().join(",")
            ))
        }
        "gt" | "gte" | "lt" | "lte" => {
            let path_expr = make_path_expr();
            let value_param = format!("?{}", params.len() + 1);
            let compare = match op.as_str() {
                "gt" => ">",
                "gte" => ">=",
                "lt" => "<",
                "lte" => "<=",
                _ => unreachable!(),
            };
            params.push(Box::new(filter.value.clone()));
            Ok(build_numeric_or_text_expr(
                &path_expr,
                &value_param,
                compare,
            ))
        }
        _ => Err(format!("unsupported property operator: {}", filter.op)),
    }
}

fn escape_like_pattern(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn build_numeric_or_text_expr(left_expr: &str, value_param: &str, compare: &str) -> String {
    format!(
        "((is_numeric_text({left_expr}) AND is_numeric_text({value_param}) AND CAST({left_expr} AS REAL) {compare} CAST({value_param} AS REAL)) OR ((NOT is_numeric_text({left_expr}) OR NOT is_numeric_text({value_param})) AND {left_expr} {compare} {value_param}))"
    )
}

fn build_order_by_sql(
    order_by: &str,
    descending: bool,
    params: &mut Vec<Box<dyn rusqlite::types::ToSql>>,
) -> Result<Option<String>, String> {
    if order_by.is_empty() {
        return Ok(Some(" ORDER BY id ASC".to_string()));
    }
    let direction = if descending { "DESC" } else { "ASC" };
    let order_sql = match order_by {
        "name" => {
            format!(" ORDER BY name {direction}, id ASC")
        }
        "created" => {
            format!(" ORDER BY created {direction}, id ASC")
        }
        "updated" => {
            format!(" ORDER BY updated {direction}, id ASC")
        }
        _ => {
            if let Some(key) = order_by.strip_prefix("property:") {
                if !is_valid_property_key(key) {
                    return Err(format!("invalid property key: {key}"));
                }
                let path = format!("$.{key}");
                let path_expr = format!("?{}", params.len() + 1);
                params.push(Box::new(path));
                let value_expr = format!("json_extract(properties, {path_expr})");
                format!(
                    " ORDER BY CASE WHEN {value_expr} IS NULL THEN 1 ELSE 0 END, CASE WHEN is_numeric_text({value_expr}) THEN 0 ELSE 1 END, CASE WHEN is_numeric_text({value_expr}) THEN CAST({value_expr} AS REAL) ELSE CAST(NULL AS REAL) END {direction}, CASE WHEN is_numeric_text({value_expr}) THEN '' ELSE {value_expr} END {direction}, id ASC"
                )
            } else {
                return Err(format!("unsupported order_by: {order_by}"));
            }
        }
    };
    Ok(Some(order_sql))
}

fn row_to_principal_credential(
    row: &rusqlite::Row,
) -> Result<PrincipalCredential, rusqlite::Error> {
    Ok(PrincipalCredential {
        id: row.get(0)?,
        principal: row.get(1)?,
        token_hash: row.get(2)?,
        status: row.get(3)?,
        created: row.get(4)?,
        rotated_at: row.get(5)?,
        revoked_at: row.get(6)?,
    })
}

fn row_to_link(row: &rusqlite::Row) -> rusqlite::Result<Link> {
    Ok(Link {
        id: row.get(0)?,
        from_id: row.get(1)?,
        to_id: row.get(2)?,
        relation: row.get(3)?,
        created: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::security;
    use std::path::PathBuf;

    fn test_db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn temp_db_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sekai-chisei-{name}-{}-{}.db",
            std::process::id(),
            Uuid::new_v4().simple()
        ))
    }

    fn table_columns(db: &SekaiDb, table: &str) -> Vec<String> {
        let conn = db.conn();
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn migrate_all_upgrades_previous_schema_fixture() {
        let path = temp_db_path("upgrade");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sekai_work_units (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    target_object_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    requested_spec TEXT NOT NULL DEFAULT '',
                    scope_id TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    timeout_seconds INTEGER NOT NULL DEFAULT 0,
                    heartbeat_ttl_seconds INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    admitted_at INTEGER NOT NULL DEFAULT 0,
                    started_at INTEGER NOT NULL DEFAULT 0,
                    finished_at INTEGER NOT NULL DEFAULT 0,
                    last_heartbeat_at INTEGER NOT NULL DEFAULT 0,
                    failure_reason TEXT NOT NULL DEFAULT '',
                    cancel_reason TEXT NOT NULL DEFAULT '',
                    owner_principal TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE chisei_eval_iterations (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    suite_id TEXT NOT NULL,
                    changed_file TEXT NOT NULL,
                    diff_hash TEXT NOT NULL,
                    parent_iteration_id TEXT NOT NULL,
                    baseline_run_id TEXT NOT NULL,
                    candidate_run_id TEXT NOT NULL,
                    delta REAL NOT NULL,
                    regressed INTEGER NOT NULL,
                    created INTEGER NOT NULL
                );
                CREATE TABLE chisei_sample_observations (
                    request_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL DEFAULT '',
                    spec TEXT NOT NULL DEFAULT '',
                    resolved_model TEXT NOT NULL DEFAULT '',
                    output_content TEXT NOT NULL DEFAULT '',
                    sample_reason TEXT NOT NULL DEFAULT '',
                    input_tokens INTEGER NOT NULL DEFAULT 0,
                    output_tokens INTEGER NOT NULL DEFAULT 0,
                    stop_reason TEXT NOT NULL DEFAULT '',
                    timestamp INTEGER NOT NULL,
                    scored INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE sekai_task_observations (
                    request_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    model TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    packages_json TEXT NOT NULL DEFAULT '[]',
                    context_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (request_id, component_id)
                );
                CREATE TABLE sekai_task_observation_baselines (
                    component_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    task_total INTEGER NOT NULL,
                    task_succeeded INTEGER NOT NULL,
                    consecutive_failures INTEGER NOT NULL,
                    created INTEGER NOT NULL
                );",
            )
            .unwrap();
        }

        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        db.migrate_all().unwrap();

        let work_unit_columns = table_columns(&db, "sekai_work_units");
        assert!(work_unit_columns.contains(&"creator_principal".to_string()));
        assert!(work_unit_columns.contains(&"idempotency_key".to_string()));
        assert!(work_unit_columns.contains(&"updated_at".to_string()));

        let iteration_columns = table_columns(&db, "chisei_eval_iterations");
        assert!(iteration_columns.contains(&"namespace".to_string()));

        let observation_columns = table_columns(&db, "chisei_sample_observations");
        assert!(observation_columns.contains(&"attempts".to_string()));

        let task_observation_columns = table_columns(&db, "sekai_task_observations");
        assert!(task_observation_columns.contains(&"component_id".to_string()));

        let baseline_columns = table_columns(&db, "sekai_task_observation_baselines");
        assert!(baseline_columns.contains(&"task_succeeded".to_string()));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn new_fails_for_garbage_db_file() {
        let path = temp_db_path("garbage");
        std::fs::write(&path, b"not a sqlite database").unwrap();

        let err = match SekaiDb::new(path.to_str().unwrap()) {
            Ok(_) => panic!("garbage database unexpectedly opened"),
            Err(err) => err,
        };
        assert!(!err.trim().is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn file_database_uses_wal_and_five_second_busy_timeout() {
        let path = temp_db_path("wal");
        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();

        {
            let conn = db.conn();
            let journal_mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            let busy_timeout_ms: i64 = conn
                .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
                .unwrap();
            assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
            assert_eq!(busy_timeout_ms, 5000);
        }

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn make_obj(id: &str, kind: &str, name: &str) -> Object {
        Object {
            id: id.into(),
            kind: kind.into(),
            name: name.into(),
            namespace: "default".into(),
            external_id: format!("{}:{}", kind, name),
            properties: HashMap::new(),
            created: 1000,
            updated: 1000,
        }
    }

    fn make_obj_with_property(id: &str, kind: &str, name: &str, key: &str, value: &str) -> Object {
        let mut obj = make_obj(id, kind, name);
        obj.properties.insert(key.into(), value.into());
        obj
    }

    #[test]
    fn test_crud_object() {
        let db = test_db();
        let mut obj = make_obj("o1", "namespace", "my-namespace");
        obj.properties.insert("language".into(), "rust".into());
        db.create_object(&obj).unwrap();

        let got = db.get_object("o1").unwrap().unwrap();
        assert_eq!(got.name, "my-namespace");
        assert_eq!(got.properties["language"], "rust");

        obj.name = "renamed".into();
        obj.updated = 2000;
        db.update_object(&obj).unwrap();
        let got = db.get_object("o1").unwrap().unwrap();
        assert_eq!(got.name, "renamed");

        db.delete_object("o1").unwrap();
        assert!(db.get_object("o1").unwrap().is_none());
    }

    #[test]
    fn test_list_and_find() {
        let db = test_db();
        db.create_object(&make_obj("r1", "namespace", "alpha"))
            .unwrap();
        db.create_object(&make_obj("r2", "namespace", "beta"))
            .unwrap();
        db.create_object(&make_obj("c1", "component", "comp"))
            .unwrap();

        let all = db.list_objects(&ListFilter::default()).unwrap();
        assert_eq!(all.len(), 3);

        let namespaces = db
            .list_objects(&ListFilter {
                kind: Some("namespace".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(namespaces.len(), 2);

        let found = db.find_by_external_id("namespace:alpha").unwrap();
        assert_eq!(found.unwrap().id, "r1");
    }

    #[test]
    fn test_list_objects_filters_by_interface() {
        use crate::sekai::schema::{InterfaceDef, ObjectType, PropertyDef, PropertyType};

        let db = test_db();
        db.upsert_interface(&InterfaceDef {
            name: "RiskScored".into(),
            description: "Risk scored".into(),
            properties: vec![],
            is_builtin: false,
        })
        .unwrap();
        db.upsert_interface(&InterfaceDef {
            name: "Governed".into(),
            description: "Governed".into(),
            properties: vec![],
            is_builtin: false,
        })
        .unwrap();
        db.upsert_object_type(&ObjectType {
            kind: "model".into(),
            description: "Model".into(),
            properties: vec![PropertyDef {
                name: "risk_score".into(),
                prop_type: PropertyType::Float,
                required: false,
                description: String::new(),
                enum_values: vec![],
                link_kind: String::new(),
                compute_expr: String::new(),
                classification: crate::sekai::schema::default_property_classification(),
                struct_fields: vec![],
            }],
            is_builtin: false,
            implements: vec!["RiskScored".into(), "Governed".into()],
        })
        .unwrap();
        db.upsert_object_type(&ObjectType {
            kind: "component".into(),
            description: "Component".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec!["Governed".into()],
        })
        .unwrap();
        db.create_object(&make_obj("m1", "model", "model")).unwrap();
        db.create_object(&make_obj("c1", "component", "component"))
            .unwrap();

        let (objects, total) = db
            .list_objects_with_total(&ListFilter {
                interface_filter: vec!["RiskScored".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(objects[0].id, "m1");

        let (objects, total) = db
            .list_objects_with_total(&ListFilter {
                interface_filter: vec!["RiskScored".into(), "Governed".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(objects[0].id, "m1");
    }

    #[test]
    fn malformed_object_row_returns_error_without_poisoning_connection() {
        let db = test_db();
        db.create_object(&make_obj("good", "namespace", "good"))
            .unwrap();
        {
            let conn = db.conn();
            conn.execute(
                "INSERT INTO sekai_objects
                 (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    "bad",
                    "namespace",
                    "bad",
                    "default",
                    "namespace:bad",
                    "{}",
                    "not-an-integer",
                    1000_i64,
                ),
            )
            .unwrap();
        }

        assert!(db.get_object("bad").is_err());
        assert!(db.find_by_external_id("namespace:bad").is_err());

        let good = db.get_object("good").unwrap().unwrap();
        assert_eq!(good.id, "good");
    }

    #[test]
    fn poisoned_connection_lock_recovers_and_counts() {
        let db = test_db();
        let before = db.db_lock_poisoned_total();

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _conn = db.conn();
            panic!("poison connection lock for test");
        }));
        assert!(poisoned.is_err());

        db.ping().unwrap();
        assert!(db.db_lock_poisoned_total() > before);
        db.ping().unwrap();
    }

    #[test]
    fn list_objects_with_total_for_principals_orders_by_property_with_visibility_filter() {
        let db = test_db();
        db.create_object(&make_obj_with_property(
            "alice-only",
            "widget",
            "widget-alice",
            "tier",
            "20",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "bob-only",
            "widget",
            "widget-bob",
            "tier",
            "30",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "public",
            "widget",
            "widget-public",
            "tier",
            "10",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "no-tier",
            "widget",
            "widget-no-tier",
            "region",
            "us",
        ))
        .unwrap();

        db.create_grant(&security::Grant {
            id: format!("grant-{}", Uuid::new_v4().simple()),
            object_id: "alice-only".to_string(),
            principal: "alice".to_string(),
            role: security::Role::Viewer,
            created: 1,
        })
        .unwrap();
        db.create_grant(&security::Grant {
            id: format!("grant-{}", Uuid::new_v4().simple()),
            object_id: "bob-only".to_string(),
            principal: "bob".to_string(),
            role: security::Role::Viewer,
            created: 1,
        })
        .unwrap();

        let (ordered, total) = db
            .list_objects_with_total_for_principals(
                &ListFilter {
                    kind: Some("widget".into()),
                    order_by: "property:tier".into(),
                    ..Default::default()
                },
                &["alice"],
            )
            .unwrap();

        assert_eq!(total, 3);
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].id, "public");
        assert_eq!(ordered[1].id, "alice-only");
        assert_eq!(ordered[2].id, "no-tier");
    }

    #[test]
    fn test_links() {
        let db = test_db();
        db.create_object(&make_obj("r1", "namespace", "my-namespace"))
            .unwrap();
        db.create_object(&make_obj("c1", "component", "comp"))
            .unwrap();

        let link = Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: "contains".into(),
            created: 1000,
        };
        db.create_link(&link).unwrap();

        let links = db
            .get_links("r1", "contains", &Direction::Outgoing)
            .unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].to_id, "c1");

        let objs = db
            .get_linked_objects("r1", "contains", &Direction::Outgoing)
            .unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].name, "comp");

        let incoming = db
            .get_linked_objects("c1", "contains", &Direction::Incoming)
            .unwrap();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].name, "my-namespace");

        db.delete_link("l1").unwrap();
        let links = db
            .get_links("r1", "contains", &Direction::Outgoing)
            .unwrap();
        assert_eq!(links.len(), 0);
    }

    #[test]
    fn list_objects_with_property_filters_and_ordering() {
        let db = test_db();
        db.create_object(&make_obj_with_property(
            "a", "widget", "widget-a", "tier", "2",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "b", "widget", "widget-b", "tier", "10",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "c", "widget", "widget-c", "tier", "4",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "d", "widget", "widget-d", "region", "us",
        ))
        .unwrap();

        let matches = db
            .list_objects_with_total(&ListFilter {
                kind: Some("widget".into()),
                property_filters: vec![PropertyFilter {
                    key: "tier".into(),
                    op: "gt".into(),
                    value: "1".into(),
                }],
                order_by: "property:tier".into(),
                descending: false,
                ..Default::default()
            })
            .unwrap()
            .0;
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].id, "a");
        assert_eq!(matches[1].id, "c");
        assert_eq!(matches[2].id, "b");

        let matches_desc = db
            .list_objects_with_total(&ListFilter {
                kind: Some("widget".into()),
                property_filters: vec![PropertyFilter {
                    key: "tier".into(),
                    op: "gt".into(),
                    value: "1".into(),
                }],
                order_by: "property:tier".into(),
                descending: true,
                ..Default::default()
            })
            .unwrap()
            .0;
        assert_eq!(matches_desc.len(), 3);
        assert_eq!(matches_desc[0].id, "b");
        assert_eq!(matches_desc[1].id, "c");
        assert_eq!(matches_desc[2].id, "a");

        let total = db
            .list_objects_with_total(&ListFilter {
                kind: Some("widget".into()),
                property_filters: vec![PropertyFilter {
                    key: "tier".into(),
                    op: "gt".into(),
                    value: "1".into(),
                }],
                order_by: "property:tier".into(),
                descending: false,
                ..Default::default()
            })
            .unwrap()
            .1;
        assert_eq!(total, 3);

        let missing_last = db
            .list_objects_with_total(&ListFilter {
                kind: Some("widget".into()),
                order_by: "property:region".into(),
                ..Default::default()
            })
            .unwrap()
            .0;
        assert_eq!(missing_last[0].id, "d");
    }

    #[test]
    fn list_objects_filter_string_and_in_operators() {
        let db = test_db();
        db.create_object(&make_obj_with_property(
            "x",
            "component",
            "a",
            "status",
            "todo",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "y",
            "component",
            "b",
            "status",
            "done",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "z",
            "component",
            "c",
            "status",
            "blocked",
        ))
        .unwrap();

        let all = db
            .list_objects_with_total(&ListFilter {
                kind: Some("component".into()),
                property_filters: vec![PropertyFilter {
                    key: "status".into(),
                    op: "in".into(),
                    value: "todo,done".into(),
                }],
                ..Default::default()
            })
            .unwrap()
            .0;
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|obj| obj.id == "x"));
        assert!(all.iter().any(|obj| obj.id == "y"));

        let count = db
            .list_objects_with_total(&ListFilter {
                kind: Some("component".into()),
                property_filters: vec![PropertyFilter {
                    key: "status".into(),
                    op: "contains".into(),
                    value: "do".into(),
                }],
                ..Default::default()
            })
            .unwrap()
            .1;
        assert_eq!(count, 2);
    }

    #[test]
    fn list_objects_property_filter_in_with_empty_values_returns_empty_without_error() {
        let db = test_db();
        db.create_object(&make_obj_with_property(
            "x",
            "component",
            "a",
            "status",
            "todo",
        ))
        .unwrap();

        let count = db
            .list_objects_with_total(&ListFilter {
                kind: Some("component".into()),
                property_filters: vec![PropertyFilter {
                    key: "status".into(),
                    op: "in".into(),
                    value: ",  ,".into(),
                }],
                ..Default::default()
            })
            .unwrap()
            .1;
        assert_eq!(count, 0);
    }

    #[test]
    fn list_objects_contains_escapes_like_wildcards() {
        let db = test_db();
        db.create_object(&make_obj_with_property(
            "a",
            "component",
            "a",
            "status",
            "a%b",
        ))
        .unwrap();
        db.create_object(&make_obj_with_property(
            "b",
            "component",
            "b",
            "status",
            "aXb",
        ))
        .unwrap();

        let filtered = db
            .list_objects_with_total(&ListFilter {
                kind: Some("component".into()),
                property_filters: vec![PropertyFilter {
                    key: "status".into(),
                    op: "contains".into(),
                    value: "a%b".into(),
                }],
                ..Default::default()
            })
            .unwrap()
            .0;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "a");
    }

    #[test]
    fn list_all_objects_returns_all_matching_results() {
        let db = test_db();
        for i in 0..1105 {
            db.create_object(&make_obj(
                &format!("obj-{i}"),
                "widget",
                &format!("widget-{i}"),
            ))
            .unwrap();
        }

        let objects = db
            .list_all_objects(&ListFilter {
                kind: Some("widget".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(objects.len(), 1105);
    }

    #[test]
    fn list_objects_combined_property_filters_and_pagination() {
        let db = test_db();
        db.create_object(&make_obj_with_property("a", "service", "s-a", "tier", "10"))
            .unwrap();
        db.create_object(&make_obj_with_property("b", "service", "s-b", "tier", "20"))
            .unwrap();
        db.create_object(&make_obj_with_property("c", "service", "s-c", "tier", "20"))
            .unwrap();
        db.create_object(&make_obj_with_property(
            "d", "service", "s-d", "status", "ready",
        ))
        .unwrap();

        let filtered = db
            .list_objects_with_total(&ListFilter {
                kind: Some("service".into()),
                property_filters: vec![
                    PropertyFilter {
                        key: "tier".into(),
                        op: "gte".into(),
                        value: "10".into(),
                    },
                    PropertyFilter {
                        key: "tier".into(),
                        op: "lte".into(),
                        value: "20".into(),
                    },
                ],
                order_by: "name".into(),
                limit: 2,
                offset: 0,
                ..Default::default()
            })
            .unwrap()
            .0;
        assert_eq!(filtered.len(), 2);
        assert_eq!(
            filtered
                .iter()
                .map(|obj| obj.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );

        let second_page = db
            .list_objects_with_total(&ListFilter {
                kind: Some("service".into()),
                property_filters: vec![
                    PropertyFilter {
                        key: "tier".into(),
                        op: "gte".into(),
                        value: "10".into(),
                    },
                    PropertyFilter {
                        key: "tier".into(),
                        op: "lte".into(),
                        value: "20".into(),
                    },
                ],
                order_by: "name".into(),
                limit: 2,
                offset: 2,
                ..Default::default()
            })
            .unwrap();
        let results = second_page.0;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "c");
        assert_eq!(second_page.1, 3);
    }

    #[test]
    fn list_objects_parameterized_values_are_safe() {
        let db = test_db();
        db.create_object(&make_obj_with_property(
            "o1",
            "component",
            "safe",
            "name",
            "trusted",
        ))
        .unwrap();

        let matches = db
            .list_objects_with_total(&ListFilter {
                kind: Some("component".into()),
                property_filters: vec![PropertyFilter {
                    key: "name".into(),
                    op: "eq".into(),
                    value: "x'; DROP TABLE sekai_objects; --".into(),
                }],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(matches.0.len(), 0);
        assert_eq!(matches.1, 0);
    }

    #[test]
    fn principal_credentials_round_trip() {
        let db = test_db();
        let _credential = db
            .create_principal_credential("alice", "hash-alice", 1)
            .unwrap();
        let active = db.list_active_credentials().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].principal, "alice");
        assert_eq!(active[0].status, "active");

        let rotated = db
            .rotate_principal_credential("alice", "hash-alice-2")
            .unwrap();
        assert_eq!(rotated.principal, "alice");

        let all = db.list_credentials(Some("alice"), None).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|c| c.status == "revoked"));

        let revoked = db.revoke_principal_credential("alice").unwrap();
        assert!(revoked.is_some());
        let active = db.list_active_credentials().unwrap();
        assert!(active.is_empty());
        assert!(matches!(
            db.list_credentials(Some("alice"), Some("revoked"))
                .unwrap()
                .len(),
            2..=2
        ));
    }
}

use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;
use std::sync::RwLock;

pub use sekai_types::security::{Grant, GrantTerm, GrantTermError, NamespaceGrantPolicy, Role};

const DEFAULT_OPEN_ENDED_MIGRATION_MS: i64 = 90 * 24 * 60 * 60 * 1000;

pub fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn grant_live(not_after_ms: i64) -> bool {
    not_after_ms == 0 || unix_now_ms() < not_after_ms
}

pub fn grant_is_live_admin(grant: &Grant) -> bool {
    matches!(grant.role, Role::Admin) && grant_live(grant.not_after_ms)
}

/// SQLite unix-epoch milliseconds, including the current second's fraction.
pub const SQLITE_UNIX_NOW_MS: &str = "CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)";

pub fn policy_namespace_for_object(kind: &str, namespace: &str, external_id: &str) -> String {
    if kind == "namespace" {
        let from_external = external_id
            .strip_prefix("namespace:")
            .unwrap_or(external_id);
        if !from_external.is_empty() {
            return from_external.to_string();
        }
    }
    namespace.to_string()
}

type CachedGrants = HashMap<String, HashMap<String, (Role, i64)>>;

pub struct SecurityChecker {
    grants: RwLock<CachedGrants>,
}

impl Default for SecurityChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityChecker {
    pub fn new() -> Self {
        Self {
            grants: RwLock::new(HashMap::new()),
        }
    }

    pub fn load(&self, grants: &[Grant]) {
        let mut map = self.grants.write().unwrap();
        Self::replace_locked(&mut map, grants);
    }

    /// Replace the cache from `load` while holding the write lock so a
    /// concurrent `add_grant` cannot land between the snapshot and the swap.
    pub fn reload<F>(&self, load: F) -> Result<(), String>
    where
        F: FnOnce() -> Result<Vec<Grant>, String>,
    {
        let mut map = self.grants.write().unwrap();
        let grants = load()?;
        Self::replace_locked(&mut map, &grants);
        Ok(())
    }

    fn replace_locked(map: &mut CachedGrants, grants: &[Grant]) {
        map.clear();
        for g in grants {
            map.entry(g.object_id.clone())
                .or_default()
                .insert(g.principal.clone(), (g.role.clone(), g.not_after_ms));
        }
    }

    pub fn add_grant(&self, g: &Grant) {
        let mut map = self.grants.write().unwrap();
        map.entry(g.object_id.clone())
            .or_default()
            .insert(g.principal.clone(), (g.role.clone(), g.not_after_ms));
    }

    pub fn remove_grant(&self, object_id: &str, principal: &str) {
        let mut map = self.grants.write().unwrap();
        if let Some(m) = map.get_mut(object_id) {
            m.remove(principal);
            if m.is_empty() {
                map.remove(object_id);
            }
        }
    }

    pub fn can_access(&self, object_id: &str, principals: &[&str]) -> bool {
        let map = self.grants.read().unwrap();
        let m = match map.get(object_id) {
            Some(m) => m,
            None => return true,
        }; // no ACL = world-readable
        principals
            .iter()
            .any(|p| m.get(*p).is_some_and(|(_, until)| grant_live(*until)))
    }

    pub fn can_write(&self, object_id: &str, principals: &[&str]) -> bool {
        let map = self.grants.read().unwrap();
        let m = match map.get(object_id) {
            Some(m) => m,
            None => return true,
        };
        principals.iter().any(|p| {
            matches!(
                m.get(*p),
                Some((Role::Editor | Role::Admin, until)) if grant_live(*until)
            )
        })
    }

    pub fn can_admin(&self, object_id: &str, principals: &[&str]) -> bool {
        let map = self.grants.read().unwrap();
        let m = match map.get(object_id) {
            Some(m) => m,
            None => return false,
        };
        principals.iter().any(|p| {
            matches!(
                m.get(*p),
                Some((Role::Admin, until)) if grant_live(*until)
            )
        })
    }

    pub fn filter_objects<'a>(
        &self,
        objects: &'a [Object],
        principals: &[&str],
    ) -> Vec<&'a Object> {
        objects
            .iter()
            .filter(|o| self.can_access(&o.id, principals))
            .collect()
    }
}

fn grant_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Grant> {
    let role: String = row.get(3)?;
    Ok(Grant {
        id: row.get(0)?,
        object_id: row.get(1)?,
        principal: row.get(2)?,
        role: Role::parse(&role).unwrap_or(Role::Viewer),
        created: row.get(4)?,
        purpose: row.get(5)?,
        not_after_ms: row.get(6)?,
        exception_reason: row.get(7)?,
    })
}

impl SekaiDb {
    pub fn migrate_grants(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_grants (
                id TEXT PRIMARY KEY,
                object_id TEXT NOT NULL,
                principal TEXT NOT NULL,
                role TEXT NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_grants_object ON sekai_grants(object_id);
            DELETE FROM sekai_grants
            WHERE rowid NOT IN (
                SELECT MAX(rowid) FROM sekai_grants GROUP BY object_id, principal
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_grants_object_principal
                ON sekai_grants(object_id, principal);
            CREATE TABLE IF NOT EXISTS sekai_team_principals (
                principal TEXT PRIMARY KEY,
                created INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sekai_namespace_grant_policy (
                namespace TEXT PRIMARY KEY,
                max_duration_ms INTEGER NOT NULL,
                require_terms INTEGER NOT NULL
            );",
        )
        .map_err(|e| e.to_string())?;
        let _ = conn.execute(
            "ALTER TABLE sekai_grants ADD COLUMN purpose TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE sekai_grants ADD COLUMN not_after_ms INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE sekai_grants ADD COLUMN exception_reason TEXT NOT NULL DEFAULT ''",
            [],
        );
        Ok(())
    }

    pub fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        let conn = self.conn();
        insert_grant(&conn, grant)
    }

    pub fn create_grant_with_decision(
        &self,
        grant: &Grant,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        crate::sekai::audit::validate_decision(decision)?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        insert_grant(&tx, grant)?;
        crate::sekai::ledger::insert_chained_decision(&tx, decision)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        let existing = self.get_grant(id)?;
        if existing.is_some() {
            let conn = self.conn();
            conn.execute("DELETE FROM sekai_grants WHERE id = ?1", params![id])
                .map_err(|e| e.to_string())?;
        }
        Ok(existing)
    }

    pub fn get_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id,object_id,principal,role,created,purpose,not_after_ms,exception_reason FROM sekai_grants WHERE id=?1",
            params![id],
            grant_from_row,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id,object_id,principal,role,created,purpose,not_after_ms,exception_reason FROM sekai_grants WHERE object_id=?1 ORDER BY created, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id], grant_from_row)
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_all_grants(&self) -> Result<Vec<Grant>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id,object_id,principal,role,created,purpose,not_after_ms,exception_reason FROM sekai_grants ORDER BY object_id, principal",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], grant_from_row)
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn set_namespace_grant_policy(
        &self,
        policy: &sekai_types::security::NamespaceGrantPolicy,
    ) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_namespace_grant_policy (namespace, max_duration_ms, require_terms)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(namespace) DO UPDATE SET
                max_duration_ms=excluded.max_duration_ms,
                require_terms=excluded.require_terms",
            params![
                policy.namespace,
                policy.max_duration_ms,
                policy.require_terms as i64
            ],
        )
        .map_err(|e| e.to_string())?;
        if policy.require_terms {
            let duration = if policy.max_duration_ms > 0 {
                policy.max_duration_ms
            } else {
                DEFAULT_OPEN_ENDED_MIGRATION_MS
            };
            let end = unix_now_ms().saturating_add(duration);
            conn.execute(
                "UPDATE sekai_grants
                 SET not_after_ms = ?1
                 WHERE not_after_ms = 0
                   AND exception_reason = ''
                   AND object_id IN (
                     SELECT id FROM sekai_objects
                     WHERE namespace = ?2
                        OR (kind = 'namespace'
                            AND (external_id = 'namespace:' || ?2
                                 OR external_id = ?2
                                 OR name = ?2))
                   )",
                params![end, policy.namespace],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn namespace_grant_policy(
        &self,
        namespace: &str,
    ) -> Result<Option<sekai_types::security::NamespaceGrantPolicy>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT namespace, max_duration_ms, require_terms
             FROM sekai_namespace_grant_policy WHERE namespace=?1",
            params![namespace],
            |row| {
                Ok(sekai_types::security::NamespaceGrantPolicy {
                    namespace: row.get(0)?,
                    max_duration_ms: row.get(1)?,
                    require_terms: row.get::<_, i64>(2)? != 0,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_namespace_roles_for_principal(
        &self,
        principal: &str,
    ) -> Result<Vec<(String, Role)>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT o.external_id, g.role
                 FROM sekai_grants g
                 JOIN sekai_objects o ON o.id = g.object_id
                 WHERE g.principal = ?1 AND o.kind = 'namespace'
                   AND (g.not_after_ms = 0 OR g.not_after_ms > {SQLITE_UNIX_NOW_MS})
                 ORDER BY o.external_id"
            ))
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![principal], |row| {
                let external_id: String = row.get(0)?;
                let role: String = row.get(1)?;
                Ok((
                    external_id
                        .strip_prefix("namespace:")
                        .unwrap_or(&external_id)
                        .to_string(),
                    Role::parse(&role).unwrap_or(Role::Viewer),
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }
}

pub fn insert_grant(conn: &rusqlite::Connection, grant: &Grant) -> Result<(), String> {
    conn.execute(
        "INSERT INTO sekai_grants (id,object_id,principal,role,created,purpose,not_after_ms,exception_reason)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(object_id,principal) DO UPDATE SET
            id=excluded.id, role=excluded.role, created=excluded.created,
            purpose=excluded.purpose, not_after_ms=excluded.not_after_ms,
            exception_reason=excluded.exception_reason",
        params![
            grant.id,
            grant.object_id,
            grant.principal,
            grant.role.as_str(),
            grant.created,
            grant.purpose,
            grant.not_after_ms,
            grant.exception_reason
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

impl SekaiDb {
    pub fn is_team_principal(&self, principal: &str) -> Result<bool, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sekai_team_principals WHERE principal = ?1)",
            params![principal],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_world_readable_when_no_acl() {
        let sc = SecurityChecker::new();
        assert!(sc.can_access("obj-1", &["user-a"]));
        assert!(sc.can_write("obj-1", &["user-a"]));
    }

    #[test]
    fn test_acl_enforcement() {
        let sc = SecurityChecker::new();
        sc.add_grant(&Grant {
            id: "g1".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 0,
            ..Default::default()
        });
        assert!(sc.can_access("obj-1", &["alice"]));
        assert!(!sc.can_access("obj-1", &["bob"]));
        assert!(!sc.can_write("obj-1", &["alice"])); // viewer can't write
    }

    #[test]
    fn test_editor_can_write() {
        let sc = SecurityChecker::new();
        sc.add_grant(&Grant {
            id: "g1".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 0,
            ..Default::default()
        });
        assert!(sc.can_write("obj-1", &["alice"]));
    }

    #[test]
    fn expired_grant_denies_access_until_renewed() {
        let sc = SecurityChecker::new();
        let expired = Grant {
            id: "g1".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 0,
            purpose: "audit".into(),
            not_after_ms: 1,
            ..Default::default()
        };
        sc.add_grant(&expired);
        assert!(!sc.can_access("obj-1", &["alice"]));
        assert!(!sc.can_write("obj-1", &["alice"]));
        let renewed = Grant {
            not_after_ms: i64::MAX,
            ..expired
        };
        sc.add_grant(&renewed);
        assert!(sc.can_access("obj-1", &["alice"]));
        assert!(sc.can_write("obj-1", &["alice"]));
    }

    #[test]
    fn test_remove_grant_restores_world_readable() {
        let sc = SecurityChecker::new();
        sc.add_grant(&Grant {
            id: "g1".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Admin,
            created: 0,
            ..Default::default()
        });
        assert!(!sc.can_access("obj-1", &["bob"]));
        sc.remove_grant("obj-1", "alice");
        assert!(sc.can_access("obj-1", &["bob"])); // back to world-readable
    }

    #[test]
    fn test_grant_persistence() {
        let db = SekaiDb::new(":memory:").unwrap();
        let grant = Grant {
            id: "g1".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 10,
            ..Default::default()
        };
        db.create_grant(&grant).unwrap();
        let listed = db.list_grants("obj-1").unwrap();
        assert_eq!(listed.len(), 1);
        let deleted = db.delete_grant("g1").unwrap().unwrap();
        assert_eq!(deleted.principal, "alice");
        assert!(db.list_grants("obj-1").unwrap().is_empty());
    }

    #[test]
    fn grant_reload_applies_latest_role_last() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_grant(&Grant {
            id: "older-admin".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Admin,
            created: 10,
            ..Default::default()
        })
        .unwrap();
        db.create_grant(&Grant {
            id: "newer-viewer".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 5,
            ..Default::default()
        })
        .unwrap();

        let checker = SecurityChecker::new();
        checker.load(&db.list_all_grants().unwrap());
        assert!(checker.can_access("obj-1", &["alice"]));
        assert!(!checker.can_write("obj-1", &["alice"]));
        assert!(db.get_grant("older-admin").unwrap().is_none());
        assert_eq!(db.list_all_grants().unwrap().len(), 1);
    }

    fn widget(id: &str, namespace: &str) -> crate::domain::Object {
        crate::domain::Object {
            id: id.into(),
            kind: "widget".into(),
            name: id.into(),
            namespace: namespace.into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn grant_terms_persist_and_expired_namespace_role_is_hidden() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&crate::domain::Object {
            id: "ns-ops".into(),
            kind: "namespace".into(),
            name: "ops".into(),
            namespace: "ops".into(),
            external_id: "namespace:ops".into(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_grant(&Grant {
            id: "g1".into(),
            object_id: "ns-ops".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 10,
            purpose: "audit".into(),
            not_after_ms: 1,
            ..Default::default()
        })
        .unwrap();
        let stored = db.get_grant("g1").unwrap().unwrap();
        assert_eq!(stored.purpose, "audit");
        assert_eq!(stored.not_after_ms, 1);
        assert!(
            db.list_namespace_roles_for_principal("alice")
                .unwrap()
                .is_empty()
        );
        db.create_grant(&Grant {
            id: "g1".into(),
            object_id: "ns-ops".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 10,
            purpose: "audit".into(),
            not_after_ms: i64::MAX,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            db.list_namespace_roles_for_principal("alice").unwrap(),
            vec![("ops".into(), Role::Editor)]
        );
    }

    #[test]
    fn opt_in_policy_stamps_a_default_end_date_on_open_ended_grants() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&widget("widget-1", "ops")).unwrap();
        db.create_grant(&Grant {
            id: "g1".into(),
            object_id: "widget-1".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 10,
            ..Default::default()
        })
        .unwrap();
        db.set_namespace_grant_policy(&NamespaceGrantPolicy {
            namespace: "ops".into(),
            max_duration_ms: 10_000,
            require_terms: true,
        })
        .unwrap();
        let stored = db.get_grant("g1").unwrap().unwrap();
        let now = unix_now_ms();
        assert!(stored.not_after_ms > now);
        assert!(stored.not_after_ms <= now + 10_000);
    }

    #[test]
    fn policy_opt_in_reloads_cached_grant_expiry() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&widget("obj-1", "ops")).unwrap();
        db.create_grant(&Grant {
            id: "g1".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 10,
            ..Default::default()
        })
        .unwrap();
        let checker = SecurityChecker::new();
        checker.load(&db.list_all_grants().unwrap());
        assert!(checker.can_access("obj-1", &["alice"]));
        db.set_namespace_grant_policy(&NamespaceGrantPolicy {
            namespace: "ops".into(),
            max_duration_ms: 1,
            require_terms: true,
        })
        .unwrap();
        checker.load(&db.list_all_grants().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(!checker.can_access("obj-1", &["alice"]));
    }

    #[test]
    fn sqlite_access_denies_expired_grants() {
        use crate::db::graph::GraphBackend;
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&widget("obj-1", "")).unwrap();
        db.create_grant(&Grant {
            id: "g1".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 1,
            purpose: "audit".into(),
            not_after_ms: 1,
            ..Default::default()
        })
        .unwrap();
        assert!(!db.can_access("obj-1", &["alice"]).unwrap());
        db.create_grant(&Grant {
            id: "g1".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 1,
            purpose: "audit".into(),
            not_after_ms: i64::MAX,
            ..Default::default()
        })
        .unwrap();
        assert!(db.can_access("obj-1", &["alice"]).unwrap());
    }
}

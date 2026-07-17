use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "editor" => Some(Self::Editor),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
            Self::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub id: String,
    pub object_id: String,
    pub principal: String,
    pub role: Role,
    pub created: i64,
}

pub struct SecurityChecker {
    grants: RwLock<HashMap<String, HashMap<String, Role>>>, // object_id -> principal -> role
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
        map.clear();
        for g in grants {
            map.entry(g.object_id.clone())
                .or_default()
                .insert(g.principal.clone(), g.role.clone());
        }
    }

    pub fn add_grant(&self, g: &Grant) {
        let mut map = self.grants.write().unwrap();
        map.entry(g.object_id.clone())
            .or_default()
            .insert(g.principal.clone(), g.role.clone());
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
        principals.iter().any(|p| m.contains_key(*p))
    }

    pub fn can_write(&self, object_id: &str, principals: &[&str]) -> bool {
        let map = self.grants.read().unwrap();
        let m = match map.get(object_id) {
            Some(m) => m,
            None => return true,
        };
        principals
            .iter()
            .any(|p| matches!(m.get(*p), Some(Role::Editor) | Some(Role::Admin)))
    }

    pub fn can_admin(&self, object_id: &str, principals: &[&str]) -> bool {
        let map = self.grants.read().unwrap();
        let m = match map.get(object_id) {
            Some(m) => m,
            None => return false,
        };
        principals
            .iter()
            .any(|p| matches!(m.get(*p), Some(Role::Admin)))
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

impl SekaiDb {
    pub(crate) fn migrate_grants(&self) -> Result<(), String> {
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
            );",
        )
        .map_err(|e| e.to_string())
    }

    pub fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_grants (id,object_id,principal,role,created)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(object_id,principal) DO UPDATE SET
                id=excluded.id, role=excluded.role, created=excluded.created",
            params![
                grant.id,
                grant.object_id,
                grant.principal,
                grant.role.as_str(),
                grant.created
            ],
        )
        .map_err(|e| e.to_string())?;
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
            "SELECT id,object_id,principal,role,created FROM sekai_grants WHERE id=?1",
            params![id],
            |row| {
                let role: String = row.get(3)?;
                Ok(Grant {
                    id: row.get(0)?,
                    object_id: row.get(1)?,
                    principal: row.get(2)?,
                    role: Role::parse(&role).unwrap_or(Role::Viewer),
                    created: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id,object_id,principal,role,created FROM sekai_grants WHERE object_id=?1 ORDER BY created, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id], |row| {
                let role: String = row.get(3)?;
                Ok(Grant {
                    id: row.get(0)?,
                    object_id: row.get(1)?,
                    principal: row.get(2)?,
                    role: Role::parse(&role).unwrap_or(Role::Viewer),
                    created: row.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_all_grants(&self) -> Result<Vec<Grant>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id,object_id,principal,role,created FROM sekai_grants ORDER BY object_id, principal",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let role: String = row.get(3)?;
                Ok(Grant {
                    id: row.get(0)?,
                    object_id: row.get(1)?,
                    principal: row.get(2)?,
                    role: Role::parse(&role).unwrap_or(Role::Viewer),
                    created: row.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_namespace_roles_for_principal(
        &self,
        principal: &str,
    ) -> Result<Vec<(String, Role)>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT o.external_id, g.role
                 FROM sekai_grants g
                 JOIN sekai_objects o ON o.id = g.object_id
                 WHERE g.principal = ?1 AND o.kind = 'namespace'
                 ORDER BY o.external_id",
            )
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
        });
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
        })
        .unwrap();
        db.create_grant(&Grant {
            id: "newer-viewer".into(),
            object_id: "obj-1".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 5,
        })
        .unwrap();

        let checker = SecurityChecker::new();
        checker.load(&db.list_all_grants().unwrap());
        assert!(checker.can_access("obj-1", &["alice"]));
        assert!(!checker.can_write("obj-1", &["alice"]));
        assert!(db.get_grant("older-admin").unwrap().is_none());
        assert_eq!(db.list_all_grants().unwrap().len(), 1);
    }
}

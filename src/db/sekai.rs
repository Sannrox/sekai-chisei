use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

use crate::domain::{Direction, Link, ListFilter, Object};

pub struct SekaiDb {
    pub(crate) conn: Mutex<Connection>,
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
        conn.busy_timeout(Duration::from_secs(1))
            .map_err(|e| e.to_string())?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
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
            CREATE INDEX IF NOT EXISTS idx_links_to ON sekai_links(to_id, relation);",
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn migrate_principal_credentials(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT 1", [], |_| Ok(()))
            .map_err(|e| e.to_string())
    }

    pub fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, principal, token_hash, status, created, rotated_at, revoked_at FROM sekai_principal_credentials WHERE token_hash = ?1 AND status = 'active' ORDER BY created DESC LIMIT 1",
            params![token_hash],
            row_to_principal_credential,
        )
        .optional()
        .map_err(|error| error.to_string())
    }

    pub fn principal_credentials_activity_epoch(&self) -> Result<i64, String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let mut conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        Ok(rows.filter_map(|row| row.ok()).collect())
    }

    pub fn list_active_credentials(&self) -> Result<Vec<PrincipalCredential>, String> {
        self.list_credentials(None, Some("active"))
    }

    pub fn create_object(&self, o: &Object) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let props = serde_json::to_string(&o.properties).unwrap_or_default();
        conn.execute(
            "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![o.id, o.kind, o.name, o.namespace, o.external_id, props, o.created, o.updated],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
            params![id],
            |row| Ok(row_to_object(row)),
        ).optional().map_err(|e| e.to_string())
    }

    pub fn update_object(&self, o: &Object) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let props = serde_json::to_string(&o.properties).unwrap_or_default();
        let n = conn.execute(
            "UPDATE sekai_objects SET kind=?2, name=?3, namespace=?4, external_id=?5, properties=?6, updated=?7 WHERE id=?1",
            params![o.id, o.kind, o.name, o.namespace, o.external_id, props, o.updated],
        ).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("not found".into());
        }
        Ok(())
    }

    pub fn delete_object(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sekai_objects WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        conn.execute(
            "DELETE FROM sekai_links WHERE from_id = ?1 OR to_id = ?1",
            params![id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        let conn = self.conn.lock().unwrap();
        let mut sql = "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE 1=1".to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
        if let Some(k) = &filter.kind {
            sql.push_str(&format!(" AND kind = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(k.clone()));
        }
        if let Some(n) = &filter.name {
            sql.push_str(&format!(" AND name = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(n.clone()));
        }
        if let Some(ns) = &filter.namespace {
            sql.push_str(&format!(" AND namespace = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(ns.clone()));
        }
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| Ok(row_to_object(row)))
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE external_id = ?1",
            params![external_id],
            |row| Ok(row_to_object(row)),
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
        let conn = self.conn.lock().unwrap();
        let json_path = format!("$.{}", key);
        let mut stmt = conn.prepare(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE kind = ?1 AND json_extract(properties, ?2) = ?3"
        ).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![kind, json_path, value], |row| {
                Ok(row_to_object(row))
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn create_link(&self, l: &Link) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO sekai_links (id, from_id, to_id, relation, created) VALUES (?1,?2,?3,?4,?5)",
            params![l.id, l.from_id, l.to_id, l.relation, l.created],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_link(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sekai_links WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_link(&self, id: &str) -> Result<Option<Link>, String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
            results.push(row_to_link(row));
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

fn row_to_object(row: &rusqlite::Row) -> Object {
    let props_str: String = row.get(5).unwrap_or_default();
    let properties: HashMap<String, String> = serde_json::from_str(&props_str).unwrap_or_default();
    Object {
        id: row.get(0).unwrap(),
        kind: row.get(1).unwrap(),
        name: row.get(2).unwrap(),
        namespace: row.get(3).unwrap_or_default(),
        external_id: row.get(4).unwrap_or_default(),
        properties,
        created: row.get(6).unwrap(),
        updated: row.get(7).unwrap(),
    }
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

fn row_to_link(row: &rusqlite::Row) -> Link {
    Link {
        id: row.get(0).unwrap(),
        from_id: row.get(1).unwrap(),
        to_id: row.get(2).unwrap(),
        relation: row.get(3).unwrap(),
        created: row.get(4).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
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
    fn principal_credentials_round_trip() {
        let db = test_db();
        db.migrate_principal_credentials().unwrap();
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

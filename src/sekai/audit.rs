use crate::db::sekai::SekaiDb;
use rusqlite::params;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Decision {
    pub id: String,
    pub timestamp: i64,
    pub actor: String,
    pub action: String,
    pub reason: String,
    pub evidence: HashMap<String, String>,
    pub target_id: String,
    pub outcome: String,
}

#[derive(Debug, Clone)]
pub struct ObjectChange {
    pub id: String,
    pub object_id: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub changed_by: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default)]
pub struct DecisionFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub after: i64,
    pub limit: i32,
    pub offset: i32,
}

impl SekaiDb {
    pub fn migrate_audit(&self) {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_decisions (
                id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, actor TEXT NOT NULL,
                action TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '{}',
                target_id TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS sekai_object_changes (
                id TEXT PRIMARY KEY, object_id TEXT NOT NULL, field TEXT NOT NULL,
                old_value TEXT NOT NULL DEFAULT '', new_value TEXT NOT NULL DEFAULT '',
                changed_by TEXT NOT NULL DEFAULT '', timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_changes_object ON sekai_object_changes(object_id);"
        ).unwrap();
    }

    pub fn record_decision(&self, d: &Decision) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let evidence = serde_json::to_string(&d.evidence).unwrap_or_default();
        conn.execute("INSERT INTO sekai_decisions (id,timestamp,actor,action,reason,evidence,target_id,outcome) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![d.id, d.timestamp, d.actor, d.action, d.reason, evidence, d.target_id, d.outcome]).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_decisions(&self, f: &DecisionFilter) -> Result<Vec<Decision>, String> {
        let conn = self.conn.lock().unwrap();
        let mut sql = "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome FROM sekai_decisions WHERE 1=1".to_string();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(a) = &f.actor {
            sql.push_str(" AND actor = ?");
            params.push(Box::new(a.clone()));
        }
        if let Some(a) = &f.action {
            sql.push_str(" AND action = ?");
            params.push(Box::new(a.clone()));
        }
        if f.after > 0 {
            sql.push_str(" AND timestamp > ?");
            params.push(Box::new(f.after));
        }
        sql.push_str(" ORDER BY timestamp DESC");
        if f.limit > 0 {
            sql.push_str(" LIMIT ?");
            params.push(Box::new(f.limit));
        }
        if f.offset > 0 {
            sql.push_str(" OFFSET ?");
            params.push(Box::new(f.offset));
        }

        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let mut results = Vec::new();
        let mut rows = stmt
            .query(param_refs.as_slice())
            .map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let ev_str: String = row.get(5).unwrap_or_default();
            results.push(Decision {
                id: row.get(0).unwrap(),
                timestamp: row.get(1).unwrap(),
                actor: row.get(2).unwrap(),
                action: row.get(3).unwrap(),
                reason: row.get(4).unwrap_or_default(),
                evidence: serde_json::from_str(&ev_str).unwrap_or_default(),
                target_id: row.get(6).unwrap_or_default(),
                outcome: row.get(7).unwrap_or_default(),
            });
        }
        Ok(results)
    }

    pub fn record_object_change(&self, c: &ObjectChange) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute("INSERT INTO sekai_object_changes (id,object_id,field,old_value,new_value,changed_by,timestamp) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![c.id, c.object_id, c.field, c.old_value, c.new_value, c.changed_by, c.timestamp]).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        let conn = self.conn.lock().unwrap();
        let effective_limit = if limit > 0 { limit } else { 100 };
        let sql = "SELECT id,object_id,field,old_value,new_value,changed_by,timestamp FROM sekai_object_changes WHERE object_id=?1 ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3";
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut rows = stmt
            .query(params![object_id, effective_limit, offset])
            .map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            results.push(ObjectChange {
                id: row.get(0).unwrap(),
                object_id: row.get(1).unwrap(),
                field: row.get(2).unwrap(),
                old_value: row.get(3).unwrap_or_default(),
                new_value: row.get(4).unwrap_or_default(),
                changed_by: row.get(5).unwrap_or_default(),
                timestamp: row.get(6).unwrap(),
            });
        }
        Ok(results)
    }

    pub fn purge_old_records(&self, before: i64) -> Result<i32, String> {
        let conn = self.conn.lock().unwrap();
        let n1 = conn
            .execute(
                "DELETE FROM sekai_decisions WHERE timestamp < ?1",
                params![before],
            )
            .map_err(|e| e.to_string())?;
        let n2 = conn
            .execute(
                "DELETE FROM sekai_object_changes WHERE timestamp < ?1",
                params![before],
            )
            .map_err(|e| e.to_string())?;
        Ok((n1 + n2) as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> SekaiDb {
        let db = SekaiDb::new(":memory:").unwrap();
        db.migrate_audit();
        db
    }

    #[test]
    fn test_decision_crud() {
        let db = setup();
        db.record_decision(&Decision {
            id: "d1".into(),
            timestamp: 100,
            actor: "sentinel".into(),
            action: "create_task".into(),
            reason: "degraded".into(),
            evidence: HashMap::new(),
            target_id: "c1".into(),
            outcome: "task_created".into(),
        })
        .unwrap();
        db.record_decision(&Decision {
            id: "d2".into(),
            timestamp: 200,
            actor: "sentinel".into(),
            action: "alert".into(),
            reason: "".into(),
            evidence: HashMap::new(),
            target_id: "".into(),
            outcome: "".into(),
        })
        .unwrap();

        let all = db.list_decisions(&DecisionFilter::default()).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = db
            .list_decisions(&DecisionFilter {
                action: Some("alert".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_object_change_and_purge() {
        let db = setup();
        db.record_object_change(&ObjectChange {
            id: "ch1".into(),
            object_id: "o1".into(),
            field: "name".into(),
            old_value: "old".into(),
            new_value: "new".into(),
            changed_by: "user".into(),
            timestamp: 50,
        })
        .unwrap();
        db.record_object_change(&ObjectChange {
            id: "ch2".into(),
            object_id: "o1".into(),
            field: "tier".into(),
            old_value: "p2".into(),
            new_value: "p1".into(),
            changed_by: "user".into(),
            timestamp: 150,
        })
        .unwrap();

        let changes = db.list_object_changes("o1", 10, 0).unwrap();
        assert_eq!(changes.len(), 2);

        let purged = db.purge_old_records(100).unwrap();
        assert_eq!(purged, 1); // ch1 purged (timestamp 50 < 100)

        let changes = db.list_object_changes("o1", 10, 0).unwrap();
        assert_eq!(changes.len(), 1);
    }
}

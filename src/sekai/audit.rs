use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeSet, HashMap};

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

pub fn record_object_diff(
    db: &SekaiDb,
    actor: &str,
    before: Option<&Object>,
    after: Option<&Object>,
) -> Result<u32, String> {
    let timestamp = chrono::Utc::now().timestamp_millis();
    let changes = object_diff_changes(actor, before, after, timestamp);
    let count = changes.len() as u32;
    db.record_object_changes(&changes)?;
    Ok(count)
}

pub(crate) fn object_diff_changes(
    actor: &str,
    before: Option<&Object>,
    after: Option<&Object>,
    timestamp: i64,
) -> Vec<ObjectChange> {
    let mut changes = Vec::new();

    match (before, after) {
        (None, Some(after)) => changes.push(ObjectChange {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: after.id.clone(),
            field: "_created".into(),
            old_value: String::new(),
            new_value: format!("{}/{}", after.kind, after.name),
            changed_by: actor.into(),
            timestamp,
        }),
        (Some(before), None) => changes.push(ObjectChange {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: before.id.clone(),
            field: "_deleted".into(),
            old_value: format!("{}/{}", before.kind, before.name),
            new_value: String::new(),
            changed_by: actor.into(),
            timestamp,
        }),
        (Some(before), Some(after)) => {
            push_if_changed(
                &mut changes,
                actor,
                timestamp,
                &after.id,
                "kind",
                &before.kind,
                &after.kind,
            );
            push_if_changed(
                &mut changes,
                actor,
                timestamp,
                &after.id,
                "name",
                &before.name,
                &after.name,
            );
            push_if_changed(
                &mut changes,
                actor,
                timestamp,
                &after.id,
                "namespace",
                &before.namespace,
                &after.namespace,
            );
            push_if_changed(
                &mut changes,
                actor,
                timestamp,
                &after.id,
                "external_id",
                &before.external_id,
                &after.external_id,
            );

            let property_keys = before
                .properties
                .keys()
                .chain(after.properties.keys())
                .collect::<BTreeSet<_>>();
            for key in property_keys {
                let old_value = before.properties.get(key).cloned().unwrap_or_default();
                let new_value = after.properties.get(key).cloned().unwrap_or_default();
                push_if_changed(
                    &mut changes,
                    actor,
                    timestamp,
                    &after.id,
                    &format!("properties.{key}"),
                    &old_value,
                    &new_value,
                );
            }
        }
        (None, None) => {}
    }

    changes
}

fn push_if_changed(
    changes: &mut Vec<ObjectChange>,
    actor: &str,
    timestamp: i64,
    object_id: &str,
    field: &str,
    old_value: &str,
    new_value: &str,
) {
    if old_value == new_value {
        return;
    }
    changes.push(ObjectChange {
        id: uuid::Uuid::new_v4().to_string(),
        object_id: object_id.into(),
        field: field.into(),
        old_value: old_value.into(),
        new_value: new_value.into(),
        changed_by: actor.into(),
        timestamp,
    });
}

impl SekaiDb {
    pub(crate) fn migrate_audit(&self) -> Result<(), String> {
        let conn = self.conn();
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
        )
        .map_err(|e| e.to_string())
    }

    pub fn record_decision(&self, d: &Decision) -> Result<(), String> {
        let conn = self.conn();
        let evidence = serde_json::to_string(&d.evidence).unwrap_or_default();
        conn.execute("INSERT INTO sekai_decisions (id,timestamp,actor,action,reason,evidence,target_id,outcome) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![d.id, d.timestamp, d.actor, d.action, d.reason, evidence, d.target_id, d.outcome]).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_decisions(&self, f: &DecisionFilter) -> Result<Vec<Decision>, String> {
        let conn = self.conn();
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
            let ev_str: String = row.get(5).map_err(|e| e.to_string())?;
            results.push(Decision {
                id: row.get(0).map_err(|e| e.to_string())?,
                timestamp: row.get(1).map_err(|e| e.to_string())?,
                actor: row.get(2).map_err(|e| e.to_string())?,
                action: row.get(3).map_err(|e| e.to_string())?,
                reason: row.get(4).map_err(|e| e.to_string())?,
                evidence: serde_json::from_str(&ev_str).unwrap_or_default(),
                target_id: row.get(6).map_err(|e| e.to_string())?,
                outcome: row.get(7).map_err(|e| e.to_string())?,
            });
        }
        Ok(results)
    }

    pub fn record_object_change(&self, c: &ObjectChange) -> Result<(), String> {
        let conn = self.conn();
        conn.execute("INSERT INTO sekai_object_changes (id,object_id,field,old_value,new_value,changed_by,timestamp) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![c.id, c.object_id, c.field, c.old_value, c.new_value, c.changed_by, c.timestamp]).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn record_object_changes(&self, changes: &[ObjectChange]) -> Result<(), String> {
        if changes.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        insert_object_changes(&tx, changes)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn create_object_with_audit(&self, object: &Object, actor: &str) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let props = serde_json::to_string(&object.properties).unwrap_or_default();
        tx.execute(
            "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                object.id,
                object.kind,
                object.name,
                object.namespace,
                object.external_id,
                props,
                object.created,
                object.updated
            ],
        )
        .map_err(|e| e.to_string())?;
        let changes = object_diff_changes(
            actor,
            None,
            Some(object),
            chrono::Utc::now().timestamp_millis(),
        );
        insert_object_changes(&tx, &changes)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn update_object_with_audit(
        &self,
        object: &Object,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let before = tx
            .query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
                params![object.id],
                crate::db::sekai::row_to_object,
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some(before_object) = before else {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(None);
        };
        let props = serde_json::to_string(&object.properties).unwrap_or_default();
        tx.execute(
            "UPDATE sekai_objects SET kind=?2, name=?3, namespace=?4, external_id=?5, properties=?6, updated=?7 WHERE id=?1",
            params![
                object.id,
                object.kind,
                object.name,
                object.namespace,
                object.external_id,
                props,
                object.updated
            ],
        )
        .map_err(|e| e.to_string())?;
        let changes = object_diff_changes(
            actor,
            Some(&before_object),
            Some(object),
            chrono::Utc::now().timestamp_millis(),
        );
        insert_object_changes(&tx, &changes)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(before_object))
    }

    pub fn delete_object_with_audit(
        &self,
        id: &str,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let before = tx
            .query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
                params![id],
                crate::db::sekai::row_to_object,
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
        if let Some(before) = &before {
            insert_object_changes(
                &tx,
                &[ObjectChange {
                    id: uuid::Uuid::new_v4().to_string(),
                    object_id: before.id.clone(),
                    field: "_deleted".into(),
                    old_value: format!("{}/{}", before.kind, before.name),
                    new_value: String::new(),
                    changed_by: actor.into(),
                    timestamp: chrono::Utc::now().timestamp_millis(),
                }],
            )?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(before)
    }

    pub fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        let conn = self.conn();
        let effective_limit = if limit > 0 { limit } else { 100 };
        let sql = "SELECT id,object_id,field,old_value,new_value,changed_by,timestamp FROM sekai_object_changes WHERE object_id=?1 ORDER BY timestamp DESC, rowid DESC LIMIT ?2 OFFSET ?3";
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut rows = stmt
            .query(params![object_id, effective_limit, offset])
            .map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            results.push(ObjectChange {
                id: row.get(0).map_err(|e| e.to_string())?,
                object_id: row.get(1).map_err(|e| e.to_string())?,
                field: row.get(2).map_err(|e| e.to_string())?,
                old_value: row.get(3).map_err(|e| e.to_string())?,
                new_value: row.get(4).map_err(|e| e.to_string())?,
                changed_by: row.get(5).map_err(|e| e.to_string())?,
                timestamp: row.get(6).map_err(|e| e.to_string())?,
            });
        }
        Ok(results)
    }

    pub fn object_change_kind(&self, object_id: &str) -> Result<Option<String>, String> {
        let conn = self.conn();
        let marker = conn
            .query_row(
                "SELECT field, old_value, new_value FROM sekai_object_changes
                 WHERE object_id = ?1 AND field IN ('_created', '_deleted')
                 ORDER BY timestamp DESC, rowid DESC LIMIT 1",
                params![object_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;
        Ok(marker.and_then(|(field, old_value, new_value)| {
            let value = if field == "_deleted" {
                old_value
            } else {
                new_value
            };
            value.split_once('/').map(|(kind, _)| kind.to_string())
        }))
    }

    pub fn purge_old_records(&self, before: i64) -> Result<i32, String> {
        let conn = self.conn();
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

pub(crate) fn insert_object_changes(
    conn: &Connection,
    changes: &[ObjectChange],
) -> Result<(), String> {
    let mut stmt = conn
        .prepare("INSERT INTO sekai_object_changes (id,object_id,field,old_value,new_value,changed_by,timestamp) VALUES (?1,?2,?3,?4,?5,?6,?7)")
        .map_err(|e| e.to_string())?;
    for change in changes {
        stmt.execute(params![
            change.id,
            change.object_id,
            change.field,
            change.old_value,
            change.new_value,
            change.changed_by,
            change.timestamp
        ])
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn object(
        id: &str,
        name: &str,
        namespace: &str,
        external_id: &str,
        properties: HashMap<String, String>,
    ) -> Object {
        Object {
            id: id.into(),
            kind: "component".into(),
            name: name.into(),
            namespace: namespace.into(),
            external_id: external_id.into(),
            properties,
            created: 1,
            updated: 1,
        }
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

    #[test]
    fn record_object_diff_records_lifecycle_rows() {
        let db = setup();
        let obj = object("o1", "api", "default", "ext-1", HashMap::new());

        assert_eq!(
            record_object_diff(&db, "tester", None, Some(&obj)).unwrap(),
            1
        );
        assert_eq!(
            record_object_diff(&db, "tester", Some(&obj), None).unwrap(),
            1
        );

        let changes = db.list_object_changes("o1", 10, 0).unwrap();
        assert_eq!(changes[0].field, "_deleted");
        assert_eq!(changes[0].old_value, "component/api");
        assert_eq!(changes[1].field, "_created");
        assert_eq!(changes[1].new_value, "component/api");
        assert!(changes.iter().all(|change| change.changed_by == "tester"));
    }

    #[test]
    fn record_object_diff_records_changed_fields_and_properties() {
        let db = setup();
        let before = object(
            "o1",
            "api",
            "default",
            "ext-1",
            HashMap::from([
                ("removed".into(), "old".into()),
                ("status".into(), "todo".into()),
                ("same".into(), "kept".into()),
            ]),
        );
        let after = object(
            "o1",
            "worker",
            "prod",
            "ext-2",
            HashMap::from([
                ("added".into(), "new".into()),
                ("status".into(), "done".into()),
                ("same".into(), "kept".into()),
            ]),
        );
        let mut after = after;
        after.kind = "service".into();

        assert_eq!(
            record_object_diff(&db, "tester", Some(&before), Some(&after)).unwrap(),
            7
        );

        let changes = db.list_object_changes("o1", 10, 0).unwrap();
        let fields = changes
            .iter()
            .map(|change| change.field.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            fields,
            vec![
                "properties.status",
                "properties.removed",
                "properties.added",
                "external_id",
                "namespace",
                "name",
                "kind",
            ]
        );
        assert_eq!(changes[0].old_value, "todo");
        assert_eq!(changes[0].new_value, "done");
        assert_eq!(changes[1].old_value, "old");
        assert_eq!(changes[1].new_value, "");
        assert_eq!(changes[2].old_value, "");
        assert_eq!(changes[2].new_value, "new");
        assert_eq!(changes[6].old_value, "component");
        assert_eq!(changes[6].new_value, "service");
    }

    #[test]
    fn record_object_diff_ignores_noop_update() {
        let db = setup();
        let obj = object("o1", "api", "default", "ext-1", HashMap::new());

        assert_eq!(
            record_object_diff(&db, "tester", Some(&obj), Some(&obj)).unwrap(),
            0
        );
        assert!(db.list_object_changes("o1", 10, 0).unwrap().is_empty());
    }

    #[test]
    fn record_object_diff_returns_insert_errors() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_changes", []).unwrap();
        }
        let obj = object("o1", "api", "default", "ext-1", HashMap::new());

        assert!(record_object_diff(&db, "tester", None, Some(&obj)).is_err());
    }
}

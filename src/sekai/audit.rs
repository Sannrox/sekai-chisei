use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::security::{Grant, Role};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub target_id: Option<String>,
    pub after: i64,
    pub limit: i32,
    pub offset: i32,
}

fn validate_decision(decision: &Decision) -> Result<(), String> {
    if decision.id.trim().is_empty() {
        return Err("decision id required".into());
    }
    let evidence = serde_json::to_string(&decision.evidence).map_err(|error| error.to_string())?;
    let parsed: HashMap<String, String> = serde_json::from_str(&evidence)
        .map_err(|error| format!("decision evidence must be a string map: {error}"))?;
    for (key, value) in &parsed {
        if looks_like_secret(value) {
            return Err(format!(
                "decision evidence must not store secret material in field {key}"
            ));
        }
    }
    Ok(())
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "sk-",
        "ghp_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "bearer ",
        "akia",
        "asia",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
        || (lower.starts_with("eyj") && lower.matches('.').count() == 2)
}

pub fn record_object_diff(
    db: &RuntimeDb,
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
        (Some(before), None) => {
            changes.push(ObjectChange {
                id: uuid::Uuid::new_v4().to_string(),
                object_id: before.id.clone(),
                field: "_deleted".into(),
                old_value: format!("{}/{}", before.kind, before.name),
                new_value: String::new(),
                changed_by: actor.into(),
                timestamp,
            });
            changes.push(ObjectChange {
                id: uuid::Uuid::new_v4().to_string(),
                object_id: before.id.clone(),
                field: "_namespace".into(),
                old_value: before.namespace.clone(),
                new_value: String::new(),
                changed_by: actor.into(),
                timestamp,
            });
        }
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
    pub fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, String> {
        let conn = self.conn();
        let external_id = format!("namespace:{}", namespace.trim());
        let mut statement = conn
            .prepare(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects WHERE external_id = ?1 ORDER BY id LIMIT 2",
            )
            .map_err(|error| error.to_string())?;
        let objects = statement
            .query_map(params![external_id], crate::db::sekai::row_to_object)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if objects.len() > 1 || objects.iter().any(|object| object.kind != "namespace") {
            return Err(format!(
                "canonical namespace identity {external_id:?} is not uniquely held by a namespace boundary"
            ));
        }
        Ok(objects.into_iter().next())
    }

    pub fn ensure_team_namespace(
        &self,
        namespace: &str,
        principal: &str,
        member_role: Role,
        actor: &str,
    ) -> Result<(Object, Vec<Grant>), String> {
        crate::db::team_namespace::validate_team_namespace_bootstrap(namespace, principal)?;
        let namespace = namespace.trim();
        let principal = principal.trim();
        let external_id = format!("namespace:{namespace}");
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let objects = {
            let mut statement = tx
                .prepare(
                    "SELECT id, kind, name, namespace, external_id, properties, created, updated
                     FROM sekai_objects WHERE external_id = ?1 ORDER BY id LIMIT 2",
                )
                .map_err(|error| error.to_string())?;
            statement
                .query_map(params![external_id], crate::db::sekai::row_to_object)
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        if objects.len() > 1 || objects.iter().any(|object| object.kind != "namespace") {
            return Err(format!(
                "canonical namespace identity {external_id:?} is not uniquely held by a namespace boundary"
            ));
        }
        tx.execute(
            "INSERT OR IGNORE INTO sekai_team_principals (principal, created) VALUES (?1, ?2)",
            params![principal, now],
        )
        .map_err(|error| error.to_string())?;
        let object = if let Some(mut object) = objects.into_iter().next() {
            let original = object.clone();
            object.namespace = namespace.into();
            object
                .properties
                .insert("team_managed".into(), "true".into());
            object
                .properties
                .insert("runtime_boundary".into(), namespace.into());
            if object.namespace != original.namespace || object.properties != original.properties {
                object.updated = now;
                let properties = serde_json::to_string(&object.properties).unwrap_or_default();
                tx.execute(
                    "UPDATE sekai_objects SET namespace = ?1, properties = ?2, updated = ?3 WHERE id = ?4",
                    params![object.namespace, properties, object.updated, object.id],
                )
                .map_err(|error| error.to_string())?;
                insert_object_changes(
                    &tx,
                    &object_diff_changes(actor, Some(&original), Some(&object), now),
                )?;
            }
            object
        } else {
            let orphan_grants: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM sekai_grants WHERE object_id = ?1",
                    params![external_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if orphan_grants > 0 {
                return Err(format!(
                    "namespace {namespace:?} has grants without a namespace boundary"
                ));
            }
            let object = Object {
                id: external_id.clone(),
                kind: "namespace".into(),
                name: namespace.into(),
                namespace: namespace.into(),
                external_id: external_id.clone(),
                properties: HashMap::from([
                    ("team_managed".into(), "true".into()),
                    ("runtime_boundary".into(), namespace.into()),
                ]),
                created: now,
                updated: now,
            };
            let properties = serde_json::to_string(&object.properties).unwrap_or_default();
            tx.execute(
                "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    object.id,
                    object.kind,
                    object.name,
                    object.namespace,
                    object.external_id,
                    properties,
                    object.created,
                    object.updated
                ],
            )
            .map_err(|error| error.to_string())?;
            insert_object_changes(&tx, &object_diff_changes(actor, None, Some(&object), now))?;
            object
        };

        let grants = [
            ("root", Role::Admin),
            ("local", Role::Admin),
            (principal, member_role),
        ]
        .into_iter()
        .map(|(grant_principal, role)| Grant {
            id: format!("team:{namespace}:{grant_principal}"),
            object_id: object.id.clone(),
            principal: grant_principal.into(),
            role,
            created: now,
        })
        .collect::<Vec<_>>();
        for grant in &grants {
            tx.execute(
                "INSERT INTO sekai_grants (id, object_id, principal, role, created)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(object_id, principal) DO UPDATE SET
                    id=excluded.id, role=excluded.role, created=excluded.created",
                params![
                    grant.id,
                    grant.object_id,
                    grant.principal,
                    grant.role.as_str(),
                    grant.created
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok((object, grants))
    }

    pub(crate) fn migrate_audit(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_decisions (
                id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, actor TEXT NOT NULL,
                action TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '{}',
                target_id TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT '',
                namespace TEXT NOT NULL DEFAULT '', data_class TEXT NOT NULL DEFAULT 'unclassified'
            );
            CREATE TABLE IF NOT EXISTS sekai_object_changes (
                id TEXT PRIMARY KEY, object_id TEXT NOT NULL, field TEXT NOT NULL,
                old_value TEXT NOT NULL DEFAULT '', new_value TEXT NOT NULL DEFAULT '',
                changed_by TEXT NOT NULL DEFAULT '', timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_changes_object ON sekai_object_changes(object_id);
            CREATE INDEX IF NOT EXISTS idx_decisions_target ON sekai_decisions(target_id, timestamp);
            CREATE TABLE IF NOT EXISTS sekai_schema_migrations (
                name TEXT PRIMARY KEY
            );"
        )
        .map_err(|e| e.to_string())?;
        let mut added_lifecycle_column = false;
        for column in [
            "namespace TEXT NOT NULL DEFAULT ''",
            "data_class TEXT NOT NULL DEFAULT 'unclassified'",
        ] {
            match conn.execute(
                &format!("ALTER TABLE sekai_decisions ADD COLUMN {column}"),
                [],
            ) {
                Ok(_) => added_lifecycle_column = true,
                Err(error) if error.to_string().contains("duplicate column name") => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        conn.execute_batch(
            "INSERT OR IGNORE INTO sekai_object_changes
                 (id, object_id, field, old_value, new_value, changed_by, timestamp)
             SELECT 'audit-namespace-backfill-current:' || hex(object.id), object.id,
                    '_namespace', object.namespace, '', 'migration', object.updated
             FROM sekai_objects object
             WHERE object.namespace <> ''
               AND NOT EXISTS (
                   SELECT 1 FROM sekai_object_changes marker
                   WHERE marker.object_id = object.id AND marker.field = '_namespace'
               );
             INSERT OR IGNORE INTO sekai_object_changes
                 (id, object_id, field, old_value, new_value, changed_by, timestamp)
             SELECT 'audit-namespace-backfill-history:' || hex(change.object_id), change.object_id,
                    '_namespace', COALESCE(NULLIF(change.new_value, ''), change.old_value), '',
                    'migration', change.timestamp
             FROM sekai_object_changes change
             WHERE change.field = 'namespace'
               AND COALESCE(NULLIF(change.new_value, ''), change.old_value) <> ''
               AND NOT EXISTS (
                   SELECT 1 FROM sekai_object_changes newer
                   WHERE newer.object_id = change.object_id
                     AND newer.field = 'namespace'
                     AND (newer.timestamp > change.timestamp
                          OR (newer.timestamp = change.timestamp AND newer.rowid > change.rowid))
               )
               AND NOT EXISTS (
                   SELECT 1 FROM sekai_object_changes marker
                   WHERE marker.object_id = change.object_id AND marker.field = '_namespace'
               );",
        )
        .map_err(|error| error.to_string())?;
        let tombstone_backfill_pending: bool = conn
            .query_row(
                "SELECT NOT EXISTS(
                    SELECT 1 FROM sekai_schema_migrations
                    WHERE name='audit_lifecycle_tombstones_v1'
                )",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !added_lifecycle_column && !tombstone_backfill_pending {
            return Ok(());
        }
        let legacy = {
            let mut stmt = conn
                .prepare("SELECT id,evidence FROM sekai_decisions")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, evidence) in legacy {
            let evidence: HashMap<String, String> =
                serde_json::from_str(&evidence).unwrap_or_default();
            let erasure_tombstone = evidence
                .get("erasure_tombstone")
                .is_some_and(|value| value == "true");
            if !added_lifecycle_column && !erasure_tombstone {
                continue;
            }
            let namespace = evidence
                .get("namespace")
                .or_else(|| evidence.get("project"))
                .cloned()
                .unwrap_or_default();
            let data_class = evidence
                .get("data_class")
                .cloned()
                .unwrap_or_else(|| "unclassified".into());
            conn.execute(
                "UPDATE sekai_decisions SET namespace=?1,data_class=?2 WHERE id=?3",
                params![namespace, data_class, id],
            )
            .map_err(|e| e.to_string())?;
        }
        conn.execute(
            "INSERT OR IGNORE INTO sekai_schema_migrations(name)
             VALUES ('audit_lifecycle_tombstones_v1')",
            [],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn record_decision(&self, d: &Decision) -> Result<(), String> {
        validate_decision(d)?;
        let conn = self.conn();
        crate::sekai::ledger::insert_chained_decision(&conn, d)
    }

    pub fn record_decisions(&self, decisions: &[Decision]) -> Result<(), String> {
        if decisions.is_empty() {
            return Ok(());
        }
        for decision in decisions {
            validate_decision(decision)?;
        }
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        for decision in decisions {
            crate::sekai::ledger::insert_chained_decision(&transaction, decision)?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String> {
        self.record_decisions_idempotently_by(decisions, |existing, requested| {
            existing == requested
        })
    }

    pub fn record_decisions_idempotently_by(
        &self,
        decisions: &[Decision],
        equivalent: impl Fn(&Decision, &Decision) -> bool,
    ) -> Result<(), String> {
        if decisions.is_empty() {
            return Ok(());
        }
        for decision in decisions {
            validate_decision(decision)?;
        }
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        for decision in decisions {
            let existing = transaction
                .query_row(
                    "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                     FROM sekai_decisions WHERE id=?1",
                    params![decision.id],
                    |row| {
                        let evidence: String = row.get(5)?;
                        Ok(Decision {
                            id: row.get(0)?,
                            timestamp: row.get(1)?,
                            actor: row.get(2)?,
                            action: row.get(3)?,
                            reason: row.get(4)?,
                            evidence: serde_json::from_str(&evidence).map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    5,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                            target_id: row.get(6)?,
                            outcome: row.get(7)?,
                        })
                    },
                )
                .optional()
                .map_err(|error| error.to_string())?;
            match existing {
                Some(existing) if equivalent(&existing, decision) => continue,
                Some(_) => {
                    return Err(format!(
                        "conflicting audit decision already exists for {}",
                        decision.id
                    ));
                }
                None => crate::sekai::ledger::insert_chained_decision(&transaction, decision)?,
            }
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn get_decision(&self, id: &str) -> Result<Option<Decision>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome FROM sekai_decisions WHERE id = ?1",
            params![id],
            |row| {
                let decision_id: String = row.get(0)?;
                let ev_str: String = row.get(5)?;
                let evidence = serde_json::from_str(&ev_str).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok(Decision {
                    id: decision_id,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    reason: row.get(4)?,
                    evidence,
                    target_id: row.get(6)?,
                    outcome: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
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
        if let Some(t) = &f.target_id {
            sql.push_str(" AND target_id = ?");
            params.push(Box::new(t.clone()));
        }
        if f.after > 0 {
            sql.push_str(" AND timestamp > ?");
            params.push(Box::new(f.after));
        }
        // Decisions can share a millisecond timestamp. `rowid` preserves
        // insertion order so consumers reading the latest signal cannot pick
        // an older same-millisecond decision nondeterministically.
        sql.push_str(" ORDER BY timestamp DESC, rowid DESC");
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
            let id: String = row.get(0).map_err(|e| e.to_string())?;
            let evidence = serde_json::from_str(&ev_str)
                .map_err(|error| format!("corrupt decision evidence for {id}: {error}"))?;
            results.push(Decision {
                id,
                timestamp: row.get(1).map_err(|e| e.to_string())?,
                actor: row.get(2).map_err(|e| e.to_string())?,
                action: row.get(3).map_err(|e| e.to_string())?,
                reason: row.get(4).map_err(|e| e.to_string())?,
                evidence,
                target_id: row.get(6).map_err(|e| e.to_string())?,
                outcome: row.get(7).map_err(|e| e.to_string())?,
            });
        }
        Ok(results)
    }

    /// Decisions for a namespace overlapping `[start, end)`, filtered in SQL
    /// before the limit so other tenants cannot crowd out the window.
    pub fn list_compliance_decisions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<Decision>, String> {
        // Callers may pass max+1 to detect overflow; allow that sentinel.
        let limit = limit.min(10_001) as i64;
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                 FROM sekai_decisions
                 WHERE timestamp >= ?1 AND timestamp < ?2
                   AND json_valid(evidence)
                   AND (
                     json_extract(evidence, '$.namespace') = ?3
                     OR json_extract(evidence, '$.project') = ?3
                   )
                 ORDER BY timestamp ASC, rowid ASC
                 LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![start_timestamp_ms, end_timestamp_ms, namespace, limit],
                |row| {
                    let evidence: String = row.get(5)?;
                    Ok(Decision {
                        id: row.get(0)?,
                        timestamp: row.get(1)?,
                        actor: row.get(2)?,
                        action: row.get(3)?,
                        reason: row.get(4)?,
                        evidence: serde_json::from_str(&evidence).unwrap_or_default(),
                        target_id: row.get(6)?,
                        outcome: row.get(7)?,
                    })
                },
            )
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    pub fn list_decisions_for_action_namespace(
        &self,
        action: &str,
        namespace: &str,
    ) -> Result<Vec<Decision>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                 FROM sekai_decisions
                 WHERE action=?1 AND namespace=?2
                 ORDER BY timestamp DESC, rowid DESC",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![action, namespace], |row| {
                let evidence: String = row.get(5)?;
                Ok(Decision {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    reason: row.get(4)?,
                    evidence: serde_json::from_str(&evidence).unwrap_or_default(),
                    target_id: row.get(6)?,
                    outcome: row.get(7)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    /// Load only decisions attributable to one work unit or one of its model
    /// requests. Evidence is JSON, so filtering here avoids materializing the
    /// entire durable audit ledger in report processes.
    pub fn list_work_unit_decisions(
        &self,
        work_unit_id: &str,
        request_ids: &BTreeSet<String>,
    ) -> Result<Vec<Decision>, String> {
        let conn = self.conn();
        let mut sql = "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome FROM sekai_decisions WHERE json_valid(evidence) AND (json_extract(evidence, '$.work_unit') = ? OR json_extract(evidence, '$.work_unit_id') = ? OR (json_extract(evidence, '$.scope_kind') = 'work_unit' AND substr(json_extract(evidence, '$.budget_subject'), -length(?)) = ?)".to_string();
        let budget_suffix = format!("/work_unit:{work_unit_id}");
        let mut values: Vec<String> = vec![
            work_unit_id.into(),
            work_unit_id.into(),
            budget_suffix.clone(),
            budget_suffix,
        ];
        if !request_ids.is_empty() {
            sql.push_str(" OR json_extract(evidence, '$.request_id') IN (");
            sql.push_str(&vec!["?"; request_ids.len()].join(","));
            sql.push_str(") OR (actor IN ('chisei.egress','chisei.privacy','chisei.sampling') AND target_id IN (");
            sql.push_str(&vec!["?"; request_ids.len()].join(","));
            sql.push_str("))");
            values.extend(request_ids.iter().cloned());
            values.extend(request_ids.iter().cloned());
        }
        sql.push_str(") ORDER BY timestamp ASC, rowid ASC");
        let refs = values
            .iter()
            .map(|value| value as &dyn rusqlite::types::ToSql)
            .collect::<Vec<_>>();
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(refs.as_slice(), |row| {
                let evidence: String = row.get(5)?;
                Ok(Decision {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    reason: row.get(4)?,
                    evidence: serde_json::from_str(&evidence).unwrap_or_default(),
                    target_id: row.get(6)?,
                    outcome: row.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
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
        if object.id.starts_with("namespace:") && object.kind != "namespace" {
            return Err("namespace:* object IDs are reserved for namespace boundaries".into());
        }
        if object.external_id.starts_with("namespace:") && object.kind != "namespace" {
            return Err("namespace:* external IDs are reserved for namespace boundaries".into());
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let historical_changes: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sekai_object_changes WHERE object_id = ?1",
                params![object.id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if historical_changes > 0 {
            return Err("object IDs with audit history cannot be reused".into());
        }
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
        if object.external_id.starts_with("namespace:") && object.kind != "namespace" {
            return Err("namespace:* external IDs are reserved for namespace boundaries".into());
        }
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
        if before_object.namespace != object.namespace {
            return Err("object namespace is immutable".into());
        }
        if before_object.kind != object.kind {
            crate::sekai::ontology::validate_object_kind_change(&tx, &object.id, &object.kind)?;
        }
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
                &object_diff_changes(
                    actor,
                    Some(before),
                    None,
                    chrono::Utc::now().timestamp_millis(),
                ),
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

    pub fn list_visible_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        let conn = self.conn();
        let effective_limit = if limit > 0 { limit } else { 100 };
        let sql = "SELECT id,object_id,field,old_value,new_value,changed_by,timestamp FROM sekai_object_changes WHERE object_id=?1 AND field <> '_namespace' ORDER BY timestamp DESC, rowid DESC LIMIT ?2 OFFSET ?3";
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id, effective_limit, offset], |row| {
                Ok(ObjectChange {
                    id: row.get(0)?,
                    object_id: row.get(1)?,
                    field: row.get(2)?,
                    old_value: row.get(3)?,
                    new_value: row.get(4)?,
                    changed_by: row.get(5)?,
                    timestamp: row.get(6)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
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

    pub fn object_change_namespace(&self, object_id: &str) -> Result<Option<String>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT old_value FROM sekai_object_changes
             WHERE object_id = ?1 AND field = '_namespace'
             ORDER BY timestamp DESC, rowid DESC LIMIT 1",
            params![object_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map(|value| value.filter(|namespace| !namespace.is_empty()))
        .map_err(|e| e.to_string())
    }

    pub fn purge_old_records(&self, before: i64) -> Result<i32, String> {
        // Decisions are hash-chained: only a contiguous old prefix is purged
        // and its head is anchored so the remaining chain stays verifiable.
        let n1 = self.purge_decisions_with_anchor(before)?;
        let conn = self.conn();
        // Attestations follow their decision: once the decision is purged,
        // keeping the attestation would only make legitimately retired
        // history verify as tampering (and grow the table without bound).
        let n2 = conn
            .execute(
                "DELETE FROM sekai_attestations \
                 WHERE decision_id NOT IN (SELECT id FROM sekai_decisions)",
                [],
            )
            .map_err(|e| e.to_string())?;
        let n3 = conn
            .execute(
                "DELETE FROM sekai_object_changes WHERE timestamp < ?1",
                params![before],
            )
            .map_err(|e| e.to_string())?;
        Ok(n1 + (n2 + n3) as i32)
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

    fn setup() -> RuntimeDb {
        RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()))
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
    fn persists_decision_lifecycle_classification_from_evidence() {
        let db = setup();
        db.record_decision(&Decision {
            id: "classified".into(),
            timestamp: 1,
            actor: "actor".into(),
            action: "test".into(),
            reason: String::new(),
            evidence: HashMap::from([
                ("project".into(), "namespace-a".into()),
                ("data_class".into(), "sensitive".into()),
            ]),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();

        let stored: (String, String) = db
            .conn()
            .query_row(
                "SELECT namespace,data_class FROM sekai_decisions WHERE id='classified'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, ("namespace-a".into(), "sensitive".into()));
    }

    #[test]
    fn one_time_migration_normalizes_legacy_tombstone_projections() {
        let db = setup();
        db.record_decision(&Decision {
            id: "erased".into(),
            timestamp: 1,
            actor: "actor".into(),
            action: "test".into(),
            reason: String::new(),
            evidence: HashMap::from([
                ("project".into(), "namespace-a".into()),
                ("data_class".into(), "sensitive".into()),
            ]),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();
        let tombstone = serde_json::to_string(&HashMap::from([(
            "erasure_tombstone".to_string(),
            "true".to_string(),
        )]))
        .unwrap();
        db.conn()
            .execute(
                "UPDATE sekai_decisions SET evidence=?1 WHERE id='erased'",
                params![tombstone],
            )
            .unwrap();
        db.conn()
            .execute(
                "DELETE FROM sekai_schema_migrations
                 WHERE name='audit_lifecycle_tombstones_v1'",
                [],
            )
            .unwrap();

        db.migrate_audit().unwrap();

        let stored: (String, String) = db
            .conn()
            .query_row(
                "SELECT namespace,data_class FROM sekai_decisions WHERE id='erased'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, (String::new(), "unclassified".into()));
    }

    #[test]
    fn completed_migration_preserves_tombstone_tamper_evidence() {
        let db = setup();
        db.record_decision(&Decision {
            id: "erased".into(),
            timestamp: 1,
            actor: "actor".into(),
            action: "test".into(),
            reason: String::new(),
            evidence: HashMap::from([("erasure_tombstone".into(), "true".into())]),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();
        db.conn()
            .execute(
                "UPDATE sekai_decisions
                 SET namespace='namespace-a',data_class='sensitive'
                 WHERE id='erased'",
                [],
            )
            .unwrap();

        db.migrate_audit().unwrap();

        let stored: (String, String) = db
            .conn()
            .query_row(
                "SELECT namespace,data_class FROM sekai_decisions WHERE id='erased'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, ("namespace-a".into(), "sensitive".into()));
        assert!(!db.verify_ledger().unwrap().ok);
    }

    #[test]
    fn migration_preserves_projection_tamper_evidence() {
        let db = setup();
        db.record_decision(&Decision {
            id: "classified".into(),
            timestamp: 1,
            actor: "actor".into(),
            action: "test".into(),
            reason: String::new(),
            evidence: HashMap::from([
                ("project".into(), "namespace-a".into()),
                ("data_class".into(), "sensitive".into()),
            ]),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();
        db.conn()
            .execute(
                "UPDATE sekai_decisions SET namespace='' WHERE id='classified'",
                [],
            )
            .unwrap();

        db.migrate_audit().unwrap();

        let stored_namespace: String = db
            .conn()
            .query_row(
                "SELECT namespace FROM sekai_decisions WHERE id='classified'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored_namespace.is_empty());
        assert!(!db.verify_ledger().unwrap().ok);
    }

    #[test]
    fn decisions_with_equal_timestamps_return_newest_insertion_first() {
        let db = setup();
        for id in ["older", "newer"] {
            db.record_decision(&Decision {
                id: id.into(),
                timestamp: 100,
                actor: "chisei.scoring".into(),
                action: "scored".into(),
                reason: String::new(),
                evidence: HashMap::new(),
                target_id: "acme".into(),
                outcome: "stable".into(),
            })
            .unwrap();
        }
        let decisions = db.list_decisions(&DecisionFilter::default()).unwrap();
        assert_eq!(decisions[0].id, "newer");
        assert_eq!(decisions[1].id, "older");
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
            2
        );

        let changes = db.list_object_changes("o1", 10, 0).unwrap();
        assert_eq!(changes[0].field, "_namespace");
        assert_eq!(changes[0].old_value, "default");
        assert_eq!(changes[1].field, "_deleted");
        assert_eq!(changes[1].old_value, "component/api");
        assert_eq!(changes[2].field, "_created");
        assert_eq!(changes[2].new_value, "component/api");
        let visible = db.list_visible_object_changes("o1", 1, 0).unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].field, "_deleted");
        let next_visible = db.list_visible_object_changes("o1", 1, 1).unwrap();
        assert_eq!(next_visible.len(), 1);
        assert_eq!(next_visible[0].field, "_created");
        assert_eq!(
            db.object_change_namespace("o1").unwrap().as_deref(),
            Some("default")
        );
        assert!(changes.iter().all(|change| change.changed_by == "tester"));
    }

    #[test]
    fn audited_object_ids_and_namespaces_are_immutable() {
        let db = setup();
        let original = object("stable-id", "api", "alpha", "api:stable", HashMap::new());
        db.create_object_with_audit(&original, "tester").unwrap();

        let mut moved = original.clone();
        moved.namespace = "beta".into();
        assert_eq!(
            db.update_object_with_audit(&moved, "tester").unwrap_err(),
            "object namespace is immutable"
        );

        db.delete_object_with_audit(&original.id, "tester").unwrap();
        assert_eq!(
            db.create_object_with_audit(&original, "tester")
                .unwrap_err(),
            "object IDs with audit history cannot be reused"
        );
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
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_changes", []).unwrap();
        }
        let obj = object("o1", "api", "default", "ext-1", HashMap::new());

        assert!(record_object_diff(&db, "tester", None, Some(&obj)).is_err());
    }

    #[test]
    fn migration_recovers_deleted_object_namespaces_from_legacy_changes() {
        let db = setup();
        db.record_object_change(&ObjectChange {
            id: "legacy-namespace".into(),
            object_id: "deleted-object".into(),
            field: "namespace".into(),
            old_value: String::new(),
            new_value: "acme".into(),
            changed_by: "alice".into(),
            timestamp: 1,
        })
        .unwrap();
        db.record_object_change(&ObjectChange {
            id: "legacy-deleted".into(),
            object_id: "deleted-object".into(),
            field: "_deleted".into(),
            old_value: "component/api".into(),
            new_value: String::new(),
            changed_by: "alice".into(),
            timestamp: 2,
        })
        .unwrap();

        db.migrate_audit().unwrap();

        assert_eq!(
            db.object_change_namespace("deleted-object").unwrap(),
            Some("acme".into())
        );
    }

    #[test]
    fn work_unit_query_skips_malformed_unrelated_evidence() {
        let db = setup();
        db.record_decision(&Decision {
            id: "malformed".into(),
            timestamp: 1,
            actor: "actor".into(),
            action: "action".into(),
            reason: String::new(),
            evidence: HashMap::new(),
            target_id: String::new(),
            outcome: "allowed".into(),
        })
        .unwrap();
        {
            let conn = db.conn();
            conn.execute(
                "UPDATE sekai_decisions SET evidence='not json' WHERE id='malformed'",
                [],
            )
            .unwrap();
        }

        assert!(
            db.list_work_unit_decisions("task", &BTreeSet::new())
                .unwrap()
                .is_empty()
        );
    }
}

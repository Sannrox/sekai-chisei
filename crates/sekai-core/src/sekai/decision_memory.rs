//! Decision memory for parked Action reviews (#1465).
//!
//! Each grant or deny stores structured reasoning. Later parked instances of
//! the same type see similar past decisions the reviewer is allowed to read.

use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionMemory {
    pub memory_id: String,
    pub namespace: String,
    pub type_id: String,
    pub version: String,
    pub instance_id: String,
    pub outcome: String,
    pub reason: String,
    #[serde(default)]
    pub conditions_json: String,
    #[serde(default)]
    pub facts_json: String,
    pub decided_by: String,
    pub decided_at_ms: i64,
    #[serde(default)]
    pub superseded: bool,
    #[serde(default)]
    pub parameters_json: String,
}

fn parameter_keys(parameters_json: &str) -> Vec<String> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str(parameters_json) else {
        return Vec::new();
    };
    let mut keys: Vec<String> = map.keys().cloned().collect();
    keys.sort();
    keys
}

/// Two parameter objects are similar when they share a key and, when both
/// have `object_id`, that id matches. Empty objects are not similar.
pub fn similar_parameters(left: &str, right: &str) -> bool {
    let left_keys = parameter_keys(left);
    let right_keys = parameter_keys(right);
    if left_keys.is_empty() || right_keys.is_empty() {
        return false;
    }
    if !left_keys.iter().any(|key| right_keys.contains(key)) {
        return false;
    }
    let left_obj = serde_json::from_str::<serde_json::Value>(left)
        .ok()
        .and_then(|value| {
            value
                .get("object_id")
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        });
    let right_obj = serde_json::from_str::<serde_json::Value>(right)
        .ok()
        .and_then(|value| {
            value
                .get("object_id")
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        });
    match (left_obj, right_obj) {
        (Some(left_id), Some(right_id)) => left_id == right_id,
        _ => true,
    }
}

impl SekaiDb {
    pub fn migrate_decision_memory(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_action_decision_memory (
                    memory_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    type_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    decided_at_ms INTEGER NOT NULL,
                    body_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_decision_memory_type
                    ON sekai_action_decision_memory(namespace, type_id, decided_at_ms DESC);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn put_decision_memory(&self, memory: &DecisionMemory) -> Result<(), String> {
        self.migrate_decision_memory()?;
        let body = serde_json::to_string(memory).map_err(|error| error.to_string())?;
        self.conn()
            .execute(
                "INSERT INTO sekai_action_decision_memory
                 (memory_id, namespace, type_id, instance_id, decided_at_ms, body_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(memory_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    type_id = excluded.type_id,
                    instance_id = excluded.instance_id,
                    decided_at_ms = excluded.decided_at_ms,
                    body_json = excluded.body_json",
                params![
                    memory.memory_id,
                    memory.namespace,
                    memory.type_id,
                    memory.instance_id,
                    memory.decided_at_ms,
                    body,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_decision_memory(
        &self,
        namespace: &str,
        type_id: &str,
    ) -> Result<Vec<DecisionMemory>, String> {
        self.list_decision_memory_page(namespace, type_id, 0, i64::MAX)
    }

    pub fn list_decision_memory_page(
        &self,
        namespace: &str,
        type_id: &str,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<DecisionMemory>, String> {
        self.migrate_decision_memory()?;
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT body_json FROM sekai_action_decision_memory
                 WHERE namespace = ?1 AND type_id = ?2
                 ORDER BY decided_at_ms DESC
                 LIMIT ?3 OFFSET ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, type_id, limit, offset], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body = row.map_err(|error| error.to_string())?;
            out.push(
                serde_json::from_str(&body)
                    .map_err(|error| format!("corrupt decision memory: {error}"))?,
            );
        }
        Ok(out)
    }

    pub fn get_decision_memory(&self, memory_id: &str) -> Result<Option<DecisionMemory>, String> {
        self.migrate_decision_memory()?;
        let body: Option<String> = {
            let conn = self.conn();
            conn.query_row(
                "SELECT body_json FROM sekai_action_decision_memory WHERE memory_id = ?1",
                params![memory_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
        };
        body.map(|body| serde_json::from_str(&body).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn mark_decision_memory_superseded(&self, memory_id: &str) -> Result<bool, String> {
        let Some(mut memory) = self.get_decision_memory(memory_id)? else {
            return Ok(false);
        };
        memory.superseded = true;
        self.put_decision_memory(&memory)?;
        Ok(true)
    }
}

pub const MAX_PRECEDENTS: usize = 20;
/// Newest rows inspected on `GetActionInstance` before giving up.
pub const MAX_SCAN_ROWS: i64 = 256;

pub fn precedents_for(
    memories: &[DecisionMemory],
    namespace: &str,
    type_id: &str,
    parameters_json: &str,
    readable_instances: &[String],
) -> Vec<DecisionMemory> {
    memories
        .iter()
        .filter(|memory| {
            memory.namespace == namespace
                && memory.type_id == type_id
                && similar_parameters(&memory.parameters_json, parameters_json)
                && readable_instances
                    .iter()
                    .any(|id| id == &memory.instance_id)
        })
        .take(MAX_PRECEDENTS)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory(id: &str, instance: &str, params: &str, superseded: bool) -> DecisionMemory {
        DecisionMemory {
            memory_id: id.into(),
            namespace: "acme".into(),
            type_id: "spend".into(),
            version: "1".into(),
            instance_id: instance.into(),
            outcome: "deny".into(),
            reason: "over threshold".into(),
            conditions_json: String::new(),
            facts_json: r#"{"object_id":"rec-1"}"#.into(),
            decided_by: "bob".into(),
            decided_at_ms: 10,
            superseded,
            parameters_json: params.into(),
        }
    }

    #[test]
    fn similar_actions_share_object_id() {
        assert!(similar_parameters(
            r#"{"object_id":"rec-1","amount":10}"#,
            r#"{"object_id":"rec-1","amount":99}"#
        ));
        assert!(!similar_parameters(
            r#"{"object_id":"rec-1","amount":10}"#,
            r#"{"object_id":"rec-2","amount":10}"#
        ));
        assert!(!similar_parameters("{}", r#"{"object_id":"rec-1"}"#));
    }

    #[test]
    fn precedents_filter_unrelated_and_unreadable() {
        let memories = vec![
            memory("m1", "ai-1", r#"{"object_id":"rec-1"}"#, false),
            memory("m2", "ai-2", r#"{"object_id":"rec-1"}"#, true),
            memory("m3", "ai-3", r#"{"object_id":"rec-9"}"#, false),
        ];
        let shown = precedents_for(
            &memories,
            "acme",
            "spend",
            r#"{"object_id":"rec-1"}"#,
            &["ai-1".into(), "ai-2".into()],
        );
        assert_eq!(shown.len(), 2);
        assert!(shown.iter().any(|row| row.instance_id == "ai-1"));
        assert!(
            shown
                .iter()
                .any(|row| row.superseded && row.instance_id == "ai-2")
        );
        assert!(!shown.iter().any(|row| row.instance_id == "ai-3"));
    }

    #[test]
    fn sqlite_round_trip_and_supersede() {
        let db = SekaiDb::new(":memory:").unwrap();
        let row = memory("m1", "ai-1", r#"{"object_id":"rec-1"}"#, false);
        db.put_decision_memory(&row).unwrap();
        let listed = db.list_decision_memory("acme", "spend").unwrap();
        assert_eq!(listed, vec![row]);
        assert!(db.mark_decision_memory_superseded("m1").unwrap());
        assert!(db.list_decision_memory("acme", "spend").unwrap()[0].superseded);
        let mut newer = memory("m2", "ai-2", r#"{"object_id":"rec-1"}"#, false);
        newer.decided_at_ms = 20;
        db.put_decision_memory(&newer).unwrap();
        assert_eq!(
            db.list_decision_memory_page("acme", "spend", 0, 1).unwrap()[0].memory_id,
            "m2"
        );
        assert_eq!(
            db.list_decision_memory_page("acme", "spend", 1, 1).unwrap()[0].memory_id,
            "m1"
        );
    }
}

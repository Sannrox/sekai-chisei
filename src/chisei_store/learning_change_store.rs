//! SQLite persistence for governed learning changes (#714).

use rusqlite::{OptionalExtension, params};

use crate::chisei::learning_change::LearningChange;
use crate::db::sekai::SekaiDb;

pub trait LearningChangeStoreSekaiDbExt {
    fn put_learning_change(&self, record: &LearningChange) -> Result<(), String>;

    fn get_learning_change(&self, change_id: &str) -> Result<Option<LearningChange>, String>;

    fn list_learning_changes(&self, namespace: Option<&str>)
    -> Result<Vec<LearningChange>, String>;
}

impl LearningChangeStoreSekaiDbExt for SekaiDb {
    fn put_learning_change(&self, record: &LearningChange) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode learning change: {error}"))?;
        self.conn()
            .execute(
                "INSERT INTO chisei_learning_changes
                    (change_id, namespace, learning_id, status, record_json, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(change_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    learning_id = excluded.learning_id,
                    status = excluded.status,
                    record_json = excluded.record_json,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    record.change_id,
                    record.namespace,
                    record.learning_id,
                    record.status,
                    json,
                    record.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn get_learning_change(&self, change_id: &str) -> Result<Option<LearningChange>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM chisei_learning_changes WHERE change_id = ?1",
                params![change_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode learning change: {error}"))
        })
        .transpose()
    }

    fn list_learning_changes(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<LearningChange>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM chisei_learning_changes
                 WHERE (?1 IS NULL OR namespace = ?1)
                 ORDER BY updated_at_ms ASC, learning_id ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut records = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            records.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode learning change: {error}"))?,
            );
        }
        Ok(records)
    }
}

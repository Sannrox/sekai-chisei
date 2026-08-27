//! SQLite persistence for governed data-quality rules and results (#681).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::chisei::data_quality::{DataQualityResult, DataQualityRule};

impl SekaiDb {
    pub(crate) fn migrate_data_quality_rules(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_data_quality_rules (
                    namespace TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_digest TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    published_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (namespace, rule_id)
                );
                CREATE TABLE IF NOT EXISTS chisei_data_quality_results (
                    result_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    evaluated_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_data_quality_results_ns
                    ON chisei_data_quality_results(namespace, rule_id);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn put_data_quality_rule(&self, record: &DataQualityRule) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode data quality rule: {error}"))?;
        self.conn()
            .execute(
                "INSERT INTO chisei_data_quality_rules
                    (namespace, rule_id, rule_digest, record_json, published_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(namespace, rule_id) DO UPDATE SET
                    rule_digest = excluded.rule_digest,
                    record_json = excluded.record_json,
                    published_at_ms = excluded.published_at_ms",
                params![
                    record.namespace,
                    record.rule_id,
                    record.rule_digest,
                    json,
                    record.published_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_data_quality_rule(
        &self,
        namespace: &str,
        rule_id: &str,
    ) -> Result<Option<DataQualityRule>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM chisei_data_quality_rules
                 WHERE namespace = ?1 AND rule_id = ?2",
                params![namespace, rule_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode data quality rule: {error}"))
        })
        .transpose()
    }

    pub fn list_data_quality_rules(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<DataQualityRule>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM chisei_data_quality_rules
                 WHERE (?1 IS NULL OR namespace = ?1)
                 ORDER BY published_at_ms ASC, rule_id ASC",
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
                    .map_err(|error| format!("decode data quality rule: {error}"))?,
            );
        }
        Ok(records)
    }

    pub fn put_data_quality_result(&self, record: &DataQualityResult) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode data quality result: {error}"))?;
        self.conn()
            .execute(
                "INSERT INTO chisei_data_quality_results
                    (result_id, namespace, rule_id, status, record_json, evaluated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(result_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    rule_id = excluded.rule_id,
                    status = excluded.status,
                    record_json = excluded.record_json,
                    evaluated_at_ms = excluded.evaluated_at_ms",
                params![
                    record.result_id,
                    record.namespace,
                    record.rule_id,
                    record.status,
                    json,
                    record.evaluated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_data_quality_result(
        &self,
        result_id: &str,
    ) -> Result<Option<DataQualityResult>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM chisei_data_quality_results WHERE result_id = ?1",
                params![result_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode data quality result: {error}"))
        })
        .transpose()
    }

    pub fn list_data_quality_results(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<DataQualityResult>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM chisei_data_quality_results
                 WHERE (?1 IS NULL OR namespace = ?1)
                 ORDER BY evaluated_at_ms ASC, rule_id ASC",
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
                    .map_err(|error| format!("decode data quality result: {error}"))?,
            );
        }
        Ok(records)
    }
}

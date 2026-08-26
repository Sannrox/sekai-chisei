//! SQLite persistence for source-webhook verifying keys (#673).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::source_webhook::SourceWebhookKeyPin;

impl SekaiDb {
    pub fn put_source_webhook_key(&self, pin: &SourceWebhookKeyPin) -> Result<(), String> {
        let json = serde_json::to_string(pin)
            .map_err(|error| format!("encode source webhook key: {error}"))?;
        self.conn()
            .execute(
                "INSERT INTO sekai_source_webhook_keys
                    (pin_id, namespace, source_instance, key_id, record_json, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(pin_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    source_instance = excluded.source_instance,
                    key_id = excluded.key_id,
                    record_json = excluded.record_json,
                    enabled = excluded.enabled",
                params![
                    pin.pin_id,
                    pin.namespace,
                    pin.source_instance,
                    pin.key_id,
                    json,
                    i64::from(pin.enabled),
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_source_webhook_key(
        &self,
        namespace: &str,
        source_instance: &str,
        key_id: &str,
    ) -> Result<Option<SourceWebhookKeyPin>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_source_webhook_keys
                 WHERE namespace = ?1 AND source_instance = ?2 AND key_id = ?3",
                params![namespace, source_instance, key_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode source webhook key: {error}"))
        })
        .transpose()
    }

    pub fn list_source_webhook_keys(
        &self,
        namespace: Option<&str>,
        source_instance: Option<&str>,
    ) -> Result<Vec<SourceWebhookKeyPin>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_source_webhook_keys
                 WHERE (?1 IS NULL OR namespace = ?1)
                   AND (?2 IS NULL OR source_instance = ?2)
                 ORDER BY pin_id ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, source_instance], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        let mut pins = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            pins.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode source webhook key: {error}"))?,
            );
        }
        Ok(pins)
    }
}

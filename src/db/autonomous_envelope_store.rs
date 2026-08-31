//! SQLite persistence for autonomous envelopes (#715).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::autonomous_envelope::{AUTONOMY_UNAVAILABLE, AutonomousEnvelope};

impl SekaiDb {
    pub fn get_autonomous_envelope(
        &self,
        namespace: &str,
        envelope_id: &str,
    ) -> Result<Option<AutonomousEnvelope>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_autonomous_envelopes
                 WHERE namespace = ?1 AND envelope_id = ?2",
                params![namespace, envelope_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode autonomous envelope: {error}"))
        })
        .transpose()
    }

    pub fn put_autonomous_envelope(&self, envelope: &AutonomousEnvelope) -> Result<(), String> {
        let json = serde_json::to_string(envelope)
            .map_err(|error| format!("encode autonomous envelope: {error}"))?;
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_autonomous_envelopes
                    (namespace, envelope_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, envelope_id) DO NOTHING",
                params![
                    envelope.namespace,
                    envelope.envelope_id,
                    envelope.owner,
                    json
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(AUTONOMY_UNAVAILABLE.into());
        }
        Ok(())
    }

    pub fn cas_autonomous_envelope(
        &self,
        expected: &AutonomousEnvelope,
        next: &AutonomousEnvelope,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.envelope_id != next.envelope_id
            || expected.owner != next.owner
        {
            return Err(AUTONOMY_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode autonomous envelope: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT record_json FROM sekai_autonomous_envelopes
                 WHERE namespace = ?1 AND envelope_id = ?2",
                params![expected.namespace, expected.envelope_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current: AutonomousEnvelope =
            serde_json::from_str(&current.ok_or(AUTONOMY_UNAVAILABLE)?)
                .map_err(|error| format!("decode autonomous envelope: {error}"))?;
        if current != *expected {
            return Err(AUTONOMY_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_autonomous_envelopes
                 SET record_json = ?1
                 WHERE namespace = ?2 AND envelope_id = ?3 AND owner = ?4",
                params![next_json, next.namespace, next.envelope_id, next.owner],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(AUTONOMY_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

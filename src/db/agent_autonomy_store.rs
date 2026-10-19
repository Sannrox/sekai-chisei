//! SQLite persistence for gradual agent autonomy grants (#1469).

use rusqlite::{Connection, OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::agent_autonomy::{AgentAutonomyGrant, CONCURRENT_CHANGE, STATUS_LIVE_GRANT};
use crate::sekai::audit::Decision;

impl SekaiDb {
    fn migrate_agent_autonomy(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_agent_autonomy (
                    namespace TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    type_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, principal, type_id)
                );",
            )
            .map_err(|error| error.to_string())
    }

    pub fn get_agent_autonomy(
        &self,
        namespace: &str,
        principal: &str,
        type_id: &str,
    ) -> Result<Option<AgentAutonomyGrant>, String> {
        self.migrate_agent_autonomy()?;
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_agent_autonomy
                 WHERE namespace = ?1 AND principal = ?2 AND type_id = ?3",
                params![namespace, principal, type_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode agent autonomy: {error}"))
        })
        .transpose()
    }

    pub fn put_agent_autonomy(&self, grant: &AgentAutonomyGrant) -> Result<(), String> {
        self.migrate_agent_autonomy()?;
        let json = encode_grant(grant)?;
        write_agent_autonomy(&self.conn(), grant, &json)
    }

    pub fn put_agent_autonomy_with_receipt(
        &self,
        grant: &AgentAutonomyGrant,
        decision: &Decision,
    ) -> Result<(), String> {
        crate::sekai::audit::validate_decision(decision)?;
        self.migrate_agent_autonomy()?;
        let json = encode_grant(grant)?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        write_agent_autonomy(&tx, grant, &json)?;
        crate::sekai::ledger::insert_chained_decision(&tx, decision)?;
        tx.commit().map_err(|error| error.to_string())
    }
}

fn encode_grant(grant: &AgentAutonomyGrant) -> Result<String, String> {
    serde_json::to_string(grant).map_err(|error| format!("encode agent autonomy: {error}"))
}

fn write_agent_autonomy(
    conn: &Connection,
    grant: &AgentAutonomyGrant,
    json: &str,
) -> Result<(), String> {
    let changed = if grant.status == STATUS_LIVE_GRANT {
        conn.execute(
            "INSERT INTO sekai_agent_autonomy
                (namespace, principal, type_id, record_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace, principal, type_id) DO UPDATE SET
                record_json = excluded.record_json
             WHERE json_extract(sekai_agent_autonomy.record_json, '$.status')
                   != 'live'
                OR (
                    json_extract(sekai_agent_autonomy.record_json, '$.envelope_id')
                        = json_extract(excluded.record_json, '$.envelope_id')
                    AND json_extract(sekai_agent_autonomy.record_json, '$.granted_at_ms')
                        = json_extract(excluded.record_json, '$.granted_at_ms')
                )",
            params![grant.namespace, grant.principal, grant.type_id, json],
        )
        .map_err(|error| error.to_string())?
    } else {
        conn.execute(
            "UPDATE sekai_agent_autonomy
             SET record_json = ?4
             WHERE namespace = ?1 AND principal = ?2 AND type_id = ?3
               AND json_extract(record_json, '$.status') = 'live'
               AND json_extract(record_json, '$.granted_at_ms') = ?5",
            params![
                grant.namespace,
                grant.principal,
                grant.type_id,
                json,
                grant.granted_at_ms
            ],
        )
        .map_err(|error| error.to_string())?
    };
    if changed == 0 {
        return Err(CONCURRENT_CHANGE.into());
    }
    Ok(())
}

//! SQLite persistence for governed federation revocations (#703).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::federation_revocation::FederationRevocation;

impl SekaiDb {
    pub fn put_federation_revocation(&self, record: &FederationRevocation) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode federation revocation: {error}"))?;
        self.conn()
            .execute(
                "INSERT INTO sekai_federation_revocations
                    (revocation_id, subject_kind, subject_id, status, record_json, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(revocation_id) DO UPDATE SET
                    subject_kind = excluded.subject_kind,
                    subject_id = excluded.subject_id,
                    status = excluded.status,
                    record_json = excluded.record_json,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    record.revocation_id,
                    record.subject_kind.as_str(),
                    record.subject_id,
                    record.status,
                    json,
                    record.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_federation_revocation(
        &self,
        revocation_id: &str,
    ) -> Result<Option<FederationRevocation>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_federation_revocations WHERE revocation_id = ?1",
                params![revocation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode federation revocation: {error}"))
        })
        .transpose()
    }

    pub fn list_federation_revocations(
        &self,
        subject_kind: Option<&str>,
    ) -> Result<Vec<FederationRevocation>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_federation_revocations
                 WHERE (?1 IS NULL OR subject_kind = ?1)
                 ORDER BY updated_at_ms ASC, subject_id ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![subject_kind], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut records = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            records.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode federation revocation: {error}"))?,
            );
        }
        Ok(records)
    }
}

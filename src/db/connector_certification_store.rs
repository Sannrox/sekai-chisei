//! SQLite persistence for connector certifications (#710).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::connector_certification::{CONNECTOR_UNAVAILABLE, ConnectorCertification};

impl SekaiDb {
    pub fn get_connector_certification(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<ConnectorCertification>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_connector_certifications
                 WHERE namespace = ?1 AND certification_id = ?2",
                params![namespace, certification_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode connector certification: {error}"))
        })
        .transpose()
    }

    pub fn list_connector_certifications(
        &self,
        namespace: &str,
    ) -> Result<Vec<ConnectorCertification>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_connector_certifications
                 WHERE namespace = ?1
                 ORDER BY certification_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut certifications = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            certifications.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode connector certification: {error}"))?,
            );
        }
        Ok(certifications)
    }

    pub fn commit_connector_certifications(
        &self,
        certifications: &[&ConnectorCertification],
    ) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        for certification in certifications {
            let json = serde_json::to_string(certification)
                .map_err(|error| format!("encode connector certification: {error}"))?;
            let changed = if certification.superseded_by.is_empty() {
                tx.execute(
                    "INSERT INTO sekai_connector_certifications
                        (namespace, certification_id, owner, record_json)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(namespace, certification_id) DO NOTHING",
                    params![
                        certification.namespace,
                        certification.certification_id,
                        certification.owner,
                        json
                    ],
                )
                .map_err(constraint_unavailable)?
            } else {
                tx.execute(
                    "UPDATE sekai_connector_certifications
                     SET record_json = ?4
                     WHERE namespace = ?1
                       AND certification_id = ?2
                       AND owner = ?3
                       AND json_extract(record_json, '$.superseded_by') = ''",
                    params![
                        certification.namespace,
                        certification.certification_id,
                        certification.owner,
                        json
                    ],
                )
                .map_err(constraint_unavailable)?
            };
            if changed == 0 {
                return Err(CONNECTOR_UNAVAILABLE.into());
            }
        }
        tx.commit().map_err(constraint_unavailable)?;
        Ok(())
    }

    pub fn cas_connector_certification(
        &self,
        expected: &ConnectorCertification,
        next: &ConnectorCertification,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.certification_id != next.certification_id
            || expected.owner != next.owner
        {
            return Err(CONNECTOR_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode connector certification: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT record_json FROM sekai_connector_certifications
                 WHERE namespace = ?1 AND certification_id = ?2",
                params![expected.namespace, expected.certification_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current: ConnectorCertification =
            serde_json::from_str(&current.ok_or(CONNECTOR_UNAVAILABLE)?)
                .map_err(|error| format!("decode connector certification: {error}"))?;
        if current != *expected {
            return Err(CONNECTOR_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_connector_certifications
                 SET record_json = ?1
                 WHERE namespace = ?2 AND certification_id = ?3 AND owner = ?4",
                params![next_json, next.namespace, next.certification_id, next.owner],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(CONNECTOR_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn constraint_unavailable(error: rusqlite::Error) -> String {
    let text = error.to_string();
    if text.to_ascii_lowercase().contains("unique") {
        CONNECTOR_UNAVAILABLE.into()
    } else {
        text
    }
}

//! SQLite persistence for model-platform certifications (#713).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::model_platform::{MODEL_UNAVAILABLE, ModelPlatformCertification};

impl SekaiDb {
    pub fn get_model_platform_certification(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<ModelPlatformCertification>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_model_platform_certifications
                 WHERE namespace = ?1 AND certification_id = ?2",
                params![namespace, certification_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode model platform certification: {error}"))
        })
        .transpose()
    }

    pub fn put_model_platform_certification(
        &self,
        certification: &ModelPlatformCertification,
    ) -> Result<(), String> {
        let json = serde_json::to_string(certification)
            .map_err(|error| format!("encode model platform certification: {error}"))?;
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_model_platform_certifications
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
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(MODEL_UNAVAILABLE.into());
        }
        Ok(())
    }

    pub fn cas_model_platform_certification(
        &self,
        expected: &ModelPlatformCertification,
        next: &ModelPlatformCertification,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.certification_id != next.certification_id
            || expected.owner != next.owner
        {
            return Err(MODEL_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode model platform certification: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT record_json FROM sekai_model_platform_certifications
                 WHERE namespace = ?1 AND certification_id = ?2",
                params![expected.namespace, expected.certification_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current: ModelPlatformCertification =
            serde_json::from_str(&current.ok_or(MODEL_UNAVAILABLE)?)
                .map_err(|error| format!("decode model platform certification: {error}"))?;
        if current != *expected {
            return Err(MODEL_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_model_platform_certifications
                 SET record_json = ?1
                 WHERE namespace = ?2 AND certification_id = ?3 AND owner = ?4",
                params![next_json, next.namespace, next.certification_id, next.owner],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(MODEL_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

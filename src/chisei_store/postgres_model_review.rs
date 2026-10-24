//! PostgreSQL parity for model review state (#1493).

use crate::chisei::model_review::{FamilyEnablementRecord, ModelReviewRecord};
use crate::db::postgres::PostgresDb;

pub trait PostgresModelReviewPostgresDbExt {
    fn put_model_review_record(&self, record: &ModelReviewRecord) -> Result<(), String>;

    fn insert_model_review_record_if_absent(
        &self,
        record: &ModelReviewRecord,
    ) -> Result<bool, String>;

    fn get_model_review_record(
        &self,
        namespace: &str,
        provider: &str,
        model: &str,
        artifact_digest: &str,
    ) -> Result<Option<ModelReviewRecord>, String>;

    fn list_model_review_records(&self, namespace: &str) -> Result<Vec<ModelReviewRecord>, String>;

    fn put_family_enablement_record(&self, record: &FamilyEnablementRecord) -> Result<(), String>;

    fn insert_family_enablement_record_if_absent(
        &self,
        record: &FamilyEnablementRecord,
    ) -> Result<bool, String>;

    fn get_family_enablement_record(
        &self,
        namespace: &str,
        region_label: &str,
        family_id: &str,
    ) -> Result<Option<FamilyEnablementRecord>, String>;

    fn list_family_enablement_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<FamilyEnablementRecord>, String>;

    fn model_review_row_count(&self) -> Result<i64, String>;

    fn family_enablement_row_count(&self) -> Result<i64, String>;
}

impl PostgresModelReviewPostgresDbExt for PostgresDb {
    fn put_model_review_record(&self, record: &ModelReviewRecord) -> Result<(), String> {
        record.validate()?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_model_review (
                    namespace, provider, model, artifact_digest, status, actor, reason, updated_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (namespace, provider, model, artifact_digest) DO UPDATE SET
                    status = EXCLUDED.status,
                    actor = EXCLUDED.actor,
                    reason = EXCLUDED.reason,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &record.namespace,
                    &record.identity.provider,
                    &record.identity.model,
                    &record.identity.artifact_digest,
                    &record.status.as_str(),
                    &record.actor,
                    &record.reason,
                    &record.updated_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn insert_model_review_record_if_absent(
        &self,
        record: &ModelReviewRecord,
    ) -> Result<bool, String> {
        record.validate()?;
        let inserted = self
            .connection()?
            .execute(
                "INSERT INTO chisei_model_review (
                    namespace, provider, model, artifact_digest, status, actor, reason, updated_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (namespace, provider, model, artifact_digest) DO NOTHING",
                &[
                    &record.namespace,
                    &record.identity.provider,
                    &record.identity.model,
                    &record.identity.artifact_digest,
                    &record.status.as_str(),
                    &record.actor,
                    &record.reason,
                    &record.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(inserted > 0)
    }

    fn get_model_review_record(
        &self,
        namespace: &str,
        provider: &str,
        model: &str,
        artifact_digest: &str,
    ) -> Result<Option<ModelReviewRecord>, String> {
        self.connection()?
            .query_opt(
                "SELECT namespace, provider, model, artifact_digest, status, actor, reason, updated_at_ms
                 FROM chisei_model_review
                 WHERE namespace = $1 AND provider = $2 AND model = $3 AND artifact_digest = $4",
                &[&namespace, &provider, &model, &artifact_digest],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                ModelReviewRecord::from_columns(
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get(3),
                    &row.get::<_, String>(4),
                    row.get(5),
                    row.get(6),
                    row.get(7),
                )
            })
            .transpose()
    }

    fn list_model_review_records(&self, namespace: &str) -> Result<Vec<ModelReviewRecord>, String> {
        self.connection()?
            .query(
                "SELECT namespace, provider, model, artifact_digest, status, actor, reason, updated_at_ms
                 FROM chisei_model_review
                 WHERE namespace = $1
                 ORDER BY provider, model, artifact_digest",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                ModelReviewRecord::from_columns(
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get(3),
                    &row.get::<_, String>(4),
                    row.get(5),
                    row.get(6),
                    row.get(7),
                )
            })
            .collect()
    }

    fn put_family_enablement_record(&self, record: &FamilyEnablementRecord) -> Result<(), String> {
        record.validate()?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_model_family_enablement (
                    namespace, region_label, family_id, status, actor, reason, updated_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (namespace, region_label, family_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    actor = EXCLUDED.actor,
                    reason = EXCLUDED.reason,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &record.namespace,
                    &record.region_label,
                    &record.family_id,
                    &record.status.as_str(),
                    &record.actor,
                    &record.reason,
                    &record.updated_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn insert_family_enablement_record_if_absent(
        &self,
        record: &FamilyEnablementRecord,
    ) -> Result<bool, String> {
        record.validate()?;
        let inserted = self
            .connection()?
            .execute(
                "INSERT INTO chisei_model_family_enablement (
                    namespace, region_label, family_id, status, actor, reason, updated_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (namespace, region_label, family_id) DO NOTHING",
                &[
                    &record.namespace,
                    &record.region_label,
                    &record.family_id,
                    &record.status.as_str(),
                    &record.actor,
                    &record.reason,
                    &record.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(inserted > 0)
    }

    fn get_family_enablement_record(
        &self,
        namespace: &str,
        region_label: &str,
        family_id: &str,
    ) -> Result<Option<FamilyEnablementRecord>, String> {
        self.connection()?
            .query_opt(
                "SELECT namespace, region_label, family_id, status, actor, reason, updated_at_ms
                 FROM chisei_model_family_enablement
                 WHERE namespace = $1 AND region_label = $2 AND family_id = $3",
                &[&namespace, &region_label, &family_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                FamilyEnablementRecord::from_columns(
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    &row.get::<_, String>(3),
                    row.get(4),
                    row.get(5),
                    row.get(6),
                )
            })
            .transpose()
    }

    fn list_family_enablement_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<FamilyEnablementRecord>, String> {
        self.connection()?
            .query(
                "SELECT namespace, region_label, family_id, status, actor, reason, updated_at_ms
                 FROM chisei_model_family_enablement
                 WHERE namespace = $1
                 ORDER BY region_label, family_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                FamilyEnablementRecord::from_columns(
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    &row.get::<_, String>(3),
                    row.get(4),
                    row.get(5),
                    row.get(6),
                )
            })
            .collect()
    }

    fn model_review_row_count(&self) -> Result<i64, String> {
        self.connection()?
            .query_one("SELECT COUNT(*) FROM chisei_model_review", &[])
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }

    fn family_enablement_row_count(&self) -> Result<i64, String> {
        self.connection()?
            .query_one("SELECT COUNT(*) FROM chisei_model_family_enablement", &[])
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }
}

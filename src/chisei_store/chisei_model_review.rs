//! Model review state (#1493) on both community backends.

use crate::chisei::model_review::{FamilyEnablementRecord, ModelReviewRecord};
use crate::chisei_store::postgres_model_review::PostgresModelReviewPostgresDbExt;
use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;

pub trait ChiseiModelReviewBackend: Send + Sync {
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

impl ChiseiModelReviewBackend for SekaiDb {
    fn put_model_review_record(&self, record: &ModelReviewRecord) -> Result<(), String> {
        record.validate()?;
        self.conn()
            .execute(
                "INSERT INTO chisei_model_review (
                    namespace, provider, model, artifact_digest, status, actor, reason, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (namespace, provider, model, artifact_digest) DO UPDATE SET
                    status = excluded.status,
                    actor = excluded.actor,
                    reason = excluded.reason,
                    updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![
                    record.namespace,
                    record.identity.provider,
                    record.identity.model,
                    record.identity.artifact_digest,
                    record.status.as_str(),
                    record.actor,
                    record.reason,
                    record.updated_at_ms,
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
            .conn()
            .execute(
                "INSERT INTO chisei_model_review (
                    namespace, provider, model, artifact_digest, status, actor, reason, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (namespace, provider, model, artifact_digest) DO NOTHING",
                rusqlite::params![
                    record.namespace,
                    record.identity.provider,
                    record.identity.model,
                    record.identity.artifact_digest,
                    record.status.as_str(),
                    record.actor,
                    record.reason,
                    record.updated_at_ms,
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
        self.conn()
            .query_row(
                "SELECT namespace, provider, model, artifact_digest, status, actor, reason, updated_at_ms
                 FROM chisei_model_review
                 WHERE namespace = ?1 AND provider = ?2 AND model = ?3 AND artifact_digest = ?4",
                rusqlite::params![namespace, provider, model, artifact_digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional_mapped()
    }

    fn list_model_review_records(&self, namespace: &str) -> Result<Vec<ModelReviewRecord>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT namespace, provider, model, artifact_digest, status, actor, reason, updated_at_ms
                 FROM chisei_model_review
                 WHERE namespace = ?1
                 ORDER BY provider, model, artifact_digest",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(
                |(
                    namespace,
                    provider,
                    model,
                    artifact_digest,
                    status,
                    actor,
                    reason,
                    updated_at_ms,
                )| {
                    ModelReviewRecord::from_columns(
                        namespace,
                        provider,
                        model,
                        artifact_digest,
                        &status,
                        actor,
                        reason,
                        updated_at_ms,
                    )
                },
            )
            .collect()
    }

    fn put_family_enablement_record(&self, record: &FamilyEnablementRecord) -> Result<(), String> {
        record.validate()?;
        self.conn()
            .execute(
                "INSERT INTO chisei_model_family_enablement (
                    namespace, region_label, family_id, status, actor, reason, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (namespace, region_label, family_id) DO UPDATE SET
                    status = excluded.status,
                    actor = excluded.actor,
                    reason = excluded.reason,
                    updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![
                    record.namespace,
                    record.region_label,
                    record.family_id,
                    record.status.as_str(),
                    record.actor,
                    record.reason,
                    record.updated_at_ms,
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
            .conn()
            .execute(
                "INSERT INTO chisei_model_family_enablement (
                    namespace, region_label, family_id, status, actor, reason, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (namespace, region_label, family_id) DO NOTHING",
                rusqlite::params![
                    record.namespace,
                    record.region_label,
                    record.family_id,
                    record.status.as_str(),
                    record.actor,
                    record.reason,
                    record.updated_at_ms,
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
        self.conn()
            .query_row(
                "SELECT namespace, region_label, family_id, status, actor, reason, updated_at_ms
                 FROM chisei_model_family_enablement
                 WHERE namespace = ?1 AND region_label = ?2 AND family_id = ?3",
                rusqlite::params![namespace, region_label, family_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional_mapped()
    }

    fn list_family_enablement_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<FamilyEnablementRecord>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT namespace, region_label, family_id, status, actor, reason, updated_at_ms
                 FROM chisei_model_family_enablement
                 WHERE namespace = ?1
                 ORDER BY region_label, family_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(
                |(namespace, region_label, family_id, status, actor, reason, updated_at_ms)| {
                    FamilyEnablementRecord::from_columns(
                        namespace,
                        region_label,
                        family_id,
                        &status,
                        actor,
                        reason,
                        updated_at_ms,
                    )
                },
            )
            .collect()
    }

    fn model_review_row_count(&self) -> Result<i64, String> {
        self.conn()
            .query_row("SELECT COUNT(*) FROM chisei_model_review", [], |row| {
                row.get(0)
            })
            .map_err(|error| error.to_string())
    }

    fn family_enablement_row_count(&self) -> Result<i64, String> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM chisei_model_family_enablement",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }
}

trait OptionalMapped<T> {
    fn optional_mapped(self) -> Result<Option<T>, String>;
}

impl OptionalMapped<ModelReviewRecord>
    for Result<(String, String, String, String, String, String, String, i64), rusqlite::Error>
{
    fn optional_mapped(self) -> Result<Option<ModelReviewRecord>, String> {
        match self {
            Ok((
                namespace,
                provider,
                model,
                artifact_digest,
                status,
                actor,
                reason,
                updated_at_ms,
            )) => Ok(Some(ModelReviewRecord::from_columns(
                namespace,
                provider,
                model,
                artifact_digest,
                &status,
                actor,
                reason,
                updated_at_ms,
            )?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }
}

impl OptionalMapped<FamilyEnablementRecord>
    for Result<(String, String, String, String, String, String, i64), rusqlite::Error>
{
    fn optional_mapped(self) -> Result<Option<FamilyEnablementRecord>, String> {
        match self {
            Ok((namespace, region_label, family_id, status, actor, reason, updated_at_ms)) => {
                Ok(Some(FamilyEnablementRecord::from_columns(
                    namespace,
                    region_label,
                    family_id,
                    &status,
                    actor,
                    reason,
                    updated_at_ms,
                )?))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }
}

impl ChiseiModelReviewBackend for PostgresDb {
    fn put_model_review_record(&self, record: &ModelReviewRecord) -> Result<(), String> {
        PostgresModelReviewPostgresDbExt::put_model_review_record(self, record)
    }
    fn insert_model_review_record_if_absent(
        &self,
        record: &ModelReviewRecord,
    ) -> Result<bool, String> {
        PostgresModelReviewPostgresDbExt::insert_model_review_record_if_absent(self, record)
    }
    fn get_model_review_record(
        &self,
        namespace: &str,
        provider: &str,
        model: &str,
        artifact_digest: &str,
    ) -> Result<Option<ModelReviewRecord>, String> {
        PostgresModelReviewPostgresDbExt::get_model_review_record(
            self,
            namespace,
            provider,
            model,
            artifact_digest,
        )
    }
    fn list_model_review_records(&self, namespace: &str) -> Result<Vec<ModelReviewRecord>, String> {
        PostgresModelReviewPostgresDbExt::list_model_review_records(self, namespace)
    }
    fn put_family_enablement_record(&self, record: &FamilyEnablementRecord) -> Result<(), String> {
        PostgresModelReviewPostgresDbExt::put_family_enablement_record(self, record)
    }
    fn insert_family_enablement_record_if_absent(
        &self,
        record: &FamilyEnablementRecord,
    ) -> Result<bool, String> {
        PostgresModelReviewPostgresDbExt::insert_family_enablement_record_if_absent(self, record)
    }
    fn get_family_enablement_record(
        &self,
        namespace: &str,
        region_label: &str,
        family_id: &str,
    ) -> Result<Option<FamilyEnablementRecord>, String> {
        PostgresModelReviewPostgresDbExt::get_family_enablement_record(
            self,
            namespace,
            region_label,
            family_id,
        )
    }
    fn list_family_enablement_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<FamilyEnablementRecord>, String> {
        PostgresModelReviewPostgresDbExt::list_family_enablement_records(self, namespace)
    }
    fn model_review_row_count(&self) -> Result<i64, String> {
        PostgresModelReviewPostgresDbExt::model_review_row_count(self)
    }
    fn family_enablement_row_count(&self) -> Result<i64, String> {
        PostgresModelReviewPostgresDbExt::family_enablement_row_count(self)
    }
}

//! PostgreSQL persistence for source-webhook verifying-key pins (ADR 0035)
//! and registered source-type descriptors (ADR 0060), with the same
//! semantics as the SQLite stores (#1322).

use postgres::GenericClient;

use crate::db::postgres::PostgresDb;
use crate::sekai::source_type_descriptor::{DESCRIPTOR_UNAVAILABLE, StoredSourceTypeDescriptor};
use crate::sekai::source_webhook::SourceWebhookKeyPin;

impl PostgresDb {
    pub fn put_source_webhook_key(&self, pin: &SourceWebhookKeyPin) -> Result<(), String> {
        let json = serde_json::to_string(pin)
            .map_err(|error| format!("encode source webhook key: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_source_webhook_keys
                    (pin_id, namespace, source_instance, key_id, record_json, enabled)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT(pin_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    source_instance = excluded.source_instance,
                    key_id = excluded.key_id,
                    record_json = excluded.record_json,
                    enabled = excluded.enabled",
                &[
                    &pin.pin_id,
                    &pin.namespace,
                    &pin.source_instance,
                    &pin.key_id,
                    &json,
                    &pin.enabled,
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
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_source_webhook_keys
                 WHERE namespace = $1 AND source_instance = $2 AND key_id = $3",
                &[&namespace, &source_instance, &key_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_pin(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_source_webhook_keys(
        &self,
        namespace: Option<&str>,
        source_instance: Option<&str>,
    ) -> Result<Vec<SourceWebhookKeyPin>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_source_webhook_keys
                 WHERE ($1::TEXT IS NULL OR namespace = $1)
                   AND ($2::TEXT IS NULL OR source_instance = $2)
                 ORDER BY pin_id ASC",
                &[&namespace, &source_instance],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| decode_pin(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn get_source_type_descriptor(
        &self,
        namespace: &str,
        digest: &str,
    ) -> Result<Option<StoredSourceTypeDescriptor>, String> {
        get_descriptor(&mut *self.connection()?, namespace, digest, RowLock::None)
    }

    /// Insert-only: an existing digest or a reused identity is unavailable.
    pub fn put_source_type_descriptor(
        &self,
        descriptor: &StoredSourceTypeDescriptor,
    ) -> Result<(), String> {
        let json = serde_json::to_string(descriptor)
            .map_err(|error| format!("encode source-type descriptor: {error}"))?;
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO sekai_source_type_descriptors
                    (namespace, digest, source, record_kind, schema_revision, status, owner, record_json)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT DO NOTHING",
                &[
                    &descriptor.namespace,
                    &descriptor.digest,
                    &descriptor.source,
                    &descriptor.record_kind,
                    &descriptor.schema_revision,
                    &descriptor.status,
                    &descriptor.admitted_by,
                    &json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(DESCRIPTOR_UNAVAILABLE.into());
        }
        Ok(())
    }

    /// Replace `expected` with `next` (status and owner only) under a row lock.
    pub fn cas_source_type_descriptor(
        &self,
        expected: &StoredSourceTypeDescriptor,
        next: &StoredSourceTypeDescriptor,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.digest != next.digest
            || expected.admitted_by != next.admitted_by
            || expected.source != next.source
            || expected.record_kind != next.record_kind
            || expected.schema_revision != next.schema_revision
        {
            return Err(DESCRIPTOR_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode source-type descriptor: {error}"))?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let current = get_descriptor(
            &mut transaction,
            &expected.namespace,
            &expected.digest,
            RowLock::Update,
        )?
        .ok_or(DESCRIPTOR_UNAVAILABLE)?;
        if current != *expected {
            return Err(DESCRIPTOR_UNAVAILABLE.into());
        }
        transaction
            .execute(
                "UPDATE sekai_source_type_descriptors
                 SET status = $1, owner = $2, record_json = $3
                 WHERE namespace = $4 AND digest = $5",
                &[
                    &next.status,
                    &next.admitted_by,
                    &next_json,
                    &next.namespace,
                    &next.digest,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }
}

/// Row lock taken while reading a descriptor. Apply holds `Share` until it
/// commits and retire takes `Update`, so a retire and an apply serialize while
/// applies under one descriptor do not block each other.
pub enum RowLock {
    None,
    Share,
    Update,
}

pub fn get_descriptor(
    client: &mut impl GenericClient,
    namespace: &str,
    digest: &str,
    lock: RowLock,
) -> Result<Option<StoredSourceTypeDescriptor>, String> {
    let lock = match lock {
        RowLock::None => "",
        RowLock::Share => " FOR SHARE",
        RowLock::Update => " FOR UPDATE",
    };
    client
        .query_opt(
            &format!(
                "SELECT record_json FROM sekai_source_type_descriptors
                 WHERE namespace = $1 AND digest = $2{lock}"
            ),
            &[&namespace, &digest],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            serde_json::from_str(&row.get::<_, String>(0))
                .map_err(|error| format!("decode source-type descriptor: {error}"))
        })
        .transpose()
}

fn decode_pin(json: &str) -> Result<SourceWebhookKeyPin, String> {
    serde_json::from_str(json).map_err(|error| format!("decode source webhook key: {error}"))
}

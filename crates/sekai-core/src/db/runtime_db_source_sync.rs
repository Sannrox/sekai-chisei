//! Dual-backend community-store dispatch for source sync.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn apply_source_batch(
        &self,
        batch: &SourceBatch,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<SourceBatchResult, String> {
        self.apply_source_batch_with_policy_generation(
            batch,
            authenticated_producer,
            now_ms,
            None,
            None,
        )
    }

    pub fn apply_source_batch_with_policy_generation(
        &self,
        batch: &SourceBatch,
        authenticated_producer: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
        authorized_objects: Option<&[Object]>,
    ) -> Result<SourceBatchResult, String> {
        match self {
            Self::Sqlite(db) => db.apply_source_batch_with_policy_generation(
                batch,
                authenticated_producer,
                now_ms,
                expected_policy_generation,
                authorized_objects,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.apply_source_batch_with_policy_generation(
                    batch,
                    authenticated_producer,
                    now_ms,
                    expected_policy_generation,
                    authorized_objects,
                )
            }),
        }
    }

    pub fn get_source_write_record(
        &self,
        transaction_id: &str,
        object_id: &str,
    ) -> Result<Option<crate::sekai::value_explanation::SourceWriteRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_source_write_record(transaction_id, object_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_source_write_record(transaction_id, object_id)
            }),
        }
    }

    pub fn list_source_batch_transactions(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
        before: Option<&crate::db::object_sync::BatchHistoryCursor>,
        limit: usize,
    ) -> Result<Option<crate::db::object_sync::SourceBatchHistory>, String> {
        match self {
            Self::Sqlite(db) => ObjectSyncBackend::list_source_batch_transactions(
                db.as_ref(),
                namespace,
                source_instance,
                type_digest,
                before,
                limit,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ObjectSyncBackend::list_source_batch_transactions(
                    db.as_ref(),
                    namespace,
                    source_instance,
                    type_digest,
                    before,
                    limit,
                )
            }),
        }
    }

    pub fn get_source_identity_lineage(
        &self,
        namespace: &str,
        source_id: &str,
    ) -> Result<Option<crate::sekai::object_lineage::ObjectLineage>, String> {
        match self {
            Self::Sqlite(db) => {
                ObjectSyncBackend::get_source_identity_lineage(db.as_ref(), namespace, source_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ObjectSyncBackend::get_source_identity_lineage(db.as_ref(), namespace, source_id)
            }),
        }
    }

    pub fn get_source_sync_state(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<SourceSyncState>, String> {
        match self {
            Self::Sqlite(db) => ObjectSyncBackend::get_source_sync_state(
                db.as_ref(),
                namespace,
                source_instance,
                type_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                ObjectSyncBackend::get_source_sync_state(
                    db.as_ref(),
                    namespace,
                    source_instance,
                    type_digest,
                )
            }),
        }
    }

    pub fn get_source_type_descriptor(
        &self,
        namespace: &str,
        digest: &str,
    ) -> Result<Option<crate::sekai::source_type_descriptor::StoredSourceTypeDescriptor>, String>
    {
        match self {
            Self::Sqlite(db) => db.get_source_type_descriptor(namespace, digest),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_source_type_descriptor(namespace, digest)
            }),
        }
    }

    pub fn put_source_type_descriptor(
        &self,
        descriptor: &crate::sekai::source_type_descriptor::StoredSourceTypeDescriptor,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_source_type_descriptor(descriptor),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_source_type_descriptor(descriptor))
            }
        }
    }

    pub fn cas_source_type_descriptor(
        &self,
        expected: &crate::sekai::source_type_descriptor::StoredSourceTypeDescriptor,
        next: &crate::sekai::source_type_descriptor::StoredSourceTypeDescriptor,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_source_type_descriptor(expected, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.cas_source_type_descriptor(expected, next))
            }
        }
    }

    pub fn put_source_webhook_key(
        &self,
        pin: &crate::sekai::source_webhook::SourceWebhookKeyPin,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_source_webhook_key(pin),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_source_webhook_key(pin))
            }
        }
    }

    pub fn get_source_webhook_key(
        &self,
        namespace: &str,
        source_instance: &str,
        key_id: &str,
    ) -> Result<Option<crate::sekai::source_webhook::SourceWebhookKeyPin>, String> {
        match self {
            Self::Sqlite(db) => db.get_source_webhook_key(namespace, source_instance, key_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_source_webhook_key(namespace, source_instance, key_id)
            }),
        }
    }

    pub fn list_source_webhook_keys(
        &self,
        namespace: Option<&str>,
        source_instance: Option<&str>,
    ) -> Result<Vec<crate::sekai::source_webhook::SourceWebhookKeyPin>, String> {
        match self {
            Self::Sqlite(db) => db.list_source_webhook_keys(namespace, source_instance),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_source_webhook_keys(namespace, source_instance)
            }),
        }
    }
}

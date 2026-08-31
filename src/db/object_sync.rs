//! Backend-neutral persistence for bounded source-batch object sync.

use std::collections::{BTreeMap, HashMap};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::domain::Object;
use crate::sekai::audit::{insert_object_changes, object_diff_changes};
use crate::sekai::object_lineage::{ObjectLineage, bind_sync_lineage};
use crate::sekai::object_sync::{
    OperationOutcome, SOURCE_BATCH_V2_VERSION, SourceBatch, SourceBatchResult, SourceBatchStatus,
    SourceBatchTransaction, SourceBinding, SourceCheckpoint, SourceDeliveryMode,
    SourceRecordResult, SourceSyncGeneration, SourceSyncGenerationStatus, SourceSyncState,
    SyncDecision, SyncedObject, is_schema_drift_denial, schema_quarantine_record_reason,
    sync_github_record,
};

pub const POSTGRES_OBJECT_SYNC_SURFACE: &str = "sekai.object-sync";

#[cfg(test)]
const SOURCE_BINDINGS_TABLE: &str = "sekai_source_bindings";
#[cfg(test)]
const SOURCE_BATCHES_TABLE: &str = "sekai_source_batch_transactions";
#[cfg(test)]
const SOURCE_IDENTITIES_TABLE: &str = "sekai_source_identities";
#[cfg(test)]
const SOURCE_RESULTS_TABLE: &str = "sekai_source_record_results";
#[cfg(test)]
const SOURCE_CHECKPOINTS_TABLE: &str = "sekai_source_checkpoints";
#[cfg(test)]
const SOURCE_GENERATIONS_TABLE: &str = "sekai_source_sync_generations";

pub(crate) const RESERVED_SYNC_PROPERTIES: &[&str] = &[
    "sync_source",
    "sync_source_instance",
    "sync_source_id",
    "sync_source_version",
    "sync_payload_digest",
    "sync_type_digest",
    "sync_tombstoned",
];

pub trait ObjectSyncBackend: Send + Sync {
    fn apply_source_batch(
        &self,
        batch: &SourceBatch,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<SourceBatchResult, String>;

    /// Internal backend-neutral inspection of the lineage owned by one
    /// persisted source identity. This is not an authorization or RPC surface.
    #[doc(hidden)]
    fn get_source_identity_lineage(
        &self,
        namespace: &str,
        source_id: &str,
    ) -> Result<Option<ObjectLineage>, String> {
        let _ = (namespace, source_id);
        Err("source identity lineage is unavailable".into())
    }

    fn get_source_sync_state(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<SourceSyncState>, String>;
}

impl ObjectSyncBackend for SekaiDb {
    fn apply_source_batch(
        &self,
        batch: &SourceBatch,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<SourceBatchResult, String> {
        SekaiDb::apply_source_batch(self, batch, authenticated_producer, now_ms)
    }

    fn get_source_identity_lineage(
        &self,
        namespace: &str,
        source_id: &str,
    ) -> Result<Option<ObjectLineage>, String> {
        SekaiDb::get_source_identity_lineage(self, namespace, source_id)
    }

    fn get_source_sync_state(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<SourceSyncState>, String> {
        SekaiDb::get_source_sync_state(self, namespace, source_instance, type_digest)
    }
}

impl ObjectSyncBackend for PostgresDb {
    fn apply_source_batch(
        &self,
        batch: &SourceBatch,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<SourceBatchResult, String> {
        PostgresDb::apply_source_batch(self, batch, authenticated_producer, now_ms)
    }

    fn get_source_identity_lineage(
        &self,
        namespace: &str,
        source_id: &str,
    ) -> Result<Option<ObjectLineage>, String> {
        PostgresDb::get_source_identity_lineage(self, namespace, source_id)
    }

    fn get_source_sync_state(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<SourceSyncState>, String> {
        PostgresDb::get_source_sync_state(self, namespace, source_instance, type_digest)
    }
}

#[derive(Debug)]
pub(crate) enum ApplyError {
    Denied {
        code: &'static str,
        message: &'static str,
    },
    Storage(String),
}

impl ApplyError {
    pub(crate) fn denied(code: &'static str, message: &'static str) -> Self {
        Self::Denied { code, message }
    }

    pub(crate) fn is_denial(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    pub(crate) fn code(&self) -> Option<&'static str> {
        match self {
            Self::Denied { code, .. } => Some(code),
            Self::Storage(_) => None,
        }
    }

    pub(crate) fn storage(error: impl std::fmt::Display) -> Self {
        Self::Storage(error.to_string())
    }
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { code, message } => write!(formatter, "{code}: {message}"),
            Self::Storage(message) => write!(formatter, "storage_error: {message}"),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<rusqlite::Error> for ApplyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<postgres::Error> for ApplyError {
    fn from(error: postgres::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

#[derive(Debug)]
pub(crate) struct PreparedRecord {
    pub(crate) source_id: String,
    pub(crate) object: SyncedObject,
    pub(crate) decision: SyncDecision,
    pub(crate) lineage: ObjectLineage,
    pub(crate) display_name: String,
    pub(crate) observed_at_ms: i64,
    pub(crate) properties_json: String,
    pub(crate) source_sequence: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct PreparedBatch {
    pub(crate) binding_id: String,
    pub(crate) transaction_id: String,
    pub(crate) batch_json: String,
    pub(crate) records: Vec<PreparedRecord>,
}

impl PreparedBatch {
    pub(crate) fn new(batch: &SourceBatch) -> Result<Self, ApplyError> {
        let mut records = Vec::with_capacity(batch.records.len());
        for record in &batch.records {
            if record
                .properties
                .keys()
                .any(|key| RESERVED_SYNC_PROPERTIES.contains(&key.as_str()))
            {
                return Err(ApplyError::denied(
                    "reserved_property",
                    "record properties contain a plane-owned object-sync metadata key",
                ));
            }
            let decision = sync_github_record(record.clone(), &batch.type_digest);
            let object = match &decision {
                SyncDecision::Upsert(object) | SyncDecision::Tombstone(object) => object.clone(),
                SyncDecision::Conflict { .. } | SyncDecision::Reject { .. } => {
                    return Err(ApplyError::denied(
                        "invalid_record",
                        "record cannot be projected by the object-sync contract",
                    ));
                }
            };
            let lineage = bind_sync_lineage(
                &batch.type_digest,
                &object.source_id,
                &object.type_name,
                &object.object_id,
            )
            .map_err(ApplyError::Storage)?;
            let mut properties = record.properties.clone();
            properties.insert("sync_source".into(), record.source.clone());
            properties.insert(
                "sync_source_instance".into(),
                record.source_instance.clone(),
            );
            properties.insert("sync_source_id".into(), object.source_id.clone());
            properties.insert("sync_source_version".into(), record.source_version.clone());
            properties.insert("sync_payload_digest".into(), record.payload_digest.clone());
            properties.insert("sync_type_digest".into(), batch.type_digest.clone());
            properties.insert("sync_tombstoned".into(), record.deleted.to_string());
            let properties_json = serde_json::to_string(&properties)
                .map_err(|error| ApplyError::Storage(error.to_string()))?;
            records.push(PreparedRecord {
                source_id: object.source_id.clone(),
                object,
                decision,
                lineage,
                display_name: record.display_name.clone(),
                observed_at_ms: record.observed_at_ms,
                properties_json,
                source_sequence: record.source_sequence,
            });
        }

        Ok(Self {
            binding_id: stable_id(
                "source-binding",
                &[&batch.namespace, &batch.source, &batch.source_instance],
            ),
            transaction_id: stable_id(
                "source-batch",
                &[
                    &batch.namespace,
                    &batch.producer_identity,
                    &batch.idempotency_key,
                ],
            ),
            batch_json: serde_json::to_string(batch)
                .map_err(|error| ApplyError::Storage(error.to_string()))?,
            records,
        })
    }
}

#[derive(Debug)]
enum OpenDisposition {
    Open,
    Committed(Box<SourceBatchResult>),
}

#[derive(Debug)]
struct StoredBatch {
    transaction: SourceBatchTransaction,
    result_json: String,
}

#[derive(Debug)]
struct StoredBinding {
    binding: SourceBinding,
    updated_at_ms: i64,
}

#[derive(Debug)]
struct StoredIdentity {
    binding_id: String,
    type_digest: String,
    type_name: String,
    object_id: String,
    source_version: String,
    payload_digest: String,
}

impl SekaiDb {
    pub(crate) fn migrate_object_sync(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_objects_github_source_identity
                    ON sekai_objects(namespace, external_id)
                    WHERE external_id LIKE 'github:%';

                CREATE TABLE IF NOT EXISTS sekai_source_bindings (
                    binding_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    producer_identity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_instance TEXT NOT NULL,
                    family TEXT NOT NULL,
                    adapter_id TEXT NOT NULL,
                    adapter_version TEXT NOT NULL,
                    type_digest TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    updated_at_ms INTEGER NOT NULL,
                    UNIQUE(namespace, source, source_instance)
                );
                CREATE INDEX IF NOT EXISTS idx_sekai_source_bindings_lookup
                    ON sekai_source_bindings(namespace, source_instance, type_digest);

                CREATE TABLE IF NOT EXISTS sekai_source_batch_transactions (
                    transaction_id TEXT PRIMARY KEY,
                    binding_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    producer_identity TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    batch_digest TEXT NOT NULL,
                    batch_json TEXT NOT NULL,
                    current_cursor TEXT NOT NULL,
                    proposed_next_cursor TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('OPEN', 'COMMITTED', 'ABORTED', 'QUARANTINED')),
                    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'denial', 'unavailable')),
                    opened_at_ms INTEGER NOT NULL,
                    closed_at_ms INTEGER,
                    reason TEXT NOT NULL,
                    result_json TEXT NOT NULL DEFAULT '',
                    contract_version TEXT NOT NULL DEFAULT 'sekai.source-batch/v1',
                    delivery_mode TEXT,
                    sync_generation INTEGER,
                    feed_epoch TEXT,
                    offset_start INTEGER,
                    offset_end INTEGER,
                    snapshot_complete INTEGER,
                    UNIQUE(namespace, producer_identity, idempotency_key),
                    FOREIGN KEY(binding_id) REFERENCES sekai_source_bindings(binding_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_source_batches_one_open
                    ON sekai_source_batch_transactions(binding_id) WHERE status='OPEN';
                CREATE INDEX IF NOT EXISTS idx_sekai_source_batches_history
                    ON sekai_source_batch_transactions(binding_id, opened_at_ms);

                CREATE TABLE IF NOT EXISTS sekai_source_identities (
                    namespace TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    type_digest TEXT NOT NULL,
                    type_name TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    tombstoned INTEGER NOT NULL CHECK(tombstoned IN (0, 1)),
                    synced_object_json TEXT NOT NULL,
                    lineage_json TEXT NOT NULL,
                    last_transaction_id TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, source_id),
                    UNIQUE(object_id),
                    FOREIGN KEY(binding_id) REFERENCES sekai_source_bindings(binding_id)
                );
                CREATE TRIGGER IF NOT EXISTS trg_sekai_source_objects_no_generic_update
                BEFORE UPDATE ON sekai_objects
                WHEN EXISTS (
                    SELECT 1 FROM sekai_source_identities
                    WHERE sekai_source_identities.object_id = OLD.id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'source-owned object is immutable outside source sync');
                END;
                CREATE TRIGGER IF NOT EXISTS trg_sekai_source_objects_no_generic_delete
                BEFORE DELETE ON sekai_objects
                WHEN EXISTS (
                    SELECT 1 FROM sekai_source_identities
                    WHERE sekai_source_identities.object_id = OLD.id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'source-owned object is immutable outside source sync');
                END;

                CREATE TABLE IF NOT EXISTS sekai_source_record_results (
                    transaction_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    decision_json TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'denial', 'unavailable')),
                    reason TEXT NOT NULL,
                    lineage_json TEXT NOT NULL,
                    source_sequence INTEGER,
                    PRIMARY KEY(transaction_id, source_id),
                    FOREIGN KEY(transaction_id)
                        REFERENCES sekai_source_batch_transactions(transaction_id)
                );

                CREATE TABLE IF NOT EXISTS sekai_source_checkpoints (
                    binding_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    cursor TEXT NOT NULL,
                    committed_batch_digest TEXT NOT NULL,
                    advanced_at_ms INTEGER NOT NULL,
                    contract_version TEXT NOT NULL DEFAULT 'sekai.source-batch/v1',
                    delivery_mode TEXT,
                    sync_generation INTEGER,
                    feed_epoch TEXT,
                    committed_offset INTEGER,
                    FOREIGN KEY(binding_id) REFERENCES sekai_source_bindings(binding_id)
                );
                CREATE INDEX IF NOT EXISTS idx_sekai_source_checkpoints_namespace
                    ON sekai_source_checkpoints(namespace);

                CREATE TABLE IF NOT EXISTS sekai_source_sync_generations (
                    binding_id TEXT NOT NULL,
                    sync_generation INTEGER NOT NULL CHECK(sync_generation > 0),
                    status TEXT NOT NULL CHECK(
                        status IN ('SNAPSHOTTING', 'ACTIVE', 'RECOVERY_REQUIRED', 'SUPERSEDED')
                    ),
                    delivery_mode TEXT NOT NULL CHECK(
                        delivery_mode IN ('snapshot', 'change_feed')
                    ),
                    feed_epoch TEXT,
                    committed_offset INTEGER,
                    reason TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(binding_id, sync_generation),
                    CHECK(committed_offset IS NULL OR committed_offset >= 0),
                    FOREIGN KEY(binding_id) REFERENCES sekai_source_bindings(binding_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_source_generations_one_current
                    ON sekai_source_sync_generations(binding_id)
                    WHERE status IN ('SNAPSHOTTING', 'ACTIVE', 'RECOVERY_REQUIRED');
                CREATE TABLE IF NOT EXISTS sekai_source_webhook_keys (
                    pin_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    source_instance TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
                    UNIQUE(namespace, source_instance, key_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_open_table_sources (
                    source_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sekai_open_table_snapshots (
                    source_id TEXT PRIMARY KEY,
                    snapshot_digest TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    FOREIGN KEY(source_id) REFERENCES sekai_open_table_sources(source_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_event_stream_bindings (
                    stream_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sekai_event_stream_checkpoints (
                    stream_id TEXT PRIMARY KEY,
                    committed_offset INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    FOREIGN KEY(stream_id) REFERENCES sekai_event_stream_bindings(stream_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_event_stream_admitted_events (
                    stream_id TEXT NOT NULL,
                    event_offset INTEGER NOT NULL,
                    generation INTEGER NOT NULL,
                    feed_epoch TEXT NOT NULL,
                    event_digest TEXT NOT NULL,
                    PRIMARY KEY(stream_id, event_offset),
                    FOREIGN KEY(stream_id) REFERENCES sekai_event_stream_bindings(stream_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_event_subscriptions (
                    namespace TEXT NOT NULL,
                    subscription_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, subscription_id)
                );
                DELETE FROM sekai_event_stream_checkpoints
                WHERE stream_id NOT IN (
                    SELECT DISTINCT stream_id FROM sekai_event_stream_admitted_events
                );
                CREATE TABLE IF NOT EXISTS sekai_governed_documents (
                    namespace TEXT NOT NULL,
                    document_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, document_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_governed_renditions (
                    namespace TEXT NOT NULL,
                    document_id TEXT NOT NULL,
                    rendition_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, document_id, rendition_id),
                    FOREIGN KEY(namespace, document_id)
                        REFERENCES sekai_governed_documents(namespace, document_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_governed_images (
                    namespace TEXT NOT NULL,
                    image_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, image_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_governed_image_renditions (
                    namespace TEXT NOT NULL,
                    image_id TEXT NOT NULL,
                    rendition_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, image_id, rendition_id),
                    FOREIGN KEY(namespace, image_id)
                        REFERENCES sekai_governed_images(namespace, image_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_governed_image_annotations (
                    namespace TEXT NOT NULL,
                    image_id TEXT NOT NULL,
                    annotation_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, image_id, annotation_id),
                    FOREIGN KEY(namespace, image_id)
                        REFERENCES sekai_governed_images(namespace, image_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_client_packages (
                    namespace TEXT NOT NULL,
                    package_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, package_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS sekai_client_packages_live_identity
                ON sekai_client_packages(
                    namespace,
                    json_extract(record_json, '$.language'),
                    json_extract(record_json, '$.package_name')
                )
                WHERE json_extract(record_json, '$.superseded_by') = '';
                CREATE TABLE IF NOT EXISTS sekai_capability_packages (
                    namespace TEXT NOT NULL,
                    certification_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, certification_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS sekai_capability_packages_live_identity
                ON sekai_capability_packages(
                    namespace,
                    json_extract(record_json, '$.package_id')
                )
                WHERE json_extract(record_json, '$.superseded_by') = ''
                  AND json_extract(record_json, '$.revocation') = '';
                CREATE TABLE IF NOT EXISTS sekai_federation_network_contracts (
                    namespace TEXT NOT NULL,
                    contract_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, contract_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_federation_network_exchanges (
                    namespace TEXT NOT NULL,
                    contract_id TEXT NOT NULL,
                    exchange_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, contract_id, exchange_id),
                    FOREIGN KEY(namespace, contract_id)
                        REFERENCES sekai_federation_network_contracts(namespace, contract_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_workflow_action_bindings (
                    namespace TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, binding_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS sekai_workflow_action_bindings_identity
                ON sekai_workflow_action_bindings(
                    namespace,
                    json_extract(record_json, '$.profile_id'),
                    json_extract(record_json, '$.source_instance'),
                    json_extract(record_json, '$.step_id')
                );
                CREATE TABLE IF NOT EXISTS sekai_workflow_action_callbacks (
                    namespace TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    cursor_value INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, binding_id, cursor_value),
                    FOREIGN KEY(namespace, binding_id)
                        REFERENCES sekai_workflow_action_bindings(namespace, binding_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_workflow_action_commands (
                    namespace TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    expected_cursor INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, binding_id, command, expected_cursor),
                    FOREIGN KEY(namespace, binding_id)
                        REFERENCES sekai_workflow_action_bindings(namespace, binding_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_connector_certifications (
                    namespace TEXT NOT NULL,
                    certification_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, certification_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS sekai_connector_certifications_live_identity
                ON sekai_connector_certifications(
                    namespace,
                    json_extract(record_json, '$.connector_id')
                )
                WHERE json_extract(record_json, '$.superseded_by') = ''
                  AND json_extract(record_json, '$.revocation') = '';
                CREATE TABLE IF NOT EXISTS sekai_warehouse_projections (
                    namespace TEXT NOT NULL,
                    projection_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, projection_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_warehouse_pages (
                    namespace TEXT NOT NULL,
                    projection_id TEXT NOT NULL,
                    page_digest TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, projection_id, page_digest),
                    FOREIGN KEY(namespace, projection_id)
                        REFERENCES sekai_warehouse_projections(namespace, projection_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_lakehouse_snapshots (
                    namespace TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, snapshot_id)
                );",
            )
            .map_err(|error| error.to_string())?;
        for statement in [
            "ALTER TABLE sekai_source_batch_transactions ADD COLUMN contract_version TEXT NOT NULL DEFAULT 'sekai.source-batch/v1'",
            "ALTER TABLE sekai_source_batch_transactions ADD COLUMN delivery_mode TEXT",
            "ALTER TABLE sekai_source_batch_transactions ADD COLUMN sync_generation INTEGER",
            "ALTER TABLE sekai_source_batch_transactions ADD COLUMN feed_epoch TEXT",
            "ALTER TABLE sekai_source_batch_transactions ADD COLUMN offset_start INTEGER",
            "ALTER TABLE sekai_source_batch_transactions ADD COLUMN offset_end INTEGER",
            "ALTER TABLE sekai_source_batch_transactions ADD COLUMN snapshot_complete INTEGER",
            "ALTER TABLE sekai_source_record_results ADD COLUMN source_sequence INTEGER",
            "ALTER TABLE sekai_source_checkpoints ADD COLUMN contract_version TEXT NOT NULL DEFAULT 'sekai.source-batch/v1'",
            "ALTER TABLE sekai_source_checkpoints ADD COLUMN delivery_mode TEXT",
            "ALTER TABLE sekai_source_checkpoints ADD COLUMN sync_generation INTEGER",
            "ALTER TABLE sekai_source_checkpoints ADD COLUMN feed_epoch TEXT",
            "ALTER TABLE sekai_source_checkpoints ADD COLUMN committed_offset INTEGER",
        ] {
            match self.conn().execute(statement, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                    if message.contains("duplicate column name") => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        self.conn()
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_sekai_source_batches_generation
                 ON sekai_source_batch_transactions(
                    binding_id, sync_generation, opened_at_ms
                 )",
                [],
            )
            .map_err(|error| error.to_string())?;
        rebuild_source_batch_status_constraint(&self.conn())?;
        Ok(())
    }

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
        batch
            .validate_for_producer(authenticated_producer)
            .map_err(|error| error.to_string())?;
        if now_ms <= 0 {
            return Err("invalid_timestamp: now_ms must be positive".into());
        }
        let prepared = PreparedBatch::new(batch).map_err(|error| error.to_string())?;
        match self
            .persist_source_batch_open(batch, &prepared, now_ms)
            .map_err(|error| error.to_string())?
        {
            OpenDisposition::Committed(result) => Ok(*result),
            OpenDisposition::Open => self
                .commit_source_batch(
                    batch,
                    &prepared,
                    authenticated_producer,
                    now_ms,
                    expected_policy_generation,
                    authorized_objects,
                )
                .map_err(|error| error.to_string()),
        }
    }

    fn persist_source_batch_open(
        &self,
        batch: &SourceBatch,
        prepared: &PreparedBatch,
        now_ms: i64,
    ) -> Result<OpenDisposition, ApplyError> {
        let mut conn = self.conn();
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(stored) = load_batch_by_key(
            &transaction,
            &batch.namespace,
            &batch.producer_identity,
            &batch.idempotency_key,
        )? {
            if stored.transaction.batch_digest != batch.batch_digest {
                return Err(ApplyError::denied(
                    "idempotency_conflict",
                    "idempotency key is already bound to different canonical batch input",
                ));
            }
            if stored.transaction.transaction_id != prepared.transaction_id
                || stored.transaction.binding_id != prepared.binding_id
            {
                return Err(ApplyError::denied(
                    "replay_identity_conflict",
                    "stored replay identity does not match the canonical batch identity",
                ));
            }
            return match stored.transaction.status {
                SourceBatchStatus::Committed | SourceBatchStatus::Quarantined => {
                    let result = parse_stored_result(&stored)?;
                    transaction.commit()?;
                    Ok(OpenDisposition::Committed(Box::new(result)))
                }
                SourceBatchStatus::Open => {
                    let binding = load_binding_by_id(&transaction, &prepared.binding_id)?
                        .ok_or_else(|| {
                            ApplyError::denied(
                                "orphaned_open_transaction",
                                "open transaction has no stable source binding",
                            )
                        })?;
                    validate_binding(&binding.binding, batch)?;
                    transaction.commit()?;
                    Ok(OpenDisposition::Open)
                }
                SourceBatchStatus::Aborted => Err(ApplyError::denied(
                    "batch_aborted",
                    "matching source batch was durably aborted and cannot become success",
                )),
            };
        }

        let binding = match load_binding_by_source(
            &transaction,
            &batch.namespace,
            &batch.source,
            &batch.source_instance,
        )? {
            Some(binding) => {
                validate_binding(&binding.binding, batch)?;
                binding
            }
            None => {
                let binding = SourceBinding {
                    binding_id: prepared.binding_id.clone(),
                    namespace: batch.namespace.clone(),
                    producer_identity: batch.producer_identity.clone(),
                    source: batch.source.clone(),
                    source_instance: batch.source_instance.clone(),
                    family: batch.family.clone(),
                    adapter_id: batch.adapter_id.clone(),
                    adapter_version: batch.adapter_version.clone(),
                    type_digest: batch.type_digest.clone(),
                    created_at_ms: now_ms,
                    active: true,
                };
                transaction.execute(
                    "INSERT INTO sekai_source_bindings (
                        binding_id, namespace, producer_identity, source, source_instance,
                        family, adapter_id, adapter_version, type_digest, created_at_ms,
                        active, updated_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?10)",
                    params![
                        binding.binding_id,
                        binding.namespace,
                        binding.producer_identity,
                        binding.source,
                        binding.source_instance,
                        binding.family,
                        binding.adapter_id,
                        binding.adapter_version,
                        binding.type_digest,
                        binding.created_at_ms,
                    ],
                )?;
                StoredBinding {
                    binding,
                    updated_at_ms: now_ms,
                }
            }
        };

        if batch.contract_version != SOURCE_BATCH_V2_VERSION {
            preflight_cursor_and_delivery(&transaction, &binding.binding, batch)?;
        }

        let open_exists: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sekai_source_batch_transactions
                WHERE binding_id=?1 AND status='OPEN'
             )",
            params![prepared.binding_id],
            |row| row.get(0),
        )?;
        if open_exists {
            return Err(ApplyError::denied(
                "open_transaction_conflict",
                "source binding already has a different open transaction",
            ));
        }

        transaction.execute(
            "INSERT INTO sekai_source_batch_transactions (
                transaction_id, binding_id, namespace, producer_identity, idempotency_key,
                batch_digest, batch_json, current_cursor, proposed_next_cursor, status,
                outcome, opened_at_ms, closed_at_ms, reason, result_json, contract_version,
                delivery_mode, sync_generation, feed_epoch, offset_start, offset_end,
                snapshot_complete
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'OPEN',
                       'unavailable', ?10, NULL, 'awaiting atomic commit', '', ?11,
                       ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                prepared.transaction_id,
                prepared.binding_id,
                batch.namespace,
                batch.producer_identity,
                batch.idempotency_key,
                batch.batch_digest,
                prepared.batch_json,
                batch.current_cursor,
                batch.proposed_next_cursor,
                now_ms,
                batch.contract_version,
                batch
                    .delivery
                    .as_ref()
                    .map(|delivery| delivery_mode_db(delivery.mode)),
                batch
                    .delivery
                    .as_ref()
                    .map(|delivery| delivery.sync_generation as i64),
                batch
                    .delivery
                    .as_ref()
                    .and_then(|delivery| delivery.source_feed_epoch.as_deref()),
                batch
                    .delivery
                    .as_ref()
                    .and_then(|delivery| delivery.offset_start)
                    .map(|value| value as i64),
                batch
                    .delivery
                    .as_ref()
                    .and_then(|delivery| delivery.offset_end)
                    .map(|value| value as i64),
                batch
                    .delivery
                    .as_ref()
                    .map(|delivery| delivery.snapshot_complete),
            ],
        )?;
        transaction.commit()?;
        Ok(OpenDisposition::Open)
    }

    fn commit_source_batch(
        &self,
        batch: &SourceBatch,
        prepared: &PreparedBatch,
        authenticated_producer: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
        authorized_objects: Option<&[Object]>,
    ) -> Result<SourceBatchResult, ApplyError> {
        let mut conn = self.conn();
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::sekai::audit::require_sqlite_policy_generation(
            &transaction,
            &batch.namespace,
            expected_policy_generation,
        )
        .map_err(ApplyError::Storage)?;
        let stored = load_batch_by_key(
            &transaction,
            &batch.namespace,
            &batch.producer_identity,
            &batch.idempotency_key,
        )?
        .ok_or_else(|| {
            ApplyError::denied(
                "missing_open_transaction",
                "source batch has no durable open transaction",
            )
        })?;
        if stored.transaction.batch_digest != batch.batch_digest {
            return Err(ApplyError::denied(
                "idempotency_conflict",
                "idempotency key is already bound to different canonical batch input",
            ));
        }
        match stored.transaction.status {
            SourceBatchStatus::Committed | SourceBatchStatus::Quarantined => {
                return parse_stored_result(&stored);
            }
            SourceBatchStatus::Aborted => {
                return Err(ApplyError::denied(
                    "batch_aborted",
                    "matching source batch was durably aborted and cannot become success",
                ));
            }
            SourceBatchStatus::Open => {}
        }

        let binding = load_binding_by_id(&transaction, &prepared.binding_id)?.ok_or_else(|| {
            ApplyError::denied(
                "orphaned_open_transaction",
                "open transaction has no stable source binding",
            )
        })?;
        let preflight = validate_binding(&binding.binding, batch).and_then(|()| {
            preflight_commit_state(&transaction, &binding.binding, batch, &prepared.records)
        });
        if let Err(error) = preflight {
            if !error.is_denial() {
                return Err(error);
            }
            if is_schema_drift_denial(error.code()) {
                let result = persist_schema_quarantine(
                    &transaction,
                    &binding.binding,
                    batch,
                    prepared,
                    &stored,
                    now_ms,
                    &error,
                )?;
                transaction.commit()?;
                return Ok(result);
            }
            if error.code() == Some("missing_range") {
                mark_generation_recovery_required(
                    &transaction,
                    &prepared.binding_id,
                    batch,
                    now_ms,
                )?;
            }
            transaction.execute(
                "UPDATE sekai_source_batch_transactions
                 SET status='ABORTED', outcome='denial', closed_at_ms=?1, reason=?2
                 WHERE transaction_id=?3 AND status='OPEN'",
                params![now_ms, error.to_string(), prepared.transaction_id],
            )?;
            transaction.execute(
                "UPDATE sekai_source_bindings SET updated_at_ms=?1 WHERE binding_id=?2",
                params![now_ms, prepared.binding_id],
            )?;
            transaction.commit()?;
            return Err(error);
        }

        if let Some(authorized) = authorized_objects {
            for expected in authorized {
                let current = load_object(&transaction, &expected.id)?;
                require_authorized_object_snapshot(
                    current.as_ref(),
                    Some(std::slice::from_ref(expected)),
                    &expected.id,
                )?;
            }
        }
        let mut record_results = Vec::with_capacity(prepared.records.len());
        for prepared_record in &prepared.records {
            let before = load_object(&transaction, &prepared_record.object.object_id)?;
            require_authorized_object_snapshot(
                before.as_ref(),
                authorized_objects,
                &prepared_record.object.object_id,
            )?;
            transaction.execute(
                "DELETE FROM sekai_source_identities
                 WHERE namespace=?1 AND source_id=?2",
                params![batch.namespace, prepared_record.source_id],
            )?;
            let mut object = Object {
                id: prepared_record.object.object_id.clone(),
                kind: prepared_record.object.type_name.clone(),
                name: prepared_record.display_name.clone(),
                namespace: batch.namespace.clone(),
                external_id: prepared_record.source_id.clone(),
                properties: serde_json::from_str::<BTreeMap<String, String>>(
                    &prepared_record.properties_json,
                )
                .map_err(|error| ApplyError::Storage(error.to_string()))?
                .into_iter()
                .collect::<HashMap<_, _>>(),
                created: before
                    .as_ref()
                    .map(|object| object.created)
                    .unwrap_or(prepared_record.observed_at_ms.min(now_ms)),
                updated: now_ms,
            };
            if let Some(existing) = &before
                && let Some(policy) = crate::db::object_security::load_active_policy_sqlite(
                    &transaction,
                    &object.namespace,
                    &object.kind,
                )
                .map_err(ApplyError::Storage)?
            {
                policy.preserve_unwritable_properties(existing, &mut object);
            }
            let properties_json = crate::domain::storage_properties_json(&object.properties)
                .map_err(ApplyError::Storage)?;
            transaction.execute(
                "INSERT INTO sekai_objects
                    (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                    kind=excluded.kind,
                    name=excluded.name,
                    namespace=excluded.namespace,
                    external_id=excluded.external_id,
                    properties=excluded.properties,
                    updated=excluded.updated",
                params![
                    object.id,
                    object.kind,
                    object.name,
                    object.namespace,
                    object.external_id,
                    properties_json,
                    object.created,
                    object.updated,
                ],
            )?;
            let changes = object_diff_changes(
                authenticated_producer,
                before.as_ref(),
                Some(&object),
                now_ms,
            );
            insert_object_changes(&transaction, &changes).map_err(ApplyError::Storage)?;

            let reason = match prepared_record.decision {
                SyncDecision::Upsert(_) => "upserted",
                SyncDecision::Tombstone(_) => "tombstoned",
                SyncDecision::Conflict { .. } | SyncDecision::Reject { .. } => {
                    return Err(ApplyError::Storage(
                        "prepared sync decision changed after validation".into(),
                    ));
                }
            };
            let record_result = SourceRecordResult {
                transaction_id: prepared.transaction_id.clone(),
                source_id: prepared_record.source_id.clone(),
                source_version: prepared_record.object.source_version.clone(),
                decision: prepared_record.decision.clone(),
                outcome: OperationOutcome::Success,
                reason: reason.into(),
                source_sequence: prepared_record.source_sequence,
            };
            let synced_object_json = serde_json::to_string(&prepared_record.object)
                .map_err(|error| ApplyError::Storage(error.to_string()))?;
            let lineage_json = serde_json::to_string(&prepared_record.lineage)
                .map_err(|error| ApplyError::Storage(error.to_string()))?;
            let decision_json = serde_json::to_string(&prepared_record.decision)
                .map_err(|error| ApplyError::Storage(error.to_string()))?;
            transaction.execute(
                "INSERT INTO sekai_source_identities (
                    namespace, source_id, binding_id, type_digest, type_name, object_id,
                    source_version, payload_digest, tombstoned, synced_object_json,
                    lineage_json, last_transaction_id, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(namespace, source_id) DO UPDATE SET
                    source_version=excluded.source_version,
                    payload_digest=excluded.payload_digest,
                    tombstoned=excluded.tombstoned,
                    synced_object_json=excluded.synced_object_json,
                    lineage_json=excluded.lineage_json,
                    last_transaction_id=excluded.last_transaction_id,
                    updated_at_ms=excluded.updated_at_ms",
                params![
                    batch.namespace,
                    prepared_record.source_id,
                    prepared.binding_id,
                    batch.type_digest,
                    prepared_record.object.type_name,
                    prepared_record.object.object_id,
                    prepared_record.object.source_version,
                    prepared_record.object.payload_digest,
                    prepared_record.object.tombstoned,
                    synced_object_json,
                    lineage_json,
                    prepared.transaction_id,
                    now_ms,
                ],
            )?;
            transaction.execute(
                "INSERT INTO sekai_source_record_results (
                    transaction_id, source_id, source_version, decision_json,
                    outcome, reason, lineage_json, source_sequence
                 ) VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6, ?7)",
                params![
                    prepared.transaction_id,
                    prepared_record.source_id,
                    prepared_record.object.source_version,
                    decision_json,
                    reason,
                    lineage_json,
                    prepared_record.source_sequence.map(|value| value as i64),
                ],
            )?;
            record_results.push(record_result);
        }

        let committed_transaction = SourceBatchTransaction {
            transaction_id: prepared.transaction_id.clone(),
            binding_id: prepared.binding_id.clone(),
            namespace: batch.namespace.clone(),
            producer_identity: batch.producer_identity.clone(),
            idempotency_key: batch.idempotency_key.clone(),
            batch_digest: batch.batch_digest.clone(),
            current_cursor: batch.current_cursor.clone(),
            proposed_next_cursor: batch.proposed_next_cursor.clone(),
            status: SourceBatchStatus::Committed,
            outcome: OperationOutcome::Success,
            opened_at_ms: stored.transaction.opened_at_ms,
            closed_at_ms: Some(now_ms),
            reason: "committed".into(),
            contract_version: batch.contract_version.clone(),
            delivery_mode: batch.delivery.as_ref().map(|delivery| delivery.mode),
            sync_generation: batch
                .delivery
                .as_ref()
                .map(|delivery| delivery.sync_generation),
            source_feed_epoch: batch
                .delivery
                .as_ref()
                .and_then(|delivery| delivery.source_feed_epoch.clone()),
            offset_start: batch
                .delivery
                .as_ref()
                .and_then(|delivery| delivery.offset_start),
            offset_end: batch
                .delivery
                .as_ref()
                .and_then(|delivery| delivery.offset_end),
            snapshot_complete: batch
                .delivery
                .as_ref()
                .map(|delivery| delivery.snapshot_complete),
        };
        let result = SourceBatchResult {
            transaction: committed_transaction,
            records: record_results,
            checkpoint_advanced: true,
        };
        let result_json = serde_json::to_string(&result)
            .map_err(|error| ApplyError::Storage(error.to_string()))?;
        let updated = transaction.execute(
            "UPDATE sekai_source_batch_transactions
             SET status='COMMITTED', outcome='success', closed_at_ms=?1,
                 reason='committed', result_json=?2
             WHERE transaction_id=?3 AND status='OPEN'",
            params![now_ms, result_json, prepared.transaction_id],
        )?;
        if updated != 1 {
            return Err(ApplyError::Storage(
                "open source batch changed during atomic commit".into(),
            ));
        }
        commit_generation_state(&transaction, &prepared.binding_id, batch, now_ms)?;
        transaction.execute(
            "INSERT INTO sekai_source_checkpoints (
                binding_id, namespace, cursor, committed_batch_digest, advanced_at_ms,
                contract_version, delivery_mode, sync_generation, feed_epoch,
                committed_offset
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(binding_id) DO UPDATE SET
                namespace=excluded.namespace,
                cursor=excluded.cursor,
                committed_batch_digest=excluded.committed_batch_digest,
                advanced_at_ms=excluded.advanced_at_ms,
                contract_version=excluded.contract_version,
                delivery_mode=excluded.delivery_mode,
                sync_generation=excluded.sync_generation,
                feed_epoch=excluded.feed_epoch,
                committed_offset=excluded.committed_offset",
            params![
                prepared.binding_id,
                batch.namespace,
                batch.proposed_next_cursor,
                batch.batch_digest,
                now_ms,
                batch.contract_version,
                batch
                    .delivery
                    .as_ref()
                    .map(|delivery| delivery_mode_db(delivery.mode)),
                batch
                    .delivery
                    .as_ref()
                    .map(|delivery| delivery.sync_generation as i64),
                batch
                    .delivery
                    .as_ref()
                    .and_then(|delivery| delivery.source_feed_epoch.as_deref()),
                batch.delivery.as_ref().and_then(|delivery| {
                    match delivery.mode {
                        SourceDeliveryMode::Snapshot if !delivery.snapshot_complete => None,
                        SourceDeliveryMode::Snapshot | SourceDeliveryMode::ChangeFeed => {
                            delivery.offset_end.map(|value| value as i64)
                        }
                    }
                }),
            ],
        )?;
        transaction.execute(
            "UPDATE sekai_source_bindings SET updated_at_ms=?1 WHERE binding_id=?2",
            params![now_ms, prepared.binding_id],
        )?;
        transaction.commit()?;
        Ok(result)
    }

    pub(crate) fn get_source_identity_lineage(
        &self,
        namespace: &str,
        source_id: &str,
    ) -> Result<Option<ObjectLineage>, String> {
        let conn = self.conn();
        let lineage_json = conn
            .query_row(
                "SELECT lineage_json FROM sekai_source_identities
                 WHERE namespace=?1 AND source_id=?2",
                params![namespace, source_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| "source identity lineage is unavailable".to_string())?;
        lineage_json
            .map(|lineage_json| {
                serde_json::from_str(&lineage_json)
                    .map_err(|_| "stored source identity lineage is invalid".to_string())
            })
            .transpose()
    }

    pub fn get_source_sync_state(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<SourceSyncState>, String> {
        let conn = self.conn();
        let Some(binding) = conn
            .query_row(
                "SELECT binding_id, namespace, producer_identity, source, source_instance,
                        family, adapter_id, adapter_version, type_digest, created_at_ms,
                        active, updated_at_ms
                 FROM sekai_source_bindings
                 WHERE namespace=?1 AND source='github'
                   AND source_instance=?2 AND type_digest=?3
                 ORDER BY binding_id LIMIT 1",
                params![namespace, source_instance, type_digest],
                raw_binding_from_row,
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(stored_binding_from_raw)
            .transpose()
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let checkpoint = load_checkpoint(&conn, &binding.binding.binding_id)
            .map_err(|error| error.to_string())?;
        let open_transaction = load_latest_transaction(&conn, &binding.binding.binding_id, "OPEN")
            .map_err(|error| error.to_string())?
            .map(|stored| stored.transaction);
        let last_stored = load_latest_closed_result(&conn, &binding.binding.binding_id)
            .map_err(|error| error.to_string())?;
        let last_result = last_stored
            .as_ref()
            .map(parse_stored_result)
            .transpose()
            .map_err(|error| error.to_string())?;
        let current_generation = load_current_generation(&conn, &binding.binding.binding_id)
            .map_err(|error| error.to_string())?;
        let latest_transaction = load_latest_transaction_any(&conn, &binding.binding.binding_id)
            .map_err(|error| error.to_string())?
            .map(|stored| stored.transaction);
        let mut updated_at_ms = binding.updated_at_ms;
        if let Some(checkpoint) = &checkpoint {
            updated_at_ms = updated_at_ms.max(checkpoint.advanced_at_ms);
        }
        if let Some(transaction) = &open_transaction {
            updated_at_ms = updated_at_ms.max(transaction.opened_at_ms);
        }
        if let Some(stored) = &last_stored {
            updated_at_ms = updated_at_ms.max(
                stored
                    .transaction
                    .closed_at_ms
                    .unwrap_or(stored.transaction.opened_at_ms),
            );
        }
        if let Some(generation) = &current_generation {
            updated_at_ms = updated_at_ms.max(generation.updated_at_ms);
        }
        if let Some(transaction) = &latest_transaction {
            updated_at_ms =
                updated_at_ms.max(transaction.closed_at_ms.unwrap_or(transaction.opened_at_ms));
        }
        Ok(Some(SourceSyncState {
            binding: binding.binding,
            checkpoint,
            open_transaction,
            last_result,
            current_generation,
            latest_transaction,
            updated_at_ms,
        }))
    }
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update(b"\n");
    }
    format!("{prefix}-{:x}", digest.finalize())
}

fn delivery_mode_db(mode: SourceDeliveryMode) -> &'static str {
    match mode {
        SourceDeliveryMode::Snapshot => "snapshot",
        SourceDeliveryMode::ChangeFeed => "change_feed",
    }
}

fn delivery_mode_from_db(value: &str) -> Result<SourceDeliveryMode, ApplyError> {
    match value {
        "snapshot" => Ok(SourceDeliveryMode::Snapshot),
        "change_feed" => Ok(SourceDeliveryMode::ChangeFeed),
        _ => Err(ApplyError::Storage("invalid source delivery mode".into())),
    }
}

fn generation_status_from_db(value: &str) -> Result<SourceSyncGenerationStatus, ApplyError> {
    match value {
        "SNAPSHOTTING" => Ok(SourceSyncGenerationStatus::Snapshotting),
        "ACTIVE" => Ok(SourceSyncGenerationStatus::Active),
        "RECOVERY_REQUIRED" => Ok(SourceSyncGenerationStatus::RecoveryRequired),
        "SUPERSEDED" => Ok(SourceSyncGenerationStatus::Superseded),
        _ => Err(ApplyError::Storage(
            "invalid source sync generation status".into(),
        )),
    }
}

fn u64_from_i64(value: i64) -> Result<u64, ApplyError> {
    u64::try_from(value)
        .map_err(|_| ApplyError::Storage("negative persisted delivery position".into()))
}

fn optional_u64_from_i64(value: Option<i64>) -> Result<Option<u64>, ApplyError> {
    value.map(u64_from_i64).transpose()
}

fn to_sqlite_conversion_error(error: ApplyError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(error))
}

pub(crate) fn validate_binding(
    binding: &SourceBinding,
    batch: &SourceBatch,
) -> Result<(), ApplyError> {
    if !binding.active {
        return Err(ApplyError::denied(
            "inactive_binding",
            "source binding is inactive",
        ));
    }
    if binding.namespace != batch.namespace
        || binding.source != batch.source
        || binding.source_instance != batch.source_instance
    {
        return Err(ApplyError::denied(
            "binding_source_conflict",
            "source batch does not match the stable source binding",
        ));
    }
    if binding.producer_identity != batch.producer_identity {
        return Err(ApplyError::denied(
            "binding_producer_conflict",
            "source binding belongs to a different authenticated producer",
        ));
    }
    if binding.family != batch.family
        || binding.adapter_id != batch.adapter_id
        || binding.adapter_version != batch.adapter_version
    {
        return Err(ApplyError::denied(
            "binding_contract_conflict",
            "source binding contract differs from the submitted batch",
        ));
    }
    Ok(())
}

fn preflight_cursor_and_delivery(
    conn: &Connection,
    binding: &SourceBinding,
    batch: &SourceBatch,
) -> Result<(), ApplyError> {
    let checkpoint = load_checkpoint(conn, &binding.binding_id)?;
    match checkpoint {
        Some(checkpoint) if checkpoint.cursor != batch.current_cursor => {
            return Err(ApplyError::denied(
                "stale_cursor",
                "current cursor does not match the plane-owned checkpoint",
            ));
        }
        None if !batch.current_cursor.is_empty() => {
            return Err(ApplyError::denied(
                "foreign_cursor",
                "current cursor is foreign to a binding without a checkpoint",
            ));
        }
        Some(_) | None => {}
    }
    preflight_delivery_state(conn, binding, batch)
}

fn preflight_commit_state(
    conn: &Connection,
    binding: &SourceBinding,
    batch: &SourceBatch,
    records: &[PreparedRecord],
) -> Result<(), ApplyError> {
    preflight_cursor_and_delivery(conn, binding, batch)?;
    if binding.type_digest != batch.type_digest {
        return Err(ApplyError::denied(
            "binding_type_conflict",
            "source binding cannot move across type revisions",
        ));
    }

    for record in records {
        let identity = load_identity(conn, &batch.namespace, &record.source_id)?;
        let object = load_object(conn, &record.object.object_id)?;
        match (&identity, &object) {
            (Some(identity), Some(object)) => {
                if identity.binding_id != binding.binding_id
                    || identity.type_digest != batch.type_digest
                    || identity.type_name != record.object.type_name
                    || identity.object_id != record.object.object_id
                    || object.namespace != batch.namespace
                    || object.external_id != record.source_id
                    || object.kind != record.object.type_name
                {
                    return Err(ApplyError::denied(
                        "type_identity_conflict",
                        "source identity conflicts with its bound type or graph object",
                    ));
                }
                let mut projected_properties =
                    serde_json::from_str::<HashMap<String, String>>(&record.properties_json)
                        .map_err(|error| ApplyError::Storage(error.to_string()))?;
                if let Some(policy) = crate::db::object_security::load_active_policy_sqlite(
                    conn,
                    &object.namespace,
                    &object.kind,
                )
                .map_err(ApplyError::Storage)?
                {
                    let mut projected = object.clone();
                    projected.properties = projected_properties;
                    policy.preserve_unwritable_properties(object, &mut projected);
                    projected_properties = projected.properties;
                }
                if identity.source_version == record.object.source_version
                    && (identity.payload_digest != record.object.payload_digest
                        || object.name != record.display_name
                        || object.properties != projected_properties)
                {
                    return Err(ApplyError::denied(
                        "source_revision_conflict",
                        "immutable source version is bound to different payload content",
                    ));
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(ApplyError::denied(
                    "ambiguous_identity_state",
                    "source identity and graph object do not form a complete applied pair",
                ));
            }
            (None, None) => {}
        }
        let collision: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sekai_objects
                WHERE namespace=?1 AND external_id=?2 AND id<>?3
             )",
            params![batch.namespace, record.source_id, record.object.object_id,],
            |row| row.get(0),
        )?;
        if collision {
            return Err(ApplyError::denied(
                "source_identity_conflict",
                "source identity is already projected to a different graph object",
            ));
        }
    }
    Ok(())
}

fn preflight_delivery_state(
    conn: &Connection,
    binding: &SourceBinding,
    batch: &SourceBatch,
) -> Result<(), ApplyError> {
    let current = load_current_generation(conn, &binding.binding_id)?;
    if batch.contract_version != SOURCE_BATCH_V2_VERSION {
        if current.is_some() {
            return Err(ApplyError::denied(
                "legacy_batch_after_v2",
                "legacy source batches cannot advance a generation-enabled binding",
            ));
        }
        return Ok(());
    }
    let delivery = batch.delivery.as_ref().ok_or_else(|| {
        ApplyError::denied(
            "missing_delivery_metadata",
            "v2 source batches require delivery metadata",
        )
    })?;
    match delivery.mode {
        SourceDeliveryMode::Snapshot => match current {
            None => {
                if delivery.sync_generation != 1 {
                    return Err(ApplyError::denied(
                        "generation_conflict",
                        "the first snapshot generation must be one",
                    ));
                }
            }
            Some(generation) => match generation.status {
                SourceSyncGenerationStatus::Snapshotting
                    if generation.sync_generation == delivery.sync_generation => {}
                SourceSyncGenerationStatus::RecoveryRequired
                    if generation
                        .sync_generation
                        .checked_add(1)
                        .is_some_and(|next| next == delivery.sync_generation) => {}
                SourceSyncGenerationStatus::Active => {
                    return Err(ApplyError::denied(
                        "phase_conflict",
                        "an active generation cannot be proactively reset",
                    ));
                }
                SourceSyncGenerationStatus::RecoveryRequired => {
                    return Err(ApplyError::denied(
                        "generation_conflict",
                        "recovery snapshot generation is not the required successor",
                    ));
                }
                SourceSyncGenerationStatus::Snapshotting
                | SourceSyncGenerationStatus::Superseded => {
                    return Err(ApplyError::denied(
                        "generation_conflict",
                        "snapshot generation does not match current state",
                    ));
                }
            },
        },
        SourceDeliveryMode::ChangeFeed => {
            let generation = current.ok_or_else(|| {
                ApplyError::denied(
                    "phase_conflict",
                    "a change feed cannot create a synchronization generation",
                )
            })?;
            if generation.status == SourceSyncGenerationStatus::RecoveryRequired {
                return Err(ApplyError::denied(
                    "recovery_required",
                    "the current generation requires a recovery snapshot",
                ));
            }
            if generation.status != SourceSyncGenerationStatus::Active {
                return Err(ApplyError::denied(
                    "phase_conflict",
                    "change feed requires an active synchronization generation",
                ));
            }
            if generation.sync_generation != delivery.sync_generation {
                return Err(ApplyError::denied(
                    "generation_conflict",
                    "change feed generation does not match current state",
                ));
            }
            if generation.source_feed_epoch != delivery.source_feed_epoch {
                return Err(ApplyError::denied(
                    "feed_epoch_conflict",
                    "change feed epoch does not match current state",
                ));
            }
            let committed_offset = generation.committed_offset.ok_or_else(|| {
                ApplyError::denied(
                    "phase_conflict",
                    "active generation has no committed handoff offset",
                )
            })?;
            let offset_start = delivery.offset_start.ok_or_else(|| {
                ApplyError::denied(
                    "missing_delivery_range",
                    "change feed requires a delivery range",
                )
            })?;
            if offset_start < committed_offset {
                return Err(ApplyError::denied(
                    "overlapping_range",
                    "change feed overlaps the committed delivery position",
                ));
            }
            if offset_start > committed_offset {
                return Err(ApplyError::denied(
                    "missing_range",
                    "change feed starts after the committed delivery position",
                ));
            }
        }
    }
    Ok(())
}

fn mark_generation_recovery_required(
    conn: &Connection,
    binding_id: &str,
    batch: &SourceBatch,
    now_ms: i64,
) -> Result<(), ApplyError> {
    let Some(delivery) = &batch.delivery else {
        return Ok(());
    };
    let updated = conn.execute(
        "UPDATE sekai_source_sync_generations
         SET status='RECOVERY_REQUIRED', reason='missing_range', updated_at_ms=?1
         WHERE binding_id=?2 AND sync_generation=?3 AND status='ACTIVE'",
        params![now_ms, binding_id, delivery.sync_generation as i64],
    )?;
    if updated != 1 {
        return Err(ApplyError::Storage(
            "missing-range recovery transition lost current generation".into(),
        ));
    }
    Ok(())
}

fn commit_generation_state(
    conn: &Connection,
    binding_id: &str,
    batch: &SourceBatch,
    now_ms: i64,
) -> Result<(), ApplyError> {
    if batch.contract_version != SOURCE_BATCH_V2_VERSION {
        return Ok(());
    }
    let delivery = batch
        .delivery
        .as_ref()
        .ok_or_else(|| ApplyError::Storage("validated v2 batch has no delivery metadata".into()))?;
    match delivery.mode {
        SourceDeliveryMode::Snapshot => {
            conn.execute(
                "UPDATE sekai_source_sync_generations
                 SET status='SUPERSEDED', reason='recovered_by_successor', updated_at_ms=?1
                 WHERE binding_id=?2 AND status='RECOVERY_REQUIRED'
                   AND sync_generation<>?3",
                params![now_ms, binding_id, delivery.sync_generation as i64],
            )?;
            let (status, mode, epoch, committed_offset, reason) = if delivery.snapshot_complete {
                (
                    "ACTIVE",
                    "change_feed",
                    delivery.source_feed_epoch.as_deref(),
                    delivery.offset_end.map(|value| value as i64),
                    "snapshot_handoff_committed",
                )
            } else {
                (
                    "SNAPSHOTTING",
                    "snapshot",
                    None,
                    None,
                    "snapshot_in_progress",
                )
            };
            conn.execute(
                "INSERT INTO sekai_source_sync_generations (
                    binding_id, sync_generation, status, delivery_mode, feed_epoch,
                    committed_offset, reason, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                 ON CONFLICT(binding_id, sync_generation) DO UPDATE SET
                    status=excluded.status,
                    delivery_mode=excluded.delivery_mode,
                    feed_epoch=excluded.feed_epoch,
                    committed_offset=excluded.committed_offset,
                    reason=excluded.reason,
                    updated_at_ms=excluded.updated_at_ms",
                params![
                    binding_id,
                    delivery.sync_generation as i64,
                    status,
                    mode,
                    epoch,
                    committed_offset,
                    reason,
                    now_ms,
                ],
            )?;
        }
        SourceDeliveryMode::ChangeFeed => {
            let updated = conn.execute(
                "UPDATE sekai_source_sync_generations
                 SET delivery_mode='change_feed', committed_offset=?1,
                     reason='change_feed_committed', updated_at_ms=?2
                 WHERE binding_id=?3 AND sync_generation=?4 AND status='ACTIVE'",
                params![
                    delivery.offset_end.map(|value| value as i64),
                    now_ms,
                    binding_id,
                    delivery.sync_generation as i64,
                ],
            )?;
            if updated != 1 {
                return Err(ApplyError::Storage(
                    "active generation changed during atomic commit".into(),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn require_authorized_object_snapshot(
    before: Option<&Object>,
    authorized: Option<&[Object]>,
    object_id: &str,
) -> Result<(), ApplyError> {
    let Some(authorized) = authorized else {
        return Ok(());
    };
    let expected = authorized.iter().find(|object| object.id == object_id);
    match (before, expected) {
        (Some(current), Some(expected)) if current.persisted_state_matches(expected) => Ok(()),
        (None, None) => Ok(()),
        _ => Err(ApplyError::denied(
            "object_changed_since_authorization",
            crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION,
        )),
    }
}

fn load_object(conn: &Connection, object_id: &str) -> Result<Option<Object>, ApplyError> {
    conn.query_row(
        "SELECT id, kind, name, namespace, external_id, properties, created, updated
         FROM sekai_objects WHERE id=?1",
        params![object_id],
        crate::db::sekai::row_to_object,
    )
    .optional()
    .map_err(ApplyError::from)
}

fn load_identity(
    conn: &Connection,
    namespace: &str,
    source_id: &str,
) -> Result<Option<StoredIdentity>, ApplyError> {
    conn.query_row(
        "SELECT binding_id, type_digest, type_name, object_id, source_version, payload_digest
         FROM sekai_source_identities WHERE namespace=?1 AND source_id=?2",
        params![namespace, source_id],
        |row| {
            Ok(StoredIdentity {
                binding_id: row.get(0)?,
                type_digest: row.get(1)?,
                type_name: row.get(2)?,
                object_id: row.get(3)?,
                source_version: row.get(4)?,
                payload_digest: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(ApplyError::from)
}

fn load_checkpoint(
    conn: &Connection,
    binding_id: &str,
) -> Result<Option<SourceCheckpoint>, ApplyError> {
    conn.query_row(
        "SELECT binding_id, namespace, cursor, committed_batch_digest, advanced_at_ms,
                contract_version, delivery_mode, sync_generation, feed_epoch, committed_offset
         FROM sekai_source_checkpoints WHERE binding_id=?1",
        params![binding_id],
        |row| {
            Ok(SourceCheckpoint {
                binding_id: row.get(0)?,
                namespace: row.get(1)?,
                cursor: row.get(2)?,
                committed_batch_digest: row.get(3)?,
                advanced_at_ms: row.get(4)?,
                contract_version: row.get(5)?,
                delivery_mode: row
                    .get::<_, Option<String>>(6)?
                    .map(|value| delivery_mode_from_db(&value))
                    .transpose()
                    .map_err(to_sqlite_conversion_error)?,
                sync_generation: optional_u64_from_i64(row.get(7)?)
                    .map_err(to_sqlite_conversion_error)?,
                source_feed_epoch: row.get(8)?,
                committed_offset: optional_u64_from_i64(row.get(9)?)
                    .map_err(to_sqlite_conversion_error)?,
            })
        },
    )
    .optional()
    .map_err(ApplyError::from)
}

fn load_current_generation(
    conn: &Connection,
    binding_id: &str,
) -> Result<Option<SourceSyncGeneration>, ApplyError> {
    conn.query_row(
        "SELECT binding_id, sync_generation, status, delivery_mode, feed_epoch,
                committed_offset, reason, created_at_ms, updated_at_ms
         FROM sekai_source_sync_generations
         WHERE binding_id=?1
           AND status IN ('SNAPSHOTTING', 'ACTIVE', 'RECOVERY_REQUIRED')
         ORDER BY sync_generation DESC LIMIT 1",
        params![binding_id],
        |row| {
            let generation = u64_from_i64(row.get(1)?).map_err(to_sqlite_conversion_error)?;
            let status = generation_status_from_db(&row.get::<_, String>(2)?)
                .map_err(to_sqlite_conversion_error)?;
            let delivery_mode = delivery_mode_from_db(&row.get::<_, String>(3)?)
                .map_err(to_sqlite_conversion_error)?;
            let committed_offset =
                optional_u64_from_i64(row.get(5)?).map_err(to_sqlite_conversion_error)?;
            Ok(SourceSyncGeneration {
                binding_id: row.get(0)?,
                sync_generation: generation,
                status,
                delivery_mode,
                source_feed_epoch: row.get(4)?,
                committed_offset,
                reason: row.get(6)?,
                created_at_ms: row.get(7)?,
                updated_at_ms: row.get(8)?,
            })
        },
    )
    .optional()
    .map_err(ApplyError::from)
}

type RawBinding = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    bool,
    i64,
);

fn raw_binding_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawBinding> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
    ))
}

fn stored_binding_from_raw(raw: RawBinding) -> Result<StoredBinding, ApplyError> {
    Ok(StoredBinding {
        binding: SourceBinding {
            binding_id: raw.0,
            namespace: raw.1,
            producer_identity: raw.2,
            source: raw.3,
            source_instance: raw.4,
            family: raw.5,
            adapter_id: raw.6,
            adapter_version: raw.7,
            type_digest: raw.8,
            created_at_ms: raw.9,
            active: raw.10,
        },
        updated_at_ms: raw.11,
    })
}

fn load_binding_by_source(
    conn: &Connection,
    namespace: &str,
    source: &str,
    source_instance: &str,
) -> Result<Option<StoredBinding>, ApplyError> {
    conn.query_row(
        "SELECT binding_id, namespace, producer_identity, source, source_instance,
                family, adapter_id, adapter_version, type_digest, created_at_ms,
                active, updated_at_ms
         FROM sekai_source_bindings
         WHERE namespace=?1 AND source=?2 AND source_instance=?3",
        params![namespace, source, source_instance],
        raw_binding_from_row,
    )
    .optional()?
    .map(stored_binding_from_raw)
    .transpose()
}

fn load_binding_by_id(
    conn: &Connection,
    binding_id: &str,
) -> Result<Option<StoredBinding>, ApplyError> {
    conn.query_row(
        "SELECT binding_id, namespace, producer_identity, source, source_instance,
                family, adapter_id, adapter_version, type_digest, created_at_ms,
                active, updated_at_ms
         FROM sekai_source_bindings WHERE binding_id=?1",
        params![binding_id],
        raw_binding_from_row,
    )
    .optional()?
    .map(stored_binding_from_raw)
    .transpose()
}

type RawBatch = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<bool>,
);

fn raw_batch_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawBatch> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
        row.get(19)?,
        row.get(20)?,
    ))
}

fn stored_batch_from_raw(raw: RawBatch) -> Result<StoredBatch, ApplyError> {
    let status = match raw.8.as_str() {
        "OPEN" => SourceBatchStatus::Open,
        "COMMITTED" => SourceBatchStatus::Committed,
        "ABORTED" => SourceBatchStatus::Aborted,
        "QUARANTINED" => SourceBatchStatus::Quarantined,
        _ => return Err(ApplyError::Storage("invalid source batch status".into())),
    };
    let outcome = match raw.9.as_str() {
        "success" => OperationOutcome::Success,
        "denial" => OperationOutcome::Denial,
        "unavailable" => OperationOutcome::Unavailable,
        _ => return Err(ApplyError::Storage("invalid source batch outcome".into())),
    };
    Ok(StoredBatch {
        transaction: SourceBatchTransaction {
            transaction_id: raw.0,
            binding_id: raw.1,
            namespace: raw.2,
            producer_identity: raw.3,
            idempotency_key: raw.4,
            batch_digest: raw.5,
            current_cursor: raw.6,
            proposed_next_cursor: raw.7,
            status,
            outcome,
            opened_at_ms: raw.10,
            closed_at_ms: raw.11,
            reason: raw.12,
            contract_version: raw.14,
            delivery_mode: raw.15.as_deref().map(delivery_mode_from_db).transpose()?,
            sync_generation: optional_u64_from_i64(raw.16)?,
            source_feed_epoch: raw.17,
            offset_start: optional_u64_from_i64(raw.18)?,
            offset_end: optional_u64_from_i64(raw.19)?,
            snapshot_complete: raw.20,
        },
        result_json: raw.13,
    })
}

const BATCH_SELECT: &str =
    "SELECT transaction_id, binding_id, namespace, producer_identity, idempotency_key,
            batch_digest, current_cursor, proposed_next_cursor, status, outcome,
            opened_at_ms, closed_at_ms, reason, result_json, contract_version,
            delivery_mode, sync_generation, feed_epoch, offset_start, offset_end,
            snapshot_complete
     FROM sekai_source_batch_transactions";

fn load_batch_by_key(
    conn: &Connection,
    namespace: &str,
    producer_identity: &str,
    idempotency_key: &str,
) -> Result<Option<StoredBatch>, ApplyError> {
    let sql = format!(
        "{BATCH_SELECT} WHERE namespace=?1 AND producer_identity=?2 AND idempotency_key=?3"
    );
    conn.query_row(
        &sql,
        params![namespace, producer_identity, idempotency_key],
        raw_batch_from_row,
    )
    .optional()?
    .map(stored_batch_from_raw)
    .transpose()
}

fn load_latest_transaction(
    conn: &Connection,
    binding_id: &str,
    status: &str,
) -> Result<Option<StoredBatch>, ApplyError> {
    let sql = format!(
        "{BATCH_SELECT} WHERE binding_id=?1 AND status=?2
         ORDER BY COALESCE(closed_at_ms, opened_at_ms) DESC, transaction_id DESC LIMIT 1"
    );
    conn.query_row(&sql, params![binding_id, status], raw_batch_from_row)
        .optional()?
        .map(stored_batch_from_raw)
        .transpose()
}

fn load_latest_transaction_any(
    conn: &Connection,
    binding_id: &str,
) -> Result<Option<StoredBatch>, ApplyError> {
    let sql = format!(
        "{BATCH_SELECT} WHERE binding_id=?1
         ORDER BY COALESCE(closed_at_ms, opened_at_ms) DESC, transaction_id DESC LIMIT 1"
    );
    conn.query_row(&sql, params![binding_id], raw_batch_from_row)
        .optional()?
        .map(stored_batch_from_raw)
        .transpose()
}

fn rebuild_source_batch_status_constraint(conn: &Connection) -> Result<(), String> {
    let sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master
             WHERE type='table' AND name='sekai_source_batch_transactions'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(sql) = sql else {
        return Ok(());
    };
    if sql.contains("QUARANTINED") {
        return Ok(());
    }
    conn.execute_batch(
        "PRAGMA foreign_keys=OFF;
         CREATE TABLE sekai_source_batch_transactions_new (
            transaction_id TEXT PRIMARY KEY,
            binding_id TEXT NOT NULL,
            namespace TEXT NOT NULL,
            producer_identity TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            batch_digest TEXT NOT NULL,
            batch_json TEXT NOT NULL,
            current_cursor TEXT NOT NULL,
            proposed_next_cursor TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('OPEN', 'COMMITTED', 'ABORTED', 'QUARANTINED')),
            outcome TEXT NOT NULL CHECK(outcome IN ('success', 'denial', 'unavailable')),
            opened_at_ms INTEGER NOT NULL,
            closed_at_ms INTEGER,
            reason TEXT NOT NULL,
            result_json TEXT NOT NULL DEFAULT '',
            contract_version TEXT NOT NULL DEFAULT 'sekai.source-batch/v1',
            delivery_mode TEXT,
            sync_generation INTEGER,
            feed_epoch TEXT,
            offset_start INTEGER,
            offset_end INTEGER,
            snapshot_complete INTEGER,
            UNIQUE(namespace, producer_identity, idempotency_key),
            FOREIGN KEY(binding_id) REFERENCES sekai_source_bindings(binding_id)
         );
         INSERT INTO sekai_source_batch_transactions_new
            SELECT * FROM sekai_source_batch_transactions;
         DROP TABLE sekai_source_batch_transactions;
         ALTER TABLE sekai_source_batch_transactions_new
            RENAME TO sekai_source_batch_transactions;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_source_batches_one_open
            ON sekai_source_batch_transactions(binding_id) WHERE status='OPEN';
         CREATE INDEX IF NOT EXISTS idx_sekai_source_batches_history
            ON sekai_source_batch_transactions(binding_id, opened_at_ms);
         CREATE INDEX IF NOT EXISTS idx_sekai_source_batches_generation
            ON sekai_source_batch_transactions(
                binding_id, sync_generation, opened_at_ms
            );
         PRAGMA foreign_keys=ON;",
    )
    .map_err(|error| error.to_string())
}

fn load_latest_closed_result(
    conn: &Connection,
    binding_id: &str,
) -> Result<Option<StoredBatch>, ApplyError> {
    let committed = load_latest_transaction(conn, binding_id, "COMMITTED")?;
    let quarantined = load_latest_transaction(conn, binding_id, "QUARANTINED")?;
    Ok(match (committed, quarantined) {
        (None, None) => None,
        (Some(result), None) | (None, Some(result)) => Some(result),
        (Some(left), Some(right)) => {
            let left_closed = left
                .transaction
                .closed_at_ms
                .unwrap_or(left.transaction.opened_at_ms);
            let right_closed = right
                .transaction
                .closed_at_ms
                .unwrap_or(right.transaction.opened_at_ms);
            if (left_closed, left.transaction.transaction_id.as_str())
                >= (right_closed, right.transaction.transaction_id.as_str())
            {
                Some(left)
            } else {
                Some(right)
            }
        }
    })
}

fn persist_schema_quarantine(
    transaction: &rusqlite::Transaction<'_>,
    binding: &SourceBinding,
    batch: &SourceBatch,
    prepared: &PreparedBatch,
    stored: &StoredBatch,
    now_ms: i64,
    error: &ApplyError,
) -> Result<SourceBatchResult, ApplyError> {
    let batch_reason = error.to_string();
    let mut record_results = Vec::with_capacity(prepared.records.len());
    for prepared_record in &prepared.records {
        let identity = load_identity(transaction, &batch.namespace, &prepared_record.source_id)?;
        let object = load_object(transaction, &prepared_record.object.object_id)?;
        let admitted = identity.as_ref().map(|identity| SyncedObject {
            object_id: identity.object_id.clone(),
            type_name: identity.type_name.clone(),
            source_id: prepared_record.source_id.clone(),
            source_version: identity.source_version.clone(),
            payload_digest: identity.payload_digest.clone(),
            properties: object
                .as_ref()
                .map(|object| {
                    object
                        .properties
                        .iter()
                        .filter(|(key, _)| !RESERVED_SYNC_PROPERTIES.contains(&key.as_str()))
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            tombstoned: false,
            type_digest: identity.type_digest.clone(),
        });
        let reason = schema_quarantine_record_reason(
            &binding.type_digest,
            &batch.type_digest,
            admitted.as_ref(),
            &prepared_record.object,
            &batch_reason,
        );
        let decision = SyncDecision::Reject {
            reason: reason.clone(),
        };
        let decision_json =
            serde_json::to_string(&decision).map_err(|err| ApplyError::Storage(err.to_string()))?;
        let lineage_json = serde_json::to_string(&prepared_record.lineage)
            .map_err(|err| ApplyError::Storage(err.to_string()))?;
        transaction.execute(
            "INSERT INTO sekai_source_record_results (
                transaction_id, source_id, source_version, decision_json,
                outcome, reason, lineage_json, source_sequence
             ) VALUES (?1, ?2, ?3, ?4, 'denial', ?5, ?6, ?7)",
            params![
                prepared.transaction_id,
                prepared_record.source_id,
                prepared_record.object.source_version,
                decision_json,
                reason,
                lineage_json,
                prepared_record.source_sequence.map(|value| value as i64),
            ],
        )?;
        record_results.push(SourceRecordResult {
            transaction_id: prepared.transaction_id.clone(),
            source_id: prepared_record.source_id.clone(),
            source_version: prepared_record.object.source_version.clone(),
            decision,
            outcome: OperationOutcome::Denial,
            reason,
            source_sequence: prepared_record.source_sequence,
        });
    }
    let quarantined_transaction = SourceBatchTransaction {
        transaction_id: prepared.transaction_id.clone(),
        binding_id: prepared.binding_id.clone(),
        namespace: batch.namespace.clone(),
        producer_identity: batch.producer_identity.clone(),
        idempotency_key: batch.idempotency_key.clone(),
        batch_digest: batch.batch_digest.clone(),
        current_cursor: batch.current_cursor.clone(),
        proposed_next_cursor: batch.proposed_next_cursor.clone(),
        status: SourceBatchStatus::Quarantined,
        outcome: OperationOutcome::Denial,
        opened_at_ms: stored.transaction.opened_at_ms,
        closed_at_ms: Some(now_ms),
        reason: batch_reason.clone(),
        contract_version: batch.contract_version.clone(),
        delivery_mode: batch.delivery.as_ref().map(|delivery| delivery.mode),
        sync_generation: batch
            .delivery
            .as_ref()
            .map(|delivery| delivery.sync_generation),
        source_feed_epoch: batch
            .delivery
            .as_ref()
            .and_then(|delivery| delivery.source_feed_epoch.clone()),
        offset_start: batch
            .delivery
            .as_ref()
            .and_then(|delivery| delivery.offset_start),
        offset_end: batch
            .delivery
            .as_ref()
            .and_then(|delivery| delivery.offset_end),
        snapshot_complete: batch
            .delivery
            .as_ref()
            .map(|delivery| delivery.snapshot_complete),
    };
    let result = SourceBatchResult {
        transaction: quarantined_transaction,
        records: record_results,
        checkpoint_advanced: false,
    };
    let result_json =
        serde_json::to_string(&result).map_err(|err| ApplyError::Storage(err.to_string()))?;
    let updated = transaction.execute(
        "UPDATE sekai_source_batch_transactions
         SET status='QUARANTINED', outcome='denial', closed_at_ms=?1,
             reason=?2, result_json=?3
         WHERE transaction_id=?4 AND status='OPEN'",
        params![now_ms, batch_reason, result_json, prepared.transaction_id],
    )?;
    if updated != 1 {
        return Err(ApplyError::Storage(
            "open source batch changed during schema quarantine".into(),
        ));
    }
    transaction.execute(
        "UPDATE sekai_source_bindings SET updated_at_ms=?1 WHERE binding_id=?2",
        params![now_ms, prepared.binding_id],
    )?;
    Ok(result)
}

fn parse_stored_result(stored: &StoredBatch) -> Result<SourceBatchResult, ApplyError> {
    if !matches!(
        stored.transaction.status,
        SourceBatchStatus::Committed | SourceBatchStatus::Quarantined
    ) || stored.result_json.is_empty()
    {
        return Err(ApplyError::Storage(
            "closed source batch is missing its stored result".into(),
        ));
    }
    serde_json::from_str(&stored.result_json).map_err(|error| {
        ApplyError::Storage(format!("invalid stored source batch result: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::object_sync::{
        ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
        GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_V2_VERSION, SOURCE_BATCH_VERSION,
        SOURCE_GITHUB, SourceBatchStatus, SourceDeliveryMode, SourceDeliveryWindow, SourceRecord,
        SourceSyncGenerationStatus,
    };

    const PRODUCER: &str = "connector/github-primary";
    const TYPE_DIGEST: &str = GITHUB_OBJECT_SYNC_TYPE_DIGEST;
    const OTHER_TYPE_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const PAYLOAD_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sample_object(id: &str, name: &str) -> Object {
        Object {
            id: id.into(),
            kind: "Issue".into(),
            name: name.into(),
            namespace: "ops".into(),
            external_id: id.into(),
            properties: HashMap::from([("state".into(), "open".into())]),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn authorized_sync_snapshot_rejects_stale_or_missing_current_rows() {
        let current = sample_object("issue-1", "Bounded sync");
        require_authorized_object_snapshot(
            Some(&current),
            Some(std::slice::from_ref(&current)),
            "issue-1",
        )
        .unwrap();
        let mut stale = current.clone();
        stale.name = "changed".into();
        assert!(
            require_authorized_object_snapshot(
                Some(&stale),
                Some(std::slice::from_ref(&current)),
                "issue-1"
            )
            .unwrap_err()
            .code()
                == Some("object_changed_since_authorization")
        );
        assert!(
            require_authorized_object_snapshot(Some(&current), Some(&[]), "issue-1")
                .unwrap_err()
                .code()
                == Some("object_changed_since_authorization")
        );
        require_authorized_object_snapshot(None, Some(&[]), "issue-1").unwrap();
        require_authorized_object_snapshot(Some(&current), None, "issue-1").unwrap();
    }

    fn record() -> SourceRecord {
        SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            external_id: "12".into(),
            source_version: "node-v1".into(),
            type_name: "Issue".into(),
            display_name: "Bounded sync".into(),
            payload_digest: PAYLOAD_DIGEST.into(),
            properties: BTreeMap::from([
                ("state".into(), "open".into()),
                ("title".into(), "Bounded sync".into()),
            ]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }
    }

    fn batch(current_cursor: &str, next_cursor: &str, key: &str) -> SourceBatch {
        let mut batch = SourceBatch {
            contract_version: SOURCE_BATCH_VERSION.into(),
            namespace: "acme".into(),
            producer_identity: PRODUCER.into(),
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            family: FAMILY_OBJECT_SYNC.into(),
            adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
            adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
            type_digest: TYPE_DIGEST.into(),
            current_cursor: current_cursor.into(),
            proposed_next_cursor: next_cursor.into(),
            idempotency_key: key.into(),
            batch_digest: String::new(),
            collected_at_ms: 20,
            records: vec![record()],
            delivery: None,
        };
        redigest(&mut batch);
        batch
    }

    fn redigest(batch: &mut SourceBatch) {
        batch.batch_digest = batch.canonical_digest().unwrap();
    }

    fn snapshot_batch(
        current_cursor: &str,
        next_cursor: &str,
        key: &str,
        generation: u64,
        complete: bool,
        handoff_offset: Option<u64>,
    ) -> SourceBatch {
        let mut batch = batch(current_cursor, next_cursor, key);
        batch.contract_version = SOURCE_BATCH_V2_VERSION.into();
        batch.delivery = Some(SourceDeliveryWindow {
            mode: SourceDeliveryMode::Snapshot,
            sync_generation: generation,
            source_feed_epoch: complete.then(|| "epoch-1".into()),
            offset_start: None,
            offset_end: handoff_offset,
            snapshot_complete: complete,
        });
        redigest(&mut batch);
        batch
    }

    fn change_batch(
        current_cursor: &str,
        next_cursor: &str,
        key: &str,
        generation: u64,
        offset_start: u64,
    ) -> SourceBatch {
        let mut batch = batch(current_cursor, next_cursor, key);
        batch.contract_version = SOURCE_BATCH_V2_VERSION.into();
        batch.records[0].source_sequence = Some(offset_start + 1);
        batch.delivery = Some(SourceDeliveryWindow {
            mode: SourceDeliveryMode::ChangeFeed,
            sync_generation: generation,
            source_feed_epoch: Some("epoch-1".into()),
            offset_start: Some(offset_start),
            offset_end: Some(offset_start + 1),
            snapshot_complete: false,
        });
        redigest(&mut batch);
        batch
    }

    fn db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn checkpoint(db: &SekaiDb) -> Option<String> {
        db.get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
            .unwrap()
            .and_then(|state| state.checkpoint.map(|checkpoint| checkpoint.cursor))
    }

    #[test]
    fn commits_batch_object_audit_identity_and_checkpoint() {
        let db = db();
        let batch = batch("", "cursor:1", "batch-1");
        let result = db.apply_source_batch(&batch, PRODUCER, 100).unwrap();

        assert_eq!(result.transaction.status, SourceBatchStatus::Committed);
        assert_eq!(result.transaction.outcome, OperationOutcome::Success);
        assert!(result.checkpoint_advanced);
        assert_eq!(result.records.len(), 1);
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:1"));

        let object_id = match &result.records[0].decision {
            SyncDecision::Upsert(object) => object.object_id.clone(),
            other => panic!("expected upsert, got {other:?}"),
        };
        let object = db.get_object(&object_id).unwrap().unwrap();
        assert_eq!(object.kind, "Issue");
        assert_eq!(object.name, "Bounded sync");
        assert_eq!(object.external_id, "github:acme/ops#12");
        assert_eq!(object.properties["sync_type_digest"], TYPE_DIGEST);
        assert_eq!(object.properties["sync_tombstoned"], "false");
        assert!(
            !db.list_object_changes(&object_id, 100, 0)
                .unwrap()
                .is_empty()
        );

        let identity_count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM sekai_source_identities", [], |row| {
                row.get(0)
            })
            .unwrap();
        let result_count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_source_record_results",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((identity_count, result_count), (1, 1));
    }

    #[test]
    fn exact_replay_returns_stored_result_without_new_changes() {
        let db = db();
        let batch = batch("", "cursor:1", "batch-1");
        let first = db.apply_source_batch(&batch, PRODUCER, 100).unwrap();
        let object_id = match &first.records[0].decision {
            SyncDecision::Upsert(object) => object.object_id.clone(),
            other => panic!("expected upsert, got {other:?}"),
        };
        let audit_count = db.list_object_changes(&object_id, 100, 0).unwrap().len();

        let mut replay = batch.clone();
        replay.collected_at_ms += 1_000;
        let second = db.apply_source_batch(&replay, PRODUCER, 200).unwrap();

        assert_eq!(second, first);
        assert_eq!(
            db.list_object_changes(&object_id, 100, 0).unwrap().len(),
            audit_count
        );
    }

    #[test]
    fn ordered_feed_gap_aborts_and_successor_snapshot_recovers() {
        let db = db();
        let snapshot = snapshot_batch("", "cursor:snapshot", "snapshot-1", 1, true, Some(40));
        let snapshot_result = db.apply_source_batch(&snapshot, PRODUCER, 100).unwrap();
        let active = db
            .get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(
            active.current_generation.as_ref().unwrap().status,
            SourceSyncGenerationStatus::Active
        );
        assert_eq!(
            active.current_generation.as_ref().unwrap().committed_offset,
            Some(40)
        );

        let mut feed = change_batch("cursor:snapshot", "cursor:41", "feed-41", 1, 40);
        feed.records[0].source_version = "node-v2".into();
        redigest(&mut feed);
        db.apply_source_batch(&feed, PRODUCER, 200).unwrap();
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:41"));

        let overlap = change_batch("cursor:41", "cursor:overlap", "overlap", 1, 40);
        assert!(
            db.apply_source_batch(&overlap, PRODUCER, 300)
                .unwrap_err()
                .starts_with("overlapping_range:")
        );
        let after_overlap = db
            .get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(
            after_overlap.latest_transaction.unwrap().status,
            SourceBatchStatus::Aborted
        );
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:41"));

        let missing = change_batch("cursor:41", "cursor:missing", "missing", 1, 50);
        assert!(
            db.apply_source_batch(&missing, PRODUCER, 400)
                .unwrap_err()
                .starts_with("missing_range:")
        );
        let recovery_required = db
            .get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovery_required
                .current_generation
                .as_ref()
                .unwrap()
                .status,
            SourceSyncGenerationStatus::RecoveryRequired
        );
        assert_eq!(
            recovery_required
                .latest_transaction
                .as_ref()
                .unwrap()
                .status,
            SourceBatchStatus::Aborted
        );
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:41"));

        let mut recovery = snapshot_batch(
            "cursor:41",
            "cursor:recovered",
            "snapshot-2",
            2,
            true,
            Some(80),
        );
        recovery.records[0].source_version = "node-v3".into();
        redigest(&mut recovery);
        db.apply_source_batch(&recovery, PRODUCER, 500).unwrap();
        let recovered = db
            .get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered.current_generation.as_ref().unwrap().status,
            SourceSyncGenerationStatus::Active
        );
        assert_eq!(
            recovered
                .current_generation
                .as_ref()
                .unwrap()
                .sync_generation,
            2
        );
        let superseded: String = db
            .conn()
            .query_row(
                "SELECT status FROM sekai_source_sync_generations
                 WHERE binding_id=?1 AND sync_generation=1",
                params![recovered.binding.binding_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(superseded, "SUPERSEDED");

        let replay = db.apply_source_batch(&snapshot, PRODUCER, 600).unwrap();
        assert_eq!(replay, snapshot_result);
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:recovered"));
    }

    #[test]
    fn v2_open_resumes_after_restart_and_migration_is_idempotent() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("ordered-sync.sqlite");
        let snapshot = snapshot_batch("", "cursor:snapshot", "snapshot-1", 1, true, Some(40));
        {
            let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
            let prepared = PreparedBatch::new(&snapshot).unwrap();
            assert!(matches!(
                db.persist_source_batch_open(&snapshot, &prepared, 100)
                    .unwrap(),
                OpenDisposition::Open
            ));
            db.migrate_object_sync().unwrap();
        }
        let reopened = SekaiDb::new(path.to_str().unwrap()).unwrap();
        let result = reopened
            .apply_source_batch(&snapshot, PRODUCER, 200)
            .unwrap();
        assert_eq!(result.transaction.opened_at_ms, 100);
        assert_eq!(
            reopened
                .get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
                .unwrap()
                .unwrap()
                .current_generation
                .unwrap()
                .status,
            SourceSyncGenerationStatus::Active
        );
    }

    #[test]
    fn v1_checkpoint_can_seed_generation_one_but_cannot_advance_afterward() {
        let db = db();
        let legacy = batch("", "cursor:legacy", "legacy-1");
        let legacy_result = db.apply_source_batch(&legacy, PRODUCER, 100).unwrap();
        let mut snapshot = snapshot_batch(
            "cursor:legacy",
            "cursor:snapshot",
            "snapshot-1",
            1,
            true,
            Some(40),
        );
        snapshot.records[0].source_version = "node-v2".into();
        redigest(&mut snapshot);
        db.apply_source_batch(&snapshot, PRODUCER, 200).unwrap();

        let mut later_legacy = batch("cursor:snapshot", "cursor:legacy-2", "legacy-2");
        later_legacy.records[0].source_version = "node-v3".into();
        redigest(&mut later_legacy);
        assert!(
            db.apply_source_batch(&later_legacy, PRODUCER, 300)
                .unwrap_err()
                .starts_with("legacy_batch_after_v2:")
        );
        assert_eq!(
            db.apply_source_batch(&legacy, PRODUCER, 400).unwrap(),
            legacy_result
        );
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:snapshot"));
    }

    #[test]
    fn durable_open_batch_resumes_after_restart() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("sync.sqlite");
        let batch = batch("", "cursor:1", "batch-1");
        {
            let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
            let prepared = PreparedBatch::new(&batch).unwrap();
            assert!(matches!(
                db.persist_source_batch_open(&batch, &prepared, 100)
                    .unwrap(),
                OpenDisposition::Open
            ));
            let state = db
                .get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
                .unwrap()
                .unwrap();
            assert_eq!(
                state.open_transaction.unwrap().status,
                SourceBatchStatus::Open
            );
            assert!(state.checkpoint.is_none());
        }

        let reopened = SekaiDb::new(path.to_str().unwrap()).unwrap();
        let result = reopened.apply_source_batch(&batch, PRODUCER, 200).unwrap();
        assert_eq!(result.transaction.opened_at_ms, 100);
        assert_eq!(result.transaction.closed_at_ms, Some(200));
        assert_eq!(checkpoint(&reopened).as_deref(), Some("cursor:1"));
    }

    #[test]
    fn stale_cursor_and_idempotency_conflict_leave_checkpoint_unchanged() {
        let db = db();
        let first = batch("", "cursor:1", "batch-1");
        db.apply_source_batch(&first, PRODUCER, 100).unwrap();

        let stale = batch("cursor:foreign", "cursor:2", "batch-2");
        assert!(
            db.apply_source_batch(&stale, PRODUCER, 200)
                .unwrap_err()
                .starts_with("stale_cursor:")
        );
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:1"));

        let mut conflict = first;
        conflict.proposed_next_cursor = "cursor:other".into();
        redigest(&mut conflict);
        assert!(
            db.apply_source_batch(&conflict, PRODUCER, 300)
                .unwrap_err()
                .starts_with("idempotency_conflict:")
        );
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:1"));
    }

    #[test]
    fn invalid_authority_contract_record_and_foreign_cursor_create_no_state() {
        let cases = [
            {
                let batch = batch("", "cursor:1", "batch-1");
                (batch, "connector/foreign", "producer_identity_mismatch:")
            },
            {
                let mut batch = batch("", "cursor:1", "batch-1");
                batch.contract_version = "sekai.source-batch/v3".into();
                (batch, PRODUCER, "unsupported_version:")
            },
            {
                let mut batch = batch("", "cursor:1", "batch-1");
                batch.records[0].type_name = "Discussion".into();
                redigest(&mut batch);
                (batch, PRODUCER, "unsupported_record_type:")
            },
            {
                let mut batch = batch("", "cursor:1", "batch-1");
                batch.type_digest = OTHER_TYPE_DIGEST.into();
                redigest(&mut batch);
                (batch, PRODUCER, "unbound_type_revision:")
            },
            {
                let batch = batch("cursor:foreign", "cursor:1", "batch-1");
                (batch, PRODUCER, "foreign_cursor:")
            },
        ];

        for (batch, authenticated_producer, expected_code) in cases {
            let db = db();
            assert!(
                db.apply_source_batch(&batch, authenticated_producer, 100)
                    .unwrap_err()
                    .starts_with(expected_code)
            );
            assert!(
                db.get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
                    .unwrap()
                    .is_none()
            );
            let objects: i64 = db
                .conn()
                .query_row("SELECT COUNT(*) FROM sekai_objects", [], |row| row.get(0))
                .unwrap();
            assert_eq!(objects, 0);
        }
    }

    #[test]
    fn type_identity_conflict_fails_before_mutation() {
        let db = db();
        let first = batch("", "cursor:1", "batch-1");
        let result = db.apply_source_batch(&first, PRODUCER, 100).unwrap();
        let object_id = match &result.records[0].decision {
            SyncDecision::Upsert(object) => object.object_id.clone(),
            other => panic!("expected upsert, got {other:?}"),
        };
        let before = db.get_object(&object_id).unwrap().unwrap();

        let mut conflicting = batch("cursor:1", "cursor:2", "batch-2");
        conflicting.records[0].type_name = "PullRequest".into();
        redigest(&mut conflicting);
        let quarantined = db.apply_source_batch(&conflicting, PRODUCER, 200).unwrap();
        assert_eq!(
            quarantined.transaction.status,
            SourceBatchStatus::Quarantined
        );
        assert!(!quarantined.checkpoint_advanced);
        assert!(
            quarantined.records[0]
                .reason
                .starts_with("type_identity_conflict:")
        );
        let replay = db.apply_source_batch(&conflicting, PRODUCER, 250).unwrap();
        assert_eq!(replay, quarantined);
        let after = db.get_object(&object_id).unwrap().unwrap();
        assert_eq!(after.kind, before.kind);
        assert_eq!(after.updated, before.updated);
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:1"));
        let state = db
            .get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(state.last_result.as_ref(), Some(&quarantined));
    }

    #[test]
    fn immutable_source_revision_conflict_preserves_object_and_checkpoint() {
        let db = db();
        let first = batch("", "cursor:1", "batch-1");
        let result = db.apply_source_batch(&first, PRODUCER, 100).unwrap();
        let object_id = match &result.records[0].decision {
            SyncDecision::Upsert(object) => object.object_id.clone(),
            other => panic!("expected upsert, got {other:?}"),
        };
        let before = db.get_object(&object_id).unwrap().unwrap();

        let mut conflicting = batch("cursor:1", "cursor:2", "batch-2");
        conflicting.records[0].payload_digest =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
        conflicting.records[0].display_name = "Conflicting payload".into();
        redigest(&mut conflicting);
        let quarantined = db.apply_source_batch(&conflicting, PRODUCER, 200).unwrap();
        assert_eq!(
            quarantined.transaction.status,
            SourceBatchStatus::Quarantined
        );
        assert!(!quarantined.checkpoint_advanced);
        assert!(
            quarantined.records[0]
                .reason
                .starts_with("source_revision_conflict:")
        );

        let after = db.get_object(&object_id).unwrap().unwrap();
        assert_eq!(after.name, before.name);
        assert_eq!(after.properties, before.properties);
        assert_eq!(after.updated, before.updated);
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:1"));

        let mut forged_digest = batch("cursor:1", "cursor:2", "batch-3");
        forged_digest.records[0].display_name = "Changed under the same digest".into();
        forged_digest.records[0]
            .properties
            .insert("state".into(), "closed".into());
        redigest(&mut forged_digest);
        let forged = db
            .apply_source_batch(&forged_digest, PRODUCER, 300)
            .unwrap();
        assert_eq!(forged.transaction.status, SourceBatchStatus::Quarantined);
        assert!(
            forged.records[0]
                .reason
                .starts_with("source_revision_conflict:")
        );
        let after_forged_digest = db.get_object(&object_id).unwrap().unwrap();
        assert_eq!(after_forged_digest.name, before.name);
        assert_eq!(after_forged_digest.properties, before.properties);
        assert_eq!(after_forged_digest.updated, before.updated);
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:1"));
    }

    #[test]
    fn github_source_identity_is_unique_across_graph_objects() {
        let db = db();
        let first = batch("", "cursor:1", "batch-1");
        db.apply_source_batch(&first, PRODUCER, 100).unwrap();

        let collision = Object {
            id: "ordinary:collision".into(),
            kind: "Issue".into(),
            name: "Conflicting ordinary object".into(),
            namespace: "acme".into(),
            external_id: first.records[0].source_id(),
            properties: HashMap::new(),
            created: 200,
            updated: 200,
        };
        assert!(db.create_object(&collision).is_err());
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:1"));
    }

    #[test]
    fn generic_mutations_cannot_modify_source_owned_objects() {
        let db = db();
        let first = batch("", "cursor:1", "batch-1");
        let first_result = db.apply_source_batch(&first, PRODUCER, 100).unwrap();
        let object_id = match &first_result.records[0].decision {
            SyncDecision::Upsert(object) => object.object_id.clone(),
            other => panic!("expected upsert, got {other:?}"),
        };
        let mut generic_update = db.get_object(&object_id).unwrap().unwrap();
        generic_update.name = "Generic overwrite".into();
        generic_update.updated = 150;
        assert!(db.update_object(&generic_update).is_err());
        assert!(db.delete_object(&object_id).is_err());

        let mut refresh = batch("cursor:1", "cursor:2", "batch-2");
        refresh.records[0].source_version = "node-v2".into();
        refresh.records[0].display_name = "Source-owned refresh".into();
        refresh.records[0].payload_digest =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
        redigest(&mut refresh);
        db.apply_source_batch(&refresh, PRODUCER, 200).unwrap();
        let refreshed = db.get_object(&object_id).unwrap().unwrap();
        assert_eq!(refreshed.name, "Source-owned refresh");
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:2"));
    }

    #[test]
    fn tombstone_updates_the_same_object_id() {
        let db = db();
        let first = batch("", "cursor:1", "batch-1");
        let first_result = db.apply_source_batch(&first, PRODUCER, 100).unwrap();
        let first_id = match &first_result.records[0].decision {
            SyncDecision::Upsert(object) => object.object_id.clone(),
            other => panic!("expected upsert, got {other:?}"),
        };

        let mut deleted = batch("cursor:1", "cursor:2", "batch-2");
        deleted.records[0].deleted = true;
        deleted.records[0].source_version = "node-v2".into();
        redigest(&mut deleted);
        let deleted_result = db.apply_source_batch(&deleted, PRODUCER, 200).unwrap();
        let tombstoned = match &deleted_result.records[0].decision {
            SyncDecision::Tombstone(object) => object,
            other => panic!("expected tombstone, got {other:?}"),
        };
        assert_eq!(tombstoned.object_id, first_id);
        assert!(db.get_object(&first_id).unwrap().unwrap().properties["sync_tombstoned"] == "true");
        assert_eq!(checkpoint(&db).as_deref(), Some("cursor:2"));
    }

    #[test]
    fn commit_precondition_failure_aborts_open_without_checkpoint() {
        let db = db();
        let batch = batch("", "cursor:1", "batch-1");
        let prepared = PreparedBatch::new(&batch).unwrap();
        db.persist_source_batch_open(&batch, &prepared, 100)
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_objects
                    (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, 'Issue', 'foreign', 'acme', ?2, '{}', 101, 101)",
                params![
                    prepared.records[0].object.object_id,
                    prepared.records[0].source_id
                ],
            )
            .unwrap();

        assert!(
            db.apply_source_batch(&batch, PRODUCER, 200)
                .unwrap_err()
                .starts_with("ambiguous_identity_state:")
        );
        assert!(checkpoint(&db).is_none());
        let status: String = db
            .conn()
            .query_row(
                "SELECT status FROM sekai_source_batch_transactions
                 WHERE transaction_id=?1",
                params![prepared.transaction_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "ABORTED");
        assert!(
            db.apply_source_batch(&batch, PRODUCER, 300)
                .unwrap_err()
                .starts_with("batch_aborted:")
        );
    }

    #[test]
    fn source_state_retrieval_and_runtime_dispatch_are_backend_neutral() {
        let runtime = RuntimeDb::memory();
        let batch = batch("", "cursor:1", "batch-1");
        runtime.apply_source_batch(&batch, PRODUCER, 100).unwrap();
        let state = runtime
            .get_source_sync_state("acme", "acme/ops", TYPE_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(state.binding.producer_identity, PRODUCER);
        assert_eq!(state.checkpoint.unwrap().cursor, "cursor:1");
        assert!(state.open_transaction.is_none());
        assert_eq!(
            state.last_result.unwrap().transaction.status,
            SourceBatchStatus::Committed
        );
        assert!(
            runtime
                .get_source_sync_state("acme", "acme/ops", OTHER_TYPE_DIGEST)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn additive_migration_creates_tables_and_preserves_old_objects() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("upgrade.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sekai_objects (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    namespace TEXT NOT NULL DEFAULT '',
                    external_id TEXT NOT NULL DEFAULT '',
                    properties TEXT NOT NULL DEFAULT '{}',
                    created INTEGER NOT NULL,
                    updated INTEGER NOT NULL
                 );
                 INSERT INTO sekai_objects
                    (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES ('legacy-object', 'component', 'legacy', 'acme', 'legacy', '{}', 1, 1);",
            )
            .unwrap();
        drop(connection);

        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        assert!(db.get_object("legacy-object").unwrap().is_some());
        for table in [
            SOURCE_BINDINGS_TABLE,
            SOURCE_BATCHES_TABLE,
            SOURCE_IDENTITIES_TABLE,
            SOURCE_RESULTS_TABLE,
            SOURCE_CHECKPOINTS_TABLE,
            SOURCE_GENERATIONS_TABLE,
        ] {
            let exists: bool = db
                .conn()
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1
                     )",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing migration table {table}");
        }
        for (table, column) in [
            (SOURCE_BATCHES_TABLE, "sync_generation"),
            (SOURCE_BATCHES_TABLE, "offset_start"),
            (SOURCE_BATCHES_TABLE, "offset_end"),
            (SOURCE_RESULTS_TABLE, "source_sequence"),
            (SOURCE_CHECKPOINTS_TABLE, "sync_generation"),
            (SOURCE_CHECKPOINTS_TABLE, "committed_offset"),
        ] {
            let exists: bool = db
                .conn()
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM pragma_table_info(?1) WHERE name=?2
                     )",
                    params![table, column],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing migration column {table}.{column}");
        }
    }

    #[test]
    fn upgrades_sqlite_status_check_to_allow_quarantine() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("legacy-status.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sekai_objects (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    namespace TEXT NOT NULL DEFAULT '',
                    external_id TEXT NOT NULL DEFAULT '',
                    properties TEXT NOT NULL DEFAULT '{}',
                    created INTEGER NOT NULL,
                    updated INTEGER NOT NULL
                 );
                 CREATE TABLE sekai_source_bindings (
                    binding_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    producer_identity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_instance TEXT NOT NULL,
                    family TEXT NOT NULL,
                    adapter_id TEXT NOT NULL,
                    adapter_version TEXT NOT NULL,
                    type_digest TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    updated_at_ms INTEGER NOT NULL,
                    UNIQUE(namespace, source, source_instance)
                 );
                 CREATE TABLE sekai_source_batch_transactions (
                    transaction_id TEXT PRIMARY KEY,
                    binding_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    producer_identity TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    batch_digest TEXT NOT NULL,
                    batch_json TEXT NOT NULL,
                    current_cursor TEXT NOT NULL,
                    proposed_next_cursor TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('OPEN', 'COMMITTED', 'ABORTED')),
                    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'denial', 'unavailable')),
                    opened_at_ms INTEGER NOT NULL,
                    closed_at_ms INTEGER,
                    reason TEXT NOT NULL,
                    result_json TEXT NOT NULL DEFAULT '',
                    UNIQUE(namespace, producer_identity, idempotency_key),
                    FOREIGN KEY(binding_id) REFERENCES sekai_source_bindings(binding_id)
                 );",
            )
            .unwrap();
        drop(connection);

        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        let sql: String = db
            .conn()
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type='table' AND name='sekai_source_batch_transactions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(sql.contains("QUARANTINED"), "{sql}");

        let first = batch("", "cursor:1", "batch-1");
        db.apply_source_batch(&first, PRODUCER, 100).unwrap();
        let mut conflicting = batch("cursor:1", "cursor:2", "batch-2");
        conflicting.records[0].type_name = "PullRequest".into();
        redigest(&mut conflicting);
        let quarantined = db.apply_source_batch(&conflicting, PRODUCER, 200).unwrap();
        assert_eq!(
            quarantined.transaction.status,
            SourceBatchStatus::Quarantined
        );
        assert!(!quarantined.checkpoint_advanced);
    }
}

//! One pull sync: snapshot pages from the Source, applied as source batches
//! under the plane-owned cursor (ADR 0022).
//!
//! Each page starts from the cursor the plane committed, so a runtime that
//! dies mid-sync loses nothing: the next holder reads the same cursor and
//! goes on. A batch applied just before a crash has already moved that
//! cursor, so it is not applied twice; a holder racing a takeover is refused
//! as a checkpoint conflict, which fails the sync as unavailable rather than
//! the Source as invalid. Batches name the Source, so a
//! disabled Source refuses them even from a runtime whose claim has not yet
//! lapsed. Object identity stays `source_id(source, source_instance,
//! external_id)`.

use sekai_client::CallOptions;
use sekai_client::protocol::sekai::{
    self as pb, ApplySourceBatchRequest, ApplySourceBatchResponse, ConnectorSource,
    GetSourceSyncStateRequest, GetSourceSyncStateResponse,
};
use sekai_client::{SdkError, SdkErrorCode};
use sekai_source_sdk::{
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, MAX_SOURCE_BATCH_RECORDS, SOURCE_GITHUB, SnapshotRead,
    SourceAdapterConfig, SourceBatch, build_source_batch,
};
use std::sync::Arc;

use crate::runtime::Runtime;
use crate::sync::{Prepared, SyncFailure, blocking};

/// Pages one sync applies at most; the rest waits for the next interval.
const MAX_PAGES: usize = 100;

fn property_value_to_proto(value: &sekai_source_sdk::PropertyValue) -> pb::PropertyValue {
    use pb::property_value::Kind;
    use sekai_source_sdk::PropertyValue;
    pb::PropertyValue {
        kind: Some(match value {
            PropertyValue::String(text) => Kind::StringValue(text.clone()),
            PropertyValue::Int(int) => Kind::IntValue(*int),
            PropertyValue::Float(float) => Kind::FloatValue(*float),
            PropertyValue::Bool(flag) => Kind::BoolValue(*flag),
            PropertyValue::Struct(fields) => Kind::StructValue(pb::StructValue {
                fields: fields
                    .iter()
                    .map(|(key, nested)| (key.clone(), property_value_to_proto(nested)))
                    .collect(),
            }),
            other => Kind::StringValue(other.as_cell()),
        }),
    }
}

fn property_map_to_proto(
    properties: impl IntoIterator<Item = (String, sekai_source_sdk::PropertyValue)>,
) -> std::collections::HashMap<String, pb::PropertyValue> {
    properties
        .into_iter()
        .map(|(key, value)| (key, property_value_to_proto(&value)))
        .collect()
}

impl Runtime {
    /// Reads and applies the Source's pages from the committed cursor
    /// until the Source reports them complete.
    pub(crate) async fn sync(
        &self,
        index: usize,
        source: &ConnectorSource,
        prepared: Prepared,
    ) -> Result<(), SyncFailure> {
        // The GitHub profile is code-owned; a registered type binds its
        // descriptor digest when it reads pages.
        if prepared.connector.fixed_source != Some(SOURCE_GITHUB) {
            return Err(SyncFailure::Unsupported);
        }
        let client = &self.clients[index];
        let adapter = SourceAdapterConfig {
            namespace: source.namespace.clone(),
            producer_identity: client.config().principal.clone(),
            source_instance: source.source_instance.clone(),
            type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        };
        let prepared = Arc::new(prepared);
        for _ in 0..MAX_PAGES {
            let state: GetSourceSyncStateResponse = client
                .raw()
                .unary(
                    "/sekai.SekaiService/GetSourceSyncState",
                    GetSourceSyncStateRequest {
                        namespace: adapter.namespace.clone(),
                        source_instance: adapter.source_instance.clone(),
                        type_digest: adapter.type_digest.clone(),
                    },
                    CallOptions::new(),
                )
                .await
                .map_err(plane_failure)?;
            let state = state.state.filter(|_| state.found).unwrap_or_default();
            // A batch another producer left open settles first; the sync
            // fails visibly until it does.
            if state.open_transaction.is_some() {
                return Err(SyncFailure::Unavailable);
            }
            let cursor = state
                .checkpoint
                .map(|checkpoint| checkpoint.cursor)
                .filter(|cursor| !cursor.is_empty());
            let (connectors, reading, after) =
                (self.connectors.clone(), prepared.clone(), cursor.clone());
            let page = match blocking(move || {
                connectors.read_page(&reading, after.as_deref(), MAX_SOURCE_BATCH_RECORDS)
            })
            .await?
            {
                SnapshotRead::Complete if cursor.is_some() => return Ok(()),
                // Completion is valid only after a committed page.
                SnapshotRead::Complete => return Err(SyncFailure::Invalid),
                SnapshotRead::Page(page) => page,
            };
            if page.proposed_next_cursor.is_empty()
                || Some(&page.proposed_next_cursor) == cursor.as_ref()
            {
                return Err(SyncFailure::Invalid);
            }
            // A batch carries at least one record, so an empty page commits
            // nothing: a last page leaves the cursor where it is, and any
            // other could never move it.
            if page.records.is_empty() {
                return if page.complete {
                    Ok(())
                } else {
                    Err(SyncFailure::Invalid)
                };
            }
            let batch = build_source_batch(
                &adapter,
                cursor.as_deref().unwrap_or_default(),
                &page.proposed_next_cursor,
                page.collected_at_ms,
                page.records,
            )
            .map_err(|_| SyncFailure::Invalid)?;
            let applied: ApplySourceBatchResponse = client
                .raw()
                .unary(
                    "/sekai.SekaiService/ApplySourceBatch",
                    ApplySourceBatchRequest {
                        batch: Some(to_proto(batch, &source.source_id)),
                    },
                    CallOptions::new(),
                )
                .await
                .map_err(plane_failure)?;
            let committed = applied
                .result
                .and_then(|result| result.transaction)
                .is_some_and(|transaction| transaction.status == "COMMITTED");
            // A quarantined or aborted batch holds the cursor until an
            // operator repairs it.
            if !committed {
                return Err(SyncFailure::Invalid);
            }
            if page.complete {
                return Ok(());
            }
        }
        Ok(())
    }
}

/// A plane refusal as the sync's failure class. A refused batch is the
/// Source's problem; anything else, including a checkpoint conflict
/// (aborted), is the plane being unavailable.
fn plane_failure(error: SdkError) -> SyncFailure {
    match error.code {
        SdkErrorCode::PermissionDenied | SdkErrorCode::Unauthenticated => {
            SyncFailure::PermissionMissing
        }
        SdkErrorCode::InvalidArgument | SdkErrorCode::FailedPrecondition => SyncFailure::Invalid,
        _ => SyncFailure::Unavailable,
    }
}

/// The batch on the wire, naming the Source it syncs.
fn to_proto(batch: SourceBatch, source_id: &str) -> pb::SourceBatch {
    pb::SourceBatch {
        contract_version: batch.contract_version,
        namespace: batch.namespace,
        producer_identity: batch.producer_identity,
        source: batch.source,
        source_instance: batch.source_instance,
        family: batch.family,
        adapter_id: batch.adapter_id,
        adapter_version: batch.adapter_version,
        type_digest: batch.type_digest,
        current_cursor: batch.current_cursor,
        proposed_next_cursor: batch.proposed_next_cursor,
        idempotency_key: batch.idempotency_key,
        batch_digest: batch.batch_digest,
        collected_at_ms: batch.collected_at_ms,
        records: batch
            .records
            .into_iter()
            .map(|record| pb::SourceRecord {
                source: record.source,
                source_instance: record.source_instance,
                external_id: record.external_id,
                source_version: record.source_version,
                type_name: record.type_name,
                display_name: record.display_name,
                payload_digest: record.payload_digest,
                properties: property_map_to_proto(record.properties),
                deleted: record.deleted,
                observed_at_ms: record.observed_at_ms,
                source_sequence: record.source_sequence,
            })
            .collect(),
        delivery: None,
        source_id: source_id.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_checkpoint_conflict_fails_the_sync_not_the_source() {
        for (code, failure) in [
            (SdkErrorCode::Aborted, SyncFailure::Unavailable),
            (SdkErrorCode::AlreadyExists, SyncFailure::Unavailable),
            (
                SdkErrorCode::PermissionDenied,
                SyncFailure::PermissionMissing,
            ),
            (SdkErrorCode::FailedPrecondition, SyncFailure::Invalid),
        ] {
            assert_eq!(plane_failure(SdkError::new(code)), failure, "{code:?}");
        }
    }
}

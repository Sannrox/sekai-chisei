//! Bounded ordered change-feed runner for v2 source-sync adapters.

use crate::object_sync_sdk::{
    FlushDisposition, GetSourceSyncStateInput, SourceAdapterConfig, SourceGenerationStatus,
    SourceOutbox, SourceRunDisposition, SourceRunReport, SourceSyncStateView, SourceSyncTransport,
    TransportFailure, build_source_batch_v2,
};
use sekai_chisei::sekai::object_sync::{
    MAX_SOURCE_BATCH_RECORDS, SourceBatch, SourceDeliveryMode, SourceDeliveryWindow, SourceRecord,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeFeedPage {
    /// Source-owned exclusive lower bound for this page.
    pub offset_start: u64,
    pub records: Vec<SourceRecord>,
    pub proposed_next_cursor: String,
    pub collected_at_ms: i64,
    pub caught_up: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeFeedSourceFailure {
    Unavailable,
    Invalid,
    UnsupportedOrdering,
}

/// Source-owned reader for one bounded, normalized, ordered feed page.
pub trait ChangeFeedSource {
    fn read_change_feed(
        &mut self,
        source_feed_epoch: &str,
        committed_offset: u64,
        max_records: usize,
    ) -> Result<ChangeFeedPage, ChangeFeedSourceFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeFeedRunError {
    Outbox,
    StateUnavailable,
    StateAmbiguous,
}

impl std::fmt::Display for ChangeFeedRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Outbox => "change-feed outbox is unavailable",
            Self::StateUnavailable => "source sync state is unavailable",
            Self::StateAmbiguous => "source sync state is ambiguous",
        })
    }
}

impl std::error::Error for ChangeFeedRunError {}

/// Flush one exact pending batch, then collect and apply at most one new page.
pub fn run_change_feed<T: SourceSyncTransport, S: ChangeFeedSource>(
    config: &SourceAdapterConfig,
    outbox: &SourceOutbox,
    transport: &mut T,
    source: &mut S,
    max_records: usize,
) -> Result<SourceRunReport, ChangeFeedRunError> {
    if max_records == 0 || max_records > MAX_SOURCE_BATCH_RECORDS {
        return Ok(SourceRunReport {
            disposition: SourceRunDisposition::InvalidInput,
            batches_committed: 0,
            committed_cursor: None,
            sync_generation: None,
            committed_offset: None,
        });
    }

    if let Some(pending) = pending_binding_batch(config, outbox)? {
        let entry = outbox
            .flush_idempotency_key(&pending.idempotency_key, transport, true)
            .map_err(|_| ChangeFeedRunError::Outbox)?;
        match entry.disposition {
            FlushDisposition::Pending => {
                let state = read_state(config, transport)?;
                return Ok(SourceRunReport::from_state(
                    SourceRunDisposition::Pending,
                    0,
                    &state,
                ));
            }
            FlushDisposition::Quarantined => {
                let state = read_state(config, transport)?;
                return Ok(SourceRunReport::from_state(
                    rejected_disposition(&state),
                    0,
                    &state,
                ));
            }
            FlushDisposition::Committed => {
                let state = read_state(config, transport)?;
                if !state_matches_feed_batch(&state, &pending) {
                    return Ok(SourceRunReport::from_state(
                        SourceRunDisposition::RecoveryRequired,
                        0,
                        &state,
                    ));
                }
            }
        }
    }

    let state = read_state(config, transport)?;
    let (sync_generation, source_feed_epoch, committed_offset) = match active_feed(&state) {
        Ok(active) => active,
        Err(disposition) => {
            return Ok(SourceRunReport::from_state(disposition, 0, &state));
        }
    };
    let page = match source.read_change_feed(source_feed_epoch, committed_offset, max_records) {
        Ok(page) => page,
        Err(ChangeFeedSourceFailure::UnsupportedOrdering) => {
            return Ok(SourceRunReport::from_state(
                SourceRunDisposition::UnsupportedOrdering,
                0,
                &state,
            ));
        }
        Err(ChangeFeedSourceFailure::Invalid) => {
            return Ok(SourceRunReport::from_state(
                SourceRunDisposition::InvalidInput,
                0,
                &state,
            ));
        }
        Err(ChangeFeedSourceFailure::Unavailable) => {
            return Ok(SourceRunReport::from_state(
                SourceRunDisposition::Pending,
                0,
                &state,
            ));
        }
    };

    if page.records.is_empty() {
        let disposition = if page.caught_up
            && page.offset_start == committed_offset
            && (page.proposed_next_cursor.is_empty()
                || state.current_cursor.as_deref() == Some(page.proposed_next_cursor.as_str()))
        {
            SourceRunDisposition::CaughtUp
        } else {
            SourceRunDisposition::InvalidInput
        };
        return Ok(SourceRunReport::from_state(disposition, 0, &state));
    }
    let Some(offset_end) = validate_page(&page, max_records) else {
        return Ok(SourceRunReport::from_state(
            SourceRunDisposition::InvalidInput,
            0,
            &state,
        ));
    };
    let delivery = SourceDeliveryWindow {
        mode: SourceDeliveryMode::ChangeFeed,
        sync_generation,
        source_feed_epoch: Some(source_feed_epoch.to_owned()),
        offset_start: Some(page.offset_start),
        offset_end: Some(offset_end),
        snapshot_complete: false,
    };
    let batch = match build_source_batch_v2(
        config,
        state.current_cursor.as_deref().unwrap_or_default(),
        &page.proposed_next_cursor,
        page.collected_at_ms,
        page.records,
        delivery,
    ) {
        Ok(batch) => batch,
        Err(_) => {
            return Ok(SourceRunReport::from_state(
                SourceRunDisposition::InvalidInput,
                0,
                &state,
            ));
        }
    };
    outbox
        .enqueue(&batch)
        .map_err(|_| ChangeFeedRunError::Outbox)?;
    let entry = outbox
        .flush_idempotency_key(&batch.idempotency_key, transport, true)
        .map_err(|_| ChangeFeedRunError::Outbox)?;
    match entry.disposition {
        FlushDisposition::Pending => Ok(SourceRunReport::from_state(
            SourceRunDisposition::Pending,
            0,
            &state,
        )),
        FlushDisposition::Quarantined => {
            let rejected = read_state(config, transport)?;
            Ok(SourceRunReport::from_state(
                rejected_disposition(&rejected),
                0,
                &rejected,
            ))
        }
        FlushDisposition::Committed => {
            let verified = read_state(config, transport)?;
            if !state_matches_feed_batch(&verified, &batch) {
                return Ok(SourceRunReport::from_state(
                    SourceRunDisposition::RecoveryRequired,
                    0,
                    &verified,
                ));
            }
            Ok(SourceRunReport::from_state(
                if page.caught_up {
                    SourceRunDisposition::CaughtUp
                } else {
                    SourceRunDisposition::InProgress
                },
                1,
                &verified,
            ))
        }
    }
}

fn active_feed(state: &SourceSyncStateView) -> Result<(u64, &str, u64), SourceRunDisposition> {
    if !state.found {
        return Err(
            if state.current_cursor.is_some()
                || state.generation_status.is_some()
                || state.sync_generation.is_some()
                || state.source_feed_epoch.is_some()
                || state.committed_offset.is_some()
            {
                SourceRunDisposition::RecoveryRequired
            } else {
                SourceRunDisposition::SnapshotRequired
            },
        );
    }
    if state.open_transaction || state.current_cursor.is_none() {
        return Err(SourceRunDisposition::RecoveryRequired);
    }
    match state.generation_status {
        Some(SourceGenerationStatus::RecoveryRequired) => {
            return Err(SourceRunDisposition::RecoveryRequired);
        }
        Some(SourceGenerationStatus::Snapshotting) | None => {
            return Err(SourceRunDisposition::SnapshotRequired);
        }
        Some(SourceGenerationStatus::Superseded) => {
            return Err(SourceRunDisposition::RecoveryRequired);
        }
        Some(SourceGenerationStatus::Active) => {}
    }
    if state.delivery_mode != Some(SourceDeliveryMode::ChangeFeed) {
        return Err(SourceRunDisposition::SnapshotRequired);
    }
    match (
        state.sync_generation,
        state.source_feed_epoch.as_deref(),
        state.committed_offset,
    ) {
        (Some(generation), Some(epoch), Some(offset)) if generation > 0 && !epoch.is_empty() => {
            Ok((generation, epoch, offset))
        }
        _ => Err(SourceRunDisposition::RecoveryRequired),
    }
}

fn validate_page(page: &ChangeFeedPage, max_records: usize) -> Option<u64> {
    if page.records.len() > max_records
        || page.proposed_next_cursor.is_empty()
        || page.collected_at_ms <= 0
    {
        return None;
    }
    let mut expected = page.offset_start.checked_add(1)?;
    for record in &page.records {
        if record.source_sequence != Some(expected) {
            return None;
        }
        expected = expected.checked_add(1)?;
    }
    expected.checked_sub(1)
}

fn state_matches_feed_batch(state: &SourceSyncStateView, batch: &SourceBatch) -> bool {
    let Some(delivery) = batch.delivery.as_ref() else {
        return false;
    };
    delivery.mode == SourceDeliveryMode::ChangeFeed
        && state.found
        && !state.open_transaction
        && state.generation_status == Some(SourceGenerationStatus::Active)
        && state.delivery_mode == Some(SourceDeliveryMode::ChangeFeed)
        && state.current_cursor.as_deref() == Some(batch.proposed_next_cursor.as_str())
        && state.last_committed_batch_digest.as_deref() == Some(batch.batch_digest.as_str())
        && state.latest_transaction_idempotency_key.as_deref()
            == Some(batch.idempotency_key.as_str())
        && state.sync_generation == Some(delivery.sync_generation)
        && state.source_feed_epoch == delivery.source_feed_epoch
        && state.committed_offset == delivery.offset_end
}

fn rejected_disposition(state: &SourceSyncStateView) -> SourceRunDisposition {
    if state.generation_status == Some(SourceGenerationStatus::RecoveryRequired)
        || state
            .latest_transaction_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("missing") && reason.contains("range"))
    {
        SourceRunDisposition::RecoveryRequired
    } else {
        SourceRunDisposition::Rejected
    }
}

fn read_state<T: SourceSyncTransport>(
    config: &SourceAdapterConfig,
    transport: &mut T,
) -> Result<SourceSyncStateView, ChangeFeedRunError> {
    transport
        .get_source_sync_state(&GetSourceSyncStateInput {
            namespace: config.namespace.clone(),
            source_instance: config.source_instance.clone(),
            type_digest: config.type_digest.clone(),
        })
        .map_err(|failure| match failure {
            TransportFailure::Unavailable => ChangeFeedRunError::StateUnavailable,
            TransportFailure::Ambiguous => ChangeFeedRunError::StateAmbiguous,
        })
}

fn pending_binding_batch(
    config: &SourceAdapterConfig,
    outbox: &SourceOutbox,
) -> Result<Option<SourceBatch>, ChangeFeedRunError> {
    let pending = outbox.pending().map_err(|_| ChangeFeedRunError::Outbox)?;
    Ok(pending.into_iter().find(|batch| {
        batch.namespace == config.namespace
            && batch.source_instance == config.source_instance
            && batch.type_digest == config.type_digest
    }))
}

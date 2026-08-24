//! Bounded checkpoint-driven snapshot transport for source-sync adapters.
//!
//! The control plane owns the committed cursor. This helper never interprets
//! cursor contents: it replays a durable pending page first, reads
//! `GetSourceSyncState`, and asks the source for the page after that exact
//! opaque cursor.

use crate::object_sync_sdk::{
    FlushDisposition, GetSourceSyncStateInput, SourceAdapterConfig, SourceGenerationStatus,
    SourceOutbox, SourceRunDisposition, SourceRunReport, SourceSyncStateView, SourceSyncTransport,
    TransportFailure, build_source_batch, build_source_batch_v2,
};
use sekai_chisei::sekai::object_sync::{
    MAX_SOURCE_BATCH_RECORDS, SourceBatch, SourceDeliveryMode, SourceDeliveryWindow, SourceRecord,
};

pub const DEFAULT_MAX_SNAPSHOT_PAGES_PER_RUN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotRunLimits {
    pub max_pages_per_run: usize,
    pub max_records_per_page: usize,
}

impl Default for SnapshotRunLimits {
    fn default() -> Self {
        Self {
            max_pages_per_run: DEFAULT_MAX_SNAPSHOT_PAGES_PER_RUN,
            max_records_per_page: MAX_SOURCE_BATCH_RECORDS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPage {
    pub records: Vec<SourceRecord>,
    pub proposed_next_cursor: String,
    pub collected_at_ms: i64,
    /// Local source knowledge. The cursor remains opaque to the control plane.
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRead {
    Page(SnapshotPage),
    /// Valid only after at least one durable page checkpoint already exists.
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSourceFailure {
    Unavailable,
    Invalid,
}

/// Source-owned page reader. Authentication and remote payload collection stay
/// outside this interface; implementations return normalized records only.
pub trait SnapshotPageSource {
    fn read_page(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<SnapshotRead, SnapshotSourceFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationSnapshotPage {
    pub records: Vec<SourceRecord>,
    pub proposed_next_cursor: String,
    pub collected_at_ms: i64,
    pub complete: bool,
    /// Required only for the terminal page.
    pub source_feed_epoch: Option<String>,
    /// Required only for the terminal page.
    pub handoff_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerationSnapshotRead {
    Page(GenerationSnapshotPage),
}

pub trait GenerationSnapshotSource {
    fn read_generation_page(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<GenerationSnapshotRead, SnapshotSourceFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRunOutcome {
    Complete {
        pages_committed: usize,
        committed_cursor: String,
    },
    InProgress {
        pages_committed: usize,
        committed_cursor: Option<String>,
    },
    Pending {
        pages_committed: usize,
        committed_cursor: Option<String>,
    },
    RecoveryRequired {
        pages_committed: usize,
        committed_cursor: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotRunError {
    InvalidLimits,
    Outbox,
    StateUnavailable,
    StateAmbiguous,
    SourceUnavailable,
    InvalidPage,
    Rejected,
}

impl std::fmt::Display for SnapshotRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "snapshot runner limits are invalid",
            Self::Outbox => "snapshot outbox is unavailable",
            Self::StateUnavailable => "source sync state is unavailable",
            Self::StateAmbiguous => "source sync state is ambiguous",
            Self::SourceUnavailable => "snapshot source is unavailable",
            Self::InvalidPage => "snapshot source returned an invalid page",
            Self::Rejected => "snapshot page was rejected",
        })
    }
}

impl std::error::Error for SnapshotRunError {}

/// Process a bounded number of snapshot pages.
///
/// Every invocation starts from durable outbox and control-plane evidence.
/// Exact commits may advance the loop; ambiguous delivery remains pending and
/// an unpaired server-side OPEN transaction requires operator repair or exact
/// replay from another durable copy.
pub fn run_snapshot<T: SourceSyncTransport, S: SnapshotPageSource>(
    config: &SourceAdapterConfig,
    outbox: &SourceOutbox,
    transport: &mut T,
    source: &mut S,
    limits: SnapshotRunLimits,
) -> Result<SnapshotRunOutcome, SnapshotRunError> {
    validate_limits(limits)?;
    let mut pages_committed = 0;

    if let Some(pending) = pending_binding_batch(config, outbox)? {
        let entry = outbox
            .flush_idempotency_key(&pending.idempotency_key, transport, true)
            .map_err(|_| SnapshotRunError::Outbox)?;
        match entry.disposition {
            FlushDisposition::Pending => {
                return Ok(SnapshotRunOutcome::Pending {
                    pages_committed,
                    committed_cursor: None,
                });
            }
            FlushDisposition::Quarantined => return Err(SnapshotRunError::Rejected),
            FlushDisposition::Committed => {
                let state = read_state(config, transport)?;
                if !state_matches_batch(&state, &pending) {
                    return Ok(SnapshotRunOutcome::RecoveryRequired {
                        pages_committed,
                        committed_cursor: state.current_cursor,
                    });
                }
            }
        }
    }

    loop {
        let state = read_state(config, transport)?;
        let committed_cursor = state.current_cursor.clone();

        if state.open_transaction || (!state.found && state.current_cursor.is_some()) {
            return Ok(SnapshotRunOutcome::RecoveryRequired {
                pages_committed,
                committed_cursor,
            });
        }

        let read = source
            .read_page(state.current_cursor.as_deref(), limits.max_records_per_page)
            .map_err(|failure| match failure {
                SnapshotSourceFailure::Unavailable => SnapshotRunError::SourceUnavailable,
                SnapshotSourceFailure::Invalid => SnapshotRunError::InvalidPage,
            })?;
        let page = match read {
            SnapshotRead::Complete => {
                return state
                    .current_cursor
                    .map(|committed_cursor| SnapshotRunOutcome::Complete {
                        pages_committed,
                        committed_cursor,
                    })
                    .ok_or(SnapshotRunError::InvalidPage);
            }
            SnapshotRead::Page(page) => page,
        };
        validate_page(&page, state.current_cursor.as_deref(), limits)?;

        let batch = build_source_batch(
            config,
            state.current_cursor.as_deref().unwrap_or_default(),
            &page.proposed_next_cursor,
            page.collected_at_ms,
            page.records,
        )
        .map_err(|_| SnapshotRunError::InvalidPage)?;
        outbox
            .enqueue(&batch)
            .map_err(|_| SnapshotRunError::Outbox)?;
        let entry = outbox
            .flush_idempotency_key(&batch.idempotency_key, transport, true)
            .map_err(|_| SnapshotRunError::Outbox)?;

        match entry.disposition {
            FlushDisposition::Committed => {
                let verified_state = read_state(config, transport)?;
                if !state_matches_batch(&verified_state, &batch) {
                    return Ok(SnapshotRunOutcome::RecoveryRequired {
                        pages_committed,
                        committed_cursor: verified_state.current_cursor,
                    });
                }
                pages_committed += 1;
                if page.complete {
                    return Ok(SnapshotRunOutcome::Complete {
                        pages_committed,
                        committed_cursor: batch.proposed_next_cursor,
                    });
                }
                if pages_committed == limits.max_pages_per_run {
                    return Ok(SnapshotRunOutcome::InProgress {
                        pages_committed,
                        committed_cursor: Some(batch.proposed_next_cursor),
                    });
                }
            }
            FlushDisposition::Pending => {
                return Ok(SnapshotRunOutcome::Pending {
                    pages_committed,
                    committed_cursor,
                });
            }
            FlushDisposition::Quarantined => return Err(SnapshotRunError::Rejected),
        }
    }
}

/// Process generation-fenced v2 snapshot pages.
///
/// A new generation is admitted only for a new/legacy binding or after the
/// plane reports the prior generation as recovery-required.
pub fn run_generation_snapshot_v2<T: SourceSyncTransport, S: GenerationSnapshotSource>(
    config: &SourceAdapterConfig,
    outbox: &SourceOutbox,
    transport: &mut T,
    source: &mut S,
    limits: SnapshotRunLimits,
) -> Result<SourceRunReport, SnapshotRunError> {
    if validate_limits(limits).is_err() {
        return Ok(SourceRunReport {
            disposition: SourceRunDisposition::InvalidInput,
            batches_committed: 0,
            committed_cursor: None,
            sync_generation: None,
            committed_offset: None,
        });
    }
    let mut batches_committed = 0;

    if let Some(pending) = pending_binding_batch(config, outbox)? {
        let entry = outbox
            .flush_idempotency_key(&pending.idempotency_key, transport, true)
            .map_err(|_| SnapshotRunError::Outbox)?;
        match entry.disposition {
            FlushDisposition::Pending => {
                let state = read_state(config, transport)?;
                return Ok(SourceRunReport::from_state(
                    SourceRunDisposition::Pending,
                    batches_committed,
                    &state,
                ));
            }
            FlushDisposition::Quarantined => {
                let state = read_state(config, transport)?;
                return Ok(SourceRunReport::from_state(
                    rejected_disposition(&state),
                    batches_committed,
                    &state,
                ));
            }
            FlushDisposition::Committed => {
                let state = read_state(config, transport)?;
                if !state_matches_v2_batch(&state, &pending) {
                    return Ok(SourceRunReport::from_state(
                        SourceRunDisposition::RecoveryRequired,
                        batches_committed,
                        &state,
                    ));
                }
                batches_committed += 1;
            }
        }
    }

    loop {
        let state = read_state(config, transport)?;
        if state.open_transaction || (!state.found && state.current_cursor.is_some()) {
            return Ok(SourceRunReport::from_state(
                SourceRunDisposition::RecoveryRequired,
                batches_committed,
                &state,
            ));
        }
        let Some(sync_generation) = snapshot_generation(&state) else {
            let disposition = if state.generation_status == Some(SourceGenerationStatus::Active) {
                SourceRunDisposition::CaughtUp
            } else {
                SourceRunDisposition::RecoveryRequired
            };
            return Ok(SourceRunReport::from_state(
                disposition,
                batches_committed,
                &state,
            ));
        };

        let page = match source
            .read_generation_page(state.current_cursor.as_deref(), limits.max_records_per_page)
        {
            Ok(GenerationSnapshotRead::Page(page)) => page,
            Err(SnapshotSourceFailure::Unavailable) => {
                return Ok(SourceRunReport::from_state(
                    SourceRunDisposition::Pending,
                    batches_committed,
                    &state,
                ));
            }
            Err(SnapshotSourceFailure::Invalid) => {
                return Ok(SourceRunReport::from_state(
                    SourceRunDisposition::InvalidInput,
                    batches_committed,
                    &state,
                ));
            }
        };
        if !valid_generation_page(&page, state.current_cursor.as_deref(), limits) {
            return Ok(SourceRunReport::from_state(
                SourceRunDisposition::InvalidInput,
                batches_committed,
                &state,
            ));
        }

        let delivery = SourceDeliveryWindow {
            mode: SourceDeliveryMode::Snapshot,
            sync_generation,
            source_feed_epoch: page.source_feed_epoch.clone(),
            offset_start: None,
            offset_end: page.handoff_offset,
            snapshot_complete: page.complete,
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
                    batches_committed,
                    &state,
                ));
            }
        };
        outbox
            .enqueue(&batch)
            .map_err(|_| SnapshotRunError::Outbox)?;
        let entry = outbox
            .flush_idempotency_key(&batch.idempotency_key, transport, true)
            .map_err(|_| SnapshotRunError::Outbox)?;
        match entry.disposition {
            FlushDisposition::Pending => {
                return Ok(SourceRunReport::from_state(
                    SourceRunDisposition::Pending,
                    batches_committed,
                    &state,
                ));
            }
            FlushDisposition::Quarantined => {
                let rejected_state = read_state(config, transport)?;
                return Ok(SourceRunReport::from_state(
                    rejected_disposition(&rejected_state),
                    batches_committed,
                    &rejected_state,
                ));
            }
            FlushDisposition::Committed => {
                let verified = read_state(config, transport)?;
                if !state_matches_v2_batch(&verified, &batch) {
                    return Ok(SourceRunReport::from_state(
                        SourceRunDisposition::RecoveryRequired,
                        batches_committed,
                        &verified,
                    ));
                }
                batches_committed += 1;
                if page.complete {
                    return Ok(SourceRunReport::from_state(
                        SourceRunDisposition::CaughtUp,
                        batches_committed,
                        &verified,
                    ));
                }
                if batches_committed == limits.max_pages_per_run {
                    return Ok(SourceRunReport::from_state(
                        SourceRunDisposition::InProgress,
                        batches_committed,
                        &verified,
                    ));
                }
            }
        }
    }
}

fn read_state<T: SourceSyncTransport>(
    config: &SourceAdapterConfig,
    transport: &mut T,
) -> Result<crate::object_sync_sdk::SourceSyncStateView, SnapshotRunError> {
    transport
        .get_source_sync_state(&GetSourceSyncStateInput {
            namespace: config.namespace.clone(),
            source_instance: config.source_instance.clone(),
            type_digest: config.type_digest.clone(),
        })
        .map_err(|failure| match failure {
            TransportFailure::Unavailable => SnapshotRunError::StateUnavailable,
            TransportFailure::Ambiguous => SnapshotRunError::StateAmbiguous,
        })
}

fn state_matches_batch(
    state: &crate::object_sync_sdk::SourceSyncStateView,
    batch: &sekai_chisei::sekai::object_sync::SourceBatch,
) -> bool {
    state.found
        && !state.open_transaction
        && state.current_cursor.as_deref() == Some(batch.proposed_next_cursor.as_str())
        && state.last_committed_batch_digest.as_deref() == Some(batch.batch_digest.as_str())
}

fn snapshot_generation(state: &SourceSyncStateView) -> Option<u64> {
    match state.generation_status {
        None if state.sync_generation.is_none() => Some(1),
        Some(SourceGenerationStatus::Snapshotting)
            if state.delivery_mode == Some(SourceDeliveryMode::Snapshot) =>
        {
            state.sync_generation
        }
        Some(SourceGenerationStatus::RecoveryRequired) => state
            .sync_generation
            .and_then(|generation| generation.checked_add(1)),
        _ => None,
    }
}

fn state_matches_v2_batch(state: &SourceSyncStateView, batch: &SourceBatch) -> bool {
    let Some(delivery) = batch.delivery.as_ref() else {
        return false;
    };
    let common = state.found
        && !state.open_transaction
        && state.current_cursor.as_deref() == Some(batch.proposed_next_cursor.as_str())
        && state.last_committed_batch_digest.as_deref() == Some(batch.batch_digest.as_str())
        && state.latest_transaction_idempotency_key.as_deref()
            == Some(batch.idempotency_key.as_str())
        && state.sync_generation == Some(delivery.sync_generation);
    if !common {
        return false;
    }
    match delivery.mode {
        SourceDeliveryMode::Snapshot if delivery.snapshot_complete => {
            state.generation_status == Some(SourceGenerationStatus::Active)
                && state.delivery_mode == Some(SourceDeliveryMode::ChangeFeed)
                && state.source_feed_epoch == delivery.source_feed_epoch
                && state.committed_offset == delivery.offset_end
        }
        SourceDeliveryMode::Snapshot => {
            state.generation_status == Some(SourceGenerationStatus::Snapshotting)
                && state.delivery_mode == Some(SourceDeliveryMode::Snapshot)
                && state.source_feed_epoch.is_none()
                && state.committed_offset.is_none()
        }
        SourceDeliveryMode::ChangeFeed => false,
    }
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

fn validate_limits(limits: SnapshotRunLimits) -> Result<(), SnapshotRunError> {
    if limits.max_pages_per_run == 0
        || limits.max_records_per_page == 0
        || limits.max_records_per_page > MAX_SOURCE_BATCH_RECORDS
    {
        Err(SnapshotRunError::InvalidLimits)
    } else {
        Ok(())
    }
}

fn validate_page(
    page: &SnapshotPage,
    committed_cursor: Option<&str>,
    limits: SnapshotRunLimits,
) -> Result<(), SnapshotRunError> {
    if page.records.is_empty()
        || page.records.len() > limits.max_records_per_page
        || page.proposed_next_cursor.is_empty()
        || committed_cursor == Some(page.proposed_next_cursor.as_str())
    {
        Err(SnapshotRunError::InvalidPage)
    } else {
        Ok(())
    }
}

fn valid_generation_page(
    page: &GenerationSnapshotPage,
    committed_cursor: Option<&str>,
    limits: SnapshotRunLimits,
) -> bool {
    let terminal_metadata_valid = if page.complete {
        page.source_feed_epoch
            .as_deref()
            .is_some_and(|epoch| !epoch.is_empty())
            && page.handoff_offset.is_some()
    } else {
        page.source_feed_epoch.is_none() && page.handoff_offset.is_none()
    };
    !page.records.is_empty()
        && page.records.len() <= limits.max_records_per_page
        && !page.proposed_next_cursor.is_empty()
        && committed_cursor != Some(page.proposed_next_cursor.as_str())
        && terminal_metadata_valid
}

fn pending_binding_batch(
    config: &SourceAdapterConfig,
    outbox: &SourceOutbox,
) -> Result<Option<sekai_chisei::sekai::object_sync::SourceBatch>, SnapshotRunError> {
    let pending = outbox.pending().map_err(|_| SnapshotRunError::Outbox)?;
    Ok(pending.into_iter().find(|batch| {
        batch.namespace == config.namespace
            && batch.source_instance == config.source_instance
            && batch.type_digest == config.type_digest
    }))
}

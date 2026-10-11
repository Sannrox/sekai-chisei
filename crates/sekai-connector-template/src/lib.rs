//! Source connector built on `sekai-source-sdk`.
//!
//! `run_once` is one sync step: replay this binding's pending outbox batch, read the page
//! after the plane-committed cursor, and commit it as exactly one
//! `ApplySourceBatch` transaction. Call it until it reports `UpToDate` or a
//! committed final page.

pub mod config;
pub mod fake;
pub mod source;
pub mod transport;

use config::ConnectorConfig;
use sekai_source_sdk::{
    FlushDisposition, GetSourceSyncStateInput, MAX_SOURCE_BATCH_RECORDS, SnapshotPageSource,
    SnapshotRead, SourceOutbox, SourceSyncTransport, build_registered_source_batch,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// One page committed; the checkpoint now points at `cursor`. `complete`
    /// is the source's own signal that this was the final page.
    Committed { cursor: String, complete: bool },
    /// Delivery outcome unknown; the exact batch stays in the outbox.
    Pending,
    /// The plane rejected the batch; it moved to the outbox quarantine.
    Quarantined,
    /// The source has nothing after the committed cursor.
    UpToDate,
}

pub fn run_once<S: SnapshotPageSource, T: SourceSyncTransport>(
    config: &ConnectorConfig,
    outbox: &SourceOutbox,
    source: &mut S,
    transport: &mut T,
) -> Result<RunOutcome, String> {
    // Replay only this binding's pending batch; a shared outbox may hold others.
    let own = outbox.pending()?.into_iter().filter(|batch| {
        batch.namespace == config.namespace
            && batch.source == config.source
            && batch.source_instance == config.source_instance
            && batch.type_digest == config.type_digest
    });
    for pending in own {
        let disposition = outbox
            .flush_idempotency_key(&pending.idempotency_key, transport, true)?
            .disposition;
        if let Some(outcome) = unfinished(disposition) {
            return Ok(outcome);
        }
    }

    let state = transport
        .get_source_sync_state(&GetSourceSyncStateInput {
            namespace: config.namespace.clone(),
            source_instance: config.source_instance.clone(),
            type_digest: config.type_digest.clone(),
        })
        .map_err(|_| "source sync state is unavailable".to_string())?;
    if state.open_transaction {
        return Ok(RunOutcome::Pending);
    }
    let cursor = state.current_cursor;
    let page = match source
        .read_page(cursor.as_deref(), MAX_SOURCE_BATCH_RECORDS)
        .map_err(|failure| format!("source read failed: {failure:?}"))?
    {
        // Completion is only valid once a page checkpoint is durable.
        SnapshotRead::Complete if cursor.is_some() => return Ok(RunOutcome::UpToDate),
        SnapshotRead::Complete => {
            return Err("source reported completion before any committed page".into());
        }
        SnapshotRead::Page(page) => page,
    };
    if page.proposed_next_cursor.is_empty() || Some(&page.proposed_next_cursor) == cursor.as_ref() {
        return Err("source page did not advance the cursor".into());
    }
    let batch = build_registered_source_batch(
        &config.adapter(),
        &config.source,
        cursor.as_deref().unwrap_or_default(),
        &page.proposed_next_cursor,
        page.collected_at_ms,
        page.records,
    )?;
    outbox.enqueue(&batch)?;
    let disposition = outbox
        .flush_idempotency_key(&batch.idempotency_key, transport, true)?
        .disposition;
    Ok(unfinished(disposition).unwrap_or(RunOutcome::Committed {
        cursor: batch.proposed_next_cursor,
        complete: page.complete,
    }))
}

fn unfinished(disposition: FlushDisposition) -> Option<RunOutcome> {
    match disposition {
        FlushDisposition::Committed => None,
        FlushDisposition::Pending => Some(RunOutcome::Pending),
        FlushDisposition::Quarantined => Some(RunOutcome::Quarantined),
    }
}
